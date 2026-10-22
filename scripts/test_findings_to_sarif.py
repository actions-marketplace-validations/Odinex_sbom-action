#!/usr/bin/env python3
"""Fixture tests for findings-to-sarif.py — locks down the SARIF 2.1.0
contract: one rule per canonical vulnerability (rules reused across
components), result per component finding with purl artifact and stable
partialFingerprints, severity → level mapping (null/non-string severity
→ note, MEDIUM → warning), byte-identical output across runs, and the
structural validator (fails loudly on every construct this tool emits).

Run: python3 scripts/test_findings_to_sarif.py
"""

import hashlib
import importlib.util
import json
import os
import sys
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "findings-to-sarif.py")
spec = importlib.util.spec_from_file_location("findings_to_sarif", SCRIPT)
sarif_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sarif_mod)


def vuln(vuln_id, severity="MODERATE", **extra):
    base = {"id": vuln_id, "osvIds": [vuln_id], "aliases": [],
            "summary": f"Summary of {vuln_id}",
            "databaseSpecificSeverity": severity,
            "epss": None, "kev": None, "references": []}
    base.update(extra)
    return base


def finding(purl, vulns_list, lockfile="/bun.lock"):
    return {"component": {"purl": purl, "name": "x", "version": "1.0",
                          "lockfile": lockfile},
            "vulnerabilities": vulns_list}


def sarify(findings_list):
    doc = {"findings": findings_list}
    sarif = sarif_mod.build_sarif(doc)
    errors = sarif_mod.validate_sarif(sarif)
    assert not errors, errors
    return sarif


class RuleContractTests(unittest.TestCase):
    def test_one_rule_per_canonical_vulnerability(self):
        sarif = sarify([
            finding("pkg:npm/a@1.0", [vuln("GHSA-1", "HIGH")]),
            finding("pkg:npm/b@2.0", [vuln("GHSA-1", "HIGH"),
                                      vuln("GHSA-2", "LOW")]),
        ])
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual([r["id"] for r in rules], ["GHSA-1", "GHSA-2"])
        results = sarif["runs"][0]["results"]
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertEqual(
                rules[result["ruleIndex"]]["id"], result["ruleId"])

    def test_rule_properties_carry_epss_kev_osvids_lockfile(self):
        epss = {"score": 0.97, "percentile": 0.9994, "date": "2026-10-17"}
        kev = {"knownExploited": True, "dueDate": "2026-10-19",
               "added": "2026-10-16"}
        sarif = sarify([finding("pkg:npm/a@1.0",
                               [vuln("CVE-2020-1472", "CRITICAL",
                                     epss=epss, kev=kev,
                                     osvIds=["GHSA-x", "PYSEC-y"])])])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["id"], "CVE-2020-1472")
        self.assertEqual(rule["shortDescription"]["text"],
                         "Summary of CVE-2020-1472")
        self.assertEqual(rule["properties"]["epss"], epss)
        self.assertEqual(rule["properties"]["kev"], kev)
        self.assertEqual(rule["properties"]["osvIds"],
                         ["GHSA-x", "PYSEC-y"])
        self.assertEqual(rule["properties"]["lockfile"], "/bun.lock")

    def test_non_string_finding_id_is_stringified_for_sarif(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln(12345, "HIGH")])])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(rule["id"], "12345")
        self.assertEqual(result["ruleId"], "12345")
        self.assertEqual(rule["shortDescription"]["text"], "Summary of 12345")


class ResultContractTests(unittest.TestCase):
    def test_result_artifact_is_purl(self):
        sarif = sarify([finding("pkg:npm/brace-expansion@2.1.4",
                                [vuln("GHSA-1")])])
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(
            result["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"],
            "pkg:npm/brace-expansion@2.1.4")
        self.assertEqual(result["ruleId"], "GHSA-1")
        self.assertEqual(result["properties"]["lockfile"], "/bun.lock")

    def test_partial_fingerprint_is_stable_hash_of_purl_and_key(self):
        expected = hashlib.sha256(
            b"pkg:npm/a@1.0|CVE-2024-47081").hexdigest()
        sarif1 = sarify([finding("pkg:npm/a@1.0",
                                 [vuln("CVE-2024-47081")])])
        sarif2 = sarify([finding("pkg:npm/a@1.0",
                                 [vuln("CVE-2024-47081")])])
        fp1 = sarif1["runs"][0]["results"][0]["partialFingerprints"]
        fp2 = sarif2["runs"][0]["results"][0]["partialFingerprints"]
        self.assertEqual(fp1, fp2)
        self.assertEqual(
            fp1[sarif_mod.FINGERPRINT_KEY], expected)

    def test_fingerprints_differ_per_purl(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln("GHSA-1")]),
                        finding("pkg:npm/b@2.0", [vuln("GHSA-1")])])
        results = sarif["runs"][0]["results"]
        fp_a = results[0]["partialFingerprints"][sarif_mod.FINGERPRINT_KEY]
        fp_b = results[1]["partialFingerprints"][sarif_mod.FINGERPRINT_KEY]
        self.assertNotEqual(fp_a, fp_b)


class LevelMappingTests(unittest.TestCase):
    def test_critical_high_error_moderate_medium_warning(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [
            vuln("GHSA-crit", "CRITICAL"),
            vuln("GHSA-high", "HIGH"),
            vuln("GHSA-mod", "MODERATE"),
            vuln("GHSA-med", "MEDIUM"),
        ])])
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        self.assertEqual(levels, ["error", "error", "warning", "warning"])

    def test_low_and_null_severity_map_to_note(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [
            vuln("GHSA-low", "LOW"),
            vuln("GHSA-null", None),
        ])])
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        self.assertEqual(levels, ["note", "note"])

    def test_unknown_severity_maps_to_note_not_dropped(self):
        sarif = sarify([finding("pkg:npm/a@1.0",
                                [vuln("GHSA-x", "SOMETHING_ELSE")])])
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "note")

    def test_non_string_severity_maps_to_note_not_crash(self):
        # database_specific.severity is arbitrary per-database data —
        # a truthy non-string must not raise AttributeError
        for bad in (123, ["HIGH"], {"severity": "HIGH"}, True):
            self.assertEqual(
                sarif_mod.severity_to_level(bad), "note", msg=repr(bad))
        sarif = sarify([finding("pkg:npm/a@1.0",
                                [vuln("GHSA-n", 123)])])
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "note")

    def test_non_string_summary_falls_back_to_id_help_uri_ignored(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [
            vuln("GHSA-s", "HIGH", summary=123,
                 references=[{"type": "ADVISORY", "url": 123}])])])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["shortDescription"]["text"], "GHSA-s")
        self.assertNotIn("helpUri", rule)
        self.assertEqual(sarif_mod.validate_sarif(sarif), [])


class DeterminismTests(unittest.TestCase):
    def _findings(self):
        return [finding("pkg:npm/a@1.0",
                         [vuln("CVE-2024-47081", "HIGH")]),
                finding("pkg:npm/b@2.0",
                        [vuln("CVE-2024-47081", "HIGH"),
                         vuln("GHSA-2", "LOW")])]

    def test_identical_findings_produce_identical_serialization(self):
        # No sort_keys: pins dict insertion (key) order, so a future
        # change that emits keys nondeterministically fails here
        one = json.dumps(sarif_mod.build_sarif(
            {"findings": self._findings()}), indent=2)
        two = json.dumps(sarif_mod.build_sarif(
            {"findings": self._findings()}), indent=2)
        self.assertEqual(one, two)

    def test_main_writes_byte_identical_sarif_across_runs(self):
        # End-to-end byte-identity through the real write path
        # (main -> json.dump(indent=2) + newline), not just structural
        # equality: two full runs over identical findings must produce
        # identical files
        def run(tmpdir):
            os.makedirs(tmpdir, exist_ok=True)
            findings_path = os.path.join(tmpdir, "vulnerabilities.json")
            sarif_path = os.path.join(tmpdir, "findings.sarif")
            output_path = os.path.join(tmpdir, "github_output.txt")
            with open(findings_path, "w", encoding="utf-8") as f:
                json.dump({"findings": self._findings()}, f)
            saved = {}
            try:
                for key, value in (("INPUT_FINDINGS_FILE", findings_path),
                                   ("INPUT_SARIF_OUTPUT", sarif_path),
                                   ("GITHUB_OUTPUT", output_path)):
                    saved[key] = os.environ.get(key)
                    os.environ[key] = value
                self.assertEqual(sarif_mod.main(), 0)
            finally:
                for key, value in saved.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            with open(sarif_path, "rb") as f:
                return f.read()

        import tempfile
        base = tempfile.mkdtemp()
        first = run(os.path.join(base, "run1"))
        second = run(os.path.join(base, "run2"))
        self.assertTrue(first)
        self.assertEqual(first, second)


class ValidationTests(unittest.TestCase):
    def test_valid_sarif_has_no_errors(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln("GHSA-1")])])
        self.assertEqual(sarif_mod.validate_sarif(sarif), [])

    def test_missing_version_fails(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln("GHSA-1")])])
        del sarif["version"]
        self.assertTrue(sarif_mod.validate_sarif(sarif))

    def test_result_with_unknown_rule_fails(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln("GHSA-1")])])
        sarif["runs"][0]["results"][0]["ruleId"] = "GHSA-unknown"
        self.assertTrue(sarif_mod.validate_sarif(sarif))

    def test_result_with_bad_rule_index_fails(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln("GHSA-1")])])
        sarif["runs"][0]["results"][0]["ruleIndex"] = 7
        self.assertTrue(sarif_mod.validate_sarif(sarif))

    def test_result_with_invalid_level_fails(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln("GHSA-1")])])
        sarif["runs"][0]["results"][0]["level"] = "severe"
        self.assertTrue(sarif_mod.validate_sarif(sarif))

    def test_result_with_empty_message_fails(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln("GHSA-1")])])
        sarif["runs"][0]["results"][0]["message"] = {}
        self.assertTrue(sarif_mod.validate_sarif(sarif))

    def test_result_without_artifact_uri_fails(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln("GHSA-1")])])
        sarif["runs"][0]["results"][0]["locations"] = []
        self.assertTrue(sarif_mod.validate_sarif(sarif))

    def test_non_string_fingerprint_fails(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln("GHSA-1")])])
        sarif["runs"][0]["results"][0]["partialFingerprints"] = {
            sarif_mod.FINGERPRINT_KEY: 12345}
        self.assertTrue(sarif_mod.validate_sarif(sarif))

    def test_rule_without_short_description_fails(self):
        sarif = sarify([finding("pkg:npm/a@1.0", [vuln("GHSA-1")])])
        del sarif["runs"][0]["tool"]["driver"]["rules"][0][
            "shortDescription"]
        self.assertTrue(sarif_mod.validate_sarif(sarif))

    def test_empty_findings_produce_valid_empty_sarif(self):
        sarif = sarif_mod.build_sarif({"findings": []})
        self.assertEqual(sarif_mod.validate_sarif(sarif), [])
        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"], [])


if __name__ == "__main__":
    unittest.main()
