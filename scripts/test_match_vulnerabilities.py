#!/usr/bin/env python3
"""Fixture tests for match-vulnerabilities.py — locks down the
detail-fetch contract added in the review follow-ups:

- detailsFetched marker: false when any OSV record in the alias group
  could not be retrieved (non-404 fetch failure, 404 withdrawal, parse
  failure, or ID rejected by validation); true otherwise, including
  "advisory fetched fine but genuinely has no summary".
- OSV ID URL defense: IDs must match full-string [A-Za-z0-9._-]+ before being
  interpolated into the /v1/vulns/{id} path.
- Byte-identical findings output across runs (determinism).

All HTTP is mocked; no network access. Run:
python3 scripts/test_match_vulnerabilities.py
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "match-vulnerabilities.py")
spec = importlib.util.spec_from_file_location("match_vulnerabilities", SCRIPT)
matcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matcher)

SBOM = {
    "components": [
        {"type": "library", "bom-ref": "pkg:npm/express@4.21.2",
         "purl": "pkg:npm/express@4.21.2",
         "name": "express", "version": "4.21.2"}
    ],
    "dependencies": [],
    "metadata": {"timestamp": "2026-10-17T00:00:00Z",
                 "component": {"name": "test-app"}},
}

ADVISORY = {
    "id": "GHSA-1", "aliases": ["CVE-2024-47081"],
    "schema_version": "1.9.0", "summary": "Fake advisory summary",
    "database_specific": {"severity": "HIGH"},
}


def make_http(batch_response, detail_responses):
    """Return (fake_http_request, urls_seen). detail_responses maps
    OSV ID -> (status_code, body_obj); IDs with no entry return 404."""
    urls = []

    def fake(url, *, data=None, timeout=30):
        urls.append(url)
        if url.endswith("/v1/querybatch"):
            return 200, json.dumps(batch_response).encode("utf-8")
        vuln_id = url.rsplit("/v1/vulns/", 1)[1]
        if vuln_id in detail_responses:
            code, body = detail_responses[vuln_id]
            if isinstance(body, bytes):
                return code, body
            return code, json.dumps(body).encode("utf-8")
        return 404, b"{}"

    return fake, urls


class ScannerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.sbom_path = os.path.join(self.tmpdir.name, "sbom.cdx.json")
        with open(self.sbom_path, "w", encoding="utf-8") as f:
            json.dump(SBOM, f)
        self.findings_path = os.path.join(self.tmpdir.name, "findings.json")
        self._old_env = {
            k: os.environ.get(k)
            for k in ("INPUT_SBOM_FILE", "INPUT_FINDINGS_OUTPUT",
                      "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY")
        }
        os.environ["INPUT_SBOM_FILE"] = self.sbom_path
        os.environ["INPUT_FINDINGS_OUTPUT"] = self.findings_path
        for k in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
            os.environ.pop(k, None)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def run_scan(self, batch_response, detail_responses):
        fake, urls = make_http(batch_response, detail_responses)
        self._old_http = matcher.http_request
        matcher.http_request = fake
        self.addCleanup(setattr, matcher, "http_request", self._old_http)
        scanner = matcher.Scanner()
        scanner.run()
        with open(self.findings_path, "r", encoding="utf-8") as f:
            return json.load(f), scanner, urls

    def first_vuln(self, findings_doc):
        self.assertEqual(findings_doc["scanStatus"], "complete")
        return findings_doc["findings"][0]["vulnerabilities"][0]


class DetailsFetchedTests(ScannerTestCase):
    def batch(self, *ids):
        return {"results": [{"vulns": [{"id": i} for i in ids]}]}

    def test_true_when_advisory_fetched(self):
        doc, _, _ = self.run_scan(
            self.batch("GHSA-1"), {"GHSA-1": (200, ADVISORY)})
        vuln = self.first_vuln(doc)
        self.assertTrue(vuln["detailsFetched"])
        self.assertEqual(vuln["summary"], "Fake advisory summary")

    def test_true_when_advisory_genuinely_has_no_summary(self):
        record = {k: v for k, v in ADVISORY.items() if k != "summary"}
        doc, _, _ = self.run_scan(
            self.batch("GHSA-1"), {"GHSA-1": (200, record)})
        vuln = self.first_vuln(doc)
        self.assertTrue(vuln["detailsFetched"])
        self.assertIsNone(vuln["summary"])

    def test_false_on_detail_fetch_failure(self):
        doc, _, _ = self.run_scan(
            self.batch("GHSA-1"), {"GHSA-1": (500, {})})
        vuln = self.first_vuln(doc)
        self.assertFalse(vuln["detailsFetched"])
        self.assertIsNone(vuln["summary"])
        self.assertIsNone(vuln["databaseSpecificSeverity"])
        self.assertEqual(doc["scanStatus"], "complete",
                         "detail failure must not fake a partial scan")

    def test_false_on_404_withdrawn(self):
        doc, _, _ = self.run_scan(self.batch("GHSA-1"), {})
        vuln = self.first_vuln(doc)
        self.assertFalse(vuln["detailsFetched"])

    def test_false_on_unparseable_body(self):
        doc, _, _ = self.run_scan(
            self.batch("GHSA-1"), {"GHSA-1": (200, b"not json{")})
        self.assertFalse(self.first_vuln(doc)["detailsFetched"])

    def test_false_on_json_detail_that_is_not_an_object(self):
        for body in (["not", "an advisory"], "text", 123, None):
            with self.subTest(body=body):
                doc, _, _ = self.run_scan(
                    self.batch("GHSA-1"), {"GHSA-1": (200, body)})
                self.assertFalse(self.first_vuln(doc)["detailsFetched"])

    def test_alias_group_merged_when_all_records_fetched(self):
        other = {"id": "PYSEC-1", "aliases": ["CVE-2024-47081"],
                 "schema_version": "1.7.5", "summary": "Other record"}
        doc, _, _ = self.run_scan(
            self.batch("GHSA-1", "PYSEC-1"),
            {"GHSA-1": (200, ADVISORY), "PYSEC-1": (200, other)})
        vulns = doc["findings"][0]["vulnerabilities"]
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["id"], "CVE-2024-47081")
        self.assertEqual(vulns[0]["osvIds"], ["GHSA-1", "PYSEC-1"])
        self.assertTrue(vulns[0]["detailsFetched"])

    def test_failed_record_cannot_join_its_alias_group(self):
        """When a record fails to fetch, its aliases are unknown, so the
        alias closure cannot merge it — the finding is emitted standalone
        with detailsFetched: false (uncertainty stays visible)."""
        other = {"id": "PYSEC-1", "aliases": ["CVE-2024-47081"],
                 "schema_version": "1.7.5", "summary": "Other record"}
        doc, _, _ = self.run_scan(
            self.batch("GHSA-1", "PYSEC-1"),
            {"GHSA-1": (200, ADVISORY), "PYSEC-1": (500, {})})
        vulns = doc["findings"][0]["vulnerabilities"]
        self.assertEqual(len(vulns), 2)
        by_id = {v["id"]: v for v in vulns}
        self.assertEqual(by_id["CVE-2024-47081"]["osvIds"], ["GHSA-1"])
        self.assertTrue(by_id["CVE-2024-47081"]["detailsFetched"])
        self.assertEqual(by_id["PYSEC-1"]["osvIds"], ["PYSEC-1"])
        self.assertFalse(by_id["PYSEC-1"]["detailsFetched"])
        self.assertIsNone(by_id["PYSEC-1"]["summary"])


class OsvIdValidationTests(ScannerTestCase):
    def test_invalid_id_never_reaches_url(self):
        evil = "GHSA-1/../../v1/vulns/other"
        doc, _, urls = self.run_scan(
            {"results": [{"vulns": [{"id": evil}]}]}, {})
        for url in urls:
            self.assertNotIn("../", url)
            self.assertNotIn("other", url)
        vuln = self.first_vuln(doc)
        self.assertFalse(vuln["detailsFetched"])

    def test_non_string_id_never_reaches_url(self):
        doc, _, _ = self.run_scan(
            {"results": [{"vulns": [{"id": 12345}]}]}, {})
        vuln = self.first_vuln(doc)
        self.assertFalse(vuln["detailsFetched"])
        self.assertEqual(vuln["id"], 12345,
                         "evidence is preserved raw; only the URL is defended")

    def test_trailing_newline_and_mixed_type_ids_never_reach_url_or_crash(self):
        invalid = "GHSA-newline\n"
        doc, _, urls = self.run_scan(
            {"results": [{"vulns": [
                {"id": "GHSA-1"}, {"id": 12345}, {"id": invalid},
            ]}]},
            {"GHSA-1": (200, ADVISORY)})
        detail_urls = [url for url in urls if "/v1/vulns/" in url]
        self.assertEqual(detail_urls, ["https://api.osv.dev/v1/vulns/GHSA-1"])
        by_osv_id = {
            osv_id: vuln
            for vuln in doc["findings"][0]["vulnerabilities"]
            for osv_id in vuln["osvIds"]
        }
        self.assertTrue(by_osv_id["GHSA-1"]["detailsFetched"])
        self.assertFalse(by_osv_id[12345]["detailsFetched"])
        self.assertFalse(by_osv_id[invalid]["detailsFetched"])

    def test_valid_ids_still_fetched(self):
        doc, _, urls = self.run_scan(
            {"results": [{"vulns": [{"id": "GHSA-9hjg-9r4m-mvj7"}]}]},
            {"GHSA-9hjg-9r4m-mvj7": (200, ADVISORY)})
        self.assertTrue(urls[-1].endswith("/v1/vulns/GHSA-9hjg-9r4m-mvj7"))
        self.assertTrue(self.first_vuln(doc)["detailsFetched"])


class DeterminismTests(ScannerTestCase):
    def test_byte_identical_output_across_runs(self):
        batch = {"results": [{"vulns": [{"id": "GHSA-1"}]}]}
        details = {"GHSA-1": (200, ADVISORY)}
        path_a = os.path.join(self.tmpdir.name, "a.json")
        path_b = os.path.join(self.tmpdir.name, "b.json")

        os.environ["INPUT_FINDINGS_OUTPUT"] = path_a
        self.findings_path = path_a
        self.run_scan(batch, details)
        os.environ["INPUT_FINDINGS_OUTPUT"] = path_b
        self.findings_path = path_b
        doc_b, _, _ = self.run_scan(batch, details)

        with open(path_a, "rb") as f:
            bytes_a = f.read()
        with open(path_b, "rb") as f:
            bytes_b = f.read()
        self.assertEqual(bytes_a, bytes_b)
        self.assertTrue(doc_b["findings"][0]["vulnerabilities"][0]
                        ["detailsFetched"])


if __name__ == "__main__":
    unittest.main()
