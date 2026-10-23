#!/usr/bin/env python3
"""Fixture tests for annotate-reachability.py — locks down the v0
reachability contract: the frozen field schema, the fail-secure
classification rules (direct, transitive, not-imported, dynamic-import
→ unknown), annotate-only behavior (no finding ever removed or
downgraded), determinism, and the fail-open policy.

Run: python3 scripts/test_annotate_reachability.py
"""

import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "annotate-reachability.py")
spec = importlib.util.spec_from_file_location("annotate_reachability", SCRIPT)
annotate_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(annotate_mod)


def vuln(vuln_id="CVE-2020-0001", **extra):
    base = {"id": vuln_id, "osvIds": [], "aliases": [], "epss": None,
            "kev": {"knownExploited": False}}
    base.update(extra)
    return base


def finding(purl, bom_ref=None, vulns=None, name=None):
    return {
        "component": {
            "bomRef": bom_ref if bom_ref is not None else f"ref:{purl}",
            "purl": purl,
            "name": name or purl.split("/")[-1].split("@")[0],
            "version": purl.rsplit("@", 1)[-1],
            "lockfile": "/package-lock.json",
        },
        "vulnerabilities": vulns if vulns is not None else [vuln()],
    }


def findings_doc(findings_list):
    return {"generatedAt": "2026-10-22T00:00:00Z", "scanStatus": "complete",
            "findings": findings_list}


def sbom_doc(components, dependencies):
    """components: [(ref, purl)], dependencies: [(ref, [dependsOn refs])]."""
    comps = []
    for ref, purl in components:
        comps.append({"type": "library", "bom-ref": ref, "purl": purl,
                      "version": purl.rsplit("@", 1)[-1]})
    deps = [{"ref": ref, "dependsOn": list(ons)} for ref, ons in dependencies]
    return {"components": comps, "dependencies": deps}


# A graph with real npm edges: demo-wrapper -> victim-pkg (the transitive
# fixture used by several tests).
NPM_GRAPH_SBOM = sbom_doc(
    [("ref-wrapper", "pkg:npm/demo-wrapper@1.0.0"),
     ("ref-victim", "pkg:npm/victim-pkg@2.0.0")],
    [("ref-wrapper", ["ref-victim"])])

PY_GRAPH_SBOM = sbom_doc(
    [("ref-flask", "pkg:pypi/Flask@2.2.5"),
     ("ref-jinja", "pkg:pypi/Jinja2@3.1.2")],
    [("ref-flask", ["ref-jinja"])])


class ReachabilityTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def write_tree(self, files):
        for rel, content in files.items():
            path = os.path.join(self.dir, rel)
            os.makedirs(os.path.dirname(path) or self.dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

    def classify(self, doc, tree_files, sbom=None):
        self.write_tree(tree_files)
        scan = annotate_mod.scan_source(self.dir)
        graph = (annotate_mod.load_graph(sbom) if sbom is not None
                 else annotate_mod.DependencyGraph())
        sbom_pypi_names = []
        if sbom is not None:
            for comp in sbom.get("components") or []:
                parsed = annotate_mod.parse_purl(comp.get("purl"))
                if parsed and parsed[0] == "pypi":
                    sbom_pypi_names.append(parsed[1])
        counts = annotate_mod.classify_findings(doc, scan, graph,
                                                sbom_pypi_names)
        return doc, counts


class DirectImportTests(ReachabilityTestBase):
    def test_direct_static_import_is_imported(self):
        doc = findings_doc([finding("pkg:npm/lodash@4.17.20")])
        doc, counts = self.classify(doc, {
            "src/app.js": ("import lodash from 'lodash';\n"
                           "import path from 'node:path';\n"),
            "src/other.ts": "const _ = require('lodash');\n",
        })
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "imported")
        self.assertEqual(reach["evidence"], ["src/app.js", "src/other.ts"])
        self.assertIn("static import", reach["note"])
        self.assertEqual(counts["imported"], 1)

    def test_direct_dynamic_literal_import_is_imported(self):
        doc = findings_doc([finding("pkg:npm/lodash@4.17.20")])
        doc, _ = self.classify(doc, {
            "src/lazy.js": "const x = await import('lodash');\n",
        })
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "imported")
        self.assertEqual(reach["evidence"], ["src/lazy.js"])
        self.assertIn("dynamic import with literal specifier", reach["note"])

    def test_scoped_npm_package_purl_is_decoded(self):
        doc = findings_doc([finding("pkg:npm/%40scope/pkg@1.0.0")])
        doc, _ = self.classify(doc, {
            "src/app.ts": "import widget from '@scope/pkg/lib/thing';\n",
        })
        self.assertEqual(doc["findings"][0]["reachability"]["level"],
                         "imported")

    def test_export_from_and_subpath_specifiers(self):
        doc = findings_doc([finding("pkg:npm/lodash@4.17.20")])
        doc, _ = self.classify(doc, {
            "src/barrel.js": "export * from 'lodash/merge';\n",
        })
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "imported")
        self.assertEqual(reach["evidence"], ["src/barrel.js"])

    def test_relative_and_builtin_specifiers_are_not_package_refs(self):
        doc = findings_doc([finding("pkg:npm/some-pkg@1.0.0",
                                    bom_ref="ref-unused")])
        doc, _ = self.classify(doc, {
            "src/app.js": ("import x from './util.js';\n"
                           "const f = require('fs');\n"
                           "import 'node:path';\n"),
        }, sbom=NPM_GRAPH_SBOM)
        self.assertEqual(doc["findings"][0]["reachability"]["level"],
                         "not-imported")
        self.assertEqual(doc["findings"][0]["reachability"]["evidence"], [])

    def test_python_direct_identity_import(self):
        doc = findings_doc([
            finding("pkg:pypi/requests@2.31.0", bom_ref="ref-requests"),
            finding("pkg:pypi/Flask@2.2.5", bom_ref="ref-flask"),
        ])
        doc, counts = self.classify(doc, {
            "src/app.py": ("import requests\n"
                           "from flask import Flask\n"
                           "import os\n"
                           "from . import helper\n"),
            "src/__init__.py": "",
            "src/helper.py": "x = 1\n",
        }, sbom=PY_GRAPH_SBOM)
        levels = [f["reachability"]["level"] for f in doc["findings"]]
        self.assertEqual(levels, ["imported", "imported"])
        self.assertEqual(counts["imported"], 2)

    def test_python_mapping_table_import_name_not_dist_name(self):
        doc = findings_doc([
            finding("pkg:pypi/beautifulsoup4@4.12.0",
                    bom_ref="ref-bs4"),
            finding("pkg:pypi/Pillow@10.0.0", bom_ref="ref-pillow"),
        ])
        doc, _ = self.classify(doc, {
            "src/app.py": ("from bs4 import BeautifulSoup\n"
                           "import PIL.Image as Image\n"),
        }, sbom=PY_GRAPH_SBOM)
        levels = [f["reachability"]["level"] for f in doc["findings"]]
        self.assertEqual(levels, ["imported", "imported"])


class TransitiveTests(ReachabilityTestBase):
    def test_transitive_chain_via_sbom_graph(self):
        doc = findings_doc([
            finding("pkg:npm/victim-pkg@2.0.0", bom_ref="ref-victim"),
        ])
        doc, counts = self.classify(doc, {
            "src/app.js": "import wrap from 'demo-wrapper';\n",
        }, sbom=NPM_GRAPH_SBOM)
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "imported")
        self.assertEqual(reach["evidence"], ["src/app.js"])
        self.assertIn("demo-wrapper@1.0.0", reach["note"])
        self.assertIn("victim-pkg@2.0.0", reach["note"])
        self.assertEqual(counts["imported"], 1)

    def test_unreachable_package_with_usable_graph_is_not_imported(self):
        doc = findings_doc([
            finding("pkg:npm/unused-pkg@1.0.0", bom_ref="ref-unused"),
        ])
        doc, _ = self.classify(doc, {
            "src/app.js": "import wrap from 'demo-wrapper';\n",
        }, sbom=NPM_GRAPH_SBOM)
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "not-imported")
        self.assertIn("not a runtime safety claim", reach["note"])

    def test_graph_unusable_forces_unknown(self):
        doc = findings_doc([
            finding("pkg:npm/unused-pkg@1.0.0", bom_ref="ref-unused"),
        ])
        doc, _ = self.classify(doc, {
            "src/app.js": "import wrap from 'demo-wrapper';\n",
        }, sbom=None)
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "unknown")
        self.assertIn("no dependency-graph edges available for npm",
                      reach["note"])


class UncertaintyTriggerTests(ReachabilityTestBase):
    def test_dynamic_import_variable_forces_unknown(self):
        doc = findings_doc([
            finding("pkg:npm/unused-pkg@1.0.0", bom_ref="ref-unused"),
        ])
        doc, _ = self.classify(doc, {
            "src/app.js": "import wrap from 'demo-wrapper';\n",
            "src/lazy.js": "const mod = await import(moduleName);\n",
        }, sbom=NPM_GRAPH_SBOM)
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "unknown")
        self.assertIn("non-literal dynamic import/require present (src/lazy.js)",
                      reach["note"])

    def test_dynamic_trigger_does_not_block_positive_verdicts(self):
        doc = findings_doc([
            finding("pkg:npm/lodash@4.17.20", bom_ref="ref-lodash"),
        ])
        doc, _ = self.classify(doc, {
            "src/app.js": "import lodash from 'lodash';\n",
            "src/lazy.js": "const mod = await import(moduleName);\n",
        }, sbom=NPM_GRAPH_SBOM)
        self.assertEqual(doc["findings"][0]["reachability"]["level"],
                         "imported")

    def test_python_unmapped_module_forces_unknown(self):
        doc = findings_doc([
            finding("pkg:pypi/cryptography@42.0.4",
                    bom_ref="ref-crypto"),
        ])
        doc, _ = self.classify(doc, {
            "src/app.py": ("import flask\n"
                           "import zzz_mystery\n"),
        }, sbom=PY_GRAPH_SBOM)
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "unknown")
        self.assertIn("unmapped Python import 'zzz_mystery'", reach["note"])

    def test_python_literal_dynamic_import_unmapped_module_forces_unknown(self):
        # Kilocode PR #26 review (WARNING): a literal dynamic import of
        # an unmapped module is an unresolvable specifier too — it must
        # force `unknown` on negative verdicts, exactly like a static
        # unmapped import.
        doc = findings_doc([
            finding("pkg:pypi/cryptography@42.0.4",
                    bom_ref="ref-crypto"),
        ])
        doc, _ = self.classify(doc, {
            "src/app.py": ("import importlib\n"
                           "import flask\n"
                           "mod = importlib.import_module('zzz_mystery')\n"),
        }, sbom=PY_GRAPH_SBOM)
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "unknown")
        self.assertIn("unmapped Python import 'zzz_mystery'", reach["note"])

    def test_python_literal_dynamic_mapped_module_does_not_force_unknown(self):
        # Companion to the test above: a literal dynamic import of a
        # module that maps to a known distribution (yaml -> PyYAML) is
        # positive evidence, not an uncertainty trigger — with a usable
        # graph and no import reference, the verdict stays not-imported.
        doc = findings_doc([
            finding("pkg:pypi/cryptography@42.0.4",
                    bom_ref="ref-crypto"),
        ])
        doc, _ = self.classify(doc, {
            "src/app.py": ("import importlib\n"
                           "import flask\n"
                           "mod = importlib.import_module('yaml')\n"),
        }, sbom=PY_GRAPH_SBOM)
        self.assertEqual(doc["findings"][0]["reachability"]["level"],
                         "not-imported")

    def test_python_stdlib_unavailable_degrades_fail_secure(self):
        # Kilocode PR #26 review (SUGGESTION): sys.stdlib_module_names
        # needs Python 3.10+. On older interpreters PY_STDLIB is empty,
        # so stdlib imports are reported as unmapped — the degradation
        # is fail-secure (more unknowns, never fewer).
        doc = findings_doc([
            finding("pkg:pypi/cryptography@42.0.4",
                    bom_ref="ref-crypto"),
        ])
        real_stdlib = annotate_mod.PY_STDLIB
        annotate_mod.PY_STDLIB = frozenset()
        try:
            doc, _ = self.classify(doc, {
                "src/app.py": ("import os\n"
                               "import flask\n"),
            }, sbom=PY_GRAPH_SBOM)
        finally:
            annotate_mod.PY_STDLIB = real_stdlib
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "unknown")
        self.assertIn("unmapped Python import 'os'", reach["note"])

    def test_python_unparseable_file_forces_unknown(self):
        doc = findings_doc([
            finding("pkg:pypi/cryptography@42.0.4",
                    bom_ref="ref-crypto"),
        ])
        doc, _ = self.classify(doc, {
            "src/app.py": "import flask\n",
            "src/broken.py": "def f(:\n",
        }, sbom=PY_GRAPH_SBOM)
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "unknown")
        self.assertIn("unparseable Python source file (src/broken.py)",
                      reach["note"])

    def test_python_importlib_variable_forces_unknown(self):
        doc = findings_doc([
            finding("pkg:pypi/cryptography@42.0.4",
                    bom_ref="ref-crypto"),
        ])
        doc, _ = self.classify(doc, {
            "src/app.py": ("import importlib\n"
                           "import flask\n"
                           "mod = importlib.import_module(name)\n"),
        }, sbom=PY_GRAPH_SBOM)
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "unknown")
        self.assertIn("non-literal importlib.import_module/__import__",
                      reach["note"])

    def test_no_source_files_degrades_to_unknown(self):
        doc = findings_doc([finding("pkg:npm/lodash@4.17.20")])
        doc, _ = self.classify(doc, {}, sbom=NPM_GRAPH_SBOM)
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "unknown")
        self.assertIn("no source files found", reach["note"])


class SchemaAndPolicyTests(ReachabilityTestBase):
    def test_annotation_only_nothing_else_changes(self):
        doc = findings_doc([
            finding("pkg:npm/lodash@4.17.20", bom_ref="ref-lodash",
                    vulns=[vuln("CVE-2024-0001", epss={"score": 0.5,
                             "percentile": 0.9, "date": "2026-10-22"}),
                           vuln("CVE-2024-0002")]),
            finding("pkg:npm/unused-pkg@1.0.0", bom_ref="ref-unused"),
        ])
        before = copy.deepcopy(doc)
        doc, counts = self.classify(doc, {
            "src/app.js": "import lodash from 'lodash';\n",
        }, sbom=NPM_GRAPH_SBOM)
        self.assertEqual(counts["imported"], 1)
        self.assertEqual(counts["not-imported"], 1)
        self.assertEqual(counts["unknown"], 0)
        after_stripped = copy.deepcopy(doc)
        for entry in after_stripped["findings"]:
            entry.pop("reachability", None)
        self.assertEqual(after_stripped, before)
        for entry in doc["findings"]:
            reach = entry["reachability"]
            self.assertIn(reach["level"], annotate_mod.LEVELS)
            self.assertIsInstance(reach["evidence"], list)
            self.assertEqual(reach["evidence"],
                             sorted(reach["evidence"]))
            self.assertTrue(reach["note"])

    def test_unsupported_ecosystem_is_unknown(self):
        doc = findings_doc([finding("pkg:golang/golang.org/x/net@0.1.0")])
        doc, _ = self.classify(doc, {"src/app.py": "import os\n"})
        reach = doc["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "unknown")
        self.assertIn("not covered by reachability v0", reach["note"])

    def test_kev_note_and_summary_prominence(self):
        doc = findings_doc([
            finding("pkg:npm/lodash@4.17.20", bom_ref="ref-lodash",
                    vulns=[vuln("CVE-2024-0001",
                                kev={"knownExploited": True,
                                     "dueDate": "2026-10-24",
                                     "added": "2026-10-22"})]),
        ])
        doc, _ = self.classify(doc, {
            "src/app.js": "import lodash from 'lodash';\n",
        }, sbom=NPM_GRAPH_SBOM)
        reach = doc["findings"][0]["reachability"]
        self.assertTrue(reach["note"].endswith(
            annotate_mod.KEV_NOTE_SUFFIX))

        summary_path = os.path.join(self.dir, "summary.md")
        os.environ["GITHUB_STEP_SUMMARY"] = summary_path
        try:
            annotate_mod.write_step_summary(doc, {"imported": 1})
            with open(summary_path, encoding="utf-8") as f:
                content = f.read()
        finally:
            del os.environ["GITHUB_STEP_SUMMARY"]
        self.assertIn("## Reachability (import-level, v0)", content)
        self.assertIn("⚠️ KEV", content)
        self.assertIn("Annotates only", content)
        # The KEV data row must come after the table separator and be the
        # first data row (KEV findings surface first, whatever the level).
        separator_index = content.index("| --- | --- | --- | --- |\n")
        kev_row_index = content.index("| ⚠️ KEV | imported |")
        self.assertLess(separator_index, kev_row_index)
        first_data_row = content[separator_index + len(
            "| --- | --- | --- | --- |\n"):].lstrip()
        self.assertTrue(first_data_row.startswith("| ⚠️ KEV |"),
                        msg=first_data_row[:80])

    def test_determinism_byte_identical_output(self):
        doc1 = findings_doc([finding("pkg:npm/lodash@4.17.20",
                                     bom_ref="ref-lodash")])
        doc2 = copy.deepcopy(doc1)
        tree = {"src/app.js": "import lodash from 'lodash';\n"}
        doc1, _ = self.classify(doc1, tree, sbom=NPM_GRAPH_SBOM)
        doc2, _ = self.classify(doc2, tree, sbom=NPM_GRAPH_SBOM)
        self.assertEqual(json.dumps(doc1, indent=2, sort_keys=True),
                         json.dumps(doc2, indent=2, sort_keys=True))


class MainEndToEndTests(ReachabilityTestBase):
    ENV_KEYS = ("INPUT_FINDINGS_FILE", "INPUT_SBOM_FILE",
                "INPUT_SOURCE_PATH", "GITHUB_OUTPUT",
                "GITHUB_STEP_SUMMARY")

    def run_main(self, doc, tree_files, sbom=None):
        findings_path = os.path.join(self.dir, "vulnerabilities.json")
        with open(findings_path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        sbom_path = None
        if sbom is not None:
            sbom_path = os.path.join(self.dir, "sbom.cdx.json")
            with open(sbom_path, "w", encoding="utf-8") as f:
                json.dump(sbom, f)
        output_path = os.path.join(self.dir, "github_output.txt")
        summary_path = os.path.join(self.dir, "summary.md")
        self.write_tree(tree_files)
        saved = {k: os.environ.get(k) for k in self.ENV_KEYS}
        os.environ["INPUT_FINDINGS_FILE"] = findings_path
        os.environ["INPUT_SBOM_FILE"] = sbom_path or ""
        os.environ["INPUT_SOURCE_PATH"] = self.dir
        os.environ["GITHUB_OUTPUT"] = output_path
        os.environ["GITHUB_STEP_SUMMARY"] = summary_path
        try:
            rc = annotate_mod.main()
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        with open(findings_path, encoding="utf-8") as f:
            annotated = json.load(f)
        with open(output_path, encoding="utf-8") as f:
            outputs = f.read()
        return rc, annotated, outputs, summary_path

    def test_main_annotates_and_writes_outputs(self):
        doc = findings_doc([
            finding("pkg:npm/victim-pkg@2.0.0", bom_ref="ref-victim"),
        ])
        rc, annotated, outputs, _ = self.run_main(doc, {
            "src/app.js": "import wrap from 'demo-wrapper';\n",
        }, sbom=NPM_GRAPH_SBOM)
        self.assertEqual(rc, 0)
        reach = annotated["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "imported")
        self.assertIn("reachability-imported-count=1", outputs)
        self.assertIn("reachability-not-imported-count=0", outputs)
        self.assertIn("reachability-unknown-count=0", outputs)

    def test_main_missing_findings_file_fails_loudly(self):
        os.environ["INPUT_FINDINGS_FILE"] = os.path.join(self.dir,
                                                        "missing.json")
        self.addCleanup(os.environ.pop, "INPUT_FINDINGS_FILE", None)
        self.assertEqual(annotate_mod.main(), 1)

    def test_main_fail_open_on_unexpected_failure(self):
        doc = findings_doc([
            finding("pkg:npm/lodash@4.17.20", bom_ref="ref-lodash"),
        ])
        real_scan_source = annotate_mod.scan_source
        annotate_mod.scan_source = lambda path: (_ for _ in ()).throw(
            RuntimeError("boom"))
        try:
            rc, annotated, outputs, _ = self.run_main(doc, {})
        finally:
            annotate_mod.scan_source = real_scan_source
        self.assertEqual(rc, 0)
        reach = annotated["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "unknown")
        self.assertIn("reachability assessment failed", reach["note"])
        self.assertIn("reachability-unknown-count=1", outputs)

    def test_main_fail_open_when_summary_unwritable(self):
        # Kilocode PR #26 review (SUGGESTION): output writing must be
        # inside the fail-open envelope — a failure in write_outputs /
        # write_step_summary warns and exits 0, and the annotated
        # findings (already written atomically) are not lost.
        doc = findings_doc([
            finding("pkg:npm/victim-pkg@2.0.0", bom_ref="ref-victim"),
        ])
        real_summary = annotate_mod.write_step_summary
        annotate_mod.write_step_summary = (
            lambda doc, counts: (_ for _ in ()).throw(
                OSError("read-only file system")))
        try:
            rc, annotated, outputs, _ = self.run_main(doc, {
                "src/app.js": "import wrap from 'demo-wrapper';\n",
            }, sbom=NPM_GRAPH_SBOM)
        finally:
            annotate_mod.write_step_summary = real_summary
        self.assertEqual(rc, 0)
        reach = annotated["findings"][0]["reachability"]
        self.assertEqual(reach["level"], "imported")
        self.assertIn("reachability-imported-count=1", outputs)

    def test_main_atomic_write_leaves_findings_uncorrupted_on_failure(self):
        # The annotated findings are written via temp + atomic os.replace:
        # if the replace fails, the original findings file stays valid
        # JSON (no truncated file for the SARIF step to choke on), the
        # temp file is cleaned up, and the step still exits 0.
        doc = findings_doc([
            finding("pkg:npm/victim-pkg@2.0.0", bom_ref="ref-victim"),
        ])
        findings_path = os.path.join(self.dir, "vulnerabilities.json")
        with open(findings_path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        output_path = os.path.join(self.dir, "github_output.txt")
        summary_path = os.path.join(self.dir, "summary.md")
        saved = {k: os.environ.get(k)
                 for k in ("INPUT_FINDINGS_FILE", "INPUT_SBOM_FILE",
                           "INPUT_SOURCE_PATH", "GITHUB_OUTPUT",
                           "GITHUB_STEP_SUMMARY")}
        os.environ["INPUT_FINDINGS_FILE"] = findings_path
        os.environ["INPUT_SBOM_FILE"] = ""
        os.environ["INPUT_SOURCE_PATH"] = self.dir
        os.environ["GITHUB_OUTPUT"] = output_path
        os.environ["GITHUB_STEP_SUMMARY"] = summary_path
        real_replace = annotate_mod.os.replace
        annotate_mod.os.replace = (
            lambda a, b: (_ for _ in ()).throw(OSError("replace failed")))
        try:
            rc = annotate_mod.main()
        finally:
            annotate_mod.os.replace = real_replace
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(rc, 0)
        with open(findings_path, encoding="utf-8") as f:
            unannotated = json.load(f)
        self.assertNotIn("reachability",
                         unannotated["findings"][0])
        self.assertFalse(
            os.path.exists(findings_path + ".tmp-reachability"))


class PurlParsingTests(unittest.TestCase):
    def test_parse_purl_cases(self):
        self.assertEqual(
            annotate_mod.parse_purl("pkg:npm/lodash@4.17.20"),
            ("npm", "lodash"))
        self.assertEqual(
            annotate_mod.parse_purl("pkg:npm/%40scope/pkg@1.0.0"),
            ("npm", "@scope/pkg"))
        self.assertEqual(
            annotate_mod.parse_purl("pkg:npm/%40scope/pkg@1.0.0?vcs_url=x"),
            ("npm", "@scope/pkg"))
        self.assertEqual(
            annotate_mod.parse_purl("pkg:pypi/requests@2.31.0"),
            ("pypi", "requests"))
        self.assertIsNone(annotate_mod.parse_purl("not-a-purl"))
        self.assertIsNone(annotate_mod.parse_purl(None))
        self.assertIsNone(annotate_mod.parse_purl("pkg:npm/"))

    def test_pep503_normalize(self):
        self.assertEqual(annotate_mod.pep503_normalize("Flask"), "flask")
        self.assertEqual(annotate_mod.pep503_normalize("python_dateutil"),
                         "python-dateutil")

    def test_frozen_level_vocabulary(self):
        self.assertEqual(annotate_mod.LEVELS,
                         ("imported", "not-imported", "unknown"))


if __name__ == "__main__":
    unittest.main()
