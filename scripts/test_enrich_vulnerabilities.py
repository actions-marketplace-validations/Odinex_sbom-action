#!/usr/bin/env python3
"""Fixture tests for enrich-vulnerabilities.py — locks down the enriched
JSON contract: epss null for CVE-less groups, kev false when the feed was
fetched, kev null when it was not, EPSS threshold on the 0-1 scale, and
the http_get retry policy (retryable statuses only).

Run: python3 sbom-action/scripts/test_enrich_vulnerabilities.py
"""

import importlib.util
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "enrich-vulnerabilities.py")
spec = importlib.util.spec_from_file_location("enrich_vulnerabilities", SCRIPT)
enrich_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enrich_mod)


def vuln(vuln_id, **extra):
    base = {"id": vuln_id, "osvIds": [], "aliases": [],
            "epss": None, "kev": None}
    base.update(extra)
    return base


def findings_doc(vulns_list):
    return {"findings": [{"component": {"purl": "pkg:x/y@1.0"},
                          "vulnerabilities": vulns_list}]}


EPSS_A = {"score": 0.97, "percentile": 0.9994, "date": "2026-10-16"}
EPSS_B = {"score": 0.0098, "percentile": 0.61531, "date": "2026-10-16"}
KEV_A = {"knownExploited": True, "dueDate": "2026-10-19",
         "added": "2026-10-16"}


class EnrichContractTests(unittest.TestCase):
    def test_kev_false_when_feed_fetched(self):
        doc = findings_doc([vuln("CVE-2024-47081")])
        kev_count, high = enrich_mod.enrich(
            doc, {"CVE-2024-47081": EPSS_B}, {}, kev_ok=True)
        v = doc["findings"][0]["vulnerabilities"][0]
        self.assertEqual(v["epss"], EPSS_B)
        self.assertEqual(v["kev"], {"knownExploited": False})
        self.assertEqual((kev_count, high), (0, 0))

    def test_kev_null_when_feed_unreachable(self):
        doc = findings_doc([vuln("CVE-2024-47081")])
        enrich_mod.enrich(doc, {"CVE-2024-47081": EPSS_B}, {}, kev_ok=False)
        v = doc["findings"][0]["vulnerabilities"][0]
        self.assertIsNotNone(v["epss"])
        self.assertIsNone(v["kev"])

    def test_no_cve_group_keeps_epss_null_kev_false(self):
        doc = findings_doc([vuln("GHSA-abc", osvIds=["GHSA-abc"])])
        enrich_mod.enrich(doc, {}, {"CVE-2024-47081": KEV_A}, kev_ok=True)
        v = doc["findings"][0]["vulnerabilities"][0]
        self.assertIsNone(v["epss"])
        self.assertEqual(v["kev"], {"knownExploited": False})

    def test_kev_match_and_high_epss_threshold(self):
        doc = findings_doc([vuln("CVE-2020-1472")])
        kev_count, high = enrich_mod.enrich(
            doc, {"CVE-2020-1472": EPSS_A}, {"CVE-2020-1472": KEV_A},
            kev_ok=True)
        v = doc["findings"][0]["vulnerabilities"][0]
        self.assertEqual(v["kev"], KEV_A)
        self.assertEqual((kev_count, high), (1, 1))

    def test_threshold_is_0_90_scale_not_90(self):
        self.assertEqual(enrich_mod.HIGH_EPSS_PERCENTILE, 0.90)
        doc = findings_doc([vuln("CVE-2024-47081")])
        _, high = enrich_mod.enrich(
            doc, {"CVE-2024-47081": {"score": 0.5, "percentile": 0.95,
                                     "date": "d"}}, {}, kev_ok=True)
        self.assertEqual(high, 1)

    def test_resolve_cve(self):
        self.assertEqual(enrich_mod.resolve_cve(vuln("CVE-2024-47081")),
                         "CVE-2024-47081")
        self.assertIsNone(enrich_mod.resolve_cve(
            vuln("GHSA-abc", osvIds=["GHSA-abc"],
                 aliases=["PYSEC-2026-1"])))

    def test_non_string_id_is_not_a_cve_and_does_not_crash_enrichment(self):
        doc = findings_doc([vuln(12345), vuln("CVE-2024-47081")])
        self.assertIsNone(enrich_mod.resolve_cve(vuln(12345)))
        kev_count, high = enrich_mod.enrich(
            doc, {"CVE-2024-47081": EPSS_A}, {}, kev_ok=True)
        self.assertEqual((kev_count, high), (0, 1))
        self.assertIsNone(doc["findings"][0]["vulnerabilities"][0]["epss"])


class HttpGetRetryTests(unittest.TestCase):
    def test_permanent_404_fails_immediately(self):
        calls = []

        class Resp:
            def __init__(self, code):
                self.status = code

            def read(self):
                return b"{}"

        def fake_urlopen(req, timeout=None):
            calls.append(req.full_url)
            raise urllib.error.HTTPError(
                req.full_url, 404, "Not Found", {}, None)

        real_urlopen = urllib.request.urlopen
        urllib.request.urlopen = fake_urlopen
        real_sleep = enrich_mod.time.sleep
        enrich_mod.time.sleep = lambda s: (_ for _ in ()).throw(
            AssertionError("404 must not be retried"))
        try:
            self.assertIsNone(enrich_mod.http_get("https://x/404", 5))
            self.assertEqual(len(calls), 1)
        finally:
            urllib.request.urlopen = real_urlopen
            enrich_mod.time.sleep = real_sleep

    def test_retryable_503_retries_then_succeeds(self):
        attempts = []

        class Resp:
            status = 200

            def read(self):
                return b'{"data": []}'

        class Ctx:
            def __enter__(self):
                return Resp()

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=None):
            attempts.append(1)
            if len(attempts) < 3:
                raise urllib.error.HTTPError(
                    req.full_url, 503, "Unavailable", {}, None)
            return Ctx()

        real_urlopen = urllib.request.urlopen
        real_sleep = enrich_mod.time.sleep
        urllib.request.urlopen = fake_urlopen
        enrich_mod.time.sleep = lambda s: None
        try:
            self.assertEqual(enrich_mod.http_get("https://x/ok", 5), {"data": []})
            self.assertEqual(len(attempts), 3)
        finally:
            urllib.request.urlopen = real_urlopen
            enrich_mod.time.sleep = real_sleep


if __name__ == "__main__":
    unittest.main()
