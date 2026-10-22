#!/usr/bin/env python3
"""Fixture tests for the telemetry client contract. No network.

Locked-down contract:
- repoHash: SHA-256(salt + ':' + repo), 64 lowercase hex, deterministic,
  salt-dependent (differs from the unsalted hash), repo-dependent.
- lockfile_types: CSV -> dedupe (first-seen order), lowercase, unknown
  types dropped, hard cap of 8.
- build_event: exactly the 9 schema-v1 fields (server rejects unknown
  fields); counts parsed from strings, invalid or negative -> 0;
  scanStatus only ever 'complete' or 'partial'; ts is RFC 3339 UTC 'Z'.
- send_event: single POST to <base>/api/v1/events, Content-Type JSON,
  2 s timeout, 2xx -> True, anything else -> False, never raises.
- main: no-op outside GitHub Actions; no-op when DO_NOT_TRACK is truthy;
  exit code always 0 (fail-open), including on send failure.
- Payload: the serialized event stays under the server's 4 KiB cap.
"""

import hashlib
import importlib.util
import json
import os
import re
import unittest
import urllib.request

SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "telemetry.py")
_spec = importlib.util.spec_from_file_location("telemetry", SCRIPT_PATH)
telemetry = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(telemetry)

ENV_KEYS = (
    "GITHUB_ACTIONS",
    "GITHUB_REPOSITORY",
    "DO_NOT_TRACK",
    "INPUT_TELEMETRY_URL",
    "INPUT_COMPONENTS_COUNT",
    "INPUT_FINDINGS_COUNT",
    "INPUT_KEV_COUNT",
    "INPUT_LOCKFILES_FOUND",
    "INPUT_SCAN_STATUS",
)

REPO_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class FakeResponse:
    def __init__(self, status=204):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeUrlopen:
    """Records the call and replays a canned result without any network."""

    def __init__(self, result):
        self.result = result  # FakeResponse, Exception, or callable
        self.calls = []

    def __call__(self, request, timeout=None):
        self.calls.append({"request": request, "timeout": timeout})
        if isinstance(self.result, Exception):
            raise self.result
        if callable(self.result):
            return self.result(self.calls[-1])
        return self.result


class TelemetryTestCase(unittest.TestCase):
    """Common fixtures: isolated env, mocked urlopen, restored on cleanup."""

    def setUp(self):
        saved_env = {key: os.environ.get(key) for key in ENV_KEYS}
        for key in ENV_KEYS:
            os.environ.pop(key, None)

        def restore_env():
            for key, value in saved_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        self.addCleanup(restore_env)

        original_urlopen = urllib.request.urlopen
        self.addCleanup(setattr, urllib.request, "urlopen", original_urlopen)

    def install_urlopen(self, result):
        fake = FakeUrlopen(result)
        urllib.request.urlopen = fake
        return fake


class TestRepoHash(TelemetryTestCase):
    def test_hex_shape_and_deterministic(self):
        first = telemetry.repo_hash("octocat/example")
        self.assertRegex(first, REPO_HASH_RE)
        self.assertEqual(first, telemetry.repo_hash("octocat/example"))

    def test_salt_depends(self):
        repo = "octocat/example"
        unsalted = hashlib.sha256(repo.encode("utf-8")).hexdigest()
        self.assertNotEqual(telemetry.repo_hash(repo), unsalted)

    def test_repo_depends(self):
        self.assertNotEqual(
            telemetry.repo_hash("octocat/example"),
            telemetry.repo_hash("octocat/other"),
        )


class TestLockfileTypes(TelemetryTestCase):
    def test_dedupe_preserves_first_seen_order(self):
        self.assertEqual(
            telemetry.lockfile_types("npm,pip,npm,bun"),
            ["npm", "pip", "bun"],
        )

    def test_unknown_and_noise_dropped(self):
        self.assertEqual(
            telemetry.lockfile_types("npm, cargo, , PIP,notalockfile"),
            ["npm", "pip"],
        )

    def test_empty_and_none(self):
        self.assertEqual(telemetry.lockfile_types(""), [])
        self.assertEqual(telemetry.lockfile_types(None), [])

    def test_cap_at_eight(self):
        # 8 known types exist; feed 5 known types cycled to exceed the cap
        csv = ",".join(["npm", "yarn", "pnpm", "bun", "poetry", "pipenv", "pip"] * 3)
        self.assertEqual(
            telemetry.lockfile_types(csv),
            ["npm", "yarn", "pnpm", "bun", "poetry", "pipenv", "pip"],
        )  # only 7 distinct known types -> all kept, order deduped

    def test_max_lockfile_types_constant(self):
        self.assertEqual(telemetry.MAX_LOCKFILE_TYPES, 8)


class TestBuildEvent(TelemetryTestCase):
    def event(self, **overrides):
        base = dict(
            repository="octocat/example",
            components_count="150",
            findings_count="7",
            kev_count="1",
            lockfiles_csv="npm,pip",
            scan_status="complete",
        )
        base.update(overrides)
        return telemetry.build_event(**base)

    def test_exact_field_set(self):
        self.assertEqual(
            set(self.event().keys()),
            {
                "schemaVersion",
                "eventType",
                "repoHash",
                "componentsCount",
                "findingsCount",
                "kevCount",
                "lockfileTypes",
                "scanStatus",
                "ts",
            },
        )

    def test_values(self):
        event = self.event()
        self.assertEqual(event["schemaVersion"], 1)
        self.assertEqual(event["eventType"], "run")
        self.assertEqual(event["repoHash"], telemetry.repo_hash("octocat/example"))
        self.assertEqual(event["componentsCount"], 150)
        self.assertEqual(event["findingsCount"], 7)
        self.assertEqual(event["kevCount"], 1)
        self.assertEqual(event["lockfileTypes"], ["npm", "pip"])
        self.assertEqual(event["scanStatus"], "complete")
        self.assertRegex(event["ts"], TS_RE)

    def test_invalid_counts_become_zero(self):
        event = self.event(components_count="not-a-number", findings_count="", kev_count="-3")
        self.assertEqual(event["componentsCount"], 0)
        self.assertEqual(event["findingsCount"], 0)
        self.assertEqual(event["kevCount"], 0)

    def test_scan_status_only_complete_or_partial(self):
        self.assertEqual(self.event(scan_status="complete")["scanStatus"], "complete")
        self.assertEqual(self.event(scan_status="partial")["scanStatus"], "partial")
        self.assertEqual(self.event(scan_status="")["scanStatus"], "partial")
        self.assertEqual(self.event(scan_status="COMPLETE")["scanStatus"], "partial")
        self.assertEqual(self.event(scan_status="garbage")["scanStatus"], "partial")

    def test_lockfile_types_normalized(self):
        event = self.event(lockfiles_csv="npm,cargo,npm")
        self.assertEqual(event["lockfileTypes"], ["npm"])

    def test_payload_under_server_cap(self):
        # Worst case: 8 lockfile types, long repo name, big counts
        event = telemetry.build_event(
            "a-very-long-organization-name/an-extremely-long-repository-name-with-many-characters",
            "999999999", "999999999", "999999999",
            ",".join(telemetry.KNOWN_LOCKFILE_TYPES),
            "complete",
        )
        self.assertLess(len(json.dumps(event).encode("utf-8")), telemetry.MAX_PAYLOAD_BYTES)


class TestSendEvent(TelemetryTestCase):
    def send(self, result, base_url="https://telemetry.example"):
        fake = self.install_urlopen(result)
        event = telemetry.build_event(
            "octocat/example", "10", "2", "0", "npm", "complete"
        )
        ok = telemetry.send_event(base_url, event)
        return fake, ok

    def test_url_method_headers_and_timeout(self):
        fake, ok = self.send(FakeResponse(204))
        self.assertTrue(ok)
        self.assertEqual(len(fake.calls), 1)
        request = fake.calls[0]["request"]
        self.assertEqual(request.full_url, "https://telemetry.example/api/v1/events")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.headers.get("Content-type"), "application/json")
        self.assertEqual(fake.calls[0]["timeout"], telemetry.TIMEOUT_SECONDS)
        self.assertEqual(fake.calls[0]["timeout"], 2)

    def test_base_url_trailing_slash_normalized(self):
        fake, _ = self.send(FakeResponse(204), base_url="https://telemetry.example/")
        self.assertEqual(
            fake.calls[0]["request"].full_url,
            "https://telemetry.example/api/v1/events",
        )

    def test_other_2xx_accepted(self):
        _, ok = self.send(FakeResponse(200))
        self.assertTrue(ok)

    def test_non_2xx_rejected(self):
        _, ok = self.send(FakeResponse(404))
        self.assertFalse(ok)
        _, ok = self.send(FakeResponse(500))
        self.assertFalse(ok)

    def test_exception_returns_false(self):
        _, ok = self.send(OSError("connection refused"))
        self.assertFalse(ok)

    def test_single_attempt_only(self):
        fake, _ = self.send(OSError("connection refused"))
        self.assertEqual(len(fake.calls), 1)  # no retries

    def test_payload_over_cap_not_sent(self):
        fake = self.install_urlopen(FakeResponse(204))
        event = telemetry.build_event("octocat/example", "1", "1", "0", "npm", "complete")
        original = telemetry.MAX_PAYLOAD_BYTES
        telemetry.MAX_PAYLOAD_BYTES = 1  # force the cap
        try:
            self.assertFalse(telemetry.send_event("https://telemetry.example", event))
            self.assertEqual(len(fake.calls), 0)
        finally:
            telemetry.MAX_PAYLOAD_BYTES = original


class TestMain(TelemetryTestCase):
    def run_main(self):
        return telemetry.main()

    def test_noop_outside_github_actions(self):
        os.environ["GITHUB_REPOSITORY"] = "octocat/example"
        fake = self.install_urlopen(FakeResponse(204))
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(fake.calls), 0)

    def test_noop_when_do_not_track_set(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        os.environ["GITHUB_REPOSITORY"] = "octocat/example"
        os.environ["DO_NOT_TRACK"] = "1"
        fake = self.install_urlopen(FakeResponse(204))
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(fake.calls), 0)

    def test_do_not_track_falsy_values_still_send(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        os.environ["GITHUB_REPOSITORY"] = "octocat/example"
        os.environ["DO_NOT_TRACK"] = "0"
        fake = self.install_urlopen(FakeResponse(204))
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(fake.calls), 1)

    def test_noop_without_repository(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        fake = self.install_urlopen(FakeResponse(204))
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(fake.calls), 0)

    def test_happy_path_sends_schema_v1_event(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        os.environ["GITHUB_REPOSITORY"] = "octocat/example"
        os.environ["INPUT_TELEMETRY_URL"] = "https://telemetry.example"
        os.environ["INPUT_COMPONENTS_COUNT"] = "150"
        os.environ["INPUT_FINDINGS_COUNT"] = "7"
        os.environ["INPUT_KEV_COUNT"] = "1"
        os.environ["INPUT_LOCKFILES_FOUND"] = "npm,pip"
        os.environ["INPUT_SCAN_STATUS"] = "complete"

        sent = {}

        def capture(call):
            sent["body"] = json.loads(call["request"].data.decode("utf-8"))
            return FakeResponse(204)

        fake = self.install_urlopen(capture)
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(sent["body"]["repoHash"], telemetry.repo_hash("octocat/example"))
        self.assertEqual(sent["body"]["schemaVersion"], 1)
        self.assertEqual(sent["body"]["lockfileTypes"], ["npm", "pip"])

    def test_fail_open_on_send_failure(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        os.environ["GITHUB_REPOSITORY"] = "octocat/example"
        self.install_urlopen(OSError("network down"))
        self.assertEqual(self.run_main(), 0)

    def test_default_url_used_when_input_empty(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        os.environ["GITHUB_REPOSITORY"] = "octocat/example"
        fake = self.install_urlopen(FakeResponse(204))
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(
            fake.calls[0]["request"].full_url,
            "https://telemetry.databoast.com/api/v1/events",
        )


class TestIsTruthy(TelemetryTestCase):
    def test_unset_is_false(self):
        # Regression: str(None) == "none" once counted as truthy, which
        # silently disabled telemetry for every run without DO_NOT_TRACK.
        self.assertFalse(telemetry.is_truthy(None))

    def test_truthy_values(self):
        for value in ("1", "true", "yes", "anything"):
            self.assertTrue(telemetry.is_truthy(value))

    def test_falsy_values(self):
        for value in ("", " ", "0", "false", "no", "False", "NO"):
            self.assertFalse(telemetry.is_truthy(value))


class TestServerSchemaAlignment(TelemetryTestCase):
    """The client must not be able to emit what the collector rejects."""

    def test_lockfile_types_subset_of_known(self):
        for name in telemetry.KNOWN_LOCKFILE_TYPES:
            self.assertIn(name, ("npm", "yarn", "pnpm", "bun", "poetry", "pipenv", "pip"))
        self.assertLessEqual(len(telemetry.KNOWN_LOCKFILE_TYPES), telemetry.MAX_LOCKFILE_TYPES)

    def test_salt_matches_documented_value(self):
        # Published in the README and runbook section 9; changing it breaks
        # the pseudonymization story, so it is pinned by the tests.
        self.assertEqual(telemetry.SALT, "odinex-sbom-telemetry-v1")


if __name__ == "__main__":
    unittest.main()
