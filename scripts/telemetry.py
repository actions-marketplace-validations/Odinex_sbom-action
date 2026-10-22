#!/usr/bin/env python3
"""Anonymous opt-out usage telemetry for the SBOM GitHub Action.

Sends one schema-v1 "run" event per workflow run to the project's telemetry
collector, so repeat use can be measured (the success gate metric: a repo
hash with at least 2 runs per ISO week, sustained over 4 consecutive weeks).
Fail-open by design: telemetry can never fail a build.

Contract:
- Env vars in:
    GITHUB_ACTIONS           must be 'true' or the script is a no-op
    GITHUB_REPOSITORY        'owner/repo' (default GitHub runner env var)
    DO_NOT_TRACK             set to any truthy value to skip silently
    INPUT_TELEMETRY_URL      collector base URL
                             (default https://telemetry.databoast.com)
    INPUT_COMPONENTS_COUNT   library components in the SBOM
    INPUT_FINDINGS_COUNT     unique vulnerabilities matched
    INPUT_KEV_COUNT          findings listed in the CISA KEV catalog
    INPUT_LOCKFILES_FOUND    comma-separated lockfile types (CSV)
    INPUT_SCAN_STATUS        'complete' or anything else -> 'partial'
- Out: one HTTP POST to <base>/api/v1/events; single attempt, 2 s timeout,
  no retries. Exit code is always 0; problems print ::warning:: only.

Privacy: the event carries the run counts and the detected lockfile types —
no source code, no file paths, no CI metadata, no IPs. The repository is
represented by repoHash = SHA-256(SALT + ':' + GITHUB_REPOSITORY). The salt
is published here on purpose: a salted hash is pseudonymous, not anonymous —
anyone who knows a repo name and this salt can compute its hash. That is the
documented trade-off (runbook section 9, data inventory).

The event schema is frozen at v1 on the server (unknown fields rejected,
4 KiB body cap); the client mirrors both limits defensively.
"""

import datetime
import hashlib
import json
import os
import urllib.request

SALT = "odinex-sbom-telemetry-v1"
DEFAULT_TELEMETRY_URL = "https://telemetry.databoast.com"
KNOWN_LOCKFILE_TYPES = ("npm", "yarn", "pnpm", "bun", "poetry", "pipenv", "pip")
MAX_LOCKFILE_TYPES = 8
TIMEOUT_SECONDS = 2
MAX_PAYLOAD_BYTES = 4096


def log(message):
    print(f"[telemetry] {message}")


def warn(message):
    print(f"::warning::{message}")


def is_truthy(value):
    """Return True for values that count as 'set' for DO_NOT_TRACK.
    None (unset) and empty/falsey strings count as not set."""
    if value is None:
        return False
    return str(value).strip().lower() not in ("", "0", "false", "no")


def repo_hash(repository):
    """Return the salted SHA-256 pseudonym for an 'owner/repo' string."""
    material = f"{SALT}:{repository}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def lockfile_types(csv):
    """Normalize the lockfile CSV: strip, lowercase, dedupe (first-seen
    order), drop unknown types, cap at MAX_LOCKFILE_TYPES."""
    seen = []
    for token in str(csv or "").split(","):
        name = token.strip().lower()
        if name and name in KNOWN_LOCKFILE_TYPES and name not in seen:
            seen.append(name)
    return seen[:MAX_LOCKFILE_TYPES]


def parse_count(value):
    """Parse a count from a step-output string; anything invalid or negative
    becomes 0 (fail-open: a missing step output must not crash the step)."""
    try:
        count = int(str(value).strip())
    except (TypeError, ValueError):
        return 0
    return count if count >= 0 else 0


def utc_timestamp():
    """Return the current UTC time as an RFC 3339 'Z' string."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_event(repository, components_count, findings_count, kev_count,
                lockfiles_csv, scan_status):
    """Build the schema-v1 event dict (exact field set, server rejects
    unknown fields)."""
    return {
        "schemaVersion": 1,
        "eventType": "run",
        "repoHash": repo_hash(repository),
        "componentsCount": parse_count(components_count),
        "findingsCount": parse_count(findings_count),
        "kevCount": parse_count(kev_count),
        "lockfileTypes": lockfile_types(lockfiles_csv),
        "scanStatus": "complete" if str(scan_status).strip() == "complete" else "partial",
        "ts": utc_timestamp(),
    }


def send_event(base_url, event):
    """POST one event to the collector. Single attempt, TIMEOUT_SECONDS
    timeout, no retries. Returns True on any 2xx, False otherwise; never
    raises."""
    body = json.dumps(event).encode("utf-8")
    if len(body) > MAX_PAYLOAD_BYTES:
        warn(f"telemetry payload is {len(body)} bytes (cap {MAX_PAYLOAD_BYTES}) — not sent")
        return False
    endpoint = str(base_url).rstrip("/") + "/api/v1/events"
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return 200 <= response.status < 300
    except Exception as exc:  # fail-open: any failure is a warning, not an error
        warn(f"telemetry send failed: {exc}")
        return False


def main():
    """Entry point. Always returns 0 — telemetry must never fail the build."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        log("not running inside GitHub Actions — telemetry skipped")
        return 0
    if is_truthy(os.environ.get("DO_NOT_TRACK")):
        log("DO_NOT_TRACK is set — telemetry skipped")
        return 0
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not repository:
        warn("GITHUB_REPOSITORY is not set — telemetry skipped")
        return 0
    event = build_event(
        repository,
        os.environ.get("INPUT_COMPONENTS_COUNT", ""),
        os.environ.get("INPUT_FINDINGS_COUNT", ""),
        os.environ.get("INPUT_KEV_COUNT", ""),
        os.environ.get("INPUT_LOCKFILES_FOUND", ""),
        os.environ.get("INPUT_SCAN_STATUS", ""),
    )
    base_url = os.environ.get("INPUT_TELEMETRY_URL", "").strip() or DEFAULT_TELEMETRY_URL
    if send_event(base_url, event):
        log("usage telemetry reported")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
