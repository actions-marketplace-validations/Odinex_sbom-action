#!/usr/bin/env python3
"""findings-to-sarif.py — SARIF 2.1.0 conversion for GitHub code scanning.

Pipeline step 4 (SBOM → OSV match → enrich → SARIF). Reads the enriched
findings JSON and writes a SARIF 2.1.0 log that github/codeql-action/
upload-sarif@v3 uploads to the repository's Security tab.

Contract:
- Rule per canonical vulnerability: `id` = canonical key,
  `shortDescription` from the advisory summary, `properties` = epss,
  kev, osvIds, lockfile (first-seen; a vulnerability matched in several
  lockfiles keeps its precise per-finding lockfile in the *result*
  properties).
- Result per component finding: artifactLocation.uri = purl,
  `partialFingerprints` = sha256(purl + "|" + canonical key). The
  findings carry no source locations, so GitHub cannot compute its own
  line-based fingerprints — an explicit, stable fingerprint is required
  for dedup across runs (finding persists; upgrade fixed → disappears).
- Level mapping: `databaseSpecificSeverity` CRITICAL/HIGH → `error`,
  MODERATE/MEDIUM → `warning`, LOW/null → `note` (null is a valid
  severity in the findings JSON — PYSEC records often have none).
- The SARIF document is validated against the 2.1.0 schema requirements
  before it is written — fail loudly on invalid, never emit a broken
  log. Stdlib-only, so this is a structural validation of every 2.1.0
  requirement the emitted constructs must satisfy, not a full
  jsonschema pass.

Upload permission: code-scanning upload requires the *consumer* workflow
to grant `permissions: security-events: write`. The Action itself stays
read-only; the conditional upload step is the only part that needs the
grant, and `upload-sarif: 'false'` keeps the workflow at zero write
scope.

Environment (set by action.yml, or manually for local runs):
  INPUT_FINDINGS_FILE   path to the enriched findings JSON (default:
                        vulnerabilities.json)
  INPUT_SARIF_OUTPUT    path of the SARIF file to write (default:
                        findings.sarif)

Outputs via $GITHUB_OUTPUT:
  sarif-file, sarif-results

Requires only the Python 3 standard library.
"""

import hashlib
import json
import os
import sys

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/schemas/"
    "sarif-schema-2.1.0.json"
)
TOOL_NAME = "CycloneDX SBOM Generator"
TOOL_INFORMATION_URI = "https://github.com/Odinex/sbom-action"
FINGERPRINT_KEY = "sbomActionVuln/v1"
FINGERPRINT_SEPARATOR = "|"

# databaseSpecificSeverity (GHSA scale) → SARIF level.
# CRITICAL and HIGH both map to `error`: code scanning renders `error`
# red and fails any status checks configured on the severity; MODERATE
# and MEDIUM both map to `warning` (some databases use MEDIUM); LOW and
# null (a valid value — PYSEC records often lack it) map to `note`.
SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MODERATE": "warning",
    "MEDIUM": "warning",
    "LOW": "note",
}

VALID_LEVELS = {"none", "note", "warning", "error"}


def log(msg):
    print(f"[findings-to-sarif] {msg}")


def severity_to_level(severity):
    """Map `databaseSpecificSeverity` to a SARIF level.

    Unknown or null severity maps to `note` (never silently dropped, but
    never louder than the evidence warrants — mirroring the matcher's
    treatment of null as a valid value, not an error). The value is
    sourced from OSV's `database_specific.severity`, which is arbitrary
    per-database data, so a truthy non-string value (number, object)
    must not crash the run — it is unknown and maps to `note`.
    """
    key = str(severity or "").upper()
    return SEVERITY_TO_LEVEL.get(key, "note")


def fingerprint(purl, vuln_id):
    """Stable fingerprint for a component finding: sha256 over
    purl + "|" + canonical key. Separator avoids concatenation
    ambiguity; the hash is stable across runs for the same component
    and vulnerability, so code scanning deduplicates correctly."""
    raw = f"{purl}{FINGERPRINT_SEPARATOR}{vuln_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def first_reference_url(vuln):
    for ref in vuln.get("references") or []:
        url = ref.get("url")
        if isinstance(url, str) and url:
            return url
    return None


def _text(value):
    """Return value if it is a non-empty string, else ''.

    `summary` and `id` are sourced from OSV records (arbitrary
    per-database data); a non-string must not leak into a SARIF field
    that requires a string — shortDescription.text falls back to the
    id, and an empty id is caught by the validator (fail loudly)."""
    return value if isinstance(value, str) and value else ""


def _sarif_id(value):
    """Return an ID safe for SARIF's string-only identifier fields.

    The matcher retains malformed non-string OSV IDs as raw evidence while
    marking their details unavailable. SARIF rule IDs and result ruleIds must
    still be strings, so stringify those values at this output boundary.
    """
    return value if isinstance(value, str) else "" if value is None else str(value)


def build_rule(vuln, lockfile):
    """One SARIF rule per canonical vulnerability."""
    vuln_id = _sarif_id(vuln.get("id"))
    rule = {
        "id": vuln_id,
        "shortDescription": {
            "text": _text(vuln.get("summary")) or vuln_id,
        },
        "properties": {
            "epss": vuln.get("epss"),
            "kev": vuln.get("kev"),
            "osvIds": vuln.get("osvIds") or [],
            "lockfile": lockfile,
        },
    }
    help_uri = first_reference_url(vuln)
    if help_uri:
        rule["helpUri"] = help_uri
    return rule


def build_result(vuln, component, rule_index):
    """One SARIF result per component finding."""
    purl = component.get("purl") or ""
    lockfile = component.get("lockfile") or ""
    vuln_id = _sarif_id(vuln.get("id"))
    summary = _text(vuln.get("summary")) or vuln_id
    return {
        "ruleId": vuln_id,
        "ruleIndex": rule_index,
        "level": severity_to_level(vuln.get("databaseSpecificSeverity")),
        "message": {"text": f"{summary} (affected component: {purl})"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": purl},
            },
        }],
        "partialFingerprints": {
            FINGERPRINT_KEY: fingerprint(purl, vuln_id),
        },
        "properties": {
            "purl": purl,
            "component": component.get("name") or "",
            "version": component.get("version") or "",
            "lockfile": lockfile,
        },
    }


def build_sarif(doc):
    """Convert the enriched findings JSON to a SARIF 2.1.0 log.

    Deterministic: the findings JSON is already sorted by
    `component.purl` then `vulnerabilities[].id`; rules are emitted in
    first-encounter order and results in findings order, so two runs
    over identical findings produce byte-identical SARIF.
    """
    rules = []
    rule_index = {}
    results = []
    for finding in doc.get("findings") or []:
        component = finding.get("component") or {}
        for vuln in finding.get("vulnerabilities") or []:
            vuln_id = _sarif_id(vuln.get("id"))
            if vuln_id not in rule_index:
                rule_index[vuln_id] = len(rules)
                rules.append(build_rule(vuln, component.get("lockfile") or ""))
            results.append(build_result(vuln, component, rule_index[vuln_id]))
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "informationUri": TOOL_INFORMATION_URI,
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


def validate_sarif(sarif):
    """Structural validation against the SARIF 2.1.0 schema requirements
    the emitted constructs must satisfy. Returns a list of error
    strings; an empty list means valid. Not a full jsonschema pass —
    the goal is to fail loudly before an invalid log is written or
    uploaded (code scanning rejects malformed SARIF opaquely)."""
    errors = []
    if sarif.get("$schema") != SARIF_SCHEMA_URI:
        errors.append("$schema must be the SARIF 2.1.0 schema URI")
    if sarif.get("version") != SARIF_VERSION:
        errors.append(f"version must be '{SARIF_VERSION}'")
    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("runs must be a non-empty array")
        return errors
    for run_index, run in enumerate(runs):
        where = f"runs[{run_index}]"
        driver = ((run.get("tool") or {}).get("driver") or {})
        if not driver.get("name"):
            errors.append(f"{where}.tool.driver.name is required")
        rules = driver.get("rules")
        if rules is not None and not isinstance(rules, list):
            errors.append(f"{where}.tool.driver.rules must be an array")
            rules = None
        rule_ids = []
        if rules:
            for i, rule in enumerate(rules):
                where_r = f"{where}.tool.driver.rules[{i}]"
                rule_id = rule.get("id")
                if not isinstance(rule_id, str) or not rule_id:
                    errors.append(f"{where_r}.id must be a non-empty string")
                else:
                    rule_ids.append(rule_id)
                text = ((rule.get("shortDescription") or {}).get("text"))
                if not isinstance(text, str) or not text:
                    errors.append(
                        f"{where_r}.shortDescription.text is required")
        results = run.get("results")
        if results is None:
            results = []
        if not isinstance(results, list):
            errors.append(f"{where}.results must be an array")
            results = []
        for i, result in enumerate(results):
            where_res = f"{where}.results[{i}]"
            rule_id = result.get("ruleId")
            if not isinstance(rule_id, str) or not rule_id:
                errors.append(f"{where_res}.ruleId must be a non-empty string")
            elif rule_ids and rule_id not in rule_ids:
                errors.append(
                    f"{where_res}.ruleId '{rule_id}' has no matching rule")
            rule_index = result.get("ruleIndex")
            if rule_index is not None:
                if not isinstance(rule_index, int) or isinstance(
                        rule_index, bool):
                    errors.append(f"{where_res}.ruleIndex must be an integer")
                elif rules and not 0 <= rule_index < len(rules):
                    errors.append(
                        f"{where_res}.ruleIndex {rule_index} out of range")
                elif rules and rules[rule_index].get("id") != rule_id:
                    errors.append(
                        f"{where_res}.ruleIndex does not point at rule "
                        f"'{rule_id}'")
            level = result.get("level")
            if level not in VALID_LEVELS:
                errors.append(
                    f"{where_res}.level must be one of "
                    f"{sorted(VALID_LEVELS)}, got {level!r}")
            message = ((result.get("message") or {}).get("text"))
            if not isinstance(message, str) or not message:
                errors.append(f"{where_res}.message.text must be a non-empty string")
            locations = result.get("locations")
            if not locations:
                errors.append(
                    f"{where_res}.locations must carry at least one "
                    "physicalLocation with an artifactLocation.uri "
                    "(the purl artifact is required for dedup)")
            for j, location in enumerate(locations or []):
                uri = ((((location.get("physicalLocation") or {})
                        .get("artifactLocation") or {}).get("uri")) or "")
                if not isinstance(uri, str) or not uri:
                    errors.append(
                        f"{where_res}.locations[{j}].physicalLocation."
                        "artifactLocation.uri is required")
            for key, value in (result.get("partialFingerprints")
                               or {}).items():
                if not key:
                    errors.append(
                        f"{where_res}.partialFingerprints keys must be "
                        "non-empty")
                if not isinstance(value, str) or not value:
                    errors.append(
                        f"{where_res}.partialFingerprints['{key}'] must be "
                        "a non-empty string")
    return errors


def main():
    findings_file = os.environ.get("INPUT_FINDINGS_FILE",
                                   "vulnerabilities.json")
    sarif_output = os.environ.get("INPUT_SARIF_OUTPUT", "findings.sarif")

    log(f"Findings file: {findings_file}")
    if not os.path.isfile(findings_file):
        print(f"::error::Findings file not found: {findings_file}")
        return 1
    with open(findings_file, "r", encoding="utf-8") as f:
        doc = json.load(f)

    sarif = build_sarif(doc)
    errors = validate_sarif(sarif)
    if errors:
        for error in errors:
            print(f"::error::Invalid SARIF: {error}")
        return 1

    with open(sarif_output, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
        f.write("\n")

    run = sarif["runs"][0]
    results_count = len(run["results"])
    rules_count = len(run["tool"]["driver"].get("rules") or [])
    log(f"SARIF written to {sarif_output}: {results_count} results, "
        f"{rules_count} rules (one per canonical vulnerability)")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"sarif-file={sarif_output}\n")
            f.write(f"sarif-results={results_count}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
