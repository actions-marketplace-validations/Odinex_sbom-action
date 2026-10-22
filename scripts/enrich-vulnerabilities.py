#!/usr/bin/env python3
"""enrich-vulnerabilities.py — EPSS + CISA KEV enrichment.

Pipeline step 3 (SBOM → OSV match → enrich). Reads the findings JSON
written by match-vulnerabilities.py, fills the reserved `epss` and `kev`
slots per vulnerability, and writes the enriched JSON back in place.

Data sources (both free, no keys):
  EPSS  FIRST API batch endpoint
        GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,...
        (~100 CVEs per call)
  KEV   single JSON download
        https://www.cisa.gov/sites/default/files/feeds/
        known_exploited_vulnerabilities.json
        one GET per run, in-memory lookup by CVE ID

CVE resolution: canonical keys already prefer CVEs, so a CVE-keyed
canonical ID resolves directly. If the canonical key is not a CVE, no CVE
exists anywhere in the alias group (Phase 3 of the matcher would have
chosen it as the canonical key otherwise) — `epss` stays `null` for
those findings, and `kev` is `{ knownExploited: false }` when the feed
was fetched (KEV is CVE-keyed, so a CVE-less advisory cannot be listed)
or `null` when it was not (documented, not an error).

Degradation: source unreachable → slots stay `null` + `::warning::`.
Enrichment gaps are prioritization losses, not scan-integrity losses —
`scanStatus` is never touched. A successfully fetched KEV feed with no
match yields `{ knownExploited: false }`; an unreachable feed leaves the
slot `null` (unknown ≠ not exploited).

Determinism caveat: EPSS updates daily — `epss.date` records the score's
date; determinism assertions for the ground-truth dataset must use
recorded fixtures (same pattern as `generatedAt`).

Environment (set by action.yml, or manually for local runs):
  INPUT_FINDINGS_FILE      path to the findings JSON (default:
                           vulnerabilities.json)
  INPUT_EPSS_API_URL       EPSS API base URL (default:
                           https://api.first.org)
  INPUT_KEV_FEED_URL       KEV feed URL (default: the CISA URL above)

Outputs via $GITHUB_OUTPUT / $GITHUB_STEP_SUMMARY:
  kev-count, high-epss-count (percentile >= 0.90)

Requires only the Python 3 standard library.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

EPSS_BATCH_SIZE = 100
HIGH_EPSS_PERCENTILE = 0.90
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1
RETRYABLE_CODES = {429, 500, 502, 503, 504}
EPSS_TIMEOUT = 30
KEV_TIMEOUT = 60

DEFAULT_EPSS_API_URL = "https://api.first.org"
DEFAULT_KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def log(msg):
    print(f"[enrich-vulnerabilities] {msg}")


def warn(msg):
    print(f"::warning::{msg}")


def http_get(url, timeout):
    """GET url and parse JSON. Retries network errors and retryable
    statuses ({429, 500, 502, 503, 504}) with exponential backoff
    (1s/2s/4s, max 3 attempts); other HTTP statuses (e.g. 404) fail
    immediately. Returns parsed JSON or None on failure."""
    delay = RETRY_BASE_DELAY
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url,
                                        headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code not in RETRYABLE_CODES or attempt == MAX_RETRIES:
                return None
            time.sleep(delay)
            delay *= 2
        except Exception:
            if attempt == MAX_RETRIES:
                return None
            time.sleep(delay)
            delay *= 2
    return None


def resolve_cve(vuln):
    """Resolve a CVE for a vulnerability group.

    Canonical keys that are CVEs resolve directly. A non-CVE canonical
    key means no CVE exists anywhere in the alias group (the matcher's
    Phase 3 prefers CVEs as canonical keys), so no CVE can be resolved —
    returns None and `epss` stays null (documented, not an error).
    """
    vuln_id = vuln.get("id")
    if isinstance(vuln_id, str) and vuln_id.startswith("CVE-"):
        return vuln_id
    return None


def fetch_epss(cves, api_url):
    """Fetch EPSS scores for all CVEs. Returns ({cve: epss_obj}, ok).

    ok is False if any batch failed; scores from successful batches are
    still kept (partial enrichment beats none).
    """
    scores = {}
    ok = True
    for start in range(0, len(cves), EPSS_BATCH_SIZE):
        chunk = cves[start:start + EPSS_BATCH_SIZE]
        url = f"{api_url}/data/v1/epss?cve=" + ",".join(chunk)
        data = http_get(url, EPSS_TIMEOUT)
        if data is None:
            warn(f"EPSS API unreachable for batch starting at "
                 f"{url.split('?')[0]} (CVEs {chunk[0]}..{chunk[-1]}) — "
                 "epss slots stay null for unfetched CVEs")
            ok = False
            continue
        for entry in data.get("data") or []:
            try:
                scores[entry["cve"]] = {
                    "score": float(entry["epss"]),
                    "percentile": float(entry["percentile"]),
                    "date": entry["date"],
                }
            except (KeyError, TypeError, ValueError):
                continue
    return scores, ok


def fetch_kev(feed_url):
    """Download the KEV feed. Returns ({cve: kev_obj}, ok)."""
    data = http_get(feed_url, KEV_TIMEOUT)
    if data is None:
        warn(f"KEV feed unreachable ({feed_url}) — kev slots stay null")
        return {}, False
    kev = {}
    for entry in data.get("vulnerabilities") or []:
        cve = entry.get("cveID")
        if cve:
            kev[cve] = {
                "knownExploited": True,
                "dueDate": entry.get("dueDate"),
                "added": entry.get("dateAdded"),
            }
    return kev, True


def enrich(doc, epss_scores, kev_entries, kev_ok):
    """Fill epss/kev slots in place. Returns (kev_count, high_epss_count).

    kev slots stay null when the KEV feed could not be fetched
    (unknown is not the same as not exploited).
    """
    kev_count = 0
    high_epss_count = 0
    for finding in doc.get("findings") or []:
        for vuln in finding.get("vulnerabilities") or []:
            cve = resolve_cve(vuln)
            epss = epss_scores.get(cve) if cve else None
            kev_entry = kev_entries.get(cve) if (cve and kev_ok) else None
            vuln["epss"] = epss
            vuln["kev"] = kev_entry or (
                {"knownExploited": False} if kev_ok else None)
            if epss and epss["percentile"] >= HIGH_EPSS_PERCENTILE:
                high_epss_count += 1
            if kev_entry:
                kev_count += 1
    return kev_count, high_epss_count


def write_outputs(findings_file, doc, epss_ok, kev_ok,
                  kev_count, high_epss_count):
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"findings-file={findings_file}\n")
            f.write(f"kev-count={kev_count}\n")
            f.write(f"high-epss-count={high_epss_count}\n")

    log(f"Outputs: kev-count={kev_count}, "
        f"high-epss-count={high_epss_count}")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        rows = []
        for finding in doc.get("findings") or []:
            for vuln in finding.get("vulnerabilities") or []:
                epss = vuln.get("epss")
                kev = vuln.get("kev") or {}
                rows.append((
                    epss["percentile"] if epss else -1.0,
                    kev.get("knownExploited"),
                    finding["component"].get("purl") or "",
                    vuln.get("id") or "",
                    epss,
                ))
        rows.sort(key=lambda r: (-r[0], r[2], str(r[3])))
        with open(step_summary, "a", encoding="utf-8") as f:
            f.write("## Prioritization (EPSS + KEV)\n\n")
            if not epss_ok or not kev_ok:
                missing = " / ".join(
                    name for name, ok in (("EPSS", epss_ok), ("KEV", kev_ok))
                    if not ok)
                f.write(f"⚠️ {missing} enrichment data was unavailable — "
                        "corresponding slots are null "
                        "(prioritization loss, not a scan-integrity loss).\n\n")
            if not rows:
                f.write("_No vulnerability findings to prioritize._\n\n")
                return
            f.write("Findings sorted by EPSS percentile (descending):\n\n")
            f.write("| ⚠️ KEV | EPSS | Percentile | Vulnerability | Component |\n")
            f.write("| --- | --- | --- | --- | --- |\n")
            for _, is_kev, purl, vuln_id, epss in rows:
                kev_flag = "⚠️ KEV" if is_kev else ""
                if epss:
                    epss_col = f"{epss['score']:.4f}"
                    pct_col = f"{epss['percentile'] * 100:.2f}%"
                else:
                    epss_col = pct_col = "—"
                f.write(f"| {kev_flag} | {epss_col} | {pct_col} "
                        f"| `{vuln_id}` | `{purl}` |\n")
            f.write("\n")


def main():
    findings_file = os.environ.get("INPUT_FINDINGS_FILE",
                                   "vulnerabilities.json")
    epss_api_url = os.environ.get("INPUT_EPSS_API_URL",
                                  DEFAULT_EPSS_API_URL).rstrip("/")
    kev_feed_url = os.environ.get("INPUT_KEV_FEED_URL", DEFAULT_KEV_FEED_URL)

    log(f"Findings file: {findings_file}")
    if not os.path.isfile(findings_file):
        print(f"::error::Findings file not found: {findings_file}")
        return 1
    with open(findings_file, "r", encoding="utf-8") as f:
        doc = json.load(f)

    findings = doc.get("findings") or []
    vulns = [v for fnd in findings for v in fnd.get("vulnerabilities") or []]
    log(f"Enriching {len(vulns)} vulnerability findings "
        f"across {len(findings)} components")

    cves = sorted({c for v in vulns if (c := resolve_cve(v))})
    no_cve = len(vulns) - len([v for v in vulns if resolve_cve(v)])
    if no_cve:
        log(f"{no_cve} findings have no CVE in their alias group — "
            "epss stays null; kev reflects KEV lookup status "
            "(documented, not an error)")

    if not cves:
        log("No CVEs to look up — skipping EPSS/KEV fetches")
        epss_scores, epss_ok, kev_entries, kev_ok = {}, True, {}, True
    else:
        epss_scores, epss_ok = fetch_epss(cves, epss_api_url)
        kev_entries, kev_ok = fetch_kev(kev_feed_url)

    kev_count, high_epss_count = enrich(doc, epss_scores, kev_entries, kev_ok)

    with open(findings_file, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")

    log(f"Enriched: {len(epss_scores)} EPSS scores, "
        f"{kev_count} KEV entries, {high_epss_count} high-EPSS "
        f"(percentile >= {HIGH_EPSS_PERCENTILE:.2f})")
    log(f"Enriched findings written to {findings_file}")
    write_outputs(findings_file, doc, epss_ok, kev_ok,
                  kev_count, high_epss_count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
