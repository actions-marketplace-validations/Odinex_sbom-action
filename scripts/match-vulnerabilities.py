#!/usr/bin/env python3
"""match-vulnerabilities.py — OSV.dev vulnerability matching.

Three-phase pipeline:
  Phase 1: Batch matching via POST /v1/querybatch (purl-native, 1000-query chunks)
  Phase 2: Advisory detail fetch via GET /v1/vulns/{id} (dedup by OSV ID)
  Phase 3: Global alias closure via union-find over the alias graph (in-memory)

Contract-compatible with the previous bash implementation: reads the same
environment variables, writes the same findings JSON shape, and reports
through $GITHUB_OUTPUT / $GITHUB_STEP_SUMMARY.

Environment (set by action.yml, or manually for local runs):
  INPUT_SBOM_FILE          path to the CycloneDX SBOM (required)
  INPUT_FINDINGS_OUTPUT    output file for findings JSON (default: vulnerabilities.json)
  INPUT_OSV_API_URL        OSV API base URL (default: https://api.osv.dev)
  INPUT_FAIL_ON_OSV_ERROR  'true' to fail when the OSV scan is partial (default: false)

Requires only the Python 3 standard library (no curl, no jq).
"""

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

BATCH_SIZE = 1000
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1
MAX_400_RETRIES = 10
RETRYABLE_CODES = {429, 500, 502, 503, 504}
BATCH_TIMEOUT = 90
DETAIL_TIMEOUT = 30
PURL_RE = re.compile(r"^pkg:[a-z][a-z0-9+.-]*/.+@.+")
# \Z, unlike $, cannot match immediately before a trailing newline.
OSV_ID_RE = re.compile(r"[A-Za-z0-9._-]+\Z")
INDEX_RE = re.compile(r"index (\d+)")


def log(msg):
    print(f"[match-vulnerabilities] {msg}")


def warn(msg):
    print(f"::warning::{msg}")


def load_sbom(path):
    if not os.path.isfile(path):
        print(f"::error::SBOM file not found: {path}")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def http_request(url, *, data=None, timeout):
    """GET (data=None) or POST JSON to url. Returns (status_code, body_bytes).

    Retries 429, 5xx, and network errors with exponential backoff
    (1s/2s/4s, max 3 attempts). status_code 0 means a network error.
    """
    headers = {"Content-Type": "application/json"} if data is not None else {}
    delay = RETRY_BASE_DELAY
    for attempt in range(1, MAX_RETRIES + 1):
        code, body = 0, b""
        try:
            req = urllib.request.Request(
                url, data=data, headers=headers,
                method="POST" if data is not None else "GET",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code, body = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            code, body = e.code, e.read()
        except (urllib.error.URLError, TimeoutError, OSError):
            code, body = 0, b""
        if code == 200 or (code != 0 and code not in RETRYABLE_CODES):
            return code, body
        if attempt < MAX_RETRIES:
            warn(f"HTTP {code} from {url}, retrying in {delay}s "
                 f"(attempt {attempt}/{MAX_RETRIES})")
            time.sleep(delay)
            delay *= 2
    return code, body


def extract_components(sbom):
    """Library components with purls, root project excluded.

    Combined exclusion rule: a component is the root if its name equals
    metadata.component.name, OR it is the single graph root (has its own
    dependsOn entry and nothing depends on it). Name matching alone fails
    when source-name differs from package name; graph-root detection alone
    fails on degenerate lockfiles with stripped dependencies fields.

    Returns (components, not_scanned) where not_scanned is a list of purls
    that failed local pre-validation.
    """
    metadata = sbom.get("metadata") or {}
    source_name = (metadata.get("component") or {}).get("name") or ""
    dependencies = sbom.get("dependencies") or []

    depended_upon = set()
    for dep in dependencies:
        for ref in dep.get("dependsOn") or []:
            depended_upon.add(ref)
    own_depends_on = {dep.get("ref") for dep in dependencies if dep.get("dependsOn")}

    candidates = []
    graph_roots = []
    for comp in sbom.get("components") or []:
        if comp.get("type") != "library":
            continue
        bom_ref = comp.get("bom-ref")
        has_own_depends_on = bom_ref in own_depends_on
        is_depended_upon = bom_ref in depended_upon
        lockfile = None
        for prop in comp.get("properties") or []:
            if prop.get("name") == "syft:location:0:path":
                lockfile = prop.get("value")
                break
        entry = {
            "bomRef": bom_ref,
            "purl": comp.get("purl"),
            "name": comp.get("name"),
            "version": comp.get("version"),
            "lockfile": lockfile,
            "_hasOwnDependsOn": has_own_depends_on,
            "_isDependedUpon": is_depended_upon,
        }
        candidates.append(entry)
        if has_own_depends_on and not is_depended_upon:
            graph_roots.append(entry)

    single_graph_root = len(graph_roots) == 1

    components, not_scanned = [], []
    for entry in candidates:
        is_graph_root = single_graph_root and entry["_hasOwnDependsOn"] \
            and not entry["_isDependedUpon"]
        if entry["name"] == source_name or is_graph_root:
            continue
        if not entry["purl"]:
            continue
        if PURL_RE.match(entry["purl"]):
            components.append({k: entry[k] for k in
                               ("bomRef", "purl", "name", "version", "lockfile")})
        else:
            warn(f"Invalid purl skipped: {entry['purl']} (component: {entry['name']})")
            not_scanned.append(entry["purl"])

    log(f"Extracted {len(components)} library components "
        f"(root project excluded, invalid purls filtered)")
    return components, not_scanned


def query_batch(api_url, batch, page_token=None):
    """POST one batch to /v1/querybatch. Returns (results, failed, rejected).

    failed=True means the batch could not be queried (after 400 recovery);
    the caller must mark all remaining purls as not scanned. rejected lists
    purls removed via HTTP 400 recovery (valid shape, rejected by OSV).
    """
    queries = [{"package": {"purl": c["purl"]}} for c in batch]
    if page_token is not None:
        for q, tok in zip(queries, page_token):
            q["page_token"] = tok
    body = json.dumps({"queries": queries}).encode("utf-8")
    rejected = []

    for attempt in range(MAX_400_RETRIES + 1):
        code, resp = http_request(f"{api_url}/v1/querybatch",
                                  data=body, timeout=BATCH_TIMEOUT)
        if code == 200:
            try:
                results = json.loads(resp).get("results")
            except (ValueError, AttributeError):
                results = None
            if results is None or len(results) != len(batch):
                return None, True, rejected
            return results, False, rejected
        if code == 400 and attempt < MAX_400_RETRIES:
            try:
                parsed = json.loads(resp)
                error_msg = parsed.get("error") or parsed.get("message") or ""
            except ValueError:
                error_msg = ""
            match = INDEX_RE.search(error_msg)
            if match and batch:
                bad_index = int(match.group(1))
                if 0 <= bad_index < len(batch):
                    bad_purl = batch[bad_index]["purl"]
                    warn(f"OSV rejected purl at index {bad_index}: "
                         f"{bad_purl} — {error_msg}")
                    rejected.append(bad_purl)
                    del batch[bad_index]
                    body = json.dumps({"queries": [
                        {"package": {"purl": c["purl"]}} for c in batch
                    ]}).encode("utf-8")
                    log(f"Removed invalid purl, retrying with "
                        f"{len(batch)} components (attempt {attempt + 1})")
                    continue
            return None, True, rejected
        return None, True, rejected
    return None, True, rejected


class Scanner:
    def __init__(self):
        self.sbom_file = os.environ.get("INPUT_SBOM_FILE")
        if not self.sbom_file:
            print("::error::INPUT_SBOM_FILE is required")
            sys.exit(1)
        self.findings_output = os.environ.get("INPUT_FINDINGS_OUTPUT",
                                              "vulnerabilities.json")
        self.api_url = os.environ.get("INPUT_OSV_API_URL", "https://api.osv.dev")
        self.fail_on_error = os.environ.get("INPUT_FAIL_ON_OSV_ERROR", "false")

        self.sbom = load_sbom(self.sbom_file)
        self.scan_status = "complete"
        self.not_scanned = []
        self.advisories = {}
        self.unavailable_details = set()

    def mark_not_scanned(self, purl):
        self.not_scanned.append(purl)

    def run_batch_phase(self, components):
        """Phase 1: batch matching. Returns list of per-component results:
        [{"component": ..., "vulns": [...], "next_page_token": ...}]."""
        results = []
        for offset in range(0, len(components), BATCH_SIZE):
            batch_num = offset // BATCH_SIZE + 1
            batch = components[offset:offset + BATCH_SIZE]
            log(f"Batch {batch_num}: querying {len(batch)} components")

            batch_results, failed, rejected = query_batch(self.api_url,
                                                          list(batch))
            self.not_scanned.extend(rejected)
            if failed:
                warn(f"Batch {batch_num} failed")
                self.scan_status = "partial"
                for c in batch:
                    self.mark_not_scanned(c["purl"])
                continue

            for comp, res in zip(batch, batch_results):
                # Clean results are {} — the vulns key is absent, not empty.
                results.append({
                    "component": comp,
                    "vulns": res.get("vulns") or [],
                    "next_page_token": res.get("next_page_token"),
                })

            self.handle_pagination(results, batch_num)

        # IDs come from a remote response. Keep malformed values as evidence so
        # Phase 2 can mark their findings detailsFetched: false, but use a
        # type-safe ordering so a mixed response cannot abort the scan.
        unique_ids = sorted({v["id"] for r in results for v in r["vulns"]},
                            key=str)
        log(f"Phase 1 complete: {len(unique_ids)} unique vulnerability IDs found")
        return results, unique_ids

    def handle_pagination(self, results, batch_num):
        """Resend tokened queries until no next_page_token remains."""
        page = 1
        tokened = [(i, r["next_page_token"]) for i, r in enumerate(results)
                   if r["next_page_token"]]
        while tokened:
            page += 1
            log(f"Batch {batch_num} pagination page {page}: "
                f"{len(tokened)} tokened queries")
            batch = [results[i]["component"] for i, _ in tokened]
            tokens = [tok for _, tok in tokened]
            page_results, failed, _ = query_batch(self.api_url, batch,
                                                  page_token=tokens)
            if failed:
                warn(f"Pagination page {page} failed for batch {batch_num}")
                self.scan_status = "partial"
                for i, _ in tokened:
                    self.mark_not_scanned(results[i]["component"]["purl"])
                break
            next_tokened = []
            for (i, _), res in zip(tokened, page_results):
                results[i]["vulns"].extend(res.get("vulns") or [])
                results[i]["next_page_token"] = res.get("next_page_token")
                if res.get("next_page_token"):
                    next_tokened.append((i, res["next_page_token"]))
            tokened = next_tokened

    def run_advisory_phase(self, unique_ids):
        """Phase 2: fetch full advisory records, deduped by OSV ID.

        IDs that fail validation, fetch, or parse land in
        unavailable_details — build_vulnerability marks those findings
        detailsFetched: false so downstream consumers can distinguish
        "advisory has no summary" from "we could not retrieve the record".

        TODO: if pilot repos hit slow Phase 2, parallelize with a thread
        pool. YAGNI at phase-1 scale.
        """
        if not unique_ids:
            log("Phase 2: no advisories to fetch")
            return
        log(f"Phase 2: fetching {len(unique_ids)} unique advisories")

        fetched = skipped = failed = 0
        for vuln_id in unique_ids:
            if vuln_id in self.advisories:
                continue
            if not isinstance(vuln_id, str) or not OSV_ID_RE.match(vuln_id):
                warn(f"Invalid OSV ID skipped: {vuln_id!r} — fails full-string "
                     "[A-Za-z0-9._-]+ validation; not used in the detail-fetch URL")
                self.unavailable_details.add(vuln_id)
                failed += 1
                continue
            code, body = http_request(f"{self.api_url}/v1/vulns/{vuln_id}",
                                      timeout=DETAIL_TIMEOUT)
            if code == 200:
                try:
                    record = json.loads(body)
                    if not isinstance(record, dict):
                        raise ValueError("advisory detail must be an object")
                except (TypeError, ValueError):
                    warn(f"Failed to parse advisory {vuln_id}")
                    self.unavailable_details.add(vuln_id)
                    failed += 1
                else:
                    self.advisories[vuln_id] = record
                    fetched += 1
            elif code == 404:
                warn(f"Advisory {vuln_id} not found (404) — "
                     "may have been withdrawn")
                self.unavailable_details.add(vuln_id)
                skipped += 1
            else:
                warn(f"Failed to fetch advisory {vuln_id} (HTTP {code})")
                self.unavailable_details.add(vuln_id)
                failed += 1

        log(f"Phase 2 complete: {fetched} fetched, {skipped} skipped (404), "
            f"{failed} failed")

    def compute_canonical_keys(self, matched_ids):
        """Phase 3: global union-find over the alias graph.

        Two IDs are connected if they share any alias or one lists the
        other (aliasing is not guaranteed symmetric or transitive per
        record, so closure must be global). Canonical key per component:
        lexicographically smallest CVE alias if any, else lexicographically
        smallest of all IDs in the component.

        Returns {osv_id: canonical_key} for all matched IDs.
        """
        parent = {}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            parent.setdefault(a, a)
            parent.setdefault(b, b)
            parent[find(a)] = find(b)

        for osv_id, record in self.advisories.items():
            parent.setdefault(osv_id, osv_id)
            for alias in record.get("aliases") or []:
                union(osv_id, alias)
        for osv_id in matched_ids:
            parent.setdefault(osv_id, osv_id)

        components = {}
        for node in parent:
            components.setdefault(find(node), set()).add(node)

        canonical = {}
        for nodes in components.values():
            cves = sorted(n for n in nodes
                          if isinstance(n, str) and n.startswith("CVE-"))
            key = cves[0] if cves else min(nodes, key=str)
            for node in nodes:
                canonical[node] = key
        log(f"Phase 3 complete: {len(components)} alias components")
        return canonical

    def build_vulnerability(self, canon_id, group_ids, canonical):
        """Merge all OSV records in a canonical group into one finding.

        detailsFetched is false when any OSV record in the group could
        not be retrieved (fetch/parse failure, 404 withdrawal, or an ID
        rejected by validation) — the merged fields may then be based on
        incomplete advisory data, and consumers must not read null
        summary/severity as "the advisory has none".
        """
        records = [self.advisories[i] for i in group_ids if i in self.advisories]

        def schema_key(record):
            version = record.get("schema_version") or "0"
            try:
                return tuple(int(p) for p in version.split("."))
            except ValueError:
                return (0,)

        # Primary source: record with the highest schema version.
        primary = max(records, key=schema_key) if records else {}
        database_specific = primary.get("database_specific") or {}
        return {
            "id": canon_id,
            "osvIds": sorted(group_ids, key=str),
            "aliases": sorted((i for i in group_ids if i != canon_id),
                              key=str),
            "osvSchemaVersion": primary.get("schema_version"),
            "summary": primary.get("summary"),
            "severity": primary.get("severity"),
            "databaseSpecificSeverity": database_specific.get("severity"),
            "detailsFetched": all(i not in self.unavailable_details
                                  for i in group_ids),
            "references": primary.get("references"),
            "affectedRanges": primary.get("affected"),
            "epss": None,
            "kev": None,
        }

    def join_findings(self, batch_results):
        """Join batch results, deduped advisories, and component metadata
        into the findings array (only components with >=1 match)."""
        canonical = self.compute_canonical_keys(
            {v["id"] for r in batch_results for v in r["vulns"]})

        groups = {}
        for r in batch_results:
            for vuln in r["vulns"]:
                canon = canonical[vuln["id"]]
                groups.setdefault(canon, set()).add(vuln["id"])

        findings = []
        for result in batch_results:
            if not result["vulns"]:
                continue
            canon_ids = sorted({canonical[v["id"]] for v in result["vulns"]},
                               key=str)
            vulnerabilities = [self.build_vulnerability(cid, groups[cid], canonical)
                               for cid in canon_ids]
            findings.append({"component": result["component"],
                             "vulnerabilities": vulnerabilities})

        findings.sort(key=lambda f: f["component"]["purl"])
        for finding in findings:
            finding["vulnerabilities"].sort(key=lambda v: str(v["id"]))
        return findings

    def write_findings(self, findings):
        """Write the findings JSON. generatedAt is sourced from the SBOM's
        metadata.timestamp (not wall clock) for fixture determinism."""
        sbom_hash = hashlib.sha256(open(self.sbom_file, "rb").read()).hexdigest()
        timestamp = (self.sbom.get("metadata") or {}).get("timestamp") or ""
        not_scanned_list = sorted(set(self.not_scanned))

        findings_doc = {
            "generatedAt": timestamp,
            "source": {"sbom": self.sbom_file, "sbomHash": f"sha256:{sbom_hash}"},
            "scanStatus": self.scan_status,
            "findings": findings,
            "summary": {
                "componentsScanned": self.components_scanned,
                "componentsNotScanned": len(not_scanned_list),
                "componentsNotScannedList": not_scanned_list,
                "componentsWithVulnerabilities": len(findings),
                "totalVulnerabilityFindings":
                    sum(len(f["vulnerabilities"]) for f in findings),
                "uniqueVulnerabilityIds":
                    len({v["id"] for f in findings for v in f["vulnerabilities"]}),
            },
        }
        with open(self.findings_output, "w", encoding="utf-8") as f:
            json.dump(findings_doc, f, indent=2)
            f.write("\n")

    def write_outputs(self):
        with open(self.findings_output, "r", encoding="utf-8") as f:
            summary = json.load(f)["summary"]

        github_output = os.environ.get("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a", encoding="utf-8") as f:
                f.write(f"vulnerabilities-found={summary['uniqueVulnerabilityIds']}\n")
                f.write(f"findings-file={self.findings_output}\n")
                f.write(f"components-with-vulns={summary['componentsWithVulnerabilities']}\n")
                f.write(f"scan-status={self.scan_status}\n")

        step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if step_summary:
            with open(step_summary, "a", encoding="utf-8") as f:
                f.write("## Vulnerability Scan (OSV.dev)\n\n")
                if self.scan_status == "partial":
                    f.write("⚠️ **Scan status: PARTIAL** — some components could "
                            "not be scanned. See `componentsNotScannedList` in "
                            "the findings file.\n\n")
                else:
                    f.write("✅ **Scan status: COMPLETE** — all components were "
                            "scanned.\n\n")
                f.write("| Metric | Value |\n| --- | --- |\n")
                f.write(f"| Components scanned | {summary['componentsScanned']} |\n")
                f.write(f"| Components not scanned | "
                        f"{summary['componentsNotScanned']} |\n")
                f.write(f"| Components with vulnerabilities | "
                        f"{summary['componentsWithVulnerabilities']} |\n")
                f.write(f"| Total vulnerability findings | "
                        f"{summary['totalVulnerabilityFindings']} |\n")
                f.write(f"| Unique vulnerabilities (canonical keys) | "
                        f"{summary['uniqueVulnerabilityIds']} |\n")
                f.write(f"| Findings file | `{self.findings_output}` |\n\n")
                if self.scan_status == "partial":
                    f.write("### Components not scanned\n\n```\n")
                    for purl in summary["componentsNotScannedList"]:
                        f.write(f"{purl}\n")
                    f.write("```\n")

        log(f"Outputs: vulnerabilities-found={summary['uniqueVulnerabilityIds']}, "
            f"components-with-vulns={summary['componentsWithVulnerabilities']}, "
            f"scan-status={self.scan_status}")

    def run(self):
        log("Starting OSV vulnerability matching")
        log(f"SBOM: {self.sbom_file}")
        log(f"OSV API: {self.api_url}")
        log(f"Findings output: {self.findings_output}")

        components, invalid = extract_components(self.sbom)
        self.components_scanned = len(components)
        self.not_scanned.extend(invalid)

        if not components:
            log("No components to scan — writing empty findings")
            self.write_findings([])
            self.write_outputs()
            return 0

        batch_results, unique_ids = self.run_batch_phase(components)

        if not unique_ids:
            log("No vulnerabilities found — writing empty findings")
            self.write_findings([])
            self.write_outputs()
            return 0

        self.run_advisory_phase(unique_ids)
        findings = self.join_findings(batch_results)
        self.write_findings(findings)
        self.write_outputs()
        log(f"Done. Findings written to {self.findings_output}")

        if self.fail_on_error == "true" and self.scan_status == "partial":
            print("::error::OSV scan was partial and fail-on-osv-error is true")
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(Scanner().run())
