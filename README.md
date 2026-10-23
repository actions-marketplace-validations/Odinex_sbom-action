# CycloneDX SBOM GitHub Action

A free, open-source GitHub Action that generates a [CycloneDX](https://cyclonedx.org/) JSON SBOM (Software Bill of Materials) from your project's lockfiles using [Syft](https://github.com/anchore/syft), matches components against [OSV.dev](https://osv.dev/) vulnerability advisories, enriches them with EPSS scores and CISA KEV status, annotates each finding with import-level reachability (parsed locally on the runner), and surfaces the findings in the GitHub **Security tab** via a SARIF 2.1.0 code-scanning upload. Runs on GitHub-hosted runners — no tokens required.

## Features

- **Lockfile-only scanning** — every component has an exact, pinned, auditable version (never manifest ranges)
- **Multi-ecosystem support** — JavaScript/TypeScript (npm, yarn, pnpm, bun) and Python (pip, Poetry, Pipenv)
- **Monorepo-friendly** — recursively detects lockfiles in nested subdirectories
- **Reproducible** — pinned Syft version for consistent output across runs
- **Vulnerability matching** — queries OSV.dev (Google-operated) for known vulnerabilities in your dependencies
- **Prioritization** — enriches findings with EPSS scores (FIRST API) and CISA KEV status: "which findings do I look at first"
- **Reachability annotation** — labels each finding `imported` / `not-imported` / `unknown` by parsing source imports locally on the runner (annotation only; findings are never removed, suppressed, or downgraded)
- **Security-tab integration** — converts findings to SARIF 2.1.0 and uploads them to GitHub code scanning (opt out with `upload-sarif: 'false'`)
- **Minimal permissions** — the Action itself is read-only + artifact upload; the code-scanning upload (the only optional write) is documented and switchable
- **Rich outputs** — SBOM file path, component count, detected lockfiles, vulnerability counts, scan status, and SARIF stats exposed as action outputs

## Supported Lockfiles

| Ecosystem | Package Manager | Lockfile |
|-----------|----------------|----------|
| JavaScript/TypeScript | npm | `package-lock.json`, `npm-shrinkwrap.json` |
| JavaScript/TypeScript | yarn | `yarn.lock` |
| JavaScript/TypeScript | pnpm | `pnpm-lock.yaml` |
| JavaScript/TypeScript | bun | `bun.lock` |
| Python | pip | `requirements*.txt`, `constraints*.txt` |
| Python | Poetry | `poetry.lock` |
| Python | Pipenv | `Pipfile.lock` |

## Quickstart

Drop these four lines into a job in `.github/workflows/sbom.yml`:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: Odinex/sbom-action@v0
```

That runs with all defaults: lockfile detection, CycloneDX SBOM generation, OSV.dev matching, EPSS/KEV enrichment, artifact uploads, and a SARIF upload to the Security tab.

The SARIF upload needs two things from the consumer repository: the `security-events: write` permission (plus `actions: read` in private repositories) and GitHub code scanning available on its plan — free for public repositories, but private repositories require GitHub Team/Enterprise with Code Security. If your private repository is on a personal Free/Pro plan, set `upload-sarif: 'false'`; every other step still runs and the findings are attached as a workflow artifact (details in [Code Scanning (SARIF)](#code-scanning-sarif)).

## Full example

```yaml
name: SBOM

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 3 * * 1'  # weekly re-scan

# security-events: write is needed only for the SARIF code-scanning upload;
# private repositories also need actions: read. To run at zero write scope
# instead — also the right choice for private repos without GitHub Code
# Security — set `upload-sarif: 'false'` below and use
# `permissions: contents: read` only.
permissions:
  contents: read
  security-events: write

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Odinex/sbom-action@v0   # the published Action
        with:
          path: '.'
          output: 'sbom.cdx.json'
          syft-version: 'v1.54.1'
          scan-vulnerabilities: 'true'   # default: true
          findings-output: 'vulnerabilities.json'
          upload-sarif: 'true'           # default: true — findings appear in the Security tab
```

The Action generates two artifacts (90-day retention):
- `sbom-cyclonedx` — the CycloneDX JSON SBOM
- `vulnerability-findings` — the OSV.dev vulnerability findings JSON

and, when `upload-sarif` is enabled, uploads `findings.sarif` to GitHub code scanning.

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Directory to scan, relative to the repository root | `.` |
| `output` | Path of the CycloneDX JSON SBOM to write | `sbom.cdx.json` |
| `syft-version` | Pinned Syft release to install | `v1.54.1` |
| `source-name` | Name recorded in SBOM metadata (defaults to repository name) | `''` |
| `fail-on-no-lockfile` | Fail the workflow if no supported lockfile is found (`true`/`false`) | `false` |
| `upload-artifact` | Upload artifacts as workflow artifacts (`true`/`false`) | `true` |
| `scan-vulnerabilities` | Query OSV.dev for vulnerabilities in SBOM components (`true`/`false`) | `true` |
| `findings-output` | Path of the vulnerability findings JSON to write | `vulnerabilities.json` |
| `osv-api-url` | OSV API base URL (override for testing or self-hosted OSV) | `https://api.osv.dev` |
| `fail-on-osv-error` | Fail the workflow if the OSV API is unreachable (`true`/`false`) | `false` |
| `epss-api-url` | EPSS API base URL (override for testing or self-hosted FIRST API) | `https://api.first.org` |
| `kev-feed-url` | CISA KEV feed URL (override for testing or mirrors) | CISA `known_exploited_vulnerabilities.json` |
| `assess-reachability` | Annotate each finding with import-level reachability by parsing source imports locally (`true`/`false`); annotation only — never removes findings | `true` |
| `sarif-output` | Path of the SARIF 2.1.0 code-scanning report to write | `findings.sarif` |
| `upload-sarif` | Upload the SARIF report to GitHub code scanning (`true`/`false`) | `true` |
| `telemetry` | Report one anonymous usage event per run — see [Usage Telemetry (opt-out)](#usage-telemetry-opt-out) | `true` |
| `telemetry-url` | Telemetry collector base URL (override for testing or self-hosting) | `https://telemetry.databoast.com` |

## Outputs

| Output | Description |
|--------|-------------|
| `sbom-file` | Path to the generated CycloneDX SBOM |
| `components-count` | Number of library components in the SBOM |
| `lockfiles-found` | Comma-separated list of supported lockfiles detected |
| `vulnerabilities-found` | Number of unique vulnerabilities matched, counted by canonical key (all aliases of one CVE count once) |
| `findings-file` | Path to the generated vulnerability findings JSON |
| `components-with-vulns` | Number of components with at least one vulnerability |
| `scan-status` | Scan completeness: `complete` or `partial` |
| `kev-count` | Number of findings listed in the CISA KEV catalog |
| `high-epss-count` | Number of findings with EPSS percentile >= 0.90 (90th percentile) |
| `reachability-imported-count` | Number of findings annotated reachability level `imported` |
| `reachability-not-imported-count` | Number of findings annotated reachability level `not-imported` |
| `reachability-unknown-count` | Number of findings annotated reachability level `unknown` |
| `sarif-file` | Path to the generated SARIF 2.1.0 code-scanning report |
| `sarif-results` | Number of results in the generated SARIF report |

## Code Scanning (SARIF)

When vulnerability scanning is enabled, the findings are also converted to a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) report and (by default) uploaded to GitHub code scanning via [`github/codeql-action/upload-sarif@v3`](https://github.com/github/codeql-action), so alerts appear where developers already look — the repository's **Security** tab.

**Permissions**: code scanning is the only part of the Action that needs write scope. The consumer workflow must grant:

```yaml
permissions:
  contents: read          # the Action itself is read-only
  security-events: write  # required for the SARIF upload only
  actions: read           # additionally required in private repositories
```

The extra `actions: read` matters in private repositories: without it the upload is rejected with `Resource not accessible by integration` (see [github/codeql-action#2117](https://github.com/github/codeql-action/issues/2117)).

**Availability**: on GitHub, code scanning — including third-party SARIF uploads — is free for **public** repositories; **private** repositories require GitHub Team or Enterprise with **Code Security** enabled ([GitHub docs](https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning)). On a personal Free/Pro plan there is no setting that enables it for a private repository — the upload fails with `Code scanning is not enabled for this repository` ([GitHub docs](https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/private-repository-enablement)). That is a plan limitation, not a permissions problem: no workflow change can fix it.

In that case, keep the workflow read-only and skip the upload:

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@v4
  - uses: Odinex/sbom-action@v0
    with:
      upload-sarif: 'false'
```

With `upload-sarif: 'false'` the upload step is skipped and no write scope is needed, but the rest of the pipeline is unchanged: the SARIF report is still generated and validated (its path is exposed in the `sarif-file` output), and the complete enriched findings JSON is still attached to the run as the `vulnerability-findings` artifact — only the Security-tab upload is omitted.

The SARIF report follows the alias-closure model of the matcher:

- **Rule per canonical vulnerability** — `id` is the canonical key (the deduplicated CVE/GHSA identity), `shortDescription` from the advisory summary, `helpUri` pointing at the advisory. Rule `properties` carry `epss`, `kev`, `osvIds` (all OSV IDs preserved as evidence), and the `lockfile` of the first component that reported the vulnerability.
- **Result per component finding** — one alert per (component, canonical vulnerability), never double-reported for aliased GHSA/CVE records. The artifact is the component's **purl**; result `properties` carry the exact per-finding `lockfile`, `purl`, `component` name, and `version`.
- **Stable fingerprints** — findings carry no source locations, so GitHub cannot compute line-based fingerprints itself. Each result ships `partialFingerprints` = SHA-256 over `purl|canonical key`, keeping alerts deduplicated across runs (an alert persists while the dependency stays vulnerable and disappears after the upgrade).
- **Level mapping** — `databaseSpecificSeverity` `CRITICAL`/`HIGH` → `error`, `MODERATE`/`MEDIUM` → `warning`, `LOW`/`null` → `note`. A `null` severity is valid (PYSEC records often have none) and maps to `note` rather than being dropped; unknown values also map to `note`.
- **Validated before written** — the report is structurally validated against the SARIF 2.1.0 requirements it uses and the script fails loudly on any violation, rather than emitting a malformed log that code scanning would reject opaquely.

## Privacy: What Leaves the Runner

Every outbound data flow, exhaustively:

| Flow | Destination | When | Data |
|---|---|---|---|
| Vulnerability matching | [OSV.dev](https://osv.dev), operated by Google | `scan-vulnerabilities: 'true'` (default) | package purls (name + pinned version) |
| EPSS scores | FIRST EPSS API ([api.first.org](https://api.first.org)) | after matching | CVE identifiers |
| KEV catalog | CISA KEV feed (download only) | after matching | nothing is sent; the feed is fetched |
| Reachability annotation | nowhere — runs entirely on the runner | after enrichment | nothing is sent; source imports are parsed locally and never leave the runner |
| Usage telemetry | `telemetry.databoast.com` (Helsinki, EU) | `telemetry: 'true'` (default) | one anonymous event: counts, lockfile types, salted repo hash |
| SBOM / findings / SARIF | GitHub itself | `upload-artifact` / `upload-sarif` (default) | generated reports |

No source code, no file contents, no repository metadata, and no CI metadata is ever sent to a third party. Every flow is switchable via the inputs table below.

## Data Sent to OSV.dev

When vulnerability scanning is enabled (default), the Action sends **package purls only** (e.g., `pkg:npm/express@4.21.2`) to [OSV.dev](https://osv.dev/), which is operated by Google. **No source code, file contents, or repository metadata is transmitted.**

**Private repositories**: vulnerability matching sends your dependencies' purls (package name + pinned version) to OSV.dev, and CVE identifiers to FIRST for EPSS scores. No source code or file contents ever leave the runner. If that matters for your repository, set `scan-vulnerabilities: 'false'`.

## Usage Telemetry (opt-out)

By default the Action reports **one anonymous event per run** to the project's telemetry collector (`https://telemetry.databoast.com`), measuring the success gate the project set for itself:

> Repeat use = distinct repository hashes with **at least 2 runs per ISO week, sustained over 4 consecutive weeks**.

**What is sent** (fixed schema v1; the collector rejects unknown fields):

| Field | Value |
|-------|-------|
| `schemaVersion` | `1` |
| `eventType` | `"run"` |
| `repoHash` | salted SHA-256 of `owner/repo` — see below |
| `componentsCount` | library components in the SBOM |
| `findingsCount` | unique matched advisories, deduplicated across components (a CVE affecting several components counts once, not once per component) |
| `kevCount` | findings listed in the CISA KEV catalog |
| `lockfileTypes` | detected lockfile types, e.g. `["npm", "pip"]` (max 8) |
| `scanStatus` | `complete` or `partial` |
| `ts` | UTC timestamp |

**Skipped steps**: the event is sent even when vulnerability scanning is disabled (`scan-vulnerabilities: 'false'`) or an earlier step did not run — SBOM-only usage is still usage of the Action. In that case the counts are `0` and `scanStatus` is `partial`, which by schema-v1 definition means *anything short of a fully completed scan* — including a scan that never ran. There is deliberately no separate "disabled" state: schema v1 (frozen on the collector) accepts only `complete`/`partial`, and suppressing scan-disabled runs would bias the repeat-use gate metric.

**What is never sent**: repository name, source code, file contents, dependency names or purls, CI metadata (actor, branch, commit), IP addresses. The collector stores no IPs and keeps no access logs.

**Pseudonymization, stated honestly**: `repoHash` is SHA-256 over a fixed, published salt (`odinex-sbom-telemetry-v1`) and the `owner/repo` string. A salted hash is **pseudonymous, not anonymous** — anyone who knows a repo name and this salt can compute its hash. The salt is published rather than hidden because the client ships to every consumer anyway; hiding it would be security-by-obscurity, not anonymity. If you need hard anonymity, opt out.

**Opt out** — either works, no questions asked:

- set the Action input `telemetry: 'false'`, or
- set the `DO_NOT_TRACK` environment variable in the job (any value other than `0`/`false`/`no`).

**Where the data lives**: a single server in Helsinki, EU (Hetzner), behind Caddy with TLS; a direct DNS record, no CDN or other third party in the data path. The collector implementation and deployment runbook are maintained privately by the project; the schema table above is the complete client-side data flow. The client is fail-open — telemetry problems can never fail your build — and the script is a no-op outside GitHub Actions.

## Findings File Format

The `vulnerabilities.json` file contains:

```json
{
  "generatedAt": "2026-10-16T22:07:50+03:00",
  "source": {
    "sbom": "sbom.cdx.json",
    "sbomHash": "sha256:..."
  },
  "scanStatus": "complete",
  "findings": [
    {
      "component": {
        "bomRef": "pkg:npm/requests@2.31.0?package-id=abc123",
        "purl": "pkg:pypi/requests@2.31.0",
        "name": "requests",
        "version": "2.31.0",
        "lockfile": "/requirements.txt"
      },
      "reachability": {
        "level": "imported",
        "evidence": ["src/app.py"],
        "note": "imported directly via static import"
      },
      "vulnerabilities": [
        {
          "id": "CVE-2024-47081",
          "osvIds": ["GHSA-9hjg-9r4m-mvj7", "PYSEC-2026-1872"],
          "aliases": ["GHSA-9hjg-9r4m-mvj7", "PYSEC-2026-1872"],
          "osvSchemaVersion": "1.9.0",
          "summary": "Requests vulnerable to credential leak on redirect",
          "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}
          ],
          "databaseSpecificSeverity": "MODERATE",
          "detailsFetched": true,
          "references": [
            {"type": "ADVISORY", "url": "https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7"}
          ],
          "affectedRanges": [],
          "epss": {
            "score": 0.0098,
            "percentile": 0.61531,
            "date": "2026-10-16"
          },
          "kev": { "knownExploited": false }
        }
      ]
    }
  ],
  "summary": {
    "componentsScanned": 150,
    "componentsNotScanned": 0,
    "componentsNotScannedList": [],
    "componentsWithVulnerabilities": 12,
    "totalVulnerabilityFindings": 34,
    "uniqueVulnerabilityIds": 28
  }
}
```

### Key properties

- **`scanStatus`**: `complete` (all batches succeeded) or `partial` (one or more batches failed — see `componentsNotScanned`). A partial scan is **never** a clean bill of health — the job summary shows a prominent warning.
- **`generatedAt`**: Sourced from the SBOM's `metadata.timestamp` (not wall clock) — enables byte-identical fixture determinism for ground-truth diffs.
- **`findings[]`**: Lists **only components with at least one match** — clean components are omitted.
- **Global alias closure**: Vulnerabilities are grouped by canonical key computed via connected components (union-find) over the global alias graph:
  - If any CVE aliases exist in the component: **lexicographically smallest CVE alias**
  - Else: **lexicographically smallest of all IDs** in the component (OSV IDs + non-CVE aliases)
  - All OSV IDs preserved in `osvIds` array as evidence. `aliases` contains all non-canonical IDs.
  - This prevents double-reporting when records alias the same CVE, each other, or transitively.
- **`osvSchemaVersion`**: Stored **per-vulnerability** (not top-level) — aliased records can have different schema versions. When merging aliased records, the highest schema version is used.
- **`databaseSpecificSeverity`**: Captured from `database_specific.severity`. **Nullable** — PYSEC records often have no `database_specific.severity` at all; `null` is a valid value.
- **`detailsFetched`**: `false` when any OSV record in the alias group could not be retrieved (fetch/parse failure, 404 withdrawal, or an ID rejected by validation) — `summary`/`severity` may then be based on incomplete advisory data and must not be read as "the advisory has none". `true` means every matched OSV record was fetched. OSV IDs are validated against `^[A-Za-z0-9._-]+$` before being used in the `/v1/vulns/{id}` detail-fetch path.
- **`bomRef`**: Stored **raw** (with `?package-id=...` suffix) — preserves join integrity with the SBOM.
- **`componentsNotScannedList`**: Array of purls for components that failed to scan (batch failure, invalid purl, etc.) — for auditability.
- **`epss`**: `{ score, percentile, date }` from the FIRST EPSS API, or `null`. `score` and `percentile` are on the FIRST API's 0–1 scale. EPSS is CVE-keyed: canonical keys that are CVEs resolve directly; a non-CVE canonical key means no CVE exists anywhere in the alias group (the matcher prefers CVEs as canonical keys), so those findings keep `epss: null` (documented, not an error).
- **`kev`**: `{ knownExploited: true, dueDate, added }` when the vulnerability's CVE is in the CISA KEV catalog, else `{ knownExploited: false }`. Stays `null` when the KEV feed is unreachable — unknown is not the same as not exploited.
- **`reachability`**: `{ level, evidence, note }` — import-level reachability annotation (pipeline step 5). `level` is `imported` (the package is imported by app code, directly or via a transitive chain through SBOM dependency-graph edges), `not-imported` (no import reference and no graph path, with a usable dependency graph for the ecosystem), or `unknown` (default; dynamic `import()`/`require()`/`import_module` with a non-literal argument, unmapped Python modules, unparseable source files, or a missing/unusable dependency graph). `evidence` is a sorted list of repo-relative file paths; `note` is a deterministic human-readable explanation. **Annotation only** — the field never removes, suppresses, or downgrades a finding, so the false-suppression rate is zero by construction. KEV findings carry a note stating that reachability does not affect KEV response obligations, and surface first in the step summary regardless of level.
- **Enrichment determinism caveat**: EPSS updates daily — `epss.date` records the score's date; determinism assertions for the ground-truth dataset must use recorded fixtures (same pattern as `generatedAt`).
- **Enrichment degradation**: EPSS/KEV source unreachable → slots stay `null` + `::warning::`; `scanStatus` is never touched (prioritization loss ≠ scan-integrity loss).
- **`lockfile`**: Comes from `syft:location:0:path` property — full provenance. **Limitation**: only the first location is captured; Syft can emit `syft:location:1:path` etc. when a package appears in multiple lockfiles.
- **Root component exclusion**: The repo's own app package is excluded from scanning (combined rule: name match against `metadata.component.name` OR single graph root — the one component with its own `dependsOn` that nothing depends on) — prevents wasted queries, false positives from name collisions, and unnecessary data transmission.
- **Known behavior — multi-lockfile root packages**: with several lockfiles (e.g. `bun.lock` + `package-lock.json`) each lockfile contributes its own dependency graph, so the single-graph-root guard does not fire and per-lockfile root packages (e.g. the npm workspaces pseudo-root) are only excluded when their name matches `metadata.component.name`. In practice they are usually version-less, so local purl pre-validation filters them (surfaced in `componentsNotScannedList`) before anything is sent to OSV. Excluding per-lockfile graph roots was evaluated against the dual-lockfile test SBOM and declined: Syft's per-lockfile dependency graphs are partial (46 apparent "roots", nearly all genuine direct dependencies), so a graph-based exclusion would deterministically drop real components from the scan — the fail-open direction is to query them.
- **Deterministic**: Findings sorted by `component.purl` then `vulnerabilities[].id`.

## Running Locally

The scripts work outside GitHub Actions. **Prerequisites**: `jq` (SBOM generation) and Python 3 (vulnerability matching) must be installed; both are preinstalled on GitHub-hosted runners.

```bash
# Generate SBOM (requires Syft: https://github.com/anchore/syft/releases)
export SYFT_BIN=syft
INPUT_PATH=. \
INPUT_OUTPUT=sbom.cdx.json \
INPUT_SOURCE_NAME=my-project \
bash scripts/generate-sbom.sh

# Match vulnerabilities against OSV.dev
INPUT_SBOM_FILE=sbom.cdx.json \
INPUT_FINDINGS_OUTPUT=vulnerabilities.json \
INPUT_OSV_API_URL=https://api.osv.dev \
python3 scripts/match-vulnerabilities.py

# Enrich findings with EPSS scores and CISA KEV status
INPUT_FINDINGS_FILE=vulnerabilities.json \
python3 scripts/enrich-vulnerabilities.py

# Annotate findings with import-level reachability (local-only)
INPUT_FINDINGS_FILE=vulnerabilities.json \
INPUT_SBOM_FILE=sbom.cdx.json \
INPUT_SOURCE_PATH=. \
python3 scripts/annotate-reachability.py

# Convert findings to SARIF 2.1.0 (upload is a separate CI concern)
INPUT_FINDINGS_FILE=vulnerabilities.json \
INPUT_SARIF_OUTPUT=findings.sarif \
python3 scripts/findings-to-sarif.py

# Verify output
jq '.summary, .scanStatus' vulnerabilities.json
jq '.findings[] | select(.component.name == "requests")' vulnerabilities.json
jq '.runs[0].results | length' findings.sarif
```

## Project Structure

```
.
├── action.yml                          # Composite action definition
├── README.md                           # This file
├── LICENSE                             # Apache-2.0
├── NOTICE                              # Upstream attribution (Syft, OSV.dev, EPSS, CISA KEV)
├── scripts/
│   ├── generate-sbom.sh                # Lockfile detection + Syft invocation
│   ├── match-vulnerabilities.py        # OSV.dev vulnerability matching (3-phase)
│   ├── enrich-vulnerabilities.py       # EPSS (FIRST API) + CISA KEV enrichment
│   ├── annotate-reachability.py        # Import-level reachability annotation (local-only)
│   ├── findings-to-sarif.py            # SARIF 2.1.0 conversion for code scanning
│   ├── telemetry.py                   # Opt-out usage telemetry client
│   ├── test_telemetry.py              # fixture tests for the telemetry contract
│   ├── test_match_vulnerabilities.py   # fixture tests for the matching contract (mocked HTTP)
│   ├── test_enrich_vulnerabilities.py  # fixture tests for the enrichment contract
│   ├── test_annotate_reachability.py  # fixture tests for the reachability contract
└── test_findings_to_sarif.py          # fixture tests for the SARIF contract
```

## How It Works

1. **Detect** — recursively finds supported lockfiles in the target directory (excluding `node_modules`, `venv`, `.venv`)
2. **Scan** — invokes Syft with explicit cataloger selection (`javascript-lock-cataloger`, `python-package-cataloger`) to produce a clean, reproducible CycloneDX 1.7 JSON SBOM
3. **Match** — queries OSV.dev in three phases:
   - **Phase 1 (batch)**: `POST /v1/querybatch` matches components by pinned version (purl-native, 1000-query chunks)
   - **Phase 2 (detail)**: `GET /v1/vulns/{id}` fetches full advisory records (on-disk dedup by OSV ID)
   - **Phase 3 (alias closure)**: Global union-find over the alias graph deduplicates vulnerabilities by canonical key (lexicographically smallest CVE alias, or smallest of all IDs if no CVE)
4. **Enrich** — fills the reserved `epss`/`kev` slots per vulnerability (separate step, so every step's input/output stays inspectable):
   - **EPSS**: FIRST API batch endpoint (~100 CVEs per call) — `epss.date` recorded for determinism
   - **KEV**: single CISA feed download per run, in-memory lookup by CVE ID
   - Source unreachable → slots stay `null` + `::warning::`; `scanStatus` is never touched
5. **Assess** — annotates each finding with import-level reachability (separate step, local-only):
   - Parses `import`/`require`/dynamic `import()` statements across repo source on the runner (JavaScript/TypeScript via regex, Python via the `ast` module)
   - Maps module specifiers to packages (Python import-name ≠ dist-name cases handled: `bs4` → `beautifulsoup4`, `PIL` → `Pillow`, etc.), then walks the SBOM dependency graph for transitive chains
   - Adds `reachability: { level, evidence, note }` per finding — `imported` / `not-imported` / `unknown`; dynamic imports with non-literal arguments, unmapped modules, unparseable files, and missing/unusable dependency graphs all degrade to `unknown` (fail-secure)
   - **Annotation only** — no finding is ever removed, suppressed, or downgraded; KEV findings surface first in the step summary regardless of level; source never leaves the runner
6. **Convert** — emits a SARIF 2.1.0 report (one rule per canonical vulnerability, one result per component finding, stable partial fingerprints for cross-run dedup, validated against the 2.1.0 requirements before it is written) and uploads it to code scanning when `upload-sarif` is enabled
7. **Report** — writes findings JSON, writes a summary to the GitHub Actions job summary (findings table sorted by EPSS percentile descending, KEV rows flagged ⚠️), and uploads both SBOM and findings as artifacts

Every component in the SBOM carries a `syft:location:0:path` property pointing to the exact lockfile it was derived from — full provenance for auditability.

## Design Decisions

- **Composite action** (not Docker) — faster startup, Syft installs as a pinned static binary in seconds
- **Explicit cataloger selection** — keeps the SBOM free of noise (binaries, OS packages) and comparable across runs
- **Lockfiles only** — `package.json` or `pyproject.toml` ranges are never scanned; only pinned lockfile catalogers are enabled
- **Fail-open by default** — unsupported repos warn but exit 0, so org-wide adoption via `.github` reuse can't break unrelated builds
- **Purl-native OSV queries** — the pinned version lives in the purl; no separate `version` field (the API rejects both)
- **Asymmetric HTTP timeouts** — `--max-time 90` for batch POSTs, `--max-time 30` for detail GETs; hung connections fail fast
- **HTTP status discrimination** — 404 → skip (withdrawn), 429/5xx → retry with backoff (max 3 retries, 1s/2s/4s)
- **Explicit SARIF fingerprints** — dependency findings have no source locations, so GitHub cannot derive fingerprints; a SHA-256 over `purl|canonical key` keeps code-scanning alerts stable across runs
- **Optional write scope** — the Action stays read-only; the code-scanning upload is the only step needing `security-events: write`, it is documented in the quickstart, and `upload-sarif: 'false'` restores zero write scope
- **No filtering** — raw matching only; prioritization (EPSS/KEV) and relevance (reachability) are separate pipeline steps
- **Reachability annotates only** — the step adds a `reachability` field and never removes, suppresses, or downgrades a finding, so the false-suppression rate is zero by construction; the iron rule (never downgrade a vulnerability without deterministic evidence) keeps all uncertainty at `unknown`, and function-level AST analysis stays phase-2 (OSV's machine-readable vulnerable-symbol data is Go-only; npm/PyPI coverage is near zero)
- **Local-only reachability** — source imports are parsed on the runner with zero network calls; nothing leaves the runner in this step (see the privacy table)
- **Opt-out telemetry, fail-open** — one anonymous event per run (counts, lockfile types, salted repo hash); `telemetry: 'false'` or `DO_NOT_TRACK` disables it; the step uses `always()` so failed runs still count honestly as `partial`, and telemetry problems can never fail the build

## License

Apache License 2.0 — see [LICENSE](LICENSE). Upstream attribution (Syft, OSV.dev, EPSS, CISA KEV) is in [NOTICE](NOTICE).
