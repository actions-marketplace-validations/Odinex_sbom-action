#!/usr/bin/env bash
#
# generate-sbom.sh — CycloneDX SBOM generation via Syft (phase 1 of the roadmap).
#
# Scope (v0): JavaScript/TypeScript via package-lock.json / npm-shrinkwrap.json /
# yarn.lock / pnpm-lock.yaml / bun.lock, and Python via requirements*.txt /
# poetry.lock / Pipfile.lock. Only pinned, lockfile-derived packages are
# reported — never ranges from manifests — so every component has an exact,
# auditable version.
#
# Environment (set by action.yml, or manually for local runs):
#   INPUT_PATH                  directory to scan (default: .)
#   INPUT_OUTPUT                output file (default: sbom.cdx.json)
#   INPUT_SOURCE_NAME           SBOM metadata name (default: directory basename)
#   INPUT_FAIL_ON_NO_LOCKFILE   'true' to fail when no supported lockfile exists
#   SYFT_BIN                    syft binary path (default: syft)

set -euo pipefail

SCAN_PATH="${INPUT_PATH:-.}"
OUTPUT="${INPUT_OUTPUT:-sbom.cdx.json}"
SOURCE_NAME="${INPUT_SOURCE_NAME:-$(basename "$(cd "${SCAN_PATH}" && pwd)")}"
FAIL_ON_NO_LOCKFILE="${INPUT_FAIL_ON_NO_LOCKFILE:-false}"
SYFT_BIN="${SYFT_BIN:-syft}"

# Lockfile scope kept deliberately narrow per the roadmap: npm, yarn, pnpm, bun,
# pip requirements, Poetry. Detection also recurses into subdirectories so
# monorepos and microservice layouts work without configuration.
detect_lockfiles() {
  local found=()
  while IFS= read -r -d '' file; do
    case "$(basename "${file}")" in
      package-lock.json|npm-shrinkwrap.json) found+=("npm:${file}") ;;
      yarn.lock)                            found+=("yarn:${file}") ;;
      pnpm-lock.yaml)                       found+=("pnpm:${file}") ;;
      bun.lock)                             found+=("bun:${file}") ;;
      poetry.lock)                          found+=("poetry:${file}") ;;
      Pipfile.lock)                         found+=("pipenv:${file}") ;;
      *) case "$(basename "${file}")" in requirements*.txt|constraints*.txt) found+=("pip:${file}") ;; esac ;;
    esac
  done < <(find "${SCAN_PATH}" -type f \
              \( -name 'package-lock.json' -o -name 'npm-shrinkwrap.json' \
                 -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' \
                 -o -name 'bun.lock' \
                 -o -name 'poetry.lock' -o -name 'Pipfile.lock' \
                 -o -name 'requirements*.txt' -o -name 'constraints*.txt' \) \
              -not -path '*/node_modules/*' -not -path '*/.venv/*' -not -path '*/venv/*' \
              -print0)
  # printf reuses its format when given no arguments, which would emit a
  # phantom empty line (and a false "1 lockfile detected") on empty results.
  if [ "${#found[@]}" -gt 0 ]; then
    printf '%s\n' "${found[@]}"
  fi
}

echo "::group::Detecting supported lockfiles in ${SCAN_PATH}"
mapfile -t LOCKFILES < <(detect_lockfiles || true)
echo "${#LOCKFILES[@]} lockfile(s) detected"
printf '  %s\n' "${LOCKFILES[@]:-}"
echo "::endgroup::"

if [ "${#LOCKFILES[@]}" -eq 0 ]; then
  echo "::warning::No supported lockfile found (npm/yarn/pnpm/bun, requirements/poetry)."
  if [ "${FAIL_ON_NO_LOCKFILE}" = "true" ]; then
    exit 1
  fi
  exit 0
fi

# Governance signal: multiple JavaScript lockfiles in one tree mean two package
# managers can pin different versions of the same package (e.g. bun.lock pinning
# @babel/generator@7.29.7 while package-lock.json pins @7.29.8). The SBOM then
# contains both inventories, and a vulnerability verdict against one of them may
# not describe what actually ships. Surface it loudly instead of silently merging.
JS_LOCKFILE_COUNT=$(printf '%s\n' "${LOCKFILES[@]}" | cut -d: -f1 | grep -cE '^(npm|yarn|pnpm|bun)$' || true)
if [ "${JS_LOCKFILE_COUNT}" -gt 1 ]; then
  JS_TOOLS=$(printf '%s\n' "${LOCKFILES[@]}" | cut -d: -f1 \
              | grep -E '^(npm|yarn|pnpm|bun)$' | sort -u | paste -sd, -)
  echo "::warning::Multiple JavaScript lockfiles found (${JS_TOOLS}). Different package managers can pin different versions of the same package; the SBOM lists both inventories and vulnerability verdicts may be ambiguous. Standardize on one package manager (commit one lockfile) so the SBOM reflects a single authoritative inventory."
  MULTI_JS_LOCKFILES="true"
fi

# Only the two catalogers in scope. Explicit selection keeps the SBOM free of
# unrelated noise (e.g. binary, image or OS packages) and keeps results
# comparable across runs — both matter for the ground-truth dataset later.
echo "::group::Generating CycloneDX SBOM with Syft"
"${SYFT_BIN}" scan "dir:${SCAN_PATH}" \
  --select-catalogers "+javascript-lock-cataloger,+python-package-cataloger" \
  --source-name "${SOURCE_NAME}" \
  -o "cyclonedx-json=${OUTPUT}"
echo "::endgroup::"

COMPONENTS=$(jq '[.components[]? | select(.type == "library")] | length' "${OUTPUT}")
LOCKFILE_LIST=$(printf '%s\n' "${LOCKFILES[@]}" | cut -d: -f1 | paste -sd, -)

# Components attributed to each lockfile — provenance for the count above, and
# the basis for spotting inventory drift between coexisting lockfiles.
LOCKFILE_COUNTS=$(jq -r '
  [ .components[]? | select(.type == "library")
    | (.properties[]? | select(.name == "syft:location:0:path") | .value) ]
  | group_by(.)
  | map("\(length) \(.[0])")
  | .[]
' "${OUTPUT}" || true)

echo "SBOM written to ${OUTPUT} — ${COMPONENTS} library components"
echo "Components per lockfile:"
while IFS= read -r line; do
  echo "  ${line}"
done <<< "${LOCKFILE_COUNTS}"

# Outputs for downstream steps (vulnerability matching, EPSS/KEV enrichment,
# reachability) and for the workflow job summary.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "sbom-file=${OUTPUT}"
    echo "components-count=${COMPONENTS}"
    echo "lockfiles-found=${LOCKFILE_LIST}"
  } >> "${GITHUB_OUTPUT}"
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## CycloneDX SBOM"
    echo ""
    echo "| Item | Value |"
    echo "| --- | --- |"
    echo "| Components | ${COMPONENTS} |"
    echo "| Lockfiles | ${LOCKFILE_LIST} |"
    echo "| Output | \`${OUTPUT}\` |"
    echo "| Generator | $(${SYFT_BIN} version -o json | jq -r '"syft " + .version') |"
    echo ""
    echo "Components per lockfile:"
    echo ""
    echo '```'
    while IFS= read -r line; do
      echo "${line}"
    done <<< "${LOCKFILE_COUNTS}"
    echo '```'
    if [ "${MULTI_JS_LOCKFILES:-}" = "true" ]; then
      echo ""
      echo "⚠️ Multiple JavaScript lockfiles detected — different package managers can pin different versions of the same package. The SBOM lists both inventories; standardize on one package manager so verdicts map to a single authoritative inventory."
    fi
  } >> "${GITHUB_STEP_SUMMARY}"
fi