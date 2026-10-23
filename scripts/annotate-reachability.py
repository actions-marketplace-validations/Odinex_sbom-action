#!/usr/bin/env python3
"""annotate-reachability.py — import-level reachability annotation (v0).

Pipeline step 5 (SBOM → OSV match → enrich → reachability → SARIF).
Reads the findings JSON written by the earlier steps, parses the
repository's own source code LOCALLY, and annotates each finding entry
in place with a `reachability` object:

  {"level": "imported" | "not-imported" | "unknown",
   "evidence": ["src/app.ts"],      # sorted, repo-relative file paths
   "note": "..."}                   # deterministic, human-readable

v0 ANNOTATES ONLY — findings are never removed, suppressed, or
downgraded, so the false-suppression rate is zero by construction.
All uncertainty stays "unknown" (iron rule: never downgrade a
vulnerability without deterministic evidence).

Classification (fail-secure — the contract is documented in this
repository's README, "How It Works" step 5 and "Findings File Format"):
  imported       direct import in repo source (static, or dynamic with
                 a literal specifier), or reachable from a
                 directly-imported package through SBOM dependency-graph
                 edges (transitive chain)
  not-imported   no direct import + no graph path + no uncertainty
                 trigger + a usable dependency graph for the ecosystem
  unknown        everything else (dynamic imports with non-literal
                 specifiers, unmapped Python modules, unparseable files,
                 unsupported ecosystems, missing data, assessment failure)

Privacy: the step parses source code on the runner and makes ZERO
network calls — nothing new leaves the runner. `urllib.parse` is used
only for URL-decoding purl namespaces, never for network I/O.

Environment (set by action.yml, or manually for local runs):
  INPUT_FINDINGS_FILE   findings JSON to annotate in place (default:
                        vulnerabilities.json)
  INPUT_SBOM_FILE       CycloneDX SBOM for dependency-graph edges
                        (optional; absent → no transitive resolution)
  INPUT_SOURCE_PATH     source tree to parse (default: .)

Outputs via $GITHUB_OUTPUT / $GITHUB_STEP_SUMMARY:
  reachability-imported-count, reachability-not-imported-count,
  reachability-unknown-count

Requires only the Python 3 standard library.
"""

import ast
import json
import os
import re
import sys
import urllib.parse

LEVEL_IMPORTED = "imported"
LEVEL_NOT_IMPORTED = "not-imported"
LEVEL_UNKNOWN = "unknown"
LEVELS = (LEVEL_IMPORTED, LEVEL_NOT_IMPORTED, LEVEL_UNKNOWN)

JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
PY_EXTENSION = ".py"
EXCLUDED_DIR_NAMES = {"node_modules", "venv", ".venv", ".git"}
MAX_TRIGGER_REASONS_IN_NOTE = 5

# Known import-name != dist-name cases (module -> candidate distributions).
# Small by design, one-line additions (the Bun lesson: scope lists are
# wrong; keep additions one-line). Keys match the top-level module name
# as it appears in the import statement; values are PEP 503-normalized
# at comparison time.
PY_MODULE_TO_DISTS = {
    "attr": ["attrs"],
    "bs4": ["beautifulsoup4"],
    "cv2": ["opencv-python"],
    "Crypto": ["pycryptodome", "pycryptodomex"],
    "dateutil": ["python-dateutil"],
    "dotenv": ["python-dotenv"],
    "jwt": ["PyJWT"],
    "OpenSSL": ["pyOpenSSL"],
    "PIL": ["Pillow"],
    "skimage": ["scikit-image"],
    "sklearn": ["scikit-learn"],
    "yaml": ["PyYAML"],
}

PY_STDLIB = frozenset(getattr(sys, "stdlib_module_names", ()))

JS_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster",
    "console", "constants", "crypto", "dgram", "diagnostics_channel",
    "dns", "domain", "events", "fs", "http", "http2", "https",
    "inspector", "module", "net", "os", "path", "perf_hooks", "process",
    "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "sys", "timers", "tls", "trace_events", "tty",
    "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
}

# Conservative file-level scan (stdlib regex, no parser dependency on the
# runner): recognized forms are trusted positive evidence. Multi-line
# import clauses are handled by [\s] in the clause classes; `import` seen
# inside strings/comments can only inflate a verdict (the harmless
# direction for an annotation-only step) and never creates one.
JS_IMPORT_FROM_RE = re.compile(
    r"\bimport\s+[\w$*{},\s]*?\s*from\s*['\"]([^'\"\n]+)['\"]")
JS_IMPORT_BARE_RE = re.compile(r"\bimport\s*['\"]([^'\"\n]+)['\"]")
JS_EXPORT_FROM_RE = re.compile(
    r"\bexport\s+[^;'\"\n]*?from\s*['\"]([^'\"\n]+)['\"]")
JS_REQUIRE_RE = re.compile(r"\brequire\s*\(\s*['\"]([^'\"\n]+)['\"]\s*\)")
JS_DYNAMIC_LITERAL_RE = re.compile(
    r"\bimport\s*\(\s*['\"]([^'\"\n]+)['\"]\s*\)")
# import(x) / require(x) with a non-literal first argument (variable,
# template literal, concatenation) — the loaded module is not statically
# knowable. A string literal right after the paren is the only benign case.
JS_DYNAMIC_TRIGGER_RE = re.compile(r"\b(?:import|require)\s*\(\s*(?!['\"])")

KEV_NOTE_SUFFIX = ("; CISA KEV listed — reachability does not affect "
                   "KEV response obligations")


def log(msg):
    print(f"[annotate-reachability] {msg}")


def warn(msg):
    print(f"::warning::{msg}")


def pep503_normalize(name):
    """PEP 503 normalization: `Flask`/`flask`/`fl_ask` -> `flask`."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_purl(purl):
    """Return (ecosystem, package_name) or None. npm scopes are decoded
    (`pkg:npm/%40scope/pkg@1.0.0` -> `("@scope/pkg")`)."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[len("pkg:"):]
    body = body.split("?", 1)[0].split("#", 1)[0]
    parts = body.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    eco = parts[0]
    name_part = "/".join(parts[1:])
    name, _, _version = name_part.rpartition("@")
    if not name:
        name = name_part
    if eco == "npm":
        segments = [urllib.parse.unquote(s) for s in name.split("/")]
        if segments[0].startswith("@") and len(segments) >= 2:
            package = f"{segments[0]}/{segments[1]}"
        else:
            package = segments[0]
    else:
        package = urllib.parse.unquote(name)
    return eco, package


def js_specifier_to_package(specifier):
    """Bare specifier -> npm package name; None for app-internal, URL,
    data, builtin, or node:-prefixed specifiers (never package refs)."""
    if not specifier:
        return None
    if specifier.startswith((".", "/", "data:", "node:")):
        return None
    if "://" in specifier:
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        if len(parts) < 2:
            return None
        return f"{parts[0]}/{parts[1]}"
    package = parts[0]
    if package in JS_BUILTINS:
        return None
    return package


def scan_js_text(text):
    """Return (packages, dynamic_packages, trigger_fired)."""
    packages, dynamic = set(), set()
    for regex in (JS_IMPORT_FROM_RE, JS_IMPORT_BARE_RE, JS_EXPORT_FROM_RE,
                  JS_REQUIRE_RE):
        for match in regex.finditer(text):
            package = js_specifier_to_package(match.group(1))
            if package:
                packages.add(package)
    for match in JS_DYNAMIC_LITERAL_RE.finditer(text):
        package = js_specifier_to_package(match.group(1))
        if package:
            dynamic.add(package)
    trigger = JS_DYNAMIC_TRIGGER_RE.search(text) is not None
    return packages, dynamic, trigger


def scan_py_text(text):
    """Return (modules, dynamic_modules, trigger_fired).

    Raises SyntaxError on unparseable source (the caller treats it as an
    uncertainty trigger). Non-literal __import__/import_module arguments
    fire the trigger; literal arguments count as import evidence.
    """
    modules, dynamic = set(), set()
    trigger = False
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top:
                    modules.add(top)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # relative import — app-local
            if node.module:
                top = node.module.split(".")[0]
                if top:
                    modules.add(top)
        elif isinstance(node, ast.Call):
            func = node.func
            is_dunder_import = (isinstance(func, ast.Name)
                                and func.id == "__import__")
            is_import_module = (isinstance(func, ast.Attribute)
                                and func.attr == "import_module")
            if is_dunder_import or is_import_module:
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    top = arg.value.split(".")[0]
                    if top:
                        dynamic.add(top)
                else:
                    trigger = True
    return modules, dynamic, trigger


class SourceScan:
    """Import evidence + uncertainty triggers parsed from local source."""

    def __init__(self):
        self.empty = True                      # no parsable source at all
        self.app_local = set()                 # app-local top-level module names
        # npm: package -> {files}; js dynamic-literal imports kept separate
        self.js_packages = {}                  # static/require/export evidence
        self.js_dynamic = {}                   # import('literal') evidence
        self.js_trigger_files = []             # files with non-literal import()
        self.py_modules = {}                   # module -> {files}
        self.py_dynamic = {}                   # module -> {files} (literal arg)
        self.py_trigger_files = []             # non-literal import_module etc.
        self.py_parse_failures = []            # unparseable .py files


def scan_source(source_path):
    """Walk the source tree deterministically and parse JS/Python imports."""
    scan = SourceScan()
    if not os.path.isdir(source_path):
        warn(f"Source path not found: {source_path} — reachability "
             "degrades to unknown where source evidence is required")
        return scan
    source_root = os.path.normpath(source_path)
    for root, dirs, files in os.walk(source_path):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIR_NAMES)
        dir_name = os.path.basename(root)
        if ("__init__.py" in files and root != source_root and dir_name):
            scan.app_local.add(dir_name)
        for fname in sorted(files):
            path = os.path.join(root, fname)
            rel = os.path.relpath(path, source_root).replace(os.sep, "/")
            ext = os.path.splitext(fname)[1]
            if ext in JS_EXTENSIONS:
                scan.empty = False
                try:
                    with open(path, "r", encoding="utf-8",
                              errors="replace") as f:
                        text = f.read()
                except OSError as e:
                    warn(f"Unreadable JS/TS source file skipped: {rel} ({e})")
                    scan.js_trigger_files.append(rel)
                    continue
                packages, dynamic, trigger = scan_js_text(text)
                for pkg in packages:
                    scan.js_packages.setdefault(pkg, set()).add(rel)
                for pkg in dynamic:
                    scan.js_dynamic.setdefault(pkg, set()).add(rel)
                if trigger:
                    scan.js_trigger_files.append(rel)
            elif ext == PY_EXTENSION:
                scan.empty = False
                stem = os.path.splitext(fname)[0]
                if stem and stem != "__init__":
                    scan.app_local.add(stem)
                try:
                    with open(path, "r", encoding="utf-8",
                              errors="replace") as f:
                        text = f.read()
                except OSError as e:
                    warn(f"Unreadable Python source file skipped: {rel} ({e})")
                    scan.py_trigger_files.append(rel)
                    continue
                try:
                    modules, dynamic, trigger = scan_py_text(text)
                except SyntaxError:
                    warn(f"Unparseable Python source file skipped: {rel}")
                    scan.py_parse_failures.append(rel)
                    continue
                for module in modules:
                    scan.py_modules.setdefault(module, set()).add(rel)
                for module in dynamic:
                    scan.py_dynamic.setdefault(module, set()).add(rel)
                if trigger:
                    scan.py_trigger_files.append(rel)
    return scan


def js_direct_evidence(scan):
    """(files_by_package, dynamic_only_packages) for npm."""
    files_by_package = {}
    for pkg, files in scan.js_packages.items():
        files_by_package.setdefault(pkg, set()).update(files)
    for pkg, files in scan.js_dynamic.items():
        files_by_package.setdefault(pkg, set()).update(files)
    dynamic_only = {p for p in scan.js_dynamic if p not in scan.js_packages}
    return files_by_package, dynamic_only


def py_module_candidate_dists(module):
    """All distributions a module name could belong to (normalized)."""
    dists = {pep503_normalize(module)}
    dists |= {pep503_normalize(d)
              for d in PY_MODULE_TO_DISTS.get(module, [])}
    return dists


def py_direct_evidence(scan):
    """(files_by_dist, dynamic_only_dists) for pypi, PEP 503-normalized."""
    files_by_dist = {}
    for module, files in scan.py_modules.items():
        for dist in py_module_candidate_dists(module):
            files_by_dist.setdefault(dist, set()).update(files)
    for module, files in scan.py_dynamic.items():
        for dist in py_module_candidate_dists(module):
            files_by_dist.setdefault(dist, set()).update(files)
    static_dists = {d for module in scan.py_modules
                    for d in py_module_candidate_dists(module)}
    dynamic_only = {d for module in scan.py_dynamic
                    for d in py_module_candidate_dists(module)}
    dynamic_only -= static_dists
    return files_by_dist, dynamic_only


def py_unaccounted_modules(scan, sbom_pypi_names):
    """Modules that cannot be attributed to any known distribution:
    not stdlib, not app-local, not in the mapping table, and not
    PEP 503-identical to a distribution in the SBOM inventory — from
    static imports AND literal dynamic imports (importlib.import_module /
    __import__ with a literal string). Each is an unresolvable
    specifier — it could be a finding's package under an unknown
    import name, so it must force `unknown` on negative verdicts."""
    unaccounted = []
    known = {pep503_normalize(n) for n in sbom_pypi_names}
    for module in sorted(set(scan.py_modules) | set(scan.py_dynamic)):
        if module in PY_STDLIB or module in scan.app_local:
            continue
        if module in PY_MODULE_TO_DISTS:
            continue
        if pep503_normalize(module) in known:
            continue
        unaccounted.append(module)
    return unaccounted


class DependencyGraph:
    """SBOM dependency-graph edges, joined on raw bomRefs."""

    def __init__(self):
        self.ref_labels = {}   # ref -> "name@version"
        self.ref_packages = {} # ref -> package (identity used in graph keys)
        self.ref_eco = {}      # ref -> "npm" | "pypi"
        self.pkg_refs = {}     # (eco, package) -> [refs]
        self.adjacency = {}    # ref -> sorted dependsOn refs
        self.usable = {"npm": False, "pypi": False}


def load_graph(sbom):
    graph = DependencyGraph()
    for comp in sbom.get("components") or []:
        if comp.get("type") != "library":
            continue
        ref = comp.get("bom-ref")
        parsed = parse_purl(comp.get("purl"))
        if not ref or not parsed:
            continue
        eco, package = parsed
        if eco not in ("npm", "pypi"):
            continue
        if eco == "pypi":
            package = pep503_normalize(package)
        version = comp.get("version")
        graph.ref_labels[ref] = f"{package}@{version}" if version else package
        graph.ref_packages[ref] = package
        graph.ref_eco[ref] = eco
        graph.pkg_refs.setdefault((eco, package), []).append(ref)
    for dep in sbom.get("dependencies") or []:
        ref = dep.get("ref")
        depends_on = dep.get("dependsOn") or []
        if not ref or not depends_on:
            continue
        graph.adjacency[ref] = sorted(set(depends_on))
        eco = graph.ref_eco.get(ref)
        if eco:
            graph.usable[eco] = True
    for refs in graph.pkg_refs.values():
        refs.sort()
    return graph


def transitive_chains(graph, eco, root_refs):
    """BFS from root refs. Returns {ref: chain} where chain is the list
    of refs from a root (inclusive) to the reachable ref, and the parent
    map for chain reconstruction. Deterministic: sorted traversal."""
    parent = {}
    seen = set(root_refs)
    queue = sorted(root_refs)
    while queue:
        ref = queue.pop(0)
        for dep in graph.adjacency.get(ref, []):
            if dep in seen:
                continue
            seen.add(dep)
            parent[dep] = ref
            queue.append(dep)
    chains = {}
    for ref in seen:
        chain = [ref]
        while chain[-1] in parent:
            chain.append(parent[chain[-1]])
        chain.reverse()
        chains[ref] = chain
    return chains


def _note_reasons_for(scan, eco, graph, unaccounted_py, no_source):
    """Deterministic ordered reasons why `not-imported` is impossible."""
    reasons = []
    if no_source:
        reasons.append("no source files found under the source path; "
                       "import-level evidence unavailable")
        return reasons
    if eco == "npm":
        for rel in sorted(scan.js_trigger_files):
            reasons.append(f"non-literal dynamic import/require present "
                           f"({rel})")
    elif eco == "pypi":
        for module in unaccounted_py[:MAX_TRIGGER_REASONS_IN_NOTE]:
            reasons.append(f"unmapped Python import '{module}' cannot be "
                           "attributed to a known distribution")
        for rel in sorted(scan.py_trigger_files):
            reasons.append(f"non-literal importlib.import_module/__import__ "
                           f"present ({rel})")
        for rel in sorted(scan.py_parse_failures):
            reasons.append(f"unparseable Python source file ({rel})")
    if eco and not graph.usable.get(eco, False):
        reasons.append(f"no dependency-graph edges available for {eco}; "
                       "transitive loading cannot be excluded")
    return reasons


def _kev_in_finding(finding):
    for vuln in finding.get("vulnerabilities") or []:
        kev = vuln.get("kev")
        if isinstance(kev, dict) and kev.get("knownExploited"):
            return True
    return False


def classify_findings(doc, scan, graph, sbom_pypi_names):
    """Annotate every finding entry in place. Returns per-level counts.

    Annotate only: this function adds the `reachability` object and
    touches nothing else — no finding or vulnerability field is ever
    removed or modified (the acceptance-criterion-3 guarantee).
    """
    js_files, js_dynamic_only = js_direct_evidence(scan)
    py_files, py_dynamic_only = py_direct_evidence(scan)
    unaccounted_py = py_unaccounted_modules(scan, sbom_pypi_names)
    no_source = scan.empty

    # Transitive resolution per ecosystem: roots = every app-imported
    # package's SBOM refs (imported packages without findings still
    # carry their dependency edges — transitivity must flow through them).
    chains = {}
    if not no_source:
        for eco, files_by in (("npm", js_files), ("pypi", py_files)):
            root_refs = []
            for package in sorted(files_by):
                root_refs.extend(graph.pkg_refs.get((eco, package), []))
            if root_refs:
                chains[eco] = transitive_chains(graph, eco, root_refs)

    counts = {LEVEL_IMPORTED: 0, LEVEL_NOT_IMPORTED: 0, LEVEL_UNKNOWN: 0}
    for finding in doc.get("findings") or []:
        component = finding.get("component") or {}
        parsed = parse_purl(component.get("purl"))
        kev = _kev_in_finding(finding)

        if parsed is None:
            level, evidence, note = (
                LEVEL_UNKNOWN, [],
                "reachability assessment unavailable: component has no "
                "parsable purl")
        elif parsed[0] not in ("npm", "pypi"):
            level, evidence, note = (
                LEVEL_UNKNOWN, [],
                f"ecosystem {parsed[0]} not covered by reachability v0")
        else:
            eco, package = parsed
            if eco == "pypi":
                package = pep503_normalize(package)
            files_by = js_files if eco == "npm" else py_files
            dynamic_only = (js_dynamic_only if eco == "npm"
                            else py_dynamic_only)
            direct_files = files_by.get(package) or set()

            if direct_files:
                form = ("dynamic import with literal specifier"
                        if package in dynamic_only
                        else "static import")
                level = LEVEL_IMPORTED
                evidence = sorted(direct_files)
                note = f"imported directly via {form}"
            elif eco in chains:
                ref = component.get("bomRef")
                chain = chains[eco].get(ref)
                if chain and ref in graph.ref_labels:
                    labels = [graph.ref_labels.get(r, r) for r in chain]
                    root_name = graph.ref_packages.get(chain[0], "")
                    root_files = files_by.get(root_name) or set()
                    level = LEVEL_IMPORTED
                    evidence = sorted(root_files)
                    note = ("imported via transitive dependency chain "
                            "(SBOM dependency graph): "
                            + " → ".join(labels))
                else:
                    level, evidence, note = _negative_verdict(
                        scan, eco, graph, unaccounted_py, no_source)
            else:
                level, evidence, note = _negative_verdict(
                    scan, eco, graph, unaccounted_py, no_source)

        if kev:
            note += KEV_NOTE_SUFFIX
        finding["reachability"] = {"level": level,
                                   "evidence": evidence,
                                   "note": note}
        counts[level] += 1
    return counts


def _negative_verdict(scan, eco, graph, unaccounted_py, no_source):
    reasons = _note_reasons_for(scan, eco, graph, unaccounted_py, no_source)
    if reasons:
        return (LEVEL_UNKNOWN, [],
                "no direct import found; " + "; ".join(reasons))
    return (LEVEL_NOT_IMPORTED, [],
            "not imported: no import statement references this package "
            "and no SBOM dependency-graph path connects it to the "
            "app-imported set (import-level evidence, not a runtime "
            "safety claim)")


def annotate_all_unknown(doc, reason):
    for finding in doc.get("findings") or []:
        finding["reachability"] = {"level": LEVEL_UNKNOWN,
                                   "evidence": [],
                                   "note": f"reachability assessment "
                                           f"failed: {reason}"}
    return {LEVEL_IMPORTED: 0, LEVEL_NOT_IMPORTED: 0,
            LEVEL_UNKNOWN: len(doc.get("findings") or [])}


def write_outputs(findings_file, counts):
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"reachability-imported-count="
                    f"{counts[LEVEL_IMPORTED]}\n")
            f.write(f"reachability-not-imported-count="
                    f"{counts[LEVEL_NOT_IMPORTED]}\n")
            f.write(f"reachability-unknown-count="
                    f"{counts[LEVEL_UNKNOWN]}\n")
    log(f"Outputs: reachability-imported-count={counts[LEVEL_IMPORTED]}, "
        f"reachability-not-imported-count={counts[LEVEL_NOT_IMPORTED]}, "
        f"reachability-unknown-count={counts[LEVEL_UNKNOWN]}")


def write_step_summary(doc, counts):
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not step_summary:
        return
    rows = []
    level_order = {LEVEL_IMPORTED: 0, LEVEL_UNKNOWN: 1,
                   LEVEL_NOT_IMPORTED: 2}
    for finding in doc.get("findings") or []:
        reach = finding.get("reachability") or {}
        rows.append((
            0 if _kev_in_finding(finding) else 1,
            level_order.get(reach.get("level"), 1),
            (finding.get("component") or {}).get("purl") or "",
            reach.get("level") or LEVEL_UNKNOWN,
            len(reach.get("evidence") or []),
        ))
    rows.sort()
    with open(step_summary, "a", encoding="utf-8") as f:
        f.write("## Reachability (import-level, v0)\n\n")
        f.write("Annotates only — findings are never removed, suppressed, "
                "or downgraded. `not-imported` is import-level evidence "
                "about application source, not a runtime safety claim.\n\n")
        if not rows:
            f.write("_No findings to annotate._\n\n")
            return
        f.write("| ⚠️ KEV | Level | Component | Evidence files |\n")
        f.write("| --- | --- | --- | --- |\n")
        for kev_rank, _order, purl, level, evidence_count in rows:
            kev_flag = "⚠️ KEV" if kev_rank == 0 else ""
            f.write(f"| {kev_flag} | {level} | `{purl}` | "
                    f"{evidence_count} |\n")
        f.write("\n")


def main():
    findings_file = os.environ.get("INPUT_FINDINGS_FILE",
                                   "vulnerabilities.json")
    sbom_file = os.environ.get("INPUT_SBOM_FILE") or ""
    source_path = os.environ.get("INPUT_SOURCE_PATH", ".")

    log(f"Findings file: {findings_file}")
    log(f"SBOM file: {sbom_file or '(none — no transitive resolution)'}")
    log(f"Source path: {source_path}")
    if not hasattr(sys, "stdlib_module_names"):
        warn("Python < 3.10 detected: sys.stdlib_module_names is "
             "unavailable — stdlib imports will be treated as unmapped "
             "and push verdicts toward unknown (fail-secure; noisier, "
             "never unsafe). GitHub-hosted runners ship 3.10+, so this "
             "affects local runs only")
    if not os.path.isfile(findings_file):
        print(f"::error::Findings file not found: {findings_file}")
        return 1
    try:
        with open(findings_file, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        warn(f"Findings file unreadable ({e}) — reachability annotation "
             "skipped (fail-open)")
        return 0

    findings = doc.get("findings") or []
    log(f"Annotating {len(findings)} finding entries")
    try:
        sbom = None
        sbom_pypi_names = []
        if sbom_file:
            if os.path.isfile(sbom_file):
                with open(sbom_file, "r", encoding="utf-8") as f:
                    sbom = json.load(f)
                for comp in sbom.get("components") or []:
                    parsed = parse_purl(comp.get("purl"))
                    if parsed and parsed[0] == "pypi":
                        sbom_pypi_names.append(parsed[1])
            else:
                warn(f"SBOM file not found: {sbom_file} — transitive "
                     "chains cannot be resolved; verdicts degrade to "
                     "unknown where the dependency graph is required")
        graph = load_graph(sbom) if sbom is not None else DependencyGraph()
        scan = scan_source(source_path)
        if scan.empty:
            warn("No JS/TS or Python source files found — import-level "
                 "evidence unavailable; findings degrade to unknown")
        counts = classify_findings(doc, scan, graph, sbom_pypi_names)
    except Exception as e:  # fail-open: annotate-only, never fail the build
        warn(f"Reachability assessment failed ({type(e).__name__}: {e}) — "
             "all findings annotated unknown")
        counts = annotate_all_unknown(
            doc, f"{type(e).__name__}: {e}")

    # Fail-open output path (Kilocode PR #26 review): a failure while
    # writing the annotated findings, $GITHUB_OUTPUT, or the step
    # summary must never fail the build — the annotation is additive,
    # so downstream steps simply consume the unannotated findings.
    # The annotated file is written via temp + atomic os.replace so a
    # mid-write failure cannot leave a truncated findings file for the
    # SARIF step to choke on.
    tmp_file = findings_file + ".tmp-reachability"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        os.replace(tmp_file, findings_file)
        write_outputs(findings_file, counts)
        write_step_summary(doc, counts)
    except Exception as e:  # fail-open: outputs never fail the build
        try:
            os.remove(tmp_file)
        except OSError:
            pass
        warn(f"Reachability outputs could not be written "
             f"({type(e).__name__}: {e}) — the annotated findings may be "
             f"missing or stale; failing open")
        return 0
    log(f"Annotated findings written to {findings_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
