from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from analyzer.java_graph import JavaGraph, build_java_graph


def compute_all_metrics(
    repo_dir: Path,
    *,
    spec_headers: list[dict],
    mode: str,
    max_graph_depth: int,
) -> dict:
    # Build Java graph (entrypoints, methods, call edges, sinks, security flags)
    graph: JavaGraph | None = None
    java_files = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "target", "build", ".gradle", ".idea"}]
        for fn in files:
            if fn.endswith(".java"):
                java_files.append(str(Path(root) / fn))

    t0 = time.perf_counter()
    if java_files:
        graph = build_java_graph(repo_dir, max_files=None)
    graph_build_sec = time.perf_counter() - t0

    out: dict = {
        "_internal": {
            "java_files": len(java_files),
            "java_graph_build_sec": graph_build_sec,
            "java_graph": {"nodes": graph.nodes_count if graph else 0, "edges": graph.edges_count if graph else 0},
        }
    }

    # Compute each metric ID present in the spec, even if we can only return an approximation.
    ids_in_spec = [h["id"] for h in spec_headers]
    for metric_id in ids_in_spec:
        if metric_id == "A1":
            out["A1"] = metric_A1_ASE(graph)
        elif metric_id == "A2":
            out["A2"] = metric_A2_ECI(graph, max_graph_depth=max_graph_depth)
        elif metric_id == "A3":
            out["A3"] = metric_A3_IET(graph)
        elif metric_id == "B1":
            out["B1"] = metric_B1_IDS(graph, max_graph_depth=max_graph_depth)
        elif metric_id == "B2":
            out["B2"] = metric_B2_PPI(graph, max_graph_depth=max_graph_depth)
        elif metric_id == "B3":
            out["B3"] = metric_B3_MPSP(graph, max_graph_depth=max_graph_depth)
        elif metric_id == "B4":
            out["B4"] = metric_B4_FSS(graph)
        elif metric_id == "C1":
            out["C1"] = metric_C1_TPC(graph, max_graph_depth=max_graph_depth)
        elif metric_id == "C2":
            out["C2"] = metric_C2_ETI(graph)
        elif metric_id == "C3":
            out["C3"] = metric_C3_SFA(graph)
        elif metric_id == "D1":
            out["D1"] = metric_D1_PAD(repo_dir)
        elif metric_id == "D2":
            out["D2"] = metric_D2_TCPD(graph, max_graph_depth=max_graph_depth)
        elif metric_id == "E1":
            out["E1"] = metric_E1_OSDR(repo_dir, mode=mode)
        elif metric_id == "F1":
            out["F1"] = metric_F1_VFCP(repo_dir, graph, mode=mode)
        elif metric_id == "F2":
            out["F2"] = metric_F2_SRP(repo_dir, graph)
        elif metric_id == "M1":
            out["M1"] = metric_M1_topology(graph)
        else:
            out[metric_id] = {"status": "unknown_metric_id"}

    _normalize_metrics(out)
    _compute_aggregate(out)
    return out


# ---------------------------------------------------------------------------
# Нормализация: приведение всех метрик к [0, 1], где 0 = безопасно, 1 = критично.
# ---------------------------------------------------------------------------

_ASE_CAP = 1000
_ECI_CAP = 30.0
_TPC_CAP = 10.0
_PAD_CAP = 4.0
_TCPD_CAP = 10.0


def _normalize_metrics(out: dict) -> None:
    """Нормализует неограниченные метрики и инвертирует метрики с обратной семантикой.

    Изменяет ``out`` на месте. Исходные значения сохраняются в ``raw_*`` полях.
    """
    # --- A1 (ASE): логарифмическая шкала ---
    a1 = out.get("A1")
    if a1 and a1.get("status") == "ok" and a1.get("ASE") is not None:
        raw = a1["ASE"]
        a1["raw_ASE"] = raw
        a1["ASE"] = min(1.0, math.log2(1 + max(0, raw)) / math.log2(1 + _ASE_CAP))

    # --- A2 (ECI): среднее по top-N с линейным cap ---
    a2 = out.get("A2")
    if a2 and a2.get("status") == "ok" and a2.get("top") is not None:
        eci_values = [entry["ECI"] for entry in a2["top"]]
        raw_max = max(eci_values) if eci_values else 0.0
        avg_eci = sum(eci_values) / len(eci_values) if eci_values else 0.0
        a2["raw_ECI_max"] = raw_max
        a2["ECI_avg"] = min(1.0, avg_eci / _ECI_CAP)

    # --- B1 (IDS): инверсия (больше слоёв = безопаснее → 1 - v) ---
    b1 = out.get("B1")
    if b1 and b1.get("status") == "ok" and b1.get("IDS_system") is not None:
        raw = b1["IDS_system"]
        b1["raw_IDS"] = raw
        b1["IDS"] = 1.0 - raw

    # --- B3 (MPSP): инверсия ---
    b3 = out.get("B3")
    if b3 and b3.get("status") == "ok" and b3.get("MPSP_system") is not None:
        raw = b3["MPSP_system"]
        b3["raw_MPSP"] = raw
        b3["MPSP"] = 1.0 - raw

    # --- B4 (FSS): инверсия ---
    b4 = out.get("B4")
    if b4 and b4.get("status") == "ok" and b4.get("FSS") is not None:
        raw = b4["FSS"]
        b4["raw_FSS"] = raw
        b4["FSS"] = 1.0 - raw

    # --- C1 (TPC): линейный cap ---
    c1 = out.get("C1")
    if c1 and c1.get("status") == "ok" and c1.get("TPC_max_consecutive_unsafe_hops") is not None:
        raw = c1["TPC_max_consecutive_unsafe_hops"]
        c1["raw_TPC"] = raw
        c1["TPC"] = min(1.0, raw / _TPC_CAP)

    # --- D1 (PAD): линейный cap ---
    d1 = out.get("D1")
    if d1 and d1.get("status") == "ok" and d1.get("PAD") is not None:
        raw = d1["PAD"]
        d1["raw_PAD"] = raw
        d1["PAD"] = min(1.0, raw / _PAD_CAP)

    # --- D2 (TCPD): линейный cap ---
    d2 = out.get("D2")
    if d2 and d2.get("status") == "ok" and d2.get("TCPD_max_hops_after_last_auth") is not None:
        raw = d2["TCPD_max_hops_after_last_auth"]
        d2["raw_TCPD"] = raw
        d2["TCPD"] = min(1.0, raw / _TCPD_CAP)


# ---------------------------------------------------------------------------
# Агрегированный скор
# ---------------------------------------------------------------------------

# Веса по группам: отражают относительную важность для общей безопасности.
_METRIC_WEIGHTS: dict[str, float] = {
    "A1": 0.08,
    "A2": 0.07,
    "A3": 0.07,
    "B1": 0.10,
    "B2": 0.10,
    "B3": 0.05,
    "B4": 0.05,
    "C1": 0.08,
    "C2": 0.06,
    "C3": 0.08,
    "D1": 0.04,
    "D2": 0.06,
    "E1": 0.06,
    "F1": 0.05,
    "F2": 0.05,
}

# Маппинг: metric_id → ключ с нормализованным [0,1] значением внутри словаря метрики.
_METRIC_SCORE_KEY: dict[str, str] = {
    "A1": "ASE",
    "A2": "ECI_avg",
    "A3": "IET_system",
    "B1": "IDS",
    "B2": "PPI",
    "B3": "MPSP",
    "B4": "FSS",
    "C1": "TPC",
    "C2": "ETI",
    "C3": "SFA",
    "D1": "PAD",
    "D2": "TCPD",
    "E1": "OSDR",
    "F1": "VFCP",
    "F2": "SRP",
}


def _compute_aggregate(out: dict) -> None:
    """Вычисляет взвешенный агрегированный скор по всем доступным метрикам.

    Результат помещается в ``out["aggregate"]``.
    """
    components: dict[str, float] = {}
    notes: list[str] = []
    weight_sum = 0.0
    weighted_sum = 0.0

    for metric_id, weight in _METRIC_WEIGHTS.items():
        block = out.get(metric_id)
        if not block or block.get("status") != "ok":
            continue
        key = _METRIC_SCORE_KEY.get(metric_id)
        if not key:
            continue
        value = block.get(key)
        if value is None:
            continue
        components[metric_id] = value
        weight_sum += weight
        weighted_sum += weight * value

    if weight_sum > 0:
        score = weighted_sum / weight_sum
    else:
        score = None
        notes.append("No metrics available for aggregation.")

    excluded = [
        mid for mid in _METRIC_WEIGHTS
        if mid not in components
    ]
    if excluded:
        notes.append(f"Excluded (unavailable): {', '.join(excluded)}.")

    out["aggregate"] = {
        "score": score,
        "components": components,
        "available": len(components),
        "notes": notes,
    }


def _na(graph: JavaGraph | None, reason: str) -> dict:
    return {"status": "not_available", "reason": reason}


def metric_A1_ASE(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    # Heuristic weights: chosen for prototype, tune later.
    base = 1.0
    mult_string = 1.3
    mult_map_object = 1.5
    mult_no_auth = 1.4
    mult_no_validation = 1.2

    total = 0.0
    per_entry = []
    for ep in graph.entrypoints:
        m = base
        if ep.param_risk == "stringy":
            m *= mult_string
        elif ep.param_risk == "untyped":
            m *= mult_map_object
        if not ep.has_auth:
            m *= mult_no_auth
        if not ep.has_validation:
            m *= mult_no_validation
        total += m
        per_entry.append({"method": ep.method_id, "score": m, "has_auth": ep.has_auth, "has_validation": ep.has_validation})
    return {
        "status": "ok",
        "ASE": total,
        "entrypoints": len(graph.entrypoints),
        "sample": per_entry[:50],
        "notes": ["Heuristic weights; static-only; method call graph is approximate."],
    }


def metric_A2_ECI(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    # ECI = Cognitive_Complexity / (Distance_to_Entry + 1)
    # Distance computed on approximate call graph, bounded by max_graph_depth.
    distances = graph.distance_from_entrypoints(max_depth=max_graph_depth)
    top = []
    for mid, complexity in graph.method_complexity.items():
        d = distances.get(mid)
        if d is None:
            continue
        eci = complexity / (d + 1)
        top.append((eci, mid, complexity, d))
    top.sort(reverse=True)
    return {
        "status": "ok",
        "top": [{"method": mid, "ECI": eci, "complexity": c, "distance": d} for (eci, mid, c, d) in top[:50]],
        "methods_reachable": len(distances),
        "notes": ["Cognitive complexity is an approximation; distances overapprox due to heuristic call edges."],
    }


def metric_A3_IET(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    weighted_sum = 0.0
    weight_total = 0.0
    per = []
    for ep in graph.entrypoints:
        w = {"http": 1.0, "mq": 0.8, "job": 0.5}.get(ep.entry_type, 0.7)
        entropy = {"low": 0.2, "medium": 0.5, "high": 0.8, "very_high": 1.0}.get(ep.entropy_level, 0.5)
        if ep.has_validation:
            entropy *= 0.7
        weighted_sum += entropy * w
        weight_total += w
        per.append({"method": ep.method_id, "entropy": entropy, "weight": w, "type": ep.entry_type})
    iet = (weighted_sum / weight_total) if weight_total else 0.0
    return {"status": "ok", "IET_system": iet, "entrypoints": len(graph.entrypoints), "sample": per[:50]}


def metric_B1_IDS(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    res = graph.defense_in_depth_paths(max_depth=max_graph_depth)
    if res.get("system_min_ratio") is None:
        return {
            "status": "not_available",
            "reason": "no_entry_to_sink_paths",
            "paths_analyzed": res.get("paths_analyzed", 0),
            "notes": ["No entrypoint->sink path found within max_graph_depth."],
        }
    return {
        "status": "ok",
        "IDS_system": res["system_min_ratio"],
        "paths_analyzed": res["paths_analyzed"],
        "min_path": res["min_path"],
        "notes": ["Computed over bounded BFS state space (layers bitmask)."],
    }


def metric_B2_PPI(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    min_dist = graph.min_distance_unauth_to_privileged(max_depth=max_graph_depth)
    if min_dist is None:
        return {"status": "ok", "PPI": 0.0, "min_distance": None, "notes": ["No unauth->privileged path found (within depth)."]}
    return {"status": "ok", "PPI": 1.0 / (min_dist + 1), "min_distance": min_dist}


def metric_B3_MPSP(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    mpsp = graph.path_security_parity(max_depth=max_graph_depth)
    return {"status": "ok", "MPSP_system": mpsp["system_min_ratio"], "worst_operation": mpsp["worst_operation"]}


def metric_B4_FSS(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    return {"status": "ok", **graph.fail_safe_score()}


def metric_C1_TPC(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    return {"status": "ok", **graph.tainted_path_complexity(max_depth=max_graph_depth)}


def metric_C2_ETI(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    return {"status": "ok", **graph.error_transparency_index()}


def metric_C3_SFA(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    return {"status": "ok", **graph.secret_flow_analysis()}


def metric_D1_PAD(repo_dir: Path) -> dict:
    exts = {}
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "target", "build", ".gradle", ".idea"}]
        for fn in files:
            p = Path(root) / fn
            ext = p.suffix.lower()
            if not ext:
                continue
            exts[ext] = exts.get(ext, 0) + 1
    # Languages: extremely rough classification by extensions.
    lang_ext = {
        "java": {".java"},
        "kotlin": {".kt", ".kts"},
        "js": {".js", ".jsx"},
        "ts": {".ts", ".tsx"},
        "python": {".py"},
        "go": {".go"},
        "rust": {".rs"},
        "csharp": {".cs"},
    }
    present = []
    for lang, s in lang_ext.items():
        if any(ext in exts for ext in s):
            present.append(lang)
    boundaries = max(0, len(present) - 1)
    return {
        "status": "ok",
        "languages_present": present,
        "boundaries": boundaries,
        "PAD": float(boundaries),
        "notes": ["Boundary count only; policy-gap weighting requires org-specific security policy model."],
    }


def metric_D2_TCPD(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    return {"status": "ok", **graph.trust_chain_depth(max_depth=max_graph_depth)}


def metric_E1_OSDR(repo_dir: Path, *, mode: str) -> dict:
    # This prototype reports only dependency surface; deep ecosystem health requires external data sources (GH, libs.io, etc.)
    root_pom = repo_dir / "pom.xml"
    if not root_pom.exists():
        return {"status": "ok", "OSDR": None, "notes": ["No pom.xml; E1 not implemented for this build system."]}

    # "Direct" dependencies: approximate by counting <dependency> tags in selected Maven modules.
    meta_file = repo_dir / ".csa" / "mvn-deps-meta.json"
    selected_modules: list[str] = []
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            selected_modules = list(meta.get("modules_selected") or [])
        except json.JSONDecodeError:
            selected_modules = []
    if not selected_modules:
        selected_modules = ["."]

    direct = 0
    for mod in selected_modules:
        pom = (repo_dir / mod / "pom.xml") if mod != "." else root_pom
        if not pom.exists():
            continue
        text = pom.read_text(encoding="utf-8", errors="ignore")
        direct += len(re.findall(r"<dependency>\s*", text))

    res: dict = {
        "status": "ok",
        "direct_dependencies_estimate": direct,
        "direct_modules_considered": selected_modules,
        "OSDR": None,
        "notes": [],
    }
    if mode != "full":
        res["notes"].append("Fast mode: transitive dependency ratio not resolved.")
        return res

    dep_list = repo_dir / ".csa" / "mvn-dependency-list.txt"
    if not dep_list.exists():
        res["notes"].append("No Maven dependency list found (.csa/mvn-dependency-list.txt).")
        return res

    coords: list[str] = []
    ansi = re.compile("\x1b\\[[0-9;]*[A-Za-z]")
    for line in dep_list.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = ansi.sub("", line).strip()
        if not line or line.startswith("[INFO]") or "Downloading" in line:
            continue
        if line.count(":") >= 4:
            coords.append(line)

    total = len(coords)
    transitive = max(0, total - direct)
    trans_ratio = (transitive / total) if total else None
    res.update(
        {
            "dependencies_total_estimate": total,
            "dependencies_transitive_estimate": transitive,
            "transitive_ratio_estimate": trans_ratio,
            # Placeholder composite: start with transitive ratio only.
            "OSDR": trans_ratio,
        }
    )
    res["notes"].append("Prototype: OSDR currently equals transitive_ratio_estimate (ecosystem health not enriched).")
    return res


_JAVA_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_JAVA_DUP_STR_LIT_RE = re.compile(r"\"(?:\\\\.|[^\"\\\\])*\"")
_JAVA_DUP_CHAR_LIT_RE = re.compile(r"'(?:\\\\.|[^'\\\\])+'")
_JAVA_DUP_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_JAVA_DUP_LINE_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)
_JAVA_DUP_HEX_RE = re.compile(r"\b0x[0-9A-Fa-f]+\b")
_JAVA_DUP_NUM_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_JAVA_DUP_TOK_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*|==|!=|<=|>=|&&|\|\||<<|>>>|>>|[-+*/%&|^!~?:=<>.,;(){}\[\]]"
)
_JAVA_KEYWORDS = {
    # Java keywords + common literals
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
    # newer/common
    "record",
    "sealed",
    "permits",
    "var",
    # literals
    "true",
    "false",
    "null",
}


def _is_test_path(path: Path) -> bool:
    parts = [p.lower() for p in path.parts]
    if "src" in parts and "test" in parts:
        return True
    if "test" in parts or "tests" in parts:
        return True
    return False


def _estimate_test_coverage(repo_dir: Path, graph: JavaGraph) -> tuple[float, dict]:
    """Static heuristic: class is considered 'covered' if its simple name appears in test source identifiers."""
    # Collect production classes from graph (exclude test files when the graph provides the flag).
    prod_classes_simple: set[str] = set()
    prod_classes_fqn: set[str] = set()
    for mid, flags in graph.method_flags.items():
        if flags.get("is_test"):
            continue
        cls_fqn = mid.split("#", 1)[0]
        if not cls_fqn:
            continue
        prod_classes_fqn.add(cls_fqn)
        prod_classes_simple.add(cls_fqn.split(".")[-1])

    test_files = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "target", "build", ".gradle", ".idea"}]
        if not _is_test_path(Path(root)):
            continue
        for fn in files:
            if fn.endswith(".java"):
                test_files.append(Path(root) / fn)

    identifiers: set[str] = set()
    max_identifiers = 2_000_000
    bytes_scanned = 0
    max_bytes = 50_000_000  # 50 MB across tests
    for p in test_files:
        if bytes_scanned >= max_bytes:
            break
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        bytes_scanned += len(raw)
        text = raw.decode("utf-8", errors="ignore")
        for ident in _JAVA_IDENT_RE.findall(text):
            identifiers.add(ident)
            if len(identifiers) >= max_identifiers:
                break
        if len(identifiers) >= max_identifiers:
            break

    covered = 0
    for simple in prod_classes_simple:
        if simple in identifiers:
            covered += 1

    total = len(prod_classes_simple)
    estimate = (covered / total) if total else 0.0
    meta = {
        "heuristic": "class simple-name appears in test identifiers",
        "prod_classes": total,
        "covered_classes": covered,
        "test_files_considered": len(test_files),
        "bytes_scanned": bytes_scanned,
        "identifiers_collected": len(identifiers),
    }
    return estimate, meta


def _tokenize_java_for_dup(text: str) -> list[str]:
    # Best-effort normalization for "logical" duplicates:
    # - drop comments
    # - replace literals with placeholders
    # - normalize identifiers to "id" (except keywords)
    if not text:
        return []

    if len(text) < 120:
        return []

    # Strip string/char literals first to avoid confusing comment stripping.
    text = _JAVA_DUP_STR_LIT_RE.sub(" STR ", text)
    text = _JAVA_DUP_CHAR_LIT_RE.sub(" CHR ", text)

    # Strip comments (best-effort).
    text = _JAVA_DUP_BLOCK_COMMENT_RE.sub(" ", text)
    text = _JAVA_DUP_LINE_COMMENT_RE.sub(" ", text)

    # Replace numbers (incl hex) with NUM.
    text = _JAVA_DUP_HEX_RE.sub(" NUM ", text)
    text = _JAVA_DUP_NUM_RE.sub(" NUM ", text)

    # Tokenize. Keep operators/punct as tokens to retain structure.
    raw_tokens = _JAVA_DUP_TOK_RE.findall(text)
    tokens: list[str] = []
    for t in raw_tokens:
        if not t:
            continue
        if t in {"STR", "CHR", "NUM"}:
            tokens.append(t)
            continue
        if t[0].isalpha() or t[0] == "_":
            tokens.append(t if t in _JAVA_KEYWORDS else "id")
        else:
            tokens.append(t)
    return tokens


def _estimate_duplication_factor(graph: JavaGraph) -> tuple[float, dict]:
    """Static heuristic: token-hash method bodies and compute duplicated-token ratio."""
    min_tokens = 40  # ignore tiny methods/getters
    total_tokens = 0
    groups: dict[str, list[int]] = {}
    methods_considered = 0

    for mid, flags in graph.method_flags.items():
        if flags.get("is_test"):
            continue
        body = flags.get("body_text") or ""
        if not body:
            continue
        tokens = _tokenize_java_for_dup(body)
        if len(tokens) < min_tokens:
            continue
        methods_considered += 1
        tok_count = len(tokens)
        total_tokens += tok_count

        h = hashlib.sha1()
        for t in tokens:
            h.update(t.encode("utf-8", errors="ignore"))
            h.update(b" ")
        fp = h.hexdigest()
        groups.setdefault(fp, []).append(tok_count)

    duplicated_tokens = 0
    duplicated_methods = 0
    duplicate_groups = 0
    for counts in groups.values():
        if len(counts) <= 1:
            continue
        duplicate_groups += 1
        duplicated_methods += len(counts) - 1
        duplicated_tokens += sum(counts) - max(counts)  # keep one "original"

    estimate = (duplicated_tokens / total_tokens) if total_tokens else 0.0
    meta = {
        "heuristic": "normalized token hash over method bodies; duplicated-token ratio",
        "methods_considered": methods_considered,
        "min_tokens": min_tokens,
        "groups_total": len(groups),
        "groups_duplicated": duplicate_groups,
        "methods_duplicated": duplicated_methods,
        "total_tokens": total_tokens,
        "duplicated_tokens": duplicated_tokens,
    }
    return estimate, meta


def _summary_excluding_tests(graph: JavaGraph) -> tuple[dict, dict, dict]:
    prod_methods = [mid for mid, f in graph.method_flags.items() if not f.get("is_test")]
    prod_set = set(prod_methods)

    out_deg = []
    for mid in prod_methods:
        out_deg.append(sum(1 for dst in graph.edges.get(mid, ()) if dst in prod_set))
    coupling = {"avg_out_degree": (sum(out_deg) / len(out_deg)) if out_deg else 0.0, "methods": len(out_deg)}

    vals = [graph.method_complexity.get(mid, 0) for mid in prod_methods]
    complexity = {"avg_cognitive": (sum(vals) / len(vals)) if vals else 0.0, "methods": len(vals)}

    concrete = 0
    total = 0
    for mid in prod_methods:
        ck = graph.method_flags.get(mid, {}).get("class_kind")
        if ck:
            total += 1
            if ck == "concrete":
                concrete += 1
    abstraction = {"concrete_ratio": (concrete / total) if total else 1.0, "samples": total}
    return coupling, complexity, abstraction


def metric_F1_VFCP(repo_dir: Path, graph: JavaGraph | None, *, mode: str) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    # Composite predictor. Coverage/duplication are static estimates in this prototype.
    coupling, complexity, abstraction = _summary_excluding_tests(graph)
    coverage, coverage_meta = _estimate_test_coverage(repo_dir, graph)
    dup, dup_meta = _estimate_duplication_factor(graph)

    # Normalize into 0..1 with naive caps.
    norm_coupling = min(1.0, coupling["avg_out_degree"] / 20.0)
    norm_complexity = min(1.0, complexity["avg_cognitive"] / 30.0)
    norm_abstraction = 1.0 - min(1.0, abstraction["concrete_ratio"])

    # Coverage/duplication estimates are already 0..1.
    norm_coverage = min(1.0, max(0.0, coverage))
    norm_dup = min(1.0, max(0.0, dup))

    vfcp = (0.25 * norm_coupling) + (0.25 * norm_complexity) + (0.2 * (1 - norm_coverage)) + (0.15 * norm_dup) + (0.15 * norm_abstraction)
    return {
        "status": "ok",
        "VFCP": vfcp,
        "signals": {
            "coupling": coupling,
            "complexity": complexity,
            "test_coverage": norm_coverage,
            "test_coverage_meta": coverage_meta,
            "duplicate_factor": norm_dup,
            "duplicate_factor_meta": dup_meta,
            "abstraction": abstraction,
        },
        "notes": ["Static estimates: coverage via test identifier mentions; duplicates via normalized token hashing (tests excluded)."],
    }


def metric_F2_SRP(repo_dir: Path, graph: JavaGraph | None) -> dict:
    # Static proxy: count security constructs and estimate test coverage by string reference in test sources.
    if not graph:
        return _na(graph, "no_java_graph")

    constructs = graph.security_constructs
    if not constructs:
        return {"status": "ok", "SRP": 0.0, "constructs": 0, "uncovered": 0, "notes": ["No constructs found by heuristic patterns."]}

    test_text = ""
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "target", "build", ".gradle", ".idea"}]
        if "src" not in Path(root).parts:
            continue
        if "test" not in Path(root).parts:
            continue
        for fn in files:
            if fn.endswith(".java"):
                p = Path(root) / fn
                try:
                    test_text += p.read_text(encoding="utf-8", errors="ignore") + "\n"
                except OSError:
                    pass

    uncovered = 0
    for c in constructs:
        # c is like {"kind":"authz","symbol":"SomeClass"}; check in tests
        sym = c.get("symbol") or ""
        if sym and sym not in test_text:
            uncovered += 1

    srp = uncovered / len(constructs) if constructs else 0.0
    return {"status": "ok", "SRP": srp, "constructs": len(constructs), "uncovered": uncovered, "notes": ["Heuristic: tests 'cover' construct if symbol name appears in test sources."]}


def metric_M1_topology(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    # Export a lightweight topology for later graph visualization.
    return {
        "status": "ok",
        "nodes": graph.nodes_count,
        "edges": graph.edges_count,
        "entrypoints": len(graph.entrypoints),
        "sinks": len(graph.sinks),
        "export": graph.export_topology(limit_nodes=5000, limit_edges=20000),
        "notes": ["Export is truncated by limits to keep report size bounded."],
    }
