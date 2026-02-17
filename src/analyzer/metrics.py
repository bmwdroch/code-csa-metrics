from __future__ import annotations

import json
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
            out["F1"] = metric_F1_VFCP(graph, mode=mode)
        elif metric_id == "F2":
            out["F2"] = metric_F2_SRP(repo_dir, graph)
        elif metric_id == "M1":
            out["M1"] = metric_M1_topology(graph)
        else:
            out[metric_id] = {"status": "unknown_metric_id"}

    return out


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


def metric_F1_VFCP(graph: JavaGraph | None, *, mode: str) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    # Composite predictor. Coverage/duplication are best-effort in this prototype.
    # Coupling: efferent only (outgoing edges) normalized.
    coupling = graph.coupling_summary()
    complexity = graph.complexity_summary()
    coverage = None
    dup = None
    abstraction = graph.abstraction_summary()

    # Normalize into 0..1 with naive caps.
    norm_coupling = min(1.0, coupling["avg_out_degree"] / 20.0)
    norm_complexity = min(1.0, complexity["avg_cognitive"] / 30.0)
    norm_abstraction = 1.0 - min(1.0, abstraction["concrete_ratio"])

    # Missing signals: treat as neutral (0.5) for now.
    norm_coverage = 0.5
    norm_dup = 0.5

    vfcp = (0.25 * norm_coupling) + (0.25 * norm_complexity) + (0.2 * (1 - norm_coverage)) + (0.15 * norm_dup) + (0.15 * norm_abstraction)
    return {
        "status": "ok",
        "VFCP": vfcp,
        "signals": {
            "coupling": coupling,
            "complexity": complexity,
            "test_coverage": coverage,
            "duplicate_factor": dup,
            "abstraction": abstraction,
        },
        "notes": ["Prototype normalization; coverage/duplicates are not computed yet (neutral default)."],
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
