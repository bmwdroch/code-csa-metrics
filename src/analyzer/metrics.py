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

from analyzer.java_graph import ETI_LEAK_PAT, JavaGraph, build_java_graph


_DISABLED_METRICS: dict[str, str] = {}


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
        if metric_id in _DISABLED_METRICS:
            out[metric_id] = {
                "status": "disabled",
                "reason": _DISABLED_METRICS[metric_id],
            }
            continue
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
            out["E1"] = metric_E1_OSDR(repo_dir)
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


def _method_location(graph: JavaGraph, method_id: str) -> tuple[str | None, int | None]:
    """Извлекает файл и строку метода из method_flags."""
    flags = graph.method_flags.get(method_id, {})
    return flags.get("rel_path"), flags.get("start_line")


def metric_A1_ASE(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    # Heuristic weights: chosen for prototype, tune later.
    base = 1.0
    mult_string = 1.3
    mult_map_object = 1.5
    mult_no_auth = 1.4
    mult_no_validation = 1.2
    # Theoretical maximum per-node raw score (untyped + no_auth + no_validation).
    _max_raw = mult_map_object * mult_no_auth * mult_no_validation  # 1.5 × 1.4 × 1.2 = 2.52

    total = 0.0
    per_entry = []
    findings: list[dict] = []
    for ep in graph.entrypoints:
        m = base
        if ep.param_risk == "stringy":
            m *= mult_string
        elif ep.param_risk == "untyped":
            m *= mult_map_object
        elif ep.param_risk == "binary":
            m *= mult_map_object
        if not ep.has_auth:
            m *= mult_no_auth
        if not ep.has_validation:
            m *= mult_no_validation
        total += m
        per_entry.append({
            "method": ep.method_id,
            "score": round(min(1.0, m / _max_raw), 4),
            "has_auth": ep.has_auth,
            "has_validation": ep.has_validation,
        })
        rel_path, start_line = _method_location(graph, ep.method_id)
        if not ep.has_auth:
            findings.append({
                "metric": "A1", "severity": "high",
                "file": rel_path, "line": start_line,
                "method": ep.method_id,
                "what": "Endpoint без аутентификации",
                "why": "HTTP-метод доступен без проверки подлинности, потенциальный вектор несанкционированного доступа",
                "fix": "Добавьте аннотацию @PreAuthorize или @Secured с указанием требуемой роли",
            })
        if not ep.has_validation:
            findings.append({
                "metric": "A1", "severity": "medium",
                "file": rel_path, "line": start_line,
                "method": ep.method_id,
                "what": "Endpoint без валидации входных данных",
                "why": "Входные параметры не проверяются, что допускает передачу некорректных или вредоносных данных",
                "fix": "Добавьте @Valid к параметрам DTO или явную валидацию входных данных",
            })
    return {
        "status": "ok",
        "ASE": total,
        "entrypoints": len(graph.entrypoints),
        "sample": per_entry[:50],
        "findings": findings,
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
    _eci_cap = 30.0
    findings: list[dict] = []
    top_entries = []
    for (eci, mid, c, d) in top[:50]:
        rel_path, start_line = _method_location(graph, mid)
        top_entries.append({
            "method": mid, "ECI": eci,
            "ECI_norm": round(min(1.0, eci / _eci_cap), 4),
            "complexity": c, "distance": d,
        })
        if eci >= 10.0:
            findings.append({
                "metric": "A2",
                "severity": "high" if eci >= 20.0 else "medium",
                "file": rel_path, "line": start_line,
                "method": mid,
                "what": f"Высокая сложность вблизи входа (ECI={eci:.1f})",
                "why": f"Метод со сложностью {c} на расстоянии {d} хопов от входа — "
                       "сложная логика близко к точке входа повышает риск ошибок безопасности",
                "fix": "Разделите метод на более простые части или вынесите сложную логику дальше от точки входа",
            })
    return {
        "status": "ok",
        "top": top_entries,
        "methods_reachable": len(distances),
        "findings": findings,
        "notes": ["Cognitive complexity is an approximation; distances overapprox due to heuristic call edges."],
    }


def metric_A3_IET(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    weighted_sum = 0.0
    weight_total = 0.0
    per = []
    findings: list[dict] = []
    for ep in graph.entrypoints:
        w = {"http": 1.0, "mq": 0.8, "job": 0.5}.get(ep.entry_type, 0.7)
        entropy = {"low": 0.2, "medium": 0.5, "high": 0.8, "very_high": 1.0}.get(ep.entropy_level, 0.5)
        if ep.has_validation:
            entropy *= 0.7
        weighted_sum += entropy * w
        weight_total += w
        per.append({"method": ep.method_id, "entropy": entropy, "weight": w, "type": ep.entry_type})
        if entropy >= 0.7:
            rel_path, start_line = _method_location(graph, ep.method_id)
            findings.append({
                "metric": "A3",
                "severity": "high" if entropy >= 0.9 else "medium",
                "file": rel_path, "line": start_line,
                "method": ep.method_id,
                "what": f"Endpoint принимает данные высокой энтропии (entropy={entropy:.2f})",
                "why": "Входные данные с высокой энтропией (нетипизированные, произвольные строки) "
                       "увеличивают вероятность инъекционных атак",
                "fix": "Добавьте строгую типизацию параметров и валидацию (@Valid, @Pattern, @Size)",
            })
    iet = (weighted_sum / weight_total) if weight_total else 0.0
    return {"status": "ok", "IET_system": iet, "entrypoints": len(graph.entrypoints), "sample": per[:50], "findings": findings}


def metric_B1_IDS(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    res = graph.defense_in_depth_paths(max_depth=max_graph_depth)
    if res.get("system_min_ratio") is None:
        return {
            "status": "not_available",
            "reason": "no_entry_to_sink_paths",
            "paths_analyzed": res.get("paths_analyzed", 0),
            "findings": [],
            "notes": ["No entrypoint->sink path found within max_graph_depth."],
        }
    findings: list[dict] = []
    min_path = res.get("min_path", {})
    ratio = res["system_min_ratio"]
    if ratio < 0.5:
        sink_id = min_path.get("sink", "")
        rel_path, start_line = _method_location(graph, sink_id) if sink_id else (None, None)
        findings.append({
            "metric": "B1",
            "severity": "critical" if ratio < 0.2 else "high",
            "file": rel_path, "line": start_line,
            "method": sink_id or None,
            "what": f"Путь от входа до приёмника с {min_path.get('layers', 0)}/6 защитных слоёв",
            "why": "Недостаточное количество защитных слоёв между точкой входа и критической операцией "
                   "позволяет обойти защиту при компрометации одного уровня",
            "fix": "Добавьте промежуточные проверки: аутентификацию, авторизацию, валидацию, "
                   "санитизацию на пути от входа до приёмника",
        })
    return {
        "status": "ok",
        "IDS_system": res["system_min_ratio"],
        "paths_analyzed": res["paths_analyzed"],
        "min_path": min_path,
        "findings": findings,
        "notes": ["Computed over bounded BFS state space (layers bitmask)."],
    }


def metric_B2_PPI(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    unauth_entrypoints = [ep for ep in graph.entrypoints if not ep.has_auth]
    privileged_sinks = [s for s in graph.sinks if s.privileged]
    if not unauth_entrypoints or not privileged_sinks:
        return {
            "status": "ok",
            "PPI": 0.0,
            "min_distance": None,
            "findings": [],
            "notes": ["No unauthenticated entrypoints or privileged sinks detected."],
        }

    min_dist = graph.min_distance_unauth_to_privileged(max_depth=max_graph_depth)
    if min_dist is None:
        return {
            "status": "not_available",
            "reason": "no_path_within_max_depth",
            "min_distance": None,
            "entrypoints_unauth": len(unauth_entrypoints),
            "sinks_privileged": len(privileged_sinks),
            "findings": [],
            "notes": ["Unauthenticated entrypoints and privileged sinks exist, but no path was found within max_graph_depth."],
        }
    ppi = 1.0 - min(1.0, math.log(min_dist + 1) / math.log(11))
    findings: list[dict] = []
    if min_dist <= 3:
        findings.append({
            "metric": "B2",
            "severity": "critical" if min_dist <= 1 else "high",
            "file": None, "line": None,
            "method": None,
            "what": f"Привилегированная операция доступна за {min_dist} хопов от публичного входа",
            "why": "Короткий путь от неаутентифицированного входа до привилегированной операции "
                   "означает минимальное количество проверок на пути к критичным данным",
            "fix": "Добавьте промежуточные слои авторизации между публичными входами и привилегированными операциями",
        })
    return {"status": "ok", "PPI": ppi, "min_distance": min_dist, "findings": findings}


def metric_B3_MPSP(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    mpsp = graph.path_security_parity(max_depth=max_graph_depth)
    findings: list[dict] = []
    ratio = mpsp["system_min_ratio"]
    if ratio < 0.5:
        worst = mpsp.get("worst_operation")
        findings.append({
            "metric": "B3",
            "severity": "high" if ratio < 0.3 else "medium",
            "file": None, "line": None, "method": None,
            "what": f"Несогласованность защиты путей к операции (паритет {ratio:.2f})",
            "why": "Разные пути к одной и той же операции имеют различные уровни защиты — "
                   "атакующий использует наименее защищённый путь",
            "fix": "Обеспечьте одинаковый набор проверок безопасности на всех путях к критическим операциям",
        })
    return {"status": "ok", "MPSP_system": ratio, "worst_operation": mpsp["worst_operation"], "findings": findings}


def metric_B4_FSS(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    result = graph.fail_safe_score()
    findings: list[dict] = []
    for cb in graph.catch_blocks:
        if not isinstance(cb, dict):
            continue
        body = cb["body_text"]
        stripped = re.sub(r"\s+", "", body)
        is_empty = stripped in {"{}", "{/* */}", "{//}"}
        if is_empty:
            findings.append({
                "metric": "B4", "severity": "critical",
                "file": cb.get("rel_path"), "line": cb.get("start_line"),
                "method": cb.get("method_id"),
                "what": "Пустой catch-блок",
                "why": "При возникновении исключения выполнение продолжится без обработки ошибки, "
                       "что может привести к обходу проверок безопасности (fail-open)",
                "fix": "Добавьте throw, return с ошибкой или логирование внутри catch-блока",
            })
        elif "throw" not in body and re.search(r"return\s+(true|false|0|null)\b", body):
            findings.append({
                "metric": "B4", "severity": "medium",
                "file": cb.get("rel_path"), "line": cb.get("start_line"),
                "method": cb.get("method_id"),
                "what": "Catch-блок с неоднозначной обработкой (return без throw)",
                "why": "Возврат значения по умолчанию вместо пробрасывания исключения может "
                       "маскировать ошибки безопасности",
                "fix": "Пробрасывайте исключение (throw) или явно обрабатывайте ошибку с логированием",
            })
    result["findings"] = findings
    return {"status": "ok", **result}


def metric_C1_TPC(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    result = graph.tainted_path_complexity(max_depth=max_graph_depth)
    findings: list[dict] = []
    max_hops = result.get("TPC_max_consecutive_unsafe_hops", 0)
    if max_hops >= 3:
        findings.append({
            "metric": "C1",
            "severity": "critical" if max_hops >= 6 else ("high" if max_hops >= 4 else "medium"),
            "file": None, "line": None, "method": None,
            "what": f"Путь длиной {max_hops} хопов без валидации/санитизации",
            "why": "Длинная цепочка вызовов без промежуточной проверки данных позволяет "
                   "распространение заражённых данных до критических операций",
            "fix": "Добавьте промежуточную валидацию или санитизацию данных на этом пути",
        })
    result["findings"] = findings
    return {"status": "ok", **result}


def metric_C2_ETI(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    result = graph.error_transparency_index()
    findings: list[dict] = []
    for cb in graph.catch_blocks:
        if not isinstance(cb, dict):
            continue
        if ETI_LEAK_PAT.search(cb["body_text"]):
            findings.append({
                "metric": "C2", "severity": "high",
                "file": cb.get("rel_path"), "line": cb.get("start_line"),
                "method": cb.get("method_id"),
                "what": "Утечка деталей исключения в ответ клиенту",
                "why": "getMessage(), printStackTrace() или toString() исключения в ответе "
                       "раскрывают внутреннюю структуру приложения атакующему",
                "fix": "Возвращайте обобщённое сообщение об ошибке, детали логируйте серверно",
            })
    result["findings"] = findings
    return {"status": "ok", **result}


def metric_C3_SFA(graph: JavaGraph | None) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    result = graph.secret_flow_analysis()
    findings: list[dict] = []
    for s in result.get("sample", []):
        mid = s.get("method", "")
        rel_path, start_line = _method_location(graph, mid) if mid else (None, None)
        findings.append({
            "metric": "C3", "severity": "high",
            "file": rel_path, "line": start_line,
            "method": mid,
            "what": "Секрет (password/token) утекает в лог или сериализацию",
            "why": "Конфиденциальные данные в логах или сериализованном выводе доступны "
                   "всем, кто имеет доступ к логам или ответам API",
            "fix": "Используйте @ToString.Exclude, маскирование или фильтрацию секретов перед логированием",
        })
    result["findings"] = findings
    return {"status": "ok", **result}


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
    findings: list[dict] = []
    if boundaries >= 2:
        findings.append({
            "metric": "D1",
            "severity": "medium" if boundaries < 3 else "high",
            "file": None, "line": None, "method": None,
            "what": f"Проект использует {len(present)} языков ({', '.join(present)})",
            "why": "Каждая технологическая граница — потенциальная точка потери контекста безопасности, "
                   "сериализации и конвертации данных",
            "fix": "Обеспечьте единую политику безопасности на всех технологических границах",
        })
    return {
        "status": "ok",
        "languages_present": present,
        "boundaries": boundaries,
        "PAD": float(boundaries),
        "findings": findings,
        "notes": ["Boundary count only; policy-gap weighting requires org-specific security policy model."],
    }


def metric_D2_TCPD(graph: JavaGraph | None, *, max_graph_depth: int) -> dict:
    if not graph:
        return _na(graph, "no_java_graph")
    result = graph.trust_chain_depth(max_depth=max_graph_depth)
    findings: list[dict] = []
    max_hops = result.get("TCPD_max_hops_after_last_auth", 0)
    if max_hops >= 3:
        findings.append({
            "metric": "D2",
            "severity": "high" if max_hops >= 5 else "medium",
            "file": None, "line": None, "method": None,
            "what": f"Цепочка доверия длиной {max_hops} хопов после последней проверки auth",
            "why": "Длинная цепочка посредников после последней проверки авторизации увеличивает "
                   "риск потери контекста безопасности",
            "fix": "Добавьте повторную проверку авторизации ближе к критической операции",
        })
    result["findings"] = findings
    return {"status": "ok", **result}


# ---------------------------------------------------------------------------
# E1 (OSDR): классификация зависимостей и парсинг манифестов сборки
# ---------------------------------------------------------------------------

_BASELINE_GROUPS: set[str] = {
    "org.springframework",
    "org.springframework.boot",
    "org.springframework.security",
    "org.springframework.data",
    "org.springframework.cloud",
    "org.springframework.kafka",
    "org.springframework.amqp",
    "org.springframework.retry",
    "org.springframework.session",
    "org.springframework.ws",
    "org.springframework.webflow",
    "org.springframework.integration",
    "org.springframework.batch",
    "jakarta.servlet",
    "jakarta.persistence",
    "jakarta.validation",
    "jakarta.annotation",
    "jakarta.transaction",
    "jakarta.xml",
    "jakarta.ws",
    "jakarta.json",
    "jakarta.inject",
    "jakarta.enterprise",
    "jakarta.activation",
    "jakarta.mail",
    "javax.servlet",
    "javax.persistence",
    "javax.validation",
    "javax.annotation",
    "javax.transaction",
    "javax.xml",
    "javax.ws",
    "javax.json",
    "javax.inject",
    "javax.enterprise",
    "org.junit",
    "org.junit.jupiter",
    "junit",
    "org.mockito",
    "org.hamcrest",
    "org.assertj",
    "org.testcontainers",
    "com.fasterxml.jackson",
    "com.fasterxml.jackson.core",
    "com.fasterxml.jackson.datatype",
    "com.fasterxml.jackson.module",
    "org.slf4j",
    "ch.qos.logback",
    "org.apache.logging.log4j",
    "org.projectlombok",
    "io.micrometer",
    "org.yaml",
    "org.apache.commons",
    "com.google.guava",
    "org.apache.httpcomponents",
    "org.apache.tomcat",
    "io.netty",
    "io.projectreactor",
    "io.swagger",
    "org.springdoc",
    "org.mapstruct",
    "org.liquibase",
    "org.flywaydb",
    "org.hibernate",
    "org.hibernate.validator",
    "com.zaxxer",
    "org.postgresql",
    "com.mysql",
    "com.h2database",
    "org.hsqldb",
    "redis.clients",
    "io.lettuce",
    "org.mongodb",
    "org.apache.kafka",
    "com.rabbitmq",
    "io.grpc",
    "com.google.protobuf",
}

_SECURITY_CRYPTO_KEYWORDS: set[str] = {
    "bcprov", "bcpkix", "bcpg", "bcmail", "bouncy-castle", "bouncycastle",
    "spring-security", "shiro", "keycloak",
    "nimbus-jose-jwt", "jjwt", "java-jwt", "jose4j",
    "jasypt", "tink", "conscrypt",
    "pac4j", "oauth2", "opensaml", "xmlsec",
    "crypto", "cipher", "encryption", "gpg",
}

_GRADLE_DEP_DECL_RE = re.compile(
    r"""^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\b""",
)

_GRADLE_COORD_RE = re.compile(
    r"""['"]([^'"]+:[^'"]+)['"]""",
)

_GRADLE_GROUP_ARG_RE = re.compile(
    r"""\bgroup\s*[:=]\s*['"]([^'"]+)['"]""",
)

_GRADLE_NAME_ARG_RE = re.compile(
    r"""\bname\s*[:=]\s*['"]([^'"]+)['"]""",
)

_GRADLE_GROUP_RE = re.compile(
    r"""^\s*group\s*=\s*['"]([^'"]+)['"]""",
    re.MULTILINE,
)


def _classify_dependency(
    group_id: str,
    artifact_id: str,
    internal_prefix: str | None,
) -> str:
    """Классифицирует зависимость по group и artifact.

    Args:
        group_id: Идентификатор группы (например, ``org.springframework``).
        artifact_id: Идентификатор артефакта.
        internal_prefix: Префикс groupId проекта для определения самописных библиотек.

    Returns:
        Категория: ``BASELINE``, ``INTERNAL``, ``SECURITY_SELF``, ``RISKY_SECURITY``, ``OTHER``.
    """
    artifact_lower = artifact_id.lower()
    is_security = any(kw in artifact_lower for kw in _SECURITY_CRYPTO_KEYWORDS)

    if internal_prefix:
        internal = internal_prefix.strip().rstrip(".")
        if internal and (group_id == internal or group_id.startswith(internal + ".")):
            return "SECURITY_SELF" if is_security else "INTERNAL"

    for baseline in _BASELINE_GROUPS:
        if group_id == baseline or group_id.startswith(baseline + "."):
            return "BASELINE"

    if is_security:
        return "RISKY_SECURITY"

    return "OTHER"


def _extract_pom_group_id(pom_text: str) -> str | None:
    """Извлекает groupId проекта из pom.xml, игнорируя ``<parent>`` блок.

    В дочерних Maven-модулях первый ``<groupId>`` часто принадлежит секции
    ``<parent>`` (например, ``org.springframework.boot``). Функция сначала ищет
    ``<groupId>`` за пределами ``<parent>...</parent>``, и только если проектный
    groupId не объявлен явно, возвращает groupId из ``<parent>``.

    Args:
        pom_text: Содержимое pom.xml.

    Returns:
        groupId или ``None``.
    """
    stripped = re.sub(r"<parent>.*?</parent>", "", pom_text, flags=re.DOTALL)
    m = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", stripped)
    if m:
        return m.group(1)
    parent_m = re.search(
        r"<parent>.*?<groupId>\s*([^<]+?)\s*</groupId>.*?</parent>",
        pom_text,
        re.DOTALL,
    )
    return parent_m.group(1) if parent_m else None


def _parse_pom_dependencies(pom_text: str) -> list[dict[str, str]]:
    """Извлекает зависимости из содержимого pom.xml.

    Args:
        pom_text: Содержимое pom.xml.

    Returns:
        Список словарей с ключами ``group``, ``artifact``, ``scope``.
    """
    deps: list[dict[str, str]] = []
    dep_pattern = re.compile(
        r"<dependency>\s*"
        r"<groupId>\s*([^<]+?)\s*</groupId>\s*"
        r"<artifactId>\s*([^<]+?)\s*</artifactId>"
        r"(?:\s*<version>[^<]*</version>)?"
        r"(?:\s*<scope>\s*([^<]*?)\s*</scope>)?",
        re.DOTALL,
    )
    for m in dep_pattern.finditer(pom_text):
        deps.append({
            "group": m.group(1).strip(),
            "artifact": m.group(2).strip(),
            "scope": (m.group(3) or "compile").strip(),
        })
    return deps


def _parse_gradle_dependencies(gradle_text: str) -> list[dict[str, str]]:
    """Извлекает зависимости из build.gradle / build.gradle.kts.

    Args:
        gradle_text: Содержимое Gradle-файла.

    Returns:
        Список словарей с ключами ``group``, ``artifact``, ``scope``.
    """
    deps: list[dict[str, str]] = []
    lines = gradle_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not _GRADLE_DEP_DECL_RE.search(line):
            i += 1
            continue

        statement = line
        paren_depth = line.count("(") - line.count(")")
        j = i
        while paren_depth > 0 and j + 1 < len(lines):
            j += 1
            statement += "\n" + lines[j]
            paren_depth += lines[j].count("(") - lines[j].count(")")

        group_m = _GRADLE_GROUP_ARG_RE.search(statement)
        name_m = _GRADLE_NAME_ARG_RE.search(statement)
        if group_m and name_m:
            deps.append({
                "group": group_m.group(1).strip(),
                "artifact": name_m.group(1).strip(),
                "scope": "compile",
            })
        else:
            for coord_m in _GRADLE_COORD_RE.finditer(statement):
                coord = coord_m.group(1)
                parts = [p.strip() for p in coord.split(":")]
                if len(parts) >= 2 and parts[0] and parts[1]:
                    deps.append({
                        "group": parts[0],
                        "artifact": parts[1],
                        "scope": "compile",
                    })

        i = j + 1
    return deps


def _detect_internal_prefix(repo_dir: Path) -> str | None:
    """Определяет groupId-префикс проекта из корневого манифеста сборки.

    Args:
        repo_dir: Корень репозитория.

    Returns:
        Префикс groupId или ``None``.
    """
    root_pom = repo_dir / "pom.xml"
    if root_pom.exists():
        text = root_pom.read_text(encoding="utf-8", errors="ignore")
        gid = _extract_pom_group_id(text)
        if gid:
            return gid

    for name in ("build.gradle", "build.gradle.kts"):
        gf = repo_dir / name
        if gf.exists():
            text = gf.read_text(encoding="utf-8", errors="ignore")
            m = _GRADLE_GROUP_RE.search(text)
            if m:
                return m.group(1)
    return None


_OSDR_W_OTHER = 1.0
_OSDR_W_SECURITY_SELF = 3.0
_OSDR_W_RISKY_SECURITY = 2.0
_OSDR_THRESHOLD = 50.0


def metric_E1_OSDR(repo_dir: Path) -> dict:
    """Оценка риска зависимостей (OSDR).

    Парсит pom.xml и build.gradle напрямую (без Maven/Gradle, без JVM),
    классифицирует зависимости и вычисляет score.

    Args:
        repo_dir: Корень анализируемого репозитория.

    Returns:
        Словарь с результатом метрики.
    """
    all_deps: list[dict[str, str]] = []
    pom_files: list[Path] = []
    gradle_files: list[Path] = []

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "target", "build", ".gradle", ".idea"}]
        for fn in files:
            p = Path(root) / fn
            if fn == "pom.xml":
                pom_files.append(p)
            elif fn in ("build.gradle", "build.gradle.kts"):
                gradle_files.append(p)

    if not pom_files and not gradle_files:
        return {
            "status": "not_available",
            "reason": "no_build_manifest",
            "OSDR": None,
            "notes": ["No pom.xml or build.gradle found; E1 not applicable."],
        }

    internal_prefix = _detect_internal_prefix(repo_dir)

    for pf in pom_files:
        text = pf.read_text(encoding="utf-8", errors="ignore")
        all_deps.extend(_parse_pom_dependencies(text))

    for gf in gradle_files:
        text = gf.read_text(encoding="utf-8", errors="ignore")
        all_deps.extend(_parse_gradle_dependencies(text))

    seen: set[tuple[str, str]] = set()
    unique_deps: list[dict[str, str]] = []
    for d in all_deps:
        key = (d["group"], d["artifact"])
        if key not in seen:
            seen.add(key)
            unique_deps.append(d)

    classification: dict[str, list[dict[str, str]]] = {
        "BASELINE": [],
        "INTERNAL": [],
        "SECURITY_SELF": [],
        "RISKY_SECURITY": [],
        "OTHER": [],
    }

    for dep in unique_deps:
        cat = _classify_dependency(dep["group"], dep["artifact"], internal_prefix)
        classification[cat].append(dep)

    count_other = len(classification["OTHER"])
    count_sec_self = len(classification["SECURITY_SELF"])
    count_risky_sec = len(classification["RISKY_SECURITY"])

    raw_score = (
        count_other * _OSDR_W_OTHER
        + count_sec_self * _OSDR_W_SECURITY_SELF
        + count_risky_sec * _OSDR_W_RISKY_SECURITY
    )
    osdr = min(1.0, raw_score / _OSDR_THRESHOLD)

    findings: list[dict] = []

    for dep in classification["SECURITY_SELF"]:
        findings.append({
            "metric": "E1",
            "severity": "high",
            "file": "pom.xml / build.gradle",
            "line": None,
            "method": None,
            "what": f"Самописная security/crypto библиотека: {dep['group']}:{dep['artifact']}",
            "why": "Собственная реализация криптографии или механизмов безопасности увеличивает "
                   "вероятность ошибок в критичном коде",
            "fix": "Используйте проверенные библиотеки (Spring Security, Bouncy Castle) "
                   "вместо собственных реализаций",
        })

    for dep in classification["RISKY_SECURITY"]:
        findings.append({
            "metric": "E1",
            "severity": "medium",
            "file": "pom.xml / build.gradle",
            "line": None,
            "method": None,
            "what": f"Security/crypto зависимость: {dep['group']}:{dep['artifact']}",
            "why": "Зависимость от сторонней security/crypto библиотеки вне базового набора "
                   "требует дополнительного контроля обновлений и уязвимостей",
            "fix": "Убедитесь, что библиотека актуальна и отслеживается в процессе "
                   "управления уязвимостями (SCA)",
        })

    if count_other > 20:
        findings.append({
            "metric": "E1",
            "severity": "medium" if count_other < 40 else "high",
            "file": "pom.xml / build.gradle",
            "line": None,
            "method": None,
            "what": f"Большое количество сторонних зависимостей: {count_other}",
            "why": "Каждая дополнительная зависимость увеличивает поверхность атаки "
                   "и риск supply-chain компрометации",
            "fix": "Проведите аудит зависимостей, удалите неиспользуемые, "
                   "консолидируйте дублирующую функциональность",
        })

    classification_summary = {
        cat: [f"{d['group']}:{d['artifact']}" for d in deps_list]
        for cat, deps_list in classification.items()
        if deps_list
    }

    return {
        "status": "ok",
        "OSDR": round(osdr, 4),
        "raw_score": round(raw_score, 2),
        "total_dependencies": len(unique_deps),
        "internal_prefix": internal_prefix,
        "classification": classification_summary,
        "counts": {
            "baseline": len(classification["BASELINE"]),
            "internal": len(classification["INTERNAL"]),
            "security_self": count_sec_self,
            "risky_security": count_risky_sec,
            "other": count_other,
        },
        "findings": findings,
        "notes": [],
    }


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
    findings: list[dict] = []
    if norm_coverage < 0.3:
        findings.append({
            "metric": "F1", "severity": "medium",
            "file": None, "line": None, "method": None,
            "what": f"Низкое покрытие тестами ({norm_coverage:.0%})",
            "why": "Низкое покрытие тестами увеличивает стоимость и риск исправления уязвимостей — "
                   "невозможно уверенно проверить, что исправление не сломало другую функциональность",
            "fix": "Увеличьте покрытие тестами, особенно для кода, связанного с безопасностью",
        })
    if norm_dup > 0.3:
        findings.append({
            "metric": "F1", "severity": "medium",
            "file": None, "line": None, "method": None,
            "what": f"Высокий уровень дублирования кода ({norm_dup:.0%})",
            "why": "Дублированный код требует исправления уязвимости в нескольких местах, "
                   "что увеличивает риск пропуска одного из них",
            "fix": "Устраните дублирование, выделив общую логику в отдельные методы",
        })
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
        "findings": findings,
        "notes": ["Static estimates: coverage via test identifier mentions; duplicates via normalized token hashing (tests excluded)."],
    }


_IDENTIFIER_TOKEN_PAT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def _iter_java_test_files(repo_dir: Path) -> Iterable[Path]:
    ignore_dirs = {".git", "target", "build", ".gradle", ".idea"}
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        if not _is_test_path(Path(root)):
            continue
        for fn in files:
            if fn.endswith(".java"):
                yield Path(root) / fn


def metric_F2_SRP(repo_dir: Path, graph: JavaGraph | None) -> dict:
    # Static proxy: count security constructs and estimate test coverage by string reference in test sources.
    if not graph:
        return _na(graph, "no_java_graph")

    constructs = graph.security_constructs
    if not constructs:
        return {"status": "ok", "SRP": 0.0, "constructs": 0, "uncovered": 0, "notes": ["No constructs found by heuristic patterns."]}

    symbols = {c.get("symbol") for c in constructs if c.get("symbol")}
    covered_symbols: set[str] = set()
    remaining_symbols = set(symbols)

    for p in _iter_java_test_files(repo_dir):
        if not remaining_symbols:
            break
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        ids = set(_IDENTIFIER_TOKEN_PAT.findall(text))
        if not ids:
            continue
        matched = ids & remaining_symbols
        if matched:
            covered_symbols.update(matched)
            remaining_symbols.difference_update(matched)

    uncovered = 0
    findings: list[dict] = []
    for c in constructs:
        sym = c.get("symbol") or ""
        if sym and sym not in covered_symbols:
            uncovered += 1
            findings.append({
                "metric": "F2", "severity": "medium",
                "file": None, "line": None,
                "method": None,
                "what": f"Конструкция безопасности ({c.get('kind', '?')}) в {sym} не покрыта тестами",
                "why": "Изменение непокрытого тестами кода безопасности при рефакторинге может "
                       "незаметно нарушить защиту (регрессия безопасности)",
                "fix": f"Добавьте тесты для класса {sym}, проверяющие поведение механизма {c.get('kind', '')}",
            })

    srp = uncovered / len(constructs) if constructs else 0.0
    return {"status": "ok", "SRP": srp, "constructs": len(constructs), "uncovered": uncovered, "findings": findings, "notes": ["Heuristic: tests 'cover' construct if symbol name appears in test sources."]}


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
