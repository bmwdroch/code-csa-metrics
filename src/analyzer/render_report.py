"""Генератор интерактивного HTML-отчёта CSA (все метрики безопасности).

Читает combined.json и создаёт самодостаточный HTML-файл с D3.js force-directed
графом и панелью сводных показателей в HUD-стилистике.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Разбор аргументов командной строки.

    Args:
        argv: Список аргументов. ``None`` означает ``sys.argv[1:]``.

    Returns:
        Пространство имён с полями ``input`` и ``output``.
    """
    parser = argparse.ArgumentParser(
        description="Генерация интерактивного HTML-отчёта CSA (все метрики)",
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Путь к combined.json",
    )
    parser.add_argument(
        "--output", "-o",
        default="csa-report.html",
        help="Путь к выходному HTML-файлу (по умолчанию: csa-report.html)",
    )
    parser.add_argument(
        "--max-graph-nodes",
        type=int,
        default=500,
        help="Максимум узлов для графа (по умолчанию: 500). "
             "При превышении отбираются наиболее значимые узлы.",
    )
    return parser.parse_args(argv)


def _load_combined(path: Path) -> dict[str, Any]:
    """Загрузка и валидация combined.json.

    Args:
        path: Путь к файлу.

    Returns:
        Десериализованный словарь.

    Raises:
        FileNotFoundError: Файл не найден.
        json.JSONDecodeError: Невалидный JSON.
    """
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


_TEST_CLASS_RE = re.compile(r"(^Test[A-Z]|Tests?$)")


def _is_test_node(method_id: str) -> bool:
    """Определяет, является ли метод тестовым по имени класса.

    Распознаёт стандартные соглашения именования Java-тестов:
    суффиксы ``Test``/``Tests`` и префикс ``Test`` перед заглавной буквой.

    Args:
        method_id: Полный идентификатор метода вида ``pkg.ClassName#method()``.

    Returns:
        ``True`` если метод принадлежит тестовому классу.
    """
    if "#" not in method_id:
        return False
    class_part = method_id.split("#")[0]
    class_name = class_part.rsplit(".", 1)[-1] if "." in class_part else class_part
    return bool(_TEST_CLASS_RE.search(class_name))


def _make_label(method_id: str) -> str:
    """Формирует короткую метку из полного идентификатора метода.

    Из ``org.springframework.samples.petclinic.owner.OwnerController#showOwner(int)``
    получится ``OwnerController#showOwner()``.

    Args:
        method_id: Полный идентификатор метода.

    Returns:
        Сокращённая метка ``ClassName#methodName()``.
    """
    if "#" not in method_id:
        parts = method_id.rsplit(".", 1)
        return parts[-1] if len(parts) > 1 else method_id

    class_part, method_part = method_id.split("#", 1)
    class_name = class_part.rsplit(".", 1)[-1] if "." in class_part else class_part
    method_name = method_part.split("(")[0] + "()"
    return f"{class_name}#{method_name}"


def _classify_nodes(
    all_nodes: list[str],
    entrypoint_ids: set[str],
    sink_ids: set[str],
) -> list[dict[str, Any]]:
    """Классификация узлов графа по типам.

    Каждый узел получает тип: ``entrypoint``, ``sink``, ``test`` или ``regular``.
    Приоритет: entrypoint > sink > test > regular.

    Args:
        all_nodes: Список всех идентификаторов методов.
        entrypoint_ids: Множество идентификаторов точек входа.
        sink_ids: Множество идентификаторов стоков.

    Returns:
        Список словарей с ключами ``id``, ``label``, ``type``.
    """
    result: list[dict[str, Any]] = []
    for node_id in all_nodes:
        if node_id in entrypoint_ids:
            node_type = "entrypoint"
        elif node_id in sink_ids:
            node_type = "sink"
        elif _is_test_node(node_id):
            node_type = "test"
        else:
            node_type = "regular"
        result.append({
            "id": node_id,
            "label": _make_label(node_id),
            "type": node_type,
        })
    return result


_METRIC_META: dict[str, dict[str, str]] = {
    "A1": {"name": "ASE", "title": "Открытость поверхности атаки", "group": "A", "score_key": "ASE"},
    "A2": {"name": "ECI", "title": "Индекс взрывной сложности", "group": "A", "score_key": "ECI_avg"},
    "A3": {"name": "IET", "title": "Входная энтропия", "group": "A", "score_key": "IET_system"},
    "B1": {"name": "IDS", "title": "Глубина эшелонированной защиты", "group": "B", "score_key": "IDS"},
    "B2": {"name": "PPI", "title": "Индекс близости к привилегиям", "group": "B", "score_key": "PPI"},
    "B3": {"name": "MPSP", "title": "Паритет защиты по путям", "group": "B", "score_key": "MPSP"},
    "B4": {"name": "FSS", "title": "Оценка безопасного отказа", "group": "B", "score_key": "FSS"},
    "C1": {"name": "TPC", "title": "Сложность пути заражённых данных", "group": "C", "score_key": "TPC"},
    "C2": {"name": "ETI", "title": "Индекс прозрачности ошибок", "group": "C", "score_key": "ETI"},
    "C3": {"name": "SFA", "title": "Анализ потоков секретов", "group": "C", "score_key": "SFA"},
    "D1": {"name": "PAD", "title": "Дрейф атак на стыках технологий", "group": "D", "score_key": "PAD"},
    "D2": {"name": "TCPD", "title": "Глубина цепочки доверия", "group": "D", "score_key": "TCPD"},
    "E1": {"name": "OSDR", "title": "Риск зависимостей с открытым кодом", "group": "E", "score_key": "OSDR"},
    "F1": {"name": "VFCP", "title": "Предиктор сложности исправления", "group": "F", "score_key": "VFCP"},
    "F2": {"name": "SRP", "title": "Вероятность регрессии безопасности", "group": "F", "score_key": "SRP"},
}

_GROUP_NAMES: dict[str, str] = {
    "A": "Поверхность атаки",
    "B": "Глубина защиты",
    "C": "Потоки данных",
    "D": "Технологические границы",
    "E": "Зависимости",
    "F": "Изменяемость",
}


def _trim_graph(
    all_nodes: list[str],
    all_edges: list[list[str]],
    entrypoint_ids: set[str],
    sink_ids: set[str],
    max_nodes: int,
) -> tuple[list[str], list[list[str]]]:
    """Сокращение графа до max_nodes наиболее значимых узлов.

    Приоритет отбора: точки входа, стоки, затем узлы с наибольшим числом
    связей. Рёбра фильтруются до оставшихся узлов.

    Args:
        all_nodes: Все идентификаторы узлов.
        all_edges: Все рёбра ``[source, target]``.
        entrypoint_ids: Множество точек входа.
        sink_ids: Множество стоков.
        max_nodes: Максимальное число узлов.

    Returns:
        Кортеж ``(trimmed_nodes, trimmed_edges)``.
    """
    if len(all_nodes) <= max_nodes:
        return all_nodes, all_edges

    # Считаем степень каждого узла
    degree: dict[str, int] = {}
    for src, tgt in all_edges:
        degree[src] = degree.get(src, 0) + 1
        degree[tgt] = degree.get(tgt, 0) + 1

    node_set = set(all_nodes)
    kept: set[str] = set()

    # 1. Все точки входа и стоки
    kept |= entrypoint_ids & node_set
    kept |= sink_ids & node_set

    # 2. Добираем по степени до лимита
    if len(kept) < max_nodes:
        remaining = [n for n in all_nodes if n not in kept]
        remaining.sort(key=lambda n: degree.get(n, 0), reverse=True)
        kept.update(remaining[: max_nodes - len(kept)])

    trimmed_nodes = [n for n in all_nodes if n in kept]
    trimmed_edges = [e for e in all_edges if e[0] in kept and e[1] in kept]
    return trimmed_nodes, trimmed_edges


def _build_graph_data(data: dict[str, Any], *, max_graph_nodes: int = 500) -> dict[str, Any]:
    """Формирование структуры GRAPH_DATA для встраивания в HTML.

    Args:
        data: Полный словарь combined.json.
        max_graph_nodes: Максимальное число узлов для графа визуализации.

    Returns:
        Словарь GRAPH_DATA со всеми полями для визуализации.
    """
    analyzer = data.get("analyzer", data)
    meta = analyzer.get("meta", {})
    metrics = analyzer.get("metrics", {})

    m1 = metrics.get("M1", {})
    a1 = metrics.get("A1", {})
    aggregate = metrics.get("aggregate", {})

    export = m1.get("export", {})
    raw_nodes = export.get("nodes", [])
    raw_edges = export.get("edges", [])

    # Определение точек входа: предпочитаем entrypoint_ids из export,
    # при отсутствии используем A1.sample[].method как запасной вариант
    if "entrypoint_ids" in export:
        entrypoint_ids = set(export["entrypoint_ids"])
    else:
        entrypoint_ids = {s["method"] for s in a1.get("sample", []) if "method" in s}

    sink_ids = set(export.get("sink_ids", []))

    # Сокращение графа до лимита
    all_nodes, all_edges = _trim_graph(
        raw_nodes, raw_edges, entrypoint_ids, sink_ids, max_graph_nodes,
    )

    # Классификация узлов
    nodes = _classify_nodes(all_nodes, entrypoint_ids, sink_ids)

    # Рёбра
    edges = [{"source": e[0], "target": e[1]} for e in all_edges]

    # Детали точек входа из A1
    entrypoint_details: dict[str, dict[str, Any]] = {}
    for sample in a1.get("sample", []):
        mid = sample.get("method", "")
        if mid:
            entrypoint_details[mid] = {
                "has_auth": sample.get("has_auth", False),
                "has_validation": sample.get("has_validation", False),
                "score": sample.get("score", 0.0),
            }

    # Все метрики: нормализованные значения из _METRIC_META
    all_metrics: dict[str, Any] = {}
    for mid, meta_info in _METRIC_META.items():
        block = metrics.get(mid, {})
        score_key = meta_info["score_key"]
        value = block.get(score_key)
        all_metrics[mid] = {
            "id": mid,
            "name": meta_info["name"],
            "title": meta_info["title"],
            "group": meta_info["group"],
            "status": block.get("status", "not_available"),
            "value": round(value, 4) if value is not None else None,
        }

    # Оверлеи: данные по узлам для метрик A1, A2, A3
    metric_overlays: dict[str, dict[str, float]] = {}

    # A1: score per entrypoint
    a1_overlay: dict[str, float] = {}
    for sample in a1.get("sample", []):
        mid_s = sample.get("method", "")
        if mid_s and sample.get("score") is not None:
            a1_overlay[mid_s] = sample["score"]
    if a1_overlay:
        metric_overlays["A1"] = a1_overlay

    # A2: ECI per method
    a2 = metrics.get("A2", {})
    a2_overlay: dict[str, float] = {}
    for entry in a2.get("top", []):
        mid_e = entry.get("method", "")
        if mid_e and entry.get("ECI") is not None:
            a2_overlay[mid_e] = entry["ECI"]
    if a2_overlay:
        metric_overlays["A2"] = a2_overlay

    # A3: entropy per entrypoint
    a3 = metrics.get("A3", {})
    a3_overlay: dict[str, float] = {}
    for sample in a3.get("sample", []):
        mid_s = sample.get("method", "")
        if mid_s and sample.get("entropy") is not None:
            a3_overlay[mid_s] = sample["entropy"]
    if a3_overlay:
        metric_overlays["A3"] = a3_overlay

    # Радар: средние значения по группам метрик
    group_values: dict[str, list[float]] = {}
    for mid, info in all_metrics.items():
        if info["value"] is not None and info["status"] == "ok":
            group_values.setdefault(info["group"], []).append(info["value"])

    radar_data: list[dict[str, Any]] = []
    for gid in ("A", "B", "C", "D", "E", "F"):
        vals = group_values.get(gid, [])
        avg = round(min(1.0, max(0.0, sum(vals) / len(vals))), 4) if vals else None
        radar_data.append({"group": gid, "label": _GROUP_NAMES[gid], "value": avg})

    repo_url = meta.get("repo_url", "")
    repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1] if repo_url else "unknown"

    return {
        "meta": {
            "repo_url": repo_url,
            "repo_name": repo_name,
            "mode": meta.get("mode", ""),
            "git_head": meta.get("git_head", ""),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        },
        "summary": {
            "nodes": m1.get("nodes", len(all_nodes)),
            "edges": m1.get("edges", len(all_edges)),
            "entrypoints": m1.get("entrypoints", len(entrypoint_ids)),
            "sinks": m1.get("sinks", len(sink_ids)),
            "aggregate_score": round(aggregate.get("score", 0.0), 4),
        },
        "nodes": nodes,
        "edges": edges,
        "entrypoint_details": entrypoint_details,
        "all_metrics": all_metrics,
        "metric_overlays": metric_overlays,
        "radar": radar_data,
        "aggregate": {
            "score": round(aggregate.get("score", 0.0), 4),
            "components": aggregate.get("components", {}),
        },
    }


def _render_html(graph_data: dict[str, Any]) -> str:
    """Генерация полного HTML-документа с встроенными CSS, JS и данными графа.

    Создаёт самодостаточный HTML с двумя вкладками: дашборд (радар + карточки
    метрик) и граф (D3 force-directed с оверлеями метрик). Все стили и скрипты
    встроены. Тема оформления — HUD dark.

    Args:
        graph_data: Структура GRAPH_DATA, сформированная ``_build_graph_data``.

    Returns:
        Строка с полным HTML-документом.
    """
    data_json = json.dumps(graph_data, ensure_ascii=False, indent=2)
    # Предотвращение выхода из контекста <script> через последовательность </
    data_json = data_json.replace("</", "<\\/")
    meta = graph_data["meta"]
    summary = graph_data["summary"]
    score_pct = round(summary["aggregate_score"] * 100, 1)
    commit_short = meta["git_head"][:8] if meta["git_head"] else "n/a"

    html = f"""\
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CSA Security Report &mdash; {_escape_html(meta["repo_name"])}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ======================================================================
   CSS Variables (HUD Theme)
   ====================================================================== */
:root {{
  --bg: #000000;
  --surface-1: #0d0d0d;
  --surface-2: #171717;
  --surface-3: #1f1f1f;
  --border: rgba(255, 255, 255, 0.08);
  --border-strong: rgba(255, 255, 255, 0.15);
  --text-primary: #ffffff;
  --text-secondary: #a3a3a3;
  --text-tertiary: #6b6b6b;
  --accent: #fb923c;
  --accent-soft: rgba(249, 115, 22, 0.1);
  --danger: #f87171;
  --success: #34d399;
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

html, body {{
  font-family: 'JetBrains Mono', monospace;
  background: var(--bg);
  color: var(--text-primary);
  height: 100%;
  overflow: hidden;
}}

/* ======================================================================
   Layout
   ====================================================================== */
#app {{
  display: flex;
  flex-direction: column;
  height: 100vh;
}}

/* ======================================================================
   Header / HUD Panel
   ====================================================================== */
.hud-panel {{
  position: relative;
  background: rgba(13, 13, 13, 0.85);
  backdrop-filter: blur(15px);
  -webkit-backdrop-filter: blur(15px);
  border: 1px solid var(--border);
  padding: 0.75rem 1.25rem;
}}
.hud-panel-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
}}
.hud-panel-title {{
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--text-primary);
  letter-spacing: 0.05em;
}}
.hud-panel-meta {{
  display: flex;
  gap: 1.5rem;
  align-items: center;
  flex-wrap: wrap;
}}
.hud-panel-meta span {{
  font-size: 0.6875rem;
  color: var(--text-tertiary);
  letter-spacing: 0.05em;
}}
.hud-panel-meta span b {{
  color: var(--text-secondary);
  font-weight: 500;
}}

/* ======================================================================
   Dot Corners
   ====================================================================== */
.dot-corner {{
  position: absolute;
  width: 4px;
  height: 4px;
  background: var(--text-secondary);
  z-index: 2;
}}
.dot-corner.tl {{ top: 6px; left: 6px; }}
.dot-corner.tr {{ top: 6px; right: 6px; }}
.dot-corner.bl {{ bottom: 6px; left: 6px; }}
.dot-corner.br {{ bottom: 6px; right: 6px; }}

/* ======================================================================
   Summary Row
   ====================================================================== */
.summary-row {{
  display: flex;
  gap: 0;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}}
.stat-card {{
  position: relative;
  flex: 1;
  background: var(--surface-1);
  border-right: 1px solid var(--border);
  padding: 0.75rem 1rem;
  min-width: 0;
}}
.stat-card:last-child {{ border-right: none; }}
.stat-label {{
  font-size: 0.5625rem;
  font-weight: 500;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.15em;
  margin-bottom: 0.35rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}}
.stat-value {{
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1;
}}
.stat-value.accent {{ color: var(--accent); }}
.stat-value.danger {{ color: var(--danger); }}

/* Progress bar for aggregate score */
.progress-bar {{
  position: relative;
  width: 100%;
  height: 4px;
  background: var(--surface-2);
  margin-top: 0.5rem;
  overflow: hidden;
}}
.progress-fill {{
  height: 100%;
  background: linear-gradient(90deg, var(--accent), #fdba74);
  transition: width 0.3s ease;
}}

/* ======================================================================
   Tab Navigation
   ====================================================================== */
.tab-nav {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--surface-1);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}}

/* ======================================================================
   Tab Content
   ====================================================================== */
.tab-content {{
  display: none;
  flex: 1;
  min-height: 0;
}}
.tab-content.active[data-tab-type="dashboard"] {{
  display: block;
  overflow-y: auto;
}}
.tab-content.active[data-tab-type="graph"] {{
  display: flex;
  flex-direction: column;
}}

/* ======================================================================
   Dashboard Content
   ====================================================================== */
.dashboard-content {{
  padding: 1.5rem 2rem;
  overflow-y: auto;
  flex: 1;
}}

/* Radar */
.radar-container {{
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 1rem 0 1.5rem;
}}

/* Metric Cards Grid */
.metrics-grid {{
  max-width: 960px;
  margin: 0 auto;
}}
.metrics-group {{
  margin-bottom: 1.5rem;
}}
.metrics-group-header {{
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 0.75rem;
  padding-bottom: 0.35rem;
  border-bottom: 1px solid var(--border);
}}
.metrics-group-row {{
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}}
.metric-card {{
  position: relative;
  flex: 1 1 180px;
  max-width: 220px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  padding: 0.75rem 0.875rem;
  cursor: pointer;
  transition: border-color 0.2s, background 0.2s;
}}
.metric-card:hover {{
  border-color: var(--border-strong);
  background: var(--surface-3);
}}
.metric-card.disabled {{
  opacity: 0.35;
  cursor: default;
  pointer-events: none;
}}
.metric-card-id {{
  font-size: 0.5625rem;
  font-weight: 600;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 0.25rem;
}}
.metric-card-name {{
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--text-primary);
  margin-bottom: 0.125rem;
}}
.metric-card-title {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  margin-bottom: 0.5rem;
  line-height: 1.3;
}}
.metric-card-value {{
  font-size: 1rem;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 0.35rem;
}}
.metric-progress {{
  width: 100%;
  height: 3px;
  background: var(--surface-1);
  overflow: hidden;
}}
.metric-progress-fill {{
  height: 100%;
  transition: width 0.3s ease;
}}

/* ======================================================================
   Btn-clipped (shared)
   ====================================================================== */
.btn-clipped {{
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0.4rem 0.8rem;
  background: transparent;
  border: none;
  color: var(--text-secondary);
  font-family: inherit;
  font-size: 0.6875rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  cursor: pointer;
  transition: all 0.2s ease;
  z-index: 0;
  --btn-cut: 6px;
  --btn-border-color: var(--border);
  --btn-fill: var(--bg);
  clip-path: polygon(
    0 0,
    calc(100% - var(--btn-cut)) 0,
    100% var(--btn-cut),
    100% 100%,
    var(--btn-cut) 100%,
    0 calc(100% - var(--btn-cut))
  );
}}
.btn-clipped::before,
.btn-clipped::after {{
  content: '';
  position: absolute;
  inset: 0;
  pointer-events: none;
}}
.btn-clipped::before {{
  background: var(--btn-border-color);
  z-index: -2;
}}
.btn-clipped::after {{
  inset: 1px;
  background: var(--btn-fill);
  clip-path: polygon(
    0 0,
    calc(100% - var(--btn-cut)) 0,
    100% var(--btn-cut),
    100% 100%,
    var(--btn-cut) 100%,
    0 calc(100% - var(--btn-cut))
  );
  z-index: -1;
  transition: background-color 0.2s ease;
}}
.btn-clipped:hover {{
  color: var(--text-primary);
  --btn-border-color: var(--border-strong);
  --btn-fill: var(--surface-2);
}}
.btn-clipped.active {{
  color: var(--bg);
  --btn-border-color: var(--accent);
  --btn-fill: var(--accent);
  font-weight: 600;
}}

/* ======================================================================
   Toolbar (Filter Buttons inside Graph tab)
   ====================================================================== */
.toolbar {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--surface-1);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  flex-wrap: wrap;
}}
.toolbar-label {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-right: 0.5rem;
}}
.toolbar-separator {{
  width: 1px;
  height: 20px;
  background: var(--border);
  margin: 0 0.25rem;
}}
.metric-select {{
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  font-family: inherit;
  font-size: 0.6875rem;
  padding: 0.35rem 0.5rem;
  outline: none;
  cursor: pointer;
  transition: border-color 0.2s;
}}
.metric-select:hover, .metric-select:focus {{
  border-color: var(--border-strong);
  color: var(--text-primary);
}}
.overlay-info {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  margin-left: 0.35rem;
}}

/* ======================================================================
   Graph Container
   ====================================================================== */
.graph-wrapper {{
  flex: 1;
  display: flex;
  position: relative;
  overflow: hidden;
}}
#graph-svg {{
  flex: 1;
  background: var(--bg);
}}

/* ======================================================================
   Tooltip
   ====================================================================== */
.tooltip {{
  position: absolute;
  pointer-events: none;
  background: rgba(13, 13, 13, 0.95);
  backdrop-filter: blur(10px);
  border: 1px solid var(--border-strong);
  padding: 0.4rem 0.6rem;
  font-size: 0.6875rem;
  color: var(--text-primary);
  white-space: nowrap;
  z-index: 100;
  opacity: 0;
  transition: opacity 0.15s ease;
}}
.tooltip.visible {{ opacity: 1; }}

/* ======================================================================
   Detail Panel (right side)
   ====================================================================== */
.detail-panel {{
  position: absolute;
  top: 0;
  right: 0;
  width: 340px;
  height: 100%;
  background: rgba(13, 13, 13, 0.92);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-left: 1px solid var(--border);
  padding: 1.25rem;
  overflow-y: auto;
  transform: translateX(100%);
  transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
  z-index: 50;
}}
.detail-panel.open {{ transform: translateX(0); }}
.detail-panel-close {{
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  background: none;
  border: 1px solid var(--border);
  color: var(--text-tertiary);
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  font-size: 0.875rem;
  font-family: inherit;
  transition: color 0.15s, border-color 0.15s;
}}
.detail-panel-close:hover {{
  color: var(--text-primary);
  border-color: var(--border-strong);
}}
.detail-title {{
  font-size: 0.625rem;
  font-weight: 600;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.15em;
  margin-bottom: 1rem;
}}
.detail-field {{
  margin-bottom: 0.875rem;
}}
.detail-field-label {{
  font-size: 0.5625rem;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 0.25rem;
}}
.detail-field-value {{
  font-size: 0.8125rem;
  color: var(--text-primary);
  word-break: break-all;
  line-height: 1.4;
}}

/* Badges */
.badge {{
  display: inline-flex;
  align-items: center;
  padding: 0.2rem 0.5rem;
  font-size: 0.5625rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  margin-right: 0.35rem;
  margin-bottom: 0.25rem;
}}
.badge.accent {{
  background: var(--accent-soft);
  border-color: rgba(249, 115, 22, 0.3);
  color: var(--accent);
}}
.badge.danger {{
  background: rgba(239, 68, 68, 0.1);
  border-color: rgba(239, 68, 68, 0.3);
  color: #f87171;
}}
.badge.success {{
  background: rgba(16, 185, 129, 0.1);
  border-color: rgba(16, 185, 129, 0.3);
  color: #34d399;
}}
.badge.warning {{
  background: rgba(245, 158, 11, 0.1);
  border-color: rgba(245, 158, 11, 0.3);
  color: #fbbf24;
}}

/* ======================================================================
   Legend
   ====================================================================== */
.legend {{
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-left: auto;
}}
.legend-item {{
  display: flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.625rem;
  color: var(--text-tertiary);
}}
.legend-dot {{
  width: 8px;
  height: 8px;
  border-radius: 50%;
}}

/* ======================================================================
   Pulsating animation for entry points
   ====================================================================== */
@keyframes pulse-ring {{
  0% {{ r: 7; opacity: 0.6; }}
  100% {{ r: 14; opacity: 0; }}
}}
.node-pulse {{
  animation: pulse-ring 2s ease-out infinite;
}}
</style>
</head>
<body>
<div id="app">

  <!-- Header -->
  <div class="hud-panel">
    <span class="dot-corner tl"></span>
    <span class="dot-corner tr"></span>
    <span class="dot-corner bl"></span>
    <span class="dot-corner br"></span>
    <div class="hud-panel-header">
      <div class="hud-panel-title">CSA &middot; SECURITY REPORT</div>
      <div class="hud-panel-meta">
        <span>repo: <b>{_escape_html(meta["repo_name"])}</b></span>
        <span>mode: <b>{_escape_html(meta["mode"])}</b></span>
        <span>commit: <b>{_escape_html(commit_short)}</b></span>
        <span>generated: <b>{_escape_html(meta["generated_at"])}</b></span>
      </div>
    </div>
  </div>

  <!-- Summary Row -->
  <div class="summary-row">
    <div class="stat-card">
      <span class="dot-corner tl"></span><span class="dot-corner tr"></span>
      <span class="dot-corner bl"></span><span class="dot-corner br"></span>
      <div class="stat-label">Узлы</div>
      <div class="stat-value">{summary["nodes"]}</div>
    </div>
    <div class="stat-card">
      <span class="dot-corner tl"></span><span class="dot-corner tr"></span>
      <span class="dot-corner bl"></span><span class="dot-corner br"></span>
      <div class="stat-label">Связи</div>
      <div class="stat-value">{summary["edges"]}</div>
    </div>
    <div class="stat-card">
      <span class="dot-corner tl"></span><span class="dot-corner tr"></span>
      <span class="dot-corner bl"></span><span class="dot-corner br"></span>
      <div class="stat-label">Точки входа</div>
      <div class="stat-value accent">{summary["entrypoints"]}</div>
    </div>
    <div class="stat-card">
      <span class="dot-corner tl"></span><span class="dot-corner tr"></span>
      <span class="dot-corner bl"></span><span class="dot-corner br"></span>
      <div class="stat-label">Стоки</div>
      <div class="stat-value danger">{summary["sinks"]}</div>
    </div>
    <div class="stat-card">
      <span class="dot-corner tl"></span><span class="dot-corner tr"></span>
      <span class="dot-corner bl"></span><span class="dot-corner br"></span>
      <div class="stat-label">Совокупная оценка</div>
      <div class="stat-value accent">{score_pct}<span style="font-size:0.875rem;font-weight:400;color:var(--text-tertiary)">%</span></div>
      <div class="progress-bar">
        <div class="progress-fill" style="width:{score_pct}%"></div>
      </div>
    </div>
  </div>

  <!-- Tab Navigation -->
  <div class="tab-nav">
    <button class="btn-clipped active" data-tab="dashboard" onclick="switchTab('dashboard')">Дашборд</button>
    <button class="btn-clipped" data-tab="graph" onclick="switchTab('graph')">Граф</button>
  </div>

  <!-- ================================================================
       Dashboard Tab
       ================================================================ -->
  <div id="tab-dashboard" class="tab-content active" data-tab-type="dashboard">
    <div class="dashboard-content">
      <div class="radar-container">
        <svg id="radar-svg" width="400" height="400"></svg>
      </div>
      <div class="metrics-grid" id="metrics-cards"></div>
    </div>
  </div>

  <!-- ================================================================
       Graph Tab
       ================================================================ -->
  <div id="tab-graph" class="tab-content" data-tab-type="graph">

    <!-- Toolbar -->
    <div class="toolbar">
      <span class="toolbar-label">Фильтр:</span>
      <button class="btn-clipped active" data-filter="all" onclick="setFilter('all')">Все</button>
      <button class="btn-clipped" data-filter="entrypoints" onclick="setFilter('entrypoints')">Точки входа</button>
      <button class="btn-clipped" data-filter="sinks" onclick="setFilter('sinks')">Стоки</button>
      <button class="btn-clipped" data-filter="hide-tests" onclick="setFilter('hide-tests')">Скрыть тесты</button>

      <div class="toolbar-separator"></div>

      <span class="toolbar-label">Оверлей:</span>
      <select id="metric-overlay-select" class="metric-select" onchange="setMetricOverlay(this.value)">
        <option value="topology">Топология</option>
      </select>
      <span class="overlay-info" id="overlay-info"></span>

      <div class="legend">
        <div class="legend-item"><div class="legend-dot" style="background:#fb923c"></div>Точка входа</div>
        <div class="legend-item"><div class="legend-dot" style="background:#f87171"></div>Сток</div>
        <div class="legend-item"><div class="legend-dot" style="background:#6b6b6b"></div>Метод</div>
        <div class="legend-item"><div class="legend-dot" style="background:#6b6b6b;opacity:0.3"></div>Тест</div>
      </div>
    </div>

    <!-- Graph Area -->
    <div class="graph-wrapper">
      <svg id="graph-svg"></svg>
      <div class="tooltip" id="tooltip"></div>

      <!-- Detail Panel -->
      <div class="detail-panel" id="detail-panel">
        <button class="detail-panel-close" onclick="closeDetail()">&times;</button>
        <div class="detail-title">Информация об узле</div>
        <div id="detail-content"></div>
      </div>
    </div>

  </div>

</div>

<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
// =========================================================================
//  Data
// =========================================================================
const GRAPH_DATA = {data_json};

// =========================================================================
//  Constants
// =========================================================================
const NODE_STYLE = {{
  entrypoint: {{ r: 7, fill: '#fb923c', opacity: 1 }},
  sink:       {{ r: 7, fill: '#f87171', opacity: 1 }},
  test:       {{ r: 2, fill: '#6b6b6b', opacity: 0.3 }},
  regular:    {{ r: 3, fill: '#6b6b6b', opacity: 1 }},
}};

const GROUP_NAMES = {{
  A: 'Поверхность атаки',
  B: 'Глубина защиты',
  C: 'Потоки данных',
  D: 'Технологические границы',
  E: 'Зависимости',
  F: 'Изменяемость',
}};

// =========================================================================
//  State
// =========================================================================
let currentFilter = 'all';
let currentOverlay = 'topology';
let overlayMin = 0;
let overlayMax = 1;
let selectedNode = null;

// =========================================================================
//  Helpers
// =========================================================================
function escapeHtml(str) {{
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}}

function riskColor(t) {{
  t = Math.max(0, Math.min(1, t));
  const r1 = 0x34, g1 = 0xd3, b1 = 0x99;  // #34d399 green
  const r2 = 0xfb, g2 = 0xbf, b2 = 0x24;  // #fbbf24 yellow
  const r3 = 0xf8, g3 = 0x71, b3 = 0x71;  // #f87171 red
  let r, g, b;
  if (t < 0.5) {{
    const s = t * 2;
    r = r1 + (r2 - r1) * s;
    g = g1 + (g2 - g1) * s;
    b = b1 + (b2 - b1) * s;
  }} else {{
    const s = (t - 0.5) * 2;
    r = r2 + (r3 - r2) * s;
    g = g2 + (g3 - g2) * s;
    b = b2 + (b3 - b2) * s;
  }}
  return `rgb(${{Math.round(r)}},${{Math.round(g)}},${{Math.round(b)}})`;
}}

function riskBarColor(v) {{
  if (v < 0.3) return '#34d399';
  if (v < 0.7) return '#fbbf24';
  return '#f87171';
}}

// =========================================================================
//  Tab Switching
// =========================================================================
function switchTab(tabId) {{
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-nav .btn-clipped').forEach(btn => btn.classList.remove('active'));
  document.getElementById('tab-' + tabId).classList.add('active');
  document.querySelector('.tab-nav .btn-clipped[data-tab="' + tabId + '"]').classList.add('active');
  if (tabId === 'graph') {{
    const w = svg.node().parentElement.clientWidth;
    const h = svg.node().parentElement.clientHeight;
    svg.attr('viewBox', [0, 0, w, h]);
    simulation.force('center', d3.forceCenter(w / 2, h / 2));
    simulation.alpha(0.3).restart();
  }}
}}

// =========================================================================
//  Populate metric overlay select
// =========================================================================
(function populateOverlaySelect() {{
  const sel = document.getElementById('metric-overlay-select');
  const metricsMap = GRAPH_DATA.all_metrics;
  const ids = Object.keys(metricsMap).sort();
  ids.forEach(mid => {{
    const m = metricsMap[mid];
    if (m.status === 'ok') {{
      const opt = document.createElement('option');
      opt.value = mid;
      opt.textContent = mid + ' — ' + m.name;
      sel.appendChild(opt);
    }}
  }});
}})();

// =========================================================================
//  Build Radar Chart
// =========================================================================
(function buildRadar() {{
  const radarSvg = d3.select('#radar-svg');
  const W = 400, H = 400;
  const cx = W / 2, cy = H / 2;
  const R = 140;
  const data = GRAPH_DATA.radar;
  const n = data.length;
  const angleSlice = (2 * Math.PI) / n;
  const levels = [0.25, 0.5, 0.75, 1.0];
  const gRadar = radarSvg.append('g').attr('transform', `translate(${{cx}},${{cy}})`);

  // Grid polygons
  levels.forEach(lv => {{
    const pts = [];
    for (let i = 0; i < n; i++) {{
      const angle = angleSlice * i - Math.PI / 2;
      pts.push([R * lv * Math.cos(angle), R * lv * Math.sin(angle)]);
    }}
    gRadar.append('polygon')
      .attr('points', pts.map(p => p.join(',')).join(' '))
      .attr('fill', 'none')
      .attr('stroke', 'rgba(255,255,255,0.12)')
      .attr('stroke-width', lv === 1.0 ? 1.5 : 0.5)
      .attr('stroke-dasharray', lv === 1.0 ? 'none' : '2,3');

    // Level label on first axis
    const labelAngle = angleSlice * 0 - Math.PI / 2;
    gRadar.append('text')
      .attr('x', R * lv * Math.cos(labelAngle) + 6)
      .attr('y', R * lv * Math.sin(labelAngle) - 4)
      .attr('fill', 'rgba(255,255,255,0.25)')
      .attr('font-size', '9px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .text(Math.round(lv * 100) + '%');
  }});

  // Axis lines + labels
  data.forEach((d, i) => {{
    const angle = angleSlice * i - Math.PI / 2;
    const x2 = R * Math.cos(angle);
    const y2 = R * Math.sin(angle);
    gRadar.append('line')
      .attr('x1', 0).attr('y1', 0)
      .attr('x2', x2).attr('y2', y2)
      .attr('stroke', 'rgba(255,255,255,0.1)')
      .attr('stroke-width', 1);

    // Group letter label
    const lx = (R + 16) * Math.cos(angle);
    const ly = (R + 16) * Math.sin(angle);
    gRadar.append('text')
      .attr('x', lx).attr('y', ly)
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('fill', '#e5e5e5')
      .attr('font-size', '13px')
      .attr('font-weight', '600')
      .attr('font-family', 'JetBrains Mono, monospace')
      .text(d.group);

    // Group name label
    const nlx = (R + 34) * Math.cos(angle);
    const nly = (R + 34) * Math.sin(angle);
    gRadar.append('text')
      .attr('x', nlx).attr('y', nly)
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('fill', '#737373')
      .attr('font-size', '9px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .text(d.label.length > 14 ? d.label.slice(0, 14) + '..' : d.label);

    // Value label near dot
    const v = (d.value !== null && d.value !== undefined) ? d.value : null;
    if (v !== null) {{
      const vx = (R * v + 10) * Math.cos(angle);
      const vy = (R * v + 10) * Math.sin(angle);
      gRadar.append('text')
        .attr('x', vx).attr('y', vy)
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'central')
        .attr('fill', riskBarColor(v))
        .attr('font-size', '9px')
        .attr('font-weight', '600')
        .attr('font-family', 'JetBrains Mono, monospace')
        .text(Math.round(v * 100) + '%');
    }}
  }});

  // Data area polygon
  const valuePts = [];
  data.forEach((d, i) => {{
    const v = (d.value !== null && d.value !== undefined) ? Math.min(1, Math.max(0, d.value)) : 0;
    const angle = angleSlice * i - Math.PI / 2;
    valuePts.push([R * v * Math.cos(angle), R * v * Math.sin(angle)]);
  }});
  gRadar.append('polygon')
    .attr('points', valuePts.map(p => p.join(',')).join(' '))
    .attr('fill', 'rgba(251,146,60,0.12)')
    .attr('stroke', '#fb923c')
    .attr('stroke-width', 2);

  // Dots on vertices
  valuePts.forEach((p, i) => {{
    const v = data[i].value;
    if (v !== null && v !== undefined) {{
      gRadar.append('circle')
        .attr('cx', p[0]).attr('cy', p[1])
        .attr('r', 4)
        .attr('fill', '#fb923c')
        .attr('stroke', '#000')
        .attr('stroke-width', 1.5);
    }}
  }});
}})();

// =========================================================================
//  Build Metric Cards
// =========================================================================
(function buildMetricCards() {{
  const container = document.getElementById('metrics-cards');
  const groups = {{}};
  Object.values(GRAPH_DATA.all_metrics).forEach(m => {{
    if (!groups[m.group]) groups[m.group] = [];
    groups[m.group].push(m);
  }});
  const groupOrder = ['A', 'B', 'C', 'D', 'E', 'F'];
  groupOrder.forEach(gid => {{
    const items = groups[gid];
    if (!items) return;
    const grp = document.createElement('div');
    grp.className = 'metrics-group';
    const hdr = document.createElement('div');
    hdr.className = 'metrics-group-header';
    hdr.textContent = gid + ' — ' + (GROUP_NAMES[gid] || gid);
    grp.appendChild(hdr);
    const row = document.createElement('div');
    row.className = 'metrics-group-row';
    items.forEach(m => {{
      const card = document.createElement('div');
      card.className = 'metric-card' + (m.status !== 'ok' ? ' disabled' : '');
      if (m.status === 'ok') {{
        card.onclick = function() {{
          switchTab('graph');
          setMetricOverlay(m.id);
          document.getElementById('metric-overlay-select').value = m.id;
        }};
      }}
      const val = m.value !== null ? m.value : 0;
      const pct = Math.round(val * 100);
      card.innerHTML =
        '<div class="metric-card-id">' + escapeHtml(m.id) + '</div>' +
        '<div class="metric-card-name">' + escapeHtml(m.name) + '</div>' +
        '<div class="metric-card-title">' + escapeHtml(m.title) + '</div>' +
        '<div class="metric-card-value">' + (m.value !== null ? pct + '%' : 'N/A') + '</div>' +
        '<div class="metric-progress"><div class="metric-progress-fill" style="width:' +
        pct + '%;background:' + (m.value !== null ? riskBarColor(val) : '#333') + '"></div></div>';
      row.appendChild(card);
    }});
    grp.appendChild(row);
    container.appendChild(grp);
  }});
}})();

// =========================================================================
//  Build D3 Graph
// =========================================================================
const svg = d3.select('#graph-svg');

/* Initial size: use window dimensions since the graph tab may be hidden */
const initW = window.innerWidth;
const initH = window.innerHeight;

svg.attr('viewBox', [0, 0, initW, initH]);

const g = svg.append('g');

// Zoom
const zoom = d3.zoom()
  .scaleExtent([0.1, 8])
  .on('zoom', (event) => {{
    g.attr('transform', event.transform);
  }});
svg.call(zoom);

// Build node index
const nodeIndex = new Map();
GRAPH_DATA.nodes.forEach((n, i) => {{ nodeIndex.set(n.id, i); }});

// Filter edges to only include those whose source/target exist in nodes
const validEdges = GRAPH_DATA.edges.filter(e => nodeIndex.has(e.source) && nodeIndex.has(e.target));

// Simulation
const simulation = d3.forceSimulation(GRAPH_DATA.nodes)
  .force('link', d3.forceLink(validEdges).id(d => d.id).distance(40).strength(0.3))
  .force('charge', d3.forceManyBody().strength(-60).distanceMax(300))
  .force('center', d3.forceCenter(initW / 2, initH / 2))
  .force('collision', d3.forceCollide().radius(d => NODE_STYLE[d.type].r + 1))
  .alphaDecay(0.03);

svg.append('defs');

// Draw edges
const linkG = g.append('g').attr('class', 'links');
const links = linkG.selectAll('line')
  .data(validEdges)
  .join('line')
  .attr('stroke', '#555')
  .attr('stroke-width', 0.5)
  .attr('stroke-opacity', 0.8);

// Draw nodes
const nodeG = g.append('g').attr('class', 'nodes');

// Pulse rings for entrypoints
const pulseG = g.append('g').attr('class', 'pulses');
const pulses = pulseG.selectAll('circle')
  .data(GRAPH_DATA.nodes.filter(d => d.type === 'entrypoint'))
  .join('circle')
  .attr('r', 7)
  .attr('fill', 'none')
  .attr('stroke', '#fb923c')
  .attr('stroke-width', 1)
  .attr('opacity', 0.6)
  .each(function() {{
    const el = d3.select(this);
    function animatePulse() {{
      el.attr('r', 7).attr('opacity', 0.6)
        .transition().duration(2000).ease(d3.easeQuadOut)
        .attr('r', 16).attr('opacity', 0)
        .on('end', animatePulse);
    }}
    animatePulse();
  }});

const nodes = nodeG.selectAll('circle')
  .data(GRAPH_DATA.nodes)
  .join('circle')
  .attr('r', d => NODE_STYLE[d.type].r)
  .attr('fill', d => NODE_STYLE[d.type].fill)
  .attr('opacity', d => NODE_STYLE[d.type].opacity)
  .attr('stroke', 'none')
  .attr('stroke-width', 0)
  .style('cursor', 'pointer')
  .call(d3.drag()
    .on('start', dragStarted)
    .on('drag', dragged)
    .on('end', dragEnded)
  );

// Tooltip
const tooltip = document.getElementById('tooltip');

nodes
  .on('mouseenter', (event, d) => {{
    tooltip.textContent = d.label;
    tooltip.classList.add('visible');
  }})
  .on('mousemove', (event) => {{
    const rect = svg.node().parentElement.getBoundingClientRect();
    tooltip.style.left = (event.clientX - rect.left + 12) + 'px';
    tooltip.style.top = (event.clientY - rect.top - 8) + 'px';
  }})
  .on('mouseleave', () => {{
    tooltip.classList.remove('visible');
  }})
  .on('click', (event, d) => {{
    event.stopPropagation();
    selectNode(d);
  }});

svg.on('click', () => {{
  deselectNode();
  closeDetail();
}});

// Simulation tick
simulation.on('tick', () => {{
  links
    .attr('x1', d => d.source.x)
    .attr('y1', d => d.source.y)
    .attr('x2', d => d.target.x)
    .attr('y2', d => d.target.y);

  nodes
    .attr('cx', d => d.x)
    .attr('cy', d => d.y);

  pulses
    .attr('cx', d => d.x)
    .attr('cy', d => d.y);
}});

// =========================================================================
//  Drag handlers
// =========================================================================
function dragStarted(event, d) {{
  if (!event.active) simulation.alphaTarget(0.3).restart();
  d.fx = d.x;
  d.fy = d.y;
}}

function dragged(event, d) {{
  d.fx = event.x;
  d.fy = event.y;
}}

function dragEnded(event, d) {{
  if (!event.active) simulation.alphaTarget(0);
  d.fx = null;
  d.fy = null;
}}

// =========================================================================
//  Selection
// =========================================================================
function selectNode(d) {{
  selectedNode = d;

  // Reset stroke
  nodes
    .attr('stroke', 'none')
    .attr('stroke-width', 0);

  // Reset edges depending on overlay mode
  if (currentOverlay === 'topology') {{
    links
      .attr('stroke', '#555')
      .attr('stroke-width', 0.5)
      .attr('stroke-opacity', 0.8);
  }}

  // Highlight selected node
  nodes.filter(n => n.id === d.id)
    .attr('stroke', '#fb923c')
    .attr('stroke-width', 2);

  // Highlight connected edges
  links.filter(l => l.source.id === d.id || l.target.id === d.id)
    .attr('stroke', '#fb923c')
    .attr('stroke-width', 1.5)
    .attr('stroke-opacity', 1);

  showDetail(d);
}}

function deselectNode() {{
  selectedNode = null;
  nodes.attr('stroke', 'none').attr('stroke-width', 0);
  if (currentOverlay === 'topology') {{
    links.attr('stroke', '#555').attr('stroke-width', 0.5).attr('stroke-opacity', 0.8);
  }} else {{
    links.attr('stroke', '#555').attr('stroke-width', 0.5).attr('stroke-opacity', 0.15);
  }}
}}

// =========================================================================
//  Detail panel
// =========================================================================
function showDetail(d) {{
  const panel = document.getElementById('detail-panel');
  const content = document.getElementById('detail-content');

  const typeLabels = {{
    entrypoint: '<span class="badge accent">Точка входа</span>',
    sink: '<span class="badge danger">Сток</span>',
    test: '<span class="badge warning">Тест</span>',
    regular: '<span class="badge">Метод</span>',
  }};

  let html = `
    <div class="detail-field">
      <div class="detail-field-label">Тип</div>
      <div class="detail-field-value">${{typeLabels[d.type]}}</div>
    </div>
    <div class="detail-field">
      <div class="detail-field-label">Краткое имя</div>
      <div class="detail-field-value">${{escapeHtml(d.label)}}</div>
    </div>
    <div class="detail-field">
      <div class="detail-field-label">Полный идентификатор</div>
      <div class="detail-field-value" style="font-size:0.6875rem">${{escapeHtml(d.id)}}</div>
    </div>
  `;

  // Connected edges count
  const inCount = validEdges.filter(e => (e.target.id || e.target) === d.id).length;
  const outCount = validEdges.filter(e => (e.source.id || e.source) === d.id).length;
  html += `
    <div class="detail-field">
      <div class="detail-field-label">Связи</div>
      <div class="detail-field-value">
        <span class="badge">входящих: ${{inCount}}</span>
        <span class="badge">исходящих: ${{outCount}}</span>
      </div>
    </div>
  `;

  // A1 entrypoint details
  const ep = GRAPH_DATA.entrypoint_details[d.id];
  if (ep) {{
    html += `
      <div class="detail-field">
        <div class="detail-field-label">Безопасность (A1)</div>
        <div class="detail-field-value">
          <span class="badge ${{ep.has_auth ? 'success' : 'danger'}}">${{ep.has_auth ? 'auth: да' : 'auth: нет'}}</span>
          <span class="badge ${{ep.has_validation ? 'success' : 'danger'}}">${{ep.has_validation ? 'валидация: да' : 'валидация: нет'}}</span>
        </div>
      </div>
      <div class="detail-field">
        <div class="detail-field-label">Оценка ASE</div>
        <div class="detail-field-value" style="color:var(--accent)">${{ep.score.toFixed(2)}}</div>
      </div>
    `;
  }}

  // Overlay metric details for this node
  if (currentOverlay !== 'topology') {{
    const overlayData = GRAPH_DATA.metric_overlays[currentOverlay];
    const metricInfo = GRAPH_DATA.all_metrics[currentOverlay];
    if (metricInfo) {{
      const nodeVal = overlayData ? overlayData[d.id] : undefined;
      const oRange = overlayMax - overlayMin || 1;
      const normVal = nodeVal !== undefined ? (nodeVal - overlayMin) / oRange : undefined;
      html += `
        <div class="detail-field">
          <div class="detail-field-label">Оверлей: ${{escapeHtml(currentOverlay)}} — ${{escapeHtml(metricInfo.name)}}</div>
          <div class="detail-field-value" style="color:${{normVal !== undefined ? riskColor(normVal) : 'var(--text-tertiary)'}}">
            ${{nodeVal !== undefined ? nodeVal.toFixed(2) : 'нет данных'}}
          </div>
        </div>
        <div class="detail-field">
          <div class="detail-field-label">Системное значение ${{escapeHtml(currentOverlay)}}</div>
          <div class="detail-field-value">${{metricInfo.value !== null ? (metricInfo.value * 100).toFixed(1) + '%' : 'N/A'}}</div>
        </div>
      `;
    }}
  }}

  content.innerHTML = html;
  panel.classList.add('open');
}}

function closeDetail() {{
  document.getElementById('detail-panel').classList.remove('open');
}}

// =========================================================================
//  Metric Overlay System
// =========================================================================
function setMetricOverlay(metricId) {{
  currentOverlay = metricId;
  document.getElementById('metric-overlay-select').value = metricId;
  const t = d3.transition().duration(400);

  if (metricId === 'topology') {{
    // Restore original topology view
    nodes.transition(t)
      .attr('fill', d => NODE_STYLE[d.type].fill)
      .attr('r', d => getNodeRadius(d))
      .attr('opacity', d => getNodeOpacity(d));
    links.transition(t)
      .attr('stroke', '#555')
      .attr('stroke-opacity', d => {{
        const srcVis = isNodeVisible(d.source);
        const tgtVis = isNodeVisible(d.target);
        return (srcVis && tgtVis) ? 0.8 : 0.05;
      }});
    pulses.transition(t).attr('opacity', 0.6);
    updateOverlayInfo(null);
    return;
  }}

  const metricInfo = GRAPH_DATA.all_metrics[metricId];
  const overlayData = GRAPH_DATA.metric_overlays[metricId];

  if (overlayData) {{
    // Normalize overlay values to [0, 1] for color and size
    const vals = Object.values(overlayData);
    const oMin = Math.min(...vals);
    const oMax = Math.max(...vals);
    const oRange = oMax - oMin || 1;
    overlayMin = oMin;
    overlayMax = oMax;
    function normalize(v) {{ return (v - oMin) / oRange; }}

    nodes.transition(t)
      .attr('fill', d => {{
        const v = overlayData[d.id];
        return v !== undefined ? riskColor(normalize(v)) : '#333';
      }})
      .attr('r', d => {{
        if (!isNodeVisible(d)) return 1;
        const v = overlayData[d.id];
        return v !== undefined ? 3 + normalize(v) * 9 : 2;
      }})
      .attr('opacity', d => {{
        if (!isNodeVisible(d)) return 0.03;
        const v = overlayData[d.id];
        return v !== undefined ? 1 : 0.15;
      }});
    links.transition(t)
      .attr('stroke', '#555')
      .attr('stroke-opacity', 0.15);
    pulses.transition(t).attr('opacity', 0);
  }} else {{
    // Metric has no per-node overlay — keep topology, just show info
    nodes.transition(t)
      .attr('fill', d => NODE_STYLE[d.type].fill)
      .attr('r', d => getNodeRadius(d))
      .attr('opacity', d => getNodeOpacity(d));
    links.transition(t)
      .attr('stroke', '#555')
      .attr('stroke-opacity', d => {{
        const srcVis = isNodeVisible(d.source);
        const tgtVis = isNodeVisible(d.target);
        return (srcVis && tgtVis) ? 0.8 : 0.05;
      }});
    pulses.transition(t).attr('opacity', 0.6);
  }}

  updateOverlayInfo(metricId);
}}

function updateOverlayInfo(metricId) {{
  const infoEl = document.getElementById('overlay-info');
  if (!metricId) {{
    infoEl.textContent = '';
    return;
  }}
  const m = GRAPH_DATA.all_metrics[metricId];
  if (!m) {{ infoEl.textContent = ''; return; }}
  const overlayData = GRAPH_DATA.metric_overlays[metricId];
  const nodeCount = overlayData ? Object.keys(overlayData).length : 0;
  const valStr = m.value !== null ? (m.value * 100).toFixed(1) + '%' : 'N/A';
  infoEl.textContent = m.title + ' = ' + valStr + (nodeCount ? ' (' + nodeCount + ' узлов)' : ' (системная)');
  if (m.value !== null) {{
    infoEl.style.color = m.value < 0.3 ? 'var(--success)' : m.value < 0.7 ? '#fbbf24' : 'var(--danger)';
  }} else {{
    infoEl.style.color = 'var(--text-tertiary)';
  }}
}}

// =========================================================================
//  Filters
// =========================================================================
function setFilter(filter) {{
  currentFilter = filter;

  // Update buttons
  document.querySelectorAll('.toolbar .btn-clipped[data-filter]').forEach(btn => {{
    btn.classList.toggle('active', btn.dataset.filter === filter);
  }});

  applyFilter();
}}

function applyFilter() {{
  const t = d3.transition().duration(300);

  if (currentOverlay !== 'topology' && GRAPH_DATA.metric_overlays[currentOverlay]) {{
    // Re-apply overlay with current filter
    setMetricOverlay(currentOverlay);
    return;
  }}

  nodes.transition(t)
    .attr('opacity', d => getNodeOpacity(d))
    .attr('r', d => getNodeRadius(d));

  pulses.transition(t)
    .attr('opacity', d => currentFilter === 'sinks' ? 0 : 0.6);

  links.transition(t)
    .attr('stroke-opacity', d => {{
      const srcVisible = isNodeVisible(d.source);
      const tgtVisible = isNodeVisible(d.target);
      return (srcVisible && tgtVisible) ? 0.8 : 0.05;
    }});

  // Re-apply selection highlight if any
  if (selectedNode) {{
    links.filter(l => l.source.id === selectedNode.id || l.target.id === selectedNode.id)
      .transition(t)
      .attr('stroke', '#fb923c')
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 1);
  }}
}}

function isNodeVisible(d) {{
  switch (currentFilter) {{
    case 'entrypoints': return d.type === 'entrypoint';
    case 'sinks': return d.type === 'sink';
    case 'hide-tests': return d.type !== 'test';
    default: return true;
  }}
}}

function getNodeOpacity(d) {{
  if (!isNodeVisible(d)) return 0.03;
  return NODE_STYLE[d.type].opacity;
}}

function getNodeRadius(d) {{
  if (!isNodeVisible(d)) return 1;
  return NODE_STYLE[d.type].r;
}}

// =========================================================================
//  Resize handler
// =========================================================================
let _resizeTimer;
window.addEventListener('resize', () => {{
  clearTimeout(_resizeTimer);
  _resizeTimer = setTimeout(() => {{
    if (!document.getElementById('tab-graph').classList.contains('active')) return;
    const w = svg.node().parentElement.clientWidth;
    const h = svg.node().parentElement.clientHeight;
    svg.attr('viewBox', [0, 0, w, h]);
    simulation.force('center', d3.forceCenter(w / 2, h / 2));
    simulation.alpha(0.1).restart();
  }}, 150);
}});
</script>
</body>
</html>"""

    return html


def _escape_html(text: str) -> str:
    """Экранирование спецсимволов HTML.

    Args:
        text: Исходная строка.

    Returns:
        Строка с заменёнными ``&``, ``<``, ``>``, ``"`` и ``'``.
    """
    import html as _html_mod
    return _html_mod.escape(text, quote=True)


def main(argv: list[str] | None = None) -> int:
    """Точка входа CLI-скрипта.

    Args:
        argv: Аргументы командной строки. ``None`` означает ``sys.argv[1:]``.

    Returns:
        Код возврата: 0 при успехе, 1 при ошибке.
    """
    args = _parse_args(argv)
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Ошибка: файл не найден: {input_path}", file=sys.stderr)
        return 1

    try:
        data = _load_combined(input_path)
    except json.JSONDecodeError as exc:
        print(f"Ошибка разбора JSON: {exc}", file=sys.stderr)
        return 1

    graph_data = _build_graph_data(data, max_graph_nodes=args.max_graph_nodes)
    html = _render_html(graph_data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    node_counts = {}
    for n in graph_data["nodes"]:
        node_counts[n["type"]] = node_counts.get(n["type"], 0) + 1

    print(f"Отчёт CSA сгенерирован: {output_path}")
    print(f"  Узлов: {len(graph_data['nodes'])} "
          f"(entrypoint={node_counts.get('entrypoint', 0)}, "
          f"sink={node_counts.get('sink', 0)}, "
          f"test={node_counts.get('test', 0)}, "
          f"regular={node_counts.get('regular', 0)})")
    print(f"  Связей: {len(graph_data['edges'])}")
    print(f"  Размер файла: {output_path.stat().st_size:,} байт")
    available = sum(1 for m in graph_data["all_metrics"].values() if m["status"] == "ok")
    total = len(graph_data["all_metrics"])
    print(f"  Метрик: {available}/{total} доступно")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
