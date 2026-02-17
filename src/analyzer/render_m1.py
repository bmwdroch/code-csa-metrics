"""Генератор интерактивного HTML-отчёта для метрики M1 (Security Topology Graph).

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
        description="Генерация интерактивного HTML-отчёта M1 (Security Topology Graph)",
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Путь к combined.json",
    )
    parser.add_argument(
        "--output", "-o",
        default="m1-report.html",
        help="Путь к выходному HTML-файлу (по умолчанию: m1-report.html)",
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


def _build_graph_data(data: dict[str, Any]) -> dict[str, Any]:
    """Формирование структуры GRAPH_DATA для встраивания в HTML.

    Args:
        data: Полный словарь combined.json.

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
    all_nodes = export.get("nodes", [])
    all_edges = export.get("edges", [])

    # Определение точек входа: предпочитаем entrypoint_ids из export,
    # при отсутствии используем A1.sample[].method как запасной вариант
    if "entrypoint_ids" in export:
        entrypoint_ids = set(export["entrypoint_ids"])
    else:
        entrypoint_ids = {s["method"] for s in a1.get("sample", []) if "method" in s}

    sink_ids = set(export.get("sink_ids", []))

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
    }


def _render_html(graph_data: dict[str, Any]) -> str:
    """Генерация полного HTML-документа с встроенными CSS, JS и данными графа.

    Args:
        graph_data: Структура GRAPH_DATA для визуализации.

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
<title>M1 Security Topology &mdash; {_escape_html(meta["repo_name"])}</title>
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
   Toolbar (Filter Buttons)
   ====================================================================== */
.toolbar {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--surface-1);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}}
.toolbar-label {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-right: 0.5rem;
}}

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
      <div class="hud-panel-title">M1 &middot; SECURITY TOPOLOGY GRAPH</div>
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

  <!-- Toolbar -->
  <div class="toolbar">
    <span class="toolbar-label">Фильтр:</span>
    <button class="btn-clipped active" data-filter="all" onclick="setFilter('all')">Все</button>
    <button class="btn-clipped" data-filter="entrypoints" onclick="setFilter('entrypoints')">Точки входа</button>
    <button class="btn-clipped" data-filter="sinks" onclick="setFilter('sinks')">Стоки</button>
    <button class="btn-clipped" data-filter="hide-tests" onclick="setFilter('hide-tests')">Скрыть тесты</button>

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

// =========================================================================
//  State
// =========================================================================
let currentFilter = 'all';
let selectedNode = null;

// =========================================================================
//  Build D3 graph
// =========================================================================
const svg = d3.select('#graph-svg');
const width = svg.node().parentElement.clientWidth;
const height = svg.node().parentElement.clientHeight;

svg.attr('viewBox', [0, 0, width, height]);

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
  .force('center', d3.forceCenter(width / 2, height / 2))
  .force('collision', d3.forceCollide().radius(d => NODE_STYLE[d.type].r + 1))
  .alphaDecay(0.03);

svg.append('defs');

// Draw edges
const linkG = g.append('g').attr('class', 'links');
const links = linkG.selectAll('line')
  .data(validEdges)
  .join('line')
  .attr('stroke', '#333')
  .attr('stroke-width', 0.5)
  .attr('stroke-opacity', 0.6);

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

  // Reset all
  nodes
    .attr('stroke', 'none')
    .attr('stroke-width', 0);

  links
    .attr('stroke', '#333')
    .attr('stroke-width', 0.5)
    .attr('stroke-opacity', 0.6);

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
  links.attr('stroke', '#333').attr('stroke-width', 0.5).attr('stroke-opacity', 0.6);
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

  content.innerHTML = html;
  panel.classList.add('open');
}}

function closeDetail() {{
  document.getElementById('detail-panel').classList.remove('open');
}}

function escapeHtml(str) {{
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}}

// =========================================================================
//  Filters
// =========================================================================
function setFilter(filter) {{
  currentFilter = filter;

  // Update buttons
  document.querySelectorAll('.toolbar .btn-clipped').forEach(btn => {{
    btn.classList.toggle('active', btn.dataset.filter === filter);
  }});

  applyFilter();
}}

function applyFilter() {{
  const t = d3.transition().duration(300);

  nodes.transition(t)
    .attr('opacity', d => getNodeOpacity(d))
    .attr('r', d => getNodeRadius(d));

  pulses.transition(t)
    .attr('opacity', d => currentFilter === 'sinks' ? 0 : (currentFilter === 'hide-tests' ? 0.6 : 0.6));

  links.transition(t)
    .attr('stroke-opacity', d => {{
      const srcVisible = isNodeVisible(d.source);
      const tgtVisible = isNodeVisible(d.target);
      return (srcVisible && tgtVisible) ? 0.6 : 0.03;
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
//  Resize handler (с дебаунсингом)
// =========================================================================
let _resizeTimer;
window.addEventListener('resize', () => {{
  clearTimeout(_resizeTimer);
  _resizeTimer = setTimeout(() => {{
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

    graph_data = _build_graph_data(data)
    html = _render_html(graph_data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    node_counts = {}
    for n in graph_data["nodes"]:
        node_counts[n["type"]] = node_counts.get(n["type"], 0) + 1

    print(f"Отчёт M1 сгенерирован: {output_path}")
    print(f"  Узлов: {len(graph_data['nodes'])} "
          f"(entrypoint={node_counts.get('entrypoint', 0)}, "
          f"sink={node_counts.get('sink', 0)}, "
          f"test={node_counts.get('test', 0)}, "
          f"regular={node_counts.get('regular', 0)})")
    print(f"  Связей: {len(graph_data['edges'])}")
    print(f"  Размер файла: {output_path.stat().st_size:,} байт")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
