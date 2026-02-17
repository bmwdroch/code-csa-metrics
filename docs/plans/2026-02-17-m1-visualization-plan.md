# M1 Visualization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Создать Python-генератор `render_m1.py`, который из `combined.json` создаёт самодостаточный интерактивный HTML с графом топологии безопасности (M1) и сводным дашбордом.

**Architecture:** Скрипт обогащает экспорт M1 (добавляет `entrypoint_ids`, `sink_ids` в вывод `export_topology`), затем рендерит Jinja2-подобный HTML-шаблон со встроенными CSS (из UI-kit) и JS (D3.js v7 через CDN). Данные вшиваются как JSON-литерал в `<script>`.

**Tech Stack:** Python 3.12, D3.js v7 (CDN), UI-kit CSS (inline), tree-sitter (уже в проекте)

---

### Task 1: Обогатить экспорт M1 типами узлов

**Files:**
- Modify: `src/analyzer/java_graph.py:588-606` (метод `export_topology`)
- Modify: `src/analyzer/metrics.py:816-828` (функция `metric_M1_topology`)

**Step 1: Расширить `export_topology` для включения идентификаторов точек входа и стоков**

В `src/analyzer/java_graph.py`, метод `export_topology` сейчас возвращает только `nodes` и `edges`. Добавить `entrypoint_ids` и `sink_ids`:

```python
def export_topology(self, *, limit_nodes: int, limit_edges: int) -> dict:
    nodes = set(self.edges.keys())
    for s in self.edges.values():
        nodes |= s
    nodes_l = list(nodes)[:limit_nodes]
    node_set = set(nodes_l)
    edges_l = []
    for src, dsts in self.edges.items():
        if src not in node_set:
            continue
        for dst in dsts:
            if dst not in node_set:
                continue
            edges_l.append([src, dst])
            if len(edges_l) >= limit_edges:
                break
        if len(edges_l) >= limit_edges:
            break

    ep_ids = [ep.method_id for ep in self.entrypoints if ep.method_id in node_set]
    sink_ids = [s.method_id for s in self.sinks if s.method_id in node_set]

    return {
        "nodes": nodes_l,
        "edges": edges_l,
        "entrypoint_ids": ep_ids,
        "sink_ids": sink_ids,
    }
```

**Step 2: Проверить, что тесты проходят**

Run: `cd /home/development/code-csa-metrics && python -m pytest tests/ -v 2>/dev/null || echo "No tests yet — OK"`
Expected: нет поломок (тестов может не быть)

**Step 3: Коммит**

```bash
git add src/analyzer/java_graph.py
git commit -m "feat(M1): добавить entrypoint_ids и sink_ids в export_topology"
```

---

### Task 2: Создать Python-генератор render_m1.py

**Files:**
- Create: `src/analyzer/render_m1.py`

**Step 1: Создать скрипт-генератор**

Скрипт принимает `combined.json` и путь для выходного HTML. Извлекает данные M1, A1, aggregate, meta. Классифицирует узлы на 4 типа: entrypoint, sink, test, regular. Генерирует HTML с вшитыми данными.

Ключевая логика классификации узлов:
- Точки входа: из `M1.export.entrypoint_ids` (если есть) или из `A1.sample[].method`
- Стоки: из `M1.export.sink_ids` (если есть)
- Тестовые: по паттерну `Tests#` или `Test#` в method_id
- Остальные: regular

Структура генерируемого HTML:
1. `<head>` — inline CSS из UI-kit, мета-теги
2. Заголовок — HUD-панель с метаданными репозитория
3. Stat-карточки — 5 штук (nodes, edges, entrypoints, sinks, aggregate score)
4. Область графа — `<svg>` контейнер для D3 с фильтрами и панелью деталей
5. `<script>` — D3.js логика: force simulation, zoom, drag, фильтрация, тултипы

`render_m1.py` — CLI-скрипт:
```
python -m analyzer.render_m1 --input out/v4-fast-petclinic/combined.json --output m1-report.html
```

**Step 2: Написать полный скрипт**

Полный код render_m1.py: ~300 строк Python (парсинг данных, шаблон HTML, CLI).

HTML-шаблон внутри скрипта как многострочная f-string / Template, содержит:
- Встроенный CSS (подмножество UI-kit: переменные, card-hud, stat-card, badge, btn-clipped, progress-bar, hud-panel, corner decorations)
- D3.js v7 подключение через `<script src="https://d3js.org/d3.v7.min.js">`
- Встроенный JS: инициализация force simulation, рендеринг узлов/рёбер, интерактивность

**Step 3: Проверить генерацию на данных petclinic**

Run: `cd /home/development/code-csa-metrics && python -m analyzer.render_m1 --input out/v4-fast-petclinic/combined.json --output /tmp/m1-test.html`
Expected: файл `/tmp/m1-test.html` создан, размер > 10KB

**Step 4: Коммит**

```bash
git add src/analyzer/render_m1.py
git commit -m "feat(M1): добавить генератор интерактивного HTML-отчёта для M1"
```

---

### Task 3: Валидация — открыть HTML и проверить визуально

**Step 1: Проверить структуру сгенерированного HTML**

Run: `python -c "from pathlib import Path; h = Path('/tmp/m1-test.html').read_text(); print(f'Size: {len(h)} chars'); print('D3 ref:', 'd3.v7' in h); print('SVG:', '<svg' in h); print('Stat cards:', h.count('stat-card')); print('Nodes data:', 'GRAPH_DATA' in h)"`
Expected: Size > 10000, D3 ref: True, SVG: True, Stat cards >= 5

**Step 2: Проверить корректность JSON-данных в HTML**

Run: `python -c "
from pathlib import Path
import re, json
h = Path('/tmp/m1-test.html').read_text()
m = re.search(r'const GRAPH_DATA = ({.*?});', h, re.DOTALL)
if m:
    data = json.loads(m.group(1))
    print('nodes:', len(data.get('nodes',[])))
    print('edges:', len(data.get('edges',[])))
    print('entrypoints:', len(data.get('entrypoint_ids',[])))
    print('sinks:', len(data.get('sink_ids',[])))
else:
    print('ERROR: GRAPH_DATA not found')
"`
Expected: nodes: 163, edges: 257, entrypoints: 17 (или ~17), sinks: 13 (или ~13)

**Step 3: Коммит финальный**

```bash
git add -A
git commit -m "docs: добавить план реализации визуализации M1"
```
