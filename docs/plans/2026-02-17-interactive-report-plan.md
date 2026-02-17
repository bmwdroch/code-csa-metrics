# Интерактивный HTML-отчёт всех метрик CSA — План реализации

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Переделать render_m1.py в render_report.py — полноценный интерактивный HTML-дашборд со всеми 15 метриками, радарной диаграммой, карточками метрик с цветовым кодированием, переключением визуализации графа по выбранной метрике (цвет + размер узлов + подсветка путей), и более читаемыми рёбрами.

**Architecture:** Один самодостаточный HTML-файл с D3.js. Две вкладки: «Дашборд» (радар + карточки) и «Граф» (force-directed с оверлеем метрик). Python-модуль render_report.py принимает combined.json и генерирует report.html. Данные всех метрик встраиваются в JSON-литерал внутри `<script>`.

**Tech Stack:** Python 3.12, D3.js v7 (CDN), самодостаточный HTML/CSS/JS.

---

### Task 1: Переименование модуля render_m1 → render_report

**Files:**
- Rename: `src/analyzer/render_m1.py` → `src/analyzer/render_report.py`

**Step 1: Переименовать файл**

```bash
cd /home/development/code-csa-metrics
git mv src/analyzer/render_m1.py src/analyzer/render_report.py
```

**Step 2: Обновить ссылки внутри модуля**

В `src/analyzer/render_report.py`:
- Строка 28: описание argparse → `"Генерация интерактивного HTML-отчёта CSA (все метрики)"`
- Строка 38: default → `"csa-report.html"`
- Строка 1: docstring → обновить описание модуля
- Строка 234: `<title>` → `"CSA Security Report"`
- Строка 650: заголовок панели → обновить

**Step 3: Коммит**

```bash
git add -A
git commit -m "refactor: переименовать render_m1 → render_report"
```

---

### Task 2: Расширить _build_graph_data — все метрики + оверлеи

**Files:**
- Modify: `src/analyzer/render_report.py` — функция `_build_graph_data()` (строки 140-208)

**Step 1: Добавить словарь описаний метрик**

Перед `_build_graph_data` добавить константу:

```python
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
```

**Step 2: Расширить возвращаемый словарь `_build_graph_data`**

После существующего кода (строка 186) добавить сбор всех метрик:

```python
# Все метрики с нормализованными значениями
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

# Оверлеи: данные метрик по отдельным узлам для окраски графа
metric_overlays: dict[str, dict[str, float]] = {}

# A1: score по каждой точке входа
a1_overlay: dict[str, float] = {}
for sample in a1.get("sample", []):
    mid_s = sample.get("method", "")
    if mid_s and sample.get("score") is not None:
        a1_overlay[mid_s] = sample["score"]
if a1_overlay:
    metric_overlays["A1"] = a1_overlay

# A2: ECI по каждому методу
a2 = metrics.get("A2", {})
a2_overlay: dict[str, float] = {}
for entry in a2.get("top", []):
    mid_e = entry.get("method", "")
    if mid_e and entry.get("ECI") is not None:
        a2_overlay[mid_e] = entry["ECI"]
if a2_overlay:
    metric_overlays["A2"] = a2_overlay

# A3: entropy по каждой точке входа
a3 = metrics.get("A3", {})
a3_overlay: dict[str, float] = {}
for sample in a3.get("sample", []):
    mid_s = sample.get("method", "")
    if mid_s and sample.get("entropy") is not None:
        a3_overlay[mid_s] = sample["entropy"]
if a3_overlay:
    metric_overlays["A3"] = a3_overlay

# Средние по группам для радара
group_values: dict[str, list[float]] = {}
for mid, info in all_metrics.items():
    if info["value"] is not None and info["status"] == "ok":
        group_values.setdefault(info["group"], []).append(info["value"])

radar_data: list[dict[str, Any]] = []
for gid in ("A", "B", "C", "D", "E", "F"):
    vals = group_values.get(gid, [])
    avg = round(sum(vals) / len(vals), 4) if vals else None
    radar_data.append({
        "group": gid,
        "label": _GROUP_NAMES[gid],
        "value": avg,
    })
```

Добавить в return-словарь (после `"entrypoint_details"`):

```python
"all_metrics": all_metrics,
"metric_overlays": metric_overlays,
"radar": radar_data,
"aggregate": {
    "score": round(aggregate.get("score", 0.0), 4),
    "components": aggregate.get("components", {}),
},
```

**Step 3: Коммит**

```bash
git add src/analyzer/render_report.py
git commit -m "feat(report): расширить _build_graph_data — все метрики, оверлеи, радар"
```

---

### Task 3: HTML-каркас — табы, хедер, структура страницы

**Files:**
- Modify: `src/analyzer/render_report.py` — функция `_render_html()` (строки 211-1086)

**Step 1: Заменить тело `_render_html` — HTML-структура**

Полная замена HTML. Сохраняется HUD-стиль, но добавляются:
- Навигация табами (Дашборд / Граф) в виде `btn-clipped` кнопок под хедером
- `<div id="tab-dashboard">` — область дашборда
- `<div id="tab-graph">` — область графа (скрыта по умолчанию, если нужно показать дашборд первым)
- Хедер: без изменений (repo, mode, commit, generated_at)
- Summary row: совокупная оценка + число метрик ok/unavailable

Ключевые CSS-добавления:
- `.tab-nav` — контейнер навигации табов
- `.tab-content` — секция содержимого таба, `display:none` по умолчанию, `.tab-content.active` → `display:flex`/`display:block`

JS-функция переключения:

```javascript
function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-nav .btn-clipped').forEach(btn => btn.classList.remove('active'));
  document.getElementById('tab-' + tabId).classList.add('active');
  document.querySelector('.tab-nav .btn-clipped[data-tab="' + tabId + '"]').classList.add('active');
  if (tabId === 'graph') {
    // Перезапуск симуляции при переключении на граф (размеры SVG могли измениться)
    const w = svg.node().parentElement.clientWidth;
    const h = svg.node().parentElement.clientHeight;
    svg.attr('viewBox', [0, 0, w, h]);
    simulation.force('center', d3.forceCenter(w / 2, h / 2));
    simulation.alpha(0.3).restart();
  }
}
```

**Step 2: Коммит**

```bash
git add src/analyzer/render_report.py
git commit -m "feat(report): HTML-каркас с табами Дашборд/Граф"
```

---

### Task 4: Вкладка «Дашборд» — радарная диаграмма

**Files:**
- Modify: `src/analyzer/render_report.py` — внутри `_render_html()`, секция JavaScript

**Step 1: Реализовать радарную диаграмму на D3.js**

Внутри `<div id="tab-dashboard">` разместить `<svg id="radar-svg">`. В JS:

- Радар с 6 осями (A-F), масштаб 0–1
- Сетка: 3 концентрических многоугольника (0.33, 0.66, 1.0) из тонких линий (`stroke: var(--border)`)
- Подписи осей — аббревиатуры групп
- Заполненная область значений (`fill: var(--accent-soft)`, `stroke: var(--accent)`)
- Точки на вершинах области значений
- Тултип при наведении на точку — название группы и значение

Размер SVG: 300x300, отцентрированный в верхней части дашборда.

Для групп, у которых `value === null`, ось рисуется серой пунктирной линией, точка не отображается.

**Step 2: Коммит**

```bash
git add src/analyzer/render_report.py
git commit -m "feat(report): радарная диаграмма по группам метрик"
```

---

### Task 5: Вкладка «Дашборд» — карточки метрик

**Files:**
- Modify: `src/analyzer/render_report.py` — внутри `_render_html()`, HTML + CSS + JS

**Step 1: Реализовать сетку карточек**

Под радаром — блок `.metrics-grid`. Карточки генерируются из `GRAPH_DATA.all_metrics` через JS при загрузке:

```javascript
function renderMetricCards() {
  const container = document.getElementById('metrics-cards');
  const groups = {};
  Object.values(GRAPH_DATA.all_metrics).forEach(m => {
    if (!groups[m.group]) groups[m.group] = [];
    groups[m.group].push(m);
  });
  // Порядок групп
  ['A','B','C','D','E','F'].forEach(gid => {
    const items = groups[gid] || [];
    // Заголовок группы
    const header = document.createElement('div');
    header.className = 'metrics-group-header';
    header.textContent = GRAPH_DATA.radar.find(r => r.group === gid)?.label || gid;
    container.appendChild(header);
    // Карточки
    const row = document.createElement('div');
    row.className = 'metrics-group-row';
    items.forEach(m => {
      const card = document.createElement('div');
      card.className = 'metric-card' + (m.status !== 'ok' ? ' disabled' : '');
      card.dataset.metricId = m.id;
      const colorClass = m.value === null ? '' : m.value < 0.3 ? 'success' : m.value < 0.7 ? 'warning' : 'danger';
      card.innerHTML = `
        <div class="metric-card-id">${m.id}</div>
        <div class="metric-card-name">${escapeHtml(m.name)}</div>
        <div class="metric-card-value ${colorClass}">${m.value !== null ? (m.value * 100).toFixed(1) + '%' : 'n/a'}</div>
        <div class="progress-bar"><div class="progress-fill ${colorClass}" style="width:${m.value !== null ? (m.value * 100) : 0}%"></div></div>
        <div class="metric-card-title">${escapeHtml(m.title)}</div>
      `;
      if (m.status === 'ok') {
        card.addEventListener('click', () => {
          switchTab('graph');
          setMetricOverlay(m.id);
        });
        card.style.cursor = 'pointer';
      }
      row.appendChild(card);
    });
    container.appendChild(row);
  });
}
```

CSS для карточек:

```css
.metrics-grid {
  padding: 1rem;
  overflow-y: auto;
}
.metrics-group-header {
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.15em;
  margin: 1rem 0 0.5rem;
}
.metrics-group-row {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}
.metric-card {
  position: relative;
  background: var(--surface-1);
  border: 1px solid var(--border);
  padding: 0.75rem;
  min-width: 140px;
  flex: 1;
  max-width: 200px;
  transition: border-color 0.2s;
}
.metric-card:hover:not(.disabled) {
  border-color: var(--accent);
}
.metric-card.disabled {
  opacity: 0.4;
}
.metric-card-id {
  font-size: 0.625rem;
  font-weight: 700;
  color: var(--text-secondary);
  letter-spacing: 0.1em;
}
.metric-card-name {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0.15rem 0;
}
.metric-card-value {
  font-size: 1.25rem;
  font-weight: 700;
  line-height: 1;
  margin: 0.25rem 0;
}
.metric-card-value.success { color: var(--success); }
.metric-card-value.warning { color: #fbbf24; }
.metric-card-value.danger { color: var(--danger); }
.metric-card-title {
  font-size: 0.5625rem;
  color: var(--text-tertiary);
  margin-top: 0.35rem;
  line-height: 1.3;
}
.progress-bar .progress-fill.success { background: var(--success); }
.progress-bar .progress-fill.warning { background: #fbbf24; }
.progress-bar .progress-fill.danger { background: var(--danger); }
```

**Step 2: Коммит**

```bash
git add src/analyzer/render_report.py
git commit -m "feat(report): карточки всех метрик с цветовым кодированием"
```

---

### Task 6: Вкладка «Граф» — улучшение рёбер и выпадающий список метрик

**Files:**
- Modify: `src/analyzer/render_report.py` — секция графа в `_render_html()`

**Step 1: Исправить цвет рёбер**

В константах JS заменить:
- Базовый `stroke` рёбер: `#333` → `#555`
- Базовый `stroke-opacity`: `0.6` → `0.8`
- Отфильтрованные рёбра: `0.03` → `0.05`
- Рёбра при deselect: `#333` → `#555`, `0.6` → `0.8`

**Step 2: Добавить выпадающий список метрик в тулбар**

В `.toolbar` после кнопок фильтра добавить:

```html
<span class="toolbar-label" style="margin-left:1.5rem">Оверлей:</span>
<select id="metric-overlay-select" class="metric-select" onchange="setMetricOverlay(this.value)">
  <option value="topology" selected>Топология (по умолчанию)</option>
  <!-- Опции генерируются в JS -->
</select>
```

В JS при инициализации заполнить `<select>`:

```javascript
function initMetricSelect() {
  const sel = document.getElementById('metric-overlay-select');
  Object.values(GRAPH_DATA.all_metrics).forEach(m => {
    if (m.status !== 'ok') return;
    const opt = document.createElement('option');
    opt.value = m.id;
    opt.textContent = m.id + ' — ' + m.name;
    sel.appendChild(opt);
  });
}
```

CSS для `select`:

```css
.metric-select {
  font-family: inherit;
  font-size: 0.6875rem;
  background: var(--surface-2);
  color: var(--text-primary);
  border: 1px solid var(--border);
  padding: 0.35rem 0.5rem;
  cursor: pointer;
  outline: none;
}
.metric-select:focus { border-color: var(--accent); }
```

**Step 3: Коммит**

```bash
git add src/analyzer/render_report.py
git commit -m "feat(report): светлые рёбра, выпадающий список метрик в тулбаре"
```

---

### Task 7: Оверлей метрик на граф — цвет и размер узлов

**Files:**
- Modify: `src/analyzer/render_report.py` — секция JS в `_render_html()`

**Step 1: Реализовать `setMetricOverlay(metricId)`**

```javascript
let currentOverlay = 'topology';

function setMetricOverlay(metricId) {
  currentOverlay = metricId;
  document.getElementById('metric-overlay-select').value = metricId;

  if (metricId === 'topology') {
    // Возврат к стандартному виду
    nodes.transition().duration(400)
      .attr('r', d => getNodeRadius(d))
      .attr('fill', d => NODE_STYLE[d.type].fill)
      .attr('opacity', d => getNodeOpacity(d));
    links.transition().duration(400)
      .attr('stroke', '#555')
      .attr('stroke-width', 0.5)
      .attr('stroke-opacity', 0.8);
    pulses.transition().duration(400).attr('opacity', 0.6);
    return;
  }

  const overlay = GRAPH_DATA.metric_overlays[metricId];
  const hasNodeData = overlay && Object.keys(overlay).length > 0;

  if (hasNodeData) {
    // Определить min/max для масштабирования
    const values = Object.values(overlay);
    const maxVal = Math.max(...values);
    const minVal = Math.min(...values);
    const range = maxVal - minVal || 1;

    nodes.transition().duration(400)
      .attr('fill', d => {
        if (overlay[d.id] !== undefined) {
          const t = (overlay[d.id] - minVal) / range;
          return riskColor(t);
        }
        return '#3a3a3a';  // серый для узлов без данных
      })
      .attr('r', d => {
        if (overlay[d.id] !== undefined) {
          const t = (overlay[d.id] - minVal) / range;
          return 3 + t * 9;  // от 3 до 12
        }
        return 2;
      })
      .attr('opacity', d => overlay[d.id] !== undefined ? 1 : 0.2);

    // Приглушить пульсации
    pulses.transition().duration(400).attr('opacity', 0);

    // Рёбра: подсветить связанные с имеющими данные
    links.transition().duration(400)
      .attr('stroke', d => {
        const srcHas = overlay[d.source.id] !== undefined;
        const tgtHas = overlay[d.target.id] !== undefined;
        return (srcHas && tgtHas) ? '#666' : '#333';
      })
      .attr('stroke-opacity', d => {
        const srcHas = overlay[d.source.id] !== undefined;
        const tgtHas = overlay[d.target.id] !== undefined;
        return (srcHas || tgtHas) ? 0.6 : 0.05;
      });
  } else {
    // Системная метрика без данных по узлам — показать стандартный вид
    // и отобразить значение метрики в тулбаре
    nodes.transition().duration(400)
      .attr('r', d => getNodeRadius(d))
      .attr('fill', d => NODE_STYLE[d.type].fill)
      .attr('opacity', d => getNodeOpacity(d));
    links.transition().duration(400)
      .attr('stroke', '#555')
      .attr('stroke-width', 0.5)
      .attr('stroke-opacity', 0.8);
    pulses.transition().duration(400).attr('opacity', 0.6);
  }

  updateOverlayInfo(metricId);
}

// Цвет по шкале риска: зелёный → жёлтый → красный
function riskColor(t) {
  // t ∈ [0, 1]
  if (t < 0.5) {
    // зелёный (#34d399) → жёлтый (#fbbf24)
    const r = Math.round(52 + (251 - 52) * (t * 2));
    const g = Math.round(211 + (191 - 211) * (t * 2));
    const b = Math.round(153 + (36 - 153) * (t * 2));
    return `rgb(${r},${g},${b})`;
  } else {
    // жёлтый (#fbbf24) → красный (#f87171)
    const s = (t - 0.5) * 2;
    const r = Math.round(251 + (248 - 251) * s);
    const g = Math.round(191 + (113 - 191) * s);
    const b = Math.round(36 + (113 - 36) * s);
    return `rgb(${r},${g},${b})`;
  }
}
```

**Step 2: Добавить информационную строку оверлея**

Под select добавить `<span id="overlay-info">`. При выборе метрики в ней отображается значение:

```javascript
function updateOverlayInfo(metricId) {
  const info = document.getElementById('overlay-info');
  if (metricId === 'topology') {
    info.textContent = '';
    return;
  }
  const m = GRAPH_DATA.all_metrics[metricId];
  if (!m) { info.textContent = ''; return; }
  const overlay = GRAPH_DATA.metric_overlays[metricId];
  const nodeCount = overlay ? Object.keys(overlay).length : 0;
  const valStr = m.value !== null ? (m.value * 100).toFixed(1) + '%' : 'n/a';
  info.textContent = m.title + ' = ' + valStr + (nodeCount > 0 ? ' (' + nodeCount + ' узлов)' : ' (системная)');
  info.style.color = m.value !== null ? (m.value < 0.3 ? 'var(--success)' : m.value < 0.7 ? '#fbbf24' : 'var(--danger)') : 'var(--text-tertiary)';
}
```

**Step 3: Коммит**

```bash
git add src/analyzer/render_report.py
git commit -m "feat(report): оверлей метрик на граф — цвет, размер, подсветка"
```

---

### Task 8: Обновить панель деталей узла — показ значений выбранной метрики

**Files:**
- Modify: `src/analyzer/render_report.py` — функция `showDetail()` в JS

**Step 1: Расширить showDetail**

В существующей функции `showDetail(d)`, после блока A1 entrypoint details, добавить:

```javascript
// Значение текущего оверлея для этого узла
if (currentOverlay !== 'topology') {
  const m = GRAPH_DATA.all_metrics[currentOverlay];
  const overlay = GRAPH_DATA.metric_overlays[currentOverlay];
  if (m) {
    html += `
      <div class="detail-field">
        <div class="detail-field-label">${escapeHtml(currentOverlay + ' — ' + m.name)}</div>
        <div class="detail-field-value">`;
    if (overlay && overlay[d.id] !== undefined) {
      html += `<span style="color:var(--accent)">${overlay[d.id].toFixed(4)}</span>`;
    } else {
      html += `<span style="color:var(--text-tertiary)">Нет данных для этого узла</span>`;
    }
    html += `</div></div>`;
    html += `
      <div class="detail-field">
        <div class="detail-field-label">Системное значение ${escapeHtml(currentOverlay)}</div>
        <div class="detail-field-value">${m.value !== null ? (m.value * 100).toFixed(1) + '%' : 'n/a'}</div>
      </div>
    `;
  }
}
```

**Step 2: Коммит**

```bash
git add src/analyzer/render_report.py
git commit -m "feat(report): панель деталей показывает значение выбранной метрики"
```

---

### Task 9: Обновить CLI и выходное имя файла

**Files:**
- Modify: `src/analyzer/render_report.py` — `_parse_args()` и `main()`

**Step 1: Обновить CLI**

- `--output` default: `"csa-report.html"`
- Описание в argparse: `"Генерация интерактивного HTML-отчёта CSA (все метрики)"`
- Print при генерации: `"Отчёт CSA сгенерирован:"`

**Step 2: Обновить вывод статистики**

В функции `main()` после генерации добавить вывод количества доступных метрик:

```python
available = sum(1 for m in graph_data["all_metrics"].values() if m["status"] == "ok")
total = len(graph_data["all_metrics"])
print(f"  Метрик: {available}/{total} доступно")
```

**Step 3: Коммит**

```bash
git add src/analyzer/render_report.py
git commit -m "feat(report): обновить CLI — имя файла и статистика метрик"
```

---

### Task 10: Интеграционная проверка — генерация отчёта из тестовых данных

**Files:**
- Используется: `src/analyzer/render_report.py`

**Step 1: Создать минимальный тестовый combined.json**

```bash
cat > /tmp/test-combined.json << 'TESTEOF'
{
  "orchestrator": {"meta": {"repo_url": "https://github.com/test/repo", "mode": "fast"}},
  "analyzer": {
    "meta": {"repo_url": "https://github.com/test/repo", "git_head": "abc12345", "git_branch": "main", "mode": "fast"},
    "metrics": {
      "A1": {"status": "ok", "ASE": 0.42, "entrypoints": 5, "sample": [
        {"method": "com.test.Controller#index(String)", "score": 2.1, "has_auth": true, "has_validation": false},
        {"method": "com.test.Controller#create(Object)", "score": 3.5, "has_auth": false, "has_validation": false}
      ]},
      "A2": {"status": "ok", "ECI_avg": 0.35, "top": [
        {"method": "com.test.Service#process(String)", "ECI": 8.5, "complexity": 17, "distance": 1}
      ], "methods_reachable": 10},
      "A3": {"status": "ok", "IET_system": 0.55, "entrypoints": 5, "sample": [
        {"method": "com.test.Controller#index(String)", "entropy": 0.5, "weight": 1.0, "type": "http"}
      ]},
      "B1": {"status": "ok", "IDS": 0.6, "IDS_system": 0.4, "paths_analyzed": 3},
      "B2": {"status": "ok", "PPI": 0.25, "min_distance": 3},
      "B3": {"status": "ok", "MPSP": 0.7, "MPSP_system": 0.3},
      "B4": {"status": "ok", "FSS": 0.8, "raw_FSS": 0.2},
      "C1": {"status": "ok", "TPC": 0.3, "TPC_max_consecutive_unsafe_hops": 3},
      "C2": {"status": "ok", "ETI": 0.15},
      "C3": {"status": "ok", "SFA": 0.05},
      "D1": {"status": "ok", "PAD": 0.25, "languages_present": ["java"]},
      "D2": {"status": "ok", "TCPD": 0.4},
      "E1": {"status": "ok", "OSDR": 0.6},
      "F1": {"status": "ok", "VFCP": 0.45},
      "F2": {"status": "ok", "SRP": 0.2},
      "M1": {"status": "ok", "nodes": 6, "edges": 7, "entrypoints": 2, "sinks": 1, "export": {
        "nodes": ["com.test.Controller#index(String)", "com.test.Controller#create(Object)", "com.test.Service#process(String)", "com.test.Repository#save(Object)", "com.test.Service#validate(String)", "com.test.TestController#testIndex()"],
        "edges": [["com.test.Controller#index(String)", "com.test.Service#process(String)"], ["com.test.Controller#create(Object)", "com.test.Service#validate(String)"], ["com.test.Service#validate(String)", "com.test.Service#process(String)"], ["com.test.Service#process(String)", "com.test.Repository#save(Object)"], ["com.test.Controller#create(Object)", "com.test.Repository#save(Object)"], ["com.test.TestController#testIndex()", "com.test.Controller#index(String)"], ["com.test.Controller#index(String)", "com.test.Service#validate(String)"]],
        "entrypoint_ids": ["com.test.Controller#index(String)", "com.test.Controller#create(Object)"],
        "sink_ids": ["com.test.Repository#save(Object)"]
      }},
      "aggregate": {"score": 0.38, "components": {"A1": 0.42, "B1": 0.6}, "available": 15}
    }
  }
}
TESTEOF
```

**Step 2: Запустить генерацию**

```bash
cd /home/development/code-csa-metrics
python -m analyzer.render_report --input /tmp/test-combined.json --output /tmp/csa-report.html
```

Ожидается:
- Файл `/tmp/csa-report.html` создан
- Вывод содержит "Отчёт CSA сгенерирован"
- Размер файла > 10 КБ (самодостаточный HTML)

**Step 3: Визуальная проверка**

Открыть `/tmp/csa-report.html` в браузере (или проверить структуру через grep):
- Присутствуют обе вкладки
- Радарная диаграмма отрисована
- 15 карточек метрик с цветами
- Граф с 6 узлами и 7 рёбрами
- Рёбра видимые (цвет #555)
- Переключение оверлея меняет цвет/размер узлов

**Step 4: Финальный коммит**

```bash
git add -A
git commit -m "test: проверить генерацию отчёта на тестовых данных"
```

---

## Порядок зависимостей

```
Task 1 (переименование) → Task 2 (данные) → Task 3 (каркас) → Task 4 (радар) → Task 5 (карточки) → Task 6 (рёбра + select) → Task 7 (оверлей) → Task 8 (панель деталей) → Task 9 (CLI) → Task 10 (проверка)
```

Все задачи строго последовательны, поскольку каждая наращивает единый файл `render_report.py`.
