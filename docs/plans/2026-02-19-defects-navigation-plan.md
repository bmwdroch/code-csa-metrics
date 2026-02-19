# Defects Navigation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Переработать раздел «Дефекты» в HTML-отчёте CSQA: группировка по файлу, сортировка файлов по числу дефектов, сворачиваемые карточки деталей.

**Architecture:** Все изменения — в одном файле `src/analyzer/render_report.py` внутри функции `_render_html`. Функция `renderFindings()` в генерируемом JS переписывается полностью. CSS добавляется в существующий `<style>` блок. Данные `GRAPH_DATA.findings` не меняются. Существующие фильтры (`setGroupFilter`, `setSevFilter`) не трогаются.

**Tech Stack:** Python (генерация HTML-строки), vanilla JS, CSS (HUD dark theme, clip-path buttons).

---

### Task 1: Регрессионные тесты на группировку findings

**Files:**
- Modify: `tests/test_metric_engine_regressions.py`

**Step 1: Добавь тестовый класс в конец файла**

Открой `tests/test_metric_engine_regressions.py`. В конце файла (после последнего класса) добавь:

```python
class RenderReportFindingsGroupingTests(unittest.TestCase):
    """Тесты группировки и сортировки findings для раздела дефектов."""

    def _make_data(self, findings: list[dict]) -> dict:
        """Минимальный combined.json с заданным списком findings."""
        return {
            "analyzer": {
                "meta": {
                    "repo_url": "https://example.com/org/repo",
                    "mode": "fast",
                    "git_head": "abcd1234",
                },
                "metrics": {
                    "M1": {"export": {"nodes": [], "edges": []}},
                    "A1": {
                        "status": "ok",
                        "ASE": 0.5,
                        "entrypoints": 0,
                        "sample": [],
                        "findings": [],
                    },
                    "aggregate": {"score": 0.5, "components": {}},
                    **{mid: {"status": "ok", "findings": []} for mid in
                       ["A2","A3","B1","B2","B3","B4","C1","C2","C3","D1","D2","E1","F1","F2","M1"]},
                },
            }
        }

    def test_findings_sorted_by_severity_within_file(self) -> None:
        """Дефекты внутри файла должны сортироваться critical > high > medium > low."""
        # Встраиваем findings в A1 (произвольная метрика)
        data = self._make_data([])
        data["analyzer"]["metrics"]["A1"]["findings"] = [
            {"metric": "A1", "severity": "medium", "file": "Foo.java", "line": 5, "what": "medium", "why": "", "fix": ""},
            {"metric": "A1", "severity": "critical", "file": "Foo.java", "line": 1, "what": "critical", "why": "", "fix": ""},
            {"metric": "A1", "severity": "high", "file": "Foo.java", "line": 3, "what": "high", "why": "", "fix": ""},
        ]

        graph_data = render_report._build_graph_data(data)
        findings = graph_data["findings"]

        # _build_graph_data уже сортирует по severity (critical first)
        severities = [f["severity"] for f in findings]
        self.assertEqual(severities, ["critical", "high", "medium"])

    def test_findings_include_system_level_without_file(self) -> None:
        """Дефекты без поля file должны попадать в список findings."""
        data = self._make_data([])
        data["analyzer"]["metrics"]["B1"] = {
            "status": "ok",
            "IDS_system": 0.8,
            "IDS": 0.8,
            "findings": [
                {
                    "metric": "B1",
                    "severity": "critical",
                    "file": None,
                    "line": None,
                    "method": None,
                    "what": "Системный дефект",
                    "why": "почему",
                    "fix": "исправление",
                }
            ],
        }

        graph_data = render_report._build_graph_data(data)
        system_findings = [f for f in graph_data["findings"] if not f.get("file")]
        self.assertEqual(len(system_findings), 1)
        self.assertEqual(system_findings[0]["what"], "Системный дефект")

    def test_render_html_contains_file_group_css_class(self) -> None:
        """Сгенерированный HTML должен содержать CSS-класс .file-group."""
        data = self._make_data([])
        graph_data = render_report._build_graph_data(data)
        html_output = render_report._render_html(graph_data)
        self.assertIn(".file-group", html_output)

    def test_render_html_contains_finding_row_css_class(self) -> None:
        """Сгенерированный HTML должен содержать CSS-класс .finding-row."""
        data = self._make_data([])
        graph_data = render_report._build_graph_data(data)
        html_output = render_report._render_html(graph_data)
        self.assertIn(".finding-row", html_output)

    def test_render_html_groupby_file_js_present(self) -> None:
        """Сгенерированный JS должен содержать логику группировки по файлу."""
        data = self._make_data([])
        graph_data = render_report._build_graph_data(data)
        html_output = render_report._render_html(graph_data)
        # Ключевой идентификатор новой логики группировки
        self.assertIn("fileGroups", html_output)
```

**Step 2: Запусти тесты — убедись, что три новых падают**

```bash
cd /home/development/code-csa-metrics
python -m pytest tests/test_metric_engine_regressions.py::RenderReportFindingsGroupingTests -v
```

Ожидаемый результат: два теста пройдут (`test_findings_sorted_by_severity_within_file`, `test_findings_include_system_level_without_file`), три упадут с AssertionError — CSS-классов и `fileGroups` ещё нет.

**Step 3: Зафиксируй тесты**

```bash
git add tests/test_metric_engine_regressions.py
git commit -m "test: add failing tests for defects navigation file-grouping UI"
```

---

### Task 2: CSS для файловых секций и сворачиваемых строк

**Files:**
- Modify: `src/analyzer/render_report.py` — в функции `_render_html`, блок `<style>` (искать строку `/* ======================================================================`)

**Context:** В `_render_html` есть большой CSS-блок. Нужно добавить новые правила после секции `.no-findings` (около строки 1087 в оригинальном файле).

**Step 1: Найди место вставки**

В `src/analyzer/render_report.py` найди строку:
```css
.no-findings {{
  text-align: center;
  padding: 3rem;
  color: var(--text-tertiary);
  font-size: 0.875rem;
}}
```

После закрывающей `}}` этого правила добавь новый блок CSS (перед `/* Badges */`):

```css
/* ======================================================================
   File Groups (findings tab)
   ====================================================================== */
.file-group {{
  margin-bottom: 0.75rem;
  border: 1px solid var(--border);
}}
.file-group-header {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background: var(--surface-2);
  cursor: pointer;
  user-select: none;
  transition: background 0.15s;
}}
.file-group-header:hover {{
  background: var(--surface-3);
}}
.file-group-name {{
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--text-secondary);
  font-family: 'JetBrains Mono', monospace;
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
.file-group-count {{
  font-size: 0.5625rem;
  font-weight: 600;
  padding: 0.1rem 0.4rem;
  background: var(--surface-1);
  border: 1px solid var(--border);
  color: var(--text-tertiary);
  flex-shrink: 0;
}}
.file-group-arrow {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  flex-shrink: 0;
  transition: transform 0.15s;
}}
.file-group-body {{
  border-top: 1px solid var(--border);
}}
.file-group-body.collapsed {{
  display: none;
}}
.finding-row {{
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  padding: 0.375rem 0.75rem;
  cursor: pointer;
  transition: background 0.1s;
  border-bottom: 1px solid transparent;
}}
.finding-row:hover {{
  background: var(--surface-2);
}}
.finding-row:last-child {{
  border-bottom: none;
}}
.finding-row-dot {{
  font-size: 0.5rem;
  flex-shrink: 0;
  margin-top: 0.15rem;
}}
.finding-row-what {{
  font-size: 0.75rem;
  color: var(--text-primary);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
.finding-row-line {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  font-family: 'JetBrains Mono', monospace;
  flex-shrink: 0;
}}
.finding-row-detail {{
  padding: 0.5rem 0.75rem 0.625rem 2rem;
  background: var(--surface-1);
  border-top: 1px solid var(--border);
  font-size: 0.6875rem;
  color: var(--text-secondary);
  line-height: 1.5;
}}
.finding-row-detail.collapsed {{
  display: none;
}}
.finding-row-detail strong {{
  color: var(--text-tertiary);
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.5625rem;
  letter-spacing: 0.05em;
}}
.finding-row-method {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  font-family: 'JetBrains Mono', monospace;
  margin-bottom: 0.35rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
```

**Step 2: Запусти тест CSS-класса**

```bash
cd /home/development/code-csa-metrics
python -m pytest tests/test_metric_engine_regressions.py::RenderReportFindingsGroupingTests::test_render_html_contains_file_group_css_class tests/test_metric_engine_regressions.py::RenderReportFindingsGroupingTests::test_render_html_contains_finding_row_css_class -v
```

Ожидаемый результат: оба теста PASS.

**Step 3: Зафиксируй**

```bash
git add src/analyzer/render_report.py
git commit -m "feat(report): add CSS for file-group and finding-row collapsible layout"
```

---

### Task 3: Переписать renderFindings() в генерируемом JS

**Files:**
- Modify: `src/analyzer/render_report.py` — в функции `_render_html`, блок `<script>` (искать `function renderFindings()`)

**Context:** Нужно заменить всю функцию `renderFindings()` и добавить вспомогательные константы/переменные.

**Step 1: Добавь константу порядка серьёзности**

Найди в блоке `<script>` строку:
```js
let currentGroupFilter = 'all';
let currentSevFilter = 'all';
```

Добавь после неё:
```js
const SEV_ORDER = {{ critical: 0, high: 1, medium: 2, low: 3 }};
const SEV_COLORS = {{
  critical: '#f87171',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#34d399',
}};
const expandedFindings = new Set();
let expandedFileGroups = new Set();  // файлы, у которых тело свёрнуто
```

**Step 2: Замени функцию renderFindings()**

Найди блок:
```js
function renderFindings() {{
  const list = document.getElementById('findings-list');
  ...
  list.innerHTML = html;
}}
```

(от `function renderFindings()` до закрывающей `}}`) и замени его целиком на:

```js
function renderFindings() {{
  const list = document.getElementById('findings-list');
  const countEl = document.getElementById('findings-count');
  const findings = GRAPH_DATA.findings || [];

  const filtered = findings.filter(f => {{
    const group = (f.metric || '').charAt(0);
    if (currentGroupFilter !== 'all' && group !== currentGroupFilter) return false;
    if (currentSevFilter !== 'all' && f.severity !== currentSevFilter) return false;
    return true;
  }});

  countEl.textContent = filtered.length + ' / ' + findings.length;

  if (filtered.length === 0) {{
    list.innerHTML = '<div class="no-findings">Дефекты не обнаружены (или отфильтрованы)</div>';
    return;
  }}

  // Группировка по файлу
  const fileGroups = {{}};
  const systemGroup = [];

  filtered.forEach((f, idx) => {{
    const key = f.file || null;
    if (key) {{
      if (!fileGroups[key]) fileGroups[key] = [];
      fileGroups[key].push({{ f, idx }});
    }} else {{
      systemGroup.push({{ f, idx }});
    }}
  }});

  // Сортировка файлов по числу дефектов (убывание)
  const sortedFiles = Object.keys(fileGroups).sort(
    (a, b) => fileGroups[b].length - fileGroups[a].length
  );

  // Сортировка дефектов внутри группы по severity
  function sortBySev(items) {{
    return items.slice().sort(
      (a, b) => (SEV_ORDER[a.f.severity] ?? 99) - (SEV_ORDER[b.f.severity] ?? 99)
    );
  }}

  function renderFindingRow({{ f, idx }}) {{
    const sev = f.severity || 'low';
    const color = SEV_COLORS[sev] || '#94a3b8';
    const line = f.line ? ':' + f.line : '';
    const isExpanded = expandedFindings.has(idx);

    const detailClass = 'finding-row-detail' + (isExpanded ? '' : ' collapsed');
    const methodHtml = f.method
      ? '<div class="finding-row-method">' + escapeHtml(f.method) + '</div>'
      : '';

    return (
      '<div class="finding-row" onclick="toggleFinding(' + idx + ')">' +
        '<span class="finding-row-dot" style="color:' + color + '">&#9679;</span>' +
        '<span class="finding-severity ' + sev + '">' + escapeHtml(sev) + '</span>' +
        '<span class="finding-row-what">' + escapeHtml(f.what || '') + '</span>' +
        (line ? '<span class="finding-row-line">' + escapeHtml(line) + '</span>' : '') +
      '</div>' +
      '<div class="' + detailClass + '" id="frd-' + idx + '">' +
        methodHtml +
        '<strong>Почему: </strong>' + escapeHtml(f.why || '') + '<br>' +
        '<strong>Исправление: </strong>' + escapeHtml(f.fix || '') +
      '</div>'
    );
  }}

  function renderGroup(groupKey, items, isSystem) {{
    const sorted = sortBySev(items);
    const isCollapsed = expandedFileGroups.has(groupKey);
    const bodyClass = 'file-group-body' + (isCollapsed ? ' collapsed' : '');
    const arrow = isCollapsed ? '&#9654;' : '&#9660;';
    const label = isSystem ? 'Уровень системы' : groupKey;

    return (
      '<div class="file-group">' +
        '<div class="file-group-header" onclick="toggleFileGroup(' + JSON.stringify(groupKey) + ')">' +
          '<span class="file-group-name">' + escapeHtml(label) + '</span>' +
          '<span class="file-group-count">' + items.length + '</span>' +
          '<span class="file-group-arrow" id="fga-' + CSS.escape(groupKey) + '">' + arrow + '</span>' +
        '</div>' +
        '<div class="' + bodyClass + '" id="fgb-' + CSS.escape(groupKey) + '">' +
          sorted.map(renderFindingRow).join('') +
        '</div>' +
      '</div>'
    );
  }}

  let html = sortedFiles.map(f => renderGroup(f, fileGroups[f], false)).join('');
  if (systemGroup.length > 0) {{
    html += renderGroup('__system__', systemGroup, true);
  }}
  list.innerHTML = html;
}}

function toggleFinding(idx) {{
  if (expandedFindings.has(idx)) {{
    expandedFindings.delete(idx);
  }} else {{
    expandedFindings.add(idx);
  }}
  const el = document.getElementById('frd-' + idx);
  if (el) el.classList.toggle('collapsed');
}}

function toggleFileGroup(key) {{
  if (expandedFileGroups.has(key)) {{
    expandedFileGroups.delete(key);
  }} else {{
    expandedFileGroups.add(key);
  }}
  const bodyId = 'fgb-' + CSS.escape(key);
  const arrowId = 'fga-' + CSS.escape(key);
  const bodyEl = document.getElementById(bodyId);
  const arrowEl = document.getElementById(arrowId);
  if (bodyEl) bodyEl.classList.toggle('collapsed');
  if (arrowEl) arrowEl.innerHTML = expandedFileGroups.has(key) ? '&#9654;' : '&#9660;';
}}
```

**Важно:** при замене блоков сохраняй двойные фигурные скобки `{{` и `}}` — это Python f-string экранирование в `_render_html`. Каждый `{` в JS должен быть `{{` в Python, каждый `}` — `}}`.

**Step 3: Убедись, что старые вызовы `renderFindings()` не изменились**

Проверь, что вызовы `renderFindings()` в конце `<script>` (строка `renderFindings();`) и внутри `setGroupFilter`/`setSevFilter` остались нетронутыми.

**Step 4: Запусти все тесты**

```bash
cd /home/development/code-csa-metrics
python -m pytest tests/test_metric_engine_regressions.py -v
```

Ожидаемый результат: все тесты PASS, включая `test_render_html_groupby_file_js_present`.

**Step 5: Зафиксируй**

```bash
git add src/analyzer/render_report.py
git commit -m "feat(report): rewrite renderFindings() with file-group layout and collapsible rows"
```

---

### Task 4: Удалить старые CSS-классы finding-card (cleanup)

**Files:**
- Modify: `src/analyzer/render_report.py` — блок `<style>`

**Context:** Старые классы `.finding-card`, `.finding-header`, `.finding-metric`, `.finding-what`, `.finding-detail` больше не используются в новом `renderFindings()`. Их нужно удалить, чтобы не загромождать HTML.

**Step 1: Найди и удали устаревшие CSS-правила**

В блоке `<style>` найди секцию (около строки 1021 в оригинале):
```css
.finding-card {{
  border: 1px solid var(--border);
  background: var(--surface-1);
  ...
}}
```

Удали эти правила (`.finding-card`, `.finding-card:hover`, `.finding-header`, `.finding-metric`, `.finding-severity` не удаляй — severity badges используются в новом коде, `.finding-location`, `.finding-what`, `.finding-detail strong`).

**Что оставить обязательно:**
- `.findings-wrapper` — контейнер прокрутки
- `.findings-toolbar` — тулбар с кнопками
- `.findings-count` — счётчик
- `.finding-severity` и его варианты `.critical`, `.high`, `.medium`, `.low` — используются в `.finding-row`
- `.no-findings` — сообщение об отсутствии дефектов

**Что удалить:**
- `.finding-card` и `.finding-card:hover`
- `.finding-header`
- `.finding-metric`
- `.finding-location`
- `.finding-what`
- `.finding-detail` (не `.finding-row-detail` — тот новый)

**Step 2: Запусти все тесты**

```bash
cd /home/development/code-csa-metrics
python -m pytest tests/ -v
```

Ожидаемый результат: все тесты PASS.

**Step 3: Зафиксируй**

```bash
git add src/analyzer/render_report.py
git commit -m "refactor(report): remove obsolete finding-card CSS rules"
```

---

### Task 5: Ручная визуальная проверка

**Context:** Нужно сгенерировать тестовый отчёт с заранее заданными findings и проверить вид в браузере.

**Step 1: Создай тестовый combined.json**

```bash
cat > /tmp/test_combined.json << 'EOF'
{
  "analyzer": {
    "meta": {
      "repo_url": "https://github.com/test/repo",
      "mode": "fast",
      "git_head": "abcd1234ef"
    },
    "metrics": {
      "M1": {
        "status": "ok",
        "nodes": 5,
        "edges": 3,
        "entrypoints": 2,
        "sinks": 1,
        "export": {
          "nodes": ["A", "B", "C"],
          "edges": [["A", "B"], ["B", "C"]],
          "entrypoint_ids": ["A"],
          "sink_ids": ["C"]
        }
      },
      "A1": {
        "status": "ok",
        "ASE": 0.6,
        "entrypoints": 2,
        "sample": [],
        "findings": [
          {"metric": "A1", "severity": "high", "file": "src/AuthController.java", "line": 18, "method": "com.example.AuthController#login()", "what": "Endpoint без аутентификации", "why": "HTTP-метод доступен без проверки подлинности", "fix": "Добавьте @PreAuthorize"},
          {"metric": "A1", "severity": "medium", "file": "src/AuthController.java", "line": 42, "method": "com.example.AuthController#register()", "what": "Endpoint без валидации", "why": "Входные параметры не проверяются", "fix": "Добавьте @Valid"}
        ]
      },
      "B4": {
        "status": "ok",
        "FSS": 0.3,
        "raw_FSS": 0.7,
        "findings": [
          {"metric": "B4", "severity": "critical", "file": "src/AuthController.java", "line": 87, "method": "com.example.AuthController#handleError()", "what": "Пустой catch-блок", "why": "При исключении выполнение продолжится без обработки ошибки", "fix": "Добавьте throw или логирование"},
          {"metric": "B4", "severity": "medium", "file": "src/UserService.java", "line": 203, "method": "com.example.UserService#save()", "what": "Catch с неоднозначной обработкой", "why": "return без throw может маскировать ошибки", "fix": "Пробрасывайте исключение"}
        ]
      },
      "B2": {
        "status": "ok",
        "PPI": 0.8,
        "min_distance": 1,
        "findings": [
          {"metric": "B2", "severity": "critical", "file": null, "line": null, "method": null, "what": "Привилегированная операция доступна за 1 хоп от публичного входа", "why": "Минимальное количество проверок на пути к критичным данным", "fix": "Добавьте промежуточные слои авторизации"}
        ]
      },
      "aggregate": {"score": 0.55, "components": {"A1": 0.6, "B4": 0.3, "B2": 0.8}}
    }
  }
}
EOF
```

**Step 2: Сгенерируй отчёт**

```bash
cd /home/development/code-csa-metrics
python -m analyzer.render_report --input /tmp/test_combined.json --output /tmp/test_report.html
```

Ожидаемый вывод:
```
Отчёт CSQA сгенерирован: /tmp/test_report.html
  Узлов: 3 (entrypoint=1, sink=1, test=0, regular=1)
  ...
```

**Step 3: Открой в браузере (если есть GUI)**

```bash
xdg-open /tmp/test_report.html 2>/dev/null || echo "Открой /tmp/test_report.html вручную"
```

**Что проверить:**
- Вкладка «Дефекты» показывает секции файлов
- `src/AuthController.java (3)` идёт первым (3 дефекта > 1 в UserService.java)
- Внутри AuthController: critical первым, затем high, medium
- Клик на строку дефекта раскрывает детали «Почему» и «Исправление»
- Секция «Уровень системы» есть (1 дефект B2 без файла)
- Клик на заголовок секции сворачивает/разворачивает тело
- Фильтры по группе и серьёзности работают

**Step 4: Зафиксируй после успешной проверки** (коммит не нужен, всё уже закоммичено)

---

### Task 6: Финальный прогон всех тестов

**Step 1: Запусти полный тестовый набор**

```bash
cd /home/development/code-csa-metrics
python -m pytest tests/ -v 2>&1
```

Ожидаемый результат: все тесты PASS (включая 5 новых из `RenderReportFindingsGroupingTests`).

**Step 2: Проверь, что вся ветка чистая**

```bash
git status
git log --oneline -5
```

**Ожидаемые коммиты (новые):**
```
feat(report): rewrite renderFindings() with file-group layout and collapsible rows
feat(report): add CSS for file-group and finding-row collapsible layout
test: add failing tests for defects navigation file-grouping UI
docs: add defects navigation design for file-grouped findings view
```
