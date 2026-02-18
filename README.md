# CSQA Metrics

Статический анализ безопасности Java-репозиториев. Клонирует публичный GitHub-репозиторий, строит граф вызовов на основе Tree-sitter и вычисляет 15 метрик по пяти группам: поверхность атаки, глубина защиты, потоки данных, изменяемость, регрессионный риск. Результат — интерактивный HTML-отчёт с радар-чартом, картами метрик и визуализацией графа.

## Быстрый старт (Docker Compose)

```bash
# 1. Скопировать и заполнить переменные
cp .env.example .env
nano .env   # обязательно: CSA_WEB_TOKEN

# 2. Собрать образы и запустить
docker-compose up --build -d

# 3. Открыть в браузере
# http://<host>:8080/<CSA_WEB_TOKEN>/
```

При первом запуске `docker-compose up --build` собирает два образа: веб-сервер и аналитический контейнер (`csqa-metrics:fast`). Последующие запуски используют кеш слоёв.

## Переменные окружения

| Переменная | Обязательная | По умолчанию | Описание |
|---|---|---|---|
| `CSA_WEB_TOKEN` | да | — | Токен в URL-префиксе (`/{token}/`). Генерация: `python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(16)).decode())"` |
| `CSQA_DATA_DIR` | нет | `/var/lib/csqa` | Хостовый путь для хранения отчётов. Важно: это путь на хосте, не внутри контейнера. |
| `PORT` | нет | `8080` | Порт веб-сервера. |

## Архитектура

```
Браузер → FastAPI (web-контейнер)
                │
                └── orchestrate.py
                        │  DooD: /var/run/docker.sock
                        └── docker run csqa-metrics:fast
                                │  клонирует репозиторий
                                │  строит граф вызовов (Tree-sitter)
                                │  вычисляет метрики
                                └── report.json → render_report.py → report.html
```

Веб-контейнер не содержит JVM и не клонирует репозитории — он только обслуживает HTTP и запускает аналитический контейнер через Docker socket (паттерн DooD). Аналитический контейнер изолирован, не имеет доступа к сети хоста и завершается сразу после генерации отчёта.

## Метрики

15 метрик по 5 группам, каждая нормализована в диапазон [0, 1] где 0 — минимальный риск:

| Группа | Метрики |
|---|---|
| A — Поверхность атаки | ASE, ECI, IET |
| B — Глубина защиты | IDS, PPI, MPSP, FSS |
| C — Потоки данных | ETI, DPI, DDT |
| D — Изменяемость | CCD, CMR, API |
| F — Регрессионный риск | TCI, RRI |

Полное описание алгоритмов — в `docs/metrics.md`.

## Запуск из командной строки

Без веб-интерфейса, напрямую через оркестратор:

```bash
# Создать и активировать виртуальное окружение
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-web.txt tree_sitter==0.21.3 tree_sitter_languages==1.10.2

# Собрать образ аналитика (один раз)
docker build -f src/docker/Dockerfile --target fast -t csqa-metrics:fast .

# Запустить анализ
python src/orchestrate.py \
  --repo-url https://github.com/WebGoat/WebGoat \
  --mode fast \
  --render-html \
  --out-dir out/latest

# Открыть отчёт
xdg-open out/latest/report.html
```

Параметры оркестратора:

| Параметр | По умолчанию | Описание |
|---|---|---|
| `--repo-url` | langchain4j/langchain4j | URL GitHub-репозитория |
| `--mode` | full | `fast` — только Tree-sitter; `full` — + граф зависимостей Maven |
| `--render-html` | — | Генерировать интерактивный HTML-отчёт |
| `--max-graph-nodes` | 500 | Максимум узлов в визуальном графе отчёта |
| `--out-dir` | out/latest | Директория для артефактов (относительно корня репозитория) |
| `--build-image` | — | Пересобрать Docker-образ перед запуском |
| `--timeout` | 0 | Таймаут контейнера в секундах (0 — без ограничений) |

## Артефакты

После анализа в `--out-dir`:

| Файл | Содержимое |
|---|---|
| `report.json` | Метрики, граф, технический анализ (внутри контейнера) |
| `orchestrator.json` | Таймингли и статистика ресурсов на стороне хоста |
| `combined.json` | Объединённый отчёт (входные данные для HTML) |
| `report.html` | Интерактивный отчёт (генерируется с `--render-html`) |
| `container.log` | Лог выполнения внутри контейнера |

## Разработка

```bash
# Запустить веб-сервер локально (без Docker)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-web.txt
python run_web.py --port 8080
# http://localhost:8080/dev/

# Перегенерировать HTML-отчёт из существующего combined.json
python src/analyzer/render_report.py \
  --input out/latest/combined.json \
  --output out/latest/report.html \
  --max-graph-nodes 500

# Тесты
pytest tests/
```

## Требования

- Docker Engine 24+
- Docker Compose v2 (`docker-compose` или `docker compose`)
- Доступ к публичным GitHub-репозиториям из контейнера

Для локального запуска без Docker дополнительно: Python 3.12+, `tree_sitter==0.21.3`, `tree_sitter_languages==1.10.2`.
