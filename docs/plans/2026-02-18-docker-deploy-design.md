# Docker-развёртывание CSQA Metrics

**Дата:** 2026-02-18
**Статус:** утверждён

## Цель

Упаковать проект в Docker Compose так, чтобы развернуть на Timeweb Apps (или любом VPS) одной командой: скопировал репозиторий, выставил переменные окружения, запустил `docker-compose up --build -d`.

## Архитектура

Два Docker-образа, паттерн DooD (Docker-outside-of-Docker):

```
docker-compose up --build
       │
       ├─ csqa-analyzer-init  ── строит csqa-metrics:fast, сразу завершается
       │
       └─ web  (FastAPI / uvicorn, порт 8080)
              ├── /var/run/docker.sock  ← DooD: доступ к хостовому daemon
              └── ${CSQA_DATA_DIR}/out → /app/out  ← bind mount
                              │
                              └── docker run csqa-metrics:fast \
                                    -v ${CSQA_DATA_DIR}/out/job-xxx:/out
```

Веб-контейнер вызывает `orchestrate.py`, который через Docker CLI (DooD) спавнит аналитический контейнер на хостовом daemon. Отчёты записываются в bind-mount директорию, доступную обоим.

## Проблема DooD и её решение

При DooD-паттерне `docker run -v /app/out/job-xxx:/out` передаёт путь **хостовому** daemon, который ищет `/app/out/job-xxx` на хосте, а не внутри веб-контейнера. Без синхронизации путей контейнер аналитика не найдёт директорию.

Решение: единая переменная `CSQA_DATA_DIR` используется и как bind-mount source в `docker-compose.yml`, и передаётся в `orchestrate.py` через `CSQA_HOST_OUT_DIR`. Таким образом путь внутри контейнера (`/app/out`) и путь на хосте (`${CSQA_DATA_DIR}/out`) всегда синхронизированы.

## Файлы

| Файл | Действие | Описание |
|---|---|---|
| `Dockerfile` | создать | Образ веб-сервера |
| `docker-compose.yml` | создать | Оркестрация двух сервисов |
| `.env.example` | создать | Документация переменных |
| `src/orchestrate.py` | изменить | Читать `CSQA_HOST_OUT_DIR` для volume mount |

## Переменные окружения

| Переменная | Обязательная | Дефолт | Описание |
|---|---|---|---|
| `CSA_WEB_TOKEN` | да | — | Токен в URL-префиксе (`/{token}/`) |
| `CSQA_DATA_DIR` | нет | `/var/lib/csqa` | Хостовый путь для хранения отчётов |
| `PORT` | нет | `8080` | Порт веб-сервера |

## Dockerfile (веб-образ)

Базовый образ `python:3.12-slim`. Дополнительно устанавливается пакет `docker.io` — он даёт только Docker CLI без daemon, что достаточно для DooD. Зависимости проекта из `requirements-web.txt`. Точка входа — `python run_web.py`.

## docker-compose.yml

Два сервиса:

- **`csqa-analyzer-init`** — собирает образ `csqa-metrics:fast` из `src/docker/Dockerfile --target fast`, переопределяет entrypoint на `exit 0`, `restart: no`. Нужен только для тега образа на хосте, сам не работает.
- **`web`** — зависит от завершения `csqa-analyzer-init` (`condition: service_completed_successfully`), монтирует docker socket и bind-mount для отчётов, передаёт env vars.

## Изменение orchestrate.py

Добавить три строки в начало `_run_job`-логики: читать `CSQA_HOST_OUT_DIR` из окружения. Если переменная задана — использовать `{CSQA_HOST_OUT_DIR}/{job_id}` как источник volume при `docker run`. Если не задана — использовать прежнее поведение (путь `out_dir`), что сохраняет обратную совместимость для локального запуска без Docker Compose.
