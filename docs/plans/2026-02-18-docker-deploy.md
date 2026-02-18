# Docker Deploy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Упаковать CSQA Metrics в Docker Compose с DooD для деплоя на Timeweb Apps одной командой.

**Architecture:** Два образа — `web` (FastAPI + Docker CLI) и `csqa-metrics:fast` (анализатор). Веб-контейнер монтирует `/var/run/docker.sock` и через `orchestrate.py` спавнит аналитический контейнер на хостовом daemon. Переменная `CSQA_HOST_OUT_DIR` синхронизирует пути bind-mount между хостом и контейнером.

**Tech Stack:** Docker Compose v2, python:3.12-slim, docker.io CLI, FastAPI/uvicorn.

---

### Task 1: Добавить .env в .gitignore

**Files:**
- Modify: `.gitignore`

**Step 1: Добавить строку**

```
.env
```

**Step 2: Commit**

```bash
git add .gitignore
git commit -m "chore: ignore .env file"
```

---

### Task 2: Dockerfile для веб-образа

**Files:**
- Create: `Dockerfile`

**Step 1: Написать Dockerfile**

```dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Docker CLI для DooD (только клиент, без daemon)
RUN apt-get update && apt-get install -y --no-install-recommends \
      docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements-web.txt .
RUN pip install --no-cache-dir -r requirements-web.txt

COPY src/ ./src/
COPY run_web.py .

EXPOSE 8080

CMD ["python", "run_web.py"]
```

**Step 2: Проверить сборку**

```bash
docker build -t csqa-web-test .
```
Ожидаем: Successfully built ...

**Step 3: Commit**

```bash
git add Dockerfile
git commit -m "feat(docker): add web server Dockerfile"
```

---

### Task 3: Изменить orchestrate.py — поддержка CSQA_HOST_OUT_DIR

**Files:**
- Modify: `src/orchestrate.py:250-253`

**Step 1: Найти место вставки**

Строка ~250: `f"{out_dir}:/out"` внутри `docker_run_cmd +=`.

**Step 2: Добавить логику host path перед блоком `docker_run_cmd +=`**

Вставить сразу после строки `docker_run_cmd += ["-v", f"{m2}:/root/.m2"]`
и до `docker_run_cmd += ["-v", f"{out_dir}:/out", ...]`:

```python
    # DooD: Docker daemon ищет путь на ХОСТЕ, а не внутри контейнера.
    # CSQA_HOST_OUT_DIR задаётся через docker-compose как хостовый аналог /app/out.
    host_out_base = os.environ.get("CSQA_HOST_OUT_DIR")
    docker_vol_src = Path(host_out_base) / out_dir.name if host_out_base else out_dir
```

**Step 3: Заменить `out_dir` на `docker_vol_src` в `-v` флаге**

```python
    docker_run_cmd += [
        "-v",
        f"{docker_vol_src}:/out",
        ...
    ]
```

**Step 4: Проверить синтаксис**

```bash
python -c "import src.orchestrate"
```
Ожидаем: нет вывода (нет ошибок).

**Step 5: Commit**

```bash
git add src/orchestrate.py
git commit -m "feat(docker): support CSQA_HOST_OUT_DIR for DooD volume mounting"
```

---

### Task 4: docker-compose.yml и .env.example

**Files:**
- Create: `docker-compose.yml`
- Create: `.env.example`

**Step 1: Написать docker-compose.yml**

```yaml
version: "3.9"

services:

  # Строит образ csqa-metrics:fast и сразу завершается.
  # Нужен только как build-цель; web зависит от его завершения.
  csqa-analyzer-init:
    build:
      context: .
      dockerfile: src/docker/Dockerfile
      target: fast
    image: csqa-metrics:fast
    restart: "no"
    entrypoint: ["sh", "-c", "exit 0"]

  web:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "${PORT:-8080}:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ${CSQA_DATA_DIR:-/var/lib/csqa}/out:/app/out
    environment:
      CSA_WEB_TOKEN: ${CSA_WEB_TOKEN:-}
      CSQA_HOST_OUT_DIR: ${CSQA_DATA_DIR:-/var/lib/csqa}/out
    restart: unless-stopped
    depends_on:
      csqa-analyzer-init:
        condition: service_completed_successfully
```

**Step 2: Написать .env.example**

```bash
# Токен доступа — подставляется в URL: http://host:8080/<CSA_WEB_TOKEN>/
# Генерация: python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(16)).decode())"
CSA_WEB_TOKEN=

# Хостовый путь для хранения отчётов.
# ВАЖНО: это путь на ХОСТЕ (не внутри контейнера).
# Он используется и как bind-mount source, и передаётся аналитику через CSQA_HOST_OUT_DIR.
# Директория создаётся Docker автоматически.
CSQA_DATA_DIR=/var/lib/csqa

# Порт веб-сервера (опционально, дефолт 8080)
# PORT=8080
```

**Step 3: Commit**

```bash
git add docker-compose.yml .env.example
git commit -m "feat(docker): add docker-compose and .env.example"
```

---

### Task 5: Интеграционная проверка

**Step 1: Создать .env из примера**

```bash
cp .env.example .env
```

**Step 2: Собрать и поднять**

```bash
docker-compose up --build -d
```
Ожидаем: `csqa-analyzer-init` exits 0, `web` запущен.

**Step 3: Проверить статус**

```bash
docker-compose ps
```
Ожидаем: `web` — `running`, `csqa-analyzer-init` — `exited (0)`.

**Step 4: Проверить веб-интерфейс**

```bash
curl --noproxy localhost -s http://localhost:8080/test/ -o /dev/null -w "%{http_code}"
```
Ожидаем: `200`.

**Step 5: Финальный commit если всё ок**

```bash
git add .
git commit -m "feat: docker-compose deployment ready for Timeweb Apps"
```
