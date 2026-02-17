# --- base: Python + tree-sitter + git (общая для fast и full) ---
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY src/analyzer/ /app/analyzer/
COPY docs/metrics.md /app/spec/metrics.md

RUN pip install --no-cache-dir tree_sitter==0.21.3 tree_sitter_languages==1.10.2

# --- fast: только tree-sitter анализ, без JVM (~250 МБ) ---
FROM base AS fast
ENTRYPOINT ["python", "-m", "analyzer.main"]

# --- full: base + JRE для mvnw dependency:list (~450 МБ) ---
FROM base AS full
RUN apt-get update && apt-get install -y --no-install-recommends \
      default-jre-headless curl \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["python", "-m", "analyzer.main"]
