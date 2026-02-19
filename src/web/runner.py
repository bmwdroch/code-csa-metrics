"""Job runner for CSA Metrics web interface.

Each analysis job runs orchestrate.py in a background thread and monitors
container.log for progress keywords to drive the SSE progress stream.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

# Repo root: src/web/runner.py → parents[2]
REPO_ROOT = Path(__file__).resolve().parents[2]

# Keywords expected in container.log → (min_percent, status_message)
# Ordered from first to last so we don't go backwards.
_LOG_STAGES: list[tuple[str, int, str]] = [
    ("Cloning into", 20, "Клонирование репозитория..."),
    ("remote: Counting", 25, "Подсчёт объектов..."),
    ("Receiving objects", 30, "Загрузка объектов..."),
    ("Resolving deltas", 38, "Распаковка дельт..."),
    ('"status": "ok"', 78, "Формирование отчёта..."),
    ('"status": "error"', 78, "Анализ завершён с ошибками, формирование отчёта..."),
]

# Slow drift: while running and no new keywords, nudge percent toward this cap
_DRIFT_CAP = 72
_DRIFT_STEP = 1       # percent per tick
_DRIFT_INTERVAL = 8.0  # seconds between ticks


@dataclass
class Job:
    id: str
    repo_url: str
    status: str = "queued"   # queued | running | done | failed
    percent: int = 0
    message: str = "В очереди..."
    error: str | None = None
    created_at: float = field(default_factory=time.time)

    @property
    def out_dir(self) -> Path:
        return REPO_ROOT / "out" / f"web-{self.id}"

    @property
    def repo_display(self) -> str:
        """Return 'owner/repo' extracted from a GitHub URL."""
        parts = self.repo_url.rstrip("/").rstrip(".git").split("/")
        return "/".join(parts[-2:]) if len(parts) >= 2 else self.repo_url


class JobRunner:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────────────────────────

    def start_job(self, repo_url: str) -> str:
        """Create and start a new analysis job. Returns job ID."""
        job_id = uuid.uuid4().hex[:12]
        job = Job(id=job_id, repo_url=repo_url)
        with self._lock:
            self._jobs[job_id] = job
        t = threading.Thread(target=self._run_job, args=(job,), daemon=True)
        t.start()
        return job_id

    def get_job(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[Job]:
        with self._lock:
            return list(self._jobs.values())

    # ── Internal ────────────────────────────────────────────────────────────────

    def _update(
        self,
        job: Job,
        percent: int,
        message: str,
        status: str = "running",
        *,
        force: bool = False,
    ) -> None:
        """Thread-safe job state update. Never goes backwards unless forced."""
        with self._lock:
            if status == "running" and not force and percent <= job.percent:
                return
            job.percent = percent
            job.message = message
            job.status = status

    def _run_job(self, job: Job) -> None:
        self._update(job, 5, "Инициализация конвейера анализа...")

        orchestrate = REPO_ROOT / "src" / "orchestrate.py"
        out_dir_rel = f"out/web-{job.id}"

        cmd = [
            sys.executable, str(orchestrate),
            "--repo-url", job.repo_url,
            "--mode", "fast",
            "--render-html",
            "--out-dir", out_dir_rel,
        ]

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(REPO_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            self._update(job, 0, f"Не удалось запустить: {exc}", status="failed", force=True)
            job.error = str(exc)
            return
        except Exception as exc:  # noqa: BLE001
            self._update(job, 0, f"Непредвиденная ошибка: {exc}", status="failed", force=True)
            job.error = str(exc)
            return

        self._update(job, 10, "Запуск Docker-контейнера...")

        # Monitor container.log for progress keywords
        log_mon = threading.Thread(
            target=self._monitor_container_log,
            args=(job, job.out_dir / "container.log"),
            daemon=True,
        )
        log_mon.start()

        # Slow drift: nudge percent upward so the bar doesn't stall visually
        drift_t = threading.Thread(
            target=self._drift_progress,
            args=(job,),
            daemon=True,
        )
        drift_t.start()

        # Drain orchestrate stdout (keeps the pipe from blocking on large output)
        def _drain() -> None:
            if proc.stdout:
                for _ in proc.stdout:
                    pass

        drain_t = threading.Thread(target=_drain, daemon=True)
        drain_t.start()

        proc.wait()
        drain_t.join(timeout=5)
        log_mon.join(timeout=3)

        if proc.returncode == 0:
            self._update(job, 100, "Анализ завершён!", status="done", force=True)
        else:
            with self._lock:
                if job.status == "running":
                    job.status = "failed"
                    job.percent = 0
                    job.message = f"Ошибка анализа (код завершения {proc.returncode})"
                    job.error = (
                        f"orchestrate.py завершился с кодом {proc.returncode}. "
                        "Убедитесь, что Docker-образ csqa-metrics:fast собран."
                    )

    def _monitor_container_log(self, job: Job, log_path: Path) -> None:
        """Tail container.log and map keywords to progress stages."""
        deadline = time.time() + 180  # wait up to 3 min for container to start
        while not log_path.exists():
            if time.time() > deadline or job.status in ("done", "failed"):
                return
            time.sleep(0.5)

        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                while job.status == "running":
                    line = fh.readline()
                    if not line:
                        if job.status != "running":
                            break
                        time.sleep(0.15)
                        continue
                    lw = line.lower()
                    for keyword, pct, msg in _LOG_STAGES:
                        if keyword.lower() in lw:
                            self._update(job, pct, msg)
                            break
        except OSError:
            pass

    def _drift_progress(self, job: Job) -> None:
        """Slowly nudge percent forward so the bar never looks frozen."""
        time.sleep(15)  # give real signals a head start
        while job.status == "running":
            with self._lock:
                if job.percent < _DRIFT_CAP:
                    job.percent = min(job.percent + _DRIFT_STEP, _DRIFT_CAP)
            time.sleep(_DRIFT_INTERVAL)
