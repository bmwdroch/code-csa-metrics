"""FastAPI web interface for CSA Metrics.

Access is controlled by a base64 token in the URL path:
    http://host:8080/<CSA_WEB_TOKEN>/

Set the CSA_WEB_TOKEN environment variable to the token string that users
must include in their URL.  If the variable is unset every request is allowed
(useful for local development).

Routes (all prefixed with /{token}):
    GET  /                      Landing page – enter GitHub repo URL
    POST /run                   Start an analysis job → redirect to progress
    GET  /job/{job_id}          Progress page (auto-redirects when done)
    GET  /api/job/{job_id}/events  SSE stream of progress events
    GET  /report/{job_id}       Serve the finished report.html
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.templating import Jinja2Templates

from web.runner import JobRunner

# ── Configuration ───────────────────────────────────────────────────────────────

_VALID_TOKEN: str = os.environ.get("CSA_WEB_TOKEN", "")
_TEMPLATES_DIR = Path(__file__).parent / "templates"

_GITHUB_RE = re.compile(
    r"^https?://github\.com/[\w.\-]+/[\w.\-]+(\.git)?(/.*)?$",
    re.IGNORECASE,
)

# ── App ─────────────────────────────────────────────────────────────────────────

app = FastAPI(title="CSA Metrics", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
runner = JobRunner()


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _check_token(token: str) -> None:
    if _VALID_TOKEN and token != _VALID_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid access token")


def _validate_github_url(url: str) -> bool:
    return bool(_GITHUB_RE.match(url.strip()))


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


# ── Routes ──────────────────────────────────────────────────────────────────────

@app.get("/{token}/", response_class=HTMLResponse)
async def index(token: str, request: Request, error: str = ""):
    _check_token(token)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "token": token, "error": error},
    )


@app.post("/{token}/run")
async def run_analysis(
    token: str,
    request: Request,
    repo_url: str = Form(...),
    max_nodes: int = Form(500),
):
    _check_token(token)
    url = repo_url.strip().rstrip("/")
    if not _validate_github_url(url):
        return RedirectResponse(
            f"/{token}/?error=Invalid+GitHub+URL.+Must+be+https%3A%2F%2Fgithub.com%2Fowner%2Frepo",
            status_code=303,
        )
    job_id = runner.start_job(url, max_nodes=max_nodes)
    return RedirectResponse(f"/{token}/job/{job_id}", status_code=303)


@app.get("/{token}/job/{job_id}", response_class=HTMLResponse)
async def progress_page(token: str, job_id: str, request: Request):
    _check_token(token)
    job = runner.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status == "done":
        return RedirectResponse(f"/{token}/report/{job_id}", status_code=303)
    return templates.TemplateResponse(
        "progress.html",
        {"request": request, "token": token, "job": job},
    )


@app.get("/{token}/api/job/{job_id}/events")
async def job_events(token: str, job_id: str):
    _check_token(token)

    async def _stream():
        last_percent = -1
        last_status = ""
        while True:
            job = runner.get_job(job_id)
            if job is None:
                yield _sse("fail", {"message": "Job not found"})
                return

            changed = job.percent != last_percent or job.status != last_status
            if changed:
                last_percent = job.percent
                last_status = job.status
                yield _sse("progress", {
                    "percent": job.percent,
                    "message": job.message,
                    "status": job.status,
                })

            if job.status == "done":
                yield _sse("done", {"redirect": f"/{token}/report/{job_id}"})
                return

            if job.status == "failed":
                yield _sse("fail", {"message": job.message or "Analysis failed"})
                return

            # Keepalive comment (prevents proxies from closing idle connections)
            yield ": keepalive\n\n"
            await asyncio.sleep(0.4)

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/{token}/report/{job_id}")
async def serve_report(token: str, job_id: str):
    _check_token(token)
    job = runner.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status == "running" or job.status == "queued":
        return RedirectResponse(f"/{token}/job/{job_id}", status_code=303)
    if job.status == "failed":
        raise HTTPException(
            status_code=500,
            detail=job.error or "Analysis failed — no report generated",
        )
    report_path = job.out_dir / "report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")
    return FileResponse(str(report_path), media_type="text/html")


# ── Health check ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}
