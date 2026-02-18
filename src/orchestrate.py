#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CmdResult:
    returncode: int
    stdout: str
    stderr: str
    duration_sec: float


def run_cmd(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
            timeout: float | None = None) -> CmdResult:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        end = time.perf_counter()
        return CmdResult(proc.returncode, proc.stdout, proc.stderr, end - start)
    except subprocess.TimeoutExpired:
        end = time.perf_counter()
        return CmdResult(-1, "", "timeout", end - start)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, obj: object) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def start_docker_stats_sampler(container_name: str, stats: dict) -> tuple[subprocess.Popen[str], threading.Thread]:
    cmd = [
        "docker",
        "stats",
        container_name,
        "--format",
        "{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    ansi = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

    def reader() -> None:
        if not proc.stdout:
            return
        for raw in proc.stdout:
            line = ansi.sub("", raw).replace("\r", "").strip()
            if not line or "|" not in line:
                continue
            cpu_s, mem_usage_s, mem_perc_s = (p.strip() for p in line.split("|", 2))
            stats["samples"] += 1
            try:
                cpu = float(cpu_s.replace("%", "").replace(",", ".").strip())
                cur = stats.get("max_cpu_perc")
                if cur is None or cpu > cur:
                    stats["max_cpu_perc"] = cpu
            except ValueError:
                pass
            used_b, _limit_b = parse_mem_usage(mem_usage_s)
            if used_b is not None:
                cur = stats.get("max_mem_used_bytes")
                if cur is None or used_b > cur:
                    stats["max_mem_used_bytes"] = used_b
            try:
                memp = float(mem_perc_s.replace("%", "").replace(",", ".").strip())
                cur = stats.get("max_mem_perc")
                if cur is None or memp > cur:
                    stats["max_mem_perc"] = memp
            except ValueError:
                pass

    t = threading.Thread(target=reader, name="docker-stats-reader", daemon=True)
    t.start()
    return proc, t


def parse_mem_usage(mem_usage_field: str) -> tuple[int | None, int | None]:
    parts = [p.strip() for p in mem_usage_field.split("/", 1)]
    if len(parts) != 2:
        return None, None

    def parse_size(s: str) -> int | None:
        s = s.strip()
        if not s:
            return None
        units = {
            "B": 1,
            "kB": 1000,
            "KB": 1000,
            "KiB": 1024,
            "MB": 1000 * 1000,
            "MiB": 1024 * 1024,
            "GB": 1000 * 1000 * 1000,
            "GiB": 1024 * 1024 * 1024,
        }
        num = ""
        unit = ""
        for ch in s:
            if (ch.isdigit() or ch == ".") and not unit:
                num += ch
            else:
                unit += ch
        num = num.strip()
        unit = unit.strip()
        if not num:
            return None
        mult = units.get(unit, None)
        if mult is None:
            return None
        return int(float(num) * mult)

    return parse_size(parts[0]), parse_size(parts[1])


def main() -> int:
    parser = argparse.ArgumentParser(description="Orchestrate CSQA metrics analyzer in Docker and measure timings.")
    parser.add_argument("--repo-url", default="https://github.com/langchain4j/langchain4j", help="Target Git repo URL")
    parser.add_argument("--ref", default="", help="Git ref (branch/tag/commit). Empty = default branch HEAD")
    parser.add_argument("--mode", choices=["fast", "full"], default="full", help="Analyzer mode")
    parser.add_argument("--build-image", action="store_true", help="Build analyzer image(s) before run")
    parser.add_argument("--image-tag", default="", help="Docker image tag override (auto-selected by mode if empty)")
    parser.add_argument("--out-dir", default="out/latest", help="Output directory (relative to repo root)")
    parser.add_argument("--deps-max-modules", type=int, default=8, help="Max Maven modules to analyze for deps (full mode)")
    parser.add_argument("--cpu", default="", help="Docker --cpus value, e.g. 2.0")
    parser.add_argument("--memory", default="", help="Docker --memory value, e.g. 2g")
    parser.add_argument("--m2-cache-dir", default="", help="Host dir to mount as /root/.m2 (speeds up Maven in full mode)")
    parser.add_argument("--timeout", type=int, default=0, help="Container timeout in seconds (0 = no limit)")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    out_dir = (repo_root / args.out_dir).resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    ensure_dir(out_dir)

    # Выбор образа по режиму: fast-образ без JVM, full-образ с JRE.
    if args.image_tag:
        image_tag = args.image_tag
    else:
        image_tag = f"csqa-metrics:{args.mode}"

    orchestrator = {
        "meta": {
            "repo_root": str(repo_root),
            "started_at_unix": time.time(),
            "target_repo_url": args.repo_url,
            "target_ref": args.ref,
            "mode": args.mode,
            "image_tag": image_tag,
        },
        "timings": {},
        "docker": {},
        "stats": {
            "samples": 0,
            "max_cpu_perc": None,
            "max_mem_used_bytes": None,
            "max_mem_perc": None,
        },
        "errors": [],
    }

    if args.build_image:
        dockerfile = repo_root / "src" / "docker" / "Dockerfile"
        # Собираем целевой образ (fast или full) через --target.
        build_cmd = [
            "docker", "build",
            "-f", str(dockerfile),
            "--target", args.mode,
            "-t", image_tag,
            str(repo_root),
        ]
        t = run_cmd(build_cmd, cwd=repo_root)
        orchestrator["timings"]["docker_build_sec"] = t.duration_sec
        if t.returncode != 0:
            orchestrator["errors"].append({"step": "docker_build", "stderr": t.stderr[-4000:], "stdout": t.stdout[-4000:]})
            write_json(out_dir / "orchestrator.json", orchestrator)
            return 2

    container_name = f"csqa-metrics-{int(time.time())}"

    docker_run_cmd = ["docker", "run", "-d", "--name", container_name]
    if args.cpu:
        docker_run_cmd += ["--cpus", args.cpu]
    if args.memory:
        docker_run_cmd += ["--memory", args.memory]
    if args.m2_cache_dir:
        m2 = Path(args.m2_cache_dir)
        if not m2.is_absolute():
            m2 = (repo_root / m2).resolve()
        ensure_dir(m2)
        docker_run_cmd += ["-v", f"{m2}:/root/.m2"]

    docker_run_cmd += [
        "-v",
        f"{out_dir}:/out",
        image_tag,
        "--repo-url",
        args.repo_url,
        "--out",
        "/out/report.json",
        "--mode",
        args.mode,
        "--deps-max-modules",
        str(args.deps_max_modules),
    ]
    if args.ref:
        docker_run_cmd += ["--ref", args.ref]

    t_run = time.perf_counter()
    r = run_cmd(docker_run_cmd, cwd=repo_root)
    orchestrator["timings"]["docker_run_create_sec"] = r.duration_sec
    if r.returncode != 0:
        orchestrator["errors"].append({"step": "docker_run", "stderr": r.stderr[-4000:], "stdout": r.stdout[-4000:]})
        write_json(out_dir / "orchestrator.json", orchestrator)
        return 2
    container_id = r.stdout.strip()
    orchestrator["docker"]["container_id"] = container_id
    orchestrator["docker"]["container_name"] = container_name

    stats_proc, stats_thread = start_docker_stats_sampler(container_name, orchestrator["stats"])

    # Ожидание завершения контейнера с опциональным таймаутом.
    timed_out = False
    if args.timeout > 0:
        wait_res = run_cmd(["docker", "wait", container_name], timeout=args.timeout)
        if wait_res.returncode == -1 and wait_res.stderr == "timeout":
            timed_out = True
            run_cmd(["docker", "stop", "-t", "5", container_name])
            wait_res = run_cmd(["docker", "wait", container_name])
    else:
        wait_res = run_cmd(["docker", "wait", container_name])

    orchestrator["timings"]["docker_wait_sec"] = wait_res.duration_sec
    orchestrator["docker"]["exit_code"] = wait_res.stdout.strip()
    orchestrator["docker"]["timed_out"] = timed_out
    orchestrator["timings"]["docker_run_total_wall_sec"] = time.perf_counter() - t_run

    # Stop stats sampler (docker stats keeps streaming even after container exit).
    stats_proc.terminate()
    try:
        stats_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        stats_proc.kill()
    stats_thread.join(timeout=5)

    logs = run_cmd(["docker", "logs", container_name])
    if logs.returncode == 0:
        (out_dir / "container.log").write_text(logs.stdout, encoding="utf-8")
    else:
        orchestrator["errors"].append({"step": "docker_logs", "stderr": logs.stderr[-2000:]})

    rm = run_cmd(["docker", "rm", "-f", container_name])
    orchestrator["timings"]["docker_rm_sec"] = rm.duration_sec

    write_json(out_dir / "orchestrator.json", orchestrator)

    # Combine reports if analyzer report exists
    combined = {"orchestrator": orchestrator, "analyzer": None}
    report_path = out_dir / "report.json"
    if report_path.exists():
        try:
            combined["analyzer"] = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            orchestrator["errors"].append({"step": "read_report", "error": str(e)})
    write_json(out_dir / "combined.json", combined)

    print(f"Wrote: {out_dir}/combined.json")
    if orchestrator["errors"]:
        print("Errors:")
        for err in orchestrator["errors"]:
            print(f"- {err.get('step')}: {err.get('error') or 'see orchestrator.json'}")
        return 3

    if timed_out:
        print(f"Container timed out after {args.timeout}s, see {out_dir}/container.log")
        return 5

    container_exit = orchestrator["docker"].get("exit_code", "0").strip()
    if container_exit != "0":
        print(f"Container exited with code {container_exit}, see {out_dir}/container.log")
        return 4

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
