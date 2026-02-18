import argparse
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from analyzer.metrics import compute_all_metrics
from analyzer.spec import load_metric_headers
from analyzer.tech import collect_technical_metrics
from analyzer.timing import Timings


@dataclass(frozen=True)
class CmdResult:
    returncode: int
    stdout: str
    stderr: str
    duration_sec: float


def run_cmd(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> CmdResult:
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    end = time.perf_counter()
    return CmdResult(proc.returncode, proc.stdout, proc.stderr, end - start)


def git_clone(repo_url: str, ref: str, dest: Path, depth: int) -> dict:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        # fresh run in ephemeral container, but keep safe
        run_cmd(["rm", "-rf", str(dest)])
    args = ["git", "clone", "--no-tags", "--depth", str(depth), repo_url, str(dest)]
    res = run_cmd(args)
    if res.returncode != 0:
        raise RuntimeError(f"git clone failed: {res.stderr.strip()}")

    if ref:
        r = run_cmd(["git", "checkout", "--force", ref], cwd=dest)
        if r.returncode != 0:
            # Shallow clone may not contain an arbitrary commit SHA/tag; try fetching the ref explicitly.
            fetch = run_cmd(["git", "fetch", "--no-tags", "--depth", str(depth), "origin", ref], cwd=dest)
            if fetch.returncode == 0:
                r = run_cmd(["git", "checkout", "--force", ref], cwd=dest)
        if r.returncode != 0:
            raise RuntimeError(f"git checkout {ref} failed: {r.stderr.strip()}")

    head = run_cmd(["git", "rev-parse", "HEAD"], cwd=dest)
    branch = run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=dest)
    return {
        "clone_sec": res.duration_sec,
        "head": head.stdout.strip() if head.returncode == 0 else "",
        "branch": branch.stdout.strip() if branch.returncode == 0 else "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="CSQA metrics analyzer (runs inside container)")
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--ref", default="")
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--mode", choices=["fast", "full"], default="full")
    parser.add_argument("--out", default="/out/report.json")
    parser.add_argument("--workdir", default="/work")
    parser.add_argument("--max-graph-depth", type=int, default=12)
    parser.add_argument("--deps-max-modules", type=int, default=8, help="Max Maven modules to analyze for deps (full mode)")
    args = parser.parse_args()

    timings = Timings()
    report: dict = {
        "meta": {
            "repo_url": args.repo_url,
            "ref": args.ref,
            "depth": args.depth,
            "mode": args.mode,
            "started_at_unix": time.time(),
        },
        "spec": {},
        "timings": {},
        "resources": {},
        "technical": {},
        "metrics": {},
        "notes": [],
        "errors": [],
    }

    # Load metric spec headers (sanity: ensure we report all IDs present in docs/metrics.md)
    spec_path = Path("/app/spec/metrics.md")
    spec_headers = load_metric_headers(spec_path)
    report["spec"]["headers"] = spec_headers

    workdir = Path(args.workdir)
    repo_dir = workdir / "repo"

    try:
        with timings.step("clone"):
            clone_meta = git_clone(args.repo_url, args.ref, repo_dir, args.depth)
        report["meta"].update({"git_head": clone_meta["head"], "git_branch": clone_meta["branch"]})
        report["timings"]["clone_sec"] = clone_meta["clone_sec"]

        with timings.step("technical"):
            report["technical"] = collect_technical_metrics(repo_dir, mode=args.mode, deps_max_modules=args.deps_max_modules)

        with timings.step("metrics"):
            computed = compute_all_metrics(
                repo_dir,
                spec_headers=spec_headers,
                mode=args.mode,
                max_graph_depth=args.max_graph_depth,
            )
            report["metrics"] = computed

    except Exception as e:
        report["errors"].append({"error": str(e)})

    report["timings"].update(timings.as_dict())
    report["resources"] = timings.resource_snapshot()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Emit minimal stdout for docker logs
    print(json.dumps({"status": "ok" if not report["errors"] else "error", "out": str(out_path)}, ensure_ascii=False))

    return 0 if not report["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
