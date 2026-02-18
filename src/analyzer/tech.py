import os
import re
import subprocess
import time
import json
from pathlib import Path


def _run(cmd: list[str], cwd: Path) -> tuple[int, str, str, float]:
    start = time.perf_counter()
    p = subprocess.run(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    end = time.perf_counter()
    return p.returncode, p.stdout, p.stderr, end - start


def _parse_maven_modules(pom_text: str) -> list[str]:
    modules = []
    in_modules = False
    for line in pom_text.splitlines():
        if "<modules" in line:
            in_modules = True
        if in_modules:
            m = re.search(r"<module>\s*([^<]+?)\s*</module>", line)
            if m:
                modules.append(m.group(1).strip())
        if "</modules>" in line and in_modules:
            break
    return modules


def collect_technical_metrics(repo_dir: Path, *, mode: str, deps_max_modules: int) -> dict:
    file_counts: dict[str, int] = {}
    total_bytes = 0
    total_files = 0
    total_lines = 0

    for root, dirs, files in os.walk(repo_dir):
        # prune common build dirs
        dirs[:] = [d for d in dirs if d not in {".git", "target", "build", ".gradle", ".idea"}]
        for fn in files:
            p = Path(root) / fn
            try:
                st = p.stat()
            except OSError:
                continue
            total_bytes += st.st_size
            total_files += 1
            ext = p.suffix.lower() or "<none>"
            file_counts[ext] = file_counts.get(ext, 0) + 1
            # very cheap LoC estimate for text-ish files
            if ext in {".java", ".kt", ".kts", ".groovy", ".xml", ".yml", ".yaml", ".md", ".properties"}:
                try:
                    total_lines += sum(1 for _ in p.open("rb"))
                except OSError:
                    pass

    tech = {
        "size_bytes": total_bytes,
        "files_total": total_files,
        "lines_estimate": total_lines,
        "file_counts_by_ext": dict(sorted(file_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "build_system": {},
        "deps": {},
    }

    # Detect build system
    has_pom = (repo_dir / "pom.xml").exists()
    has_gradle = (repo_dir / "build.gradle").exists() or (repo_dir / "build.gradle.kts").exists()
    tech["build_system"] = {"maven": has_pom, "gradle": has_gradle}

    # Optional: resolve dependencies with Maven wrapper (expensive).
    if mode == "full" and has_pom and (repo_dir / "mvnw").exists():
        pom_text = (repo_dir / "pom.xml").read_text(encoding="utf-8", errors="ignore")
        modules = _parse_maven_modules(pom_text)
        tech["deps"]["maven_modules_total"] = len(modules)

        # We'll run dependency:list for a limited number of modules to keep CI impact bounded.
        # Many large repos have dozens of modules; full reactor dependency resolution is expensive.
        selected = modules[: max(0, deps_max_modules)]
        tech["deps"]["maven_modules_analyzed"] = len(selected)
        tech["deps"]["maven_modules_selected"] = selected

        out_file = repo_dir / ".csa" / "mvn-dependency-list.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        # Absolute path so each module run appends into the same file.
        out_file_abs = str(out_file)

        # Reset output file for clean run.
        try:
            out_file.unlink()
        except FileNotFoundError:
            pass

        meta_file = repo_dir / ".csa" / "mvn-deps-meta.json"
        meta_file.write_text(
            json.dumps({"modules_total": len(modules), "modules_selected": selected}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

        total_dur = 0.0
        worst_exit = 0
        stderr_tails: list[str] = []
        for mod in selected or ["."]:
            cmd: list[str] = [
                "bash",
                str(repo_dir / "mvnw"),
                "-q",
                "-DskipTests",
            ]
            if mod != ".":
                cmd += ["-pl", mod]
            cmd += [
                "dependency:list",
                f"-DoutputFile={out_file_abs}",
                "-DappendOutput=true",
            ]
            code, _out, err, dur = _run(cmd, cwd=repo_dir)
            total_dur += dur
            if code != 0:
                worst_exit = code
                stderr_tails.extend(err.splitlines()[-20:])

        tech["deps"]["mvn_dependency_list_sec"] = total_dur
        tech["deps"]["mvn_dependency_list_exit"] = worst_exit

        dep_lines: list[str] = []
        if out_file.exists():
            # Strip ANSI color codes that Maven may emit into the output file.
            ansi = re.compile("\x1b\\[[0-9;]*[A-Za-z]")
            for raw in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = ansi.sub("", raw).strip()
                if not line or line.startswith("[INFO]") or "Downloading" in line:
                    continue
                if line.count(":") >= 4:
                    dep_lines.append(line)

        tech["deps"]["mvn_dependency_list_count"] = len(dep_lines)
        tech["deps"]["mvn_dependency_list_sample"] = dep_lines[:50]
        if stderr_tails:
            tech["deps"]["mvn_dependency_list_stderr_tail"] = stderr_tails[-50:]

    return tech
