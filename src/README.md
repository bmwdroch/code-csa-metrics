# Prototype: CSA Metrics Pipeline Benchmark

Goal: measure the pipeline impact of computing security-oriented code quality metrics from `docs/metrics.md`.

This prototype consists of:
- a containerized analyzer that clones a target repo, builds an approximate code graph for Java, computes metrics, and writes a JSON report;
- a host orchestrator that builds/runs the container and measures container lifecycle timings + resource usage.

Quick start (default target: langchain4j/langchain4j):
```bash
cd /home/development/code-csa-metrics
python3 src/orchestrate.py --build-image
```

Useful runs:
```bash
# Fast: no Maven deps
python3 src/orchestrate.py --mode fast

# Full: resolve deps for E1 (cache Maven downloads between runs)
python3 src/orchestrate.py --mode full --m2-cache-dir out/m2-cache --deps-max-modules 8

# Generate interactive HTML report (E1 intentionally excluded)
python3 src/orchestrate.py --mode fast --render-html
```

Artifacts:
- `out/latest/report.json` - analyzer report (inside-container timings + computed metrics)
- `out/latest/orchestrator.json` - host-level timings + container stats sampling
- `out/latest/combined.json` - merged report
- `out/latest/report.html` - interactive HTML report (generated with `--render-html`, E1 intentionally excluded)

What gets measured:
- Container lifecycle: `orchestrator.timings.*` (create/start, wait/runtime, rm)
- Analyzer stages: `analyzer.timings.clone_sec`, `analyzer.timings.technical_sec`, `analyzer.timings.metrics_sec`
- Resource peaks (sampled): `orchestrator.stats.max_cpu_perc`, `orchestrator.stats.max_mem_used_bytes`
- Static code graph build time: `analyzer.metrics._internal.java_graph_build_sec`

Notes:
- Graph and static analysis are heuristic (no full Java type resolution). The point of this prototype is to measure CI cost/feasibility first, then iterate on accuracy.
- Graph tech choice: Tree-sitter Java parser + heuristic call-edge linking.
  - Why: fast, no build needed, works on raw source, predictable in containers.
  - Tradeoff: imprecise dispatch/type resolution; edges are an over-approximation.
- Modes:
  - `--mode fast`: clone + Java graph + metrics (no Maven deps resolution).
  - `--mode full`: additionally resolves Maven deps for `E1` via `mvnw dependency:list` on a limited number of modules.
- Maven cache: use `--m2-cache-dir out/m2-cache` to mount `/root/.m2` and measure warm-cache timings.
