import argparse
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

# Local CI/dev environments may not have tree-sitter runtime installed.
if "tree_sitter_languages" not in sys.modules:
    stub = types.ModuleType("tree_sitter_languages")

    class _StubParser:
        def parse(self, src: bytes):
            raise RuntimeError("stub parser")

    def _get_parser(_lang: str):
        return _StubParser()

    stub.get_parser = _get_parser
    sys.modules["tree_sitter_languages"] = stub

from analyzer import java_graph, metrics, render_report  # noqa: E402
from analyzer import main as analyzer_main  # noqa: E402


class MetricE1RegressionTests(unittest.TestCase):
    def test_e1_not_available_without_build_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            out = metrics.compute_all_metrics(
                repo_dir,
                spec_headers=[{"id": "E1", "title": "OSDR"}],
                mode="fast",
                max_graph_depth=3,
            )
        self.assertEqual(out["E1"]["status"], "not_available")
        self.assertIsNone(out["E1"]["OSDR"])
        self.assertNotIn("E1", out["aggregate"]["components"])

    def test_e1_returns_ok_with_pom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            pom = repo_dir / "pom.xml"
            pom.write_text(
                "<project>"
                "<groupId>com.example</groupId>"
                "<artifactId>app</artifactId>"
                "<dependencies>"
                "<dependency>"
                "<groupId>org.springframework.boot</groupId>"
                "<artifactId>spring-boot-starter</artifactId>"
                "</dependency>"
                "<dependency>"
                "<groupId>com.obscure</groupId>"
                "<artifactId>obscure-lib</artifactId>"
                "</dependency>"
                "</dependencies>"
                "</project>",
                encoding="utf-8",
            )
            out = metrics.compute_all_metrics(
                repo_dir,
                spec_headers=[{"id": "E1", "title": "OSDR"}],
                mode="fast",
                max_graph_depth=3,
            )
        self.assertEqual(out["E1"]["status"], "ok")
        self.assertIsNotNone(out["E1"]["OSDR"])
        self.assertIn("E1", out["aggregate"]["components"])
        self.assertEqual(out["E1"]["counts"]["baseline"], 1)
        self.assertEqual(out["E1"]["counts"]["other"], 1)

    def test_e1_skips_parent_group_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            pom = repo_dir / "pom.xml"
            pom.write_text(
                "<project>"
                "<parent>"
                "<groupId>org.springframework.boot</groupId>"
                "<artifactId>spring-boot-starter-parent</artifactId>"
                "<version>3.0.0</version>"
                "</parent>"
                "<groupId>com.mycompany</groupId>"
                "<artifactId>my-app</artifactId>"
                "<dependencies>"
                "<dependency>"
                "<groupId>com.mycompany</groupId>"
                "<artifactId>my-util</artifactId>"
                "</dependency>"
                "</dependencies>"
                "</project>",
                encoding="utf-8",
            )
            out = metrics.compute_all_metrics(
                repo_dir,
                spec_headers=[{"id": "E1", "title": "OSDR"}],
                mode="fast",
                max_graph_depth=3,
            )
        self.assertEqual(out["E1"]["internal_prefix"], "com.mycompany")
        self.assertEqual(out["E1"]["counts"]["internal"], 1)

    def test_e1_parses_gradle_map_style_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            gradle = repo_dir / "build.gradle"
            gradle.write_text(
                "group = 'com.example'\n"
                "dependencies {\n"
                "  implementation group: 'org.springframework.boot', name: 'spring-boot-starter'\n"
                "  implementation(group: 'com.vendor', name: 'utility-lib', version: '1.2.3')\n"
                "  testImplementation group: 'org.crypto', name: 'crypto-core'\n"
                "}\n",
                encoding="utf-8",
            )
            out = metrics.compute_all_metrics(
                repo_dir,
                spec_headers=[{"id": "E1", "title": "OSDR"}],
                mode="fast",
                max_graph_depth=3,
            )

        self.assertEqual(out["E1"]["status"], "ok")
        self.assertEqual(out["E1"]["total_dependencies"], 3)
        self.assertEqual(out["E1"]["counts"]["baseline"], 1)
        self.assertEqual(out["E1"]["counts"]["other"], 1)
        self.assertEqual(out["E1"]["counts"]["risky_security"], 1)

    def test_e1_internal_prefix_uses_namespace_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            pom = repo_dir / "pom.xml"
            pom.write_text(
                "<project>"
                "<groupId>com.acme</groupId>"
                "<artifactId>app</artifactId>"
                "<dependencies>"
                "<dependency>"
                "<groupId>com.acme</groupId>"
                "<artifactId>internal-lib</artifactId>"
                "</dependency>"
                "<dependency>"
                "<groupId>com.acmex</groupId>"
                "<artifactId>external-lib</artifactId>"
                "</dependency>"
                "</dependencies>"
                "</project>",
                encoding="utf-8",
            )
            out = metrics.compute_all_metrics(
                repo_dir,
                spec_headers=[{"id": "E1", "title": "OSDR"}],
                mode="fast",
                max_graph_depth=3,
            )

        self.assertEqual(out["E1"]["internal_prefix"], "com.acme")
        self.assertEqual(out["E1"]["counts"]["internal"], 1)
        self.assertEqual(out["E1"]["counts"]["other"], 1)


class MetricB2RegressionTests(unittest.TestCase):
    def test_b2_returns_not_available_when_no_path_found_within_depth(self) -> None:
        graph = java_graph.JavaGraph(
            edges={"ep": {"mid"}, "mid": set()},
            method_complexity={},
            method_flags={},
            entrypoints=[
                java_graph.EntryPoint(
                    method_id="ep",
                    entry_type="http",
                    has_auth=False,
                    has_validation=False,
                    param_risk="low",
                    entropy_level="low",
                )
            ],
            sinks=[java_graph.Sink(method_id="priv", kind="db", privileged=True)],
            catch_blocks=[],
            security_constructs=[],
        )

        res = metrics.metric_B2_PPI(graph, max_graph_depth=1)
        self.assertEqual(res["status"], "not_available")
        self.assertEqual(res["reason"], "no_path_within_max_depth")
        self.assertIsNone(res["min_distance"])


class MetricF2PathRegressionTests(unittest.TestCase):
    def test_metric_f2_scans_tests_directory_without_src_test_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            (repo_dir / "tests").mkdir(parents=True, exist_ok=True)
            (repo_dir / "tests" / "AuthTest.java").write_text(
                "class AuthTest { LoginService loginService; }",
                encoding="utf-8",
            )

            graph = java_graph.JavaGraph(
                edges={},
                method_complexity={},
                method_flags={},
                entrypoints=[],
                sinks=[],
                catch_blocks=[],
                security_constructs=[{"kind": "authz", "symbol": "LoginService"}],
            )

            res = metrics.metric_F2_SRP(repo_dir, graph)
            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["constructs"], 1)
            self.assertEqual(res["uncovered"], 0)
            self.assertAlmostEqual(res["SRP"], 0.0, places=6)


class RenderReportRegressionTests(unittest.TestCase):
    def test_graph_summary_counts_only_visible_entrypoints_and_sinks(self) -> None:
        data = {
            "analyzer": {
                "meta": {"repo_url": "https://example.com/org/repo", "mode": "fast", "git_head": "abcd1234"},
                "metrics": {
                    "M1": {
                        "export": {
                            "nodes": ["A"],
                            "edges": [],
                            "entrypoint_ids": ["A", "B"],
                            "sink_ids": ["C"],
                        }
                    },
                    "A1": {"sample": []},
                    "aggregate": {"score": 0.5, "components": {}},
                },
            }
        }

        graph_data = render_report._build_graph_data(data, max_graph_nodes=500)
        self.assertEqual(graph_data["summary"]["nodes"], 1)
        self.assertEqual(graph_data["summary"]["entrypoints"], 1)
        self.assertEqual(graph_data["summary"]["sinks"], 0)


class AnalyzerMainRegressionTests(unittest.TestCase):
    def test_main_writes_error_report_when_spec_loading_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "report.json"
            workdir = Path(tmp) / "work"
            args = argparse.Namespace(
                repo_url="https://example.com/repo.git",
                ref="",
                depth=1,
                mode="fast",
                out=str(out_path),
                workdir=str(workdir),
                max_graph_depth=12,
                deps_max_modules=8,
            )

            with (
                mock.patch.object(analyzer_main.argparse.ArgumentParser, "parse_args", return_value=args),
                mock.patch.object(analyzer_main, "load_metric_headers", side_effect=FileNotFoundError("metrics.md missing")),
            ):
                rc = analyzer_main.main()

            self.assertEqual(rc, 1)
            self.assertTrue(out_path.exists())
            report = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertTrue(report["errors"])
            self.assertIn("metrics.md missing", report["errors"][0]["error"])


class JavaGraphHelpersRegressionTests(unittest.TestCase):
    def test_enclosing_type_for_method_uses_nested_class_path(self) -> None:
        method_node = types.SimpleNamespace(start_byte=60, end_byte=90)
        type_decls = [
            {"name": "Outer", "start": 0, "end": 200, "kind": "concrete"},
            {"name": "Inner", "start": 50, "end": 150, "kind": "abstract"},
        ]

        cls, kind = java_graph._enclosing_type_for_method(method_node, type_decls)
        self.assertEqual(cls, "Outer.Inner")
        self.assertEqual(kind, "abstract")

    def test_resolve_placeholder_edges_keeps_recursive_calls(self) -> None:
        edges = {"pkg.C#foo()": {"name:foo"}}
        defs = {"foo": ["pkg.C#foo()"]}

        resolved = java_graph._resolve_placeholder_edges(edges, defs)
        self.assertEqual(resolved["pkg.C#foo()"], {"pkg.C#foo()"})


class RenderReportFindingsGroupingTests(unittest.TestCase):
    """Тесты группировки и сортировки findings для раздела дефектов."""

    def _make_data(self, findings: list[dict]) -> dict:
        """Минимальный combined.json с заданным списком findings."""
        return {
            "analyzer": {
                "meta": {
                    "repo_url": "https://example.com/org/repo",
                    "mode": "fast",
                    "git_head": "abcd1234",
                },
                "metrics": {
                    "M1": {"export": {"nodes": [], "edges": []}},
                    "A1": {
                        "status": "ok",
                        "ASE": 0.5,
                        "entrypoints": 0,
                        "sample": [],
                        "findings": [],
                    },
                    "aggregate": {"score": 0.5, "components": {}},
                    **{mid: {"status": "ok", "findings": []} for mid in
                       ["A2","A3","B1","B2","B3","B4","C1","C2","C3","D1","D2","E1","F1","F2","M1"]},
                },
            }
        }

    def test_findings_sorted_by_severity_within_file(self) -> None:
        """Дефекты внутри файла должны сортироваться critical > high > medium > low."""
        data = self._make_data([])
        data["analyzer"]["metrics"]["A1"]["findings"] = [
            {"metric": "A1", "severity": "medium", "file": "Foo.java", "line": 5, "what": "medium", "why": "", "fix": ""},
            {"metric": "A1", "severity": "critical", "file": "Foo.java", "line": 1, "what": "critical", "why": "", "fix": ""},
            {"metric": "A1", "severity": "high", "file": "Foo.java", "line": 3, "what": "high", "why": "", "fix": ""},
        ]

        graph_data = render_report._build_graph_data(data)
        findings = graph_data["findings"]

        severities = [f["severity"] for f in findings]
        self.assertEqual(severities, ["critical", "high", "medium"])

    def test_findings_include_system_level_without_file(self) -> None:
        """Дефекты без поля file должны попадать в список findings."""
        data = self._make_data([])
        data["analyzer"]["metrics"]["B1"] = {
            "status": "ok",
            "IDS_system": 0.8,
            "IDS": 0.8,
            "findings": [
                {
                    "metric": "B1",
                    "severity": "critical",
                    "file": None,
                    "line": None,
                    "method": None,
                    "what": "Системный дефект",
                    "why": "почему",
                    "fix": "исправление",
                }
            ],
        }

        graph_data = render_report._build_graph_data(data)
        system_findings = [f for f in graph_data["findings"] if not f.get("file")]
        self.assertEqual(len(system_findings), 1)
        self.assertEqual(system_findings[0]["what"], "Системный дефект")

    def test_render_html_contains_file_group_css_class(self) -> None:
        """Сгенерированный HTML должен содержать CSS-класс .file-group."""
        data = self._make_data([])
        graph_data = render_report._build_graph_data(data)
        html_output = render_report._render_html(graph_data)
        self.assertIn(".file-group", html_output)

    def test_render_html_contains_finding_row_css_class(self) -> None:
        """Сгенерированный HTML должен содержать CSS-класс .finding-row."""
        data = self._make_data([])
        graph_data = render_report._build_graph_data(data)
        html_output = render_report._render_html(graph_data)
        self.assertIn(".finding-row", html_output)

    def test_render_html_groupby_file_js_present(self) -> None:
        """Сгенерированный JS должен содержать логику группировки по файлу."""
        data = self._make_data([])
        graph_data = render_report._build_graph_data(data)
        html_output = render_report._render_html(graph_data)
        self.assertIn("fileGroups", html_output)


if __name__ == "__main__":
    unittest.main()
