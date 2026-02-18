import argparse
import os
import shutil
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

from analyzer import java_graph, metrics  # noqa: E402
import orchestrate  # noqa: E402


class ParserSkipRegressionTests(unittest.TestCase):
    def test_build_java_graph_skips_file_with_parse_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            (repo_dir / "Broken.java").write_bytes(b"// BROKEN")
            (repo_dir / "AlsoBroken.java").write_bytes(b"// ALSO BROKEN")

            class AlwaysFailParser:
                def parse(self, src: bytes):
                    raise RuntimeError("synthetic parse failure")

            with mock.patch.object(java_graph, "_JAVA_PARSER", AlwaysFailParser()):
                graph = java_graph.build_java_graph(repo_dir, max_files=None)

            self.assertEqual(graph.nodes_count, 0)
            self.assertEqual(len(graph.method_flags), 0)


class MetricF2RegressionTests(unittest.TestCase):
    def test_metric_f2_counts_uncovered_constructs_per_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            (repo_dir / "src" / "test" / "java").mkdir(parents=True, exist_ok=True)
            (repo_dir / "src" / "test" / "java" / "AuthTest.java").write_text(
                "class AuthTest { LoginService loginService; }",
                encoding="utf-8",
            )
            (repo_dir / "src" / "main" / "java").mkdir(parents=True, exist_ok=True)
            (repo_dir / "src" / "main" / "java" / "Prod.java").write_text(
                "class Prod { PaymentValidator paymentValidator; }",
                encoding="utf-8",
            )

            graph = java_graph.JavaGraph(
                edges={},
                method_complexity={},
                method_flags={},
                entrypoints=[],
                sinks=[],
                catch_blocks=[],
                security_constructs=[
                    {"kind": "authz", "symbol": "LoginService"},
                    {"kind": "validation", "symbol": "PaymentValidator"},
                    {"kind": "sanitize", "symbol": "PaymentValidator"},
                ],
            )

            res = metrics.metric_F2_SRP(repo_dir, graph)

            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["constructs"], 3)
            self.assertEqual(res["uncovered"], 2)
            self.assertAlmostEqual(res["SRP"], 2 / 3, places=6)


class OrchestratorInterruptRegressionTests(unittest.TestCase):
    def test_keyboard_interrupt_cleans_up_container_and_sampler(self) -> None:
        class DummyProc:
            def __init__(self) -> None:
                self.terminated = False
                self.waited = False
                self.killed = False

            def terminate(self) -> None:
                self.terminated = True

            def wait(self, timeout=None) -> None:
                self.waited = True

            def kill(self) -> None:
                self.killed = True

        class DummyThread:
            def __init__(self) -> None:
                self.joined = False

            def join(self, timeout=None) -> None:
                self.joined = True

        proc = DummyProc()
        thread = DummyThread()
        out_dir = f"out/test-interrupt-{os.getpid()}"
        args = argparse.Namespace(
            repo_url="https://example.com/repo.git",
            ref="",
            mode="fast",
            build_image=False,
            image_tag="csqa-metrics:test",
            out_dir=out_dir,
            render_html=False,
            deps_max_modules=1,
            cpu="",
            memory="",
            m2_cache_dir="",
            timeout=0,
        )

        calls: list[list[str]] = []

        def fake_run_cmd(cmd, *, cwd=None, env=None, timeout=None):
            calls.append(cmd)
            if cmd[:2] == ["docker", "run"]:
                return orchestrate.CmdResult(0, "container-123\n", "", 0.01)
            if cmd[:2] == ["docker", "wait"]:
                raise KeyboardInterrupt
            if cmd[:2] == ["docker", "stop"]:
                return orchestrate.CmdResult(0, "", "", 0.01)
            if cmd[:2] == ["docker", "logs"]:
                return orchestrate.CmdResult(0, "logline\n", "", 0.01)
            if cmd[:2] == ["docker", "rm"]:
                return orchestrate.CmdResult(0, "", "", 0.01)
            return orchestrate.CmdResult(0, "", "", 0.01)

        with (
            mock.patch.object(orchestrate.argparse.ArgumentParser, "parse_args", return_value=args),
            mock.patch.object(orchestrate, "run_cmd", side_effect=fake_run_cmd),
            mock.patch.object(orchestrate, "start_docker_stats_sampler", return_value=(proc, thread)),
        ):
            rc = orchestrate.main()

        self.assertEqual(rc, 130)
        self.assertTrue(proc.terminated)
        self.assertTrue(proc.waited)
        self.assertTrue(thread.joined)
        self.assertTrue(any(cmd[:2] == ["docker", "stop"] for cmd in calls))
        self.assertTrue(any(cmd[:2] == ["docker", "logs"] for cmd in calls))
        self.assertTrue(any(cmd[:2] == ["docker", "rm"] for cmd in calls))

        shutil.rmtree(REPO_ROOT / out_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
