import argparse
import copy
import json
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from hive import bees
from hive.codex_bees import CodexBees, MixedBees, add_arguments, build, drop_nulls, strict_schema


ANSWERS = {
    "planner": {"modules": [{"id": "one", "title": "entry", "functions": ["0x1000"], "rationale": None}],
                "skipped": [], "notes": None},
    "worker": {"status": "done", "functions": [{"entry": "0x1000", "name": None,
                                               "status": "rebuilt", "notes": None}],
               "contract_requests": None, "unknowns": None},
    "repair": {"status": "done", "functions": [], "contract_requests": [], "unknowns": []},
    "councillor": {"verdict": "accept", "defects": [], "summary": None},
    "tester": {"cases": [{"id": "stdin", "files": [{"name": "input", "text": "abc", "base64": None}],
                          "steps": [{"args": [], "stdin": None}], "why": None}]},
}


def overrides(argv):
    return tomllib.loads("\n".join(argv[index + 1] for index, arg in enumerate(argv) if arg == "-c"))


class SchemaTests(unittest.TestCase):
    def test_all_role_schemas_are_strict_recursively_without_mutating_claude(self):
        original = copy.deepcopy(bees.SCHEMAS)

        def check(schema):
            if isinstance(schema, list):
                for item in schema:
                    check(item)
            elif isinstance(schema, dict):
                if schema.get("type") == "object":
                    self.assertEqual(schema["required"], list(schema["properties"]))
                    self.assertIs(schema["additionalProperties"], False)
                for item in schema.values():
                    check(item)

        for role in ("planner", "worker", "repair", "councillor", "tester"):
            check(strict_schema(bees.SCHEMAS[role]))
        self.assertEqual(bees.SCHEMAS, original)
        schema = strict_schema(bees.SCHEMAS["worker"])
        self.assertEqual(schema["required"], ["status", "functions", "contract_requests", "unknowns"])
        self.assertEqual(schema["properties"]["status"]["enum"], ["done", "partial", "blocked"])
        self.assertEqual(schema["properties"]["unknowns"]["anyOf"][1], {"type": "null"})

    def test_optional_enum_and_nested_objects_are_nullable(self):
        schema = strict_schema({"type": "object", "properties": {
            "mode": {"type": "string", "enum": ["a", "b"]},
            "child": {"type": "object", "properties": {"text": {"type": "string"}}}}})
        self.assertEqual(schema["properties"]["mode"], {
            "anyOf": [{"type": "string", "enum": ["a", "b"]}, {"type": "null"}]})
        child = schema["properties"]["child"]["anyOf"][0]
        self.assertEqual(child["required"], ["text"])
        self.assertIs(child["additionalProperties"], False)

    def test_null_removal_preserves_false_empty_values_and_array_positions(self):
        value = {"optional": None, "nested": [{"drop": None, "keep": ""}, None],
                 "false": False, "zero": 0, "empty": []}
        self.assertEqual(drop_nulls(value), {"nested": [{"keep": ""}, None],
                                            "false": False, "zero": 0, "empty": []})
        self.assertIn("optional", value)


class CodexRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.folder = self.root / "bee"
        self.folder.mkdir()
        self.runner = CodexBees(engine=self.root / 'engine "quoted"', inputs=self.root / "inputs with spaces",
                                python='/python "quoted"', config_dir=self.root / "config", timeout=7)

    def run_bee(self, role="worker", *, answer=None, returncode=0, stderr="", write=True):
        def run(argv, **kwargs):
            if write:
                Path(argv[argv.index("-o") + 1]).write_text(json.dumps(ANSWERS[role] if answer is None else answer))
            return subprocess.CompletedProcess(argv, returncode, stdout="not the final answer", stderr=stderr)

        with patch("hive.codex_bees.subprocess.run", side_effect=run) as process:
            result = self.runner(role, "bee-1", "TASK", self.folder)
        return result, process.call_args

    def test_argv_locks_sandbox_approvals_network_and_the_single_mcp_server(self):
        for role in ("planner", "worker", "repair", "councillor", "tester"):
            with self.subTest(role=role):
                result, call = self.run_bee(role)
                self.assertTrue(result["ok"], result)
                argv, kwargs = call.args[0], call.kwargs
                self.assertEqual(argv[:2], ["codex", "exec"])
                for flag in ("--ignore-user-config", "--skip-git-repo-check", "--ephemeral"):
                    self.assertIn(flag, argv)
                self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", argv)
                self.assertNotIn("--approve-for-me", argv)
                self.assertNotIn("--add-dir", argv)
                self.assertNotIn("-m", argv)
                self.assertEqual(argv[-1], "-")
                self.assertEqual(argv[argv.index("-C") + 1], str(self.folder.resolve()))
                self.assertEqual(argv[argv.index("--sandbox") + 1],
                                 "read-only" if role == "councillor" else "workspace-write")
                config = overrides(argv)
                self.assertEqual(config["approval_policy"], "never")
                self.assertIs(config["sandbox_workspace_write"]["network_access"], False)
                self.assertEqual(config["sandbox_workspace_write"]["writable_roots"], [])
                self.assertIs(config["sandbox_workspace_write"]["exclude_tmpdir_env_var"], True)
                self.assertIs(config["sandbox_workspace_write"]["exclude_slash_tmp"], True)
                self.assertEqual(config["web_search"], "disabled")
                self.assertEqual(set(config["mcp_servers"]), {"reverseai"})
                server = config["mcp_servers"]["reverseai"]
                self.assertEqual(server["command"], '/python "quoted"')
                self.assertEqual(server["args"], ["-B", "-m", "reverseai", "mcp", "--inputs",
                                                   str((self.root / "inputs with spaces").resolve()), "--with-ghidra"])
                self.assertEqual(server["env"], {"PYTHONPATH": str((self.root / 'engine "quoted"').resolve()),
                                                  "PYTHONDONTWRITEBYTECODE": "1"})
                schema_path = Path(argv[argv.index("--output-schema") + 1])
                self.assertFalse(schema_path.is_relative_to(self.folder))
                self.assertIs(json.loads(schema_path.read_text())["additionalProperties"], False)
                self.assertEqual(kwargs["input"], bees.brief(role, "TASK"))
                self.assertEqual(kwargs["cwd"], self.folder)
                self.assertEqual(kwargs["timeout"], 7)
                self.assertTrue(kwargs["capture_output"])
                self.assertTrue(kwargs["text"])
                self.assertFalse(kwargs["check"])

    def test_model_effort_and_enabled_tools_are_explicit(self):
        self.runner.model, self.runner.effort = "chosen-model", "high"
        self.runner.enabled = ("ghidra", "yara")
        result, call = self.run_bee()
        self.assertTrue(result["ok"])
        argv = call.args[0]
        self.assertEqual(argv[argv.index("-m") + 1], "chosen-model")
        config = overrides(argv)
        self.assertEqual(config["model_reasoning_effort"], "high")
        self.assertEqual(config["mcp_servers"]["reverseai"]["args"][-2:], ["--with-ghidra", "--with-yara"])

    def test_final_file_is_parsed_and_optional_nulls_removed_for_the_queen(self):
        result, _ = self.run_bee()
        self.assertEqual(result["output"], {"status": "done", "functions": [{"entry": "0x1000", "status": "rebuilt"}]})
        self.assertIn("seconds", result)
        result, _ = self.run_bee("tester")
        self.assertEqual(result["output"]["cases"][0], {
            "id": "stdin", "files": [{"name": "input", "text": "abc"}], "steps": [{"args": []}]})

    def test_nonzero_exit_cannot_accept_a_valid_answer(self):
        result, _ = self.run_bee(returncode=3, stderr="native refusal")
        self.assertFalse(result["ok"])
        self.assertIn("exit 3: native refusal", result["error"])

    def test_missing_file_cannot_reuse_a_previous_success(self):
        self.assertTrue(self.run_bee()[0]["ok"])
        result, _ = self.run_bee(write=False)
        self.assertFalse(result["ok"])
        self.assertIsNone(result["output"])

    def test_malformed_json_and_invalid_output_fail_closed(self):
        bad = [[], "text", 3, None, {}, {**ANSWERS["worker"], "extra": True},
               {**ANSWERS["worker"], "status": "accepted"},
               {**ANSWERS["worker"], "functions": [None]},
               {**ANSWERS["worker"], "functions": [{"entry": 123, "name": None,
                                                     "status": "rebuilt", "notes": None}]},
               {"status": "done", "functions": []}]
        for value in bad:
            with self.subTest(value=value):
                def run(argv, **kwargs):
                    Path(argv[argv.index("-o") + 1]).write_text(json.dumps(value))
                    return subprocess.CompletedProcess(argv, 0, "", "")
                with patch("hive.codex_bees.subprocess.run", side_effect=run):
                    self.assertFalse(self.runner("worker", "bad", "TASK", self.folder)["ok"])
        def malformed(argv, **kwargs):
            Path(argv[argv.index("-o") + 1]).write_text("{broken")
            return subprocess.CompletedProcess(argv, 0, "", "")
        with patch("hive.codex_bees.subprocess.run", side_effect=malformed):
            self.assertFalse(self.runner("worker", "bad", "TASK", self.folder)["ok"])

    def test_timeout_startup_io_and_invalid_role_fail_without_raising(self):
        for error in (subprocess.TimeoutExpired("codex", 7), FileNotFoundError("missing codex"),
                      OSError("native failure")):
            with self.subTest(error=error), patch("hive.codex_bees.subprocess.run", side_effect=error):
                result = self.runner("worker", "failure", "TASK", self.folder)
                self.assertFalse(result["ok"])
                self.assertTrue(result["error"])
                if isinstance(error, subprocess.TimeoutExpired):
                    self.assertEqual(result["seconds"], 7)
        self.assertFalse(self.runner("unknown", "failure", "TASK", self.folder)["ok"])
        with patch("hive.codex_bees.subprocess.run") as process:
            self.assertFalse(self.runner("worker", "../escape", "TASK", self.folder)["ok"])
            process.assert_not_called()
        self.runner.config_dir = self.folder / "not-a-directory"
        self.runner.config_dir.write_text("occupied")
        self.assertFalse(self.runner("worker", "failure", "TASK", self.folder)["ok"])

    def test_each_bee_has_separate_output_and_schema_paths(self):
        first = self.runner.argv("worker", "m01-build", self.folder)
        second = self.runner.argv("councillor", "m01-council-r1-io", self.folder)
        for flag in ("--output-schema", "-o"):
            self.assertNotEqual(first[first.index(flag) + 1], second[second.index(flag) + 1])


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.claude = Mock(return_value={"ok": True, "output": {"runner": "claude"}})
        self.codex = Mock(return_value={"ok": True, "output": {"runner": "codex"}})

    def test_mixed_routing_covers_the_queens_names_and_all_repair_rounds(self):
        runner = MixedBees(self.claude, self.codex)
        routes = [("planner", "planner", "claude"), ("planner", "planner-fix2", "claude"),
                  ("tester", "tester", "claude"), ("repair", "behaviour-fix-2", "claude"),
                  ("worker", "m01-build", "claude"), ("worker", "m02-build", "codex"),
                  ("worker", "m03-build", "claude"), ("worker", "m100-build", "codex"),
                  ("repair", "m01-repair-b1", "claude"), ("repair", "m02-repair-b3", "codex"),
                  ("repair", "m01-repair-c2", "claude"), ("repair", "m02-repair-c2", "codex"),
                  ("repair", "m01-repair-l2", "claude"), ("repair", "m02-repair-l3", "codex"),
                  ("councillor", "m01-council-r1-control", "codex"),
                  ("councillor", "m01-council-r1-io", "codex"),
                  ("councillor", "m01-council-r1-data", "claude"),
                  ("councillor", "m02-council-r2-control", "claude"),
                  ("councillor", "m02-council-r2-io", "claude"),
                  ("councillor", "m02-council-r2-data", "codex")]
        for role, name, expected in routes:
            with self.subTest(name=name):
                self.claude.reset_mock()
                self.codex.reset_mock()
                result = runner(role, name, "TASK", Path("bee"))
                selected, other = ((self.claude, self.codex) if expected == "claude" else (self.codex, self.claude))
                selected.assert_called_once_with(role, name, "TASK", Path("bee"))
                other.assert_not_called()
                self.assertIs(result, selected.return_value)

    def test_single_model_policies_route_every_role_to_that_model(self):
        for policy, selected, other in (("claude", self.claude, self.codex), ("codex", self.codex, self.claude)):
            runner = MixedBees(self.claude, self.codex, policy)
            for role in ("planner", "worker", "repair", "councillor", "tester"):
                selected.reset_mock()
                other.reset_mock()
                self.assertIs(runner(role, "any-name", "TASK", "bee"), selected.return_value)
                selected.assert_called_once_with(role, "any-name", "TASK", "bee")
                other.assert_not_called()

    def test_unknown_policy_and_ambiguous_module_names_are_rejected(self):
        with self.assertRaises(ValueError):
            MixedBees(self.claude, self.codex, "other")
        runner = MixedBees(self.claude, self.codex)
        for role, name in (("worker", "unknown"), ("worker", "m00-build"),
                           ("councillor", "m01-council-r1-unknown"), ("repair", "m02-repair-x1"), ("unknown", "")):
            self.assertFalse(runner(role, name, "TASK", "bee")["ok"])
        self.claude.assert_not_called()
        self.codex.assert_not_called()

    def test_cli_factory_preserves_claude_default_and_separates_codex_settings(self):
        parser = argparse.ArgumentParser()
        add_arguments(parser)
        self.assertIs(build(parser.parse_args([]), self.claude), self.claude)
        settings = {"engine": ".", "inputs": ".", "config_dir": ".", "timeout": 123}
        args = parser.parse_args(["--bee-policy", "mixed", "--codex", "/bin/codex-test",
                                  "--codex-model", "chosen-model", "--codex-effort", "high"])
        runner = build(args, self.claude, **settings)
        self.assertIsInstance(runner, MixedBees)
        self.assertIs(runner.claude, self.claude)
        self.assertEqual(runner.codex.codex, "/bin/codex-test")
        self.assertEqual(runner.codex.model, "chosen-model")
        self.assertEqual(runner.codex.effort, "high")
        self.assertEqual(runner.codex.timeout, 123)
        self.assertIsInstance(build(parser.parse_args(["--bee-policy", "codex"]), self.claude, **settings), CodexBees)


if __name__ == "__main__":
    unittest.main()
