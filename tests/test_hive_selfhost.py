import argparse
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from hive import bees, codex_bees, selfhost

ANSWER = {"verdict": "accept", "defects": []}


class ServerUrlTests(unittest.TestCase):
    def test_this_machine_is_accepted(self):
        for url in ("http://127.0.0.1:11434", "http://localhost:1234/", "http://[::1]:8080", "https://127.0.0.2"):
            with self.subTest(url=url):
                self.assertFalse(selfhost.server_url(url).endswith("/"))

    def test_another_machine_needs_the_remote_flag(self):
        with self.assertRaisesRegex(ValueError, "--model-server-remote"):
            selfhost.server_url("http://gpu.lan:8000")
        self.assertEqual(selfhost.server_url("http://gpu.lan:8000/", allow_remote=True), "http://gpu.lan:8000")

    def test_credentials_queries_and_other_schemes_are_refused(self):
        for url in ("http://user:pw@127.0.0.1:11434", "http://127.0.0.1:11434?key=1", "file:///tmp/x", "127.0.0.1:11434",
                    ""):
            with self.subTest(url=url), self.assertRaises(ValueError):
                selfhost.server_url(url)


class EnvironmentTests(unittest.TestCase):
    def test_no_subscription_or_cloud_credential_reaches_the_bee(self):
        base = {"PATH": "/usr/bin", "HOME": "/home/x", "CLAUDE_CODE_OAUTH_TOKEN": "secret-oauth",
                "ANTHROPIC_API_KEY": "secret-key", "ANTHROPIC_AUTH_TOKEN": "secret-token",
                "ANTHROPIC_BASE_URL": "https://api.anthropic.com", "CLAUDE_CODE_USE_BEDROCK": "1",
                "AWS_BEARER_TOKEN_BEDROCK": "secret-aws", "OPENAI_API_KEY": "secret-openai"}
        env = selfhost.claude_environment(base, "http://127.0.0.1:11434", "qwen3.6:35b")
        self.assertFalse([value for value in env.values() if "secret" in value])
        self.assertEqual(env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:11434")
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], selfhost.PLACEHOLDER_TOKEN)
        self.assertEqual(env["ANTHROPIC_API_KEY"], "")
        self.assertEqual(env["ANTHROPIC_DEFAULT_HAIKU_MODEL"], "qwen3.6:35b")
        self.assertNotIn("CLAUDE_CODE_USE_BEDROCK", env)
        self.assertEqual((env["PATH"], env["HOME"]), ("/usr/bin", "/home/x"))

    def test_the_claude_runner_passes_its_environment(self):
        tmp = Path(tempfile.mkdtemp())
        runner = bees.ClaudeBees(engine=tmp, inputs=tmp, config_dir=tmp / "cfg", env={"PATH": "/usr/bin"})
        done = subprocess.CompletedProcess([], 0, json.dumps({"structured_output": ANSWER}), "")
        with mock.patch.object(bees.subprocess, "run", return_value=done) as run:
            self.assertTrue(runner("councillor", "c", "task", tmp)["ok"])
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin"})
        default = bees.ClaudeBees(engine=tmp, inputs=tmp, config_dir=tmp / "cfg")
        with mock.patch.object(bees.subprocess, "run", return_value=done) as run:
            default("councillor", "c", "task", tmp)
        self.assertIsNone(run.call_args.kwargs["env"])  # unchanged default: inherit


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--model")
        codex_bees.add_arguments(self.parser)
        self.kwargs = {"engine": self.tmp, "inputs": self.tmp, "config_dir": self.tmp / "codex"}

    def claude(self):
        return bees.ClaudeBees(engine=self.tmp, inputs=self.tmp, config_dir=self.tmp / "cfg")

    def test_without_a_model_server_nothing_changes(self):
        claude = self.claude()
        self.assertIs(codex_bees.build(self.parser.parse_args([]), claude, **self.kwargs), claude)
        self.assertIsNone(claude.env)
        codex = codex_bees.build(self.parser.parse_args(["--bee-policy", "codex"]), claude, **self.kwargs)
        self.assertIs(type(codex), codex_bees.CodexBees)

    def test_claude_bees_go_to_the_server_with_the_named_model(self):
        claude = self.claude()
        args = self.parser.parse_args(["--model-server", "http://127.0.0.1:11434", "--model", "qwen3.6:35b"])
        self.assertIs(codex_bees.build(args, claude, **self.kwargs), claude)
        self.assertEqual(claude.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:11434")
        self.assertIn("qwen3.6:35b", claude.argv("councillor", "c"))

    def test_codex_bees_use_a_selfhost_provider_and_keep_their_sandbox(self):
        args = self.parser.parse_args(["--bee-policy", "codex", "--model-server", "http://127.0.0.1:11434",
                                       "--codex-model", "gpt-oss:20b"])
        codex = codex_bees.build(args, self.claude(), **self.kwargs)
        self.assertIsInstance(codex, selfhost.SelfHostedCodexBees)
        argv = codex.argv("worker", "w", self.tmp)
        self.assertIn('model_provider="selfhost"', argv)
        provider = next(item for item in argv if item.startswith("model_providers.selfhost="))
        self.assertIn('base_url="http://127.0.0.1:11434/v1"', provider)
        self.assertIn('wire_api="responses"', provider)
        self.assertEqual(argv[argv.index("-m") + 1], "gpt-oss:20b")
        self.assertIn("sandbox_workspace_write.network_access=false", argv)
        self.assertEqual(argv[-1], "-")
        self.assertFalse(codex.allow_network)  # the network probe still decides

    def test_missing_model_names_and_remote_servers_stop_the_command(self):
        for argv, text in ((["--model-server", "http://127.0.0.1:11434"], "--model"),
                           (["--bee-policy", "codex", "--model-server", "http://127.0.0.1:1"], "--codex-model"),
                           (["--model-server", "http://gpu.lan:8000", "--model", "m"], "--model-server-remote"),
                           (["--model-server-remote"], "needs --model-server")):
            with self.subTest(argv=argv), self.assertRaisesRegex(SystemExit, text):
                codex_bees.build(self.parser.parse_args(argv), self.claude(), **self.kwargs)


class FakeAnthropic(http.server.BaseHTTPRequestHandler):
    """A model server that answers every bee with ANSWER through the CLI's structured-output tool."""

    seen = []

    def log_message(self, *args):
        pass

    def reply(self, status, payload, content_type="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        type(self).seen.append({"method": "GET", "path": self.path})
        self.reply(404, {"type": "error", "error": {"type": "not_found_error", "message": "not here"}})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        type(self).seen.append({"method": "POST", "path": self.path, "authorization": self.headers.get("authorization"),
                                "x-api-key": self.headers.get("x-api-key"), "model": body.get("model")})
        if "count_tokens" in self.path:
            return self.reply(200, {"input_tokens": 100})
        tools = [tool.get("name", "") for tool in body.get("tools", [])]
        structured = next((name for name in tools if "StructuredOutput" in name), None)
        answered = any(isinstance(m.get("content"), list) and any(c.get("type") == "tool_result" for c in m["content"])
                       for m in body.get("messages", []))
        if structured and not answered:
            blocks, stop = [{"type": "tool_use", "id": "toolu_selfhost", "name": structured, "input": ANSWER}], "tool_use"
        else:
            blocks, stop = [{"type": "text", "text": "Done."}], "end_turn"
        message = {"id": "msg_selfhost", "type": "message", "role": "assistant", "model": body.get("model"),
                   "content": blocks, "stop_reason": stop, "stop_sequence": None,
                   "usage": {"input_tokens": 10, "output_tokens": 10}}
        if not body.get("stream"):
            return self.reply(200, message)
        events = [("message_start", {"type": "message_start", "message": dict(message, content=[], stop_reason=None)})]
        for index, block in enumerate(blocks):
            start = dict(block, input={}) if block["type"] == "tool_use" else dict(block, text="")
            delta = ({"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
                     if block["type"] == "tool_use" else {"type": "text_delta", "text": block["text"]})
            events += [("content_block_start", {"type": "content_block_start", "index": index, "content_block": start}),
                       ("content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}),
                       ("content_block_stop", {"type": "content_block_stop", "index": index})]
        events += [("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                      "usage": {"output_tokens": 10}}),
                   ("message_stop", {"type": "message_stop"})]
        self.reply(200, "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode(),
                   "text/event-stream")


@unittest.skipUnless(os.environ.get("HIVE_SELFHOST_LIVE") == "1" and shutil.which("claude"),
                     "live check: set HIVE_SELFHOST_LIVE=1 with Claude Code installed")
class LiveClaudeTests(unittest.TestCase):
    def test_a_real_claude_bee_answers_through_a_self_hosted_server(self):
        FakeAnthropic.seen = []
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeAnthropic)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        tmp = Path(tempfile.mkdtemp())
        url = f"http://127.0.0.1:{server.server_address[1]}"
        root = Path(__file__).resolve().parents[1]
        runner = bees.ClaudeBees(engine=root, inputs=tmp, config_dir=tmp / "cfg", model="local-test-model",
                                 env=selfhost.claude_environment(os.environ, url, "local-test-model"), timeout=300)
        answer = runner("councillor", "c", "Reply with the verdict accept and no defects.", tmp)
        self.assertTrue(answer["ok"], answer)
        self.assertEqual(answer["output"], ANSWER)
        posts = [request for request in FakeAnthropic.seen if request["method"] == "POST"]
        self.assertTrue(posts)
        for request in posts:  # never print a header value: a leak would put a real token in the test log
            placeholder = request["authorization"] in (None, f"Bearer {selfhost.PLACEHOLDER_TOKEN}")
            self.assertTrue(placeholder and request["x-api-key"] in (None, "", selfhost.PLACEHOLDER_TOKEN),
                            "a credential other than the placeholder reached the model server")
        self.assertEqual({request["model"] for request in posts if request["model"]}, {"local-test-model"})


if __name__ == "__main__":
    unittest.main()
