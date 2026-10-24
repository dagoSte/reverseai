"""tests/mcp_client.py against a tiny fake stdio server written by the test; no ReverseAI server is needed."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

from tests import mcp_client

# The fake server echoes each request's method and params; "big", "silent", "noisy", "garbage" and "other_id" misbehave
# on purpose. With --hang it ignores end of input. It reads only its own stdin and writes only its own streams.
FAKE_SERVER = r'''
import json, sys, time
for raw in sys.stdin.buffer:
    message = json.loads(raw)
    if "id" not in message:
        sys.stderr.write("notification " + message["method"] + "\n")
        sys.stderr.flush()
        continue
    method = message["method"]
    if method == "silent":
        continue
    if method == "noisy":
        sys.stderr.write("x" * 1024 * 1024)
        sys.stderr.flush()
    if method == "big":
        head = '{"jsonrpc": "2.0", "id": %d, "pad": "' % message["id"]
        sys.stdout.buffer.write(head.encode() + b"x" * int(message["params"]["size"]) + b'"}\n')
    elif method == "garbage":
        sys.stdout.buffer.write(b"not json\n")
    else:
        answer = message["id"] + (100 if method == "other_id" else 0)
        reply = {"jsonrpc": "2.0", "id": answer, "result": {"method": method, "params": message.get("params")}}
        sys.stdout.buffer.write(json.dumps(reply).encode() + b"\n")
    sys.stdout.flush()
if "--hang" in sys.argv:
    time.sleep(60)
'''


class ClientTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.script = Path(folder.name, "fake_server.py")
        self.script.write_text(FAKE_SERVER, encoding="utf-8")

    def client(self, *extra, **options):
        client = mcp_client.Client([sys.executable, "-I", str(self.script), *extra], **options)
        self.addCleanup(lambda: client.process.poll() is not None or client.close(timeout=1))
        return client

    def test_requests_carry_the_modern_meta_and_ids_match_replies(self):
        client = self.client()
        first = client.discover()
        self.assertEqual((first["id"], first["result"]["method"]), (1, "server/discover"))
        self.assertEqual(first["result"]["params"]["_meta"], mcp_client.META)
        self.assertEqual(mcp_client.META["io.modelcontextprotocol/protocolVersion"], "2026-07-28")
        call = client.call_tool("list_files")
        self.assertEqual((call["id"], call["result"]["method"]), (2, "tools/call"))
        self.assertEqual(call["result"]["params"]["name"], "list_files")
        self.assertEqual(call["result"]["params"]["arguments"], {})
        legacy = client.request("initialize", {"protocolVersion": "2025-11-25"}, modern=False)
        self.assertNotIn("_meta", legacy["result"]["params"])
        client.notify("notifications/initialized")
        self.assertEqual(client.request("ping")["id"], 4)  # the notification got no reply and took no id
        self.assertEqual(client.close(), 0)
        self.assertIn("notification notifications/initialized", client.stderr)

    def test_a_missing_reply_times_out_and_a_wrong_reply_is_refused(self):
        client = self.client()
        with self.assertRaisesRegex(mcp_client.ClientError, "no reply"):
            client.request("silent", timeout=0.3)
        with self.assertRaisesRegex(mcp_client.ClientError, "not JSON"):
            client.request("garbage")
        with self.assertRaisesRegex(mcp_client.ClientError, "does not answer"):
            client.request("other_id")
        self.assertEqual(client.close(), 0)

    def test_a_reply_over_the_size_bound_is_refused_without_reading_it_all(self):
        client = self.client(max_line=4096)
        self.assertEqual(len(client.request("big", {"size": 1000})["pad"]), 1000)
        with self.assertRaisesRegex(mcp_client.ClientError, "longer than the client's limit"):
            client.request("big", {"size": 100_000})
        self.assertIsNotNone(client.close(timeout=2))

    def test_stderr_chatter_does_not_block_and_is_kept_bounded(self):
        client = self.client()
        self.assertEqual(client.request("noisy")["result"]["method"], "noisy")
        self.assertEqual(client.close(), 0)
        self.assertEqual(len(client.stderr), mcp_client.MAX_STDERR)

    def test_close_kills_only_its_own_child_when_it_ignores_end_of_input(self):
        client = self.client("--hang")
        self.assertEqual(client.request("ping")["result"]["method"], "ping")
        code = client.close(timeout=0.5)
        self.assertNotEqual(code, 0)
        self.assertIsNotNone(client.process.poll())

    def test_the_reverseai_command_line_is_fixed(self):
        captured = {}

        class Recorder(mcp_client.Client):
            def __init__(self, argv, **options):
                captured.update(argv=argv, options=options)

        Recorder.reverseai(Path("/inputs"), "--with-ghidra", timeout=5)
        self.assertEqual(captured["argv"], [sys.executable, "-B", "-m", "reverseai", "mcp", "--inputs", "/inputs",
                                            "--with-ghidra"])
        self.assertEqual(captured["options"], {"timeout": 5})


if __name__ == "__main__":
    unittest.main()
