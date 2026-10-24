"""MCP lifecycle, bounded framing and isolated calls with a small catalog stand-in."""

import contextlib
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import reverseai
from reverseai import cli, intake, mcp, pipeline
from reverseai.contract import canonical_json


def request(method, params=None, *, identifier=1, modern=True):
    params = dict(params or {})
    if modern:
        params["_meta"] = {mcp.VERSION_KEY: mcp.SUPPORTED[0], mcp.CAPABILITIES_KEY: {}}
    return {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}


def catalog_standin():
    module = types.ModuleType("reverseai.mcp_tools")
    module.UnknownTool = type("UnknownTool", (Exception,), {})
    module.ToolInputError = type("ToolInputError", (Exception,), {})
    module.calls = []
    module.catalog = lambda enabled: [{"name": name, "inputSchema": {"type": "object"}}
                                      for name in ("list_files", "analyze_file", "read_bytes")]
    module.list_files = lambda root: {"files": [{"name": "sample.bin", "size": 8}], "truncated": False}

    def command(name, args, *, root, out, enabled):
        if name not in ("analyze_file", "read_bytes"):
            raise module.UnknownTool()
        if not isinstance(args, dict) or set(args) != {"file"} or args["file"] != "sample.bin":
            raise module.ToolInputError("Choose sample.bin from list_files.")
        module.calls.append((name, args, root, out, enabled))
        if name == "analyze_file":
            return ["analyze", str(Path(root, args["file"])), "--out", out]
        return ["query", str(Path(root, args["file"])), "--query", "read_bytes",
                "--arg", "length=4", "--out", out]

    module.command = command
    return module


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tools = catalog_standin()
        self.modules = patch.dict(sys.modules, {"reverseai.mcp_tools": self.tools})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def serve(self, *messages, root="/operator-inputs", enabled=frozenset(), raw=None, stdin=None):
        if raw is None:
            raw = b"".join(canonical_json(message).encode() + b"\n" for message in messages)
        stdin = stdin if stdin is not None else io.BytesIO(raw)
        stdout, stderr = io.BytesIO(), io.StringIO()
        code = mcp.serve(stdin, stdout, stderr, root=root, enabled=enabled)
        replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
        return code, replies, stdout.getvalue(), stderr.getvalue()

    def test_modern_discovery_tools_ping_and_metadata_are_per_request(self):
        messages = (request("server/discover", identifier="discover"), request("tools/list", identifier=7),
                    request("ping", identifier=-1), request("ping", identifier=0, modern=False))
        code, replies, _, errors = self.serve(*messages)
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual([r["id"] for r in replies], ["discover", 7, -1, 0])
        discover = replies[0]["result"]
        self.assertEqual(discover["supportedVersions"], list(mcp.SUPPORTED))
        self.assertEqual(discover["capabilities"], {"tools": {}})
        self.assertIn("untrusted", discover["instructions"])
        self.assertEqual([tool["name"] for tool in replies[1]["result"]["tools"]],
                         ["list_files", "analyze_file", "read_bytes"])
        self.assertNotIn("nextCursor", replies[1]["result"])
        for reply in replies[:3]:
            self.assertEqual(reply["result"]["resultType"], "complete")
            self.assertEqual(reply["result"]["_meta"][mcp.INFO_KEY],
                             {"name": "reverseai", "version": reverseai.__version__})
        self.assertEqual(replies[3]["error"]["code"], -32602)

    def test_every_legacy_revision_and_fallback_select_handshake_semantics(self):
        for version in (*mcp.SUPPORTED, "1900-01-01"):
            with self.subTest(version=version):
                init = request("initialize", {"protocolVersion": version, "capabilities": {},
                                               "clientInfo": {"name": "test", "version": "1"}}, modern=False)
                notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                code, replies, _, _ = self.serve(init, notification, request("ping", modern=False),
                                               request("tools/list", modern=False), request("ping"))
                self.assertEqual(code, 0)
                self.assertEqual(len(replies), 4)
                selected = version if version in mcp.SUPPORTED[1:] else "2025-11-25"
                self.assertEqual(replies[0]["result"]["protocolVersion"], selected)
                self.assertEqual(replies[0]["result"]["capabilities"], {"tools": {"listChanged": False}})
                self.assertEqual(replies[0]["result"]["serverInfo"]["title"], "ReverseAI")
                self.assertEqual(replies[1]["result"], {})
                self.assertIn("tools", replies[2]["result"])
                for reply in replies[:3]:
                    self.assertNotIn("resultType", reply["result"])
                self.assertEqual(replies[3]["result"]["resultType"], "complete")

    def test_legacy_progress_metadata_is_not_mistaken_for_modern_metadata(self):
        init = request("initialize", {"protocolVersion": "2025-06-18"}, modern=False)
        ping = request("ping", {"_meta": {"progressToken": "p"}}, modern=False)
        discover = request("server/discover", modern=False)
        _, replies, _, _ = self.serve(init, ping, discover)
        self.assertEqual(replies[1]["result"], {})
        self.assertEqual(replies[2]["error"]["code"], -32602)

    def test_legacy_state_does_not_fill_in_partial_modern_metadata(self):
        init = request("initialize", {"protocolVersion": "2025-06-18"}, modern=False)
        for partial in ({mcp.VERSION_KEY: "2026-07-28"}, {mcp.CAPABILITIES_KEY: {}},
                        {"io.modelcontextprotocol/clientInfo": {"name": "client"}}):
            with self.subTest(partial=partial):
                ping = request("ping", {"_meta": partial}, modern=False)
                _, replies, _, _ = self.serve(init, ping, request("ping", modern=False))
                self.assertEqual(replies[1]["error"]["code"], -32602)
                self.assertEqual(replies[2]["result"], {})

    def test_unsupported_version_returns_the_defined_code_and_selection_data(self):
        future = request("ping", identifier="future")
        future["params"]["_meta"][mcp.VERSION_KEY] = "2099-01-01"
        _, replies, _, _ = self.serve(future, request("ping"))
        self.assertEqual(replies[0], {"jsonrpc": "2.0", "id": "future", "error": {
            "code": -32022, "message": "Unsupported protocol version",
            "data": {"requested": "2099-01-01", "supported": list(mcp.SUPPORTED)}}})
        self.assertIn("result", replies[1])

    def test_missing_partial_and_wrongly_typed_metadata_never_run_a_tool(self):
        bad = ({}, {"_meta": []}, {"_meta": {mcp.VERSION_KEY: "2026-07-28"}},
               {"_meta": {mcp.CAPABILITIES_KEY: {}}},
               {"_meta": {mcp.VERSION_KEY: 2026, mcp.CAPABILITIES_KEY: {}}},
               {"_meta": {mcp.VERSION_KEY: "2026-07-28", mcp.CAPABILITIES_KEY: []}})
        with patch.object(cli, "main") as run:
            for params in bad:
                _, replies, _, _ = self.serve(request("tools/call", params, modern=False))
                self.assertEqual(replies[0]["error"]["code"], -32602)
            run.assert_not_called()

    def test_notifications_are_silent_and_cannot_initialize_a_session(self):
        notes = [{"jsonrpc": "2.0", "method": method, "params": {"protocolVersion": "2025-06-18"}}
                 for method in ("notifications/initialized", "notifications/cancelled", "initialize", "tools/call", "unknown")]
        _, replies, _, _ = self.serve(*notes, request("ping", modern=False))
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0]["error"]["code"], -32602)
        self.assertEqual(self.tools.calls, [])

    def test_parse_failures_are_bounded_errors_and_do_not_poison_the_next_request(self):
        bad = (b"{broken", b"\xff", b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
               b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}')
        ping = canonical_json(request("ping", identifier="still-alive")).encode() + b"\n"
        for raw in bad:
            with self.subTest(raw=raw[:50]):
                code, replies, _, _ = self.serve(raw=raw + b"\n" + ping)
                self.assertEqual(code, 0)
                self.assertEqual(replies[0]["id"], None)
                self.assertEqual(replies[0]["error"]["code"], -32700)
                self.assertEqual(replies[1]["id"], "still-alive")

    def test_deep_batch_is_refused_without_relying_on_the_python_decoder_depth_limit(self):
        raw = b"[" * 1500 + b"0" + b"]" * 1500 + b"\n"
        raw += canonical_json(request("ping")).encode() + b"\n"
        _, replies, _, _ = self.serve(raw=raw)
        # Python releases differ in whether parsing reaches the batch validation.
        self.assertIn(replies[0]["error"]["code"], (-32700, -32600))
        self.assertIn("result", replies[1])

    def test_batches_scalars_invalid_envelopes_and_invalid_ids_are_refused(self):
        for bad in ([], [request("ping")], None, 4, "text", {}, {"jsonrpc": "1.0", "method": "ping"},
                    {"jsonrpc": "2.0", "id": 1, "result": {}},
                    *(request("ping", identifier=value) for value in (None, True, 1.5))):
            with self.subTest(bad=bad):
                _, replies, _, _ = self.serve(bad)
                self.assertEqual(replies[0]["error"]["code"], -32600)

    def test_invalid_params_unknown_method_and_unknown_tool_use_protocol_errors(self):
        cases = [(request("missing/method"), -32601),
                 (request("tools/list", {"cursor": "page-2"}), -32602),
                 (request("tools/call", {"name": "not-a-tool"}), -32602),
                 (request("tools/call", {"name": 4}), -32602),
                 (request("initialize", modern=False), -32602)]
        malformed = request("ping"); malformed["params"] = []
        cases.append((malformed, -32602))
        for message, code in cases:
            with self.subTest(message=message):
                _, replies, _, _ = self.serve(message)
                self.assertEqual(replies[0]["error"]["code"], code)
        _, replies, _, _ = self.serve(request("tools/call", {"name": "not-a-tool"}))
        self.assertEqual(replies[0]["error"]["message"], "Unknown tool: not-a-tool")

    def test_overlong_lines_are_drained_with_bounded_reads_before_resuming(self):
        class Observed(io.BytesIO):
            sizes = []
            def readline(self, size=-1):
                self.sizes.append(size)
                return super().readline(size)
        good = canonical_json(request("ping")).encode() + b"\n"
        stream = Observed(b"x" * (mcp.MAX_LINE_BYTES * 3 + 17) + b"\n" + good)
        _, replies, _, _ = self.serve(stdin=stream)
        self.assertEqual(len(replies), 2)
        self.assertEqual(replies[0]["error"]["code"], -32700)
        self.assertIn("result", replies[1])
        self.assertEqual(max(stream.sizes), 1024 * 1024 + 1)
        self.assertNotIn(-1, stream.sizes)
        _, replies, _, _ = self.serve(raw=b"x" * (mcp.MAX_LINE_BYTES + 1))
        self.assertEqual(len(replies), 1)

    def test_line_limit_counts_the_lf_and_accepts_the_exact_byte_boundary(self):
        message = request("ping")
        message["params"]["padding"] = ""
        raw = canonical_json(message).encode() + b"\n"
        message["params"]["padding"] = "x" * (mcp.MAX_LINE_BYTES - len(raw))
        raw = canonical_json(message).encode() + b"\n"
        self.assertEqual(len(raw), mcp.MAX_LINE_BYTES)
        _, replies, _, _ = self.serve(raw=raw)
        self.assertIn("result", replies[0])
        _, replies, _, _ = self.serve(raw=raw[:-1] + b" \n")
        self.assertEqual(replies[0]["error"]["code"], -32700)

    def test_escaped_surrogates_never_break_the_utf8_protocol_stream(self):
        strange = request("ping", identifier="\ud800")
        future = request("ping")
        future["params"]["_meta"][mcp.VERSION_KEY] = "\udfff"
        raw = b"".join(json.dumps(value, ensure_ascii=True).encode() + b"\n"
                       for value in (strange, future, request("ping", identifier="after")))
        code, replies, wire, _ = self.serve(raw=raw)
        self.assertEqual(code, 0)
        wire.decode("utf-8")
        self.assertEqual(replies[0]["id"], "\ud800")
        self.assertEqual(replies[1]["error"]["code"], -32022)
        self.assertEqual(replies[2]["id"], "after")

    def test_eof_final_line_without_lf_empty_input_and_crlf_are_supported(self):
        self.assertEqual(self.serve(raw=b"")[:2], (0, []))
        for end in (b"", b"\r\n"):
            _, replies, _, _ = self.serve(raw=canonical_json(request("ping")).encode() + end)
            self.assertEqual(len(replies), 1)
            self.assertIn("result", replies[0])

    def test_list_files_is_a_tool_result_and_has_no_model_or_cli_call(self):
        with patch.object(cli, "main") as run:
            _, replies, _, _ = self.serve(request("tools/call", {"name": "list_files"}))
            result = replies[0]["result"]
            self.assertEqual(result["structuredContent"], self.tools.list_files(None))
            self.assertFalse(result["isError"])
            self.assertTrue(result["content"][0]["text"].startswith(mcp.NOTICE))
            run.assert_not_called()
        for args in ({"path": "/outside"}, [], None):
            _, replies, _, _ = self.serve(request("tools/call", {"name": "list_files", "arguments": args}))
            self.assertTrue(replies[0]["result"]["isError"])

    def test_listing_names_are_inert_in_markdown_and_preserved_in_the_structured_result(self):
        name = "<img src=x>`[link]"
        listing = {"files": [{"name": name, "size": 4}], "truncated": True}
        with patch.object(self.tools, "list_files", return_value=listing):
            _, replies, _, _ = self.serve(request("tools/call", {"name": "list_files"}))
        result = replies[0]["result"]
        self.assertEqual(result["structuredContent"]["files"][0]["name"], name)
        text = result["content"][0]["text"]
        self.assertIn("`<img src=x>'[link]`", text)
        self.assertIn("[File listing truncated.]", text)

    def test_invalid_tool_arguments_are_tool_errors_and_leave_no_temporary_output(self):
        with patch.object(cli, "main") as run:
            _, replies, raw, _ = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "../x"}}))
            self.assertEqual(replies[0]["result"]["isError"], True)
            self.assertIn("Choose sample.bin", replies[0]["result"]["content"][0]["text"])
            self.assertNotIn(b"Traceback", raw)
            run.assert_not_called()

    def test_listing_refusals_are_fixed_tool_errors_and_unknown_catalog_races_are_protocol_errors(self):
        for error, field in ((self.tools.ToolInputError("File listing unavailable. Choose a readable input directory."), "result"),
                             (RuntimeError("/private/secret"), "result")):
            with patch.object(self.tools, "list_files", side_effect=error):
                _, replies, raw, errors = self.serve(request("tools/call", {"name": "list_files"}))
                self.assertTrue(replies[0][field]["isError"])
                self.assertNotIn(b"/private/secret", raw)
                self.assertNotIn("/private/secret", errors)
        folders = []
        def refuse(name, args, **kwargs):
            folders.append(Path(kwargs["out"]).parent)
            raise self.tools.UnknownTool()
        with patch.object(self.tools, "command", side_effect=refuse):
            _, replies, _, _ = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "sample.bin"}}))
        self.assertEqual(replies[0]["error"]["code"], -32602)
        self.assertTrue(folders)
        self.assertTrue(all(not path.exists() for path in folders))

    def test_validation_failure_removes_the_temporary_directory_before_returning(self):
        folders = []
        def refuse(name, args, **kwargs):
            folders.append(Path(kwargs["out"]).parent)
            self.assertTrue(folders[-1].is_dir())
            raise self.tools.ToolInputError("Choose a listed relative file.")
        with patch.object(self.tools, "command", side_effect=refuse):
            _, replies, _, _ = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "sample.bin"}}))
        self.assertTrue(replies[0]["result"]["isError"])
        self.assertTrue(all(not path.exists() for path in folders))

    def test_real_cli_byte_query_preserves_the_report_and_cleans_the_private_directory(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "sample.bin").write_bytes(b"abcdefgh")
            _, replies, raw, errors = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "sample.bin"}}),
                                               root=root, enabled=frozenset({"ghidra"}))
            self.assertEqual(errors, "")
            result = replies[0]["result"]
            self.assertFalse(result["isError"])
            report = result["structuredContent"]["report"]
            finding = report["results"][0]["findings"][0]
            self.assertEqual(finding["value"]["hex"], "61626364")
            self.assertEqual(finding["verdict"], "supported")
            self.assertEqual(self.tools.calls[0][-1], frozenset({"ghidra"}))
            out = Path(self.tools.calls[0][3])
            self.assertFalse(out.parent.exists())
            self.assertNotIn(root.encode(), raw)
            self.assertNotIn(str(out).encode(), raw)

    def test_cli_intake_refusals_keep_the_fixed_line_and_clean_the_temporary_directory(self):
        for problem in ("hard_link", "too_large", "changed_during_read"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as root:
                sample = Path(root, "sample.bin"); sample.write_bytes(b"abcdefgh")
                if problem == "hard_link":
                    os.link(sample, Path(root, "second.bin"))
                elif problem == "too_large":
                    with sample.open("r+b") as handle:
                        handle.truncate(intake.MAX_INPUT_BYTES + 1)
                def snapshot(*args, **kwargs):
                    raise intake.IntakeError("Input changed while reading")
                changed = (patch.object(intake, "snapshot", side_effect=snapshot) if problem == "changed_during_read"
                           else contextlib.nullcontext())
                with changed:
                    _, replies, raw, _ = self.serve(request("tools/call", {
                        "name": "read_bytes", "arguments": {"file": "sample.bin"}}), root=root)
                result = replies[0]["result"]
                self.assertTrue(result["isError"])
                self.assertEqual(result["content"][0]["text"], mcp.NOTICE + "\n\nreverseai: input refused: IntakeError")
                self.assertNotIn(root.encode(), raw)
                self.assertNotIn(b"Traceback", raw)
                self.assertFalse(Path(self.tools.calls[-1][3]).parent.exists())

    def test_first_fixed_intake_line_is_selected_without_returning_other_diagnostics(self):
        def refuse(argv, **kwargs):
            print("private diagnostic /private/secret", file=sys.stderr)
            print("reverseai: input refused: IntakeError", file=sys.stderr)
            print("reverseai: input refused: OSError", file=sys.stderr)
            raise SystemExit(1)
        with patch.object(cli, "main", side_effect=refuse):
            _, replies, raw, _ = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "sample.bin"}}))
        self.assertEqual(replies[0]["result"]["content"][0]["text"],
                         mcp.NOTICE + "\n\nreverseai: input refused: IntakeError")
        self.assertNotIn(b"/private/secret", raw)
        self.assertNotIn(b"OSError", raw)

    def test_other_cli_failures_keep_the_generic_message(self):
        for line in ("reverseai: output failed: OSError", "reverseai: analysis failed: ValueError", "/private/secret"):
            def fail(argv, **kwargs):
                print(line, file=sys.stderr)
                raise SystemExit(1)
            with self.subTest(line=line), patch.object(cli, "main", side_effect=fail):
                _, replies, _, _ = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "sample.bin"}}))
            self.assertEqual(replies[0]["result"]["content"][0]["text"], mcp.NOTICE + "\n\n" + mcp.FAILURE_MESSAGE)

    def fake_report(self, argv, *, _on_status=None, markdown="Static report", report=None, code=0):
        report = report if report is not None else {"results": []}
        if _on_status is not None:
            _on_status(tuple(row["status"] for row in report.get("results", ())))
        out = Path(argv[argv.index("--out") + 1]); out.mkdir()
        (out / "report.md").write_text(markdown, encoding="utf-8")
        (out / "report.json").write_text(canonical_json(report) + "\n")
        print("CLI summary must not enter the protocol stream")
        print("private diagnostic /private/secret", file=sys.stderr)
        return code

    def test_output_capture_and_cleanup_survive_return_exit_exception_and_missing_reports(self):
        def exit_now(argv, **kwargs):
            print("private summary /private/secret")
            raise SystemExit("private failure /private/secret")
        for effect in (self.fake_report, exit_now,
                       lambda argv, **kw: (_ for _ in ()).throw(RuntimeError("/private/secret")), lambda argv, **kw: 0):
            with self.subTest(effect=effect), patch.object(cli, "main", side_effect=effect):
                _, replies, raw, errors = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "sample.bin"}}))
                self.assertEqual(len(replies), 1)
                self.assertNotIn(b"private summary", raw)
                self.assertNotIn(b"CLI summary", raw)
                self.assertNotIn(b"/private/secret", raw)
                self.assertNotIn("/private/secret", errors)
                self.assertNotIn(b"Traceback", raw)
                self.assertFalse(Path(self.tools.calls[-1][3]).parent.exists())

    def test_markdown_cut_includes_the_notice_and_note_and_keeps_utf8_valid(self):
        def large(argv, **kwargs):
            return self.fake_report(argv, **kwargs, markdown="α😀" * 500)
        with patch.object(cli, "main", side_effect=large), patch.object(mcp, "MAX_TEXT_BYTES", 256):
            _, replies, _, _ = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "sample.bin"}}))
            text = replies[0]["result"]["content"][0]["text"]
            self.assertTrue(text.startswith(mcp.NOTICE))
            self.assertTrue(text.endswith(mcp.TEXT_CUT))
            self.assertLessEqual(len(text.encode("utf-8")), 256)
            self.assertNotIn("�", text)

    def test_structured_report_is_omitted_at_the_serialized_object_limit(self):
        for count in (100, 110, 1000):
            report = {"x": "a" * count}
            def render(argv, **kwargs):
                return self.fake_report(argv, **kwargs, report=report)
            with self.subTest(count=count), patch.object(cli, "main", side_effect=render), \
                    patch.object(mcp, "MAX_STRUCTURED_BYTES", 128):
                _, replies, _, _ = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "sample.bin"}}))
                structured = replies[0]["result"]["structuredContent"]
                if len(canonical_json({"report": report}).encode()) <= 128:
                    self.assertEqual(structured, {"report": report})
                else:
                    self.assertIsNone(structured["report"])
                    self.assertIn("narrow", structured["omitted"])
                self.assertFalse(replies[0]["result"]["isError"])

    def test_error_and_exhausted_budget_in_reports_are_tool_errors(self):
        for status, expected in (("ok", False), ("error", True), ("budget_exceeded", True)):
            with self.subTest(status=status), patch.object(cli, "main", side_effect=lambda argv, **kw: self.fake_report(
                    argv, **kw, report={"results": [{"status": status}]})):
                _, replies, _, _ = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "sample.bin"}}))
                self.assertEqual(replies[0]["result"]["isError"], expected)

    def test_status_callback_marks_budget_failure_when_the_json_report_is_omitted(self):
        for status, expected in (("ok", False), ("error", True), ("budget_exceeded", True)):
            def render(argv, **kwargs):
                return self.fake_report(argv, **kwargs, report={"results": [{"status": status}], "large": "x" * 1000})
            with self.subTest(status=status), patch.object(cli, "main", side_effect=render), \
                    patch.object(mcp, "MAX_STRUCTURED_BYTES", 128):
                _, replies, _, _ = self.serve(request("tools/call", {"name": "read_bytes", "arguments": {"file": "sample.bin"}}))
                result = replies[0]["result"]
                self.assertIsNone(result["structuredContent"]["report"])
                self.assertEqual(result["isError"], expected)
                if expected:
                    self.assertIn(mcp.FAILURE_MESSAGE, result["content"][0]["text"])

    def test_captured_diagnostics_have_a_fixed_memory_bound(self):
        stream = mcp._Capture()
        self.assertEqual(stream.write("x" * 100000), 100000)
        stream.write("y" * 100000)
        self.assertEqual(len(stream.getvalue()), mcp.MAX_DIAGNOSTIC_CHARS)

    def test_io_failures_return_one_with_bounded_fixed_diagnostics(self):
        class BrokenInput(io.BytesIO):
            def readline(self, size=-1):
                raise OSError("/private/secret")
        code, _, _, errors = self.serve(stdin=BrokenInput())
        self.assertEqual(code, 1)
        self.assertNotIn("/private/secret", errors)
        class BrokenOutput(io.BytesIO):
            def write(self, value):
                raise BrokenPipeError("/private/secret")
        stderr = io.StringIO()
        self.assertEqual(mcp.serve(io.BytesIO(canonical_json(request("ping")).encode()), BrokenOutput(), stderr,
                                   root="/operator-inputs", enabled=frozenset()), 1)
        self.assertNotIn("/private/secret", stderr.getvalue())


class CommandTests(unittest.TestCase):
    def test_private_status_callback_preserves_cli_exit_codes_and_output(self):
        original = pipeline.query_bytes
        for status, expected_code in (("ok", 0), ("budget_exceeded", 0), ("error", 1)):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as folder:
                sample = Path(folder, "sample.bin"); sample.write_bytes(b"abcdefgh")
                def query(*args, **kwargs):
                    analysis = original(*args, **kwargs)
                    return replace(analysis, results=tuple(replace(row, status=status) for row in analysis.results))
                results, statuses = [], []
                with patch.object(pipeline, "query_bytes", side_effect=query):
                    for number, callback in enumerate((None, statuses.append)):
                        stdout, stderr = io.StringIO(), io.StringIO()
                        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                            try:
                                code = cli.main(["query", str(sample), "--query", "read_bytes", "--arg", "length=4",
                                                 "--out", str(Path(folder, f"out-{number}"))], _on_status=callback)
                            except SystemExit as error:
                                code = error.code
                        results.append((code, stdout.getvalue(), stderr.getvalue()))
                self.assertEqual(results[0], results[1])
                self.assertEqual(results[0][0], expected_code)
                self.assertEqual(statuses, [(status,)])

    def test_subcommand_resolves_root_and_passes_only_operator_flags(self):
        with tempfile.TemporaryDirectory() as folder:
            child = Path(folder, "child"); child.mkdir()
            stdin = io.TextIOWrapper(io.BytesIO())
            stdout = io.TextIOWrapper(io.BytesIO())
            stderr = io.StringIO()
            with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout), \
                    patch.object(sys, "stderr", stderr), patch.object(mcp, "serve", return_value=0) as serve:
                self.assertEqual(cli.main(["mcp", "--inputs", str(child / ".."), "--with-ghidra", "--with-jsparser"]), 0)
                serve.assert_called_once_with(stdin.buffer, stdout.buffer, stderr, root=os.path.realpath(folder),
                                               enabled=frozenset({"ghidra", "jsparser"}))

    def test_invalid_root_is_a_safe_cli_error_before_serving(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(mcp, "serve") as serve:
            path = Path(folder, "file.bin"); path.write_bytes(b"inert fixture")
            for root in (path, Path(folder, "missing")):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                    cli.main(["mcp", "--inputs", str(root)])
                self.assertEqual(raised.exception.code, 1)
                self.assertIn("existing directory", stderr.getvalue())
                self.assertNotIn(folder, stderr.getvalue())
            serve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
