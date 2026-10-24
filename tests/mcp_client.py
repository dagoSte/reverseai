"""A small stdio MCP client for end-to-end tests; standard library only.

It starts one server process (by default `python -B -m reverseai mcp --inputs DIR`), sends JSON-RPC requests one line
each with the modern per-request `_meta`, and reads one reply line per request with a timeout and a size bound. Two
reader threads drain stdout and stderr, so a chatty server never blocks and the client works where select() cannot
watch pipes. close() ends stdin, waits with a timeout and kills only its own child.
"""

import json
import os
import queue
import subprocess
import sys
import threading

PROTOCOL_VERSION = "2026-07-28"
META = {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {}}
MAX_LINE = 4 * 1024 * 1024  # above the server's 256 KiB report text plus 1 MiB of structured content
MAX_STDERR = 64 * 1024
CHUNK = 65536


class ClientError(Exception):
    """The server did not answer in time, answered too much, or answered something that is not one JSON reply."""


class Client:
    def __init__(self, argv, *, cwd=None, env=None, timeout=60.0, max_line=MAX_LINE):
        self.timeout, self.max_line, self.next_id = timeout, max_line, 0
        self.lines, self.stderr_tail = queue.Queue(), bytearray()
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        cwd=cwd, env=env, shell=False)
        self.readers = [threading.Thread(target=self._read_stdout, daemon=True),
                        threading.Thread(target=self._read_stderr, daemon=True)]
        for reader in self.readers:
            reader.start()

    @classmethod
    def reverseai(cls, inputs, *flags, python=sys.executable, **options):
        """The ReverseAI server over DIR, with the operator's --with-... flags."""
        return cls([python, "-B", "-m", "reverseai", "mcp", "--inputs", os.fspath(inputs), *flags], **options)

    def _read_stdout(self):
        pending = bytearray()
        while chunk := self.process.stdout.read1(CHUNK):
            pending.extend(chunk)
            while (end := pending.find(b"\n")) >= 0:
                self.lines.put(bytes(pending[:end]))
                del pending[:end + 1]
            if len(pending) > self.max_line:
                self.lines.put(ClientError("reply line longer than the client's limit"))
                return
        self.lines.put(None)  # end of output

    def _read_stderr(self):
        while chunk := self.process.stderr.read1(CHUNK):
            self.stderr_tail.extend(chunk)
            del self.stderr_tail[:-MAX_STDERR]

    def send(self, message):
        """Write one message as one line; bytes are sent as given (for malformed-input tests)."""
        raw = message if isinstance(message, bytes) else json.dumps(message, separators=(",", ":")).encode("utf-8")
        self.process.stdin.write(raw + b"\n")
        self.process.stdin.flush()

    def read_line(self, timeout=None):
        try:
            line = self.lines.get(timeout=self.timeout if timeout is None else timeout)
        except queue.Empty:
            raise ClientError("no reply within the timeout") from None
        if isinstance(line, ClientError):
            raise line
        if line is None:
            raise ClientError("the server closed its output")
        if len(line) > self.max_line:
            raise ClientError("reply line longer than the client's limit")
        return line

    def request(self, method, params=None, *, modern=True, timeout=None):
        """Send one request and return its reply object (result or error)."""
        self.next_id += 1
        params = dict(params or {})
        if modern:
            params["_meta"] = {**META, **params.get("_meta", {})}
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        try:
            reply = json.loads(self.read_line(timeout))
        except ValueError:
            raise ClientError("the reply is not JSON") from None
        if not isinstance(reply, dict) or reply.get("id") != self.next_id:
            raise ClientError("the reply does not answer this request")
        return reply

    def notify(self, method, params=None):
        self.send({"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})})

    def discover(self):
        return self.request("server/discover")

    def list_tools(self):
        return self.request("tools/list")

    def call_tool(self, name, arguments=None, *, timeout=None):
        return self.request("tools/call", {"name": name, "arguments": arguments or {}}, timeout=timeout)

    @property
    def stderr(self):
        return bytes(self.stderr_tail).decode("utf-8", "replace")

    def close(self, timeout=10.0):
        """End stdin, wait for the server to exit, kill it (only this child) if it does not; return its exit code."""
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            code = self.process.wait()
        for reader in self.readers:
            reader.join(timeout=5)
        self.process.stdout.close()
        self.process.stderr.close()
        return code

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.process.poll() is None or not self.process.stdin.closed:
            self.close()
