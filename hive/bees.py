"""Bees: one headless coding-agent process per task, each with its own ReverseAI MCP server.

Every bee runs in its own folder, may write only there, and gets a fixed tool set for its role.
No role gets a shell or the web: bees read text that comes from untrusted binaries, so a
prompt-injection attempt in that text can at most change files in the bee's own folder, which
the queen then checks. Each bee starts its own `reverseai mcp` server, so contained Ghidra
questions from different bees run in parallel instead of queueing on one stdio server.

The default runner drives Claude Code in print mode on the user's own login (no API key).
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROLES = Path(__file__).with_name("roles")
# Texts with which model providers and their CLIs report a refusal by usage policy or safety classifiers.
REFUSAL = re.compile(r"(?i)usage polic|safeguards? (?:flagged|blocked|prevented)|flagged (?:this|the) (?:message|request)"
                     r"|cybersecurity topic|cyber safeguard|unable to respond to this request|violat\w* (?:our|the) "
                     r"(?:usage|acceptable)|content (?:policy|filter)|refused by the model|stop_reason.{0,4}refusal")


def is_refusal(*texts):
    """True when any text carries a provider refusal rather than an ordinary failure."""
    return any(isinstance(t, str) and REFUSAL.search(t) for t in texts)
COMMON = "common.md"

# Built-in tools per role; every role also gets the read-only ReverseAI MCP tools. Claude Code governs
# file writes through Edit rules, so every role that writes also needs Edit (its rule is fenced too).
TOOLSETS = {
    "planner": ("Read", "Write", "Edit"),
    "worker": ("Read", "Write", "Edit"),
    "repair": ("Read", "Write", "Edit"),
    "councillor": ("Read",),
    "tester": ("Read", "Write", "Edit"),
}

_STR = {"type": "string"}
_STRS = {"type": "array", "items": _STR}

SCHEMAS = {
    "planner": {
        "type": "object",
        "properties": {
            "modules": {"type": "array", "items": {
                "type": "object",
                "properties": {"id": _STR, "title": _STR, "functions": _STRS, "rationale": _STR},
                "required": ["id", "title", "functions"]}},
            "skipped": {"type": "array", "items": {
                "type": "object", "properties": {"entry": _STR, "reason": _STR}, "required": ["entry", "reason"]}},
            "notes": _STR,
        },
        "required": ["modules", "skipped"],
    },
    "worker": {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["done", "partial", "blocked"]},
            "functions": {"type": "array", "items": {
                "type": "object",
                "properties": {"entry": _STR, "name": _STR,
                               "status": {"type": "string", "enum": ["rebuilt", "stub", "skipped"]},
                               "notes": _STR},
                "required": ["entry", "status"]}},
            "contract_requests": _STRS,
            "unknowns": _STRS,
        },
        "required": ["status", "functions"],
    },
    "councillor": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["accept", "refute"]},
            "defects": {"type": "array", "items": {
                "type": "object",
                "properties": {"function": _STR, "problem": _STR, "evidence": _STR, "fix": _STR},
                "required": ["function", "problem", "evidence"]}},
            "summary": _STR,
        },
        "required": ["verdict", "defects"],
    },
    "tester": {
        "type": "object",
        "properties": {
            "cases": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "id": _STR,
                    "files": {"type": "array", "items": {
                        "type": "object",
                        "properties": {"name": _STR, "text": _STR, "base64": _STR},
                        "required": ["name"]}},
                    "steps": {"type": "array", "items": {
                        "type": "object",
                        "properties": {"args": _STRS, "stdin": _STR},
                        "required": ["args"]}},
                    "why": _STR},
                "required": ["id", "steps"]}},
        },
        "required": ["cases"],
    },
}
SCHEMAS["repair"] = SCHEMAS["worker"]


def brief(role, task):
    """The shared role-card prefix first (identical across sibling bees), the task last."""
    common = (ROLES / COMMON).read_text(encoding="utf-8")
    card = (ROLES / f"{role if role != 'repair' else 'worker'}.md").read_text(encoding="utf-8")
    return f"{common}\n\n{card}\n\n# Your task\n\n{task}\n"


class ClaudeBees:
    """Run each bee as `claude -p` in its own folder with its own ReverseAI MCP server."""

    def __init__(self, *, engine, inputs, enabled=("ghidra",), claude="claude", model=None, effort=None,
                 timeout=2400, python=sys.executable, config_dir, env=None):
        self.engine, self.inputs, self.enabled = str(engine), str(inputs), tuple(enabled)
        self.claude, self.model, self.effort, self.timeout, self.python = claude, model, effort, timeout, python
        self.config_dir = Path(config_dir)
        self.env = env  # None inherits this process's environment; hive.selfhost sets a self-hosted one

    def _mcp_config(self, name):
        self.config_dir.mkdir(parents=True, exist_ok=True)
        path = self.config_dir / f"{name}.json"
        env = {"PYTHONPATH": self.engine, "PYTHONDONTWRITEBYTECODE": "1"}
        args = ["-B", "-m", "reverseai", "mcp", "--inputs", self.inputs, *("--with-" + t for t in self.enabled)]
        path.write_text(json.dumps({"mcpServers": {"reverseai": {
            "type": "stdio", "command": self.python, "args": args, "env": env}}}, indent=1), encoding="utf-8")
        return path

    def argv(self, role, name):
        tools = TOOLSETS[role]
        argv = [self.claude, "-p", "--output-format", "json", "--json-schema", json.dumps(SCHEMAS[role]),
                "--mcp-config", str(self._mcp_config(name)), "--strict-mcp-config",
                "--tools", ",".join(tools), "--permission-mode", "dontAsk", "--no-session-persistence",
                "--allowedTools", "mcp__reverseai__*", *(f"{tool}(./**)" for tool in tools)]
        if self.model:
            argv[2:2] = ["--model", self.model]
        if self.effort:
            argv[2:2] = ["--effort", self.effort]
        return argv

    def __call__(self, role, name, task, folder):
        started = time.monotonic()
        try:
            completed = subprocess.run(self.argv(role, name), input=brief(role, task), cwd=folder, env=self.env,
                                       capture_output=True, text=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"no answer within {self.timeout} s", "seconds": self.timeout}
        except OSError as error:
            return {"ok": False, "error": f"cannot start {self.claude}: {error}", "seconds": 0}
        seconds = round(time.monotonic() - started, 1)
        try:
            data = json.loads(completed.stdout)
        except json.JSONDecodeError:
            tail = (completed.stderr or completed.stdout or "").strip()[-300:]
            return {"ok": False, "error": f"exit {completed.returncode}: {tail}", "seconds": seconds,
                    **({"refused": True} if is_refusal(completed.stderr, completed.stdout) else {})}
        output = data.get("structured_output")
        if output is None and isinstance(data.get("result"), str):
            try:
                output = json.loads(data["result"])
            except json.JSONDecodeError:
                output = None
        ok = not data.get("is_error") and isinstance(output, dict)
        refused = not ok and (data.get("stop_reason") == "refusal"
                              or is_refusal(data.get("result"), data.get("subtype"), completed.stderr))
        return {"ok": ok, "output": output, "seconds": seconds, "turns": data.get("num_turns"),
                "cost_usd": data.get("total_cost_usd"),
                **({} if ok else {"error": str(data.get("result") or data.get("subtype"))[:300]}),
                **({"refused": True} if refused else {})}


def environment_ok(claude="claude"):
    """True when the agent CLI can be found; the run itself proves the login."""
    return any((Path(p) / claude).is_file() for p in os.environ.get("PATH", "").split(os.pathsep)) or Path(claude).is_file()
