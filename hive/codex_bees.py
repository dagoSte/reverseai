"""Codex bees and mixed Claude/Codex councils.

Codex bees have a shell, can read the disk and can execute programs. On macOS,
codex-cli 0.165.0 allowed network access through `codex exec` in both sandbox modes,
despite network_access=false; `codex sandbox` blocked the same command. A preliminary
probe decides whether each sandbox mode may run bees; an inconclusive probe refuses
them. This reachability check is not a guarantee of isolation against every destination.
An explicit --codex-allow-network opt-out warns on every result. Use Codex bees only
for software the operator would run anyway, never for malware.
"""

import json
import re
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path

from hive.bees import REFUSAL, SCHEMAS, brief, is_refusal

NETWORK_REFUSAL = "Codex sandbox allowed network access; Codex bees refused"
NETWORK_WARNING = "Codex bees ran without network isolation"
NETWORK_COMMAND = "curl --max-time 5 --silent --show-error --output /dev/null https://example.com"
NETWORK_SCHEMA = {"type": "object", "properties": {"exit_code": {"type": "integer"}},
                  "required": ["exit_code"], "additionalProperties": False}
NETWORK_TASK = ("Network isolation probe. Run exactly this shell command once, with no extra commands, "
                "wrappers, redirections or file reads:\n" + NETWORK_COMMAND
                + "\nReport its actual exit code. Never invent a result or substitute another command. "
                "If execution is unavailable, report -1.")


def strict_schema(schema):
    """Require every object property, allowing null for originally optional fields."""
    if isinstance(schema, list):
        return [strict_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    result = {key: strict_schema(value) for key, value in schema.items()}
    if schema.get("type") == "object":
        required = schema.get("required", [])
        result["properties"] = {
            key: value if key in required else {"anyOf": [value, {"type": "null"}]}
            for key, value in result.get("properties", {}).items()
        }
        result["required"] = list(result["properties"])
        result["additionalProperties"] = False
    return result


def drop_nulls(value):
    """Restore omitted optional object fields without changing array positions."""
    if isinstance(value, dict):
        return {key: drop_nulls(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [drop_nulls(item) for item in value]
    return value


def _matches(value, schema):
    """Validate the small schema vocabulary used by bees and the network probe."""
    if "anyOf" in schema:
        return any(_matches(value, alternative) for alternative in schema["anyOf"])
    if "enum" in schema and value not in schema["enum"]:
        return False
    kind = schema["type"]
    if kind == "object":
        properties = schema["properties"]
        return (isinstance(value, dict) and value.keys() == properties.keys()
                and all(_matches(value[key], child) for key, child in properties.items()))
    if kind == "array":
        return isinstance(value, list) and all(_matches(item, schema["items"]) for item in value)
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return type(value) is int
    return kind == "null" and value is None


class ProviderRefusal(ValueError):
    """Codex ended because the model provider refused the request."""


def failure_messages(stdout):
    """Messages of the error events in `codex exec --json` output; tool output never counts."""
    messages = []
    for line in (stdout or "").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "error":
            messages.append(str(event.get("message", "")))
        elif event.get("type") == "turn.failed":
            error = event.get("error")
            messages.append(str(error.get("message", "") if isinstance(error, dict) else error))
    return messages


def refusal_excerpt(*texts):
    """The text around the first provider refusal in any of the texts, or an empty string."""
    for text in texts:
        match = REFUSAL.search(text) if isinstance(text, str) else None
        if match:
            return " ".join(text[max(0, match.start() - 120):match.end() + 120].split())
    return ""


class CodexBees:
    """One non-interactive Codex process and ReverseAI MCP server per named bee."""

    def __init__(self, *, engine, inputs, enabled=("ghidra",), codex="codex", model=None, effort=None,
                 timeout=2400, python=sys.executable, config_dir, allow_network=False, env=None):
        self.env = env  # None inherits this process's environment; hive.selfhost sets a self-hosted one
        self.engine, self.inputs = str(Path(engine).resolve()), str(Path(inputs).resolve())
        self.enabled, self.codex, self.model = tuple(enabled), codex, model
        self.effort, self.timeout, self.python = effort, timeout, str(python)
        self.config_dir = Path(config_dir).resolve()
        self.allow_network = allow_network
        self._network_checks = {}
        self._network_lock = threading.Lock()

    def _paths(self, name):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError("invalid bee name")
        return self.config_dir / f"{name}.schema.json", self.config_dir / f"{name}.output.json"

    def argv(self, role, name, folder, *, schema=None):
        schema_path, output_path = self._paths(name)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        schema_path.write_text(json.dumps(strict_schema(SCHEMAS[role]) if schema is None else schema),
                               encoding="utf-8")
        output_path.unlink(missing_ok=True)  # A failed retry must not reuse an earlier answer.
        mcp_args = ["-B", "-m", "reverseai", "mcp", "--inputs", self.inputs,
                    *("--with-" + tool for tool in self.enabled)]
        mcp = ("mcp_servers={reverseai={command=" + json.dumps(self.python)
               + ",args=" + json.dumps(mcp_args) + ",env={PYTHONPATH=" + json.dumps(self.engine)
               + ',PYTHONDONTWRITEBYTECODE="1"}}}')
        argv = [self.codex, "exec", "--ignore-user-config", "--skip-git-repo-check", "--ephemeral", "--json",
                "-C", str(Path(folder).resolve()), "--sandbox",
                "read-only" if role == "councillor" else "workspace-write",
                "-c", 'approval_policy="never"', "-c", "sandbox_workspace_write.network_access=false",
                "-c", "sandbox_workspace_write.writable_roots=[]",
                "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
                "-c", "sandbox_workspace_write.exclude_slash_tmp=true", "-c", 'web_search="disabled"',
                "-c", mcp, "--output-schema", str(schema_path), "-o", str(output_path)]
        if self.model:
            argv += ["-m", self.model]
        if self.effort:
            argv += ["-c", "model_reasoning_effort=" + json.dumps(self.effort)]
        return [*argv, "-"]

    def _execute(self, role, name, task, folder, *, schema=None):
        completed = subprocess.run(self.argv(role, name, folder, schema=schema), input=task, cwd=folder, env=self.env,
                                   capture_output=True, text=True, timeout=self.timeout, check=False)
        if completed.returncode:
            failures = failure_messages(completed.stdout)
            # Classify the whole diagnostic before shortening it: a refusal may sit far from the tail.
            refusal = refusal_excerpt(completed.stderr, *failures)
            if refusal:
                raise ProviderRefusal(f"exit {completed.returncode}: refused by the model provider: {refusal}")
            diagnostic = (completed.stderr or "\n".join(failures) or completed.stdout or "no diagnostic").strip()[-240:]
            raise ValueError(f"exit {completed.returncode}: {diagnostic}")
        _, output_path = self._paths(name)
        output = json.loads(output_path.read_text(encoding="utf-8"))
        if not _matches(output, strict_schema(SCHEMAS[role]) if schema is None else schema):
            raise ValueError("answer does not match the bee's output schema")
        return completed, output

    def _network_ok(self, role, folder):
        mode = "read-only" if role == "councillor" else "workspace-write"
        with self._network_lock:
            if mode not in self._network_checks:
                self._network_checks[mode] = False
                try:
                    completed, output = self._execute(role, f"network-probe-{mode}", NETWORK_TASK,
                                                      folder, schema=NETWORK_SCHEMA)
                    events = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
                    commands = [event["item"] for event in events if event.get("type") == "item.completed"
                                and event.get("item", {}).get("type") == "command_execution"]
                    if len(commands) == 1:
                        command = commands[0]
                        argv = shlex.split(command["command"])
                        if (len(argv) == 3 and Path(argv[0]).name in ("sh", "bash", "zsh")
                                and argv[1] in ("-c", "-lc")):
                            argv = shlex.split(argv[2])
                        # DNS/connect refusals qualify; TLS, local errors and timeouts do not.
                        self._network_checks[mode] = (
                            argv == shlex.split(NETWORK_COMMAND)
                            and type(command.get("exit_code")) is int and command["exit_code"] in (6, 7)
                            and output["exit_code"] == command["exit_code"]
                            and any(event.get("type") == "turn.completed" for event in events))
                except Exception:
                    pass  # Missing or inconsistent native evidence leaves this mode refused.
            return self._network_checks[mode]

    def __call__(self, role, name, task, folder):
        started = time.monotonic()
        warning = {"warning": NETWORK_WARNING} if self.allow_network else {}
        try:
            self._paths(name)
            if role not in SCHEMAS:
                raise ValueError(f"unknown bee role: {role}")
            if not self.allow_network and not self._network_ok(role, folder):
                return {"ok": False, "output": None, "error": NETWORK_REFUSAL,
                        "seconds": round(time.monotonic() - started, 1)}
            _, output = self._execute(role, name, brief(role, task), folder)
            return {"ok": True, "output": drop_nulls(output),
                    "seconds": round(time.monotonic() - started, 1), **warning}
        except subprocess.TimeoutExpired:
            return {"ok": False, "output": None, "error": f"no answer within {self.timeout} s",
                    "seconds": self.timeout, **warning}
        except Exception as error:
            if isinstance(error, ProviderRefusal) or is_refusal(str(error)):
                return {"ok": False, "output": None, "error": str(error)[:300], "refused": True,
                        "seconds": round(time.monotonic() - started, 1), **warning}
            return {"ok": False, "output": None, "error": str(error)[:300],
                    "seconds": round(time.monotonic() - started, 1), **warning}


class MixedBees:
    """Alternate module builders and give the other model two of three council seats."""

    def __init__(self, claude, codex, policy="mixed"):
        if policy not in ("claude", "codex", "mixed"):
            raise ValueError("bee policy must be claude, codex or mixed")
        self.claude, self.codex, self.policy = claude, codex, policy

    def __call__(self, role, name, task, folder):
        if self.policy != "mixed":
            runner = self.claude if self.policy == "claude" else self.codex
        elif role in ("planner", "tester") or (role == "repair" and re.fullmatch(r"behaviour-fix-\d+", name)):
            runner = self.claude
        else:
            pattern = (r"m(\d+)-council-r\d+-(control|io|data)" if role == "councillor" else
                       r"m(\d+)-build" if role == "worker" else
                       r"m(\d+)-repair-[bcl]\d+" if role == "repair" else "")
            match = re.fullmatch(pattern, name) if pattern else None
            if not match or int(match[1]) < 1:
                return {"ok": False, "output": None, "seconds": 0,
                        "error": "cannot route bee role/name in mixed policy"}
            use_claude = int(match[1]) % 2 == 1
            if role == "councillor" and match[2] in ("control", "io"):
                use_claude = not use_claude
            runner = self.claude if use_claude else self.codex
        return runner(role, name, task, folder)


def add_arguments(parser):
    parser.add_argument("--bee-policy", choices=("claude", "codex", "mixed"), default="claude",
                        help="Bee models: Claude only, Codex only, or alternating builders and mixed councils")
    parser.add_argument("--codex", default="codex", help="Codex CLI executable")
    parser.add_argument("--codex-model", help="Model for Codex bees (default: Codex CLI's default)")
    parser.add_argument("--codex-effort", help="Reasoning effort for Codex bees")
    parser.add_argument("--codex-allow-network", action="store_true",
                        help="Accept Codex network access: skip the isolation probe and warn on every bee result")
    from hive import selfhost
    selfhost.add_arguments(parser)


def build(args, claude_runner, **runner_kwargs):
    """Build from CLI options; kwargs are CodexBees' shared engine/input/config settings."""
    from hive import selfhost
    runner, extra = selfhost.apply(args, claude_runner)
    if args.bee_policy == "claude":
        return claude_runner
    codex = runner(**dict(runner_kwargs, codex=args.codex, model=args.codex_model, effort=args.codex_effort,
                          allow_network=args.codex_allow_network), **extra)
    return codex if args.bee_policy == "codex" else MixedBees(claude_runner, codex, args.bee_policy)
