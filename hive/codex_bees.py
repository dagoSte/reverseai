"""Codex bees and mixed Claude/Codex councils.

Codex bees have a sandboxed shell with no network and writes limited to their folder
(councillors are read-only). They can read the disk. Use them only for software the
operator would run anyway, never for malware.
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path

from hive.bees import SCHEMAS, brief


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
    """Validate the object/array/string/null vocabulary used by the bee schemas."""
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
    return kind == "null" and value is None


class CodexBees:
    """One non-interactive Codex process and ReverseAI MCP server per named bee."""

    def __init__(self, *, engine, inputs, enabled=("ghidra",), codex="codex", model=None, effort=None,
                 timeout=2400, python=sys.executable, config_dir):
        self.engine, self.inputs = str(Path(engine).resolve()), str(Path(inputs).resolve())
        self.enabled, self.codex, self.model = tuple(enabled), codex, model
        self.effort, self.timeout, self.python = effort, timeout, str(python)
        self.config_dir = Path(config_dir).resolve()

    def _paths(self, name):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError("invalid bee name")
        return self.config_dir / f"{name}.schema.json", self.config_dir / f"{name}.output.json"

    def argv(self, role, name, folder):
        schema_path, output_path = self._paths(name)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        schema_path.write_text(json.dumps(strict_schema(SCHEMAS[role])), encoding="utf-8")
        output_path.unlink(missing_ok=True)  # A failed retry must not reuse an earlier answer.
        mcp_args = ["-B", "-m", "reverseai", "mcp", "--inputs", self.inputs,
                    *("--with-" + tool for tool in self.enabled)]
        mcp = ("mcp_servers={reverseai={command=" + json.dumps(self.python)
               + ",args=" + json.dumps(mcp_args) + ",env={PYTHONPATH=" + json.dumps(self.engine)
               + ',PYTHONDONTWRITEBYTECODE="1"}}}')
        argv = [self.codex, "exec", "--ignore-user-config", "--skip-git-repo-check", "--ephemeral",
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

    def __call__(self, role, name, task, folder):
        started = time.monotonic()
        try:
            completed = subprocess.run(self.argv(role, name, folder), input=brief(role, task),
                                       cwd=folder, capture_output=True, text=True,
                                       timeout=self.timeout, check=False)
            if completed.returncode:
                diagnostic = (completed.stderr or completed.stdout or "no diagnostic").strip()[-240:]
                raise ValueError(f"exit {completed.returncode}: {diagnostic}")
            _, output_path = self._paths(name)
            output = json.loads(output_path.read_text(encoding="utf-8"))
            if not _matches(output, strict_schema(SCHEMAS[role])):
                raise ValueError("answer does not match the bee's output schema")
            return {"ok": True, "output": drop_nulls(output),
                    "seconds": round(time.monotonic() - started, 1)}
        except subprocess.TimeoutExpired:
            return {"ok": False, "output": None, "error": f"no answer within {self.timeout} s",
                    "seconds": self.timeout}
        except Exception as error:
            return {"ok": False, "output": None, "error": str(error)[:300],
                    "seconds": round(time.monotonic() - started, 1)}


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


def build(args, claude_runner, **runner_kwargs):
    """Build from CLI options; kwargs are CodexBees' shared engine/input/config settings."""
    if args.bee_policy == "claude":
        return claude_runner
    codex = CodexBees(**dict(runner_kwargs, codex=args.codex, model=args.codex_model, effort=args.codex_effort))
    return codex if args.bee_policy == "codex" else MixedBees(claude_runner, codex, args.bee_policy)
