"""Bring your own model: run the hive's bees on a model server you host yourself (experimental).

The bees keep their agent CLI, so the fences do not depend on the model: Claude Code still enforces the
per-role tools, the folder-scoped write rules and `dontAsk`; Codex still runs in its sandbox behind the
network probe. Only the model behind the CLI changes:

- Claude bees talk to a server with the Anthropic Messages API (for example Ollama 0.14 or later,
  LM Studio 0.4.1 or later, llama.cpp `llama-server`), through ANTHROPIC_BASE_URL.
- Codex bees talk to a server with the OpenAI Responses API through a `selfhost` model provider.

The subscription login never reaches the model server: every Anthropic or Claude credential variable is
removed from the bee's environment and replaced by a placeholder token. The queen's checks (council,
evidence checker, confined compiler, conformance) stay the gate whatever the model; nothing here claims
that a self-hosted model is good enough for a long reverse-engineering run. Measure it first.
"""

import ipaddress
import json
import os
import urllib.parse

from hive.codex_bees import CodexBees

PLACEHOLDER_TOKEN = "self-hosted"
# Credentials and routing a bee must never inherit when it talks to a self-hosted server.
DROPPED_PREFIXES = ("ANTHROPIC_", "CLAUDE_CODE_USE_", "AWS_BEARER_TOKEN_BEDROCK", "VERTEX_", "CLOUD_ML_")
DROPPED = frozenset({"CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_SUBAGENT_MODEL", "OPENAI_API_KEY", "OPENAI_BASE_URL"})


def server_url(url, *, allow_remote=False):
    """The model server's base URL, refused when it could leak or is not what the owner meant."""
    parsed = urllib.parse.urlsplit(url or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("--model-server must be an http:// or https:// URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("--model-server must not carry credentials, a query or a fragment")
    host = parsed.hostname
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback and not allow_remote:
        raise ValueError(f"--model-server {host} is not this machine; add --model-server-remote to send the bees' "
                         "prompts (program evidence included) to it")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def claude_environment(base, url, model):
    """Environment for `claude -p` against a self-hosted Anthropic Messages server."""
    env = {key: value for key, value in base.items()
           if key not in DROPPED and not key.startswith(DROPPED_PREFIXES)}
    env.update({
        "ANTHROPIC_BASE_URL": url,
        "ANTHROPIC_AUTH_TOKEN": PLACEHOLDER_TOKEN,
        "ANTHROPIC_API_KEY": "",
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
        "CLAUDE_CODE_SUBAGENT_MODEL": model,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
    })
    return env


class SelfHostedCodexBees(CodexBees):
    """Codex bees whose model is served by a self-hosted OpenAI Responses server."""

    def __init__(self, *, server, **kwargs):
        super().__init__(**kwargs)
        if not self.model:
            raise ValueError("self-hosted Codex bees need --codex-model")
        self.server = server

    def argv(self, role, name, folder, *, schema=None):
        argv = super().argv(role, name, folder, schema=schema)
        provider = ("model_providers.selfhost={name=\"selfhost\",base_url=" + json.dumps(self.server + "/v1")
                    + ",wire_api=\"responses\"}")
        return [*argv[:-1], "-c", 'model_provider="selfhost"', "-c", provider, argv[-1]]


def add_arguments(parser):
    parser.add_argument("--model-server", metavar="URL",
                        help="Experimental: run the bees on a model server you host (Claude bees: Anthropic Messages "
                             "API; Codex bees: OpenAI Responses API). Needs --model or --codex-model")
    parser.add_argument("--model-server-remote", action="store_true",
                        help="Allow a --model-server on another machine (the bees' prompts and evidence go there)")


def apply(args, claude_runner):
    """Point the Claude runner at the self-hosted server; returns the Codex runner class and its extra settings."""
    if not args.model_server:
        if args.model_server_remote:
            raise SystemExit("hive: --model-server-remote needs --model-server")
        return CodexBees, {}
    try:
        url = server_url(args.model_server, allow_remote=args.model_server_remote)
    except ValueError as error:
        raise SystemExit(f"hive: {error}") from None
    if args.bee_policy in ("claude", "mixed"):
        if not getattr(args, "model", None):
            raise SystemExit("hive: --model-server needs --model, the model name your server serves to Claude bees")
        claude_runner.env = claude_environment(os.environ, url, args.model)
        claude_runner.model = args.model
    if args.bee_policy in ("codex", "mixed") and not args.codex_model:
        raise SystemExit("hive: --model-server needs --codex-model, the model name your server serves to Codex bees")
    return SelfHostedCodexBees, {"server": url}
