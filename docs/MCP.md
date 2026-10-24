# Using ReverseAI from an MCP client

`reverseai mcp` lets an AI agent, or any other client of the Model Context Protocol (MCP), ask ReverseAI the same
questions as the command line. It adds no analysis of its own: every tool call runs the existing `analyze` or
`query` command, with the same checks, budgets, reviewer and reports. For the questions themselves see
[USAGE](USAGE.md); for installation see [INSTALL](INSTALL.md); for the trust model see [SECURITY](SECURITY.md).

```sh
reverseai mcp --inputs DIR [--with-lief] [--with-yarax] [--with-ghidra] [--with-jadx] [--with-jsparser]
```

`DIR` is a directory of files you have approved for analysis. The client starts this command itself and talks to it
over its standard input and output; you do not run it by hand.

## What the client can and cannot do

- **Local only.** The server speaks over stdin and stdout and opens no network port.
- **Only files under `DIR`.** Every tool except `list_files` takes a `file` argument: a relative path inside `DIR` (no absolute paths,
  no `..`, no empty parts). A link anywhere along that path is refused, even one that points inside `DIR`, and
  the usual intake checks still apply (one regular file, not a link, at most 64 MiB, unchanged while it is read).
  `list_files` lists regular files under `DIR` with their sizes and never follows links. The check and the read
  are separate steps: another process of the same user could swap a directory in between. As in
  [SECURITY](SECURITY.md), the host account itself is trusted; keep `DIR` writable only by you.
- **Your flags, not the client's.** The contained tools (LIEF, YARA-X, Ghidra, JADX, the JavaScript parser) run only
  when you start the server with their flags and their pinned images are present. No request can enable a tool,
  pass a Docker option, choose an output path or reach a shell.
- **Nothing is executed.** As with the command line, the files are read as data; no sample runs.
- **File text is untrusted.** Reports quote strings, names and decompiled code from the files. Each result begins
  with a line saying so, and the server's instructions tell the agent to treat that text as data, never as
  instructions. A file can still contain text written to mislead an agent, so keep a person in the loop for any
  action an agent proposes after reading a report.
- **Bounded results.** The Markdown report is cut at 256 KiB with a closing note; the JSON report is included as
  `structuredContent` up to 1 MiB, otherwise it is omitted with a hint to narrow or page the query. Each call's
  reports are written to a private temporary directory that is removed afterwards.
- **Errors are messages.** A wrong argument, a refused file, a failed analysis or an exceeded budget comes back as a
  tool result marked as an error with a short, fixed explanation.

## Tools

All tools are read-only and idempotent. They are listed in one page, in this order:

| Tool | What it does | Needs |
| --- | --- | --- |
| `list_files` | Names and sizes of the regular files under `DIR` | - |
| `analyze_file` | The whole-file analysis of one file | LIEF, YARA-X and Ghidra join the run when enabled |
| `binary_overview`, `list_segments`, `inspect_native_load_image`, `list_names`, `read_bytes`, `list_strings`, `search_strings` | Native file structure, names, bytes and strings, verified on the host | - |
| `list_procedures`, `search_procedures`, `procedure_info`, `procedure_pseudo_code`, `procedure_assembly`, `procedure_callees`, `procedure_callers`, `analyze_function`, `xrefs` | Functions, code and references as Ghidra reads them | `--with-ghidra` |
| `inspect_android_package`, `search_android_classes`, `inspect_android_class`, `inspect_android_method`, `trace_android_references` | APK and DEX structure verified on the host | `--with-jadx` adds Java to `inspect_android_method` |
| `analyze_javascript_application` | Files, package.json declarations and lexical hints of a JavaScript ZIP, ASAR, npm tarball or bundle | `--with-jsparser` adds the module, call and parse details |

Each query tool takes `file` plus that query's own arguments, with the types, limits and defaults the command line
uses; the client sees them in the tool's input schema, and unknown arguments are refused. Large lists are paged
with `start` and `limit`, as on the command line. For `analyze_javascript_application` the archive is `file`, and
one file inside it is chosen with `member_file` (the command line's `--arg file=`). A query uses only its own
contained tool: Ghidra for the code queries, JADX for `inspect_android_method`, the parser for the JavaScript
syntax details.

`list_files` returns `structuredContent` `{"files": [{"name": ..., "size": ...}], "truncated": ...}` and a readable
listing. It visits at most 10,000 entries to a depth of 8 and returns at most 1,000 files; names that are not plain
portable relative names (not UTF-8, or with a backslash, a colon or a control character) are skipped. `truncated`
is true whenever a limit was reached or a name was skipped. The other tools return the report as
`structuredContent` `{"report": ...}`.

## Configuring a client

The examples use an installed package at `/path/to/.venv` and approved files in `/path/to/approved-inputs`; use
your own absolute paths. On Windows the program is `C:\path\to\.venv\Scripts\reverseai.exe` (Windows support is
experimental; see [INSTALL](INSTALL.md)). To enable a contained tool, add its flag after `--inputs DIR`, for
example `"--with-ghidra"`.

### Claude Code

Add the server for this project (stored in `.mcp.json`, shared with the project):

```sh
claude mcp add --transport stdio --scope project reverseai -- /path/to/.venv/bin/reverseai mcp --inputs /path/to/approved-inputs
```

Or write the project's `.mcp.json` yourself:

```json
{
  "mcpServers": {
    "reverseai": {
      "type": "stdio",
      "command": "/path/to/.venv/bin/reverseai",
      "args": ["mcp", "--inputs", "/path/to/approved-inputs"]
    }
  }
}
```

Use `--scope local` (the default) to keep it to yourself, or `--scope user` for every project. Claude Code asks
before it first uses a project's servers from `.mcp.json`. It warns when one tool result passes 10,000 tokens and
stores results over its limit (25,000 tokens by default, or 50,000 characters of text) in a file instead of the
conversation; prefer paged queries, or raise `MAX_MCP_OUTPUT_TOKENS` before starting Claude Code.

### Codex CLI

```sh
codex mcp add reverseai -- /path/to/.venv/bin/reverseai mcp --inputs /path/to/approved-inputs
```

Or add it to `~/.codex/config.toml` (or a trusted project's `.codex/config.toml`):

```toml
[mcp_servers.reverseai]
command = "/path/to/.venv/bin/reverseai"
args = ["mcp", "--inputs", "/path/to/approved-inputs"]
tool_timeout_sec = 300
```

Codex stops a tool call after 60 seconds by default; Ghidra queries can take up to 240 seconds, so raise
`tool_timeout_sec` when you enable `--with-ghidra`.

### Cursor

Put this in the project's `.cursor/mcp.json` (or `~/.cursor/mcp.json` for every project):

```json
{
  "mcpServers": {
    "reverseai": {
      "type": "stdio",
      "command": "/path/to/.venv/bin/reverseai",
      "args": ["mcp", "--inputs", "${workspaceFolder}/approved-inputs"]
    }
  }
}
```

Cursor asks for approval before it uses an MCP tool unless your run mode allows it.

## Protocol

The server follows MCP revision `2026-07-28`: each request carries its protocol version and client capabilities in
`params._meta`, and `server/discover` describes the server. Clients that still open with `initialize` (revisions
`2025-11-25`, `2025-06-18` and `2025-03-26`) are served too. Messages are JSON-RPC 2.0, one per line; a line over
1 MiB is refused, and the server never sends requests to the client.

## Trying it without an agent

`tests/mcp_client.py` is a small client used by the end-to-end tests. It starts the server, sends requests and
reads each reply with a timeout and a size limit:

```python
from tests.mcp_client import Client

with Client.reverseai("/path/to/approved-inputs") as client:
    print(client.discover()["result"]["supportedVersions"])
    print(client.call_tool("list_files")["result"]["structuredContent"]["files"])
    reply = client.call_tool("binary_overview", {"file": "sample.bin"})
```

Run it from the repository root with Python 3.12 or later.
