# The hive: an AI analyst team on top of ReverseAI

The hive is an optional team of AI agents that analyses a native program with ReverseAI and
rebuilds it as C or C++ source. A **queen** splits the work, a **hive of bees** works in parallel, and
an **independent council** plus a deterministic **evidence checker** decide what is accepted.
The ReverseAI engine itself stays model-free: the hive is a separate layer in `hive/` that
talks to the engine only through its MCP server and command line.

Status: experimental. It needs prepared Ghidra exports (`reverseai prepare`, ReverseAI 0.8.0)
and Claude Code logged in with your own subscription; Codex bees, if you choose them, use your
Codex login. No API key is used.

## Roles

| Role | Who | Does | Never does |
| --- | --- | --- | --- |
| Queen | Python code (`hive/queen.py`) | Exports the program map, freezes the plan, schedules bees, compiles and links, runs the checks, computes the verdict | Write code, review, vote, or override a check |
| Planner | One bee | Splits functions into modules, marks library and runtime code to skip, writes the frozen interface `contract.h` | Rebuild or judge |
| Builder | One bee per module, in parallel | Rebuilds its module's functions as C from the evidence; writes claims citing finding IDs | Edit the contract or another module |
| Councillor | Three per module, one lens each | Tries to refute the module against the original's assembly: control flow and arithmetic, input/output, data and memory | Write anything; see the author's notes |
| Tester | One bee, only with `--run-original` | Designs conformance cases from strings and logic | Run anything |

## How a run works

1. **Survey.** The queen prepares the file once (Ghidra analyses it in its locked container and
   keeps the project in the private cache), then exports every function, call and string into
   `survey/map.json`.
2. **Pre-flight.** Before any bee is spent, the queen checks whether the program is packed or
   obfuscated (see [Pre-flight](#pre-flight)). A packed program stops the run with the reasons,
   unless you start it with `--allow-packed`. Then the queen chooses the language: C, or C++ when
   the map shows C++ (see [Languages](#languages)).
3. **Plan.** The planner proposes modules and `contract.h`. The queen checks that every function
   is either skipped with a reason or in exactly one module, splits oversized modules, checks
   that the contract compiles on its own, and freezes it read-only. Every global the contract
   declares (`extern ...; /* 0xADDRESS */`) gets exactly one owner module, the one whose functions
   reference it most in the exported data references; that builder defines it from the original's
   bytes and the others only use the declaration, so tables and settings are not left undefined.
   A declaration the queen cannot read with certainty (an attribute, `_Atomic(int)`, an inline struct,
   two names at once, two names at one address) goes back to the planner in the canonical form, and the
   run stops before any builder if it is never fixed: no global is silently left without an owner.
4. **Build.** Builders work in parallel, one folder each. Every module is compiled alone from a
   clean stage containing snapshots of its source and the frozen contract, with
   `-Wall -Wextra -fwrapv -fno-strict-aliasing`. This requires Clang with a closed virtual
   filesystem (`-ivfsoverlay`, no fallthrough): generated includes and include-existence queries
   can see only that stage and the compiler's system header directories. Other compilers are
   refused. Before the planner starts, a native positive/negative probe checks the selected
   compiler once: the outside-file query must fail and nonempty inline assembly must be disabled
   in the selected C or C++ mode. The compiler receives `-fno-gnu-inline-asm` and `-fno-asm-blocks`;
   the preprocessor VFS alone does not confine the assembler. Symlinked or hard-linked sources
   and contracts are refused. The queen scans the whole expanded output for file-loading
   constructs, without trusting source line markers, then compiles the original source in the
   same confinement so macro context is kept. Generated source-location overrides are refused.
   Each compiler command has a 60-second deadline and captured-output limits of 16 MiB stdout
   and 256 KiB stderr; crossing a limit stops the command (the owned process group on POSIX).
   Compiler messages go back to the builder, at most three times. A builder must report every
   assigned function rebuilt and status `done`; repair reports update the entries they touch
   while preserving the other functions' reported state.
5. **Council.** Three councillors, each with a fresh context, review a renamed copy of the module
   without the builder's notes. Only behavioural differences with evidence (an address in the
   original or a finding ID) count. The builder must fix them or disprove them with evidence; a
   fresh council reviews again. A module still refuted after two rounds is **disputed**, never
   silently accepted. Every configured seat must return a valid verdict; a missing or failed
   seat leaves the module **incomplete**, including a refused Codex seat in a mixed council.
6. **Link.** The queen links all modules and routes undefined or duplicate symbols to the module
   that owns them, at most three rounds. Each repaired module returns to council on its new
   source; a missing or refuting verdict prevents acceptance.
7. **Evidence check.** `tools/hive_check.py` re-runs every question that a claim cites, through
   ReverseAI itself, and keeps a claim only if each cited finding ID comes back with a
   `supported` or `derived` verdict. Finding IDs are bound to the file's hash and the result's
   content, so a made-up ID, an ID from another file or a stale ID is rejected. The queen binds
   every citation to the target file and requires the checker's input hash to match the survey.
   These checks run after the last repair, including behaviour repairs.
8. **Behaviour (optional).** With `--run-original`, the tester writes cases; the queen runs the
   original and the rebuild on each case in a fresh folder and compares the exit code, stdout and
   every file created (by hash), and stderr with the program's path masked (its first 2,000
   characters). At least **two nonempty cases**, with unique IDs after filename
   normalisation, must complete; empty suites, colliding IDs and timeouts cannot prove behaviour.
   Differences go to one fixer bee, at most two rounds; changed modules return to council.
   A failed relink removes the older binary, invalidates the link result and stops the behaviour
   proof; the queen never falls back to a binary built from earlier objects.
9. **Verdict.** Code computes it: **accepted** only if the program links, every module is
   accepted by its council, no function is a stub, the checker rejected no claim and every
   conformance case is identical. Without `--run-original` the best verdict is
   **accepted without behaviour proof**.

With `--run-original --fuzz N`, add up to 500 deterministic mutants after the ordinary behaviour
checks and repairs (`N` defaults to 0, off). They change only case-file bytes, including stdin files,
using bit flips, insertion, deletion, truncation, boundary bytes and splicing between cases; arguments
stay unchanged and each file stays within the 64 KiB case limit. The input SHA-256 and source case ID
seed each sequence. Mutants use the final rebuilt binary and extend the conformance totals; differences
are reported without another repair round. No-op and duplicate inputs are discarded with bounded
attempts; cases whose files the executor skips add no mutants. Complete mutant pairs are compared
even if others time out or are missing: the report keeps the plain result, differing cases and a
separate `incomplete` list. Any incomplete mutant prevents acceptance. `tests/fuzz.json` records the
seed and bounded base64 inputs of both differing and incomplete mutants for reproduction, and is
cleared at the start of each conformance attempt.

## Who has the final word

- A failed check cannot be overruled by any agent. The council can only add a veto.
- The queen is code. She cannot vote, and her plan is reviewed only through its results.
- A claim without a resolvable citation is dropped, whatever it says.

## Speed

- **One MCP server per bee.** ReverseAI's MCP server answers one request at a time, so the hive
  gives every bee its own server process: Ghidra questions from different bees run in parallel
  containers instead of queueing.
- **Analyse once.** Preparation runs Ghidra's auto-analysis once; later questions load the
  cached project.
- **Barriers only where needed.** Modules run as independent pipelines (build, compile, council,
  repair); the queen waits only after the plan, before linking and before the final checks.
- `--bees N` sets how many bees work at once (default 4). Each contained Ghidra question uses up
  to 2 CPUs and 2 GiB, so size N to your Docker VM. `--max-bees` caps the whole run.

## Pre-flight

Rebuilding a packed program from static evidence only rebuilds its unpacking stub, and
obfuscation (flattened control flow, virtual machines) defeats decompilation, so the queen checks
first, deterministically, in `hive/preflight.py`:

- packer section names (UPX, MPRESS, ASPack, PECompact, Themida, VMProtect, Enigma, NsPack, ...)
  and packer marker strings in the file;
- byte entropy of each executable segment and of the whole file, computed from the approved file
  over the segment ranges that ReverseAI verifies (compressed or encrypted bytes are close to
  8 bits per byte);
- imports that only load more code (`LoadLibrary`/`GetProcAddress`, `dlopen`/`dlsym`, ...);
- very few functions or strings for the code size, or one function holding most of the code.

Any strong signal gives **packed** (the run stops); two weak signals give **suspected** (the run
warns and continues). The result is in `survey/preflight/preflight.json` and in the report.
Nothing is unpacked or executed: unpacking stays your decision. A clean verdict does not prove
that a program is neither packed nor obfuscated.

## Languages

`--language auto` (the default) rebuilds in C, or in C++ when the map shows at least two signs of
C++: mangled names (`_Z...`), qualified names (`Class::method`), C++ runtime imports
(`__cxa_throw`, `__gxx_personality_v0`, ...) or `operator new`/`delete`. `--language c` and
`--language cpp` force a choice. C++ builders rebuild classes with the layout the assembly shows,
pinned with `static_assert`, and virtual methods in vtable order; the contract becomes
`contract.hpp` and the queen compiles with `c++ -std=gnu++17`. Other languages (Java for Android
apps, ports to Rust, Go or Python) are not handled yet.

## Bee models

`--bee-policy claude` (the default) runs every bee on Claude Code. `--bee-policy codex` runs every
bee on the Codex CLI (`codex exec`), and `--bee-policy mixed` alternates: odd-numbered modules are
built by Claude and even ones by Codex, repairs stay with the module's builder, and each council
gives two of its three seats to the model that did not build the module, so the majority of every
council is non-author. The planner, the tester and the behaviour fixer stay on Claude. Different
models make fewer of the same mistakes, which is why mixed councils are worth having.

Codex bees are less fenced than Claude bees, and this was measured on 2026-10-31 with
codex-cli 0.165.0 on macOS: writes outside the bee's folder were denied, but a Codex bee could read
files elsewhere on the disk, run programs (including the input), and reach the network from inside
`codex exec` in both its read-only and workspace-write modes, although `codex sandbox` alone blocks
it. The hive therefore probes the Codex sandbox before its first Codex bee and refuses Codex bees
while the probe reaches the network. `--codex-allow-network` skips that refusal for operators who
accept the risk on software they would run anyway; never use Codex bees on malware.

### Self-hosted models (experimental)

`--model-server URL` runs the bees on a model you host yourself, for teams that cannot send program
evidence to a cloud provider or want the analysis to stay on their own network. The bees keep their
agent CLI, so nothing about the fences depends on the model: Claude Code still enforces each role's
tools, the folder-scoped writes and `dontAsk`, and Codex still runs in its sandbox behind the network
probe.

- Claude bees (`--model NAME`) need a server with the Anthropic Messages API, for example Ollama 0.14
  or later, LM Studio 0.4.1 or later or llama.cpp's `llama-server`. Give it a large context: Claude
  Code's prompt and tool definitions are long, and Ollama recommends 64k tokens or more.
- Codex bees (`--bee-policy codex`, `--codex-model NAME`) need a server with the OpenAI Responses
  API (Ollama 0.13.3 or later, vLLM and others). The hive adds a `selfhost` model provider for them.
- The server must be on this machine unless you add `--model-server-remote`, because the bees'
  prompts carry program evidence.
- No login or key reaches a self-hosted bee. Its environment is an allowlist (system basics such as
  `PATH` and `HOME`, locale, certificate paths) plus the server routing, with a placeholder token for
  Claude bees. Subscription logins, cloud credentials and API or repository tokens are left out.

```bash
OLLAMA_CONTEXT_LENGTH=65536 ollama serve &
python3 -m hive run --inputs /path/to/approved-inputs --file program --out new-hive-run \
  --model-server http://127.0.0.1:11434 --model qwen3.6:35b
```

This is plumbing, not a quality claim. A test drives a real Claude Code bee through a stand-in server
that speaks the Messages API; no self-hosted model has yet been measured on a whole run. Long
reverse-engineering runs are hard for local models (many tool calls, long decompiler output), so
expect smaller models to manage narrow roles at best. The queen's checks stay the gate whatever the
model: councils, the evidence checker, the confined compiler and the conformance cases.

## Safety

- Bees read text that comes from untrusted binaries. No Claude bee has a shell, the web or the
  ability to start other agents (Codex bees differ: see [Bee models](#bee-models)). Each bee runs with Claude Code's `dontAsk` permission mode and file rules
  limited to its own folder (`Read(./**)`, `Write(./**)`, `Edit(./**)`), so reads and writes
  anywhere else are denied; councillors can only read. ReverseAI's MCP tools are read-only and
  never execute the input.
- Each bee's MCP configuration, the frozen contract and the build stage live outside the bee's
  folder or are copied fresh by the queen, so a bee cannot change what the queen compiles or
  checks.
- The original program runs **only** with `--run-original`, in a temporary folder with a short
  timeout and a minimal environment. That is not a sandbox: use it only for software you would
  run anyway, and never for malware.
- Workspaces contain decompiled code and data from the input. Treat them as sensitive.
- Use the hive only on programs you are entitled to analyse and rebuild; see the README's
  responsible-use notice.

## Run it

From a ReverseAI 0.8.0 checkout, with Docker running, the pinned Ghidra image present and
Claude Code logged in:

```sh
python3 -m hive run --inputs /path/to/approved-inputs --file program --out new-hive-run --bees 4
python3 -m hive run --inputs /path/to/approved-inputs --file program --out new-hive-run --run-original
```

Run the same command again with the same `--out` to resume. Accepted modules are kept only when
their input, assignment, source, contract, compiled object and compiler policy still match the queen's saved
decision. The authoritative decisions live outside bee folders, in `.hive/status/`; module
`status.json` files are informational copies. Frozen contracts can be replaced on a resumed run.

## Workspace

| Path | Contents |
| --- | --- |
| `survey/map.json` | Functions, calls, strings and imports exported from the prepared project |
| `plan/` | The planner's `contract.h`, `PLAN.md` and the normalised `modules.json` |
| `src/contract.h` | The frozen interface, read-only |
| `modules/mNN/` | One builder's folder: `BRIEF.md`, `mNN.c`, `claims.json`, `NOTES.md`, `status.json` |
| `council/` | One read-only seat per councillor and round |
| `build/` | Objects, the linked rebuild in `build/bin/` |
| `check/` | Merged claims and the checker's `verdicts.json` with every re-run report |
| `tests/` | Cases and results, only with `--run-original` |
| `REPORT.md`, `result.json`, `hive.log` | The verdict, its reasons and the timeline |

## Limits

- The bees run on Claude Code (and optionally Codex), so the provider's usage policies and safety
  classifiers apply: work on malware in particular may be refused. The hive recognises a refusal
  and records it as "refused by the model provider" in the log and the report: a refused planner
  stops the run before any other bee, a refused builder leaves its module refused, and after three
  refusals (`refusal_limit`) no further bee starts. The run then ends not accepted, never as a
  silent pass.
- C and C++ output only; Objective-C, Swift, Go and Rust programs are not handled specially.
- The pre-flight recognises common packers and strong signs of obfuscation; it does not unpack,
  and it can miss custom packers or light obfuscation.
- Rebuilt code follows Ghidra's and the agents' reading of the assembly. It is not the original
  source, and conformance cases show equal behaviour only on the cases run.
