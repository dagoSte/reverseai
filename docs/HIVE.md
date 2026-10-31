# The hive: an AI analyst team on top of ReverseAI

The hive is an optional team of AI agents that analyses a native program with ReverseAI and
rebuilds it as C source. A **queen** splits the work, a **hive of bees** works in parallel, and
an **independent council** plus a deterministic **evidence checker** decide what is accepted.
The ReverseAI engine itself stays model-free: the hive is a separate layer in `hive/` that
talks to the engine only through its MCP server and command line.

Status: experimental. It needs prepared Ghidra exports (`reverseai prepare`, ReverseAI 0.8.0)
and Claude Code logged in with your own subscription. No API key is used.

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
2. **Plan.** The planner proposes modules and `contract.h`. The queen checks that every function
   is either skipped with a reason or in exactly one module, splits oversized modules, checks
   that the contract compiles on its own, and freezes it read-only.
3. **Build.** Builders work in parallel, one folder each. Every module is compiled alone from a
   clean stage that holds only its source and the frozen contract, with
   `-Wall -Wextra -fwrapv -fno-strict-aliasing`. Inline assembly, `#embed`, `.incbin` and
   `dlopen` fail the module outright. Compiler messages go back to the builder, at most three
   times.
4. **Council.** Three councillors, each with a fresh context, review a renamed copy of the module
   without the builder's notes. Only behavioural differences with evidence (an address in the
   original or a finding ID) count. The builder must fix them or disprove them with evidence; a
   fresh council reviews again. A module still refuted after two rounds is **disputed**, never
   silently accepted.
5. **Link.** The queen links all modules and routes undefined or duplicate symbols to the module
   that owns them, at most three rounds.
6. **Evidence check.** `tools/hive_check.py` re-runs every question that a claim cites, through
   ReverseAI itself, and keeps a claim only if each cited finding ID comes back with a
   `supported` or `derived` verdict. Finding IDs are bound to the file's hash and the result's
   content, so a made-up ID, an ID from another file or a stale ID is rejected.
7. **Behaviour (optional).** With `--run-original`, the tester writes cases; the queen runs the
   original and the rebuild on each case in a fresh folder and compares stdout, stderr, exit
   code and every file created. Differences go to one fixer bee, at most two rounds.
8. **Verdict.** Code computes it: **accepted** only if the program links, every module is
   accepted by its council, no function is a stub, the checker rejected no claim and every
   conformance case is identical. Without `--run-original` the best verdict is
   **accepted without behaviour proof**.

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

## Safety

- Bees read text that comes from untrusted binaries. No bee has a shell, the web or the ability to
  start other agents. Each bee runs with Claude Code's `dontAsk` permission mode and file rules
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

Run the same command again with the same `--out` to resume: the survey and the modules that a
council already decided are kept.

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

- C output only; C++, Objective-C, Swift, Go and Rust programs are not handled specially.
- Packed or obfuscated programs are not detected yet.
- Rebuilt code follows Ghidra's and the agents' reading of the assembly. It is not the original
  source, and conformance cases show equal behaviour only on the cases run.
