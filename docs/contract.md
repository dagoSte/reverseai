# ReverseAI contract (reverseai.contract/1)

The types live in `reverseai/contract.py`. This page fixes how the M1 components
connect, so lanes can be built in parallel and joined without negotiation.
A lane that needs a change to this contract asks the coordinator; it does not edit
`contract.py`.

## Data flow

```text
approved file
  -> intake.snapshot()            frozen bytes + InputRef            (lane A)
  -> analyst.plan(InputRef)       AnalysisTask                        (lane A structural, lane B capability)
  -> Gateway.run(task, bytes)     AnalysisResult with evidence only   (lane B)
  -> analyst.conclude(task, ev)   tuple[Finding, ...]                 (lane A structural, lane B capability)
  -> review(...)                  tuple[ReviewVerdict, ...]           (lane A)
  -> report                       JSON + Markdown                     (coordinator integration)
```

## Module interfaces

| Module | Owner | Exports |
| --- | --- | --- |
| `reverseai/intake.py` | lane A | `snapshot(path) -> tuple[bytes, InputRef]` |
| `reverseai/tools/structure.py` | lane A | `TOOL: ToolSpec` named `structure` |
| `reverseai/analysts/structural.py` | lane A | `plan(InputRef) -> AnalysisTask`, `conclude(AnalysisTask, tuple[Evidence, ...]) -> tuple[Finding, ...]` |
| `reverseai/review.py` | lane A | `review(data: bytes, input: InputRef, results: Iterable[AnalysisResult], tools: Mapping[str, ToolRef]) -> tuple[ReviewVerdict, ...]` |
| `reverseai/tools/strings.py` | lane B | `TOOL: ToolSpec` named `strings` |
| `reverseai/analysts/capability.py` | lane B | `plan`, `conclude` as above |
| `reverseai/gateway.py` | lane B | `Gateway(tools: Iterable[ToolSpec], budget: Budget)` with `run(task, data) -> AnalysisResult` |
| `reverseai/pipeline.py`, `reverseai/cli.py`, `reverseai/report.py` | coordinator | integration |

## Rules every component keeps

1. **Tools only observe.** A handler receives the frozen bytes and validated
   arguments and returns `Observation`s. It never opens files, runs processes,
   uses the network or reads the environment.
2. **Only the gateway makes evidence**, with `make_evidence`, so the evidence ID,
   input hash and excerpt hash are always computed the same way.
3. **The gateway refuses** an operation that is not registered, arguments that
   `OperationSpec.validate_args` rejects, and any request beyond the task or global
   `Budget`. Hitting a budget returns status `budget_exceeded` with the evidence
   gathered so far; it never raises past the pipeline.
4. **De-duplication.** One `Gateway` instance is shared by all tasks of a run. An
   operation whose `operation_key` was already executed returns the stored
   evidence without calling the handler again.
5. **Findings cite evidence.** `conclude` sees only evidence of its own task and
   returns findings made with `make_finding`. A finding with no evidence is
   allowed to exist, so the reviewer can reject it.
6. **The reviewer re-checks bytes.** For each cited evidence item it recomputes
   the input hash, checks the tool name and version against the registered tools,
   checks that the location is inside the input and that the excerpt hash matches
   the frozen bytes. A finding is `unsupported` if any cited item is missing or
   fails, or if it cites none; `contradicted` if another finding whose cited
   evidence also all verifies has the same `claim_key` and a different `value`;
   otherwise `supported`. An unsupported finding never contradicts anything, so
   a claim without valid evidence cannot cancel a verified one.
7. **Errors are short and inert.** Error and reason strings never contain input
   bytes or host paths.
8. **No execution.** Nothing in M1 runs the sample, installs software, opens a
   network connection or calls a model.

## Known-answer fixtures

Each lane writes a deterministic generator for its own synthetic fixtures under
`tests/` and asserts the exact expected evidence and findings. Fixtures are built
from declared values in code; no binary fixture files are committed and no real
malware or third-party binaries are used.

## Proof command

```sh
python3 -B -m unittest discover -s tests -t . -v
```

Run from the repository root with Python 3.12 or later and the standard library only.
