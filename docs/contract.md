# ReverseAI contract (reverseai.contract/2)

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
| `reverseai/review.py` | lane A | `review(data: bytes, input: InputRef, results: Iterable[AnalysisResult], tools: Mapping[str, ToolSpec]) -> tuple[ReviewVerdict, ...]` (tools keyed by tool name) |
| `reverseai/tools/strings.py` | lane B | `TOOL: ToolSpec` named `strings` |
| `reverseai/analysts/capability.py` | lane B | `plan`, `conclude` as above |
| `reverseai/gateway.py` | lane B | `Gateway(tools: Iterable[ToolSpec], budget: Budget)` with `run(task, data) -> AnalysisResult` |
| `reverseai/claims.py` | coordinator (contract) | `RULES` (confidence and allowed operations per claim_key), `STATEMENTS`, `check(finding, cited_evidence) -> tuple[str, ...]` reasons |
| `reverseai/contained.py` | M2a | the only path from a contained handler to its worker: stages the snapshot, runs the pinned image with fixed limits, returns its bounded stdout |
| `reverseai/tools/lief_tool.py` | M2a | `TOOL: ToolSpec` named `lief`, `contained=True`: `lief.headers`, `lief.sections` |
| `containers/lief/` | M2a | worker image definition and in-container worker; never imported on the host |
| `reverseai/pipeline.py`, `reverseai/cli.py`, `reverseai/report.py` | coordinator | integration |

## Rules every component keeps

1. **Tools only observe.** A handler receives the frozen bytes and validated
   arguments and returns `Observation`s. It never opens files, runs processes,
   uses the network or reads the environment.
   *Contained variant* (amendment to contract/1, decision `owner-m2-choices`): a
   `ToolSpec` with `contained=True` has handlers that reach one fixed, pinned
   worker image only through `reverseai/contained.py`. The worker sees one
   read-only frozen snapshot of the input and a bounded private `/tmp`; it gets no
   host path, network, Docker socket, credentials or agent input, runs as a
   non-root user with every capability dropped on a read-only root, and is
   stopped at its time, memory, CPU, process and output limits. Its stdout must
   pass `parse_worker_reply` (protocol `reverseai.worker/1`): bounded
   observations plus the digest of the snapshot it read, which must equal the
   `InputRef` hash, or an error class name. The digest is checked first, so a
   worker that could not read its snapshot (it reports the digest of no bytes)
   is refused as a snapshot mismatch, not by its error name; it still fails
   closed. Worker replies are untrusted beyond
   their schema: before any evidence is made, the host re-derives every value of
   every observation from the controller's own bytes at that observation's
   Location, with in-process decoding, and refuses the whole reply when a value
   disagrees, is missing, is unknown or cannot be re-derived. A compromised
   worker can therefore withhold evidence but never invent it. The gateway then
   makes evidence from the controller's own bytes with `make_evidence`;
   worker-supplied evidence IDs or excerpt hashes are never accepted. The controller never parses with the
   tool natively, and the sample itself is never executed. `ToolSpec.runtime`
   records the image digest and platform; the `ToolRef` version changes whenever
   the adapter, image or hidden settings change.
2. **Only the gateway makes evidence**, with `make_evidence`, so the evidence ID,
   input hash and excerpt hash are always computed the same way.
3. **The gateway refuses** an operation that is not registered, arguments that
   `OperationSpec.validate_args` rejects, and any request beyond the task or global
   `Budget`. Hitting a budget returns status `budget_exceeded` with the evidence
   gathered so far; it never raises past the pipeline. A task's `max_evidence`
   bounds the evidence returned for that task; the global budget counts each
   unique evidence item the run produces once, including items a task did not
   receive because of its own limit.
4. **De-duplication.** One `Gateway` instance is shared by all tasks of a run. An
   operation whose `operation_key` was already executed returns the stored
   evidence without calling the handler again. An execution cut short by time
   may be retried after its worker stops. Fixed observation, global evidence and
   output cuts are cached and replayed as `budget_exceeded` without invoking the
   handler again. Retries do not charge the unique-operation budget twice.
5. **Findings cite evidence.** `conclude` sees only evidence of its own task, as
   copies: the pipeline keeps the gateway's records for the result. It returns
   findings made with `make_finding`, whose ID binds every field. A finding with no evidence is
   allowed to exist, so the reviewer can reject it.
6. **The reviewer re-checks bytes.** Analyst output is untrusted. The reviewer
   checks that `len(data)` and the input hash match the `InputRef`. It resolves a
   finding's evidence IDs only inside the finding's own `AnalysisResult`. For each
   cited item it checks that the record still matches its content-bound ID
   (`evidence_intact`), recomputes the input hash, checks the tool name and version
   and that the operation is registered for that tool, checks that the location is
   inside the input and that the excerpt hash matches the frozen bytes. A finding
   that no longer matches its own ID (`finding_intact`), or that shares its ID with
   different content, is `unsupported`. A finding is also `unsupported` if any cited
   item is missing or fails, if it cites none, or if `reverseai.claims.check` finds
   that its claim_key has no rule, that its confidence differs from the rule's,
   that it cites an operation the rule does not allow, or that the citations of
   any allowed operation do not yield exactly the claimed value (a rule may allow
   several operations, for example a stdlib parser and a contained tool; each
   must agree). The reviewer
   thereby checks that a claim follows from its evidence, not only that the
   evidence exists; `contradicted` if another finding whose cited
   evidence also all verifies has the same `claim_key` and a different `value`;
   otherwise `supported`. An unsupported finding never contradicts anything, so
   a claim without valid evidence cannot cancel a verified one.
7. **Errors are short and inert.** Error and reason strings never contain input
   bytes or host paths. Reports do contain bounded text taken from the sample
   (strings, URLs, section names); it stays untrusted, and the Markdown report
   escapes it so it cannot render as HTML, links or images.
   Reports are deterministic for a given input and budget unless a shared global
   budget is exhausted; then which concurrent task received the last slots may
   vary, and the result says `budget_exceeded`.
8. **No execution.** Nothing in M1 runs the sample, installs software, opens a
   network connection or calls a model.

## Contained worker interface (M2a)

Fixed by the coordinator so the worker image and the host executor can be built
in parallel. Nothing in this interface comes from a sample, an analyst or a peer.

- **Image**: built locally from a digest-pinned base and a hash-pinned wheel;
  `containers/lief/image.lock.json` records `image_id`, `platform`
  (`linux/arm64`), `base_digest`, `wheel_sha256` and `adapter_version`. The host
  refuses to run an image whose ID differs from the lock.
- **Entrypoint**: `python3 -I -B /opt/reverseai/worker.py`, user `65534:65534`,
  no shell needed. Arguments: `<operation> <canonical JSON of validated args>`.
- **Input**: one file `/snapshot/input` (mode 0444 in a 0555 directory) on a
  read-only bind mount of a private per-run folder under
  `/Users/Shared/rea-safe-staging-501`, removed after the run. No other mount.
- **Run flags** (exact, built by `reverseai/contained.py` as an argv list):
  `docker run --rm --init --pull never --name reverseai-<random> --platform linux/arm64
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges
  --user 65534:65534 --pids-limit 64 --memory 512m --memory-swap 512m --cpus 1
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m --log-driver none
  --mount type=bind,source=<run folder>,target=/snapshot,readonly
  <image_id> <operation> <args>`.
- **Environment**: the container's environment must equal the image's; the
  verifier refuses any variable the engine injects (for example proxy settings).
- **Output**: one `reverseai.worker/1` JSON object on stdout, at most
  `MAX_WORKER_REPLY_BYTES`; stderr is discarded. Wall limit per run 45 s; on
  timeout the host kills the named container and reports `budget_exceeded`.
- **Observations**: field names follow M1 (`format`, `machine_name`, `shnum`
  with `shoff`, `number_of_sections`; section `index`, `offset`, `size`,
  `writable`, `executable`), one observation per physical structure, each
  Location inside that structure and at most 4,096 bytes.

## Contained YARA-X worker (M2b)

Same container interface, run flags, environment, reply protocol and limits as
M2a; only what differs is listed. Fixed by the coordinator before the lanes.

- **Image**: `containers/yarax/`, built locally from the same digest-pinned
  `python:3.12-slim` base and the hash-pinned wheel
  `yara_x-1.21.0-cp38-abi3-manylinux_2_28_aarch64.whl` (SHA-256
  `9bd9961b44b47dd747d526e61c703a2a8170426d003e789e7724bc7862de6d56`, owner
  decision `owner-m2b-download`). `containers/yarax/image.lock.json` records the
  M2a fields plus `ruleset_sha256`; adapter version `1.21.0-r2` (rebuilt for the 4-per-pattern cap); tool name `yarax`.
- **Ruleset**: `containers/yarax/m2_fixture_v1.json` is the only rule source:
  reviewed rules, each with an `id`, a `category` and literal byte patterns given
  as hex (4 to 256 bytes, no wildcards, jumps, regexes, modules, includes or
  external variables). The image copies this file; the worker generates YARA
  source from it, every rule with condition `any of them`, and compiles it at
  start. Compiled or serialized rules are never loaded. The host refuses to run
  when the SHA-256 of its own copy differs from the lock's `ruleset_sha256`.
- **Operation** `yarax.matches`: args `ruleset` enum `("m2_fixture_v1",)`,
  default `m2_fixture_v1`; `max_matches` int 1..64, default 32; at most 64
  observations. The worker sets a scan timeout below the 45 s wall limit and a
  per-pattern match limit of 4, and reports matches in ascending (offset, rule,
  pattern) order, cut at `max_matches`. Worker and host refuse a ruleset whose
  pattern count times 4 exceeds 64, so a `max_matches` of 64 never hides a
  matched rule (decision `m2b-per-pattern-cap`).
- **Observation**: one per match, value
  `{"ruleset": <name>, "rule": <rule id>, "pattern": <pattern id>}` at
  `Location(offset, len(pattern bytes))`.
- **Host re-derivation** (rule 1 applied to M2b): the host looks the rule and
  pattern up in its own copy of the ruleset and refuses the whole reply unless
  the value has exactly those three fields, the ruleset is the requested one,
  the Location length equals the pattern length and the input bytes at the
  Location equal the pattern bytes. Observations must be distinct and in the
  stated order. A compromised worker can hide matches but never add one.
- **Claim**: `signatures.rule_matches`, confidence `observed`, cites only
  `yarax.matches`; its value is the sorted unique rule IDs of the cited matches.
  The capability analyst plans it when the YARA-X tool is available.

## Derived evidence (contract/2, M3)

Owner decision `owner-m3-derived`. Some tools interpret code (functions,
pseudocode, calls) in ways the host cannot re-derive from the input bytes.
Contract/2 admits them as **derived** evidence, never as verified fact.

- **Declared per operation**: `OperationSpec.derived = True`. Rule 1 still
  applies to everything the host can check: for a derived operation the host
  re-derives the observation's **anchor** (its Location must be exactly the
  file range the observation names, mapped through the host's own section
  decoding, inside an executable section where the value says code) and checks
  the value's schema and bounds; the remaining fields are the tool's
  interpretation. A refusal fails the whole operation, as before.
- **Evidence records are unchanged**: the gateway still makes them with
  `make_evidence`, bound to the input bytes at the anchor, the tool, the
  operation and the exact observation value. A derived observation is always
  anchored in the input; output that cannot be anchored is not admitted.
- **Claims**: a claim rule whose operations are all derived must carry
  confidence `inferred`. A rule never mixes derived and non-derived operations.
- **Verdicts**: `VERDICT_STATUS` gains `derived`. A finding whose provenance
  and claim checks pass is `derived` (not `supported`) when any cited
  evidence comes from a derived operation; its reason says so. A derived
  finding never contradicts and is never contradicted: it is the tool's
  reading, shown with its source, not a fact that competes with verified ones.
- **Reports** list derived findings in their own section, "Derived by
  analysis tools (not verified against the bytes)", after the supported ones,
  with the tool, image and operation that produced them.
- **Roles**: `ROLES` gains `code` for the analyst that plans Ghidra operations.

## Contained Ghidra worker (M3a)

Same container interface and reply protocol as M2a; what differs:

- **Image**: `containers/ghidra/`, linux/arm64, built from the pinned
  `python:3.12-slim` base with the owner-approved downloads (`owner-m3-downloads`):
  Ghidra 12.1.4 (`ddac49f9...d4db`), Temurin JDK 21.0.12.1+1 aarch64
  (`23e37e02...e223`) and, in a build stage only, Debian `g++`/`make` to
  build the arm64 decompiler and demangler natives. Lock keys: the M2a keys plus
  `ghidra_sha256`, `jdk_sha256`; `wheel_sha256` is absent. Adapter `12.1.4-r1`.
- **Resource profile** (per tool, fixed in `reverseai/contained.py`; LIEF and
  YARA-X keep theirs): `--memory 2g --memory-swap 2g --pids-limit 256
  --cpus 2 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m`, wall limit 240 s.
  Every other run flag is the M2a flag. The native verifier proves this profile.
- **Analysis**: one headless import per run into a project under `/tmp`, fixed
  reviewed query code baked into the image, fixed analyzers: no servers, no
  debugger, no external debug-file lookup, Swift demangler off, analysis timeout
  below the wall limit. Requests cannot select scripts, loaders or options.
  M3a accepts ELF and PE; Mach-O comes with the host decoder in M3b.
- **Operation** `ghidra.analyze` (derived): args `max_functions` int 1..128
  default 64, `decompile` int 0..16 default 8, `max_chars` int 64..2048 default
  1024, `max_calls` int 0..256 default 128; at most 400 observations. One run
  returns three kinds, each anchored at its file range:
  - `{"kind": "function", "index", "name", "entry", "size"}` at the function's
    first bytes (at most 4,096), functions address-sorted, index from 0;
  - `{"kind": "pseudocode", "index", "entry", "text", "truncated"}` at the same
    anchor, for the entry-point function and then the largest functions
    (ties by lower entry), `decompile` in all, text cut at `max_chars`;
  - `{"kind": "call", "from", "to", "to_name"}` at the call instruction's bytes.
  `name`/`to_name` are at most 128 printable characters. Values are virtual
  addresses; the host maps each anchor through its own section table and refuses
  an observation whose anchor is not inside an executable section.
- **Claims** (all `inferred`, all derived): `code.functions` = names in index
  order; `code.pseudocode` = `{"entry", "text", "truncated"}` for one function
  (one finding per decompiled function); `code.calls` = sorted unique
  `[from, to_name]` pairs.

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
