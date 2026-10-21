# ReverseAI contract (reverseai.contract/3)

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
  `ghidra_sha256`, `jdk_sha256`; `wheel_sha256` is absent. Adapter `12.1.4-r2` (function span, decision `m3a-function-span`).
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
    (ties by lower entry), `decompile` in all, text cut at `max_chars`
    characters and, when needed, to the longest prefix whose observation value
    fits 4,096 bytes (`truncated` true when cut; decision `m3c-pseudocode-fit`);
  - `{"kind": "call", "from", "to", "to_name"}` at the call instruction's bytes.
  `name`/`to_name` are at most 128 printable characters. Values are virtual
  addresses; the host maps each anchor through its own section table and refuses
  an observation whose anchor is not inside an executable section.
  A function's `size` is its span: from `entry` to the last byte of its body,
  so a body with gaps keeps the calls in its later ranges; a call's instruction
  must lie inside the span of the function named by `from`. Section tables
  count only what is mapped from the file: ELF sections with `SHF_ALLOC`, and
  for PE the first `min(SizeOfRawData, VirtualSize)` bytes (`SizeOfRawData`
  when `VirtualSize` is 0). Decision `m3a-function-span`.
- **Claims** (all `inferred`, all derived): `code.functions` = names in index
  order; `code.pseudocode` = `{"entry", "text", "truncated"}` for one function
  (one finding per decompiled function); `code.calls` = sorted unique
  `[from, to_name]` pairs.

## Mach-O and imports on the host (M3b)

Host tools stay in-process and standard-library only; their observations are
verified evidence (not derived), as in M1.

- **Mach-O decoding** in `reverseai/tools/structure.py`: thin 32- and 64-bit
  little-endian Mach-O (`0xfeedface`, `0xfeedfacf`) is decoded; big-endian thin
  files and universal (fat) files (`0xcafebabe`, `0xcafebabf`) are identified
  only: `structure.identify` reports `format` `macho` or `macho-universal`, and
  for universal files an `architectures` list of at most 8 machine names.
  `structure.headers` gives `{"structure": "macho", "format": "macho",
  "machine_name", "filetype", "ncmds", "number_of_sections"}` at the Mach-O header
  (28 or 32 bytes); `structure.sections` gives one observation per section of
  every `LC_SEGMENT`/`LC_SEGMENT_64`, `{"index", "name" ("<segname>,<sectname>"),
  "offset", "size", "writable", "executable"}` at the section header (68 or 80
  bytes); `executable` is the segment's `initprot` execute bit or a section
  instruction attribute (`S_ATTR_PURE_INSTRUCTIONS`, `S_ATTR_SOME_INSTRUCTIONS`),
  `writable` the segment's `initprot` write bit. The existing format, machine,
  section-count and writable-executable claims apply unchanged. A public helper
  `macho_sections(data)` returns the same section rows plus `addr` for other host
  code (the Ghidra anchor check).
- **Imports**: new operation `structure.imports`, arg `max_imports` int 1..256
  default 128, at most 256 observations, for ELF (`DT_NEEDED` libraries and
  undefined dynamic symbols), PE (import directory: DLL names and imported names or
  ordinals as `#<n>`) and thin Mach-O (`LC_LOAD_DYLIB`/`LC_LOAD_WEAK_DYLIB` paths,
  and since M3c `LC_REEXPORT_DYLIB`, `LC_LAZY_LOAD_DYLIB` and `LC_LOAD_UPWARD_DYLIB`
  through the same dylib command layout, and undefined symbols from `LC_SYMTAB`).
  Little-endian fat magics are not universal (M3c). Observations:
  `{"kind": "library", "name"}` at the bytes of that name, and
  `{"kind": "symbols", "library": <name or null>, "names": [at most 32]}` at the
  bytes of the first name in the group. Names are at most 128 printable
  characters, escaped as section names are. Malformed tables are cut, never read
  past the input.
- **Claims** (observed, verified): `imports.libraries` = sorted unique library
  names of the cited `library` observations; `imports.symbols` = sorted unique
  names of the cited `symbols` observations. One finding each.
- **Ghidra on Mach-O (M3b)**: the worker accepts thin Mach-O; the host maps
  Ghidra anchors through `macho_sections` (an anchor must lie inside an executable
  section's file bytes). Adapter `12.1.4-r4` (decision `m3b-fix-round`).

## Assembly, references and referenced strings (M3c)

The same single `ghidra.analyze` run (one container, same resource profile and
wall limit) reports three more derived kinds. Adapter `12.1.4-r5`. Decision
`m3c-contract`.

- **New args** (all ints, defaults when absent): `assembly` 0..8 default 4,
  `max_instructions` 1..64 default 32, `max_refs` 0..128 default 64,
  `max_strings` 0..64 default 32. At most 600 observations (the sum of every
  kind's maximum). The reply limit stays 262,144 bytes: the M3a kinds are
  emitted as before, then `assembly`, `ref` and `string` observations in that
  order, each added only while the encoded reply stays within the limit; an
  observation is never cut, and a reply at every maximum is never refused for
  its size.
- `{"kind": "assembly", "index", "entry", "instructions", "truncated"}` at the
  same anchor as function `index` (equal location and entry), for `assembly`
  functions chosen in the pseudocode order (entry-point function first, then the
  largest, ties by lower entry): a subset of that selection in that order, each
  function at most once (a listing that fails or does not fit the reply is
  omitted, as pseudocode may be). `instructions` is a non-empty
  list of at most `max_instructions` `[delta, length, text]` rows in address
  order from the entry: `delta` the instruction's offset from the entry,
  `length` 1..16, rows non-overlapping (`delta + length` at most the next
  `delta`) and inside the anchor (`delta + length` at most the location
  length); `text` 1..64 printable ASCII characters, the instruction as Ghidra
  prints it. Only instructions wholly inside the anchor are listed; the worker
  confirms each one's bytes against the snapshot. `truncated` is true when the
  function has instructions that were not listed (cut by `max_instructions`, by
  the anchor's end or by the 4,096-byte observation limit).
- `{"kind": "ref", "from", "to", "type", "to_name"}` at the referencing
  instruction's bytes (1..16 bytes inside an executable section and inside the
  span of the function whose entry is `from`, as for `call`). `type` is one of
  `read`, `write`, `read_write`, `data` (any other data reference, such as an
  address taken) and `jump` (a jump to an address outside the function's body);
  calls stay `call`, including a jump Ghidra reads as a tail call (flow type
  call-terminator, decision `m3c-tail-call`), and flow inside the function's
  body is not reported. `to`
  is a virtual address that may lie outside the file (zero-fill, external,
  unresolved); `to_name` at most 128 printable characters, empty when Ghidra has
  no symbol there. Rows are unique, sorted by (instruction file offset, `to`,
  `type`), at most `max_refs`.
- `{"kind": "string", "address", "encoding", "text", "truncated", "from"}` at
  the string's own bytes, for distinct `to` addresses of the reply's `ref`
  observations whose target bytes hold a string under this fixed rule, which the
  host re-derives from the snapshot: `ascii` when 2..128 bytes in 0x20..0x7e
  start at the target, else `utf-16le` when 2..128 code units `XX 00` with `XX`
  in 0x20..0x7e do; `ascii` wins whenever its whole rule holds. `truncated` is
  true only when the run reaches 128 characters and the next character still
  matches inside the same section's file bytes (no terminator is then needed);
  otherwise a terminator (one zero byte, or two for `utf-16le`) must follow there. The location is exactly the encoded `text`
  (terminator excluded); it and its terminator lie inside one section's file
  bytes (executable or not: ELF `SHF_ALLOC` sections that are not `SHT_NOBITS`,
  PE raw data within the mapped extent, Mach-O sections that are not zero-fill),
  and that section maps the location to `address`. `from` is the sorted unique
  `from` values of the reply's `ref` observations whose `to` is `address`, the
  lowest 8 when there are more, never empty. Sorted by `address`, unique, at
  most `max_strings`.
- **Host check** (`reverseai/tools/ghidra_verify.py`): the rules above, every
  string re-derived from the bytes (text, encoding, terminator or truncation,
  section, address) and every `from` list recomputed from the reply's `ref`
  rows; any violation refuses the whole reply, as in M3a. Instruction texts,
  reference types, targets and names remain Ghidra's reading.
- **Claims** (all `inferred`, all derived, in `DERIVED_CLAIMS`):
  `code.assembly` = `{"entry", "instructions", "truncated"}` for one function
  (one finding per disassembled function); `code.references` = sorted unique
  `[from, type, to, to_name]` rows; `code.strings` = the cited string
  observations as `{"address", "encoding", "text", "truncated", "from"}`, one per
  address, in address order. A string's bytes are re-read by the host, yet the
  finding stays derived: that code references the string is Ghidra's reading.
- **Imports claim bounds** (decision `m3b-deferred-to-m3c`, R3-P): the
  `imports.*` rules refuse a symbols group of more than 32 names and any name that
  is empty, longer than 128 characters or not printable.

## Targeted queries (M3d)

M3d answers one question at a time, by name, address or text, with paging, next
to the whole-file `analyze` run. The query names are REA Safe Agent's 16 native
query names, so M7 can compare them one by one. Decision `m3d-contract`.

- **Command**: `python3 -m reverseai query FILE --query NAME [--arg KEY=VALUE ...]
  --out DIR [--with-ghidra]`. NAME is one of the closed table below
  (`reverseai/queries.py`); each `--arg` key must be one the query accepts and its
  value is checked by the operation's `ArgSpec` (integers in decimal or `0x` hex);
  anything else is refused before the input is read. A query runs its fixed
  operations through the same intake, gateway, budgets and reviewer as `analyze`
  and writes the same report files; the report adds `"query": {"name", "args"}`
  (JSON) and a line naming the query and its arguments (Markdown). A Ghidra query
  without `--with-ghidra`, or without the Ghidra image, exits 1 cleanly.
- **Paging**: list operations take `start` (0-based) and `limit`. Every row
  carries `index` (its place in the operation's full, deterministic order) and
  `total` (rows in that order). A page holds rows `start..start+n-1`; when
  `start+n < total` the report says so and gives the next `start`. A row missing
  from a page is never evidence that it does not exist. List claims have the
  value `{"start", "total", "rows"}`: indexes contiguous from `start`, one `total`,
  rows in index order; an empty page makes no finding. A long page is split into
  findings of at most 64 citations, each a contiguous page; the reviewer compares
  verified pages of one list row by row, within the task (one query and its
  arguments) that produced them, so they contradict only by a different `total`
  or a different row at the same index (decision `m3d-seams-paging`); results of
  different queries are never compared as one list. `bytes.read` is checked against
  its own cited bytes and offset, so two readings never contradict; string rows
  must sit at their cited offset and hold printable ASCII (decision `m3d-fix-round`).

| Query | Operations (fixed arguments) | Accepted `--arg` keys |
| --- | --- | --- |
| `binary_overview` | `structure.identify`, `.headers`, `.sections`, `.imports`, `.entry` | none |
| `list_segments` | `structure.segments` | `start`, `limit` |
| `inspect_native_load_image` | `structure.segments`, `structure.entry` | `start`, `limit` |
| `list_names` | `structure.symbols` | `query`, `start`, `limit` |
| `read_bytes` | `structure.read_bytes` | `mode`, `at`, `length` |
| `list_strings` | `strings.list` | `encoding`, `min_length`, `start`, `limit` |
| `search_strings` | `strings.search` | `query`, `encoding`, `start`, `limit` |
| `list_procedures` | `ghidra.functions` (`query` "") | `start`, `limit` |
| `search_procedures` | `ghidra.functions` | `query`, `start`, `limit` |
| `procedure_info` | `ghidra.function` (`parts` info) | `select`, `entry`, `name` |
| `procedure_pseudo_code` | `ghidra.function` (`parts` pseudocode) | `select`, `entry`, `name`, `max_chars` |
| `procedure_assembly` | `ghidra.function` (`parts` assembly) | `select`, `entry`, `name`, `start`, `limit` |
| `procedure_callees` | `ghidra.function` (`parts` callees) | `select`, `entry`, `name`, `max_calls` |
| `procedure_callers` | `ghidra.function` (`parts` callers) | `select`, `entry`, `name`, `max_calls` |
| `analyze_function` | `ghidra.function` (`parts` all) | every `ghidra.function` key except `parts` |
| `xrefs` | `ghidra.xrefs` | `address`, `start`, `limit` |

### Host operations (verified, in-process, stdlib)

Search text is the `ArgSpec` kind `literal`: a bounded number of printable
characters that may contain `/` or start with `-`. Only in-process tools may
declare it (a contained `ToolSpec` refuses one), so Ghidra's `query` and `name`
keep the `str` rule (no `/`, `\`, leading `-`, at most 256 characters).

Rows are re-derived by the host from the bytes, as in M1; names are escaped and
cut as section and import names are (at most 128 printable characters). A table
walk reads at most 65,536 entries in all; a file whose otherwise valid tables
need more is refused (`StructureError`, no observation), so `total` is never a
count cut short. Malformed or truncated tables keep their valid prefix.
`structure.file_sections(data)` is a public helper: the file-backed sections of
ELF (`SHF_ALLOC`, not `SHT_NOBITS`), PE (raw data within `min(SizeOfRawData,
VirtualSize)`, `SizeOfRawData` when `VirtualSize` is 0) and thin Mach-O (not
zero-fill) as `{"name", "address", "offset", "size", "executable"}` rows.

- `structure.segments`: args `start` 0..65535 default 0, `limit` 1..256 default
  64. One row per ELF program header, PE section header or Mach-O
  `LC_SEGMENT`/`LC_SEGMENT_64`, in file order: `{"kind": "segment", "index",
  "total", "name", "offset", "filesz", "address", "memsz", "readable", "writable",
  "executable"}` at the declaring header (32/56, 40 or 56/72 bytes). ELF `name` is
  the program header type (`LOAD`, `DYNAMIC`, `INTERP`, `NOTE`, `PHDR`, `TLS`,
  `GNU_STACK`, `GNU_RELRO`, `GNU_EH_FRAME`, else `0x` hex) and the permissions
  are `PF_R/W/X`; PE `address` is `ImageBase + VirtualAddress`, `memsz`
  `VirtualSize`, `offset`/`filesz` the raw data, permissions from
  `IMAGE_SCN_MEM_*`; Mach-O uses `segname`, `fileoff`, `filesize`, `vmaddr`,
  `vmsize`, `initprot`. Claim `segments.list` (observed) rows
  `[name, offset, filesz, address, memsz, readable, writable, executable]`.
- `structure.entry`: no args, at most 1 observation: `{"kind": "entry",
  "address", "offset"}` at the field that declares it (ELF `e_entry`, PE
  `AddressOfEntryPoint`, Mach-O `LC_MAIN` `entryoff` or the `LC_UNIXTHREAD` pc);
  `address` virtual (PE `ImageBase` + RVA; Mach-O `__TEXT` `vmaddr` + `entryoff`),
  `offset` the file offset it maps to through `file_sections`, else null. No
  observation when the file declares none (ELF `e_entry` 0). Claim `load.entry`
  (observed) = `{"address", "offset"}`.
- `structure.symbols`: args `query` literal 0..128 default "" (case-sensitive
  substring of the name; "" lists all), `start` 0..1048575 default 0, `limit` 1..256 default
  128. Rows in table order: ELF `.symtab`, or `.dynsym` when there is no
  `.symtab`, without index 0, `STT_SECTION` and `STT_FILE`; Mach-O `LC_SYMTAB`
  without stab entries; PE export names. Empty names are skipped. `{"kind":
  "symbol", "index", "total", "name", "address", "type", "binding", "defined"}` at
  the name's bytes; `type` ELF `func`, `object`, `notype`, `tls`, `common`,
  `ifunc` or `other`, Mach-O `symbol`, PE `export`; `binding` `local`, `global`,
  `weak` or `other` (Mach-O external is `global`, PE `global`); `defined` bool.
  Claim `symbols.list` (observed) rows `[name, address, type, binding, defined]`.
- `structure.read_bytes`: args `mode` enum `offset`|`address` default `offset`,
  `at` int 0..2^64-1 default 0, `length` 1..2000 default 256 (the hex must fit the
  4,096-byte observation limit); at most 1 observation. `offset`: bytes `[at, min(at + length, size))`, none when `at` is at
  or past the end. `address`: `at` must map into exactly one `file_sections` row;
  the range is cut at that row's file end; none otherwise. `{"kind": "bytes",
  "offset", "address", "hex"}` at exactly those bytes; `address` is the virtual
  address when the offset lies in exactly one file-backed section, else null;
  `hex` lowercase. Claim `bytes.read` (observed) = `{"offset", "address", "hex"}`;
  the reviewer also checks that `hex` decodes to bytes whose SHA-256 is the cited
  evidence's excerpt hash.
- `strings.list`: args `encoding` enum `any`|`ascii`|`utf16le` default `any`,
  `min_length` 4..64 default 6, `start` 0..1048575 default 0, `limit` 1..256
  default 128. The printable runs of `strings.extract` (ASCII, UTF-16LE), merged
  in offset order (ASCII first on ties): `{"kind": "string", "index", "total",
  "offset", "encoding", "text", "truncated"}` at the run's bytes (at most 4,096),
  `text` at most 256 characters, `truncated` when longer. Claim `strings.listed`
  (observed) rows `[offset, encoding, text, truncated]`; for an untruncated row
  the reviewer checks that the encoded text is exactly the cited bytes.
- `strings.search`: args `query` literal 1..128, `encoding` and `start` as
  `strings.list`, `limit` 1..256 default 64. The `strings.list` runs (minimum
  length 4) whose full text contains `query` (case-sensitive), same rows and
  order, `total` counting matches. Claim `strings.matches` (observed), same rows
  and checks as `strings.listed`.

### Ghidra operations (derived, contained)

Same image, resource profile and wall limit as M3a; adapter `12.1.4-r6`. The
query script takes a fixed mode argument; requests still cannot choose scripts
or options. Each operation is one container run (one import and analysis).
Rows are added only while the encoded reply fits 262,144 bytes; an observation
is never cut. Anchors follow the M3a rules (a function's first bytes, at most
4,096, inside an executable section; an instruction's 1..16 bytes).

- `ghidra.functions`: args `query` str default "", `start` 0..65535 default 0,
  `limit` 1..128 default 64; at most 128 observations. File-backed, executable,
  non-external functions in address order whose name contains `query`:
  `{"kind": "function_row", "index", "total", "name", "entry", "size"}` at the
  function's anchor. Claim `code.function_list` (derived) rows
  `[name, entry, size]`.
- `ghidra.function`: args `select` enum `entry`|`name` default `entry`, `entry`
  int 0..2^64-1 default 0, `name` str default "", `parts` enum
  `info`|`pseudocode`|`assembly`|`callees`|`callers`|`all` default `all`, `start`
  0..65535 default 0, `limit` 1..256 default 64, `max_chars` 64..2048 default
  1024, `max_calls` 0..256 default 64, `max_refs` 0..128 default 64; at most 643
  observations (1 + 1 + 1 + 256 + 256 + 128, every part at its maximum). The target is the function whose entry is `entry`, or the
  lowest-entry function named exactly `name`; no observation when there is none.
  - always `{"kind": "target", "name", "entry", "size", "matches", "callers_total",
    "callees_total"}` at the function's anchor (`matches`: functions with that name,
    1 for `select` entry); claim `code.function_info` (derived) = the value
    without `kind`;
  - `pseudocode` or `all`: one M3a `pseudocode` observation (index 0), claim
    `code.pseudocode`;
  - `assembly` or `all`: `{"kind": "instructions", "entry", "start", "total",
    "rows", "truncated"}` at the bytes from the first listed instruction to the
    end of the last (at most 4,096); `rows` at most `limit` M3c rows `[delta,
    length, text]`, `delta` from `entry`, inside the function's span; `total` the
    function's instruction count; `truncated` when the anchor or observation limit
    stopped the page before `limit`; claim `code.instructions` = the value without
    `kind`, and the reviewer checks the cited location starts at the first row and
    ends at the last row's end;
  - `callees` or `all`: M3a `call` rows from the target (`from` = target entry),
    at most `max_calls`, claim `code.calls`;
  - `callers` or `all`: `{"kind": "caller", "at", "from", "to"}` at each call
    instruction in file-backed executable code whose target is the target's entry,
    in address order, at most `max_calls`; `at` the instruction's virtual address,
    `from` the containing function's entry or null, `to` the target entry; claim
    `code.callers` = `{"to", "rows": [[at, from], ...]}` in `at` order;
  - `all` only: M3c `ref` rows from the target, at most `max_refs`, claim
    `code.references`.
- `ghidra.xrefs`: args `address` int 0..2^64-1 (required), `start` 0..65535
  default 0, `limit` 1..256 default 64; at most 256 observations. Every reference
  to `address` from an instruction in file-backed executable code, in instruction
  address order: `{"kind": "xref", "index", "total", "at", "from", "to", "type"}`
  at the instruction's bytes; `type` `call` (tail calls included), `jump`, `read`,
  `write`, `read_write` or `data`; `from` the containing function's entry or null;
  `to` equals `address` (also when `address` has no file bytes). Claim
  `code.xrefs` (derived) = `{"to", "start", "total", "rows": [[at, from, type], ...]}`.
- **Counts**: `total`, `callers_total` and `callees_total` count the rows that pass
  the worker's anchor checks. Instructions are indexed from the entry in address
  order (a body chunk before the entry is not listed). A run that would count more
  than 65,536 callers, callees, xrefs or functions, or more than 1,000,000
  instructions in one function, fails with a fixed error instead of reporting a
  total cut short; these query counts never reuse `ghidra.analyze`'s emission caps
  (decision `m3d-fix-round`). `callers_total` and `callees_total` count call
  instructions (each once), as the `caller` and `call` rows do. `ghidra.xrefs` rows
  are ordered by `at`, then `type` (ASCII order); one instruction may give several
  rows of different types, never two of the same type. An `instructions` page is
  `truncated` exactly when it holds fewer than `limit` rows and
  `start + len(rows) < total`; no `instructions` observation when `start` is at or
  past `total`.
- **Host check** (`ghidra_verify`): per mode, exact field sets and types, anchors
  as above (an instruction's `at` must be the virtual address its offset maps to;
  `to` the target entry or `address`), indexes contiguous from `start`, one
  `total`, counts within `limit`/`max_*`; any violation refuses the whole reply.
  `analyze` keeps `ghidra.analyze` unchanged.
- All `code.*` claims stay in `DERIVED_CLAIMS` (every claim whose operations are
  all `ghidra.*`).

## Child artifacts and Android packages (M4a, contract/3)

M4a reads Android packages on the host, stdlib only: the ZIP container, the binary
manifest and the DEX files, all verified evidence. Decompiled Java (JADX) is M4b
and needs an owner-approved download. Decision `m4a-contract`.

- **Child artifacts** (`reverseai.contract/3`): an observation may name an
  `artifact`, a member stored or deflated inside the input:
  `{"member", "method" (0 stored or 8 deflate), "data_offset", "compressed_size",
  "size", "crc32", "sha256"}`. Its location and excerpt hash are then inside the
  child's bytes. `contract.materialize(data, artifact)` re-derives the child from
  the input: the compressed range inside the input, raw deflate inflated to
  exactly `size` with nothing left over, CRC-32 and SHA-256 equal; at most 32 MiB
  per child and 100:1 expansion; stored members have equal sizes. The gateway
  materializes each child once per operation (at most 128 MiB of distinct
  children, else `budget_exceeded`); the reviewer re-materializes it independently
  once per review (same budget, each distinct child charged at its declared size
  before it is inflated, so a child that fails still spends it; decision
  `m4a-fix-round-2`) and refuses evidence whose child does not match the input. Evidence without an artifact keeps its contract/2 ID and meaning.
  Worker replies (contained tools) cannot name artifacts yet.
- **Tools** `apk` 0.1.0 and `dex` 0.1.0 (in-process): `reverseai/tools/apk.py` (ZIP,
  manifest; operations `apk.*`) and `reverseai/tools/dex.py` (DEX; operations
  `dex.*`). `apk` inflates members with its own bounded inflater (same limits,
  equivalence tested) and `dex` takes its children from `apk`; the gateway and
  the reviewer re-derive every child independently with `contract.materialize`. Limits: input at most 64 MiB (intake), at most
  2,048 members, methods 0 and 8 only; encrypted members, ZIP64, multi-disk
  archives, duplicate or traversing names, and local headers or data descriptors
  that disagree with the central directory are refused or flagged; DEX versions
  035, 037, 038 and 039 (036 was never released) in little-endian order with a
  right checksum and signature; at most 65,536 type, proto, field, method and
  class entries per DEX and 1,048,576 string entries (strings decoded only when
  used, each scan at most 65,536 bytes), at most 262,144 `class_data` and
  `type_list` entries in all per DEX; references decoded as a stream, never a
  list of every instruction; the code decoded for one DEX, aliased code items
  included, at most the DEX's size (decision `m4a-seams-x2`); at most 128 MiB of
  decoded strings per operation, re-decodes included (`m4a-seams-x3`); a DEX past these limits is refused with a fixed
  error, never cut to a total that looks complete. ZIP tables keep their valid
  prefix when malformed, never read past the buffer. Member names are escaped as import names (at most 255 printable
  characters); DEX strings are decoded from MUTF-8 and escaped the same way (at
  most 256 characters, `truncated` when longer). Every literal selector of a `dex.*`
  operation (`member`, `query`, `class`, `method`, `prototype`) is compared with
  the escaped text the rows show, never the raw decoded text, so a displayed
  identity can always be copied back (decision `m4a-fix-round-2`).
- `apk.inventory`: args `start` 0..65535 default 0, `limit` 1..256 default 128.
  Central directory entries in order: `{"kind": "member", "index", "total",
  "name", "method", "compressed_size", "size", "crc32", "sha256", "flags"}` at the
  central directory entry (at most 4,096 bytes, in the input itself); `sha256` is
  the materialized child's hash, or null when the member cannot be materialized;
  `flags` a sorted list of refusal reasons (`crc`, `duplicate_name`, `encrypted`,
  `header_mismatch`, `long_name`, `ratio`, `symlink`, `too_large`, `traversing_name`,
  `unsupported_method`), empty when clean; `long_name` marks an escaped name longer than 255
  characters, listed as its first 255 escaped characters and never materialized; `crc` covers every failed
  materialization (CRC, inflate, size or trailing data); a flagged member is listed but never
  materialized; an empty name is listed only with `traversing_name`. The whole archive is refused (no observation) for ZIP64, multiple
  disks, an ambiguous end of central directory or bytes before the first local
  header other than none; an APK signing block between the last member and the
  central directory is allowed. Manifest decoding is bounded too: XML depth 256,
  at most 65,536 chunks, attributes and string entries in all, and 32 MiB of
  decoded strings (decision `m4a-seams-z`). Claim `android.members` (observed) page rows
  `[name, method, compressed_size, size, crc32, sha256, flags]`.
- `apk.manifest`: args `start` 0..65535 default 0, `limit` 1..256 default 256.
  The attributes of `AndroidManifest.xml` in document order, each
  `{"kind": "manifest_attribute", "index", "total", "element_index", "element",
  "attribute", "type", "value"}` at its 20-byte attribute record inside the child
  (artifact = that member). `element_index` counts start tags from 0, `element`
  is the tag name, `attribute` the name with `android:` when in the Android
  namespace, `type` one of `string`, `int`, `bool`, `reference`, `other`, and
  `value` a string (`string`; `reference` as `@0x7f...`; `other` as `0x` hex), an
  int or a bool. Claims (observed): `android.manifest` page rows `[element_index,
  element, attribute, type, value]`; `android.permissions` = sorted unique values
  of the cited `uses-permission` (and `uses-permission-sdk-23`) `android:name`
  string attributes; more than 64 are split into several findings, each a subset,
  which never contradict each other (decision `m4a-fix-round`).
- `dex.classes`: args `member` literal 0..255 default "" (one DEX member by name;
  "" for every `classes*.dex` member in central directory order), `query` literal
  0..128 default "" (substring of the class descriptor), `class` literal 0..255
  default "" (when set, exactly that descriptor and `query` must be ""; decision
  `m4a-fix-round`), `start` 0..1048575 default 0, `limit` 1..256 default 128. `{"kind": "class", "index", "total",
  "dex", "name", "access", "superclass", "interfaces", "interfaces_total",
  "source_file"}` at the
  32-byte `class_def_item` inside the DEX child; `dex` is the member name,
  `name` and `superclass` descriptors (`superclass` null for none), `interfaces`
  the leading declared interfaces while the observation stays within 4,096
  bytes, `interfaces_total` the declared count (at most 64, else the operation
  fails; decision `m4a-fix-round-2`), `source_file` or null ("" is a valid DEX
  value), `access` the flags as an int.
  Claim `android.classes` (observed) page rows `[dex, name, access, superclass]`.
- `dex.methods`: args `member` literal 0..255 default "" (as `dex.classes`: ""
  selects every `classes*.dex` member, and a class defined in several members
  lists each member's methods in member order; decision `m4a-seams-x4`),
  `class` literal 1..255 (exact descriptor), `start` 0..65535 default 0, `limit`
  1..256 default 128. The class's direct then virtual methods in `class_data`
  order: `{"kind": "method", "index", "total", "dex", "class", "name",
  "prototype", "access", "code_offset", "code_units"}` at the 8-byte
  `method_id_item`; `prototype` as `(params)return` descriptors, `code_offset`
  and `code_units` null without code. Claim `android.methods` (observed) page
  rows `[dex, class, name, prototype, access, code_offset, code_units]`.
- `dex.references`: args `member` literal 0..255 default "" (as `dex.classes`),
  `class` literal 1..255, `method` literal 1..255, `prototype` literal 0..255
  default "" (exact; "" for every overload), `direction` enum `from`|`to` default
  `from`, `start` 0..65535 default 0, `limit` 1..256 default 128. `from`: the
  references the method's code makes, in code order; `to`: every instruction in
  the selected DEX members that references the method, in member and code order.
  `{"kind": "dex_ref", "index", "total", "dex", "from_class", "from_method",
  "from_prototype", "at", "ref_kind", "target", "target_truncated"}` at the
  instruction's code units inside the DEX child; `at` the instruction's offset
  inside the child; `ref_kind` `method`, `field`, `string` or `type`; `target`
  `Lcls;->name(params)ret`, `Lcls;->name:Type`, the string or a type descriptor.
  Only a string literal is cut (escaped, at 256 characters, `target_truncated`
  true); an identity (descriptor, name, prototype, member) longer than 255
  escaped characters, or a composed target longer than 512, fails the operation
  with a fixed error rather than an ambiguous cut (decision `m4a-seams-x`). Only references decoded from complete, valid instructions count;
  a method whose code cannot be decoded gives no rows and the run fails with a
  fixed error rather than a total cut short. Claim `android.references`
  (observed) page rows `[dex, from_class, from_method, from_prototype, at,
  ref_kind, target, target_truncated]`.
- These are declarations in the bytes: a reference in code is not evidence that
  it runs, and a permission declared is not evidence that it is used.
- **Queries** (`reverseai/queries.py`), REA's Android names: `inspect_android_package`
  (`apk.inventory`, `apk.manifest`), `search_android_classes` (`dex.classes`),
  `inspect_android_class` (`dex.classes` with the exact `class`, `dex.methods`), `inspect_android_method` (`dex.methods`, `dex.references`
  `from`; decompiled Java comes with M4b), `trace_android_references`
  (`dex.references`; `direction` from the arguments).

## Decompiled Java through JADX (M4b, contract/3)

Decisions `owner-next-m4b`, `m4b-contract`. JADX reads the package as data; its
Java is the decompiler's reading, kept **derived** like Ghidra's pseudocode.

- **Image**: `containers/jadx/`, linux/arm64, built from the pinned
  `python:3.12-slim` base with JADX 1.5.6 (`jadx-1.5.6.zip`, `545ea2be...8974`,
  the one approved download) and the JDK bytes already approved for Ghidra
  (Temurin 21.0.12.1+1, `23e37e02...e223`); a fixed driver is compiled at build
  time against the bundled `jadx-1.5.6-all.jar` (`fe3e12c4...554b`, its Apache-2.0
  LICENSE kept with it). Lock keys: `adapter_version` `1.5.6-r1`, `platform`,
  `base_digest`, `jadx_zip_sha256`, `jadx_jar_sha256`, `jdk_sha256`,
  `driver_sha256`, `worker_sha256`, `image_id`.
- **Resource profile** (fixed in `reverseai/contained.py`, proven by the native
  verifier): `--memory 2g --memory-swap 2g --pids-limit 256 --cpus 2
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m`, wall 120 s, JVM heap 1,536 MiB,
  one JADX thread (decision `m4b-w-plan`; measured: about 4 s and a 207 MB heap
  peak for a 21.7 MB DEX of 60,001 methods).
- **Analysis**: the host resolves the escaped selectors with `dex.py` first.
  The worker request carries the artifact of every clean `classes*.dex` member
  (central directory order, at most 16 and 128 MiB, for type resolution), the
  selected methods as targets (member, and class, name and prototype as hex of
  their raw decoded text, so no escaping or injection question reaches Java),
  `start` and `max_chars`. The worker re-materializes each member from the
  read-only snapshot into `/tmp` and refuses unless size, CRC-32 and SHA-256 equal
  the artifact; JADX reads only those DEX files, never the ZIP, with only its DEX
  input plugin, no resource decoding, no deobfuscation or renames, comments at
  WARN (no paths), no export outside `/tmp`, no option chosen by a request. JADX's
  display names appear only inside the Java text.
- **Argument kind `identity`**: 0..255 printable ASCII characters, the escaped
  form rows show. Unlike `literal`, a contained tool may declare it; its worker
  compares it as text only, never as a path, option or program.
- **Operation** `jadx.method` (derived): args `member` identity 0..255 default ""
  (as `dex.methods`: "" for every `classes*.dex` member), `class` identity
  1..255, `method` identity 1..255, `prototype` identity 0..255 default "" ("" for
  every overload), `start` int 0..1048575 default 0, `max_chars` int 64..2048
  default 1024. One observation per matched method with code, in member and
  `method_id` order, at most 16 (more fails the operation with a fixed error);
  methods without code (abstract, native) have none.
  `{"kind": "java", "dex", "class", "name", "prototype", "form", "start", "total",
  "text"}`: identities as `dex.methods` rows; `form` `java` (decompiled),
  `fallback` (JADX's fallback listing when it could not decompile), `omitted`
  (JADX by design prints no text for this method: a default constructor that
  only calls `super()`, a synthetic accessor, bridge or inlined lambda; decision
  `m4b-omitted`) or `error` (nothing produced); `omitted` and `error` have
  `text` "", `start` = `total` = 0; `total` the length in
  characters of the method's whole text; `text` its characters from `start`, at
  most `max_chars`, cut further to the longest prefix whose observation fits
  4,096 bytes. The text is printable ASCII, newline and tab only: the driver
  writes every other UTF-16 unit as a Java `\uXXXX` escape, and `start` and
  `total` count characters of that escaped text. The class declaration line JADX
  prints before a class's first method is not part of the method's text.
- **Reply and anchors**: the worker answers each target, in order, with its
  status (`ok`, `fallback`, `omitted`, `decompile_failed`, `class_not_found`,
  `method_not_found`, `no_code`), JADX's `code_offset` and `insns_count` for the
  method, `total` and `text`; a whole-run failure (`memory`, `timeout`, `input`)
  is a fixed error and fails the operation. It names no location or artifact.
  The host builds each observation itself: identities escaped from its own
  `dex.py` rows, `form` `java` for `ok`, `fallback` for `fallback`, `omitted`
  for `omitted`, `error` otherwise; it requires JADX's `code_offset` and `insns_count` to equal the
  verified `code_offset` and `code_units` of that method (for `ok` and
  `fallback`), and anchors the observation at the method's instructions (the
  `insns` of its `code_item`, at most their first 4,096 bytes) inside the
  member's child artifact. A reply for other methods, in another order, or with
  other counts fails the operation. Other statuses carry null `code_offset` and
  `insns_count`, `total` 0 and `text` "" and become `form` `error`. A `start` at
  or past the end gives an empty page at `start` = `total`. A method whose code
  has no instructions counts as without code. Any flagged `classes*.dex` member
  refuses the whole operation, as for `dex.*` (decision `m4b-host-bounds`).
- **Claim** `android.java` (inferred, derived): the observation's fields but
  `kind`, one finding per method page. It never contradicts and is never
  contradicted.
- **Queries**: `inspect_android_method` adds `jadx.method` (same `member`,
  `class`, `method`, `prototype`; `java_start`, `max_chars`) when run with
  `--with-jadx` and the locally built pinned image; without it the Java part is
  absent and the report says so. The Android selector arguments of the queries
  are `identity`, since rows show escaped identities.
- **Report**: the derived section shows each method's Java in a fenced block
  with the tool, image and page (`characters a..b of N`, next `start`).

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
