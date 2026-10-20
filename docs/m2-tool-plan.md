# M2: contained real tools behind the evidence contract

Status: design proposal, checked on **2026-10-20**. This document authorizes no
installation, image build, runtime launch, model call or external transfer.
Only public documentation/release metadata and committed REA sources were read.
No tool archives, wheels or samples were downloaded; no tool was installed or run.

M1 establishes deterministic tasks, allowlisted operations, budgets and evidence.
M2 should first add **contained LIEF header/section inspection**, then YARA-X
literal matches; Ghidra and JADX follow after derived evidence is specified.
This ordering is a design choice, not a measured performance or safety ranking.
All limits and commands below are proposed acceptance criteria, not passed checks.

## 1. Candidate inventory and supply chain

Versions below were the upstream stable releases observed on 2026-10-20.
Use the version-specific links, not a future `latest` response, as build inputs.
Hashes below are publisher metadata, not a claim that artifact bytes were verified.
Installed sizes, linkage, execution compatibility and whole-image vulnerabilities
are **not verified** for ReverseAI. Each dependency needs its own inventory.

### Ghidra headless

- Version **12.1.4**, tag `Ghidra_12.1.4_build`, published 2026-09-21.
  Asset: `ghidra_12.1.4_PUBLIC_20260921.zip`, 569,649,598 bytes compressed.
  [Release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build),
  [release metadata](https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_12.1.4_build).
- Project license: **Apache-2.0**; bundled components need separate notices.
  [Pinned license](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/LICENSE).
- This release requires **64-bit JDK 21**; the moving development README is not
  the release's requirement. Source builds additionally list Gradle, Python and
  native build tools. Prefer the release bundle for the planned headless worker.
  [Pinned installation/build instructions](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/README.md).
- Stage the release and separately pinned JDK in an approved build-only fetch
  step. Verify Ghidra SHA-256
  `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`
  before extraction; keep the JDK's exact URL/hash in the eventual dependency lock.
  The JDK artifact and resulting image digest are **not verified** in this plan.
  [Published Ghidra digest](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build).
- Linux arm64 needs separately built decompiler/demangler natives and fresh proof;
  the release ZIP alone is insufficient. REA builds these from its verified archive;
  this is prior-project evidence, not ReverseAI support.
  [REA build/security baseline](https://github.com/dagoSte/rea-safe-agents/blob/c6f45cd27f1ed8ca774d5438d86d4b4f81c484fe/skills/rea-isolated/references/security-model.md).
- Parsing advisory **GHSA-vxmq-6v38-hgf6** describes cyclic PE unwind metadata
  causing stack overflow during import and names 12.1.4 as patched. Its broad
  affected-range field must not be read as a clean-version certification.
  [Advisory](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-vxmq-6v38-hgf6).
- **GHSA-3f3p-5h4j-gq2r** covers XML-import path traversal/local reads, patched
  in 12.1.3; **GHSA-p4ff-f27r-j8q7** covers a native decompiler heap overflow,
  patched in 12.1.3. Limit loaders and retain the process/container boundary.
  [XML advisory](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-3f3p-5h4j-gq2r),
  [decompiler advisory](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-p4ff-f27r-j8q7).
- **GHSA-c3pf-92jf-vq96** concerns Windows Swift-demangler executable lookup,
  patched in 12.1.4. **GHSA-8pr2-46mf-v2r2** names 12.2 as the debugger ISF
  server fix; the observed stable release is earlier. The proposed profile does
  not launch that server; test its absence rather than claiming all fixes landed.
  [Windows advisory](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-c3pf-92jf-vq96),
  [ISF advisory](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-8pr2-46mf-v2r2).
- Further relevant parser/analyzer advisories (upstream patched-version fields):

  | Advisory | Risk; patched release |
  | --- | --- |
  | [GHSA-pcfh-853f-q3gh](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-pcfh-853f-q3gh) | Conditional Swift-demangler code execution; 12.1.3. Disable this analyzer. |
  | [GHSA-j9qm-gxv4-62p4](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-j9qm-gxv4-62p4) | Native decompiler out-of-bounds write; 12.1.1. |
  | [GHSA-57g6-7qw2-p5hx](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-57g6-7qw2-p5hx) | External debug-file path traversal; 12.1. |
  | [GHSA-r82g-8jpp-8cfx](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-r82g-8jpp-8cfx) | ELF GNU-hash parser infinite loop; 12.1.2. |
  | [GHSA-4w7g-wmg8-fgv5](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-4w7g-wmg8-fgv5) | DB-options exception retains a lock, causing denial of service; 12.1.4. |

### JADX CLI

- Version **1.5.6**, published 2026-07-10; cross-platform asset
  `jadx-1.5.6.zip`, 72,646,741 bytes compressed. It requires a system runtime.
  [Release](https://github.com/skylot/jadx/releases/tag/v1.5.6),
  [release metadata](https://api.github.com/repos/skylot/jadx/releases/tags/v1.5.6).
- Project license: **Apache-2.0**.
  [Pinned license](https://github.com/skylot/jadx/blob/v1.5.6/LICENSE).
- Runtime: **64-bit Java 11+**; source build: JDK 17+.
  [Pinned requirements/CLI options](https://github.com/skylot/jadx/blob/v1.5.6/README.md).
  The actual default thread count is `max(1, availableProcessors()/2)`, despite
  the README help example saying 16. Fix it explicitly and disable ambient config/export.
  [Pinned JadxArgs implementation](https://github.com/skylot/jadx/blob/v1.5.6/jadx-core/src/main/java/jadx/api/JadxArgs.java).
- Stage that exact ZIP in the build-only fetch step and verify SHA-256
  `545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974`.
  Freeze bundled JARs and the Java runtime in the final image inventory.
  [Published asset digest](https://api.github.com/repos/skylot/jadx/releases/tags/v1.5.6).
- **GHSA-gpvc-ccw7-744v / CVE-2026-54684**: XAPK absolute paths can plant
  plugins for a later run; affected 1.5.2–1.5.5, patched 1.5.6. Use a fresh home
  and workspace, refuse XAPK/project/script inputs, and admit only pinned plugins.
  [Advisory](https://github.com/skylot/jadx/security/advisories/GHSA-gpvc-ccw7-744v).
- **GHSA-w6f5-h4x4-rfpj / CVE-2026-42049**: GUI Gradle-export code injection,
  patched 1.5.6; **GHSA-jwv3-q635-w9m4 / CVE-2026-42447**: summary HTML
  injection in jadx-gui, also patched 1.5.6. Do not build exports or render tool HTML.
  [Export advisory](https://github.com/skylot/jadx/security/advisories/GHSA-w6f5-h4x4-rfpj),
  [HTML advisory](https://github.com/skylot/jadx/security/advisories/GHSA-jwv3-q635-w9m4).
- The release also records XML-bomb hardening. Keep decompression, time and memory
  caps even with patched code. The direct CLI adapter is proposed; REA's MCP
  bridge is not a required dependency for ReverseAI.
  [Release fixes](https://github.com/skylot/jadx/releases/tag/v1.5.6).

### LIEF open-source core

- Version **1.0.0**, published 2026-07-12, project license **Apache-2.0**.
  This selection excludes optional LIEF Extended functionality.
  [Release](https://github.com/lief-project/LIEF/releases/tag/1.0.0),
  [pinned core license](https://github.com/lief-project/LIEF/blob/1.0.0/LICENSE).
- The Python package declares Python >=3.9 and no `Requires-Dist` entries.
  Choose a pinned CPython 3.12+ Linux worker; its native extension still requires
  architecture/libc compatibility. These wheels are tagged `manylinux_2_28`.
  [PyPI metadata](https://pypi.org/pypi/lief/1.0.0/json).
- Preferred offline inputs for that worker, verified against PyPI metadata:
  `lief-1.0.0-cp312-abi3-manylinux_2_28_x86_64.whl` (3,674,893 bytes), SHA-256
  `41ff868f5328fc8e5237a9e1f4718590e0ee9180c1422b3e4948b7116ba4517c`;
  `lief-1.0.0-cp312-abi3-manylinux_2_28_aarch64.whl` (3,604,777 bytes), SHA-256
  `a9e4b9e165bde0163624e159c8c7a096e3d6f671371c70d008baac7ac1f04f0d`.
  These are compressed package sizes, not measured RAM or installed footprints.
  [Exact wheel records](https://pypi.org/pypi/lief/1.0.0/json).
- In a future controlled image build, use a local wheelhouse, `--no-index`,
  `--only-binary=:all:`, `--require-hashes` and a requirements lock; refuse source-build
  fallback. Record both package and base-image digests. No install was run here.
- **GHSA-p84g-9fv8-52qw**: crafted ELF note sizes cause uncontrolled allocation
  before bounds checks; affects <1.0.0 and is patched in 1.0.0. Small input size
  alone cannot bound parser allocation. Keep the parser outside the controller.
  [Advisory](https://github.com/lief-project/LIEF/security/advisories/GHSA-p84g-9fv8-52qw).

### YARA-X

- Version **1.21.0**, published 2026-09-29; license **BSD-3-Clause**.
  [Release](https://github.com/VirusTotal/yara-x/releases/tag/v1.21.0),
  [license](https://github.com/VirusTotal/yara-x/blob/v1.21.0/LICENSE).
- A native CLI bundle and Python bindings are available. The Python package
  declares Python >=3.9, no `Requires-Dist` entries, and Linux abi3 wheels.
  The pinned source workspace declares Rust **1.93.0** for builds; prebuilt
  artifacts avoid a runtime Rust compiler. Full native linkage is **not verified**.
  [PyPI records](https://pypi.org/pypi/yara-x/1.21.0/json),
  [pinned workspace](https://github.com/VirusTotal/yara-x/blob/v1.21.0/Cargo.toml).
- CLI artifacts: `yara-x-v1.21.0-x86_64-unknown-linux-gnu.tar.gz`
  (10,009,639 bytes), SHA-256
  `01585181e8979e36ac10ab123fcf8921cf8ba879bf942916413e091e18d64852`;
  `yara-x-v1.21.0-aarch64-unknown-linux-gnu.tar.gz` (8,865,059 bytes), SHA-256
  `8d56947d82c7959a65fd4a7327d339d326649f6208c01c9f7fe7fd249e61c66a`.
  [Published metadata](https://api.github.com/repos/VirusTotal/yara-x/releases/tags/v1.21.0).
- Prefer the Python binding for structured match offsets in the proposed worker:
  x86_64 wheel SHA-256
  `33bc3665170e640752fed275a7ad6551079696f00d698c9433607dfc6bdd7493`;
  aarch64 wheel SHA-256
  `9bd9961b44b47dd747d526e61c703a2a8170426d003e789e7724bc7862de6d56`.
  Both are `yara_x-1.21.0-cp38-abi3-manylinux_2_28_<arch>.whl`.
  Verify exact bytes offline; use the same hash-locked wheelhouse policy as LIEF.
  [Wheel records](https://pypi.org/pypi/yara-x/1.21.0/json).
- **GHSA-2jx3-ff3v-j7jj**: unsafe deserialization of compiled rules can lead to
  memory corruption; affects <=1.18.0, patched 1.19.0. Accept only reviewed rule
  source built into the image; never load compiled rules supplied with a sample.
  [Advisory](https://github.com/VirusTotal/yara-x/security/advisories/GHSA-2jx3-ff3v-j7jj).
- Upstream exposes match offsets/lengths, scan timeouts, match limits and disabling
  rule includes. The wrapper must set those explicitly and pin its allowed modules.
  [Python API](https://virustotal.github.io/yara-x/docs/api/python/).

### Dependency review boundary

The public upstream advisory feeds were read on 2026-10-20; the observations above
are selected relevant entries, not an exhaustive vulnerability assessment of an
image, JDK, OS or all transitive packages. No exploit samples were fetched.
Before an M2 build is accepted, refresh advisories, inventory all bundled/native
dependencies, scan the exact resulting image and retain a disposition per finding.
Retain required licenses/notices; confirm redistribution scope on actual artifacts.
A matching checksum establishes bytes against the recorded source, not trust in it.

## 2. Narrow operations and evidence

Everything in this section is a proposed adapter interface. Existing M1 types are
in [contract.py](../reverseai/contract.py) and [the contract](contract.md).
Tool names below satisfy its lowercase name grammar; arguments use existing
`ArgSpec("int", minimum, maximum, default=...)` or closed `enum` choices.
Defaults are written as `default N`; omitted arguments take those defaults.
Every operation sets `max_observations`; every observation remains <=4,096 JSON
bytes and every `Location` is a nonempty, half-open range <=4,096 bytes.
Requests cannot supply flags, script bodies, executable names, host paths or URLs.

### LIEF: direct-input evidence first

| OperationSpec name | ArgSpecs; observation cap | Observation; Location |
| --- | --- | --- |
| `lief.headers` | no args; cap 3 | ELF: one physical ELF header. PE: separate DOS, signature+COFF and optional-header observations, each containing only fields in its own range. |
| `lief.sections` | `max_sections`: int 1..64, default 32; cap 64 | Section index, file offset/size and flags; physical section-header entry (ELF) or section-table record (PE); names deferred. |

First admit only ELF and PE; reject other formats, overlays interpreted as new
inputs, writes and execution-related APIs. Check every offset/size addition before
forming a range. Virtual addresses are not file offsets. Truncated headers are an
explicit error; a short/empty observation list does not mean a complete parse.
Names that live in a separate string table need their own evidence item if claimed
as directly verified bytes. Otherwise omit names in the first operation version.
For PE, the DOS observation binds `e_lfanew` at 0x3C; signature+COFF binds format,
machine and section count; the optional header binds its magic/entry fields.
Do not span the gap with one Location: `e_lfanew` may exceed 4,096. Check the
declared optional-header size before reading each field; refuse structures above
the location cap. [PE layout](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
The adapter and known-answer tests must verify semantic field decoding too;
M1's generic reviewer verifies hashes/locations, not whether a parser interpreted
a header correctly. Use fixed parsers/options; do not expose LIEF's mutation APIs.

### YARA-X: fixed rule source, bounded matches

| OperationSpec name | ArgSpecs; observation cap | Observation; Location |
| --- | --- | --- |
| `yarax.matches` | `ruleset`: enum `("m2_fixture_v1",)`, default `m2_fixture_v1`; `max_matches`: int 1..64, default 32; cap 64 | Rule/pattern IDs and match length; the nonempty matching input bytes at the reported offset, clipped visibly at 4,096. |
| `yarax.rule_metadata` | `ruleset`: same enum/default; `max_rules`: int 1..32, default 16; cap 32 | Bounded identifiers/tags/metadata of the reviewed rules; these belong to a rule artifact, not the sample, so require derived evidence. |

Only `matches` enters the first YARA-X increment. Its rules use fixed nonempty
literal/hex patterns; no includes, user globals, external rule files, serialized
rules or arbitrary regexes. Reject condition-only rules for byte-backed findings.
Rule execution by the approved engine is tool code; sample bytes are never
executed. Dynamic rule-module parsing and executable-memory needs require their
own native profile probes before enabling a broader ruleset.

### Ghidra: one import, restricted queries

| OperationSpec name | ArgSpecs; observation cap | Observation; Location |
| --- | --- | --- |
| `ghidra.functions` | `max_functions`: int 1..128, default 64; cap 128 | Stable address-sorted function inventory; analyzed identities/boundaries are derived; attach mapped input bytes separately when available. |
| `ghidra.imports` | `max_imports`: int 1..128, default 64; cap 128 | Bounded imported names/addresses; direct string/table byte ranges only with checked file mapping, otherwise derived output. |
| `ghidra.decompile` | `function_index`: int 0..127, default 0; `max_chars`: int 64..512, default 512; cap 1 | Pseudocode plus truncation/status; Location inside a bounded UTF-8 output artifact, never a fabricated input offset. |

Indices refer to a canonical address-sorted inventory of the same pinned import;
out-of-range indices fail. The image contains fixed reviewed Java query code;
requests cannot select scripts, loaders, analysis options, projects or destinations.
Disable servers, debugging, external debug-file resolution, the Swift demangler
analyzer and unneeded analyzers; verify these settings in the pinned wrapper.
Pseudocode and recovered function boundaries are inferred analysis, not source
recovery guarantees. Derived operations remain unavailable under contract/1.

### JADX: approved APK/DEX only

| OperationSpec name | ArgSpecs; observation cap | Observation; Location |
| --- | --- | --- |
| `jadx.manifest` | `max_components`: int 1..64, default 32; cap 64 | Package/permission/component items; ranges in bounded decoded manifest artifacts tied to the APK member. |
| `jadx.classes` | `max_classes`: int 1..128, default 64; cap 128 | Stable class inventory; physical DEX class records for direct DEX input, derived member ranges for compressed APK entries. |
| `jadx.decompile` | `class_index`: int 0..127, default 0; `max_chars`: int 64..512, default 512; cap 1 | Bounded source-like text and decompilation-error flag; range in derived output. |

Use fresh internal project/output names and a canonical class ordering. Reject
JAR/Class conversion, XAPK, Gradle export, saved projects and script input in this
profile. Preserve errors rather than presenting incomplete source as exact.
Archive-member paths never become host destinations; enforce member count, total
expanded bytes, per-member bytes and compression-ratio limits before extraction.

### Required contract proposals, kept out of M1

1. **Contained execution.** Rule 1 currently forbids handlers from running
   processes/opening files. Before M2 the owner selects a contract/1 amendment
   or contract/2 and records the compatibility boundary. Add a trusted-executor variant:
   the gateway adapter submits validated data to a fixed contained worker, whose
   approved executable may read only its snapshot and private workspace. The
   controller is never a native parser host. The existing prohibition on sample
   execution, arbitrary processes and agent-controlled paths remains binding.
   Workers return bounded **Observations**, status and their snapshot digest,
   never authoritative Evidence/IDs. After checking that digest against its frozen
   input, the gateway validates ranges and calls `make_evidence` on controller-held
   bytes; worker-supplied excerpt hashes or evidence IDs are not accepted.
2. **Derived evidence.** Add a discriminated artifact/derivation record containing
   root input SHA-256, parent artifact/member hash and identity, transform/tool
   version, validated operation arguments, full runtime/image identity, artifact
   byte length/SHA-256, and location plus excerpt hash in that artifact.
   Bound expansion depth/count/bytes. Retain artifact bytes and the controller's
   derivation manifest with the private report until explicit deletion; ephemeral
   execution caches cannot be their only storage. Chain authentication here means
   recomputing every parent/output hash to a root in that trusted manifest, not a
   digital signature or proof of the transform's semantic correctness.
   Recompute stored hashes/locations and rerun small deterministic transforms in
   independent checks. A tool-output digest binds an output, not its correctness.
3. Never substitute an arbitrary header byte as provenance for a decompilation,
   decoded manifest or rule metadata. Keep direct evidence compatible with M1;
   reject unknown evidence kinds. Add semantic known-answer and contradiction
   checks for derived findings before they can be marked supported.
4. Record adapter, image, architecture, options and rule digests in a versioned
   execution manifest. `ToolRef` currently names only a tool/version; require a
   new adapter version whenever hidden settings change, or extend the cache key
   contract explicitly. Do not silently reuse results across execution contexts.

## 3. Containment inheritance and fresh verification

Reviewed source revision: REA Safe Agent
`c6f45cd27f1ed8ca774d5438d86d4b4f81c484fe`. Reuse designs/code selectively with
MIT attribution; this plan copies no implementation and transfers no test badge.

| Reuse source | Inherited mechanism | ReverseAI must demonstrate again |
| --- | --- | --- |
| [input_snapshot.py](https://github.com/dagoSte/rea-safe-agents/blob/c6f45cd27f1ed8ca774d5438d86d4b4f81c484fe/skills/rea-isolated/scripts/input_snapshot.py) | Refuse symlinks/reparse points, hard links and special files; compare opened identity and stable size/timestamps; hash approved copies. | Native path/alias/race tests; changed bytes fail, added files excluded; root and every ancestor handled safely; input <=64 MiB initially. |
| [container.py](https://github.com/dagoSte/rea-safe-agents/blob/c6f45cd27f1ed8ca774d5438d86d4b4f81c484fe/skills/rea-isolated/scripts/container.py) | Local daemon, immutable local image ID, create stopped, inspect exact command/environment/resources, then attach/start; exact-ID cleanup. | Negative inspection mutations refuse startup; no tag substitution, remote daemon, unmanaged mount, injected environment or broad cleanup. |
| [agent_container.py](https://github.com/dagoSte/rea-safe-agents/blob/c6f45cd27f1ed8ca774d5438d86d4b4f81c484fe/skills/rea-isolated/scripts/agent_container.py) | Zero-mount lifecycle and bounded framing are reusable ideas; REA's Claude agent receives a subscription login and uses a provider relay. | Do not inherit login/provider transport. M2 has no agent/model role; only offline native tool workers. |
| [security-model.md](https://github.com/dagoSte/rea-safe-agents/blob/c6f45cd27f1ed8ca774d5438d86d4b4f81c484fe/skills/rea-isolated/references/security-model.md) | Non-root UID, dropped caps, no-new-privileges, read-only root, bounded tmpfs, active seccomp, trusted host/runtime. | Native in-container probes plus exact inspected configuration on each claimed platform/image/profile. |
| [Desktop hardening](https://github.com/dagoSte/rea-safe-agents/blob/c6f45cd27f1ed8ca774d5438d86d4b4f81c484fe/docs/desktop-hardening.md) | Dedicated canonical staging and optional strict saved-share policy, separate from container mounts. | Only approved disposable snapshots need sharing; saved-policy success retains `effective_vm_verified: false`. No automatic share changes/restarts. |

The initial tool worker may receive exactly one read-only mount of private frozen
copies; originals, host home, source repository, outputs and controller state are
never mounted. No agent process is part of M2. A later stdin-only
worker may eliminate the tool's input mount, but requires separate verification.
Tool workers require `network=none`, no published ports, no Docker socket/CLI,
non-root UID/GID, `cap-drop=ALL`, `no-new-privileges`, no devices and private
PID/IPC/UTS/cgroup namespaces. Seccomp must be active, not merely omitted in args.
Require read-only roots, explicit memory/CPU/PID caps and bounded writable
tmpfs with `nosuid,nodev,noexec`; approved immutable tool executables remain usable.
The following additional controls are enforced in pinned REA
[create_args/verify_container](https://github.com/dagoSte/rea-safe-agents/blob/c6f45cd27f1ed8ca774d5438d86d4b4f81c484fe/skills/rea-isolated/scripts/container.py#L262);
require them again and test each inspection rejection before startup:

| Control | Required inspected value | Negative control: reject before start |
| --- | --- | --- |
| `--log-driver=none` | `HostConfig.LogConfig.Type == "none"` | Substitute `json-file` or a remote driver; `network=none` does not constrain daemon logging. |
| Unprivileged | `HostConfig.Privileged == false` | Set true. |
| No host user namespace | `HostConfig.UsernsMode != "host"` | Set `host`. |
| `--init` | `HostConfig.Init == true` | Set false/missing. |
| `--rm` | `HostConfig.AutoRemove == true` | Set false/missing. |
| No image-declared volumes | `Config.Volumes` absent/empty, exact allowed mount list | Inject a `VOLUME` declaration or extra mount. |
| Disable extra swap | `HostConfig.MemorySwap == HostConfig.Memory == profile bytes` | Set swap to `-1` or another size. |

Probe root-write refusal, effective capabilities, seccomp, network interfaces,
denied outbound attempts, absent host sentinel/socket and allowed scratch writes.
Use inert test data and an owned local network sentinel; no Internet sample test.
JVM native helpers/JIT and YARA-X rule execution must fit the profile without
weakening it on failure. Account for native memory outside Java heap limits.
Inspect settings first, then prove enforcement with native runtime probes.

Assumptions retained explicitly: trusted host OS/controller/native Docker CLI,
daemon, kernel/hypervisor and dependency retrieval/build machinery; reviewed
wrappers, not parser output, decide authority. Shared-kernel containers are not
independent VM boundaries. Desktop saved settings do not attest live VM shares.
The pinned REA floors are historical context, not current ReverseAI runtime
approval; reassess runtime advisories before M2 deployment. Parsed data and peer
messages never authorize host actions. No model/provider egress is in this plan.
Windows Docker is an **unverified future direction**; mocks or POSIX mode bits
cannot establish native Windows path, ACL, mount, namespace or runtime behavior.
No runtime/container verification was performed during this documentation lane.

## 4. Scheduling and budgets

Continue using `Budget` and `operation_key` from [contract.py](../reverseai/contract.py).
One gateway belongs to one analysis; task limits also apply on cache replay.
The M1 semaphore bounds calls; it does not allocate memory/CPU across containers.
For M2a set concurrency **1** and one fixed LIEF profile, using the existing atomic
admission path; defer a weighted scheduler until multiple profiles can overlap.
Set both task/global wall budgets to 45 s, with at most 30 s parsing and the rest
for startup/transport/cleanup; override M1's 30 s task default explicitly. Admit
only if that remaining lifecycle allowance fits. These are unmeasured proposals:

| Worker | Memory incl. tmpfs/native | CPUs | PIDs | Tmpfs | Wall | Evidence/output |
| --- | --- | --- | --- | --- | --- | --- |
| LIEF | 512 MiB | 1 | 64 | 64 MiB | 30 s | 128 / 128 KiB |
| YARA-X | 1,024 MiB | 1 | 64 | 64 MiB | 60 s | 128 / 128 KiB |
| JADX | 2,048 MiB | 2 | 128 | 512 MiB | 120 s | 256 / 256 KiB |
| Ghidra | 4,096 MiB | 2 | 256 | 1,024 MiB | 300 s | 256 / 256 KiB |

M2a reserves only the LIEF row, with 32 operations and 128 evidence / 128 KiB output.
For later overlapping profiles, propose concurrency 2, at most one JVM worker,
5,120 MiB aggregate memory, 3 CPUs, 320 PIDs, 1,088 MiB tmpfs (Ghidra + YARA-X),
600 s wall, 32 operations, 1,024 evidence items and 1 MiB UTF-8 evidence per analysis.
Container memory includes charged tmpfs; reserve it without counting it twice.
Admit only when every aggregate cap permits it; include startup/protocol overhead.
Reserve the actual runtime/gate resource with the coordinator before testing;
do not stop unrelated containers or change Desktop sharing to meet a deadline.

Import Ghidra once per input hash **and pinned execution context**, under a shared
single-flight import lock. Queries reuse that import's private project; a new
tool/image/adapter/options/architecture identity requires a new import.
Likewise parse a DEX once per worker context and compile only pinned YARA rules.
Use `operation_key` on validated/defaulted args; include context digests in the
eventual versioned cache contract. Cache complete bound records and explicit
non-budget errors; retain partial diagnostics without serving them as cached
results to later tasks. For M2a use ephemeral, analysis-local execution caches.
Later derived evidence has separately retained private artifacts/manifests.
Restarted/failed/OOM workers cannot publish a partial artifact as a complete one.
Global counters and reservations remain atomic across concurrent task calls.

Set tool-internal timeouts below the controller's deadline; on overrun terminate
the exact owned container/process group and confirm exit/removal before releasing
its reservation. Reject late responses and preserve prior evidence/diagnostics.
A Python thread timeout alone cannot stop native parsing or reclaim memory.
Bound frames, JSON depth/items, stdout/stderr, artifact count/bytes and pending
requests before decoding; errors use fixed inert classes/codes, never raw paths.
Derived text stays untrusted in JSON, Markdown and terminal reports: escape
controls/markup and label it so hyperlinks/HTML cannot impersonate provenance.

## 5. Smallest M2 milestone and proof

Proposed M2a: one pinned LIEF worker image, `lief.headers` and `lief.sections`,
one input snapshot, direct-byte evidence, the existing reviewer/report and an
updated structural analyst. Extend its plan/tool filter for LIEF and normalize
header fields to the same values for `format.container`, `format.machine` and
`format.section_count`; group/cite only the physical observations supporting each
value. Give index-based writable/executable section lists the distinct claim key
`sections.writable_executable_indices`; do not reuse M1's name-based value without
byte-backed names. Pin normalization, exact citations and contradiction tests.
Integration points: [structural analyst](../reverseai/analysts/structural.py), [claim-key comparison](../reverseai/review.py).
Approve contained-executor contract versioning first; no derived-evidence schema
is needed while every exposed field has honest checked input-byte provenance.
Keep the host package standard-library-only and never import `lief` there.
Follow with M2b: YARA-X fixed literal/hex rules and `yarax.matches`; defer rule
metadata, decompilation, arbitrary rules and archive-derived claims.

Known-answer fixtures: generate inert ELF32/64 LE/BE and PE32/PE32+ headers and
section tables from declared integers; include a writable/executable section,
truncated headers, invalid section offsets/counts and an oversized note header.
Include PE `e_lfanew = 0x2000`: assert separate DOS/COFF/optional-header ranges,
no gap-spanning evidence, and rejection of undersized declared optional headers.
Assert exact fields, physical locations, excerpt hashes, stable evidence IDs and
review outcomes; compare relevant M1 structural values as an additional oracle.
No fixture is launched. Test malformed inputs inside the capped worker only.
YARA-X fixtures declare literal/hex and UTF-16LE markers at exact offsets, a clean
control, repeats, boundary matches and floods; assert fixed rule/pattern IDs and
offsets. A changed input/ruleset/image must miss the relevant cache.
Synthetic worker modes exercise exit, timeout, OOM, output overflow, malformed
JSON, protocol callbacks and child cleanup without real exploit downloads.

Proposed commands, **not existing tools or proofs run by this lane**:

```sh
python3 -B -m unittest discover -s tests -t . -v
python3 -B tests/verify_m2_runtime.py --tool lief --profile small --offline
python3 -B tests/verify_m2_runtime.py --tool yarax --profile small --offline
```

Implement the named verifier before claiming it exists. Its real interface must
accept explicit pinned image IDs, local context and private staging/output paths;
its receipt binds platform/architecture, helper hashes, profile, inputs, tool and
image identities, every native boundary probe and exit/cleanup outcomes.
Unit tests must fail for removed allowlist/budget/hash checks; native negative
controls must fail for missing restrictions. No skipped mandatory runtime probe
counts as acceptance. Run the whole release suite and final non-author block
on the exact integrated sources, recording every fix delta and unresolved limit.
A pass on one platform/image/profile grants no claim for another.

## 6. Owner choices before M2 execution

Record these future design selections before M2 builds; they do not block this M1 document.

| Decision | Recommended option | Alternative and trade-off |
| --- | --- | --- |
| First real parser | LIEF headers/sections: directly checkable byte evidence. | YARA-X literal matches first: narrower pattern behavior, fewer structural facts. |
| Executor contract version | Explicitly amend contract/1 for the contained-executor variant, preserving direct evidence. | Contract/2 immediately: clearer compatibility break, broader consumer migration. |
| First native target | One available Linux-container architecture with fresh native proof; choose the actual runner before build. | Two architectures immediately: broader scope, separate images and runtime proofs. |
| Input delivery | One inspected read-only frozen snapshot mount for tool workers; no agent role in M2. | Stdin-only worker: fewer mounts, a new transfer/storage protocol to prove. |
| Derived output | Defer until an explicit contract/2 artifact chain and semantic tests are accepted. | Design it alongside M2a: earlier decompilers, larger review and proof scope. |
| Rules | Bundled reviewed fixture rules, no includes or uploaded compiled rules. | Curated external source rules later: new licensing, provenance and resource review. |
| Cache lifetime | Ephemeral execution cache; retain derived artifacts/manifests with private reports. One Ghidra import per context. | Persistent execution cache later: separate storage, integrity and invalidation design. |
| Resource ceiling | Measure within the proposed caps; fail clearly on larger inputs. | A separately reviewed large profile: higher aggregate reservations and fresh proofs. |

Unverified before implementation: exact base/JDK/runtime locks and images,
installed footprints/native dependencies, actual Ghidra/JADX adapter APIs,
determinism and semantic accuracy, JVM/YARA-X profile compatibility, complete
dependency vulnerability disposition and native platform/container enforcement.
None is established by M1's unit tests or inherited REA reports.
