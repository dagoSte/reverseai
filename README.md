<p align="center">
  <img src="media/banner.svg" width="100%" alt="ReverseAI: look inside untrusted files without running them. Open reverse-engineering tools in locked, offline containers. Every finding points at exact bytes, checked twice.">
</p>

https://github.com/user-attachments/assets/884cff5d-e37e-49c3-9bb7-8fbcf118e2ee

<p align="center">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-22c55e?style=flat-square">
  <img alt="Version 0.7.0" src="https://img.shields.io/badge/version-0.7.0-38bdf8?style=flat-square">
  <img alt="Python 3.12 or later" src="https://img.shields.io/badge/python-3.12%2B-3776ab?style=flat-square&logo=python&logoColor=white">
  <img alt="No Python dependencies" src="https://img.shields.io/badge/dependencies-none-22c55e?style=flat-square">
  <img alt="Platforms: macOS, Linux, Windows (experimental)" src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows%20(experimental)-64748b?style=flat-square">
  <br>
  <img alt="Samples are never executed" src="https://img.shields.io/badge/samples-never%20executed-0ea5e9?style=flat-square">
  <img alt="Containers: offline, read-only, non-root" src="https://img.shields.io/badge/containers-offline%20%C2%B7%20read--only%20%C2%B7%20non--root-0ea5e9?style=flat-square&logo=docker&logoColor=white">
  <img alt="Evidence: byte-anchored" src="https://img.shields.io/badge/evidence-byte--anchored-14b8a6?style=flat-square">
  <img alt="Tools: Ghidra, JADX, LIEF, YARA-X, Babel" src="https://img.shields.io/badge/tools-Ghidra%20%C2%B7%20JADX%20%C2%B7%20LIEF%20%C2%B7%20YARA--X%20%C2%B7%20Babel-6366f1?style=flat-square">
  <img alt="MCP server: protocol 2026-07-28" src="https://img.shields.io/badge/MCP%20server-2026--07--28-a855f7?style=flat-square">
</p>

<p align="center">
  <a href="#why-reverseai">Why</a> ·
  <a href="#what-it-analyses">What it analyses</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#the-tools">The tools</a> ·
  <a href="#the-secure-container-infrastructure">Secure containers</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

**ReverseAI is an open-source engine for static reverse engineering of untrusted
files.** It opens programs, Android apps and JavaScript packages *without running
them*, puts the heavy analysis tools inside locked, offline containers, and reports as
verified only what it can prove from the file's own bytes. Every answer says where in
the file it comes from, which tool produced it and whether ReverseAI verified it
or it is a tool's interpretation.

It works from the command line and from AI agents: its MCP server lets Claude Code,
Codex, Cursor or any other Model Context Protocol client investigate a file, while
every answer it receives stays checkable and the file never leaves its locked setup.

## Why ReverseAI

Looking inside a suspicious file usually means trusting a large toolchain with
it, and then trusting whatever the tool, or an AI model, says about it.
ReverseAI removes both kinds of blind trust:

- **The file is never executed.** It is copied once into a frozen, fingerprinted
  snapshot and read as data. No sample code, install script or package manager
  ever runs.
- **Heavy tools are locked away.** Decompilers and parsers run in a fresh
  container per question, with no network, a read-only system, no privileges and
  hard limits. Nothing of your home folder or workspace is visible to them.
- **Nothing is taken on faith.** ReverseAI recomputes every byte-level fact a
  tool reports, such as headers, offsets, matches and code anchors, from the
  original bytes. A single mismatch rejects the tool's whole answer, so a
  compromised or buggy tool can hide evidence but cannot invent verified evidence.
- **Facts and interpretations stay apart.** Decompiled code and call graphs are
  useful but are a tool's reading; they are always labelled as such and can never
  overrule a verified fact.
- **Open and reproducible.** MIT-licensed, built on official open-source tools
  pinned by hash, with no Python dependencies. The same file and settings give the
  same report.

## What it analyses

| You give it | You get |
| --- | --- |
| **Native programs**: Linux (ELF), Windows (PE) and macOS (Mach-O) executables and libraries | File structure, segments and sections, entry point, imported libraries and functions, symbols, strings and raw byte ranges. With Ghidra: the list of functions, decompiled pseudocode, assembly, who calls what, and cross-references. |
| **Android apps**: APK packages and the DEX bytecode inside them | Package contents, the binary manifest's declarations such as the package name and permissions, classes, methods and the references between them. With JADX: the decompiled Java of a chosen method. |
| **JavaScript applications**: ZIP archives, Electron ASAR archives, npm packages (`.tgz`) and single bundles | The file inventory, `package.json` declarations (including install scripts, read but never run) and hints such as process spawning, dynamic code or credential access. With the Babel parser: where modules are imported and where sensitive functions are called. |

You can ask for a **full report** on a file (`analyze`) or ask **one precise
question** (`query`): list the functions, decompile one, show who calls it, search
the strings, read bytes at an address, inspect an Android class or method, or page
through a JavaScript application. The full list of questions is in the
[usage guide](docs/USAGE.md).

Every report comes as JSON and Markdown and sorts findings into four groups:

| Label | Meaning |
| --- | --- |
| **Supported** | ReverseAI verified the value from the cited bytes with a fixed rule for that kind of claim. |
| **Derived** | A tool's interpretation, such as decompiled code or a call relationship, anchored to bytes ReverseAI verified, but still the tool's reading. |
| **Unsupported** | A claim whose evidence did not check out, shown with the reviewer's reason. |
| **Contradicted** | Verified facts that disagree with each other. |

Supported means the bytes say exactly this; it never means the file is safe,
malicious or behaves in a certain way.

## How it works

<p align="center">
  <img src="media/how-it-works.svg" width="100%" alt="How ReverseAI works: an approved file is frozen and fingerprinted; a gateway runs only allowlisted operations within time and output budgets; built-in parsers read native, Android and JavaScript formats in-process, while LIEF, YARA-X, Ghidra, JADX and a JavaScript parser each run in a locked container per request; the host re-derives every byte-level value and anchor from the original bytes; evidence records the file fingerprint, tool, operation and exact byte range; analysts cite evidence, an independent reviewer re-checks every citation, and the report separates supported, derived, unsupported and contradicted findings.">
</p>

1. **Freeze the file.** You approve one regular file. ReverseAI copies it into a
   private snapshot and fingerprints it with SHA-256; everything afterwards refers
   to that fingerprint. Links, hard-linked files and files that change while being
   read are refused.
2. **Go through the gateway.** A gateway accepts only a fixed list of operations,
   each with its own time and output budget. Nothing else can be asked of a tool.
3. **Read simple formats directly.** ReverseAI's own parsers, written with the
   Python standard library alone, decode executable headers, imports, strings,
   APK archives, the Android manifest, DEX bytecode, gzip and tar streams, ASAR
   archives and JSON. Their results are the verified reference.
4. **Run heavy tools in a locked container.** Ghidra, JADX, LIEF, YARA-X and the
   JavaScript parser run one fresh container per request, as described
   [below](#the-secure-container-infrastructure).
5. **Check the tool's answer.** The host recomputes every byte-level fact the
   tool reports from the original bytes and rejects the whole reply on any
   mismatch. A decompiled function or Java method is accepted only if it is
   anchored to code that ReverseAI located and verified itself; its text and
   relationships remain the tool's interpretation.
6. **Record evidence.** Each item of evidence binds the file fingerprint, the tool
   and its version, the operation, and the exact byte range with its own hash. For
   a file inside an archive it also records which member it came from and how that
   member was rebuilt from the original bytes.
7. **Write findings.** Analysts turn evidence into findings, and every finding
   must cite its evidence.
8. **Review independently.** A reviewer re-reads the cited bytes, rebuilds
   compressed members from the original archive and applies a fixed rule for each
   kind of claim. What it cannot confirm is not reported as supported.
9. **Report.** JSON and Markdown reports name each tool version and container
   image, and are written with private permissions into a new or empty folder.

## The tools

ReverseAI uses official releases of established open-source tools. Each one was
downloaded once, verified against its published hash and built into a local
image; at analysis time nothing is downloaded, pulled or installed.

| Tool | What it does in ReverseAI | How its answer is checked |
| --- | --- | --- |
| **Built-in parsers** (Python standard library) | Structure, imports, strings and bytes of ELF, PE and Mach-O files; APK members, the binary manifest and DEX classes, methods and references; JavaScript archives, packages and hints | They are the verified reference that every other tool is checked against. |
| [**Ghidra**](https://github.com/NationalSecurityAgency/ghidra) 12.1.4 | Functions, decompiled pseudocode, assembly, calls and cross-references of native programs | Every address and byte anchor is re-read from the file; its interpretations are labelled derived. |
| [**JADX**](https://github.com/skylot/jadx) 1.5.6 | Decompiled Java for a chosen Android method | Accepted only for the method ReverseAI's own DEX decoder verified, with the same code position and instruction count. |
| [**LIEF**](https://github.com/lief-project/LIEF) 1.0.0 | A second reading of executable headers and sections | Every reported value is recomputed from the bytes; any difference rejects the reply. |
| [**YARA-X**](https://github.com/VirusTotal/yara-x) 1.21.0 | Signature matching with a reviewed set of literal rules | Every match is found again at its exact offset. |
| [**Babel parser**](https://babeljs.io/docs/babel-parser) 8.0.4 on Node.js 24 | JavaScript, JSX and TypeScript syntax: module imports and calls to sensitive functions | It returns positions only; ReverseAI re-reads each import source or call name from the bytes. |

Each tool keeps its own license; see [third-party notices](THIRD_PARTY_NOTICES.md).

## The secure container infrastructure

<p align="center">
  <img src="media/infrastructure.svg" width="100%" alt="ReverseAI infrastructure: on the trusted host, an AI agent over MCP stdio or the command line drives the ReverseAI engine (intake, gateway, built-in parsers, re-derivation, evidence, independent reviewer), reading an approved inputs folder and writing private reports; Ghidra, JADX, LIEF, YARA-X and the Babel parser run in a Docker Desktop Linux VM, one fresh locked container per request, receiving a read-only snapshot and a fixed request and returning a bounded reply that the host re-checks.">
</p>

Every contained tool runs under the same locked profile, enforced on each run and
verified against the real Docker engine:

| Layer | What is enforced |
| --- | --- |
| **Image** | Built locally from hash-checked inputs and identified by its exact image ID in a lock file that ships with ReverseAI. Runs use `--pull never`, so a changed or tampered tag is never fetched. |
| **Lifetime** | One fresh container per request, started with a minimal init process and removed afterwards. |
| **Network** | None at all (`--network none`). |
| **File system** | Read-only root file system. The only writable space is a small in-memory scratch area mounted without execute, set-user-ID or device permissions. |
| **Privileges** | An unprivileged user, every Linux capability dropped and privilege escalation disabled (`no-new-privileges`). |
| **Resources** | Hard limits on processes, memory (with no swap), CPUs, wall-clock time and the size of the reply. |
| **Input** | A single read-only mount: the frozen snapshot of the approved file in a dedicated staging folder, deleted after the run. Never your home folder or workspace. |
| **Output** | One bounded JSON reply, treated as untrusted data and re-checked by the host before anything becomes evidence. Container logging is off. |

**Proven, not assumed.** A native verifier inspects each image and the running
configuration, then starts control containers that try to reach the network,
write to the file system, gain privileges, spawn unlimited processes, exhaust
memory, run past their time and flood their output. Each attempt must be stopped.
Known-answer files then check that the tool still gives correct results. Every
run writes a receipt naming the image, lock, verifier and outcome.

**Honest boundaries.** Docker, its virtual machine and kernel, and the ReverseAI
host program are trusted; the built-in parsers run on the host, outside the
containers. Containment is currently proven for Linux ARM64 containers under
Docker Desktop on macOS; other platforms need their own proof. The full model is
in the [security guide](docs/SECURITY.md).

## Quick start

Start with the [step-by-step guide](START.md), or tell your coding agent:
**"Read docs/AGENT_SETUP.md and follow it."** The [setup prompt](docs/AGENT_SETUP.md)
asks for your approved input directory before connecting your client.

Requirements: Python 3.12 or later, with venv and pip. Host analysis needs no
Docker. On Windows, use CPython 3.12.4 or later and the paths in
[INSTALL](docs/INSTALL.md); every analysis needs a new output directory.

Recommended on macOS or Linux, from a trusted checkout already on your machine:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --no-deps .
reverseai doctor
```

The install uses local source without a package download. `doctor` reads no
sample and never pulls, builds or starts a container; inspect its tool rows as
well as its exit status.

Other local installation paths:

| Path | Command |
| --- | --- |
| uv, if already installed | `uv tool install --offline --no-python-downloads --python python3 /path/to/reverseai` |
| An approved wheel, inside the dedicated venv | `python -m pip install --no-index --no-deps /approved/reverseai-0.7.0-py3-none-any.whl` |
| Editable development install, inside the dedicated venv and trusted checkout | `python -m pip install --no-index --no-deps -e .` |

The uv path creates a tool environment; use the executable location it prints.
Editable installs keep the checkout on Python's import path: use a dedicated
venv and keep the checkout in place. All paths use trusted source or an approved
local wheel; never install an analysed package or run its install scripts.

With the recommended venv active, analyse a file or ask one question:

```sh
reverseai analyze "/path/to/approved-file" --out new-report-folder
reverseai query "/path/to/approved-file" --query list_strings --out new-query-folder
```

Each output folder contains `report.json` and `report.md`. Choose a fresh folder
for each call. The [usage guide](docs/USAGE.md) lists format-specific questions
and paging. Contained tools need Docker and their exact local images; the
[installation guide](docs/INSTALL.md) covers building them from approved inputs
(offline except Ghidra's build, which still needs network) and the native proof.

### Use it from an AI agent

Start ReverseAI as a local MCP server over a folder of files you approved; the agent
sees one tool per question plus `list_files` and `analyze_file`:

```sh
claude mcp add --transport stdio reverseai -- /path/to/.venv/bin/reverseai mcp --inputs /path/to/approved-files
```

The server talks only over standard input and output, reads only files inside that
folder, runs a contained tool only when you add its flag (for example `--with-ghidra`),
and marks every quoted text from the files as untrusted. Results go to your agent and,
through it, to the agent's model provider, including text quoted from the files: use a
provider and plan you trust with that content. Setup for Claude Code, Codex and Cursor,
and the full security model, are in the [MCP guide](docs/MCP.md).

## Use cases

The commands below assume the virtual environment from the quick start is active and
that each file has been copied into a folder of approved inputs. Every command writes
its JSON and Markdown report into a new folder; nothing is executed. Prompts for an
agent work once the MCP server is connected as shown above.

### Check an Electron app before installing it

The app's code is in `app.asar` (on macOS inside `Contents/Resources/`). List what it
contains, look for process spawning, then let the parser show the real calls:

```sh
reverseai query app.asar --query analyze_javascript_application --arg detail=summary --out check-app
reverseai query app.asar --query analyze_javascript_application --arg detail=hints --arg category=shell --out check-app-shell
reverseai query app.asar --query analyze_javascript_application --arg detail=calls --with-jsparser --out check-app-calls
```

Agent prompt: *"Does the Electron app in the folder start other processes, read credentials or
contact hard-coded endpoints? Cite the file and byte range for every claim."*

### Review an Android app before it reaches your devices

```sh
reverseai query app.apk --query inspect_android_package --out review-apk
reverseai query app.apk --query search_android_classes --arg query=Activity --out review-classes
reverseai query app.apk --query inspect_android_method --arg class='Lcom/example/MainActivity;' --arg method=onCreate --with-jadx --out review-oncreate
```

The first report lists the package's files and its manifest (package name, version,
permissions); copy a class name exactly as the second report shows it.

Agent prompt: *"Which permissions does this app declare, and which of its methods call the
network or read contacts? Separate verified facts from decompiled code."*

### Vet an npm package before adding the dependency

Download the package tarball without running anything, then read it:

```sh
npm pack some-package@1.2.3 --ignore-scripts
reverseai query some-package-1.2.3.tgz --query analyze_javascript_application --arg detail=package --out vet-package
reverseai query some-package-1.2.3.tgz --query analyze_javascript_application --arg detail=hints --out vet-hints
reverseai query some-package-1.2.3.tgz --query analyze_javascript_application --arg detail=modules --with-jsparser --out vet-modules
```

The package report shows its `package.json` declarations, install scripts included; they
are read, never run.

Agent prompt: *"Compare version 1.2.3 and 1.2.4 of this package: which install scripts,
imports or sensitive calls are new?"*

### Triage a suspicious program

```sh
reverseai query sample.exe --query binary_overview --out triage-overview
reverseai query sample.exe --query search_strings --arg query=http --out triage-urls
reverseai query sample.exe --query list_procedures --with-ghidra --out triage-functions
reverseai analyze sample.exe --with-lief --with-yarax --with-ghidra --out triage-full
```

The same works for Linux (ELF) and macOS (Mach-O) programs. A universal macOS binary is
recognised but not yet split into its architectures, and a packed program shows little
of its real code; recognising packers is on the roadmap.

Agent prompt: *"Profile sample.exe: format, imports, notable strings, and what its entry
function calls. Mark which findings are verified and which are Ghidra's reading."*

### Keep an evidence record for an audit or an incident

```sh
mkdir -p evidence
reverseai analyze vendor-agent.exe --with-lief --with-yarax --out evidence/vendor-agent
```

`report.json` records the file's SHA-256, every tool and image used, and for each
finding the exact byte range it rests on, so a colleague or auditor can check the same
facts against the same file later.

## Platforms

| Platform | Status |
| --- | --- |
| macOS on Apple silicon | Supported: the whole test suite and the installed package are proven, and the contained tools are proven natively. |
| Linux ARM64 | Supported: the whole test suite and the installed package are proven in a clean container. |
| Linux x86-64 and Windows x86-64 | Host analysis is expected to work but is not yet proven; Windows report output is experimental. Their automated proofs are ready and will run once hosted CI is enabled. |

## Roadmap

**Available today**

- Native programs on Linux, Windows and macOS: structure, imports, strings, and
  with Ghidra functions, decompiled code, assembly, calls and cross-references.
- Android apps: manifest, classes, methods and references, and decompiled Java
  with JADX.
- JavaScript applications in ZIP, Electron ASAR, npm package or bundle form:
  inventory, declarations, hints, and syntax with the Babel parser.
- Offline installation, a setup check, reproducible packages and the MIT license.
- An MCP server (protocol revision 2026-07-28, with older clients supported) that
  gives AI agents the same verified questions, confined to a folder you choose.

**Next**

- **x86-64**: container images for Intel and AMD machines (Linux servers, Windows
  PCs, Intel Macs), with the same offline, unprivileged containment proven natively
  on each. Today the containers run on ARM64 (Apple silicon and Linux ARM64);
  x86-64 programs can already be analysed there.
- **Benchmark**: measured accuracy on a public corpus of files with known
  answers, with the method and raw results published.
- **AI analyst team**: agents that plan and ask questions in parallel, with the
  independent reviewer keeping the final word.

**Later**

- **Enterprise mode**: the same engine hosted on our infrastructure and reachable
  over MCP, for teams that need central policy and audit trails.
- **Clean-room kit**: evidence-cited functional specifications that support
  clean-room reimplementation.

## Responsible use and legal notice

ReverseAI is a tool for examining files you are entitled to examine. How you use it is
your responsibility.

- **Intended purpose.** ReverseAI is built for defensive security work: examining
  suspicious or potentially dangerous software, such as malware, untrusted packages and
  third-party components, to understand its risks without running it, for incident
  response, threat analysis and pre-adoption review.
- **Analyse only what you may analyse.** Use ReverseAI on files you own or are authorised
  to examine. Licence agreements of third-party software may restrict reverse
  engineering, decompilation or disassembly, and the law of your country may allow such
  activities only for specific purposes (for example interoperability or security
  research) and under specific conditions. Complying with those licences and laws,
  including copyright, trade-secret, computer-misuse, data-protection and export-control
  rules, is up to you.
- **No misuse.** Do not use ReverseAI to infringe intellectual property, circumvent
  protection measures, build or improve malware, or access systems or data without
  authorisation.
- **No advice.** Findings, decompiled code and any AI-generated summary can be incomplete
  or wrong. Check them before relying on them. Nothing ReverseAI produces is legal,
  security or compliance advice.
- **Dangerous files stay dangerous.** ReverseAI never executes the files it reads, but the
  files themselves may be malicious. Store and handle them according to your
  organisation's policy.
- **Your data.** Reports can contain text taken from the analysed files. When an AI agent
  uses ReverseAI, results go to that agent and its model provider.
- **No warranty, no liability.** ReverseAI is provided "as is", without warranty of any
  kind, under the [MIT License](LICENSE). To the maximum extent permitted by applicable
  law, the authors and contributors are not liable for any claim, damages or other
  liability arising from the use or misuse of the software or of its results, including
  any analysis of third-party software or files.
- **Trademarks.** Names of third-party tools and products belong to their owners; their
  mention does not imply endorsement.

## Open source

ReverseAI is free and open source under the [MIT License](LICENSE). The engine,
the containment profile and the verification rules stay open; the planned
enterprise mode adds hosting and integration on top of the same open core.
Third-party tools keep their own licenses, listed in the
[third-party notices](THIRD_PARTY_NOTICES.md). Release history is in the
[changelog](CHANGELOG.md).

Created by **Stefano D'Agostino**.
