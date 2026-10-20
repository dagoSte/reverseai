# ReverseAI

**A team of AI agents. Open reverse-engineering tools. Verifiable evidence.**

ReverseAI is an experimental project for coordinated, static reverse engineering
of untrusted files. Specialist agents will use narrowly defined analysis tools
in parallel, then a reviewer will check the evidence behind their conclusions.

**Status: M1 prototype.** Two deterministic analysts (file structure and string
indicators) run through an allowlisting gateway, and an evidence reviewer checks
every claim against the frozen input bytes. It uses only the Python standard
library and synthetic test fixtures. No external analysis tools, model-driven
agents, containers or platform containment are part of M1, and none is claimed.

## Try the M1 prototype

Python 3.12 or later, no dependencies:

```sh
python3 -m reverseai analyze path/to/approved-file --out new-report-dir
python3 -B -m unittest discover -s tests -t . -v
```

The command reads one approved regular file without executing it and writes
`report.json` and `report.md`: supported findings with their byte evidence, and
rejected claims with the reviewer's reasons. Findings marked *inferred* are hints
from names in the file, not proof of behaviour. The contract between components
is in [docs/contract.md](docs/contract.md).

Known limits of M1, by design:

- Only ELF and PE headers and section tables are parsed. A Mach-O file is
  recognized by its magic bytes only; universal (fat) binaries are reported as
  unrecognized. String indicators are lexical hints (an API name or a word such
  as "connect"), never proof of behaviour.
- The reviewer checks provenance and the claim rules in `reverseai/claims.py`; a
  claim type without a rule is never supported. The Markdown report states each
  supported finding in the reviewer's own words; an analyst's free wording appears
  only under rejected claims and in the JSON.
- Time budgets are soft: a Python handler that overruns is reported and its late
  output discarded, but it cannot be killed. M1 has no process or container
  isolation and claims none.
- Reports are reproducible for a given input and budget unless a shared global
  budget runs out; then which concurrent analyst received the last slots may vary,
  and the run says `budget_exceeded`.
- Reports contain bounded text taken from the sample. They are written with
  private permissions, and Markdown shows that text only inside code spans.

## Planned workflow

1. Select and approve input bytes.
2. Create private frozen copies for contained analysis.
3. Schedule independent analysis tasks within shared resource budgets.
4. Run approved tool operations through a controlled gateway.
5. Collect evidence with input hashes, tool versions and precise locations.
6. Review contradictions and unsupported claims before producing the report.

Initial tool candidates are Ghidra, JADX, the open-source LIEF core and YARA-X.
capa, FLOSS and Binwalk are later candidates, subject to interface, license,
dependency and containment review. Tools are candidates, not installed features.
Samples will not be launched as native programs in the initial static profile.

## Security foundation

The project intends to reuse selected safeguards from
[REA Safe Agent](https://github.com/dagoSte/rea-safe-agents): approved snapshots,
separately contained analysis and receiving clients, restricted tools, bounded
messages, fixed model destinations and repeatable verification.

The initial goal is direct use of open analysis tools without the REA runtime.
Any reused code must retain its license and attribution. REA Safe Agent's tests,
badges and past verification do not automatically apply to this new project.

The host controller, runtime and relevant kernel/hypervisor remain trusted.
Agent messages and tool results remain untrusted data. Agreement between agents
is not proof. Any future model-provider connection must disclose what data
leaves the machine.

## Development

The repository starts private. Project documentation is written in English.
The development team uses a separate local Squadra registry and dashboard;
these are not the product's analysis-agent runtime.

Claude coordinates development. Codex windows support implementation and
independent review in separately assigned scopes. Private inputs, logins,
transcripts, coordination state and local analysis outputs stay outside Git.

Developed by **Stefano D'Agostino**.
