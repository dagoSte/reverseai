# ReverseAI

**A team of AI agents. Open reverse-engineering tools. Verifiable evidence.**

ReverseAI is an experimental project for coordinated, static reverse engineering
of untrusted files. Specialist agents will use narrowly defined analysis tools
in parallel, then a reviewer will check the evidence behind their conclusions.

**Status: project bootstrap and architecture planning.** The analysis engine and
agent team are not implemented yet. No containment or platform verification of
ReverseAI is claimed.

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
