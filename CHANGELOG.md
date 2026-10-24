# Changelog

## Released milestones

Dates below are the release tags' creator dates: tagger date for annotated tags,
commit date for lightweight tags. Scope follows the repository's
[roadmap](README.md#roadmap); release candidates are not listed as releases.

| Date | Tag | Change |
| --- | --- | --- |
| 2026-10-24 | `m6b` | Version 0.6.1: MIT license with Metadata-Version 2.4 and preserved license files, offline editable install, an owner-started manual host-proof workflow for Linux and Windows x86-64 with SHA-pinned actions, experimental Windows report output bound to a directory handle, and offline LIEF and YARA-X builders; the whole suite and the same installed wheel proven on macOS ARM64 (Python 3.15) and in a Linux ARM64 container (Python 3.12). Windows and Linux x86-64 receipts await an owner-started run; an offline Ghidra build and AMD64 images remain deferred. |
| 2026-10-22 | `m6` | Version 0.6.0: Python packaging with a dependency-free in-tree build backend, reproducible wheel and sdist, offline installation, `reverseai --version` and a read-only `doctor`; the whole suite and the installed wheel proven on macOS ARM64 (Python 3.15) and in a Linux ARM64 container (Python 3.12). |
| 2026-10-22 | `m5c` | npm tarballs: bounded gzip/tar reading, file and header provenance, and existing JavaScript queries without extraction or installation. |
| 2026-10-22 | `m5b` | JavaScript syntax through a pinned parser in a locked container; module sources and sensitive calls remain derived, with verified byte anchors. |
| 2026-10-22 | `m5a` | Host-verified JavaScript file inventory, package.json declarations and lexical hints without sample execution. |
| 2026-10-22 | `m4b` | Contained JADX decompilation to derived Java, bound to host-verified DEX methods. |
| 2026-10-21 | `m4a` | APK inventory, binary manifest and DEX classes, methods and references, with compressed-member evidence under contract/3. |
| 2026-10-21 | `m3d` | Targeted native queries by name, address or text with paging. |
| 2026-10-21 | `m3c` | Ghidra assembly, references from code and referenced strings reported as derived evidence. |
| 2026-10-20 | `m3b` | Mach-O host decoding, verified imports for ELF/PE/Mach-O and Ghidra analysis of Mach-O. |
| 2026-10-20 | `m3a` | Contained Ghidra analysis of ELF/PE functions, pseudocode and calls as derived evidence under contract/2. |
| 2026-10-20 | `m2b` | Contained YARA-X with a reviewed literal ruleset and host-verified signature matches. |
| 2026-10-20 | `m2a` | Contained LIEF with host re-derivation of every reported header and section value. |
| 2026-10-20 | `m1` | Gateway, structural and capability analysts, evidence reviewer, and JSON/Markdown reports. |
