# Using ReverseAI

This guide lists every question ReverseAI can answer, the commands that ask
them, the optional contained tools, and the known limits. For installation see
[INSTALL](INSTALL.md); for the trust model see [SECURITY](SECURITY.md); for an
overview see the [README](../README.md).

## Queries

Ask one question about an approved file without executing it:

```sh
python3 -m reverseai query FILE --query NAME [--arg KEY=VALUE ...] --out DIR [--with-ghidra] [--with-jadx] [--with-jsparser]
```

Host results are verified from the bytes; Ghidra, JADX and JavaScript parser results remain derived readings.
Ghidra queries require `--with-ghidra` and the locally built, pinned image.
`inspect_android_method` adds the method's decompiled Java with `--with-jadx` and the locally
built, pinned JADX image; without it the Java part is absent and the report says so.
Each Java page has a form: `java` (decompiled), `fallback` (JADX's own listing when it could
not decompile), `omitted` (JADX prints no text for the method by design, such as a default
constructor) or `error` (nothing produced).
Pages show `rows a..b of N` and the next `start` (Java pages: `characters a..b of N`); a missing row is never evidence of absence.

| Query | Question | Result |
| --- | --- | --- |
| `binary_overview` | Overview of format, layout, imports and entry point | Verified (host) |
| `list_segments` | Declared segments and their permissions | Verified (host) |
| `inspect_native_load_image` | Segments and declared entry point | Verified (host) |
| `list_names` | Declared symbols, optionally filtered by name | Verified (host) |
| `read_bytes` | A bounded range by file offset or address | Verified (host) |
| `list_strings` | Printable ASCII and UTF-16LE runs | Verified (host) |
| `search_strings` | Printable runs containing literal text | Verified (host) |
| `list_procedures` | File-backed executable functions | Derived (Ghidra) |
| `search_procedures` | Functions whose names contain text | Derived (Ghidra) |
| `procedure_info` | A function selected by entry or exact name | Derived (Ghidra) |
| `procedure_pseudo_code` | The selected function's decompiled text | Derived (Ghidra) |
| `procedure_assembly` | An instruction page for the selected function | Derived (Ghidra) |
| `procedure_callees` | Functions called by the selected function | Derived (Ghidra) |
| `procedure_callers` | Call sites targeting the selected function | Derived (Ghidra) |
| `analyze_function` | Function info, pseudocode, assembly, calls and references | Derived (Ghidra) |
| `xrefs` | References to the selected address | Derived (Ghidra) |
| `inspect_android_package` | APK members and binary manifest declarations | Verified (host) |
| `search_android_classes` | DEX classes whose descriptors contain the search text | Verified (host) |
| `inspect_android_class` | Metadata and declared methods for the exact class; copy its displayed name | Verified (host) |
| `inspect_android_method` | The class's methods and the selected method's code references; with `--with-jadx`, the method's decompiled Java | Verified (host); Java derived (JADX) |
| `trace_android_references` | References from or to a method, selected by class, name and optional prototype | Verified (host) |
| `analyze_javascript_application` | Files, package.json declarations and lexical hints (`detail` `summary`, `files`, `package` or `hints`); with `--with-jsparser`, module sources, sensitive calls and parse status (`modules`, `calls`, `parse`) | Verified (host); syntax derived (parser) |

## Examples

Python 3.12 or later, no Python dependencies:

```sh
python3 -m reverseai analyze path/to/approved-file --out new-report-dir
python3 -m reverseai query path/to/approved-file --query list_segments --arg limit=16 --out new-query-dir
python3 -m reverseai query path/to/approved.apk --query search_android_classes --arg query=Main --out new-android-report
python3 -m reverseai query path/to/approved-js.zip --query analyze_javascript_application --arg detail=summary --out new-js-report
python3 -m reverseai query path/to/approved-package.tgz --query analyze_javascript_application --arg detail=summary --out new-tarball-report
python3 -B -m unittest discover -s tests -t . -v
```

The JavaScript query accepts a ZIP, an Electron ASAR archive (its files are read as stored
members; unpacked and link entries are listed with a flag and never read), an npm
tarball or a single JavaScript bundle, with no Docker or downloads. Tarball names
keep their `package/` prefix: copy the displayed name when selecting a file, such as
`--arg file=package/package.json`. Names never become host paths; no package manager
or install script is invoked. Use `detail=files`, `detail=package` or `detail=hints` to page one
part of the analysis; `summary` takes the first page of each part.

With `--with-jsparser`, `detail=modules`, `detail=calls` and `detail=parse` add the
parser's reading. It reports where module sources stand (`import`, `export ... from`,
`require` and `import()` with a literal) and calls whose name is on a fixed list of
sensitive functions; common names count only with their receiver (`http.get`,
`Buffer.from`, `fs.write`), so `map.get(k)` is not a call. The host converts each
answer to exact byte offsets and re-derives the literal's value or the call's dotted
name from those bytes, so every anchor is verified; that the bytes are an import or a
call rather than text in a comment is the parser's reading, reported as *derived*. The
parser executes, imports, resolves and transpiles nothing and follows no module; a
call built from strings, computed properties or escapes is not reported. `detail=parse`
shows each file's status: `ok`, `syntax_error` (rows recovered so far still count) or
`decode_error` (not UTF-8). More than 64 files, a file over 4 MiB or more than 32 MiB in
all refuse the whole operation before the parser runs.

With Docker and the locally built, pinned images (`tools/build_lief_image.py`,
`tools/build_yarax_image.py`, `tools/build_ghidra_image.py`, `tools/build_jadx_image.py`,
`tools/build_jsparser_image.py`), add `--with-lief`, `--with-yarax`, `--with-ghidra`,
`--with-jadx` and `--with-jsparser`; the command
refuses cleanly when an image or Docker is missing. The JADX image builds offline from a
directory that already holds `jadx-1.5.6.zip` (the one approved download, SHA-256
`545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974`) and the Temurin JDK
tarball used for Ghidra; the tool checks both and never downloads or pulls:

```sh
python3 -B tools/build_jadx_image.py --download-dir <private folder with the two files>
python3 -m reverseai query path/to/approved.apk --query inspect_android_method --arg class='Lcom/example/Main;' --arg method=onCreate --with-jadx --out new-java-report
```

The parser image builds offline from a directory that already holds the five approved
downloads: `node-v24.22.1-linux-arm64.tar.xz` (SHA-256
`dbabf7a1cbf947e6059ffad2c27b80041db97dea1e553b62afdee7f13fca336e`) and the npm tarballs of
`@babel/parser` 8.0.4, `@babel/types` 8.0.4, `@babel/helper-string-parser` 8.0.6 and
`@babel/helper-validator-identifier` 8.0.6, each checked against its registry sha512
integrity. The tool never downloads, pulls or runs npm:

```sh
python3 -B tools/build_jsparser_image.py --download-dir <private folder with the five files>
python3 -m reverseai query path/to/approved-js.zip --query analyze_javascript_application --arg detail=calls --with-jsparser --out new-js-calls-report
```

The native containment proof (`--tool yarax`, `ghidra`, `jadx` and `jsparser` likewise):

```sh
python3 -B tests/verify_m2_runtime.py --tool lief --profile small --offline --lock containers/lief/image.lock.json --receipt <new file>
```

The command reads one approved regular file without executing it and writes
`report.json` and `report.md`: supported findings with their byte evidence, and
rejected claims with the reviewer's reasons. Findings marked *inferred* are hints,
not proof of behaviour. The contract between components is in
[docs/contract.md](contract.md).

Known limits, by design:

- An npm tarball must contain exactly one valid gzip member and a complete tar.
  Inflation is capped at 128 MiB and 100 times the compressed input size; the tar
  has at most 65,536 physical headers, including extensions and directories.
  Trailing data, concatenated gzip streams, truncation and bad checksums refuse
  the operation. Symlinks, hard links and unsafe names are flagged; their rows
  cite the tar header rather than passing a payload to an analyzer.
- ELF, PE and thin little-endian Mach-O headers, sections and imports are parsed;
  big-endian and universal Mach-O files are identified only. String indicators and signature rules are
  lexical hints, never proof of behaviour.
- Decompiled Java is JADX's reading of the method: plausible code is not verified source.
- JavaScript hints include comments and strings, so false positives remain; calls
  split by comments or long whitespace, indirect calls and filesystem calls without
  a literal `fs` receiver can be missed.
  They do not establish execution or behaviour. The hints use no syntax tree, module
  resolution or deobfuscation; their fixed patterns and bounded spans can miss other forms.
- JavaScript syntax rows are the parser's reading of each file on its own: no module
  resolution, data flow or deobfuscation. A syntax query takes at most 64 files, 4 MiB
  each and 32 MiB in all; a larger input is refused, never read in part.
- A claim type without a rule in `reverseai/claims.py` is never supported. The
  Markdown report states supported findings in the reviewer's own words.
- In-process handlers have soft time budgets; contained workers have hard wall,
  memory and process limits. Containment is proven on Docker Desktop linux/arm64
  only; other platforms need their own proof.
- Reports contain bounded text taken from the sample. They are written with
  private permissions, and Markdown shows that text only inside code spans or fenced code blocks.
