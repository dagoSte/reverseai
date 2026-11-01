"""The queen: deterministic orchestration of a ReverseAI analyst team (the hive).

The queen is code, not a model. She exports the program map from ReverseAI, asks one planner
bee to split the work and freeze the shared interface (`contract.h`), runs builder bees in
parallel (one per module, each with its own MCP server), compiles and links what they write,
and sends every module to an independent council that tries to refute it. Then the binding
checks run: every claim's citations are re-run through ReverseAI (tools/hive_check.py) and,
only when the operator allows it, the original and the rebuild run the same conformance cases.
The final verdict is computed from those results by code; nothing can override a failed check.

    python -m hive run --inputs DIR --file NAME --out NEW_DIR [--bees 4] [--run-original]

Every run needs prepared exports (`reverseai prepare`, ReverseAI 0.8.0 or later) and a
contained Ghidra image. See docs/HIVE.md.
"""

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from hive import bees as bees_module
from hive import codex_bees, languages, preflight
from reverseai import intake

ROOT = Path(__file__).resolve().parents[1]
WARNINGS = ("-O1", "-Wall", "-Wextra", "-Wno-unused-parameter", "-fwrapv", "-fno-strict-aliasing")
CFLAGS = (languages.C.standard, *WARNINGS)
FORBIDDEN = re.compile(r"\b(?:asm|__asm__|__asm)\b|\.incbin|#\s*embed\b|\bdlopen\b|#\s*pragma\s+comment\b")
EXPANDED_FORBIDDEN = re.compile(r"\.(?:incbin|include)\b|#\s*embed\b|\bdlopen\b|#\s*pragma\s+comment\b")
COMPILED_IDENTITY = ("source_sha256", "contract_sha256", "object_sha256", "compiler_sha256")
MAX_COMPILER_STDOUT = 16 * 1024 * 1024
MAX_COMPILER_STDERR = 256 * 1024
PROTOTYPE = re.compile(r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;\s*/\*\s*0x([0-9a-fA-F]+)\s*\*/")
EXTERN_DECLARATION = re.compile(r"\bextern\b([^;{}]*);\s*/\*\s*0x([0-9a-fA-F]+)\s*\*/")
POINTER_INNER = re.compile(r"\*\s*(?:(?:const|volatile|restrict)\s+)*([A-Za-z_]\w*)\s*(?:\[\]\s*)*")
PLAIN_DECLARATOR = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\[\]\s*)*$")
LAST_NAME = re.compile(r"\b([A-Za-z_]\w*)$")
INLINE_TYPE_EXTERN = re.compile(r"\bextern\b(?!\s*\"C(?:\+\+)?\")[^;{}]*\{")
INLINE_TYPE_DECLARATOR = re.compile(r"\s*(?:\*\s*)*[A-Za-z_]\w*\s*(?:\[[^\]]*\]\s*)*;")  # `} name;` after a body
ADDRESS_COMMENT = re.compile(r"\s*/\*\s*0x([0-9a-fA-F]+)\s*\*/")
DATA_REFERENCE_TYPES = frozenset({"read", "write", "read_write", "data"})
QUALIFIERS = frozenset({"const", "volatile", "restrict", "__restrict", "_Atomic"})
# Words that can never be a global's or a function's name in a contract declaration.
RESERVED = QUALIFIERS | frozenset({
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "bool", "_Complex",
    "struct", "union", "enum", "class", "typename", "auto", "register", "static", "extern", "thread_local",
    "_Thread_local", "__thread", "inline", "__inline", "__inline__", "typedef", "sizeof", "alignas", "_Alignas",
    "__attribute__", "__declspec", "__extension__", "__typeof__", "typeof", "decltype", "noexcept", "constexpr"})  # export reference kinds that touch data
GLOBAL_SPAN = 64 * 1024  # a reference this far past a global's address still counts as using it (tables)
LENSES = (
    ("control", "control flow and arithmetic: conditions, loops, integer widths, signedness, overflow, "
                "shifts and return values, checked against the ASSEMBLY of every function"),
    ("io", "everything the program reads and writes: output bytes and formats, error messages, exit "
           "codes, files, stdin/stdout/stderr handling and the order of operations"),
    ("data", "data and memory: structs and offsets, constant tables, globals and their initial values, "
             "buffer sizes, endianness and pointer arithmetic"),
)
MAX_CASE_FILE = 64 * 1024
MIN_CASES = 2


class HiveError(RuntimeError):
    pass


def hexed(value):
    return f"0x{value:x}"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_file(path, data, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
    try:
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


# --- ReverseAI, run as its command line from an engine checkout -----------------------------------

class Engine:
    def __init__(self, *, root, inputs, file, enabled=("ghidra",), python=sys.executable, timeout=1500):
        self.root, self.inputs, self.file = Path(root), Path(inputs), file
        self.enabled, self.python, self.timeout = tuple(enabled), python, timeout

    @property
    def path(self):
        return self.inputs / self.file

    def _run(self, argv, timeout=None):
        env = dict(os.environ, PYTHONPATH=str(self.root), PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([self.python, "-B", "-m", "reverseai", *argv], capture_output=True, text=True,
                              env=env, timeout=timeout or self.timeout, check=False)

    def prepare(self):
        done = self._run(["prepare", str(self.path), *("--with-" + t for t in self.enabled), "--json"], timeout=1100)
        if done.returncode != 0:
            raise HiveError("prepare failed: " + (done.stderr.strip().splitlines() or ["?"])[-1])
        return json.loads(done.stdout)

    def query(self, name, args, out):
        Path(out).parent.mkdir(parents=True, exist_ok=True)  # the CLI creates --out itself, not its parents
        argv = ["query", str(self.path), "--query", name, "--out", str(out), *("--with-" + t for t in self.enabled)]
        for key, value in args.items():
            argv += ["--arg", f"{key}={value}"]
        done = self._run(argv)
        report = Path(out) / "report.json"
        if done.returncode != 0 or not report.is_file():
            raise HiveError(f"{name} {args} failed: " + (done.stderr.strip().splitlines() or ["?"])[-1])
        return json.loads(report.read_text(encoding="utf-8"))


def export_rows(report, claim_key):
    rows, total = [], None
    for result in report.get("results", []):
        for finding in result.get("findings", []):
            if finding.get("claim_key") == claim_key and finding.get("verdict") in ("supported", "derived"):
                rows += finding["value"]["rows"]
                total = finding["value"]["total"]
    return sorted(rows, key=lambda row: row["index"]), total


def survey(engine, folder, log):
    """Export functions, calls and strings of the prepared program into map.json."""
    folder.mkdir(parents=True, exist_ok=True)
    receipt = engine.prepare()
    log(f"prepared {engine.file}: {json.dumps(receipt, sort_keys=True)[:200]}")
    tables = {}
    for part, key in (("functions", "code.export_functions"), ("calls", "code.export_calls"),
                      ("strings", "code.export_strings"), ("references", "code.export_references")):
        rows, start = [], 0
        while True:
            report = engine.query("export_program", {"part": part, "start": start, "limit": 128},
                                  folder / "pages" / f"{part}-{start:06d}")
            page, total = export_rows(report, key)
            rows += page
            start += len(page)
            if not page or total is None or start >= total:
                break
        tables[part] = rows
        log(f"survey: {len(rows)} {part}")
    report_sha = report["input"]["sha256"]
    functions = [{"entry": r["entry"], "hex": hexed(r["entry"]), "name": r["name"], "size": r["size"],
                  "signature": r.get("signature")} for r in tables["functions"]]
    known = {f["entry"] for f in functions}
    program_map = {
        "file": engine.file, "input_sha256": report_sha, "functions": functions,
        "calls": [{"from": hexed(r["from"]), "to": hexed(r["to"]), "to_name": r.get("to_name")} for r in tables["calls"]],
        "imports": sorted({r.get("to_name") for r in tables["calls"] if r["to"] not in known and r.get("to_name")}),
        "strings": [{"from": hexed(r["from"]), "address": hexed(r["address"]), "text": r["text"]} for r in tables["strings"]],
        "references": [{"from": hexed(r["from"]), "to": hexed(r["to"]), "type": r.get("type")} for r in tables["references"]],
    }
    (folder / "map.json").write_text(json.dumps(program_map, indent=1, ensure_ascii=False), encoding="utf-8")
    return program_map


# --- Plan ------------------------------------------------------------------------------------------

def normalise_plan(plan, program_map, max_functions):
    """Every non-skipped function in exactly one module of bounded size; leftovers by address."""
    entries = {f["hex"]: f for f in program_map["functions"]}
    skipped = {s["entry"].lower(): s["reason"] for s in plan.get("skipped", []) if s.get("entry", "").lower() in entries}
    seen, modules = set(), []
    for module in plan.get("modules", []):
        functions = []
        for entry in (str(e).lower() for e in module.get("functions", [])):
            if entry in entries and entry not in skipped and entry not in seen:
                seen.add(entry)
                functions.append(entry)
        for chunk in range(0, len(functions), max_functions):
            modules.append({"title": module.get("title", "").strip()[:120] or "module",
                            "functions": functions[chunk:chunk + max_functions]})
    left = sorted((e for e in entries if e not in seen and e not in skipped), key=lambda e: int(e, 16))
    for chunk in range(0, len(left), max_functions):
        modules.append({"title": "functions the planner left unassigned", "functions": left[chunk:chunk + max_functions]})
    for number, module in enumerate(modules, 1):
        module["id"] = f"m{number:02d}"
    return modules, skipped


def contract_names(text):
    return {int(entry, 16): name for name, entry in PROTOTYPE.findall(text)}


def _closing(text, start):
    """Index of the parenthesis that closes the one at text[start], or -1."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _top_level(text, character):
    depth = 0
    for current in text:
        depth += current == "("
        depth -= current == ")"
        if current == character and depth == 0:
            return True
    return False


def _extern_kind(body):
    """("data", name), ("function", None) or ("unreadable", None) for the text between `extern` and `;`.

    A narrow grammar, not a C parser: plain objects and arrays, pointer declarators such as `(*callback)(int)` or
    `(*handlers[4])(void)`, and function prototypes. Every other form is unreadable, so it goes back to the planner."""
    body = re.sub(r"\[[^\]]*\]", "[]", " ".join(body.split()))  # array sizes may hold sizeof(...)
    if "=" in body or _top_level(body, ","):
        return "unreadable", None  # initialisers and several names in one declaration
    first = body.find("(")
    if first < 0:
        plain = PLAIN_DECLARATOR.search(body)
        named = plain and plain.group(1) not in RESERVED and body[:plain.start()].strip()
        return ("data", plain.group(1)) if named and ")" not in body else ("unreadable", None)
    prefix, close = body[:first].strip(), _closing(body, first)
    if not prefix or close < 0:
        return "unreadable", None
    inner, rest = body[first + 1:close].strip(), body[close + 1:].strip()
    pointer = POINTER_INNER.fullmatch(inner)
    if pointer and pointer.group(1) not in RESERVED and LAST_NAME.search(prefix):
        follows_array = re.fullmatch(r"(?:\[\]\s*)*", rest)
        follows_parameters = rest.startswith("(") and _closing(rest, 0) == len(rest) - 1
        if follows_array or follows_parameters:
            return "data", pointer.group(1)
    name = LAST_NAME.search(prefix)
    if name and name.group(1) not in RESERVED and prefix[:name.start()].strip() and not rest:
        return "function", None
    return "unreadable", None


def _global_declarations(text):
    """(name or None, address, declaration) for every `extern ...; /* 0xADDRESS */` that declares data.

    Function prototypes marked extern are not data; pointer declarators such as `(*callback)` or `(*handlers[4])` are.
    A form outside the narrow grammar of _extern_kind, or an extern that defines its type inline, has no name, so
    contract_global_problems sends it back to the planner instead of losing it."""
    found = []
    for body, address in EXTERN_DECLARATION.findall(text):
        kind, name = _extern_kind(body)
        if kind != "function":
            found.append((name, int(address, 16), " ".join(body.split())))
    for match in INLINE_TYPE_EXTERN.finditer(text):
        close, depth = match.end() - 1, 0
        for close in range(match.end() - 1, len(text)):
            depth += text[close] == "{"
            depth -= text[close] == "}"
            if depth == 0:
                break
        declarator = INLINE_TYPE_DECLARATOR.match(text, close + 1)
        annotated = declarator and ADDRESS_COMMENT.match(text, declarator.end())
        if annotated:
            found.append((None, int(annotated.group(1), 16),
                          " ".join(text[match.start() + 6:declarator.end() - 1].split())))
    return found


def contract_globals(text):
    """Global data the contract declares as `extern ...; /* 0xADDRESS */`: {address: name}.

    Call contract_global_problems first: a declaration it cannot read, or two names at one address, is refused there."""
    return {address: name for name, address, _ in _global_declarations(text) if name}


def contract_global_problems(text):
    """Declarations the queen could not give an owner without losing one: unreadable ones and shared addresses."""
    problems, names_at = [], {}
    for name, address, body in _global_declarations(text):
        if not name:
            problems.append(f"cannot read the name of `extern {body};` at {hexed(address)}: write each global as "
                            "`extern TYPE NAME; /* 0xADDRESS */`, one name per line, without attributes or "
                            "initialisers, with a typedef for complex types such as _Atomic(int) or an inline "
                            "struct; write function prototypes without extern")
        else:
            names_at.setdefault(address, []).append(name)
    for address, names in sorted(names_at.items()):
        if len(names) > 1:
            problems.append(f"{', '.join(names)} share the address {hexed(address)}: declare one global per address")
    return problems


def assign_globals(globals_by_address, modules, program_map):
    """Give every global exactly one owner module: the one whose functions reference it most.

    A data reference counts for the global at or below its target (within GLOBAL_SPAN and before the next global), so an
    access into a table counts for the table. Ties go to the lowest module id; a global no module references goes to the
    first module. Returns {name: module id}."""
    if not modules:
        return {}
    addresses = sorted(globals_by_address)
    module_of = {entry: m["id"] for m in modules for entry in m["functions"]}
    counts = {address: {} for address in addresses}
    for ref in program_map.get("references", []):
        if ref.get("type") is not None and ref["type"] not in DATA_REFERENCE_TYPES:
            continue  # jumps and other control flow do not use data
        target, owner = int(ref["to"], 16), module_of.get(ref["from"])
        if owner is None:
            continue
        below = [a for a in addresses if a <= target]
        if not below or target - below[-1] >= GLOBAL_SPAN:
            continue
        base = below[-1]  # the nearest global at or below the target; the next one starts above it
        counts[base][owner] = counts[base].get(owner, 0) + 1
    order = [m["id"] for m in modules]
    owners = {}
    for address in addresses:
        votes = counts[address]
        owner = (min(votes, key=lambda mid: (-votes[mid], order.index(mid))) if votes else order[0])
        owners[globals_by_address[address]] = owner
    return owners


# --- Building and checking -------------------------------------------------------------------------

class Build:
    def __init__(self, folder, cc=None, cflags=None, ldflags=("-lm",), language=languages.C):
        self.folder, self._cc = Path(folder).resolve(), cc
        self._cflags = tuple(cflags) if cflags is not None else None
        self.language, self.ldflags = language, tuple(ldflags)
        self.include_paths = {}
        self.checked_compiler = None
        (self.folder / "obj").mkdir(parents=True, exist_ok=True)

    @property
    def cc(self):
        return self._cc or self.language.cc()

    @property
    def cflags(self):
        return self._cflags if self._cflags is not None else (self.language.standard, *WARNINGS)

    @property
    def compiler_sha256(self):
        policy = [str(self.cc), [str(flag) for flag in self.cflags], self.language.name, "no-inline-asm-v2"]
        return hashlib.sha256(json.dumps(policy).encode()).hexdigest()

    def _run(self, argv, stage):
        env = {k: os.environ[k] for k in ("PATH", "SDKROOT", "DEVELOPER_DIR", "SystemRoot") if k in os.environ}
        env.update(HOME=str(stage), TMPDIR=str(stage), LC_ALL="C")
        process = None
        buffers = [bytearray(), bytearray()]
        overflow = threading.Event()
        capture_error = threading.Event()
        stopped = threading.Event()
        stop_lock = threading.Lock()
        def stop():
            with stop_lock:
                if stopped.is_set():
                    return
                stopped.set()
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except ProcessLookupError:
                    pass
        def drain(pipe, buffer, limit):
            try:
                while chunk := os.read(pipe.fileno(), min(65536, limit + 1 - len(buffer))):
                    if len(buffer) + len(chunk) > limit:
                        overflow.set()
                        stop()
                        break
                    buffer.extend(chunk)
            except OSError:
                capture_error.set()
                stop()
            finally:
                pipe.close()
        try:
            process = subprocess.Popen(argv, cwd=stage, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=os.name == "posix")
            readers = [threading.Thread(target=drain, args=(pipe, buffer, limit), daemon=True)
                       for pipe, buffer, limit in zip((process.stdout, process.stderr), buffers,
                                                       (MAX_COMPILER_STDOUT, MAX_COMPILER_STDERR))]
            for reader in readers:
                reader.start()
            deadline = time.monotonic() + 60
            try:
                # Drain before reaping so a limiting reader still owns the process-group identity.
                for reader in readers:
                    reader.join(timeout=max(0, deadline - time.monotonic()))
                if any(reader.is_alive() for reader in readers):
                    raise subprocess.TimeoutExpired(argv, 60)
                code = process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                stop()
                process.wait()
                return subprocess.CompletedProcess(argv, 124, "", "compiler timed out")
            finally:
                for reader in readers:
                    reader.join(timeout=1)
            if overflow.is_set():
                return subprocess.CompletedProcess(argv, 125, "", "compiler output limit exceeded")
            if capture_error.is_set():
                return subprocess.CompletedProcess(argv, 125, "", "compiler output could not be read")
            if any(reader.is_alive() for reader in readers):
                return subprocess.CompletedProcess(argv, 125, "", "compiler output streams did not close")
            return subprocess.CompletedProcess(argv, code, buffers[0].decode("utf-8", errors="replace"),
                                                buffers[1].decode("utf-8", errors="replace"))
        except OSError as error:
            return subprocess.CompletedProcess(argv, 127, "", f"compiler could not start: {type(error).__name__}")

    def _stage(self, unit, source, contract):
        stage = self.folder / "stage" / unit
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True)
        for path, name in ((contract, self.language.header), (source, self.language.source(unit))):
            if path is None:
                continue
            data, _ = intake.snapshot(path)
            text = data.decode("utf-8")
            # Reject location spoofing before inspecting the compiler's expanded source locations.
            logical = text.replace("??=", "#").replace("??/", "\\").replace("%:", "#")
            logical = re.sub(r"\\\r?\n|/\*.*?\*/", "", logical, flags=re.S)
            if re.search(r"(?m)^\s*#\s*(?:line\b|\d)", logical):
                raise HiveError("generated source may not override source locations")
            if FORBIDDEN.search(logical):
                raise HiveError("forbidden constructs in generated source or contract")
            (stage / name).write_bytes(data)
        if source is None:
            (stage / self.language.source(unit)).write_text(f'#include "{self.language.header}"\n')
        return stage

    def _closed(self, stage, unit):
        flags = [self.cc, *self.cflags, "--no-default-config", "-fno-modules",
                 "-fno-gnu-inline-asm", "-fno-asm-blocks"]
        key = (self.cc, self.cflags, self.language.name)
        if key not in self.include_paths:
            discovery = self._run([*flags, "-E", "-v", "-x", self.language.syntax_kind, "-"], stage)
            match = re.search(r"#include <\.\.\.> search starts here:(.*?)End of search list\.",
                              discovery.stderr, re.S)
            if discovery.returncode or not match:
                raise HiveError("a Clang compiler with a closed VFS is required")
            self.include_paths[key] = [line.strip().removesuffix(" (framework directory)")
                                       for line in match[1].splitlines() if line.strip()]
        roots = [{"type": "directory-remap", "name": str(path), "external-contents": str(path)}
                 for path in [stage, *self.include_paths[key]]]
        control = self.folder / "vfs" / f"{unit}.json"
        control.parent.mkdir(exist_ok=True)
        control.write_text(json.dumps({"version": 0, "case-sensitive": "true", "fallthrough": False, "roots": roots}))
        return [*flags, "-ivfsoverlay", str(control)]

    def ensure_confinement(self):
        if self.checked_compiler == self.compiler_sha256:
            return
        stage = self.folder / "stage" / "capability"
        stage.mkdir(parents=True, exist_ok=True)
        source = stage / self.language.source("capability")
        closed = self._closed(stage, "capability")
        outside = self.folder / "vfs" / "outside-capability.h"
        outside.write_text("#error outside capability marker\n")
        source.write_text('#include <stddef.h>\n#if __has_include(' + json.dumps(str(outside)) + ')\n'
                          '#error compiler VFS is not closed\n#endif\nint main(void) { return 0; }\n')
        positive = self._run([*closed, "-x", self.language.syntax_kind, "-c", source.name,
                              "-o", str(stage / "positive.o")], stage)
        if positive.returncode:
            raise HiveError("compiler confinement unavailable: " + positive.stderr[-1000:])
        source.write_text('#define J(a,b) a ## b\nJ(__as,m__)("nop");\n'
                          'int main(void) { J(__as,m__)("nop"); return 0; }\n')
        negative = self._run([*closed, "-x", self.language.syntax_kind, "-fsyntax-only", source.name], stage)
        if negative.returncode == 0 or negative.stderr.count("GNU-style inline assembly is disabled") != 2:
            raise HiveError("compiler does not refuse nonempty inline assembly")
        self.checked_compiler = self.compiler_sha256

    def _compile(self, stage, unit, *, syntax=False):
        closed = self._closed(stage, unit)
        expanded = self._run([*closed, "-E", "-x", self.language.syntax_kind, self.language.source(unit)], stage)
        if expanded.returncode:
            return expanded
        # Symbol labels in system declarations are not assembly statements; the compiler disables those.
        if EXPANDED_FORBIDDEN.search(expanded.stdout):
            return subprocess.CompletedProcess(closed, 1, "", "forbidden constructs after preprocessing")
        action = ["-fsyntax-only"] if syntax else ["-c", "-o", str(stage / "unit.o")]
        return self._run([*closed, "-x", self.language.syntax_kind, *action, self.language.source(unit)], stage)

    def syntax(self, header):
        try:
            stage = self._stage("syntax", None, header)
            done = self._compile(stage, "syntax", syntax=True)
            return done.returncode == 0, done.stderr[-4000:]
        except (intake.IntakeError, UnicodeError, HiveError) as error:
            return False, str(error)

    def compile(self, module_id, source, contract):
        """Compile one module from a clean stage holding only its source and the frozen contract."""
        obj = self.folder / "obj" / f"{module_id}.o"
        obj.unlink(missing_ok=True)
        try:
            stage = self._stage(module_id, source, contract)
            done = self._compile(stage, module_id)
            identity = {"source_sha256": sha256(stage / self.language.source(module_id)),
                        "contract_sha256": sha256(stage / self.language.header),
                        "compiler_sha256": self.compiler_sha256}
            if done.returncode == 0:
                (stage / "unit.o").replace(obj)
                identity["object_sha256"] = sha256(obj)
            return {"ok": done.returncode == 0, "errors": done.stderr[-4000:] if done.returncode else "",
                    "warnings": done.stderr[-4000:] if not done.returncode else "", "log": done.stderr[-4000:], **identity}
        except (intake.IntakeError, UnicodeError, HiveError) as error:
            return {"ok": False, "errors": str(error), "warnings": ""}

    def link(self, module_ids, name):
        output = self.folder / "bin" / name
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".link")
        output.unlink(missing_ok=True)
        temporary.unlink(missing_ok=True)
        objects = [str(self.folder / "obj" / f"{m}.o") for m in module_ids]
        done = self._run([self.cc, "--no-default-config", *objects, "-o", str(temporary), *self.ldflags], self.folder)
        if done.returncode == 0:
            temporary.replace(output)
        else:
            temporary.unlink(missing_ok=True)
        return {"ok": done.returncode == 0, "log": done.stderr[-8000:],
                "binary": str(output) if done.returncode == 0 else None}


def link_blame(log, owners, module_ids):
    """Map linker messages to the modules that must fix them."""
    blamed = {}
    for symbol in re.findall(r'"_?([A-Za-z_]\w*)", referenced from|undefined reference to `([A-Za-z_]\w*)\'', log):
        name = next(s for s in symbol if s)
        if name in owners:
            blamed.setdefault(owners[name], []).append(f"undefined symbol {name}: define it in this module")
    for name in re.findall(r"duplicate symbol '_?([A-Za-z_]\w*)'|multiple definition of `([A-Za-z_]\w*)'", log):
        name = next(s for s in name if s) if isinstance(name, tuple) else name
        for module in module_ids:
            if module != owners.get(name) and f"{module}.o" in log:
                blamed.setdefault(module, []).append(f"duplicate symbol {name}: only {owners.get(name, 'its owner')} may define it")
    for module in module_ids:
        if module not in blamed and re.search(rf"\b{module}\.o\b", log):
            blamed[module] = ["linker error mentioning this module; see the log"]
    return blamed


def run_cases(cases, binary, folder, timeout=20):
    """Run every case in a fresh folder; compare-ready results with the binary's path hidden."""
    results = {}
    for case in cases:
        work = Path(tempfile.mkdtemp(prefix=f"{case['id']}-", dir=folder))
        for item in case.get("files", []):
            target = (work / item["name"]).resolve()
            if work.resolve() not in target.parents:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            data = base64.b64decode(item["base64"]) if item.get("base64") else item.get("text", "").encode()
            target.write_bytes(data[:MAX_CASE_FILE])
        steps = []
        for step in case["steps"]:
            stdin = (work / step["stdin"]) if step.get("stdin") else None
            try:
                with (stdin.open("rb") if stdin and stdin.is_file() else open(os.devnull, "rb")) as handle:
                    done = subprocess.run([binary, *step["args"]], cwd=work, stdin=handle, capture_output=True,
                                          timeout=timeout, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                steps.append({"code": done.returncode, "out": hashlib.sha256(done.stdout).hexdigest(),
                              "out_head": done.stdout[:200].decode("latin-1"),
                              "err": done.stderr.decode("latin-1").replace(str(binary), "PROG")[:2000]})
            except subprocess.TimeoutExpired:
                steps.append({"code": "timeout"})
        files = {str(p.relative_to(work)): sha256(p) for p in sorted(work.rglob("*")) if p.is_file()}
        results[case["id"]] = {"steps": steps, "files": files}
        shutil.rmtree(work, ignore_errors=True)
    return results


def compare(original, rebuilt):
    same, different = [], []
    for case_id, expected in original.items():
        (same if rebuilt.get(case_id) == expected else different).append(case_id)
    return same, different


# --- The hive --------------------------------------------------------------------------------------

class Queen:
    def __init__(self, *, engine, out, bees, slots=4, max_functions=12, compile_rounds=3, council_rounds=2,
                 lenses=len(LENSES), link_rounds=3, behaviour_rounds=2, run_original=False, cases=40,
                 max_bees=400, build=None, check=None, language="c", preflight=None, allow_packed=False):
        self.engine, self.out, self.bees = engine, Path(out).resolve(), bees
        self.slots = threading.BoundedSemaphore(slots)
        self.workers = slots
        self.max_functions, self.compile_rounds, self.council_rounds = max_functions, compile_rounds, council_rounds
        self.lenses = LENSES[:max(1, min(lenses, len(LENSES)))]
        self.link_rounds, self.behaviour_rounds = link_rounds, behaviour_rounds
        self.run_original, self.case_target, self.max_bees = run_original, cases, max_bees
        self.build = build or Build(self.out / "build")
        self.requested_language = language
        self.preflight, self.allow_packed, self.preflight_result = preflight, allow_packed, None
        self.lang = self.build.language
        self.check = check
        self.lock = threading.RLock()
        self.spent = {"bees": 0, "seconds": 0.0, "cost_usd": 0.0}
        self.events = []
        self.statuses = {}

    # bookkeeping
    def log(self, message):
        line = f"[{time.strftime('%H:%M:%S')}] {message}"
        with self.lock:
            self.events.append(line)
            with (self.out / "hive.log").open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        print(line, flush=True)

    def bee(self, role, name, task, folder):
        with self.lock:
            if self.spent["bees"] >= self.max_bees:
                self.log(f"budget: {name} not started, the run's limit of {self.max_bees} bees is reached")
                return {"ok": False, "error": "bee budget exhausted"}
            self.spent["bees"] += 1
        with self.slots:
            self.log(f"{name}: {role} started")
            answer = self.bees(role, name, task, folder)
        with self.lock:
            self.spent["seconds"] += answer.get("seconds") or 0
            self.spent["cost_usd"] += answer.get("cost_usd") or 0
        (Path(folder) / f".answer-{name}.json").write_text(json.dumps(answer, indent=1, ensure_ascii=False))
        self.log(f"{name}: {'done' if answer.get('ok') else 'FAILED ' + answer.get('error', '')[:160]} "
                 f"in {answer.get('seconds', 0)} s")
        return answer

    # phases
    def plan(self, program_map):
        folder = self.out / "plan"
        folder.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.out / "survey" / "map.json", folder / "map.json")
        task = (f"Program file: `{self.engine.file}` with {len(program_map['functions'])} functions and "
                f"{len(program_map['imports'])} imported names. Function limit per module: {self.max_functions}. "
                f"Target language: {self.lang.label}. {self.lang.guidance} Read `map.json`, then write the "
                f"interface as `{self.lang.header}` (it replaces `contract.h` in your role card) and `PLAN.md` in "
                "this folder and answer with the plan.")
        answer = self.bee("planner", "planner", task, folder)
        if not answer.get("ok"):
            raise HiveError("the planner did not produce a plan: " + answer.get("error", ""))
        modules, skipped = normalise_plan(answer["output"], program_map, self.max_functions)
        contract = folder / self.lang.header
        for attempt in range(1 + self.compile_rounds):
            ok, errors = (self.build.syntax(contract) if contract.is_file()
                          else (False, f"{self.lang.header} was not written"))
            if ok:
                problems = contract_global_problems(contract.read_text(encoding="utf-8", errors="replace"))
                if problems:
                    ok, errors = False, ("Every global needs exactly one owner: declare each one once as "
                                         "`extern TYPE NAME; /* 0xADDRESS */`, one name per address.\n" + "\n".join(problems))
            if ok:
                break
            if attempt == self.compile_rounds:
                raise HiveError(f"{self.lang.header} is not usable: " + errors[-1000:])
            self.bee("planner", f"planner-fix{attempt + 1}",
                     f"Your `{self.lang.header}` is not usable yet. Fix only these problems, keep the plan, and "
                     f"answer with the same plan:\n```\n{errors[-4000:]}\n```", folder)
        frozen = self.out / "src" / self.lang.header
        frozen.parent.mkdir(parents=True, exist_ok=True)
        write_file(frozen, intake.snapshot(contract)[0], 0o444)
        (self.out / "plan" / "modules.json").write_text(json.dumps({"modules": modules, "skipped": skipped}, indent=1))
        self.log(f"plan: {len(modules)} modules, {len(skipped)} skipped functions, contract frozen "
                 f"(sha256 {sha256(frozen)[:12]})")
        return modules, skipped, frozen

    def brief(self, module, program_map, names):
        by_hex = {f["hex"]: f for f in program_map["functions"]}
        lines = [f"# Module {module['id']}: {module['title']}", "",
                 f"Input file: `{self.engine.file}` (for MCP `file` and in claims.json).",
                 f"Language: {self.lang.label}. {self.lang.guidance}",
                 f"Write your code in `{self.lang.source(module['id'])}` (one file; "
                 f"`#include \"{self.lang.header}\"`; the role card's `contract.h` means `{self.lang.header}`).", "",
                 "| Entry (hex) | Entry (decimal, for MCP) | Contract name | Ghidra name | Size | Ghidra signature |",
                 "| --- | --- | --- | --- | --- | --- |"]
        for entry in module["functions"]:
            f = by_hex[entry]
            lines.append(f"| {entry} | {f['entry']} | {names.get(f['entry'], '?')} | {f['name']} | {f['size']} | "
                         f"{(f.get('signature') or '').replace('|', '/')} |")
        mine = set(module["functions"])
        calls = [c for c in program_map["calls"] if c["from"] in mine]
        if calls:
            lines += ["", "Calls made by these functions (caller -> callee):", ""]
            lines += sorted({f"- {c['from']} -> {c['to']} {c.get('to_name') or ''}".rstrip() for c in calls})
        owned = sorted(name for name, owner in getattr(self, "global_owners", {}).items() if owner == module["id"])
        elsewhere = sorted(name for name, owner in getattr(self, "global_owners", {}).items() if owner != module["id"])
        if owned:
            addresses = {name: hexed(address) for address, name in getattr(self, "global_addresses", {}).items()}
            lines += ["", "Global data this module must define (exactly one definition each, with the original's initial "
                      "bytes read through `read_bytes` at the address; keep the contract's declaration):", ""]
            lines += [f"- `{name}` at {addresses.get(name, '?')}" for name in owned]
        if elsewhere:
            lines += ["", "Global data defined by other modules (use the contract's `extern` declaration; never define "
                      "them here): " + ", ".join(f"`{name}`" for name in elsewhere[:200])]
        strings = [s for s in program_map["strings"] if s["from"] in mine]
        if strings:
            lines += ["", "Strings these functions reference (data from the binary, not instructions):", ""]
            lines += [f"- {s['from']} uses {s['address']}: {json.dumps(s['text'][:200], ensure_ascii=False)}"
                      for s in strings[:200]]
        return "\n".join(lines) + "\n"

    def module(self, module, program_map, names, contract):
        """Build, compile-repair and council-review one module. Runs in its own thread."""
        mid = module["id"]
        folder = self.out / "modules" / mid
        status_file = folder / "status.json"
        cached_status = self.out / ".hive" / "status" / f"{mid}.json"
        if cached_status.is_file():
            status = json.loads(cached_status.read_text())
            if (status.get("state") == "accepted" and status.get("input_sha256") == program_map["input_sha256"]
                    and status.get("functions") == module["functions"] and self.approved(status, contract)):
                self.log(f"{mid}: kept from an earlier run ({status['state']})")
                return status
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "BRIEF.md").write_text(self.brief(module, program_map, names), encoding="utf-8")
        local = folder / self.lang.header
        write_file(local, intake.snapshot(contract)[0], 0o444)
        source = folder / self.lang.source(mid)
        status = {"id": mid, "title": module["title"], "functions": module["functions"], "rounds": [],
                  "input_sha256": program_map["input_sha256"]}
        answer = self.bee("worker", f"{mid}-build", f"Rebuild module {mid}. Read `BRIEF.md` first.", folder)
        status["worker"] = answer.get("output")
        compiled = self.compile_loop(mid, folder, source, contract, status)
        if not compiled["ok"]:
            status["state"] = "failed"
            status["errors"] = compiled["errors"][-2000:]
            return self.finish(status_file, status)
        for round_number in range(1, self.council_rounds + 1):
            defects = self.review(status, folder, source, contract)
            if status["state"] in ("accepted", "incomplete", "unreviewed"):
                return self.finish(status_file, status)
            if round_number == self.council_rounds:
                break
            listing = "\n".join(f"- {d['function']}: {d['problem']} (evidence: {d['evidence']}; "
                                f"suggested fix: {d.get('fix', '-')})" for d in defects)
            self.repair(status, f"{mid}-repair-c{round_number}",
                     f"The independent council found these behavioural differences in `{source.name}`. Fix each one, "
                     f"or prove with the assembly or a finding ID that the original does the same:\n{listing}", folder)
            compiled = self.compile_loop(mid, folder, source, contract, status)
            if not compiled["ok"]:
                status["state"] = "failed"
                status["errors"] = compiled["errors"][-2000:]
                return self.finish(status_file, status)
        status["state"] = "disputed"
        return self.finish(status_file, status)

    def finish(self, status_file, status):
        data = json.dumps(status, indent=1, ensure_ascii=False).encode("utf-8")
        write_file(status_file, data)
        write_file(self.out / ".hive" / "status" / f"{status['id']}.json", data)
        self.log(f"{status['id']}: {status['state']}")
        return status

    def compile_loop(self, mid, folder, source, contract, status):
        for attempt in range(self.compile_rounds + 1):
            result = self.build.compile(mid, source, contract)
            status["compiled"] = {k: result[k] for k in COMPILED_IDENTITY if k in result}
            status.setdefault("compiles", []).append({"ok": result["ok"], "errors": result["errors"][-1000:]})
            if result["ok"] and not result["warnings"].strip():
                return result
            if attempt == self.compile_rounds:
                return result
            problem = result["errors"] if not result["ok"] else result["warnings"]
            self.repair(status, f"{mid}-repair-b{attempt + 1}",
                        f"`{source.name}` does not compile cleanly with `{self.build.cc} {' '.join(self.build.cflags)}`. "
                        "Fix exactly these "
                        f"messages without changing behaviour:\n```\n{problem[-4000:]}\n```", folder)
        return result

    def repair(self, status, name, task, folder):
        answer = self.bee("repair", name, task, folder)
        self.merge_worker(status, answer)
        return answer

    def merge_worker(self, status, answer, *, all_functions=None):
        report = answer.get("output") if answer.get("ok") else None
        previous = status.get("worker") or {}
        try:
            if not isinstance(report, dict) or report.get("status") not in ("done", "partial", "blocked"):
                raise ValueError
            expected = {int(entry, 16) for entry in status["functions"]}
            allowed = {int(entry, 16) for entry in all_functions} if all_functions is not None else expected
            def rows(data, permitted):
                result = {}
                for row in data:
                    entry = int(row["entry"], 0)
                    if entry not in permitted or entry in result or row.get("status") not in ("rebuilt", "stub", "skipped"):
                        raise ValueError
                    result[entry] = row
                return result
            updates = {entry: row for entry, row in rows(report["functions"], allowed).items() if entry in expected}
            merged = {} if set(updates) == expected else rows(previous.get("functions", []), expected)
            for entry, row in updates.items():
                merged[entry] = dict(merged.get(entry, {}), **row)
            status["worker"] = {**previous, **report, "functions": list(merged.values())}
        except (KeyError, TypeError, ValueError):
            status["worker"] = None

    def complete_worker(self, status):
        report = status.get("worker") or {}
        try:
            rows = report["functions"]
            expected = {int(entry, 16) for entry in status["functions"]}
            entries = [int(row["entry"], 0) for row in rows if row["status"] == "rebuilt"]
            return (report.get("status") == "done" and len(entries) == len(rows) == len(expected)
                    and set(entries) == expected)
        except (KeyError, TypeError, ValueError):
            return False

    def identity(self, mid, contract):
        try:
            source = self.out / "modules" / mid / self.lang.source(mid)
            return {"source_sha256": intake.snapshot(source)[1].sha256,
                    "contract_sha256": intake.snapshot(contract)[1].sha256,
                    "object_sha256": sha256(self.build.folder / "obj" / f"{mid}.o"),
                    "compiler_sha256": self.build.compiler_sha256}
        except (OSError, intake.IntakeError):
            return None

    def approved(self, status, contract):
        identity = self.identity(status["id"], contract)
        reviewed = status.get("reviewed")
        return bool(identity and status.get("compiled") == identity and self.complete_worker(status)
                    and reviewed == {k: identity[k] for k in ("source_sha256", "contract_sha256")})

    def review(self, status, folder, source, contract):
        status.pop("reviewed", None)
        if not self.complete_worker(status):
            status["state"] = "incomplete"
            status["errors"] = "the builder did not report every assigned function rebuilt with status done"
            return []
        number = len(status["rounds"]) + 1
        result = self.council(status["id"], folder, source, contract, number)
        status["rounds"].append({"council": number, **result})
        status["reviewed"] = result.get("reviewed")
        status["state"] = ("incomplete" if not result["complete"] else "disputed" if result["defects"] else
                           "accepted" if self.approved(status, contract) else "unreviewed")
        return result["defects"]

    def council(self, mid, folder, source, contract, round_number):
        unit = f"unit-{hashlib.sha256((mid + str(round_number)).encode()).hexdigest()[:6]}"
        source_bytes, source_ref = intake.snapshot(source)
        contract_bytes, contract_ref = intake.snapshot(contract)
        def review(lens):
            seat = self.out / "council" / f"{mid}-r{round_number}-{lens[0]}"
            shutil.rmtree(seat, ignore_errors=True)
            seat.mkdir(parents=True)
            (seat / f"{unit}{self.lang.extension}").write_bytes(source_bytes)
            (seat / self.lang.header).write_bytes(contract_bytes)
            shutil.copyfile(folder / "BRIEF.md", seat / "BRIEF.md")
            answer = self.bee("councillor", f"{mid}-council-r{round_number}-{lens[0]}",
                              f"Review `{unit}{self.lang.extension}` ({self.lang.label}) against the original "
                              "functions listed in `BRIEF.md`. "
                              f"Your lens: {lens[1]}.", seat)
            output = answer.get("output") if answer.get("ok") else None
            return output if isinstance(output, dict) and output.get("verdict") in ("accept", "refute") else None
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.lenses)) as pool:
            verdicts = list(pool.map(review, self.lenses))
        defects = []
        for verdict in verdicts:
            if verdict is None:
                continue
            for defect in verdict.get("defects", []):
                if re.search(r"0x[0-9a-fA-F]+|(fi|ev)-[0-9a-f]{16}", defect.get("evidence", "")):
                    defects.append(defect)
        missing = sum(v is None for v in verdicts)
        if missing:
            self.log(f"{mid}: {missing} councillor(s) gave no verdict in round {round_number}")
        return {"complete": missing == 0, "missing": missing, "defects": defects,
                "reviewed": {"source_sha256": source_ref.sha256, "contract_sha256": contract_ref.sha256}}

    def integrate(self, modules, names, contract):
        owners = {}
        for module in modules:
            for entry in module["functions"]:
                if int(entry, 16) in names:
                    owners[names[int(entry, 16)]] = module["id"]
        owners.update(getattr(self, "global_owners", {}))
        result = {"ok": False, "log": "no module compiled"}
        for attempt in range(self.link_rounds + 1):
            built = [m["id"] for m in modules if (self.build.folder / "obj" / f"{m['id']}.o").is_file()]
            if not built:
                break
            result = self.build.link(built, self.engine.file)
            if result["ok"] or attempt == self.link_rounds:
                break
            blamed = link_blame(result["log"], owners, built)
            self.log(f"link round {attempt + 1}: errors in {', '.join(sorted(blamed)) or 'no module'}")
            if not blamed:
                break
            def repair(item):
                mid, problems = item
                folder = self.out / "modules" / mid
                status = self.statuses[mid]
                self.repair(status, f"{mid}-repair-l{attempt + 1}",
                         "Linking the whole program failed because of this module. Fix these problems:\n"
                         + "\n".join("- " + p for p in problems), folder)
                compiled = self.compile_loop(mid, folder, folder / self.lang.source(mid), contract, status)
                if compiled["ok"]:
                    self.review(status, folder, folder / self.lang.source(mid), contract)
                else:
                    status["state"], status["errors"] = "failed", compiled["errors"]
                self.finish(folder / "status.json", status)
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
                list(pool.map(repair, sorted(blamed.items())))
        self.log(f"link: {'ok' if result['ok'] else 'FAILED'}")
        return result

    def conformance(self, binary, modules, contract, *, link=None):
        link = link if link is not None else {"ok": True, "binary": binary}
        folder = self.out / "tests"
        folder.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.out / "survey" / "map.json", folder / "map.json")
        for module in modules:
            brief = self.out / "modules" / module["id"] / "BRIEF.md"
            if brief.is_file():
                shutil.copyfile(brief, folder / f"BRIEF-{module['id']}.md")
        answer = self.bee("tester", "tester", f"Write about {self.case_target} conformance cases for "
                          f"`{self.engine.file}`.", folder)
        if not answer.get("ok"):
            return {"ran": False, "reason": "the tester bee gave no cases"}
        cases = answer["output"]["cases"][:200]
        if len(cases) < MIN_CASES or any(not c.get("id") or not c.get("steps") for c in cases):
            return {"ran": False, "reason": f"behaviour proof requires at least {MIN_CASES} nonempty cases"}
        for case in cases:
            case["id"] = re.sub(r"[^A-Za-z0-9_.-]", "_", case["id"])[:64]
        if len({c["id"] for c in cases}) != len(cases):
            return {"ran": False, "reason": "case IDs must be unique after normalisation"}
        (folder / "cases.json").write_text(json.dumps(cases, indent=1, ensure_ascii=False))
        runs = folder / "runs"
        runs.mkdir(exist_ok=True)
        stage = folder / "original" / self.engine.file
        stage.parent.mkdir(parents=True, exist_ok=True)
        write_file(stage, intake.snapshot(self.engine.path)[0], 0o555)
        original = run_cases(cases, str(stage), runs)
        rebuilt_binary = binary
        for round_number in range(self.behaviour_rounds + 1):
            rebuilt = run_cases(cases, rebuilt_binary, runs)
            same, different = compare(original, rebuilt)
            self.log(f"conformance round {round_number}: {len(same)}/{len(cases)} identical")
            if not different or round_number == self.behaviour_rounds:
                break
            repaired = self.behaviour_fix(round_number + 1, cases, original, rebuilt, different, modules, contract)
            link.clear()
            link.update(repaired)
            if not link["ok"]:
                return {"ran": False, "reason": "the current objects failed to relink after a behaviour fix"}
            rebuilt_binary = link["binary"]
        (folder / "results.json").write_text(json.dumps({"original": original, "rebuilt": rebuilt}, indent=1))
        expected = {c["id"] for c in cases}
        complete = set(original) == set(rebuilt) == expected and all(
            len(results[c["id"]].get("steps", [])) == len(c["steps"])
            and all(type(step.get("code")) is int for step in results[c["id"]]["steps"])
            for results in (original, rebuilt) for c in cases if c["id"] in results)
        if not complete:
            return {"ran": False, "reason": "conformance execution is incomplete or timed out"}
        return {"ran": True, "cases": len(cases), "identical": len(same), "different": different}

    def behaviour_fix(self, round_number, cases, original, rebuilt, different, modules, contract):
        folder = self.out / "fixes" / f"b{round_number}"
        folder.mkdir(parents=True, exist_ok=True)
        for module in modules:
            source = self.out / "modules" / module["id"] / self.lang.source(module["id"])
            if source.is_file():
                shutil.copyfile(source, folder / source.name)
        write_file(folder / self.lang.header, intake.snapshot(contract)[0], 0o444)
        by_id = {c["id"]: c for c in cases}
        lines = []
        for case_id in different[:25]:
            lines.append(f"## {case_id}\ncase: {json.dumps(by_id[case_id], ensure_ascii=False)[:1500]}\n"
                         f"original: {json.dumps(original[case_id], ensure_ascii=False)[:1500]}\n"
                         f"rebuild:  {json.dumps(rebuilt[case_id], ensure_ascii=False)[:1500]}\n")
        (folder / "FAILURES.md").write_text("\n".join(lines), encoding="utf-8")
        before = {p.name: sha256(p) for p in folder.glob(f"m*{self.lang.extension}")}
        answer = self.bee("repair", f"behaviour-fix-{round_number}",
                 "The rebuilt program behaves differently from the original in the cases listed in `FAILURES.md` "
                 "(stdout is compared by hash, with its first bytes shown). The module sources are in this "
                 "folder. Find the cause with the MCP tools and fix the modules; change nothing else.", folder)
        changed = [p for p in folder.glob(f"m*{self.lang.extension}") if before.get(p.name) != sha256(p)]
        for path in changed:
            mid = path.stem
            if mid not in self.statuses:
                continue
            status = self.statuses[mid]
            self.merge_worker(status, answer, all_functions=[entry for module in modules for entry in module["functions"]])
            compiled = self.build.compile(mid, path, contract)
            status["compiled"] = {k: compiled[k] for k in COMPILED_IDENTITY if k in compiled}
            module_folder = self.out / "modules" / mid
            if compiled["ok"]:
                write_file(module_folder / path.name,
                           (self.build.folder / "stage" / mid / path.name).read_bytes())
                self.review(status, module_folder, module_folder / path.name, contract)
            else:
                status["state"], status["errors"] = "failed", compiled["errors"]
            self.finish(module_folder / "status.json", status)
        self.log(f"behaviour fix {round_number}: {len(changed)} module(s) changed")
        result = self.build.link([m["id"] for m in modules if (self.out / "build" / "obj" / f"{m['id']}.o").is_file()],
                                 self.engine.file)
        return result

    def claims(self, modules):
        merged = []
        for module in modules:
            path = self.out / "modules" / module["id"] / "claims.json"
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for claim in data.get("claims", []) if isinstance(data, dict) else []:
                if isinstance(claim, dict):
                    claim = dict(claim, id=f"{module['id']}.{claim.get('id', '')}"[:128])
                    for citation in claim.get("citations", []):
                        citation["file"] = self.engine.file
                        if isinstance(citation.get("args"), dict):
                            citation["args"].pop("file", None)
                    merged.append(claim)
        path = self.out / "check" / "claims.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"file": self.engine.file, "claims": merged}, indent=1, ensure_ascii=False))
        return path, len(merged)

    def run(self):
        self.out.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        self.log(f"hive started on {self.engine.file}: {self.workers} bees at a time, councils of {len(self.lenses)}")
        map_file = self.out / "survey" / "map.json"
        program_map = (json.loads(map_file.read_text()) if map_file.is_file()
                       else survey(self.engine, self.out / "survey", self.log))
        if self.preflight:
            self.preflight_result = self.preflight(self.engine, program_map, self.out / "survey" / "preflight")
            verdict = self.preflight_result["verdict"]
            self.log(f"pre-flight: {verdict}" + "".join(f"; {s['detail']}" for s in self.preflight_result["signals"]))
            if verdict == "packed" and not self.allow_packed:
                return self.stop_packed(program_map, started)
        self.lang, reasons = languages.choose(self.requested_language, program_map)
        self.build.language = self.lang
        self.language_reasons = reasons
        self.log(f"language: {self.lang.label} ({'; '.join(reasons)})")
        self.build.ensure_confinement()
        modules, skipped, contract = self.plan(program_map)
        names = contract_names(contract.read_text(encoding="utf-8"))
        self.global_addresses = contract_globals(contract.read_text(encoding="utf-8"))
        self.global_owners = assign_globals(self.global_addresses, modules, program_map)
        if self.global_owners:
            self.log(f"globals: {len(self.global_owners)} owned by "
                     f"{len(set(self.global_owners.values()))} module(s)")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            statuses = list(pool.map(lambda m: self.module(m, program_map, names, contract), modules))
        self.statuses = {s["id"]: s for s in statuses}
        link = self.integrate(modules, names, contract)
        conformance = {"ran": False, "reason": "not allowed: start with --run-original to run the original"}
        if self.run_original and link["ok"]:
            conformance = self.conformance(link["binary"], modules, contract, link=link)
        claims_path, claim_count = self.claims(modules)
        check = None
        if self.check and claim_count:
            shutil.rmtree(self.out / "check" / "result", ignore_errors=True)
            summary, _ = self.check(claims_path, self.out / "check" / "result")
            check = summary
            self.log(f"checker: {summary['confirmed']}/{summary['claims']} claims confirmed")
        for status in statuses:
            if status["state"] == "accepted" and not self.approved(status, contract):
                status["state"] = "unreviewed"
                self.finish(self.out / "modules" / status["id"] / "status.json", status)
        result = self.verdict(program_map, modules, skipped, statuses, link, check, claim_count, conformance)
        result["seconds"] = round(time.monotonic() - started)
        result["spent"] = self.spent
        (self.out / "result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
        (self.out / "REPORT.md").write_text(render(result), encoding="utf-8")
        self.log(f"verdict: {result['verdict']} — {result['reason']}")
        return result

    def stop_packed(self, program_map, started):
        pre = self.preflight_result
        result = {"file": self.engine.file, "input_sha256": program_map["input_sha256"],
                  "functions": len(program_map["functions"]), "skipped": 0, "modules": {}, "link": False,
                  "binary": None, "check": None, "claims": 0, "preflight": pre,
                  "conformance": {"ran": False, "reason": "the run stopped at the pre-flight"},
                  "verdict": "not started",
                  "reason": "the pre-flight found a packed program (" + (", ".join(pre["packers"]) or "high entropy")
                            + "); " + pre["advice"] + " Start with --allow-packed to try anyway",
                  "seconds": round(time.monotonic() - started), "spent": self.spent}
        (self.out / "result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
        (self.out / "REPORT.md").write_text(render(result), encoding="utf-8")
        self.log(f"verdict: {result['verdict']} — {result['reason']}")
        return result

    def verdict(self, program_map, modules, skipped, statuses, link, check, claim_count, conformance):
        states = {s["id"]: s["state"] for s in statuses}
        stubs = sum(1 for s in statuses for f in (s.get("worker") or {}).get("functions", []) if f.get("status") != "rebuilt")
        reasons = []
        if not link["ok"]:
            reasons.append("the program does not link")
        bad = sorted(m for m, state in states.items() if state != "accepted")
        if bad:
            reasons.append(f"modules not accepted by the council: {', '.join(bad)}")
        if stubs:
            reasons.append(f"{stubs} function(s) reported as stub or skipped by their builder")
        incomplete = sorted(s["id"] for s in statuses if not self.complete_worker(s))
        if incomplete:
            reasons.append("incomplete builder reports: " + ", ".join(incomplete))
        if check is None:
            reasons.append("no claim was checked" if claim_count == 0 else "claims were not checked")
        elif check["rejected"]:
            reasons.append(f"{check['rejected']} claim(s) rejected by the evidence checker")
        if check is not None and check.get("input_sha256") != [program_map["input_sha256"]]:
            reasons.append("the evidence checker did not bind every question to the target input hash")
        if self.run_original and not conformance.get("ran"):
            reasons.append("behaviour proof incomplete: " + conformance.get("reason", "no results"))
        if conformance.get("ran") and (conformance.get("cases", 0) < MIN_CASES
                                       or conformance.get("identical", 0) != conformance.get("cases")):
            reasons.append("behaviour proof has too few or incomplete cases")
        if conformance.get("ran") and conformance["different"]:
            reasons.append(f"{len(conformance['different'])} conformance case(s) differ")
        return {
            "file": self.engine.file, "input_sha256": program_map["input_sha256"],
            "language": self.lang.label, "language_reasons": getattr(self, "language_reasons", []),
            "preflight": self.preflight_result,
            "functions": len(program_map["functions"]), "skipped": len(skipped), "modules": states,
            "link": link["ok"], "binary": link.get("binary") if link["ok"] else None,
            "check": check, "claims": claim_count, "conformance": conformance,
            "verdict": "accepted" if not reasons and conformance.get("ran") else
                       "accepted without behaviour proof" if not reasons else "not accepted",
            "reason": "; ".join(reasons) or ("every check passed" if conformance.get("ran") else
                                             "every static check passed; behaviour was not run"),
        }


def render(result):
    lines = [f"# Hive report: {result['file']}", "", f"**Verdict: {result['verdict']}.** {result['reason']}.", "",
             f"- Input SHA-256: `{result['input_sha256']}`",
             (f"- Language: {result['language']} ({'; '.join(result.get('language_reasons', []))})"
              if result.get("language") else "- Language: not chosen"),
             "- Pre-flight: " + (f"{result['preflight']['verdict']}" + "".join(
                 f"; {s['detail']}" for s in result["preflight"]["signals"]) if result.get("preflight") else "not run"),
             f"- Functions: {result['functions']} ({result['skipped']} skipped as library or runtime code)",
             f"- Modules: {len(result['modules'])}; accepted "
             f"{sum(s == 'accepted' for s in result['modules'].values())}",
             f"- Link: {'ok' if result['link'] else 'failed'}"]
    check = result["check"]
    lines.append(f"- Evidence checker: {check['confirmed']}/{check['claims']} claims confirmed" if check
                 else f"- Evidence checker: not run ({result['claims']} claims)")
    conformance = result["conformance"]
    lines.append(f"- Conformance: {conformance['identical']}/{conformance['cases']} cases identical"
                 if conformance.get("ran") else f"- Conformance: not run ({conformance.get('reason')})")
    spent = result.get("spent", {})
    lines += [f"- Bees: {spent.get('bees', 0)}, agent time {round(spent.get('seconds', 0) / 60)} min, "
              f"wall time {round(result.get('seconds', 0) / 60)} min", "", "| Module | State |", "| --- | --- |"]
    lines += [f"| {m} | {s} |" for m, s in sorted(result["modules"].items())]
    lines += ["", "The verdict is computed by code from the checks above. Rebuilt code is derived from Ghidra's",
              "interpretation and the agents' reading of the assembly; it is not the original source."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m hive", description="Run the ReverseAI analyst team")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Analyse and rebuild one approved native program")
    run.add_argument("--inputs", required=True, type=Path, help="Directory of approved inputs")
    run.add_argument("--file", required=True, help="Program name inside --inputs")
    run.add_argument("--out", required=True, type=Path, help="Workspace folder (new, or an earlier run to resume)")
    run.add_argument("--bees", type=int, default=4, help="Bees working at the same time (default 4)")
    run.add_argument("--max-bees", type=int, default=400, help="Bee processes for the whole run (default 400)")
    run.add_argument("--max-functions", type=int, default=12, help="Functions per module (default 12)")
    run.add_argument("--council", type=int, default=3, choices=(1, 2, 3), help="Councillors per module (default 3)")
    run.add_argument("--model", help="Model for every bee (default: the agent CLI's default)")
    run.add_argument("--claude", default="claude", help="Claude Code executable")
    run.add_argument("--check-jobs", type=int, default=2, help="Questions the evidence checker runs at once")
    run.add_argument("--run-original", action="store_true",
                     help="Allow running the original program on the conformance cases (benign software only)")
    run.add_argument("--cases", type=int, default=40, help="Conformance cases to ask for (default 40)")
    run.add_argument("--language", choices=("auto", "c", "cpp"), default="auto",
                     help="Language to rebuild in (default: detected from the program)")
    run.add_argument("--allow-packed", action="store_true",
                     help="Continue even when the pre-flight finds a packed program")
    codex_bees.add_arguments(run)
    args = parser.parse_args(argv)
    if not args.inputs.is_dir() or not (args.inputs / args.file).is_file():
        parser.error("--file must name a regular file inside --inputs")
    if not bees_module.environment_ok(args.claude):
        parser.error(f"cannot find {args.claude}; install Claude Code and log in first")
    sys.path.insert(0, str(ROOT))
    from tools import hive_check
    inputs = args.inputs.resolve()
    engine = Engine(root=ROOT, inputs=inputs, file=args.file)
    config_dir = args.out.resolve() / ".hive" / "mcp"
    claude = bees_module.ClaudeBees(engine=ROOT, inputs=inputs, claude=args.claude, model=args.model,
                                    config_dir=config_dir)
    bees = codex_bees.build(args, claude, engine=ROOT, inputs=inputs, config_dir=config_dir.parent / "codex")
    def check(claims, out):
        return hive_check.check(inputs, claims, out, enabled=frozenset({"ghidra"}), jobs=args.check_jobs)
    queen = Queen(engine=engine, out=args.out, bees=bees, slots=args.bees, max_functions=args.max_functions,
                  lenses=args.council, run_original=args.run_original, cases=args.cases, max_bees=args.max_bees,
                  check=check, language=args.language, preflight=preflight.run, allow_packed=args.allow_packed)
    try:
        result = queen.run()
    except HiveError as error:
        print(f"hive: {error}", file=sys.stderr)
        return 2
    return 0 if result["verdict"].startswith("accepted") else 1
