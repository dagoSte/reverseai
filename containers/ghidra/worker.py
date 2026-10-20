"""ReverseAI Ghidra worker: one operation on /snapshot/input, one reverseai.worker/1 JSON object on stdout.

Entrypoint (docs/contract.md, "Contained Ghidra worker (M3a)"):
    python3 -I -B /opt/reverseai/worker.py ghidra.analyze <canonical JSON of validated args>

The worker accepts ELF and PE only and runs one headless Ghidra import of the snapshot into a
project under /tmp, with a fixed loader (libraries never loaded), the reviewed scripts baked into
the image (ReverseAIOptions turns off the analyzers that could look outside the input; ReverseAIQuery
writes functions, calls and pseudocode as JSON), a fixed heap and timeouts below the 240 s wall
limit. Requests choose only the four bounded counts: never a script, loader or option.

Ghidra's addresses may be rebased, so every anchor is mapped again here with this file's own
section table (stdlib decoding): an observation's address is the file's virtual address of its
anchor, and an anchor is kept only inside an executable section. Each anchor is cross-checked:
Ghidra's bytes there equal the snapshot's, Ghidra's memory block maps its address back to the same
file offset, and every anchor has the same Ghidra-to-file address delta; anything else is
InconsistentAnchor. Observations follow the M3a seams: functions in address order, pseudocode for
the entry-point function and then the largest, calls from emitted functions only, inside them.
Errors are class names only. Nothing but the one JSON object is written, to stdout only.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys

PROTOCOL = "reverseai.worker/1"
ADAPTER_VERSION = "12.1.4-r1"
SNAPSHOT = "/snapshot/input"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_REPLY_BYTES = 262_144
MAX_QUERY_BYTES = 32 * 1024 * 1024
MAX_LOCATION = 4096
MAX_NAME = 128
ARGS = {"max_functions": (1, 128, 64), "decompile": (0, 16, 8), "max_chars": (64, 2048, 1024), "max_calls": (0, 256, 128)}
GHIDRA = Path("/opt/ghidra")
SCRIPTS = Path(__file__).resolve().parent / "ghidra_scripts"
WORK = Path("/tmp/reverseai-ghidra")
HEAP = "1G"
ANALYSIS_SECONDS = 120  # Ghidra's own per-file analysis timeout
DECOMPILE_SECONDS = 40  # all decompilation together
GHIDRA_SECONDS = 210  # the whole headless run, below the 240 s wall limit
LOADERS = {"elf": "ElfLoader", "pe": "PeLoader"}


class WorkerFailure(Exception):
    """An expected refusal; its class name is the reply's error."""


class InvalidRequest(WorkerFailure):
    pass


class InputTooLarge(WorkerFailure):
    pass


class SnapshotUnreadable(WorkerFailure):
    pass


class UnsupportedFormat(WorkerFailure):
    pass


class TruncatedStructure(WorkerFailure):
    pass


class GhidraTimeout(WorkerFailure):
    pass


class GhidraFailed(WorkerFailure):
    """Ghidra exited without the query's output."""


class InvalidQueryOutput(WorkerFailure):
    """The query's JSON is missing, too large or not the expected shape."""


class AnalysisOptionOn(WorkerFailure):
    """An option ReverseAIOptions turns off (PDB, DWARF, Swift) was still on after analysis."""


class InconsistentAnchor(WorkerFailure):
    """Ghidra's address, bytes or memory block disagree with the snapshot at an anchor."""


class ReplyTooLarge(WorkerFailure):
    pass


# ---- The file's own sections: offset <-> virtual address -----------------------------------------

def need(data, offset, length):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise TruncatedStructure()


def kind(data):
    if data[:4] == b"\x7fELF":
        return "elf"
    if len(data) >= 0x40 and data[:2] == b"MZ":
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 4 <= len(data) and data[e_lfanew:e_lfanew + 4] == b"PE\0\0":
            return "pe"
    raise UnsupportedFormat()


def elf_map(data):
    """(entry VA, [(file start, file end, VA start, executable)]) from the ELF section headers."""
    need(data, 0, 0x34)
    width, order = {1: 32, 2: 64}.get(data[4]), {1: "<", 2: ">"}.get(data[5])
    if width is None or order is None:
        raise UnsupportedFormat()
    if width == 64:
        need(data, 0, 64)
        entry, shoff = struct.unpack_from(order + "QQ", data, 24)[0], struct.unpack_from(order + "Q", data, 40)[0]
        shentsize, shnum = struct.unpack_from(order + "HH", data, 58)
        row, size = order + "IIQQQQIIQQ", 64
    else:
        entry, shoff = struct.unpack_from(order + "I", data, 24)[0], struct.unpack_from(order + "I", data, 32)[0]
        shentsize, shnum = struct.unpack_from(order + "HH", data, 46)
        row, size = order + "IIIIIIIIII", 40
    sections = []
    if shnum:
        if shentsize != size:
            raise UnsupportedFormat()
        need(data, shoff, size * shnum)
        for index in range(shnum):
            _, kind_, flags, address, offset, length = struct.unpack_from(row, data, shoff + size * index)[:6]
            if kind_ != 8 and flags & 0x2 and length:  # allocated and in the file (not NOBITS)
                need(data, offset, length)
                sections.append((offset, offset + length, address, bool(flags & 0x4)))
    return entry, sections


def pe_map(data):
    """(entry VA, [(file start, file end, VA start, executable)]) from the PE section table."""
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    need(data, coff, 20)
    count, optional_size = struct.unpack_from("<H", data, coff + 2)[0], struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    need(data, optional, optional_size)
    if optional_size < 32:
        raise UnsupportedFormat()
    magic, entry_rva = struct.unpack_from("<H", data, optional)[0], struct.unpack_from("<I", data, optional + 16)[0]
    if magic == 0x20B and optional_size >= 32:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    elif magic == 0x10B and optional_size >= 32:
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
    else:
        raise UnsupportedFormat()
    table = optional + optional_size
    need(data, table, 40 * count)
    sections = []
    for index in range(count):
        virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", data, table + 40 * index + 8)
        characteristics = struct.unpack_from("<I", data, table + 40 * index + 36)[0]
        length = min(raw_size, virtual_size) if virtual_size else raw_size
        if length:
            need(data, raw, length)
            sections.append((raw, raw + length, image_base + rva, bool(characteristics & 0x20000000)))
    return image_base + entry_rva, sections


def section_at(sections, offset, length=1):
    found = [s for s in sections if s[0] <= offset and offset + length <= s[1]]
    return found[0] if len(found) == 1 else None


def offset_of(sections, address):
    found = [s for s in sections if s[2] <= address < s[2] + (s[1] - s[0])]
    return found[0][0] + (address - found[0][2]) if len(found) == 1 else None


# ---- Request -----------------------------------------------------------------------------------

def parse_request(argv):
    if len(argv) != 2:
        raise InvalidRequest()
    operation, text = argv
    try:
        args = json.loads(text, object_pairs_hook=lambda pairs: dict(pairs) if len({k for k, _ in pairs}) == len(pairs) else None)
    except ValueError:
        raise InvalidRequest() from None
    if operation != "ghidra.analyze" or not isinstance(args, dict) or not set(args) <= set(ARGS):
        raise InvalidRequest()
    checked = {}
    for name, (minimum, maximum, default) in ARGS.items():
        value = args.get(name, default)
        if type(value) is not int or not minimum <= value <= maximum:
            raise InvalidRequest()
        checked[name] = value
    return operation, checked


# ---- Ghidra ------------------------------------------------------------------------------------

def ghidra_argv(format_, out, args, entry_offset):
    """The one fixed headless command; the request contributes only bounded integers."""
    loader = LOADERS[format_]
    return ["/bin/bash", str(GHIDRA / "support" / "analyzeHeadless"), str(WORK / "project"), "reverseai",
            "-import", SNAPSHOT, "-readOnly", "-deleteProject", "-max-cpu", "2",
            "-analysisTimeoutPerFile", str(ANALYSIS_SECONDS),
            "-loader", loader, "-loader-loadLibraries", "false", "-loader-linkExistingProjectLibraries", "false",
            "-scriptPath", str(SCRIPTS), "-preScript", "ReverseAIOptions.java",
            "-postScript", "ReverseAIQuery.java", str(out), str(args["max_functions"]), str(args["decompile"]),
            str(entry_offset), str(DECOMPILE_SECONDS),
            "-log", str(WORK / "ghidra.log"), "-scriptlog", str(WORK / "script.log")]


def ghidra_env():
    home = WORK / "home"
    # Every JVM (Ghidra's launch support too) needs a writable home: user 65534's passwd home does not exist.
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "JAVA_HOME": "/opt/jdk",
            "GHIDRA_HEADLESS_MAXMEM": HEAP, "JAVA_TOOL_OPTIONS": f"-Duser.home={home} -Djava.io.tmpdir={WORK}"}


def run_ghidra(format_, args, entry_offset):
    """Run the fixed headless analysis and return the query's parsed JSON."""
    shutil.rmtree(WORK, ignore_errors=True)
    for folder in ("home", "project"):
        (WORK / folder).mkdir(parents=True, mode=0o700)
    out = WORK / "query.json"
    with open(WORK / "headless.out", "wb") as log:
        process = subprocess.Popen(ghidra_argv(format_, out, args, entry_offset), env=ghidra_env(), cwd=WORK,
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=GHIDRA_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise GhidraTimeout() from None
    try:
        with open(out, "rb") as stream:
            raw = stream.read(MAX_QUERY_BYTES + 1)
    except OSError:
        raise GhidraFailed() from None
    if len(raw) > MAX_QUERY_BYTES:
        raise InvalidQueryOutput()
    try:
        return json.loads(raw)
    except ValueError:
        raise InvalidQueryOutput() from None


# ---- Observations ------------------------------------------------------------------------------

def _int(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise InvalidQueryOutput()
    return value


def _hex(value, limit):
    if not isinstance(value, str) or len(value) > 2 * limit or not re.fullmatch(r"(?:[0-9a-f]{2})*", value):
        raise InvalidQueryOutput()
    return bytes.fromhex(value)


def printable_name(value):
    if not isinstance(value, str):
        raise InvalidQueryOutput()
    return "".join(c if " " <= c <= "~" else "?" for c in value)[:MAX_NAME]


def printable_text(value):
    if not isinstance(value, str):
        raise InvalidQueryOutput()
    return "".join(c if c.isprintable() or c in "\n\t" else "?" for c in value)


class Anchors:
    """Maps Ghidra addresses to this file's offsets and VAs, and checks every anchor against the bytes."""

    def __init__(self, data, sections, blocks):
        self.data, self.sections, self.delta = data, sections, None
        self.blocks = []
        for block in blocks:
            if not isinstance(block, dict):
                raise InvalidQueryOutput()
            self.blocks.append((_int(block.get("start")), _int(block.get("size"), 1), block.get("file_offset")))

    def block_offset(self, address):
        found = [b for b in self.blocks if b[0] <= address < b[0] + b[1]]
        if len(found) != 1 or type(found[0][2]) is not int or found[0][2] < 0:
            return None
        return found[0][2] + (address - found[0][0])

    def anchor(self, address, offset, raw, length):
        """The file VA of a Ghidra address whose first `length` bytes Ghidra reported as `raw` at file `offset`."""
        section = section_at(self.sections, offset, length)
        if section is None or not section[3]:
            return None  # not inside one executable section: not admitted
        if self.block_offset(address) != offset or len(raw) < length or raw[:length] != self.data[offset:offset + length]:
            raise InconsistentAnchor()
        va = section[2] + (offset - section[0])
        if self.delta is None:
            self.delta = address - va
        elif address - va != self.delta:
            raise InconsistentAnchor()
        return va, section


def observations(data, query, args):
    """The reply's observations from the query output, after every check; pure and testable without Ghidra."""
    format_ = kind(data)
    entry_va, sections = (elf_map if format_ == "elf" else pe_map)(data)
    if not isinstance(query, dict) or not isinstance(query.get("blocks"), list) or not isinstance(query.get("functions"), list):
        raise InvalidQueryOutput()
    options = query.get("options_off")
    if not isinstance(options, dict) or not all(isinstance(v, str) for v in options.values()):
        raise InvalidQueryOutput()
    if any(value.lower() == "true" for value in options.values()):
        raise AnalysisOptionOn()
    anchors = Anchors(data, sections, query["blocks"])
    if not all(isinstance(item, dict) for item in query["functions"]):
        raise InvalidQueryOutput()
    functions = []
    for item in sorted(query["functions"], key=lambda item: _int(item.get("entry"))):
        address, size, offset = item["entry"], _int(item.get("size"), 1), item.get("file_offset")
        if item.get("anchored") is not True or type(offset) is not int or offset < 0 or len(functions) == args["max_functions"]:
            continue  # the query anchors only file-backed executable functions, the first max_functions of them
        section = section_at(sections, offset)
        if section is None:
            continue
        length = min(size, MAX_LOCATION, section[1] - offset)
        mapped = anchors.anchor(address, offset, _hex(item.get("bytes"), MAX_LOCATION), length)
        if mapped is None:
            continue
        functions.append({"address": address, "va": mapped[0], "offset": offset, "length": length, "size": size,
                          "name": printable_name(item.get("name")), "calls": item.get("calls", [])})
    functions.sort(key=lambda f: f["va"])
    result = []
    for index, function in enumerate(functions):
        function["index"] = index
        result.append({"location": {"offset": function["offset"], "length": function["length"]},
                       "value": {"kind": "function", "index": index, "name": function["name"], "entry": function["va"],
                                 "size": function["size"]}})
    result += pseudocode(query.get("pseudocode", []), functions, entry_va, args)
    result += calls(functions, anchors, args)
    return result


def pseudocode(items, functions, entry_va, args):
    """Entry-point function first if emitted, then the largest (ties: lower entry), at most `decompile`."""
    if not isinstance(items, list):
        raise InvalidQueryOutput()
    texts = {}
    for item in items:
        if not isinstance(item, dict):
            raise InvalidQueryOutput()
        texts[_int(item.get("entry"))] = printable_text(item.get("text"))  # texts of functions not emitted are ignored
    first = [f for f in functions if f["va"] == entry_va]
    order = first + sorted((f for f in functions if f["va"] != entry_va), key=lambda f: (-f["size"], f["va"]))
    result = []
    for function in order[:args["decompile"]]:
        text = texts.get(function["address"])
        if text is None:
            continue  # a failed decompilation is omitted
        result.append({"location": {"offset": function["offset"], "length": function["length"]},
                       "value": {"kind": "pseudocode", "index": function["index"], "entry": function["va"],
                                 "text": text[:args["max_chars"]], "truncated": len(text) > args["max_chars"]}})
    return result


def calls(functions, anchors, args):
    """Calls from emitted functions whose whole instruction lies inside that function's [entry, entry + size)."""
    found = set()
    for function in functions:
        if not isinstance(function["calls"], list):
            raise InvalidQueryOutput()
        for item in function["calls"]:
            if not isinstance(item, dict):
                raise InvalidQueryOutput()
            address, length, offset = _int(item.get("address")), _int(item.get("length"), 1), item.get("file_offset")
            target, target_offset = _int(item.get("to")), item.get("to_file_offset")
            if length > 16 or type(offset) is not int or offset < 0:
                continue
            mapped = anchors.anchor(address, offset, _hex(item.get("bytes"), 16), length)
            if mapped is None or mapped[0] < function["va"] or mapped[0] + length > function["va"] + function["size"]:
                continue
            to = None
            if type(target_offset) is int and target_offset >= 0:
                section = section_at(anchors.sections, target_offset)
                to = section[2] + (target_offset - section[0]) if section else None
            if to is None:
                to = target - anchors.delta
            if to < 0:
                continue
            found.add((mapped[0], offset, length, function["va"], to, printable_name(item.get("to_name", ""))))
    return [{"location": {"offset": offset, "length": length},
             "value": {"kind": "call", "from": start, "to": to, "to_name": name}}
            for _, offset, length, start, to, name in sorted(found)[:args["max_calls"]]]


def run(operation, args, data, query_of=None):
    """Observations for ghidra.analyze; query_of(format, args, entry offset) defaults to the headless Ghidra run."""
    format_ = kind(data)
    entry_va, sections = (elf_map if format_ == "elf" else pe_map)(data)
    entry_offset = offset_of(sections, entry_va)
    query = (query_of or run_ghidra)(format_, args, -1 if entry_offset is None else entry_offset)
    return observations(data, query, args)


# ---- Reply --------------------------------------------------------------------------------------

def error_name(exc):
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) else "WorkerError"


def encode(message):
    return (json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def reply(argv, data, query_of=None, digest=None):
    """One reply; data None means the snapshot could not be read, digest defaults to the SHA-256 of data."""
    digest = digest or hashlib.sha256(data or b"").hexdigest()
    try:
        if data is None:
            raise SnapshotUnreadable()
        operation, args = parse_request(argv)
        if len(data) > MAX_INPUT_BYTES:
            raise InputTooLarge()
        message = {"protocol": PROTOCOL, "status": "ok", "snapshot_sha256": digest,
                   "observations": run(operation, args, data, query_of)}
        if len(encode(message)) > MAX_REPLY_BYTES:
            raise ReplyTooLarge()
        return message
    except Exception as exc:  # every failure is one short, inert error reply
        return {"protocol": PROTOCOL, "status": "error", "snapshot_sha256": digest, "error": error_name(exc)}


def read_snapshot(path):
    """At most MAX_INPUT_BYTES + 1 bytes, and the SHA-256 of the whole file: the digest the host compares."""
    digest, kept = hashlib.sha256(), bytearray()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
            kept += chunk[:MAX_INPUT_BYTES + 1 - len(kept)]
    return bytes(kept), digest.hexdigest()


def main(argv=None, snapshot=SNAPSHOT):
    try:
        data, digest = read_snapshot(snapshot)
    except OSError:
        data, digest = None, None
    sys.stdout.buffer.write(encode(reply(sys.argv[1:] if argv is None else argv, data, digest=digest)))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
