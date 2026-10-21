"""ReverseAI Ghidra worker: one operation on /snapshot/input, one reverseai.worker/1 JSON object on stdout.

Entrypoint (docs/contract.md, "Contained Ghidra worker (M3a)"):
    python3 -I -B /opt/reverseai/worker.py ghidra.analyze <canonical JSON of validated args>

The worker accepts ELF, PE and thin little-endian Mach-O only and runs one headless Ghidra import of
the snapshot into a project under /tmp, with a fixed loader per format (libraries never loaded), the
reviewed scripts baked into
the image (ReverseAIOptions turns off the analyzers that could look outside the input; ReverseAIQuery
writes functions, calls, other references, pseudocode and instruction listings as JSON), a fixed heap
and timeouts below the 240 s wall limit. Requests choose only the eight bounded counts: never a script,
loader or option.

Ghidra's addresses may be rebased, so every anchor is mapped again here with this file's own
section table (stdlib decoding; only file-mapped bytes count: ELF SHF_ALLOC sections, PE
min(SizeOfRawData, VirtualSize), decision m3a-function-span; Mach-O LC_SEGMENT(_64) sections with
file bytes inside their segment's file range, executable by the segment's initprot or an instruction
attribute, as the host's macho_sections, decision m3b-macho-zerofill): an observation's address is the
file's virtual address of its anchor, and an anchor is kept only inside an executable section. The
entry point that leads the pseudocode is the one the host checks (Mach-O: structure.macho_entry's rule,
decision m3b-macho-entry).
Each anchor is cross-checked: Ghidra's bytes there equal the snapshot's, Ghidra's memory block maps
its address back to the same file offset, and every anchor has the same Ghidra-to-file address
delta; anything else is InconsistentAnchor. What stays Ghidra's reading, reported as derived and
never as verified: names, a function's size (its span from the entry to the last body byte), call
and reference targets, reference types, instruction texts and pseudocode. Observations follow the M3a
seams: functions in address order, pseudocode for the entry-point function and then the largest (cut
to fit the 4,096-byte observation limit, decision m3c-pseudocode-fit), calls from emitted functions
only, inside their span. Then the M3c kinds (decision m3c-contract), each added only while the encoded
reply stays within its limit: instruction listings in the pseudocode order, each instruction's bytes
confirmed; non-call references with their contract type; and the strings the referenced bytes hold,
decoded here from the snapshot by the contract rule. Errors are class names only. Nothing but the
one JSON object is written, to stdout only.
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
ADAPTER_VERSION = "12.1.4-r5"
SNAPSHOT = "/snapshot/input"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_REPLY_BYTES = 262_144
MAX_QUERY_BYTES = 32 * 1024 * 1024
MAX_LOCATION = 4096
MAX_OBSERVATION_BYTES = 4096  # an observation value's canonical JSON, as the host's Observation bounds it
MAX_NAME = 128
MAX_INSTRUCTION_TEXT = 64
MAX_STRING_CHARS = 128
MAX_STRING_FROM = 8
ARGS = {"max_functions": (1, 128, 64), "decompile": (0, 16, 8), "max_chars": (64, 2048, 1024), "max_calls": (0, 256, 128),
        "assembly": (0, 8, 4), "max_instructions": (1, 64, 32), "max_refs": (0, 128, 64), "max_strings": (0, 64, 32)}
GHIDRA = Path("/opt/ghidra")
SCRIPTS = Path(__file__).resolve().parent / "ghidra_scripts"
WORK = Path("/tmp/reverseai-ghidra")
HEAP = "1G"
ANALYSIS_SECONDS = 120  # Ghidra's own per-file analysis timeout
DECOMPILE_SECONDS = 40  # all decompilation together
GHIDRA_SECONDS = 210  # the whole headless run, below the 240 s wall limit
LOADERS = {"elf": "ElfLoader", "pe": "PeLoader", "macho": "MachoLoader"}
MACHO_MAGICS = {b"\xce\xfa\xed\xfe": 32, b"\xcf\xfa\xed\xfe": 64}  # thin little-endian only
MACHO_ZEROFILL = (0x1, 0xC, 0x12)  # S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL: no file bytes
MACHO_THREADS = {0x1000007: (4, 42, 128), 0x100000C: (6, 68, 256)}  # cputype: (flavor, count, pc offset) x86_64 rip, arm64 pc


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
    if data[:4] in MACHO_MAGICS:
        return "macho"
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


def _thread_pcs(data, start, end, expected):
    """Program counters of the expected (flavor, count, pc offset) states in one LC_UNIXTHREAD, None if malformed."""
    pcs = []
    while start < end:
        if start + 8 > end:
            return None
        flavor, count = struct.unpack_from("<II", data, start)
        state = start + 8
        if count > (end - state) // 4:
            return None
        if expected and flavor == expected[0]:
            if count != expected[1]:
                return None
            pcs.append(struct.unpack_from("<Q", data, state + expected[2])[0])
        start = state + count * 4
    return pcs


def macho_map(data):
    """(entry VA or 0, [(file start, file end, VA start, executable)]) from the LC_SEGMENT(_64) sections of a thin
    little-endian Mach-O. A section counts only with file bytes inside its segment's file range; executable is the
    segment's initprot execute bit or a section instruction attribute. The entry follows the host's macho_entry: one
    LC_MAIN through the one segment whose file bytes hold entryoff, else one x86_64 or arm64 LC_UNIXTHREAD pc, else 0."""
    width = MACHO_MAGICS[data[:4]]
    header = 32 if width == 64 else 28
    need(data, 0, header)
    cputype = struct.unpack_from("<I", data, 4)[0]
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    need(data, header, sizeofcmds)
    segment_cmd, segment_size, section_size = (0x19, 72, 80) if width == 64 else (0x1, 56, 68)
    segment_row, section_row = ("<16sQQQQiiII", "<16s16sQQIIIIIIII") if width == 64 else ("<16sIIIIiiII", "<16s16sIIIIIIIII")
    at, end, sections, segments, mains, threads, valid = header, header + sizeofcmds, [], [], [], [], True
    for _ in range(ncmds):
        if at + 8 > end:
            raise TruncatedStructure()
        cmd, cmdsize = struct.unpack_from("<II", data, at)
        if cmdsize < 8 or at + cmdsize > end:
            raise TruncatedStructure()
        if cmd == segment_cmd:
            if cmdsize < segment_size:
                raise TruncatedStructure()
            _, vmaddr, vmsize, fileoff, filesize, _, initprot, nsects, _ = struct.unpack_from(segment_row, data, at + 8)
            if segment_size + nsects * section_size > cmdsize:
                raise TruncatedStructure()
            segments.append((fileoff, filesize, vmaddr, vmsize))
            for index in range(nsects):
                row = struct.unpack_from(section_row, data, at + segment_size + index * section_size)
                address, size, offset, flags = row[2], row[3], row[4], row[8]
                inside = fileoff <= offset and offset + size <= fileoff + filesize
                if size and offset and inside and (flags & 0xFF) not in MACHO_ZEROFILL:
                    need(data, offset, size)
                    sections.append((offset, offset + size, address, bool(initprot & 0x4) or bool(flags & 0x80000400)))
        elif cmd == 0x80000028:  # LC_MAIN: entryoff is a file offset inside __TEXT
            valid = valid and cmdsize >= 24
            if cmdsize >= 24:
                mains.append(struct.unpack_from("<Q", data, at + 8)[0])
        elif cmd == 0x5:  # LC_UNIXTHREAD: (flavor, count, state) records
            pcs = _thread_pcs(data, at + 8, at + cmdsize, MACHO_THREADS.get(cputype))
            valid = valid and pcs is not None
            threads += pcs or []
        at += cmdsize
    if not valid or len(mains) > 1:
        return 0, sections
    if mains:
        found = [vmaddr + mains[0] - fileoff for fileoff, filesize, vmaddr, vmsize in segments
                 if fileoff + filesize <= len(data) and 0 <= mains[0] - fileoff < min(filesize, vmsize)
                 and vmaddr + vmsize <= 2**width]
        return (found[0] if len(found) == 1 else 0), sections
    return (threads[0] if len(threads) == 1 else 0), sections


FILE_MAPS = {"elf": elf_map, "pe": pe_map, "macho": macho_map}


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
            str(entry_offset), str(DECOMPILE_SECONDS), str(args["assembly"]), str(args["max_instructions"]),
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


def _size(value):
    """Bytes of value's JSON as encode() and the host's canonical_json write it (UTF-8, sorted keys, no spaces)."""
    return len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


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
    entry_va, sections = FILE_MAPS[format_](data)
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
                          "name": printable_name(item.get("name")), "calls": item.get("calls", []),
                          "refs": item.get("refs", [])})
    functions.sort(key=lambda f: f["va"])
    result = []
    for index, function in enumerate(functions):
        function["index"] = index
        result.append({"location": {"offset": function["offset"], "length": function["length"]},
                       "value": {"kind": "function", "index": index, "name": function["name"], "entry": function["va"],
                                 "size": function["size"]}})
    result += pseudocode(query.get("pseudocode", []), functions, entry_va, args)
    result += calls(functions, anchors, args)
    reply = Fit(result)
    for item in assembly(query.get("assembly", []), functions, entry_va, anchors, args):
        reply.add(item)
    for item in references(functions, anchors, args):
        reply.add(item)
    for item in strings(data, sections, [o["value"] for o in reply.items if o["value"]["kind"] == "ref"], args):
        reply.add(item)
    return reply.items


class Fit:
    """Observations added in order only while the encoded reply stays within MAX_REPLY_BYTES; one never cut."""

    def __init__(self, items):
        self.items = list(items)
        envelope = len(encode({"protocol": PROTOCOL, "status": "ok", "snapshot_sha256": "0" * 64, "observations": []}))
        self.size = envelope + sum(map(_size, self.items)) + max(0, len(self.items) - 1)

    def add(self, item):
        grown = self.size + _size(item) + (1 if self.items else 0)
        if grown <= MAX_REPLY_BYTES:
            self.items.append(item)
            self.size = grown


def ranked(functions, entry_va):
    """The pseudocode order: the entry-point function first if emitted, then the largest (ties: lower entry)."""
    first = [f for f in functions if f["va"] == entry_va]
    return first + sorted((f for f in functions if f["va"] != entry_va), key=lambda f: (-f["size"], f["va"]))


def pseudocode(items, functions, entry_va, args):
    """Texts in the ranked order, at most `decompile`; each cut at max_chars and, if its observation value would pass
    MAX_OBSERVATION_BYTES, to the longest prefix that fits (decision m3c-pseudocode-fit)."""
    if not isinstance(items, list):
        raise InvalidQueryOutput()
    texts = {}
    for item in items:
        if not isinstance(item, dict):
            raise InvalidQueryOutput()
        texts[_int(item.get("entry"))] = printable_text(item.get("text"))  # texts of functions not emitted are ignored
    result = []
    for function in ranked(functions, entry_va)[:args["decompile"]]:
        text = texts.get(function["address"])
        if text is None:
            continue  # a failed decompilation is omitted
        value = {"kind": "pseudocode", "index": function["index"], "entry": function["va"],
                 "text": text[:args["max_chars"]], "truncated": len(text) > args["max_chars"]}
        if _size(value) > MAX_OBSERVATION_BYTES:
            whole, low, high = value["text"], 0, len(value["text"])
            value["truncated"] = True
            while low < high:  # the longest prefix that fits; the size grows with the prefix
                value["text"] = whole[:(low + high + 1) // 2]
                low, high = (len(value["text"]), high) if _size(value) <= MAX_OBSERVATION_BYTES else (low, len(value["text"]) - 1)
            value["text"] = whole[:low]
        result.append({"location": {"offset": function["offset"], "length": function["length"]}, "value": value})
    return result


def _instruction(anchors, function, item):
    """(file VA, file offset, length) of a query instruction whose whole bytes lie inside the function's span."""
    if not isinstance(item, dict):
        raise InvalidQueryOutput()
    address, length, offset = _int(item.get("address")), _int(item.get("length"), 1), item.get("file_offset")
    if length > 16 or type(offset) is not int or offset < 0:
        return None
    mapped = anchors.anchor(address, offset, _hex(item.get("bytes"), 16), length)
    if mapped is None or mapped[0] < function["va"] or mapped[0] + length > function["va"] + function["size"]:
        return None
    return mapped[0], offset, length


def _target(anchors, item):
    """A call or reference target as a file VA: through its file offset when one section holds it, else Ghidra's
    address less the rebase delta; None below zero."""
    target, target_offset = _int(item.get("to")), item.get("to_file_offset")
    if type(target_offset) is int and target_offset >= 0:
        section = section_at(anchors.sections, target_offset)
        if section:
            return section[2] + (target_offset - section[0])
    return target - anchors.delta if target >= anchors.delta else None


def calls(functions, anchors, args):
    """Calls from emitted functions whose whole instruction lies inside that function's [entry, entry + size)."""
    found = set()
    for function in functions:
        if not isinstance(function["calls"], list):
            raise InvalidQueryOutput()
        for item in function["calls"]:
            mapped = _instruction(anchors, function, item)
            to = _target(anchors, item) if mapped else None
            if to is not None:
                found.add((mapped[0], mapped[1], mapped[2], function["va"], to, printable_name(item.get("to_name", ""))))
    return [{"location": {"offset": offset, "length": length},
             "value": {"kind": "call", "from": start, "to": to, "to_name": name}}
            for _, offset, length, start, to, name in sorted(found)[:args["max_calls"]]]


def assembly(items, functions, entry_va, anchors, args):
    """Instruction listings for the first `assembly` functions in the ranked order, each at the function's anchor:
    [delta, length, text] rows in address order, non-overlapping and wholly inside the anchor, each one's bytes
    confirmed; at most max_instructions rows and 4,096 bytes of value; truncated when any instruction of the function
    is not listed. A function with no listable instruction is omitted."""
    if not isinstance(items, list):
        raise InvalidQueryOutput()
    listings = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("instructions"), list):
            raise InvalidQueryOutput()
        if _int(item.get("count")) < len(item["instructions"]):
            raise InvalidQueryOutput()
        listings[_int(item.get("entry"))] = item
    result = []
    for function in ranked(functions, entry_va)[:args["assembly"]]:
        item = listings.get(function["address"])
        if item is None:
            continue  # a failed listing is omitted
        value = {"kind": "assembly", "index": function["index"], "entry": function["va"], "instructions": [], "truncated": False}
        end, after = function["offset"] + function["length"], function["offset"]
        for row in item["instructions"][:args["max_instructions"]]:
            mapped = _instruction(anchors, function, row)
            if mapped is None or mapped[1] < after or mapped[1] + mapped[2] > end:
                break  # outside the anchor, before the previous row's end, or not in an executable section
            text = printable_name(row.get("text"))[:MAX_INSTRUCTION_TEXT] or "?"
            value["instructions"].append([mapped[1] - function["offset"], mapped[2], text])
            if _size(value) > MAX_OBSERVATION_BYTES:
                value["instructions"].pop()
                break
            after = mapped[1] + mapped[2]
        if value["instructions"]:
            value["truncated"] = len(value["instructions"]) < item["count"]
            result.append({"location": {"offset": function["offset"], "length": function["length"]}, "value": value})
    return result


def ref_type(item):
    """The contract type of one query reference from Ghidra's flags, None when it is not reported."""
    flags = [item.get(name) for name in ("flow", "jump", "read", "write", "data", "inside")]
    if not all(type(flag) is bool for flag in flags):
        raise InvalidQueryOutput()
    flow, jump, read, write, data, inside = flags
    if flow:
        return "jump" if jump and not inside else None  # flow inside the body is not reported
    if read and write:
        return "read_write"
    return "read" if read else "write" if write else "data" if data else None


def references(functions, anchors, args):
    """Non-call references from emitted functions' instructions inside their span; one row per contract key (instruction
    file offset, to, type), the lowest when the query repeats a key with other details; sorted by that key, at most
    max_refs."""
    found = {}
    for function in functions:
        if not isinstance(function["refs"], list):
            raise InvalidQueryOutput()
        for item in function["refs"]:
            kind = ref_type(item) if isinstance(item, dict) else None
            mapped = _instruction(anchors, function, item) if kind else None
            to = _target(anchors, item) if mapped else None
            if to is not None:
                row = (mapped[1], to, kind, mapped[2], function["va"], printable_name(item.get("to_name", "")))
                found[row[:3]] = min(found.get(row[:3], row), row)
    return [{"location": {"offset": offset, "length": length},
             "value": {"kind": "ref", "from": start, "to": to, "type": kind, "to_name": name}}
            for offset, to, kind, length, start, name in sorted(found.values())[:args["max_refs"]]]


def decode_string(data, sections, address):
    """(file offset, encoded length, encoding, text, truncated) of the string at address under the contract rule, or
    None: ascii when 2..128 bytes in 0x20..0x7e start there, then a zero byte; else utf-16le with XX 00 units and a
    00 00 terminator; a run that reaches 128 characters with the next one still matching is truncated instead. The text
    and its terminator (or that next unit) lie inside one section, and no other section maps any of those addresses or
    file bytes: an ambiguous string is omitted, never refused (the host maps the whole span both ways)."""
    found = [s for s in sections if s[2] <= address < s[2] + (s[1] - s[0])]
    if len(found) != 1:
        return None
    start, end = found[0][0] + (address - found[0][2]), found[0][1]

    def run(step, matches):
        count = 0
        while count <= MAX_STRING_CHARS and start + (count + 1) * step <= end and matches(start + count * step):
            count += 1
        return count

    for encoding, step in (("ascii", 1), ("utf-16le", 2)):
        count = run(step, lambda at: 0x20 <= data[at] <= 0x7E and (step == 1 or data[at + 1] == 0))
        truncated = count > MAX_STRING_CHARS
        count = min(count, MAX_STRING_CHARS)
        terminated = start + (count + 1) * step <= end and not any(data[start + count * step:start + (count + 1) * step])
        if count >= 2 and (truncated or terminated):
            span = (count + 1) * step
            virtual = [s for s in sections if s[2] < address + span and address < s[2] + (s[1] - s[0])]
            backed = [s for s in sections if s[0] < start + span and start < s[1]]
            if virtual != found or backed != found:
                return None
            return start, count * step, encoding, data[start:start + count * step].decode(encoding), truncated
    return None


def strings(data, sections, refs, args):
    """Strings at the distinct `to` of the reply's references, by address, at most max_strings; `from` the sorted
    referencing functions, the lowest MAX_STRING_FROM."""
    sources = {}
    for ref in refs:
        sources.setdefault(ref["to"], set()).add(ref["from"])
    result = []
    for address in sorted(sources):
        decoded = decode_string(data, sections, address) if len(result) < args["max_strings"] else None
        if decoded is None:
            continue
        offset, length, encoding, text, truncated = decoded
        result.append({"location": {"offset": offset, "length": length},
                       "value": {"kind": "string", "address": address, "encoding": encoding, "text": text,
                                 "truncated": truncated, "from": sorted(sources[address])[:MAX_STRING_FROM]}})
    return result


def run(operation, args, data, query_of=None):
    """Observations for ghidra.analyze; query_of(format, args, entry offset) defaults to the headless Ghidra run."""
    format_ = kind(data)
    entry_va, sections = FILE_MAPS[format_](data)
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
