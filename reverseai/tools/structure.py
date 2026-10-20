"""Bounded structural parsing of ELF, PE and Mach-O (tool "structure").

Handlers only read the frozen bytes they are given. Every offset and count
from the input is checked against the input size before it is used, loops
are bounded by input extents and fixed scan limits, and no size field is an allocation request.
Malformed input raises StructureError, a ValueError with a short message.
"""

from __future__ import annotations

import struct

from reverseai.contract import (
    MAX_OBSERVATION_BYTES, ArgSpec, ContractError, Location, Observation, OperationSpec, ToolRef, ToolSpec, canonical_json,
)

REF = ToolRef("structure", "0.1.0")
MAX_SECTIONS = 256
MAX_NAME_BYTES = 64
UNKNOWN_PREFIX = 16
MAX_IMPORTS = 256
MAX_IMPORT_NAME = 128
MAX_TABLE_ENTRIES = 65536

ELF_MAGIC = b"\x7fELF"
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
FAT_MAGICS = {b"\xca\xfe\xba\xbe": (">", 20), b"\xca\xfe\xba\xbf": (">", 32),
              b"\xbe\xba\xfe\xca": ("<", 20), b"\xbf\xba\xfe\xca": ("<", 32)}
MACHO_MACHINES = {7: "x86", 0x1000007: "x86_64", 12: "arm", 0x100000C: "aarch64",
                  18: "powerpc", 0x1000012: "powerpc64"}

ELF_TYPES = {0: "none", 1: "relocatable", 2: "executable", 3: "shared", 4: "core"}
ELF_MACHINES = {3: "x86", 8: "mips", 20: "powerpc", 21: "powerpc64", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
PE_MACHINES = {0x14C: "x86", 0x1C4: "arm", 0x8664: "x86_64", 0xAA64: "aarch64"}
PE_OPTIONAL = {0x10B: "pe32", 0x20B: "pe32+"}
SHF_WRITE, SHF_EXECINSTR = 0x1, 0x4
SHN_XINDEX = 0xFFFF
SCN_MEM_EXECUTE, SCN_MEM_WRITE = 0x20000000, 0x80000000


class StructureError(ContractError):
    """The input claims a format whose structure is truncated or inconsistent."""


def _need(data, offset, length, what):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise StructureError(f"{what} lies outside the input")


def _name(raw: bytes) -> str:
    """Printable ASCII for an untrusted name; other bytes and the backslash itself become \\xNN escapes."""
    return "".join(chr(b) if 0x20 <= b < 0x7F and b != 0x5C else "\\x{:02x}".format(b) for b in raw[:MAX_NAME_BYTES])


def _pe_offset(data):
    """Offset of the "PE\\0\\0" signature, or None when the input is not a PE image."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset + 4 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        return None
    return offset


def _format(data):
    if data[:4] == ELF_MAGIC:
        return "elf", 0, 4
    pe = _pe_offset(data)
    if pe is not None:
        return "pe", pe, 4
    if data[:4] in MACHO_MAGICS:
        return "macho", 0, 4
    if data[:4] in FAT_MAGICS:
        return "macho-universal", 0, 4
    if data[:4] in ZIP_MAGICS:
        return "zip", 0, 4
    return "unknown", 0, min(UNKNOWN_PREFIX, len(data))


def identify(data, args):
    kind, offset, length = _format(data)
    if not length:
        return []  # an empty input has no bytes to cite
    excerpt = data[offset:offset + length]
    value = {"format": kind, "magic": excerpt.hex()}
    if kind == "macho-universal":
        order, entry_size = FAT_MAGICS[data[:4]]
        count = struct.unpack_from(order + "I", data, 4)[0] if len(data) >= 8 else 0
        count = min(count, 8, max(0, (len(data) - 8) // entry_size))
        value["architectures"] = [MACHO_MACHINES.get(struct.unpack_from(order + "I", data, 8 + entry_size * i)[0], "unknown")
                                  for i in range(count)]
    return [Observation(Location(offset, length), value)]


def _macho_layout(data):
    if data[:4] not in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return None
    width = 64 if data[:4] == b"\xcf\xfa\xed\xfe" else 32
    size = 32 if width == 64 else 28
    _need(data, 0, size, "Mach-O header")
    _, machine, _, filetype, ncmds, sizeofcmds, _ = struct.unpack_from("<7I", data)
    return width, size, machine, filetype, ncmds, sizeofcmds


def _macho_commands(data, h):
    _, position, _, _, count, size = h
    _need(data, position, size, "Mach-O load commands")
    end = position + size
    if count > min(size // 8, MAX_TABLE_ENTRIES):
        raise StructureError("Mach-O command count exceeds its table")
    for _ in range(count):
        if position + 8 > end:
            raise StructureError("Truncated Mach-O load command")
        command, length = struct.unpack_from("<II", data, position)
        if length < 8 or length % 4 or position + length > end:
            raise StructureError("Invalid Mach-O load command size")
        yield command, position, length
        position += length


def _macho_section_rows(data, h):
    index = 0
    for command, position, length in _macho_commands(data, h):
        if command not in (1, 0x19):
            continue
        width = 64 if command == 0x19 else 32
        if width != h[0]:
            raise StructureError("Mach-O segment width disagrees with its header")
        segment_size, section_size = (72, 80) if width == 64 else (56, 68)
        if length < segment_size:
            raise StructureError("Truncated Mach-O segment")
        prot_offset = 60 if width == 64 else 44
        initprot, count = struct.unpack_from("<II", data, position + prot_offset)
        fileoff, filesize = struct.unpack_from("<QQ" if width == 64 else "<II", data, position + (40 if width == 64 else 32))
        if count > (length - segment_size) // section_size:
            raise StructureError("Mach-O sections exceed their load command")
        for ordinal in range(count):
            start = position + segment_size + section_size * ordinal
            sectname, segname = struct.unpack_from("<16s16s", data, start)
            address, size, offset = struct.unpack_from("<QQI" if width == 64 else "<III", data, start + 32)
            flags = struct.unpack_from("<I", data, start + (64 if width == 64 else 56))[0]
            row = {"index": index, "name": _name(segname.split(b"\0", 1)[0]) + "," + _name(sectname.split(b"\0", 1)[0]),
                   "addr": address, "offset": offset, "size": size,
                   "writable": bool(initprot & 2), "executable": bool(initprot & 4 or flags & 0x80000400)}
            backed = (flags & 0xFF not in (1, 0xC, 0x12) and fileoff <= offset
                      and offset + size <= min(len(data), fileoff + filesize))
            yield Location(start, section_size), row, backed
            index += 1


def macho_sections(data):
    """File-backed thin LE Mach-O sections for host address mapping; original indices are retained."""
    h = _macho_layout(data)
    if h is None:
        return []
    rows = []
    for _, row, backed in _macho_section_rows(data, h):
        if row["index"] >= MAX_SECTIONS:
            break
        if backed:
            rows.append(row)
    return rows


def macho_entry(data):
    """Entry VA from LC_MAIN or a supported LC_UNIXTHREAD state; malformed/ambiguous inputs yield None."""
    try:
        h = _macho_layout(data)
        if h is None:
            return None
        commands = list(_macho_commands(data, h))
        mains, thread_entries, segments = [], [], []
        for command, position, size in commands:
            if command == 0x80000028:
                if size < 24:
                    return None
                mains.append(struct.unpack_from("<Q", data, position + 8)[0])
            elif command in (1, 0x19):
                width = 64 if command == 0x19 else 32
                if width != h[0] or size < (72 if width == 64 else 56):
                    return None
                section_count = struct.unpack_from("<I", data, position + (64 if width == 64 else 48))[0]
                if section_count > (size - (72 if width == 64 else 56)) // (80 if width == 64 else 68):
                    return None
                segments.append(struct.unpack_from("<QQQQ" if width == 64 else "<IIII", data, position + 24))
            elif command == 5:
                start, end = position + 8, position + size
                while start < end:
                    if start + 8 > end:
                        return None
                    flavor, count = struct.unpack_from("<II", data, start)
                    state = start + 8
                    if count > (end - state) // 4:
                        return None
                    expected = (4, 42, 128) if h[2] == 0x1000007 else (6, 68, 256) if h[2] == 0x100000C else None
                    if expected and flavor == expected[0]:
                        if count != expected[1]:
                            return None
                        thread_entries.append(struct.unpack_from("<Q", data, state + expected[2])[0])
                    start = state + count * 4
        if mains:
            if len(mains) != 1:
                return None
            entries = []
            for address, virtual_size, offset, size in segments:
                delta = mains[0] - offset
                if (offset + size <= len(data) and 0 <= delta < min(size, virtual_size)
                        and address + virtual_size <= 2**h[0]):
                    entries.append(address + delta)
            return entries[0] if len(entries) == 1 else None
        return thread_entries[0] if len(thread_entries) == 1 else None
    except StructureError:
        return None


def _elf_layout(data):
    _need(data, 0, 16, "ELF identification")
    width = {1: 32, 2: 64}.get(data[4])
    order = {1: "<", 2: ">"}.get(data[5])
    if width is None or order is None:
        raise StructureError("Unsupported ELF class or byte order")
    size = 52 if width == 32 else 64
    _need(data, 0, size, "ELF header")
    word = "I" if width == 32 else "Q"
    fields = struct.unpack_from(order + "HHI" + word * 3 + "IHHHHHH", data, 16)
    names = ("type", "machine", "version", "entry", "phoff", "shoff", "flags", "ehsize", "phentsize", "phnum",
             "shentsize", "shnum", "shstrndx")
    return width, order, size, dict(zip(names, fields))


def _pe_layout(data, pe):
    coff = pe + 4
    _need(data, coff, 20, "COFF header")
    machine, sections, timestamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, coff)
    if optional_size < 20:
        raise StructureError("PE optional header is smaller than the fields read")
    optional = coff + 20
    _need(data, optional, 20, "Optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    entry = struct.unpack_from("<I", data, optional + 16)[0]
    return {"machine": machine, "sections": sections, "timestamp": timestamp, "optional_size": optional_size,
            "characteristics": characteristics, "magic": magic, "entry": entry, "optional": optional}


def headers(data, args):
    kind, offset, _ = _format(data)
    if kind == "elf":
        width, order, size, h = _elf_layout(data)
        return [Observation(Location(0, size), {
            "format": "elf", "class": width, "endianness": "little" if order == "<" else "big",
            "type": h["type"], "type_name": ELF_TYPES.get(h["type"], "unknown"),
            "machine": h["machine"], "machine_name": ELF_MACHINES.get(h["machine"], "unknown"),
            "entry": h["entry"], "shnum": h["shnum"], "shoff": h["shoff"],
        })]
    if kind == "pe":
        h = _pe_layout(data, offset)
        # Signature, COFF header and the optional header up to AddressOfEntryPoint.
        return [Observation(Location(offset, h["optional"] + 20 - offset), {
            "format": "pe", "machine": h["machine"], "machine_name": PE_MACHINES.get(h["machine"], "unknown"),
            "number_of_sections": h["sections"], "timestamp": h["timestamp"], "characteristics": h["characteristics"],
            "optional_magic": PE_OPTIONAL.get(h["magic"], "unknown"), "entry_rva": h["entry"],
        })]
    if kind == "macho":
        h = _macho_layout(data)
        if h is not None:
            count = sum(1 for _ in _macho_section_rows(data, h))
            return [Observation(Location(0, h[1]), {
                "structure": "macho", "format": "macho", "machine_name": MACHO_MACHINES.get(h[2], "unknown"),
                "filetype": h[3], "ncmds": h[4], "number_of_sections": count,
            })]
    return []


def _elf_sections(data, limit):
    width, order, _, h = _elf_layout(data)
    entry = 40 if width == 32 else 64
    if h["shnum"] == 0 and h["shoff"] == 0:
        return []  # no section header table
    if h["shentsize"] != entry:
        raise StructureError("Unexpected ELF section header size")
    layout = order + ("IIIIIIIIII" if width == 32 else "IIQQQQIIQQ")
    shnum, shstrndx = h["shnum"], h["shstrndx"]
    if shnum == 0 or shstrndx == SHN_XINDEX:
        # Extended numbering: section 0 holds the real count (sh_size) and name table index (sh_link).
        _need(data, h["shoff"], entry, "ELF section header 0")
        first = struct.unpack_from(layout, data, h["shoff"])
        shnum = shnum or first[5]
        shstrndx = first[6] if shstrndx == SHN_XINDEX else shstrndx
    if shnum == 0:
        return []
    count = min(shnum, limit)
    _need(data, h["shoff"], entry * count, "ELF section header table")
    strtab = None
    if 0 < shstrndx < shnum:  # SHN_UNDEF (0) means no name table
        index_offset = h["shoff"] + entry * shstrndx
        _need(data, index_offset, entry, "ELF section name table header")
        values = struct.unpack_from(layout, data, index_offset)
        _need(data, values[4], values[5], "ELF section name table")
        strtab = (values[4], values[5])
    found = []
    for index in range(count):
        offset = h["shoff"] + entry * index
        name, kind, flags, _, start, size = struct.unpack_from(layout, data, offset)[:6]
        label = ""
        if strtab is not None and name < strtab[1]:
            begin = strtab[0] + name
            end = min(strtab[0] + strtab[1], begin + MAX_NAME_BYTES)
            terminator = data.find(b"\0", begin, end)
            label = _name(data[begin:end if terminator < 0 else terminator])
        found.append(Observation(Location(offset, entry), {
            "index": index, "name": label, "type": kind, "flags": flags, "offset": start, "size": size,
            "executable": bool(flags & SHF_EXECINSTR), "writable": bool(flags & SHF_WRITE),
        }))
    return found


def _pe_sections(data, pe, limit):
    h = _pe_layout(data, pe)
    table = h["optional"] + h["optional_size"]
    count = min(h["sections"], limit)
    _need(data, table, 40 * count, "PE section table")
    found = []
    for index in range(count):
        offset = table + 40 * index
        raw_name, virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<8sIIII", data, offset)
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        found.append(Observation(Location(offset, 40), {
            "index": index, "name": _name(raw_name.split(b"\0", 1)[0]), "virtual_address": virtual_address,
            "virtual_size": virtual_size, "offset": raw_offset, "size": raw_size, "characteristics": characteristics,
            "executable": bool(characteristics & SCN_MEM_EXECUTE), "writable": bool(characteristics & SCN_MEM_WRITE),
        }))
    return found


def sections(data, args):
    limit = args["max_sections"]
    kind, offset, _ = _format(data)
    if kind == "elf":
        return _elf_sections(data, limit)
    if kind == "pe":
        return _pe_sections(data, offset, limit)
    if kind == "macho":
        h = _macho_layout(data)
        if h is not None:
            found = []
            for location, row, _ in _macho_section_rows(data, h):
                value = {key: value for key, value in row.items() if key != "addr"}
                found.append(Observation(location, value))
                if len(found) >= limit:
                    break
            return found
    return []


def _import_name(data, start, end):
    """A bounded, nonempty C string; its citation covers exactly the rendered prefix's source bytes."""
    end = min(end, len(data))
    if not 0 <= start < end:
        return None
    stop = data.find(b"\0", start, min(end, start + MAX_IMPORT_NAME + 1))
    if stop < 0:
        if end - start <= MAX_IMPORT_NAME:
            return None
        stop = start + MAX_IMPORT_NAME
    rendered, consumed = "", 0
    for byte in data[start:stop]:
        part = chr(byte) if 0x20 <= byte < 0x7F and byte != 0x5C else "\\x{:02x}".format(byte)
        if len(rendered) + len(part) > MAX_IMPORT_NAME:
            break
        rendered += part
        consumed += 1
    return (rendered, Location(start, consumed)) if consumed else None


def _elf_import_records(data):
    width, order, _, h = _elf_layout(data)
    entry = 40 if width == 32 else 64
    if h["shoff"] == 0 or h["shentsize"] != entry:
        return
    layout = order + ("IIIIIIIIII" if width == 32 else "IIQQQQIIQQ")
    _need(data, h["shoff"], entry, "ELF section header 0")
    count = h["shnum"] or struct.unpack_from(layout, data, h["shoff"])[5]
    count = min(count, (len(data) - h["shoff"]) // entry, MAX_TABLE_ENTRIES)
    remaining = MAX_TABLE_ENTRIES
    for index in range(count):
        values = struct.unpack_from(layout, data, h["shoff"] + entry * index)
        kind, offset, size, link, entsize = values[1], values[4], values[5], values[6], values[9]
        if kind not in (6, 11) or link >= count:
            continue
        strings = struct.unpack_from(layout, data, h["shoff"] + entry * link)
        if strings[1] != 3:
            continue
        strings_start, strings_size = strings[4], strings[5]
        if not 0 <= offset < len(data) or not 0 <= strings_start < len(data):
            continue
        expected = (8 if width == 32 else 16) if kind == 6 else (16 if width == 32 else 24)
        if entsize != expected:
            continue
        entries = min(size // entsize, (len(data) - offset) // entsize, remaining)
        remaining -= entries
        for i in range(entries):
            position = offset + i * entsize
            if kind == 6:
                tag, name = struct.unpack_from(order + ("II" if width == 32 else "QQ"), data, position)
                if tag == 0:
                    break
                if tag != 1:
                    continue
            else:
                name = struct.unpack_from(order + "I", data, position)[0]
                section = struct.unpack_from(order + "H", data, position + (14 if width == 32 else 6))[0]
                if section != 0:
                    continue
            if name == 0 or name >= strings_size:
                continue
            value = _import_name(data, strings_start + name, strings_start + strings_size)
            if value:
                yield ("library" if kind == 6 else "symbols"), None, value


def _pe_import_records(data, pe):
    h = _pe_layout(data, pe)
    optional, plus = h["optional"], h["magic"] == 0x20B
    if h["magic"] not in (0x10B, 0x20B):
        return
    directories = 112 if plus else 96
    if h["optional_size"] < directories + 16:
        return
    _need(data, optional, h["optional_size"], "PE optional header")
    if struct.unpack_from("<I", data, optional + directories - 4)[0] < 2:
        return
    rva, size = struct.unpack_from("<II", data, optional + directories + 8)
    if not rva or not size:
        return
    rows = [o.value for o in _pe_sections(data, pe, MAX_SECTIONS)]
    header_size = struct.unpack_from("<I", data, optional + 60)[0]

    def mapped(address, length=1):
        spans = []
        if 0 <= address and address + length <= min(header_size, len(data)):
            spans.append((address, min(header_size, len(data))))
        for row in rows:
            extent = min(row["size"], row["virtual_size"]) if row["virtual_size"] else row["size"]
            delta = address - row["virtual_address"]
            if 0 <= delta and delta + length <= extent:
                start = row["offset"] + delta
                end = min(len(data), row["offset"] + extent)
                if start + length <= end:
                    spans.append((start, end))
        return spans[0] if len(spans) == 1 and address + length <= 2**32 else None

    for index in range(min(size // 20, MAX_TABLE_ENTRIES)):
        descriptor = mapped(rva + index * 20, 20)
        if descriptor is None:
            break
        original, stamp, chain, name_rva, first = struct.unpack_from("<5I", data, descriptor[0])
        if not any((original, stamp, chain, name_rva, first)):
            break
        name_span = mapped(name_rva) if name_rva else None
        library = _import_name(data, *name_span) if name_span else None
        if library is None:
            break
        yield "library", None, library
        word = 8 if plus else 4
        thunk_rva = original or first
        for ordinal in range(MAX_TABLE_ENTRIES):
            thunk = mapped(thunk_rva + word * ordinal, word) if thunk_rva else None
            if thunk is None:
                break
            value = struct.unpack_from("<Q" if plus else "<I", data, thunk[0])[0]
            if value == 0:
                break
            if value & (1 << (word * 8 - 1)):
                if value & ~((1 << (word * 8 - 1)) | 0xFFFF):
                    break
                name = ("#" + str(value & 0xFFFF), Location(thunk[0], word))
            else:
                span = mapped(value, 3)
                name = _import_name(data, span[0] + 2, span[1]) if span else None
            if name is None:
                break
            yield "symbols", library[0], name


def _macho_import_records(data):
    h = _macho_layout(data)
    if h is None:
        return
    symbols = []
    for command, position, size in _macho_commands(data, h):
        if command in (0xC, 0x80000018):
            if size < 24:
                break
            start = struct.unpack_from("<I", data, position + 8)[0]
            value = _import_name(data, position + start, position + size) if 24 <= start < size else None
            if value:
                yield "library", None, value
        elif command == 2:
            if size < 24:
                break
            symbols.append(struct.unpack_from("<4I", data, position + 8))
    remaining = MAX_TABLE_ENTRIES
    for offset, count, strings, strings_size in symbols:
        entry = 16 if h[0] == 64 else 12
        if offset >= len(data) or strings >= len(data):
            continue
        count = min(count, (len(data) - offset) // entry, remaining)
        remaining -= count
        for index in range(count):
            position = offset + entry * index
            name, kind, section, _, value = struct.unpack_from("<IBBHQ" if h[0] == 64 else "<IBBHI", data, position)
            if kind & 0xE0 or kind & 0x0E or section or value or not name or name >= strings_size:
                continue
            imported = _import_name(data, strings + name, strings + strings_size)
            if imported:
                yield "symbols", None, imported


def imports(data, args):
    """Import declarations, cut at malformed tables, bounded by observation count and JSON size."""
    kind, offset, _ = _format(data)
    records = (_elf_import_records(data) if kind == "elf" else _pe_import_records(data, offset) if kind == "pe"
               else _macho_import_records(data) if kind == "macho" else ())
    found, names, library, anchor = [], [], None, None

    def flush():
        if names:
            found.append(Observation(anchor, {"kind": "symbols", "library": library, "names": list(names)}))
            names.clear()

    try:
        for kind, current_library, (name, location) in records:
            if kind == "library":
                flush()
                if len(found) >= args["max_imports"]:
                    break
                found.append(Observation(location, {"kind": "library", "name": name}))
            else:
                value = {"kind": "symbols", "library": current_library, "names": names + [name]}
                if names and (library != current_library or len(names) == 32
                              or len(canonical_json(value).encode()) > MAX_OBSERVATION_BYTES):
                    flush()
                if len(found) >= args["max_imports"]:
                    break
                if not names:
                    library, anchor = current_library, location
                names.append(name)
            if len(found) >= args["max_imports"]:
                break
    except StructureError:
        pass  # Retain the valid prefix, including any pending symbol group.
    if len(found) < args["max_imports"]:
        flush()
    return found


TOOL = ToolSpec(REF, {
    "structure.identify": OperationSpec("structure.identify", {}, identify, max_observations=1),
    "structure.headers": OperationSpec("structure.headers", {}, headers, max_observations=1),
    "structure.sections": OperationSpec("structure.sections",
                                        {"max_sections": ArgSpec("int", minimum=1, maximum=MAX_SECTIONS, default=64)},
                                        sections, max_observations=MAX_SECTIONS),
    "structure.imports": OperationSpec("structure.imports",
                                       {"max_imports": ArgSpec("int", minimum=1, maximum=MAX_IMPORTS, default=128)},
                                       imports, max_observations=MAX_IMPORTS),
})
