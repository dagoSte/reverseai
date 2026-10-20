"""Bounded structural parsing of ELF and PE headers (tool "structure").

Handlers only read the frozen bytes they are given. Every offset and count
from the input is checked against the input size before it is used, loops
are bounded by max_sections, and nothing is allocated from a size field.
Malformed input raises StructureError, a ValueError with a short message.
"""

from __future__ import annotations

import struct

from reverseai.contract import ArgSpec, ContractError, Location, Observation, OperationSpec, ToolRef, ToolSpec

REF = ToolRef("structure", "0.1.0")
MAX_SECTIONS = 256
MAX_NAME_BYTES = 64
UNKNOWN_PREFIX = 16

ELF_MAGIC = b"\x7fELF"
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")

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
    if data[:4] in ZIP_MAGICS:
        return "zip", 0, 4
    return "unknown", 0, min(UNKNOWN_PREFIX, len(data))


def identify(data, args):
    kind, offset, length = _format(data)
    if not length:
        return []  # an empty input has no bytes to cite
    excerpt = data[offset:offset + length]
    return [Observation(Location(offset, length), {"format": kind, "magic": excerpt.hex()})]


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
    if shstrndx < shnum:
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
    return []


TOOL = ToolSpec(REF, {
    "structure.identify": OperationSpec("structure.identify", {}, identify, max_observations=1),
    "structure.headers": OperationSpec("structure.headers", {}, headers, max_observations=1),
    "structure.sections": OperationSpec("structure.sections",
                                        {"max_sections": ArgSpec("int", minimum=1, maximum=MAX_SECTIONS, default=64)},
                                        sections, max_observations=MAX_SECTIONS),
})
