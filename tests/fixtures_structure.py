"""Deterministic, inert ELF and PE fixtures built from declared values; no binary files.

Each builder returns (data, layout): the bytes and the offsets its fixed rules
produced, so tests can state exact expected observations.
"""

from __future__ import annotations

import struct

# (name, sh_type, sh_flags, size): .text is AX, .data WA, .rwx WAX (writable and executable).
ELF_SECTIONS = ((b".text", 1, 0x6, 32), (b".data", 1, 0x3, 16), (b".rwx", 1, 0x7, 8))
# (name, characteristics, raw size): code RX, data RW, rwx RWX.
PE_SECTIONS = ((b".text", 0x60000020, 0x200), (b".data", 0xC0000040, 0x200), (b".rwx", 0xE0000020, 0x200))


def elf(*, width=64, order="<", kind=2, machine=62, entry=0x401000, sections=ELF_SECTIONS):
    """An ELF header, section contents, .shstrtab and a section table (null entry first, .shstrtab last)."""
    header_size, entry_size = (64, 64) if width == 64 else (52, 40)
    contents, offsets, position = b"", [], header_size
    for _, _, _, size in sections:
        offsets.append(position)
        contents += bytes(size)
        position += size
    names, name_offsets = b"\0", []
    for name, _, _, _ in sections:
        name_offsets.append(len(names))
        names += name + b"\0"
    shstrtab_name = len(names)
    names += b".shstrtab\0"
    strtab_offset = position
    position += len(names)
    shoff = (position + 7) & ~7
    shnum = len(sections) + 2
    word = "Q" if width == 64 else "I"
    layout = order + ("IIQQQQIIQQ" if width == 64 else "IIIIIIIIII")
    table = bytes(entry_size)  # SHN_UNDEF
    for (name, sh_type, flags, size), name_offset, offset in zip(sections, name_offsets, offsets):
        table += struct.pack(layout, name_offset, sh_type, flags, 0, offset, size, 0, 0, 1, 0)
    table += struct.pack(layout, shstrtab_name, 3, 0, 0, strtab_offset, len(names), 0, 0, 1, 0)
    ident = b"\x7fELF" + bytes([2 if width == 64 else 1, 1 if order == "<" else 2, 1]) + bytes(9)
    header = ident + struct.pack(order + "HHI" + word * 3 + "IHHHHHH", kind, machine, 1, entry, 0, shoff, 0,
                                 header_size, 0, 0, entry_size, shnum, shnum - 1)
    data = header + contents + names
    data += bytes(shoff - len(data)) + table
    return data, {"header_size": header_size, "entry_size": entry_size, "shoff": shoff, "shnum": shnum,
                  "offsets": offsets, "name_offsets": name_offsets, "strtab_offset": strtab_offset}


def pe(*, plus=True, machine=0x8664, entry_rva=0x1000, timestamp=0x5F5E1000, characteristics=0x22, sections=PE_SECTIONS):
    """DOS header (e_lfanew 0x80), PE signature, COFF and optional headers, section table, raw data at 0x200 alignment."""
    lfanew, alignment = 0x80, 0x200
    optional_size = 240 if plus else 224
    dos = b"MZ" + bytes(0x3A) + struct.pack("<I", lfanew) + bytes(lfanew - 0x40)
    coff = struct.pack("<HHIIIHH", machine, len(sections), timestamp, 0, 0, optional_size, characteristics)
    optional = struct.pack("<HBBIIIII", 0x20B if plus else 0x10B, 14, 0, 0x200, 0x400, 0, entry_rva, 0x1000)
    optional += bytes(optional_size - len(optional))
    table_offset = lfanew + 4 + 20 + optional_size
    headers_end = table_offset + 40 * len(sections)
    raw = (headers_end + alignment - 1) // alignment * alignment
    table, raw_offsets = b"", []
    for index, (name, flags, size) in enumerate(sections):
        raw_offsets.append(raw)
        table += struct.pack("<8sIIIIIIHHI", name, size, 0x1000 * (index + 1), size, raw, 0, 0, 0, 0, flags)
        raw += size
    data = dos + b"PE\0\0" + coff + optional + table
    data += bytes(raw_offsets[0] - len(data)) if sections else b""
    for _, _, size in sections:
        data += bytes(size)
    return data, {"lfanew": lfanew, "optional_size": optional_size, "table_offset": table_offset, "raw_offsets": raw_offsets}


def patched(data, offset, fmt, value):
    """A copy of data with one packed field replaced: the malformed variants below."""
    out = bytearray(data)
    struct.pack_into(fmt, out, offset, value)
    return bytes(out)


def malformed():
    """Named truncated or inconsistent inputs and the operations that must reject them with ValueError."""
    elf64, elf_layout = elf()
    pe64, pe_layout = pe()
    coff = pe_layout["lfanew"] + 4
    both, tables = ("structure.headers", "structure.sections"), ("structure.sections",)
    return {
        "elf truncated identification": (elf64[:10], both),
        "elf truncated header": (elf64[:40], both),
        "elf bad class": (patched(elf64, 4, "B", 9), both),
        "elf bad byte order": (patched(elf64, 5, "B", 0), both),
        "elf section table past end": (patched(elf64, 40, "<Q", len(elf64)), tables),
        "elf huge section count": (patched(elf64, 60, "<H", 0xFFFF), tables),
        "elf wrong section entry size": (patched(elf64, 58, "<H", 12), tables),
        "elf name table past end": (patched(elf64, elf_layout["shoff"] + 64 * (elf_layout["shnum"] - 1) + 24, "<Q", 2**63), tables),
        "elf truncated section table": (elf64[:elf_layout["shoff"] + 70], tables),
        "pe truncated coff": (pe64[:coff + 10], both),
        "pe truncated optional": (pe64[:coff + 30], both),
        "pe huge section count": (patched(pe64, coff + 2, "<H", 0xFFFF), tables),
        "pe huge optional size": (patched(pe64, coff + 16, "<H", 0xFFFF), tables),
        "pe truncated section table": (pe64[:pe_layout["table_offset"] + 50], tables),
    }


def structure_evidence(data, task):
    """What a gateway would produce for the task, built without importing the gateway."""
    from reverseai.contract import make_evidence
    from reverseai.tools.structure import TOOL

    evidence = []
    for request in task.operations:
        spec = TOOL.operations[request.operation]
        for observation in spec.handler(data, spec.validate_args(request.args)):
            evidence.append(make_evidence(data, TOOL.ref, request.operation, observation))
    return tuple(evidence)
