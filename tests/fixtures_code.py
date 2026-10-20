"""Deterministic ELF64 and PE32+ x86-64 fixtures with real instructions, for the M3 Ghidra lanes; no binary files.

The same four hand-assembled functions are placed in each container:

    entry        calls add_numbers, then compute, then exits (mov eax, 60; xor edi, edi; syscall; ret)
    add_numbers  push rbp; mov rbp, rsp; mov eax, edi; add eax, esi; pop rbp; ret
    compute      push rbx; add_numbers(2, 3); mov ebx, eax; constant(); add eax, ebx; pop rbx; ret
    constant     mov eax, 42; ret

with four direct `call rel32` instructions (5 bytes each) and int3 padding between functions. The
ELF has a .symtab naming them (entry is `_start`); the PE has no symbols. elf_data_only() is a clean
control with no executable section and no entry point. Each builder returns (data, layout): the
bytes and the declared addresses, file offsets and sizes, so tests can state exact expectations.
"""

from __future__ import annotations

import struct

PAD = 0xCC  # int3 between functions
# Function name, offset inside .text; their bytes are assembled by _code below.
FUNCTIONS = (("_start", 0x00), ("add_numbers", 0x20), ("compute", 0x30), ("constant", 0x50))
TEXT_SIZE = 0x56


def _rel32(at, length, target):
    return struct.pack("<i", target - (at + length))


def _code():
    """(.text bytes, functions [(name, offset, size)], calls [(from offset, call offset, target offset)])."""
    starts = dict(FUNCTIONS)
    text = bytearray([PAD]) * TEXT_SIZE
    calls = []

    def put(offset, *parts):
        at = offset
        for part in parts:
            if isinstance(part, tuple):  # ("call", target name)
                target = starts[part[1]]
                calls.append((offset, at, target))
                part = b"\xe8" + _rel32(at, 5, target)
            text[at:at + len(part)] = part
            at += len(part)
        return at - offset

    sizes = {
        "_start": put(0x00, ("call", "add_numbers"), ("call", "compute"), b"\xb8\x3c\x00\x00\x00", b"\x31\xff",
                      b"\x0f\x05", b"\xc3"),
        "add_numbers": put(0x20, b"\x55", b"\x48\x89\xe5", b"\x89\xf8", b"\x01\xf0", b"\x5d", b"\xc3"),
        "compute": put(0x30, b"\x53", b"\xbf\x02\x00\x00\x00", b"\xbe\x03\x00\x00\x00", ("call", "add_numbers"),
                       b"\x89\xc3", ("call", "constant"), b"\x01\xd8", b"\x5b", b"\xc3"),
        "constant": put(0x50, b"\xb8\x2a\x00\x00\x00", b"\xc3"),
    }
    functions = [(name, offset, sizes[name]) for name, offset in FUNCTIONS]
    assert functions[-1][1] + functions[-1][2] == TEXT_SIZE
    return bytes(text), functions, calls


def _layout(text_offset, text_address, functions, calls, *, named):
    """Declared addresses and file offsets; names are None when the container has no symbols (the tool names them)."""
    by_offset = {offset: name if named else None for name, offset, _ in functions}
    return {
        "entry": text_address + dict((n, o) for n, o, _ in functions)["_start"],
        "text": {"offset": text_offset, "address": text_address, "size": TEXT_SIZE},
        "functions": [{"name": by_offset[offset], "entry": text_address + offset, "offset": text_offset + offset, "size": size}
                      for name, offset, size in functions],
        "calls": [{"from": text_address + start, "address": text_address + at, "offset": text_offset + at, "length": 5,
                   "to": text_address + target, "to_name": by_offset[target]} for start, at, target in calls],
    }


def _strtab(names):
    table, offsets = b"\0", {}
    for name in names:
        offsets[name] = len(table)
        table += name + b"\0"
    return table, offsets


def elf_code():
    """ET_EXEC x86-64: one R+X PT_LOAD over headers and .text, then .symtab, .strtab, .shstrtab and the section table."""
    text, functions, calls = _code()
    base, text_offset = 0x400000, 0x100
    text_address = base + text_offset
    strtab, names = _strtab([name.encode() for name, _, _ in functions])
    symtab = bytes(24) + b"".join(
        struct.pack("<IBBHQQ", names[name.encode()], 0x12, 0, 1, text_address + offset, size)  # GLOBAL FUNC in section 1
        for name, offset, size in functions)
    shstrtab, shnames = _strtab([b".text", b".symtab", b".strtab", b".shstrtab"])
    symtab_offset = text_offset + TEXT_SIZE + (-(text_offset + TEXT_SIZE) % 8)
    strtab_offset = symtab_offset + len(symtab)
    shstrtab_offset = strtab_offset + len(strtab)
    shoff = shstrtab_offset + len(shstrtab) + (-(shstrtab_offset + len(shstrtab)) % 8)
    sections = [bytes(64),
                struct.pack("<IIQQQQIIQQ", shnames[b".text"], 1, 0x6, text_address, text_offset, TEXT_SIZE, 0, 0, 16, 0),
                struct.pack("<IIQQQQIIQQ", shnames[b".symtab"], 2, 0, 0, symtab_offset, len(symtab), 3, 1, 8, 24),
                struct.pack("<IIQQQQIIQQ", shnames[b".strtab"], 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0),
                struct.pack("<IIQQQQIIQQ", shnames[b".shstrtab"], 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)]
    layout = _layout(text_offset, text_address, functions, calls, named=True)
    header = (b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, layout["entry"], 64, shoff, 0, 64, 56, 1, 64, len(sections), 4))
    load = struct.pack("<IIQQQQQQ", 1, 0x5, 0, base, base, text_offset + TEXT_SIZE, text_offset + TEXT_SIZE, 0x1000)
    data = bytearray(header + load)
    data += bytes(text_offset - len(data)) + text
    data += bytes(symtab_offset - len(data)) + symtab + strtab + shstrtab
    data += bytes(shoff - len(data)) + b"".join(sections)
    layout.update(format="elf", image_base=base, shoff=shoff, section_names=[".text", ".symtab", ".strtab", ".shstrtab"])
    return bytes(data), layout


def pe_code():
    """PE32+ x86-64 console executable: .text (code, RX) and .data (RW), no symbols, no imports."""
    text, functions, calls = _code()
    image_base, lfanew, file_alignment = 0x140000000, 0x40, 0x200
    text_rva, data_rva, text_offset, data_offset = 0x1000, 0x2000, 0x200, 0x400
    sections = (struct.pack("<8sIIIIIIHHI", b".text", TEXT_SIZE, text_rva, file_alignment, text_offset, 0, 0, 0, 0, 0x60000020)
                + struct.pack("<8sIIIIIIHHI", b".data", 0x10, data_rva, file_alignment, data_offset, 0, 0, 0, 0, 0xC0000040))
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x5F5E1000, 0, 0, 240, 0x22)
    optional = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, 0, file_alignment, file_alignment, 0,
                           text_rva, text_rva, image_base, 0x1000, file_alignment, 6, 0, 0, 0, 6, 0, 0,
                           0x3000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16) + bytes(16 * 8)
    assert len(optional) == 240
    data = bytearray(b"MZ" + bytes(0x3A) + struct.pack("<I", lfanew))
    data += b"PE\0\0" + coff + optional + sections
    data += bytes(text_offset - len(data)) + text + bytes(file_alignment - TEXT_SIZE)
    data += b"ReverseAI data\0\0" + bytes(file_alignment - 16)
    layout = _layout(text_offset, image_base + text_rva, functions, calls, named=False)
    layout.update(format="pe", image_base=image_base, section_names=[".text", ".data"],
                  text_raw_size=file_alignment, data={"offset": data_offset, "address": image_base + data_rva, "size": 0x10})
    return bytes(data), layout


def elf_data_only():
    """A clean control: ET_EXEC with one R+W PT_LOAD and a .data section, no executable section and entry 0."""
    payload = b"ReverseAI clean data-only control\0" + bytes(range(32))
    base, data_offset = 0x400000, 0x100
    shstrtab, shnames = _strtab([b".data", b".shstrtab"])
    shstrtab_offset = data_offset + len(payload)
    shoff = shstrtab_offset + len(shstrtab) + (-(shstrtab_offset + len(shstrtab)) % 8)
    sections = [bytes(64),
                struct.pack("<IIQQQQIIQQ", shnames[b".data"], 1, 0x3, base + data_offset, data_offset, len(payload), 0, 0, 8, 0),
                struct.pack("<IIQQQQIIQQ", shnames[b".shstrtab"], 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)]
    header = (b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, shoff, 0, 64, 56, 1, 64, len(sections), 2))
    load = struct.pack("<IIQQQQQQ", 1, 0x6, data_offset, base + data_offset, base + data_offset, len(payload), len(payload), 0x1000)
    data = bytearray(header + load)
    data += bytes(data_offset - len(data)) + payload + shstrtab
    data += bytes(shoff - len(data)) + b"".join(sections)
    return bytes(data), {"format": "elf", "entry": 0, "functions": [], "calls": [], "shoff": shoff,
                         "data": {"offset": data_offset, "address": base + data_offset, "size": len(payload)}}
