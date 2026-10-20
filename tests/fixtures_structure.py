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


def elf(*, width=64, order="<", kind=2, machine=62, entry=0x401000, sections=ELF_SECTIONS, extended=False, shstrndx=None):
    """An ELF header, section contents, .shstrtab and a section table (null entry first, .shstrtab last).

    extended uses ELF extended numbering: e_shnum 0 and e_shstrndx SHN_XINDEX, with the real values in
    section 0's sh_size and sh_link; extended="index" moves only the name table index there.
    shstrndx overrides the name table index.
    """
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
    names_index = shnum - 1 if shstrndx is None else shstrndx
    count_moved, index_moved = extended is True, bool(extended)
    table = struct.pack(layout, 0, 0, 0, 0, 0, shnum if count_moved else 0, names_index if index_moved else 0, 0, 0, 0)
    for (name, sh_type, flags, size), name_offset, offset in zip(sections, name_offsets, offsets):
        table += struct.pack(layout, name_offset, sh_type, flags, 0, offset, size, 0, 0, 1, 0)
    table += struct.pack(layout, shstrtab_name, 3, 0, 0, strtab_offset, len(names), 0, 0, 1, 0)
    ident = b"\x7fELF" + bytes([2 if width == 64 else 1, 1 if order == "<" else 2, 1]) + bytes(9)
    header = ident + struct.pack(order + "HHI" + word * 3 + "IHHHHHH", kind, machine, 1, entry, 0, shoff, 0,
                                 header_size, 0, 0, entry_size, 0 if count_moved else shnum, 0xFFFF if index_moved else names_index)
    data = header + contents + names
    data += bytes(shoff - len(data)) + table
    return data, {"header_size": header_size, "entry_size": entry_size, "shoff": shoff, "shnum": shnum,
                  "offsets": offsets, "name_offsets": name_offsets, "strtab_offset": strtab_offset}


def pe(*, plus=True, machine=0x8664, entry_rva=0x1000, timestamp=0x5F5E1000, characteristics=0x22, sections=PE_SECTIONS,
       optional_size=None):
    """DOS header (e_lfanew 0x80), PE signature, COFF and optional headers, section table, raw data at 0x200 alignment.

    optional_size declares and lays out a shorter optional header (at least 20 bytes: magic through entry point).
    """
    lfanew, alignment = 0x80, 0x200
    optional_size = optional_size or (240 if plus else 224)
    dos = b"MZ" + bytes(0x3A) + struct.pack("<I", lfanew) + bytes(lfanew - 0x40)
    coff = struct.pack("<HHIIIHH", machine, len(sections), timestamp, 0, 0, optional_size, characteristics)
    optional = struct.pack("<HBBIIIII", 0x20B if plus else 0x10B, 14, 0, 0x200, 0x400, 0, entry_rva, 0x1000)
    optional = optional[:optional_size] + bytes(max(0, optional_size - len(optional)))
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
        # Undersized: the following bytes exist, so only the declared size can reject them.
        "pe zero optional size": (patched(pe64, coff + 16, "<H", 0), both),
        "pe optional size below its fields": (patched(pe64, coff + 16, "<H", 8), both),
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


MACHO_SECTIONS = ((b"__text", b"__TEXT", 0x80000400, 5, 16),
                  (b"__data", b"__DATA", 0, 3, 8), (b"__rwx", b"__RWX", 0, 7, 8))


def macho(*, width=64, order="<", machine=None, sections=MACHO_SECTIONS, libraries=(), symbols=(), entry="main"):
    """Thin Mach-O, one segment per section, plus optional dylib/symtab/entry commands; no code is executed.

    Each section is (sectname, segname, flags, initprot, size). Symbols are undefined external
    nlist entries, except one defined control. layout gives every relevant field/name offset.
    """
    header_size, segment_size, section_size = (32, 72, 80) if width == 64 else (28, 56, 68)
    machine = machine if machine is not None else (0x1000007 if width == 64 else 7)
    commands, section_offsets, dylib_names = [], [], []
    position = header_size
    for _ in sections:
        section_offsets.append(position + segment_size)
        commands.append(bytes(segment_size + section_size))
        position += segment_size + section_size
    for index, name in enumerate(libraries):
        command = 0xC if index % 2 == 0 else 0x80000018
        size = (24 + len(name) + 1 + 7) & ~7
        dylib_names.append(position + 24)
        commands.append(struct.pack(order + "6I", command, size, 24, 0, 0, 0) + name + b"\0" + bytes(size - 25 - len(name)))
        position += size
    symtab_command = position if symbols else None
    if symbols:
        commands.append(bytes(24))
        position += 24
    entry_command = position if entry else None
    if entry == "main":
        commands.append(bytes(24))
        position += 24
    elif entry in ("x86_thread", "arm_thread"):
        count, pc_offset, flavor = (42, 128, 4) if entry == "x86_thread" else (68, 256, 6)
        state = bytearray(count * 4)
        commands.append(struct.pack(order + "4I", 5, 16 + len(state), flavor, count) + state)
        position += 16 + len(state)
    content_start = (position + 15) & ~15
    raw, section_addresses = content_start, []
    base = 0x100000000 if width == 64 else 0x1000
    for index, (sectname, segname, flags, prot, size) in enumerate(sections):
        address = base + raw
        section_addresses.append(address)
        if width == 64:
            segment = struct.pack(order + "II16sQQQQIIII", 0x19, segment_size + section_size, segname,
                                  address, size, raw, size, 7, prot, 1, 0)
            section = struct.pack(order + "16s16sQQIIIIIIII", sectname, segname, address, size, raw, 0, 0, 0, flags, 0, 0, 0)
        else:
            segment = struct.pack(order + "II16s8I", 1, segment_size + section_size, segname,
                                  address, size, raw, size, 7, prot, 1, 0)
            section = struct.pack(order + "16s16s9I", sectname, segname, address, size, raw, 0, 0, 0, flags, 0, 0)
        commands[index] = segment + section
        raw += size
    symbol_entry_size = 16 if width == 64 else 12
    symbols_offset = raw
    strings = b"\0"
    symbol_names = []
    entries = bytes(symbol_entry_size)  # Undefined null symbol must never become an import.
    for name in symbols:
        symbol_names.append(len(strings))
        values = (len(strings), 1, 0, 0, 0)
        entries += struct.pack(order + ("IBBHQ" if width == 64 else "IBBHI"), *values)
        strings += name + b"\0"
    # A defined symbol is a negative control, even though it has a name.
    entries += struct.pack(order + ("IBBHQ" if width == 64 else "IBBHI"), len(strings), 0xF, 1, 0, section_addresses[0] if sections else 1)
    strings += b"defined_control\0"
    strings_offset = symbols_offset + len(entries)
    if symbols:
        commands[len(sections) + len(libraries)] = struct.pack(order + "6I", 2, 24, symbols_offset,
                                                                            len(entries) // symbol_entry_size, strings_offset, len(strings))
    entry_address = section_addresses[0] if sections else 0
    if entry == "main":
        commands[-1] = struct.pack(order + "IIQQ", 0x80000028, 24, content_start, 0)
    elif entry in ("x86_thread", "arm_thread"):
        command = bytearray(commands[-1])
        struct.pack_into(order + "Q", command, 16 + pc_offset, entry_address)
        commands[-1] = bytes(command)
    command_bytes = b"".join(commands)
    header = struct.pack(order + "7I", 0xFEEDFACF if width == 64 else 0xFEEDFACE, machine, 3, 2, len(commands), len(command_bytes), 0)
    if width == 64:
        header += bytes(4)
    data = header + command_bytes + bytes(content_start - header_size - len(command_bytes)) + bytes(raw - content_start)
    if symbols:
        data += entries + strings
    return data, {"header_size": header_size, "section_size": section_size, "section_offsets": section_offsets,
                  "content_start": content_start, "addresses": section_addresses, "dylib_names": dylib_names,
                  "symtab_command": symtab_command, "symbols_offset": symbols_offset, "strings_offset": strings_offset,
                  "symbol_names": [strings_offset + i for i in symbol_names], "entry_command": entry_command, "entry": entry_address}


def macho_fat(*, width=32, order=">", machines=(7, 0x1000007, 0x100000C)):
    """Only the universal wrapper is needed by identify; no architecture slice is interpreted."""
    header = struct.pack(order + "II", 0xCAFEBABE if width == 32 else 0xCAFEBABF, len(machines))
    layout = order + ("5I" if width == 32 else "IIQQII")
    rows = b"".join(struct.pack(layout, machine, 0, 0, 0, 0, *(() if width == 32 else (0,))) for machine in machines)
    return header + rows


def elf_imports(*, width=64, order="<", libraries=(b"libalpha.so", b"libbeta.so"), symbols=(b"alpha", b"beta")):
    """SHT_DYNAMIC and SHT_DYNSYM linked to .dynstr, plus a defined-symbol negative control."""
    dynamic_entry, symbol_entry, section_entry = (16, 24, 64) if width == 64 else (8, 16, 40)
    names, library_offsets, symbol_offsets = b"\0", [], []
    for group, offsets in ((libraries, library_offsets), (symbols, symbol_offsets)):
        for name in group:
            offsets.append(len(names))
            names += name + b"\0"
    defined = len(names)
    names += b"defined_control\0"
    dynamic = b"".join(struct.pack(order + ("QQ" if width == 64 else "II"), 1, i) for i in library_offsets) + bytes(dynamic_entry)
    syms = bytes(symbol_entry)
    for i in symbol_offsets + [defined]:
        section = 1 if i == defined else 0
        syms += struct.pack(order + "IBBHQQ", i, 0x12, 0, section, 0, 0) if width == 64 else struct.pack(order + "IIIBBH", i, 0, 0, 0x12, 0, section)
    data, layout = elf(width=width, order=order, sections=((b".dynamic", 6, 3, len(dynamic)),
                            (b".dynstr", 3, 2, len(names)), (b".dynsym", 11, 2, len(syms))))
    out = bytearray(data)
    for offset, value in zip(layout["offsets"], (dynamic, names, syms)):
        out[offset:offset + len(value)] = value
    for index, entsize in ((1, dynamic_entry), (3, symbol_entry)):
        header = layout["shoff"] + index * section_entry
        struct.pack_into(order + "I", out, header + (40 if width == 64 else 24), 2)
        struct.pack_into(order + ("Q" if width == 64 else "I"), out, header + (56 if width == 64 else 36), entsize)
    layout.update(library_names=[layout["offsets"][1] + i for i in library_offsets],
                  symbol_names=[layout["offsets"][1] + i for i in symbol_offsets], dynamic=layout["offsets"][0],
                  dynsym=layout["offsets"][2], strings=layout["offsets"][1], strings_size=len(names))
    return bytes(out), layout


def pe_imports(*, plus=True, libraries=((b"KERNEL32.dll", (b"ExitProcess", 7)), (b"USER32.dll", (b"MessageBoxA",))), original=True):
    """One .idata section with import descriptors, DLL names, hints/names and terminated thunk lists."""
    descriptor_size, rva, word = 20 * (len(libraries) + 1), 0x1000, 8 if plus else 4
    blob = bytearray(descriptor_size)
    dll_names, symbol_names, thunk_offsets = [], [], []
    for index, (library, symbols) in enumerate(libraries):
        name_offset = len(blob)
        dll_names.append(name_offset)
        blob += library + b"\0"
        values, offsets = [], []
        for symbol in symbols:
            if isinstance(symbol, int):
                values.append((1 << (word * 8 - 1)) | symbol)
                offsets.append(None)
            else:
                blob += bytes(-len(blob) % 2)
                values.append(rva + len(blob))
                offsets.append(len(blob) + 2)
                blob += bytes(2) + symbol + b"\0"
        blob += bytes(-len(blob) % word)
        thunks = len(blob)
        thunk_offsets.append(thunks)
        for i, value in enumerate(values):
            blob += struct.pack("<Q" if plus else "<I", value)
            if offsets[i] is None:
                offsets[i] = thunks + word * i
        blob += bytes(word)
        symbol_names.append(offsets)
        struct.pack_into("<5I", blob, index * 20, rva + thunks if original else 0, 0, 0, rva + name_offset, rva + thunks)
    raw_size = (len(blob) + 0x1FF) & ~0x1FF
    data, layout = pe(plus=plus, sections=((b".idata", 0xC0000040, raw_size),))
    out = bytearray(data)
    raw = layout["raw_offsets"][0]
    optional = layout["lfanew"] + 24
    directories = optional + (112 if plus else 96)
    struct.pack_into("<I", out, directories - 4, 16)
    struct.pack_into("<II", out, directories + 8, rva, descriptor_size)
    struct.pack_into("<I", out, optional + 60, raw)
    out[raw:raw + len(blob)] = blob
    layout.update(descriptor=raw, directory=directories + 8, library_names=[raw + i for i in dll_names],
                  symbol_names=[[raw + i for i in group] for group in symbol_names],
                  thunks=[raw + i for i in thunk_offsets], word=word)
    return bytes(out), layout
