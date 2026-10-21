"""Re-derive Ghidra byte anchors and referenced strings, not code semantics."""

from collections import namedtuple
import struct

from reverseai.contract import ContractError, Location, Observation
from reverseai.tools import structure
from reverseai.tools.structure import (
    SHF_EXECINSTR, SCN_MEM_EXECUTE, _elf_layout, _format, _need, _pe_layout,
)

REFUSED = "Worker code anchor not confirmed by the bytes"
SHF_ALLOC = 0x2
_Section = namedtuple("_Section", "va offset size span executable")
_FIELDS = {
    "function": {"kind", "index", "name", "entry", "size"},
    "pseudocode": {"kind", "index", "entry", "text", "truncated"},
    "call": {"kind", "from", "to", "to_name"},
    "assembly": {"kind", "index", "entry", "instructions", "truncated"},
    "ref": {"kind", "from", "to", "type", "to_name"},
    "string": {"kind", "address", "encoding", "text", "truncated", "from"},
}


def _check(condition):
    if not condition:
        raise ContractError(REFUSED)


def _uint(value, minimum=0):
    return type(value) is int and minimum <= value < 2**64


def _name(value):
    return isinstance(value, str) and len(value) <= 128 and all(char.isprintable() for char in value)


def _sections(data):
    kind, pe, _ = _format(data)
    sections = []
    if kind == "macho":
        _check(data[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"))
        mapped = structure.macho_sections(data)
        _check(bool(mapped))
        width = 64 if data[:4] == b"\xcf\xfa\xed\xfe" else 32
        _check(all(row["addr"] + row["size"] <= 2**width for row in mapped))
        sections = [_Section(row["addr"], row["offset"], row["size"], row["size"], row["executable"])
                    for row in mapped]
        return sections, structure.macho_entry(data)
    if kind == "elf":
        width, order, _, header = _elf_layout(data)
        entry, layout = (40, "IIIIIIIIII") if width == 32 else (64, "IIQQQQIIQQ")
        if header["shnum"] == header["shoff"] == 0:
            return sections, header["entry"]
        _check(header["shentsize"] == entry and header["shoff"] > 0)
        count = header["shnum"]
        if count == 0:
            _need(data, header["shoff"], entry, "ELF section header zero")
            count = struct.unpack_from(order + layout, data, header["shoff"])[5]
        _need(data, header["shoff"], count * entry, "ELF section table")
        for index in range(count):
            _, kind, flags, va, offset, size = struct.unpack_from(order + layout, data, header["shoff"] + index * entry)[:6]
            backed = size if kind not in (0, 8) else 0
            if backed:
                _need(data, offset, backed, "ELF section contents")
            if flags & SHF_ALLOC:
                _check(va + size <= 2**width)
                sections.append(_Section(va, offset, backed, size if kind else 0, bool(flags & SHF_EXECINSTR)))
        return sections, header["entry"]
    _check(kind == "pe")
    header = _pe_layout(data, pe)
    optional = header["optional"]
    _check(header["magic"] in (0x10B, 0x20B) and header["optional_size"] >= 32)
    _need(data, optional, header["optional_size"], "PE optional header")
    base = struct.unpack_from("<Q" if header["magic"] == 0x20B else "<I", data,
                              optional + (24 if header["magic"] == 0x20B else 28))[0]
    width = 64 if header["magic"] == 0x20B else 32
    _check(base + header["entry"] < 2**width)
    table = optional + header["optional_size"]
    _need(data, table, header["sections"] * 40, "PE section table")
    for index in range(header["sections"]):
        at = table + index * 40
        _, virtual_size, rva, size, offset = struct.unpack_from("<8sIIII", data, at)
        flags = struct.unpack_from("<I", data, at + 36)[0]
        span = max(size, virtual_size)
        _check(rva + span <= 2**32 and base + rva + span <= 2**width)
        if size:
            _need(data, offset, size, "PE section contents")
        backed = min(size, virtual_size or size)
        sections.append(_Section(base + rva, offset, backed, backed, bool(flags & SCN_MEM_EXECUTE)))
    return sections, base + header["entry"]


def _map(sections, start, length, *, virtual):
    matches = [section for section in sections
               if start < (section.va + section.span if virtual else section.offset + section.size)
               and start + length > (section.va if virtual else section.offset)
               and (section.span if virtual else section.size) > 0]
    _check(len(matches) == 1)
    section = matches[0]
    delta = start - (section.va if virtual else section.offset)
    _check(section.executable and 0 <= delta and delta + length <= section.size)
    return (section.offset if virtual else section.va) + delta, section


def _function_anchor(sections, entry, size):
    offset, section = _map(sections, entry, 1, virtual=True)
    length = min(size, 4096, section.size - (entry - section.va))
    _map(sections, entry, length, virtual=True)
    _map(sections, offset, length, virtual=False)
    return Location(offset, length)


def _file_map(sections, start, length, *, virtual):
    """String mapping admits only file-backed bytes, independent of execute permission."""
    matches = [section for section in sections if section.size > 0
               and start < (section.va if virtual else section.offset) + section.size
               and start + length > (section.va if virtual else section.offset)]
    _check(len(matches) == 1)
    section = matches[0]
    delta = start - (section.va if virtual else section.offset)
    _check(0 <= delta and delta + length <= section.size)
    return (section.offset if virtual else section.va) + delta, section


def _string_bytes(data, offset, end):
    for encoding, width in (("ascii", 1), ("utf-16le", 2)):
        chars = []
        while len(chars) < 128 and offset + (len(chars) + 1) * width <= end:
            unit = data[offset + len(chars) * width:offset + (len(chars) + 1) * width]
            if not 0x20 <= unit[0] <= 0x7e or (width == 2 and unit[1] != 0):
                break
            chars.append(chr(unit[0]))
        following = data[offset + len(chars) * width:min(end, offset + (len(chars) + 1) * width)]
        truncated = (len(chars) == 128 and len(following) == width
                     and 0x20 <= following[0] <= 0x7e and (width == 1 or following[1] == 0))
        if len(chars) >= 2 and (truncated or following == bytes(width)):
            return encoding, "".join(chars), truncated
    raise ContractError(REFUSED)


def verify(data, observations, args):
    """Validate the whole reply before admitting any derived observation."""
    try:
        _verify(data, observations, args)
    except (ContractError, struct.error, TypeError, KeyError, ValueError):
        raise ContractError(REFUSED) from None


def _verify(data, observations, args):
    args = {"assembly": 4, "max_instructions": 32, "max_refs": 64, "max_strings": 32, **args}
    _check(isinstance(data, bytes) and isinstance(observations, (list, tuple)) and len(observations) <= 600)
    sections, binary_entry = _sections(data)
    groups = {kind: [] for kind in _FIELDS}
    order = {kind: index for index, kind in enumerate(_FIELDS)}
    previous_kind = 0
    for item in observations:
        _check(isinstance(item, Observation) and item.location.within(len(data)))
        value = item.value
        kind = value.get("kind")
        _check(isinstance(kind, str) and kind in _FIELDS and set(value) == _FIELDS[kind])
        _check(order[kind] >= previous_kind)
        previous_kind = order[kind]
        functions = groups["function"]
        if kind == "function":
            _check(type(value["index"]) is int and value["index"] == len(functions) and _name(value["name"]))
            _check(_uint(value["entry"]) and _uint(value["size"], 1) and value["entry"] + value["size"] <= 2**64)
            _check(not functions or value["entry"] > functions[-1].value["entry"])
            _check(item.location == _function_anchor(sections, value["entry"], value["size"]))
        elif kind in ("pseudocode", "assembly"):
            _check(type(value["index"]) is int and _uint(value["entry"]) and type(value["truncated"]) is bool)
            if kind == "pseudocode":
                _check(isinstance(value["text"], str) and len(value["text"]) <= args["max_chars"])
            else:
                _check(isinstance(value["instructions"], list) and 1 <= len(value["instructions"]) <= args["max_instructions"])
                end = 0
                for row in value["instructions"]:
                    _check(isinstance(row, list) and len(row) == 3)
                    delta, length, text = row
                    _check(_uint(delta) and type(length) is int and 1 <= length <= 16
                           and end <= delta and delta + length <= item.location.length)
                    _check(isinstance(text, str) and 1 <= len(text) <= 64 and all(0x20 <= ord(c) <= 0x7e for c in text))
                    end = delta + length
        elif kind in ("call", "ref"):
            _check(_uint(value["from"]) and _uint(value["to"]) and _name(value["to_name"]))
            _check(1 <= item.location.length <= 16)
            if kind == "ref":
                _check(value["type"] in ("read", "write", "read_write", "data", "jump"))
        else:
            _check(_uint(value["address"]) and type(value["truncated"]) is bool)
            _check(isinstance(value["from"], list) and 1 <= len(value["from"]) <= 8
                   and all(_uint(entry) for entry in value["from"]))
        groups[kind].append(item)
    for kind, limit in (("function", "max_functions"), ("pseudocode", "decompile"), ("call", "max_calls"),
                        ("assembly", "assembly"), ("ref", "max_refs"), ("string", "max_strings")):
        _check(len(groups[kind]) <= args[limit])
    functions = groups["function"]
    by_entry = {item.value["entry"]: item for item in functions}
    selection = sorted(functions, key=lambda item: (item.value["entry"] != binary_entry,
                                                   -item.value["size"], item.value["entry"]))
    ranks = {item.value["index"]: index for index, item in enumerate(selection)}
    for kind in ("pseudocode", "assembly"):
        previous = -1
        for item in groups[kind]:
            value = item.value
            _check(0 <= value["index"] < len(functions))
            function = functions[value["index"]]
            _check(value["entry"] == function.value["entry"] and item.location == function.location)
            _check(ranks[value["index"]] > previous)
            previous = ranks[value["index"]]
    for item in groups["call"] + groups["ref"]:
        value = item.value
        _check(value["from"] in by_entry)
        function = by_entry[value["from"]].value
        va, _ = _map(sections, item.location.offset, item.location.length, virtual=False)
        _map(sections, va, item.location.length, virtual=True)
        _check(value["from"] <= va and va + item.location.length <= value["from"] + function["size"])
    previous = None
    origins = {}
    for item in groups["ref"]:
        value = item.value
        key = (item.location.offset, value["to"], value["type"])
        _check(previous is None or key > previous)
        previous = key
        origins.setdefault(value["to"], set()).add(value["from"])
    previous = -1
    for item in groups["string"]:
        value = item.value
        address = value["address"]
        _check(address > previous and address in origins)
        previous = address
        _check(value["from"] == sorted(origins[address])[:8])
        offset, section = _file_map(sections, address, 1, virtual=True)
        encoding, text, truncated = _string_bytes(data, offset, section.offset + section.size)
        _check((value["encoding"], value["text"], value["truncated"]) == (encoding, text, truncated))
        length = len(text.encode(encoding))
        _check(item.location == Location(offset, length))
        checked_length = length + (1 if encoding == "ascii" else 2)
        _file_map(sections, address, checked_length, virtual=True)
        _file_map(sections, offset, checked_length, virtual=False)
