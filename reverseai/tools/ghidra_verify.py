"""Re-derive derived Ghidra observations' executable byte anchors, not code semantics."""

from collections import namedtuple
import struct

from reverseai.contract import ContractError, Location, Observation
from reverseai.tools.structure import (
    SHF_EXECINSTR, SCN_MEM_EXECUTE, _elf_layout, _format, _need, _pe_layout,
)

REFUSED = "Worker code anchor not confirmed by the bytes"
_Section = namedtuple("_Section", "va offset size span executable")
_FIELDS = {
    "function": {"kind", "index", "name", "entry", "size"},
    "pseudocode": {"kind", "index", "entry", "text", "truncated"},
    "call": {"kind", "from", "to", "to_name"},
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
            _check(va + size <= 2**width)
            backed = size if kind not in (0, 8) else 0
            if backed:
                _need(data, offset, backed, "ELF section contents")
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
        sections.append(_Section(base + rva, offset, size, span, bool(flags & SCN_MEM_EXECUTE)))
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
    _check(_map(sections, entry, length, virtual=True) == (offset, section))
    _check(_map(sections, offset, length, virtual=False) == (entry, section))
    return Location(offset, length)


def verify(data, observations, args):
    """Validate the whole reply before admitting any derived observation."""
    try:
        _verify(data, observations, args)
    except (ContractError, struct.error, TypeError, KeyError, ValueError):
        raise ContractError(REFUSED) from None


def _verify(data, observations, args):
    _check(isinstance(data, bytes) and isinstance(observations, (list, tuple)) and len(observations) <= 400)
    sections, binary_entry = _sections(data)
    functions, pseudocode, calls = [], [], []
    for item in observations:
        _check(isinstance(item, Observation) and item.location.within(len(data)))
        value = item.value
        kind = value.get("kind")
        _check(kind in _FIELDS and set(value) == _FIELDS[kind])
        if kind == "function":
            _check(type(value["index"]) is int and value["index"] == len(functions) and _name(value["name"]))
            _check(_uint(value["entry"]) and _uint(value["size"], 1) and value["entry"] + value["size"] <= 2**64)
            _check(not functions or value["entry"] > functions[-1].value["entry"])
            _check(item.location == _function_anchor(sections, value["entry"], value["size"]))
            functions.append(item)
        elif kind == "pseudocode":
            _check(type(value["index"]) is int and _uint(value["entry"]) and isinstance(value["text"], str))
            _check(len(value["text"]) <= args["max_chars"] and type(value["truncated"]) is bool)
            pseudocode.append(item)
        else:
            _check(_uint(value["from"]) and _uint(value["to"]) and _name(value["to_name"]))
            _check(1 <= item.location.length <= 16)
            calls.append(item)
    _check(len(functions) <= args["max_functions"] and len(pseudocode) <= args["decompile"]
           and len(calls) <= args["max_calls"])
    by_entry = {item.value["entry"]: item for item in functions}
    selection = sorted(functions, key=lambda item: (item.value["entry"] != binary_entry,
                                                   -item.value["size"], item.value["entry"]))
    ranks = {item.value["index"]: index for index, item in enumerate(selection)}
    previous = -1
    for item in pseudocode:
        value = item.value
        _check(0 <= value["index"] < len(functions))
        function = functions[value["index"]]
        _check(value["entry"] == function.value["entry"] and item.location == function.location)
        _check(ranks[value["index"]] > previous)
        previous = ranks[value["index"]]
    for item in calls:
        value = item.value
        _check(value["from"] in by_entry)
        function = by_entry[value["from"]].value
        va, section = _map(sections, item.location.offset, item.location.length, virtual=False)
        _check(_map(sections, va, item.location.length, virtual=True) == (item.location.offset, section))
        _check(value["from"] <= va and va + item.location.length <= value["from"] + function["size"])
