"""Closed query names, typed arguments and fixed operation requests (contract M3d)."""

from dataclasses import dataclass
import re
from types import MappingProxyType

from reverseai.contract import ArgSpec, ContractError, OperationRequest, OperationSpec


def _integer(low, high, default=None):
    return ArgSpec("int", low, high, default=default)


START = _integer(0, 65535, 0)
HOST_START = _integer(0, 1048575, 0)
LIMIT = _integer(1, 256, 64)
FUNCTION_ARGS = {
    "select": ArgSpec("enum", choices=("entry", "name"), default="entry"),
    "entry": _integer(0, 2**64 - 1, 0), "name": ArgSpec("str", default=""),
}


@dataclass(frozen=True)
class QuerySpec:
    operations: tuple
    args: object
    role: str = "structural"
    fixed: object = None

    def validate(self, raw):
        return OperationSpec("query.arguments", self.args, lambda data, args: ()).validate_args(raw)

    def requests(self, args):
        return tuple(OperationRequest(name, {} if name == "structure.entry" else {**args, **(self.fixed or {})})
                     for name in self.operations)


def _query(operation, args, *, fixed=None):
    return QuerySpec((operation,), MappingProxyType(args), "code" if operation.startswith("ghidra.") else "structural",
                     MappingProxyType(fixed or {}))


TABLE = MappingProxyType({
    "binary_overview": QuerySpec(tuple("structure." + name for name in ("identify", "headers", "sections", "imports", "entry")),
                                 MappingProxyType({})),
    "list_segments": _query("structure.segments", {"start": START, "limit": LIMIT}),
    "inspect_native_load_image": QuerySpec(("structure.segments", "structure.entry"),
                                           MappingProxyType({"start": START, "limit": LIMIT})),
    "list_names": _query("structure.symbols", {"query": ArgSpec("literal", 0, 128, default=""),
                                               "start": HOST_START, "limit": _integer(1, 256, 128)}),
    "read_bytes": _query("structure.read_bytes", {"mode": ArgSpec("enum", choices=("offset", "address"), default="offset"),
                                                  "at": _integer(0, 2**64 - 1, 0), "length": _integer(1, 2000, 256)}),
    "list_strings": _query("strings.list", {"encoding": ArgSpec("enum", choices=("any", "ascii", "utf16le"), default="any"),
                                            "min_length": _integer(4, 64, 6), "start": HOST_START,
                                            "limit": _integer(1, 256, 128)}),
    "search_strings": _query("strings.search", {"query": ArgSpec("literal", 1, 128),
                                                "encoding": ArgSpec("enum", choices=("any", "ascii", "utf16le"), default="any"),
                                                "start": HOST_START, "limit": LIMIT}),
    "list_procedures": _query("ghidra.functions", {"start": START, "limit": _integer(1, 128, 64)}, fixed={"query": ""}),
    "search_procedures": _query("ghidra.functions", {"query": ArgSpec("str", default=""),
                                                    "start": START, "limit": _integer(1, 128, 64)}),
    **{name: _query("ghidra.function", {**FUNCTION_ARGS, **args}, fixed={"parts": part})
       for name, part, args in (
           ("procedure_info", "info", {}),
           ("procedure_pseudo_code", "pseudocode", {"max_chars": _integer(64, 2048, 1024)}),
           ("procedure_assembly", "assembly", {"start": START, "limit": LIMIT}),
           ("procedure_callees", "callees", {"max_calls": _integer(0, 256, 64)}),
           ("procedure_callers", "callers", {"max_calls": _integer(0, 256, 64)}),
           ("analyze_function", "all", {"start": START, "limit": LIMIT, "max_chars": _integer(64, 2048, 1024),
                                         "max_calls": _integer(0, 256, 64), "max_refs": _integer(0, 128, 64)}))},
    "xrefs": _query("ghidra.xrefs", {"address": _integer(0, 2**64 - 1), "start": START, "limit": LIMIT}),
})


def resolve(name, args):
    if not isinstance(name, str) or name not in TABLE:
        raise ContractError("Unknown query")
    spec = TABLE[name]
    return spec, spec.validate(args)


def parse_args(name, values):
    """CLI KEY=VALUE arguments, with decimal/hex integers and no duplicate keys."""
    if name not in TABLE:
        raise ContractError("Unknown query")
    schema, raw = TABLE[name].args, {}
    for item in values:
        key, separator, value = item.partition("=")
        if not separator or key not in schema or key in raw:
            raise ContractError("Invalid or duplicate query argument")
        if schema[key].kind == "int":
            if len(value) > 32 or not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", value):
                raise ContractError("Invalid query integer")
            value = int(value, 16 if value.lower().startswith("0x") else 10)
        raw[key] = value
    return resolve(name, raw)[1]
