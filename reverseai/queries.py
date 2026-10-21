"""Closed query names, typed arguments and fixed operation requests (contract M3d; Android names M4a)."""

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
    routes: object = None  # operation -> ({operation argument: query argument}, {operation argument: fixed value})

    def validate(self, raw):
        return OperationSpec("query.arguments", self.args, lambda data, args: ()).validate_args(raw)

    def requests(self, args):
        def arguments(name):
            if self.routes:
                taken, fixed = self.routes[name]
                return {**{key: args[source] for key, source in taken.items()}, **fixed}
            return {} if name == "structure.entry" else {**args, **(self.fixed or {})}
        return tuple(OperationRequest(name, arguments(name)) for name in self.operations)


def _query(operation, args, *, fixed=None):
    return QuerySpec((operation,), MappingProxyType(args), "code" if operation.startswith("ghidra.") else "structural",
                     MappingProxyType(fixed or {}))


def _routed(args, routes):
    """A query whose operations take different arguments: routes[operation] = ({argument: query argument}, fixed)."""
    return QuerySpec(tuple(routes), MappingProxyType(args), routes=MappingProxyType(
        {name: (MappingProxyType(dict(zip(taken, taken)) if isinstance(taken, tuple) else taken), MappingProxyType(fixed))
         for name, (taken, fixed) in routes.items()}))


# Android (contract/3): one DEX member by name, or "" for every classes*.dex member (decision m4a-seams-x4);
# exact descriptors and names.
ANY_DEX = ArgSpec("literal", 0, 255, default="")
CLASS = ArgSpec("literal", 1, 255)
METHOD_ARGS = {"class": CLASS, "method": ArgSpec("literal", 1, 255), "prototype": ArgSpec("literal", 0, 255, default="")}
ANDROID_LIMIT = _integer(1, 256, 128)


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
    "inspect_android_package": _routed(
        {"member_start": START, "member_limit": ANDROID_LIMIT, "attribute_start": START,
         "attribute_limit": _integer(1, 256, 256)},
        {"apk.inventory": ({"start": "member_start", "limit": "member_limit"}, {}),
         "apk.manifest": ({"start": "attribute_start", "limit": "attribute_limit"}, {})}),
    "search_android_classes": _query("dex.classes", {"member": ANY_DEX, "query": ArgSpec("literal", 0, 128, default=""),
                                                     "start": HOST_START, "limit": ANDROID_LIMIT}),
    # dex.classes takes the exact class as its query (at most 128 characters), then the class's methods
    "inspect_android_class": _routed(
        {"member": ANY_DEX, "class": ArgSpec("literal", 1, 128), "start": START, "limit": ANDROID_LIMIT},
        {"dex.classes": ({"member": "member", "query": "class"}, {}),
         "dex.methods": (("member", "class", "start", "limit"), {})}),
    "inspect_android_method": _routed(
        {"member": ANY_DEX, **METHOD_ARGS, "start": START, "limit": ANDROID_LIMIT},
        {"dex.methods": (("member", "class"), {}),
         "dex.references": (("member", "class", "method", "prototype", "start", "limit"), {"direction": "from"})}),
    "trace_android_references": _query("dex.references", {
        "member": ANY_DEX, **METHOD_ARGS, "direction": ArgSpec("enum", choices=("from", "to"), default="from"),
        "start": START, "limit": ANDROID_LIMIT}),
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
