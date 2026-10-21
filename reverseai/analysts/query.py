"""Claims for one closed query; all citations are reviewed independently afterwards."""

from reverseai.analysts import structural
from reverseai.contract import MAX_EVIDENCE_PER_FINDING, ToolRef, evidence_intact, make_finding

REFS = {"structure": ToolRef("structure", "0.1.0"), "strings": ToolRef("strings", "0.1.0"),
        "ghidra": ToolRef("ghidra", "12.1.4-r6"), "apk": ToolRef("apk", "0.1.0"), "dex": ToolRef("dex", "0.1.0")}
PAGES = {
    "structure.segments": ("segment", "segments.list", ("name", "offset", "filesz", "address", "memsz", "readable", "writable", "executable")),
    "structure.symbols": ("symbol", "symbols.list", ("name", "address", "type", "binding", "defined")),
    "strings.list": ("string", "strings.listed", ("offset", "encoding", "text", "truncated")),
    "strings.search": ("string", "strings.matches", ("offset", "encoding", "text", "truncated")),
    "ghidra.functions": ("function_row", "code.function_list", ("name", "entry", "size")),
    "ghidra.xrefs": ("xref", "code.xrefs", ("at", "from", "type")),
    # contract/3, M4a: Android packages
    "apk.inventory": ("member", "android.members", ("name", "method", "compressed_size", "size", "crc32", "sha256", "flags")),
    "apk.manifest": ("manifest_attribute", "android.manifest", ("element_index", "element", "attribute", "type", "value")),
    "dex.classes": ("class", "android.classes", ("dex", "name", "access", "superclass")),
    "dex.methods": ("method", "android.methods", ("dex", "class", "name", "prototype", "access", "code_offset", "code_units")),
    "dex.references": ("dex_ref", "android.references",
                       ("dex", "from_class", "from_method", "from_prototype", "at", "ref_kind", "target", "target_truncated")),
}
PERMISSION_ELEMENTS = ("uses-permission", "uses-permission-sdk-23")
SINGLES = {
    ("structure.entry", "entry"): ("load.entry", ("address", "offset")),
    ("structure.read_bytes", "bytes"): ("bytes.read", ("offset", "address", "hex")),
    ("ghidra.function", "target"): ("code.function_info", ("name", "entry", "size", "matches", "callers_total", "callees_total")),
    ("ghidra.function", "pseudocode"): ("code.pseudocode", ("entry", "text", "truncated")),
    ("ghidra.function", "instructions"): ("code.instructions", ("entry", "start", "total", "rows", "truncated")),
}


def _chunks(items):
    for start in range(0, len(items), MAX_EVIDENCE_PER_FINDING):
        yield items[start:start + MAX_EVIDENCE_PER_FINDING]


def _within(item, task):
    """Inside the input, or inside the child artifact the evidence names (contract/3)."""
    return item.location.within(task.input.size if item.artifact is None else item.artifact["size"])


def conclude(task, evidence):
    allowed = {request.operation for request in task.operations}
    own = {item.id: item for item in evidence if evidence_intact(item)
           and item.input_sha256 == task.input.sha256 and item.operation in allowed
           and item.tool == REFS.get(item.tool.name) and _within(item, task)}
    findings = []

    def emit(key, value, items):
        findings.append(make_finding(task.role, "Query result.", key, value, [item.id for item in items],
                                     "inferred" if key.startswith("code.") else "observed"))

    # The overview reuses the existing structural conclusions; imports are additional query results.
    if "structure.identify" in allowed:
        findings.extend(structural.conclude(task, tuple(own.values())))
    for operation in sorted(allowed):
        items = [item for item in own.values() if item.operation == operation]
        if operation in PAGES:
            kind, key, fields = PAGES[operation]
            rows = [item for item in items if item.observation.get("kind") == kind]
            if not rows or any(type(item.observation.get("index")) is not int
                               or type(item.observation.get("total")) is not int
                               or not set(fields) <= set(item.observation) for item in rows):
                continue
            rows.sort(key=lambda item: item.observation["index"])
            start, total = rows[0].observation["index"], rows[0].observation["total"]
            if start < 0 or start + len(rows) > total or any(
                    item.observation["index"] != start + i or item.observation["total"] != total for i, item in enumerate(rows)):
                continue
            if kind == "xref" and (any("to" not in item.observation for item in rows)
                                   or len({item.observation["to"] for item in rows}) != 1):
                continue
            for chunk in _chunks(rows):
                value = {"start": chunk[0].observation["index"], "total": total,
                         "rows": [[item.observation[field] for field in fields] for item in chunk]}
                if kind == "xref":
                    value["to"] = chunk[0].observation["to"]
                emit(key, value, chunk)
        for (op, kind), (key, fields) in SINGLES.items():
            if op != operation:
                continue
            selected = [item for item in items if item.observation.get("kind") == kind]
            if len(selected) == 1 and set(fields) <= set(selected[0].observation):
                emit(key, {field: selected[0].observation[field] for field in fields}, selected)
        if operation == "structure.imports":
            for kind, key in (("library", "imports.libraries"), ("symbols", "imports.symbols")):
                selected = [item for item in items if item.observation.get("kind") == kind][:MAX_EVIDENCE_PER_FINDING]
                names = [item.observation.get("name") for item in selected] if kind == "library" else [
                    name for item in selected for name in item.observation.get("names", [])]
                if names and all(isinstance(name, str) for name in names):
                    emit(key, sorted(set(names)), selected)
        if operation == "apk.manifest":
            # One finding: the permissions of the page's first 64 uses-permission names, in document order.
            selected = sorted((item for item in items if item.observation.get("kind") == "manifest_attribute"
                               and item.observation.get("element") in PERMISSION_ELEMENTS
                               and item.observation.get("attribute") == "android:name"
                               and item.observation.get("type") == "string"
                               and isinstance(item.observation.get("value"), str) and item.observation["value"]
                               and type(item.observation.get("index")) is int),
                              key=lambda item: item.observation["index"])[:MAX_EVIDENCE_PER_FINDING]
            if selected:
                emit("android.permissions", sorted({item.observation["value"] for item in selected}), selected)
        if operation == "ghidra.function":
            for kind, key, fields in (("call", "code.calls", ("from", "to_name")),
                                       ("ref", "code.references", ("from", "type", "to", "to_name"))):
                selected = [item for item in items if item.observation.get("kind") == kind and set(fields) <= set(item.observation)]
                selected.sort(key=lambda item: tuple(item.observation[field] for field in fields))
                for chunk in _chunks(selected):
                    emit(key, [list(row) for row in sorted({tuple(item.observation[field] for field in fields) for item in chunk})], chunk)
            selected = [item for item in items if item.observation.get("kind") == "caller"
                        and {"at", "from", "to"} <= set(item.observation)]
            selected.sort(key=lambda item: item.observation["at"])
            for chunk in _chunks(selected):
                if len({item.observation["to"] for item in chunk}) == 1:
                    emit("code.callers", {"to": chunk[0].observation["to"],
                                           "rows": [[item.observation["at"], item.observation["from"]] for item in chunk]}, chunk)
    return tuple(findings)
