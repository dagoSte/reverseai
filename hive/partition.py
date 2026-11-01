"""Deterministic, model-free map partitioning for the first planning stage.

``partition`` returns lossless map slices, all directed cut calls, and a bounded
summary. Count/byte caps take precedence over affinity: a connected component may
be split. No function is classified or skipped; library/runtime metadata survives.
Byte limits refer to ``encode(slice)`` (compact, sorted-key UTF-8 JSON). An
indivisible function whose complete slice exceeds the cap raises ValueError.
This module does not read files, execute programs or invoke a model.
"""

import json
from collections import defaultdict


def encode(value):
    """Canonical serialization used for the slice and summary byte budgets."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _address(value):
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError:
            raise ValueError(f"invalid address: {value!r}") from None
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError(f"invalid address: {value!r}")
    return value


def _entry(value):
    return _address(value.get("entry", value.get("hex"))) if isinstance(value, dict) else _address(value)


def _summary(groups, cuts, declared, hints, budget):
    lists = {
        "groups": [{"id": g["id"], "functions": len(g["functions"]), "bytes": g["bytes"]} for g in groups],
        "cut_edges": [{k: c[k] for k in ("from", "to", "from_group", "to_group")} for c in cuts],
        "entry_points": [hex(e) for e in sorted(declared)],
        "entry_hints": [hex(e) for e in sorted(hints - declared)],
    }
    result = {key: [] for key in lists}
    result["totals"] = {key: len(rows) for key, rows in lists.items()}
    result["totals"]["functions"] = sum(len(g["functions"]) for g in groups)
    result["omitted"] = {key: len(rows) for key, rows in lists.items()}
    if len(encode(result)) > budget:
        raise ValueError("summary budget cannot hold its counts and omission labels")
    # Round-robin samples keep group sizes, entry points and cut edges represented.
    active = [key for key, rows in lists.items() if rows]
    while active:
        for key in active[:]:
            index = len(result[key])
            result[key].append(lists[key][index])
            result["omitted"][key] -= 1
            if len(encode(result)) > budget:
                result[key].pop()
                result["omitted"][key] += 1
                active.remove(key)
            elif len(result[key]) == len(lists[key]):
                active.remove(key)
    return result


def partition(program_map, *, max_functions=128, max_bytes=65536, summary_bytes=8192):
    """Group related functions within hard caps; return groups/cut_edges/summary.

    Function rows must have consistent unique numeric entry/hex addresses. Call
    slices include incoming and outgoing edges. Strings and data references stay
    with their source (and referenced functions, when present). ``references`` and
    ``data_refs`` use the export's from/to fields. Imports are the supplied names
    actually called by the group. Entry-point lists are restricted to the slice;
    other top-level metadata is preserved and counts toward the byte cap.

    Affinity combines calls, shared string addresses/text and shared data targets.
    Sorted adjacent users represent a shared resource in O(users) edges rather
    than a quadratic clique. Greedy unions prefer stronger affinity, with numeric
    address tie breaks. Remaining groups are packed in address order. This is a
    bounded deterministic heuristic, not a minimum-cut claim.

    Summary entry_points are explicit metadata/flags; entry_hints are main/start
    name hints, not proven executable entry points. Only summary samples may be
    omitted, with exact totals. Complete slices and cut edges are never truncated.
    """
    for name, value in (("max_functions", max_functions), ("max_bytes", max_bytes),
                        ("summary_bytes", summary_bytes)):
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    # Detach every output from the caller, while rejecting non-JSON/NaN inputs.
    source = json.loads(encode(program_map))
    functions = {}
    for row in source["functions"]:
        entry = _entry(row)
        if "hex" in row and _address(row["hex"]) != entry:
            raise ValueError(f"inconsistent function address at {hex(entry)}")
        if entry in functions:
            raise ValueError(f"duplicate function at {hex(entry)}")
        functions[entry] = row
    known = set(functions)
    declared = {_entry(e) for e in source.get("entry_points", [])}
    if source.get("entry_point") is not None:
        declared.add(_entry(source["entry_point"]))
    declared.update(e for e, f in functions.items() if f.get("is_entry") is True)
    hints = {e for e, f in functions.items() if f.get("name") in ("main", "_main", "start", "_start")}

    tables = {key: sorted(source[key], key=encode)
              for key in ("calls", "strings", "references", "data_refs") if key in source}
    attached = {e: set() for e in known}
    affinity, resources = defaultdict(int), defaultdict(set)

    def relate(a, b, weight):
        if a in known and b in known and a != b:
            affinity[tuple(sorted((a, b)))] += weight

    for key, rows in tables.items():
        for index, row in enumerate(rows):
            start = _address(row["from"])
            target = _address(row["address"] if key == "strings" else row["to"])
            if start in known:
                attached[start].add((key, index))
            if key != "strings" and target in known:
                attached[target].add((key, index))
            if key == "calls":
                relate(start, target, 4)
            elif start in known:
                resources[("address", target)].add(start)
                if key == "strings" and row.get("text"):
                    resources[("text", row["text"])].add(start)
    for (kind, _), users in sorted(resources.items()):
        ordered = sorted(users)
        for a, b in zip(ordered, ordered[1:]):
            relate(a, b, 2 if kind == "text" else 3)

    def slice_map(entries, row_ids):
        result = dict(source)
        result["functions"] = [functions[e] for e in sorted(entries)]
        for key, rows in tables.items():
            result[key] = [rows[i] for table, i in sorted(row_ids) if table == key]
        if "imports" in source:
            called = {r.get("to_name") for r in result.get("calls", [])
                      if _address(r["from"]) in entries and _address(r["to"]) not in known}
            result["imports"] = sorted(name for name in source["imports"] if name in called)
        if "entry_points" in source:
            result["entry_points"] = sorted((e for e in source["entry_points"] if _entry(e) in entries), key=encode)
        return result

    parent = {e: e for e in known}
    members = {e: {e} for e in known}
    rows = {e: attached[e] for e in known}

    def root(e):
        while parent[e] != e:
            parent[e] = parent[parent[e]]
            e = parent[e]
        return e

    def merge(a, b):
        entries = members[a] | members[b]
        if len(entries) > max_functions:
            return False
        together = rows[a] | rows[b]
        if len(encode(slice_map(entries, together))) > max_bytes:
            return False
        a, b = sorted((a, b))
        parent[b] = a
        members[a], rows[a] = entries, together
        del members[b], rows[b]
        return True

    for e in sorted(known):
        needed = len(encode(slice_map({e}, rows[e])))
        if needed > max_bytes:
            raise ValueError(f"function {hex(e)} needs {needed} bytes; max_bytes is {max_bytes}")
    for (a, b), weight in sorted(affinity.items(), key=lambda item: (-item[1], item[0])):
        a, b = root(a), root(b)
        if a != b:
            merge(a, b)
    current = None
    for e in sorted(members):
        if current is None or not merge(current, e):
            current = e

    groups, owners = [], {}
    for number, (e, entries) in enumerate(sorted(members.items()), 1):
        mid = f"g{number:04d}"
        # Separate slices may touch the same row; give each its own JSON objects.
        data = encode(slice_map(entries, rows[e]))
        groups.append({"id": mid, "functions": [hex(a) for a in sorted(entries)],
                       "map": json.loads(data), "bytes": len(data)})
        owners.update((a, mid) for a in entries)
    cuts = []
    for row in tables.get("calls", []):
        a, b = _address(row["from"]), _address(row["to"])
        if a in known and b in known and owners[a] != owners[b]:
            cuts.append({**row, "from_group": owners[a], "to_group": owners[b]})
    summary = _summary(groups, cuts, declared, hints, summary_bytes)
    return {"groups": groups, "cut_edges": cuts, "summary": summary, "summary_bytes": len(encode(summary))}
