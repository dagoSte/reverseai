"""Claim rules (contract rule 6): which evidence may support a claim, and the value it must yield.

The reviewer applies these after the provenance checks. A finding is supported only
when every cited item comes from an operation its claim_key allows and the cited
observations yield exactly the finding's value; a claim_key with no rule is never
supported. Rules are trusted reviewer code, independent of the analysts.
"""

from reverseai.contract import canonical_json


def _one(values):
    """The single value all cited observations agree on, or None."""
    distinct = {canonical_json(value): value for value in values}
    return next(iter(distinct.values())) if len(distinct) == 1 else None


def _section_count(observation):
    count = observation.get("shnum", observation.get("number_of_sections"))
    if count == 0 and observation.get("shoff"):
        return None  # ELF extended numbering: the real count is in section 0, not in the header
    return count if type(count) is int else None


def _writable_executable(observations):
    if not all(o.get("writable") is True and o.get("executable") is True for o in observations):
        return None
    return sorted({str(o.get("name", "")) for o in observations})


def _category(name):
    def derive(observations):
        if not all(o.get("category") == name and isinstance(o.get("rule"), str) for o in observations):
            return None
        return sorted({o["rule"] for o in observations})
    return derive


def _writable_executable_indices(observations):
    if not all(o.get("writable") is True and o.get("executable") is True and type(o.get("index")) is int for o in observations):
        return None
    return sorted({o["index"] for o in observations})


def _urls(observations):
    if not all(o.get("rule") == "url" and isinstance(o.get("match"), str) for o in observations):
        return None
    return sorted({o["match"] for o in observations})


CATEGORIES = ("process_injection", "persistence", "network", "crypto", "anti_debug")


def _field(name):
    """One value from the observations that carry the field; observations without it (other physical headers) are ignored."""
    return lambda observations: _one(o[name] for o in observations if name in o)


_format = _field("format")
_machine = _field("machine_name")
_count = lambda obs: _one(_section_count(o) for o in obs if "shnum" in o or "number_of_sections" in o) \
    if any("shnum" in o or "number_of_sections" in o for o in obs) else None

def _signature_rules(observations):
    """Sorted unique reviewed rule IDs; every cited match must name one (the host verified its bytes)."""
    rules = [o.get("rule") for o in observations]
    return sorted(set(rules)) if rules and all(isinstance(r, str) and r for r in rules) else None


def _kind(name):
    """Observations of one derived kind, or None when any cited observation is of another kind."""
    return lambda observations: observations if observations and all(o.get("kind") == name for o in observations) else None


def _function_names(observations):
    functions = _kind("function")(observations)
    return [o["name"] for o in sorted(functions, key=lambda o: o["index"])] if functions else None


def _pseudocode(observations):
    texts = _kind("pseudocode")(observations)
    return {key: texts[0][key] for key in ("entry", "text", "truncated")} if texts and len(texts) == 1 else None


def _calls(observations):
    calls = _kind("call")(observations)
    return [list(pair) for pair in sorted({(o["from"], o["to_name"]) for o in calls})] if calls else None


def _uint(value):
    return type(value) is int and 0 <= value < 2**64


def _ascii(value, minimum, maximum):
    return isinstance(value, str) and minimum <= len(value) <= maximum and all(" " <= char <= "~" for char in value)


def _symbol(value):
    return isinstance(value, str) and len(value) <= 128 and all(char.isprintable() for char in value)


def _rows(rows):
    """1..64 [delta, length, text] instruction rows in address order, non-overlapping (contract M3c)."""
    if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
        return False
    end = 0
    for row in rows:
        if not (isinstance(row, list) and len(row) == 3 and _uint(row[0]) and row[0] >= end
                and type(row[1]) is int and 1 <= row[1] <= 16 and _ascii(row[2], 1, 64)):
            return False
        end = row[0] + row[1]
    return True


def _sources(value):
    return (isinstance(value, list) and 1 <= len(value) <= 8 and all(_uint(entry) for entry in value)
            and all(a < b for a, b in zip(value, value[1:])))


# The reviewer's own checks of the M3c shapes: a malformed reading yields nothing, even when a finding repeats it.
SHAPES = {
    "assembly": lambda o: (type(o.get("index")) is int and 0 <= o["index"] < 128 and _uint(o.get("entry"))
                           and _rows(o.get("instructions")) and type(o.get("truncated")) is bool),
    "ref": lambda o: (_uint(o.get("from")) and _uint(o.get("to")) and o.get("type") in REFERENCE_TYPES
                      and _symbol(o.get("to_name"))),
    "string": lambda o: (_uint(o.get("address")) and o.get("encoding") in ("ascii", "utf-16le")
                         and _ascii(o.get("text"), 2, 128) and type(o.get("truncated")) is bool
                         and (not o["truncated"] or len(o["text"]) == 128) and _sources(o.get("from"))),
}
FIELDS = {
    "assembly": {"kind", "index", "entry", "instructions", "truncated"},
    "ref": {"kind", "from", "to", "type", "to_name"},
    "string": {"kind", "address", "encoding", "text", "truncated", "from"},
}
REFERENCE_TYPES = ("read", "write", "read_write", "data", "jump")


def _shaped(name):
    """Observations of one M3c kind, each with exactly its contract fields and shape, or None."""
    def select(observations):
        chosen = _kind(name)(observations)
        if not chosen or not all(set(o) == FIELDS[name] and SHAPES[name](o) for o in chosen):
            return None
        return chosen
    return select


def _assembly(observations):
    listings = _shaped("assembly")(observations)
    if not listings or len(listings) != 1:
        return None
    return {key: listings[0][key] for key in ("entry", "instructions", "truncated")}


def _references(observations):
    refs = _shaped("ref")(observations)
    if not refs:
        return None
    return [list(row) for row in sorted({(o["from"], o["type"], o["to"], o["to_name"]) for o in refs})]


def _strings(observations):
    """One entry per string address, in address order; two readings of the same address yield nothing."""
    strings = _shaped("string")(observations)
    if not strings:
        return None
    by_address = {}
    for o in strings:
        entry = {key: o[key] for key in ("address", "encoding", "text", "truncated", "from")}
        if by_address.setdefault(o["address"], entry) != entry:
            return None
    return [by_address[address] for address in sorted(by_address)]


MAX_IMPORT_NAMES = 32  # decision m3b-deferred-to-m3c (R3-P): the host tool's own bounds, now also the reviewer's


def _import_name(name):
    return isinstance(name, str) and 0 < len(name) <= 128 and all(char.isprintable() for char in name)


def _import_names(kind):
    """Sorted unique names from cited import observations of one kind (library names or symbol groups)."""
    def derive(observations):
        if not observations or any(o.get("kind") != kind for o in observations):
            return None
        if kind == "library":
            names = [o.get("name") for o in observations]
        elif all(isinstance(o.get("names"), list) and 0 < len(o["names"]) <= MAX_IMPORT_NAMES for o in observations):
            names = [n for o in observations for n in o["names"]]
        else:
            return None  # a symbols group must carry 1..32 names
        return sorted(set(names)) if all(_import_name(n) for n in names) else None
    return derive


# claim_key -> (confidence the claim must carry, {operation it may cite: derive(observations) -> expected value or None}).
# A claim may cite several allowed operations; each operation's citations must yield the same value.
RULES = {
    "format.container": ("observed", {"structure.identify": _format, "lief.headers": _format}),
    "format.machine": ("observed", {"structure.headers": _machine, "lief.headers": _machine}),
    "format.section_count": ("observed", {"structure.headers": _count, "lief.headers": _count}),
    "sections.writable_executable": ("inferred", {"structure.sections": _writable_executable}),
    "sections.writable_executable_indices": ("inferred", {"lief.sections": _writable_executable_indices}),
    "strings.urls": ("observed", {"strings.indicators": _urls}),
    "signatures.rule_matches": ("observed", {"yarax.matches": _signature_rules}),
    "imports.libraries": ("observed", {"structure.imports": _import_names("library")}),
    "imports.symbols": ("observed", {"structure.imports": _import_names("symbols")}),
    # contract/2 derived claims: the tool's reading, always inferred, reviewed as "derived"
    "code.functions": ("inferred", {"ghidra.analyze": _function_names}),
    "code.pseudocode": ("inferred", {"ghidra.analyze": _pseudocode}),
    "code.calls": ("inferred", {"ghidra.analyze": _calls}),
    "code.assembly": ("inferred", {"ghidra.analyze": _assembly}),
    "code.references": ("inferred", {"ghidra.analyze": _references}),
    "code.strings": ("inferred", {"ghidra.analyze": _strings}),
    **{f"capability.{name}": ("inferred", {"strings.indicators": _category(name)}) for name in CATEGORIES},
}


# contract/2: claims that are always a tool's reading; the reviewer reports them as derived whatever a ToolSpec says.
DERIVED_CLAIMS = frozenset(key for key, (_, derivations) in RULES.items() if set(derivations) <= {"ghidra.analyze"})


# claim_key -> the fixed statement a supported finding makes; the value column says what it found.
STATEMENTS = {
    "format.container": "File format identified from its magic bytes",
    "format.machine": "Machine named in the header",
    "format.section_count": "Number of sections declared in the header",
    "sections.writable_executable": "Sections that are both writable and executable",
    "sections.writable_executable_indices": "Section indices that are both writable and executable",
    "strings.urls": "URL strings in the input",
    "signatures.rule_matches": "Reviewed signature rules whose exact byte patterns occur in the input",
    "imports.libraries": "Libraries the file declares it imports",
    "imports.symbols": "Symbols the file declares it imports",
    "code.functions": "Functions the analysis tool identified, in address order",
    "code.pseudocode": "Pseudocode the analysis tool decompiled for one function",
    "code.calls": "Calls between functions the analysis tool identified",
    "code.assembly": "Instructions the analysis tool disassembled for one function",
    "code.references": "References from code to other addresses the analysis tool identified",
    "code.strings": "Strings the analysis tool found referenced from code",
    **{f"capability.{name}": f"String hints of {name.replace('_', ' ')} capability (names only, not behaviour)" for name in CATEGORIES},
}


def statement(claim_key):
    """The reviewer's own wording for a claim; analyst prose is never shown as a verified statement."""
    return STATEMENTS.get(claim_key, "No claim rule")


def check(finding, cited):
    """Reasons the cited evidence does not yield the finding's claim; empty when it does."""
    rule = RULES.get(finding.claim_key)
    if rule is None:
        return ("no claim rule for this claim_key",)
    confidence, derivations = rule
    if not cited:
        return ("finding cites no evidence",)
    if finding.confidence != confidence:
        return (f"{finding.claim_key} must be {confidence}",)
    groups = {}
    for item in cited:
        if item.operation not in derivations:
            return (f"{finding.claim_key} may only cite {', '.join(sorted(derivations))} evidence",)
        groups.setdefault(item.operation, []).append(item.observation)
    claimed = canonical_json(finding.value)
    for operation, observations in sorted(groups.items()):
        expected = derivations[operation](observations)
        if expected is None or canonical_json(expected) != claimed:
            return ("cited evidence does not yield the claimed value",)
    return ()
