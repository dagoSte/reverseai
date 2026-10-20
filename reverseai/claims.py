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


def _field(name, convert=lambda value: value):
    """One value from the observations that carry the field; observations without it (other physical headers) are ignored."""
    def derive(observations):
        carrying = [o for o in observations if name in o]
        return _one(convert(o) for o in carrying) if carrying else None
    return derive


_format = _field("format", lambda o: o["format"])
_machine = _field("machine_name", lambda o: o["machine_name"])
_count = lambda obs: _one(_section_count(o) for o in obs if "shnum" in o or "number_of_sections" in o) \
    if any("shnum" in o or "number_of_sections" in o for o in obs) else None

# claim_key -> (confidence the claim must carry, {operation it may cite: derive(observations) -> expected value or None}).
# A claim may cite several allowed operations; each operation's citations must yield the same value.
RULES = {
    "format.container": ("observed", {"structure.identify": _format, "lief.headers": _format}),
    "format.machine": ("observed", {"structure.headers": _machine, "lief.headers": _machine}),
    "format.section_count": ("observed", {"structure.headers": _count, "lief.headers": _count}),
    "sections.writable_executable": ("inferred", {"structure.sections": _writable_executable}),
    "sections.writable_executable_indices": ("inferred", {"lief.sections": _writable_executable_indices}),
    "strings.urls": ("observed", {"strings.indicators": _urls}),
    **{f"capability.{name}": ("inferred", {"strings.indicators": _category(name)}) for name in CATEGORIES},
}


# claim_key -> the fixed statement a supported finding makes; the value column says what it found.
STATEMENTS = {
    "format.container": "File format identified from its magic bytes",
    "format.machine": "Machine named in the header",
    "format.section_count": "Number of sections declared in the header",
    "sections.writable_executable": "Sections that are both writable and executable",
    "sections.writable_executable_indices": "Section indices that are both writable and executable",
    "strings.urls": "URL strings in the input",
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
