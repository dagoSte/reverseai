"""Evidence reviewer: rule 6 of docs/contract.md, re-checked against the frozen bytes.

Analyst output is untrusted. Reasons name evidence IDs only, never input bytes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from reverseai import claims
from reverseai.contract import (
    AnalysisResult, InputRef, ReviewVerdict, ToolSpec, canonical_json, evidence_intact, finding_intact, sha256_hex,
)


def _evidence_problems(evidence, data, data_sha256, input, tools):
    if not evidence_intact(evidence):
        return ["record does not match its ID"]
    problems = []
    if len(data) != input.size:
        problems.append("input size mismatch")
    if evidence.input_sha256 != data_sha256 or evidence.input_sha256 != input.sha256:
        problems.append("input hash mismatch")
    spec = tools.get(evidence.tool.name)
    if not isinstance(spec, ToolSpec) or spec.ref != evidence.tool:
        problems.append("tool name or version not registered")
    elif evidence.operation not in spec.operations:
        problems.append("operation not registered")
    location = evidence.location
    if not location.within(len(data)):
        problems.append("location outside the input")
    elif sha256_hex(bytes(data[location.offset:location.offset + location.length])) != evidence.excerpt_sha256:
        problems.append("excerpt hash mismatch")
    return problems


def _content(finding):
    return (finding.role, finding.claim, finding.claim_key, canonical_json(finding.value), finding.evidence_ids, finding.confidence)


def review(data: bytes, input: InputRef, results: Iterable[AnalysisResult], tools: Mapping[str, ToolSpec]) -> tuple:
    """One verdict per finding ID, sorted; tools are ToolSpecs keyed by tool name."""
    data = bytes(data)
    data_sha256 = sha256_hex(data)
    findings, problems, derived = {}, {}, set()
    for result in results:
        own = {}  # citations resolve only inside the finding's own result
        for item in result.evidence:
            own.setdefault(item.id, item)
        for finding in result.findings:
            first = findings.setdefault(finding.id, finding)
            reasons = problems.setdefault(finding.id, [])
            if not finding_intact(finding):
                reasons.append("finding does not match its ID")
                continue
            if first is not finding and finding_intact(first) and _content(finding) != _content(first):
                reasons.append("finding ID reused for different content")
            local, cited = [] if finding.evidence_ids else ["finding cites no evidence"], []
            for evidence_id in finding.evidence_ids:
                item = own.get(evidence_id)
                if item is None:
                    local.append(f"{evidence_id}: evidence missing")
                    continue
                local.extend(f"{evidence_id}: {problem}" for problem in _evidence_problems(item, data, data_sha256, input, tools))
                cited.append(item)
                spec = tools.get(item.tool.name)
                if isinstance(spec, ToolSpec) and getattr(spec.operations.get(item.operation), "derived", False):
                    derived.add(finding.id)
            # Provenance first; then the claim must follow from what it cites.
            reasons.extend(local or claims.check(finding, cited))
    # Only verified findings contradict each other: neither an unsupported nor a derived claim can cancel a verified one.
    values = {}
    for finding_id, finding in findings.items():
        if not problems[finding_id] and finding_id not in derived:
            values.setdefault(finding.claim_key, set()).add(canonical_json(finding.value))
    verdicts = []
    for finding_id in sorted(findings):
        finding, reasons = findings[finding_id], tuple(dict.fromkeys(problems[finding_id]))
        if reasons:
            verdicts.append(ReviewVerdict(finding_id, "unsupported", reasons))
        elif finding_id in derived:
            verdicts.append(ReviewVerdict(finding_id, "derived", ("cites a derived operation: the tool's reading, not verified against the bytes",)))
        elif len(values[finding.claim_key]) > 1:
            verdicts.append(ReviewVerdict(finding_id, "contradicted", (f"another finding gives {finding.claim_key} a different value",)))
        else:
            verdicts.append(ReviewVerdict(finding_id, "supported"))
    return tuple(verdicts)
