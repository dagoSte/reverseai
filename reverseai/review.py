"""Evidence reviewer: rule 6 of docs/contract.md, re-checked against the frozen bytes.

For each cited evidence item the reviewer recomputes the input hash, checks the
tool name and version against the registered tools, checks that the location is
inside the input and that the excerpt hash matches the bytes. A finding is
unsupported if any cited item is missing or fails, or if it cites none;
contradicted if another finding whose cited evidence also all verifies has the
same claim_key and a different value; otherwise supported. An unsupported
finding never contradicts anything. Reasons name evidence IDs only, never
input bytes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from reverseai.contract import AnalysisResult, InputRef, ReviewVerdict, ToolRef, canonical_json, sha256_hex


def _evidence_problems(evidence, data, data_sha256, input, tools):
    problems = []
    if evidence.input_sha256 != data_sha256 or evidence.input_sha256 != input.sha256:
        problems.append("input hash mismatch")
    registered = tools.get(evidence.tool.name)
    if not isinstance(registered, ToolRef) or registered != evidence.tool:
        problems.append("tool name or version not registered")
    location = evidence.location
    if not location.within(len(data)):
        problems.append("location outside the input")
    elif sha256_hex(bytes(data[location.offset:location.offset + location.length])) != evidence.excerpt_sha256:
        problems.append("excerpt hash mismatch")
    return problems


def review(data: bytes, input: InputRef, results: Iterable[AnalysisResult], tools: Mapping[str, ToolRef]) -> tuple:
    data = bytes(data)
    data_sha256 = sha256_hex(data)
    evidence, findings = {}, {}
    for result in results:
        for item in result.evidence:
            evidence.setdefault(item.id, item)
        for finding in result.findings:
            findings.setdefault(finding.id, finding)  # the same ID means the same content
    problems = {}
    for finding_id, finding in findings.items():
        reasons = []
        if not finding.evidence_ids:
            reasons.append("finding cites no evidence")
        for evidence_id in finding.evidence_ids:
            item = evidence.get(evidence_id)
            if item is None:
                reasons.append(f"{evidence_id}: evidence missing")
                continue
            reasons.extend(f"{evidence_id}: {problem}" for problem in _evidence_problems(item, data, data_sha256, input, tools))
        problems[finding_id] = reasons
    # Only verified findings can contradict: peer findings are untrusted, so an
    # unsupported claim must not cancel a verified one.
    values = {}
    for finding_id, finding in findings.items():
        if not problems[finding_id]:
            values.setdefault(finding.claim_key, set()).add(canonical_json(finding.value))
    verdicts = []
    for finding_id in sorted(findings):
        finding, reasons = findings[finding_id], problems[finding_id]
        if reasons:
            verdicts.append(ReviewVerdict(finding_id, "unsupported", tuple(reasons)))
        elif len(values[finding.claim_key]) > 1:
            verdicts.append(ReviewVerdict(finding_id, "contradicted", (f"another finding gives {finding.claim_key} a different value",)))
        else:
            verdicts.append(ReviewVerdict(finding_id, "supported"))
    return tuple(verdicts)
