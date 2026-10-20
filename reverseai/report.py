"""Deterministic JSON and Markdown reports without timestamps or host paths.

Reports carry bounded text taken from the sample (strings, URLs, section names)
and from analysts. It stays untrusted: Markdown shows it only inside code spans,
where HTML, links, images and autolinks do not render.
"""

from dataclasses import dataclass

from reverseai import __version__, claims
from reverseai.contract import CONTRACT_VERSION, VERDICT_STATUS, InputRef, canonical_json


@dataclass(frozen=True)
class Analysis:
    input: InputRef
    tools: tuple  # tuple[ToolRef, ...]
    results: tuple  # tuple[AnalysisResult, ...]
    verdicts: tuple  # tuple[ReviewVerdict, ...]


def to_dict(analysis):
    verdicts = {v.finding_id: v for v in analysis.verdicts}
    results = []
    for result in analysis.results:
        results.append({
            "task_id": result.task_id,
            "role": result.role,
            "status": result.status,
            "errors": list(result.errors),
            "evidence": [e.to_dict() for e in result.evidence],
            "findings": [{
                "id": f.id,
                "claim": f.claim,
                "statement": claims.statement(f.claim_key),
                "claim_key": f.claim_key,
                "value": f.value,
                "confidence": f.confidence,
                "evidence_ids": list(f.evidence_ids),
                "verdict": verdicts[f.id].status if f.id in verdicts else "unreviewed",
                "reasons": list(verdicts[f.id].reasons) if f.id in verdicts else [],
            } for f in result.findings],
        })
    summary = {status: 0 for status in (*VERDICT_STATUS, "unreviewed")}
    for result in results:
        for finding in result["findings"]:
            summary[finding["verdict"]] += 1
    return {
        "contract": CONTRACT_VERSION,
        "reverseai": __version__,
        "input": {"sha256": analysis.input.sha256, "size": analysis.input.size, "name": analysis.input.name},
        "tools": [{"name": t.name, "version": t.version} for t in analysis.tools],
        "results": results,
        "summary": summary,
    }


def to_json(analysis):
    return canonical_json(to_dict(analysis)) + "\n"


def _cell(value):
    """Untrusted text as one inert code span; "-" when empty."""
    text = value if isinstance(value, str) else canonical_json(value)
    text = "".join(c if c.isprintable() else "�" for c in text).replace("`", "'")
    if len(text) > 200:
        text = text[:199] + "…"
    return "`" + text.replace("|", "\\|") + "`" if text.strip() else "-"


def to_markdown(analysis):
    report = to_dict(analysis)
    evidence = {e["id"]: e for r in report["results"] for e in r["evidence"]}
    lines = [
        "# ReverseAI static analysis report",
        "",
        f"- Input: {_cell(report['input']['name'])}, {report['input']['size']} bytes",
        f"- SHA-256: `{report['input']['sha256']}`",
        f"- Contract: {report['contract']}; ReverseAI {report['reverseai']}",
        "- Tools: " + ", ".join(f"{t['name']} {t['version']}" for t in report["tools"]),
        "- The sample was not executed. Findings marked inferred are hints, not proof of behaviour.",
        "",
        "## Supported findings",
        "",
    ]
    supported = [(r, f) for r in report["results"] for f in r["findings"] if f["verdict"] == "supported"]
    rejected = [(r, f) for r in report["results"] for f in r["findings"] if f["verdict"] != "supported"]
    if supported:
        lines += ["| Analyst | Checked statement | Value | Confidence | Evidence (operation @ offset+length) |", "|---|---|---|---|---|"]
        for result, finding in supported:
            cited = "; ".join(
                f"{evidence[i]['operation']} @ {evidence[i]['location']['offset']}+{evidence[i]['location']['length']}"
                for i in finding["evidence_ids"][:6] if i in evidence)
            more = len(finding["evidence_ids"]) - 6
            cited += f"; +{more} more" if more > 0 else ""
            lines.append(f"| {result['role']} | {finding['statement']} | {_cell(finding['value'])} | {finding['confidence']} | {cited} |")
    else:
        lines.append("No finding was supported by the evidence.")
    lines += ["", "## Rejected or unreviewed claims", ""]
    if rejected:
        lines += ["| Analyst | Claim (analyst wording, unchecked) | Verdict | Reasons |", "|---|---|---|---|"]
        for result, finding in rejected:
            lines.append(f"| {result['role']} | {_cell(finding['claim'])} | {finding['verdict']} | {_cell('; '.join(finding['reasons']))} |")
    else:
        lines.append("None.")
    lines += ["", "## Analyst runs", "", "| Analyst | Status | Evidence items | Errors |", "|---|---|---|---|"]
    for result in report["results"]:
        lines.append(f"| {result['role']} | {result['status']} | {len(result['evidence'])} | {_cell('; '.join(result['errors']))} |")
    summary = report["summary"]
    lines += ["", "Summary: " + ", ".join(f"{summary[k]} {k}" for k in summary), ""]
    return "\n".join(lines)
