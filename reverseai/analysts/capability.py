"""A deterministic capability analyst: string clues, not behavioral conclusions."""

from reverseai.contract import (
    MAX_EVIDENCE_PER_FINDING, AnalysisTask, Budget, InputRef, OperationRequest,
    content_id, make_finding,
)
from reverseai.tools.strings import RULE_CATEGORIES, TOOL


def plan(input: InputRef) -> AnalysisTask:
    return AnalysisTask(
        content_id("tk", {"input": input.sha256, "role": "capability"}),
        "capability", input,
        (OperationRequest("strings.extract"), OperationRequest("strings.indicators")),
        Budget(max_operations=2, max_concurrency=1),
    )


def conclude(task, evidence):
    if task.role != "capability":
        return ()
    categories, urls = {}, {}
    for item in sorted(evidence, key=lambda item: item.id):
        if (item.input_sha256 != task.input.sha256 or item.tool != TOOL.ref
                or item.operation != "strings.indicators" or not item.location.within(task.input.size)):
            continue
        rule = item.observation.get("rule")
        category = item.observation.get("category")
        matched = item.observation.get("match")
        if (not isinstance(rule, str) or RULE_CATEGORIES.get(rule) != category
                or not isinstance(matched, str) or not matched):
            continue
        # A representative per rule supports the rule set; repeated occurrences
        # do not consume the contract's bounded evidence list.
        categories.setdefault(category, {}).setdefault(rule, item.id)
        if rule == "url":
            urls.setdefault(matched, item.id)
    findings = []
    for category, rules in sorted(categories.items()):
        findings.append(make_finding(
            "capability", f"String indicators suggest {category.replace('_', ' ')} capabilities.",
            "capability." + category, sorted(rules), rules.values(), confidence="inferred",
        ))
    if urls:
        # Report only the URLs actually supported by this bounded set of citations.
        selected = sorted(urls)[:MAX_EVIDENCE_PER_FINDING]
        findings.append(make_finding(
            "capability", "URL strings observed in the input.", "strings.urls",
            selected, (urls[url] for url in selected), confidence="observed",
        ))
    return tuple(findings)
