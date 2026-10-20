"""M1 pipeline: snapshot -> plan -> gateway -> conclude -> review."""

from concurrent.futures import ThreadPoolExecutor

from reverseai import intake, review
from reverseai.analysts import capability, structural
from reverseai.contract import AnalysisResult, Budget
from reverseai.gateway import Gateway
from reverseai.report import Analysis
from reverseai.tools import strings, structure

ANALYSTS = (structural, capability)
TOOLS = (structure.TOOL, strings.TOOL)


def analyze_bytes(data, ref, *, budget=None, analysts=ANALYSTS, tools=TOOLS):
    """Analyse bytes that intake already froze; analysts never see a path."""
    budget = budget or Budget()
    gateway = Gateway(tools, budget)
    tasks = [analyst.plan(ref) for analyst in analysts]
    with ThreadPoolExecutor(max_workers=budget.max_concurrency) as pool:
        gathered = list(pool.map(lambda task: gateway.run(task, data), tasks))
    results = []
    for analyst, task, partial in zip(analysts, tasks, gathered):
        # The reviewer, not the analyst, decides whether partial evidence is enough.
        findings = analyst.conclude(task, partial.evidence) if partial.evidence else ()
        results.append(AnalysisResult(task.id, task.role, partial.status, partial.evidence, tuple(findings), partial.errors))
    refs = {spec.ref.name: spec.ref for spec in tools}
    verdicts = review.review(data, ref, results, refs)
    return Analysis(ref, tuple(sorted(refs.values(), key=lambda r: r.name)), tuple(results), tuple(verdicts))


def analyze_path(path, *, budget=None):
    data, ref = intake.snapshot(path)
    return analyze_bytes(data, ref, budget=budget)
