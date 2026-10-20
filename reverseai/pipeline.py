"""Pipeline: snapshot -> plan -> gateway -> conclude -> review."""

from concurrent.futures import ThreadPoolExecutor
import copy
import inspect

from reverseai import intake, review
from reverseai.analysts import capability, code, structural
from reverseai.contract import AnalysisResult, Budget
from reverseai.gateway import Gateway
from reverseai.report import Analysis
from reverseai.tools import strings, structure

ANALYSTS = (structural, capability, code)
TOOLS = (structure.TOOL, strings.TOOL)
# LIEF and YARA-X start a container per operation (45 s limit each), so a run that includes one gets more time.
CONTAINED_BUDGET = Budget(max_wall_seconds=150)
# Ghidra's single import-and-analyse run may take its full 240 s profile; the code task allows 300 s.
GHIDRA_BUDGET = Budget(max_wall_seconds=330)


def _budget(tools):
    if any(spec.contained and spec.ref.name == "ghidra" for spec in tools):
        return GHIDRA_BUDGET
    return CONTAINED_BUDGET if any(spec.contained for spec in tools) else Budget()


def _plan(analyst, ref, tools):
    """Analysts that can use optional tools say so with a tools parameter; M1 analysts are called as before.

    An optional analyst returns None when its tool is absent and then takes no part in the run.
    """
    if "tools" in inspect.signature(analyst.plan).parameters:
        return analyst.plan(ref, tools=tools)
    return analyst.plan(ref)


def analyze_bytes(data, ref, *, budget=None, analysts=ANALYSTS, tools=TOOLS):
    """Analyse bytes that intake already froze; analysts never see a path."""
    budget = budget or _budget(tools)
    gateway = Gateway(tools, budget)
    planned = [(analyst, _plan(analyst, ref, tools)) for analyst in analysts]
    planned = [(analyst, task) for analyst, task in planned if task is not None]
    analysts, tasks = [analyst for analyst, _ in planned], [task for _, task in planned]
    with ThreadPoolExecutor(max_workers=budget.max_concurrency) as pool:
        gathered = list(pool.map(lambda task: gateway.run(task, data), tasks))
    results = []
    for analyst, task, partial in zip(analysts, tasks, gathered):
        # The reviewer, not the analyst, decides whether partial evidence is enough. Analysts get
        # copies: the result keeps the gateway's records, so an analyst cannot alter them.
        findings = analyst.conclude(task, copy.deepcopy(partial.evidence)) if partial.evidence else ()
        results.append(AnalysisResult(task.id, task.role, partial.status, partial.evidence, tuple(findings), partial.errors))
    specs = {spec.ref.name: spec for spec in tools}
    verdicts = review.review(data, ref, results, specs)
    ordered = sorted(specs.values(), key=lambda spec: spec.ref.name)
    runtimes = tuple((spec.ref.name, dict(spec.runtime)) for spec in ordered if spec.contained)
    return Analysis(ref, tuple(spec.ref for spec in ordered), tuple(results), tuple(verdicts), runtimes)


def analyze_path(path, *, budget=None, tools=TOOLS):
    data, ref = intake.snapshot(path)
    return analyze_bytes(data, ref, budget=budget, tools=tools)
