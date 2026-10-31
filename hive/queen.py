"""The queen: deterministic orchestration of a ReverseAI analyst team (the hive).

The queen is code, not a model. She exports the program map from ReverseAI, asks one planner
bee to split the work and freeze the shared interface (`contract.h`), runs builder bees in
parallel (one per module, each with its own MCP server), compiles and links what they write,
and sends every module to an independent council that tries to refute it. Then the binding
checks run: every claim's citations are re-run through ReverseAI (tools/hive_check.py) and,
only when the operator allows it, the original and the rebuild run the same conformance cases.
The final verdict is computed from those results by code; nothing can override a failed check.

    python -m hive run --inputs DIR --file NAME --out NEW_DIR [--bees 4] [--run-original]

Every run needs prepared exports (`reverseai prepare`, ReverseAI 0.8.0 or later) and a
contained Ghidra image. See docs/HIVE.md.
"""

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from hive import bees as bees_module
from hive import languages

ROOT = Path(__file__).resolve().parents[1]
WARNINGS = ("-O1", "-Wall", "-Wextra", "-Wno-unused-parameter", "-fwrapv", "-fno-strict-aliasing")
CFLAGS = (languages.C.standard, *WARNINGS)
FORBIDDEN = re.compile(r"\b(?:asm|__asm__|__asm)\b|\.incbin|#\s*embed\b|\bdlopen\b")
PROTOTYPE = re.compile(r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;\s*/\*\s*0x([0-9a-fA-F]+)\s*\*/")
LENSES = (
    ("control", "control flow and arithmetic: conditions, loops, integer widths, signedness, overflow, "
                "shifts and return values, checked against the ASSEMBLY of every function"),
    ("io", "everything the program reads and writes: output bytes and formats, error messages, exit "
           "codes, files, stdin/stdout/stderr handling and the order of operations"),
    ("data", "data and memory: structs and offsets, constant tables, globals and their initial values, "
             "buffer sizes, endianness and pointer arithmetic"),
)
MAX_CASE_FILE = 64 * 1024


class HiveError(RuntimeError):
    pass


def hexed(value):
    return f"0x{value:x}"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --- ReverseAI, run as its command line from an engine checkout -----------------------------------

class Engine:
    def __init__(self, *, root, inputs, file, enabled=("ghidra",), python=sys.executable, timeout=1500):
        self.root, self.inputs, self.file = Path(root), Path(inputs), file
        self.enabled, self.python, self.timeout = tuple(enabled), python, timeout

    @property
    def path(self):
        return self.inputs / self.file

    def _run(self, argv, timeout=None):
        env = dict(os.environ, PYTHONPATH=str(self.root), PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([self.python, "-B", "-m", "reverseai", *argv], capture_output=True, text=True,
                              env=env, timeout=timeout or self.timeout, check=False)

    def prepare(self):
        done = self._run(["prepare", str(self.path), *("--with-" + t for t in self.enabled), "--json"], timeout=1100)
        if done.returncode != 0:
            raise HiveError("prepare failed: " + (done.stderr.strip().splitlines() or ["?"])[-1])
        return json.loads(done.stdout)

    def query(self, name, args, out):
        Path(out).parent.mkdir(parents=True, exist_ok=True)  # the CLI creates --out itself, not its parents
        argv = ["query", str(self.path), "--query", name, "--out", str(out), *("--with-" + t for t in self.enabled)]
        for key, value in args.items():
            argv += ["--arg", f"{key}={value}"]
        done = self._run(argv)
        report = Path(out) / "report.json"
        if done.returncode != 0 or not report.is_file():
            raise HiveError(f"{name} {args} failed: " + (done.stderr.strip().splitlines() or ["?"])[-1])
        return json.loads(report.read_text(encoding="utf-8"))


def export_rows(report, claim_key):
    rows, total = [], None
    for result in report.get("results", []):
        for finding in result.get("findings", []):
            if finding.get("claim_key") == claim_key and finding.get("verdict") in ("supported", "derived"):
                rows += finding["value"]["rows"]
                total = finding["value"]["total"]
    return sorted(rows, key=lambda row: row["index"]), total


def survey(engine, folder, log):
    """Export functions, calls and strings of the prepared program into map.json."""
    folder.mkdir(parents=True, exist_ok=True)
    receipt = engine.prepare()
    log(f"prepared {engine.file}: {json.dumps(receipt, sort_keys=True)[:200]}")
    tables = {}
    for part, key in (("functions", "code.export_functions"), ("calls", "code.export_calls"),
                      ("strings", "code.export_strings")):
        rows, start = [], 0
        while True:
            report = engine.query("export_program", {"part": part, "start": start, "limit": 128},
                                  folder / "pages" / f"{part}-{start:06d}")
            page, total = export_rows(report, key)
            rows += page
            start += len(page)
            if not page or total is None or start >= total:
                break
        tables[part] = rows
        log(f"survey: {len(rows)} {part}")
    report_sha = report["input"]["sha256"]
    functions = [{"entry": r["entry"], "hex": hexed(r["entry"]), "name": r["name"], "size": r["size"],
                  "signature": r.get("signature")} for r in tables["functions"]]
    known = {f["entry"] for f in functions}
    program_map = {
        "file": engine.file, "input_sha256": report_sha, "functions": functions,
        "calls": [{"from": hexed(r["from"]), "to": hexed(r["to"]), "to_name": r.get("to_name")} for r in tables["calls"]],
        "imports": sorted({r.get("to_name") for r in tables["calls"] if r["to"] not in known and r.get("to_name")}),
        "strings": [{"from": hexed(r["from"]), "address": hexed(r["address"]), "text": r["text"]} for r in tables["strings"]],
    }
    (folder / "map.json").write_text(json.dumps(program_map, indent=1, ensure_ascii=False), encoding="utf-8")
    return program_map


# --- Plan ------------------------------------------------------------------------------------------

def normalise_plan(plan, program_map, max_functions):
    """Every non-skipped function in exactly one module of bounded size; leftovers by address."""
    entries = {f["hex"]: f for f in program_map["functions"]}
    skipped = {s["entry"].lower(): s["reason"] for s in plan.get("skipped", []) if s.get("entry", "").lower() in entries}
    seen, modules = set(), []
    for module in plan.get("modules", []):
        functions = []
        for entry in (str(e).lower() for e in module.get("functions", [])):
            if entry in entries and entry not in skipped and entry not in seen:
                seen.add(entry)
                functions.append(entry)
        for chunk in range(0, len(functions), max_functions):
            modules.append({"title": module.get("title", "").strip()[:120] or "module",
                            "functions": functions[chunk:chunk + max_functions]})
    left = sorted((e for e in entries if e not in seen and e not in skipped), key=lambda e: int(e, 16))
    for chunk in range(0, len(left), max_functions):
        modules.append({"title": "functions the planner left unassigned", "functions": left[chunk:chunk + max_functions]})
    for number, module in enumerate(modules, 1):
        module["id"] = f"m{number:02d}"
    return modules, skipped


def contract_names(text):
    return {int(entry, 16): name for name, entry in PROTOTYPE.findall(text)}


# --- Building and checking -------------------------------------------------------------------------

class Build:
    def __init__(self, folder, cc=None, cflags=None, ldflags=("-lm",), language=languages.C):
        self.folder, self._cc, self._cflags = Path(folder), cc, cflags
        self.language, self.ldflags = language, tuple(ldflags)
        (self.folder / "obj").mkdir(parents=True, exist_ok=True)

    @property
    def cc(self):
        return self._cc or self.language.cc()

    @property
    def cflags(self):
        return tuple(self._cflags) if self._cflags is not None else (self.language.standard, *WARNINGS)

    def syntax(self, header):
        done = subprocess.run([self.cc, *self.cflags, "-fsyntax-only", "-x", self.language.syntax_kind, str(header)],
                              capture_output=True, text=True, check=False)
        return done.returncode == 0, done.stderr

    def compile(self, module_id, source, contract):
        """Compile one module from a clean stage holding only its source and the frozen contract."""
        text = Path(source).read_text(encoding="utf-8", errors="replace") if Path(source).is_file() else None
        if text is None:
            return {"ok": False, "errors": f"{Path(source).name} was not written", "warnings": ""}
        cheat = sorted(set(FORBIDDEN.findall(text)))
        if cheat:
            return {"ok": False, "errors": "forbidden constructs: " + ", ".join(cheat), "warnings": ""}
        stage = self.folder / "stage" / module_id
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True)
        shutil.copyfile(source, stage / self.language.source(module_id))
        shutil.copyfile(contract, stage / self.language.header)
        done = subprocess.run([self.cc, *self.cflags, "-c", self.language.source(module_id), "-o",
                               str(self.folder / "obj" / f"{module_id}.o")],
                              cwd=stage, capture_output=True, text=True, check=False)
        errors = "\n".join(line for line in done.stderr.splitlines() if "error" in line)
        return {"ok": done.returncode == 0, "errors": errors if done.returncode else "",
                "warnings": done.stderr if done.returncode == 0 else "", "log": done.stderr[-4000:]}

    def link(self, module_ids, name):
        output = self.folder / "bin" / name
        output.parent.mkdir(parents=True, exist_ok=True)
        objects = [str(self.folder / "obj" / f"{m}.o") for m in module_ids]
        done = subprocess.run([self.cc, *objects, "-o", str(output), *self.ldflags],
                              capture_output=True, text=True, check=False)
        return {"ok": done.returncode == 0, "log": done.stderr[-8000:], "binary": str(output)}


def link_blame(log, owners, module_ids):
    """Map linker messages to the modules that must fix them."""
    blamed = {}
    for symbol in re.findall(r'"_?([A-Za-z_]\w*)", referenced from|undefined reference to `([A-Za-z_]\w*)\'', log):
        name = next(s for s in symbol if s)
        if name in owners:
            blamed.setdefault(owners[name], []).append(f"undefined symbol {name}: define it in this module")
    for name in re.findall(r"duplicate symbol '_?([A-Za-z_]\w*)'|multiple definition of `([A-Za-z_]\w*)'", log):
        name = next(s for s in name if s) if isinstance(name, tuple) else name
        for module in module_ids:
            if module != owners.get(name) and f"{module}.o" in log:
                blamed.setdefault(module, []).append(f"duplicate symbol {name}: only {owners.get(name, 'its owner')} may define it")
    for module in module_ids:
        if module not in blamed and re.search(rf"\b{module}\.o\b", log):
            blamed[module] = ["linker error mentioning this module; see the log"]
    return blamed


def run_cases(cases, binary, folder, timeout=20):
    """Run every case in a fresh folder; compare-ready results with the binary's path hidden."""
    results = {}
    for case in cases:
        work = Path(tempfile.mkdtemp(prefix=f"{case['id']}-", dir=folder))
        for item in case.get("files", []):
            target = (work / item["name"]).resolve()
            if work.resolve() not in target.parents:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            data = base64.b64decode(item["base64"]) if item.get("base64") else item.get("text", "").encode()
            target.write_bytes(data[:MAX_CASE_FILE])
        steps = []
        for step in case["steps"]:
            stdin = (work / step["stdin"]) if step.get("stdin") else None
            try:
                with (stdin.open("rb") if stdin and stdin.is_file() else open(os.devnull, "rb")) as handle:
                    done = subprocess.run([binary, *step["args"]], cwd=work, stdin=handle, capture_output=True,
                                          timeout=timeout, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                steps.append({"code": done.returncode, "out": hashlib.sha256(done.stdout).hexdigest(),
                              "out_head": done.stdout[:200].decode("latin-1"),
                              "err": done.stderr.decode("latin-1").replace(str(binary), "PROG")[:2000]})
            except subprocess.TimeoutExpired:
                steps.append({"code": "timeout"})
        files = {str(p.relative_to(work)): sha256(p) for p in sorted(work.rglob("*")) if p.is_file()}
        results[case["id"]] = {"steps": steps, "files": files}
        shutil.rmtree(work, ignore_errors=True)
    return results


def compare(original, rebuilt):
    same, different = [], []
    for case_id, expected in original.items():
        (same if rebuilt.get(case_id) == expected else different).append(case_id)
    return same, different


# --- The hive --------------------------------------------------------------------------------------

class Queen:
    def __init__(self, *, engine, out, bees, slots=4, max_functions=12, compile_rounds=3, council_rounds=2,
                 lenses=len(LENSES), link_rounds=3, behaviour_rounds=2, run_original=False, cases=40,
                 max_bees=400, build=None, check=None, language="c"):
        self.engine, self.out, self.bees = engine, Path(out), bees
        self.slots = threading.BoundedSemaphore(slots)
        self.workers = slots
        self.max_functions, self.compile_rounds, self.council_rounds = max_functions, compile_rounds, council_rounds
        self.lenses = LENSES[:max(1, min(lenses, len(LENSES)))]
        self.link_rounds, self.behaviour_rounds = link_rounds, behaviour_rounds
        self.run_original, self.case_target, self.max_bees = run_original, cases, max_bees
        self.build = build or Build(self.out / "build")
        self.requested_language = language
        self.lang = self.build.language
        self.check = check
        self.lock = threading.RLock()
        self.spent = {"bees": 0, "seconds": 0.0, "cost_usd": 0.0}
        self.events = []

    # bookkeeping
    def log(self, message):
        line = f"[{time.strftime('%H:%M:%S')}] {message}"
        with self.lock:
            self.events.append(line)
            with (self.out / "hive.log").open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        print(line, flush=True)

    def bee(self, role, name, task, folder):
        with self.lock:
            if self.spent["bees"] >= self.max_bees:
                self.log(f"budget: {name} not started, the run's limit of {self.max_bees} bees is reached")
                return {"ok": False, "error": "bee budget exhausted"}
            self.spent["bees"] += 1
        with self.slots:
            self.log(f"{name}: {role} started")
            answer = self.bees(role, name, task, folder)
        with self.lock:
            self.spent["seconds"] += answer.get("seconds") or 0
            self.spent["cost_usd"] += answer.get("cost_usd") or 0
        (Path(folder) / f".answer-{name}.json").write_text(json.dumps(answer, indent=1, ensure_ascii=False))
        self.log(f"{name}: {'done' if answer.get('ok') else 'FAILED ' + answer.get('error', '')[:160]} "
                 f"in {answer.get('seconds', 0)} s")
        return answer

    # phases
    def plan(self, program_map):
        folder = self.out / "plan"
        folder.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.out / "survey" / "map.json", folder / "map.json")
        task = (f"Program file: `{self.engine.file}` with {len(program_map['functions'])} functions and "
                f"{len(program_map['imports'])} imported names. Function limit per module: {self.max_functions}. "
                f"Target language: {self.lang.label}. {self.lang.guidance} Read `map.json`, then write the "
                f"interface as `{self.lang.header}` (it replaces `contract.h` in your role card) and `PLAN.md` in "
                "this folder and answer with the plan.")
        answer = self.bee("planner", "planner", task, folder)
        if not answer.get("ok"):
            raise HiveError("the planner did not produce a plan: " + answer.get("error", ""))
        modules, skipped = normalise_plan(answer["output"], program_map, self.max_functions)
        contract = folder / self.lang.header
        for attempt in range(1 + self.compile_rounds):
            ok, errors = (self.build.syntax(contract) if contract.is_file()
                          else (False, f"{self.lang.header} was not written"))
            if ok:
                break
            if attempt == self.compile_rounds:
                raise HiveError(f"{self.lang.header} does not compile: " + errors[-1000:])
            self.bee("planner", f"planner-fix{attempt + 1}",
                     f"Your `{self.lang.header}` does not compile on its own. Fix only these errors, keep the plan, and "
                     f"answer with the same plan:\n```\n{errors[-4000:]}\n```", folder)
        frozen = self.out / "src" / self.lang.header
        frozen.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(contract, frozen)
        frozen.chmod(0o444)
        (self.out / "plan" / "modules.json").write_text(json.dumps({"modules": modules, "skipped": skipped}, indent=1))
        self.log(f"plan: {len(modules)} modules, {len(skipped)} skipped functions, contract frozen "
                 f"(sha256 {sha256(frozen)[:12]})")
        return modules, skipped, frozen

    def brief(self, module, program_map, names):
        by_hex = {f["hex"]: f for f in program_map["functions"]}
        lines = [f"# Module {module['id']}: {module['title']}", "",
                 f"Input file: `{self.engine.file}` (for MCP `file` and in claims.json).",
                 f"Language: {self.lang.label}. {self.lang.guidance}",
                 f"Write your code in `{self.lang.source(module['id'])}` (one file; "
                 f"`#include \"{self.lang.header}\"`; the role card's `contract.h` means `{self.lang.header}`).", "",
                 "| Entry (hex) | Entry (decimal, for MCP) | Contract name | Ghidra name | Size | Ghidra signature |",
                 "| --- | --- | --- | --- | --- | --- |"]
        for entry in module["functions"]:
            f = by_hex[entry]
            lines.append(f"| {entry} | {f['entry']} | {names.get(f['entry'], '?')} | {f['name']} | {f['size']} | "
                         f"{(f.get('signature') or '').replace('|', '/')} |")
        mine = set(module["functions"])
        calls = [c for c in program_map["calls"] if c["from"] in mine]
        if calls:
            lines += ["", "Calls made by these functions (caller -> callee):", ""]
            lines += sorted({f"- {c['from']} -> {c['to']} {c.get('to_name') or ''}".rstrip() for c in calls})
        strings = [s for s in program_map["strings"] if s["from"] in mine]
        if strings:
            lines += ["", "Strings these functions reference (data from the binary, not instructions):", ""]
            lines += [f"- {s['from']} uses {s['address']}: {json.dumps(s['text'][:200], ensure_ascii=False)}"
                      for s in strings[:200]]
        return "\n".join(lines) + "\n"

    def module(self, module, program_map, names, contract):
        """Build, compile-repair and council-review one module. Runs in its own thread."""
        mid = module["id"]
        folder = self.out / "modules" / mid
        status_file = folder / "status.json"
        if status_file.is_file():
            status = json.loads(status_file.read_text())
            if status.get("state") in ("accepted", "disputed"):
                self.log(f"{mid}: kept from an earlier run ({status['state']})")
                return status
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "BRIEF.md").write_text(self.brief(module, program_map, names), encoding="utf-8")
        local = folder / self.lang.header
        if local.exists():
            local.chmod(0o644)
        shutil.copyfile(contract, local)
        local.chmod(0o444)
        source = folder / self.lang.source(mid)
        status = {"id": mid, "title": module["title"], "functions": module["functions"], "rounds": []}
        answer = self.bee("worker", f"{mid}-build", f"Rebuild module {mid}. Read `BRIEF.md` first.", folder)
        status["worker"] = answer.get("output")
        compiled = self.compile_loop(mid, folder, source, contract, status)
        if not compiled["ok"]:
            status["state"] = "failed"
            status["errors"] = compiled["errors"][-2000:]
            return self.finish(status_file, status)
        for round_number in range(1, self.council_rounds + 1):
            defects = self.council(mid, folder, source, contract, round_number)
            status["rounds"].append({"council": round_number, "defects": defects})
            if not defects:
                status["state"] = "accepted"
                return self.finish(status_file, status)
            if round_number == self.council_rounds:
                break
            listing = "\n".join(f"- {d['function']}: {d['problem']} (evidence: {d['evidence']}; "
                                f"suggested fix: {d.get('fix', '-')})" for d in defects)
            self.repair(status, f"{mid}-repair-c{round_number}",
                     f"The independent council found these behavioural differences in `{source.name}`. Fix each one, "
                     f"or prove with the assembly or a finding ID that the original does the same:\n{listing}", folder)
            compiled = self.compile_loop(mid, folder, source, contract, status)
            if not compiled["ok"]:
                status["state"] = "failed"
                status["errors"] = compiled["errors"][-2000:]
                return self.finish(status_file, status)
        status["state"] = "disputed"
        return self.finish(status_file, status)

    def finish(self, status_file, status):
        status_file.write_text(json.dumps(status, indent=1, ensure_ascii=False))
        self.log(f"{status['id']}: {status['state']}")
        return status

    def compile_loop(self, mid, folder, source, contract, status):
        for attempt in range(self.compile_rounds + 1):
            result = self.build.compile(mid, source, contract)
            status.setdefault("compiles", []).append({"ok": result["ok"], "errors": result["errors"][-1000:]})
            if result["ok"] and not result["warnings"].strip():
                return result
            if attempt == self.compile_rounds:
                return result
            problem = result["errors"] if not result["ok"] else result["warnings"]
            self.repair(status, f"{mid}-repair-b{attempt + 1}",
                        f"`{source.name}` does not compile cleanly with `{self.build.cc} {' '.join(self.build.cflags)}`. "
                        "Fix exactly these "
                        f"messages without changing behaviour:\n```\n{problem[-4000:]}\n```", folder)
        return result

    def repair(self, status, name, task, folder):
        answer = self.bee("repair", name, task, folder)
        if answer.get("ok") and answer["output"].get("functions"):
            status["worker"] = answer["output"]
        return answer

    def council(self, mid, folder, source, contract, round_number):
        unit = f"unit-{hashlib.sha256((mid + str(round_number)).encode()).hexdigest()[:6]}"
        def review(lens):
            seat = self.out / "council" / f"{mid}-r{round_number}-{lens[0]}"
            shutil.rmtree(seat, ignore_errors=True)
            seat.mkdir(parents=True)
            shutil.copyfile(source, seat / f"{unit}{self.lang.extension}")
            shutil.copyfile(contract, seat / self.lang.header)
            shutil.copyfile(folder / "BRIEF.md", seat / "BRIEF.md")
            answer = self.bee("councillor", f"{mid}-council-r{round_number}-{lens[0]}",
                              f"Review `{unit}{self.lang.extension}` ({self.lang.label}) against the original "
                              "functions listed in `BRIEF.md`. "
                              f"Your lens: {lens[1]}.", seat)
            return answer.get("output") if answer.get("ok") else None
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.lenses)) as pool:
            verdicts = list(pool.map(review, self.lenses))
        defects = []
        for verdict in verdicts:
            if verdict is None:
                continue
            for defect in verdict.get("defects", []):
                if re.search(r"0x[0-9a-fA-F]+|(fi|ev)-[0-9a-f]{16}", defect.get("evidence", "")):
                    defects.append(defect)
        missing = sum(v is None for v in verdicts)
        if missing:
            self.log(f"{mid}: {missing} councillor(s) gave no verdict in round {round_number}")
            if missing == len(verdicts):
                return [{"function": "-", "problem": "no councillor could review this module",
                         "evidence": "0x0", "fix": "re-run the council"}]
        return defects

    def integrate(self, modules, names, contract):
        owners = {}
        for module in modules:
            for entry in module["functions"]:
                if int(entry, 16) in names:
                    owners[names[int(entry, 16)]] = module["id"]
        built = [m["id"] for m in modules if (self.out / "build" / "obj" / f"{m['id']}.o").is_file()]
        result = {"ok": False, "log": "no module compiled"}
        for attempt in range(self.link_rounds + 1):
            if not built:
                break
            result = self.build.link(built, self.engine.file)
            if result["ok"] or attempt == self.link_rounds:
                break
            blamed = link_blame(result["log"], owners, built)
            self.log(f"link round {attempt + 1}: errors in {', '.join(sorted(blamed)) or 'no module'}")
            if not blamed:
                break
            def repair(item):
                mid, problems = item
                folder = self.out / "modules" / mid
                self.bee("repair", f"{mid}-repair-l{attempt + 1}",
                         "Linking the whole program failed because of this module. Fix these problems:\n"
                         + "\n".join("- " + p for p in problems), folder)
                self.build.compile(mid, folder / self.lang.source(mid), contract)
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
                list(pool.map(repair, sorted(blamed.items())))
        self.log(f"link: {'ok' if result['ok'] else 'FAILED'}")
        return result

    def conformance(self, binary, modules, contract):
        folder = self.out / "tests"
        folder.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.out / "survey" / "map.json", folder / "map.json")
        for module in modules:
            brief = self.out / "modules" / module["id"] / "BRIEF.md"
            if brief.is_file():
                shutil.copyfile(brief, folder / f"BRIEF-{module['id']}.md")
        answer = self.bee("tester", "tester", f"Write about {self.case_target} conformance cases for "
                          f"`{self.engine.file}`.", folder)
        if not answer.get("ok"):
            return {"ran": False, "reason": "the tester bee gave no cases"}
        cases = [c for c in answer["output"]["cases"] if c.get("id") and c.get("steps")][:200]
        for case in cases:
            case["id"] = re.sub(r"[^A-Za-z0-9_.-]", "_", case["id"])[:64]
        (folder / "cases.json").write_text(json.dumps(cases, indent=1, ensure_ascii=False))
        runs = folder / "runs"
        runs.mkdir(exist_ok=True)
        stage = folder / "original" / self.engine.file
        stage.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.engine.path, stage)
        stage.chmod(0o555)
        original = run_cases(cases, str(stage), runs)
        rebuilt_binary = binary
        for round_number in range(self.behaviour_rounds + 1):
            rebuilt = run_cases(cases, rebuilt_binary, runs)
            same, different = compare(original, rebuilt)
            self.log(f"conformance round {round_number}: {len(same)}/{len(cases)} identical")
            if not different or round_number == self.behaviour_rounds:
                break
            rebuilt_binary = self.behaviour_fix(round_number + 1, cases, original, rebuilt, different, modules,
                                                contract) or rebuilt_binary
        (folder / "results.json").write_text(json.dumps({"original": original, "rebuilt": rebuilt}, indent=1))
        return {"ran": True, "cases": len(cases), "identical": len(same), "different": different}

    def behaviour_fix(self, round_number, cases, original, rebuilt, different, modules, contract):
        folder = self.out / "fixes" / f"b{round_number}"
        folder.mkdir(parents=True, exist_ok=True)
        for module in modules:
            source = self.out / "modules" / module["id"] / self.lang.source(module["id"])
            if source.is_file():
                shutil.copyfile(source, folder / source.name)
        shutil.copyfile(contract, folder / self.lang.header)
        (folder / self.lang.header).chmod(0o444)
        by_id = {c["id"]: c for c in cases}
        lines = []
        for case_id in different[:25]:
            lines.append(f"## {case_id}\ncase: {json.dumps(by_id[case_id], ensure_ascii=False)[:1500]}\n"
                         f"original: {json.dumps(original[case_id], ensure_ascii=False)[:1500]}\n"
                         f"rebuild:  {json.dumps(rebuilt[case_id], ensure_ascii=False)[:1500]}\n")
        (folder / "FAILURES.md").write_text("\n".join(lines), encoding="utf-8")
        before = {p.name: sha256(p) for p in folder.glob(f"m*{self.lang.extension}")}
        self.bee("repair", f"behaviour-fix-{round_number}",
                 "The rebuilt program behaves differently from the original in the cases listed in `FAILURES.md` "
                 "(stdout is compared by hash, with its first bytes shown). The module sources are in this "
                 "folder. Find the cause with the MCP tools and fix the modules; change nothing else.", folder)
        changed = [p for p in folder.glob(f"m*{self.lang.extension}") if before.get(p.name) != sha256(p)]
        for path in changed:
            mid = path.stem
            if self.build.compile(mid, path, contract)["ok"]:
                shutil.copyfile(path, self.out / "modules" / mid / path.name)
        self.log(f"behaviour fix {round_number}: {len(changed)} module(s) changed")
        result = self.build.link([m["id"] for m in modules if (self.out / "build" / "obj" / f"{m['id']}.o").is_file()],
                                 self.engine.file)
        return result["binary"] if result["ok"] else None

    def claims(self, modules):
        merged = []
        for module in modules:
            path = self.out / "modules" / module["id"] / "claims.json"
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for claim in data.get("claims", []) if isinstance(data, dict) else []:
                if isinstance(claim, dict):
                    claim = dict(claim, id=f"{module['id']}.{claim.get('id', '')}"[:128])
                    merged.append(claim)
        path = self.out / "check" / "claims.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"file": self.engine.file, "claims": merged}, indent=1, ensure_ascii=False))
        return path, len(merged)

    def run(self):
        self.out.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        self.log(f"hive started on {self.engine.file}: {self.workers} bees at a time, councils of {len(self.lenses)}")
        map_file = self.out / "survey" / "map.json"
        program_map = (json.loads(map_file.read_text()) if map_file.is_file()
                       else survey(self.engine, self.out / "survey", self.log))
        self.lang, reasons = languages.choose(self.requested_language, program_map)
        self.build.language = self.lang
        self.language_reasons = reasons
        self.log(f"language: {self.lang.label} ({'; '.join(reasons)})")
        modules, skipped, contract = self.plan(program_map)
        names = contract_names(contract.read_text(encoding="utf-8"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            statuses = list(pool.map(lambda m: self.module(m, program_map, names, contract), modules))
        link = self.integrate(modules, names, contract)
        claims_path, claim_count = self.claims(modules)
        check = None
        if self.check and claim_count:
            summary, _ = self.check(claims_path, self.out / "check" / "result")
            check = summary
            self.log(f"checker: {summary['confirmed']}/{summary['claims']} claims confirmed")
        conformance = {"ran": False, "reason": "not allowed: start with --run-original to run the original"}
        if self.run_original and link["ok"]:
            conformance = self.conformance(link["binary"], modules, contract)
        result = self.verdict(program_map, modules, skipped, statuses, link, check, claim_count, conformance)
        result["seconds"] = round(time.monotonic() - started)
        result["spent"] = self.spent
        (self.out / "result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
        (self.out / "REPORT.md").write_text(render(result), encoding="utf-8")
        self.log(f"verdict: {result['verdict']} — {result['reason']}")
        return result

    def verdict(self, program_map, modules, skipped, statuses, link, check, claim_count, conformance):
        states = {s["id"]: s["state"] for s in statuses}
        stubs = sum(1 for s in statuses for f in (s.get("worker") or {}).get("functions", []) if f.get("status") != "rebuilt")
        reasons = []
        if not link["ok"]:
            reasons.append("the program does not link")
        bad = sorted(m for m, state in states.items() if state != "accepted")
        if bad:
            reasons.append(f"modules not accepted by the council: {', '.join(bad)}")
        if stubs:
            reasons.append(f"{stubs} function(s) reported as stub or skipped by their builder")
        if check is None:
            reasons.append("no claim was checked" if claim_count == 0 else "claims were not checked")
        elif check["rejected"]:
            reasons.append(f"{check['rejected']} claim(s) rejected by the evidence checker")
        if conformance.get("ran") and conformance["different"]:
            reasons.append(f"{len(conformance['different'])} conformance case(s) differ")
        return {
            "file": self.engine.file, "input_sha256": program_map["input_sha256"],
            "language": self.lang.label, "language_reasons": getattr(self, "language_reasons", []),
            "functions": len(program_map["functions"]), "skipped": len(skipped), "modules": states,
            "link": link["ok"], "binary": link.get("binary") if link["ok"] else None,
            "check": check, "claims": claim_count, "conformance": conformance,
            "verdict": "accepted" if not reasons and conformance.get("ran") else
                       "accepted without behaviour proof" if not reasons else "not accepted",
            "reason": "; ".join(reasons) or ("every check passed" if conformance.get("ran") else
                                             "every static check passed; behaviour was not run"),
        }


def render(result):
    lines = [f"# Hive report: {result['file']}", "", f"**Verdict: {result['verdict']}.** {result['reason']}.", "",
             f"- Input SHA-256: `{result['input_sha256']}`",
             f"- Language: {result.get('language', 'C')} ({'; '.join(result.get('language_reasons', []))})",
             f"- Functions: {result['functions']} ({result['skipped']} skipped as library or runtime code)",
             f"- Modules: {len(result['modules'])}; accepted "
             f"{sum(s == 'accepted' for s in result['modules'].values())}",
             f"- Link: {'ok' if result['link'] else 'failed'}"]
    check = result["check"]
    lines.append(f"- Evidence checker: {check['confirmed']}/{check['claims']} claims confirmed" if check
                 else f"- Evidence checker: not run ({result['claims']} claims)")
    conformance = result["conformance"]
    lines.append(f"- Conformance: {conformance['identical']}/{conformance['cases']} cases identical"
                 if conformance.get("ran") else f"- Conformance: not run ({conformance.get('reason')})")
    spent = result.get("spent", {})
    lines += [f"- Bees: {spent.get('bees', 0)}, agent time {round(spent.get('seconds', 0) / 60)} min, "
              f"wall time {round(result.get('seconds', 0) / 60)} min", "", "| Module | State |", "| --- | --- |"]
    lines += [f"| {m} | {s} |" for m, s in sorted(result["modules"].items())]
    lines += ["", "The verdict is computed by code from the checks above. Rebuilt code is derived from Ghidra's",
              "interpretation and the agents' reading of the assembly; it is not the original source."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m hive", description="Run the ReverseAI analyst team")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Analyse and rebuild one approved native program")
    run.add_argument("--inputs", required=True, type=Path, help="Directory of approved inputs")
    run.add_argument("--file", required=True, help="Program name inside --inputs")
    run.add_argument("--out", required=True, type=Path, help="Workspace folder (new, or an earlier run to resume)")
    run.add_argument("--bees", type=int, default=4, help="Bees working at the same time (default 4)")
    run.add_argument("--max-bees", type=int, default=400, help="Bee processes for the whole run (default 400)")
    run.add_argument("--max-functions", type=int, default=12, help="Functions per module (default 12)")
    run.add_argument("--council", type=int, default=3, choices=(1, 2, 3), help="Councillors per module (default 3)")
    run.add_argument("--model", help="Model for every bee (default: the agent CLI's default)")
    run.add_argument("--claude", default="claude", help="Claude Code executable")
    run.add_argument("--check-jobs", type=int, default=2, help="Questions the evidence checker runs at once")
    run.add_argument("--run-original", action="store_true",
                     help="Allow running the original program on the conformance cases (benign software only)")
    run.add_argument("--cases", type=int, default=40, help="Conformance cases to ask for (default 40)")
    args = parser.parse_args(argv)
    if not args.inputs.is_dir() or not (args.inputs / args.file).is_file():
        parser.error("--file must name a regular file inside --inputs")
    if not bees_module.environment_ok(args.claude):
        parser.error(f"cannot find {args.claude}; install Claude Code and log in first")
    sys.path.insert(0, str(ROOT))
    from tools import hive_check
    inputs = args.inputs.resolve()
    engine = Engine(root=ROOT, inputs=inputs, file=args.file)
    bees = bees_module.ClaudeBees(engine=ROOT, inputs=inputs, claude=args.claude, model=args.model,
                                  config_dir=args.out.resolve() / ".hive" / "mcp")
    def check(claims, out):
        return hive_check.check(inputs, claims, out, enabled=frozenset({"ghidra"}), jobs=args.check_jobs)
    queen = Queen(engine=engine, out=args.out, bees=bees, slots=args.bees, max_functions=args.max_functions,
                  lenses=args.council, run_original=args.run_original, cases=args.cases, max_bees=args.max_bees,
                  check=check)
    try:
        result = queen.run()
    except HiveError as error:
        print(f"hive: {error}", file=sys.stderr)
        return 2
    return 0 if result["verdict"].startswith("accepted") else 1
