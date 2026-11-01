"""Deterministic file mutations and reports; execution stays in queen.run_cases."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import random
import re

MAX_MUTANTS = 500
MUTATORS = ("bitflip", "insert", "delete", "truncate", "boundary", "splice")
BOUNDARIES = (0x00, 0xff, 0x7f, 0x80)


def count(value):
    """Validate both the command-line count and the Python keyword."""
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        value = int(value)
    if type(value) is not int or not 0 <= value <= MAX_MUTANTS:
        raise ValueError(f"fuzz count must be between 0 and {MAX_MUTANTS}")
    return value


def mutate(data, operation, rng, max_file_size, other=b""):
    """Apply one bounded byte operation; arguments and filenames are never involved."""
    data = data[:max_file_size]
    if operation == "bitflip":
        if not data:
            result = bytes([1 << rng.randrange(8)])
        else:
            at = rng.randrange(len(data))
            result = data[:at] + bytes([data[at] ^ (1 << rng.randrange(8))]) + data[at + 1:]
    elif operation == "insert":
        at = rng.randrange(len(data) + 1)
        result = data[:at] + bytes([rng.randrange(256)]) + data[at:]
    elif operation == "delete":
        at = rng.randrange(len(data)) if data else 0
        result = data[:at] + data[at + 1:]
    elif operation == "truncate":
        result = data[:rng.randrange(len(data))] if data else b""
    elif operation == "boundary":
        at = rng.randrange(len(data)) if data else 0
        choices = [value for value in BOUNDARIES if not data or value != data[at]]
        result = data[:at] + bytes([rng.choice(choices)]) + data[at + 1:]
    elif operation == "splice":
        other = other[:max_file_size]
        result = data[:rng.randrange(len(data) + 1)] + other[rng.randrange(len(other) + 1):]
    else:
        raise ValueError(f"unknown fuzz mutator: {operation}")
    return result[:max_file_size]


def generate(cases, input_sha256, total, max_file_size):
    """At most total fresh case IDs, seeded by the input hash and each normalised source ID."""
    total = count(total)
    if not total:
        return []
    if not isinstance(input_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", input_sha256):
        raise ValueError("fuzzing needs the input SHA-256")
    if type(max_file_size) is not int or max_file_size < 1:
        raise ValueError("fuzz file cap must be positive")
    reserved, sources = set(), []
    for case in cases:
        if not isinstance(case.get("id"), str):
            raise ValueError("fuzz source cases need string IDs")
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", case["id"])[:64]
        if not name or name in reserved:
            raise ValueError("fuzz source IDs must be unique after normalisation")
        reserved.add(name)
        source = copy.deepcopy(case)
        source["id"] = name
        data = [(base64.b64decode(item["base64"]) if item.get("base64")
                 else item.get("text", "").encode())[:max_file_size] for item in case.get("files", [])]
        source["files"] = [{"name": item["name"], "base64": base64.b64encode(content).decode("ascii")}
                           for item, content in zip(case.get("files", []), data)]
        if data:
            seed = hashlib.sha256(f"hive-fuzz-v1\0{input_sha256.lower()}\0{name}".encode()).digest()
            sources.append((source, data, random.Random(int.from_bytes(seed, "big"))))
    sources.sort(key=lambda item: item[0]["id"])
    if not sources:
        return []
    operations = MUTATORS if len(sources) > 1 else MUTATORS[:-1]
    mutants, sequence = [], 1
    for index in range(total):
        source, files, rng = sources[index % len(sources)]
        operation = operations[index % len(operations)]
        at, other = rng.randrange(len(files)), b""
        if operation == "splice":
            donors = [data for case, contents, _ in sources if case["id"] != source["id"] for data in contents]
            other = rng.choice(donors)
        mutant = copy.deepcopy(source)
        changed = mutate(files[at], operation, rng, max_file_size, other)
        mutant["files"][at]["base64"] = base64.b64encode(changed).decode("ascii")
        while True:
            suffix = f"-{sequence}"
            name = "fz-" + source["id"][:64 - 3 - len(suffix)] + suffix
            sequence += 1
            if name not in reserved:
                break
        reserved.add(name)
        mutant["id"] = name
        mutants.append(mutant)
    return mutants


def summarise(cases, original, rebuilt, seed, compare):
    """No incomplete or timed-out execution counts as a successful fuzz proof."""
    result = {"cases": len(cases), "identical": 0, "different": [], "seed": seed}
    expected = {case["id"] for case in cases}
    complete = bool(cases) and len(expected) == len(cases)
    for executions in (original, rebuilt):
        if not isinstance(executions, dict) or set(executions) != expected:
            complete = False
            continue
        for case in cases:
            row = executions[case["id"]]
            steps = row.get("steps") if isinstance(row, dict) else None
            if (not case.get("steps") or not isinstance(steps, list) or len(steps) != len(case["steps"])
                    or not all(isinstance(step, dict) and type(step.get("code")) is int for step in steps)):
                complete = False
    result["ran"] = complete
    if complete:
        same, different = compare(original, rebuilt)
        result.update(identical=len(same), different=different)
    else:
        result["reason"] = ("no case files to mutate" if not cases
                            else "fuzz execution is incomplete or timed out")
    return result


def write_report(path, summary, cases):
    """Keep the complete, bounded input of every observed divergent mutant."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    different = set(summary["different"])
    with path.open("w", encoding="utf-8") as handle:
        json.dump(dict(summary, inputs=[case for case in cases if case["id"] in different]), handle,
                  indent=1, ensure_ascii=False)
        handle.write("\n")
