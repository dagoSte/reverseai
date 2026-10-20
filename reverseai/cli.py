"""Command line: python3 -m reverseai analyze FILE --out DIR"""

import argparse
import os
from pathlib import Path
import sys

from reverseai import pipeline, report
from reverseai.contract import ContractError


def write_new(path, text):
    """Create the file or fail; never follow or replace an existing entry."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="reverseai", description="Static analysis with verifiable evidence (M1 prototype).")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Analyse one approved file without executing it")
    analyze.add_argument("file", type=Path)
    analyze.add_argument("--out", type=Path, required=True, help="New or empty directory for report.json and report.md")
    args = parser.parse_args(argv)

    out = args.out
    if out.is_symlink() or (out.exists() and (not out.is_dir() or any(out.iterdir()))):
        parser.exit(1, "reverseai: --out must be a new or empty directory\n")
    try:
        analysis = pipeline.analyze_path(args.file)
    except (ContractError, OSError) as error:
        parser.exit(1, f"reverseai: input refused: {type(error).__name__}\n")
    out.mkdir(mode=0o755, exist_ok=True)
    write_new(out / "report.json", report.to_json(analysis))
    write_new(out / "report.md", report.to_markdown(analysis))
    summary = report.to_dict(analysis)["summary"]
    print(f"{analysis.input.sha256}  " + ", ".join(f"{summary[k]} {k}" for k in summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
