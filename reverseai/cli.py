"""Command line: python3 -m reverseai analyze FILE --out DIR"""

import argparse
import os
from pathlib import Path
import stat
import sys

from reverseai import intake, pipeline, report

# Reports hold text taken from untrusted samples: private to the user.
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
REPORTS = ("report.json", "report.md")


class OutputRefused(Exception):
    """--out is not a new or empty real directory, or cannot be bound safely."""


def safe_directories():
    return os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")


def open_output(path):
    """Bind --out to a directory handle before the analysis, so a later swap of the path cannot redirect the reports."""
    if not safe_directories():
        raise OutputRefused("this platform lacks safe directory handles")
    try:
        os.mkdir(path, DIRECTORY_MODE)
    except FileExistsError:
        pass
    except OSError:
        raise OutputRefused("--out cannot be created") from None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise OutputRefused("--out must be a new or empty directory") from None
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode) or os.listdir(descriptor):
        os.close(descriptor)
        raise OutputRefused("--out must be a new or empty directory")
    return descriptor


def write_new(directory, name, text):
    """Create the file inside the bound directory or fail; never follow or replace an existing entry."""
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE, dir_fd=directory)
    with os.fdopen(descriptor, "w", encoding="utf-8", errors="backslashreplace", newline="\n") as handle:
        handle.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="reverseai", description="Static analysis with verifiable evidence (M1 prototype).")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Analyse one approved file without executing it")
    analyze.add_argument("file", type=Path)
    analyze.add_argument("--out", type=Path, required=True, help="New or empty directory for report.json and report.md")
    args = parser.parse_args(argv)

    try:
        unusable = args.out.is_symlink() or (args.out.exists() and (not args.out.is_dir() or any(args.out.iterdir())))
    except OSError:
        unusable = True
    if unusable:
        parser.exit(1, "reverseai: --out must be a new or empty directory\n")
    try:
        data, ref = intake.snapshot(args.file)
    except (OSError, ValueError) as error:  # ContractError is a ValueError
        parser.exit(1, f"reverseai: input refused: {type(error).__name__}\n")
    try:
        directory = open_output(args.out)
    except OutputRefused as error:
        parser.exit(1, f"reverseai: output refused: {error}\n")
    written = []
    try:
        try:
            analysis = pipeline.analyze_bytes(data, ref)
        except ValueError as error:
            parser.exit(1, f"reverseai: analysis failed: {type(error).__name__}\n")
        for name, render in zip(REPORTS, (report.to_json, report.to_markdown)):
            write_new(directory, name, render(analysis))
            written.append(name)
    except (OSError, ValueError) as error:
        parser.exit(1, f"reverseai: output failed: {type(error).__name__}; written: {', '.join(written) or 'nothing'}\n")
    finally:
        os.close(directory)
    summary = report.to_dict(analysis)["summary"]
    print(f"{analysis.input.sha256}  " + ", ".join(f"{summary[k]} {k}" for k in summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
