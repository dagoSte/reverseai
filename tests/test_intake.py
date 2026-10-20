import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverseai import intake
from reverseai.contract import ContractError, InputRef, sha256_hex


class Changed:
    """An fstat result whose selected fields differ from the real one."""

    def __init__(self, value, **changes):
        self.value, self.changes = value, changes

    def __getattr__(self, name):
        return self.changes.get(name, getattr(self.value, name))


class IntakeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.sample = self.root / "sample.bin"
        self.sample.write_bytes(b"\x7fELF frozen bytes")

    def refused(self, path, message):
        with self.assertRaises(intake.IntakeError) as caught:
            intake.snapshot(path)
        self.assertIsInstance(caught.exception, ContractError)
        self.assertEqual(str(caught.exception), message)
        self.assertNotIn(str(self.root), str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)  # no OSError text with the path is chained

    def test_a_regular_file_is_frozen_with_its_basename(self):
        data, ref = intake.snapshot(self.sample)
        self.assertEqual(data, b"\x7fELF frozen bytes")
        self.assertEqual(ref, InputRef(sha256=sha256_hex(data), size=len(data), name="sample.bin"))
        self.assertEqual(intake.snapshot(str(self.sample)), (data, ref))

    def test_links_and_non_regular_files_are_refused(self):
        link = self.root / "link.bin"
        link.symlink_to(self.sample)
        self.refused(link, "Symlinks and reparse points cannot be input files")
        self.refused(self.root, "Only a regular file can be an input")
        hard = self.root / "hard.bin"
        os.link(self.sample, hard)
        self.refused(self.sample, "Hard-linked input files need a separate copy")
        self.refused(hard, "Hard-linked input files need a separate copy")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs need a POSIX host")
    def test_a_fifo_is_refused_without_blocking(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo)
        self.refused(fifo, "Only a regular file can be an input")

    def test_a_missing_file_is_refused_without_its_path(self):
        self.refused(self.root / "missing.bin", "Input file could not be inspected")

    def test_the_size_limit_is_enforced(self):
        with patch.object(intake, "MAX_INPUT_BYTES", 4):
            self.refused(self.sample, "Input file exceeds the byte limit")
        with patch.object(intake, "MAX_INPUT_BYTES", len(self.sample.read_bytes())):
            self.assertEqual(intake.snapshot(self.sample)[1].size, len(self.sample.read_bytes()))

    def test_a_file_replaced_or_changed_during_the_read_is_refused(self):
        real = os.fstat
        def replaced(descriptor):
            return Changed(real(descriptor), st_ino=real(descriptor).st_ino + 1)
        with patch.object(intake.os, "fstat", side_effect=replaced):
            self.refused(self.sample, "Input file changed identity while opening")
        calls = []
        def grown(descriptor):
            calls.append(descriptor)
            value = real(descriptor)
            return Changed(value, st_size=value.st_size + 1) if len(calls) > 1 else value
        with patch.object(intake.os, "fstat", side_effect=grown):
            self.refused(self.sample, "Input changed while reading")
        calls.clear()
        def touched(descriptor):
            calls.append(descriptor)
            value = real(descriptor)
            return Changed(value, st_mtime_ns=value.st_mtime_ns + 1) if len(calls) > 1 else value
        with patch.object(intake.os, "fstat", side_effect=touched):
            self.refused(self.sample, "Input changed while reading")

    def test_a_link_swapped_in_after_inspection_is_not_followed(self):
        if not getattr(os, "O_NOFOLLOW", 0):
            self.skipTest("O_NOFOLLOW is not available on this host")
        target = self.root / "target.bin"
        target.write_bytes(b"other bytes")
        real = intake._regular_stat
        def swap(path):
            value = real(path)
            path.unlink()
            path.symlink_to(target)
            return value
        with patch.object(intake, "_regular_stat", side_effect=swap):
            self.refused(self.sample, "Input file could not be opened")


if __name__ == "__main__":
    unittest.main()
