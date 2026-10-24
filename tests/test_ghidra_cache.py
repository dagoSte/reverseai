"""Opaque project tests use inert bytes and temporary private stores only."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from reverseai import ghidra_cache as cache


def identity(number=0):
    return cache.identity(hashlib.sha256(str(number).encode()).hexdigest(),
                          {"image_id": "sha256:" + "a" * 64, "bundle_sha256": "b" * 64, "cache_format": 1})


@unittest.skipIf(cache.fcntl is None, "POSIX cache requires descriptor and OS lock support")
class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "store"
        self.store = cache.CacheStore(self.root)
        self.blob = b"opaque project, never parsed on the host"

    def prepare(self, number=0):
        return self.store.prepare(identity(number), lambda sink: sink.write(self.blob))

    def test_absent_lookup_and_doctor_do_not_create_anything(self):
        self.assertIsNone(self.store.lookup(identity()))
        self.assertEqual(self.store.facts()["state"], "absent")
        self.assertFalse(self.root.exists())

    def test_prepare_reuses_identity_and_host_computes_exact_hash(self):
        calls = []
        def produce(sink):
            calls.append(True)
            sink.write(self.blob[:5])
            sink.write(self.blob[5:])
        first = self.store.prepare(identity(), produce)
        second = self.store.prepare(identity(), produce)
        self.assertEqual(calls, [True])
        self.assertEqual(first[2], "created")
        self.assertEqual(second[2], "reused")
        self.assertEqual(first[:2], second[:2])
        self.assertEqual(first[0]["artifact_sha256"], hashlib.sha256(self.blob).hexdigest())
        self.assertEqual(first[1], cache.analysis_id(cache.cache_key(identity()), first[0]["artifact_sha256"]))
        self.assertEqual(self.store.facts()["entries"], 1)
        for file in self.root.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)

    def test_all_identity_components_invalidate_and_path_is_irrelevant(self):
        self.prepare()
        for key, value in (("input_sha256", "c" * 64), ("image_id", "sha256:" + "d" * 64),
                           ("bundle_sha256", "e" * 64), ("cache_format", 2)):
            changed = dict(identity(), **{key: value})
            self.assertIsNone(self.store.lookup(changed))
        with cache.CacheStore(self.root).lookup(identity()) as handle:
            self.assertEqual(handle.manifest["size"], len(self.blob))

    def test_stage_contains_only_fixed_contract_fields_and_bytes(self):
        self.prepare()
        target = Path(self.temp.name) / "snapshot"
        target.mkdir()
        with self.store.lookup(identity()) as handle:
            manifest = dict(handle.manifest)
            handle.stage(target)
            self.assertIsNone(handle._lease)
        self.assertEqual({p.name for p in target.iterdir()}, {"project.tar", "cache.json"})
        self.assertEqual((target / "project.tar").read_bytes(), self.blob)
        self.assertEqual(json.loads((target / "cache.json").read_text()), manifest)
        self.assertEqual(set(manifest), {"format", "input_sha256", "image_id", "bundle_sha256", "size", "artifact_sha256"})

    def test_changed_content_size_or_digest_never_replays(self):
        self.prepare()
        path = self.root / (cache.cache_key(identity()) + ".tar")
        for bad in (b"x" * len(self.blob), self.blob[:-1], self.blob + b"x"):
            path.write_bytes(bad)
            with self.subTest(bad=bad), self.assertRaisesRegex(cache.CacheError, "^" + cache.MISSING + "$"):
                self.store.lookup(identity())
        self.assertEqual(self.prepare()[2], "created")

    def test_no_tar_parser_is_used_even_for_a_non_archive(self):
        with patch("tarfile.open", side_effect=AssertionError("host must not parse")):
            self.prepare()
            with self.store.lookup(identity()):
                pass

    def test_failure_or_empty_producer_never_publishes_a_hit(self):
        def fail(sink):
            sink.write(self.blob)
            raise TimeoutError("fixed trusted test error")
        for producer in (fail, lambda sink: None):
            with self.subTest(producer=producer), self.assertRaises((TimeoutError, cache.CacheError)):
                self.store.prepare(identity(), producer)
            self.assertIsNone(self.store.lookup(identity()))
            self.assertFalse(any(p.name.startswith(".tmp-") for p in self.root.iterdir()))

    def test_cap_plus_one_is_refused_before_writing_the_extra_bytes(self):
        with patch.object(cache, "MAX_ARTIFACT_BYTES", 16):
            with self.assertRaises(cache.CacheError):
                self.store.prepare(identity(), lambda sink: sink.write(b"x" * 17))
        self.assertIsNone(self.store.lookup(identity()))

    def test_unsafe_root_permissions_and_symlink_are_not_repaired(self):
        self.root.mkdir(mode=0o755)
        for create in (False, True):
            with self.subTest(create=create), self.assertRaisesRegex(cache.CacheError, "^" + cache.UNSAFE + "$"):
                self.store.prepare(identity(), lambda sink: None) if create else self.store.lookup(identity())
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o755)
        self.root.rmdir()
        real = Path(self.temp.name) / "elsewhere"
        real.mkdir(mode=0o700)
        self.root.symlink_to(real, target_is_directory=True)
        self.assertEqual(self.store.facts()["state"], "unsafe")
        self.assertEqual(list(real.iterdir()), [])

    def test_linked_or_world_readable_body_is_refused_without_touching_target(self):
        self.prepare()
        body = self.root / (cache.cache_key(identity()) + ".tar")
        external = Path(self.temp.name) / "external"
        body.rename(external)
        body.symlink_to(external)
        with self.assertRaises(cache.CacheError):
            self.store.lookup(identity())
        body.unlink()
        os.link(external, body)
        with self.assertRaises(cache.CacheError):
            self.store.lookup(identity())
        body.unlink()
        external.rename(body)
        body.chmod(0o644)
        with self.assertRaises(cache.CacheError):
            self.store.lookup(identity())
        self.assertEqual(body.read_bytes(), self.blob)
        self.assertEqual(body.stat().st_mode & 0o777, 0o644)

    def test_lru_evicts_the_unused_entry_and_counts_current_bytes(self):
        with patch.object(cache, "MAX_ENTRIES", 2):
            self.prepare(0)
            self.prepare(1)
            with self.store.lookup(identity(0)):
                pass
            self.prepare(2)
            self.assertIsNone(self.store.lookup(identity(1)))
            for number in (0, 2):
                with self.store.lookup(identity(number)):
                    pass
            facts = self.store.facts()
            self.assertEqual(facts["entries"], 2)
            self.assertEqual(facts["bytes"], sum(p.stat().st_size for p in self.root.iterdir()))

    def test_doctor_does_not_read_the_tar_body_or_change_files(self):
        self.prepare()
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        original = cache._open_file
        def checked(directory, name, **kwargs):
            if name.endswith(".tar"):
                raise AssertionError("doctor opened a TAR body")
            return original(directory, name, **kwargs)
        with patch.object(cache, "_open_file", side_effect=checked):
            self.assertEqual(self.store.facts()["state"], "ready")
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()})

    def test_metadata_publication_failure_never_leaves_a_hit(self):
        original = cache._atomic_json
        def fail(directory, name, value):
            if name.endswith(".json") and name != "index.json":
                raise OSError("fixed write failure")
            return original(directory, name, value)
        with patch.object(cache, "_atomic_json", side_effect=fail), self.assertRaises((OSError, cache.CacheError)):
            self.prepare()
        self.assertIsNone(self.store.lookup(identity()))
        self.assertEqual(self.prepare()[2], "created")

    def test_two_simultaneous_prepares_build_once_and_a_hit_ignores_prepare_lock(self):
        self.prepare(1)
        started, finish = threading.Event(), threading.Event()
        calls, replies, errors = [], [], []
        def producer(sink):
            calls.append(True)
            started.set()
            if not finish.wait(5):
                raise AssertionError("test synchronization failed")
            sink.write(self.blob)
        def prepare():
            try:
                replies.append(self.store.prepare(identity(), producer))
            except BaseException as error:
                errors.append(error)
        first = threading.Thread(target=prepare)
        second = threading.Thread(target=prepare)
        first.start()
        self.assertTrue(started.wait(5))
        second.start()
        try:
            with self.store.lookup(identity(1)) as hit:
                self.assertEqual(hit.manifest["size"], len(self.blob))
        finally:
            finish.set()
            first.join(5)
            second.join(5)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(calls, [True])
        self.assertEqual({reply[2] for reply in replies}, {"created", "reused"})


if __name__ == "__main__":
    unittest.main()
