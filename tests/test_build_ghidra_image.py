"""tools/build_ghidra_image.py without Docker or the internet: the Dockerfile shape, the download URL, redirect, size
and hash rules, the build context and the exact docker calls."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import urllib.request
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_ghidra_image", ROOT / "tools" / "build_ghidra_image.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)
FAKE = {"ghidra": b"stand-in Ghidra zip, never unpacked", "jdk": b"stand-in JDK tarball, never unpacked"}
BASE = "FROM " + build.BASE


def assets():
    return {key: dict(asset, sha256=hashlib.sha256(FAKE[key]).hexdigest()) for key, asset in build.ASSETS.items()}


class FakeDocker:
    def __init__(self, image_id="sha256:" + "a" * 64):
        self.calls, self.context, self.image_id = [], None, image_id

    def __call__(self, *args, capture=False):
        self.calls.append(args)
        if args[0] == "build":
            context = Path(args[-1])
            self.context = sorted(str(path.relative_to(context)) for path in context.rglob("*"))
            self.downloads = {path.name: path.read_bytes() for path in (context / "downloads").iterdir()}
            Path(args[args.index("--iidfile") + 1]).write_text(self.image_id + "\n")


class BuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.downloads = self.root / "downloads"
        self.downloads.mkdir()
        for key, asset in build.ASSETS.items():
            (self.downloads / asset["name"]).write_bytes(FAKE[key])
        self.lock = self.root / "image.lock.json"
        self.docker = FakeDocker()

    def build(self, *extra, source=None):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(build, "docker", self.docker))
            stack.enter_context(patch.object(build, "ASSETS", assets()))
            if source:
                stack.enter_context(patch.object(build, "SOURCE", source))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            return build.main(["--download-dir", str(self.downloads), "--lock", str(self.lock), *extra])

    def copy(self, label):
        source = self.root / label.replace(" ", "-")
        shutil.copytree(build.SOURCE, source, ignore=shutil.ignore_patterns("image.lock.json"))
        return source

    def dockerfile(self, label, lines):
        source = self.copy(label)
        (source / "Dockerfile").write_text("\n".join(lines) + "\n")
        return source

    def test_the_base_is_pulled_by_digest_and_the_lock_has_exactly_the_six_keys(self):
        self.assertEqual(self.build(), 0)
        pull, built = self.docker.calls
        self.assertEqual(pull, ("pull", "--platform", "linux/arm64", build.BASE))
        self.assertEqual(built[:4], ("build", "--platform", "linux/arm64", "--pull=false"))
        self.assertEqual(built[4:8], ("--iidfile", built[5], "--tag", "reverseai-ghidra:12.1.4-r1"))
        self.assertEqual(len(built), 9)  # network is restricted by the Dockerfile itself (one natives RUN)
        self.assertEqual(self.docker.context, [
            "Dockerfile", "downloads", "downloads/" + build.ASSETS["jdk"]["name"], "downloads/" + build.ASSETS["ghidra"]["name"],
            "ghidra_scripts", "ghidra_scripts/ReverseAIOptions.java", "ghidra_scripts/ReverseAIQuery.java", "unpack.py", "worker.py"])
        self.assertEqual(self.docker.downloads, {build.ASSETS[key]["name"]: FAKE[key] for key in FAKE})
        self.assertEqual(json.loads(self.lock.read_text()), {
            "adapter_version": "12.1.4-r1", "base_digest": build.BASE_DIGEST, "image_id": "sha256:" + "a" * 64,
            "ghidra_sha256": hashlib.sha256(FAKE["ghidra"]).hexdigest(), "jdk_sha256": hashlib.sha256(FAKE["jdk"]).hexdigest(),
            "platform": "linux/arm64"})

    def test_the_pinned_assets_are_the_owner_approved_files(self):
        self.assertEqual(build.ASSETS["ghidra"]["sha256"], "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db")
        self.assertEqual(build.ASSETS["jdk"]["sha256"], "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223")
        self.assertTrue(build.ASSETS["ghidra"]["url"].startswith("https://github.com/NationalSecurityAgency/ghidra/releases/download/"))
        self.assertTrue(build.ASSETS["jdk"]["url"].startswith("https://github.com/adoptium/temurin21-binaries/releases/download/"))
        self.assertEqual((build.ASSETS["ghidra"]["limit"], build.ASSETS["jdk"]["limit"]), (640 * 1024 * 1024, 256 * 1024 * 1024))

    def test_a_missing_or_different_download_is_refused_before_docker(self):
        (self.downloads / build.ASSETS["jdk"]["name"]).write_bytes(FAKE["jdk"] + b"!")
        with self.assertRaisesRegex(SystemExit, "does not match its pinned SHA-256"):
            self.build()
        (self.downloads / build.ASSETS["jdk"]["name"]).unlink()
        with self.assertRaisesRegex(SystemExit, r"missing .* \(or pass --download\)"):
            self.build()
        self.assertEqual(self.docker.calls, [])

    def test_download_fetches_only_what_is_missing(self):
        (self.downloads / build.ASSETS["jdk"]["name"]).unlink()
        fetched = []

        def fetch(asset, folder):
            fetched.append(asset["name"])
            (Path(folder) / asset["name"]).write_bytes(FAKE["jdk"])

        with patch.object(build, "fetch", fetch):
            self.assertEqual(self.build("--download"), 0)
        self.assertEqual(fetched, [build.ASSETS["jdk"]["name"]])

    def test_a_build_without_a_well_formed_image_id_writes_no_lock(self):
        for written in ("", "a" * 64, "sha256:" + "A" * 64, "sha256:" + "a" * 63):
            with self.subTest(image_id=written):
                self.docker = FakeDocker(written)
                with self.assertRaisesRegex(SystemExit, "no image ID"):
                    self.build()
                self.assertFalse(self.lock.exists())

    def test_the_real_dockerfile_is_accepted(self):
        build.check_dockerfile(build.SOURCE / "Dockerfile")

    def test_every_other_dockerfile_shape_is_refused_before_docker(self):
        natives, final = BASE + " AS natives", BASE
        apt = "RUN apt-get update && apt-get install -y g++ make"
        offline = "RUN --network=none true"
        copy = "COPY --from=natives /opt/jdk /opt/jdk"
        user = "USER 65534:65534"
        cases = (
            ("one stage only", [final, offline, user], "FROM differs"),
            ("stage under another name", [BASE + " AS builder", apt, final, user], "FROM differs"),
            ("other base for the natives", ["FROM debian:trixie AS natives", apt, final, user], "FROM differs"),
            ("a third stage", [natives, apt, BASE + " AS extra", final, user], "FROM differs"),
            ("stages swapped", [final, natives, apt, user], "FROM differs"),
            ("lower-case as", [BASE + " as natives", apt, final, user], "FROM differs"),
            ("FROM split by a continuation", [natives, apt, final, "FR\\", "OM busybox", user], "FROM differs"),
            ("COPY from another image", [natives, apt, final, "COPY --from=busybox /bin/sh /bin/sh", user], "another image or stage"),
            ("COPY from a stage index", [natives, apt, final, "COPY --from=0 /opt /opt", user], "another image or stage"),
            ("RUN from another image", [natives, apt, final, offline.replace("true", "") + "--mount=type=bind,from=natives,target=/x true", user],
             "another image or stage"),
            ("ADD", [natives, apt, final, "ADD https://example.invalid/x /x", user], "ADD is refused"),
            ("ADD split", [natives, apt, final, "A\\", "DD x /x", user], "ADD is refused"),
            ("directive", ["# syntax=docker/dockerfile:1", natives, apt, final, user], "parser directives"),
            ("non-ASCII", [natives, apt, final, "# caf\u00e9", user], "must be ASCII"),
            ("network in the image", [natives, apt, final, "RUN true", user], "network in one natives RUN only"),
            ("network twice in the natives", [natives, apt, "RUN make", final, user], "network in one natives RUN only"),
            ("no network step at all", [natives, offline, final, user], "network in one natives RUN only"),
            ("the one network step in the image", [natives, offline, final, "RUN apt-get update", user], "network in one natives RUN only"),
            ("network flag elsewhere", [natives, apt, final, "RUN true --network=none", user], "network in one natives RUN only"),
            ("no USER", [natives, apt, final, copy], "exactly one USER"),
            ("lower-case extra user", [natives, apt, final, user, "user root"], "exactly one USER"),
            ("USER root", [natives, apt, final, "USER root"], "exactly one USER"),
        )
        for label, lines, reason in cases:
            with self.subTest(label):
                with self.assertRaisesRegex(SystemExit, reason):
                    self.build(source=self.dockerfile(label, lines))
                self.assertEqual(self.docker.calls, [])
        allowed = self.dockerfile("smallest accepted", [natives, apt, offline, final, copy, offline, user])
        self.assertEqual(self.build(source=allowed), 0)


UNPACK_SPEC = importlib.util.spec_from_file_location("ghidra_unpack", ROOT / "containers" / "ghidra" / "unpack.py")
unpack = importlib.util.module_from_spec(UNPACK_SPEC)
UNPACK_SPEC.loader.exec_module(unpack)


class UnpackTests(unittest.TestCase):
    """The natives-stage helper: hash first, members only inside the destination, exec bits kept."""

    def archive(self, folder, members):
        path = Path(folder, "g.zip")
        with zipfile.ZipFile(path, "w") as bundle:
            for name, mode, body in members:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                bundle.writestr(info, body)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_members_are_unpacked_with_their_exec_bits(self):
        with tempfile.TemporaryDirectory() as folder:
            path, digest = self.archive(folder, [("g/support/analyzeHeadless", 0o100755, b"#!/bin/bash\n"),
                                                 ("g/support/launch.properties", 0o100644, b"x=1\n")])
            unpack.main(["ghidra", str(path), digest, str(Path(folder, "out"))])
            self.assertEqual(oct(Path(folder, "out/g/support/analyzeHeadless").stat().st_mode & 0o777), "0o755")
            self.assertEqual(oct(Path(folder, "out/g/support/launch.properties").stat().st_mode & 0o777), "0o644")

    def test_a_wrong_hash_or_an_escaping_member_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path, digest = self.archive(folder, [("g/ok", 0o100644, b"ok")])
            with self.assertRaisesRegex(SystemExit, "pinned SHA-256"):
                unpack.main(["ghidra", str(path), "0" * 64, str(Path(folder, "out"))])
            with self.assertRaisesRegex(SystemExit, "pinned SHA-256"):
                unpack.main(["check", str(path), "0" * 64])
            unpack.main(["check", str(path), digest])
            for label, member in (("parent path", ("../escape", 0o100644, b"x")), ("absolute", ("/tmp/abs", 0o100644, b"x")),
                                  ("link", ("g/link", 0o120777, b"/etc/passwd"))):
                with self.subTest(label):
                    bad, bad_digest = self.archive(Path(folder), [member])
                    with self.assertRaisesRegex(SystemExit, "unsafe member"):
                        unpack.main(["ghidra", str(bad), bad_digest, str(Path(folder, label.replace(" ", "-")))])
            self.assertFalse(Path(folder, "escape").exists())
            with self.assertRaisesRegex(SystemExit, "usage"):
                unpack.main(["ghidra", str(path)])


class Response(io.BytesIO):
    pass


class Opener:
    def __init__(self, body):
        self.body, self.calls = body, []

    def open(self, url, timeout):
        self.calls.append((url, timeout))
        return Response(self.body)


class DownloadTests(unittest.TestCase):
    def fetch(self, body, asset=None, limit=None):
        asset = dict(asset or assets()["jdk"])
        if limit is not None:
            asset["limit"] = limit
        opener = Opener(body)
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(build.urllib.request, "build_opener", return_value=opener) as factory:
            try:
                return build.fetch(asset, folder).read_bytes(), opener, factory
            finally:
                self.left = sorted(path.name for path in Path(folder).iterdir())

    def test_pinned_bytes_are_kept_through_the_restricted_redirect_handler(self):
        kept, opener, factory = self.fetch(FAKE["jdk"])
        self.assertEqual(kept, FAKE["jdk"])
        factory.assert_called_once_with(build.ReleaseAssetRedirects)
        self.assertEqual(opener.calls, [(build.ASSETS["jdk"]["url"], 60)])
        self.assertEqual(self.left, [build.ASSETS["jdk"]["name"]])

    def test_other_bytes_or_too_many_are_refused_and_nothing_is_left(self):
        for label, body, limit, reason in (("other bytes", FAKE["jdk"] + b"!", None, "does not match its pinned SHA-256"),
                                           ("over the cap", FAKE["jdk"], len(FAKE["jdk"]) - 1, "larger than its size cap")):
            with self.subTest(label):
                with self.assertRaisesRegex(SystemExit, reason):
                    self.fetch(body, limit=limit)
                self.assertEqual(self.left, [])

    def test_the_first_url_must_be_the_pinned_github_release_url(self):
        asset = assets()["ghidra"]
        for url in ("http://github.com/x/" + asset["name"], "https://example.invalid/x/" + asset["name"],
                    "https://github.com:8443/x/" + asset["name"], "https://github.com.evil.invalid/x/" + asset["name"],
                    "https://github.com/x/" + asset["name"] + ".exe"):
            with self.subTest(url), tempfile.TemporaryDirectory() as folder, \
                    patch.object(build.urllib.request, "build_opener", side_effect=AssertionError("request made")):
                with self.assertRaisesRegex(SystemExit, "not its pinned GitHub release URL"):
                    build.fetch(dict(asset, url=url), folder)

    def test_redirects_go_only_to_release_asset_hosts_over_https(self):
        handler = build.ReleaseAssetRedirects()
        request = urllib.request.Request(build.ASSETS["ghidra"]["url"])
        for url in ("https://release-assets.githubusercontent.com/x?sig=1", "https://objects.githubusercontent.com/x"):
            with self.subTest(url):
                self.assertEqual(handler.redirect_request(request, None, 302, "Found", {}, url).full_url, url)
        for url in ("http://release-assets.githubusercontent.com/x", "https://example.invalid/x",
                    "https://release-assets.githubusercontent.com:8443/x", "https://user:pw@objects.githubusercontent.com/x",
                    "https://githubusercontent.com/x", "https://release-assets.githubusercontent.com.evil.invalid/x"):
            with self.subTest(url), self.assertRaisesRegex(SystemExit, "outside the GitHub release-asset hosts"):
                handler.redirect_request(request, None, 302, "Found", {}, url)
        self.assertEqual(build.ReleaseAssetRedirects.max_redirections, 2)


if __name__ == "__main__":
    unittest.main()
