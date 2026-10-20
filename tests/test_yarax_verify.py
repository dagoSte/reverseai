import copy
import json
from pathlib import Path
import tempfile
import unittest

from reverseai.contained import ContainedError
from reverseai.contract import ContractError, Location, Observation, sha256_hex
from reverseai.tools import yarax_verify
from tests.fixtures_yarax import RULESET_SHA256, known_matches, match

RULESET_PATH = Path(__file__).resolve().parents[1] / "containers/yarax/m2_fixture_v1.json"
ARGS = {"ruleset": "m2_fixture_v1", "max_matches": 64}


def observation(item):
    return Observation(Location(**item["location"]), item["value"])


class RulesetTests(unittest.TestCase):
    def test_reviewed_hash_and_literal_patterns_are_frozen(self):
        patterns = yarax_verify.load_patterns(RULESET_PATH, RULESET_SHA256)
        self.assertEqual(len(patterns), 9)
        self.assertEqual(patterns[("upx_packed", "$a")], b"UPX!")
        self.assertEqual(patterns[("credential_dump_marker", "$w")], "sekurlsa::".encode("utf-16le"))
        with self.assertRaises(TypeError):
            patterns[("upx_packed", "$a")] = b"evil"

    def test_missing_file_bad_hash_malformed_and_oversized_rulesets_are_constant_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private.json"
            cases = (None, b"{}", b"\xff", b"[1]", b"x" * 65_537, RULESET_PATH.read_bytes())
            for raw in cases:
                with self.subTest(raw=None if raw is None else len(raw)):
                    if raw is not None:
                        path.write_bytes(raw)
                    digest = "0" * 64 if raw is None or raw == RULESET_PATH.read_bytes() else sha256_hex(raw)
                    with self.assertRaisesRegex(ContainedError, "^InvalidRuleset$") as error:
                        yarax_verify.load_patterns(path, digest)
                    self.assertNotIn(folder, str(error.exception))

    def test_duplicate_unknown_or_nonliteral_rule_definitions_are_refused(self):
        original = json.loads(RULESET_PATH.read_bytes())
        variants = []
        for change in (
                lambda x: x.update(ruleset="other"),
                lambda x: x.update(extra=True),
                lambda x: x["rules"].append(copy.deepcopy(x["rules"][0])),
                lambda x: x["rules"][0]["patterns"].append(copy.deepcopy(x["rules"][0]["patterns"][0])),
                lambda x: x["rules"][0]["patterns"][0].update(hex="?? ?? ?? ??"),
                lambda x: x["rules"][0]["patterns"][0].update(hex="aa"),
                lambda x: x["rules"][0]["patterns"][0].update(hex="aa" * 257),
                lambda x: x["rules"][0]["patterns"][0].update(id="$a;include")):
            value = copy.deepcopy(original)
            change(value)
            variants.append(json.dumps(value).encode())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rules.json"
            for raw in variants:
                with self.subTest(raw=raw[:60]):
                    path.write_bytes(raw)
                    with self.assertRaisesRegex(ContainedError, "^InvalidRuleset$"):
                        yarax_verify.load_patterns(path, sha256_hex(raw))


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.patterns = yarax_verify.load_patterns(RULESET_PATH, RULESET_SHA256)
        self.data, self.items = known_matches()

    def verify(self, items, *, data=None, args=ARGS):
        return yarax_verify.verify(self.data if data is None else data, tuple(map(observation, items)), args, self.patterns)

    def test_real_ascii_and_wide_matches_empty_reply_and_withheld_matches_are_allowed(self):
        self.verify(self.items)
        self.verify([])
        self.verify(self.items[2:3])

    def test_every_value_field_is_checked_and_no_extra_or_missing_field_is_allowed(self):
        for key, value in (("ruleset", "other"), ("rule", "invented"), ("pattern", "$unknown"),
                           ("rule", ["upx_packed"]), ("pattern", True), ("extra", "ignored")):
            items = copy.deepcopy(self.items)
            items[0]["value"][key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ContractError, "^" + yarax_verify.REFUSED + "$"):
                self.verify(items)
        for key in ("ruleset", "rule", "pattern"):
            item = copy.deepcopy(self.items[0])
            del item["value"][key]
            with self.subTest(missing=key), self.assertRaises(ContractError):
                self.verify([item])

    def test_offsets_length_and_actual_bytes_must_match_the_named_pattern(self):
        for changes in ({"offset": 0}, {"offset": len(self.data)}, {"length": 3}, {"length": 5}):
            item = copy.deepcopy(self.items[0])
            item["location"].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                self.verify([item])
        with self.assertRaises(ContractError):
            self.verify(self.items, data=self.data.replace(b"UPX!", b"FAKE"))
        item = match(0, literal=b"UPX!", pattern="$b")
        with self.assertRaises(ContractError):
            self.verify([item], data=b"UPX!")

    def test_duplicate_and_descending_offset_rule_or_pattern_order_are_refused(self):
        for items in ([self.items[0], self.items[0]], list(reversed(self.items))):
            with self.subTest(items=items), self.assertRaises(ContractError):
                self.verify(items)
        patterns = {("a", "$a"): b"UPX!", ("a", "$b"): b"UPX!", ("b", "$a"): b"UPX!"}
        first, second, third = [observation(match(0, rule=r, pattern=p)) for r, p in patterns]
        yarax_verify.verify(b"UPX!", (first, second, third), ARGS, patterns)
        for pair in ((second, first), (third, first)):
            with self.assertRaises(ContractError):
                yarax_verify.verify(b"UPX!", pair, ARGS, patterns)

    def test_requested_ruleset_and_exact_requested_count_are_enforced(self):
        self.verify(self.items[:1], args=dict(ARGS, max_matches=1))
        for args in (dict(ARGS, max_matches=1), dict(ARGS, ruleset="other")):
            with self.subTest(args=args), self.assertRaises(ContractError):
                self.verify(self.items, args=args)
