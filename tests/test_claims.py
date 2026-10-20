import unittest

from reverseai import claims
from reverseai.contract import Location, Observation, ToolRef, make_evidence, make_finding

DATA = bytes(range(256)) * 4
STRUCTURE, STRINGS = ToolRef("structure", "0.1.0"), ToolRef("strings", "0.1.0")


def evidence(tool, operation, offset=0, **value):
    return make_evidence(DATA, tool, operation, Observation(Location(offset, 4), value))


def finding(claim_key, value, cited, role="structural"):
    return make_finding(role, "A claim.", claim_key, value, [item.id for item in cited])


class ClaimRuleTests(unittest.TestCase):
    def test_structural_claims_must_match_their_observations(self):
        pe = evidence(STRUCTURE, "structure.identify", format="pe")
        self.assertEqual(claims.check(finding("format.container", "pe", [pe]), [pe]), ())
        self.assertEqual(claims.check(finding("format.container", "elf", [pe]), [pe]), ("cited evidence does not yield the claimed value",))
        headers = evidence(STRUCTURE, "structure.headers", 8, machine_name="x86_64", number_of_sections=3)
        self.assertEqual(claims.check(finding("format.machine", "x86_64", [headers]), [headers]), ())
        self.assertEqual(claims.check(finding("format.section_count", 3, [headers]), [headers]), ())
        self.assertNotEqual(claims.check(finding("format.section_count", 4, [headers]), [headers]), ())

    def test_extended_numbering_never_supports_a_zero_section_count(self):
        extended = evidence(STRUCTURE, "structure.headers", 8, machine_name="x86_64", shnum=0, shoff=64)
        self.assertNotEqual(claims.check(finding("format.section_count", 0, [extended]), [extended]), ())
        empty = evidence(STRUCTURE, "structure.headers", 12, machine_name="x86_64", shnum=0, shoff=0)
        self.assertEqual(claims.check(finding("format.section_count", 0, [empty]), [empty]), ())

    def test_claims_may_only_cite_their_operation(self):
        headers = evidence(STRUCTURE, "structure.headers", format="pe", machine_name="x86_64")
        reasons = claims.check(finding("format.container", "pe", [headers]), [headers])
        self.assertEqual(reasons, ("format.container may only cite structure.identify evidence",))

    def test_disagreeing_citations_yield_nothing(self):
        a = evidence(STRUCTURE, "structure.identify", 0, format="pe")
        b = evidence(STRUCTURE, "structure.identify", 4, format="elf")
        self.assertNotEqual(claims.check(finding("format.container", "pe", [a, b]), [a, b]), ())

    def test_writable_executable_sections(self):
        rwx = evidence(STRUCTURE, "structure.sections", 0, name=".rwx", writable=True, executable=True)
        rx = evidence(STRUCTURE, "structure.sections", 4, name=".text", writable=False, executable=True)
        self.assertEqual(claims.check(finding("sections.writable_executable", [".rwx"], [rwx]), [rwx]), ())
        self.assertNotEqual(claims.check(finding("sections.writable_executable", [".rwx", ".text"], [rwx, rx]), [rwx, rx]), ())

    def test_capability_and_url_claims(self):
        inject = evidence(STRINGS, "strings.indicators", 0, rule="virtual_alloc_ex", category="process_injection", match="VirtualAllocEx")
        url = evidence(STRINGS, "strings.indicators", 4, rule="url", category="network", match="https://example.invalid/x")
        ok = finding("capability.process_injection", ["virtual_alloc_ex"], [inject], "capability")
        self.assertEqual(claims.check(ok, [inject]), ())
        wrong_category = finding("capability.persistence", ["virtual_alloc_ex"], [inject], "capability")
        self.assertNotEqual(claims.check(wrong_category, [inject]), ())
        self.assertEqual(claims.check(finding("strings.urls", ["https://example.invalid/x"], [url], "capability"), [url]), ())
        self.assertNotEqual(claims.check(finding("strings.urls", ["https://evil.invalid/"], [url], "capability"), [url]), ())

    def test_unknown_claims_and_empty_citations_are_never_supported(self):
        pe = evidence(STRUCTURE, "structure.identify", format="pe")
        self.assertEqual(claims.check(finding("capability.ransomware", ["x"], [pe]), [pe]), ("no claim rule for this claim_key",))
        self.assertEqual(claims.check(finding("format.container", "pe", []), []), ("finding cites no evidence",))


if __name__ == "__main__":
    unittest.main()
