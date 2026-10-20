from dataclasses import replace
import unittest

from reverseai.analysts import capability
from reverseai.contract import (
    Budget, InputRef, Location, Observation, ToolRef, content_id, make_evidence, sha256_hex,
)
from reverseai.gateway import Gateway
from reverseai.tools.strings import TOOL
from tests.fixtures_strings import clean_control, known_strings


def input_ref(data):
    return InputRef(sha256_hex(data), len(data), "synthetic.bin")


class CapabilityTests(unittest.TestCase):
    def test_plan_is_content_bound_and_deterministic(self):
        data, _, _ = known_strings()
        task = capability.plan(input_ref(data))
        self.assertEqual(task.role, "capability")
        self.assertEqual(task.id, content_id("tk", {"input": sha256_hex(data), "role": "capability"}))
        self.assertEqual([request.operation for request in task.operations], ["strings.extract", "strings.indicators"])
        self.assertEqual(task, capability.plan(input_ref(data)))
        self.assertEqual(task.id, capability.plan(InputRef(sha256_hex(data), len(data), "alias.bin")).id)
        self.assertNotEqual(task.id, capability.plan(input_ref(data + b"\x00")).id)

    def test_exact_findings_and_exact_supporting_evidence(self):
        data, _, _ = known_strings()
        task = capability.plan(input_ref(data))
        result = Gateway([TOOL], Budget()).run(task, data)
        self.assertEqual(result.status, "ok")
        findings = capability.conclude(task, result.evidence)
        self.assertEqual({finding.claim_key: finding.value for finding in findings}, {
            "capability.anti_debug": ["check_remote_debugger_present", "is_debugger_present"],
            "capability.crypto": ["bcrypt_encrypt", "crypt_encrypt"],
            "capability.network": ["ipv4", "url", "winhttp_open", "wsa_startup"],
            "capability.persistence": ["reg_set_value_ex", "registry_run"],
            "capability.process_injection": ["create_remote_thread", "open_process", "virtual_alloc_ex", "write_process_memory"],
            "strings.urls": ["https://example.invalid/submit", "https://wide.example.invalid/path"],
        })
        for finding in findings:
            if finding.claim_key == "strings.urls":
                expected_ids = {item.id for item in result.evidence if item.operation == "strings.indicators"
                                and item.observation["rule"] == "url"}
                self.assertEqual(finding.confidence, "observed")
            else:
                category = finding.claim_key.removeprefix("capability.")
                expected_ids = {min(item.id for item in result.evidence
                                    if item.operation == "strings.indicators"
                                    and item.observation["category"] == category
                                    and item.observation["rule"] == rule) for rule in finding.value}
                self.assertEqual(finding.confidence, "inferred")
            self.assertEqual(set(finding.evidence_ids), expected_ids)
            self.assertTrue(expected_ids)
        self.assertEqual(findings, capability.conclude(task, tuple(reversed(result.evidence))))

    def test_all_gateway_evidence_has_exact_input_and_excerpt_hashes(self):
        data, _, _ = known_strings()
        result = Gateway([TOOL], Budget()).run(capability.plan(input_ref(data)), data)
        for item in result.evidence:
            self.assertEqual(item.input_sha256, sha256_hex(data))
            self.assertEqual(item.tool, ToolRef("strings", "0.1.0"))
            self.assertEqual(item.excerpt_sha256, sha256_hex(data[item.location.offset:item.location.offset + item.location.length]))

    def test_no_indicators_produces_no_findings(self):
        data = clean_control()
        task = capability.plan(input_ref(data))
        result = Gateway([TOOL], Budget()).run(task, data)
        self.assertEqual(result.status, "ok")
        self.assertTrue(result.evidence)
        self.assertEqual(capability.conclude(task, result.evidence), ())
        self.assertEqual(capability.conclude(task, ()), ())

    def test_foreign_input_tool_version_and_operation_do_not_support_findings(self):
        data = b"OpenProcess"
        task = capability.plan(input_ref(data))
        value = Observation(Location(0, 11), {"rule": "open_process", "category": "process_injection", "match": "OpenProcess"})
        foreign = (
            make_evidence(b"OtherString", TOOL.ref, "strings.indicators", value),
            make_evidence(data, ToolRef("strings", "0.2.0"), "strings.indicators", value),
            make_evidence(data, TOOL.ref, "strings.extract", value),
        )
        self.assertEqual(capability.conclude(task, foreign), ())
        self.assertEqual(capability.conclude(replace(task, role="structural"), foreign), ())

    def test_malformed_or_unknown_indicator_shapes_are_ignored(self):
        data = b"OpenProcess"
        task = capability.plan(input_ref(data))
        for value in ({"rule": "made_up", "category": "network", "match": "anything"},
                      {"rule": "open_process", "category": "crypto", "match": "OpenProcess"},
                      {"rule": "open_process", "category": "process_injection"},
                      {"rule": ["open_process"], "category": "process_injection", "match": "OpenProcess"}):
            with self.subTest(value=value):
                evidence = make_evidence(data, TOOL.ref, "strings.indicators", Observation(Location(0, 11), value))
                self.assertEqual(capability.conclude(task, (evidence,)), ())

    def test_repeated_indicators_need_only_one_representative_per_rule(self):
        data = b"OpenProcess " * 70
        task = capability.plan(input_ref(data))
        result = Gateway([TOOL], Budget()).run(task, data)
        findings = capability.conclude(task, result.evidence)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].value, ["open_process"])
        self.assertEqual(len(findings[0].evidence_ids), 1)

    def test_url_findings_are_bounded_and_cite_exactly_their_values(self):
        urls = [f"https://host{index:03d}.example.invalid" for index in range(70)]
        data = " ".join(urls).encode()
        task = capability.plan(input_ref(data))
        result = Gateway([TOOL], Budget()).run(task, data)
        url_finding = next(finding for finding in capability.conclude(task, result.evidence)
                           if finding.claim_key == "strings.urls")
        self.assertEqual(url_finding.value, urls[:64])
        cited = {item.id: item.observation["match"] for item in result.evidence if item.operation == "strings.indicators"}
        self.assertEqual(sorted(cited[item] for item in url_finding.evidence_ids), urls[:64])

    def test_partial_budget_result_only_concludes_from_retained_evidence(self):
        data = b"OpenProcess WinHttpOpen"
        task = capability.plan(input_ref(data))
        result = Gateway([TOOL], Budget(max_evidence=2)).run(task, data)
        self.assertEqual(result.status, "budget_exceeded")
        findings = capability.conclude(task, result.evidence)
        self.assertEqual([(finding.claim_key, finding.value) for finding in findings], [
            ("capability.process_injection", ["open_process"]),
        ])
        self.assertEqual(findings[0].evidence_ids, (result.evidence[1].id,))


if __name__ == "__main__":
    unittest.main()
