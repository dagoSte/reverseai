import threading
import unittest

from reverseai.contract import Budget, OperationRequest
from reverseai.gateway import Gateway
from tests.test_gateway import DATA, observation, task, tool


class OperationChargeTests(unittest.TestCase):
    def test_retrying_a_time_cut_operation_does_not_charge_the_global_budget_twice(self):
        release, calls = threading.Event(), []

        def slow(data, args):
            calls.append("observe")
            if len(calls) == 1:
                release.wait(timeout=3)
            return [observation()]

        def other(data, args):
            calls.append("other")
            return [observation(1, "other")]

        gateway = Gateway([tool(slow, other=other)], Budget(max_operations=2, max_concurrency=2))
        self.assertEqual(gateway.run(task(budget=Budget(max_wall_seconds=0.03)), DATA).status, "budget_exceeded")
        release.set()
        self.assertEqual(gateway.run(task(budget=Budget(max_wall_seconds=2)), DATA).status, "ok")
        second = gateway.run(task(OperationRequest("fake.other"), budget=Budget(max_wall_seconds=2)), DATA)
        self.assertEqual(second.status, "ok")
        self.assertEqual(calls, ["observe", "observe", "other"])


if __name__ == "__main__":
    unittest.main()
