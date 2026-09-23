import unittest

from sylanne3.recall_policy import ContinuationEstimate, evaluate_continuation


class RecallContinuationTests(unittest.TestCase):
    def test_only_positive_admitted_net_value_continues_optional_frontier(self):
        receipt = evaluate_continuation(
            ContinuationEstimate(
                "d06.continuation.v1",
                "optional-frontier",
                "frontier-1",
                evidence_gain=0.9,
                latency_cost=0.1,
                call_cost=0.1,
                context_interference=0.1,
                weights=(0.7, 0.1, 0.1, 0.1),
                threshold=0.2,
                no_progress_count=0,
                budget_admitted=True,
                deadline_admitted=True,
                permission_admitted=True,
                entry_admitted=True,
                mandatory_outstanding=False,
            )
        )
        self.assertEqual(receipt.decision, "continue")
        self.assertEqual(receipt.stop_reason, None)
        self.assertGreater(receipt.net_value, receipt.threshold)

    def test_unknown_cost_and_two_rounds_without_progress_stop_fail_closed(self):
        unknown = evaluate_continuation(
            self.estimate(call_cost=None)
        )
        self.assertEqual(unknown.decision, "stop")
        self.assertEqual(unknown.stop_reason, "unknown_cost")

        stalled = evaluate_continuation(
            self.estimate(no_progress_count=2)
        )
        self.assertEqual(stalled.decision, "stop")
        self.assertEqual(stalled.stop_reason, "no_progress")

    def test_required_check_outstanding_never_becomes_complete(self):
        receipt = evaluate_continuation(
            self.estimate(mandatory_outstanding=True, evidence_gain=0.0)
        )
        self.assertEqual(receipt.decision, "stop")
        self.assertEqual(receipt.stop_reason, "mandatory_outstanding")
        self.assertFalse(receipt.request_complete)

    @staticmethod
    def estimate(**changes):
        values = dict(
            policy_version="d06.continuation.v1",
            policy_scope="optional-frontier",
            frontier_id="frontier-1",
            evidence_gain=0.2,
            latency_cost=0.5,
            call_cost=0.5,
            context_interference=0.5,
            weights=(0.25, 0.25, 0.25, 0.25),
            threshold=0.1,
            no_progress_count=0,
            budget_admitted=True,
            deadline_admitted=True,
            permission_admitted=True,
            entry_admitted=True,
            mandatory_outstanding=False,
        )
        values.update(changes)
        return ContinuationEstimate(**values)


if __name__ == "__main__":
    unittest.main()
