import math
import unittest

from sylanne3.recall_policy import (
    Action,
    Budget,
    Evidence,
    RecallPolicy,
    RecallRequest,
    SearchResult,
    Trigger,
)


def request(**changes):
    values = dict(
        request_id="r1",
        trigger=Trigger.EXPLICIT_HISTORY,
        gaps=("when",),
        required_checks=(),
        budget=Budget(rounds=5, candidates=20, nodes=20, model_calls=2),
        timeout_seconds=5.0,
    )
    values.update(changes)
    return RecallRequest(**values)


def result(plan, *, evidence=(), candidates=0, nodes=0, model_calls=0):
    return SearchResult(
        request_id="r1",
        operation_id=plan.operation_id,
        action=plan.action,
        evidence=tuple(evidence),
        candidates_used=candidates,
        nodes_used=nodes,
        model_calls_used=model_calls,
    )


class RecallPolicyTests(unittest.TestCase):
    def test_required_check_blocks_ready_and_budget_exhaustion_is_insufficient(self):
        policy = RecallPolicy(request(required_checks=("open_promises",), budget=Budget(1, 0, 0, 0)))
        plan = policy.next()
        self.assertEqual(plan.action, Action.EXACT_CHECK)
        policy.accept(result(plan))
        final = policy.next()
        self.assertEqual(final.action, Action.INSUFFICIENT)
        self.assertIn("open_promises", final.missing_checks)

    def test_exact_check_then_working_set_can_make_request_ready(self):
        policy = RecallPolicy(request(required_checks=("corrections",)))
        exact = policy.next()
        policy.accept(result(exact, evidence=(Evidence("e1", "calendar", checks=("corrections",)),)))
        working = policy.next()
        self.assertEqual(working.action, Action.WORKING_SET)
        policy.accept(result(working, evidence=(Evidence("e2", "chat", fills=("when",)),)))
        ready = policy.next()
        self.assertEqual(ready.action, Action.READY)
        self.assertEqual({item.source_id for item in ready.evidence}, {"e1", "e2"})

    def test_same_source_can_add_task_coverage_across_stages(self):
        policy = RecallPolicy(request(required_checks=("corrections",)))
        exact = policy.next()
        policy.accept(result(exact, evidence=(
            Evidence("source-v3", "chat", checks=("corrections",), score=0.4),
        )))

        working = policy.next()
        policy.accept(result(working, evidence=(
            Evidence("source-v3", "chat", fills=("when",), score=0.7),
        )))

        ready = policy.next()
        self.assertEqual(ready.action, Action.READY)
        self.assertEqual(len(ready.evidence), 1)
        merged = ready.evidence[0]
        self.assertEqual(merged.fills, ("when",))
        self.assertEqual(merged.checks, ("corrections",))
        self.assertEqual(merged.score, 0.7)

    def test_context_gap_without_identity_clarifies_before_search(self):
        policy = RecallPolicy(request(trigger=Trigger.CONTEXT_GAP, gaps=("referent",)))
        self.assertEqual(policy.next().action, Action.WORKING_SET)
        policy.accept(result(policy.pending_plan))
        self.assertEqual(policy.next().action, Action.CLARIFY)

    def test_uncertain_trigger_conservatively_performs_exact_check(self):
        policy = RecallPolicy(request(trigger=Trigger.UNCERTAIN, required_checks=()))
        self.assertEqual(policy.next().action, Action.EXACT_CHECK)
        self.assertEqual(policy.next().targets, ("trigger_classification",))

    def test_mandatory_trigger_adds_conservative_check_when_caller_omits_it(self):
        expected = {
            Trigger.CORRECTION: "relevant_source_version",
            Trigger.COMMITMENT: "commitment_preconditions",
            Trigger.DEADLINE: "bound_responsibility_status",
        }
        for trigger, target in expected.items():
            with self.subTest(trigger=trigger):
                policy = RecallPolicy(request(trigger=trigger, required_checks=()))
                self.assertEqual(policy.next().action, Action.EXACT_CHECK)
                self.assertIn(target, policy.next().targets)

    def test_partial_required_check_can_continue_within_budget(self):
        policy = RecallPolicy(request(required_checks=("a", "b")))
        first = policy.next()
        policy.accept(result(first, evidence=(Evidence("e1", "f1", checks=("a",)),)))
        second = policy.next()
        self.assertEqual(second.action, Action.EXACT_CHECK)
        self.assertEqual(second.targets, ("b",))

    def test_greeting_uses_working_set_without_history_search(self):
        policy = RecallPolicy(request(trigger=Trigger.GREETING, gaps=()))
        plan = policy.next()
        self.assertEqual(plan.action, Action.WORKING_SET)
        policy.accept(result(plan, evidence=(Evidence("hot", "shared-work"),)))
        ready = policy.next()
        self.assertEqual(ready.action, Action.READY)
        self.assertEqual(ready.activated_source_ids, ("hot",))

    def test_maintenance_is_deferred_and_never_authorizes_action(self):
        policy = RecallPolicy(request(trigger=Trigger.MAINTENANCE, gaps=()))
        plan = policy.next()
        self.assertEqual(plan.action, Action.DEFERRED)
        self.assertFalse(plan.action_authorized)

    def test_recall_experience_is_separate_from_source_activation(self):
        greeting = RecallPolicy(request(trigger=Trigger.GREETING, gaps=()))
        p1 = greeting.next()
        greeting.accept(result(p1, evidence=(Evidence("same", "family"),)))
        self.assertFalse(greeting.next().recall_experience)

        association = RecallPolicy(request(trigger=Trigger.ASSOCIATION, gaps=()))
        p2 = association.next()
        association.accept(result(p2, evidence=(Evidence("same", "family"),)))
        self.assertTrue(association.next().recall_experience)

    def test_budget_is_reserved_before_dispatch_and_pending_plan_is_idempotent(self):
        policy = RecallPolicy(request(budget=Budget(3, 8, 6, 1)))
        working = policy.next()
        self.assertEqual(policy.remaining.rounds, 2)
        self.assertIs(policy.next(), working)
        policy.accept(result(working))
        light = policy.next()
        self.assertEqual(light.action, Action.LIGHT_SEARCH)
        self.assertEqual(policy.remaining.candidates, 0)
        self.assertEqual(policy.remaining.nodes, 0)

    def test_exact_and_working_stages_reserve_database_read_budget(self):
        policy = RecallPolicy(request(
            required_checks=("corrections",),
            budget=Budget(3, 10, 40, 0),
        ))
        exact = policy.next()
        self.assertEqual(exact.reservation, Budget(1, 8, 32, 0))
        policy.accept(result(exact, candidates=2, nodes=5))

        working = policy.next()
        self.assertEqual(working.reservation, Budget(1, 8, 32, 0))
        policy.accept(result(working, candidates=1, nodes=2))

        self.assertEqual(policy.remaining, Budget(1, 7, 33, 0))

    def test_duplicate_result_is_idempotent_but_conflict_is_rejected(self):
        policy = RecallPolicy(request())
        plan = policy.next()
        first = result(plan)
        policy.accept(first)
        remaining = policy.remaining
        policy.accept(first)
        self.assertEqual(policy.remaining, remaining)
        with self.assertRaisesRegex(ValueError, "conflicting result"):
            policy.accept(result(plan, evidence=(Evidence("new", "f"),)))

    def test_conflicting_evidence_rejects_whole_result_atomically(self):
        policy = RecallPolicy(request(gaps=("a", "b")))
        working = policy.next()
        policy.accept(result(working, evidence=(Evidence("e1", "f1", fills=("a",)),)))
        light = policy.next()
        with self.assertRaisesRegex(ValueError, "conflicting evidence"):
            policy.accept(result(light, evidence=(
                Evidence("e2", "f2", fills=("b",)),
                Evidence("e1", "different", fills=("b",)),
            )))
        self.assertNotIn("e2", policy._evidence)
        self.assertEqual(policy._missing_gaps, ["b"])
        self.assertIs(policy.pending_plan, light)

        with self.assertRaisesRegex(ValueError, "conflicting evidence"):
            policy.accept(result(light, evidence=(
                Evidence("e2", "f2", fills=("b",)),
                Evidence("e1", "f1", fills=("b",), external=False),
            )))
        self.assertNotIn("e2", policy._evidence)
        self.assertEqual(policy._missing_gaps, ["b"])
        self.assertIs(policy.pending_plan, light)

    def test_cross_request_and_wrong_action_results_are_rejected(self):
        policy = RecallPolicy(request())
        plan = policy.next()
        foreign = SearchResult("other", plan.operation_id, plan.action)
        with self.assertRaisesRegex(ValueError, "request_id"):
            policy.accept(foreign)
        wrong = SearchResult("r1", plan.operation_id, Action.DEEP_SEARCH)
        with self.assertRaisesRegex(ValueError, "action"):
            policy.accept(wrong)

    def test_same_source_family_does_not_count_as_new_external_evidence(self):
        policy = RecallPolicy(request(gaps=("a", "b")))
        working = policy.next()
        policy.accept(result(working, evidence=(Evidence("e1", "one", fills=("a",)),)))
        light = policy.next()
        policy.accept(result(light, evidence=(Evidence("e2", "one", fills=("b",)),), candidates=1))
        ready = policy.next()
        self.assertEqual(ready.action, Action.READY)
        self.assertEqual(ready.external_evidence_families, ("one",))

    def test_empty_working_set_does_not_prevent_deep_search(self):
        policy = RecallPolicy(request(gaps=("missing",), budget=Budget(5, 20, 20, 2)))
        working = policy.next()
        policy.accept(result(working))
        light = policy.next()
        policy.accept(result(light))
        deep = policy.next()
        self.assertEqual(deep.action, Action.DEEP_SEARCH)
        policy.accept(result(deep))
        self.assertEqual(policy.next().action, Action.INSUFFICIENT)

    def test_timeout_stops_dispatch_without_spending_round_budget(self):
        clock = FakeClock(10.0)
        policy = RecallPolicy(request(timeout_seconds=2.0), clock=clock)
        clock.now = 12.0
        final = policy.next()
        self.assertEqual(final.action, Action.INSUFFICIENT)
        self.assertEqual(policy.remaining, policy.request.budget)

    def test_late_result_cannot_make_ready_but_used_model_calls_stay_charged(self):
        clock = FakeClock(10.0)
        policy = RecallPolicy(request(gaps=("missing",), timeout_seconds=2.0), clock=clock)
        working = policy.next()
        policy.accept(result(working))
        light = policy.next()
        policy.accept(result(light))
        deep = policy.next()
        self.assertEqual(deep.action, Action.DEEP_SEARCH)

        clock.now = 12.0
        late = result(
            deep,
            evidence=(Evidence("late", "model", fills=("missing",)),),
            model_calls=1,
        )
        policy.accept(late)
        policy.accept(late)

        final = policy.next()
        self.assertEqual(final.action, Action.INSUFFICIENT)
        self.assertEqual(final.missing_gaps, ("missing",))
        self.assertNotIn("late", policy._evidence)
        self.assertEqual(policy.remaining.model_calls, 1)

    def test_deep_search_uses_at_most_two_model_calls_and_total_limits(self):
        policy = RecallPolicy(request(gaps=("a", "b"), budget=Budget(5, 4, 8, 2)))
        working = policy.next()
        policy.accept(result(working, evidence=(Evidence("w", "wf", fills=("a",)),)))
        light = policy.next()
        policy.accept(result(light, candidates=4, nodes=4))
        deep = policy.next()
        self.assertEqual(deep.action, Action.DEEP_SEARCH)
        self.assertEqual(deep.reservation.model_calls, 2)
        self.assertEqual(policy.remaining.model_calls, 0)
        with self.assertRaisesRegex(ValueError, "reserved"):
            policy.accept(result(deep, model_calls=3))

    def test_strict_types_enums_finite_numbers_and_unique_names(self):
        with self.assertRaises((TypeError, ValueError)):
            request(trigger="greeting")
        with self.assertRaises((TypeError, ValueError)):
            request(gaps=("x", "x"))
        with self.assertRaises((TypeError, ValueError)):
            Budget(rounds=True, candidates=1, nodes=1, model_calls=1)
        with self.assertRaises((TypeError, ValueError)):
            Evidence("e", "f", score=math.inf)
        with self.assertRaises((TypeError, ValueError)):
            SearchResult("r1", "op", Action.LIGHT_SEARCH, candidates_used=-1)
        for invalid_timeout in (True, 0, -1, math.nan, math.inf):
            with self.subTest(timeout=invalid_timeout):
                with self.assertRaises((TypeError, ValueError)):
                    request(timeout_seconds=invalid_timeout)


class FakeClock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


if __name__ == "__main__":
    unittest.main()
