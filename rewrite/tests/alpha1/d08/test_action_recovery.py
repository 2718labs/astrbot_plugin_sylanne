from dataclasses import asdict, replace
import json

from sylanne3.domains.d08.action_recovery import project_current_action_recovery_v1
from sylanne3.domains.d08.execution import ActionOutcome
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch, canonical_serialize

from .test_goal_execution_domain import _intent


NS = NamespaceId("bot", "persona")


def snapshot(level="unknown", *, unknown=(), completed=()):
    intent = _intent()
    action_key = AtomKey(Owner("activity", *NS.as_tuple,
                               intent.identity.activity_id),
                         "d08.action_intent.v1", intent.action_id)
    outcome = ActionOutcome(
        "outcome:one", intent.action_id, intent.identity.effect_id,
        intent.identity.attempt_id, level, "host_observed", (),
        tuple(completed), tuple(unknown), "settlement:one", 2.0)
    outcome_key = AtomKey(Owner("activity", *NS.as_tuple,
                                intent.identity.activity_id),
                          "d08.action_outcome.v1", outcome.outcome_id)
    rows = (
        GraphAtom(action_key, intent.revision,
                  json.loads(canonical_serialize(asdict(intent)))),
        GraphAtom(outcome_key, 1, json.loads(canonical_serialize(asdict(outcome)))),
    )
    # Reconstruct from persisted JSON; no in-memory outcome identity is reused.
    restored = tuple(GraphAtom(row.key, row.revision,
                               json.loads(json.dumps(row.value))) for row in rows)
    return intent, GraphSnapshot(restored, (NamespaceEpoch(*NS.as_tuple, 7),))


def project(intent, graph):
    return project_current_action_recovery_v1(
        graph, QueryEpoch(NS, "all", 7), intent, namespace=NS)


def test_unknown_after_restart_requires_reconciliation_and_keeps_effect_identity():
    intent, graph = snapshot("unknown", unknown=("effect:share-1",))
    result = project(intent, graph)
    assert result.status == "reconciliation_required"
    assert result.effect_id == intent.identity.effect_id
    assert {v.key.type_name for v in result.read_versions} == {
        "d08.action_intent.v1", "d08.action_outcome.v1"}
    assert result.query_epoch == QueryEpoch(NS, "all", 7)
    later = replace(intent, identity=replace(intent.identity,
                                            attempt_id="attempt:later"))
    assert project(later, graph).status == "hold"


def test_only_not_dispatched_is_recheck_candidate_and_partial_effect_holds():
    intent, not_dispatched = snapshot("not_dispatched")
    assert project(intent, not_dispatched).status == "known_nonexecution_candidate"
    intent, failed = snapshot("failed_verified")
    assert project(intent, failed).status == "hold"
    intent, partial = snapshot("failed_verified", completed=("effect:partial",))
    assert project(intent, partial).reason == "effect_may_have_occurred"


def test_missing_outcome_or_stale_query_cannot_trigger_retry():
    intent, graph = snapshot("unknown")
    assert project(intent, replace(graph, atoms=graph.atoms[:1])).reason == (
        "original_effect_outcome_unavailable")
    stale = project_current_action_recovery_v1(
        graph, QueryEpoch(NS, "all", 6), intent, namespace=NS)
    assert stale.status == "hold"
