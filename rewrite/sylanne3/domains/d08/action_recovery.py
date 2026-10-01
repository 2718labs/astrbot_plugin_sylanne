"""Current graph action-effect recovery classification; never a retry permit."""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, Owner
from ...runtime_contracts import NamespaceId, QueryEpoch
from .execution import ActionIntent, ActionOutcome, _decode


@dataclass(frozen=True, slots=True)
class CurrentActionRecoveryCandidateV1:
    status: str
    reason: str
    effect_id: str
    action_id: str
    graph_epoch: int | None
    read_versions: tuple[GraphVersion, ...]
    query_epoch: QueryEpoch | None
    negative_predicates: tuple[str, ...]


def project_current_action_recovery_v1(
    snapshot: GraphSnapshot, query: QueryEpoch, intent: ActionIntent, *,
    namespace: NamespaceId,
) -> CurrentActionRecoveryCandidateV1:
    """Classify durable outcomes for the stable effect across attempts.

    Even `known_nonexecution_candidate` needs W01's original dispatch ledger,
    current checks, and a new admission. Missing or unknown outcomes hold.
    """
    if (type(snapshot) is not GraphSnapshot or type(query) is not QueryEpoch
            or type(intent) is not ActionIntent or type(namespace) is not NamespaceId):
        raise TypeError("typed current action graph read required")
    epoch = snapshot.epochs[0] if len(snapshot.epochs) == 1 else None
    graph_epoch = epoch.revision if epoch is not None else None
    predicate = ("d08.action_outcome.v1:effect_id:all_attempts",)
    effect_id = intent.identity.effect_id
    assert effect_id is not None
    def result(status: str, reason: str, reads=()):
        return CurrentActionRecoveryCandidateV1(
            status, reason, effect_id, intent.action_id, graph_epoch,
            tuple(sorted(set(reads), key=lambda v: v.key.token)),
            query if graph_epoch == query.revision else None, predicate)
    if (epoch is None or (epoch.bot, epoch.persona) != namespace.as_tuple
            or query != QueryEpoch(namespace, "all", epoch.revision)
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)):
        return result("hold", "current_full_graph_query_unavailable")
    key = AtomKey(Owner("activity", *namespace.as_tuple,
                        intent.identity.activity_id),
                  "d08.action_intent.v1", intent.action_id)
    atom = snapshot.get(key)
    if atom is None or not atom.valid or atom.revision < 1:
        return result("hold", "current_action_unavailable")
    reads = [GraphVersion(atom.key, atom.revision)]
    try:
        current = _decode("d08.action_intent.v1", atom.value)
        if current != intent or atom.revision != intent.revision:
            return result("hold", "current_action_changed", reads)
        outcomes: list[ActionOutcome] = []
        for row in snapshot.atoms:
            if (row.key.type_name != "d08.action_outcome.v1"
                    or row.value.get("effect_id") != effect_id):
                continue
            if (not row.valid or row.revision < 1
                    or row.key.owner.kind != "activity"
                    or (row.key.owner.bot, row.key.owner.persona)
                       != namespace.as_tuple
                    or row.key.owner.subject != intent.identity.activity_id):
                return result("hold", "effect_outcome_identity_changed", reads)
            outcome = _decode("d08.action_outcome.v1", row.value)
            if outcome.action_id != intent.action_id or row.key.name != outcome.outcome_id:
                return result("hold", "effect_outcome_identity_changed", reads)
            outcomes.append(outcome)
            reads.append(GraphVersion(row.key, row.revision))
        if not outcomes:
            return result("hold", "original_effect_outcome_unavailable", reads)
        if any(outcome.result_level == "unknown" or outcome.unknown_effects
               for outcome in outcomes):
            return result("reconciliation_required", "effect_unknown", reads)
        if any(outcome.result_level in {
                "accepted", "running", "partially_observed", "completed_verified"}
               or outcome.completed_effects for outcome in outcomes):
            return result("hold", "effect_may_have_occurred", reads)
        if all(outcome.result_level == "not_dispatched"
               for outcome in outcomes):
            return result("known_nonexecution_candidate",
                          "recheck_original_dispatch_and_current_qualification", reads)
        return result("hold", "effect_result_unresolved", reads)
    except (KeyError, TypeError, ValueError):
        return result("hold", "current_action_graph_unavailable", reads)


__all__ = ["CurrentActionRecoveryCandidateV1", "project_current_action_recovery_v1"]
