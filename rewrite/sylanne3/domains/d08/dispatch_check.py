"""Narrow D08 current-row check for one passive private reply.

The installed coordinator calls this inside its write transaction. The
returned receipt is only a check candidate until the final graph receipt hook
reissues the identical read closure and Authority validates the write fence.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...authority_service.v2_execution_bridge import CurrentEffectReadV2

from ...authority_service.v2_contract import (
    AuthorityCurrentEffectSnapshotV2,
    canonical_digest as authority_digest,
)
from ...graph_types import AtomKey, GraphAtom, GraphSnapshot, Owner
from ...memory_types import source_key
from ...runtime.restore_anchor import RestoreAnchor
from ...runtime_contracts import (
    CheckReceipt, FenceScope, NamespaceId, QueryEpoch, VersionedRef, canonical_digest,
)
from .execution import (
    ActionCancellationState, ActionIntent, ActionSchema, ActionSchemaRecord,
    CommitmentConflictSnapshot, Goal, GoalExecutionProvider,
)


D08_CRITERIA_REF_V1 = "d08.commitment_conflict.criteria.v1"
D08_CRITERIA_VERSION_V1 = 1


@dataclass(frozen=True, slots=True)
class D08NegativeQueryV2:
    """Full graph query whose qualifying conflict set is empty."""

    predicate_ref: str
    query: QueryEpoch
    scanned_versions: tuple[VersionedRef, ...]
    matching_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if (type(self.predicate_ref) is not str or not self.predicate_ref
                or type(self.query) is not QueryEpoch
                or self.query.scope_ref != "all"
                or type(self.scanned_versions) is not tuple
                or any(type(item) is not VersionedRef
                       for item in self.scanned_versions)
                or type(self.matching_refs) is not tuple
                or any(type(item) is not str or not item
                       for item in self.matching_refs)):
            raise ValueError("D08 negative query closure is incomplete")


@dataclass(frozen=True, slots=True)
class DispatchCheckScopeV2:
    """D08 evidence from current SQL rows, with no independent send authority."""

    action_id: str
    graph_query: QueryEpoch
    authority_head: RestoreAnchor
    authority_snapshot_digest: str
    positive_reads: tuple[VersionedRef, ...]
    negative_queries: tuple[D08NegativeQueryV2, ...]
    receipt: CheckReceipt


def _current_atom(db, snapshot: GraphSnapshot, key: AtomKey) -> GraphAtom:
    from ...runtime.dispatch_current_projection import _bound_dispatch_projection_v3
    from ...runtime.current_graph_full_read_v3 import require_bound_graph_full_atom_v3
    namespace = NamespaceId.from_key(key)
    query = QueryEpoch(namespace,"all",snapshot.epochs[0].revision)
    fixed = _bound_dispatch_projection_v3(db,namespace,query,snapshot=snapshot)
    if fixed is not None:
        current = require_bound_graph_full_atom_v3(db,namespace,query,key)
        atom = snapshot.get(key)
        if (current is None or atom is None or not current.valid or not atom.valid
                or current.key!=key or atom.key!=key or atom.revision!=current.revision or atom.value!=current.value):
            raise ValueError(f"current D08 {key.type_name} row differs from its prepared typed head")
        return atom
    rows = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
        "AND bot=? AND persona=?",
        (key.token, key.owner.bot, key.owner.persona),
    ).fetchall()
    if len(rows) != 1:
        raise ValueError(f"current D08 {key.type_name} row is absent")
    revision, encoded, valid = rows[0]
    atom = snapshot.get(key)
    if (atom is None or not atom.valid or valid != 1
            or atom.revision != revision or atom.value != json.loads(encoded)):
        raise ValueError(f"current D08 {key.type_name} row differs from snapshot")
    return atom


def read_dispatch_check_scope_v2(
    db, snapshot: GraphSnapshot, query: QueryEpoch, scope: FenceScope,
    effect: CurrentEffectReadV2,
    authority_snapshot: AuthorityCurrentEffectSnapshotV2,
    intent: ActionIntent, schema: ActionSchema, *,
    route_binding: object, audience: tuple[str, ...], purpose: str,
    now_utc: float, valid_until_utc: float | None = None,
    expected_action_kind: str = "message",
) -> DispatchCheckScopeV2:
    """Recompute D08's fixed passive-reply check from one current graph head.

    Inputs must be supplied by W01's installed provisional/final readers under
    the same GraphStore write permit. This function never accepts a caller
    confirmation flag or an existing CheckReceipt. The final receipt hook must
    run it again against sealed rows before admission may use the result.
    """
    from ...authority_service.v2_execution_bridge import CurrentEffectReadV2

    from ...runtime.dispatch_current_projection import _bound_dispatch_projection_v3
    if type(scope) is not FenceScope:
        raise ValueError("installed D08 write scope required")
    fixed = _bound_dispatch_projection_v3(db,scope.namespace,query,snapshot=snapshot,source_metadata=True)
    if (not db.in_transaction
            or type(query) is not QueryEpoch or type(scope) is not FenceScope
            or type(effect) is not CurrentEffectReadV2
            or type(authority_snapshot) is not AuthorityCurrentEffectSnapshotV2
            or type(intent) is not ActionIntent or type(schema) is not ActionSchema
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)
            or type(audience) is not tuple or type(purpose) is not str):
        raise ValueError("installed D08 graph and Authority read is required")
    expiry = now_utc + 1.0 if valid_until_utc is None else valid_until_utc
    if (type(expiry) not in (int, float) or not math.isfinite(expiry)
            or expiry <= now_utc):
        raise ValueError("D08 check expiry is not a current finite deadline")
    namespace = scope.namespace
    from ...graph_coordinator import namespace_ref

    if (scope.operation != "write" or scope.permit.operation != "write"
            or scope.permit.pinned_anchor != scope.pinned_anchor
            or scope.authority_namespace != namespace_ref(namespace)
            or scope.operation_id != scope.permit.operation_id
            or scope.permit.effect_id not in (None, intent.identity.effect_id)
            or query != QueryEpoch(namespace, "all", scope.graph_epoch.revision + 1)
            or len(snapshot.epochs) != 1
            or snapshot.epochs[0].revision != query.revision
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona)
               != namespace.as_tuple
            or purpose != intent.purpose or purpose != "expression"
            or type(expected_action_kind) is not str
            or expected_action_kind not in ("message", "communication")
            or intent.action_kind != expected_action_kind or schema.proactive
            or schema.action_kind != expected_action_kind):
        raise ValueError("D08 private reply scope differs from the write permit")
    from .communication_route_binding import validate_communication_route_binding_v2

    validate_communication_route_binding_v2(
        route_binding, intent, audience, db=db, snapshot=snapshot,
        scope=scope, now=now_utc, expected_action_kind=expected_action_kind,
    )
    anchor = scope.pinned_anchor
    if (authority_snapshot.anchor != anchor
            or authority_snapshot.authority_id != anchor.authority_id
            or authority_snapshot.namespace != scope.authority_namespace
            or authority_snapshot.permit_digest != authority_digest(scope.permit)
            or authority_snapshot.coverage != "complete"
            or (authority_snapshot.execution_head_seq,
                authority_snapshot.execution_head_digest) != (
                anchor.execution_seq, anchor.execution_digest)
            or authority_snapshot.unresolved_effects
            or effect.state != "absent"
            or (effect.authority_id, effect.namespace, effect.effect_id,
                effect.activation_generation, effect.execution_head_seq,
                effect.execution_head_digest) != (
                anchor.authority_id, scope.authority_namespace,
                intent.identity.effect_id, anchor.activation_generation,
                anchor.execution_seq, anchor.execution_digest)):
        raise ValueError("D08 Authority effect inventory or head is not clear")
    epoch_row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if epoch_row != (query.revision,):
        raise ValueError("D08 full graph query epoch is stale")

    owner = Owner("activity", *namespace.as_tuple,
                  intent.identity.activity_id)
    goal_key = AtomKey(owner, "d08.goal.v1", intent.goal_ref)
    action_key = AtomKey(owner, "d08.action_intent.v1", intent.action_id)
    cancellation_key = AtomKey(owner, "d08.action_cancellation.v1", intent.action_id)
    d08_types = {item.name: item for item in GoalExecutionProvider().register_types()}
    action_atom = _current_atom(db, snapshot, action_key)
    current_action = d08_types["d08.action_intent.v1"].validator(action_atom.value)
    if action_atom.revision != 1 or current_action != intent:
        raise ValueError("D08 current action differs from frozen intent")
    binding = ActionSchemaRecord.bind(intent, schema)
    schema_key = AtomKey(owner, "d08.action_schema.v1", binding.schema_ref)
    goal_atom = _current_atom(db, snapshot, goal_key)
    schema_atom = _current_atom(db, snapshot, schema_key)
    cancellation_atom = _current_atom(db, snapshot, cancellation_key)
    source = AtomKey.from_token(intent.source_refs[0]) if len(intent.source_refs) == 1 else None
    if (source is None or source != source_key(
            *namespace.as_tuple, source.owner.subject or "")):
        raise ValueError("D08 reply source is not a canonical D06 graph address")
    if fixed is None:
        source_atom = _current_atom(db, snapshot, source)
        source_version = VersionedRef(source_atom.key.token,source_atom.revision)
    else:
        from ...runtime.current_graph_full_read_v3 import require_bound_graph_full_source_metadata_for_barrier_v3
        source_metadata = require_bound_graph_full_source_metadata_for_barrier_v3(db,namespace,source)
        if source_metadata.source_key!=source or not source_metadata.valid or source_metadata.revision<1:
            raise ValueError("D08 actual Source metadata pin is unavailable")
        source_version = VersionedRef(source.token,source_metadata.revision)
    goal = d08_types["d08.goal.v1"].validator(goal_atom.value)
    stored_schema = d08_types["d08.action_schema.v1"].validator(schema_atom.value)
    cancellation = d08_types["d08.action_cancellation.v1"].validator(
        cancellation_atom.value)
    if (type(goal) is not Goal or goal_atom.revision != 1
            or goal.goal_id != intent.goal_ref or goal.revision != 1
            or goal.state != "active"
            or goal.satisfaction_predicate != intent.success_predicate
            or len(intent.source_refs) != 1
            or intent.source_refs[0] not in goal.reason_refs
            or schema_atom.revision != 1 or stored_schema != binding
            or type(cancellation) is not ActionCancellationState
            or cancellation_atom.revision != 1
            or cancellation.action_id != intent.action_id
            or cancellation.action_revision != 1
            or cancellation.action_digest != canonical_digest(intent)
            or cancellation.activity_id != intent.identity.activity_id
            or cancellation.attempt_id != intent.identity.attempt_id
            or cancellation.effect_id != intent.identity.effect_id
            or cancellation.operation_id != intent.identity.operation_id
            or cancellation.state != "active" or cancellation.cancel_epoch != 0
            or intent.commitment_refs):
        raise ValueError("D08 goal, schema or initial cancellation is not current")

    from ...runtime.dispatch_current_commitments import read_current_d08_conflict_facts

    facts = read_current_d08_conflict_facts(db, namespace, snapshot, query)
    if (set(facts.missing_sources) != {
            "atomic_execution_effect_read", "current_action_cancellation_read"}
            or tuple(item for item in facts.action_intents
                     if item.action_id == intent.action_id) != (intent,)):
        raise ValueError("D08 full current conflict inventory is unavailable")
    # Counterparty is the only structured commitment target in v1. A
    # commitment to another conversation cannot veto this private reply; its
    # row still participates in the complete negative-query scan below.
    applicable_commitments = tuple(
        item for item in facts.commitments
        if item.counterparty_ref == intent.target_ref)
    conflicting_commitments = tuple(
        item.commitment_id for item in applicable_commitments
        if item.fulfillment_state not in {"fulfilled", "withdrawn"})
    unfinished_actions = []
    for other in facts.action_intents:
        if other.action_id == intent.action_id:
            continue
        if other.identity.effect_id == intent.identity.effect_id:
            raise ValueError("D08 effect is shared by another action")
        if other.target_ref != intent.target_ref:
            continue
        complete = tuple(outcome for outcome in facts.action_outcomes
                         if (outcome.action_id, outcome.effect_id,
                             outcome.attempt_id) == (
                             other.action_id, other.identity.effect_id,
                             other.identity.attempt_id)
                         and outcome.result_level == "completed_verified"
                         and not outcome.unknown_effects)
        if len(complete) != 1:
            unfinished_actions.append(other.action_id)
    if conflicting_commitments or unfinished_actions:
        raise ValueError("D08 current commitment or action conflict remains")

    checks = tuple(item for item in intent.required_checks
                   if item.check_kind == "commitment_conflict")
    if len(checks) != 1 or checks[0].provider_id != "d08.commitment_conflict":
        raise ValueError("D08 fixed commitment check is absent")
    spec = checks[0]
    expected = {
        D08_CRITERIA_REF_V1: D08_CRITERIA_VERSION_V1,
        intent.goal_ref: goal_atom.revision,
        f"commitments-query:persona:{namespace.persona_id}": query.revision,
        f"execution-epoch:{intent.action_id}": anchor.execution_seq,
        f"cancellation-epoch:{intent.action_id}": cancellation_atom.revision,
    }
    frozen = {item.ref: item.version for item in spec.required_input_versions}
    if (spec.criteria_version != D08_CRITERIA_REF_V1
            or spec.subject_ref != f"persona:{namespace.persona_id}"
            or spec.action_ref != intent.action_id or spec.purpose != purpose
            or len(frozen) != len(spec.required_input_versions)
            or frozen != expected):
        raise ValueError("D08 fixed criteria or current version set differs")
    current = CommitmentConflictSnapshot(
        spec.required_input_versions, "full",
        tuple(item.commitment_id for item in applicable_commitments), (), (),
        action_ref=intent.action_id, action_revision=intent.revision,
        intent_digest=canonical_digest(intent), schema_id=intent.schema_id,
        goal_ref=intent.goal_ref, target_ref=intent.target_ref,
        action_kind=intent.action_kind, purpose=intent.purpose,
        commitment_query_epoch_ref=f"commitments-query:persona:{namespace.persona_id}",
        commitment_query_epoch=query.revision,
        execution_epoch_ref=f"execution-epoch:{intent.action_id}",
        execution_epoch=anchor.execution_seq,
        cancellation_epoch_ref=f"cancellation-epoch:{intent.action_id}",
        cancellation_epoch=cancellation_atom.revision,
        current_read_confirmed=True,
    )
    receipt = GoalExecutionProvider().provide_required_check(
        intent, schema, current, valid_until=float(expiry))
    if receipt.result != "pass" or receipt.coverage != "full":
        raise ValueError("D08 current provider did not pass")
    positive = (source_version,) + tuple(VersionedRef(atom.key.token, atom.revision) for atom in (
        goal_atom, action_atom, schema_atom, cancellation_atom))
    commitments = tuple(VersionedRef(item.key.token, item.revision)
                        for item in facts.graph_versions
                        if item.key.type_name == "d08.commitment.v1")
    action_history = tuple(VersionedRef(item.key.token, item.revision)
                           for item in facts.graph_versions
                           if item.key.type_name in {
                               "d08.action_intent.v1", "d08.action_outcome.v1"})
    return DispatchCheckScopeV2(
        intent.action_id, query, anchor, authority_digest(authority_snapshot),
        positive,
        (D08NegativeQueryV2("d08.same_target_unfinished_commitments.v1", query,
                            commitments, ()),
         D08NegativeQueryV2("d08.same_target_unfinished_actions.v1", query,
                            action_history, ())),
        receipt,
    )


__all__ = (
    "D08_CRITERIA_REF_V1", "D08_CRITERIA_VERSION_V1",
    "D08NegativeQueryV2", "DispatchCheckScopeV2",
    "read_dispatch_check_scope_v2",
)
