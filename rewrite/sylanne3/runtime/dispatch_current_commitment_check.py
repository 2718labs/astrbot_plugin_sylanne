"""Conservative installed D08 commitment-conflict criteria for final dispatch.

This is a graph/Authority evidence read, never a CheckReceipt or send permit.
The caller must obtain the Authority snapshot from the registered reverse mTLS
callback and run this reader under one complete GraphStore write transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math

from ..authority_service.v2_contract import (
    AuthorityDispatchSnapshotV1, DispatchHandoffContextV1, MutationReceiptV2,
    OwnerDispatchWitnessV1, ExecutionBindingV2,
)
from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
from ..authority_service.reverse_handoff import require_exact_reverse_handoff_identity
from ..domains.d08.execution import (
    ActionIntent, ActionSchemaRecord, Goal, GoalExecutionProvider,
)
from ..graph_types import AtomKey, GraphSnapshot
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest
from .dispatch_admission import load_admission
from .dispatch_current_commitments import (
    CurrentD08ConflictFactsV1, read_current_d08_conflict_facts,
    read_current_d08_observed_versions,
)


CRITERIA_REF = "d08.commitment_conflict.criteria.v1"
CRITERIA_VERSION = 1


@dataclass(frozen=True, slots=True)
class CurrentD08CriteriaEvidenceV1:
    """A narrow semantic-clear observation with no RequiredCheck authority."""

    action_id: str
    query_epoch: QueryEpoch
    criteria_ref: str
    criteria_version: int
    initial_execution_seq: int
    claimed_execution_seq: int
    authority_snapshot_digest: str
    schema_ref: str
    schema_graph_revision: int
    goal_revision: int
    commitment_revisions: tuple[tuple[str, int], ...]


def evaluate_commitment_conflict_criteria_v1(
    intent: ActionIntent, goal: Goal, facts: CurrentD08ConflictFactsV1,
    authority_snapshot: AuthorityDispatchSnapshotV1,
) -> tuple[str, ...]:
    """Return blockers from the full inventories; no free-text compatibility.

    An own pinned commitment is allowed only when its current structured
    state is clear enough to identify it. Every other unfinished commitment,
    every other same-target unfinished action, and every other unresolved
    Authority effect blocks this deliberately narrow policy.
    """
    if (type(intent) is not ActionIntent or type(goal) is not Goal
            or type(facts) is not CurrentD08ConflictFactsV1
            or type(authority_snapshot) is not AuthorityDispatchSnapshotV1):
        raise TypeError("typed D08 criteria inputs are required")
    missing = []
    if goal.goal_id != intent.goal_ref or goal.state != "active":
        missing.append("current_goal_not_active")
    if any(item not in {"atomic_execution_effect_read",
                        "current_action_cancellation_read"}
           for item in facts.missing_sources):
        missing.append("current_d08_graph_source_unqualified")
    own = {item.commitment_id: item for item in facts.commitments
           if item.commitment_id in intent.commitment_refs}
    if len(own) != len(intent.commitment_refs):
        missing.append("own_pinned_commitment_missing")
    for item in own.values():
        if (item.subject_ref != f"persona:{facts.namespace.persona_id}"
                or item.establishment_state not in {"communicated", "acknowledged"}
                or item.fulfillment_state not in {"pending", "partially_fulfilled"}):
            missing.append("own_commitment_state_unqualified")
    for item in facts.commitments:
        if (item.commitment_id not in own
                and item.fulfillment_state not in {"fulfilled", "withdrawn"}):
            missing.append("other_unfinished_commitment")
    for other in facts.action_intents:
        if other.action_id == intent.action_id or other.target_ref != intent.target_ref:
            continue
        complete = tuple(outcome for outcome in facts.action_outcomes
                         if (outcome.action_id, outcome.effect_id,
                             outcome.attempt_id) == (
                                 other.action_id, other.identity.effect_id,
                                 other.identity.attempt_id)
                         and outcome.result_level == "completed_verified"
                         and not outcome.unknown_effects)
        if len(complete) != 1:
            missing.append("other_same_target_action_unfinished")
    if any(item.effect_id != intent.identity.effect_id
           for item in authority_snapshot.unresolved_effects):
        missing.append("other_authority_effect_unresolved")
    return tuple(dict.fromkeys(missing))


def _require_prepared_claimed_delta(
    claimed: MutationReceiptV2, context: DispatchHandoffContextV1,
    authority_snapshot: AuthorityDispatchSnapshotV1,
) -> int:
    """Prove that the only allowed execution-head drift is own P1 then P2."""
    if (type(claimed) is not MutationReceiptV2
            or type(context) is not DispatchHandoffContextV1
            or type(authority_snapshot) is not AuthorityDispatchSnapshotV1):
        raise ValueError("typed prepared/claimed chain is required")
    pending = claimed.pending
    prepared = pending.prepared_receipt
    if (claimed.durable_state != "committed" or pending.phase != "claimed"
            or prepared is None or prepared.durable_state != "committed"
            or prepared.pending.phase != "prepared"
            or pending.before_anchor != prepared.after_anchor
            or claimed.after_anchor != context.permit.pinned_anchor
            or claimed.after_anchor != authority_snapshot.anchor
            or prepared.after_anchor.execution_seq
            != prepared.pending.before_anchor.execution_seq + 1
            or claimed.after_anchor.execution_seq
            != prepared.after_anchor.execution_seq + 1
            or prepared.after_anchor.execution_digest
            != prepared.pending.expected_append_digest
            or claimed.after_anchor.execution_digest
            != pending.expected_append_digest):
        raise ValueError("P2 execution head has an unproven intermediate change")
    return prepared.pending.before_anchor.execution_seq


def _current_atom(db, namespace: NamespaceId, snapshot: GraphSnapshot,
                  type_name: str, name: str, *, prepared_inventory=None):
    rows = (db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name=? AND name=?",
        namespace.as_tuple + (type_name, name),
    ).fetchall()
        if prepared_inventory is None else prepared_inventory.atom_rows(db,namespace,prepared_inventory.query,(type_name,),('token','revision','value','valid'),valid_only=False,name=name))
    if len(rows) != 1:
        raise ValueError(f"current {type_name} is absent or ambiguous")
    token, revision, encoded, valid = rows[0]
    key = AtomKey.from_token(token)
    atom = snapshot.get(key)
    if (valid != 1 or atom is None or not atom.valid
            or atom.revision != revision or atom.value != (json.loads(encoded) if prepared_inventory is None else encoded)):
        raise ValueError(f"current {type_name} graph atom changed")
    spec = next(item for item in GoalExecutionProvider().register_types()
                if item.name == type_name)
    return atom, spec.validator(atom.value)


def read_current_commitment_criteria_v1(
    db, namespace: NamespaceId, snapshot: GraphSnapshot, query: QueryEpoch,
    intent: ActionIntent, schema: ActionSchemaRecord,
    claimed: MutationReceiptV2, context: DispatchHandoffContextV1,
    witness: OwnerDispatchWitnessV1,
    authority_snapshot: AuthorityDispatchSnapshotV1,
    effect: CurrentEffectReadV2, *, now_utc: float,
    prepared_inventory=None,
) -> CurrentD08CriteriaEvidenceV1:
    """Bind the fixed v1 rule to durable admission and one current graph epoch."""
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or (type(snapshot) is not GraphSnapshot if prepared_inventory is None else snapshot is not prepared_inventory.projection) or type(query) is not QueryEpoch
            or type(intent) is not ActionIntent or type(schema) is not ActionSchemaRecord
            or type(claimed) is not MutationReceiptV2
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise ValueError("current D08 criteria needs typed graph transaction inputs")
    if (len(snapshot.epochs) != 1
            or query != QueryEpoch(namespace, "all", snapshot.epochs[0].revision)):
        raise ValueError("D08 criteria needs a full current graph query")
    if prepared_inventory is None:
        rows = db.execute(
            "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchall()
        by_token = {atom.key.token: atom for atom in snapshot.atoms}
        if (len(rows) != len(by_token) or len(by_token) != len(snapshot.atoms)
                or any(token not in by_token or by_token[token].revision != revision
                       or by_token[token].value != json.loads(encoded)
                       or by_token[token].valid != bool(valid)
                       for token, revision, encoded, valid in rows)):
            raise ValueError("D08 criteria graph snapshot is incomplete")
    else:
        prepared_inventory.require_for(context,claimed.pending.binding,claimed,db,authority_snapshot=authority_snapshot)
        prepared_inventory.require_current(db,namespace,query,snapshot)
    initial_seq = _require_prepared_claimed_delta(
        claimed, context, authority_snapshot)
    binding = claimed.pending.binding
    if (type(binding) is not ExecutionBindingV2
            or binding.origin.proactive_contact
            or schema.proactive
            or binding.origin.admission_ref == ""):
        raise ValueError("D08 criteria requires responsive P0 identity")
    require_exact_reverse_handoff_identity(
        context.permit.namespace, context, binding, claimed)
    admission_receipt = load_admission(db, namespace, binding.origin.admission_ref)
    if admission_receipt is None:
        raise ValueError("D08 criteria admission is absent")
    admission = admission_receipt.admission
    if ((admission.activity_id, admission.effect_id, admission.operation_id,
         admission.graph_incarnation,
         admission.action_ref, admission.action_intent_digest,
         admission.action_schema_digest, admission.required_checks_digest)
        != (intent.identity.activity_id, intent.identity.effect_id,
            intent.identity.operation_id, binding.graph_incarnation,
            intent.action_id,
            canonical_digest(intent), canonical_digest(schema),
            canonical_digest(schema.required_checks))
            or schema.required_checks != intent.required_checks
            or schema.action_ref != intent.action_id
            or schema.action_revision != intent.revision
            or schema.operation != intent.identity
            or schema.intent_digest != canonical_digest(intent)):
        raise ValueError("D08 current schema differs from admitted action")
    schema_atom, current_schema = _current_atom(
        db, namespace, snapshot, "d08.action_schema.v1", schema.schema_ref, prepared_inventory=prepared_inventory)
    if (current_schema != schema
            or schema_atom.key.owner.kind != "activity"
            or schema_atom.key.owner.subject != intent.identity.activity_id):
        raise ValueError("D08 current schema graph atom differs")
    facts = read_current_d08_conflict_facts(db, namespace, snapshot, query, prepared_inventory=prepared_inventory)
    if tuple(item for item in facts.action_intents
             if item.action_id == intent.action_id) != (intent,):
        raise ValueError("D08 current action differs from admission")
    observed = read_current_d08_observed_versions(
        db, namespace, snapshot, query, intent.action_id, context, witness,
        authority_snapshot, effect, prepared_inventory=prepared_inventory)
    _, goal = _current_atom(db, namespace, snapshot, "d08.goal.v1", intent.goal_ref, prepared_inventory=prepared_inventory)
    specs = tuple(item for item in intent.required_checks
                  if item.check_kind == "commitment_conflict")
    receipts = tuple(item for item in admission.check_receipts
                     if item.check_kind == "commitment_conflict")
    if len(specs) != 1 or len(receipts) != 1:
        raise ValueError("D08 frozen commitment check is absent")
    spec, receipt = specs[0], receipts[0]
    if (spec.provider_id != "d08.commitment_conflict"
            or spec.criteria_version != CRITERIA_REF
            or spec.subject_ref != f"persona:{namespace.persona_id}"
            or spec.action_ref != intent.action_id or spec.purpose != intent.purpose):
        raise ValueError("D08 fixed criteria or action scope differs")
    observed_versions = {
        CRITERIA_REF: CRITERIA_VERSION,
        observed.goal_version.ref: observed.goal_version.version,
        **{item.ref: item.version for item in observed.commitment_versions},
        f"commitments-query:persona:{namespace.persona_id}": query.revision,
        f"execution-epoch:{intent.action_id}": initial_seq,
        f"cancellation-epoch:{intent.action_id}":
            observed.cancellation_graph_version.revision,
    }
    frozen_versions = {item.ref: item.version for item in spec.required_input_versions}
    if (len(observed_versions) != len(spec.required_input_versions)
            or observed_versions != frozen_versions
            or (receipt.check_kind, receipt.issuer, receipt.subject_ref,
                receipt.action_ref, receipt.purpose) != (
                    spec.check_kind, spec.provider_id, spec.subject_ref,
                    spec.action_ref, spec.purpose)
            or receipt.input_versions != spec.required_input_versions
            or receipt.result != "pass" or receipt.coverage != "full"
            or receipt.valid_until < now_utc):
        raise ValueError("D08 frozen check versions or receipt changed")
    blockers = evaluate_commitment_conflict_criteria_v1(
        intent, goal, facts, authority_snapshot)
    if blockers:
        raise ValueError("D08 semantic conflict remains: " + ",".join(blockers))
    return CurrentD08CriteriaEvidenceV1(
        intent.action_id, query, CRITERIA_REF, CRITERIA_VERSION,
        initial_seq, authority_snapshot.anchor.execution_seq,
        observed.authority_snapshot_digest, schema.schema_ref,
        schema_atom.revision, observed.goal_version.version,
        tuple((item.ref, item.version)
              for item in observed.commitment_versions),
    )


__all__ = [
    "CRITERIA_REF", "CRITERIA_VERSION", "CurrentD08CriteriaEvidenceV1",
    "evaluate_commitment_conflict_criteria_v1", "read_current_commitment_criteria_v1",
]
