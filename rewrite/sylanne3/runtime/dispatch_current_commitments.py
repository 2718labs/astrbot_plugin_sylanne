"""Transaction-verified D08 graph facts for a future commitment conflict check."""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..authority_service.v2_contract import FencePermitV2
from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
from ..domains.d08.execution import ActionIntent, ActionOutcome, Commitment, GoalExecutionProvider
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion
from ..runtime_contracts import NamespaceId, QueryEpoch
from .jobs import get_job


_TYPES = (
    "d08.commitment.v1", "d08.action_intent.v1", "d08.action_outcome.v1",
)


@dataclass(frozen=True)
class CurrentD08ConflictFactsV1:
    """Verified graph inventory; external execution/cancellation coverage stays HOLD."""

    namespace: NamespaceId
    query_epoch: QueryEpoch
    commitments: tuple[Commitment, ...]
    action_intents: tuple[ActionIntent, ...]
    action_outcomes: tuple[ActionOutcome, ...]
    graph_versions: tuple[GraphVersion, ...]
    status: str = "hold"
    missing_sources: tuple[str, ...] = (
        "atomic_execution_effect_read", "current_action_cancellation_read",
    )


@dataclass(frozen=True)
class CurrentD08ActionConflictEvidenceV1:
    """Exact action read with local effect/job observations; never final admission.

    `effect_state=clear` means the verified Authority read found no effect at
    its pinned head. For a claimed P2 this is contradictory, so it cannot pass.
    A job's cancellation observation is not an action cancellation proof until
    a durable action/attempt-to-job binding exists.
    """

    action_id: str
    effect_id: str
    operation_id: str
    graph_query_epoch: QueryEpoch
    effect_state: str  # clear, unresolved, unknown
    job_cancellation_state: str  # clear, cancelled, unknown
    action_cancellation_state: str  # currently always unknown
    job_id: str | None
    job_fence: int | None
    job_cancel_epoch: int | None
    authority_effect: CurrentEffectReadV2
    status: str = "hold"
    missing_sources: tuple[str, ...] = ()


def read_current_d08_conflict_facts(
    db, namespace: NamespaceId, snapshot: GraphSnapshot, query: QueryEpoch,
) -> CurrentD08ConflictFactsV1:
    """Verify every current D08 conflict graph row in the graph write transaction.

    Graph rows alone cannot establish the D08 conflict check's execution and
    cancellation epochs, so this function never produces a passing snapshot.
    """
    if not db.in_transaction:
        raise ValueError("D08 conflict read requires the graph transaction")
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or query != QueryEpoch(namespace, "all", snapshot.epochs[0].revision)):
        raise ValueError("D08 conflict read requires the full namespace query epoch")
    row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if (row[0] if row else 0) != query.revision:
        raise ValueError("D08 conflict graph epoch changed")

    atoms = tuple(atom for atom in snapshot.atoms
                  if atom.valid and atom.key.type_name in _TYPES)
    by_token = {atom.key.token: atom for atom in atoms}
    if len(by_token) != len(atoms):
        raise ValueError("D08 conflict snapshot repeats a graph key")
    rows = db.execute(
        "SELECT token,revision,value,type_name FROM graph_atoms "
        "WHERE bot=? AND persona=? AND type_name IN "
        "('d08.commitment.v1','d08.action_intent.v1','d08.action_outcome.v1') "
        "AND valid=1 ORDER BY token",
        namespace.as_tuple,
    ).fetchall()
    if len(rows) != len(atoms):
        raise ValueError("D08 conflict snapshot omits or invents a current row")

    specs = {spec.name: spec for spec in GoalExecutionProvider().register_types()}
    commitments = []
    intents = []
    outcomes = []
    for token, revision, encoded, type_name in rows:
        atom = by_token.get(token)
        if (atom is None or atom.key != AtomKey.from_token(token)
                or atom.key.type_name != type_name or atom.revision != revision
                or atom.value != json.loads(encoded)):
            raise ValueError("D08 conflict graph row changed")
        owner = atom.key.owner
        spec = specs[type_name]
        if ((owner.bot, owner.persona) != namespace.as_tuple
                or owner.kind not in spec.owner_kinds):
            raise ValueError("D08 conflict graph owner changed")
        decoded = spec.validator(atom.value)
        if type_name == "d08.commitment.v1":
            if (atom.key.name != decoded.commitment_id
                    or atom.revision != decoded.revision
                    or decoded.subject_ref != f"persona:{namespace.persona_id}"):
                raise ValueError("D08 commitment identity or revision changed")
            commitments.append(decoded)
        elif type_name == "d08.action_intent.v1":
            if (atom.key.name != decoded.action_id or atom.revision != decoded.revision
                    or owner.subject != decoded.identity.activity_id):
                raise ValueError("D08 action identity or revision changed")
            intents.append(decoded)
        else:
            if atom.key.name != decoded.outcome_id:
                raise ValueError("D08 outcome identity changed")
            outcomes.append(decoded)
    for values, field in ((commitments, "commitment_id"),
                          (intents, "action_id"), (outcomes, "outcome_id")):
        if len({getattr(value, field) for value in values}) != len(values):
            raise ValueError(f"D08 {field} repeats across graph owners")
    return CurrentD08ConflictFactsV1(
        namespace, QueryEpoch(namespace, "d08.conflict_graph", query.revision),
        tuple(commitments), tuple(intents), tuple(outcomes),
        tuple(GraphVersion(by_token[token].key, revision)
              for token, revision, _, _ in rows),
    )


def read_current_d08_action_conflict_evidence(
    db, namespace: NamespaceId, snapshot: GraphSnapshot, query: QueryEpoch,
    action_id: str, p2: FencePermitV2, effect: CurrentEffectReadV2,
) -> CurrentD08ActionConflictEvidenceV1:
    """Correlate one graph action with a pre-read Authority effect and job rows.

    Call inside the final graph write transaction. The Authority read must have
    happened before this callback; the caller's later Authority P2 CAS must
    still reject any execution-head movement. This read never grants dispatch.
    """
    facts = read_current_d08_conflict_facts(db, namespace, snapshot, query)
    if type(p2) is not FencePermitV2 or type(effect) is not CurrentEffectReadV2:
        raise TypeError("D08 execution evidence requires typed P2 and Authority read")
    matches = tuple(intent for intent in facts.action_intents
                    if intent.action_id == action_id)
    if len(matches) != 1:
        raise ValueError("D08 action is absent from the complete current graph read")
    intent = matches[0]
    identity = intent.identity
    if (p2.operation != "dispatch"
            or p2.namespace != "/".join(namespace.as_tuple)
            or p2.operation_id != identity.operation_id
            or p2.effect_id != identity.effect_id):
        raise ValueError("D08 action and claimed dispatch P2 identity differ")
    if any(other.action_id != action_id and other.identity.effect_id == identity.effect_id
           for other in facts.action_intents):
        raise ValueError("D08 effect is shared by multiple current actions")

    blockers = ["trusted_authority_effect_read_provenance",
                "claimed_append_identity_binding", "action_attempt_to_job_binding",
                "authority_post_graph_p2_cas"]
    anchor = p2.pinned_anchor
    effect_state = "unknown"
    if (effect.authority_id != p2.authority_id
            or effect.namespace != p2.namespace
            or effect.effect_id != identity.effect_id
            or effect.activation_generation != p2.generation
            or effect.execution_head_seq != anchor.execution_seq
            or effect.execution_head_digest != anchor.execution_digest):
        blockers.append("authority_effect_read_not_at_claimed_p2")
    elif effect.state == "absent":
        effect_state = "clear"
        blockers.append("claimed_effect_absent")
    elif (effect.state in {"unresolved", "observed"}
          and effect.effect_seq == anchor.execution_seq
          and effect.append_digest == anchor.execution_digest
          and effect.append_id is not None
          and effect.mutation_id is not None):
        effect_state = "unresolved"
        if effect.state == "observed":
            blockers.append("effect_already_observed")
    else:
        blockers.append("authority_effect_phase_or_append_unproven")

    # The durable job table is in this same graph transaction. Its schema has
    # no action_id/attempt_id key or uniqueness constraint for this triple.
    # Even a sole matching row therefore describes a job, not a proven action.
    rows = db.execute(
        "SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
        "AND (effect_id=? OR operation_id=?) ORDER BY job_id",
        namespace.as_tuple + (identity.effect_id, identity.operation_id),
    ).fetchall()
    matching = []
    for (job_id,) in rows:
        job = get_job(db, job_id)
        if (job.operation_id, job.activity_id, job.effect_id) == (
                identity.operation_id, identity.activity_id, identity.effect_id):
            matching.append(job)
        else:
            blockers.append("job_operation_or_effect_identity_collision")
    job_id = None
    job_fence = None
    job_cancel_epoch = None
    job_cancellation_state = "unknown"
    if len(matching) == 1 and len(rows) == 1:
        job = matching[0]
        job_id, job_fence, job_cancel_epoch = (
            job.job_id, job.fence, job.cancel_epoch)
        if job.phase in {"draining", "cancelled"}:
            job_cancellation_state = "cancelled"
        elif job.cancel_epoch == 0 and job.phase in {
                "queued", "running", "waiting", "deferred"}:
            job_cancellation_state = "clear"
        else:
            job_cancellation_state = "unknown"
        if job_cancellation_state == "cancelled":
            blockers.append("matching_job_cancelled")
    else:
        blockers.append("unique_current_action_job_unproven")
    return CurrentD08ActionConflictEvidenceV1(
        action_id, identity.effect_id, identity.operation_id,
        facts.query_epoch, effect_state, job_cancellation_state, "unknown",
        job_id, job_fence, job_cancel_epoch, effect,
        missing_sources=tuple(dict.fromkeys(blockers)),
    )


__all__ = [
    "CurrentD08ActionConflictEvidenceV1", "CurrentD08ConflictFactsV1",
    "read_current_d08_action_conflict_evidence", "read_current_d08_conflict_facts",
]
