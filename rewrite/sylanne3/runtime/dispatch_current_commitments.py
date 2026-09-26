"""Transaction-verified D08 graph facts for a future commitment conflict check."""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..authority_service.v2_contract import FencePermitV2
from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
from ..contracts import canonical_json
from ..domains.d08.execution import ActionIntent, ActionOutcome, Commitment, GoalExecutionProvider
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest
from .d11_types import job_graph_write
from .dispatch_action_job_binding import load_action_job_binding
from .dispatch_admission import load_admission
from .jobs import JobConflict, PersistentJob, get_job
from .dispatch_source_correction_barrier import read_source_correction_barrier


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
    The durable action/attempt-to-job binding and current job row are checked
    together. Independent D08 cancellation authority remains unresolved.
    """

    action_id: str
    effect_id: str
    operation_id: str
    graph_query_epoch: QueryEpoch
    effect_state: str  # clear, unresolved, unknown
    job_cancellation_state: str  # clear, cancelled, unknown
    action_cancellation_state: str  # independent D08 cancellation remains unknown
    job_id: str | None
    job_fence: int | None
    job_cancel_epoch: int | None
    authority_effect: CurrentEffectReadV2
    status: str = "hold"
    missing_sources: tuple[str, ...] = ()
    action_job_binding_digest: str | None = None
    job_graph_version: GraphVersion | None = None


@dataclass(frozen=True)
class CurrentJobCancellationReadV1:
    """One current durable job row, without an action/job ownership assertion."""

    namespace: NamespaceId
    job_id: str
    state: str  # clear, cancelled, unknown
    fence_state: str  # row_match, mismatch, unknown
    cancel_epoch_state: str  # row_match, mismatch, unknown
    phase: str | None
    fence: int | None
    cancel_epoch: int | None
    lease_holder: str | None
    lease_expires_utc: str | None
    latest_cancel_receipt_epoch: int | None
    missing_sources: tuple[str, ...] = ()


def read_current_job_cancellation(
    db, namespace: NamespaceId, job_id: str, *,
    expected_fence: int | None = None,
    expected_cancel_epoch: int | None = None,
) -> CurrentJobCancellationReadV1:
    """Read a job's recorded cancellation and fence in the graph transaction.

    The caller supplies any expected fence/epoch from its authenticated command.
    This function does not bind that command or a D08 action to the job. A
    clear result describes only the job row and never authorizes dispatch.
    `db.in_transaction` cannot attest that the trusted coordinator holds the
    write fence; production must call this under its BEGIN IMMEDIATE path.
    """
    if not db.in_transaction:
        raise ValueError("job cancellation read requires the graph transaction")
    if type(namespace) is not NamespaceId:
        raise TypeError("job cancellation read requires a namespace")
    for name, value in (("expected_fence", expected_fence),
                        ("expected_cancel_epoch", expected_cancel_epoch)):
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError(f"{name} must be a nonnegative exact integer")
    try:
        job = get_job(db, job_id)
    except JobConflict:
        return CurrentJobCancellationReadV1(
            namespace, job_id, "unknown", "unknown", "unknown",
            None, None, None, None, None, None, ("current_job_missing",),
        )
    if (job.bot_id, job.persona_id) != namespace.as_tuple:
        raise ValueError("job cancellation read crosses namespace")
    fence_state = ("unknown" if expected_fence is None else
                   "row_match" if job.fence == expected_fence else "mismatch")
    cancel_epoch_state = ("unknown" if expected_cancel_epoch is None else
                          "row_match" if job.cancel_epoch == expected_cancel_epoch
                          else "mismatch")
    cancel_receipts = []
    history_valid = True
    for (encoded,) in db.execute(
        "SELECT job_json FROM runtime_job_operations WHERE bot_id=? "
        "AND persona_id=? AND job_id=? AND phase='cancel'",
        namespace.as_tuple + (job_id,),
    ):
        try:
            receipt = PersistentJob(**json.loads(encoded))
        except (TypeError, ValueError):
            history_valid = False
            continue
        if (receipt.job_id, receipt.operation_id, receipt.activity_id,
                receipt.effect_id, receipt.bot_id, receipt.persona_id) != (
                job.job_id, job.operation_id, job.activity_id, job.effect_id,
                job.bot_id, job.persona_id):
            history_valid = False
        cancel_receipts.append(receipt)
    latest_cancel_epoch = max(
        (receipt.cancel_epoch for receipt in cancel_receipts), default=None)
    if (job.cancel_epoch > 0 and latest_cancel_epoch != job.cancel_epoch
            or latest_cancel_epoch is not None and latest_cancel_epoch > job.cancel_epoch
            or job.phase in {"queued", "running", "waiting", "deferred"}
            and latest_cancel_epoch is not None):
        history_valid = False
    if job.cancel_epoch > 0 and job.phase in {"draining", "cancelled"} and not any(
            receipt.cancel_epoch == job.cancel_epoch
            and receipt.fence == job.fence
            and receipt.phase in {"draining", "cancelled"}
            for receipt in cancel_receipts):
        history_valid = False
    if job.phase in {"draining", "cancelled"}:
        state = "cancelled"
    elif (job.cancel_epoch == 0 and job.phase in {
            "queued", "running", "waiting", "deferred"}
          and fence_state != "mismatch" and cancel_epoch_state != "mismatch"):
        state = "clear"
    else:
        state = "unknown"
    if not history_valid:
        state = "unknown"
    missing = []
    if fence_state == "mismatch":
        missing.append("job_worker_fence_mismatch")
    if cancel_epoch_state == "mismatch":
        missing.append("job_cancel_epoch_mismatch")
    if not history_valid:
        missing.append("job_cancel_history_mismatch")
    if expected_fence is not None:
        missing.append("current_worker_lease_unverified")
    if state == "unknown":
        missing.append("job_cancellation_state_unproven")
    return CurrentJobCancellationReadV1(
        namespace, job_id, state, fence_state, cancel_epoch_state,
        job.phase, job.fence, job.cancel_epoch, job.lease_holder,
        job.lease_expires_utc, latest_cancel_epoch, tuple(missing),
    )


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
    missing = ["atomic_execution_effect_read", "current_action_cancellation_read"]
    for atom in atoms:
        if atom.key.type_name != "d08.action_intent.v1":
            continue
        refs = atom.value.get("source_refs")
        if type(refs) is not list or not refs:
            missing.append(f"action_source_refs_unavailable:{atom.key.token}")
            continue
        barrier = read_source_correction_barrier(
            db, namespace, query, tuple(refs), dependent_ref=atom.key.token,
        )
        missing.extend(barrier.missing_sources)
    return CurrentD08ConflictFactsV1(
        namespace, QueryEpoch(namespace, "d08.conflict_graph", query.revision),
        tuple(commitments), tuple(intents), tuple(outcomes),
        tuple(GraphVersion(by_token[token].key, revision)
              for token, revision, _, _ in rows),
        missing_sources=tuple(dict.fromkeys(missing)),
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
                "current_action_cancellation_read", "authority_post_graph_p2_cas"]
    blockers.extend(facts.missing_sources)
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

    # The binding table supplies the action/attempt/admission key missing from
    # runtime_jobs. Recheck it and the current job projection in this same
    # transaction; an admission-time binding alone cannot prove current state.
    binding = None
    admission = None
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                  "AND name='graph_dispatch_action_job_bindings_v1'").fetchone():
        bound_row = db.execute(
            "SELECT admission_ref FROM graph_dispatch_action_job_bindings_v1 "
            "WHERE bot=? AND persona=? AND action_id=? AND attempt_id=?",
            namespace.as_tuple + (action_id, identity.attempt_id),
        ).fetchone()
        if bound_row is not None:
            binding = load_action_job_binding(db, namespace, bound_row[0])
            admission = load_admission(db, namespace, bound_row[0])
            if binding is None or admission is None:
                raise ValueError("durable action/job binding disappeared")
            if ((binding.namespace, binding.action_id, binding.attempt_id,
                 binding.activity_id, binding.effect_id, binding.operation_id,
                 binding.action_digest, binding.action_graph_revision) != (
                    "/".join(namespace.as_tuple), action_id,
                    identity.attempt_id, identity.activity_id,
                    identity.effect_id, identity.operation_id,
                    canonical_digest(intent), intent.revision)):
                blockers.append("current_action_job_binding_stale")

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
    binding_digest = None
    job_graph_version = None
    if len(matching) == 1 and len(rows) == 1:
        job = matching[0]
        job_read = read_current_job_cancellation(db, namespace, job.job_id)
        job_id, job_fence, job_cancel_epoch = (
            job_read.job_id, job_read.fence, job_read.cancel_epoch)
        job_cancellation_state = job_read.state
        blockers.extend(job_read.missing_sources)
        if job_cancellation_state == "cancelled":
            blockers.append("matching_job_cancelled")
        if binding is not None and admission is not None:
            projected = job_graph_write(job)
            graph_row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
                "AND bot=? AND persona=? AND type_name='runtime.job'",
                (projected.key.token, *namespace.as_tuple),
            ).fetchone()
            if (binding.job_id != job.job_id
                    or job.work_kind != "dispatch"
                    or job.budget_ref != admission.admission.budget_lease_ref
                    or job.fence < binding.job_fence
                    or job.cancel_epoch < binding.job_cancel_epoch):
                blockers.append("current_bound_job_identity_or_epoch_mismatch")
            elif (graph_row is None or graph_row[2] != 1
                  or type(graph_row[0]) is not int
                  or graph_row[0] < binding.job_graph_revision
                  or graph_row[1] != canonical_json(projected.value)):
                blockers.append("current_bound_job_graph_mismatch")
            elif "current_action_job_binding_stale" not in blockers:
                blockers.remove("action_attempt_to_job_binding")
                binding_digest = binding.digest
                job_graph_version = GraphVersion(projected.key, graph_row[0])
                if job.lease_holder is not None:
                    blockers.append("current_worker_lease_unverified")
    else:
        blockers.append("unique_current_action_job_unproven")
    return CurrentD08ActionConflictEvidenceV1(
        action_id, identity.effect_id, identity.operation_id,
        facts.query_epoch, effect_state, job_cancellation_state, "unknown",
        job_id, job_fence, job_cancel_epoch, effect,
        missing_sources=tuple(dict.fromkeys(blockers)),
        action_job_binding_digest=binding_digest,
        job_graph_version=job_graph_version,
    )


__all__ = [
    "CurrentD08ActionConflictEvidenceV1", "CurrentD08ConflictFactsV1",
    "CurrentJobCancellationReadV1", "read_current_d08_action_conflict_evidence",
    "read_current_d08_conflict_facts", "read_current_job_cancellation",
]
