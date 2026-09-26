"""Transaction-verified D08 graph facts for a future commitment conflict check."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math

from ..authority_service.v2_contract import (
    AuthorityDispatchSnapshotV1, DispatchHandoffContextV1, FencePermitV2,
    OwnerDispatchWitnessV1,
)
from ..authority_service.reverse_handoff import require_exact_authority_snapshot
from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
from ..contracts import canonical_json
from ..domains.d08.execution import (
    ActionCancellationState, ActionIntent, ActionOutcome, Commitment,
    GoalExecutionProvider, RequiredCheckSpec,
)
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion, Owner
from ..runtime_contracts import (
    CheckReceipt, NamespaceId, QueryEpoch, VersionedRef, canonical_digest,
)
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
    together. D08 cancellation is independently read from its graph history.
    """

    action_id: str
    effect_id: str
    operation_id: str
    graph_query_epoch: QueryEpoch
    effect_state: str  # clear, unresolved, unknown
    job_cancellation_state: str  # clear, cancelled, unknown
    action_cancellation_state: str  # clear, cancelled, unknown
    job_id: str | None
    job_fence: int | None
    job_cancel_epoch: int | None
    authority_effect: CurrentEffectReadV2
    status: str = "hold"
    missing_sources: tuple[str, ...] = ()
    action_job_binding_digest: str | None = None
    job_graph_version: GraphVersion | None = None
    action_cancellation_graph_version: GraphVersion | None = None


@dataclass(frozen=True, slots=True)
class CurrentD08ObservedVersionsV1:
    """Direct observations only; no synthetic RequiredCheck epoch is asserted."""

    query_epoch: QueryEpoch
    goal_version: VersionedRef
    commitment_versions: tuple[VersionedRef, ...]
    execution_head_seq: int
    execution_head_digest: str
    cancellation_graph_version: GraphVersion
    job_graph_version: GraphVersion
    action_job_binding_digest: str
    other_unresolved_effect_ids: tuple[str, ...]
    authority_snapshot_digest: str


def _map_current_d08_check_versions(
    db, namespace: NamespaceId, snapshot: GraphSnapshot, query: QueryEpoch,
    intent: ActionIntent, spec: RequiredCheckSpec, receipt: CheckReceipt,
    observed: CurrentD08ObservedVersionsV1, *, now_utc: float,
) -> tuple[VersionedRef, ...]:
    """Map only current graph/Authority observations to frozen D08 refs.

    This validates versions, not semantic commitment applicability or a
    current RequiredCheck PASS. The public reader below must create observed
    evidence inside the same graph transaction; caller-created observations
    are not authority. A current atom at criteria_version establishes only
    its revision, not that D08 designated it as a criterion.
    """
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(snapshot) is not GraphSnapshot or type(query) is not QueryEpoch
            or type(intent) is not ActionIntent or type(spec) is not RequiredCheckSpec
            or type(receipt) is not CheckReceipt
            or type(observed) is not CurrentD08ObservedVersionsV1
            or type(now_utc) not in (int, float)
            or not math.isfinite(now_utc)):
        raise ValueError("D08 check version mapping needs current typed inputs")
    if (len(snapshot.epochs) != 1
            or query != QueryEpoch(namespace, "all", snapshot.epochs[0].revision)
            or observed.query_epoch != query
            or spec.check_kind != "commitment_conflict"
            or spec.provider_id != "d08.commitment_conflict"
            or (spec,) != tuple(item for item in intent.required_checks
                                if item.check_kind == "commitment_conflict")
            or spec.subject_ref != f"persona:{namespace.persona_id}"
            or spec.action_ref != intent.action_id
            or spec.purpose != intent.purpose):
        raise ValueError("D08 frozen check scope or full query differs")
    epoch_row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if (epoch_row[0] if epoch_row else 0) != query.revision:
        raise ValueError("D08 graph epoch changed")
    try:
        criteria_key = AtomKey.from_token(spec.criteria_version)
    except (TypeError, ValueError) as exc:
        raise ValueError("D08 criteria lacks a current graph address") from exc
    if (criteria_key.owner.bot, criteria_key.owner.persona) != namespace.as_tuple:
        raise ValueError("D08 criteria crosses namespace")
    criteria = snapshot.get(criteria_key)
    criteria_row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
        "AND bot=? AND persona=?",
        (criteria_key.token, *namespace.as_tuple),
    ).fetchone()
    if (criteria is None or not criteria.valid or criteria_row is None
            or criteria_row[2] != 1 or criteria.revision != criteria_row[0]
            or criteria.value != json.loads(criteria_row[1])):
        raise ValueError("D08 criteria is not a current graph atom")
    if (observed.goal_version.ref != intent.goal_ref
            or tuple(item.ref for item in observed.commitment_versions)
            != intent.commitment_refs
            or observed.cancellation_graph_version.key.type_name
            != "d08.action_cancellation.v1"
            or observed.cancellation_graph_version.key.name != intent.action_id
            or (observed.cancellation_graph_version.key.owner.bot,
                observed.cancellation_graph_version.key.owner.persona)
            != namespace.as_tuple):
        raise ValueError("D08 observed goal, commitments or cancellation differ")
    versions = {
        spec.criteria_version: criteria.revision,
        observed.goal_version.ref: observed.goal_version.version,
        **{item.ref: item.version for item in observed.commitment_versions},
        f"commitments-query:persona:{namespace.persona_id}": query.revision,
        f"execution-epoch:{intent.action_id}": observed.execution_head_seq,
        f"cancellation-epoch:{intent.action_id}":
            observed.cancellation_graph_version.revision,
    }
    frozen = {item.ref: item.version for item in spec.required_input_versions}
    if (len(versions) != len(spec.required_input_versions)
            or len(frozen) != len(spec.required_input_versions)
            or set(versions) != set(frozen)):
        raise ValueError("D08 check refs lack a strict current mapping")
    if versions != frozen:
        # P0 -> prepared -> claimed advances Authority execution_seq twice.
        # A receipt frozen at the pre-P2 seq cannot survive this comparison.
        raise ValueError("D08 frozen execution or graph version stale after P2")
    if ((receipt.check_kind, receipt.issuer, receipt.subject_ref,
         receipt.action_ref, receipt.purpose, receipt.input_versions)
        != (spec.check_kind, spec.provider_id, spec.subject_ref,
            spec.action_ref, spec.purpose, spec.required_input_versions)
            or receipt.result != "pass" or receipt.coverage != "full"
            or receipt.valid_until < now_utc):
        raise ValueError("D08 prior receipt is incomplete or expired")
    return tuple(VersionedRef(item.ref, versions[item.ref])
                 for item in spec.required_input_versions)


def read_current_d08_check_versions(
    db, namespace: NamespaceId, snapshot: GraphSnapshot, query: QueryEpoch,
    intent: ActionIntent, spec: RequiredCheckSpec, receipt: CheckReceipt,
    action_id: str, context: DispatchHandoffContextV1,
    witness: OwnerDispatchWitnessV1,
    authority_snapshot: AuthorityDispatchSnapshotV1,
    effect: CurrentEffectReadV2, *, now_utc: float,
) -> tuple[VersionedRef, ...]:
    """Read D08 pins, then HOLD until criteria and conflict policy are issued.

    The installed D08 contract has no independent criterion issuer and no
    policy mapping all current commitments/actions to applicable conflicts.
    Matching version numbers, including the post-P2 execution sequence, do
    not close either authority gap.
    """
    observed = read_current_d08_observed_versions(
        db, namespace, snapshot, query, action_id, context, witness,
        authority_snapshot, effect)
    _map_current_d08_check_versions(
        db, namespace, snapshot, query, intent, spec, receipt, observed,
        now_utc=now_utc)
    raise ValueError("D08 criteria issuer and semantic conflict policy unavailable")


def read_current_d08_observed_versions(
    db, namespace: NamespaceId, snapshot: GraphSnapshot, query: QueryEpoch,
    action_id: str, context: DispatchHandoffContextV1,
    witness: OwnerDispatchWitnessV1,
    authority_snapshot: AuthorityDispatchSnapshotV1,
    effect: CurrentEffectReadV2,
) -> CurrentD08ObservedVersionsV1:
    """Correlate graph goal/action/job heads with the complete P2 effect set.

    The installed reverse callback must supply ``authority_snapshot`` and the
    installed V2 port must supply ``effect``. Equality checks here cannot
    authenticate arbitrary caller-created DTOs. This result deliberately has
    no ``current_read_confirmed`` or CheckReceipt field: the mapping of D08's
    synthetic cancellation/query epoch refs still needs a shared contract.
    """
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(snapshot) is not GraphSnapshot or type(query) is not QueryEpoch
            or type(context) is not DispatchHandoffContextV1
            or type(witness) is not OwnerDispatchWitnessV1
            or type(authority_snapshot) is not AuthorityDispatchSnapshotV1
            or type(effect) is not CurrentEffectReadV2):
        raise ValueError("current D08 observation requires typed graph transaction inputs")
    require_exact_authority_snapshot(context, witness, authority_snapshot)
    from ..graph_coordinator import namespace_ref

    if (len(snapshot.epochs) != 1
            or context.permit.namespace != namespace_ref(namespace)
            or query != QueryEpoch(namespace, "all", snapshot.epochs[0].revision)):
        raise ValueError("D08 observation P2 or graph query differs")
    own = tuple(item for item in authority_snapshot.unresolved_effects
                if item.effect_id == context.permit.effect_id)
    if (len(own) != 1 or own[0].phase != "claimed"
            or own[0].operation_id != context.permit.operation_id
            or own[0].mutation_id != effect.mutation_id
            or own[0].execution_seq != effect.effect_seq
            or own[0].append_digest != effect.append_digest
            or effect.state != "unresolved"
            or (effect.execution_head_seq, effect.execution_head_digest)
            != (authority_snapshot.anchor.execution_seq,
                authority_snapshot.anchor.execution_digest)):
        raise ValueError("D08 observation does not match claimed P2 effect")
    facts = read_current_d08_conflict_facts(db, namespace, snapshot, query)
    action = read_current_d08_action_conflict_evidence(
        db, namespace, snapshot, query, action_id, context.permit, effect)
    if (action.effect_state != "unresolved"
            or action.action_cancellation_state != "clear"
            or action.job_cancellation_state != "clear"
            or action.action_cancellation_graph_version is None
            or action.job_graph_version is None
            or action.action_job_binding_digest is None):
        raise ValueError("D08 action cancellation or bound job is unproven")
    intents = tuple(item for item in facts.action_intents
                    if item.action_id == action_id)
    if len(intents) != 1:
        raise ValueError("D08 current action is not unique")
    intent = intents[0]
    goal_rows = db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name='d08.goal.v1' AND name=?",
        namespace.as_tuple + (intent.goal_ref,),
    ).fetchall()
    if len(goal_rows) != 1:
        raise ValueError("D08 current goal is absent or ambiguous")
    token, revision, encoded, valid = goal_rows[0]
    goal_key = AtomKey.from_token(token)
    goal_atom = snapshot.get(goal_key)
    goal_spec = next(spec for spec in GoalExecutionProvider().register_types()
                     if spec.name == "d08.goal.v1")
    goal = goal_spec.validator(json.loads(encoded))
    if (valid != 1 or goal_atom is None or not goal_atom.valid
            or goal_atom.revision != revision or goal_atom.value != json.loads(encoded)
            or goal.goal_id != intent.goal_ref or goal.revision != revision):
        raise ValueError("D08 current goal changed")
    by_id = {item.commitment_id: item for item in facts.commitments}
    commitment_versions = []
    for ref in intent.commitment_refs:
        item = by_id.get(ref)
        if item is None:
            raise ValueError("D08 pinned commitment is absent")
        commitment_versions.append(VersionedRef(ref, item.revision))
    return CurrentD08ObservedVersionsV1(
        query, VersionedRef(intent.goal_ref, revision),
        tuple(commitment_versions), authority_snapshot.anchor.execution_seq,
        authority_snapshot.anchor.execution_digest,
        action.action_cancellation_graph_version,
        action.job_graph_version, action.action_job_binding_digest,
        tuple(item.effect_id for item in authority_snapshot.unresolved_effects
              if item.effect_id != context.permit.effect_id),
        canonical_digest(authority_snapshot),
    )


def _current_action_cancellation(
    db, namespace: NamespaceId, snapshot: GraphSnapshot, query: QueryEpoch,
    intent: ActionIntent, binding,
) -> tuple[str, GraphVersion | None, tuple[str, ...]]:
    """Read one stable D08 head and its admission origin under the graph fence."""
    missing = ("current_action_cancellation_read",)
    if binding is None or "graph_history" not in {
            row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    } or "graph_events" not in {
            row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }:
        return "unknown", None, missing
    owner = Owner("activity", *namespace.as_tuple, intent.identity.activity_id)
    action_key = AtomKey(owner, "d08.action_intent.v1", intent.action_id)
    key = AtomKey(owner, "d08.action_cancellation.v1", intent.action_id)
    # A full query epoch makes every competing same-name head visible. A
    # missing initial head is never evidence that the action is uncancelled.
    rows = db.execute(
        "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name='d08.action_cancellation.v1'",
        namespace.as_tuple,
    ).fetchall()
    relevant = tuple(row for row in rows if AtomKey.from_token(row[0]).name == intent.action_id)
    if len(relevant) != 1 or relevant[0][0] != key.token:
        return "unknown", None, missing
    token, revision, encoded, valid = relevant[0]
    matching_atoms = tuple(item for item in snapshot.atoms if item.key == key)
    if len(matching_atoms) != 1:
        return "unknown", None, missing
    atom = matching_atoms[0]
    if (not atom.valid or atom.revision != revision
            or atom.value != json.loads(encoded) or valid != 1
            or type(revision) is not int or revision not in {1, 2}):
        return "unknown", None, missing
    try:
        state = ActionCancellationState(**{
            **atom.value, "source_refs": tuple(atom.value["source_refs"]),
        })
    except (TypeError, ValueError, KeyError):
        return "unknown", None, missing
    expected = (intent.action_id, intent.revision, canonical_digest(intent),
                intent.identity.activity_id, intent.identity.attempt_id,
                intent.identity.effect_id)
    if (state.action_id, state.action_revision, state.action_digest,
            state.activity_id, state.attempt_id, state.effect_id) != expected:
        return "unknown", None, ("action_cancellation_attempt_mismatch",)
    if (binding.namespace, binding.action_id, binding.attempt_id,
            binding.activity_id, binding.effect_id, binding.action_digest,
            binding.action_graph_revision) != (
                "/".join(namespace.as_tuple), intent.action_id,
                intent.identity.attempt_id, intent.identity.activity_id,
                intent.identity.effect_id, canonical_digest(intent), intent.revision):
        return "unknown", None, missing

    def historical(version: int):
        row = db.execute(
            "SELECT value,valid,event_bot,event_persona,event_session,event_id "
            "FROM graph_history WHERE token=? AND revision=?",
            (token, version),
        ).fetchone()
        if row is None or row[1:5] != (1, *namespace.as_tuple, state.activity_id):
            return None
        event = db.execute(
            "SELECT reads,revisions,epoch_revision FROM graph_events WHERE bot=? "
            "AND persona=? AND session=? AND event_id=?",
            (*namespace.as_tuple, state.activity_id, row[5]),
        ).fetchone()
        if event is None or event[2] > query.revision:
            return None
        try:
            reads = {tuple(item) for item in json.loads(event[0])}
            revisions = {tuple(item) for item in json.loads(event[1])}
        except (TypeError, ValueError):
            return None
        action_binding = (
            (action_key.token, 0) in reads
            and (action_key.token, intent.revision) in revisions
            if version == 1 else
            (action_key.token, intent.revision) in reads
        )
        if ((token, version) not in revisions
                or not action_binding
                or (token, version - 1) not in reads):
            return None
        return row

    first = historical(1)
    if first is None or first[5] != binding.operation_id:
        return "unknown", None, missing
    try:
        initial = ActionCancellationState(**{
            **json.loads(first[0]),
            "source_refs": tuple(json.loads(first[0])["source_refs"]),
        })
    except (TypeError, ValueError, KeyError):
        return "unknown", None, missing
    if (initial.state != "active" or initial.cancel_epoch != 0
            or initial.operation_id != binding.operation_id
            or (initial.action_id, initial.action_revision, initial.action_digest,
                initial.activity_id, initial.attempt_id, initial.effect_id) != expected):
        return "unknown", None, missing
    if revision == 1:
        if state != initial or encoded != first[0]:
            return "unknown", None, missing
        return "clear", GraphVersion(key, revision), ()
    second = historical(2)
    if (second is None or second[0] != encoded or second[5] != state.operation_id
            or state.state != "cancelled" or state.cancel_epoch != 1
            or (state.action_id, state.action_revision, state.action_digest,
                state.activity_id, state.attempt_id, state.effect_id) != expected):
        return "unknown", None, missing
    return "cancelled", GraphVersion(key, revision), ("matching_action_cancelled",)


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
    from ..graph_coordinator import namespace_ref

    if (p2.operation != "dispatch"
            or p2.namespace != namespace_ref(namespace)
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

    action_cancellation_state, action_cancellation_version, cancellation_missing = (
        _current_action_cancellation(db, namespace, snapshot, query, intent, binding))
    if action_cancellation_state != "unknown":
        blockers = [item for item in blockers
                    if item != "current_action_cancellation_read"]
    blockers.extend(cancellation_missing)

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
        facts.query_epoch, effect_state, job_cancellation_state,
        action_cancellation_state,
        job_id, job_fence, job_cancel_epoch, effect,
        missing_sources=tuple(dict.fromkeys(blockers)),
        action_job_binding_digest=binding_digest,
        job_graph_version=job_graph_version,
        action_cancellation_graph_version=action_cancellation_version,
    )


__all__ = [
    "CurrentD08ActionConflictEvidenceV1", "CurrentD08ConflictFactsV1",
    "CurrentD08ObservedVersionsV1", "CurrentJobCancellationReadV1",
    "read_current_d08_action_conflict_evidence", "read_current_d08_check_versions",
    "read_current_d08_conflict_facts", "read_current_d08_observed_versions",
    "read_current_job_cancellation",
]
