"""D07 current behavioral stages for W01's Owner-fenced product assembly.

No model calls or graph commits occur here. Installed original ports read actual
sources, issuance/adoption/terminal/cost records. W01 adopts the returned typed
writes and stages the original/job/outbox in the SAME graph business transaction.
Host triggers: C02/input, adopted internal-event outbox, D11 trusted tick, and
durable D07 continuation jobs; a scheduler never counts selection as service.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
import json
import math
import sqlite3
from typing import Protocol

from ..domains.d07 import (
    AttentionPolicy, AttentionTicket, CognitiveActivity, D07DomainProvider,
    ReflectionCheckpoint, SimulationRequest,
)
from ..domains.d07.concern_round import (
    ConcernRoundV1, ConcernServiceChoiceV1, begin_concern_round,
    choose_concern_segment, concern_round_key, concern_round_write,
    read_concern_round, settle_concern_segment,
)
from ..domains.d07.current_issuer_v1 import qualify_current_source_heads_v1
from ..domains.d07.reflection_transition import compile_reflection_transition
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner
from ..memory_types import SourceRecord, access_key, source_key
from ..domains.d06 import source_correction_head_key
from ..runtime_contracts import (
    CommandEnvelope, DependencySet, DomainProposal, NamespaceId, canonical_digest,
)
from .c04_v3_contracts import GraphHeadV3


@dataclass(frozen=True, slots=True)
class ServeCurrentConcernRequestV1:
    category: str
    trigger_original_ref: str

    def __post_init__(self) -> None:
        if self.category not in {"required", "interaction", "background"} or not self.trigger_original_ref:
            raise ValueError("concern request requires category and actual trigger original")


@dataclass(frozen=True, slots=True)
class AdvanceCurrentReflectionRequestV1:
    reflection_ref: str
    cognitive_terminal_ref: str

    def __post_init__(self) -> None:
        AtomKey.from_token(self.reflection_ref)
        if not self.cognitive_terminal_ref:
            raise ValueError("reflection requires an actual cognitive terminal original")


@dataclass(frozen=True, slots=True)
class RunCurrentSimulationRequestV1:
    simulation_request_ref: str
    trigger_original_ref: str

    def __post_init__(self) -> None:
        if not self.simulation_request_ref or not self.trigger_original_ref:
            raise ValueError("simulation requires registered request and trigger originals")


@dataclass(frozen=True, slots=True)
class D07ExecutionOriginalV1:
    terminal_ref: str
    operation_id: str
    activity_id: str
    effect_id: str
    attempt_id: str
    execution_id: str
    input_digest: str
    result_digest: str
    work_kind: str
    started_at: float
    ended_at: float
    time_mapping_ref: str
    time_mapping_version: str
    parent_budget_ref: str
    cost_receipt_refs: tuple[str, ...]
    source_refs: tuple[str, ...]
    activation_generation: int
    resolved_slots: tuple[str, ...] = ()
    discriminating_refs: tuple[str, ...] = ()
    predictions: tuple[tuple[str, ...], ...] = ()
    causal_depth: int = 0
    status: str = "completed"

    def __post_init__(self) -> None:
        for field in ("terminal_ref", "operation_id", "activity_id", "effect_id", "attempt_id",
                      "execution_id", "input_digest", "result_digest", "work_kind",
                      "time_mapping_ref", "time_mapping_version", "parent_budget_ref"):
            value = getattr(self, field)
            if type(value) is not str or not value:
                raise ValueError("execution original is missing " + field)
        if (type(self.started_at) not in (int, float) or not math.isfinite(self.started_at)
                or type(self.ended_at) not in (int, float) or not math.isfinite(self.ended_at)
                or self.ended_at < self.started_at or self.status != "completed"
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(self.causal_depth) is not int or not 0 <= self.causal_depth < 2
                or not self.cost_receipt_refs):
            raise ValueError("execution original lacks completed activity/time/cost/depth facts")
        for name in ("cost_receipt_refs", "source_refs", "resolved_slots", "discriminating_refs"):
            values = getattr(self, name)
            if (type(values) is not tuple or len(set(values)) != len(values)
                    or any(type(value) is not str or not value for value in values)):
                raise ValueError("execution original collection is invalid: " + name)


@dataclass(frozen=True, slots=True)
class D07ConcernInputsV1:
    snapshot: GraphSnapshot
    tickets: tuple[AttentionTicket, ...]
    policy: AttentionPolicy
    issuance_original_refs: tuple[str, ...]
    trigger_original_ref: str
    now_utc: float
    focus_epoch: int
    execution: D07ExecutionOriginalV1 | None = None
    frozen_choice: ConcernServiceChoiceV1 | None = None
    previously_committed_effect_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class D07ReflectionInputsV1:
    snapshot: GraphSnapshot
    execution: D07ExecutionOriginalV1
    cognition_adoption_receipt_ref: str
    causal_root_ref: str
    causal_depth_original_ref: str
    working_set_write: GraphWrite | None = None


@dataclass(frozen=True, slots=True)
class D07SimulationInputsV1:
    snapshot: GraphSnapshot
    registered_request: SimulationRequest
    request_original_digest: str
    trigger_original_ref: str
    dedicated_budget_ref: str
    dedicated_budget_original_ref: str
    execution: D07ExecutionOriginalV1 | None = None


@dataclass(frozen=True, slots=True)
class D07CurrentBehaviorStageV1:
    envelope: CommandEnvelope
    work_kind: str
    request: object
    proposal: DomainProposal
    read_versions: tuple[GraphVersion, ...]
    input_digest: str
    provenance: dict
    status: str
    stop_reason: str
    execution: D07ExecutionOriginalV1 | None = None

    @property
    def stage_digest(self) -> str:
        return canonical_digest(self)


class D07CurrentOriginalReadPortV1(Protocol):
    """Installed W01 reader; all methods run in its current Owner business tx.

    Return values require actual DB/Authority originals. This port is installed
    by the host, never accepted from a public command or a serialized request.
    verify_execution checks terminal/result/cost/role-time interval ownership and
    budget/generation against the originals, not receipt DTO self-reporting.
    """
    def read_concern(self, db, envelope, request) -> D07ConcernInputsV1: ...
    def read_reflection(self, db, envelope, request) -> D07ReflectionInputsV1: ...
    def read_simulation(self, db, envelope, request) -> D07SimulationInputsV1: ...
    def verify_execution(self, db, envelope, execution, input_digest) -> None: ...
    def stage_job_outbox(self, db, stage, original_ref) -> None: ...


def _json(value):
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, AtomKey):
        return value.token
    if is_dataclass(value):
        return {field.name: _json(getattr(value, field.name)) for field in fields(value)}
    if type(value) is dict:
        return {key: _json(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [_json(item) for item in value]
    return value


def _heads(snapshot: GraphSnapshot) -> tuple[GraphHeadV3, ...]:
    return tuple(GraphHeadV3(atom.key.token, atom.revision, atom.valid,
        None if atom.revision == 0 else json.dumps(atom.value, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False)) for atom in snapshot.atoms)


def _guard(envelope: CommandEnvelope, snapshot: GraphSnapshot) -> None:
    if type(envelope) is not CommandEnvelope or type(snapshot) is not GraphSnapshot:
        raise ValueError("D07 behavior requires current typed envelope and snapshot")
    ns = envelope.authority.namespace
    if (len(snapshot.epochs) != 1 or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != ns.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or any(NamespaceId.from_key(atom.key) != ns for atom in snapshot.atoms)
            or not set(snapshot.versions) <= set(envelope.version_guard.read_versions)):
        raise ValueError("D07 current snapshot is outside its guarded namespace/read set")
    if len(envelope.authority.audience) != 1:
        raise ValueError("D07 bounded stage requires one explicit consumer audience")


def _source_reads(envelope, snapshot, roots):
    return qualify_current_source_heads_v1(envelope.authority.namespace, roots,
        _heads(snapshot), audience=envelope.authority.audience[0], purpose=envelope.authority.purpose)


def _activity(envelope, execution, stop_reason):
    if (execution.operation_id != envelope.identity.operation_id
            or execution.activity_id != envelope.identity.activity_id
            or execution.effect_id != envelope.identity.effect_id
            or execution.attempt_id != envelope.identity.attempt_id
            or execution.activation_generation != envelope.authority.activation_generation
            or execution.parent_budget_ref != envelope.parent_budget_lease_ref
            or execution.ended_at > envelope.deadline_utc):
        raise ValueError("D07 activity execution differs from frozen operation/budget/generation")
    activity = CognitiveActivity(execution.activity_id, execution.effect_id,
        execution.attempt_id, execution.work_kind, execution.started_at,
        execution.ended_at, stop_reason, execution.source_refs, execution.cost_receipt_refs)
    key = AtomKey(Owner("activity", *envelope.authority.namespace.as_tuple,
        execution.activity_id), "d07.cognitive_activity.v1", execution.activity_id)
    payload = _json(activity)
    payload["schema"] = key.type_name
    return GraphWrite(key, payload)


def _stage(envelope, snapshot, kind, request, writes, provenance, status, stop, execution=None):
    _guard(envelope, snapshot)
    guarded = {version.key: version.revision for version in envelope.version_guard.read_versions}
    for write in writes:
        if write.key not in guarded:
            raise ValueError("D07 output lacks explicit current/absent CAS read")
        spec = next(spec for spec in D07DomainProvider.type_specs() if spec.name == write.key.type_name)
        spec.validator(write.value)
    original_payload = {"schema": "d07.current-behavior-input.v1", "kind": kind,
        "request": request, "snapshot": snapshot, "input": provenance,
        "namespace": envelope.authority.namespace, "operation": envelope.identity,
        "authority": envelope.authority, "parent_budget": envelope.parent_budget_lease_ref}
    # Current admission digest is separately reproducible. The execution input
    # digest remains the original frozen work identity, not an after-the-result
    # hash of resolved slots or predictions. The installed port cross-checks it
    # against the durable prepared request and exact terminal result.
    provenance = {**provenance, "current_admission_digest": canonical_digest(original_payload)}
    input_digest = canonical_digest(original_payload) if execution is None else execution.input_digest
    proposal = DomainProposal("d07", "d07.proposal.v1",
        D07DomainProvider().descriptor.request_schema_hash, envelope, tuple(writes),
        DependencySet(historical_provenance=tuple(version for version in snapshot.versions
            if version.key.type_name == "memory.source" and version.revision > 0)),
        (() if execution is None else ("d07-activity:" + execution.effect_id,)),
        ("persistent_job", "outbox"))
    return D07CurrentBehaviorStageV1(envelope, kind, request, proposal,
        snapshot.versions, input_digest, provenance, status, stop, execution)


def advance_current_concerns_v1(envelope: CommandEnvelope,
    request: ServeCurrentConcernRequestV1, inputs: D07ConcernInputsV1) -> D07CurrentBehaviorStageV1:
    """One fair bounded phase; actual terminal alone consumes service once."""
    _guard(envelope, inputs.snapshot)
    ns = envelope.authority.namespace
    if (type(request) is not ServeCurrentConcernRequestV1
            or inputs.trigger_original_ref != request.trigger_original_ref
            or len(inputs.tickets) > 256 or len(inputs.issuance_original_refs) != len(inputs.tickets)
            or not math.isfinite(inputs.now_utc) or inputs.now_utc >= envelope.deadline_utc):
        raise ValueError("concern current inventory/trigger/time originals are incomplete")
    # Every ticket must be the current graph original with qualified ancestors;
    # the installed read port authenticates its separate issuance/adoption row.
    heads = _heads(inputs.snapshot)
    for ticket in inputs.tickets:
        key = AtomKey(Owner("persona", *ns.as_tuple), "d07.attention_ticket.v1", ticket.ticket_id)
        atom = inputs.snapshot.get(key)
        if atom is None or not atom.valid or atom.revision < 1 or atom.value != {
                "schema": key.type_name, **_json(ticket)}:
            raise ValueError("concern inventory is not the current typed ticket original")
        qualify_current_source_heads_v1(ns, ticket.source_refs, heads,
            audience=envelope.authority.audience[0], purpose=envelope.authority.purpose)
    found = read_concern_round(inputs.snapshot, ns, request.category)
    key = concern_round_key(ns, request.category)
    if found is None:
        atom = inputs.snapshot.get(key)
        if atom is None or atom.revision != 0:
            raise ValueError("concern round absence must be explicitly observed")
        state = ConcernRoundV1(ns.persona_id, request.category, 0, 0, (), (), (), ())
    else:
        state = found[0]
    provenance = {"trigger": request.trigger_original_ref, "policy": inputs.policy,
        "tickets": inputs.tickets, "issuance_originals": inputs.issuance_original_refs,
        "prior_round": state, "focus_epoch": inputs.focus_epoch}
    if inputs.execution is not None:
        if inputs.frozen_choice is None or inputs.execution.work_kind != "concern":
            raise ValueError("completed concern requires its original frozen choice")
        if set(inputs.execution.source_refs) != set(next(ticket.source_refs for ticket in inputs.tickets
                if ticket.ticket_id == inputs.frozen_choice.ticket_id)):
            raise ValueError("concern execution sources differ from original choice")
        transition = settle_concern_segment(state, inputs.frozen_choice, inputs.tickets,
            inputs.policy, effect_id=inputs.execution.effect_id,
            receipt_ref=inputs.execution.terminal_ref, now=inputs.now_utc,
            focus_epoch=inputs.focus_epoch,
            previously_committed_effect_ids=inputs.previously_committed_effect_ids)
        provenance["choice"] = inputs.frozen_choice
        writes = () if transition.next_round == state else (
            concern_round_write(ns, transition.next_round),
            _activity(envelope, inputs.execution, "bounded_concern_segment_completed"))
        return _stage(envelope, inputs.snapshot, "concern", request, writes, provenance,
            "staged" if writes else "already_recorded", transition.status, inputs.execution)
    choice = choose_concern_segment(state, inputs.tickets, inputs.policy,
        now=inputs.now_utc, focus_epoch=inputs.focus_epoch)
    writes = ()
    if choice is None:
        # A missing, expired or resource-blocked ticket cannot hold the rest of
        # a round forever. Compose the parking and next-round CAS as one graph
        # revision; no empty work or service count is manufactured.
        runnable_groups = {ticket.concern_ref or ticket.causal_root for ticket in inputs.tickets
            if ticket.category == request.category and ticket.eligible
            and ticket.resources_available and not ticket.cancel_refs
            and ticket.valid_until > inputs.now_utc}
        parking = dict(state.parked)
        for group in state.groups:
            if group not in runnable_groups:
                parking[group] = inputs.now_utc
        state = replace(state, parked=tuple(sorted(parking.items())))
        transition = begin_concern_round(state, inputs.tickets, now=inputs.now_utc)
        state = transition.next_round
        if state.round_id == provenance["prior_round"].round_id and state != provenance["prior_round"]:
            state = replace(state, revision=provenance["prior_round"].revision + 1)
        if state != provenance["prior_round"]:
            writes = (concern_round_write(ns, state),)
        choice = choose_concern_segment(state, inputs.tickets, inputs.policy,
            now=inputs.now_utc, focus_epoch=inputs.focus_epoch)
    provenance["choice"] = choice
    return _stage(envelope, inputs.snapshot, "concern", request, writes, provenance,
        "queued" if choice else "deferred", "execute_bounded_segment" if choice else "no_runnable_group")


serve_current_concern_v1 = advance_current_concerns_v1


def advance_current_reflection_v1(envelope: CommandEnvelope,
    request: AdvanceCurrentReflectionRequestV1,
    inputs: D07ReflectionInputsV1) -> D07CurrentBehaviorStageV1:
    """Advance only a real adopted cognition; repeated refs do not buy progress."""
    _guard(envelope, inputs.snapshot)
    execution = inputs.execution
    key = AtomKey.from_token(request.reflection_ref)
    if (key.type_name != "d07.reflection_checkpoint.v1"
            or request.cognitive_terminal_ref != execution.terminal_ref
            or execution.work_kind != "reflection" or not inputs.cognition_adoption_receipt_ref
            or not inputs.causal_root_ref or not inputs.causal_depth_original_ref):
        raise ValueError("reflection adopted cognition/depth original is incomplete")
    # New discriminating refs must exist and retain source permission. They are
    # read from adopted cognition originals, never caller-supplied text refs.
    _source_reads(envelope, inputs.snapshot, execution.source_refs)
    if not set(execution.discriminating_refs) <= set(execution.source_refs):
        raise ValueError("reflection discriminating refs are outside actual cognition sources")
    prior = inputs.snapshot.get(key)
    if prior is None or not prior.valid:
        raise ValueError("reflection current checkpoint is missing")
    novel = set(execution.discriminating_refs) - set(prior.value["discriminating_refs"])
    if execution.resolved_slots and not novel:
        raise ValueError("reflection cannot resolve slots without a new discriminating original")
    candidate = compile_reflection_transition(inputs.snapshot,
        envelope.authority.namespace, reflection_id=key.name,
        resolved_slots=execution.resolved_slots,
        discriminating_refs=execution.discriminating_refs, causal_depth=execution.causal_depth)
    if candidate is None:
        raise ValueError("reflection current checkpoint/depth/trigger is stale or closed")
    writes = [candidate.proposed_write, _activity(envelope, execution, candidate.next_checkpoint.status)]
    if inputs.working_set_write is not None:
        if inputs.working_set_write.key.type_name != "d07.working_set.v1":
            raise ValueError("reflection working set must be a typed D07 working set")
        writes.append(inputs.working_set_write)
    provenance = {"terminal": execution.terminal_ref,
        "cognition_adoption": inputs.cognition_adoption_receipt_ref,
        "causal_root": inputs.causal_root_ref, "causal_depth_original": inputs.causal_depth_original_ref,
        "resolved_slots": execution.resolved_slots, "discriminating_refs": execution.discriminating_refs,
        "prior_checkpoint": candidate.prior_version, "causal_depth": execution.causal_depth}
    return _stage(envelope, inputs.snapshot, "reflection", request, writes, provenance,
        "staged", candidate.next_checkpoint.status, execution)


def run_current_simulation_v1(envelope: CommandEnvelope,
    request: RunCurrentSimulationRequestV1,
    inputs: D07SimulationInputsV1) -> D07CurrentBehaviorStageV1:
    """Hypothetical baseline + <=2 alternatives with dedicated shared-budget lease."""
    _guard(envelope, inputs.snapshot)
    registered = inputs.registered_request
    if (type(request) is not RunCurrentSimulationRequestV1
            or registered.activity_id != envelope.identity.activity_id
            or inputs.request_original_digest != canonical_digest(registered)
            or request.trigger_original_ref != inputs.trigger_original_ref
            or not inputs.dedicated_budget_original_ref
            or inputs.dedicated_budget_ref != envelope.parent_budget_lease_ref
            or len(registered.alternatives) > 2):
        raise ValueError("simulation registered request/branch/dedicated budget differs")
    _source_reads(envelope, inputs.snapshot, registered.snapshot_refs)
    provenance = {"registered_request_ref": request.simulation_request_ref,
        "request": registered, "trigger": inputs.trigger_original_ref,
        "dedicated_budget": inputs.dedicated_budget_ref,
        "dedicated_budget_original": inputs.dedicated_budget_original_ref,
        "content_reality": "hypothetical", "external_evidence_eligibility": "none"}
    execution = inputs.execution
    if execution is None:
        return _stage(envelope, inputs.snapshot, "simulation", request, (), provenance,
            "queued", "requires_actual_simulation_execution")
    if (execution.work_kind != "simulation" or execution.source_refs != registered.snapshot_refs
            or len(execution.predictions) != 1 + len(registered.alternatives)
            or any(len(steps) > 2 for steps in execution.predictions)):
        raise ValueError("simulation terminal predictions do not match bounded frozen branches")
    actual_request = SimulationRequest(registered.activity_id, registered.snapshot_refs,
        registered.baseline, registered.alternatives, execution.predictions, registered.unknowns)
    result = D07DomainProvider.simulate(actual_request)
    writes = [_activity(envelope, execution, "bounded_hypothetical_simulation_completed")]
    for branch in result.branches:
        key = AtomKey(Owner("activity", *envelope.authority.namespace.as_tuple,
            registered.activity_id), "d07.simulation_branch.v1", branch.branch_id)
        writes.append(GraphWrite(key, {"schema": key.type_name, **_json(branch)}))
    provenance["simulation_result"] = result
    return _stage(envelope, inputs.snapshot, "simulation", request, writes, provenance,
        "staged", "bounded_hypothetical_simulation_completed", execution)


def prepare_current_association_interpretation_v3(
    work, result, selection, source_heads, interpretation_originals,
    installed_policy, *, binding_digest: str, execution_id: str,
    activation_generation: int, adoption_original=None, paid_original=None,
):
    """Single pure issuer API shared by prepare and final current re-admission."""
    from ..domains.d07.current_issuer_v1 import issue_current_recollection_interpretation_v3
    from .c04_direct_seed_v4 import AssociationWorkInputV4
    if type(work) is AssociationWorkInputV4:
        from ..domains.d07.current_issuer_v1 import issue_current_recollection_interpretation_v4
        return issue_current_recollection_interpretation_v4(
        work, result, selection, source_heads, interpretation_originals,
        installed_policy, binding_digest=binding_digest, execution_id=execution_id,
        activation_generation=activation_generation, adoption_original=adoption_original,
        paid_original=paid_original)

    return issue_current_recollection_interpretation_v3(
        work, result, selection, source_heads, interpretation_originals,
        installed_policy, binding_digest=binding_digest, execution_id=execution_id,
        activation_generation=activation_generation, adoption_original=adoption_original,
        paid_original=paid_original)


def issue_current_association_interpretation_in_transaction_v3(
    db: sqlite3.Connection, work, result, selection, installed_policy, *,
    binding_digest: str, execution_id: str, activation_generation: int,
    installed_semantic_original_reader=None,
):
    """W01's concrete final issuer read: candidate payloads are never inputs.

    Authority terminal authentication happens before this transaction. The
    optional installed semantic-original reader authenticates the D07 adoption
    issuer and paid call/cost originals; presence requires no extra model call.
    Its return is (AdoptedInterpretationOriginalV1, PaidCognitiveAdoptionOriginalV1|None).
    """
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise ValueError("current C04 D07 issuer needs W01's current business transaction")
    from .c04_result_adoption_v3 import select_c04_result_v3
    _, expected = select_c04_result_v3(work, result, focus_epoch=work.selection_ticket.focus_epoch)
    if selection != expected.selection_ticket:
        raise ValueError("C04 final interpretation selection differs from actual Authority result")
    ns = work.namespace
    rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    if rights != (work.access_epoch, work.delete_epoch):
        raise ValueError("C04 final D07 rights differ from frozen work")
    heads: dict[str, GraphHeadV3] = {}

    def load(key):
        if key.token not in heads:
            row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                (key.token, *ns.as_tuple)).fetchone()
            heads[key.token] = GraphHeadV3(key.token, row[0], bool(row[2]), row[1]) if row else GraphHeadV3(key.token, 0, False, None)
        return heads[key.token]

    active, done = set(), set()
    def visit(ref):
        if ref in active:
            raise ValueError("C04 current source family closure is cyclic")
        if ref in done:
            return
        if len(active) + len(done) >= 256:
            raise ValueError("C04 current source family closure is too large")
        key = AtomKey.from_token(ref)
        if key != source_key(*ns.as_tuple, key.owner.subject or ""):
            raise ValueError("C04 current source namespace differs")
        head = load(key)
        if not head.valid or head.revision < 1:
            raise ValueError("C04 final selected/current support source is unavailable")
        record = SourceRecord.from_dict(head.value)
        load(access_key(*ns.as_tuple, record.source_id))
        load(source_correction_head_key(ns, record.source_id))
        active.add(ref)
        for parent in record.parent_source_ids:
            visit(source_key(*ns.as_tuple, parent).token)
        active.remove(ref)
        done.add(ref)

    roots = [source_key(*ns.as_tuple, selection.selected_candidate_ids[0]).token]
    frozen = {head.ref: head for head in work.reads}
    for ref in (work.focus_ref, work.attention_ticket_ref):
        if load(AtomKey.from_token(ref)) != frozen.get(ref):
            raise ValueError("C04 current focus/ticket changed before final D07 issuance")
    interpretation_heads = ()
    adoption, paid = None, None
    if installed_policy.mode != "recollection_presence":
        if installed_semantic_original_reader is None:
            raise ValueError("installed current semantic original reader is missing")
        key = AtomKey.from_token(installed_policy.interpretation_ref)
        interpretation = load(key)
        adoption, paid = installed_semantic_original_reader.read_current_adoption(
            db, ns, key.token, interpretation.revision)
        value = interpretation.value
        if value is None:
            raise ValueError("installed current semantic head is unavailable")
        roots.extend((*value["source_refs"], *adoption.supporting_refs, *adoption.counter_refs))
        interpretation_heads = (interpretation,)
    for root in dict.fromkeys(roots):
        visit(root)
    return prepare_current_association_interpretation_v3(work, result, selection,
        tuple(heads[ref] for ref in sorted(heads) if ref not in {head.ref for head in interpretation_heads}),
        interpretation_heads, installed_policy, binding_digest=binding_digest,
        execution_id=execution_id, activation_generation=activation_generation,
        adoption_original=adoption, paid_original=paid)


# These content-bearing surfaces must be registered in C09's graph-business
# cleanup/rebase/restore inventory by the sole shared schema writer. Immutable
# history is still deletable; no auxiliary database or untracked result cache.
D07_CURRENT_STORAGE_INVENTORY_V1 = {
    "graph_d07_behavior_original_v1": {
        "namespace_columns": ("bot", "persona"),
        "content_columns": ("request_json", "stage_json"),
        "source_closure_column": "source_refs_json",
        "operation_column": "operation_id", "recovery": "revalidate_original_operation",
    },
}


def install_current_d07_behavior_schema_v1(db: sqlite3.Connection) -> None:
    if db.in_transaction:
        raise ValueError("install D07 current schema before runtime transactions")
    db.execute("CREATE TABLE IF NOT EXISTS graph_d07_behavior_original_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,"
        "work_kind TEXT NOT NULL,request_digest TEXT NOT NULL,stage_digest TEXT NOT NULL,"
        "input_digest TEXT NOT NULL,request_json TEXT NOT NULL,stage_json TEXT NOT NULL,"
        "source_refs_json TEXT NOT NULL,PRIMARY KEY(bot,persona,operation_id))")


def stage_current_d07_behavior_in_transaction_v1(db: sqlite3.Connection,
    stage: D07CurrentBehaviorStageV1, *, installed_port: D07CurrentOriginalReadPortV1) -> str:
    """Independently rederive, verify execution, persist original/job/outbox.

    Call before graph CAS so independent rederivation observes the prior heads.
    W01 then applies the returned graph writes within this same transaction.
    This function never commits. Exceptions roll back every staged write.
    Exact retry returns the durable original; unknown must query the same ID.
    """
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise ValueError("D07 stage needs W01's current graph business transaction")
    envelope, request = stage.envelope, stage.request
    ns = envelope.authority.namespace
    request_digest = canonical_digest({"request": request, "envelope": envelope})
    ref = "d07-current:" + canonical_digest((ns, envelope.identity.operation_id))[:48]
    row = db.execute("SELECT request_digest,stage_digest FROM graph_d07_behavior_original_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple, envelope.identity.operation_id)).fetchone()
    if row is not None:
        if row != (request_digest, stage.stage_digest):
            raise ValueError("D07 original operation conflicts; query original identity")
        return ref
    dispatch = {
        "concern": (installed_port.read_concern, advance_current_concerns_v1),
        "reflection": (installed_port.read_reflection, advance_current_reflection_v1),
        "simulation": (installed_port.read_simulation, run_current_simulation_v1),
    }
    reader, compiler = dispatch[stage.work_kind]
    current = compiler(envelope, request, reader(db, envelope, request))
    if current != stage:
        raise ValueError("D07 current independent issuer stage differs")
    if stage.execution is not None:
        installed_port.verify_execution(db, envelope, stage.execution, stage.input_digest)
    closure = sorted({version.key.token for version in stage.read_versions
                      if version.key.type_name == "memory.source" and version.revision > 0})
    db.execute("INSERT INTO graph_d07_behavior_original_v1 VALUES (?,?,?,?,?,?,?,?,?,?)",
        (*ns.as_tuple, envelope.identity.operation_id, stage.work_kind, request_digest,
         stage.stage_digest, stage.input_digest,
         json.dumps(_json(request), sort_keys=True, separators=(",", ":"), allow_nan=False),
         json.dumps(_json(stage), sort_keys=True, separators=(",", ":"), allow_nan=False),
         json.dumps(closure, separators=(",", ":"))))
    installed_port.stage_job_outbox(db, stage, ref)
    return ref


__all__ = ["ServeCurrentConcernRequestV1", "AdvanceCurrentReflectionRequestV1",
    "RunCurrentSimulationRequestV1", "D07ExecutionOriginalV1", "D07ConcernInputsV1",
    "D07ReflectionInputsV1", "D07SimulationInputsV1", "D07CurrentBehaviorStageV1",
    "D07CurrentOriginalReadPortV1", "advance_current_concerns_v1", "serve_current_concern_v1",
    "advance_current_reflection_v1", "run_current_simulation_v1",
    "prepare_current_association_interpretation_v3", "install_current_d07_behavior_schema_v1",
    "issue_current_association_interpretation_in_transaction_v3",
    "stage_current_d07_behavior_in_transaction_v1", "D07_CURRENT_STORAGE_INVENTORY_V1"]
