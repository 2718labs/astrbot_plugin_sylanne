"""D10 actual life, observed offline prefixes and current contact candidates."""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta, timezone
import json
import math

from ...graph_types import AtomKey, GraphWrite, Owner, TypeSpec
from ...runtime_contracts import CheckReceipt, DomainProposal, canonical_digest, schema_hash
from ...runtime.domain_production_contracts_v1 import ProductionOriginalRefV1, StagedDomainOperationV1
from ..d01.production_operations_v1 import plain_v1, require_locator_v1, stage_result_v1
from . import ActivityOutcome, ActivityRecipe, LifeDomain, LifeProject
from .current_contact import CurrentContactCandidateV1
from .offline_interval import (
    OfflineIntervalReadSet, OfflineTickReadSetV1, advance_observed_offline_ticks_v1,
    plan_offline_simulation_slice,
)


@dataclass(frozen=True, slots=True)
class AdvanceCurrentLifeRequestV1:
    project_ref: str
    activity_outcome_ref: str

    def __post_init__(self):
        if AtomKey.from_token(self.project_ref).type_name != "d10.life_project.v1":
            raise ValueError("life progress requires a current life project")
        require_locator_v1(self.activity_outcome_ref, "activity_outcome_ref")


@dataclass(frozen=True, slots=True)
class AdvanceCurrentOfflineRequestV1:
    offline_interval_ref: str
    clock_mapping_ref: str
    continuation_ref: str | None

    def __post_init__(self):
        require_locator_v1(self.offline_interval_ref, "offline_interval_ref")
        require_locator_v1(self.clock_mapping_ref, "clock_mapping_ref")
        if self.continuation_ref is not None:
            require_locator_v1(self.continuation_ref, "continuation_ref")


@dataclass(frozen=True, slots=True)
class PrepareCurrentContactRequestV1:
    opportunity_ref: str
    contact_policy_ref: str
    target_route_ref: str

    def __post_init__(self):
        for name in ("opportunity_ref", "contact_policy_ref", "target_route_ref"):
            require_locator_v1(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class LifeProgressHeadV1:
    project_ref: str
    recipe_ref: str
    activity_id: str
    effect_id: str
    reality: str
    step: str
    role_start: float
    role_end: float
    artifact_ref: str | None
    terminal_ref: str
    receipt_refs: tuple[str, ...]
    source_refs: tuple[str, ...]
    actuality: str = "completed"
    schema: str = "d10.life_progress.v1"

    def __post_init__(self):
        if (self.schema != "d10.life_progress.v1" or self.actuality != "completed"
                or self.reality not in {"real_execution", "role_simulation"}
                or any(type(v) not in (int, float) or not math.isfinite(v) for v in (self.role_start, self.role_end))
                or self.role_end <= self.role_start or not self.receipt_refs or not self.source_refs):
            raise ValueError("life progress requires actual complete role interval and original receipts")
        for name in ("project_ref", "recipe_ref", "activity_id", "effect_id", "step", "terminal_ref"):
            require_locator_v1(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class OfflineCheckpointV1:
    interval_ref: str
    mapping_id: str
    mapping_version: int
    processed_until_utc: str
    requested_until_utc: str
    occurrence_refs: tuple[str, ...]
    revision: int
    schema: str = "d10.offline_checkpoint.v1"

    def __post_init__(self):
        if (self.schema != "d10.offline_checkpoint.v1" or type(self.mapping_version) is not int
                or self.mapping_version < 1 or type(self.revision) is not int or self.revision < 1
                or type(self.occurrence_refs) is not tuple or len(self.occurrence_refs) > 32
                or len(set(self.occurrence_refs)) != len(self.occurrence_refs)):
            raise ValueError("offline checkpoint must be a bounded versioned actual prefix")
        from .offline_interval import _utc
        if _utc(self.processed_until_utc) > _utc(self.requested_until_utc):
            raise ValueError("offline checkpoint cannot pass the registered interval")
        require_locator_v1(self.interval_ref, "interval_ref")
        require_locator_v1(self.mapping_id, "mapping_id")
        for ref in self.occurrence_refs:
            if AtomKey.from_token(ref).type_name != "d10.offline_simulated_occurrence.v1":
                raise ValueError("offline checkpoint references a non-simulation occurrence")


def d10_production_type_specs_v1():
    def strict(value, cls, tuple_fields=()):
        if type(value) is not dict or set(value) != {field.name for field in fields(cls)}:
            raise ValueError("D10 production head has unexpected fields")
        raw = dict(value)
        for name in tuple_fields:
            raw[name] = tuple(raw[name])
        return cls(**raw)

    def occurrence(value):
        from decimal import Decimal
        from ...runtime_contracts import VersionedRef
        from .offline_interval import OfflineSimulatedOccurrenceV1
        if type(value) is not dict or set(value) != {field.name for field in fields(OfflineSimulatedOccurrenceV1)} | {"schema"}:
            raise ValueError("offline occurrence fields differ")
        raw = dict(value)
        if raw.pop("schema") != "d10.offline_simulated_occurrence.v1":
            raise ValueError("offline occurrence schema differs")
        raw["character_at"] = Decimal(raw["character_at"])
        for name in ("recipe_ref", "schedule_ref", "occurrence_ref", "source_ref", "access_ref"):
            raw[name] = VersionedRef(**raw[name])
        result = OfflineSimulatedOccurrenceV1(**raw)
        if result.world_kind != "role_simulation" or result.actuality != "computed_at_recovery":
            raise ValueError("offline occurrences cannot claim external or historical execution")
        return result

    return (
        TypeSpec("d10.life_progress.v1", ("activity",), "state",
            lambda v: strict(v, LifeProgressHeadV1, ("receipt_refs", "source_refs")), immutable=True,
            writer_domain="d10", schema_hash=schema_hash({"d10.life_progress.v1": 1})),
        TypeSpec("d10.offline_checkpoint.v1", ("persona",), "state",
            lambda v: strict(v, OfflineCheckpointV1, ("occurrence_refs",)), writer_domain="d10",
            schema_hash=schema_hash({"d10.offline_checkpoint.v1": 1})),
        TypeSpec("d10.offline_simulated_occurrence.v1", ("activity",), "state", occurrence,
            immutable=True, writer_domain="d10", schema_hash=schema_hash({"d10.offline_simulated_occurrence.v1": 1})),
    )


@dataclass(frozen=True, slots=True)
class CurrentLifeInputsV1:
    project: LifeProject
    recipe: ActivityRecipe
    recipe_ref: str
    outcome: ActivityOutcome
    progress: LifeProgressHeadV1
    actual_terminal_original: ProductionOriginalRefV1
    adopted_plan_original: ProductionOriginalRefV1
    paid_cost_originals: tuple[ProductionOriginalRefV1, ...]
    duplicate_progress: bool = False


@dataclass(frozen=True, slots=True)
class CurrentOfflineInputsV1:
    interval: OfflineIntervalReadSet
    tick_read: OfflineTickReadSetV1
    requested_until_utc: str
    boundary_utc: str | None
    interval_original: ProductionOriginalRefV1
    prior_checkpoint: OfflineCheckpointV1 | None


@dataclass(frozen=True, slots=True)
class CurrentContactInputsV1:
    candidate: CurrentContactCandidateV1
    route_original: ProductionOriginalRefV1
    boundary_originals: tuple[ProductionOriginalRefV1, ...]
    required_check: CheckReceipt | None
    source_original: ProductionOriginalRefV1
    policy_original: ProductionOriginalRefV1 | None = None


class _ExactCurrentReadV1:
    def __init__(self, expected):
        self.expected = expected

    def __call__(self, read):
        return read == self.expected


def compile_advance_current_life_v1(frame, request, inputs):
    if type(request) is not AdvanceCurrentLifeRequestV1 or type(inputs) is not CurrentLifeInputsV1:
        raise TypeError("exact current life request and observed inputs required")
    result = LifeDomain.adopt_life_progress(inputs.project, inputs.recipe, inputs.outcome)
    progress, ns = inputs.progress, frame.envelope.authority.namespace
    if (progress.project_ref != request.project_ref or progress.activity_id != inputs.outcome.activity_id
            or progress.effect_id != inputs.outcome.effect_id or progress.recipe_ref != inputs.recipe_ref
            or progress.reality != inputs.recipe.reality or progress.step != inputs.project.next_step
            or progress.step not in inputs.recipe.allowed_steps):
        raise ValueError("life current project/recipe/actual role outcome changed")
    key = AtomKey(Owner("activity", *ns.as_tuple, progress.activity_id), "d10.life_progress.v1", progress.effect_id)
    writes = () if inputs.duplicate_progress else (GraphWrite(key, plain_v1(progress),
        tuple(AtomKey.from_token(ref) for ref in progress.source_refs)),)
    return stage_result_v1(frame, "d10", "advance_life", request, writes=writes,
        provenance={"life_progress": result, "actual_progress": progress, "terminal": inputs.actual_terminal_original,
            "adopted_plan": inputs.adopted_plan_original, "duplicate": inputs.duplicate_progress},
        contribution_keys=() if inputs.duplicate_progress else ("d10-life-effect:" + progress.effect_id,),
        receiver_events=() if inputs.duplicate_progress else (("d01", "actual_life_outcome_available_for_growth"),),
        costs=inputs.paid_cost_originals, proposal_schema="d10.proposal.v1",
        proposal_hash=LifeDomain().descriptor.request_schema_hash)


def compile_advance_current_offline_v1(frame, request, inputs):
    if type(request) is not AdvanceCurrentOfflineRequestV1 or type(inputs) is not CurrentOfflineInputsV1:
        raise TypeError("exact registered offline request and observed ticks required")
    now = datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z")
    interval = plan_offline_simulation_slice(inputs.interval,
        requested_until_utc=inputs.requested_until_utc, trusted_now_utc=now,
        boundary_utc=inputs.boundary_utc, read_verifier=_ExactCurrentReadV1(inputs.interval))
    if interval.status != "candidate":
        return stage_result_v1(frame, "d10", "advance_offline", request,
            provenance={"interval": interval}, coverage="waiting_for_original", missing=(interval.reason,))
    tick_read = replace(inputs.tick_read, interval=interval)
    advanced = advance_observed_offline_ticks_v1(tick_read, trusted_now_utc=now,
        read_verifier=_ExactCurrentReadV1(tick_read))
    if not advanced.outputs:
        return stage_result_v1(frame, "d10", "advance_offline", request,
            provenance={"observed_prefix": advanced, "interval_original": inputs.interval_original},
            coverage="waiting_for_original", missing=(advanced.reason or "registered_observed_offline_ticks",),
            continuation="d10-offline:" + canonical_digest((request.offline_interval_ref, advanced.unprocessed_from_utc))[:48])
    maximum = min(frame.limits.max_role_segments, (frame.limits.max_writes - 2) // 3)
    outputs = advanced.outputs[:maximum]
    if len(outputs) != len(advanced.outputs):
        start = datetime.fromisoformat(outputs[-1].scheduled_at_utc.replace("Z", "+00:00"))
        cursor = min(start + timedelta(seconds=inputs.tick_read.recipe.cadence_seconds),
                     datetime.fromisoformat(interval.end_utc.replace("Z", "+00:00")))
        advanced = replace(advanced, outputs=outputs, processed_until_utc=cursor.isoformat().replace("+00:00", "Z"),
            unprocessed_from_utc=cursor.isoformat().replace("+00:00", "Z"), reason="bounded_adoption_window")
    ns, owner = frame.envelope.authority.namespace, Owner("activity", *frame.envelope.authority.namespace.as_tuple,
                                                         frame.envelope.identity.activity_id)
    writes, occurrence_refs = [], []
    for occurrence in outputs:
        key = AtomKey(owner, "d10.offline_simulated_occurrence.v1", occurrence.occurrence_id)
        value = plain_v1(occurrence)
        value["character_at"] = str(occurrence.character_at)
        value["schema"] = key.type_name
        writes.append(GraphWrite(key, value, (AtomKey.from_token(occurrence.source_ref.ref),)))
        occurrence_refs.append(key.token)
    checkpoint_key = AtomKey(Owner("persona", *ns.as_tuple), "d10.offline_checkpoint.v1",
        "interval:" + canonical_digest(request.offline_interval_ref)[:48])
    checkpoint = OfflineCheckpointV1(request.offline_interval_ref, interval.mapping_id, interval.mapping_version,
        advanced.processed_until_utc, advanced.unprocessed_until_utc,
        tuple(occurrence_refs),
        (inputs.prior_checkpoint.revision + 1) if inputs.prior_checkpoint else 1)
    writes.append(GraphWrite(checkpoint_key, plain_v1(checkpoint), tuple(AtomKey.from_token(ref) for ref in occurrence_refs)))
    complete = advanced.processed_until_utc == advanced.unprocessed_until_utc
    continuation = None if complete else "d10-offline:" + canonical_digest((request.offline_interval_ref, advanced.processed_until_utc))[:48]
    return stage_result_v1(frame, "d10", "advance_offline", request, writes=tuple(writes),
        provenance={"observed_prefix": plain_v1(advanced), "interval": plain_v1(interval),
            "interval_original": inputs.interval_original, "checkpoint": checkpoint,
            "content_reality": "simulation", "actuality": "computed_at_recovery"},
        contribution_keys=tuple("d10-offline-occurrence:" + occurrence.occurrence_id for occurrence in outputs),
        coverage="complete" if complete else "partial", missing=() if complete else (advanced.reason,),
        continuation=continuation, proposal_schema="d10.proposal.v1", proposal_hash=LifeDomain().descriptor.request_schema_hash)


def compile_prepare_current_contact_v1(frame, request, inputs):
    if type(request) is not PrepareCurrentContactRequestV1 or type(inputs) is not CurrentContactInputsV1:
        raise TypeError("exact contact opportunity request and current evidence required")
    candidate = inputs.candidate
    ready = candidate.status == "policy_candidate" and candidate.check is not None
    if inputs.required_check is not None and (inputs.required_check.coverage, inputs.required_check.result) != ("full", "pass"):
        ready = False
    return stage_result_v1(frame, "d10", "prepare_contact", request,
        provenance={"contact_candidate": candidate, "target_route": inputs.route_original,
            "boundaries": inputs.boundary_originals, "source": inputs.source_original,
            "required_check": inputs.required_check, "claim_phase": "final_dispatch_admission",
            "policy_approval": inputs.policy_original},
        receiver_events=(("d08", "qualified_contact_opportunity_requires_action"),) if ready else (),
        coverage="complete" if ready else "waiting_for_original",
        missing=() if ready else candidate.reasons or ("current_contact_required_checks",))


@dataclass(frozen=True, slots=True)
class CurrentLifeEffectExperienceBundleV1:
    envelope: object
    life_stage: StagedDomainOperationV1
    body_stage: StagedDomainOperationV1
    memory_proposal: DomainProposal
    experience_refs: tuple[str, ...]
    d02_settlement_refs: tuple[str, ...]
    d11_cost_settlement_refs: tuple[str, ...]
    bundle_kind: str = "d10.life_progress_effect_experience.v1"
    member_domains: tuple[str, ...] = ("d02", "d06", "d10")

    def __post_init__(self):
        if (self.bundle_kind not in {"d10.life_progress_effect_experience.v1", "d10.offline_tick_body_experience.v1"}
                or self.member_domains != ("d02", "d06", "d10")
                or self.life_stage.domain != "d10" or self.body_stage.domain != "d02"
                or self.memory_proposal.domain != "d06" or not self.experience_refs
                or any(proposal.envelope != self.envelope for proposal in
                       (*self.life_stage.proposals, *self.body_stage.proposals, self.memory_proposal))):
            raise ValueError("D10 effect/experience bundle requires exact separately issued domain members")


def verify_d10_production_stage_v1(stage):
    if stage.domain != "d10" or stage.operation_kind not in {"advance_life", "advance_offline", "prepare_contact"}:
        raise ValueError("unregistered D10 current stage")
    specs = {spec.name: spec for spec in d10_production_type_specs_v1()}
    for proposal in stage.proposals:
        if proposal.proposal_schema != "d10.proposal.v1" or proposal.proposal_schema_hash != LifeDomain().descriptor.request_schema_hash:
            raise ValueError("D10 current proposal schema differs")
        for write in proposal.typed_writes:
            spec = specs.get(write.key.type_name)
            if spec is None or write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("D10 current operation contains another write type")
            spec.validator(write.value)
    return stage
