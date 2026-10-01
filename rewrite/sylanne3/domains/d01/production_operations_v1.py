"""D01 current value and natural-growth issuers.

The inputs below are obtained by the installed reader, never by decoding a
public command as evidence.  These functions calculate candidates; W01 owns
the Owner fence, current originals, atomic CAS and the final receipt.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Mapping

from ...authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite
from ...runtime_contracts import DependencySet, DomainProposal, canonical_digest, canonical_serialize
from ...runtime.domain_production_contracts_v1 import (
    CurrentOperationFrameV1, ProductionOriginalRefV1, ProductionOutboxStageV1,
    StagedDomainOperationV1,
)
from ...runtime.jobs import PersistentJob
from . import GrowthProposal, PersonaDomain, PersonaPlan


def plain_v1(value):
    """JSON projection without changing the canonical public wire encoder."""
    if isinstance(value, AtomKey):
        return value.token
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        return str(value)
    if is_dataclass(value):
        return {field.name: plain_v1(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {key: plain_v1(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [plain_v1(item) for item in value]
    return value


def require_locator_v1(value, name):
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError(name + " must be a bounded original locator")


def current_frame_guard_v1(frame):
    if type(frame) is not CurrentOperationFrameV1:
        raise TypeError("installed current production frame required")
    ns = frame.envelope.authority.namespace
    if (len(frame.snapshot.epochs) != 1
            or (frame.snapshot.epochs[0].bot, frame.snapshot.epochs[0].persona) != ns.as_tuple
            or len({atom.key for atom in frame.snapshot.atoms}) != len(frame.snapshot.atoms)
            or not set(frame.snapshot.versions) <= set(frame.envelope.version_guard.read_versions)):
        raise ValueError("production frame is outside the command CAS read set")


def pending_job_v1(frame, domain, kind, request, *, reason, original_digest):
    """A waiting job has no execution grant and consumes no worker slot."""
    envelope, ns = frame.envelope, frame.envelope.authority.namespace
    ref = domain + "-pending:" + canonical_digest((ns, envelope.identity.operation_id,
        domain, kind, "waiting-original"))[:48]
    resource = (envelope.version_guard.resource_lease_versions[0].ref
                if envelope.version_guard.resource_lease_versions else "resource:unallocated")
    return PersistentJob(ref, envelope.identity.operation_id, envelope.identity.activity_id,
        envelope.identity.effect_id, *ns.as_tuple, ref, "waiting", domain + "." + kind,
        {"request": plain_v1(request), "input_digest": original_digest, "original_ref": ref},
        {"kind": "original_available", "reason": reason},
        datetime.fromtimestamp(envelope.deadline_utc, timezone.utc).isoformat().replace("+00:00", "Z"),
        envelope.parent_budget_lease_ref, resource, {"schema": "v1"}, None, None, 0, 0, {}, None)


def stage_result_v1(frame, domain, kind, request, *, writes=(), provenance=None,
                    contribution_keys=(), receiver_events=(), costs=(),
                    coverage="complete", missing=(), continuation=None, jobs=(),
                    proposal_schema=None, proposal_hash=None, required_parts=()):
    """Bounded staging assembly, with no generic writer/adoption capability."""
    current_frame_guard_v1(frame)
    envelope, ns = frame.envelope, frame.envelope.authority.namespace
    guarded = {version.key for version in envelope.version_guard.read_versions}
    if (len(writes) > frame.limits.max_writes
            or any(write.key not in guarded or write.key.owner.bot != ns.bot_id
                   or write.key.owner.persona != ns.persona_id for write in writes)):
        raise ValueError("domain output is not a bounded explicitly CAS-read write set")
    payload = plain_v1({"schema": domain + ".current-" + kind + ".v1", "request": request,
        "namespace": ns, "identity": envelope.identity, "authority": envelope.authority,
        "parent_budget": envelope.parent_budget_lease_ref, "now_utc": frame.now_utc,
        "owner_guard": frame.owner_guard, "policy_refs": frame.installed_policy_refs,
        "read_versions": frame.snapshot.versions, "query_coverage": frame.query_coverage,
        "observed_originals": frame.observed_originals, "provenance": provenance or {},
        "writes": writes, "coverage": coverage, "missing_inputs": missing,
        "continuation_ref": continuation})
    digest = canonical_digest(payload)
    original = ProductionOriginalRefV1(domain + ".current-" + kind,
        domain + "-current:" + digest[:48], digest, frame.snapshot.versions)
    proposals = ()
    if writes:
        if not proposal_schema or not proposal_hash:
            raise ValueError("domain proposal requires its actual installed schema")
        current_keys = {key for write in writes for key in write.dependencies}
        dependencies = DependencySet(current_invalidation=tuple(
            version for version in frame.snapshot.versions if version.key in current_keys),
            historical_provenance=tuple(version for version in frame.snapshot.versions
                if version.key.type_name == "memory.source" and version.revision > 0))
        if {version.key for version in dependencies.current_invalidation} != current_keys:
            raise ValueError("domain output invalidation dependency lacks its actual CAS read")
        proposals = (DomainProposal(domain, proposal_schema, proposal_hash, envelope,
            tuple(writes), dependencies, tuple(contribution_keys), tuple(required_parts)),)
    outbox = tuple(ProductionOutboxStageV1(ns, envelope.identity.operation_id,
        receiver, event, original) for receiver, event in receiver_events)
    return StagedDomainOperationV1(domain, kind, ns, envelope.identity.activity_id,
        envelope.identity.operation_id, canonical_digest({"request": request, "envelope": envelope}),
        frame.snapshot.versions, frame.query_coverage, proposals, tuple(jobs), outbox,
        canonical_serialize(payload), digest, tuple(costs), coverage, tuple(missing), continuation)


@dataclass(frozen=True, slots=True)
class EvaluateCurrentValuesRequestV1:
    candidate_set_ref: str
    context_ref: str

    def __post_init__(self):
        require_locator_v1(self.candidate_set_ref, "candidate_set_ref")
        require_locator_v1(self.context_ref, "context_ref")


@dataclass(frozen=True, slots=True)
class AdoptCurrentGrowthRequestV1:
    growth_proposal_ref: str
    trigger_original_ref: str
    trial_original_refs: tuple[str, ...]
    counterevidence_query_ref: str

    def __post_init__(self):
        for name in ("growth_proposal_ref", "trigger_original_ref", "counterevidence_query_ref"):
            require_locator_v1(getattr(self, name), name)
        if (type(self.trial_original_refs) is not tuple or len(self.trial_original_refs) > 16
                or len(set(self.trial_original_refs)) != len(self.trial_original_refs)):
            raise ValueError("growth trials must be unique bounded original locators")
        for ref in self.trial_original_refs:
            require_locator_v1(ref, "trial original")


@dataclass(frozen=True, slots=True)
class CurrentValuesInputsV1:
    plan: PersonaPlan
    owner_guard: OwnerAuthorizationGuardV1
    candidates: tuple[tuple[str, tuple[str, ...]], ...]
    context_tags: tuple[str, ...]
    role_binding_complete: bool
    candidate_original: ProductionOriginalRefV1
    context_original: ProductionOriginalRefV1


@dataclass(frozen=True, slots=True)
class CurrentGrowthInputsV1:
    proposal: GrowthProposal
    source_ids: tuple[str, ...]
    owner_guard: OwnerAuthorizationGuardV1
    originals: tuple[ProductionOriginalRefV1, ...]
    trials_complete: bool
    counterevidence_complete: bool
    counterevidence_conflict: bool
    paid_cost_originals: tuple[ProductionOriginalRefV1, ...] = ()


def compile_evaluate_current_values_v1(frame, request, inputs):
    if type(request) is not EvaluateCurrentValuesRequestV1 or type(inputs) is not CurrentValuesInputsV1:
        raise TypeError("exact D01 values request and current inputs required")
    current_frame_guard_v1(frame)
    domain = PersonaDomain()
    active = domain.resolve_active_role(frame.snapshot,
        namespace=frame.envelope.authority.namespace, current_guard=inputs.owner_guard)
    if active.plan != inputs.plan or len(inputs.candidates) > frame.limits.max_query_rows:
        raise ValueError("current values plan/candidate coverage changed")
    candidates = dict(inputs.candidates)
    if len(candidates) != len(inputs.candidates):
        raise ValueError("candidate IDs repeat")
    view = domain.project(active.plan, context_tags=inputs.context_tags,
                          role_binding_complete=inputs.role_binding_complete)
    evaluation = domain.evaluate_values(view, candidates)
    return stage_result_v1(frame, "d01", "evaluate_values", request,
        provenance={"persona_view": view, "candidate_original": inputs.candidate_original,
                    "context_original": inputs.context_original, "evaluation": evaluation},
        receiver_events=(("d08", "values_evaluated"),))


def compile_adopt_current_growth_v1(frame, request, inputs):
    if type(request) is not AdoptCurrentGrowthRequestV1 or type(inputs) is not CurrentGrowthInputsV1:
        raise TypeError("exact D01 growth request and current inputs required")
    current_frame_guard_v1(frame)
    missing = tuple(name for name, complete in (("completed_growth_trials", inputs.trials_complete),
        ("complete_current_counterevidence_query", inputs.counterevidence_complete)) if not complete)
    if missing or inputs.counterevidence_conflict:
        reason = "counterevidence_disputed" if inputs.counterevidence_conflict else missing[0]
        continuation = "d01-growth-pending:" + canonical_digest((request, frame.envelope.identity))[:48]
        digest = canonical_digest((request, inputs.proposal, inputs.originals))
        job = pending_job_v1(frame, "d01", "growth", request, reason=reason, original_digest=digest)
        return stage_result_v1(frame, "d01", "adopt_growth", request,
            provenance={"proposal": inputs.proposal, "originals": inputs.originals},
            coverage="waiting_for_original", missing=missing or (reason,),
            continuation=continuation, jobs=(job,), costs=inputs.paid_cost_originals)
    domain = PersonaDomain()
    # The original D01 issuer uses missing get() to denote an unconsumed
    # contribution; the production frame additionally carries explicit
    # revision-zero CAS heads. Keep those reads on the stage, and remove only
    # those absent contribution heads from the issuer's semantic snapshot.
    semantic_snapshot = GraphSnapshot(tuple(atom for atom in frame.snapshot.atoms
        if not (atom.key.type_name == "d01.growth_contribution.v1" and atom.revision == 0)),
        frame.snapshot.epochs, frame.snapshot.ingress_receipts, frame.snapshot.scene_proofs)
    candidate = domain.issue_growth_candidate(semantic_snapshot,
        namespace=frame.envelope.authority.namespace, current_guard=inputs.owner_guard,
        proposal=inputs.proposal, source_ids=inputs.source_ids)
    domain.validate_growth_candidate(candidate, semantic_snapshot,
        namespace=frame.envelope.authority.namespace, current_guard=inputs.owner_guard,
        proposal=inputs.proposal, source_ids=inputs.source_ids)
    return stage_result_v1(frame, "d01", "adopt_growth", request,
        writes=candidate.typed_writes, provenance={"candidate": candidate, "originals": inputs.originals},
        contribution_keys=tuple(domain.contribution_key(inputs.proposal.target_block, family,
            inputs.proposal.change_kind) for family in inputs.proposal.source_families),
        receiver_events=(("d08", "persona_growth_requires_commitment_reevaluation"),
                         ("d10", "persona_growth_requires_life_reevaluation")),
        costs=inputs.paid_cost_originals, proposal_schema="d01.proposal.v1",
        proposal_hash=domain.descriptor.request_schema_hash)


D01_PRODUCTION_WRITE_TYPES_V1 = frozenset({"d01.persona_plan.v1", "d01.persona_revision.v1",
    "d01.persona_activation.v1", "d01.growth_contribution.v1"})


def verify_d01_production_stage_v1(stage):
    """Closed sanctioned growth gate; it does not change ordinary validation."""
    if type(stage) is not StagedDomainOperationV1 or stage.domain != "d01":
        raise TypeError("D01 current stage required")
    if stage.operation_kind not in {"evaluate_values", "adopt_growth"}:
        raise ValueError("unregistered D01 current operation")
    specs = {spec.name: spec for spec in PersonaDomain().type_specs()}
    for proposal in stage.proposals:
        if stage.operation_kind != "adopt_growth" or proposal.proposal_schema != "d01.proposal.v1":
            raise ValueError("values evaluation cannot change persona state")
        for write in proposal.typed_writes:
            if write.key.type_name not in D01_PRODUCTION_WRITE_TYPES_V1 or write.key.owner.kind != "persona":
                raise ValueError("D01 current growth contains another write type")
            specs[write.key.type_name].validator(write.value)
    return stage
