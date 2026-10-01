"""D05 source-family contributions, explicit boundaries and correction holds."""
from __future__ import annotations

from dataclasses import dataclass, replace

from ...graph_types import AtomKey, GraphSnapshot, GraphWrite, Owner
from ...runtime_contracts import canonical_digest
from ...runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
from ..d01.production_operations_v1 import plain_v1, require_locator_v1, stage_result_v1
from .audience import qualify_contribution_for_audience
from .relationship import BoundaryRule, RelationshipContribution, RelationshipProvider
from .source_correction import compile_d05_source_reevaluation


@dataclass(frozen=True, slots=True)
class AdoptCurrentRelationshipContributionRequestV1:
    trigger_original_ref: str
    subject_entity_ref: str
    dimension: str
    semantics: str
    policy_ref: str

    def __post_init__(self):
        for name in ("trigger_original_ref", "subject_entity_ref", "dimension", "semantics", "policy_ref"):
            require_locator_v1(getattr(self, name), name)
        if not self.subject_entity_ref.startswith("entity:") or self.semantics not in {
                "external_observation", "recollection", "simulation"}:
            raise ValueError("relationship needs exact D03 entity and registered semantics")


@dataclass(frozen=True, slots=True)
class ReviseCurrentBoundaryRequestV1:
    boundary_ref: str
    intent_original_ref: str
    policy_ref: str

    def __post_init__(self):
        for name in ("boundary_ref", "intent_original_ref", "policy_ref"):
            require_locator_v1(getattr(self, name), name)
        if AtomKey.from_token(self.boundary_ref).type_name != "d05.boundary_rule":
            raise ValueError("boundary locator has another type")


@dataclass(frozen=True, slots=True)
class ReevaluateCurrentRelationshipRequestV1:
    correction_head_ref: str

    def __post_init__(self):
        if AtomKey.from_token(self.correction_head_ref).type_name != "d06.source_correction_head.v1":
            raise ValueError("relationship reevaluation needs actual D06 correction head")


@dataclass(frozen=True, slots=True)
class CurrentRelationshipContributionInputsV1:
    contribution: RelationshipContribution
    policy_dimensions: tuple[str, ...]
    policy_semantics: tuple[str, ...]
    trigger_original: ProductionOriginalRefV1
    policy_original: ProductionOriginalRefV1
    entity_original: ProductionOriginalRefV1
    existing_contribution: RelationshipContribution | None


@dataclass(frozen=True, slots=True)
class CurrentBoundaryInputsV1:
    rule: BoundaryRule
    prior_rule: BoundaryRule | None
    intent_original: ProductionOriginalRefV1
    policy_original: ProductionOriginalRefV1
    consent_originals: tuple[ProductionOriginalRefV1, ...]
    policy_dimensions: tuple[str, ...]
    policy_semantics: tuple[str, ...]


def _provider(dimensions, semantics):
    provider = RelationshipProvider()
    provider.compile_scheme({"schema": "d05.relationship.scheme.v1",
        "dimensions": tuple(dimensions), "contribution_semantics": tuple(semantics)}, None)
    return provider


def compile_adopt_current_relationship_contribution_v1(frame, request, inputs):
    if (type(request) is not AdoptCurrentRelationshipContributionRequestV1
            or type(inputs) is not CurrentRelationshipContributionInputsV1):
        raise TypeError("exact current relationship request and inputs required")
    item, ns = inputs.contribution, frame.envelope.authority.namespace
    if (item.owner_persona_ref != "persona:" + ns.persona_id
            or item.subject_entity_ref != request.subject_entity_ref
            or item.target_dimension != request.dimension or item.semantics != request.semantics
            or request.dimension not in inputs.policy_dimensions or request.semantics not in inputs.policy_semantics):
        raise ValueError("relationship current issuer scope or installed dimensions changed")
    key = AtomKey(Owner("relation", *ns.as_tuple, request.subject_entity_ref), "d05.contribution", item.key)
    prior = inputs.existing_contribution
    duplicate = prior == item
    if prior is not None and (prior.key != item.key or item.contribution_revision != prior.contribution_revision + 1):
        if not duplicate:
            raise ValueError("relationship revision must replace the same canonical contribution")
    write = GraphWrite(key, plain_v1(item))
    # The original audience qualifier examines a committed contribution. For
    # preparation use the exact proposed head in the otherwise current view;
    # the runtime independently rereads the family before this compiler.
    from ...graph_types import GraphAtom
    snapshot = GraphSnapshot(tuple(atom for atom in frame.snapshot.atoms if atom.key != key) +
        (GraphAtom(key, item.contribution_revision, write.value),), frame.snapshot.epochs)
    for audience in frame.envelope.authority.audience:
        qualification = qualify_contribution_for_audience(snapshot, item.key, namespace=ns,
            audience=audience, purpose=frame.envelope.authority.purpose)
        if qualification.status != "eligible":
            raise ValueError("relationship audience/source qualification unavailable")
    projection_key = AtomKey(key.owner, "d05.relationship_projection", request.dimension)
    projection = GraphWrite(projection_key, {"subject_entity_ref": request.subject_entity_ref,
        "dimension": request.dimension, "status": "source_qualified"}, (key,))
    writes = () if duplicate else (write, projection)
    provider = _provider(inputs.policy_dimensions, inputs.policy_semantics)
    stage = stage_result_v1(frame, "d05", "adopt_relationship_contribution", request, writes=writes,
        provenance={"contribution": item, "duplicate": duplicate, "trigger": inputs.trigger_original,
            "policy": inputs.policy_original, "entity": inputs.entity_original},
        contribution_keys=() if duplicate else (item.key,),
        receiver_events=() if duplicate else (("d08", "relationship_changed_requires_action_recheck"),),
        proposal_schema="d05.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    for proposal in stage.proposals:
        provider.validate(proposal, frame.snapshot)
    return stage


def compile_revise_current_boundary_v1(frame, request, inputs):
    if type(request) is not ReviseCurrentBoundaryRequestV1 or type(inputs) is not CurrentBoundaryInputsV1:
        raise TypeError("exact current boundary request and inputs required")
    rule, prior, key = inputs.rule, inputs.prior_rule, AtomKey.from_token(request.boundary_ref)
    if (key.owner.kind != "relation" or key.owner.subject != rule.target_entity_ref or key.name != rule.rule_id
            or rule.subject_persona_ref != "persona:" + frame.envelope.authority.namespace.persona_id
            or rule.scope_version != (1 if prior is None else prior.scope_version + 1)):
        raise ValueError("boundary revision identity or current scope changed")
    if rule.basis in {"counterparty_explicit", "mutual_agreement"} and not inputs.consent_originals:
        raise ValueError("explicit/mutual boundary lacks actual qualified consent originals")
    if rule.basis == "mutual_agreement" and (not rule.acknowledged_refs or not rule.communicated_refs):
        raise ValueError("mutual boundary requires real bilateral communication and acknowledgement")
    provider = _provider(inputs.policy_dimensions, inputs.policy_semantics)
    write = GraphWrite(key, plain_v1(rule), tuple(AtomKey.from_token(ref) for ref in rule.source_refs))
    stage = stage_result_v1(frame, "d05", "revise_boundary", request, writes=(write,),
        provenance={"prior_rule": prior, "intent": inputs.intent_original,
            "policy": inputs.policy_original, "consents": inputs.consent_originals},
        receiver_events=(("d08", "boundary_changed_requires_action_recheck"),
                         ("d10", "boundary_changed_requires_contact_recheck")),
        proposal_schema="d05.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    provider.validate(stage.proposals[0], frame.snapshot)
    return stage


def compile_reevaluate_current_relationship_v1(frame, request):
    if type(request) is not ReevaluateCurrentRelationshipRequestV1:
        raise TypeError("exact relationship correction request required")
    candidate = compile_d05_source_reevaluation(frame.snapshot, correction_head_ref=request.correction_head_ref)
    writes = []
    from .relationship import _tuple_payload
    for ref in candidate.affected_current_rule_refs:
        atom = frame.snapshot.get(AtomKey.from_token(ref))
        prior = BoundaryRule(**_tuple_payload(atom.value, "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs"))
        held = replace(prior, status="superseded", scope_version=prior.scope_version + 1,
            source_refs=tuple(dict.fromkeys((*prior.source_refs, candidate.correction_source.key.token))))
        writes.append(GraphWrite(atom.key, plain_v1(held), (candidate.correction_head.key, candidate.correction_source.key)))
    for ref in candidate.blocked_projection_refs:
        atom = frame.snapshot.get(AtomKey.from_token(ref))
        writes.append(GraphWrite(atom.key, {**atom.value, "status": "held_source_correction"},
            (candidate.correction_head.key,)))
    return stage_result_v1(frame, "d05", "reevaluate_relationship", request, writes=tuple(writes),
        provenance={"reevaluation": candidate, "historical_contributions_preserved": candidate.affected_contribution_refs},
        receiver_events=(("d08", "source_correction_requires_boundary_recheck"),
                         ("d10", "source_correction_requires_contact_recheck")),
        proposal_schema="d05.proposal.v1", proposal_hash=RelationshipProvider().descriptor.request_schema_hash)


D05_PRODUCTION_WRITE_TYPES_V1 = frozenset({"d05.contribution", "d05.boundary_rule", "d05.relationship_projection"})


def verify_d05_production_stage_v1(stage):
    if stage.domain != "d05" or stage.operation_kind not in {
            "adopt_relationship_contribution", "revise_boundary", "reevaluate_relationship"}:
        raise ValueError("unregistered D05 current stage")
    specs = {spec.name: spec for spec in RelationshipProvider().type_specs()}
    for proposal in stage.proposals:
        if proposal.proposal_schema != "d05.proposal.v1" or proposal.proposal_schema_hash != RelationshipProvider().descriptor.request_schema_hash:
            raise ValueError("D05 current proposal schema differs")
        for write in proposal.typed_writes:
            if write.key.type_name not in specs or write.key.owner.kind != "relation":
                raise ValueError("D05 current operation contains another graph type")
            specs[write.key.type_name].validator(write.value)
    return stage
