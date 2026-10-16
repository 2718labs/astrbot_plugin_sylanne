"""Actual fixed mesh metadata consumers around existing qualified domain computations."""
from dataclasses import dataclass, replace

from ..runtime_contracts import canonical_digest
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .domain_mesh_contract_v1 import (
    DomainMeshEnvelopeV1, MeshPayloadRefV1, DomainProjectionRequestV1,
    DomainProjectionResultV1, DomainEvidenceNoticeV1, DomainOutcomeV1,
)
from .domain_mesh_catalog_v1 import require_domain_mesh_route_v1, require_semantic_recipe_operation_v1


def _variant(envelope):
    require_domain_mesh_route_v1(envelope.route)
    if envelope.route.kind == "projectionRequest":
        return DomainProjectionRequestV1(envelope)
    if envelope.route.kind == "projectionResult":
        return DomainProjectionResultV1(envelope)
    if envelope.route.kind == "evidenceNotice":
        return DomainEvidenceNoticeV1(envelope)
    return DomainOutcomeV1(envelope)


def assemble_current_domain_mesh_message_v1(facts):
    """Called inside the same qualified Source Work; the envelope is not a capability."""
    from .semantic_recovery_source_v3 import require_semantic_recovery_qualified_facts_v3
    require_semantic_recovery_qualified_facts_v3(facts)
    tick = facts.tick
    profile = require_semantic_recipe_operation_v1(tick.recipe_version, facts.producer_operation_kind)
    if (type(facts.producer_original) is not ProductionOriginalRefV1
            or facts.producer_original.kind != profile.domain + ".current-" + profile.operation_kind
            or facts.producer_operation_id != tick.producer_operation_id or tick.purpose != profile.purpose):
        raise ValueError("mesh message changed its actual fixed producer original or purpose")
    envelope = DomainMeshEnvelopeV1(namespace=facts.namespace, route=profile.route,
        causal_root=tick.causal_original,
        parent_stage=tick.predecessors[-1] if tick.predecessors else tick.causal_original,
        request_ref=tick.causal_original.original_ref,
        correlation_ref=tick.causal_original.original_ref,
        payload=MeshPayloadRefV1(profile.route.schema, facts.producer_original.original_ref,
            facts.producer_original.original_digest),
        producer_original=facts.producer_original, producer_operation_id=facts.producer_operation_id,
        producer_receipt_digest=facts.producer_receipt_digest, reality="derived",
        qualification="adopted", coverage="complete", read_versions=facts.read_versions,
        query_coverage=facts.query_coverage, source_roots=tick.source_roots,
        source_closure_digest=canonical_digest(facts.source_closure), audience=tick.audience,
        provider_policies=tick.provider_policies, owner_guard=facts.owner_guard,
        activation_generation=facts.activation_generation, storage_generation=facts.storage_generation,
        access_epoch=facts.access_epoch, delete_epoch=facts.delete_epoch,
        cancellation_generations=((tick.causal_original.original_ref, tick.cancellation_generation),),
        parent_budget_lease_ref=tick.parent_budget_lease_ref,
        original_deadline_utc=tick.original_deadline_utc,
        recovery_locator=tick.producer_operation_id)
    return _variant(envelope)


def consume_current_domain_mesh_message_v1(facts, message):
    expected = assemble_current_domain_mesh_message_v1(facts)
    if type(message) is not type(expected) or message != expected:
        raise ValueError("mesh consumer requires this same Work's exact current producer metadata")
    return message


@dataclass(frozen=True, slots=True)
class MeshPersonalProjectionInputV1:
    message: DomainProjectionRequestV1
    original_input: object


@dataclass(frozen=True, slots=True)
class MeshPersonalProjectionOutputV1:
    message: DomainProjectionResultV1
    original_result: object


def _personal_source_closure(wave):
    from ..graph_types import AtomKey
    from ..memory_types import access_key
    from ..domains.d06 import source_correction_head_key
    if not wave.source_refs:
        return ()
    source = AtomKey.from_token(wave.source_refs[0])
    kinds = ("memory.source", access_key(*wave.namespace.as_tuple, source.owner.subject).type_name,
        source_correction_head_key(wave.namespace, source.owner.subject).type_name)
    return tuple(v for v in wave.read_versions if v.key.type_name in kinds)


def _personal_envelope(issued, route, payload, *, producer=None, receipt=None, qualification="candidate"):
    from .personal_candidate_eligibility_v1 import _ISSUED_WAVES, IssuedPersonalEligibilityWaveV1
    if (type(issued) is not IssuedPersonalEligibilityWaveV1 or issued not in _ISSUED_WAVES
            or issued.retention_operation.closed):
        raise ValueError("personal mesh inputs require their actual still-owned retained preparation")
    issued.execution_limit.require_current_v1()
    wave = issued.wave
    producer = issued.prepare_original if producer is None else producer
    receipt = issued.prepare_receipt if receipt is None else receipt
    return DomainMeshEnvelopeV1(namespace=wave.namespace, route=route,
        causal_root=wave.need_original, parent_stage=issued.prepare_original,
        request_ref=issued.prepare_original.original_ref, correlation_ref=canonical_digest(wave),
        payload=payload, producer_original=producer, producer_operation_id=receipt.operation_id,
        producer_receipt_digest=canonical_digest(receipt), reality="derived",
        qualification=qualification, coverage="complete", read_versions=wave.read_versions,
        query_coverage=wave.query_coverage, source_roots=wave.source_refs,
        source_closure_digest=canonical_digest(_personal_source_closure(wave)),
        audience=issued.mesh_audience, provider_policies=wave.policies, owner_guard=wave.owner_guard,
        activation_generation=wave.activation_generation, storage_generation=issued.storage_generation,
        access_epoch=wave.access_epoch, delete_epoch=wave.delete_epoch,
        cancellation_generations=wave.cancel_generations,
        parent_budget_lease_ref=wave.parent_budget_lease_ref,
        original_deadline_utc=wave.original_deadline_utc, recovery_locator=receipt.operation_id)


def issue_personal_mesh_projection_v1(issued, original_input):
    from .personal_candidate_eligibility_v1 import (
        PersonalProjectionRequestMessageV1, PERSONAL_MESH_ROUTES_V1,
    )
    if type(original_input) is not PersonalProjectionRequestMessageV1:
        raise TypeError("actual registered immutable Personal input required")
    notice_route = next(route for route in PERSONAL_MESH_ROUTES_V1 if route.kind == "evidenceNotice")
    notice = DomainEvidenceNoticeV1(_personal_envelope(issued, notice_route,
        MeshPayloadRefV1(notice_route.schema, issued.prepare_original.original_ref,
            issued.prepare_original.original_digest), qualification="adopted"))
    if notice.envelope.producer_original != issued.prepare_original:
        raise ValueError("projection request lost its actual preparation notice")
    payload = MeshPayloadRefV1(original_input.route.schema,
        "personal-projection-input:" + canonical_digest((original_input.wave_digest, original_input.route.receiver)),
        canonical_digest(original_input.inputs))
    message = DomainProjectionRequestV1(_personal_envelope(issued, original_input.route, payload))
    return MeshPersonalProjectionInputV1(message, original_input)


def compute_registered_mesh_personal_projection_v1(packet):
    from .personal_candidate_eligibility_v1 import compute_registered_personal_projection_v1
    if type(packet) is not MeshPersonalProjectionInputV1:
        raise TypeError("fixed personal mesh request packet required")
    envelope, original = packet.message.envelope, packet.original_input
    if (envelope.route != original.route or envelope.payload.payload_digest != canonical_digest(original.inputs)
            or envelope.correlation_ref != original.wave_digest):
        raise ValueError("mesh request changed its exact retained immutable input")
    result = compute_registered_personal_projection_v1(original)
    payload = MeshPayloadRefV1(result.route.schema,
        "personal-projection-result:" + canonical_digest((result.wave_digest, result.result.domain)),
        canonical_digest((result.result.domain, result.result.input_digest, result.result.statuses)))
    message = DomainProjectionResultV1(replace(envelope, route=result.route, payload=payload,
        qualification="current_projection"))
    return MeshPersonalProjectionOutputV1(message, result)


def consume_registered_mesh_personal_projection_v1(packet, wave):
    if type(packet) is not MeshPersonalProjectionOutputV1:
        raise TypeError("actual fixed Personal projection result required")
    result, envelope = packet.original_result, packet.message.envelope
    if (result.wave_digest != canonical_digest(wave) or envelope.correlation_ref != result.wave_digest
            or envelope.route != result.route or envelope.payload.payload_digest != canonical_digest(
                (result.result.domain, result.result.input_digest, result.result.statuses))):
        raise ValueError("mesh result changed the actual projection or its original wave")
    require_domain_mesh_route_v1(envelope.route)
    return result


def consume_actual_personal_mesh_outcome_v1(issued, result):
    from .personal_candidate_eligibility_v1 import PERSONAL_MESH_ROUTES_V1, ADOPT
    from .domain_production_originals_v1 import _receipt
    receipt = _receipt(result["receipt"])
    if (result["coverage"] != "complete" or result["operation_kind"] != ADOPT
            or receipt.status not in ("committed", "duplicate")):
        raise ValueError("mesh outcome requires its actual independently validated Personal adoption")
    expected = issued.prepare_receipt.operation_id.replace("personal-eligibility-prepare:", "personal-eligibility-adopt:", 1)
    if receipt.operation_id != expected:
        raise ValueError("personal outcome is not the original prepared wave's exact adoption")
    route = next(route for route in PERSONAL_MESH_ROUTES_V1 if route.kind == "outcome")
    producer = ProductionOriginalRefV1("d08.current-" + ADOPT,
        "d08-current:" + result["original_digest"][:48], result["original_digest"])
    envelope = _personal_envelope(issued, route,
        MeshPayloadRefV1(route.schema, producer.original_ref, producer.original_digest),
        producer=producer, receipt=receipt, qualification="adopted")
    return DomainOutcomeV1(envelope)
