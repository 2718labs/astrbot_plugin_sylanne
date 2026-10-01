"""Pure final-action mapping for one paid, reviewed natural private reply.

The returned objects are proposed graph material. W01 must issue the final
five current checks, adopt the payload-bound grant, and obtain D11 admission
inside its own held transaction before any segment may leave the host.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphVersion
from ...runtime_contracts import canonical_digest
from ..d09 import segment_payload_digest
from ..d09.natural_reply import (
    NaturalExpressionPlanV2, NaturalFinalActionCandidateV2,
    NaturalFinalActionMaterialV2,
)
from .execution import (
    ActionIntent, ActionSchema, BASE_REQUIRED_PROVIDERS,
    CommunicationGrantRequest, CommunicationIntentGrant,
    CommunicationSegmentSpec, SegmentGrant,
)
from .natural_plan import AdoptedNaturalPlanV2


@dataclass(frozen=True, slots=True)
class NaturalFinalCommunicationCandidateV2:
    status: str
    action_intent: ActionIntent | None
    communication_request: CommunicationGrantRequest | None
    communication_grant: CommunicationIntentGrant | None
    missing: tuple[str, ...]


def natural_final_action_parameters_digest_v2(
        material: NaturalFinalActionMaterialV2) -> str:
    """Freeze the exact output-derived body against the preselected effect."""
    if type(material) is not NaturalFinalActionMaterialV2:
        raise TypeError("typed final natural material required")
    return canonical_digest({
        "schema": "sylanne.d08.natural-final-action-parameters.v2",
        "activity_id": material.final_activity_id,
        "operation_id": material.final_operation_id,
        "effect_id": material.final_effect_id,
        "scene_id": material.scene_id,
        "audience_id": material.audience_id,
        "route_binding_digest": material.route_binding_digest,
        "segment_id": material.segment.segment_id,
        "payload_digest": material.payload_digest,
        "required_slots": material.required_slots,
        "qualified_units_digest": material.qualified_units_digest,
    })


def prepare_natural_final_communication_candidate_v2(
    final: NaturalFinalActionCandidateV2, *,
    plan: NaturalExpressionPlanV2, adopted: AdoptedNaturalPlanV2,
    intent: ActionIntent, intent_ref: str, schema: ActionSchema,
    contact_id: str, communication_action_id: str, grant_id: str,
    batch_revision: int, cancellation_epoch: int,
    required_check_refs: tuple[str, ...],
    qualification_receipt_digest: str, valid_until: float,
) -> NaturalFinalCommunicationCandidateV2:
    """Map reviewed final material to one payload-bound D08 candidate.

    The caller must obtain ``final`` by running D09 current qualification and
    Authority paid-result verification in the same W01 final write fence.
    A typed caller-supplied candidate alone never proves paid status.
    """
    def hold(reason: str) -> NaturalFinalCommunicationCandidateV2:
        return NaturalFinalCommunicationCandidateV2("hold", None, None, None,
                                                      (reason,))

    if (type(final) is not NaturalFinalActionCandidateV2
            or final.status != "candidate_hold_w01_final_admission"
            or type(final.material) is not NaturalFinalActionMaterialV2
            or type(plan) is not NaturalExpressionPlanV2
            or type(adopted) is not AdoptedNaturalPlanV2
            or type(intent) is not ActionIntent
            or type(schema) is not ActionSchema):
        return hold("current_paid_final_material_required")
    material = final.material
    if (material.final_activity_id != plan.final_activity_id
            or material.final_operation_id != plan.final_operation_id
            or material.final_effect_id != plan.final_effect_id
            or material.final_activity_id != adopted.final_activity_id
            or material.final_operation_id != adopted.final_operation_id
            or material.final_effect_id != adopted.final_effect_id
            or material.c02_operation_id != adopted.c02_operation_id
            or material.source_ref != adopted.source_ref
            or material.scene_id != plan.scene_id
            or material.audience_id != plan.audience_id
            or material.scene_ref != plan.scene_ref
            or material.audience_ref != plan.audience_ref
            or material.route_binding_digest != adopted.route_binding_digest
            or material.required_slots != plan.required_slots
            or material.qualified_units_digest != adopted.qualified_units_digest
            or material.segment.effect_id != plan.final_effect_id
            or material.payload_digest != segment_payload_digest(
                material.segment.body, material.segment.media_refs,
                material.segment.claim_uses)):
        return hold("plan_route_or_payload_changed")
    if (adopted.status != "scope_adopted_payload_pending"
            or not 0 < valid_until <= adopted.valid_until_utc
            or material.segment.media_refs
            or material.segment.delay_seconds != 0.0
            or adopted.promise_grants
            or "promise" in plan.allowed_speech_acts
            or any(row not in material.current_reads
                   for row in adopted.qualified_read_versions)
            or GraphVersion(AtomKey.from_token(plan.plan_ref.ref),
                            plan.plan_ref.version) not in material.current_reads):
        return hold("single_private_nonpromise_scope_required")
    try:
        key = AtomKey.from_token(intent_ref)
    except (TypeError, ValueError):
        return hold("final_action_graph_ref_required")
    if (key.type_name != "d08.action_intent.v1"
            or key.owner.kind != "activity"
            or key.owner.subject != material.final_activity_id
            or key.name != intent.action_id):
        return hold("final_action_graph_ref_required")
    if (intent.identity.activity_id != material.final_activity_id
            or intent.identity.operation_id != material.final_operation_id
            or intent.identity.effect_id != material.final_effect_id
            or intent.revision != 1
            or intent.action_kind != "communication"
            or intent.purpose != "expression"
            or intent.parameters_digest != natural_final_action_parameters_digest_v2(material)
            or material.final_effect_id not in intent.effect_scope
            or material.source_ref.ref not in intent.source_refs
            or any(source not in intent.source_refs
                   for claim in material.claims for source in claim.source_refs)
            or schema.schema_id != intent.schema_id
            or schema.action_kind != intent.action_kind
            or schema.proactive
            or schema.required_checks != intent.required_checks
            or not set(BASE_REQUIRED_PROVIDERS).issubset({
                (check.check_kind, check.provider_id)
                for check in intent.required_checks
            })
            or any(check.action_ref != intent.action_id
                   or check.purpose != intent.purpose
                   for check in intent.required_checks)):
        return hold("final_action_or_five_check_schema_mismatch")
    if (type(required_check_refs) is not tuple
            or len(required_check_refs) != len(intent.required_checks)
            or len(set(required_check_refs)) != len(required_check_refs)
            or any(type(ref) is not str or not ref.startswith("check:")
                   for ref in required_check_refs)):
        return hold("current_five_check_refs_required")
    claim_kinds = tuple(sorted({claim.kind.value for claim in material.claims}))
    if not claim_kinds:
        return hold("qualified_claim_set_required")
    try:
        segment = SegmentGrant(
            material.segment.segment_id, material.final_effect_id, 0,
            material.payload_digest, len(material.segment.body), (), None,
            required_check_refs, valid_until, cancellation_epoch)
        request = CommunicationGrantRequest(
            communication_action_id, contact_id, batch_revision,
            (material.audience_id,), material.required_slots, claim_kinds,
            (), (CommunicationSegmentSpec(
                segment.segment_id, segment.effect_id, segment.position,
                segment.payload_digest, segment.max_chars,
                segment.allowed_media, segment.prerequisite_segment_ref),),
            cancellation_epoch)
        grant = CommunicationIntentGrant(
            grant_id, communication_action_id, contact_id, batch_revision,
            intent_ref, intent.action_id, intent.revision,
            intent.target_ref, request.audiences, "expression",
            request.required_slots, request.allowed_claim_kinds, (),
            (segment,), qualification_receipt_digest, required_check_refs,
            valid_until, cancellation_epoch,
            route_binding_digest=material.route_binding_digest)
    except (TypeError, ValueError):
        return hold("final_grant_shape_invalid")
    return NaturalFinalCommunicationCandidateV2(
        "candidate_hold_w01_final_admission", intent, request, grant,
        ("w01_current_five_checks", "w01_payload_grant_adoption",
         "d11_final_admission"))


__all__ = [
    "NaturalFinalCommunicationCandidateV2",
    "natural_final_action_parameters_digest_v2",
    "prepare_natural_final_communication_candidate_v2",
]
