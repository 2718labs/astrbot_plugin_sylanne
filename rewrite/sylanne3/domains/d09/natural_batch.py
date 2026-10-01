"""Immutable, paid-identity-bound natural reply batch candidate.

This graph value records reviewed content; it does not prove the Authority
receipt, current source closure, D11 admission, or permission to send.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphWrite, Owner
from ...runtime_contracts import canonical_digest
from ..d08.execution import CommunicationIntentGrant
from . import ClaimKind, ClaimUse, segment_payload_digest
from .natural_reply import NaturalFinalActionCandidateV2, NaturalFinalActionMaterialV2


NATURAL_BATCH_SCHEMA_V2 = "d09.natural_verified_segment_batch.v2"
_FIELDS = frozenset({
    "schema", "version", "batch_id", "batch_digest", "qualification",
    "activity_id", "operation_id", "effect_id", "scene_id", "audience_id",
    "scene_ref", "audience_ref", "route_binding_digest", "source_ref",
    "grant_id", "grant_digest", "action_id", "intent_ref",
    "segment_authorization_ref", "required_check_refs", "valid_until",
    "cancellation_epoch", "required_slots", "qualified_units_digest",
    "current_reads", "paid_review", "claims", "segment",
})
_PAID_FIELDS = (
    "generation_original_operation_id", "generation_call_id",
    "generation_model_call_request_digest", "generation_terminal_receipt_digest",
    "generation_output_digest", "generation_reservation_operation_id",
    "review_original_operation_id", "review_call_id",
    "review_model_call_request_digest", "review_terminal_receipt_digest",
    "review_output_digest", "review_reservation_operation_id",
    "parent_budget_lease_id", "review_policy_version",
    "current_graph_guard_digest",
)


@dataclass(frozen=True, slots=True)
class NaturalVerifiedBatchProposalV2:
    status: str
    write: GraphWrite | None
    missing: tuple[str, ...]


def prepare_natural_verified_batch_proposal_v2(
    final: NaturalFinalActionCandidateV2,
    grant: CommunicationIntentGrant,
) -> NaturalVerifiedBatchProposalV2:
    """Freeze one natural segment plus both original paid job identities."""
    def hold(reason: str) -> NaturalVerifiedBatchProposalV2:
        return NaturalVerifiedBatchProposalV2("hold", None, (reason,))

    if (type(final) is not NaturalFinalActionCandidateV2
            or final.status != "candidate_hold_w01_final_admission"
            or type(final.material) is not NaturalFinalActionMaterialV2
            or type(grant) is not CommunicationIntentGrant):
        return hold("typed_paid_final_material_and_grant_required")
    material = final.material
    segment = material.segment
    paid = material.paid_receipt
    if (paid.verdict != "pass" or paid.namespace.as_tuple
            != (AtomKey.from_token(material.source_ref.ref).owner.bot,
                AtomKey.from_token(material.source_ref.ref).owner.persona)
            or paid.qualified_units_digest != material.qualified_units_digest
            or not material.current_reads
            or len({row.key for row in material.current_reads}) != len(material.current_reads)
            or grant.audiences != (material.audience_id,)
            or grant.route_binding_digest != material.route_binding_digest
            or grant.promise_grants or len(grant.segment_grants) != 1
            or grant.segment_grants[0].segment_id != segment.segment_id
            or grant.segment_grants[0].effect_id != material.final_effect_id
            or grant.segment_grants[0].payload_digest != material.payload_digest
            or grant.required_slots != material.required_slots
            or segment.effect_id != material.final_effect_id
            or segment.media_refs or segment.delay_seconds != 0.0
            or material.payload_digest != segment_payload_digest(
                segment.body, segment.media_refs, segment.claim_uses)):
        return hold("paid_scope_route_or_payload_changed")
    claims = {claim.claim_id: claim for claim in material.claims}
    if (not claims or len(claims) != len(material.claims)
            or not segment.claim_uses
            or any(use.claim_ref not in claims
                   or use.asserted_as is not claims[use.claim_ref].kind
                   or segment.body[use.start:use.end] != claims[use.claim_ref].text
                   for use in segment.claim_uses)
            or any(not set(claim.source_refs).issubset({
                row.key.token for row in material.current_reads})
                for claim in material.claims)
            or any(material.audience_id not in claim.allowed_audiences
                   for claim in material.claims)):
        return hold("current_claim_closure_or_span_changed")
    paid_value = {name: getattr(paid, name) for name in _PAID_FIELDS}
    paid_value["receipt_digest"] = canonical_digest(paid)
    value = {
        "schema": NATURAL_BATCH_SCHEMA_V2, "version": 2,
        "qualification": "paid_reviewed_current_source_hold",
        "activity_id": material.final_activity_id,
        "operation_id": material.final_operation_id,
        "effect_id": material.final_effect_id,
        "scene_id": material.scene_id, "audience_id": material.audience_id,
        "scene_ref": {"ref": material.scene_ref.ref,
                      "version": material.scene_ref.version},
        "audience_ref": {"ref": material.audience_ref.ref,
                         "version": material.audience_ref.version},
        "route_binding_digest": material.route_binding_digest,
        "source_ref": {"ref": material.source_ref.ref,
                       "version": material.source_ref.version},
        "grant_id": grant.grant_id, "grant_digest": canonical_digest(grant),
        "action_id": grant.action_id, "intent_ref": grant.intent_ref,
        "segment_authorization_ref": grant.segment_authorization_ref(segment.segment_id),
        "required_check_refs": list(grant.required_check_refs),
        "valid_until": grant.valid_until,
        "cancellation_epoch": grant.cancellation_epoch,
        "required_slots": list(material.required_slots),
        "qualified_units_digest": material.qualified_units_digest,
        "current_reads": [{"ref": row.key.token, "version": row.revision}
                          for row in material.current_reads],
        "paid_review": paid_value,
        "claims": [{"claim_id": claim.claim_id, "text": claim.text,
                    "kind": claim.kind.value, "source_refs": list(claim.source_refs),
                    "allowed_audiences": list(claim.allowed_audiences),
                    "eligibility": list(claim.eligibility),
                    "disclosure_ref": claim.disclosure_ref}
                   for claim in material.claims],
        "segment": {"segment_id": segment.segment_id,
                    "effect_id": segment.effect_id, "body": segment.body,
                    "payload_digest": material.payload_digest,
                    "claim_uses": [{"claim_ref": use.claim_ref,
                                    "start": use.start, "end": use.end,
                                    "asserted_as": use.asserted_as.value}
                                   for use in segment.claim_uses],
                    "covered_slots": list(segment.covered_slots),
                    "media_refs": [], "position": 0},
    }
    value["batch_id"] = "natural-verified-batch:" + canonical_digest(value)[:48]
    value["batch_digest"] = canonical_digest(value)
    try:
        validate_natural_verified_batch_value_v2(value)
        key = AtomKey(Owner("activity", *paid.namespace.as_tuple,
                            material.final_activity_id),
                      NATURAL_BATCH_SCHEMA_V2, value["batch_id"])
        return NaturalVerifiedBatchProposalV2(
            "candidate_hold_w01_final_admission", GraphWrite(key, value),
            ("authority_paid_original_recheck", "current_source_route_recheck",
             "d11_final_admission"))
    except (TypeError, ValueError):
        return hold("natural_verified_batch_invalid")


def validate_natural_verified_batch_value_v2(value: dict) -> None:
    """Structural TypeSpec validator; provenance remains W01's write-fence duty."""
    if (type(value) is not dict or set(value) != _FIELDS
            or value["schema"] != NATURAL_BATCH_SCHEMA_V2
            or value["version"] != 2
            or value["qualification"] != "paid_reviewed_current_source_hold"):
        raise ValueError("natural batch schema differs")
    for name in ("route_binding_digest", "qualified_units_digest", "grant_digest"):
        digest = value[name]
        if type(digest) is not str or len(digest) != 64:
            raise ValueError("natural batch digest missing")
    paid = value["paid_review"]
    if (type(paid) is not dict or set(paid) != set(_PAID_FIELDS) | {"receipt_digest"}
            or paid["generation_original_operation_id"] == paid["review_original_operation_id"]
            or paid["generation_call_id"] == paid["review_call_id"]
            or paid["generation_reservation_operation_id"]
               == paid["review_reservation_operation_id"]):
        raise ValueError("distinct paid originals required")
    segment = value["segment"]
    if (type(segment) is not dict or set(segment) != {
            "segment_id", "effect_id", "body", "payload_digest",
            "claim_uses", "covered_slots", "media_refs", "position"}
            or segment["position"] != 0 or segment["effect_id"] != value["effect_id"]
            or segment["media_refs"] != [] or type(segment["body"]) is not str
            or not segment["body"] or type(segment["claim_uses"]) is not list):
        raise ValueError("one exact natural segment required")
    uses = tuple(ClaimUse(row["claim_ref"], row["start"], row["end"],
                          ClaimKind(row["asserted_as"]))
                 for row in segment["claim_uses"])
    if segment["payload_digest"] != segment_payload_digest(
            segment["body"], (), uses):
        raise ValueError("natural payload changed")
    if (type(value["claims"]) is not list or not value["claims"]
            or len({claim["claim_id"] for claim in value["claims"]})
               != len(value["claims"])
            or any(use.claim_ref not in {claim["claim_id"] for claim in value["claims"]}
                   for use in uses)
            or type(value["current_reads"]) is not list
            or not value["current_reads"]):
        raise ValueError("natural claim/read closure missing")
    if value["batch_digest"] != canonical_digest({
            key: part for key, part in value.items() if key != "batch_digest"}):
        raise ValueError("natural batch content digest changed")


__all__ = ["NATURAL_BATCH_SCHEMA_V2", "NaturalVerifiedBatchProposalV2",
           "prepare_natural_verified_batch_proposal_v2",
           "validate_natural_verified_batch_value_v2"]
