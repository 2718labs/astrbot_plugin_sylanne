"""Finite contact content and its exact paired-model and parent-grant bindings.

These graph values record content commitments. W01 and Authority separately
authenticate the model originals and current permission to send each segment.
"""
from dataclasses import dataclass
import json

from ...graph_types import AtomKey, GraphWrite, Owner, GraphVersion
from ...runtime_contracts import NamespaceId, canonical_digest
from ..d01.production_operations_v1 import plain_v1
from ..d08.contact_plan_v1 import contact_plan_key_v1, contact_segment_ids_v1
from ..d08.execution import CommunicationIntentGrant
from . import ClaimKind, ClaimUse, ExpressionClaim, SegmentCandidate, segment_payload_digest

CONTACT_BATCH_SCHEMA_V1 = "d09.contact_verified_batch.v1"


@dataclass(frozen=True, slots=True)
class ContactPaidModelBindingV1:
    phase: str
    job_id: str
    prepare_operation_id: str
    call_id: str
    prepared_digest: str
    frozen_digest: str
    original_bindings: tuple[tuple[str, str, str], ...]
    output_digest: str
    cost_ref: str
    cost_revision: int
    cost_digest: str
    cost_operation_id: str
    cost_receipt_digest: str


@dataclass(frozen=True, slots=True)
class ContactReviewedSegmentV1:
    position: int
    operation_id: str
    segment: SegmentCandidate
    payload_digest: str
    prerequisite_segment_ref: str | None
    claims: tuple[ExpressionClaim, ...]


@dataclass(frozen=True, slots=True)
class ContactReviewedContentV1:
    namespace: NamespaceId
    contact_id: str
    activity_id: str
    plan_version: GraphVersion
    plan_digest: str
    expression_digest: str
    qualified_units_digest: str
    source_qualification_digests: tuple[str, ...]
    route_semantic_digest: str
    audience_id: str
    scene_id: str
    required_slots: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    generation: ContactPaidModelBindingV1
    review: ContactPaidModelBindingV1
    segments: tuple[ContactReviewedSegmentV1, ...]
    valid_until: float
    cancellation_epoch: int
    purpose: str = "expression"

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class ContactVerifiedBatchV1:
    schema: str
    batch_id: str
    batch_revision: int
    producing_operation_id: str
    content: ContactReviewedContentV1
    reviewed_content_digest: str
    parent_grant_ref: str
    parent_grant_revision: int
    parent_grant_digest: str
    segment_manifest_digest: str

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def contact_batch_key_v1(namespace, activity_id, contact_id):
    return AtomKey(Owner("activity", *namespace.as_tuple, activity_id),
        CONTACT_BATCH_SCHEMA_V1, "contact-batch:" + contact_id.removeprefix("contact:"))


def validate_contact_verified_batch_v1(raw):
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    batch = decode_typed_production_value_v1(raw, ContactVerifiedBatchV1)
    content = batch.content
    if (batch.schema != CONTACT_BATCH_SCHEMA_V1 or batch.batch_revision != 1
            or batch.parent_grant_revision != 1 or batch.reviewed_content_digest != content.digest
            or not 1 <= len(content.segments) <= 3
            or content.generation.phase != "contact_generation" or content.review.phase != "contact_review"
            or batch.batch_id != contact_batch_key_v1(content.namespace, content.activity_id, content.contact_id).name
            or batch.producing_operation_id != content.segments[0].operation_id
            or content.plan_version.revision != 1
            or content.plan_version.key.type_name != "d08.contact_expression_plan.v1"
            or content.purpose != "expression"
            or not content.read_versions or len({row.key for row in content.read_versions}) != len(content.read_versions)
            or sum(len(item.segment.body) for item in content.segments) > 2048):
        raise ValueError("contact batch differs from its fixed whole reviewed scope")
    covered = set()
    for index, item in enumerate(content.segments):
        ids = contact_segment_ids_v1(content.contact_id, index)
        claims = {claim.claim_id: claim for claim in item.claims}
        prior = None if index == 0 else content.segments[index - 1].segment.segment_id
        if (item.position != index or item.operation_id != ids["operation"]
                or (item.segment.segment_id, item.segment.effect_id) != (ids["segment"], ids["effect"])
                or item.prerequisite_segment_ref != prior or item.segment.media_refs or item.segment.delay_seconds != 0.0
                or item.payload_digest != segment_payload_digest(item.segment.body, (), item.segment.claim_uses)
                or not claims or len(claims) != len(item.claims) or not item.segment.claim_uses):
            raise ValueError("contact finite segment manifest changed")
        cursor = 0
        for use in item.segment.claim_uses:
            claim = claims.get(use.claim_ref)
            if (claim is None or claim.kind is not use.asserted_as or claim.allowed_audiences != (content.audience_id,)
                    or not cursor <= use.start < use.end <= len(item.segment.body)
                    or item.segment.body[cursor:use.start].strip()
                    or item.segment.body[use.start:use.end] != claim.text
                    or not set(claim.source_refs).issubset({row.key.token for row in content.read_versions})):
                raise ValueError("contact claimed text or audience changed")
            cursor = use.end
        if item.segment.body[cursor:].strip():
            raise ValueError("contact body has an unqualified text span")
        covered.update(item.segment.covered_slots)
    if not set(content.required_slots).issubset(covered):
        raise ValueError("contact whole batch omitted required slots")
    return batch


def prepare_contact_reviewed_content_v1(plan, expression, generation, review, generation_binding, review_binding):
    """Project the parsed complete model output; authenticate inputs separately."""
    from ...model_broker.contact_expression_v1 import parse_contact_generation_output_v1, parse_contact_review_output_v1
    generation_prepared, generation_frozen, generated, _ = generation
    review_prepared, review_frozen, reviewed, _ = review
    if (parse_contact_generation_output_v1(generated.canonical_output_json, generation_frozen) != generated
            or parse_contact_review_output_v1(reviewed.canonical_output_json, review_frozen, generated) != reviewed
            or reviewed.verdict != "pass" or reviewed.generation_output_digest != generated.output_digest
            or generation_frozen.input.adopted_plan != plan or generation_frozen.input.expression_plan != expression
            or generation_binding.prepared_digest != generation_prepared.digest
            or review_binding.prepared_digest != review_prepared.digest
            or generation_binding.output_digest != generated.output_digest or review_binding.output_digest != reviewed.output_digest):
        raise ValueError("contact content differs from the original reviewed whole generation")
    basis = {unit.basis_id: unit for unit in expression.units}
    segments = []
    for index, raw in enumerate(json.loads(generated.canonical_output_json)["segments"]):
        ids = contact_segment_ids_v1(plan.contact_id, index)
        claims, uses, slots = [], [], set()
        for position, unit in enumerate(raw["units"]):
            selected = tuple(basis[ref] for ref in unit["basis_ids"])
            claim_id = "contact-claim-text:" + canonical_digest((plan.contact_id, index, position, unit))[:48]
            refs = tuple(sorted({ref.ref for candidate in selected for ref in candidate.source_refs}))
            text = raw["body"][unit["start"]:unit["end"]]
            claims.append(ExpressionClaim(claim_id, text, ClaimKind(unit["kind"]), refs,
                (plan.audience_id,), ("expression",), "qualified-contact:" + canonical_digest(selected)))
            uses.append(ClaimUse(claim_id, unit["start"], unit["end"], ClaimKind(unit["kind"])))
            slots.update(unit["slot_ids"])
        segment = SegmentCandidate(ids["segment"], ids["effect"], raw["body"], tuple(uses), tuple(sorted(slots)), (), 0.0)
        segments.append(ContactReviewedSegmentV1(index, ids["operation"], segment,
            segment_payload_digest(segment.body, (), segment.claim_uses),
            None if index == 0 else segments[-1].segment.segment_id, tuple(claims)))
    return ContactReviewedContentV1(plan.namespace, plan.contact_id, plan.activity_id,
        GraphVersion(contact_plan_key_v1(plan), 1), canonical_digest(plain_v1(plan)),
        canonical_digest(plain_v1(expression)), plan.qualified_units_digest, plan.d06_qualification_digests,
        plan.route_binding_digest, plan.audience_id, plan.scene_id, plan.required_slots,
        plan.qualified_read_versions, generation_binding, review_binding, tuple(segments),
        plan.valid_until_utc, plan.cancellation_epoch)


def freeze_contact_verified_batch_v1(content, parent_grant_ref, grant):
    if (type(content) is not ContactReviewedContentV1 or type(grant) is not CommunicationIntentGrant
            or grant.contact_id != content.contact_id or grant.audiences != (content.audience_id,)
            or grant.required_slots != content.required_slots or grant.promise_grants
            or grant.route_binding_digest != content.route_semantic_digest
            or len(grant.segment_grants) != len(content.segments)):
        raise ValueError("contact parent grant differs from the whole reviewed content")
    for item, permitted in zip(content.segments, grant.segment_grants, strict=True):
        if ((permitted.segment_id, permitted.effect_id, permitted.position, permitted.payload_digest,
                permitted.prerequisite_segment_ref) != (item.segment.segment_id, item.segment.effect_id,
                item.position, item.payload_digest, item.prerequisite_segment_ref)
                or permitted.allowed_media or len(item.segment.body) > permitted.max_chars):
            raise ValueError("contact parent grant changed a reviewed segment")
    key = contact_batch_key_v1(content.namespace, content.activity_id, content.contact_id)
    batch = ContactVerifiedBatchV1(CONTACT_BATCH_SCHEMA_V1, key.name, 1, content.segments[0].operation_id,
        content, content.digest, parent_grant_ref, 1, canonical_digest(grant), grant.segment_manifest_digest)
    validate_contact_verified_batch_v1(plain_v1(batch))
    return GraphWrite(key, plain_v1(batch), tuple(row.key for row in content.read_versions if row.revision > 0))
