"""Explicit Plan2/paid2 whole reviewed content. DTOs do not grant permission."""
from dataclasses import dataclass
import json
from ...graph_types import AtomKey, GraphVersion
from ...runtime_contracts import NamespaceId, canonical_digest
from ..d01.production_operations_v1 import plain_v1
from ..d08.contact_plan_v2 import contact_plan_key_v2
from ..d08.contact_plan_v1 import contact_segment_ids_v1
from . import ClaimKind, ClaimUse, ExpressionClaim, SegmentCandidate, segment_payload_digest

@dataclass(frozen=True, slots=True)
class ContactPaidModelBindingV2:
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

    def __post_init__(self):
        from ...authority_service.contract import identifier
        if (self.phase not in ('contact_generation', 'contact_review') or type(self.job_id) is not str
                or not self.job_id.startswith('contact-model-job-v2:')
                or type(self.cost_revision) is not int or self.cost_revision < 1
                or type(self.original_bindings) is not tuple or len(self.original_bindings) != 7
                or tuple(row[0] for row in self.original_bindings) != ('prepared','prepare_commit','request','call','result','terminal','paid_cost')
                or any(type(row) is not tuple or len(row) != 3 or row[1] != self.job_id for row in self.original_bindings)):
            raise ValueError('Contact2 paid binding lacks its complete seven actual originals')
        for name in ('job_id','prepare_operation_id','call_id','cost_operation_id'):
            identifier(getattr(self,name),name)
        AtomKey.from_token(self.cost_ref)
        digests = (self.prepared_digest,self.frozen_digest,self.output_digest,self.cost_digest,self.cost_receipt_digest,
            *(row[2] for row in self.original_bindings))
        if any(type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value) for value in digests):
            raise ValueError('Contact2 paid binding digest differs')

@dataclass(frozen=True, slots=True)
class ContactReviewedSegmentV2:
    position: int
    operation_id: str
    segment: SegmentCandidate
    payload_digest: str
    prerequisite_segment_ref: str | None
    claims: tuple[ExpressionClaim, ...]

@dataclass(frozen=True, slots=True)
class ContactReviewedContentV2:
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
    generation: ContactPaidModelBindingV2
    review: ContactPaidModelBindingV2
    segments: tuple[ContactReviewedSegmentV2, ...]
    valid_until: float
    cancellation_epoch: int
    purpose: str = "expression"
    schema: str = "d09.contact-reviewed-content.v2"

    def __post_init__(self):
        if (self.schema != 'd09.contact-reviewed-content.v2' or type(self.namespace) is not NamespaceId
                or type(self.plan_version) is not GraphVersion or self.plan_version.key.type_name != 'd08.contact_expression_plan.v2'
                or type(self.plan_version.revision) is not int or self.plan_version.revision != 1
                or NamespaceId.from_key(self.plan_version.key) != self.namespace or self.purpose != 'expression'
                or type(self.generation) is not ContactPaidModelBindingV2 or type(self.review) is not ContactPaidModelBindingV2
                or self.generation.phase != 'contact_generation' or self.review.phase != 'contact_review'
                or type(self.segments) is not tuple or not 1 <= len(self.segments) <= 3
                or any(type(item) is not ContactReviewedSegmentV2 for item in self.segments)):
            raise ValueError('Contact2 content does not bind exact Plan2/paired2/finite segments')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

def prepare_contact_reviewed_content_v2(plan, expression, generation, review, generation_binding, review_binding):
    """Project the parsed complete model output; authenticate inputs separately."""
    from ...model_broker.contact_expression_v2 import parse_contact_generation_output_v2, parse_contact_review_output_v2
    generation_prepared, generation_frozen, generated, _ = generation
    review_prepared, review_frozen, reviewed, _ = review
    if (parse_contact_generation_output_v2(generated.canonical_output_json, generation_frozen) != generated
            or parse_contact_review_output_v2(reviewed.canonical_output_json, review_frozen, generated) != reviewed
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
        segments.append(ContactReviewedSegmentV2(index, ids["operation"], segment,
            segment_payload_digest(segment.body, (), segment.claim_uses),
            None if index == 0 else segments[-1].segment.segment_id, tuple(claims)))
    return ContactReviewedContentV2(plan.namespace, plan.contact_id, plan.activity_id,
        GraphVersion(contact_plan_key_v2(plan), 1), canonical_digest(plain_v1(plan)),
        canonical_digest(plain_v1(expression)), plan.qualified_units_digest, plan.d06_qualification_digests,
        plan.route_binding_digest, plan.audience_id, plan.scene_id, plan.required_slots,
        plan.qualified_read_versions, generation_binding, review_binding, tuple(segments),
        plan.valid_until_utc, plan.cancellation_epoch)
