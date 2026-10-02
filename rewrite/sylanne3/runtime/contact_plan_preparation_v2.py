"""Independent Plan B preparation; all existing current qualifications remain.

This version consumes the actual ProductionOriginalRefV1 contract and emits
no invalidating immutable fact. The installed V2 stage alone builds its
three same-transaction members and authenticated provenance.
"""
from ..domains.d06.qualified_expression import QualifiedExpressionRequest, SourceTextSpan, prepare_qualified_expression_unit
from ..domains.d08.contact_plan_v2 import PLAN, AdoptedContactExpressionPlanV2, contact_plan_key_v2
from ..domains.d08.contact_plan_v1 import contact_ids_v1
from ..domains.d09 import ClaimKind
from ..domains.d09.natural_reply import NaturalExpressionPlanV2, QualifiedExpressionUnitV2
from ..runtime_contracts import VersionedRef, canonical_digest
from .budget import get_budget_lease, require_budget_family_admissible
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .contact_route_binding_v1 import read_current_contact_route_binding_v1, contact_route_semantic_digest_v1

def prepare_contact_plan_in_transaction_v2(db, *, frame, request, installed_readers, installed_bundle, issuer):
    from .contact_plan_adoption_v2 import AdoptCurrentContactExpressionPlanRequestV2
    from .d10_production_operations_v1 import InstalledD10ProductionReadersV1
    from ..memory_types import SourceRecord
    if type(request) is not AdoptCurrentContactExpressionPlanRequestV2 or type(installed_readers) is not InstalledD10ProductionReadersV1:
        raise TypeError("actual installed contact readers and locator request required")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    inputs = installed_readers.read_contact(db, frame, request)
    if inputs.candidate.status != "policy_candidate":
        raise MissingProductionOriginalV1("current_contact_opportunity_and_owner_policy")
    ns, now = frame.envelope.authority.namespace, frame.now_utc
    if frame.envelope.authority.purpose != "expression" or len(frame.envelope.authority.audience) != 1:
        raise ValueError("contact plan must use its actual current expression audience")
    opportunity = read.head(db, request.opportunity_ref, required=True)
    source = read.head(db, opportunity.value["source_ref"], required=True)
    read.source_family(db, (source.key.token,), purpose="expression")
    source_record = SourceRecord.from_dict(source.value)
    if source_record.source_kind == "internal":
        raise MissingProductionOriginalV1("installed_internal_activity_expression_qualification")
    if not source_record.text or len(source_record.text.encode("utf-8")) > 65536:
        raise MissingProductionOriginalV1("bounded_nonempty_expressible_source")
    cause = read.original(source.key.token)
    policy_original = inputs.policy_original
    audience = frame.envelope.authority.audience[0]
    route = read_current_contact_route_binding_v1(db, read, account_ref=request.target_route_ref,
        target_entity_ref=opportunity.value["subject_ref"], audience=audience)
    generation, review = installed_bundle.model_workflows.contact_generation, installed_bundle.model_workflows.contact_review
    if generation is None or review is None:
        raise MissingProductionOriginalV1("installed_contact_generation_and_review")
    grant = issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
    lease = get_budget_lease(db, grant.lease_id)
    require_budget_family_admissible(db, lease.lease_id)
    if (installed_bundle.installation_policy.namespace != ns or grant != installed_bundle.installation_policy.root_grant
            or lease.state != "active" or audience not in generation.audiences or audience not in review.audiences
            or not {"contact_generation", "contact_review"}.issubset(grant.allowed_work_kinds)
            or any(generation.quote_ceiling.get(k, 0) + review.quote_ceiling.get(k, 0) > lease.available(k)
                   for k in set(generation.quote_ceiling) | set(review.quote_ceiling))):
        raise MissingProductionOriginalV1("current_finite_contact_model_budget")
    ids = contact_ids_v1(ns, cause.original_ref, route.target_entity_ref, "private_text")
    expires = min(frame.envelope.deadline_utc, opportunity.value["expires_at"],
        inputs.candidate.check.valid_until, grant.valid_until_utc)
    if expires <= now + generation.timeout_seconds + review.timeout_seconds:
        raise MissingProductionOriginalV1("contact_two_stage_deadline")
    guard = frame.envelope.version_guard
    candidate = prepare_qualified_expression_unit(frame.snapshot, namespace=ns,
        request=QualifiedExpressionRequest(source.key.token, "attributed_report", SourceTextSpan(0, len(source_record.text))),
        audiences=(audience,), access_epoch=guard.access_epoch, deletion_epoch=guard.delete_epoch, valid_until=expires)
    versions = {row.key.token: row.revision for row in candidate.read_versions}
    unit = QualifiedExpressionUnitV2("basis:contact-source", ClaimKind.REPORTED_CLAIM, candidate.source_excerpt, None,
        tuple(VersionedRef(ref, versions[ref]) for ref in candidate.lineage_source_refs),
        tuple(VersionedRef(row.key.token, row.revision) for row in candidate.read_versions if row.key.type_name == "memory.access"),
        tuple(VersionedRef(row.key.token, row.revision) for row in candidate.read_versions if row.key.type_name == "d06.source_correction_head.v1"),
        audience, "expression", expires, speaker_id=candidate.speaker_id, content_reality="external_report",
        qualification_digest=candidate.qualification_digest, occurred_at=candidate.occurred_at, learned_at=candidate.learned_at,
        source_kind=candidate.source_kind, assertion_status=candidate.assertion_status, d06_claim_kind=candidate.claim_kind,
        attribution_required=candidate.attribution_required, polarity_status=candidate.polarity_status,
        source_excerpt=candidate.source_excerpt, evidence_span=(candidate.evidence_span.start, candidate.evidence_span.end))
    content_types = {"memory.source", "memory.access", "d06.source_correction_head.v1", "d03.entity_anchor",
        "d03.account_binding", "d03.world_event", "d10.contact_policy.v1", "d10.proactive_opportunity.v1",
        "d10.contact_claim.v1", "d10.contact_claim.v2", "d05.boundary_rule", "d11.owner_grant.v1"}
    reads = tuple(sorted(set((*(row for row in frame.snapshot.versions if row.key.type_name in content_types
                              and (row.revision == 0 or frame.snapshot.get(row.key).valid)),
                              *candidate.read_versions)), key=lambda row: row.key.token))
    plan = AdoptedContactExpressionPlanV2(PLAN, ns, ids["plan"], ids["contact"], ids["activity"],
        cause.original_ref, cause.original_digest, VersionedRef(opportunity.key.token, opportunity.revision),
        VersionedRef(source.key.token, source.revision), route.target_entity_ref,
        VersionedRef(route.account_version.key.token, route.account_version.revision), contact_route_semantic_digest_v1(route), route.scene_ref, audience,
        policy_original.original_ref, policy_original.original_digest, inputs.candidate.check.policy_version,
        ("contact",), ("paraphrase",), canonical_digest((unit,)), (candidate.qualification_digest,), reads,
        grant.lease_id, grant.version, canonical_digest(grant), "contact-generation-reservation:" + ids["contact"][8:],
        "contact-review-reservation:" + ids["contact"][8:], tuple(sorted(generation.quote_ceiling.items())),
        tuple(sorted(review.quote_ceiling.items())), 3, 2048, 0, expires)
    key = contact_plan_key_v2(plan)
    expression = NaturalExpressionPlanV2(ns, VersionedRef(key.token, 1),
        VersionedRef(route.evidence_version.key.token, route.evidence_version.revision),
        VersionedRef(route.account_version.key.token, route.account_version.revision), ("contact",), ("paraphrase",), (),
        (unit,), expires, ids["activity"], ids["action"], "contact-batch:" + ids["contact"][8:], route.scene_ref, audience)
    return plan, expression
