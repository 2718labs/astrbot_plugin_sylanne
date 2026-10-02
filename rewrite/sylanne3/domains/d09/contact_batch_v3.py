"""Versioned Contact historical batch/provenance and current eligibility.

These closed codecs do not issue permission. The installed final stage issues
the three writes from authenticated paid content and an actual qualification.
V1 fields, hashes, freezer and historical decoder remain unchanged.
"""
from dataclasses import dataclass, fields
import json

from .contact_content_v2 import ContactReviewedContentV2
from .contact_batch_v1 import contact_segment_ids_v1
from . import segment_payload_digest
from ..d01.production_operations_v1 import plain_v1
from ..d06 import source_correction_head_key
from ...graph_types import AtomKey, Owner, TypeSpec, GraphWrite, GraphVersion, owner_grant_key
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId, canonical_digest, canonical_serialize, schema_hash
from ...runtime.d10_offline_tick_execution_v1 import OfflineTickGraphReadV1
from ...runtime.contact_qualification_v3 import CurrentContactQualificationV3
from ...runtime.domain_production_contracts_v1 import ProductionQueryCoverageV1

BATCH = 'd09.contact_verified_batch.v3'
PROVENANCE = 'd09.contact_batch_provenance.v3'
ELIGIBILITY = 'd09.contact_batch_eligibility.v3'
KINDS = frozenset((BATCH, PROVENANCE, ELIGIBILITY))
PROPOSAL_SCHEMA = 'd09.contact-final-batch-proposal.v3'
CURRENT_TYPES = frozenset(('memory.source', 'memory.access', 'd06.source_correction_head.v1',
    'd11.owner_grant.v1', 'd08.contact_expression_plan.v2', 'd08.contact_expression_plan_provenance.v2', 'd08.contact_expression_plan_eligibility.v2', 'd10.contact_policy.v1',
    'd10.proactive_opportunity.v1', 'd03.account_binding', 'd03.entity_anchor',
    'd03.role_binding', 'd05.boundary_rule', 'd01.persona_activation.v1',
    'd03.self_identity_mapping.v1', 'd12.active_scheme_head.v1'))


def _sha(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Contact v3 exact digest required')


def contact_batch_keys_v3(namespace, activity_id, contact_id):
    if type(namespace) is not NamespaceId or type(activity_id) is not str or not activity_id:
        raise ValueError('Contact v3 exact namespace/activity required')
    if type(contact_id) is not str or not contact_id.startswith('contact:') or len(contact_id) > 128:
        raise ValueError('Contact v3 contact identity differs')
    owner = Owner('activity', *namespace.as_tuple, activity_id)
    name = 'contact-batch:' + contact_id.removeprefix('contact:')
    return tuple(AtomKey(owner, kind, name) for kind in (BATCH, PROVENANCE, ELIGIBILITY))


@dataclass(frozen=True, slots=True)
class ContactVerifiedBatchV3:
    schema: str
    batch_id: str
    batch_revision: int
    producing_operation_id: str
    content: ContactReviewedContentV2
    reviewed_content_digest: str
    parent_grant_ref: str
    parent_grant_revision: int
    parent_grant_digest: str
    segment_manifest_digest: str

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def validate_contact_verified_batch_v3(raw):
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    batch = decode_typed_production_value_v1(raw, ContactVerifiedBatchV3)
    content = batch.content
    if (batch.schema != BATCH or batch.batch_revision != 1
            or batch.parent_grant_revision != 1 or batch.reviewed_content_digest != content.digest
            or not 1 <= len(content.segments) <= 3
            or content.generation.phase != "contact_generation" or content.review.phase != "contact_review"
            or batch.batch_id != contact_batch_keys_v3(content.namespace, content.activity_id, content.contact_id)[0].name
            or batch.producing_operation_id != content.segments[0].operation_id
            or content.plan_version.revision != 1
            or content.plan_version.key.type_name != "d08.contact_expression_plan.v2"
            or content.purpose != "expression"
            or not content.read_versions or len({row.key for row in content.read_versions}) != len(content.read_versions)
            or sum(len(item.segment.body) for item in content.segments) > 2048):
        raise ValueError("contact batch differs from its fixed whole reviewed scope")
    if type(batch.batch_revision) is not int or type(batch.parent_grant_revision) is not int:
        raise ValueError("Contact3 revisions must be strict integers")
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


def _reads(rows, namespace):
    if (type(rows) is not tuple or not rows or len(rows) > 1024
            or any(type(row) is not OfflineTickGraphReadV1 for row in rows)
            or len({row.ref for row in rows}) != len(rows)
            or tuple(sorted(rows, key=lambda row: row.ref)) != rows
            or any(NamespaceId.from_key(AtomKey.from_token(row.ref)) != namespace for row in rows)):
        raise ValueError('Contact v3 bounded complete read scope differs')
    return {row.ref: row for row in rows}


def _require_source_closure(rows, namespace):
    by_ref = _reads(rows, namespace)
    sources = [row for row in rows if AtomKey.from_token(row.ref).type_name == 'memory.source' and row.revision > 0]
    if not sources:
        raise ValueError('Contact v3 lacks actual Source family')
    for row in sources:
        source = SourceRecord.from_dict(json.loads(row.value_json))
        if AtomKey.from_token(row.ref) != source_key(*namespace.as_tuple, source.source_id) or not row.valid:
            raise ValueError('Contact v3 Source identity/validity differs')
        access = by_ref.get(access_key(*namespace.as_tuple, source.source_id).token)
        correction = by_ref.get(source_correction_head_key(namespace, source.source_id).token)
        if access is None or access.revision < 1 or not access.valid or correction is None:
            raise ValueError('Contact v3 omitted actual Source Access/Correction head')
        permission = json.loads(access.value_json)
        validate_access(permission)
        if permission['source_id'] != source.source_id or permission['status'] != 'active':
            raise ValueError('Contact v3 Source Access identity or withdrawal differs')
        if correction.revision == 0 and (correction.valid or correction.value_json != '{}'):
            raise ValueError('Contact v3 absence is not its actual negative head')
        for parent in source.parent_source_ids:
            original = by_ref.get(source_key(*namespace.as_tuple, parent).token)
            if original is None or original.revision < 1 or not original.valid:
                raise ValueError('Contact v3 omitted a Source ancestor')
    return by_ref


@dataclass(frozen=True, slots=True)
class ContactBatchProvenanceV3:
    batch: ContactVerifiedBatchV3
    activation_generation: int
    graph_incarnation: str
    owner_head_digest: str
    historical_reads: tuple[OfflineTickGraphReadV1, ...]
    current_reads: tuple[OfflineTickGraphReadV1, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    qualification: CurrentContactQualificationV3
    schema: str = PROVENANCE

    def __post_init__(self):
        if type(self.batch) is not ContactVerifiedBatchV3:
            raise TypeError('Contact v3 exact batch required')
        validate_contact_verified_batch_v3(plain_v1(self.batch))
        ns = self.batch.content.namespace
        if (self.schema != PROVENANCE or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(self.graph_incarnation) is not str or not self.graph_incarnation
                or type(self.qualification) is not CurrentContactQualificationV3):
            raise ValueError('Contact v3 producing scope/qualification differs')
        _sha(self.owner_head_digest)
        historical = _require_source_closure(self.historical_reads, ns)
        current = _require_source_closure(self.current_reads, ns)
        expected = tuple(row for row in self.historical_reads if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES)
        if canonical_serialize(plain_v1(self.current_reads)) != canonical_serialize(plain_v1(expected)):
            raise ValueError('Contact v3 current projection is not the complete finite historical selector')
        owner = current.get(owner_grant_key(*ns.as_tuple).token)
        plan = current.get(self.batch.content.plan_version.key.token)
        if (owner is None or owner.revision < 1 or not owner.valid or plan is None or not plan.valid
                or plan.revision != self.batch.content.plan_version.revision):
            raise ValueError('Contact v3 omitted actual Owner/plan heads')
        for kind in ('d08.contact_expression_plan_provenance.v2', 'd08.contact_expression_plan_eligibility.v2'):
            companion = current.get(AtomKey(self.batch.content.plan_version.key.owner, kind,
                self.batch.content.plan_version.key.name).token)
            if companion is None or companion.revision != 1 or not companion.valid:
                raise ValueError('Contact v3 omitted actual Plan2 provenance/eligibility')
        for version in self.batch.content.read_versions:
            actual = historical.get(version.key.token)
            if actual is None or actual.revision != version.revision:
                raise ValueError('Contact v3 proof omitted its paid content read binding')
        from ...runtime.contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
        if (type(self.query_coverage) is not tuple or len(self.query_coverage) != len(CONTACT_FINAL_QUERY_TYPES_V3)
                or {page.type_id for page in self.query_coverage} != set(CONTACT_FINAL_QUERY_TYPES_V3)
                or any(type(page) is not ProductionQueryCoverageV1 or not page.complete or page.continuation_ref is not None
                    or page.epoch.namespace != ns for page in self.query_coverage)):
            raise ValueError('Contact v3 proof lacks complete query inventories')
        epochs = {page.epoch.revision for page in self.query_coverage}
        if len(epochs) != 1 or self.qualification.check_versions.namespace != ns or (
                self.qualification.check_versions.graph_epoch != next(iter(epochs)) + 1
                or self.qualification.owner_policy_digest != self.qualification.check_versions.owner_policy_digest
                or self.qualification.route_semantic_digest != self.batch.content.route_semantic_digest):
            raise ValueError('Contact v3 qualification is not its actual E+1 whole-content scope')
        from ...runtime.contact_final_action_v1 import CONTACT_REQUIRED_PROVIDERS_V1, contact_final_action_ids_v1
        checks = self.qualification.checks
        if (len(checks) != 6 or tuple((c.check_kind, c.issuer) for c in checks) != CONTACT_REQUIRED_PROVIDERS_V1
                or any(c.result != 'pass' or c.coverage != 'full' or c.purpose != 'expression'
                    or c.subject_ref != 'persona:' + ns.persona_id
                    or c.action_ref != contact_final_action_ids_v1(self.batch.content.contact_id, 0)['action'] for c in checks)):
            raise ValueError('Contact v3 lacks the six actual first-segment provider bindings')
        for page in self.query_coverage:
            expected_page = tuple(GraphVersion(AtomKey.from_token(row.ref), row.revision)
                for row in self.historical_reads if row.revision > 0 and AtomKey.from_token(row.ref).type_name == page.type_id)
            if page.row_versions != expected_page:
                raise ValueError('Contact v3 query inventory differs from its complete frozen heads')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class ContactBatchEligibilityV3:
    batch_ref: str
    provenance_ref: str
    provenance_digest: str
    producing_operation_id: str
    activation_generation: int
    graph_incarnation: str
    current_reads: tuple[OfflineTickGraphReadV1, ...]
    schema: str = ELIGIBILITY

    def __post_init__(self):
        key = AtomKey.from_token(self.batch_ref)
        if (self.schema != ELIGIBILITY or key.type_name != BATCH
                or self.provenance_ref != AtomKey(key.owner, PROVENANCE, key.name).token
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or type(self.producing_operation_id) is not str or not self.producing_operation_id
                or type(self.graph_incarnation) is not str or not self.graph_incarnation):
            raise ValueError('Contact v3 eligibility exact fact/scope differs')
        _sha(self.provenance_digest)
        _require_source_closure(self.current_reads, NamespaceId.from_key(key))


def contact_batch_writes_from_proof_v3(proof):
    if type(proof) is not ContactBatchProvenanceV3:
        raise TypeError('Contact v3 exact historical proof required')
    batch = proof.batch
    keys = contact_batch_keys_v3(batch.content.namespace, batch.content.activity_id, batch.content.contact_id)
    eligible = ContactBatchEligibilityV3(keys[0].token, keys[1].token, proof.digest, batch.producing_operation_id,
        proof.activation_generation, proof.graph_incarnation, proof.current_reads)
    deps = tuple(dict.fromkeys((*keys[:2], *(AtomKey.from_token(row.ref) for row in proof.current_reads))))
    return (GraphWrite(keys[0], plain_v1(batch)), GraphWrite(keys[1], plain_v1(proof)),
        GraphWrite(keys[2], plain_v1(eligible), deps))


def decode_contact_batch_companion_v3(kind, raw):
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if kind == BATCH:
        return validate_contact_verified_batch_v3(raw)
    cls = {PROVENANCE: ContactBatchProvenanceV3, ELIGIBILITY: ContactBatchEligibilityV3}.get(kind)
    if cls is None:
        raise ValueError('unknown Contact v3 family')
    return decode_typed_production_value_v1(raw, cls)


PROPOSAL_HASH = schema_hash({'schema': PROPOSAL_SCHEMA, 'types': tuple(sorted(KINDS)),
    'proof_fields': tuple(field.name for field in fields(ContactBatchProvenanceV3))})


def contact_batch_type_specs_v3():
    classes = {BATCH: ContactVerifiedBatchV3, PROVENANCE: ContactBatchProvenanceV3, ELIGIBILITY: ContactBatchEligibilityV3}
    return tuple(TypeSpec(kind, ('activity',), 'projection' if kind == ELIGIBILITY else 'source',
        lambda value, kind=kind: decode_contact_batch_companion_v3(kind, value), immutable=kind != ELIGIBILITY,
        writer_domain='d09', schema_version=3,
        schema_hash=schema_hash({'type': kind, 'fields': tuple(field.name for field in fields(cls))}))
        for kind, cls in classes.items())


def validate_contact_batch_proposal_v3(proposal):
    """Closed same-proposal shape; the GCP separately authenticates issuance."""
    from ...runtime_contracts import DomainProposal
    if type(proposal) is not DomainProposal or (proposal.domain, proposal.proposal_schema,
            proposal.proposal_schema_hash) != ('d09', PROPOSAL_SCHEMA, PROPOSAL_HASH):
        raise ValueError('Contact v3 proposal requires its explicit version')
    writes = {write.key.type_name: write for write in proposal.typed_writes}
    if len(proposal.typed_writes) != 3 or set(writes) != KINDS:
        raise ValueError('Contact v3 proposal lacks its exact three families')
    proof = decode_contact_batch_companion_v3(PROVENANCE, writes[PROVENANCE].value)
    expected = contact_batch_writes_from_proof_v3(proof)
    if canonical_serialize(proposal.typed_writes) != canonical_serialize(expected):
        raise ValueError('Contact v3 fact/proof/eligibility pairing differs')
    authority, identity = proposal.envelope.authority, proposal.envelope.identity
    if ((proof.batch.content.namespace, proof.batch.content.activity_id, proof.batch.producing_operation_id)
            != (authority.namespace, identity.activity_id, identity.operation_id)
            or proof.activation_generation != authority.activation_generation):
        raise ValueError('Contact v3 proposal scope/generation/producing operation differs')
    return proposal
