"""Metadata-only Contact Plan provenance; current rights remain a separate grant."""
from dataclasses import dataclass
from ..d01.production_operations_v1 import plain_v1
from .contact_plan_v2 import PLAN,CURRENT_TYPES,AdoptedContactExpressionPlanV2
from ...graph_types import AtomKey,GraphVersion,GraphWrite,Owner,TypeSpec
from ...runtime_contracts import NamespaceId,VersionedRef,canonical_digest,schema_hash
from ...runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1,ProductionQueryCoverageV1

PROVENANCE = 'd08.contact_expression_plan_provenance.v3'
ELIGIBILITY = 'd08.contact_expression_plan_eligibility.v3'
PROPOSAL_SCHEMA = 'd08.contact-expression-plan-proposal.v3'
KINDS = frozenset((PLAN,PROVENANCE,ELIGIBILITY))


def _digest(value):
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Contact Plan3 requires an exact SHA256 commitment')


@dataclass(frozen=True,slots=True)
class ContactReadCommitmentV3:
    ref: str
    revision: int
    valid: bool
    origin: str
    codec: str | None
    byte_count: int
    payload_sha256: str | None
    semantic_algorithm: str | None
    semantic_sha256: str | None
    schema: str = 'd08.contact-read-commitment.v3'
    def __post_init__(self):
        key = AtomKey.from_token(self.ref)
        if (self.schema != 'd08.contact-read-commitment.v3' or type(self.revision) is not int or self.revision<0
                or type(self.valid) is not bool or self.origin not in {'graph_atoms','absent'}
                or type(self.byte_count) is not int or self.byte_count<0):
            raise ValueError('Contact Plan3 exact read metadata differs')
        if not self.revision:
            if (self.valid,self.origin,self.codec,self.byte_count,self.payload_sha256,self.semantic_algorithm,self.semantic_sha256) != (
                    False,'absent',None,0,None,None,None):
                raise ValueError('Contact Plan3 negative dependency contains an invented payload')
            return
        if self.origin != 'graph_atoms' or self.codec not in {'canonical-json.ascii.v1','canonical-json.utf8.v1'} or self.byte_count<1:
            raise ValueError('Contact Plan3 physical payload commitment lacks its actual codec/EOF')
        _digest(self.payload_sha256)
        if key.type_name == 'memory.source':
            if self.semantic_algorithm is not None or self.semantic_sha256 is not None:
                raise ValueError('Contact Source commitment cannot substitute a metadata semantic digest for its physical body')
        else:
            if self.semantic_algorithm != 'canonical-json.ascii.v1':
                raise ValueError('Contact nonSource semantic commitment has an unknown algorithm')
            _digest(self.semantic_sha256)


@dataclass(frozen=True,slots=True)
class ContactExpressionPlanProvenanceV3:
    plan: AdoptedContactExpressionPlanV2
    producing_operation_id: str
    activation_generation: int
    graph_incarnation: str
    owner_guard: ProductionOwnerGuardV1
    historical_reads: tuple[ContactReadCommitmentV3,...]
    current_reads: tuple[ContactReadCommitmentV3,...]
    query_coverage: tuple[ProductionQueryCoverageV1,...]
    schema: str = PROVENANCE
    def __post_init__(self):
        from ...runtime.contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
        if (self.schema != PROVENANCE or type(self.plan) is not AdoptedContactExpressionPlanV2
                or type(self.owner_guard) is not ProductionOwnerGuardV1 or not self.producing_operation_id
                or type(self.activation_generation) is not int or self.activation_generation<1 or not self.graph_incarnation
                or type(self.historical_reads) is not tuple or len(self.historical_reads)>1024
                or any(type(row) is not ContactReadCommitmentV3 for row in self.historical_reads)
                or tuple(sorted(row.ref for row in self.historical_reads)) != tuple(row.ref for row in self.historical_reads)
                or len({row.ref for row in self.historical_reads}) != len(self.historical_reads)):
            raise ValueError('Contact Plan3 exact metadata provenance differs')
        by_ref = {row.ref:row for row in self.historical_reads}
        if any(NamespaceId.from_key(AtomKey.from_token(row.ref)) != self.plan.namespace for row in self.historical_reads):
            raise ValueError('Contact Plan3 metadata crossed namespace')
        if tuple(row for row in self.historical_reads if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES) != self.current_reads:
            raise ValueError('Contact Plan3 current metadata omitted its fixed families')
        for version in self.plan.qualified_read_versions:
            row = by_ref.get(version.key.token)
            if row is None or row.revision != version.revision:
                raise ValueError('Contact Plan3 omitted an actual D06 positive/negative read')
        owner = by_ref.get(self.owner_guard.grant_ref)
        if owner is None or (owner.revision,owner.valid,owner.semantic_sha256) != (
                self.owner_guard.grant_revision,True,self.owner_guard.grant_digest):
            raise ValueError('Contact Plan3 metadata lost its actual Owner original')
        if (type(self.query_coverage) is not tuple or len(self.query_coverage) != len(CONTACT_CURRENT_TYPES)
                or {q.type_id for q in self.query_coverage} != set(CONTACT_CURRENT_TYPES)
                or any(type(q) is not ProductionQueryCoverageV1 or not q.complete or q.continuation_ref is not None
                    or q.epoch.namespace != self.plan.namespace for q in self.query_coverage)):
            raise ValueError('Contact Plan3 lacks complete positive/negative namespace query coverage')
        for query in self.query_coverage:
            expected = tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in self.historical_reads
                if row.revision>0 and AtomKey.from_token(row.ref).type_name == query.type_id)
            if expected != query.row_versions:
                raise ValueError('Contact Plan3 query EOF membership differs')
    @property
    def digest(self):
        from ...runtime.contact_plan_physical_write_v3 import contact_plan_provenance_digest_v3
        streamed = contact_plan_provenance_digest_v3(self)
        return streamed if streamed is not None else canonical_digest(plain_v1(self))


@dataclass(frozen=True,slots=True)
class ContactExpressionPlanEligibilityV3:
    namespace: NamespaceId
    plan_ref: VersionedRef
    provenance_ref: VersionedRef
    provenance_digest: str
    producing_operation_id: str
    activation_generation: int
    graph_incarnation: str
    current_reads: tuple[ContactReadCommitmentV3,...]
    schema: str = ELIGIBILITY
    def __post_init__(self):
        keys = tuple(AtomKey.from_token(ref.ref) for ref in (self.plan_ref,self.provenance_ref))
        if (self.schema != ELIGIBILITY or tuple(key.type_name for key in keys) != (PLAN,PROVENANCE)
                or keys[0].owner != keys[1].owner or keys[0].name != keys[1].name
                or any(NamespaceId.from_key(key) != self.namespace for key in keys)
                or (self.plan_ref.version,self.provenance_ref.version) != (1,1)
                or type(self.current_reads) is not tuple or any(type(row) is not ContactReadCommitmentV3 for row in self.current_reads)
                or type(self.activation_generation) is not int or self.activation_generation<1 or not self.graph_incarnation
                or not self.producing_operation_id):
            raise ValueError('Contact Plan3 current eligibility has another immutable lineage')
        _digest(self.provenance_digest)


def contact_plan_keys_v3(plan):
    if type(plan) is not AdoptedContactExpressionPlanV2:
        raise TypeError('Contact Plan3 retains the exact Plan2 business DTO')
    owner = Owner('activity',*plan.namespace.as_tuple,plan.activity_id)
    return tuple(AtomKey(owner,kind,plan.plan_id) for kind in (PLAN,PROVENANCE,ELIGIBILITY))


def contact_plan_writes_v3(proof):
    if type(proof) is not ContactExpressionPlanProvenanceV3:
        raise TypeError('Contact Plan3 requires exact metadata provenance')
    fact,provenance,eligibility = contact_plan_keys_v3(proof.plan)
    current = ContactExpressionPlanEligibilityV3(proof.plan.namespace,VersionedRef(fact.token,1),VersionedRef(provenance.token,1),
        proof.digest,proof.producing_operation_id,proof.activation_generation,proof.graph_incarnation,proof.current_reads)
    deps = tuple(sorted({fact,provenance,*(AtomKey.from_token(row.ref) for row in proof.current_reads)},key=lambda key:key.token))
    return GraphWrite(fact,plain_v1(proof.plan),()),GraphWrite(provenance,plain_v1(proof),()),GraphWrite(eligibility,plain_v1(current),deps)


def decode_contact_plan_member_v3(kind,raw):
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    classes = {PROVENANCE:ContactExpressionPlanProvenanceV3,ELIGIBILITY:ContactExpressionPlanEligibilityV3}
    if kind not in classes:
        raise ValueError('Contact Plan3 has no such versioned metadata family')
    return decode_typed_production_value_v1(raw,classes[kind])


def contact_plan_type_specs_v3():
    return tuple(TypeSpec(kind,('activity',),'state',lambda raw,kind=kind:decode_contact_plan_member_v3(kind,raw),
        immutable=kind!=ELIGIBILITY,writer_domain='d08',schema_version=3,schema_hash=schema_hash({'type':kind,'version':3}))
        for kind in (PROVENANCE,ELIGIBILITY))

PROPOSAL_HASH = schema_hash({'schema':PROPOSAL_SCHEMA,'types':tuple(sorted(KINDS)),'version':3})
