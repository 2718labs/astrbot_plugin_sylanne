"""Versioned external Contact plan: historical facts and current eligibility.

These public codecs issue no permission. The installed production command
rebuilds the real qualification and writes all three members in one Graph CAS.
"""
from dataclasses import dataclass, fields

from .contact_plan_v1 import AdoptedContactExpressionPlanV1, CONTACT_PLAN_TYPE_V1
from ..d01.production_operations_v1 import plain_v1
from ...graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize, schema_hash
from ...runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1, ProductionQueryCoverageV1
from ...runtime.d10_offline_tick_execution_v1 import OfflineTickGraphReadV1

PLAN = 'd08.contact_expression_plan.v2'
PROVENANCE = 'd08.contact_expression_plan_provenance.v2'
ELIGIBILITY = 'd08.contact_expression_plan_eligibility.v2'
KINDS = frozenset((PLAN,PROVENANCE,ELIGIBILITY))
PROPOSAL_SCHEMA = 'd08.contact-expression-plan-proposal.v2'
CURRENT_TYPES = frozenset(('memory.source','memory.access','d06.source_correction_head.v1',
    'd11.owner_grant.v1','d10.contact_policy.v1','d10.proactive_opportunity.v1',
    'd03.account_binding','d03.entity_anchor','d03.role_binding','d05.boundary_rule',
    'd01.persona_activation.v1','d03.self_identity_mapping.v1','d12.active_scheme_head.v1'))


@dataclass(frozen=True, slots=True)
class AdoptedContactExpressionPlanV2(AdoptedContactExpressionPlanV1):
    def __post_init__(self):
        if self.schema != PLAN:
            raise ValueError('Contact Plan v2 requires its explicit schema')
        # Preserve all business constraints without modifying the V1 codec.
        values={f.name:getattr(self,f.name) for f in fields(AdoptedContactExpressionPlanV1)}
        values['schema']=CONTACT_PLAN_TYPE_V1
        AdoptedContactExpressionPlanV1(**values)
        if type(self.max_segments) is not int:
            raise ValueError('Contact Plan v2 exact segment limit required')


def contact_plan_keys_v2(plan):
    if type(plan) is not AdoptedContactExpressionPlanV2:
        raise TypeError('Contact Plan v2 exact typed plan required')
    owner=Owner('activity',*plan.namespace.as_tuple,plan.activity_id)
    return tuple(AtomKey(owner,kind,plan.plan_id) for kind in (PLAN,PROVENANCE,ELIGIBILITY))


def contact_plan_key_v2(plan):
    return contact_plan_keys_v2(plan)[0]


def decode_contact_plan_v2(raw):
    return decode_contact_plan_member_v2(PLAN,raw)


def _digest(value):
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Contact Plan v2 exact commitment required')


@dataclass(frozen=True, slots=True)
class ContactExpressionPlanProvenanceV2:
    plan: AdoptedContactExpressionPlanV2
    producing_operation_id: str
    activation_generation: int
    graph_incarnation: str
    owner_guard: ProductionOwnerGuardV1
    historical_reads: tuple[OfflineTickGraphReadV1,...]
    current_reads: tuple[OfflineTickGraphReadV1,...]
    query_coverage: tuple[ProductionQueryCoverageV1,...]
    schema: str = PROVENANCE

    def __post_init__(self):
        from ...runtime.contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
        from ..d09.contact_batch_v2 import _reads, _require_source_closure
        if (self.schema!=PROVENANCE or type(self.plan) is not AdoptedContactExpressionPlanV2
                or type(self.producing_operation_id) is not str or not self.producing_operation_id
                or len(self.producing_operation_id)>128
                or type(self.activation_generation) is not int or self.activation_generation<1
                or type(self.graph_incarnation) is not str or not self.graph_incarnation
                or type(self.owner_guard) is not ProductionOwnerGuardV1):
            raise ValueError('Contact Plan v2 provenance scope/producer differs')
        by_ref=_reads(self.historical_reads,self.plan.namespace)
        _require_source_closure(self.historical_reads,self.plan.namespace)
        expected=tuple(row for row in self.historical_reads if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES)
        if canonical_serialize(expected)!=canonical_serialize(self.current_reads):
            raise ValueError('Contact Plan v2 current projection omits necessary frozen reads')
        if (self.owner_guard.grant_ref not in by_ref or self.plan.source_ref.ref not in by_ref
                or self.plan.opportunity_ref.ref not in by_ref or self.plan.route_account_ref.ref not in by_ref):
            raise ValueError('Contact Plan v2 actual Owner/source/plan scope reads missing')
        owner=by_ref[self.owner_guard.grant_ref]
        if (owner.revision!=self.owner_guard.grant_revision or not owner.valid
                or canonical_digest(__import__('json').loads(owner.value_json))!=self.owner_guard.grant_digest):
            raise ValueError('Contact Plan v2 actual Owner original differs')
        if (type(self.query_coverage) is not tuple or len(self.query_coverage)!=len(CONTACT_CURRENT_TYPES)
                or {q.type_id for q in self.query_coverage}!=set(CONTACT_CURRENT_TYPES)
                or any(type(q) is not ProductionQueryCoverageV1 or not q.complete or q.continuation_ref is not None
                    or q.epoch.namespace!=self.plan.namespace for q in self.query_coverage)):
            raise ValueError('Contact Plan v2 bounded complete query coverage required')
        for kind in CONTACT_CURRENT_TYPES:
            queries=[q for q in self.query_coverage if q.type_id==kind]
            if len(queries)!=1:
                raise ValueError('Contact Plan v2 necessary query inventory omitted')
            expected_versions=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision)
                for row in self.historical_reads if AtomKey.from_token(row.ref).type_name==kind and row.revision>0)
            if canonical_serialize(queries[0].row_versions)!=canonical_serialize(expected_versions):
                raise ValueError('Contact Plan v2 actual query inventory drifted')
        for version in self.plan.qualified_read_versions:
            row=by_ref.get(version.key.token)
            if row is None or row.revision!=version.revision:
                raise ValueError('Contact Plan v2 D06 qualification read omitted or changed')

    @property
    def digest(self):return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class ContactExpressionPlanEligibilityV2:
    namespace: NamespaceId
    plan_ref: VersionedRef
    provenance_ref: VersionedRef
    provenance_digest: str
    producing_operation_id: str
    activation_generation: int
    graph_incarnation: str
    current_reads: tuple[OfflineTickGraphReadV1,...]
    schema: str = ELIGIBILITY

    def __post_init__(self):
        from ..d09.contact_batch_v2 import _reads
        if (self.schema!=ELIGIBILITY or type(self.namespace) is not NamespaceId
                or type(self.plan_ref) is not VersionedRef or type(self.provenance_ref) is not VersionedRef
                or type(self.activation_generation) is not int or self.activation_generation<1
                or type(self.producing_operation_id) is not str or not self.producing_operation_id
                or type(self.graph_incarnation) is not str or not self.graph_incarnation):
            raise ValueError('Contact Plan v2 eligibility exact scope differs')
        keys=[AtomKey.from_token(r.ref) for r in (self.plan_ref,self.provenance_ref)]
        if (tuple(k.type_name for k in keys)!=(PLAN,PROVENANCE) or keys[0].owner!=keys[1].owner
                or keys[0].name!=keys[1].name or any(NamespaceId.from_key(k)!=self.namespace for k in keys)
                or any(type(r.version) is not int or r.version!=1 for r in (self.plan_ref,self.provenance_ref))):
            raise ValueError('Contact Plan v2 eligibility refers to wrong immutable members')
        _digest(self.provenance_digest)
        _reads(self.current_reads,self.namespace)


def decode_contact_plan_member_v2(kind,raw):
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    classes={PLAN:AdoptedContactExpressionPlanV2,PROVENANCE:ContactExpressionPlanProvenanceV2,
        ELIGIBILITY:ContactExpressionPlanEligibilityV2}
    if kind not in classes:raise ValueError('Unknown Contact Plan v2 family')
    return decode_typed_production_value_v1(raw,classes[kind])


def contact_plan_writes_v2(proof):
    if type(proof) is not ContactExpressionPlanProvenanceV2:
        raise TypeError('Contact Plan v2 closed provenance required')
    fact, provenance, eligibility=contact_plan_keys_v2(proof.plan)
    current=ContactExpressionPlanEligibilityV2(proof.plan.namespace,VersionedRef(fact.token,1),
        VersionedRef(provenance.token,1),proof.digest,proof.producing_operation_id,
        proof.activation_generation,proof.graph_incarnation,proof.current_reads)
    deps=tuple(sorted({fact,provenance,*(AtomKey.from_token(row.ref) for row in proof.current_reads)},key=lambda k:k.token))
    return (GraphWrite(fact,plain_v1(proof.plan),()),GraphWrite(provenance,plain_v1(proof),()),
        GraphWrite(eligibility,plain_v1(current),deps))


def contact_plan_type_specs_v2():
    return tuple(TypeSpec(kind,('activity',),'state',lambda raw,kind=kind:decode_contact_plan_member_v2(kind,raw),
        immutable=kind!=ELIGIBILITY,writer_domain='d08',schema_version=2,
        schema_hash=schema_hash({'type':kind,'version':2})) for kind in (PLAN,PROVENANCE,ELIGIBILITY))


PROPOSAL_HASH=schema_hash({'schema':PROPOSAL_SCHEMA,'types':tuple(sorted(KINDS)),'version':2})
