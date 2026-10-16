"""Closed Contact continuation metadata, prefix rights and immutable segment originals."""
from dataclasses import asdict,dataclass,replace
from contextlib import contextmanager
from weakref import WeakKeyDictionary
from types import MappingProxyType
import json
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..graph_types import AtomKey,GraphVersion,Owner

TABLE='graph_contact_segment_originals_v1'
COLUMNS=('bot','persona','contact_id','segment_index','operation_id','effect_id','payload_json','payload_digest','signature')
SIGN_KIND='d11.contact-segment-original.v1'
DDL=('CREATE TABLE '+TABLE+'(bot TEXT NOT NULL,persona TEXT NOT NULL,contact_id TEXT NOT NULL,segment_index INTEGER NOT NULL '
    'CHECK(segment_index>=0 AND segment_index<3),operation_id TEXT NOT NULL,effect_id TEXT NOT NULL,payload_json TEXT NOT NULL '
    'CHECK(length(CAST(payload_json AS BLOB))<=262144),payload_digest TEXT NOT NULL,signature TEXT NOT NULL,'
    'PRIMARY KEY(bot,persona,contact_id,segment_index),UNIQUE(bot,persona,operation_id),UNIQUE(bot,persona,effect_id)) STRICT')
TRIGGERS=tuple('CREATE TRIGGER '+TABLE+'_no_'+action.lower()+' BEFORE '+action+' ON '+TABLE+
    " BEGIN SELECT RAISE(ABORT,'Contact segment original immutable'); END"for action in ('UPDATE','DELETE'))
_PROJECTION_WORKS=WeakKeyDictionary()
_PROJECTION_RIGHTS=WeakKeyDictionary()
_CAPTURE_LOCATORS=WeakKeyDictionary()
_LOCATOR_WORKS=WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class ContactSegmentOriginalV1:
    namespace:NamespaceId
    contact_id:str
    segment_index:int
    segment_count:int
    operation_id:str
    effect_id:str
    request_digest:str
    dispatch_request_digest:str
    payload_digest:str
    reviewed_content_digest:str
    whole_manifest_digest:str
    first_operation_id:str
    first_admission_ref:str
    first_admission_receipt_digest:str
    old_cause_ref:str
    old_cause_digest:str
    old_causal_operation_id:str
    old_causal_dedupe_key:str
    plan_ref:str
    plan_revision:int
    plan_digest:str
    batch_ref:str
    parent_grant_ref:str
    parent_grant_digest:str
    same_claim_ref:str
    same_goal_ref:str
    goal_digest:str
    original_claim_digest:str
    source_refs:tuple[str,...]
    root_grant_id:str
    root_grant_version:int
    root_grant_digest:str
    root_lease_ref:str
    quote_id:str
    quote_version:int
    quote_digest:str
    reservation_digest:str
    reservation_ceiling:tuple[tuple[str,float],...]
    deadline_utc:float
    job_ref:str
    outbox_ref:str
    admission_ref:str
    admission_receipt_digest:str
    core_observation:dict
    producing_receipt_digest:str
    first_prospective:dict|None=None
    background_invocation:dict|None=None
    schema:str='d11.contact-segment-original.v1'
    def __post_init__(self):
        if (self.schema!=SIGN_KIND or type(self.namespace)is not NamespaceId or type(self.segment_index)is not int
                or not 0<=self.segment_index<self.segment_count<=3 or self.plan_revision<1 or self.root_grant_version<1
                or not self.contact_id.startswith('contact:') or type(self.source_refs)is not tuple or not self.source_refs):
            raise ValueError('Contact segment original requires exact finite whole-manifest identity')
        for name in ('request_digest','dispatch_request_digest','payload_digest','reviewed_content_digest','whole_manifest_digest',
                'first_admission_receipt_digest','old_cause_digest','plan_digest','parent_grant_digest','goal_digest',
                'original_claim_digest','root_grant_digest','quote_digest','reservation_digest','admission_receipt_digest','producing_receipt_digest'):
            value=getattr(self,name)
            if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
                raise ValueError('Contact segment original has an invalid actual commitment')
        if self.first_prospective is not None:
            p=self.first_prospective
            if (self.segment_index!=0 or type(p)is not dict
                    or set(p)!={'birth_ref','birth_digest','observation','successor_ref','successor_digest','final_receipt_digest'}
                    or p['successor_ref']!=self.operation_id or p['final_receipt_digest']!=self.producing_receipt_digest
                    or type(p['observation'])is not dict):
                raise ValueError('Contact first prospective metadata is not the actual birth/final successor tuple')
        if self.background_invocation is not None:
            b=self.background_invocation
            if (type(b)is not dict or set(b)!={'scope','owner','request','command','result_digest','provenance_digest'}
                    or b['request']!={'contact_id':self.contact_id,'segment_index':self.segment_index}
                    or b['scope']['namespace']!=asdict(self.namespace)
                    or b['owner']['namespace']!=asdict(self.namespace)
                    or set(b['command'])!={'activity_id','audience_ref','parent_budget_lease_ref'}
                    or b['command']['parent_budget_lease_ref']!=self.root_lease_ref):
                raise ValueError('Contact immutable background recovery metadata changed its exact actual call tuple')
        import math
        if type(self.deadline_utc)not in (int,float)or not math.isfinite(self.deadline_utc):
            raise ValueError('Contact segment requires its original finite absolute deadline')
    @property
    def digest(self):return canonical_digest(asdict(self))


def contact_segment_original_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!=set(ContactSegmentOriginalV1.__dataclass_fields__):
        raise ValueError('Contact segment original exact fields differ')
    value=ContactSegmentOriginalV1(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'source_refs':tuple(raw['source_refs']),'reservation_ceiling':tuple(tuple(row)for row in raw['reservation_ceiling'])})
    if json.loads(canonical_serialize(asdict(value)))!=raw:
        raise ValueError('Contact segment original canonical wire differs')
    return value


def install_contact_segment_schema_v1(db):
    db.execute(DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    for sql in TRIGGERS:db.execute(sql.replace('CREATE TRIGGER ','CREATE TRIGGER IF NOT EXISTS ',1))


def _point(db,*,table,columns,key_columns,key):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    return _producer_original_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key,
        legacy_reader=lambda:None)


def read_contact_segment_original_v1(db,*,namespace,contact_id,segment_index,issuer):
    row=_point(db,table=TABLE,columns=COLUMNS,key_columns=('bot','persona','contact_id','segment_index'),
        key=(*namespace.as_tuple,contact_id,segment_index))
    if row is None:return None
    from .domain_background_read_v3 import background_json_loads_v3,background_json_matches_v3
    raw=background_json_loads_v3(row[6]);value=contact_segment_original_from_wire_v1(raw)
    if (row[:6]!=(*namespace.as_tuple,contact_id,segment_index,value.operation_id,value.effect_id)
            or value.namespace!=namespace or value.digest!=row[7] or not background_json_matches_v3(row[6],raw)):
        raise AuthorityUnavailable('Contact segment original differs from exact immutable row')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,contact_id,segment_index,value.digest)),row[8])
    return value


def read_contact_continuation_segment_locator_v1(db,*,namespace,operation_id,issuer):
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    with runtime_storage_quantum_v3(db)as meter:
        row=_runtime_bounded_fixed_row_v3(db,meter,TABLE,('contact_id','segment_index'),'bot=? AND persona=? AND operation_id=?',
            (*namespace.as_tuple,operation_id))
    if row is None:return None
    return read_contact_segment_original_v1(db,namespace=namespace,contact_id=row[0],segment_index=row[1],issuer=issuer)


def _financial(db,*,namespace,kind,ref,issuer):
    from ..authority_service.contact_effect_accounting_contract_v1 import (SignedContactEffectBudgetOriginV1,
        ORIGIN_SIGN,SETTLEMENT_SIGN,from_wire,encoded_v1)
    from .domain_background_read_v3 import background_json_loads_v3,background_json_matches_v3
    row=_point(db,table='graph_contact_effect_originals_v1',columns=('payload_json','payload_digest','signature'),
        key_columns=('bot','persona','kind','original_ref'),key=(*namespace.as_tuple,kind,ref))
    if row is None:raise AuthorityUnavailable('Contact prefix lacks actual signed per-effect financial original')
    raw=background_json_loads_v3(row[0])
    if canonical_digest(raw)!=row[1]or not background_json_matches_v3(row[0],raw):
        raise AuthorityUnavailable('Contact prefix financial whole canonical commitment differs')
    if kind=='origin':
        signed=from_wire(raw,SignedContactEffectBudgetOriginV1)
        issuer._signer.verify(ORIGIN_SIGN,encoded_v1(signed.origin),signed.signature)
        if signed.signature!=row[2]or signed.origin.namespace!=namespace or signed.origin.operation_id!=ref:
            raise AuthorityUnavailable('Contact prefix budget original changed its exact signed source')
        return raw
    issuer._signer.verify(SETTLEMENT_SIGN,canonical_serialize(raw),row[2])
    if raw['schema']!='d11.contact-effect-settlement-original.v1' or raw['result']['accounting_finished']is not False:
        raise AuthorityUnavailable('Contact saved settlement cannot fabricate future Core finish')
    return {'payload':raw,'payload_digest':row[1],'signature':row[2]}


def _prefix(db,*,first,index,issuer):
    from ..authority_service.contact_effect_accounting_contract_v1 import (SignedContactEffectBudgetOriginV1,
        ContactEffectAccountingRequestV1,from_wire)
    from .domain_background_read_v3 import background_json_loads_v3
    values=[]
    for position in range(index):
        original=read_contact_segment_original_v1(db,namespace=first.namespace,contact_id=first.contact_id,segment_index=position,issuer=issuer)
        if original is None:raise AuthorityUnavailable('Contact continuation is missing an actual earlier segment original')
        if (original.first_operation_id,original.first_admission_ref,original.first_admission_receipt_digest,
                original.whole_manifest_digest,original.reviewed_content_digest,original.old_cause_ref,original.old_cause_digest,
                original.same_claim_ref,original.same_goal_ref,original.root_lease_ref)!=(
                first.operation_id,first.admission_ref,first.admission_receipt_digest,first.whole_manifest_digest,
                first.reviewed_content_digest,first.old_cause_ref,first.old_cause_digest,first.same_claim_ref,first.same_goal_ref,first.root_lease_ref):
            raise AuthorityUnavailable('Contact prefix member changed original whole manifest/claim/Goal/cause/root')
        origin=_financial(db,namespace=first.namespace,kind='origin',ref=original.operation_id,issuer=issuer)
        signed=from_wire(origin,SignedContactEffectBudgetOriginV1)
        cost_operation='contact-cost-'+canonical_digest((first.namespace,original.effect_id,'initial'))[:48]
        settlement=_financial(db,namespace=first.namespace,kind='settlement',ref=cost_operation,issuer=issuer)
        raw=settlement['payload'];result=raw['result']
        request_row=_point(db,table='graph_contact_effect_accounting_attempts_v1',
            columns=('origin_digest','fact_digest','request_json','state'),key_columns=('bot','persona','operation_id'),
            key=(*first.namespace.as_tuple,cost_operation))
        if request_row is None or request_row[3]!='committed':
            raise AuthorityUnavailable('Contact prefix accounting has no actual successful committed attempt')
        accounting_raw=background_json_loads_v3(request_row[2]);accounting=from_wire(accounting_raw,ContactEffectAccountingRequestV1)
        if (result['budget_status']!='settled' or result['observation_outcome']!='accepted'
                or (result['effect_id'],raw['origin_ref'],request_row[0],request_row[1])!=(
                    original.effect_id,original.operation_id,signed.origin.digest,result['fact_digest'])
                or accounting.origin!=signed or accounting.operation_id!=raw['request_ref']
                or signed.origin.admission_ref!=original.admission_ref
                or signed.origin.admission_receipt_digest!=original.admission_receipt_digest
                or signed.origin.request_digest!=original.dispatch_request_digest
                or (signed.origin.quote_id,signed.origin.quote_version,signed.origin.quote_digest,signed.origin.reservation_digest)!=(
                    original.quote_id,original.quote_version,original.quote_digest,original.reservation_digest)):
            raise AuthorityUnavailable('Contact prefix original receipt/quote/reservation/accounting identity differs')
        from .contact_effect_accounting_v1 import restore_stored_fact_v1
        fact=restore_stored_fact_v1(raw,signed)
        if fact.observation_outcome!='accepted' or fact.observed_mutation_id!=accounting.observed_mutation_id:
            raise AuthorityUnavailable('Contact prefix lacks exact actual accepted Core observation identity')
        reservation=_point(db,table='runtime_budget_reservations',columns=('digest','ceiling_json','actual_json','state'),
            key_columns=('lease_id','operation_id'),key=(original.root_lease_ref,original.operation_id))
        if reservation is None or reservation[0]!=original.reservation_digest or reservation[3]!='settled':
            raise AuthorityUnavailable('Contact prefix original per-segment reservation is not actually settled')
        values.append({'segment_index':position,'operation_id':original.operation_id,'effect_id':original.effect_id,
            'admission_ref':original.admission_ref,'admission_receipt_digest':original.admission_receipt_digest,
            'request_digest':original.dispatch_request_digest,'payload_digest':original.payload_digest,
            'observed_receipt_digest':fact.observed_receipt_digest,'observed_mutation_id':fact.observed_mutation_id,
            'binding_digest':fact.binding_digest,'observation_outcome':'accepted','budget_status':'settled',
            'budget_origin':origin,'settlement':settlement,'accounting_request':accounting_raw})
    return tuple(values)


def read_contact_continuation_inputs_v1(db,*,work,selector,issuer,now_utc):
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationSelectorV1
    from .contact_background_inputs_v1 import read_contact_background_inputs_v1
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    if type(selector)is not ContactContinuationSelectorV1 or work.db is not db or work.namespace!=selector.namespace:
        raise AuthorityUnavailable('Contact continuation inputs require their exact actual Source Work and selector')
    first=read_contact_segment_original_v1(db,namespace=selector.namespace,contact_id=selector.contact_id,segment_index=0,issuer=issuer)
    if first is None:raise AuthorityUnavailable('Contact continuation has no actual signed first-segment original')
    content=read_contact_reviewed_content_original_v2(db,namespace=selector.namespace,contact_id=selector.contact_id,issuer=issuer,resource_issuer=issuer._d02)
    if not 0<selector.segment_index<len(content.segments):raise AuthorityUnavailable('Contact continuation index is outside actual paid whole manifest')
    item=content.segments[selector.segment_index]
    plan,_,_,plan_digest=read_adopted_contact_plan_v2(db,namespace=selector.namespace,contact_id=selector.contact_id,issuer=issuer)
    first_terms,_,_,_=read_contact_background_inputs_v1(db,namespace=selector.namespace,contact_id=selector.contact_id,
        operation_id=first.operation_id,request_digest=first.request_digest,dedupe_key=selector.causal_dedupe_key,
        issuer=issuer,now=now_utc,owner_actor=work.contact_policy.owner_actor_id if hasattr(work,'contact_policy')else work.owner.actor)
    owner_actor=work.contact_policy.owner_actor_id if hasattr(work,'contact_policy')else work.owner.actor
    request_digest=canonical_digest(('sylanne.domain-production-command.v1',selector.namespace,
        owner_actor,'prepare_contact_dispatch_v3',PrepareCurrentContactDispatchRequestV3(selector.contact_id,selector.segment_index),
        item.operation_id,content.activity_id,content.audience_id,first.root_lease_ref))
    if (selector.operation_id!=item.operation_id or selector.request_digest!=request_digest
            or first.reviewed_content_digest!=content.digest or first.plan_digest!=plan_digest
            or (first.old_cause_ref,first.old_cause_digest,first.old_causal_operation_id,first.old_causal_dedupe_key)!=(
                first_terms['causal_original_ref'],first_terms['causal_original_digest'],first_terms['causal_operation_id'],selector.causal_dedupe_key)
            or selector.policy_id!=work.contact_policy.policy.policy_id):
        raise AuthorityUnavailable('Contact continuation selector changed original Plan/paid content/old cause')
    from .domain_background_read_v3 import background_json_loads_v3
    grant_row=_point(db,table='graph_atoms',columns=('revision','value','valid'),key_columns=('token','bot','persona'),
        key=(first.parent_grant_ref,*selector.namespace.as_tuple))
    if grant_row is None or grant_row[0]!=1 or grant_row[2]!=1:raise AuthorityUnavailable('Contact immutable whole parent grant is absent')
    from ..domains.d08.execution import GoalExecutionProvider
    validate=next(s.validator for s in GoalExecutionProvider().register_types()if s.name=='d08.communication_intent_grant.v1')
    parent=validate(background_json_loads_v3(grant_row[1]))
    if canonical_digest(parent)!=first.parent_grant_digest or parent.segment_manifest_digest!=first.whole_manifest_digest:
        raise AuthorityUnavailable('Contact continuation changed the original whole communication grant')
    goal_row=_point(db,table='graph_atoms',columns=('revision','value','valid'),key_columns=('token','bot','persona'),key=(first.same_goal_ref,*selector.namespace.as_tuple))
    claim_row=_point(db,table='graph_atoms',columns=('revision','value','valid'),key_columns=('token','bot','persona'),key=(first.same_claim_ref,*selector.namespace.as_tuple))
    if goal_row is None or goal_row[0]!=1 or goal_row[2]!=1 or canonical_digest(background_json_loads_v3(goal_row[1]))!=first.goal_digest:
        raise AuthorityUnavailable('Contact continuation changed its original active whole Goal')
    from ..domains.d10.contact_claim_v2 import decode_contact_claim_v2
    claim=decode_contact_claim_v2(background_json_loads_v3(claim_row[1]))if claim_row is not None and claim_row[2]==1 else None
    observations={}if claim is None else dict(claim.observations)
    expected_effects=tuple(part.segment.effect_id for part in content.segments)
    if (claim is None or claim.communication_action_id!=parent.communication_action_id or claim.segment_effects!=expected_effects
            or claim.status in {'released','pending_confirmation'} or observations!={expected_effects[p]:'accepted'for p in range(selector.segment_index)}
            or canonical_digest(replace(claim,observations=(),status='claimed'))!=first.original_claim_digest):
        raise AuthorityUnavailable('Contact continuation lacks exact accepted own-claim prefix')
    attempt=_point(db,table='graph_owner_domain_attempts_v3',columns=('request_digest','attempt_id','permit_json'),
        key_columns=('bot','persona','operation_id'),key=(*selector.namespace.as_tuple,selector.operation_id))
    if attempt is None or attempt[0]!=selector.request_digest:raise AuthorityUnavailable('Contact continuation has no actual current WRITE attempt')
    from ..authority_service.v2_contract import from_wire as authority_read,canonical_digest as authority_digest
    permit=authority_read(background_json_loads_v3(attempt[2]))
    current_permit=work.permit if hasattr(work,'permit')else work.scope.permit
    if permit!=current_permit or permit.operation!='write':raise AuthorityUnavailable('Contact continuation Source cannot borrow another actual WRITE')
    prefix=_prefix(db,first=first,index=selector.segment_index,issuer=issuer)
    root=issuer.current_budget_grant(db,first.root_lease_ref)
    if (root.grant_id,root.version,canonical_digest(root))!=(first.root_grant_id,first.root_grant_version,first.root_grant_digest):
        raise AuthorityUnavailable('Contact continuation cannot replace its original parent grant')
    deadline=min(first.deadline_utc,parent.valid_until,content.valid_until,root.valid_until_utc,first_terms['deadline_utc'])
    if now_utc>=deadline:raise AuthorityUnavailable('Contact continuation original absolute deadline expired')
    return {'namespace':asdict(selector.namespace),'contact_id':selector.contact_id,'segment_index':selector.segment_index,
        'segment_count':len(content.segments),'operation_id':item.operation_id,'effect_id':item.segment.effect_id,
        'request_digest':selector.request_digest,'owner_actor':owner_actor,'attempt_id':attempt[1],'permit_digest':authority_digest(permit).removeprefix('sha256:'),
        'old_cause_ref':first.old_cause_ref,'old_cause_digest':first.old_cause_digest,
        'old_causal_operation_id':first.old_causal_operation_id,'old_causal_dedupe_key':first.old_causal_dedupe_key,
        'first_operation_id':first.operation_id,'first_request_digest':first.request_digest,'first_admission_ref':first.admission_ref,
        'first_admission_receipt_digest':first.admission_receipt_digest,'whole_manifest_digest':first.whole_manifest_digest,
        'reviewed_content_digest':content.digest,'batch_ref':first.batch_ref,'parent_grant_ref':first.parent_grant_ref,
        'parent_grant_digest':first.parent_grant_digest,'same_claim_ref':first.same_claim_ref,'same_goal_ref':first.same_goal_ref,
        'plan_ref':first.plan_ref,'plan_revision':first.plan_revision,'plan_digest':first.plan_digest,
        'root_grant_id':first.root_grant_id,'root_grant_version':first.root_grant_version,'root_grant_digest':first.root_grant_digest,
        'root_lease_ref':first.root_lease_ref,'deadline_utc':float(deadline),'graph_revision':first_terms['graph_revision'],
        'graph_epoch':first_terms['graph_epoch'],'prefix':list(prefix)}


def read_contact_continuation_projection_v1(db,*,work,selector,effect_id,issuer):
    original=read_contact_segment_original_v1(db,namespace=selector.namespace,contact_id=selector.contact_id,
        segment_index=selector.segment_index,issuer=issuer)
    if original is None or original.segment_index==0 or original.effect_id!=effect_id or original.operation_id!=selector.operation_id or original.request_digest!=selector.request_digest:
        raise AuthorityUnavailable('Contact continuation projection lost its exact signed segment selector')
    from ..authority_service.contact_continuation_contract_v1 import (ContactContinuationObservationV1,
        contact_continuation_from_wire_v1)
    observed=contact_continuation_from_wire_v1(original.core_observation,ContactContinuationObservationV1)
    if observed.selector!=selector:raise AuthorityUnavailable('Contact projection cannot substitute another stored Core observation')
    from .dispatch_admission import load_request
    issued=load_request(db,selector.namespace,original.admission_ref)
    if issued is None or canonical_digest(issued[1])!=original.dispatch_request_digest or issued[0].receipt_digest!=original.admission_receipt_digest:
        raise AuthorityUnavailable('Contact continuation projection has no actual immutable same-CAS admission')
    first=read_contact_segment_original_v1(db,namespace=selector.namespace,contact_id=selector.contact_id,segment_index=0,issuer=issuer)
    prefix=_prefix(db,first=first,index=selector.segment_index,issuer=issuer)
    inputs=json.loads(observed.inputs_json)
    if canonical_serialize(prefix)!=canonical_serialize(inputs['prefix']):raise AuthorityUnavailable('Contact continuation prefix originals changed after original admission')
    return {'segment_original':asdict(original),'observation_wire':original.core_observation,'request':issued[1],
        'admission_receipt':issued[0],'inputs':{**inputs,'prefix':list(prefix)}}


class _ContactProjectionRightsProofV1:
    def __init__(self,reader):
        self.work,self.selection=reader.work,reader.selection
        self.witnesses=MappingProxyType(dict(reader.witnesses))
        self.metadata_records=MappingProxyType(dict(reader.metadata_records))
        self.rights_versions=tuple(reader.versions)
        self.purposes=MappingProxyType({ref:frozenset(values)for ref,values in reader.qualified_purposes.items()})
        self.source_records=MappingProxyType({})
        _PROJECTION_RIGHTS[self]=(self.work,self.selection,self.witnesses,self.metadata_records,self.rights_versions,self.purposes)
    def require_current_v1(self,work):
        if _PROJECTION_RIGHTS.get(self)!=(work,self.selection,self.witnesses,self.metadata_records,self.rights_versions,self.purposes):
            raise AuthorityUnavailable('Continuation projection metadata rights lost its exact original Work')
        self.selection.require_v3(work)
        for witness in self.witnesses.values():witness.require_current_v3()
        return self


def begin_contact_continuation_projection_source_read_v1(service,*,credential,subject,permit,observed_receipt,selector,policy,location):
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationSelectorV1
    from ..authority_service.v2_contract import MutationReceiptV2,FencePermitV2
    from ..authority_service.contact_background_graph_v3 import ContactBackgroundSelectorV3,begin_contact_authority_graph_read_v3
    if (type(selector)is not ContactContinuationSelectorV1 or type(observed_receipt)is not MutationReceiptV2
            or type(permit)is not FencePermitV2 or permit.operation!='read'
            or observed_receipt.pending.binding.origin.segment_index!=selector.segment_index
            or observed_receipt.pending.binding.operation_id!=selector.operation_id
            or observed_receipt.pending.binding.origin.proactive_contact is not True):
        raise AuthorityUnavailable('Continuation projection requires its independent exact typed metadata READ')
    selected=ContactBackgroundSelectorV3(selector.namespace,selector.contact_id,selector.operation_id,
        selector.request_digest,selector.policy_id,selector.causal_dedupe_key)
    work=begin_contact_authority_graph_read_v3(service,credential=credential,subject=subject,permit=permit,
        selector=selected,policy=policy,location=location)
    from datetime import datetime
    deadline=min(work.deadline_utc,datetime.fromisoformat(observed_receipt.pending.binding.utc_deadline.replace('Z','+00:00')).timestamp())
    if service._clock()>=deadline:
        from ..authority_service.current_authority_graph_read_v3 import finish_authority_graph_read_work_v3
        finish_authority_graph_read_work_v3(work)
        raise AuthorityUnavailable('Continuation projection cannot extend original dispatch deadline')
    work.deadline_utc=work.operation.deadline_utc=float(deadline)
    work.deadline_original=observed_receipt
    from ..authority_service.current_authority_graph_read_v3 import _DEADLINES,_track_authority_capability_v3
    _DEADLINES[work]=(work.operation,work.deadline_utc,observed_receipt)
    _PROJECTION_WORKS[work]=(service,selector,observed_receipt,permit,work.scope,work.operation,location)
    _track_authority_capability_v3(work,_PROJECTION_WORKS,work)
    return work


def contact_continuation_projection_source_reader_v1(work):
    origin=_PROJECTION_WORKS.get(work)
    if origin is None:return False,None
    if origin!=(work.service,origin[1],origin[2],work.permit,work.scope,work.operation,work.contact_location):
        raise AuthorityUnavailable('Continuation projection metadata factory lost actual READ origin')
    from ..authority_service.current_authority_graph_read_v3 import _AuthoritySourceMaterialReadV3
    from ..authority_service.contact_background_graph_v3 import ContactAuthoritySourceSelectionV3
    class _ProjectionRightsReadV1(_AuthoritySourceMaterialReadV3):
        def _body_refs_v3(self):return ()
        def _seal_material_v3(self):return _ContactProjectionRightsProofV1(self)
    work.source_selection=ContactAuthoritySourceSelectionV3(work,work.contact_locator)
    return True,_ProjectionRightsReadV1(work,work.source_selection)


def begin_contact_continuation_locator_source_read_v1(service,*,credential,subject,permit,context,binding,claimed_receipt,location):
    from ..authority_service.v2_contract import ExecutionBindingV2,FencePermitV2,DispatchHandoffContextV1,MutationReceiptV2
    from ..authority_service.current_authority_graph_read_v3 import (require_authority_graph_read_controller_v3,
        AuthorityGraphReadWorkV3,_ISSUER,_track_authority_capability_v3)
    if (type(binding)is not ExecutionBindingV2 or type(permit)is not FencePermitV2 or permit.operation!='read'
            or type(context)is not DispatchHandoffContextV1 or type(claimed_receipt)is not MutationReceiptV2
            or claimed_receipt.pending.binding!=binding or claimed_receipt.pending.phase!='claimed'
            or not 0<binding.origin.segment_index<binding.origin.segment_count<=3
            or binding.origin.proactive_contact is not True or binding.footprint.quota_occupancies):
        raise AuthorityUnavailable('Continuation locator requires exact typed existing segment and separate metadata READ')
    from ..authority_service.reverse_handoff import require_exact_reverse_handoff_identity
    require_exact_reverse_handoff_identity(binding.namespace,context,binding,claimed_receipt)
    controller=require_authority_graph_read_controller_v3(service)
    if controller.kind!='contact' or controller.service is not service or location is None:
        raise AuthorityUnavailable('Continuation locator has another installed Source controller')
    from datetime import datetime
    deadline=datetime.fromisoformat(binding.utc_deadline.replace('Z','+00:00')).timestamp()
    work=AuthorityGraphReadWorkV3(_ISSUER,controller,credential=credential,subject=subject,permit=permit,
        namespace=controller.location.namespace_id,request=binding,deadline_utc=deadline)
    work.continuation_locator_binding=binding
    work.continuation_locator_context=context;work.continuation_locator_claimed=claimed_receipt
    work.continuation_locator_original=None
    work.contact_location=location
    work.phase='validate'
    _LOCATOR_WORKS[work]=(service,binding,context,claimed_receipt,permit,work.scope,work.operation,location)
    _track_authority_capability_v3(work,_LOCATOR_WORKS,work)
    return work


def require_contact_continuation_locator_attachment_v1(work,request):
    capture=_CAPTURE_LOCATORS.get(work)
    if capture is not None:
        selector,write_permit=capture
        if (work.continuation_original_write_permit!=write_permit or request!=(TABLE,COLUMNS,('bot','persona','contact_id','segment_index'),
                (*work.namespace.as_tuple,selector.contact_id,selector.segment_index))):
            raise AuthorityUnavailable('Continuation existing capture locator cannot read Source/body or another attachment')
        return True
    origin=_LOCATOR_WORKS.get(work)
    if origin is None:return False
    if origin!=(work.service,work.continuation_locator_binding,work.continuation_locator_context,work.continuation_locator_claimed,
            work.permit,work.scope,work.operation,work.contact_location):
        raise AuthorityUnavailable('Continuation private locator READ origin changed')
    binding=origin[1]
    expected=(TABLE,COLUMNS,('bot','persona','contact_id','segment_index'),
        (*work.namespace.as_tuple,binding.footprint.contact_id,binding.origin.segment_index))
    if request!=expected:raise AuthorityUnavailable('Continuation locator cannot read Source/body or any other attachment')
    return True


def read_contact_continuation_locator_v1(db,*,work,binding,issuer):
    origin=_LOCATOR_WORKS.get(work)
    if origin is None or origin[1]is not binding or work.db is not db:
        raise AuthorityUnavailable('Continuation locator requires its actual fixed originating Source Work')
    original=read_contact_segment_original_v1(db,namespace=work.namespace,contact_id=binding.footprint.contact_id,
        segment_index=binding.origin.segment_index,issuer=issuer)
    if (original is None or original.operation_id!=binding.operation_id or original.effect_id!=binding.origin.effect_id
            or original.segment_count!=binding.origin.segment_count
            or original.whole_manifest_digest!=binding.origin.segment_manifest_digest.removeprefix('sha256:')
            or original.admission_ref!=binding.origin.admission_ref):
        raise AuthorityUnavailable('Continuation signed metadata locator belongs to another actual dispatch')
    work.continuation_locator_original=original
    return original


def promote_contact_continuation_metadata_source_v1(work,*,binding,selector,policy,location):
    from ..authority_service.contact_continuation_contract_v1 import (ContactContinuationSelectorV1,ContactContinuationObservationV1,
        contact_continuation_from_wire_v1)
    from ..authority_service.contact_background_graph_v3 import (ContactBackgroundSelectorV3,ContactPlanLocatorEOFV3,_BACKGROUND_WORKS)
    from ..authority_service.current_authority_graph_read_v3 import (_AuthorityCatalogueReadV3,_DEADLINES,_track_authority_capability_v3)
    origin=_LOCATOR_WORKS.get(work);original=getattr(work,'continuation_locator_original',None)
    if origin is None or origin[1]is not binding or original is None or type(selector)is not ContactContinuationSelectorV1:
        raise AuthorityUnavailable('Continuation rights promotion must derive from its actual signed locator EOF')
    observation=contact_continuation_from_wire_v1(original.core_observation,ContactContinuationObservationV1)
    if (observation.selector!=selector or policy is None or policy.namespace!=selector.namespace
            or policy.policy.policy_id!=selector.policy_id or policy.installation_id!=work.service._installation_id
            or location is not work.contact_location):
        raise AuthorityUnavailable('Continuation signed locator/current policy/location changed before rights')
    selected=ContactBackgroundSelectorV3(selector.namespace,selector.contact_id,selector.operation_id,
        selector.request_digest,selector.policy_id,selector.causal_dedupe_key)
    deadline=min(work.deadline_utc,original.deadline_utc,policy.policy.window_end)
    if work.service._clock()>=deadline:raise AuthorityUnavailable('Continuation metadata Source cannot extend original deadline')
    work.deadline_utc=work.operation.deadline_utc=float(deadline)
    work.deadline_original=original
    _DEADLINES[work]=(work.operation,work.deadline_utc,original)
    work.contact_policy,work.contact_selector,work.contact_issuer=policy,selected,work.service._issuer
    work.contact_locator=ContactPlanLocatorEOFV3(work)
    work.catalogue_reader=_AuthorityCatalogueReadV3(work)
    work.now_utc=work.service._clock();work.parent_original_id=selector.operation_id
    work.phase='contact_locator';work.complete=False;work.prepared=None
    _LOCATOR_WORKS.pop(work,None)
    _BACKGROUND_WORKS[work]=(work.service,work.controller,work.service._location,work.service._issuer,policy,selected,
        work.operation,work.scope,work.permit,work.credential,work.subject)
    _track_authority_capability_v3(work,_BACKGROUND_WORKS,work)
    _PROJECTION_WORKS[work]=(work.service,selector,binding,work.permit,work.scope,work.operation,location)
    _track_authority_capability_v3(work,_PROJECTION_WORKS,work)
    return work


def begin_contact_continuation_p2_source_read_v1(service,*,credential,subject,permit,context,binding,claimed_receipt,selector,policy,location):
    # The installed Core service has independently qualified this binding/claim;
    # this fixed factory still owns its own current Source READ and metadata rights.
    work=begin_contact_continuation_locator_source_read_v1(service,credential=credential,subject=subject,
        permit=permit,context=context,binding=binding,claimed_receipt=claimed_receipt,location=location)
    from ..authority_service.current_authority_graph_read_v3 import read_authority_graph_current_v3,finish_authority_graph_read_work_v3
    try:
        read_authority_graph_current_v3(work,lambda db:read_contact_continuation_locator_v1(db,work=work,binding=binding,issuer=service._issuer))
        return promote_contact_continuation_metadata_source_v1(work,binding=binding,selector=selector,policy=policy,location=location)
    except BaseException:
        finish_authority_graph_read_work_v3(work);raise


def read_contact_continuation_p2_selector_v1(db,*,work,binding,claim_receipt,expected_capsule,issuer):
    from ..authority_service.v2_contract import ExecutionBindingV2,MutationReceiptV2,DispatchGraphClaimReceiptV1,canonical_digest as authority_digest
    core_claimed=work.continuation_locator_claimed;context=work.continuation_locator_context
    if (type(binding)is not ExecutionBindingV2 or type(core_claimed)is not MutationReceiptV2
            or core_claimed.pending.binding!=binding or work.db is not db
            or work.continuation_locator_binding!=binding
            or (claim_receipt is not None and type(claim_receipt)is not DispatchGraphClaimReceiptV1)):
        raise AuthorityUnavailable('Continuation P2 Source has another actual binding/claim/READ tuple')
    from ..authority_service.reverse_handoff import require_exact_reverse_handoff_identity
    require_exact_reverse_handoff_identity(binding.namespace,context,binding,core_claimed)
    original=read_contact_segment_original_v1(db,namespace=work.namespace,contact_id=binding.footprint.contact_id,
        segment_index=binding.origin.segment_index,issuer=issuer)
    if (original is None or not 0<original.segment_index<original.segment_count<=3
            or original.operation_id!=binding.operation_id or original.effect_id!=binding.origin.effect_id
            or original.admission_ref!=binding.origin.admission_ref or binding.footprint.quota_occupancies
            or original.whole_manifest_digest!=binding.origin.segment_manifest_digest.removeprefix('sha256:')):
        raise AuthorityUnavailable('Continuation P2 lost its exact signed five-member original')
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationObservationV1,contact_continuation_from_wire_v1
    observation=contact_continuation_from_wire_v1(original.core_observation,ContactContinuationObservationV1)
    from .dispatch_admission import load_request
    issued=load_request(db,work.namespace,original.admission_ref)
    if issued is None or canonical_digest(issued[1])!=original.dispatch_request_digest or issued[0].receipt_digest!=original.admission_receipt_digest:
        raise AuthorityUnavailable('Continuation P2 original dispatch/admission COMMIT differs')
    request=issued[1]
    if (request.segment_index!=original.segment_index or request.effect_id!=original.effect_id
            or request.footprint!=binding.footprint or request.footprint.quota_occupancies
            or len(request.footprint.object_gate_keys)!=1 or request.footprint.contact_id!=original.contact_id):
        raise AuthorityUnavailable('Continuation P2 changed its current original footprint')
    from .contact_final_action_v1 import contact_final_action_ids_v1
    ids=contact_final_action_ids_v1(original.contact_id,original.segment_index)
    activity=AtomKey.from_token(original.job_ref).owner
    from .dispatch_graph_claim import dispatch_claim_key
    keys={'action':AtomKey(activity,'d08.action_intent.v1',ids['action']),
        'action_schema':AtomKey(activity,'d08.action_schema.v1',ids['schema']),
        'cancellation':AtomKey(activity,'d08.action_cancellation.v1',ids['action']),
        'job':AtomKey.from_token(original.job_ref),'outbox':AtomKey.from_token(original.outbox_ref),
        'claim':AtomKey.from_token(original.same_claim_ref),'goal':AtomKey.from_token(original.same_goal_ref),
        'communication_grant':AtomKey.from_token(original.parent_grant_ref),'dispatch_claim':dispatch_claim_key(work.namespace,original.effect_id)}
    members={}
    from .domain_background_read_v3 import background_json_loads_v3
    for name,key in keys.items():
        row=_point(db,table='graph_atoms',columns=('revision','value','valid'),key_columns=('token','bot','persona'),key=(key.token,*work.namespace.as_tuple))
        if row is None:
            if name!='dispatch_claim':raise AuthorityUnavailable('Continuation P2 exact member is absent')
            members[name]={'ref':key.token,'revision':0,'value':None,'valid':False};continue
        value=background_json_loads_v3(row[1])
        if row[2]!=1:raise AuthorityUnavailable('Continuation P2 exact member was invalidated')
        members[name]={'ref':key.token,'revision':row[0],'value':value,'valid':True}
        if name in ('action','action_schema','cancellation','job','outbox'):
            if row[0]!=1:raise AuthorityUnavailable('Continuation P2 new action/runtime member already changed')
            history=_point(db,table='graph_history',columns=('event_id','value','valid'),key_columns=('token','revision'),key=(key.token,1))
            if history is None or history[0]!=original.operation_id or history[2]!=1 or canonical_digest(background_json_loads_v3(history[1]))!=canonical_digest(value):
                raise AuthorityUnavailable('Continuation P2 five-member producing history differs')
    committed=_point(db,table='graph_bundle_operations',columns=('digest','activity_id','effect_id','commit_seq','receipt_json'),
        key_columns=('bot','persona','operation_id'),key=(*work.namespace.as_tuple,original.operation_id))
    from .domain_production_originals_v1 import _receipt
    receipt=None if committed is None else _receipt(background_json_loads_v3(committed[4]))
    if (receipt is None or (receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)!=committed[:4]
            or canonical_digest(receipt)!=original.producing_receipt_digest or {v.key for v in receipt.write_versions}!={keys[n]for n in ('action','action_schema','cancellation','job','outbox')}):
        raise AuthorityUnavailable('Continuation P2 has no exact original five-member Graph COMMIT')
    dc=members['dispatch_claim']
    if expected_capsule is None:
        if dc['revision']!=0 or dc['valid']:raise AuthorityUnavailable('Continuation Graph dispatch claim already exists')
    else:
        expected={'handoff_id':context.handoff_id,'operation_id':original.operation_id,'effect_id':original.effect_id,
            'binding_digest':authority_digest(binding),'claimed_receipt_digest':authority_digest(core_claimed),
            'context_digest':authority_digest(context),'p2_permit_digest':authority_digest(context.permit),
            'p2_fence_epoch':context.permit.fence_epoch,'p2_revision':context.permit.revision,
            'p2_execution_seq':context.permit.pinned_anchor.execution_seq,'p2_execution_digest':context.permit.pinned_anchor.execution_digest,
            'owner_witness_digest':expected_capsule.owner_witness_digest}
        if (type(claim_receipt)is not DispatchGraphClaimReceiptV1 or dc['revision']!=1 or not dc['valid']
                or claim_receipt.context_digest!=authority_digest(context) or claim_receipt.graph_claim_ref!='dispatch-claim:'+original.effect_id
                or claim_receipt.graph_claim_digest!='sha256:'+canonical_digest(dc['value'])
                or claim_receipt.graph_namespace!=binding.graph_namespace or claim_receipt.graph_incarnation!=binding.graph_incarnation
                or any(dc['value'][k]!=v for k,v in expected.items())):
            raise AuthorityUnavailable('Continuation post-P2 exact Graph claim differs from actual Core original')
    if (members['cancellation']['value']['state']=='cancelled' or members['goal']['revision']!=1
            or canonical_digest(members['goal']['value'])!=original.goal_digest
            or members['communication_grant']['revision']!=1
            or canonical_digest(members['communication_grant']['value'])!=original.parent_grant_digest
            or members['job']['value']['phase']!='waiting' or members['outbox']['value']['phase']!='pending'):
        raise AuthorityUnavailable('Continuation current original Goal/grant/cancellation/job/outbox changed')
    first=read_contact_segment_original_v1(db,namespace=work.namespace,contact_id=original.contact_id,segment_index=0,issuer=issuer)
    prefix=_prefix(db,first=first,index=original.segment_index,issuer=issuer)
    inputs=json.loads(observation.inputs_json)
    if canonical_serialize(prefix)!=canonical_serialize(inputs['prefix']):raise AuthorityUnavailable('Continuation P2 prefix actual original financial facts changed')
    quote=issuer._d02.original_signed_quote(db,original.quote_id,original.quote_version)
    reservation=_point(db,table='runtime_budget_reservations',columns=('digest','ceiling_json','state'),
        key_columns=('lease_id','operation_id'),key=(original.root_lease_ref,original.operation_id))
    if (canonical_digest(quote)!=original.quote_digest or reservation is None
            or reservation[0]!=original.reservation_digest or reservation[2]!='reserved'
            or canonical_serialize(background_json_loads_v3(reservation[1]))!=canonical_serialize(dict(original.reservation_ceiling))):
        raise AuthorityUnavailable('Continuation P2 original new-segment quote/reservation changed')
    return {'segment_original':asdict(original),'observation_wire':original.core_observation,'request':request,
        'admission_receipt':issued[0],'inputs':{**inputs,'prefix':list(prefix)},'p2_members':members,'prefix':prefix,
        'quote':asdict(quote),'reservation':{'digest':reservation[0],'ceiling':dict(original.reservation_ceiling),'state':'reserved'},
        'root_grant_id':original.root_grant_id,'root_grant_version':original.root_grant_version,
        'root_grant_digest':original.root_grant_digest,'root_lease_ref':original.root_lease_ref,
        'same_object_gate':request.footprint.object_gate_keys[0],'communication_action':request.footprint.communication_action,
        'quota_occupancies':()}


def record_contact_segment_original_after_commit_v1(db,*,material,receipt,admission,request):
    from .contact_final_stage_v3 import require_installed_contact_material_v3
    m=require_installed_contact_material_v3(material)
    if not db.in_transaction or not m.runtime.graph._GraphCoordinator__store._lock._is_owned() or receipt.status!='committed':
        raise AuthorityUnavailable('Contact segment original requires its actual final same-CAS writer')
    from .contact_final_action_v1 import contact_final_action_ids_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d08.execution import GoalExecutionProvider
    from ..domains.d10.contact_claim_v2 import contact_claim_key_v2,decode_contact_claim_v2
    from .contact_background_invocation_v1 import _CAPTURES,require_contact_background_call_v1
    call=m.runtime._active_contact_background_call_v1
    require_contact_background_call_v1(call)
    capture=_CAPTURES.get(id(call))
    if capture is None or capture[0]is not call or capture[1]is not m.scope:
        raise AuthorityUnavailable('Contact segment original has no actual independently captured Core observation')
    index=m.request.segment_index
    if index==0:
        observation=capture[3]
        terms=observation['inputs']
        first_operation=m.frame.envelope.identity.operation_id
        first_ref=admission.admission.admission_ref;first_digest=admission.receipt_digest
    else:
        from ..authority_service.contact_continuation_contract_v1 import ContactContinuationObservationV1,contact_continuation_to_wire_v1
        observation_value=capture[3]
        if type(observation_value)is not ContactContinuationObservationV1:
            raise AuthorityUnavailable('Later Contact segment cannot borrow the first generic observer')
        observation=contact_continuation_to_wire_v1(observation_value)
        terms=json.loads(observation_value.inputs_json)
        first_operation=terms['first_operation_id'];first_ref=terms['first_admission_ref'];first_digest=terms['first_admission_receipt_digest']
    ns=m.scope.namespace;ids=contact_final_action_ids_v1(m.content.contact_id,index)
    activity=Owner('activity',*ns.as_tuple,m.content.activity_id)
    goal_key=AtomKey(activity,'d08.goal.v1',ids['goal'])
    goal=db.execute('SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?',(goal_key.token,*ns.as_tuple)).fetchone()
    claim_key=contact_claim_key_v2(ns,m.content.contact_id)
    claim_row=db.execute('SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?',(claim_key.token,*ns.as_tuple)).fetchone()
    if goal is None or claim_row is None:raise AuthorityUnavailable('Contact segment original has no actual whole Goal and claim')
    claim=decode_contact_claim_v2(json.loads(claim_row[0]))
    from ..domains.d09.contact_batch_v3 import contact_batch_keys_v3
    batch_key=contact_batch_keys_v3(ns,m.content.activity_id,m.content.contact_id)[0]
    batch=db.execute('SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?',(batch_key.token,*ns.as_tuple)).fetchone()
    if batch is None:raise AuthorityUnavailable('Contact segment original has no actual whole immutable batch')
    batch_raw=json.loads(batch[0]);parent_ref=batch_raw['parent_grant_ref']
    grant=db.execute('SELECT value FROM graph_atoms WHERE token=? AND bot=? AND persona=?',(parent_ref,*ns.as_tuple)).fetchone()
    if grant is None:raise AuthorityUnavailable('Contact segment original has no actual whole communication grant')
    raw_grant=json.loads(grant[0]);parent=next(s.validator for s in GoalExecutionProvider().register_types()if s.name=='d08.communication_intent_grant.v1')(raw_grant)
    reserve=db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
        (m.grant.lease_id,receipt.operation_id)).fetchone()
    if reserve is None or reserve[2]!='reserved' or json.loads(reserve[1])!=dict(m.quote.ceiling):
        raise AuthorityUnavailable('Contact segment original quote/reservation was not born in this same CAS')
    expected_count=11 if index==0 else 5
    if len(receipt.write_versions)!=expected_count:raise AuthorityUnavailable('Contact segment exact original writer member count differs')
    prospective=None
    if index==0 and m.prospective_birth is not None:
        from .contact_prospective_v1 import contact_prospective_original_ref_v1,SUCCESSOR_TABLE,SUCCESSOR_COLUMNS,SUCCESSOR_SIGN
        born=json.loads(m.prospective_birth.payload_json)
        successor=m.prospective_successor
        saved=db.execute('SELECT '+','.join(SUCCESSOR_COLUMNS)+' FROM '+SUCCESSOR_TABLE+
            ' WHERE bot=? AND persona=? AND final_operation_id=?',(*ns.as_tuple,receipt.operation_id)).fetchone()
        if (successor is None or saved is None or saved[3]!=contact_prospective_original_ref_v1(ns,m.content.contact_id,born['birth_operation_id'])
                or saved[4]!=m.prospective_birth.digest or saved[6]!=successor.digest or saved[8]!=canonical_digest(receipt)):
            raise AuthorityUnavailable('First segment metadata requires its actual same-CAS birth/successor original')
        m.runtime.graph._GraphCoordinator__d11_issuer._signer.verify(SUCCESSOR_SIGN,
            canonical_serialize((ns,receipt.operation_id,successor.digest,saved[8])),saved[7])
        prospective={'birth_ref':saved[3],'birth_digest':saved[4],'observation':born['observation'],
            'successor_ref':saved[2],'successor_digest':saved[6],'final_receipt_digest':saved[8]}
    from .contact_owner_invocation_v3 import _owner_storage_wire_v3
    from ..authority_service.v2_contract import to_wire as authority_wire
    from .contact_final_stage_v3 import _contact_final_result_v3
    adopted=read_adopted_domain_operation_v1(db,ns,receipt.operation_id)
    if adopted is None or adopted['receipt']!=receipt:
        raise AuthorityUnavailable('Segment background metadata lacks its actual signed final domain original')
    saved_scope=asdict(m.scope);saved_scope['permit']=authority_wire(m.scope.permit)
    saved_result=_contact_final_result_v3(receipt=receipt,original_digest=adopted['original_digest'],job_id=m.job.job_id,
        admission_ref=admission.admission.admission_ref,dispatch_request_digest=canonical_digest(request))
    invocation={'scope':saved_scope,'owner':_owner_storage_wire_v3(m.owner),'request':asdict(m.request),
        'command':{'activity_id':m.content.activity_id,'audience_ref':m.content.audience_id,'parent_budget_lease_ref':m.grant.lease_id},
        'result_digest':canonical_digest(saved_result),'provenance_digest':canonical_digest(adopted['payload']['provenance'])}
    value=ContactSegmentOriginalV1(ns,m.content.contact_id,index,len(m.content.segments),receipt.operation_id,
        request.effect_id,call.request_digest,canonical_digest(request),m.content.segments[index].payload_digest,
        m.content.digest,parent.segment_manifest_digest,first_operation,first_ref,first_digest,
        terms['causal_original_ref']if index==0 else terms['old_cause_ref'],
        terms['causal_original_digest']if index==0 else terms['old_cause_digest'],
        terms['causal_operation_id']if index==0 else terms['old_causal_operation_id'],
        terms['dedupe_key']if index==0 else terms['old_causal_dedupe_key'],
        terms['plan_ref'],terms['plan_revision'],terms['plan_original_digest']if index==0 else terms['plan_digest'],
        batch_key.token,parent_ref,canonical_digest(parent),claim_key.token,goal_key.token,canonical_digest(json.loads(goal[0])),
        canonical_digest(replace(claim,observations=(),status='claimed')),tuple(m.frame.envelope.source_qualification.source_refs),
        m.grant.grant_id,m.grant.version,canonical_digest(m.grant),m.grant.lease_id,m.quote.quote_id,m.quote.version,
        canonical_digest(m.quote),reserve[0],tuple(sorted(m.quote.ceiling.items())),m.frame.envelope.deadline_utc,
        m.final_bundle.persistent_job_refs[0],m.final_bundle.outbox_refs[0],admission.admission.admission_ref,
        admission.receipt_digest,observation,canonical_digest(receipt),first_prospective=prospective,background_invocation=invocation)
    from .c09_paged_sql_v2 import c09_canonical_json_size_v3
    size=c09_canonical_json_size_v3(asdict(value),ascii=True,exact=True)
    if size>262144:raise AuthorityUnavailable('Contact signed segment metadata exceeds its closed schema bound')
    from ..runtime_storage_v3 import runtime_storage_v3,_operation
    _operation(runtime_storage_v3(db)).retain(size*3+65536)
    wire=canonical_serialize(asdict(value));issuer=m.runtime.graph._GraphCoordinator__d11_issuer
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((ns,value.contact_id,index,value.digest)))
    prior=db.execute('SELECT payload_digest,signature FROM '+TABLE+' WHERE bot=? AND persona=? AND contact_id=? AND segment_index=?',
        (*ns.as_tuple,value.contact_id,index)).fetchone()
    if prior is not None:raise AuthorityUnavailable('Contact segment cannot recharge or replace an existing immutable original')
    db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?,?,?,?,?,?)',(*ns.as_tuple,value.contact_id,index,value.operation_id,value.effect_id,wire,value.digest,signature))
    return value


def read_current_contact_continuation_write_attempt_v1(work,db,*,table,columns,key_columns,key):
    from .contact_domain_source_v3 import _DOMAIN_WRITE_CURRENT,require_contact_domain_fresh_write_v3
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    binding=_DOMAIN_WRITE_CURRENT.get()
    if binding is None or binding.work is not work:return False,None
    command=binding.command
    if (table!='graph_owner_domain_attempts_v3' or tuple(columns)!=('request_digest','attempt_id','permit_json')
            or tuple(key_columns)!=('bot','persona','operation_id')
            or type(command.request)is not PrepareCurrentContactDispatchRequestV3 or command.request.segment_index==0):
        return False,None
    actual=work.parent.local_result
    if tuple(key)!=(*work.namespace.as_tuple,actual[7][0]):
        raise AuthorityUnavailable('Continuation fresh WRITE cannot select another attempt metadata')
    require_contact_domain_fresh_write_v3(work,db)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    with runtime_storage_quantum_v3(db)as meter:
        row=_runtime_bounded_fixed_row_v3(db,meter,table,tuple(columns),'bot=? AND persona=? AND operation_id=?',tuple(key))
    from ..authority_service.v2_contract import from_wire as authority_read
    if row is None or row[:2]!=(binding.request_digest,binding.scope.operation_id)or authority_read(json.loads(row[2]))!=binding.scope.permit:
        raise AuthorityUnavailable('Continuation fresh WRITE attempt lacks its exact actual scope and command')
    return True,row


def read_c09_contact_segment_row_v1(columns,row,*,authority_namespace,issuer):
    from ..runtime_contracts import namespace_ref
    from .c09_paged_sql_v2 import C09PagedCaptureHold
    if tuple(columns)!=COLUMNS or len(row)!=len(COLUMNS):raise C09PagedCaptureHold('Contact segment exact C09 row differs')
    value=contact_segment_original_from_wire_v1(json.loads(row[6]))
    if (namespace_ref(value.namespace)!=authority_namespace or row[:6]!=(*value.namespace.as_tuple,value.contact_id,
            value.segment_index,value.operation_id,value.effect_id)or value.digest!=row[7]):
        raise C09PagedCaptureHold('Contact segment indexed C09 namespace/original commitment differs')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((value.namespace,value.contact_id,value.segment_index,value.digest)),row[8])
    return 'segment_original',value.operation_id,json.loads(row[6]),value.digest


def read_installed_contact_observation_locator_v1(graph,installed,operation_id):
    from .contact_dispatch_host_v3 import _INSTALLED
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    if _INSTALLED.get(id(installed))is not installed or installed.graph is not graph:
        raise AuthorityUnavailable('Contact observation metadata locator has no actual installed private consumer')
    ns=installed.route_port._namespace;store=graph._GraphCoordinator__store
    with store._lock:
        if store._db.in_transaction:raise AuthorityUnavailable('Observation locator must run outside the projection CAS')
        store._db.execute('BEGIN')
        try:
            with runtime_storage_quantum_v3(store._db)as meter:
                row=_runtime_bounded_fixed_row_v3(store._db,meter,TABLE,COLUMNS,'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation_id))
            if row is None:return None
            value=contact_segment_original_from_wire_v1(json.loads(row[6]))
            if (row[:6]!=(*ns.as_tuple,value.contact_id,value.segment_index,operation_id,value.effect_id)
                    or value.namespace!=ns or row[7]!=value.digest):
                raise AuthorityUnavailable('Installed Contact observation metadata locator changed its signed original tuple')
            graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                canonical_serialize((ns,value.contact_id,value.segment_index,value.digest)),row[8])
            return value
        finally:store._db.rollback()


def begin_contact_continuation_capture_read_v1(service,*,credential,subject,permit,write_permit,selector,policy,location):
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationSelectorV1
    from ..authority_service.v2_contract import FencePermitV2
    from ..authority_service.contact_background_graph_v3 import ContactBackgroundSelectorV3,begin_contact_authority_graph_read_v3
    if (type(selector)is not ContactContinuationSelectorV1 or type(permit)is not FencePermitV2
            or type(write_permit)is not FencePermitV2 or write_permit.operation!='write'
            or permit.operation not in {'read','write'} or (permit.operation=='write'and permit!=write_permit)
            or permit.namespace!=write_permit.namespace or permit.subject!=write_permit.subject or permit.holder!=write_permit.holder
            or write_permit.generation!=permit.generation or policy.namespace!=selector.namespace or policy.policy.policy_id!=selector.policy_id):
        raise AuthorityUnavailable('Continuation existing capture requires original exact WRITE or its independent current metadata READ')
    selected=ContactBackgroundSelectorV3(selector.namespace,selector.contact_id,selector.operation_id,selector.request_digest,
        selector.policy_id,selector.causal_dedupe_key)
    work=begin_contact_authority_graph_read_v3(service,credential=credential,subject=subject,permit=permit,
        selector=selected,policy=policy,location=location)
    work.continuation_original_write_permit=write_permit
    from ..authority_service.current_authority_graph_read_v3 import (read_authority_graph_current_v3,finish_authority_graph_read_work_v3,
        _track_authority_capability_v3,_DEADLINES)
    _PROJECTION_WORKS[work]=(service,selector,write_permit,permit,work.scope,work.operation,location)
    _track_authority_capability_v3(work,_PROJECTION_WORKS,work)
    # Read only the signed scalar/identifier capsule before any current Source
    # phase; this fixed attachment gate cannot open body or other originals.
    original_phase=work.phase
    work.phase='validate'
    _CAPTURE_LOCATORS[work]=(selector,write_permit)
    _track_authority_capability_v3(work,_CAPTURE_LOCATORS,work)
    try:
        original=read_authority_graph_current_v3(work,lambda db:read_contact_segment_original_v1(db,namespace=selector.namespace,
            contact_id=selector.contact_id,segment_index=selector.segment_index,issuer=service._issuer))
        if original is None or original.operation_id!=selector.operation_id or original.request_digest!=selector.request_digest:
            raise AuthorityUnavailable('Continuation capture metadata locator changed actual original identity')
        from ..authority_service.contact_continuation_contract_v1 import ContactContinuationObservationV1,contact_continuation_from_wire_v1
        observed=contact_continuation_from_wire_v1(original.core_observation,ContactContinuationObservationV1)
        deadline=min(work.deadline_utc,original.deadline_utc,observed.deadline_utc)
        if service._clock()>=deadline:raise AuthorityUnavailable('Continuation stored capture original absolute TTL expired before Source rights/body')
        work.deadline_utc=work.operation.deadline_utc=float(deadline);work.deadline_original=original
        _DEADLINES[work]=(work.operation,work.deadline_utc,original)
        _CAPTURE_LOCATORS.pop(work,None)
        work.phase=original_phase;work.complete=False;work.prepared=None
        return work
    except BaseException:
        finish_authority_graph_read_work_v3(work);raise

def read_contact_continuation_capture_original_v1(db,*,work,write_permit,selector,issuer):
    from ..authority_service.contact_continuation_contract_v1 import ContactContinuationSelectorV1,ContactContinuationObservationV1,contact_continuation_from_wire_v1
    from ..authority_service.v2_contract import from_wire,canonical_digest as authority_digest
    if (type(selector)is not ContactContinuationSelectorV1 or work.db is not db or work.namespace!=selector.namespace
            or work.continuation_original_write_permit!=write_permit
            or _PROJECTION_WORKS.get(work)!=(work.service,selector,write_permit,work.permit,work.scope,work.operation,work.contact_location)):
        raise AuthorityUnavailable('Continuation existing capture has another actual metadata Source READ tuple')
    original=read_contact_segment_original_v1(db,namespace=selector.namespace,contact_id=selector.contact_id,segment_index=selector.segment_index,issuer=issuer)
    if original is None or original.operation_id!=selector.operation_id or original.request_digest!=selector.request_digest:
        raise AuthorityUnavailable('Continuation existing capture is outside its exact signed five-write original')
    observed=contact_continuation_from_wire_v1(original.core_observation,ContactContinuationObservationV1)
    attempt=_point(db,table='graph_owner_domain_attempts_v3',columns=('request_digest','attempt_id','permit_json'),
        key_columns=('bot','persona','operation_id'),key=(*selector.namespace.as_tuple,selector.operation_id))
    if (attempt is None or attempt[:2]!=(selector.request_digest,write_permit.operation_id)
            or from_wire(json.loads(attempt[2]))!=write_permit or observed.selector!=selector
            or observed.attempt_id!=write_permit.operation_id or observed.permit_digest!=authority_digest(write_permit).removeprefix('sha256:')):
        raise AuthorityUnavailable('Continuation existing capture cannot borrow another actual WRITE request/attempt')
    from .dispatch_admission import load_request
    issued=load_request(db,selector.namespace,original.admission_ref)
    if issued is None or issued[0].receipt_digest!=original.admission_receipt_digest or canonical_digest(issued[1])!=original.dispatch_request_digest:
        raise AuthorityUnavailable('Continuation existing capture lost its actual immutable new-segment admission')
    first=read_contact_segment_original_v1(db,namespace=selector.namespace,contact_id=selector.contact_id,segment_index=0,issuer=issuer)
    prefix=_prefix(db,first=first,index=selector.segment_index,issuer=issuer)
    inputs=json.loads(observed.inputs_json)
    if (canonical_serialize(prefix)!=canonical_serialize(inputs['prefix'])or original.root_lease_ref!=first.root_lease_ref
            or original.deadline_utc>observed.deadline_utc or work.service._clock()>=min(work.deadline_utc,original.deadline_utc)):
        raise AuthorityUnavailable('Continuation existing capture changed its original financial prefix/root/absolute deadline')
    root=issuer.current_budget_grant(db,original.root_lease_ref)
    if (root.grant_id,root.version,canonical_digest(root))!=(original.root_grant_id,original.root_grant_version,original.root_grant_digest):
        raise AuthorityUnavailable('Continuation existing capture cannot replace its original root grant')
    from .budget import get_budget_lease,require_budget_family_admissible
    lease=get_budget_lease(db,root.lease_id);require_budget_family_admissible(db,root.lease_id)
    if lease.state!='active':raise AuthorityUnavailable('Continuation existing capture original budget is inactive')
    quote=issuer._d02.original_signed_quote(db,original.quote_id,original.quote_version)
    reservation=_point(db,table='runtime_budget_reservations',columns=('digest','ceiling_json','state'),
        key_columns=('lease_id','operation_id'),key=(root.lease_id,selector.operation_id))
    if (canonical_digest(quote)!=original.quote_digest or reservation is None or reservation[0]!=original.reservation_digest
            or reservation[2]!='reserved' or json.loads(reservation[1])!=dict(original.reservation_ceiling)):
        raise AuthorityUnavailable('Continuation existing capture original message quote/reservation changed before handoff')
    return {'segment_original':asdict(original),'observation_wire':original.core_observation,'request':issued[1],
        'admission_receipt':issued[0],'inputs':{**inputs,'prefix':list(prefix)}}
