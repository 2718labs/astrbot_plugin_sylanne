"""Exact observed-action/ACK Source Work originals; historical facts grant no send right."""
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,GraphWrite,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest,OperationIdentity
from ..domains.d01.production_operations_v1 import plain_v1
from .d01_production_operations_v1 import CurrentDomainReadV1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d08_commitment_scope_read_v1 import _ScopeJSONColumnV1

OPERATIONS=frozenset({'settle_observed_action','acknowledge_bilateral'})

def _active(db):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    return r if r is not None and r.operation_kind in OPERATIONS else None

def _state(r):
    from .current_commitment_input_source_v3 import require_commitment_input_source_v3
    return require_commitment_input_source_v3(r)

def _need(r,identity):
    from .current_method_learning_read_v3 import _need_method_input
    task=_state(r).tasks.get(identity)
    if task is None or not task.complete:_need_method_input(r,('commitment_input_metadata',identity))
    return task

class CommitmentLifecycleMetadataV3:
    def __init__(self,r):
        self.reader,self.db,self.operation=r,r.db,r.operation;self.current=None;self.columns={};self.complete=False;self.phase='outbound'
    def _begin(self,tag,table,column,keys,key,cell_id=None,metadata=False):
        from .natural_outbound_receipt_adoption_read_v3 import _ReceiptMetadataColumnV3
        cls=_ReceiptMetadataColumnV3 if metadata else _ScopeJSONColumnV1
        self.current=(tag,cls(self.reader,table=table,column=column,key_columns=keys,key=key,cell_id=cell_id))
    def value(self,tag):return self.columns[tag].require_v3(self.reader)
    def advance(self,meter):
        r=self.reader;r.require_current(meter=meter);state=_state(r)
        if self.current is not None:
            tag,column=self.current
            if column.advance(meter):self.columns[tag]=column;self.current=None
            return False
        if self.phase=='outbound':
            from .current_commitment_fulfillment_source_v3 import lifecycle_outbound_receipt_ref_v3
            ref=lifecycle_outbound_receipt_ref_v3(r)
            # Only immutable locator/header columns precede Source qualification.
            rows=r.db.execute('SELECT final_operation_id,observation_digest,source_ref,slot_ref,batch_ref,original_digest FROM graph_d13_outbound_observations_v1 WHERE bot=? AND persona=? AND (source_ref=? OR observation_digest=? OR final_operation_id=?) LIMIT 3',(*r.namespace.as_tuple,ref,ref,ref)).fetchall();meter.charge_read(8192)
            if len(rows)!=1:raise AuthorityUnavailable('Commitment lifecycle requires one actual adopted outbound observation')
            self.outbound=rows[0]
            self.bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('activity_id','effect_id','digest'),'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,self.outbound[0]))
            if self.bundle is None:raise AuthorityUnavailable('observed commitment lost its actual final bundle')
            self._begin('candidate','graph_bundle_operations','receipt_json',('bot','persona','operation_id'),(*r.namespace.as_tuple,self.outbound[0]),metadata=True);self.phase='event';return False
        if self.phase=='event':
            raw=self.value('candidate');self.family='commitment_literal'if raw.get('dispatch_candidate')is not None else'natural'
            self.candidate=raw.get('dispatch_candidate')if self.family=='commitment_literal'else raw.get('natural_dispatch_candidate')
            if type(self.candidate)is not dict or len(self.candidate.get('refs',()))!=4:raise AuthorityUnavailable('lifecycle requires one registered actual final candidate')
            self.epoch=meter.read_fixed_row(r.db,'graph_events',('epoch_revision',),'bot=? AND persona=? AND session=? AND event_id=?',(*r.namespace.as_tuple,self.bundle[0],self.outbound[0]))
            if self.epoch!=(self.candidate['graph_epoch'],):raise AuthorityUnavailable('actual final candidate event changed')
            self._begin('reads','graph_events','reads',('bot','persona','session','event_id'),(*r.namespace.as_tuple,self.bundle[0],self.outbound[0]));self.phase='revisions';return False
        if self.phase=='revisions':
            self._begin('revisions','graph_events','revisions',('bot','persona','session','event_id'),(*r.namespace.as_tuple,self.bundle[0],self.outbound[0]));self.phase='complete';return False
        if self.phase=='complete':
            self.complete=True;return True
        raise AuthorityUnavailable('unregistered Commitment lifecycle locator phase')


def lifecycle_read_plan_v3(db,*,namespace,activity_id,operation_kind,request):
    from .current_commitment_input_source_v3 import TYPES
    from .d01_production_operations_v1 import production_read_plan_v1
    from .d08_production_operations_v1 import observed_action_outcome_key_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    r=_active(db)
    if r is None or r.namespace!=namespace or r.request!=request:raise AuthorityUnavailable('actual same-Work lifecycle Source selection required')
    state=_state(r);meta=_need(r,('lifecycle_locator',))
    fixed=(*TYPES,'d08.commitment.v1')
    state.keys.update(AtomKey.from_token(token)for token in r.heads if AtomKey.from_token(token).type_name in fixed)
    selected={AtomKey.from_token(ref)for ref,_ in meta.candidate['refs']}
    selected.update(AtomKey.from_token(ref)for ref,_ in (*meta.value('reads'),*meta.value('revisions'))if AtomKey.from_token(ref).type_name in {'d08.commitment_communication_intent.v1','d08.commitment_promise_use.v1','d08.commitment_communication_intent.v2','d08.commitment_promise_use.v2','d08.commitment_fulfillment_terms.v1','d08.commitment_terms_acceptance.v1'})
    if operation_kind=='settle_observed_action':selected.update((AtomKey.from_token(request.action_intent_ref),AtomKey.from_token(request.cost_settlement_ref)))
    else:
        selected.update((AtomKey.from_token(request.commitment_ref),AtomKey.from_token(request.acceptance_interpretation_ref)))
        from ..domains.d08.commitment_fulfillment_v1 import terms_key_v1
        terms_key=terms_key_v1(namespace,AtomKey.from_token(request.commitment_ref).name)
        from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
        with runtime_storage_quantum_v3(db)as meter:
            terms_head=_runtime_bounded_fixed_row_v3(db,meter,'graph_atoms',('revision','valid'),
                'token=? AND bot=? AND persona=?',(terms_key.token,*namespace.as_tuple))
        if terms_head is not None:raise AuthorityUnavailable('terms-bearing commitment requires exact inbound terms ACCEPT producer')
        selected.add(terms_key)
    state.keys.update(selected);state.roots.update(meta.candidate['source_refs']);state.roots.add(meta.outbound[2])
    if operation_kind=='acknowledge_bilateral':state.roots.add(request.inbound_source_ref)
    for key in sorted(state.keys,key=lambda k:k.token):
        # Scope/Use metadata never opens their approved literal; actual original
        # bytes enter only the complete Source-qualified historical stream.
        if key.type_name in {'d08.commitment_communication_intent.v1','d08.commitment_promise_use.v1','d08.commitment_communication_intent.v2','d08.commitment_promise_use.v2','d08.commitment_fulfillment_terms.v1','d08.commitment_terms_acceptance.v1'}:continue
        task=_need(r,key.token)
        from ..authority_service.habit_authority_source_read_v3 import _source_refs_v3
        state.roots.update(_source_refs_v3(task.result))
    keys=state.keys|{owner_grant_key(*namespace.as_tuple)}
    if operation_kind=='settle_observed_action':
        raw=_need(r,request.action_intent_ref).result
        identity=decode_typed_production_value_v1(raw['identity'],OperationIdentity)
        from types import SimpleNamespace
        keys.add(observed_action_outcome_key_v1(AtomKey.from_token(request.action_intent_ref),SimpleNamespace(identity=identity,action_id=raw['action_id'])))
    state.metadata_complete=True
    return production_read_plan_v1(fixed,tuple(sorted(keys,key=lambda k:k.token)),tuple(sorted(state.roots)),
        tuple(dict.fromkeys((request.outbound_receipt_ref,*((request.cost_settlement_ref,request.action_intent_ref)if operation_kind=='settle_observed_action'else(request.acceptance_interpretation_ref,))))))


def read_bound_commitment_lifecycle_identity_v3(db,*,namespace,operation_kind,request):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    r=_active(db)
    if r is None or operation_kind!='settle_observed_action':return False,None
    if r.namespace!=namespace or r.request!=request:raise AuthorityUnavailable('lifecycle command identity crossed actual Work')
    key=AtomKey.from_token(request.action_intent_ref);_state(r).keys.add(key)
    raw=_need(r,key.token).result;identity=decode_typed_production_value_v1(raw['identity'],OperationIdentity)
    return True,(identity.activity_id,identity.effect_id,raw['purpose'])

class CommitmentLifecycleOriginalReadV3:
    def __init__(self,r):
        self.owner=r;self.db,self.namespace,self.operation=r.db,r.namespace,r.operation
        self.meta=_need(r,('lifecycle_locator',));self.final_operation_id=self.meta.outbound[0]
        self.family=self.meta.family;self.candidate_metadata=self.meta.candidate;self.columns={};self.current=None;self.complete=False;self.phase='observation';self.named_original=None
        self.qualified=True;self.observed=None;self.result=None;self.graph=r.graph;self.adoption_origin=None
        state=_state(r)
        if state.permission is None:raise AuthorityUnavailable('lifecycle historical Body requires actual SourceALL EOF')
        state.permission.require_for_v3(r)
    def require_current_v3(self,meter=None):
        r=self.owner;r.require_current(meter=meter);_state(r).permission.require_for_v3(r)
        if self.operation.closed:raise AuthorityUnavailable('lifecycle original lost actual retained Work')
    def _begin(self,tag,table,column,keys,key,cell_id=None):self.current=(tag,_ScopeJSONColumnV1(self.owner,table=table,column=column,key_columns=keys,key=key,cell_id=cell_id))
    def value(self,tag):return self.columns[tag].require_v3(self.owner)
    def advance(self,meter):
        self.require_current_v3(meter);r=self.owner
        if self.current is not None:
            tag,column=self.current
            if column.advance(meter):self.columns[tag]=column;self.current=None
            return False
        if self.phase=='observation':
            self._begin('observation','graph_d13_outbound_observations_v1','observation_json',('bot','persona','final_operation_id','observation_digest'),(*r.namespace.as_tuple,self.final_operation_id,self.meta.outbound[1]));self.phase='adoption';return False
        if self.phase=='adoption':
            self._begin('adoption','graph_d13_outbound_observations_v1','original_json',('bot','persona','final_operation_id','observation_digest'),(*r.namespace.as_tuple,self.final_operation_id,self.meta.outbound[1]));self.phase='verify_adoption';return False
        if self.phase=='verify_adoption':
            from ..authority_service.v2_contract import MutationReceiptV2
            from ..authority_service.observation_refinement_contract_v3 import (
                PlatformObservationRefinementReceiptV3,from_wire,observation_platform_observation_v3)
            self.observed=from_wire(self.value('observation'));original=self.value('adoption')
            if(type(self.observed)not in (MutationReceiptV2,PlatformObservationRefinementReceiptV3) or self.observed.durable_state!='committed'
                or canonical_digest(self.observed)!=self.meta.outbound[1]or canonical_digest(original)!=self.meta.outbound[5]
                or original['observation_digest']!=self.meta.outbound[1]or original['source_ref']!=self.meta.outbound[2]
                or original['slot_ref']!=self.meta.outbound[3]or original['batch_ref']!=self.meta.outbound[4]):
                raise AuthorityUnavailable('lifecycle actual adopted outbound receipt/original changed')
            origin=observation_platform_observation_v3(self.observed).binding.origin
            if (origin.operation_id,origin.activity_id,origin.effect_id)!=(self.final_operation_id,*self.meta.bundle[:2]):raise AuthorityUnavailable('lifecycle observed final identity differs')
            self.adoption_origin=LifecycleAdoptionOriginReadV3(self);self.phase='adoption_origin';return False
        if self.phase=='adoption_origin':
            if not self.adoption_origin.advance(meter):return False
            if self.family=='commitment_literal':
                from .d08_commitment_outbound_receipt_v1 import NamedCommitmentOutboundReceiptMetadataV1
                self.named_original=NamedCommitmentOutboundReceiptMetadataV1(self);self.phase='named';return False
            self.queue=list(self.meta.candidate['refs']);self.phase='natural';return False
        if self.phase=='named':
            if self.named_original.advance(meter):self.result=self.named_original.result;self.complete=True;return True
            return False
        if self.phase=='natural':
            if self.queue:
                token,revision=self.queue.pop(0)
                if [token,revision]not in self.meta.value('revisions'):raise AuthorityUnavailable('lifecycle natural member differs from actual event')
                row=meter.read_fixed_row(self.db,'graph_history',('value_cell_id','valid','event_id','event_bot','event_persona'),'token=? AND revision=?',(token,revision))
                if row is None or row[1:]!=(1,self.final_operation_id,*self.namespace.as_tuple):raise AuthorityUnavailable('lifecycle natural member origin changed')
                self._begin(token,'graph_history','value',('token','revision'),(token,revision),row[0]);return False
            from .dispatch_candidate import validate_dispatch_candidate_writes,NaturalDispatchCandidateRecoveryV2
            from ..domains.d08.execution import _decode_intent
            writes=tuple(('d09'if i==3 else'd08',GraphWrite(AtomKey.from_token(ref),self.value(ref)))for i,(ref,rev)in enumerate(self.meta.candidate['refs']))
            intent=_decode_intent(writes[0][1].value);candidate=self.meta.candidate
            evidence=validate_dispatch_candidate_writes(writes,namespace=self.namespace,identity=intent.identity,
                read_versions=tuple(GraphVersion(AtomKey.from_token(ref),rev)for ref,rev in self.meta.value('reads')),
                source_refs=tuple(candidate['source_refs']),access_epoch=candidate['access_epoch'],delete_epoch=candidate['delete_epoch'],query_epoch=candidate['query_epoch'])
            if evidence.digest!=candidate['digest']:raise AuthorityUnavailable('lifecycle actual natural candidate digest differs')
            self.result=NaturalDispatchCandidateRecoveryV2(evidence,tuple(tuple(row)for row in candidate['refs']),candidate['graph_epoch'],candidate['graph_incarnation'],candidate['graph_revision'])
            self.complete=True;return True
        raise AuthorityUnavailable('unregistered lifecycle original stream phase')
    def release_v1(self):
        if self.named_original is not None:self.named_original.release_v1()
        for column in self.columns.values():column._frozen_value=None
        self.columns.clear();self.current=self.result=self.observed=None


def lifecycle_originals_v3(r):
    return _need(r,('lifecycle_originals',))


def read_bound_commitment_lifecycle_originals_v3(db,*,namespace,plan):
    from .current_method_learning_read_v3 import method_graph_head_v3
    r=_active(db)
    if r is None:return False,None
    if namespace!=r.namespace or plan!=r.selected_plan:raise AuthorityUnavailable('lifecycle originals crossed its actual selected plan')
    task=lifecycle_originals_v3(r);result=[]
    for ref in plan.required_original_refs:
        if ref==r.request.outbound_receipt_ref:
            result.append(ProductionOriginalRefV1('d11.outbound_observation',ref,canonical_digest(task.observed)));continue
        key=AtomKey.from_token(ref);atom=method_graph_head_v3(db,namespace,key)
        if not atom.valid:raise AuthorityUnavailable('lifecycle original current head unavailable')
        history=_need(r,('lifecycle_head_original',ref,atom.revision))
        kind=key.type_name
        if kind=='runtime.cost_settlement':
            from .d11_types import cost_settlement_from_runtime
            actual=cost_settlement_from_runtime(db,**{name:atom.value[name]for name in ('bot_id','persona_id','activity_id','bundle_operation_id','effect_id','settlement_id','lease_id','cost_operation_id','budget_operation_id','budget_phase','prior_unknown_ref','execution_revoked')})
            if plain_v1(actual)!=atom.value:raise AuthorityUnavailable('lifecycle cost differs from independent D11 settlement')
            kind='d11.cost_settlement'
        if history.value('head')!=atom.value:raise AuthorityUnavailable('lifecycle current original differs from its actual adopted history')
        result.append(ProductionOriginalRefV1(kind,ref,canonical_digest(atom.value),(GraphVersion(key,atom.revision),)))
    return True,tuple(result)


class LifecycleHeadOriginalV3:
    def __init__(self,r,ref,revision):self.reader=r;self.ref,self.revision=ref,revision;self.column=self.event_column=None;self.complete=False;self.result=None
    def value(self,tag):return self.column.require_v3(self.reader)
    def advance(self,meter):
        r=self.reader;r.require_current(meter=meter);_state(r).permission.require_for_v3(r)
        row=meter.read_fixed_row(r.db,'graph_history',('value_cell_id','valid','event_bot','event_persona','event_session','event_id'),'token=? AND revision=?',(self.ref,self.revision))
        if row is None or row[1]!=1 or row[2:4]!=r.namespace.as_tuple:raise AuthorityUnavailable('lifecycle graph Original history absent')
        if self.column is None:
            self.header=row;self.column=_ScopeJSONColumnV1(r,table='graph_history',column='value',key_columns=('token','revision'),key=(self.ref,self.revision),cell_id=row[0]);return False
        if row!=self.header:raise AuthorityUnavailable('lifecycle Original history changed')
        if not self.column.complete:
            if not self.column.advance(meter):return False
        if self.event_column is None:
            self.event_column=_ScopeJSONColumnV1(r,table='graph_events',column='revisions',key_columns=('bot','persona','session','event_id'),key=tuple(self.header[2:]))
            return False
        if not self.event_column.advance(meter):return False
        if [self.ref,self.revision]not in self.event_column.require_v3(r):raise AuthorityUnavailable('lifecycle Original was not written by its actual graph event')
        if AtomKey.from_token(self.ref).type_name=='d07.current_interpretation.v1':
            bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('commit_seq',),'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,self.header[5]))
            if bundle is None or bundle[0]<1:raise AuthorityUnavailable('lifecycle semantic adoption lacks actual committed producer')
        self.complete=True;return True

    def release_v1(self):
        if self.column is not None:self.column._frozen_value=None
        if self.event_column is not None:self.event_column._frozen_value=None
        self.column=self.event_column=None

class CommitmentLifecycleDomainReadV3(CurrentDomainReadV1):
    def adopted_outbound_observation(self,db,ref):
        r=_active(db);task=lifecycle_originals_v3(r)
        if ref!=r.request.outbound_receipt_ref:raise AuthorityUnavailable('lifecycle observation ref changed')
        self.source_family(db,(task.meta.outbound[2],),purpose='context');return task.observed,self.original(ref)
    def adopted_interpretation(self,db,ref,*,question_scope):
        from ..domains.d07 import D07DomainProvider
        r=_active(db);atom=self.head(db,ref,required=True)
        next(spec for spec in D07DomainProvider.type_specs()if spec.name==atom.key.type_name).validator(atom.value)
        history=_need(r,('lifecycle_head_original',ref,atom.revision))
        if history.value('head')!=atom.value:raise AuthorityUnavailable('actual semantic adoption changed')
        value=atom.value
        if(value['question_key']!=question_scope or value['stance']!='support'or value['evidence_status']!='supported'or value['meaningful_unknowns']or value['current']is not True):
            from .d01_production_operations_v1 import MissingProductionOriginalV1
            raise MissingProductionOriginalV1('explicit_current_semantic_scope:'+question_scope)
        return atom,self.original(ref,digest=canonical_digest(value)),self.source_family(db,tuple(value['source_refs']))

def commitment_lifecycle_read_v3(db,frame):
    return CommitmentLifecycleDomainReadV3(frame)if _active(db)is not None else CurrentDomainReadV1(frame)

def current_commitment_lifecycle_recovery_v3(db,namespace,operation_id):
    r=_active(db)
    if r is None:return None
    task=lifecycle_originals_v3(r)
    if namespace!=r.namespace or operation_id!=task.final_operation_id:raise AuthorityUnavailable('lifecycle final original locator changed')
    return task.result


def commitment_lifecycle_source_groups_v3(r,roots):
    state=_state(r);meta=_need(r,('lifecycle_locator',))
    if not state.metadata_complete or set(roots)!=state.roots:raise AuthorityUnavailable('lifecycle Source roots changed after actual metadata EOF')
    expression=tuple(sorted(set(meta.candidate['source_refs'])))
    context=tuple(sorted(roots))
    return (('context',(r.audience_ref,),context),('expression',(r.audience_ref,),expression))


class LifecycleAdoptionOriginReadV3:
    """Authenticate this adoption event and any independently reused Source birth."""
    def __init__(self,owner):
        self.owner=owner;self.phase="current_setup";self.queue=[];self.complete=False
        self.current_original=owner.value("adoption");self.birth_after="";self.birth_header=None;self.prefix="current_adoption"
    def _event_setup(self,meter,original,prefix):
        owner=self.owner;r=owner.owner;op=original["operation_id"]
        self.event=meter.read_fixed_row(owner.db,"graph_events",("epoch_revision",),
            "bot=? AND persona=? AND session=? AND event_id=?",(*owner.namespace.as_tuple,"d13-outbound-observation",op))
        if self.event!=(original["pre_epoch"]+1,):raise AuthorityUnavailable("outbound adoption lacks its actual E+1 graph event")
        self.active_original=original;self.prefix=prefix;self.queue=["reads","revisions","invalidated"];self.phase="event_columns"
    def _verify_event(self,meter):
        from ..graph_types import GraphReceipt,NamespaceEpoch
        from ..authority_service.observation_refinement_contract_v3 import from_wire
        from ..authority_service.v2_contract import FencePermitV2
        o=self.owner;original=self.active_original;prefix=self.prefix
        revisions=tuple(GraphVersion(AtomKey.from_token(ref),rev)for ref,rev in o.value(prefix+"_revisions"))
        invalidated=tuple(GraphVersion(AtomKey.from_token(ref),rev)for ref,rev in o.value(prefix+"_invalidated"))
        reads=tuple(GraphVersion(AtomKey.from_token(ref),rev)for ref,rev in o.value(prefix+"_reads"))
        receipt=GraphReceipt("committed",revisions,invalidated,NamespaceEpoch(*o.namespace.as_tuple,self.event[0]))
        permit=from_wire(original["permit"])
        if (canonical_digest(receipt)!=original["graph_receipt_digest"]or type(permit)is not FencePermitV2 or permit.operation!="write"
                or permit.operation_id!=original["operation_id"]
                or original["finish_digest"]!="sha256:"+canonical_digest((original["operation_id"],permit.token,original["observation_digest"]))):
            raise AuthorityUnavailable("outbound adoption differs from its actual graph receipt/WRITE finish")
        for version in revisions:
            row=meter.read_fixed_row(o.db,"graph_history",("valid","event_bot","event_persona","event_session","event_id"),
                "token=? AND revision=?",(version.key.token,version.revision))
            if row!=(1,*o.namespace.as_tuple,"d13-outbound-observation",original["operation_id"]):
                raise AuthorityUnavailable("outbound adoption event member lost its actual immutable history")
        return reads,revisions
    def advance(self,meter):
        o=self.owner;r=o.owner;o.require_current_v3(meter)
        if self.phase=="current_setup":
            from ..memory_types import source_key
            expected=source_key(*o.namespace.as_tuple,"outbound:"+canonical_digest((o.namespace,o.final_operation_id))[:48]).token
            if o.meta.outbound[2]!=expected:raise AuthorityUnavailable("outbound Source is not this actual final dispatch's authored original")
            self.source=AtomKey.from_token(expected)
            self.source_birth=meter.read_fixed_row(o.db,"graph_history",("valid","event_bot","event_persona","event_session","event_id"),
                "token=? AND revision=?",(expected,1))
            if self.source_birth is None or self.source_birth[:4]!=(1,*o.namespace.as_tuple,"d13-outbound-observation"):
                raise AuthorityUnavailable("outbound authored Source has no actual first producer history")
            self._event_setup(meter,self.current_original,"current_adoption");return False
        if self.phase=="event_columns":
            if self.queue:
                name=self.queue.pop(0)
                o._begin(self.prefix+"_"+name,"graph_events",name,("bot","persona","session","event_id"),
                    (*o.namespace.as_tuple,"d13-outbound-observation",self.active_original["operation_id"]));return False
            reads,revisions=self._verify_event(meter)
            source_version=GraphVersion(self.source,1)
            if self.prefix=="current_adoption":
                if self.source_birth[4]==self.current_original["operation_id"]:
                    if source_version not in revisions or GraphVersion(self.source,0)not in reads:
                        raise AuthorityUnavailable("first outbound Source is not this actual adoption's absent-to-one write")
                    self.complete=True;return True
                if source_version not in reads or source_version in revisions:
                    raise AuthorityUnavailable("refined outbound fact must read the independently existing exact Source@1")
                self.phase="birth_locator";return False
            if source_version not in revisions or GraphVersion(self.source,0)not in reads:
                raise AuthorityUnavailable("reused Source birth lacks its independent actual absent-to-one producer")
            self.complete=True;return True
        if self.phase=="birth_locator":
            row=meter.read_fixed_row(o.db,"graph_d13_outbound_observations_v1",("observation_digest","source_ref","slot_ref","batch_ref","original_digest"),
                "bot=? AND persona=? AND final_operation_id=? AND source_ref=? AND observation_digest>? ORDER BY observation_digest",
                (*o.namespace.as_tuple,o.final_operation_id,self.source.token,self.birth_after))
            if row is None:raise AuthorityUnavailable("reused outbound Source has no actual first observation producer Original")
            self.birth_header=row;self.birth_after=row[0]
            o._begin("birth_original","graph_d13_outbound_observations_v1","original_json",("bot","persona","final_operation_id","observation_digest"),
                (*o.namespace.as_tuple,o.final_operation_id,row[0]));self.phase="birth_original";return False
        if self.phase=="birth_original":
            original=o.value("birth_original")
            if canonical_digest(original)!=self.birth_header[4]:raise AuthorityUnavailable("Source birth adoption original digest differs")
            if original["operation_id"]!=self.source_birth[4]:self.phase="birth_locator";return False
            if ((original["source_ref"],original["slot_ref"],original["batch_ref"],original["observation_digest"])!=
                    (self.source.token,o.meta.outbound[3],o.meta.outbound[4],self.birth_header[0])):
                raise AuthorityUnavailable("Source birth changed actual dispatch batch/slot/observation identity")
            self.birth_original=original
            o._begin("birth_observation","graph_d13_outbound_observations_v1","observation_json",("bot","persona","final_operation_id","observation_digest"),
                (*o.namespace.as_tuple,o.final_operation_id,self.birth_header[0]));self.phase="birth_observation";return False
        if self.phase=="birth_observation":
            from ..authority_service.observation_refinement_contract_v3 import from_wire,observation_platform_observation_v3
            observed=from_wire(o.value("birth_observation"))
            if canonical_digest(observed)!=self.birth_header[0]or observed.durable_state!="committed":
                raise AuthorityUnavailable("Source birth observation differs from its actual immutable original")
            first=observation_platform_observation_v3(observed);current=observation_platform_observation_v3(o.observed)
            if (first.binding!=current.binding or first.destination_ref!=current.destination_ref or first.account_ref!=current.account_ref):
                raise AuthorityUnavailable("reused Source birth belongs to another original dispatch/effect/payload/route")
            self._event_setup(meter,self.birth_original,"birth_adoption");return False
        raise AuthorityUnavailable("unregistered actual adoption/Source birth metadata phase")
