"""Private reply P2: metadata EOF, current Owner and Source ALL before selected Body."""
from dataclasses import dataclass,replace
from weakref import WeakKeyDictionary
from types import SimpleNamespace

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,GraphVersion,GraphWrite,owner_grant_key,OWNER_GRANT_TYPE
from ..runtime_contracts import NamespaceId,canonical_digest
from ..memory_types import source_key,access_key,validate_access
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .source_correction_read_v3 import _heap

_TASKS=WeakKeyDictionary()
_SEALS=WeakKeyDictionary()
_CELLS=WeakKeyDictionary()
_BODY_TYPES=frozenset({'d08.action_intent.v1','d08.action_schema.v1','d08.communication_intent_grant.v1',
    'd09.verified_segment_batch.v1','d08.goal.v1','d08.commitment.v1','d08.action_cancellation.v1',
    'd08.action_outcome.v1','d03.entity_anchor','d03.account_binding','d03.role_binding',
    'd03.world_event','d05.boundary_rule'})

def _paths(kind):
    from .current_graph_full_read_v3 import _full_metadata_paths_v3
    from ..domains.d08.commitment_communication_v1 import USE_TYPES,SCOPE_TYPES
    paths=_full_metadata_paths_v3(kind)
    if kind=='d08.action_intent.v1':paths+=tuple((v,)for v in ('required_checks',))
    if kind in USE_TYPES:paths=tuple((v,)for v in ('schema','namespace','scope','commitment','operation_id','action_id','effect_id','source_refs'))
    if kind in SCOPE_TYPES:paths=tuple((v,)for v in ('schema','namespace','commitment','fulfillment_terms','terms_acceptance',
        'source_refs','route_source_ref','platform_ref','conversation_ref','scene_ref','target_ref',
        'policy_source_refs','policy_audiences','policy_read_versions'))
    from ..domains.d08.commitment_fulfillment_v1 import TERMS_TYPE,ACCEPTANCE_TYPE
    if kind=='d03.account_binding':paths+=(('account_id',),)
    if kind=='d08.action_outcome.v1':paths=tuple((v,)for v in ('outcome_id','action_id','action_revision','operation_id','activity_id','attempt_id','effect_id','result_level','unknown_effects','source_refs','outcome_refs'))
    if kind=='d09.verified_segment_batch.v1':paths+=(('segments','*','source_refs'),)
    if kind==TERMS_TYPE:paths=tuple((v,)for v in ('schema','namespace','commitment','source_refs','source_versions'))
    if kind==ACCEPTANCE_TYPE:paths=tuple((v,)for v in ('schema','namespace','terms','inbound_source_ref','inbound_versions'))
    from .dispatch_current_inventory_v3 import _RUNTIME_JOB_TYPE_V3
    if kind==_RUNTIME_JOB_TYPE_V3:
        from .d11_types import RuntimeJobValue
        paths=tuple((v,)for v in ('schema',*RuntimeJobValue.__dataclass_fields__))
    if kind=='private.action_job_binding_metadata.v3':
        from .dispatch_action_job_binding import DispatchActionJobBindingV1
        paths=tuple((v,)for v in DispatchActionJobBindingV1.__dataclass_fields__)
    return paths

class _Selector:
    def __init__(self,owner,kind):
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        self.paths=_paths(kind);self.builder=_CanonicalJSONValueBuilderV3();self.builder.operation=owner.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,
            frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
    def emit(self,event):
        from .current_graph_full_read_v3 import _full_metadata_event_v3
        if _full_metadata_event_v3(event,self.paths):self.builder._emit(event)
    def finish(self):
        from .dispatch_current_inventory_v3 import _detach_value_v3
        if self.builder.nodes:raise AuthorityUnavailable('private P2 metadata has no complete container EOF')
        return _detach_value_v3(self.builder.value)

@dataclass(frozen=True,eq=False)
class _MetadataCell:
    task:object
    key:object
    revision:int
    valid:bool
    cell_id:str
    header:tuple
    sha256:str
    selectors:object
    def identity(self):return(self.task,self.key,self.revision,self.valid,self.cell_id,self.header,self.sha256,self.selectors)
    def require(self,task):
        if _CELLS.get(self)!=self.identity()or self.task is not task or task.owner.heads.get(self.key.token)!=(self.revision,int(self.valid),self.cell_id):
            raise AuthorityUnavailable('private metadata lost actual full cell/head/EOF commitment')
        from .dispatch_current_inventory_v3 import _detach_value_v3
        return _detach_value_v3(self.selectors)

class _SelectedMetadataColumn(DispatchOriginalJSONReadV3):
    def __init__(self,owner,kind,**kw):
        self.selector=_Selector(owner,kind)
        super().__init__(owner,**kw)
        if self.cell is not None:self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0]=='canonical-json.ascii.v1')
    def _emit(self,event):self.selector.emit(event)
    def require_v3(self,owner):
        super().require_v3(owner)
        return self.selector.finish()

class PrivateDispatchSourceReadV3:
    def __init__(self,owner):
        self.owner=owner;self.phase='census';self.cells={};self.current=None;self.columns={}
        self.candidate=None;self.refs=();self.groups=();self.metadata_seal=None;self.owner_entry=None
        self.policy=None;self.action_cell=None;self.action=None;self.scope=None;self.use_ref=None
        self.selected=set();self.closures=();self.body_queue=[];self.history_queue=[]
        self.complete=False;self.qualified=False
        self.business_keys=();self.control_keys=();self.source_all_seal=None
        self.policy_keys=();self.conflict_versions=();self.policy_before=None;self.policy_sample=None
        self.route_metadata=None;self.account_versions=();self.account_matches=()
        self.dynamic_job=None;self.dynamic_job_binding=None;self.dynamic_job_header=None
        _TASKS[owner]=(self,owner.operation,owner.fence.scope,owner.binding,owner.admission,owner.read_time)
    def actual(self,meter=None):
        from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
        from ..graph_worker import GraphStorageWorkV3
        o=self.owner;w=o.work;s=o.fence.scope
        if(type(o)is not _DispatchInventoryReadV3 or o.family!='private_reply'
                or _TASKS.get(o)!=(self,o.operation,s,o.binding,o.admission,o.read_time)
                or type(w)is not GraphStorageWorkV3 or w.state is not o or w.operation is not o.operation
                or w.coordinator is not o.graph or w.selection_digest!=o.selection_digest
                or o.operation.closed or s.operation!='read' or s.permit.operation!='read'
                or s.operation_id!=o.operation.operation_id or s.permit.operation_id!=s.operation_id):
            raise AuthorityUnavailable('private P2 left its actual admitted READ Work')
        if not o.complete:w._require_invocation(o.graph)
        upper=o.read_time.require_current_v3(o.graph,o.binding)
        if self.policy_before is not None and upper>=self.policy_before:
            raise AuthorityUnavailable('private applicability crossed its original semantic time boundary')
        if meter is not None:
            if o.graph._v2_graph_stamp(o.namespace)!=o.graph_stamp:
                raise AuthorityUnavailable('private P2 original namespace stamp changed')
            o.operation.handle.require_current(meter)
            if o.authority_epochs is not None and o._epochs(meter)!=o.authority_epochs:
                raise AuthorityUnavailable('private P2 Source access/delete epochs changed')
        return self
    def begin_census(self,codec):
        self.actual();o=self.owner
        o.parser=C09CanonicalJSONStreamV2(ensure_ascii=codec=='canonical-json.ascii.v1')
        self.selector=_Selector(o,o.pending[3]);o.body=None
    def feed_census(self,part):self.owner.parser.feed(part,self.selector.emit)
    def finish_census(self,key,revision,valid,kind,cell,digest):
        self.actual();o=self.owner;o.heads[key.token]=(revision,valid,cell)
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        data=_freeze_value_v3(self.selector.finish())
        value=_MetadataCell(self,key,revision,bool(valid),cell,tuple(o.cell.header),digest,data)
        _CELLS[value]=value.identity();self.cells[key.token]=value
        o.operation.retain(_heap((data,value.header))+1024)
        self.selector=None
    def _meta(self,ref,required=True):
        cell=self.cells.get(ref)
        if cell is None:
            if required:raise AuthorityUnavailable('private selector has no actual metadata EOF')
            return None
        return cell.require(self)
    def _begin(self,tag,table,column,keys,key,*,cell=None,metadata_kind=None):
        kw=dict(table=table,column=column,key_columns=keys,key=key,cell_id=cell)
        self.current=(tag,DispatchOriginalJSONReadV3(self.owner,**kw)if metadata_kind is None else
            _SelectedMetadataColumn(self.owner,metadata_kind,**kw))
        if self.current[1].cell is not None:
            self.current[1].parser=C09CanonicalJSONStreamV2(ensure_ascii=self.current[1].cell.header[0]=='canonical-json.ascii.v1')
    def _value(self,tag):return self.columns[tag].require_v3(self.owner)
    def _route(self,meter):
        from .first_ingress_v2 import scene_ref_for_conversation
        o=self.owner;a=o.admission.admission;ns=o.namespace
        rows=o.db.execute('SELECT ingress_operation_id,c02_operation_id,source_ref,target_entity_ref,account_ref,destination_ref,admission_digest,state,ack_digest FROM graph_post_c02_reply_ownership_v1 WHERE bot=? AND persona=? AND admission_ref=? LIMIT 2',
            (*ns.as_tuple,a.admission_ref)).fetchmany(2)
        meter.charge_read(_heap(rows))
        if len(rows)!=1:raise AuthorityUnavailable('private P2 requires one actual owned ingress route')
        row=rows[0];ingress,c02,source,target,account,destination,digest,state,ack=row
        identity=o.graph._reply_ingress_identity_locked(ns,ingress)
        sid=AtomKey.from_token(source).owner.subject
        original=meter.read_fixed_row(o.db,'graph_first_ingress_identity_v1',('source_ref',),
            'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,ingress))
        seal=meter.read_fixed_row(o.db,'graph_first_ingress_c02_committed_seals_v2',('schema','bundle_digest'),
            'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,c02))
        committed=meter.read_fixed_row(o.db,'graph_bundle_operations',('digest',),
            'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,c02))
        if(original!=(sid,)or identity['source_ref']!=sid or committed is None
                or seal!=('sylanne.first-ingress-c02-candidate.v2',committed[0])
                or state!='sylanne_owned'or not ack or digest!=a.digest
                or(identity['platform_ref'],identity['conversation_ref'])!=(account,destination)
                or(a.account_ref,a.destination_ref,a.scene_ref,a.object_ref,a.audience)!=
                    (account,destination,scene_ref_for_conversation(ns,account,destination),target,(destination,))):
            raise AuthorityUnavailable('private P2 route/C02/ownership metadata differs')
        return source
    def _closure(self,roots):
        o=self.owner;active=set();done=set()
        def visit(ref):
            key=AtomKey.from_token(ref);source=o.sources.get(ref)
            if ref in active:raise AuthorityUnavailable('private P2 Source ancestry is cyclic')
            if ref in done:return
            if len(active)+len(done)>=32:raise AuthorityUnavailable('private P2 Source closure exceeds original bound')
            if source is None or not source.valid or key!=source_key(*o.namespace.as_tuple,source.metadata['source_id']):
                raise AuthorityUnavailable('private P2 Source metadata is unavailable')
            active.add(ref)
            for parent in source.metadata['parent_source_ids']:visit(source_key(*o.namespace.as_tuple,parent).token)
            active.remove(ref);done.add(ref)
        for ref in roots:visit(ref)
        return frozenset(done)
    def _select(self,meter):
        from ..domains.d03.context import RoleBinding,RoleBindingRequest
        from ..domains.d05.relationship import BoundaryRule
        from ..domains.d03.prebatch_social import _private_route
        from ..domains.d08.commitment_communication_v1 import USE_TYPES,SCOPE_TYPES
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        o=self.owner;a=o.admission.admission;action=self.action
        roots=tuple(action['source_refs'])
        if not roots:raise AuthorityUnavailable('private admitted action has no original Source roots')
        groups=[('expression',tuple(a.audience),roots)]
        route=self._route(meter)if action['identity']['phase']!='commitment_literal_v1'else(
            self.scope.get('route_source_ref')or self.scope['source_refs'][0])
        platform,destination,sender,message,scene=_private_route(o.db,o.namespace,route)
        if(platform,destination,scene)!=(a.account_ref,a.destination_ref,a.scene_ref):
            raise AuthorityUnavailable('private exact ingress route differs from admitted scene')
        self.route_metadata=(platform,destination,sender,message,scene)
        groups.append(('context',tuple(a.audience),(route,)))
        policy=self.policy.require_v3(o)
        if policy is not None and policy[0]:groups.append(('context',tuple(policy[1]),tuple(policy[0])))
        rclosure=self._closure(roots);self.selected={ref for ref,_ in self.refs}
        metadata={ref:self._meta(ref)for ref in self.cells}
        valid={ref:m for ref,m in metadata.items()if self.cells[ref].valid}
        target=action['target_ref'];persona='persona:'+o.namespace.persona_id
        self.policy_sample=o.now_utc
        future=[v for ref,m in valid.items()if self.cells[ref].key.type_name in
            {'d03.account_binding','d03.role_binding','d05.boundary_rule'}
            for name in('effective_from','effective_until','valid_from','valid_until')
            for v in(m.get(name),)if v is not None and v>self.policy_sample]
        self.policy_before=min(future)if future else None
        request=RoleBindingRequest(persona,target,None,a.scene_ref,action['action_kind'],action['purpose'],self.policy_sample,True)
        policy_roots=set();related_events=set();policy_keys=set();account_matches=[]
        own=set(action.get('commitment_refs',()))
        conflict_types={'d08.commitment.v1','d08.action_intent.v1','d08.action_outcome.v1'}
        self.conflict_versions=tuple(GraphVersion(self.cells[ref].key,self.cells[ref].revision)for ref in sorted(valid)
            if self.cells[ref].key.type_name in conflict_types)
        outcomes=[m for ref,m in valid.items()if self.cells[ref].key.type_name=='d08.action_outcome.v1']
        ids={kind:set()for kind in conflict_types}
        for ref,m in valid.items():
            kind=self.cells[ref].key.type_name;cell=self.cells[ref]
            if kind in conflict_types:
                field={'d08.commitment.v1':'commitment_id','d08.action_intent.v1':'action_id','d08.action_outcome.v1':'outcome_id'}[kind]
                if cell.key.name!=m[field]or m[field]in ids[kind]:
                    raise AuthorityUnavailable('private complete D08 metadata identity repeats or changed')
                ids[kind].add(m[field])
                if kind in{'d08.commitment.v1','d08.action_intent.v1'}and cell.revision!=m['revision']:
                    raise AuthorityUnavailable('private complete D08 metadata revision changed')
                if kind=='d08.commitment.v1'and m['subject_ref']!=persona:
                    raise AuthorityUnavailable('private current commitment has a foreign subject')
                if kind=='d08.action_intent.v1'and cell.key.owner.subject!=m['identity']['activity_id']:
                    raise AuthorityUnavailable('private current action has a foreign activity')
            if kind=='d08.commitment.v1'and m['commitment_id']not in own and m['fulfillment_state']not in{'fulfilled','withdrawn'}:
                raise AuthorityUnavailable('private complete metadata found another unfinished commitment')
            if kind=='d08.action_intent.v1'and m['action_id']!=action['action_id']and m['identity']['effect_id']==action['identity']['effect_id']:
                raise AuthorityUnavailable('private complete metadata found another action sharing the admitted effect')
            if kind=='d08.action_intent.v1'and m['action_id']!=action['action_id']and m['target_ref']==target:
                identity=m['identity']
                complete=[v for v in outcomes if(v['action_id'],v['effect_id'],v['attempt_id'])==
                    (m['action_id'],identity['effect_id'],identity['attempt_id'])
                    and v['result_level']=='completed_verified'and not v['unknown_effects']]
                if len(complete)!=1:raise AuthorityUnavailable('private complete metadata found another unfinished same-target action')
            related=False
            if kind=='d03.entity_anchor':related=m['entity_id']==target
            elif kind=='d03.account_binding':
                related=(m['platform_namespace']==platform and m['platform_identifier']==sender
                    and m['valid_from']<=self.policy_sample and(m['valid_until']is None or self.policy_sample<m['valid_until']))
                if related:account_matches.append((ref,m['entity_id']))
            elif kind=='d03.role_binding':
                if m['status']not in{'active','review','revoked'}:raise AuthorityUnavailable('private Role selector status is unknown')
                related=RoleBinding.applies_to(SimpleNamespace(**m),request)
            elif kind=='d05.boundary_rule':
                if m['status']not in{'active','superseded','revoked'}:raise AuthorityUnavailable('private Boundary selector status is unknown')
                related=BoundaryRule.applies_to(SimpleNamespace(**m),subject_persona_ref=persona,target_entity_ref=target,
                    action_kind=action['action_kind'],audience_scope=a.audience[0],scene_ref=a.scene_ref,at_time=self.policy_sample)
            elif kind=='d08.goal.v1':related=m['goal_id']==action['goal_ref']
            elif kind=='d08.commitment.v1':related=m['commitment_id']in own
            elif kind=='d08.action_cancellation.v1':related=m.get('action_id')==action['action_id']
            elif kind=='d08.action_outcome.v1':related=m['action_id']==action['action_id']
            if related:
                self.selected.add(ref)
                if kind in{'d03.entity_anchor','d03.account_binding','d03.role_binding','d05.boundary_rule'}:
                    policy_keys.add(ref);policy_roots.update(m.get('source_refs',()))
                    related_events.update(m.get('creation_evidence_refs',()))
                    if m.get('verification_ref')is not None:related_events.add(m['verification_ref'])
        self.account_versions=tuple(GraphVersion(self.cells[ref].key,self.cells[ref].revision)for ref in sorted(valid)
            if self.cells[ref].key.type_name=='d03.account_binding')
        self.account_matches=tuple(AtomKey.from_token(ref)for ref,_ in account_matches)
        if len(account_matches)!=1 or account_matches[0][1]!=target:
            raise AuthorityUnavailable('private complete account metadata is absent, ambiguous or targets another entity')
        for ref in related_events:
            key=AtomKey.from_token(ref)
            if key.type_name=='memory.source':
                if ref not in rclosure:raise AuthorityUnavailable('private recipient evidence escaped actual R closure')
            elif key.type_name=='d03.world_event':
                if not set(self._meta(ref)['source_refs'])<=rclosure:raise AuthorityUnavailable('private arrival evidence escaped actual R closure')
                self.selected.add(ref)
            else:raise AuthorityUnavailable('private recipient evidence has an undeclared graph type')
        if policy is not None:
            for version in policy[2]:self.selected.add(version.key.token);policy_keys.add(version.key.token)
        if action['identity']['phase']=='commitment_literal_v1':
            if policy is None and not policy_roots<=rclosure:
                raise AuthorityUnavailable('V1 related policy escaped its original single Source closure')
            if policy is not None and not policy_roots<=rclosure|self._closure(policy[0]):
                raise AuthorityUnavailable('V2 related policy escaped its exact approved P3')
        else:
            extra=tuple(sorted(policy_roots-rclosure))
            if extra:groups.append(('context',('owner',),extra))
        if self.scope is not None:
            self.selected.update((self.use_ref,self.scope_ref))
            for name in('commitment','fulfillment_terms','terms_acceptance'):
                raw=self.scope.get(name)
                if raw is not None:self.selected.add(decode_typed_production_value_v1(raw,GraphVersion).key.token)
        self.groups=tuple(groups);self.closures=tuple(self._closure(g[2])for g in self.groups)
        all_sources=set().union(*self.closures)
        for ref in self.selected:
            m=self._meta(ref)
            refs=tuple(m.get('source_refs',()))+tuple(m.get('reason_refs',()))
            if m.get('inbound_source_ref')is not None:refs+=(m['inbound_source_ref'],)
            for part in m.get('segments',()):refs+=tuple(part['source_refs'])
            if not set(refs)<=all_sources:
                raise AuthorityUnavailable('private selected object Source is outside its actual frozen R/P closures')
        self.selected.add(self.dynamic_job[0])
        self.business_keys=tuple(sorted(self.selected));self.policy_keys=tuple(sorted(policy_keys))
        ownerkey=owner_grant_key(*o.namespace.as_tuple).token
        if a.owner_head_ref!=self._meta(ownerkey)['grant_id']or o.heads.get(ownerkey,())[:2]!=(dict(a.graph_reads).get(ownerkey),1):
            raise AuthorityUnavailable('private admitted current Owner grant differs from metadata census')
        self._admitted_versions()
        self.metadata_seal=(o.root,o.count,tuple(sorted((ref,cell.revision,cell.valid,cell.cell_id,cell.header,cell.sha256)
            for ref,cell in self.cells.items())),tuple(sorted((ref,v.revision,v.header,v.payload_sha256)
            for ref,v in o.source_inspections.items())),self.business_keys,self.groups,self.closures,
            self.policy,self.policy.require_v3(o),self.action_cell,self.policy_sample,self.policy_before,
            self.policy_keys,self.conflict_versions,self.route_metadata,self.account_versions,self.account_matches,
            self.dynamic_job,self.dynamic_job_binding,self.dynamic_job_header)
        _SEALS[self]=self._basis();self.phase='owner'
    def _admitted_versions(self):
        o=self.owner;a=o.admission.admission
        versions={}
        for ref,raw_revision in(*a.graph_reads,*tuple((v.ref,v.version)for check in a.check_receipts for v in check.input_versions)):
            if ref in o.heads or ref in self.business_keys:
                head=o.heads.get(ref);revision=raw_revision
                if self.dynamic_job is not None and ref==self.dynamic_job[0]:
                    if raw_revision and not self.dynamic_job_binding.job_graph_revision<=raw_revision<=head[0]:
                        raise AuthorityUnavailable('private bound job read is outside its actual admitted birth/current range')
                    revision=head[0]
                elif(raw_revision==0 and head is not None and head[:2]==(1,1)and ref in self.business_keys
                        and AtomKey.from_token(ref).type_name not in{'memory.source','memory.access','d06.source_correction_head.v1'}
                        and[ref,1]in self._value('revisions')):
                    revision=1
                if ref in versions and versions[ref]!=revision:raise AuthorityUnavailable('private admitted normalized versions conflict')
                versions[ref]=revision
                if head is None or head[:2]!=(revision,1):raise AuthorityUnavailable('private admitted graph input changed before Body')
        for ref in self.closures[0]:
            sid=o.sources[ref].metadata['source_id']
            for token in(ref,access_key(*o.namespace.as_tuple,sid).token):
                if versions.get(token)!=o.heads[token][0]:
                    raise AuthorityUnavailable('private R current Source/access was not covered by actual admitted reads')
    def _basis(self):
        o=self.owner
        return(self,o.work,o.operation,o.fence.scope,o.selection_digest,o.graph_stamp,o.authority_epochs,
            o.binding,o.admission.receipt_digest,o.admission_originals,self.metadata_seal,self.refs,self.groups,
            o.heads.get(owner_grant_key(*o.namespace.as_tuple).token))
    def prepare_owner(self):
        self.actual();o=self.owner
        if self.phase!='owner'or self.owner_entry is not None:return
        if o.db.in_transaction or o.store._lock._is_owned():
            raise AuthorityUnavailable('private P2 Owner observation must precede SQL/lock')
        from ..authority_service.owner_location_read_v3 import prepare_current_host_private_dispatch_inventory_owner_entry_v3
        self.owner_entry=prepare_current_host_private_dispatch_inventory_owner_entry_v3(o)
    def _all(self,meter):
        from ..domains.d06 import source_correction_head_key
        o=self.owner;binding=self.owner_entry.require_for_v3(o)
        self._check_dynamic_job(meter)
        self._admitted_versions()
        controls=set()
        if not all(purpose in binding.purposes and set(audiences)<=set(binding.audiences)for purpose,audiences,_ in self.groups):
            raise AuthorityUnavailable('private P2 groups exceed actual current Owner purposes/audiences')
        for (purpose,audiences,_),closure in zip(self.groups,self.closures):
            for ref in closure:
                source=o.sources[ref];source_original=o.source_inspections[ref]
                source_original.require_v3(o,meter)
                sid=source.metadata['source_id'];ak=access_key(*o.namespace.as_tuple,sid)
                access=self._meta(ak.token);ac=self.cells[ak.token]
                correction=source_correction_head_key(o.namespace,sid).token
                if not ac.valid or correction in o.heads:raise AuthorityUnavailable('private P2 current access/correction unavailable')
                validate_access(access)
                if(access['status']!='active'or access['source_id']!=sid or purpose not in access['purposes']
                        or purpose not in source.metadata['purposes']or not set(audiences)<=set(access['audiences'])
                        or not set(audiences)<=set(source.metadata['audiences'])):
                    raise AuthorityUnavailable('private P2 Source lacks exact group rights')
                controls.add(ak.token)
        controls.add(owner_grant_key(*o.namespace.as_tuple).token)
        self.control_keys=tuple(sorted(controls));self.selected=set(self.business_keys)|controls
        self.source_all_seal=(self.metadata_seal,self.business_keys,self.control_keys,self.groups,self.closures,self.owner_entry)
        self.qualified=True;o.qualified_sources=set().union(*(closure for group,closure in zip(self.groups,self.closures)if group[0]=='expression'))
        self.body_queue=sorted(self.selected);self.history_queue=list(self.refs);self.phase='body'
    def advance(self,meter):
        self.actual(meter);o=self.owner;a=o.admission.admission
        if self.current is not None:
            tag,column=self.current
            if column.advance(meter):
                self.columns[tag]=column;self.current=None
            return False
        if self.phase=='census':
            if not o.graph_eof:return False
            self._begin('bundle','graph_bundle_operations','receipt_json',('bot','persona','operation_id'),(*o.namespace.as_tuple,a.operation_id))
            self.phase='event';return False
        if self.phase=='event':
            raw=self._value('bundle');self.candidate=raw.get('dispatch_candidate')
            header=meter.read_fixed_row(o.db,'graph_bundle_operations',('activity_id','effect_id','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*o.namespace.as_tuple,a.operation_id))
            if header is None or header[:2]!=(a.activity_id,a.effect_id)or header[2]<1:
                raise AuthorityUnavailable('private candidate has no exact actual committed operation')
            if raw.get('dispatch_admission')!={'schema':a.schema,'ref':a.admission_ref,'digest':o.admission.receipt_digest}:
                raise AuthorityUnavailable('private candidate recorded another admission original')
            if(type(self.candidate)is not dict or self.candidate.get('schema')!='sylanne.d11.dispatch_candidate.v1' or self.candidate.get('status')!='source_qualified'
                    or self.candidate.get('digest')!=a.candidate_digest or len(self.candidate.get('refs',()))!=4):
                raise AuthorityUnavailable('private P2 actual candidate receipt differs')
            self.refs=tuple(tuple(v)for v in self.candidate['refs'])
            self._begin('revisions','graph_events','revisions',('bot','persona','session','event_id'),
                (*o.namespace.as_tuple,a.activity_id,a.operation_id));self.phase='reads';return False
        if self.phase=='reads':
            revisions=self._value('revisions')
            kinds=('d08.action_intent.v1','d08.action_schema.v1','d08.communication_intent_grant.v1','d09.verified_segment_batch.v1')
            for (ref,rev),kind in zip(self.refs,kinds):
                key=AtomKey.from_token(ref)
                if(key.type_name!=kind or NamespaceId.from_key(key)!=o.namespace or key.owner.kind!='activity' or key.owner.subject!=a.activity_id
                        or[ref,rev]not in revisions or o.heads.get(ref,())[:2]!=(rev,1)):
                    raise AuthorityUnavailable('private P2 exact four current event members differ')
                historical=meter.read_fixed_row(o.db,'graph_history',
                    ('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
                    'token=? AND revision=?',(ref,rev))
                if historical is None or historical[:5]!=(1,*o.namespace.as_tuple,a.activity_id,a.operation_id):
                    raise AuthorityUnavailable('private P2 metadata lost its exact original historical producer')
                from ..runtime_storage_v3 import begin_runtime_cell_read_v3
                header=begin_runtime_cell_read_v3(o.db,historical[5],erasure_owner_ref=ref).header
                cell=self.cells[ref]
                if(header[0],header[1],header[3],header[5])!=(cell.header[0],ref,cell.header[3],cell.sha256):
                    raise AuthorityUnavailable('private selector full EOF differs from the original committed cell header')
            row=meter.read_fixed_row(o.db,'graph_events',('epoch_revision',),'bot=? AND persona=? AND session=? AND event_id=?',
                (*o.namespace.as_tuple,a.activity_id,a.operation_id))
            if row!=(o.admission.graph_epoch,):raise AuthorityUnavailable('private P2 actual event epoch changed')
            self._begin('reads','graph_events','reads',('bot','persona','session','event_id'),
                (*o.namespace.as_tuple,a.activity_id,a.operation_id));self.phase='action';return False
        if self.phase=='action':
            selected=[v for v in self.cells.values()if v.valid and v.key.type_name=='d08.action_intent.v1'and v.key.name==a.action_ref]
            if len(selected)!=1 or selected[0].key.token!=self.refs[0][0]:
                raise AuthorityUnavailable('private P2 action business identity is not unique')
            self.action_cell=selected[0];self.action=self.action_cell.require(self);m=self.action
            if(m['action_id']!=a.action_ref or(m['identity']['operation_id'],m['identity']['activity_id'],m['identity']['effect_id'])!=(a.operation_id,a.activity_id,a.effect_id)):
                raise AuthorityUnavailable('private P2 action metadata differs from actual admission identity')
            from .d08_commitment_dispatch_read_v1 import begin_named_commitment_policy_metadata_v3
            self.policy=begin_named_commitment_policy_metadata_v3(o);self.phase='policy';return False
        if self.phase=='policy':
            if not self.policy.advance(meter):return False
            if self.action['identity']['phase']=='commitment_literal_v1':
                from ..domains.d08.commitment_communication_v1 import USE_TYPES
                uses=[(ref,rev)for ref,rev in self._value('revisions')if AtomKey.from_token(ref).type_name in USE_TYPES]
                if len(uses)!=1 or uses[0][1]!=1:raise AuthorityUnavailable('private named metadata has no exact same-event Use')
                self.use_ref=uses[0][0];use=self._meta(self.use_ref)
                from .domain_production_erasure_v1 import decode_typed_production_value_v1
                version=decode_typed_production_value_v1(use['scope'],GraphVersion)
                self.scope_ref=version.key.token;self.scope=self._meta(self.scope_ref)
                if o.heads.get(self.scope_ref,())[:2]!=(version.revision,1):raise AuthorityUnavailable('private named Scope current version changed')
            identity=self.action['identity']
            self.dynamic_job_header=meter.read_fixed_row(o.db,'graph_dispatch_action_job_bindings_v1',
                ('admission_ref','job_id','binding_digest'),'bot=? AND persona=? AND action_id=? AND attempt_id=?',
                (*o.namespace.as_tuple,a.action_ref,identity['attempt_id']))
            if self.dynamic_job_header is None or self.dynamic_job_header[0]!=a.admission_ref:
                raise AuthorityUnavailable('private P2 has no actual admitted action/job binding')
            self._begin('job_binding','graph_dispatch_action_job_bindings_v1','binding_json',
                ('bot','persona','action_id','attempt_id'),(*o.namespace.as_tuple,a.action_ref,identity['attempt_id']),
                metadata_kind='private.action_job_binding_metadata.v3')
            self.phase='bound_job';return False
        if self.phase=='bound_job':
            from .dispatch_action_job_binding import DispatchActionJobBindingV1
            from .d11_types import runtime_job_key
            binding=DispatchActionJobBindingV1(**self._value('job_binding'))
            if(binding.digest!=self.dynamic_job_header[2]or binding.job_id!=self.dynamic_job_header[1]
                    or(binding.namespace,binding.action_id,binding.attempt_id,binding.activity_id,binding.effect_id,
                        binding.operation_id,binding.admission_ref,binding.admission_receipt_digest,binding.action_digest)!=
                    ('/'.join(o.namespace.as_tuple),a.action_ref,a.attempt_id,a.activity_id,a.effect_id,
                        a.operation_id,a.admission_ref,o.admission.receipt_digest,a.action_intent_digest)):
                raise AuthorityUnavailable('private dynamic job metadata changed actual admission identity')
            key=runtime_job_key(*o.namespace.as_tuple,a.activity_id,binding.job_id);head=o.heads.get(key.token)
            if head is None or not head[1]or head[0]<binding.job_graph_revision:
                raise AuthorityUnavailable('private bound current runtime job is missing or precedes birth')
            raw=self._meta(key.token);o.store._registry.spec(key.type_name).validator(raw)
            if(raw['bot_id'],raw['persona_id'],raw['activity_id'],raw['effect_id'],raw['operation_id'],
                    raw['job_id'],raw['parent_budget_lease_ref'])!=(*o.namespace.as_tuple,a.activity_id,a.effect_id,
                        a.operation_id,binding.job_id,a.budget_lease_ref)or raw['fence']<binding.job_fence or raw['cancel_epoch']<binding.job_cancel_epoch:
                raise AuthorityUnavailable('private current runtime job does not match actual bound identity/budget')
            row=meter.read_fixed_row(o.db,'graph_history',('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
                'token=? AND revision=?',(key.token,binding.job_graph_revision))
            if row is None or row[:5]!=(1,*o.namespace.as_tuple,a.activity_id,a.operation_id)or[key.token,binding.job_graph_revision]not in self._value('revisions'):
                raise AuthorityUnavailable('private dynamic job lost its exact same-event admitted birth')
            self.dynamic_job_binding=binding
            self._begin('job_birth','graph_history','value',('token','revision'),
                (key.token,binding.job_graph_revision),cell=row[5],metadata_kind=key.type_name)
            self.phase='job_birth';return False
        if self.phase=='job_birth':
            binding=self.dynamic_job_binding
            from .d11_types import runtime_job_key
            key=runtime_job_key(*o.namespace.as_tuple,a.activity_id,binding.job_id)
            born=self._value('job_birth');o.store._registry.spec(key.type_name).validator(born)
            if(born['operation_id'],born['activity_id'],born['effect_id'],born['job_id'],born['parent_budget_lease_ref'],
                    born['fence'],born['cancel_epoch'])!=(a.operation_id,a.activity_id,a.effect_id,binding.job_id,a.budget_lease_ref,
                        binding.job_fence,binding.job_cancel_epoch):
                raise AuthorityUnavailable('private exact job birth metadata differs from its actual admission binding')
            scalar=self._job_scalar(meter);current=self._meta(key.token)
            if(scalar is None or scalar[:7]!=(*o.namespace.as_tuple,a.operation_id,a.activity_id,a.effect_id,
                    a.budget_lease_ref,binding.job_id)or scalar[7:]!=(current['fence'],current['cancel_epoch'],current['phase'])):
                raise AuthorityUnavailable('private current runtime job scalar/graph metadata disagree')
            self.dynamic_job=(key.token,o.heads[key.token],scalar)
            self._select(meter);return False
        if self.phase=='owner':
            if self.owner_entry is None:return False
            self._all(meter);return False
        if self.phase=='body':
            if self.body_queue:
                ref=self.body_queue.pop(0);head=o.heads.get(ref)
                if head is None:return False
                key=AtomKey.from_token(ref)
                from ..domains.d08.commitment_communication_v1 import USE_TYPES,SCOPE_TYPES
                from ..domains.d08.commitment_fulfillment_v1 import TERMS_TYPE,ACCEPTANCE_TYPE
                from .dispatch_current_inventory_v3 import _RUNTIME_JOB_TYPE_V3
                if key.type_name not in _BODY_TYPES|USE_TYPES|SCOPE_TYPES|{TERMS_TYPE,ACCEPTANCE_TYPE,OWNER_GRANT_TYPE,'memory.access',_RUNTIME_JOB_TYPE_V3}:
                    raise AuthorityUnavailable('private selected Body escaped the closed actual cohort')
                self._begin(('body',ref),'graph_atoms','value',('token',),(ref,),cell=head[2]);return False
            if self.history_queue:
                ref,rev=self.history_queue.pop(0)
                row=meter.read_fixed_row(o.db,'graph_history',('valid','event_bot','event_persona','event_session','event_id','value_cell_id'),
                    'token=? AND revision=?',(ref,rev))
                if row is None or row[:5]!=(1,*o.namespace.as_tuple,a.activity_id,a.operation_id):
                    raise AuthorityUnavailable('private candidate lost its exact original event history')
                self._begin(('history',ref),'graph_history','value',('token','revision'),(ref,rev),cell=row[5]);return False
            self._verify_body(meter);self.complete=True;return True
        return self.complete
    def _job_scalar(self,meter):
        o=self.owner
        return meter.read_fixed_row(o.db,'runtime_jobs',
            ('bot_id','persona_id','operation_id','activity_id','effect_id','budget_ref','job_id','fence','cancel_epoch','phase'),
            'job_id=?',(self.dynamic_job_binding.job_id,))
    def _check_dynamic_job(self,meter):
        if self.dynamic_job is None or self._job_scalar(meter)!=self.dynamic_job[2]:
            raise AuthorityUnavailable('private current bound job changed after its actual metadata seal')
    def _verify_body(self,meter):
        from .dispatch_candidate import validate_dispatch_candidate_writes,DispatchCandidateEvidenceV1
        from ..domains.d08 import GoalExecutionProvider
        o=self.owner;a=o.admission.admission
        if self.selected!=set(self.business_keys)|set(self.control_keys):raise AuthorityUnavailable('private selected Body cohort changed after Source ALL')
        values={}
        for ref in self.selected:
            head=o.heads.get(ref)
            if head is None:continue
            column=self.columns[('body',ref)]
            cell=self.cells.get(ref)
            if cell is not None and(column.sha256,column.byte_count)!=(cell.sha256,cell.header[3]):
                raise AuthorityUnavailable('private selected Body changed from original metadata EOF')
            value=column.require_v3(o)
            selected_metadata={key:item for key,item in value.items()if cell is not None and(key,)in _paths(cell.key.type_name)}
            if cell is not None and cell.key.type_name=='d09.verified_segment_batch.v1':
                selected_metadata['segments']=[{'source_refs':part['source_refs']}for part in value['segments']]
            if cell is not None and selected_metadata!=cell.require(self):
                raise AuthorityUnavailable('private selected Body selector fields differ from before-Source metadata')
            values[ref]=value
            o.atoms.append(GraphAtom(AtomKey.from_token(ref),head[0],value,bool(head[1])))
        specs={s.name:s for s in GoalExecutionProvider().register_types()}
        action=specs['d08.action_intent.v1'].validator(values[self.refs[0][0]])
        if canonical_digest(action)!=a.action_intent_digest or tuple(action.source_refs)!=tuple(self.action['source_refs']):
            raise AuthorityUnavailable('private actual typed action changed from admission/source metadata')
        for ref,_ in self.refs:
            if self.columns[('history',ref)].sha256!=self.columns[('body',ref)].sha256:
                raise AuthorityUnavailable('private current candidate differs from its complete original history')
        writes=tuple(('d09'if index==3 else'd08',GraphWrite(AtomKey.from_token(ref),self.columns[('history',ref)].require_v3(o)))for index,(ref,_)in enumerate(self.refs))
        reads=tuple(GraphVersion(AtomKey.from_token(ref),rev)for ref,rev in self._value('reads'))
        base=validate_dispatch_candidate_writes(writes,namespace=o.namespace,identity=action.identity,
            read_versions=reads,source_refs=tuple(self.candidate['source_refs']),access_epoch=self.candidate['access_epoch'],
            delete_epoch=self.candidate['delete_epoch'],query_epoch=self.candidate['query_epoch'])
        if type(base)is not DispatchCandidateEvidenceV1:raise AuthorityUnavailable('private exact typed candidate unavailable')
        actual=replace(base,status=self.candidate['status'],source_audience=tuple(self.candidate['source_audience']),
            source_proof_versions=tuple(tuple(v)for v in self.candidate['source_proof_versions']),source_proof_digest=self.candidate['source_proof_digest'])
        if(actual.digest!=a.candidate_digest or actual.schema_digest!=a.action_schema_digest
                or actual.grant_digest!=a.grant_digest or actual.batch_digest!=a.batch_digest
                or canonical_digest(action.required_checks)!=a.required_checks_digest):
            raise AuthorityUnavailable('private complete candidate/action/schema/grant/batch differs from admission')
        self.actual(meter);self.owner_entry.require_for_v3(o)
        from .dispatch_initial_source_read_v3 import DispatchInitialSourceReadsV3
        o.auxiliary=DispatchInitialSourceReadsV3(o,o.family,o.now_utc)
    def release(self):
        if self.policy is not None:self.policy.release_v3()
        if self.owner_entry is not None:self.owner_entry.release_v3()
        for cell in self.cells.values():_CELLS.pop(cell,None)
        _SEALS.pop(self,None);_TASKS.pop(self.owner,None)
        self.cells.clear();self.columns.clear();self.current=None
        self.owner.atoms=[];self.owner.sources={};self.owner.heads={}
        self.action=self.scope=self.metadata_seal=self.source_all_seal=None
        self.selector=None;self.policy=None;self.owner_entry=None

def require_current_private_dispatch_owner_reader_v3(reader):
    task=_TASKS.get(reader)
    if task is None:raise AuthorityUnavailable('actual privately issued P2 metadata reader required')
    task=task[0];task.actual()
    from .dispatch_admission_read_v3 import _ISSUED as ADMISSIONS,PreparedDispatchAdmissionV3
    original=reader.admission_originals;record=ADMISSIONS.get(original)
    if(type(original)is not PreparedDispatchAdmissionV3 or record is None or original.owner is not reader
            or record!=(original.owner,original.ref,original.header,original.admission,original.request,original._receipt,original._request)
            or original._receipt!=reader.admission or original._request!=reader.request):
        raise AuthorityUnavailable('private P2 Owner has no actual canonical-EOF admission/request')
    if task.metadata_seal is None or _SEALS.get(task)!=task._basis():
        raise AuthorityUnavailable('private P2 Owner cannot precede exact metadata/groups seal')
    graph=reader.graph;bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    return graph,graph._GraphCoordinator__content_fence_v2,bundle,reader.fence.scope,task.groups

def private_dispatch_metadata_identity_v3(reader):
    require_current_private_dispatch_owner_reader_v3(reader)
    return _TASKS[reader][0]._basis()

from .dispatch_current_inventory_v3 import CurrentDispatchTypedProjectionV3,_FrozenDispatchAtomV3,_freeze_value_v3

class PrivateDispatchProjectionV3(CurrentDispatchTypedProjectionV3):
    def __init__(self,task):
        o=task.owner
        super().__init__(tuple(_FrozenDispatchAtomV3(a.key,a.revision,_freeze_value_v3(a.value),a.valid,_heap(a.value))for a in o.atoms),
            (o.graph_stamp[1],),o.operation)
        object.__setattr__(self,'task',task)
    @property
    def atoms(self):raise AuthorityUnavailable('private closed projection does not claim every namespace Body')
    def get(self,key):
        result=super().get(key)
        if result is None and key.token in self.task.owner.heads:
            raise AuthorityUnavailable('private P2 existing head is outside selected Body authority')
        return result
    def _selected(self,types,*,name=None,valid_only=False):
        expected={ref for ref,head in self.task.owner.heads.items()if AtomKey.from_token(ref).type_name in types
            and(name is None or AtomKey.from_token(ref).name==name)and(not valid_only or head[1])}
        actual={atom.key.token for atom in self._atoms if atom.key.type_name in types
            and(name is None or atom.key.name==name)and(not valid_only or atom.valid)}
        if actual!=expected:
            raise AuthorityUnavailable('private whole-family Body coverage was not prepared')
        return tuple(self._view(atom)for atom in self._atoms if atom.key.token in actual)
    def atoms_for_types_v3(self,types):return self._selected(types)
    def atom_rows_v3(self,types,columns,*,name=None,valid_only=True):
        atoms=self._selected(types,name=name,valid_only=valid_only)
        return tuple(tuple({'token':a.key.token,'revision':a.revision,'valid':int(a.valid),
            'type_name':a.key.type_name,'value':a.value}[c]for c in columns)for a in atoms)

def require_private_dispatch_inventory_source_all_v3(inventory,db,meter=None):
    task=_TASKS.get(inventory.reader)
    if task is None:raise AuthorityUnavailable('private P2 Source proof was released')
    task=task[0];task.actual(meter)
    if(not task.complete or not task.qualified or _SEALS.get(task)!=task._basis()
            or inventory.operation is not task.owner.operation or inventory.db is not db
            or inventory.binding!=task.owner.binding or inventory.admission_originals is not task.owner.admission_originals
            or task.source_all_seal!=(task.metadata_seal,task.business_keys,task.control_keys,task.groups,task.closures,task.owner_entry)
            or task.selected!=set(task.business_keys)|set(task.control_keys)):
        raise AuthorityUnavailable('private P2 Source ALL left its actual metadata/Work/admission')
    task.owner_entry.require_for_v3(task.owner)
    if meter is not None:
        task._check_dynamic_job(meter)
        from .source_inspection_metadata_read_v3 import _ORIGINALS
        for ref in set().union(*task.closures):
            original=task.owner.source_inspections[ref]
            if _ORIGINALS.get(original)!=original._identity_v3()or original.owner is not task.owner:
                raise AuthorityUnavailable('private retained Source original issuance changed')
            actual=meter.read_fixed_row(db,'graph_atoms',('revision','valid','value_cell_id'),
                'bot=? AND persona=? AND token=?',(*task.owner.namespace.as_tuple,ref))
            if actual!=task.owner.heads[ref]:raise AuthorityUnavailable('private retained Source current head changed')
    return task

def release_private_dispatch_source_read_v3(reader):
    value=_TASKS.get(reader)
    if value is not None:value[0].release()

def require_private_dispatch_policy_projection_v3(inventory,db,query):
    inventory.require_current(db,inventory.namespace,query)
    task=require_private_dispatch_inventory_source_all_v3(inventory,db)
    if query!=inventory.query or db is not inventory.db:
        raise AuthorityUnavailable('private policy predicate crossed its exact current query')
    atoms=tuple(inventory.projection.get(AtomKey.from_token(ref))for ref in task.policy_keys)
    return(tuple(a for a in atoms if a.key.type_name=='d03.role_binding'),
        tuple(a for a in atoms if a.key.type_name=='d05.boundary_rule'),task.metadata_seal)

def require_private_dispatch_conflict_metadata_v3(inventory,db,query):
    inventory.require_current(db,inventory.namespace,query)
    task=require_private_dispatch_inventory_source_all_v3(inventory,db)
    if query!=inventory.query:raise AuthorityUnavailable('private D08 predicate crossed its actual current query')
    kinds={'d08.commitment.v1','d08.action_intent.v1','d08.action_outcome.v1'}
    atoms=tuple(inventory.projection.get(AtomKey.from_token(ref))for ref in task.business_keys
        if AtomKey.from_token(ref).type_name in kinds)
    return atoms,task.conflict_versions


def require_private_dispatch_policy_request_v3(inventory,db,query,request):
    task=require_private_dispatch_inventory_source_all_v3(inventory,db)
    a=task.action
    if(query!=inventory.query or(request.subject_persona_ref,request.target_entity_ref,request.group_ref,
            request.scene_ref,request.requested_action_kind,request.purpose)!=
            ('persona:'+inventory.namespace.persona_id,a['target_ref'],None,inventory.admission.admission.scene_ref,
                a['action_kind'],a['purpose'])
            or request.at_time<task.policy_sample or task.policy_before is not None and request.at_time>=task.policy_before):
        raise AuthorityUnavailable('private policy request changed its exact applicability scope/time')
    return task.metadata_seal

def require_private_dispatch_reply_account_metadata_census_v3(inventory,db,query,*,platform_ref,sender_ref,now_utc):
    inventory.require_current(db,inventory.namespace,query)
    task=require_private_dispatch_inventory_source_all_v3(inventory,db)
    if((platform_ref,sender_ref)!=(task.route_metadata[0],task.route_metadata[2])
            or now_utc<task.policy_sample or task.policy_before is not None and now_utc>=task.policy_before):
        raise AuthorityUnavailable('private account census changed its original exact route/time')
    return task.account_versions,task.account_matches
