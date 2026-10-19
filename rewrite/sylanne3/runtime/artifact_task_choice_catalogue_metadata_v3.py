"""Fixed signed metadata catalogue for current Artifact task choices.

Factories supply their real retained READ and current Owner gates. This stream
does not authorize Body reads or issue execution rights.
"""
from dataclasses import dataclass
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .conditioned_producer_source_metadata_v3 import ConditionedLocatorJSONV3,ConditionedMetadataJSONStreamV3
from .source_correction_read_v3 import _heap

_TABLE='graph_d11_life_originals_v1'
_EXTENT='artifact_task_text_extent'
_POLICY='artifact_phase_postcondition_policy'

def _paths(profile,path):
    if not path:return True
    if profile in {'scope','root','objective','approval','small'}:return True
    if profile=='producer':
        if path[0]in {'schema','namespace','identity'}:return True
        return path[0]=='provenance'and(len(path)==1 or path[1]in {
            'draft_root_capability','artifact_task_scope','artifact_task_objective'})
    if profile=='extent':
        return path[0]in {'schema','namespace','goal_head','objective_ref','objective_digest','task_source_head',
            'task_source_digest','task_c02_operation_id','registration_operation_id','basis','rule_source_head',
            'rule_source_digest','owner_guard'}
    if profile=='policy':
        return path[0]in {'schema','request','goal_head','plan_head','source_head','rule_source_head',
            'registration_operation_id','objective_ref','objective_digest','task_basis_ref','task_basis_digest',
            'amendment_original_ref','amendment_original_digest','owner_guard'}
    raise AuthorityUnavailable('Unregistered fixed task catalogue metadata profile')

def attach_task_catalogue_semantic_stream_v3(column):
    """Preserve filtered parsing while hashing the actual ASCII logical domain."""
    from ..authority_service.named_joint_binding_source_read_v3 import _MetadataStreamV3
    stream=_MetadataStreamV3(column,column.cell is None or column.cell.header[0]=='canonical-json.ascii.v1')
    stream.parser=column.parser
    column.semantic_stream=stream;column.parser=stream

class _ColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,reader,profile,**kwargs):
        self.profile=profile;self.capture=None;self.registered=False;self.extra=0
        super().__init__(reader,**kwargs)
        self.capture=ConditionedLocatorJSONV3(self)
        self.capture.retain_path_v3=lambda path:_paths(profile,path)
        self.parser=ConditionedMetadataJSONStreamV3(self.capture,
            ensure_ascii=self.cell is None or self.cell.header[0]=='canonical-json.ascii.v1')
        attach_task_catalogue_semantic_stream_v3(self)
    def semanticlogical_digest_v3(self):
        if not self.complete:raise AuthorityUnavailable('Task catalogue logical digest requires actual complete wire EOF')
        return self.semantic_stream.semantic.hexdigest()
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.nodes,self.scalar,self.fragment,self.value,
            None if self.capture is None else self.capture.__dict__))+self.extra+131072
    def _reserve(self,extra=0):
        self.extra=extra
        if not self.registered:
            self.operation.register_retained_state_v3(self);self.registered=True
        else:self.operation.refresh_retained_state_v3(self)
    def _emit(self,event):
        self.capture._emit_v3(event);self.value=self.capture.value
    def _actual(self):
        if self.operation.closed:raise AuthorityUnavailable('Task catalogue metadata READ ended')
        return self
    def close_v3(self):
        if self.registered:self.operation.unregister_retained_state_v3(self);self.registered=False
        from .dispatch_initial_source_read_v3 import _COLUMNS
        _COLUMNS.pop(self,None)
        self.nodes={};self.scalar=bytearray();self.fragment=b'';self.value=None
        self.capture=self.parser=self.semantic_stream=self.cell=self.owner=self.db=None;self._frozen_value=None

class _SignedV3:
    def __init__(self,owner,kind,ref,profile):
        self.owner,self.kind,self.ref,self.profile=owner,kind,ref,profile
        self.header=self.column=self.value=None;self.complete=False;self.absent=False
    def advance(self,meter):
        r=self.owner.reader;r.require_current(meter=meter)
        row=meter.read_fixed_row(r.db,_TABLE,('producing_operation_id','payload_digest','signature'),
            'bot=? AND persona=? AND kind=? AND original_ref=?',(*r.namespace.as_tuple,self.kind,self.ref))
        if self.header is None:
            if row is None:self.absent=self.complete=True;return True
            self.header=tuple(row)
            self.column=_ColumnV3(r,self.profile,table=_TABLE,column='payload_json',
                key_columns=('bot','persona','kind','original_ref'),key=(*r.namespace.as_tuple,self.kind,self.ref))
            return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Task catalogue signed header changed during EOF')
        if not self.column.advance(meter):return False
        if self.column.sha256!=self.header[1]:raise AuthorityUnavailable('Task catalogue signed payload differs from canonical EOF')
        from .d11_life_preparation_v1 import SIGN_KIND
        self.owner.issuer._signer.verify(SIGN_KIND,
            canonical_serialize((r.namespace,self.kind,self.ref,self.header[1])),self.header[2])
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('commit_seq',),
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,self.header[0]))
        if bundle is None or type(bundle[0])is not int or bundle[0]<1:
            raise AuthorityUnavailable('Task catalogue signed Original lacks its actual positive W01 producer')
        self.value=self.column.require_v3(r);self.complete=True;return True
    def close_v3(self):
        if self.column is not None:self.column.close_v3()
        self.column=self.value=self.owner=None

def read_task_catalogue_producer_layout_v3(reader,meter,operation):
    """Actual immutable v1 TEXT or v3 cell layout for one exact producer."""
    from .domain_production_originals_v1 import PHYSICAL_TABLE
    key=(*reader.namespace.as_tuple,operation)
    names=('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest')
    row=meter.read_fixed_row(reader.db,'graph_domain_production_originals_v1',names,
        'bot=? AND persona=? AND operation_id=?',key)
    if row is not None:return ('graph_domain_production_originals_v1','original_payload_json',None,tuple(row))
    row=meter.read_fixed_row(reader.db,PHYSICAL_TABLE,(*names,'original_payload_cell_id'),
        'bot=? AND persona=? AND operation_id=?',key)
    if row is None:raise AuthorityUnavailable('Task catalogue has no actual Domain producer Original')
    if row[:2]!=('d06','admit_owner_material_source_v1'):
        raise AuthorityUnavailable('Unregistered actual physical domain producer kind')
    return PHYSICAL_TABLE,'original_payload_cell_id',row[-1],tuple(row[:-1])

class _ProducerV3:
    def __init__(self,owner,operation):
        self.owner,self.operation=owner,operation;self.header=self.layout=None;self.columns=[];self.index=0
        self.original=self.receipt=None;self.read_versions=();self.complete=False
    def advance(self,meter):
        r=self.owner.reader;r.require_current(meter=meter);key=(*r.namespace.as_tuple,self.operation)
        table,column,cell,header=read_task_catalogue_producer_layout_v3(r,meter,self.operation)
        layout=(table,column,cell)
        if self.header is None:
            self.header,self.layout=header,layout
            self.columns=[_ColumnV3(r,'producer',table=table,column=column,cell_id=cell,
                key_columns=('bot','persona','operation_id'),key=key)]
            self.columns.extend(_ColumnV3(r,'small',table=table,column=name,
                key_columns=('bot','persona','operation_id'),key=key)for name in ('read_versions_json','receipt_json'))
            return False
        if header!=self.header or layout!=self.layout:
            raise AuthorityUnavailable('Task catalogue producer physical layout/header changed during canonical EOF')
        if self.index<len(self.columns):
            if self.columns[self.index].advance(meter):self.index+=1
            return False
        original,reads,raw=(c.require_v3(r)for c in self.columns)
        from .domain_production_originals_v1 import _receipt
        receipt=_receipt(raw)
        versions=tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in reads)
        if(self.columns[0].semanticlogical_digest_v3()!=self.header[3]or receipt.status!='committed'
                or receipt.operation_id!=self.operation or receipt.operation_digest!=self.header[4]
                or canonical_digest(receipt)!=self.header[5]or receipt.read_versions!=versions or len(versions)>1024
                or original.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}
                or original.get('identity',{}).get('operation_id')!=self.operation
                or original.get('schema')!=self.header[0]+'.current-'+self.header[1]+'.v1'):
            raise AuthorityUnavailable('Task catalogue producer lost actual immutable receipt/readset binding')
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',key)
        if bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
            raise AuthorityUnavailable('Task catalogue producer lost its actual positive W01 member')
        self.original,self.receipt,self.read_versions=original,receipt,versions;self.complete=True;return True
    def close_v3(self):
        for column in self.columns:column.close_v3()
        self.columns.clear();self.owner=self.original=self.receipt=None;self.read_versions=()

@dataclass(frozen=True,slots=True)
class ArtifactTaskChoiceCatalogueMetadataResultV3:
    task:object
    available:bool
    scope:object
    objective:object
    goal_head:GraphVersion|None
    plan_head:GraphVersion|None
    method_refs:tuple[str,...]
    source_roots:tuple[str,...]
    originals:tuple[dict,...]
    matches:tuple[tuple[str,str|None,tuple[str,...]],...]

class ArtifactTaskChoiceCatalogueMetadataV3:
    def __init__(self,reader,*,root_ref,c02_operation_id,source_ref,issuer=None):
        from ..model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1
        from .issuers import D11BudgetJobIssuer
        self.issuer=reader.graph._GraphCoordinator__d11_issuer if issuer is None else issuer
        if type(self.issuer)is not D11BudgetJobIssuer:
            raise AuthorityUnavailable('Task catalogue requires its actual installed D11 signing issuer')
        self.reader=reader;self.task=artifact_draft_task_selector_v1(reader.namespace,
            c02_operation_id=c02_operation_id,root_registration_ref=root_ref)
        source=AtomKey.from_token(source_ref)
        if source.type_name!='memory.source'or NamespaceId.from_key(source)!=reader.namespace:
            raise AuthorityUnavailable('Task catalogue cue crossed its actual namespace')
        self.source_ref=source_ref;self.stage='root';self.signed=_SignedV3(self,'draft_root_capability',root_ref,'root')
        self.root=self.scope=self.objective=self.approval=self.producer=None
        self.goal_head=self.plan_head=None;self.methods=();self.roots=[source_ref];self.originals=[]
        self.scan_kind=_EXTENT;self.after='';self.through=None;self.watermark=False;self.scan=None;self.scan_producer=None
        self.matches={(_EXTENT,None):[]};self.complete=False;self.value=None;self.closed=False
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.roots,self.originals,self.matches,self.methods,self.source_ref))*3+8192
    def _publish(self,task,producer=None):
        if task.absent:return
        roots=[self.source_ref]
        raw=task.value
        for name in ('source_ref','task_source_ref'):
            if type(raw.get(name))is str:roots.append(raw[name])
        for name in ('source_head','task_source_head','rule_source_head'):
            head=raw.get(name)
            if type(head)is dict and 'key'in head:roots.append(head['key'])
        if producer is not None:
            roots.extend(v.key.token for v in producer.read_versions if v.key.type_name=='memory.source')
        for ref in roots:
            key=AtomKey.from_token(ref)
            if key.type_name!='memory.source'or NamespaceId.from_key(key)!=self.reader.namespace:
                raise AuthorityUnavailable('Task catalogue Original declares a foreign Source locator')
        self.roots.extend(roots)
        self.originals.append({'table':_TABLE,'kind':task.kind,'ref':task.ref,'projection':raw,
            'header':task.header,'payload_digest':task.header[1],'operation_id':task.header[0],
            'source_roots':tuple(dict.fromkeys(roots)),
            'read_versions':()if producer is None else producer.read_versions,
            'write_versions':()if producer is None else producer.receipt.write_versions,
            'producer_layout':None if producer is None else producer.layout,
            'producer_header':None if producer is None else producer.header,
            'producer_original':None if producer is None else producer.original})
        self.reader.operation.refresh_retained_state_v3(self)
    def advance(self,meter):
        if self.closed:raise AuthorityUnavailable('Task catalogue metadata READ was closed')
        r=self.reader;r.require_current(meter=meter)
        if self.complete:return True
        if self.stage in {'root','scope','objective','approval'}:
            if not self.signed.advance(meter):return False
            if self.signed.absent:
                self._finish(False);return True
            if self.stage=='root':
                from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
                self.root=draft_from_wire_v1(self.signed.value,DraftRootCapabilityV1)
                if self.root.registration_ref!=self.task.root_registration_ref or self.root.source_ref!=self.source_ref:
                    raise AuthorityUnavailable('Task catalogue Root differs from actual task/cue')
                self._publish(self.signed);self.root_header=self.signed.header;self.signed.close_v3()
                from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
                self.signed=_SignedV3(self,'artifact_task_scope',task_scope_ref_v1(self.root.registration_ref),'scope')
                self.stage='scope';return False
            if self.stage=='scope':
                from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3,_decode
                self.scope=_decode(self.signed.value,IngressArtifactTaskScopeOriginalV2)
                if(type(self.scope)not in {IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3}
                        or self.scope.root!=self.root or self.scope.c02_operation_id!=self.task.c02_operation_id
                        or self.scope.source_ref!=self.source_ref or self.scope.objective_ref is None
                        or self.signed.header[0]!=self.root_header[0]):
                    raise AuthorityUnavailable('Task catalogue lacks its actual same-producer approved Scope/Root')
                self.producer=_ProducerV3(self,self.signed.header[0]);self.stage='scope_producer';return False
            if self.stage=='objective':
                from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1,_decode
                self.objective=_decode(self.signed.value,ArtifactTaskObjectiveV1)
                if(self.signed.header[1]!=self.scope.objective_digest or self.objective.namespace!=r.namespace):
                    raise AuthorityUnavailable('Task catalogue objective differs from signed task Scope')
                self._publish(self.signed);self.signed.close_v3()
                from .artifact_phase_postconditions_v1 import APPROVAL_KIND_V2
                self.signed=_SignedV3(self,APPROVAL_KIND_V2,self.scope.approval_original_ref,'approval')
                self.stage='approval';return False
            from .artifact_phase_postconditions_v1 import _standing_approval_from_wire_v2
            self.approval=_standing_approval_from_wire_v2(self.signed.value)
            if(self.approval.digest!=self.scope.approval_original_digest
                    or self.approval.scope_digest!=self.scope.standing_policy_digest
                    or self.approval.namespace!=r.namespace):
                raise AuthorityUnavailable('Task catalogue differs from actual signed approved methods')
            from .d08_personal_plan_v1 import artifact_task_initial_plan_candidates_v1
            self.methods=tuple(method for method,_,_ in artifact_task_initial_plan_candidates_v1(self.task))
            if set(self.methods)!=set(self.approval.scope.method_refs):
                raise AuthorityUnavailable('Task catalogue methods exceed the actual approved closed pair')
            self._publish(self.signed);self.signed.close_v3();self.signed=None;self.stage='headers';return False
        if self.stage=='scope_producer':
            if not self.producer.advance(meter):return False
            provenance=self.producer.original.get('provenance',{})
            if(self.producer.header[:2]!=('d10','derive_ingress_artifact_task_scope_v1')
                    or provenance.get('artifact_task_scope')!=self.signed.value
                    or provenance.get('draft_root_capability')!=self.originals[0]['projection']):
                raise AuthorityUnavailable('Task catalogue Scope/Root lost their actual W01 provenance')
            self._publish(self.signed,self.producer);self.signed.close_v3();self.producer.close_v3();self.producer=None
            self.signed=_SignedV3(self,'artifact_task_objective',self.scope.objective_ref,'objective')
            self.stage='objective';return False
        if self.stage=='headers':
            heads=[]
            for ref,kind in ((self.objective.goal_ref,'d08.goal.v1'),(self.objective.plan_ref,'d08.personal_plan.v1')):
                key=AtomKey.from_token(ref)
                if key.type_name!=kind or NamespaceId.from_key(key)!=r.namespace:
                    raise AuthorityUnavailable('Task catalogue actual objective changed its Goal/Plan namespace/type')
                row=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid'),'token=? AND bot=? AND persona=?',
                    (ref,*r.namespace.as_tuple))
                heads.append(None if row is None or row[1]!=1 else GraphVersion(key,row[0]))
            self.goal_head,self.plan_head=heads
            if self.goal_head is None or self.plan_head is None:
                self._finish(False);return True
            self.matches.update({(_POLICY,method):[]for method in self.methods});self.stage='scan';return False
        return self._advance_scan(meter)
    def _advance_scan(self,meter):
        r=self.reader
        if not self.watermark:
            row=meter.read_fixed_row(r.db,_TABLE,('original_ref',),
                'bot=? AND persona=? AND kind=? ORDER BY original_ref DESC LIMIT 1',(*r.namespace.as_tuple,self.scan_kind))
            self.through=None if row is None else row[0];self.watermark=True
            if row is None:return self._next_kind()
            return False
        if self.scan is None:
            row=meter.read_fixed_row(r.db,_TABLE,('original_ref',),
                'bot=? AND persona=? AND kind=? AND original_ref>? AND original_ref<=? ORDER BY original_ref LIMIT 1',
                (*r.namespace.as_tuple,self.scan_kind,self.after,self.through))
            if row is None:return self._next_kind()
            self.after=row[0];self.scan=_SignedV3(self,self.scan_kind,self.after,
                'extent'if self.scan_kind==_EXTENT else'policy');return False
        if not self.scan.complete:
            if not self.scan.advance(meter):return False
            if self.scan.absent:raise AuthorityUnavailable('Task catalogue watermark member disappeared')
            self.scan_producer=_ProducerV3(self,self.scan.header[0]);return False
        if not self.scan_producer.advance(meter):return False
        raw=self.scan.value;matched=None
        if self.scan_kind==_EXTENT:
            if(raw.get('goal_head')=={'key':self.goal_head.key.token,'revision':self.goal_head.revision}
                    and raw.get('task_c02_operation_id')==self.task.c02_operation_id):
                matched=(_EXTENT,None)
        else:
            request=raw.get('request',{});task=request.get('task',{})
            if(task.get('c02_operation_id')==self.task.c02_operation_id
                    and task.get('root_registration_ref')==self.task.root_registration_ref
                    and request.get('plan_ref')==self.plan_head.key.token
                    and raw.get('plan_head',{}).get('revision')==self.plan_head.revision
                    and request.get('method_ref')in self.methods):
                matched=(_POLICY,request['method_ref'])
        if matched is not None:
            if raw.get('objective_ref')!=self.scope.objective_ref or raw.get('objective_digest')!=self.scope.objective_digest:
                raise AuthorityUnavailable('Task catalogue matching Original changed actual Scope objective')
            if len(self.matches[matched])<2:
                self.matches[matched].append(self.scan.ref)
                self._publish(self.scan,self.scan_producer)
        self.scan.close_v3();self.scan_producer.close_v3();self.scan=self.scan_producer=None
        return False
    def _next_kind(self):
        if self.scan_kind==_EXTENT:
            self.scan_kind=_POLICY;self.after='';self.through=None;self.watermark=False;return False
        self._finish(True);return True
    def _finish(self,available):
        if self.signed is not None:self.signed.close_v3();self.signed=None
        self.value=ArtifactTaskChoiceCatalogueMetadataResultV3(self.task,available,self.scope,self.objective,
            self.goal_head,self.plan_head,self.methods,tuple(dict.fromkeys(self.roots)),tuple(self.originals),
            tuple((kind,method,tuple(refs[:2]))for(kind,method),refs in self.matches.items()))
        self.complete=True;self.reader.operation.refresh_retained_state_v3(self)
    def result_v3(self):
        if self.closed or not self.complete or self.reader.operation.closed:
            raise AuthorityUnavailable('Task catalogue metadata has not reached its actual complete EOF')
        return self.value
    def lookup_v3(self,kind,*,task,goal_head,plan_head,method_ref=None):
        result=self.result_v3()
        if task!=self.task or kind not in {_EXTENT,_POLICY}:
            raise AuthorityUnavailable('Task catalogue lookup changed its actual task/kind')
        if not result.available:return ()
        if(goal_head,plan_head)!=(result.goal_head,result.plan_head):
            raise AuthorityUnavailable('Task catalogue lookup changed current actual Goal/Plan headers')
        if kind==_EXTENT and method_ref is not None or kind==_POLICY and method_ref not in result.method_refs:
            raise AuthorityUnavailable('Task catalogue lookup changed its exact approved method')
        return next(refs for k,method,refs in result.matches if(k,method)==(kind,method_ref))

    def close_v3(self):
        if self.closed:return
        self.closed=True
        reader=self.reader
        for task in (self.signed,self.producer,self.scan,self.scan_producer):
            if task is not None:task.close_v3()
        self.signed=self.producer=self.scan=self.scan_producer=None
        self.value=self.root=self.scope=self.objective=self.approval=None
        self.roots.clear();self.originals.clear();self.matches.clear();self.methods=()
        self.goal_head=self.plan_head=self.task=self.issuer=None
        reader.operation.unregister_retained_state_v3(self)
        self.reader=None
