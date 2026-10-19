"""Installed Artifact control READ profiles; metadata does not issue execution rights."""
from __future__ import annotations
from dataclasses import dataclass,replace
from datetime import datetime
from weakref import WeakKeyDictionary,WeakSet
import secrets,time
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,AuthorityContext,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import(begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3)
from ..graph_worker import(create_graph_storage_work_v3,require_graph_storage_work_admission_v3,GraphStorageStepV3)
from .domain_background_read_v3 import(BackgroundReadWorkV3,_ISSUER as BACKGROUND_ISSUER,
    require_actual_background_attachment_owner_v3,bind_background_reads_v3,BackgroundReadNeededV3,
    _start_background_request_v3,_advance_background_pending_v3)
from .source_correction_read_v3 import _heap
from .first_ingress_v2 import trusted_upper
from .issuers import IssuerAuthorityDenied
from . import artifact_host_dispatch_source_v3 as common

_STATES=WeakKeyDictionary()
_TERMINALS=WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class ArtifactDiscoveryMetadataSelectorV3:
    namespace:NamespaceId
    installation_id:str
    after_job_id:str|None=None
    through_job_id:str|None=None
    limit:int=3
    def __post_init__(self):
        from .jobs import _identifier
        if type(self.namespace)is not NamespaceId or type(self.limit)is not int or not 1<=self.limit<=3:
            raise ValueError('Exact finite Artifact discovery selector required')
        _identifier(self.installation_id,'installation_id')
        for name in ('after_job_id','through_job_id'):
            if getattr(self,name)is not None:_identifier(getattr(self,name),name)
        if self.after_job_id is not None and self.through_job_id is not None and self.after_job_id>self.through_job_id:
            raise ValueError('Artifact discovery cursor escaped its original watermark')

@dataclass(frozen=True,slots=True)
class ArtifactForegroundMetadataSelectorV3:
    namespace:NamespaceId
    installation_id:str
    c02_operation_id:str
    source_ref:str
    operation_kind:str
    request:object
    def __post_init__(self):
        _validate_selector_v3(self)
        from .jobs import _identifier
        _identifier(self.operation_kind,'operation_kind')

@dataclass(frozen=True,slots=True)
class ArtifactPhaseResumeMetadataSelectorV3:
    namespace:NamespaceId
    installation_id:str
    c02_operation_id:str
    source_ref:str
    def __post_init__(self):_validate_selector_v3(self)

def _validate_selector_v3(value):
    from .jobs import _identifier
    if type(value.namespace)is not NamespaceId:raise ValueError('Exact Artifact namespace required')
    _identifier(value.installation_id,'installation_id');_identifier(value.c02_operation_id,'c02_operation_id')
    key=AtomKey.from_token(value.source_ref)
    if key.type_name!='memory.source'or NamespaceId.from_key(key)!=value.namespace:
        raise ValueError('Artifact control Source locator crossed its actual namespace')

def _no_legacy_v3():raise AuthorityUnavailable('Artifact control cannot fall back to unqualified SQL')


@dataclass(frozen=True,slots=True,kw_only=True)
class ArtifactEntryPrepareSelectorV3:
    namespace:NamespaceId
    installation_id:str
    c02_operation_id:str
    source_ref:str
    entry_kind:str
    arguments:tuple[tuple[str,object],...]
    stage:str='start'
    completed_receipts:tuple=()
    def __post_init__(self):
        _validate_selector_v3(self)
        from .artifact_host_control_algorithms_v3 import require_artifact_entry_descriptor_v3
        require_artifact_entry_descriptor_v3(self)

@dataclass(frozen=True,slots=True,kw_only=True)
class ArtifactPostCommitReadSelectorV3(ArtifactEntryPrepareSelectorV3):
    operation_id:str
    operation_kind:str
    request_digest:str
    command_digest:str
    receipt_digest:str
    write_versions:tuple[GraphVersion,...]
    business_deadline_utc:float
    def __post_init__(self):
        _validate_selector_v3(self)
        from .artifact_host_control_algorithms_v3 import require_artifact_post_commit_descriptor_v3
        require_artifact_post_commit_descriptor_v3(self)

_SELECTORS=(ArtifactDiscoveryMetadataSelectorV3,ArtifactForegroundMetadataSelectorV3,ArtifactPhaseResumeMetadataSelectorV3,
    ArtifactEntryPrepareSelectorV3,ArtifactPostCommitReadSelectorV3)

def has_artifact_host_control_work_v3(reader):return reader in _STATES

def control_state_for_dispatch_v3(reader):
    state=_STATES.get(reader)
    if state is None:return None
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    if(type(reader)is not BackgroundReadWorkV3 or type(reader.selector)not in _SELECTORS
            or reader.kind!='artifact_model_dispatch'or state.reader is not reader
            or state.identity!=common._identity_v3(reader)or reader.operation.closed
            or reader.graph._v2_graph_stamp(reader.namespace)!=reader.graph_stamp):
        raise AuthorityUnavailable('Artifact control lost its actual retained READ Work')
    context=reader.context
    if state.profile in {'discovery','phase_resume'}:
        from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelRuntimeV1
        if(type(context)is not InstalledArtifactDraftModelRuntimeV1
                or context is not reader.graph._GraphCoordinator__artifact_draft_model_runtime_v1
                or(context.graph,context.bootstrap,context.bundle,context.worker,context.issuer,context.client_grant)!=(
                    reader.graph,reader.bootstrap,reader.bundle,state.worker,
                    reader.graph._GraphCoordinator__d11_issuer,state.model_grant)):
            raise AuthorityUnavailable('Artifact-specific control READ lost its actual installed model runtime')
    else:
        from .domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
        if(type(context)is not InstalledDomainOperationRuntimeV1
                or context is not reader.graph._GraphCoordinator__domain_production_runtime_v1
                or context.graph is not reader.graph or context._bootstrap is not reader.bootstrap):
            raise AuthorityUnavailable('Shared control READ lost its actual installed domain runtime')
    if state.fences and(reader.fence is not state.fences[0]or reader.read_scope is not reader.fence.scope
            or reader.authority!=reader.fence.authority):
        raise AuthorityUnavailable('Artifact control changed its actual primary READ')
    reader.work._require_invocation(reader.graph)
    return state

class _ControlColumnV3(common._DispatchColumnV3):
    def __init__(self,state,profile,**kwargs):
        self.retention_registered=False;self.retention_extra=0
        super().__init__(state,profile,**kwargs)
        state.control_columns_v3.add(self)
        self.capture.retain_path_v3=lambda path:_retains_v3(profile,path)
        from .artifact_task_choice_catalogue_metadata_v3 import attach_task_catalogue_semantic_stream_v3
        attach_task_catalogue_semantic_stream_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.nodes,self.scalar,self.fragment,self.value,
            None if self.capture is None else self.capture.__dict__))+self.retention_extra+131072
    def _reserve(self,extra=0):
        self.retention_extra=extra
        if not self.retention_registered:
            self.operation.register_retained_state_v3(self);self.retention_registered=True
        else:self.operation.refresh_retained_state_v3(self)
    def semanticlogical_digest_v3(self):
        if not self.complete:raise AuthorityUnavailable('Artifact control logical digest requires actual complete wire EOF')
        return self.semantic_stream.semantic.hexdigest()
    def release_retention_v3(self):
        if self.retention_registered:self.operation.unregister_retained_state_v3(self)
        self.retention_registered=False
        from .dispatch_initial_source_read_v3 import _COLUMNS
        _COLUMNS.pop(self,None)
        self.nodes={};self.scalar=bytearray();self.fragment=b'';self.value=None
        self.capture=self.parser=self.semantic_stream=self.cell=None;self._frozen_value=None
    def _emit(self,event):
        if event.kind=='key'and len(event.path)==1:self.top_fields.add(event.key)
        self.capture._emit_v3(event);self.value=self.capture.value

def _retains_v3(profile,path):
    if not path:return True
    if type(profile)is tuple and len(profile)==2 and profile[0]=='control_legacy_draft':
        from .artifact_host_draft_entry_recipes_v3 import artifact_draft_metadata_paths_v3
        return artifact_draft_metadata_paths_v3(profile[1],path)
    if type(profile)is tuple and len(profile)==2 and profile[0]=='control_ingress':
        from .artifact_host_ingress_recall_metadata_v3 import ingress_control_metadata_paths_v3
        return ingress_control_metadata_paths_v3(profile[1],path)
    if type(profile)is tuple and len(profile)==3 and profile[0]=='control_recipe_locator':
        from .artifact_host_control_recipes_v3 import artifact_control_locator_paths_v3
        return artifact_control_locator_paths_v3(profile[1],profile[2],path)
    if profile in {'control_target_mode','control_phase_status'}:
        from .artifact_host_control_algorithms_v3 import artifact_control_metadata_paths_v3
        return artifact_control_metadata_paths_v3(profile,path)
    if profile=='control_saved_receipt':return path[0]in {'schema','operation_id','receipt_digest','original_digest'}
    if profile=='control_goal_state':return path[0]=='state'
    if profile=='control_cycle':
        return path[0]in {'schema','c02_operation_id','source_ref','source_revision','cancel_generation','responsibility_ref','responsibility_digest','call_plan'}
    if profile=='control_c02_evidence':return path[0]=='source_ref'
    if profile=='control_c02_seal':return path[0]in {'bundle_digest','root_grant_valid_until_utc','business_deadline_utc'}
    if profile=='control_c02_receipt':return path[0]=='first_ingress_c02'and len(path)==1
    if profile=='control_ingress_intent':return path[0]=='fingerprint'
    if profile=='control_semantic_frozen':
        if path[0]=='sources':return len(path)<=2 or len(path)==3 and path[2]in {'ref','revision','value_digest'}
        return path[0]in {'selector','task_source_ref','current_self_ref','current_self_digest',
            'root_registration_digest','source_read_versions','access_epoch','delete_epoch','deadline_utc',
            'prior_content','schema'}
    if profile=='control_job':return path[0]in {'schema','selector','prepared_digest'}
    if profile=='control_frozen':return path[0]=='target'and(len(path)==1 or path[1]=='mode')
    if profile=='control_producer':
        if path[0]in {'schema','namespace','identity'}:return True
        if path[0]=='authority':return len(path)==1 or path[1]in {'actor','namespace','purpose','audience','activation_generation','policy_ref'}
        return path[0]=='provenance'and(len(path)==1 or path[1]in {'draft_root_capability','original_prepared','foreground_responsibility','artifact_task_scope','artifact_task_objective','artifact_completion_receipt','responsibility'})
    return True

class _SignedControlV3:
    def __init__(self,state,kind,ref,profile='control_small'):
        self.state,self.kind,self.ref,self.profile=state,kind,ref,profile
        self.header=self.column=self.value=None;self.complete=False
    def advance(self,meter):
        from .d11_life_preparation_v1 import TABLE,SIGN_KIND
        r=self.state.reader;common.require_artifact_host_dispatch_current_v3(r,meter)
        row=meter.read_fixed_row(r.db,TABLE,('producing_operation_id','payload_digest','signature'),
            'bot=? AND persona=? AND kind=? AND original_ref=?',(*r.namespace.as_tuple,self.kind,self.ref))
        if self.header is None:
            if row is None:raise _ItemRefusalV3('missing_signed_original')
            self.header=tuple(row)
            self.column=_ControlColumnV3(self.state,self.profile,table=TABLE,column='payload_json',
                key_columns=('bot','persona','kind','original_ref'),key=(*r.namespace.as_tuple,self.kind,self.ref))
            return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Artifact control signed Original changed during EOF')
        if not self.column.advance(meter):return False
        if self.column.sha256!=self.header[1]:raise _ItemRefusalV3('signed_original_eof_digest')
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((r.namespace,self.kind,self.ref,self.header[1])),self.header[2])
        self.value=self.column.require_v3(r);self.complete=True;return True

class _ItemRefusalV3(Exception):
    def __init__(self,code):self.code=code;super().__init__(code)

class _ControlStateV3:
    def __init__(self,reader):
        self.reader=reader;self.selector=reader.selector;self.identity=common._identity_v3(reader);self.control_columns_v3=WeakSet()
        self.completed_stage_metadata_v3=None
        self.profile={ArtifactDiscoveryMetadataSelectorV3:'discovery',
            ArtifactForegroundMetadataSelectorV3:'foreground_selector',ArtifactPhaseResumeMetadataSelectorV3:'phase_resume',
            ArtifactEntryPrepareSelectorV3:'entry_prepare',ArtifactPostCommitReadSelectorV3:'post_commit_read'}[type(reader.selector)]
        if self.profile in {'discovery','phase_resume'}:
            self.worker,self.model_grant=reader.context.worker,reader.context.client_grant
        self.ingress_recall_metadata=None
        self.phase='metadata';self.eligibility_deadline=reader.operation.deadline_utc
        self.fences=[reader.fence];self.self_descriptor=None;self.owner_entry=None
        self.group_specs=[];self.special_source_groups_v3=[];self.groups=[];self.group_index=0
        self.source_versions={};self.expected_source_versions_v3={};self.source_complete=False;self.metadata_complete=False
        self.root_source_metadata={};self.root_source_head=None;self.c02_authority=None
        self.current_roots=();self.audiences=();self.purpose='consolidation'
        self.points=reader.points;self.metadata_headers=[];self.metadata_result=None
        self.attachments={};self.source_requests={};self.result=None
        self.verified_metadata_v3={};self.derived_refs_v3={};self.recipe_originals_v3={};self.recipe_quotes_v3=set();self.recipe_metadata_tasks_v3={};self.owner_cause_pin=None;self.semantic_locators=None;self.objective_metadata=None;self.root_registrations=None;self.post_commit_metadata=None;self.task_catalogue=None;self.existing_completion=None;self.entry_natural_deadline=None;self.draft_metadata=None
        self.validation_points=self.validation_point=None
        self.discovery=_DiscoveryV3(self)if self.profile=='discovery'else None
        self.seed=None if self.discovery is not None else _SeedV3(self)
    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.metadata_headers,self.root_source_metadata,self.current_roots,self.group_specs,self.verified_metadata_v3,self.derived_refs_v3,
            self.source_versions,self.attachments,self.metadata_result,self.result,
            *(None if task is None else task.__dict__ for task in (self.discovery,self.seed,self.semantic_locators,
                self.objective_metadata,self.root_registrations,self.post_commit_metadata,self.task_catalogue,self.existing_completion,self.entry_natural_deadline,self.ingress_recall_metadata,self.draft_metadata,self.completed_stage_metadata_v3))))*3+8192
    def require_current_v3(self,meter):return common.require_artifact_host_dispatch_current_v3(self.reader,meter)
    def source_metadata_v3(self,token,*,purpose=None,audiences=None):
        if not self.source_complete:raise AuthorityUnavailable('Artifact Source metadata has not completed its actual ALL closure')
        purpose=self.purpose if purpose is None else purpose
        audiences=self.audiences if audiences is None else tuple(audiences)
        matches=[g for g in self.groups if g.purpose==purpose and set(audiences)<=set(g.audiences)and token in g.sources]
        if not matches:raise AuthorityUnavailable('Artifact Source metadata is outside the actual qualified purpose/audience')
        values=[g.sources[token][0]for g in matches]
        if any(v!=values[0]for v in values):raise AuthorityUnavailable('Artifact Source metadata differs across actual same-stamp READs')
        return dict(values[0])
    def source_head_v3(self,token):
        key=AtomKey.from_token(token)
        if key not in self.source_versions:raise AuthorityUnavailable('Artifact Source lacks its current qualified head')
        return GraphVersion(key,self.source_versions[key])
    def metadata_value_v3(self,column):
        if not self.source_complete or column.owner is not self.reader or not column.complete:
            raise AuthorityUnavailable('Artifact metadata has not reached its actual qualified full EOF')
        return column.json_v3()
    def metadata_digest_v3(self,column):
        self.metadata_value_v3(column)
        return column.sha256
    def root_registrations_for_source_v3(self):
        task=self.root_registrations
        if not self.source_complete or task is None or not task.complete:
            raise AuthorityUnavailable('Actual complete Root registration metadata inventory required')
        return tuple(task.refs)
    def task_choice_catalogue_v3(self,kind,*,task,goal_head,plan_head,method_ref=None):
        if not self.source_complete:
            raise AuthorityUnavailable('Task catalogue lookup cannot precede actual same-Work Source EOF')
        if self.task_catalogue is None:
            raise AuthorityUnavailable('This fixed entry has no actual TaskScope catalogue metadata inventory')
        return self.task_catalogue.lookup_v3(kind,task=task,goal_head=goal_head,plan_head=plan_head,method_ref=method_ref)
    def active_task_objective_metadata_v3(self):
        task=self.objective_metadata
        if not self.source_complete or task is None or not task.complete:
            raise AuthorityUnavailable('Actual complete active Artifact objective metadata inventory required')
        return tuple(dict(row)for row in task.rows)
    def signed_metadata_v3(self,kind,ref,profile):
        if not self.source_complete:raise AuthorityUnavailable('Artifact signed status cannot precede actual Source closure')
        task=self.source_requests.get((kind,ref,profile))
        if task is None or not task.complete:
            raise BackgroundReadNeededV3(('artifact_control_signed',kind,ref,profile))
        return None if task.absent else dict(task.value)
    def signed_metadata_digest_v3(self,kind,ref,profile):
        self.signed_metadata_v3(kind,ref,profile)
        task=self.source_requests[kind,ref,profile]
        return None if task.absent else task.header[1]
    def signed_metadata_header_v3(self,kind,ref,profile):
        self.signed_metadata_v3(kind,ref,profile)
        return self.source_requests[kind,ref,profile].header
    def control_point_v3(self,table,columns,key_columns,key):
        from .domain_background_read_v3 import background_point_v3
        return background_point_v3(self.reader.db,table=table,columns=tuple(columns),
            key_columns=tuple(key_columns),key=tuple(key),legacy_reader=_no_legacy_v3)
    def register_qualified_attachment_v3(self,table,key_columns,key,column,*,family):
        return _register_qualified_attachment_v3(self,table,key_columns,key,column,family=family)

def require_artifact_control_owner_identity_v3(reader):
    state=control_state_for_dispatch_v3(reader)
    if(state is None or not state.metadata_complete or state.phase not in {'owner','root_registrations','post_commit_metadata','task_catalogue','completion_metadata','entry_natural_deadline','draft_metadata','objectives','locators','source_scopes','sources','algorithm','validate','complete'}
            or state.self_descriptor is None or reader.fence is None
            or reader.read_scope.operation_id!=reader.operation_id+':business'):
        raise AuthorityUnavailable('Artifact control Owner requires its exact metadata and current READ')
    return state

def artifact_control_owner_cause_v3(reader):
    state=require_artifact_control_owner_identity_v3(reader)
    return state.owner_cause_pin

def _prepare_owner_v3(state):
    from ..authority_service.owner_location_read_v3 import prepare_current_host_semantic_background_owner_read_entry_v3
    r=state.reader;common._observe_v3(r)
    current=common._self_v3(r);state.self_descriptor=common._self_descriptor_v3(current)
    r.graph._finish_read_fence_v3(r.fence);state.fences.clear();r.fence=r.read_scope=None
    audiences=state.audiences if state.profile!='discovery' else ('owner',)
    r.authority=replace(r.authority,actor=current.self_entity_ref,purpose=state.purpose,audience=audiences)
    r.fence=r.graph._begin_read_fence_v3(r.authority,operation_id=r.operation_id+':business')
    r.read_scope=r.fence.scope;state.fences.append(r.fence)
    if(r.fence.metadata,r.fence.epoch)!=r.graph_stamp or common._self_descriptor_v3(common._self_v3(r))!=state.self_descriptor:
        raise AuthorityUnavailable('Artifact control current Self/stamp changed across actual READ scopes')
    r.current_self=common._self_v3(r)
    state.owner_cause_pin=(r.selector,tuple(state.metadata_headers),tuple(state.group_specs),
        state.eligibility_deadline,r.read_scope.permit)
    state.owner_entry=prepare_current_host_semantic_background_owner_read_entry_v3(r)
    state.owner_entry.require_permission_v3(r)
    with r.store._lock:
        r.db.execute('BEGIN')
        try:r.owner=r.owner_binding=state.owner_entry.require_for_v3(r)
        finally:r.db.rollback()
    r.owner_guard=state.owner_entry.current_owner_guard
    if state.seed is not None:
        from .domain_production_contracts_v1 import ProductionOwnerGuardV1
        from ..graph_types import owner_grant_key
        actual_guard=ProductionOwnerGuardV1(owner_grant_key(*r.namespace.as_tuple).token,r.owner.grant_revision,
            r.owner.grant_digest.removeprefix('sha256:'),r.owner.authorization_head.removeprefix('sha256:'))
        expected=state.seed.expected_owner_guard
        if expected is not None and expected!=actual_guard:
            raise AuthorityUnavailable('Artifact control current Owner differs from its actual signed responsibility')
        root=state.seed.root
        if root is not None and(root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest)!=(
                actual_guard.grant_ref,actual_guard.grant_revision,actual_guard.grant_digest):
            raise AuthorityUnavailable('Artifact control current Owner differs from the actual original Root')
    if state.seed is not None:
        state.semantic_locators=_SemanticLocatorsV3(state)
        if state.profile=='entry_prepare':
            state.root_registrations=_RootRegistrationsV3(state);state.phase='root_registrations'
        elif state.profile=='post_commit_read':
            state.post_commit_metadata=_PostCommitMetadataV3(state);state.phase='post_commit_metadata'
        elif(type(r.selector)is ArtifactForegroundMetadataSelectorV3
                and r.selector.operation_kind=='derive_ingress_artifact_task_scope_v1'):
            state.objective_metadata=_ActiveObjectivesV3(state);state.phase='objectives'
        else:state.phase='locators'if not state.semantic_locators.complete else'source_scopes'
    else:state.phase='source_scopes'

def _open_source_scopes_v3(state):
    r=state.reader;common._observe_v3(r)
    if state.profile in {'entry_prepare','post_commit_read'}and r.selector.completed_receipts:
        if state.completed_stage_metadata_v3 is None:state.completed_stage_metadata_v3=_CompletedStageMetadataV3(state)
        if not state.completed_stage_metadata_v3.complete:state.phase='completed_stage_metadata';return
    if state.draft_metadata is None and state.profile in {'entry_prepare','post_commit_read'}:
        from .artifact_host_draft_entry_recipes_v3 import _METADATA_ENTRIES_V3,ArtifactDraftEntryMetadataV3
        if r.selector.entry_kind in _METADATA_ENTRIES_V3:
            state.draft_metadata=ArtifactDraftEntryMetadataV3(state);state.phase='draft_metadata';return
    from .artifact_host_ingress_recall_metadata_v3 import ingress_control_required_v3,IngressRecallControlMetadataV3
    if state.ingress_recall_metadata is None and ingress_control_required_v3(state):
        state.ingress_recall_metadata=IngressRecallControlMetadataV3(state)
    if state.ingress_recall_metadata is not None and not state.ingress_recall_metadata.complete:
        state.phase='ingress_recall_metadata';return
    if(state.existing_completion is None and state.profile in {'entry_prepare','post_commit_read'}
            and r.selector.entry_kind=='prepare_current_artifact_completion_source_v1'
            and not state.special_source_groups_v3):
        group=state.semantic_locators.group
        if group is not None:
            from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
            selected=group.selector
            if selected.phase_kind=='check'and selected.phase_index==len(artifact_draft_phase_sequence_v2(selected.method_ref))-1:
                state.existing_completion=_ExistingCompletionV3(state,selected);state.phase='completion_metadata';return
    for index,spec in enumerate(state.group_specs):
        name,roots,purpose,audiences=spec
        if purpose not in r.owner.purposes or not set(audiences)<=set(r.owner.audiences):
            if state.discovery is None:raise AuthorityUnavailable('Artifact control Source scope exceeds actual current Owner')
            state.discovery.accepted[index]['source_refused']='source_outside_current_owner_scope'
            continue
        fence=r.graph._begin_read_fence_v3(replace(r.authority,purpose=purpose,audience=audiences),
            operation_id=r.operation_id+':source:'+str(index))
        if(fence.metadata,fence.epoch)!=r.graph_stamp:raise AuthorityUnavailable('Artifact control shared Source stamp changed')
        state.fences.append(fence);state.groups.append(common._DispatchSourcesV3(state,fence,spec))
    state.phase='sources'

def _advance_sources_v3(state,meter):
    if state.group_index<len(state.groups):
        group=state.groups[state.group_index]
        try:group._step(meter)
        except (AuthorityUnavailable,ValueError)as error:
            state.require_current_v3(meter)
            if state.discovery is None:raise
            for item in state.discovery.accepted:
                if item['source_ref']in group.saved_roots:
                    item['source_refused']='source_'+type(error).__name__
                    item['source_refusal_detail']=str(error)[:256]
            state.group_index+=1;return
        if group.complete:
            for version in group.readset:
                old=state.source_versions.get(version.key)
                if old is not None and old!=version.revision:
                    raise AuthorityUnavailable('Artifact control ALL Source revisions conflict')
                state.source_versions[version.key]=version.revision
            state.group_index+=1
        return
    for key,revision in state.expected_source_versions_v3.items():
        if state.source_versions.get(key)!=revision:
            raise AuthorityUnavailable('Artifact original cycle Source R differs from its actual current qualified head')
    state.source_complete=True
    for token in state.current_roots:
        groups=[g for g in state.groups if g.complete and token in g.sources]
        if not groups:
            if state.discovery is None:raise AuthorityUnavailable('Artifact current root has no actual complete Source closure')
            continue
        state.root_source_metadata[token]=dict(groups[0].sources[token][0])
    if type(state.reader.selector)is not ArtifactDiscoveryMetadataSelectorV3:
        state.root_source_head=state.source_head_v3(state.reader.selector.source_ref)
    state.phase='algorithm'

def _prepare_v3(graph,runtime,selector):
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelRuntimeV1
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.v2_fence_port import V2FencePort
    graph._admin(runtime.bootstrap);require_graph_storage_work_admission_v3(graph)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly;port=graph._GraphCoordinator__content_fence_v2
    if(type(selector)not in (ArtifactDiscoveryMetadataSelectorV3,ArtifactPhaseResumeMetadataSelectorV3) or type(runtime)is not InstalledArtifactDraftModelRuntimeV1
            or runtime is not graph._GraphCoordinator__artifact_draft_model_runtime_v1
            or runtime.graph is not graph or assembly is None or type(runtime.bundle)is not AdminInstallationBundle
            or runtime.bundle is not assembly.admin_bundle or type(port)is not V2FencePort):
        raise AuthorityUnavailable('Artifact control requires its actual installed runtime and READ port')
    policy=runtime.bundle.installation_policy;grant=runtime.client_grant
    if(selector.namespace!=policy.namespace or selector.installation_id!=policy.installation_id
            or(port.installation_grant.installation_id,port.installation_grant.manifest_digest)!=(
                policy.installation_id,policy.manifest_digest)
            or(grant.installation_id,grant.manifest_digest,grant.administrator_holder)!=(
                policy.installation_id,policy.manifest_digest,policy.administrator_holder)):
        raise AuthorityUnavailable('Artifact control READ/model installation identity differs')
    return _create_control_work_v3(graph,runtime.bootstrap,runtime.bundle,runtime,selector)

def _create_control_work_v3(graph,bootstrap,bundle,context,selector):
    port=graph._GraphCoordinator__content_fence_v2
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    opid='artifact-control-read:'+secrets.token_hex(16)
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,opid,now+60.0)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db):
            authority=AuthorityContext('artifact-dispatch-metadata','d11','artifact-dispatch-metadata',
                selector.namespace,('activity',),'consolidation',('owner',),'artifact-host-control.v3',
                graph._v2_graph_stamp(selector.namespace)[0].requirements.activation_generation)
            fence=graph._begin_read_fence_v3(authority,operation_id=opid+':metadata')
            r=BackgroundReadWorkV3(BACKGROUND_ISSUER,graph,bootstrap,bundle,operation,
                kind='artifact_model_dispatch',dedupe_key=None,context=context)
            r.selector,r.fence,r.read_scope,r.authority=selector,fence,fence.scope,authority
            r.runtime=graph._GraphCoordinator__domain_production_runtime_v1
            r.lease=r.owner_binding=r.owner_guard=r.session_proof=None
            r.operation_id=opid;r.request_digest=canonical_digest(selector);r.read_finished=False
            r.initial_monotonic_deadline=time.monotonic()+operation.deadline_utc-now
            r.initial_now_utc=r.now=now;r.phase='artifact_control_metadata'
            work=create_graph_storage_work_v3(graph,kind='domain_background_read_v3',operation_id=opid,
                selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=r,operation=operation)
            r.work=work;state=_ControlStateV3(r);_STATES[r]=state;operation.register_retained_state_v3(state)
            def unwrap(value):return value.require_result_v3(work)
            def failed(error):raise error
            work.map_terminal_v3('issuer',unwrap,failed)
        return work
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise

def prepare_current_artifact_discovery_metadata_v3(graph,runtime,*,after_job_id=None,through_job_id=None,limit=3):
    p=runtime.bundle.installation_policy
    return _prepare_v3(graph,runtime,ArtifactDiscoveryMetadataSelectorV3(p.namespace,p.installation_id,after_job_id,through_job_id,limit))

def prepare_current_artifact_foreground_metadata_v3(graph,bootstrap,installed_bundle,*,selector):
    if type(selector)is not ArtifactForegroundMetadataSelectorV3:raise TypeError('Exact foreground selector required')
    return _prepare_shared_control_v3(graph,bootstrap,installed_bundle,selector)

def prepare_current_artifact_entry_metadata_v3(graph,bootstrap,installed_bundle,*,selector):
    if type(selector)is not ArtifactEntryPrepareSelectorV3:raise TypeError('Exact entry descriptor required')
    return _prepare_shared_control_v3(graph,bootstrap,installed_bundle,selector)

def prepare_current_artifact_post_commit_metadata_v3(graph,bootstrap,installed_bundle,*,selector):
    if type(selector)is not ArtifactPostCommitReadSelectorV3:raise TypeError('Exact post-commit descriptor required')
    return _prepare_shared_control_v3(graph,bootstrap,installed_bundle,selector)

def _prepare_shared_control_v3(graph,bootstrap,bundle,selector):
    from .domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.v2_fence_port import V2FencePort
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    runtime=graph._GraphCoordinator__domain_production_runtime_v1
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    port=graph._GraphCoordinator__content_fence_v2
    if(type(runtime)is not InstalledDomainOperationRuntimeV1 or runtime.graph is not graph
            or runtime._bootstrap is not bootstrap or type(bundle)is not AdminInstallationBundle
            or assembly is None or assembly.admin_bundle is not bundle or type(port)is not V2FencePort):
        raise AuthorityUnavailable('Shared control requires the actual installed domain runtime/READ ports')
    policy=bundle.installation_policy;grant=port.installation_grant
    if(selector.namespace!=policy.namespace or selector.installation_id!=policy.installation_id
            or(grant.installation_id,grant.manifest_digest,grant.administrator_holder)!=(
                policy.installation_id,policy.manifest_digest,policy.administrator_holder)):
        raise AuthorityUnavailable('Shared control changed actual installation/READ binding')
    return _create_control_work_v3(graph,bootstrap,bundle,runtime,selector)

def prepare_current_artifact_phase_resume_metadata_v3(graph,runtime,*,selector):
    if type(selector)is not ArtifactPhaseResumeMetadataSelectorV3:raise TypeError('Exact Artifact phase-resume metadata selector required')
    return _prepare_v3(graph,runtime,selector)



class _ControlProducerV3:
    def __init__(self,state,operation,domain,kinds):
        self.state,self.operation,self.domain,self.kinds=state,operation,domain,tuple(kinds)
        self.header=self.layout=None;self.columns=[];self.index=0;self.complete=False;self.original=self.receipt=None;self.read_versions=()
    def advance(self,meter):
        from .artifact_task_choice_catalogue_metadata_v3 import read_task_catalogue_producer_layout_v3
        r=self.state.reader;key=(*r.namespace.as_tuple,self.operation)
        table,payload_column,cell,row=read_task_catalogue_producer_layout_v3(r,meter,self.operation)
        layout=(table,payload_column,cell)
        if self.header is None:
            if row is None or row[0]!=self.domain or row[1]not in self.kinds:
                raise _ItemRefusalV3('producer_operation_kind')
            self.header,self.layout=tuple(row),layout
            self.columns=[_ControlColumnV3(self.state,'control_producer',table=table,column=payload_column,cell_id=cell,
                key_columns=('bot','persona','operation_id'),key=key)]
            self.columns.extend(_ControlColumnV3(self.state,'control_small',table=table,column=column,
                key_columns=('bot','persona','operation_id'),key=key)for column in ('read_versions_json','receipt_json'))
            return False
        if tuple(row or())!=self.header or layout!=self.layout:raise AuthorityUnavailable('Artifact control original producer physical layout/header changed during EOF')
        if self.index<len(self.columns):
            if self.columns[self.index].advance(meter):self.index+=1
            return False
        original,reads,receipt=(c.require_v3(r)for c in self.columns)
        from .domain_production_originals_v1 import _receipt
        actual=_receipt(receipt)
        if(self.columns[0].semanticlogical_digest_v3()!=self.header[3]or actual.status!='committed'
                or actual.operation_id!=self.operation or actual.operation_digest!=self.header[4]
                or canonical_digest(actual)!=self.header[5]
                or original.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}
                or original.get('identity',{}).get('operation_id')!=self.operation
                or original.get('schema')!=self.domain+'.current-'+self.header[1]+'.v1'):
            raise _ItemRefusalV3('producer_receipt_canonical_binding')
        versions=tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in reads)
        if actual.read_versions!=versions or len(versions)>1024:raise _ItemRefusalV3('producer_readset_receipt')
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',key)
        if bundle!=(actual.operation_digest,actual.activity_id,actual.effect_id,actual.commit_seq):
            raise _ItemRefusalV3('producer_positive_w01_bundle')
        self.original,self.receipt,self.read_versions=original,actual,versions;self.complete=True;return True



class _SeedV3:
    """Exact original metadata needed to open the same-Work business READ."""
    def __init__(self,state):
        self.state=state;self.stage='budget';self.budget=_ControlBudgetV3(state)
        self.columns=[];self.index=0;self.headers=[];self.signed_metadata=[];self.business=None;self.archive=None
        self.identity=None;self.cycle=None;self.cycle_value=None;self.signed=None;self.root=None
        self.root_ref=None;self.purpose='context';self.deadline=state.eligibility_deadline;self.original_business_deadline=None
        self.additional_roots=();self.c02_original_deadline=None;self.mirror=None;self.responsibility=None;self.expected_owner_guard=None;self.cycle_producer=None
    def business_deadline_v3(self):
        if self.stage!='complete' or self.original_business_deadline is None:
            raise AuthorityUnavailable('Actual original Artifact business deadline has not completed metadata EOF')
        deadline=self.original_business_deadline
        if self.state.profile=='post_commit_read':
            deadline=min(deadline,self.state.reader.selector.business_deadline_utc)
        return deadline
    def _point(self,meter,table,columns,where,key):
        row=meter.read_fixed_row(self.state.reader.db,table,columns,where,key)
        self.headers.append((table,columns,where,key,None if row is None else tuple(row)))
        return row
    def advance(self,meter):
        s=self.state;r=s.reader;q=r.selector;ns=r.namespace.as_tuple
        if self.stage=='budget':
            if not self.budget.advance(meter):return
            self.deadline=min(self.deadline,self.budget.grant.valid_until_utc)
            key=(*ns,q.c02_operation_id)
            self.business=self._point(meter,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',key)
            self.archive=self._point(meter,'graph_first_ingress_c02_committed_seals_v2',('schema','bundle_digest'),
                'bot=? AND persona=? AND operation_id=?',key)
            if self.business is None or self.business[3]<1 or self.archive is None:
                raise AuthorityUnavailable('Artifact control lacks its actual positive C02 W01 original')
            eventkey=(*ns,self.business[1],q.c02_operation_id)
            event=self._point(meter,'graph_events',('epoch_revision',),
                'bot=? AND persona=? AND session=? AND event_id=?',eventkey)
            if event is None:raise AuthorityUnavailable('Artifact control C02 W01 event is absent')
            self.columns=[_ControlColumnV3(s,profile,table=table,column=column,key_columns=keys,key=actual)
                for profile,table,column,keys,actual in(
                    ('control_c02_evidence','graph_first_ingress_c02_committed_seals_v2','evidence_json',('bot','persona','operation_id'),key),
                    ('control_c02_seal','graph_first_ingress_c02_committed_seals_v2','seal_json',('bot','persona','operation_id'),key),
                    ('control_c02_receipt','graph_bundle_operations','receipt_json',('bot','persona','operation_id'),key),
                    ('control_small','graph_events','reads',('bot','persona','session','event_id'),eventkey),
                    ('control_small','graph_events','revisions',('bot','persona','session','event_id'),eventkey))]
            self.stage='c02';return
        if self.stage=='c02':
            if self.index<len(self.columns):
                if self.columns[self.index].advance(meter):self.index+=1
                return
            evidence,seal,business,reads,writes=(c.require_v3(r)for c in self.columns)
            atom=AtomKey.from_token(q.source_ref)
            if(evidence.get('source_ref')!=atom.owner.subject or 'first_ingress_c02'not in business
                    or seal.get('bundle_digest')!=self.archive[1]):
                raise AuthorityUnavailable('Artifact control C02/source/archive metadata differs')
            self.c02_original_deadline=min(self.budget.grant.valid_until_utc,seal['root_grant_valid_until_utc'],seal['business_deadline_utc'])
            self.original_business_deadline=self.c02_original_deadline
            self.deadline=min(self.deadline,self.original_business_deadline)
            s.c02_authority={'operation_id':q.c02_operation_id,'business_header':tuple(self.business),
                'archive_header':tuple(self.archive),'evidence_digest':self.columns[0].sha256,
                'seal_digest':self.columns[1].sha256,'receipt_digest':self.columns[2].sha256}
            from .first_ingress_v2 import ingress_ids
            op=ingress_ids(atom.owner.subject)[2];key=(*ns,op)
            names=('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility',
                'content_fingerprint','learned_at','bundle_digest')
            row=self._point(meter,'graph_first_ingress_identity_v1',names,
                'bot=? AND persona=? AND operation_id=?',key)
            observed=self._point(meter,'ingress_first_observations',
                ('content_fingerprint','learned_at','bundle_digest'),'bot=? AND persona=? AND operation_id=?',key)
            committed=self._point(meter,'graph_bundle_operations',('digest',),
                'bot=? AND persona=? AND operation_id=?',key)
            if(row is None or row[0]!=atom.owner.subject or row[5]!='private'
                    or observed!=row[6:9]or committed!=(row[8],)):
                raise AuthorityUnavailable('Artifact control lacks its actual private committed ingress identity')
            self.identity=tuple(row);self.ingress_op=op
            self.columns=[_ControlColumnV3(s,profile,table=table,column='identity_json',
                key_columns=('bot','persona','operation_id'),key=key)
                for profile,table in(('control_small','graph_first_ingress_identity_v1'),
                    ('control_ingress_intent','graph_first_ingress_intents_v2'))]
            self.index=0;self.stage='ingress';return
        if self.stage=='ingress':
            if self.index<len(self.columns):
                if self.columns[self.index].advance(meter):self.index+=1
                return
            identity,intent=(c.require_v3(r)for c in self.columns)
            if(set(identity)!={'schema','namespace','operation_id','source_ref','platform_ref','conversation_ref',
                    'sender_ref','message_id','visibility','lineage'}
                    or identity['schema']!='sylanne3.ingress.identity.v1'or identity['namespace']!=list(ns)
                    or identity['operation_id']!=self.ingress_op
                    or tuple(identity[name]for name in('source_ref','platform_ref','conversation_ref','sender_ref',
                        'message_id','visibility'))!=self.identity[:6]
                    or intent.get('fingerprint')!=self.identity[6]):
                raise AuthorityUnavailable('Artifact control actual whole-EOF ingress identity/fingerprint differs')
            s.audiences=(identity['conversation_ref'],)
            from .foreground_cycle_v1 import foreground_cycle_ids_v1
            _,job=foreground_cycle_ids_v1(r.namespace,q.c02_operation_id)
            self.cycle=self._point(meter,'runtime_jobs',_JOB_COLUMNS,'job_id=?',(job,))
            if self.cycle is not None:
                if(self.cycle[3:5]!=ns or(not _history_disclosure_only_v3(s)and(self.cycle[9]or self.cycle[5]in _TERMINAL))
                        or self.cycle[8]!=r.bundle.installation_policy.root_lease.lease_id):
                    raise AuthorityUnavailable('Artifact control original cycle is cancelled/terminal or crossed its Root')
                self.original_business_deadline=min(self.budget.grant.valid_until_utc,_utc_v3(self.cycle[7]))
                self.deadline=min(s.eligibility_deadline,self.original_business_deadline)
                self.columns=[_ControlColumnV3(s,'control_cycle',table='runtime_jobs',column='continuation_json',
                    key_columns=('job_id',),key=(job,))]
                self.index=0;self.stage='cycle';return
            self._select_request_root_v3();return
        if self.stage=='cycle':
            if not self.columns[0].advance(meter):return
            raw=self.columns[0].require_v3(r);self.cycle_value=raw
            if self.mirror is None:self.mirror=_ControlJobMirrorV3(s,self.cycle,self.columns[0].sha256)
            if not self.mirror.advance(meter):return
            if(raw.get('c02_operation_id')!=q.c02_operation_id or raw.get('source_ref')!=q.source_ref
                    or(not _history_disclosure_only_v3(s)and raw.get('cancel_generation')!=0)):
                raise AuthorityUnavailable('Artifact control actual cycle continuation/source differs')
            if raw.get('schema')=='d11.foreground-cycle-continuation.v2':
                self.signed=_ControlProducerV3(s,self.cycle[1],'d11',('create_foreground_cycle_v2',))
                self.stage='responsibility';return
            if raw.get('schema')=='d11.foreground-source-note-continuation.v1':
                from .source_note_foreground_v1 import RESPONSIBILITY_KIND
                self.signed=_SignedControlV3(s,RESPONSIBILITY_KIND,raw['responsibility_ref'])
                self.stage='note_responsibility';return
            if raw.get('schema')!='d11.foreground-cycle-continuation.v1':
                raise AuthorityUnavailable('Artifact control actual cycle schema is unsupported')
            self.cycle_producer=_ControlProducerV3(s,self.cycle[1],'d11',('create_foreground_cycle',))
            self.stage='cycle_v1_original';return
        if self.stage=='cycle_v1_original':
            if not self.cycle_producer.advance(meter):return
            self._select_request_root_v3();return
        if self.stage=='responsibility':
            if not self.signed.advance(meter):return
            from .foreground_cycle_v1 import ForegroundResponsibilityV1
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            self.cycle_producer=self.signed
            value=decode_typed_production_value_v1(self.signed.original['provenance']['foreground_responsibility'],ForegroundResponsibilityV1)
            if(value.digest!=self.cycle_value['responsibility_digest']or value.source_ref!=q.source_ref
                    or value.c02_operation_id!=q.c02_operation_id):
                raise AuthorityUnavailable('Artifact control responsibility differs from its original cycle')
            self.responsibility=value;self.expected_owner_guard=value.owner_guard
            self.original_business_deadline=min(self.original_business_deadline,value.deadline_utc)
            self.deadline=min(self.deadline,self.original_business_deadline)
            self.root_ref=value.root_registration_ref
            if self.root_ref is not None:self.purpose='consolidation'
            self._root_or_finish_v3();return
        if self.stage=='note_responsibility':
            if not self.signed.advance(meter):return
            from .source_note_foreground_v1 import ForegroundSourceNoteResponsibilityV1
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            value=decode_typed_production_value_v1(self.signed.value,ForegroundSourceNoteResponsibilityV1)
            if(value.digest!=self.cycle_value['responsibility_digest']or value.source_ref!=q.source_ref
                    or value.c02_operation_id!=q.c02_operation_id or value.parent_budget_lease_ref!=self.budget.lease
                    or self.signed.header[0]!=self.cycle[1]):
                raise AuthorityUnavailable('Artifact control actual SourceNote responsibility/source/Root differs')
            self.responsibility=value;self.expected_owner_guard=value.owner_guard;self.signed_metadata.append(self.signed)
            self.original_business_deadline=min(self.original_business_deadline,value.deadline_utc)
            self.deadline=min(self.deadline,self.original_business_deadline);self.additional_roots=value.source_refs
            self.purpose='consolidation'
            self.cycle_producer=_ControlProducerV3(s,self.cycle[1],'d11',('create_source_note_foreground_cycle_v1',))
            self.stage='note_cycle_original';return
        if self.stage=='note_cycle_original':
            if not self.cycle_producer.advance(meter):return
            if self.cycle_producer.original.get('provenance',{}).get('responsibility')!=self.signed.value:
                raise AuthorityUnavailable('Artifact control SourceNote responsibility lost actual create producer')
            self._finish_v3();return
        if self.stage=='note_authorization':
            if not self.signed.advance(meter):return
            from .source_note_task_authorization_v1 import SourceNoteTaskAuthorizationV1
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            value=decode_typed_production_value_v1(self.signed.value,SourceNoteTaskAuthorizationV1)
            if(value.namespace!=r.namespace or value.request.c02_operation_id!=q.c02_operation_id
                    or value.request.source_ref!=q.source_ref or value.parent_budget_lease_ref!=self.budget.lease
                    or value.authorization_operation_id!=self.signed.header[0]):
                raise AuthorityUnavailable('Artifact control actual SourceNote authorization/source/Root differs')
            producer=meter.read_fixed_row(r.db,'graph_bundle_operations',('commit_seq',),
                'bot=? AND persona=? AND operation_id=?',(*ns,self.signed.header[0]))
            if producer is None or type(producer[0])is not int or producer[0]<1:
                raise AuthorityUnavailable('Artifact control SourceNote authorization lacks actual positive W01 producer')
            self.expected_owner_guard=value.owner_guard;self.signed_metadata.append(self.signed)
            self.original_business_deadline=min(self.budget.grant.valid_until_utc,value.original_deadline_utc)
            self.deadline=min(s.eligibility_deadline,self.original_business_deadline);self.additional_roots=value.source_refs
            self.purpose='consolidation';self._finish_v3();return
        if self.stage=='natural_cause':
            if not self.signed.advance(meter):return
            from .foreground_cycle_v1 import ForegroundPostC02CauseV1
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            cause=decode_typed_production_value_v1(self.signed.value,ForegroundPostC02CauseV1)
            natural=r.bundle.foreground.deadline_policy.natural
            policy=r.bundle.installation_policy
            if(natural is None or(cause.namespace,cause.installation_id,cause.manifest_digest,
                    cause.c02_operation_id,cause.source_ref,cause.commit_seq)!=(
                        r.namespace,policy.installation_id,policy.manifest_digest,
                        q.c02_operation_id,q.source_ref,self.business[3])
                    or self.signed.header[0]!=q.c02_operation_id):
                raise AuthorityUnavailable('Artifact control natural cause differs from actual C02/Source/installation')
            self.signed_metadata.append(self.signed)
            self.original_business_deadline=min(self.budget.grant.valid_until_utc,cause.cause_frozen_at_utc+natural.window_seconds)
            self.deadline=min(s.eligibility_deadline,self.original_business_deadline)
            self._finish_v3();return
        if self.stage=='root':
            if not self.signed.advance(meter):return
            from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
            root=draft_from_wire_v1(self.signed.value,DraftRootCapabilityV1);p=r.bundle.installation_policy
            if(root.source_ref!=q.source_ref or root.registration_ref!=self.root_ref
                    or(root.installation_id,root.manifest_digest)!=(p.installation_id,p.manifest_digest)):
                raise AuthorityUnavailable('Artifact control actual signed Root source/installation differs')
            self.root=root
            if self.cycle is None:
                self.original_business_deadline=min(self.budget.grant.valid_until_utc,_utc_v3(root.valid_until_utc))
            else:self.original_business_deadline=min(self.original_business_deadline,_utc_v3(root.valid_until_utc))
            self.deadline=min(s.eligibility_deadline,self.original_business_deadline)
            s.metadata_headers.append(('signed',self.signed.kind,self.signed.ref,self.signed.header))
            self.root_producer=_ControlProducerV3(s,self.signed.header[0],'d10',
                ('register_artifact_draft_root','derive_ingress_artifact_task_scope_v1'))
            self.stage='root_producer';return
        if self.stage=='root_producer':
            if not self.root_producer.advance(meter):return
            if self.root_producer.original.get('provenance',{}).get('draft_root_capability')!=self.signed.value:
                raise AuthorityUnavailable('Artifact control Root lacks its actual original setup W01 producer')
            self._finish_v3();return
        raise AuthorityUnavailable('Artifact control seed has no registered next phase')
    def _select_request_root_v3(self):
        q=self.state.reader.selector
        if type(q)is ArtifactEntryPrepareSelectorV3 and q.entry_kind=='prepare_source_note_foreground_cycle_v1':
            ref=dict(q.arguments)['authorization_original_ref']
            self.signed=_SignedControlV3(self.state,'source_note_task_authorization',ref)
            self.stage='note_authorization';return
        if type(q)is ArtifactForegroundMetadataSelectorV3:
            from .foreground_cycle_v1 import CreateForegroundCycleRequestV2
            from .source_note_foreground_v1 import CreateSourceNoteForegroundCycleRequestV1
            if type(q.request)is CreateForegroundCycleRequestV2:
                self.root_ref=q.request.draft_root_registration_ref
                if self.root_ref is not None:self.purpose='consolidation'
                elif self.cycle is None:
                    self.signed=_SignedControlV3(self.state,'foreground_post_c02_cause',q.request.cause_original_ref)
                    self.stage='natural_cause';return
            elif type(q.request)is CreateSourceNoteForegroundCycleRequestV1:
                self.signed=_SignedControlV3(self.state,'source_note_task_authorization',q.request.authorization_original_ref)
                self.stage='note_authorization';return
            elif q.operation_kind=='derive_ingress_artifact_task_scope_v1':
                self.purpose='consolidation'
        self._root_or_finish_v3()
    def _root_or_finish_v3(self):
        if self.root_ref is None:self._finish_v3()
        else:self.signed=_SignedControlV3(self.state,'draft_root_capability',self.root_ref);self.stage='root'
    def _finish_v3(self):
        s=self.state;r=s.reader
        deferred=s.profile in {'entry_prepare','post_commit_read'}and self.cycle is None and self.root is None and self.purpose!='consolidation'
        s.eligibility_deadline=min(s.eligibility_deadline,self.budget.grant.valid_until_utc,
            r.operation.deadline_utc if deferred else self.deadline)
        if r.now>=s.eligibility_deadline:raise AuthorityUnavailable('Artifact control original C02/cycle/Root deadline expired')
        cycle_sources=()if self.cycle_producer is None else tuple(
            v.key.token for v in self.cycle_producer.read_versions if v.key.type_name=='memory.source')
        s.current_roots=tuple(dict.fromkeys((r.selector.source_ref,*self.additional_roots,*cycle_sources)));s.purpose=self.purpose
        if self.cycle_producer is not None:
            s.expected_source_versions_v3={v.key:v.revision for v in self.cycle_producer.read_versions
                if v.key.type_name=='memory.source'}
        s.group_specs=[('control:'+str(i//32),s.current_roots[i:i+32],s.purpose,s.audiences)
            for i in range(0,len(s.current_roots),32)]
        s.metadata_headers.extend(('point',*pin)for pin in self.headers)
        for task in self.signed_metadata:
            s.verified_metadata_v3['graph_d11_life_originals_v1',task.kind,task.ref]={
                'projection':task.value,'header':task.header,'payload_digest':task.header[1],
                'operation_id':task.header[0],'source_roots':s.current_roots,'selector':None,'producer_header':None}
        s.verified_metadata_v3['runtime_budget_grants','budget_grant',self.budget.lease]={
            'projection':self.budget.column.require_v3(r),'header':self.budget.header,
            'payload_digest':self.budget.column.sha256,'operation_id':None,'source_roots':s.current_roots,
            'selector':None,'producer_header':None}
        if self.cycle_producer is not None:
            cp=self.cycle_producer
            s.verified_metadata_v3['graph_domain_production_originals_v1',cp.header[1],cp.operation]={
                'projection':cp.original,'header':cp.header,'payload_digest':cp.header[3],
                'operation_id':cp.operation,'source_roots':s.current_roots,'selector':None,
                'producer_header':cp.header,'read_versions':cp.read_versions,'write_versions':cp.receipt.write_versions,'physical_layout':cp.layout}
        if self.root is not None:
            s.verified_metadata_v3['graph_d11_life_originals_v1','draft_root_capability',self.root.registration_ref]={
                'projection':self.signed.value,'header':self.signed.header,'payload_digest':self.signed.header[1],
                'operation_id':self.signed.header[0],'source_roots':s.current_roots,'selector':None,
                'producer_header':self.root_producer.header}
            s.verified_metadata_v3['graph_domain_production_originals_v1',self.root_producer.header[1],self.root_producer.operation]={
                'projection':self.root_producer.original,'header':self.root_producer.header,
                'payload_digest':self.root_producer.header[3],'operation_id':self.root_producer.operation,
                'source_roots':s.current_roots,'selector':None,'producer_header':self.root_producer.header,
                'read_versions':self.root_producer.read_versions,'write_versions':self.root_producer.receipt.write_versions,
                'physical_layout':self.root_producer.layout}
        s.metadata_complete=True;s.phase='owner';self.stage='complete'

class _ControlBudgetV3(common._DispatchBudgetMetadataV3):
    def __init__(self,state):super().__init__(state,state.reader.bundle.installation_policy.root_lease.lease_id)
    def advance(self,meter):
        r=self.state.reader;self.state.require_current_v3(meter)
        row=meter.read_fixed_row(r.db,'runtime_budget_grants',('lease_id','version','signature','status'),
            'lease_id=? ORDER BY version DESC',(self.lease,))
        if row is None or row[3]!='active':raise AuthorityUnavailable('Artifact control actual installed Root grant is inactive')
        if self.header is None:
            self.header=tuple(row);self.column=_ControlColumnV3(self.state,'control_small',
                table='runtime_budget_grants',column='grant_json',key_columns=('lease_id','version'),key=(self.lease,row[1]))
            return False
        if tuple(row)!=self.header:raise AuthorityUnavailable('Artifact control actual Root grant changed during EOF')
        if not self.column.advance(meter):return False
        raw=self.column.require_v3(r)
        r.graph._GraphCoordinator__d11_issuer._signer.verify('budget-grant.v1',canonical_serialize(raw),self.header[2])
        from .issuers import BudgetLeaseGrant
        actual=BudgetLeaseGrant(**{**raw,'allowed_work_kinds':tuple(raw['allowed_work_kinds'])})
        if actual!=r.bundle.installation_policy.root_grant:
            raise AuthorityUnavailable('Artifact control signed installed Root differs from actual policy')
        lease=meter.read_fixed_row(r.db,'runtime_budget_leases',('bot_id','persona_id','currency','state'),
            'lease_id=?',(self.lease,))
        if lease!=(*r.namespace.as_tuple,actual.currency,'active'):
            raise AuthorityUnavailable('Artifact control original Root lease namespace/currency/state differs')
        self.grant=actual;self.complete=True;return True



def _utc_v3(value):return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()

_JOB_COLUMNS=('job_id','operation_id','activity_id','bot_id','persona_id','phase','work_kind','deadline_utc',
    'budget_ref','cancel_epoch','result_ref')
_TERMINAL={'cancelled','failed','completed','draining'}

class _DiscoveryV3:
    def __init__(self,state):
        self.state=state;selector=state.reader.selector
        self.after=selector.after_job_id;self.through=selector.through_job_id
        self.watermark_set=selector.through_job_id is not None
        self.scanned=0;self.eof=False;self.items=[];self.refusals=[]
        self.current=None;self.stage='next';self.column=self.signed=self.root=self.budget=self.producer=None;self.mirror=None
        self.raw=self.prepared=self.task=self.cycle=self.source_ref=None
        self.accepted=[];self.headers=[]
    def refuse_v3(self,code,error=None):
        self.refusals.append({'job_id':self.after,'reason_code':code,'phase':self.stage,
            'error_type':None if error is None else type(error).__name__})
        self.current=self.column=self.signed=self.root=self.budget=self.producer=None;self.mirror=None
        self.raw=self.prepared=self.task=self.cycle=self.source_ref=None;self.stage='next'
    def advance(self,meter):
        s=self.state;r=s.reader;ns=r.namespace.as_tuple
        try:self._advance(meter)
        except _ItemRefusalV3 as error:self.refuse_v3(error.code,error)
        # Exact codecs/signatures may reject a damaged item. The same-Work
        # current gate is repeated first; its failures always abort the page.
        except (ValueError,TypeError,KeyError,IssuerAuthorityDenied,AuthorityUnavailable)as error:
            s.require_current_v3(meter);self.refuse_v3(self.stage+'_original_'+type(error).__name__,error)
            self.refusals[-1]['detail']=str(error)[:256]
    def _advance(self,meter):
        s=self.state;r=s.reader;ns=r.namespace.as_tuple
        if self.stage=='next':
            if not self.watermark_set:
                row=meter.read_fixed_row(r.db,'runtime_jobs',('job_id',),
                    "bot_id=? AND persona_id=? AND work_kind='artifact_draft_v1' ORDER BY job_id DESC LIMIT 1",ns)
                self.through=None if row is None else row[0];self.watermark_set=True
                if self.through is None:self.eof=True
                return
            if self.eof or self.scanned>=r.selector.limit:
                s.current_roots=tuple(dict.fromkeys(item['source_ref']for item in self.accepted))
                s.group_specs=[('discovery:'+str(i),(item['source_ref'],),'consolidation',item['prepared'].audiences)
                    for i,item in enumerate(self.accepted)]
                s.audiences=tuple(dict.fromkeys(a for spec in s.group_specs for a in spec[3]))
                s.metadata_complete=True;s.phase='owner';return
            row=meter.read_fixed_row(r.db,'runtime_jobs',_JOB_COLUMNS,
                "bot_id=? AND persona_id=? AND work_kind='artifact_draft_v1' AND job_id>? AND job_id<=? ORDER BY job_id LIMIT 1",
                (*ns,self.after or'',self.through))
            if row is None:self.eof=True;return
            self.current=tuple(row);self.after=row[0];self.scanned+=1
            self.headers.append(('runtime_jobs',_JOB_COLUMNS,'job_id=?',(row[0],),self.current))
            if row[3:5]!=ns or row[6]!='artifact_draft_v1':raise _ItemRefusalV3('job_scope')
            if row[9]or row[5]in _TERMINAL:raise _ItemRefusalV3('job_cancelled_or_terminal')
            if r.now>=_utc_v3(row[7]):raise _ItemRefusalV3('job_original_deadline')
            self.column=_ControlColumnV3(s,'control_job',table='runtime_jobs',column='continuation_json',
                key_columns=('job_id',),key=(row[0],));self.stage='continuation';return
        if self.stage=='continuation':
            if not self.column.advance(meter):return
            raw=self.column.require_v3(r)
            if self.mirror is None:self.mirror=_ControlJobMirrorV3(s,self.current,self.column.sha256)
            if not self.mirror.advance(meter):return
            self.mirror=None
            if self.column.top_fields!={'schema','selector','prepared_digest'}:raise _ItemRefusalV3('job_fieldset')
            from ..model_broker.artifact_draft_v1 import(ArtifactDraftTaskSelectorV1,ArtifactDraftPhaseSelectorV2,
                artifact_draft_from_wire_v1,artifact_draft_from_wire_v2,artifact_draft_model_ids_v1,artifact_draft_model_ids_v2)
            if raw['schema']=='d11.artifact-draft-model-job.v1':
                selector=artifact_draft_from_wire_v1(raw['selector'],ArtifactDraftTaskSelectorV1)
                task=selector;ids=artifact_draft_model_ids_v1(selector);kind='c4_prepared'
            elif raw['schema']=='d11.artifact-draft-phase-model-job.v2':
                selector=artifact_draft_from_wire_v2(raw['selector'],ArtifactDraftPhaseSelectorV2)
                task=selector.task;ids=artifact_draft_model_ids_v2(selector);kind='c4_phase_prepared'
            else:raise _ItemRefusalV3('unknown_job_schema')
            if task.namespace!=r.namespace or ids['job']!=self.current[0]:raise _ItemRefusalV3('selector_job_identity')
            self.raw=raw;self.task=task;self.selector=selector
            self.signed=_SignedControlV3(s,kind,ids['job']);self.stage='prepared';return
        if self.stage=='prepared':
            if not self.signed.advance(meter):return
            from .d11_artifact_draft_model_v1 import(ArtifactDraftModelPreparedV1,ArtifactDraftModelPreparedV2,
                artifact_draft_model_from_wire_v1,artifact_draft_model_from_wire_v2)
            phase=self.signed.kind=='c4_phase_prepared'
            p=(artifact_draft_model_from_wire_v2(self.signed.value,ArtifactDraftModelPreparedV2)if phase else
                artifact_draft_model_from_wire_v1(self.signed.value,ArtifactDraftModelPreparedV1))
            policy=r.bundle.installation_policy
            if(p.selector!=self.selector or p.digest!=self.raw['prepared_digest']or p.job_id!=self.current[0]
                    or p.operation_id!=self.current[1]or p.operation_id!=self.signed.header[0]
                    or p.activity_id!=self.current[2]or p.namespace!=r.namespace
                    or(p.installation_id,p.manifest_digest,p.worker_subject)!=(
                        policy.installation_id,policy.manifest_digest,s.model_grant.subject)
                    or p.parent_budget_lease_ref!=self.current[8]):
                raise _ItemRefusalV3('prepared_job_installation_binding')
            if r.now>=_utc_v3(p.deadline_utc):raise _ItemRefusalV3('prepared_original_deadline')
            s.metadata_headers.append(('signed',self.signed.kind,self.signed.ref,self.signed.header))
            self.prepared=p
            self.producer=_ControlProducerV3(s,p.operation_id,'d11',
                ('prepare_artifact_draft_model_v2'if phase else'prepare_artifact_draft_model',))
            self.stage='producer';return
        if self.stage=='producer':
            if not self.producer.advance(meter):return
            from .foreground_cycle_v1 import foreground_cycle_ids_v1
            activity,job=foreground_cycle_ids_v1(r.namespace,self.task.c02_operation_id)
            row=meter.read_fixed_row(r.db,'runtime_jobs',_JOB_COLUMNS,'job_id=?',(job,))
            if row is None:raise _ItemRefusalV3('cycle_missing')
            self.cycle=tuple(row);self.headers.append(('runtime_jobs',_JOB_COLUMNS,'job_id=?',(job,),self.cycle))
            if(row[0]!=job or row[2]!=activity or row[3:5]!=ns or row[9]or row[5]in _TERMINAL
                    or row[8]!=self.prepared.parent_budget_lease_ref):
                raise _ItemRefusalV3('cycle_cancelled_terminal_or_scope')
            if r.now>=_utc_v3(row[7]):raise _ItemRefusalV3('cycle_original_deadline')
            self.column=_ControlColumnV3(s,'control_cycle',table='runtime_jobs',column='continuation_json',
                key_columns=('job_id',),key=(job,));self.stage='cycle';return
        if self.stage=='cycle':
            if not self.column.advance(meter):return
            raw=self.column.require_v3(r)
            if self.mirror is None:self.mirror=_ControlJobMirrorV3(s,self.cycle,self.column.sha256)
            if not self.mirror.advance(meter):return
            self.mirror=None
            if(raw['schema']not in {'d11.foreground-cycle-continuation.v1','d11.foreground-cycle-continuation.v2'}
                    or raw['c02_operation_id']!=self.task.c02_operation_id or raw['cancel_generation']!=0):
                raise _ItemRefusalV3('cycle_continuation_identity')
            key=AtomKey.from_token(raw['source_ref'])
            if key.type_name!='memory.source'or NamespaceId.from_key(key)!=r.namespace:
                raise _ItemRefusalV3('cycle_source_scope')
            self.source_ref=raw['source_ref']
            self.root=_SignedControlV3(s,'draft_root_capability',self.task.root_registration_ref)
            self.stage='root';return
        if self.stage=='root':
            if not self.root.advance(meter):return
            from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
            root=draft_from_wire_v1(self.root.value,DraftRootCapabilityV1);p=self.prepared;policy=r.bundle.installation_policy
            if((root.registration_ref,root.source_ref,root.installation_id,root.manifest_digest)!=(
                    self.task.root_registration_ref,self.source_ref,policy.installation_id,policy.manifest_digest)
                    or(root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest)!=(
                        p.owner_guard.grant_ref,p.owner_guard.grant_revision,p.owner_guard.grant_digest)):
                raise _ItemRefusalV3('root_source_owner_binding')
            if r.now>=_utc_v3(root.valid_until_utc):raise _ItemRefusalV3('root_original_deadline')
            s.metadata_headers.append(('signed',self.root.kind,self.root.ref,self.root.header))
            self.root_value=root
            self.producer=_ControlProducerV3(s,self.root.header[0],'d10',
                ('register_artifact_draft_root','derive_ingress_artifact_task_scope_v1'))
            self.stage='root_producer';return
        if self.stage=='root_producer':
            if not self.producer.advance(meter):return
            if self.producer.original.get('provenance',{}).get('draft_root_capability')!=self.root.value:
                raise _ItemRefusalV3('root_actual_producer_binding')
            self.budget=common._DispatchBudgetMetadataV3(s,self.prepared.parent_budget_lease_ref)
            self.stage='budget';return
        if self.stage=='budget':
            if not self.budget.advance(meter):return
            p=self.prepared
            if r.now>=self.budget.grant.valid_until_utc:raise _ItemRefusalV3('root_grant_original_deadline')
            reservation=meter.read_fixed_row(r.db,'runtime_budget_reservations',('digest','state'),
                'lease_id=? AND operation_id=?',(p.parent_budget_lease_ref,p.operation_id))
            if reservation is None or reservation[0]!=p.reservation_digest:
                raise _ItemRefusalV3('reservation_original_binding')
            self.accepted.append({'job_id':p.job_id,'c02_operation_id':self.task.c02_operation_id,
                'source_ref':self.source_ref,'prepared':p,'root':self.root.value,
                'grant_header':self.budget.header,'currency':self.budget.grant.currency,'reservation_header':tuple(reservation),
                'deadline_utc':min(_utc_v3(p.deadline_utc),_utc_v3(self.cycle[7]),
                    _utc_v3(self.root.value['valid_until_utc']),self.budget.grant.valid_until_utc)})
            self.current=self.column=self.signed=self.root=self.budget=self.producer=None
            self.raw=self.prepared=self.task=self.cycle=self.source_ref=None;self.stage='next';return
        raise AuthorityUnavailable('Artifact discovery has no registered next phase')
    def result_v3(self,meter):
        from .domain_production_contracts_v1 import ProductionOwnerGuardV1
        from ..graph_types import owner_grant_key
        s=self.state;r=s.reader
        guard=ProductionOwnerGuardV1(owner_grant_key(*r.namespace.as_tuple).token,r.owner.grant_revision,
            r.owner.grant_digest.removeprefix('sha256:'),r.owner.authorization_head.removeprefix('sha256:'))
        items=[]
        for item in self.accepted:
            p=item['prepared'];code=None
            grant=meter.read_fixed_row(r.db,'runtime_budget_grants',('lease_id','version','signature','status'),
                'lease_id=? ORDER BY version DESC',(p.parent_budget_lease_ref,))
            lease=meter.read_fixed_row(r.db,'runtime_budget_leases',('bot_id','persona_id','currency','state'),
                'lease_id=?',(p.parent_budget_lease_ref,))
            reservation=meter.read_fixed_row(r.db,'runtime_budget_reservations',('digest','state'),
                'lease_id=? AND operation_id=?',(p.parent_budget_lease_ref,p.operation_id))
            if item.get('source_refused'):code=item['source_refused']
            elif p.owner_guard!=guard:code='current_owner_changed'
            elif p.actor_ref!=r.current_self.self_entity_ref:code='current_self_changed'
            elif r.now>=item['deadline_utc']:code='original_deadline_elapsed'
            elif grant!=item['grant_header']:code='original_root_grant_changed'
            elif lease!=(*r.namespace.as_tuple,item['currency'],'active'):code='original_root_lease_changed'
            elif reservation!=item['reservation_header']:code='original_reservation_changed'
            elif item['source_ref']not in s.root_source_metadata:code='current_source_unqualified'
            if code:
                self.refusals.append({'job_id':item['job_id'],'reason_code':code,'phase':'disclose','error_type':None})
            else:items.append({'job_id':item['job_id'],'c02_operation_id':item['c02_operation_id'],'source_ref':item['source_ref']})
        for table,columns,where,key,header in self.headers:
            if meter.read_fixed_row(r.db,table,columns,where,key)!=header:
                raise AuthorityUnavailable('Artifact discovery page changed before disclosure')
        return {'schema':'d11.artifact-discovery-page.v3','items':tuple(items),'refusals':tuple(self.refusals),
            'after_job_id':self.after,'through_job_id':self.through,'eof':self.eof}



class _ControlJobMirrorV3:
    def __init__(self,state,header,continuation_digest):
        self.state,self.job,self.continuation_digest=state,header,continuation_digest
        self.header=self.column=None;self.complete=False
    def advance(self,meter):
        from .d11_types import runtime_job_key,RuntimeJobValue
        from dataclasses import fields
        s=self.state;r=s.reader;j=self.job;key=runtime_job_key(*r.namespace.as_tuple,j[2],j[0])
        row=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
            'token=? AND bot=? AND persona=?',(key.token,*r.namespace.as_tuple))
        if self.header is None:
            if row is None or row[1]!=1 or row[2]is None:raise _ItemRefusalV3('current_graph_job_missing')
            self.header=tuple(row)
            self.column=_ControlColumnV3(s,'control_small',table='graph_atoms',column='value',
                key_columns=('token','bot','persona'),key=(key.token,*r.namespace.as_tuple),cell_id=row[2])
            return False
        if tuple(row or())!=self.header:raise AuthorityUnavailable('Artifact control Graph job changed during metadata EOF')
        if not self.column.advance(meter):return False
        raw=self.column.require_v3(r)
        if self.column.top_fields!={f.name for f in fields(RuntimeJobValue)}:
            raise _ItemRefusalV3('graph_job_metadata_fieldset')
        value=RuntimeJobValue(**raw)
        for name,index in(('job_id',0),('operation_id',1),('activity_id',2),('bot_id',3),('persona_id',4),
                ('phase',5),('work_kind',6),('deadline_utc',7),('parent_budget_lease_ref',8),
                ('cancel_epoch',9),('result_ref',10)):
            if getattr(value,name)!=j[index]:raise _ItemRefusalV3('sql_graph_job_metadata_binding')
        if value.continuation_digest!=self.continuation_digest:raise _ItemRefusalV3('sql_graph_continuation_eof_binding')
        history=meter.read_fixed_row(r.db,'graph_history',('event_id','event_bot','event_persona','valid','value_cell_id'),
            'token=? AND revision=?',(key.token,self.header[0]))
        if history is None or history[1:]!=(*r.namespace.as_tuple,1,self.header[2]):
            raise _ItemRefusalV3('graph_job_history_member')
        bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('commit_seq',),
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,history[0]))
        if bundle is None or type(bundle[0])is not int or bundle[0]<1:raise _ItemRefusalV3('graph_job_w01_producer')
        self.complete=True;return True

class _SemanticLocatorsV3:
    """At most the actual completed phase prefix; only declared signed locators."""
    def __init__(self,state):
        from .foreground_call_plan_v1 import ForegroundArtifactPhaseGroupV2
        from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2
        raw=state.seed.cycle_value
        group=None if raw is None else raw.get('call_plan',{}).get('phase_group')
        self.state=state;self.complete=group is None;self.index=0;self.task=None;self.stage='verified'
        self.roots=list(state.current_roots);self.verified=self.adopted=self.prepared=None
        if group is None:self.group=None;return
        self.group=ForegroundArtifactPhaseGroupV2(
            artifact_draft_from_wire_v2(group['selector'],ArtifactDraftPhaseSelectorV2),
            tuple(tuple(row)for row in group['completed_phase_originals']),group['schema'])
        q=state.reader.selector
        if(self.group.selector.task.namespace!=q.namespace or self.group.selector.task.c02_operation_id!=q.c02_operation_id
                or state.seed.root is None or self.group.selector.task.root_registration_ref!=state.seed.root.registration_ref):
            raise AuthorityUnavailable('Artifact locator phase group lost its actual current task/Root')
    def _ready_v3(self,meter):
        if not self.task.advance(meter):return False
        r=self.state.reader
        producer=meter.read_fixed_row(r.db,'graph_bundle_operations',('commit_seq',),
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,self.task.header[0]))
        if producer is None or type(producer[0])is not int or producer[0]<1:
            raise AuthorityUnavailable('Artifact locator signed metadata lacks actual positive W01 producer')
        self.producer_header=tuple(producer);return True
    def advance(self,meter):
        s=self.state;r=s.reader
        if self.complete:return True
        from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2,artifact_draft_phase_sequence_v2
        from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
        if self.stage=='verified':
            if self.index>=len(self.group.completed_phase_originals):
                self.complete=True;self._finish_v3();return True
            ref,digest=self.group.completed_phase_originals[self.index]
            if self.task is None:self.task=_SignedControlV3(s,'c4_phase_verified',ref);return False
            if not self._ready_v3(meter):return False
            from .d11_artifact_draft_content_v1 import ArtifactDraftPhaseVerifiedOriginalV2,artifact_draft_phase_verification_from_wire_v2
            value=artifact_draft_phase_verification_from_wire_v2(self.task.value,ArtifactDraftPhaseVerifiedOriginalV2)
            phases=artifact_draft_phase_sequence_v2(self.group.selector.method_ref)
            previous=self.group.completed_phase_originals[self.index-1]if self.index else(None,None)
            if(value.digest!=digest or value.selector.phase_index!=self.index
                    or value.selector.phase_kind!=phases[self.index]
                    or foreground_artifact_phase_group_identity_v2(value.selector)!=foreground_artifact_phase_group_identity_v2(self.group.selector)
                    or(value.prev_verified_original_ref,value.prev_verified_original_digest)!=previous
                    or value.producing_operation_id!=self.task.header[0]):
                raise AuthorityUnavailable('Artifact locator verified prefix lost actual same-task/phase/producer joins')
            self.verified=value;self.roots.append(value.source_head.key.token)
            self._publish_v3(self.task,value.selector)
            self.task=_SignedControlV3(s,'c4_phase_adopted',value.content_adoption_ref)
            self.stage='adopted';return False
        if self.stage=='adopted':
            if not self._ready_v3(meter):return False
            from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV2,artifact_draft_content_from_wire_v2
            value=artifact_draft_content_from_wire_v2(self.task.value,ArtifactDraftContentAdoptionV2);v=self.verified
            if canonical_digest(self.task.value)!=v.content_adoption_digest:
                raise AuthorityUnavailable('Artifact locator adoption whole canonical digest differs')
            if(value.selector!=v.content_selector or value.content.content.ref!=v.source_head.key.token
                    or value.adoption_operation_id!=self.task.header[0]
                    or value.original_deadline_utc!=v.original_deadline_utc):
                raise AuthorityUnavailable('Artifact locator actual verified/adoption/source scope differs')
            self.adopted=value;self.roots.extend((*value.content.source_refs,value.task_source.ref))
            self._publish_v3(self.task,value.selector)
            ids=artifact_draft_model_ids_v2(value.selector)
            self.task=_SignedControlV3(s,'c4_phase_prepared',ids['job']);self.stage='prepared';return False
        if self.stage=='prepared':
            if not self._ready_v3(meter):return False
            from .d11_artifact_draft_model_v1 import ArtifactDraftModelPreparedV2,artifact_draft_model_from_wire_v2
            p=artifact_draft_model_from_wire_v2(self.task.value,ArtifactDraftModelPreparedV2)
            if(p.selector!=self.adopted.selector or p.digest!=self.adopted.prepared_digest
                    or p.actor_ref!=r.current_self.self_entity_ref
                    or p.operation_id!=self.task.header[0]or p.parent_budget_lease_ref!=r.bundle.installation_policy.root_lease.lease_id):
                raise AuthorityUnavailable('Artifact locator actual adoption/prepared/Root binding differs')
            self.prepared=p;self._publish_v3(self.task,p.selector)
            self.task=_SignedControlV3(s,'c4_phase_frozen',p.frozen_ref,'control_semantic_frozen')
            self.stage='frozen';return False
        if self.stage=='frozen':
            if not self._ready_v3(meter):return False
            raw=self.task.value;p=self.prepared
            from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2
            if(self.task.header[1]!=p.frozen_digest or self.task.header[0]!=p.operation_id
                    or artifact_draft_from_wire_v2(raw['selector'],ArtifactDraftPhaseSelectorV2)!=p.selector
                    or raw['task_source_ref']!=r.selector.source_ref):
                raise AuthorityUnavailable('Artifact locator frozen metadata lost actual prepared/task Source')
            self.roots.extend(source['ref']for source in raw['sources'])
            prior=raw.get('prior_content')
            if prior is not None:
                self.roots.append(prior['source_head']['ref'])
                prefix=dict(self.group.completed_phase_originals)
                if prefix.get(prior['verified_original_ref'])!=prior['verified_original_digest']:
                    raise AuthorityUnavailable('Artifact frozen prior content escapes actual completed prefix')
            self._publish_v3(self.task,p.selector)
            self.task=None;self.index+=1;self.stage='verified';return False
        raise AuthorityUnavailable('Artifact semantic locator has no registered next phase')
    def _publish_v3(self,task,selector):
        s=self.state
        s.verified_metadata_v3['graph_d11_life_originals_v1',task.kind,task.ref]={
            'projection':task.value,'header':task.header,'payload_digest':task.header[1],
            'operation_id':task.header[0],'source_roots':tuple(dict.fromkeys(self.roots)),
            'selector':selector,'producer_header':self.producer_header}
    def _finish_v3(self):
        s=self.state
        roots=tuple(dict.fromkeys(self.roots))
        for ref in roots:
            key=AtomKey.from_token(ref)
            if key.type_name!='memory.source'or NamespaceId.from_key(key)!=s.reader.namespace:
                raise AuthorityUnavailable('Artifact phase metadata Source locator crossed actual namespace')
        s.current_roots=roots
        special={ref for spec in s.special_source_groups_v3 for ref in spec[1]}
        ordinary=tuple(ref for ref in roots if ref not in special)
        s.group_specs=[('control:'+str(i//32),ordinary[i:i+32],s.purpose,s.audiences)
            for i in range(0,len(ordinary),32)]+s.special_source_groups_v3



class _ActiveObjectivesV3:
    def __init__(self,state):
        self.state=state;self.after='';self.count=0;self.task=None;self.goal=None
        self.goal_header=None;self.value=None;self.rows=[];self.roots=[];self.complete=False
    def advance(self,meter):
        from .d11_life_preparation_v1 import TABLE
        s=self.state;r=s.reader
        if self.task is None:
            row=meter.read_fixed_row(r.db,TABLE,('original_ref',),
                "bot=? AND persona=? AND kind='artifact_task_objective' AND original_ref>? ORDER BY original_ref LIMIT 1",
                (*r.namespace.as_tuple,self.after))
            if row is None:self.complete=True;return True
            self.after=row[0];self.count+=1
            if self.count>128:raise AuthorityUnavailable('Artifact active objective metadata exceeds existing complete inventory bound')
            self.task=_SignedControlV3(s,'artifact_task_objective',self.after);return False
        if self.value is None:
            if not self.task.advance(meter):return False
            from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1,task_objective_ref_v1
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            value=decode_typed_production_value_v1(self.task.value,ArtifactTaskObjectiveV1)
            policy=r.bundle.installation_policy
            if(value.namespace!=r.namespace or task_objective_ref_v1(value)!=self.after):
                raise AuthorityUnavailable('Artifact active objective signed metadata changed actual namespace/ref')
            bundle=meter.read_fixed_row(r.db,'graph_bundle_operations',('commit_seq',),
                'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,self.task.header[0]))
            if bundle is None or type(bundle[0])is not int or bundle[0]<1:
                raise AuthorityUnavailable('Artifact active objective has no positive W01 producer')
            self.value=value
            goal=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
                'token=? AND bot=? AND persona=?',(value.goal_ref,*r.namespace.as_tuple))
            self.goal_header=None if goal is None else tuple(goal)
            if goal is None or goal[1]!=1:
                self._next_v3();return False
            self.goal=_ControlColumnV3(s,'control_goal_state',table='graph_atoms',column='value',
                key_columns=('token','bot','persona'),key=(value.goal_ref,*r.namespace.as_tuple),cell_id=goal[2])
            return False
        current=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
            'token=? AND bot=? AND persona=?',(self.value.goal_ref,*r.namespace.as_tuple))
        if tuple(current or())!=self.goal_header:raise AuthorityUnavailable('Artifact active objective Goal changed during metadata EOF')
        if not self.goal.advance(meter):return False
        goal=self.goal.require_v3(r);value=self.value
        if goal.get('state')=='active':
            self.rows.append({'root_resource_id':value.root_resource_id,'filename':value.filename,
                'valid_until_utc':value.valid_until_utc,'source_ref':value.source_ref,
                'initial_c02_operation_id':value.initial_c02_operation_id,'goal_ref':value.goal_ref,
                'plan_ref':value.plan_ref,'project_ref':value.project_ref,'recipe_ref':value.recipe_ref})
            from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
            policy=r.bundle.artifact_draft
            scopes=(policy.tool_scope._installed_tool_scopes if type(policy)is AdminArtifactDraftPairedPolicyV4
                else (policy.tool_scope,))
            if any((value.root_resource_id,value.filename)==(scope.resource_id,scope.filename)for scope in scopes):
                self.roots.append(value.source_ref)
            s.verified_metadata_v3['graph_d11_life_originals_v1','artifact_task_objective',self.task.ref]={
                'projection':self.task.value,'header':self.task.header,'payload_digest':self.task.header[1],
                'operation_id':self.task.header[0],'source_roots':(value.source_ref,),'selector':None,
                'producer_header':None}
        self._next_v3();return False
    def _next_v3(self):
        if self.task is not None:self.task.column.release_retention_v3()
        if self.goal is not None:self.goal.release_retention_v3()
        self.task=self.goal=self.goal_header=self.value=None



class _RootRegistrationsV3:
    """The original Source-matched Root inventory; metadata EOF and no execution."""
    def __init__(self,state):
        self.state=state;self.after='';self.through=None;self.watermark=False;self.refs=[];self.matches=[];self.scope_matches=[]
        self.task=self.root=self.producer=None;self.complete=False
    def advance(self,meter):
        from .d11_life_preparation_v1 import TABLE
        from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
        s=self.state;r=s.reader
        if not self.watermark:
            row=meter.read_fixed_row(r.db,TABLE,('original_ref',),
                "bot=? AND persona=? AND kind='draft_root_capability' ORDER BY original_ref DESC LIMIT 1",r.namespace.as_tuple)
            self.through=None if row is None else row[0];self.watermark=True
            if row is None:self._finish_v3();return True
            return False
        if self.task is None:
            row=meter.read_fixed_row(r.db,TABLE,('original_ref',),
                "bot=? AND persona=? AND kind='draft_root_capability' AND original_ref>? AND original_ref<=? ORDER BY original_ref LIMIT 1",
                (*r.namespace.as_tuple,self.after,self.through))
            if row is None:self._finish_v3();return True
            self.after=row[0];self.task=_SignedControlV3(s,'draft_root_capability',self.after);return False
        if self.root is None:
            if not self.task.advance(meter):return False
            root=draft_from_wire_v1(self.task.value,DraftRootCapabilityV1)
            if(root.registration_ref!=self.after or NamespaceId.from_key(AtomKey.from_token(root.source_ref))!=r.namespace):
                raise AuthorityUnavailable('Actual Root metadata changed its namespace/ref')
            self.root=root
            self.producer=_ControlProducerV3(s,self.task.header[0],'d10',
                ('register_artifact_draft_root','derive_ingress_artifact_task_scope_v1'))
            return False
        if not self.producer.advance(meter):return False
        if self.producer.original.get('provenance',{}).get('draft_root_capability')!=self.task.value:
            raise AuthorityUnavailable('Source Root metadata lacks its actual signed setup W01 producer')
        if self.root.source_ref==r.selector.source_ref:
            scope=self.producer.original.get('provenance',{}).get('artifact_task_scope')
            if(scope is not None and scope.get('c02_operation_id')==r.selector.c02_operation_id
                    and scope.get('source_ref')==r.selector.source_ref and len(self.scope_matches)<2):
                self.scope_matches.append((self.root,self.task.value,self.task.header,
                    self.producer.original,self.producer.header,self.producer.read_versions,self.producer.receipt))
            self.refs.append(self.after)
            if len(self.matches)<2:self.matches.append((self.root,self.task.value,self.task.header,
                self.producer.original,self.producer.header,self.producer.read_versions,self.producer.receipt))
            if len(self.refs)>128:raise AuthorityUnavailable('Actual Source Root inventory exceeds its original 128-match bound')
        self.task.column.release_retention_v3()
        for column in self.producer.columns:column.release_retention_v3()
        self.task=self.root=self.producer=None;return False
    def _finish_v3(self):
        s=self.state;r=s.reader
        if(s.seed.root is None and s.seed.cycle is None and len(self.matches)==1
                and r.selector.entry_kind not in {'prepare_source_note_foreground_cycle_v1','prepare_selected_source_note_action_v2'}):
            root,raw,header,original,producer_header,reads,receipt=self.matches[0]
            from .domain_production_contracts_v1 import ProductionOwnerGuardV1
            from ..graph_types import owner_grant_key
            guard=ProductionOwnerGuardV1(owner_grant_key(*r.namespace.as_tuple).token,r.owner.grant_revision,
                r.owner.grant_digest.removeprefix('sha256:'),r.owner.authorization_head.removeprefix('sha256:'))
            if(root.owner_grant_ref,root.owner_grant_revision,root.owner_grant_digest)!=(
                    guard.grant_ref,guard.grant_revision,guard.grant_digest):
                raise AuthorityUnavailable('Actual selected Root metadata differs from current same-Work Owner')
            s.seed.root=root;s.seed.root_ref=root.registration_ref
            s.seed.original_business_deadline=min(s.seed.budget.grant.valid_until_utc,_utc_v3(root.valid_until_utc))
            s.eligibility_deadline=min(r.operation.deadline_utc,s.seed.original_business_deadline)
            s.purpose='consolidation'
            sources=tuple(v.key.token for v in reads if v.key.type_name=='memory.source')
            s.current_roots=tuple(dict.fromkeys((*s.current_roots,*sources)))
            s.semantic_locators.roots=list(s.current_roots)
            s.group_specs=[('control:'+str(i//32),s.current_roots[i:i+32],s.purpose,s.audiences)
                for i in range(0,len(s.current_roots),32)]
            s.verified_metadata_v3['graph_d11_life_originals_v1','draft_root_capability',root.registration_ref]={
                'projection':raw,'header':header,'payload_digest':header[1],'operation_id':header[0],
                'source_roots':s.current_roots,'selector':None,'producer_header':producer_header}
        s.eligibility_deadline=min(r.operation.deadline_utc,s.seed.original_business_deadline)
        self.complete=True

_CHOICE_ENTRIES_V3=frozenset({'read_current_post_c02_artifact_task_choice_material_v3',
    'prepare_current_post_c02_artifact_task_structure_v3','read_current_post_c02_artifact_method_prerequisites_v1',
    'run_current_post_c02_artifact_preparation_step_v1','begin_current_artifact_method_group_v3'})

def _start_choice_catalogue_v3(state):
    if state.profile not in {'entry_prepare','post_commit_read'} or state.reader.selector.entry_kind not in _CHOICE_ENTRIES_V3:
        return False
    if state.seed.root is None:return False
    from .artifact_task_choice_catalogue_metadata_v3 import ArtifactTaskChoiceCatalogueMetadataV3
    q=state.reader.selector
    state.task_catalogue=ArtifactTaskChoiceCatalogueMetadataV3(state.reader,
        root_ref=state.seed.root.registration_ref,c02_operation_id=q.c02_operation_id,source_ref=q.source_ref)
    state.phase='task_catalogue';return True

def _adopt_choice_catalogue_v3(state):
    value=state.task_catalogue.result_v3()
    state.current_roots=tuple(dict.fromkeys((*state.current_roots,*value.source_roots)))
    state.semantic_locators.roots=list(state.current_roots)
    special={ref for spec in state.special_source_groups_v3 for ref in spec[1]}
    ordinary=tuple(ref for ref in state.current_roots if ref not in special)
    state.group_specs=[('control:'+str(i//32),ordinary[i:i+32],state.purpose,state.audiences)
        for i in range(0,len(ordinary),32)]+state.special_source_groups_v3
    for item in value.originals:
        state.verified_metadata_v3[item['table'],item['kind'],item['ref']]={
            'projection':item['projection'],'header':item['header'],'payload_digest':item['payload_digest'],
            'operation_id':item['operation_id'],'source_roots':item['source_roots'],'selector':None,
            'producer_header':None,'read_versions':item['read_versions'],'write_versions':item['write_versions']}
        layout=item['producer_layout']
        if layout is not None and layout[0]=='graph_domain_production_originals_v3':
            header=item['producer_header']
            state.verified_metadata_v3[layout[0],header[1],item['operation_id']]={
                'projection':item['producer_original'],'header':header,'payload_digest':header[3],
                'operation_id':item['operation_id'],'source_roots':item['source_roots'],'selector':None,
                'producer_header':header,'read_versions':item['read_versions'],'write_versions':item['write_versions'],
                'physical_layout':layout}

class _PostCommitMetadataV3:
    """A real saved attempt receipt, its actual W01 and its original Source R."""
    def __init__(self,state):
        self.state=state;self.phase='attempt';self.header=self.column=self.producer=None
        self.receipt=None;self.complete=False
    def advance(self,meter):
        s=self.state;r=s.reader;q=r.selector;key=(*r.namespace.as_tuple,q.operation_id)
        if self.phase=='attempt':
            header=meter.read_fixed_row(r.db,'graph_owner_domain_attempts_v3',('request_digest',),
                'bot=? AND persona=? AND operation_id=?',key)
            if header!=(q.request_digest,):
                raise AuthorityUnavailable('Post-commit descriptor differs from actual foreground-selector attempt digest')
            self.header=tuple(header)
            self.column=_ControlColumnV3(s,'control_saved_receipt',table='graph_owner_domain_attempts_v3',column='receipt_json',
                key_columns=('bot','persona','operation_id'),key=key)
            self.phase='receipt';return False
        if self.phase=='receipt':
            current=meter.read_fixed_row(r.db,'graph_owner_domain_attempts_v3',('request_digest',),
                'bot=? AND persona=? AND operation_id=?',key)
            if current!=self.header:raise AuthorityUnavailable('Actual post-commit attempt changed during receipt EOF')
            if not self.column.advance(meter):return False
            value=self.column.require_v3(r)
            if(value.get('schema')!='sylanne.domain-production-receipt.v1'
                    or value.get('operation_id')!=q.operation_id or value.get('receipt_digest')!=q.receipt_digest):
                raise AuthorityUnavailable('Post-commit actual saved receipt wrapper differs from its exact descriptor')
            self.receipt=value
            from .domain_production_registry_v1 import installed_operation_v1
            operation=installed_operation_v1(q.operation_kind)
            self.producer=_ControlProducerV3(s,q.operation_id,operation.domain,(q.operation_kind,))
            self.phase='producer';return False
        if not self.producer.advance(meter):return False
        actual=self.producer.receipt;q=r.selector
        if(actual.operation_id!=q.operation_id or actual.status!='committed'
                or canonical_digest(actual)!=q.receipt_digest or actual.write_versions!=q.write_versions
                or self.receipt['original_digest']!=self.producer.header[3]):
            raise AuthorityUnavailable('Saved post-commit wrapper lost actual original committed W01/namespace/write set')
        if r.now>=q.business_deadline_utc:
            raise AuthorityUnavailable('Post-commit original business deadline expired')
        produced_root=self.producer.original.get('provenance',{}).get('draft_root_capability')
        actual_deadline=(_utc_v3(s.seed.cycle[7])if s.seed.cycle is not None else
            s.seed.root.valid_until_utc if s.seed.root is not None else
            produced_root['valid_until_utc']if produced_root is not None else s.seed.c02_original_deadline)
        if type(actual_deadline)is str:actual_deadline=_utc_v3(actual_deadline)
        if s.seed.cycle is not None or s.seed.root is not None:
            actual_deadline=min(actual_deadline,s.seed.original_business_deadline)
        if q.business_deadline_utc>min(actual_deadline,s.seed.budget.grant.valid_until_utc):
            raise AuthorityUnavailable('Post-commit descriptor extends original cycle/Root/grant deadline')
        s.seed.original_business_deadline=min(actual_deadline,s.seed.budget.grant.valid_until_utc,q.business_deadline_utc)
        s.eligibility_deadline=min(r.operation.deadline_utc,s.seed.original_business_deadline)
        roots=tuple(v.key.token for v in(*actual.read_versions,*actual.write_versions)if v.key.type_name=='memory.source')
        roots=tuple(dict.fromkeys((*s.current_roots,*roots)))
        s.current_roots=roots
        for v in actual.read_versions:
            if v.key.type_name=='memory.source':s.expected_source_versions_v3.setdefault(v.key,v.revision)
        for v in actual.write_versions:
            if v.key.type_name=='memory.source':s.expected_source_versions_v3[v.key]=v.revision
        authority=self.producer.original.get('authority')
        if type(authority)is not dict or authority.get('namespace')!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}:
            raise AuthorityUnavailable('Post-commit Original lacks its actual Source authority metadata')
        if authority.get('actor')!=r.current_self.self_entity_ref:
            raise AuthorityUnavailable('Post-commit Original belongs to another actual current Self')
        purpose=authority['purpose'];audiences=tuple(authority['audience'])
        if purpose not in r.owner.purposes or not set(audiences)<=set(r.owner.audiences):
            raise AuthorityUnavailable('Post-commit actual Original scope exceeds current Owner')
        s.purpose,s.audiences=purpose,audiences
        ordinary_roots=roots
        if q.stage=='completion_source':
            from .artifact_completion_receipt_v1 import receipt_from_wire_v1,OPERATION
            if q.operation_kind!=OPERATION:
                raise AuthorityUnavailable('Completion Source post stage requires its exact actual D06 producer')
            receipt=receipt_from_wire_v1(self.producer.original['provenance']['artifact_completion_receipt'])
            writes=tuple(v for v in actual.write_versions if v.key.token==receipt.source_ref)
            if(receipt.namespace!=r.namespace or receipt.producer_operation_id!=q.operation_id
                    or len(writes)!=1 or writes[0].revision<1 or q.business_deadline_utc>receipt.original_deadline_utc):
                raise AuthorityUnavailable('Completion Source lacks its exact actual D06 W01 member/deadline')
            s.special_source_groups_v3=[('completion_expression',(receipt.source_ref,),'expression',(s.seed.identity[2],))]
            ordinary_roots=tuple(ref for ref in roots if ref!=receipt.source_ref)
        s.group_specs=[('post_commit:'+str(i//32),ordinary_roots[i:i+32],purpose,audiences)
            for i in range(0,len(ordinary_roots),32)]+s.special_source_groups_v3
        s.semantic_locators.roots=list(roots)
        cp=self.producer
        s.verified_metadata_v3['graph_domain_production_originals_v1',q.operation_kind,q.operation_id]={
            'projection':cp.original,'header':cp.header,'payload_digest':cp.header[3],
            'operation_id':q.operation_id,'source_roots':roots,'selector':None,'producer_header':cp.header,
            'read_versions':cp.read_versions,'write_versions':cp.receipt.write_versions,'physical_layout':cp.layout}
        self.complete=True;return True


class _ExistingCompletionV3:
    def __init__(self,state,selector):
        from .artifact_completion_receipt_v1 import receipt_ids_v1
        self.state,self.selector=state,selector;self.ids=receipt_ids_v1(selector)
        self.producer=None;self.complete=False;self.absent=False
    def advance(self,meter):
        from .artifact_completion_receipt_v1 import OPERATION,receipt_from_wire_v1
        s=self.state;r=s.reader
        if self.producer is None:
            row=meter.read_fixed_row(r.db,'graph_domain_production_originals_v1',('operation_kind',),
                'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,self.ids['producer']))
            if row is None:self.absent=self.complete=True;return True
            if row!=(OPERATION,):raise AuthorityUnavailable('Actual completion locator belongs to another operation')
            self.producer=_ControlProducerV3(s,self.ids['producer'],'d06',(OPERATION,));return False
        if not self.producer.advance(meter):return False
        cp=self.producer
        value=receipt_from_wire_v1(cp.original['provenance']['artifact_completion_receipt'])
        writes=tuple(v for v in cp.receipt.write_versions if v.key.token==value.source_ref)
        policy=r.bundle.installation_policy
        if(value.selector!=self.selector or value.producer_operation_id!=self.ids['producer']
                or(value.installation_id,value.manifest_digest)!=(policy.installation_id,policy.manifest_digest)
                or len(writes)!=1 or writes[0].revision!=1
                or value.owner_guard!=s.seed.expected_owner_guard or r.now>=value.original_deadline_utc):
            raise AuthorityUnavailable('Existing completion lost actual selector/W01 Source/current Owner/deadline')
        roots=tuple(dict.fromkeys((*s.current_roots,value.source_ref,
            *(v.key.token for v in cp.read_versions if v.key.type_name=='memory.source'))))
        s.current_roots=roots;s.semantic_locators.roots=list(roots)
        s.expected_source_versions_v3[writes[0].key]=writes[0].revision
        s.special_source_groups_v3=[('completion_expression',(value.source_ref,),'expression',(s.seed.identity[2],))]
        ordinary=tuple(ref for ref in roots if ref!=value.source_ref)
        s.group_specs=[('control:'+str(i//32),ordinary[i:i+32],s.purpose,s.audiences)
            for i in range(0,len(ordinary),32)]+s.special_source_groups_v3
        s.verified_metadata_v3['graph_domain_production_originals_v1',OPERATION,cp.operation]={
            'projection':cp.original,'header':cp.header,'payload_digest':cp.header[3],'operation_id':cp.operation,
            'source_roots':roots,'selector':value.selector,'producer_header':cp.header,
            'read_versions':cp.read_versions,'write_versions':cp.receipt.write_versions,'physical_layout':cp.layout}
        self.complete=True;return True


class _EntryNaturalDeadlineV3:
    def __init__(self,state):
        from .foreground_cycle_v1 import foreground_post_c02_cause_ref_v1
        self.state=state;self.complete=False
        self.task=_SignedControlV3(state,'foreground_post_c02_cause',
            foreground_post_c02_cause_ref_v1(state.reader.namespace,state.reader.selector.c02_operation_id))
    def advance(self,meter):
        if not self.task.advance(meter):return False
        from .foreground_cycle_v1 import ForegroundPostC02CauseV1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        s=self.state;r=s.reader;seed=s.seed;q=r.selector;p=r.bundle.installation_policy
        cause=decode_typed_production_value_v1(self.task.value,ForegroundPostC02CauseV1)
        policy=r.bundle.foreground.deadline_policy.natural
        if(policy is None or(cause.namespace,cause.installation_id,cause.manifest_digest,cause.c02_operation_id,
                cause.source_ref,cause.commit_seq,self.task.header[0])!=(
                    r.namespace,p.installation_id,p.manifest_digest,q.c02_operation_id,q.source_ref,
                    seed.business[3],q.c02_operation_id)):
            raise AuthorityUnavailable('Initial control natural cause lost its actual C02/Source/install binding')
        seed.original_business_deadline=min(seed.budget.grant.valid_until_utc,cause.cause_frozen_at_utc+policy.window_seconds)
        s.eligibility_deadline=min(r.operation.deadline_utc,seed.original_business_deadline)
        s.verified_metadata_v3['graph_d11_life_originals_v1',self.task.kind,self.task.ref]={
            'projection':self.task.value,'header':self.task.header,'payload_digest':self.task.header[1],
            'operation_id':self.task.header[0],'source_roots':s.current_roots,'selector':None,'producer_header':None}
        self.complete=True;return True



class _ControlResultV3:
    def __init__(self,state):
        r=state.reader
        if state.phase!='complete'or not r.complete or not r.sealed:
            raise AuthorityUnavailable('Artifact control result requires its actual completed READ')
        self.reader=r;self.value=state.result;_TERMINALS[self]=(r,r.work,r.selection_digest)
    def require_result_v3(self,work):
        r=self.reader
        if(_TERMINALS.get(self)!=(r,work,r.selection_digest)or not r.read_finished
                or work.state is not r or not work._finish_called or r.operation.closed):
            raise AuthorityUnavailable('Artifact control result lost its finalized retained READ Work')
        work._require_invocation(r.graph);return self.value
    def release_payload_v3(self):
        saved=_TERMINALS.pop(self,None)
        if saved is not None:
            try:saved[0].release_payload_v3()
            finally:self.reader=self.value=None

def advance_artifact_host_control_v3(graph,work):
    r=work.state;s=control_state_for_dispatch_v3(r)
    if s is None or graph is not r.graph or work is not r.work:
        raise AuthorityUnavailable('Artifact control continuation belongs to another actual Work')
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        r.now=common._observe_v3(r)
        if s.phase=='owner':
            _prepare_owner_v3(s);return GraphStorageStepV3('progress')
        if s.phase=='source_scopes':
            _open_source_scopes_v3(s);return GraphStorageStepV3('progress')
        complete=False
        with r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
            if r.db.in_transaction:raise AuthorityUnavailable('Artifact control cannot retain SQL across quanta')
            s.require_current_v3(meter)
            if s.phase=='algorithm'and r.pending is None and s.discovery is None:
                try:
                    from .artifact_host_control_algorithms_v3 import(
                        read_artifact_foreground_selector_v3,read_artifact_phase_resume_v3,
                        read_artifact_entry_prepare_v3,read_artifact_post_commit_v3)
                    algorithm={'foreground_selector':read_artifact_foreground_selector_v3,
                        'phase_resume':read_artifact_phase_resume_v3,'entry_prepare':read_artifact_entry_prepare_v3,
                        'post_commit_read':read_artifact_post_commit_v3}[s.profile]
                    with bind_background_reads_v3(r,db=r.db):s.result=algorithm(r,s)
                    s.validation_points=iter(r.points.values());s.phase='validate'
                except BackgroundReadNeededV3 as needed:_start_control_request_v3(r,needed.request)
            else:
                r.db.execute('BEGIN')
                try:
                    if r.pending is not None:_advance_control_pending_v3(r,meter)
                    elif s.phase=='metadata':
                        if s.discovery is None:s.seed.advance(meter)
                        else:s.discovery.advance(meter)
                    elif s.phase=='root_registrations':
                        if s.root_registrations.advance(meter):
                            if(s.seed.root is None and r.selector.entry_kind=='prepare_post_c02_foreground_cycle_v1'
                                    and r.bundle.foreground.deadline_policy.natural is not None):
                                s.eligibility_deadline=min(r.operation.deadline_utc,s.seed.budget.grant.valid_until_utc)
                                s.entry_natural_deadline=_EntryNaturalDeadlineV3(s);s.phase='entry_natural_deadline'
                            elif not _start_choice_catalogue_v3(s):
                                s.phase='locators'if not s.semantic_locators.complete else'source_scopes'
                    elif s.phase=='entry_natural_deadline':
                        if s.entry_natural_deadline.advance(meter):
                            s.phase='locators'if not s.semantic_locators.complete else'source_scopes'
                    elif s.phase=='post_commit_metadata':
                        if s.post_commit_metadata.advance(meter)and not _start_choice_catalogue_v3(s):s.phase='locators'if not s.semantic_locators.complete else'source_scopes'
                    elif s.phase=='completed_stage_metadata':
                        if s.completed_stage_metadata_v3.advance(meter):s.phase='source_scopes'
                    elif s.phase=='draft_metadata':
                        if s.draft_metadata.advance(meter):s.phase='source_scopes'
                    elif s.phase=='completion_metadata':
                        if s.existing_completion.advance(meter):s.phase='source_scopes'
                    elif s.phase=='task_catalogue':
                        if s.task_catalogue.advance(meter):
                            _adopt_choice_catalogue_v3(s)
                            s.phase='locators'if not s.semantic_locators.complete else'source_scopes'
                    elif s.phase=='objectives':
                        if s.objective_metadata.advance(meter):
                            s.current_roots=tuple(dict.fromkeys((*s.current_roots,*s.objective_metadata.roots)))
                            s.semantic_locators.roots=list(s.current_roots)
                            s.group_specs=[('control:'+str(i//32),s.current_roots[i:i+32],s.purpose,s.audiences)
                                for i in range(0,len(s.current_roots),32)]
                            s.phase='locators'if not s.semantic_locators.complete else'source_scopes'
                    elif s.phase=='locators':
                        if s.semantic_locators.advance(meter):s.phase='source_scopes'
                    elif s.phase=='ingress_recall_metadata':
                        if s.ingress_recall_metadata.advance(meter):s.phase='source_scopes'
                    elif s.phase=='sources':_advance_sources_v3(s,meter)
                    elif s.phase=='algorithm':
                        s.validation_points=iter(r.points.values());s.phase='validate'
                    elif s.phase=='validate':
                        if s.validation_point is None:s.validation_point=next(s.validation_points,None)
                        if s.validation_point is None:complete=True
                        else:
                            p=s.validation_point
                            if not p.complete or any(c is not None and not c.complete for c in p.values.values()):
                                raise AuthorityUnavailable('Artifact control point lacks actual complete canonical EOF')
                            require_artifact_control_request_v3(r,p.request);p.require_row_v3(meter);s.validation_point=None
                    else:raise AuthorityUnavailable('Artifact control has no registered next phase')
                    s.require_current_v3(meter);r.reserve_heap_v3()
                finally:r.db.rollback()
        if complete:
            r.now=common._observe_v3(r)
            with r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
                s.require_current_v3(meter);s.owner_entry.require_for_v3(r);_require_sources_current_v3(s,meter)
                if s.discovery is not None:s.result=s.discovery.result_v3(meter)
            s.phase='complete';r.complete=r.sealed=True;r.phase='artifact_control_complete'
            r.result=_ControlResultV3(s)
            return GraphStorageStepV3('complete',r.result)
    return GraphStorageStepV3('progress')

def finish_artifact_host_control_v3(graph,work,error):
    r=work.state;s=_STATES.get(r)
    if s is None or graph is not r.graph or work is not r.work:
        raise AuthorityUnavailable('Artifact control finalization lost its exact Work')
    try:
        with bind_runtime_storage_operation_v3(r.operation,r.db):
            common._close_artifact_host_dispatch_scopes_v3(r,s);r.read_finished=True
        if error is None:work.result_lease=work.operation
    except BaseException:
        r.release_payload_v3();finish_runtime_storage_operation_v3(r.operation);raise
    if error is not None:r.release_payload_v3();finish_runtime_storage_operation_v3(r.operation)

def release_artifact_host_control_payload_v3(r):
    s=_STATES.pop(r,None)
    if s is None:return False
    if s.ingress_recall_metadata is not None:s.ingress_recall_metadata.close_v3()
    s.ingress_recall_metadata=None
    terminal=r.result
    if type(terminal)is _ControlResultV3:
        _TERMINALS.pop(terminal,None);terminal.reader=terminal.value=None
    if s.task_catalogue is not None:s.task_catalogue.close_v3()
    if s.draft_metadata is not None:s.draft_metadata.close_v3()
    for column in tuple(s.control_columns_v3):column.release_retention_v3()
    s.control_columns_v3.clear()
    for group in s.groups:common._SCOPES.pop(group,None)
    s.groups.clear();s.group_specs.clear();s.special_source_groups_v3.clear();s.source_versions.clear();s.expected_source_versions_v3.clear();s.root_source_metadata.clear()
    s.metadata_headers.clear();s.attachments.clear();s.source_requests.clear()
    s.verified_metadata_v3.clear();s.derived_refs_v3.clear();s.semantic_locators=None
    s.recipe_originals_v3.clear();s.recipe_quotes_v3.clear();s.recipe_metadata_tasks_v3.clear()
    s.discovery=s.seed=s.semantic_locators=s.objective_metadata=s.root_registrations=s.post_commit_metadata=s.task_catalogue=s.existing_completion=s.entry_natural_deadline=s.draft_metadata=None
    s.completed_stage_metadata_v3=None
    s.result=s.metadata_result=s.validation_points=s.validation_point=None
    r.operation.unregister_retained_state_v3(s)
    return True

def require_artifact_control_body_v3(r,table,key):
    s=control_state_for_dispatch_v3(r)
    if s is None:return None
    if s.profile=='discovery'or not s.source_complete or s.phase not in {'algorithm','validate'}or s.owner_entry is None:
        raise AuthorityUnavailable('Artifact control Body cannot precede actual Owner/Self/ALL Source closure')
    if not any(t==table and actual==tuple(key)for(t,keys,actual,column)in s.attachments):
        raise AuthorityUnavailable('Artifact control Body lacks its exact qualified attachment recipe')
    with runtime_storage_quantum_v3(r.db)as meter:
        s.require_current_v3(meter);s.owner_entry.require_for_v3(r)
        _require_sources_current_v3(s,meter)
    return s

def _require_sources_current_v3(state,meter):
    r=state.reader
    if state.seed is not None:
        budget=state.seed.budget
        header=meter.read_fixed_row(r.db,'runtime_budget_grants',('lease_id','version','signature','status'),
            'lease_id=? ORDER BY version DESC',(budget.lease,))
        lease=meter.read_fixed_row(r.db,'runtime_budget_leases',('bot_id','persona_id','currency','state'),
            'lease_id=?',(budget.lease,))
        if header!=budget.header or lease!=(*r.namespace.as_tuple,budget.grant.currency,'active'):
            raise AuthorityUnavailable('Artifact control original Root/grant changed before disclosure')
        if r.now>=state.seed.business_deadline_v3():
            raise AuthorityUnavailable('Artifact control original business deadline expired before disclosure')
    for key,revision in state.source_versions.items():
        row=meter.read_fixed_row(r.db,'graph_atoms',('revision',),'token=? AND bot=? AND persona=?',
            (key.token,*r.namespace.as_tuple))
        if(0 if row is None else row[0])!=revision:
            raise AuthorityUnavailable('Artifact control Source/Access/ancestor/correction changed before disclosure')

_FAMILIES=frozenset({'graph_head','graph_history','signed_original','domain_original','job_metadata','budget_original'})

def _register_qualified_attachment_v3(state,table,key_columns,key,column,*,family):
    r=state.reader;control_state_for_dispatch_v3(r)
    if state.profile=='discovery'or not state.source_complete or state.phase not in {'algorithm','validate'}:
        raise AuthorityUnavailable('Artifact attachment cannot be registered before actual qualified control READ')
    if family not in _FAMILIES:raise AuthorityUnavailable('Artifact control has no such fixed attachment family')
    from .artifact_host_control_recipes_v3 import artifact_control_attachment_recipe_v3
    roots=artifact_control_attachment_recipe_v3(state,table,tuple(key_columns),tuple(key),column,family)
    if not roots or any(AtomKey.from_token(ref)not in state.source_versions for ref in roots):
        raise AuthorityUnavailable('Artifact attachment lacks actual same-Work qualified recipe roots')
    state.attachments[table,tuple(key_columns),tuple(key),column]=(family,tuple(roots))
    return None

def require_artifact_control_request_v3(r,request):
    s=control_state_for_dispatch_v3(r)
    if s is None:return False
    table,columns,keys,key=request;keys,key,columns=tuple(keys),tuple(key),tuple(columns)
    if not s.source_complete or s.profile=='discovery':
        raise AuthorityUnavailable('Artifact discovery/initial metadata cannot issue Body point requests')
    from .artifact_host_control_recipes_v3 import artifact_control_point_recipe_v3
    recipe=artifact_control_point_recipe_v3(s,table,columns,keys,key)
    if recipe is None:raise AuthorityUnavailable('Artifact control requested no exact fixed point recipe')
    # The fixed algorithm determines actual lineage; registration never widens
    # Source scope, Owner permission, Root budget or the originating deadline.
    for column,family in recipe:
        _register_qualified_attachment_v3(s,table,keys,key,column,family=family)
    for column in columns:
        if(table,keys,key,column)not in s.attachments:
            raise AuthorityUnavailable('Artifact control point column lacks its exact registered recipe')
    return True

def _start_control_request_v3(r,request):
    if request[0]=='artifact_control_recipe_metadata':
        from .artifact_host_control_recipes_v3 import ArtifactControlRecipeMetadataTaskV3
        s=control_state_for_dispatch_v3(r);table,kind,ref=request[1:]
        task=s.recipe_metadata_tasks_v3.get((table,kind,ref))
        if task is None:
            task=ArtifactControlRecipeMetadataTaskV3(s,table,kind,ref);s.recipe_metadata_tasks_v3[table,kind,ref]=task
        r.pending=task;return
    if request[0]=='artifact_control_signed':
        s=control_state_for_dispatch_v3(r);kind,ref,profile=request[1:]
        task=s.source_requests.get((kind,ref,profile))
        if task is None:
            task=_StatusControlV3(s,kind,ref,profile);s.source_requests[kind,ref,profile]=task
        r.pending=task;return
    return _start_background_request_v3(r,request)

class _StatusControlV3(_SignedControlV3):
    def __init__(self,state,kind,ref,profile):
        if profile not in {'control_target_mode','control_phase_status'}:
            raise AuthorityUnavailable('Artifact control signed metadata profile is not registered')
        from .artifact_host_control_recipes_v3 import artifact_control_signed_recipe_v3
        artifact_control_signed_recipe_v3(state,kind,ref,profile)
        super().__init__(state,kind,ref,profile);self.absent=False
    def advance(self,meter):
        from .d11_life_preparation_v1 import TABLE
        if self.header is None:
            r=self.state.reader
            row=meter.read_fixed_row(r.db,TABLE,('producing_operation_id','payload_digest','signature'),
                'bot=? AND persona=? AND kind=? AND original_ref=?',(*r.namespace.as_tuple,self.kind,self.ref))
            if row is None:self.absent=True;self.complete=True;return True
        if not super().advance(meter):return False
        self.complete=False
        r=self.state.reader
        producer=meter.read_fixed_row(r.db,'graph_bundle_operations',('commit_seq',),
            'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,self.header[0]))
        if producer is None or type(producer[0])is not int or producer[0]<1:
            raise AuthorityUnavailable('Artifact status signature lacks its actual positive W01 producer')
        self.state.metadata_headers.append(('signed',self.kind,self.ref,self.header))
        self.state.verified_metadata_v3['graph_d11_life_originals_v1',self.kind,self.ref]={
            'projection':self.value,'header':self.header,'payload_digest':self.header[1],
            'operation_id':self.header[0],'source_roots':self.state.current_roots,'selector':None,
            'producer_header':tuple(producer)}
        self.complete=True;return True

def control_metadata_column_retains_v3(column,path):
    s=_STATES.get(column.owner)
    if s is None:return None
    # Body attachments are complete originals. Only explicit signed metadata
    # tasks use the narrow projection parser; a projection is never this column.
    if not s.source_complete:raise AuthorityUnavailable('Artifact control cannot retain Body before Source closure')
    identity=(column.table,column.key_columns,column.key,column.column)
    if identity not in s.attachments:raise AuthorityUnavailable('Artifact column lacks exact qualified registration')
    return True

def read_artifact_control_job_v3(db,job_id):
    from .domain_background_read_v3 import _active_v3,background_json_loads_v3
    r=_active_v3(db);s=None if r is None else _STATES.get(r)
    if s is None:return False,None
    from .jobs import _job_from_row
    from .d11_types import job_graph_write
    columns=('job_id','operation_id','activity_id','effect_id','bot_id','persona_id','snapshot_ref','phase','work_kind',
        'continuation_json','wake_condition_json','deadline_utc','budget_ref','resource_ref','operator_versions_json',
        'lease_holder','lease_expires_utc','fence','cancel_epoch','usage_json','result_ref')
    row=s.control_point_v3('runtime_jobs',columns,('job_id',),(job_id,))
    job=_job_from_row(row)
    if(job.bot_id,job.persona_id)!=r.namespace.as_tuple:
        raise AuthorityUnavailable('Artifact control job crossed its exact namespace')
    expected=job_graph_write(job)
    head=s.control_point_v3('graph_atoms',('revision','value','valid'),('token','bot','persona'),
        (expected.key.token,*r.namespace.as_tuple))
    if head is None or head[2]!=1 or background_json_loads_v3(head[1])!=expected.value:
        raise AuthorityUnavailable('Artifact control SQL job lost its actual current Graph mirror')
    return True,job

def read_artifact_control_quote_v3(db,issuer,quote_id,version):
    from .domain_background_read_v3 import _active_v3,background_verify_signature_v3
    r=_active_v3(db);s=None if r is None else _STATES.get(r)
    if s is None:return False,None
    if issuer is not r.graph._GraphCoordinator__d11_issuer.resource_issuer:
        raise AuthorityUnavailable('Artifact control quote crossed its actual installed signer')
    row=s.control_point_v3('runtime_resource_quotes',('quote_json','signature'),
        ('quote_id','version'),(quote_id,version))
    if row is None:raise AuthorityUnavailable('Artifact control actual signed resource quote is absent')
    background_verify_signature_v3(issuer._signer,'resource-quote.v1',row[0],row[1])
    from .issuers import _decode_quote
    quote=_decode_quote(row[0])
    if(quote.quote_id,quote.version)!=(quote_id,version):raise AuthorityUnavailable('Artifact control quote identity differs')
    return True,quote

def require_artifact_control_family_v3(r,type_id):
    if _STATES.get(r)is None:return False
    raise AuthorityUnavailable('Artifact control has no general Body inventory profile')

def require_artifact_control_rows_v3(r,request):
    if _STATES.get(r)is None:return False
    raise AuthorityUnavailable('Artifact control has no general SQL rows profile')

def _advance_control_pending_v3(reader,meter):
    task=reader.pending
    if task is None:return
    dependency=getattr(task,'dependency',None)
    if dependency is not None:
        reader.pending=dependency
        try:_advance_control_pending_v3(reader,meter)
        finally:reader.pending=task
        if dependency.complete:task.dependency=None
        return
    if not task.complete:
        try:task.advance(meter)
        except BackgroundReadNeededV3 as needed:
            _start_control_request_v3(reader,needed.request)
            task.dependency=reader.pending;reader.pending=task
            return
    if task.complete:reader.pending=None


def _history_disclosure_only_v3(state):
    if state.profile in {'post_commit_read','phase_resume'}:return True
    return(state.profile=='entry_prepare'and state.reader.selector.entry_kind in {
        '_read_post_c02_foreground_cycle_v1','read_current_post_c02_foreground_mode_v1',
        'read_current_post_c02_artifact_draft_resume_v1','read_current_artifact_phase_observation_progress_v3',
        'read_current_artifact_method_finalization_progress_v2','read_current_completed_artifact_method_v2',
        'read_current_ingress_recall_resume_v1'})


class _CompletedStageMetadataV3:
    def __init__(self,state):
        self.state=state;self.index=0;self.producer=None;self.records=[];self.complete=False
    def advance(self,meter):
        s=self.state;r=s.reader;q=r.selector
        if self.index==len(q.completed_receipts):self.complete=True;return True
        operation,digest=q.completed_receipts[self.index]
        allowed={'derive_ingress_artifact_task_scope_v1','create_artifact_task_plan_v1','create_artifact_task_project_v1',
            'initialize_artifact_task_project_checkpoint_v1','revise_artifact_task_plan_v2',
            'await_existing_artifact_revision_v1','select_existing_artifact_continuation_v1',
            'prepare_artifact_draft_project_context','wake_artifact_draft_cycle_v1','wake_artifact_draft_cycle_v2'}
        if self.producer is None:
            from .domain_production_registry_v1 import installed_operation_v1
            row=meter.read_fixed_row(r.db,'graph_domain_production_originals_v1',('domain','operation_kind'),
                'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,operation))
            if row is None or row[1]not in allowed or installed_operation_v1(row[1]).domain!=row[0]:
                raise AuthorityUnavailable('Artifact predecessor is not an actual fixed continuation command')
            self.producer=_ControlProducerV3(s,operation,row[0],(row[1],));return False
        if not self.producer.advance(meter):return False
        value=self.producer;receipt=value.receipt
        roots=tuple(v.key.token for v in receipt.read_versions if v.key.type_name=='memory.source')
        if receipt.operation_id!=operation or canonical_digest(receipt)!=digest or q.source_ref not in roots:
            raise AuthorityUnavailable('Artifact predecessor lost actual same-Source immutable receipt/W01')
        self.records.append(value);self.producer=None;self.index+=1
        s.current_roots=tuple(dict.fromkeys((*s.current_roots,*roots)))
        special={ref for spec in s.special_source_groups_v3 for ref in spec[1]}
        ordinary=tuple(ref for ref in s.current_roots if ref not in special)
        s.group_specs=[('control:'+str(i//32),ordinary[i:i+32],s.purpose,s.audiences)
            for i in range(0,len(ordinary),32)]+s.special_source_groups_v3
        return False
