"""Private metadata-only signed D08/D10 inputs of actual Artifact Host READ.

The owning dispatch profile admits every exact parent reference and Source
version. This helper shares raw canonical/HMAC mechanics with Background;
its projection is never a complete typed Body or an equality witness.
"""
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId
from .domain_background_read_v3 import BackgroundJSONColumnV3,_ISSUER,_SIGNED_INPUT_KINDS

_KEY=object()
_TASKS=WeakKeyDictionary()
_PROFILES=WeakKeyDictionary()
_D10='graph_d10_production_inputs_v1'
_INTENT='graph_d08_joint_plan_intents_v1'
_CONSENT='graph_d08_party_consents_v1'
_NODE='graph_d08_joint_node_originals_v1'
_TABLES=frozenset({_D10,_INTENT,_CONSENT,_NODE})
_INDEX_FIELDS=frozenset({'schema','namespace','source_refs','selector_kind','selector_key','binding_ref','binding_digest','registration_request_digest'})
_BINDING_FIELDS=frozenset({'schema','namespace','source_refs','node_id','plan_ref','plan_revision','owner_ref','action_kind',
    'action_ref','action_revision','action_digest','action_schema_ref','action_schema_revision','action_schema_digest',
    'project_ref','recipe_ref','goal_ref','goal_id','target_ref','target_entity_ref','role_ref','progress_ref','executor',
    'objective_ref','objective_digest','task_scope_ref','task_scope_digest','prospective_original_ref','prospective_original_digest',
    'parent_budget_lease_ref','parent_grant_id','parent_grant_version','parent_grant_digest','original_deadline_utc','purpose','audience'})
_EXECUTOR_FIELDS=frozenset({'schema','c02_operation_id','root_registration_ref','phase_selector','authorization_original_ref',
    'prepare_source_note_operation_id','prepare_source_note_request_digest','prepare_contact_operation_id','qualified_outbox_dedupe_key',
    'prospective_original_ref','prospective_original_digest','contact_id','registration_operation_id','source_ref'})
_PHASE_FIELDS=frozenset({'schema','task','decision_ref','decision_revision','decision_digest','plan_ref','plan_revision','plan_digest',
    'method_ref','phase_index','phase_kind','prev_phase_original_ref','prev_phase_original_digest'})
_TASK_FIELDS=frozenset({'schema','namespace','c02_operation_id','cycle_job_ref','root_registration_ref'})
_QUALIFICATION_FIELDS=frozenset({'schema','namespace','source_refs','plan_ref','plan_revision','plan_digest','terms_digest',
    'result_versions_digest','nodes','read_versions','producing_operation_id'})
_INTENT_FIELDS=frozenset({'plan_id','revision','source_refs','current_goal_refs','nodes'})
_NODE_LOCATORS=frozenset({'node_id','owner_ref','depends_on'})
_CONSENT_FIELDS=frozenset({'plan_proposal_ref','participant_ref','plan_revision','terms_digest','accepted_scope',
    'acceptance_interpretation_ref','inbound_source_ref','outbound_receipt_refs'})
_EXTERNAL_FIELDS=frozenset({'schema','namespace','source_refs','node_id','party_ref','contract_ref','contract_digest',
    'plan_ref','plan_revision','terms_digest','party_consent_ref','party_consent_digest','inbound_source','source_digest',
    'interpretation','interpretation_digest','actor_heads','observed_at_utc','original_deadline_utc','purpose','audience',
    'producing_operation_id','qualification'})
_BINDING_KINDS=frozenset({'joint_node_execution_binding_v1','joint_artifact_prospective_binding_v1','joint_contact_prospective_binding_v1'})

@dataclass(frozen=True,slots=True)
class ArtifactHostSignedInputHeaderV3:
    table:str
    original_ref:str
    kind:str
    producing_operation_id:str
    payload_digest:str
    signature:str
    indexed_locators:tuple[tuple[str,str],...]=()


def _owner(reader,table,ref):
    if table not in _TABLES:raise AuthorityUnavailable('Artifact signed metadata has no fixed table profile')
    from .artifact_host_dispatch_source_v3 import require_artifact_host_signed_input_metadata_owner_v3
    state=require_artifact_host_signed_input_metadata_owner_v3(reader,table,ref)
    from .issuers import D11BudgetJobIssuer
    if state.reader is not reader or type(reader.context.issuer)is not D11BudgetJobIssuer:
        raise AuthorityUnavailable('Artifact signed metadata changed actual installed issuer/reader')
    allowed=state.allowed_inputs[table,ref]
    if type(allowed)is not frozenset or not allowed:raise AuthorityUnavailable('Artifact signed metadata lacks a fixed allowed-kind set')
    return state


def _identity(state,table,ref):
    r=state.reader
    return(state,r,r.work,r.db,r.operation,r.read_scope,r.fence,r.selection_digest,r.graph_stamp,
        state.allowed_inputs[table,ref],state.input_digests.get((table,ref)),
        tuple(sorted(state.source_versions.items(),key=lambda item:item[0].token)),
        tuple(state.business_versions),tuple(state.control_versions),r.context.issuer)


def _fixed_path(field,path,*,arrays=(),versions=(),version_arrays=()):
    if len(path)==1:return True
    if field=='namespace':return len(path)==2 and path[1]in{'bot_id','persona_id'}
    if field in arrays:return len(path)==2 and type(path[1])is int
    if field in versions:return len(path)==2 and path[1]in{'key','revision'}
    if field in version_arrays:return len(path)==2 and type(path[1])is int or len(path)==3 and type(path[1])is int and path[2]in{'key','revision'}
    return False


def _retains(task,path):
    if not path:return True
    header=task._header;table=task.table;field=path[0]
    if table==_D10:
        if header.kind=='joint_executor_index_v1':
            return field in _INDEX_FIELDS and _fixed_path(field,path,arrays={'source_refs','selector_key'})
        if header.kind=='joint_plan_qualification_v1':
            if field not in _QUALIFICATION_FIELDS:return False
            if field=='nodes':
                if len(path)<3:return True
                if path[2]not in{'node_id','binding_ref','binding_digest','state','proof_ref','missing_originals'}:return False
                return len(path)==3 or path[2]=='missing_originals'and len(path)==4 and type(path[3])is int
            return _fixed_path(field,path,arrays={'source_refs'},version_arrays={'read_versions'})
        if header.kind not in _BINDING_KINDS:raise AuthorityUnavailable('Artifact signed input has no fixed binding/index metadata codec')
        if field not in _BINDING_FIELDS:return False
        if field!='executor':return _fixed_path(field,path,arrays={'source_refs','audience'})
        if len(path)==1:return True
        if path[1]not in _EXECUTOR_FIELDS:return False
        if path[1]!='phase_selector':return len(path)==2
        if len(path)<3:return True
        if path[2]not in _PHASE_FIELDS:return False
        if path[2]!='task':return len(path)==3
        if len(path)<4:return True
        if path[3]not in _TASK_FIELDS:return False
        return len(path)==4 or path[3]=='namespace'and len(path)==5 and path[4]in{'bot_id','persona_id'}
    if table==_INTENT:
        if field not in _INTENT_FIELDS:return False
        if field!='nodes':return _fixed_path(field,path,arrays={'source_refs','current_goal_refs'})
        if len(path)<3:return True
        if path[2]not in _NODE_LOCATORS:return False
        return len(path)==3 or path[2]=='depends_on'and len(path)==4 and type(path[3])is int
    if table==_CONSENT:
        return field in _CONSENT_FIELDS and _fixed_path(field,path,arrays={'accepted_scope','outbound_receipt_refs'})
    if header.kind not in {'external_node_contract_v1','external_node_observation_v1'}:
        raise AuthorityUnavailable('Artifact D08 input has no actual external-node metadata codec')
    return field in _EXTERNAL_FIELDS and _fixed_path(field,path,arrays={'source_refs','audience'},
        versions={'inbound_source','interpretation'},version_arrays={'actor_heads'})


class _ArtifactHostSignedInputMetadataTaskV3:
    def __init__(self,key,reader,table,ref):
        if key is not _KEY:raise TypeError('Actual Artifact Host metadata task factory required')
        state=_owner(reader,table,ref)
        self.reader,self.table,self.ref=reader,table,ref
        self.binding=_identity(state,table,ref);self.column=None;self._header=None;self.row=None
        self.complete=False;self.closed=False;self.absent=False
        _TASKS[self]=self.binding
    def _actual(self):
        if self.closed:raise AuthorityUnavailable('Artifact signed metadata task was released')
        state=_owner(self.reader,self.table,self.ref)
        if _TASKS.get(self)!=self.binding or _identity(state,self.table,self.ref)!=self.binding:
            raise AuthorityUnavailable('Artifact signed metadata lost actual Work/Scope/Source EOF identity')
        return state
    def _read_header(self,meter):
        r=self.reader
        columns=('producing_operation_id','payload_digest','signature')
        if self.table in {_D10,_NODE}:columns=('kind',*columns)
        if self.table==_CONSENT:columns=(*columns,'plan_proposal_ref','participant_ref','terms_digest')
        row=meter.read_fixed_row(r.db,self.table,columns,'bot=? AND persona=? AND original_ref=?',(*r.namespace.as_tuple,self.ref))
        if row is None:return None,None
        if self.table in {_D10,_NODE}:kind,producer,digest,signature=row[:4];indexed=()
        else:
            producer,digest,signature=row[:3];kind=_SIGNED_INPUT_KINDS[self.table]
            indexed=tuple(zip(('plan_proposal_ref','participant_ref','terms_digest'),row[3:]))if self.table==_CONSENT else()
        return tuple(row),ArtifactHostSignedInputHeaderV3(self.table,self.ref,kind,producer,digest,signature,indexed)
    def advance(self,meter):
        state=self._actual();r=self.reader;r.require_data_current_v3(meter)
        row,header=self._read_header(meter)
        if self.complete:
            if row!=self.row:raise AuthorityUnavailable('Artifact signed input header changed after actual EOF')
            return True
        if self.column is None:
            self.row,self._header=row,header
            if header is None:
                if self.table!=_D10 or state.allowed_inputs[self.table,self.ref]!=frozenset({'joint_executor_index_v1'})or(self.table,self.ref)in state.input_digests:
                    raise AuthorityUnavailable('Required actual Artifact parent signed input is absent')
                self.absent=True;self.complete=True;return True
            if header.kind not in state.allowed_inputs[self.table,self.ref]:raise AuthorityUnavailable('Artifact signed input kind differs from actual selected parent')
            expected=state.input_digests.get((self.table,self.ref))
            if expected is not None and expected!=header.payload_digest:raise AuthorityUnavailable('Artifact signed parent digest differs from exact actual parent commitment')
            _retains(self,('schema',))
            self.column=BackgroundJSONColumnV3(_ISSUER,r,table=self.table,column='payload_json',
                key_columns=('bot','persona','original_ref'),key=(*r.namespace.as_tuple,self.ref),locator=True,
                signer=r.context.issuer._signer,signature_kind=_SIGNED_INPUT_KINDS[self.table],signature=header.signature)
            _PROFILES[self.column]=self
            return False
        if row!=self.row:raise AuthorityUnavailable('Artifact signed input header changed during complete metadata EOF')
        if not self.column.advance(meter):return False
        column=self.column
        if(type(column)is not BackgroundJSONColumnV3 or not column.signature_verified
                or column.signature_bytes!=column.byte_count or column.canonical_digest!=header.payload_digest
                or(column.signer,column.signature_kind,column.signature)!=(r.context.issuer._signer,_SIGNED_INPUT_KINDS[self.table],header.signature)):
            raise AuthorityUnavailable('Artifact signed metadata lacks actual raw canonical/HMAC whole EOF')
        value=self._metadata_view()
        if 'namespace'in value and value['namespace']!={'bot_id':r.namespace.bot_id,'persona_id':r.namespace.persona_id}:
            raise AuthorityUnavailable('Artifact signed input metadata crossed actual namespace')
        for name,expected in header.indexed_locators:
            if value[name]!=expected:raise AuthorityUnavailable('Artifact consent metadata changed actual indexed parent identity')
        refs=tuple(value['source_refs'])if self.table!=_CONSENT else(value['inbound_source_ref'],)
        if any(type(ref)is not str for ref in refs)or len(set(refs))!=len(refs):raise AuthorityUnavailable('Artifact signed input metadata has invalid or repeated explicit Source roots')
        # Empty metadata roots grant no Body access. The private owning profile
        # admits only actual typed parents with positive W01/Source closure.
        executor=value.get('executor')
        if executor is not None and executor.get('source_ref')is not None and executor['source_ref']not in refs:refs=(*refs,executor['source_ref'])
        actual={version.key:version.revision for version in(*state.business_versions,*state.control_versions)}
        if any(type(version)is not GraphVersion for version in(*state.business_versions,*state.control_versions)):
            raise AuthorityUnavailable('Artifact Source upper bound is not the actual typed B/C readset')
        for ref in refs:
            key=AtomKey.from_token(ref);revision=state.source_versions.get(key)
            if NamespaceId.from_key(key)!=r.namespace or key.type_name!='memory.source'or revision is None or revision<1 or actual.get(key)!=revision:
                raise AuthorityUnavailable('Artifact signed metadata Source escapes independently qualified actual B/C')
        self.complete=True
        return True
    def _metadata_view(self):
        from .dispatch_current_inventory_v3 import _detach_value_v3
        from .dispatch_initial_source_read_v3 import _container_bytes_v3
        column=self.column
        self.reader.reserve_heap_v3(extra=_container_bytes_v3(column.frozen)+1024)
        return _detach_value_v3(column.frozen)
    @property
    def header(self):
        self._actual()
        if not self.complete:raise AuthorityUnavailable('Artifact signed input header has not reached complete metadata EOF')
        return self._header
    @property
    def metadata(self):
        self._actual()
        if not self.complete:raise AuthorityUnavailable('Artifact signed metadata is not complete')
        return None if self.absent else self._metadata_view()
    def release_payload_v3(self):
        if self.closed:return
        _TASKS.pop(self,None);column=self.column
        if column is not None:
            from .domain_background_read_v3 import _COLUMNS
            _PROFILES.pop(column,None);_COLUMNS.pop(column,None);self.reader.columns.discard(column)
            column.frozen=None;column.value=None;column.nodes.clear();column.scalar.clear()
            column.text_parts.clear();column.text_chars.clear();column.fragment=b'';column.parser=None
            column.signature_state=None
        self.column=None;self._header=None;self.row=None;self.binding=None;self.reader=None;self.closed=True


def prepare_artifact_host_signed_input_metadata_task_v3(reader,table,ref):
    return _ArtifactHostSignedInputMetadataTaskV3(_KEY,reader,table,ref)


def metadata_column_retains_v3(column,path):
    task=_PROFILES.get(column)
    if task is None:return None
    if type(column)is not BackgroundJSONColumnV3 or task.column is not column:raise AuthorityUnavailable('Artifact metadata column changed its exact physical type')
    task._actual()
    return _retains(task,path)


def is_artifact_host_signed_input_metadata_column_v3(column):
    task=_PROFILES.get(column)
    if task is None:return False
    if type(column)is not BackgroundJSONColumnV3 or task.column is not column:raise AuthorityUnavailable('Artifact metadata column changed its exact physical type')
    task._actual()
    return True


def require_artifact_host_signed_input_metadata_column_v3(column):
    if not is_artifact_host_signed_input_metadata_column_v3(column):raise AuthorityUnavailable('Actual private Artifact signed metadata column required')
    return _PROFILES[column].metadata
