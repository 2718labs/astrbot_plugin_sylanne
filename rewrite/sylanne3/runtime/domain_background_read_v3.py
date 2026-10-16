"""Same-operation, fixed-family background reads; never an execution grant."""
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType
from weakref import WeakSet, WeakKeyDictionary, ref
import json

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphVersion, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import (runtime_storage_v3, begin_runtime_cell_read_v3,
    bind_runtime_storage_operation_v3, runtime_storage_quantum_v3)
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .dispatch_current_inventory_v3 import _freeze_value_v3, _detach_value_v3
from .source_correction_read_v3 import _heap
from .c09_paged_sql_v2 import _quote, read_legacy_sql_cell_fragment_v2, legacy_cell_read_transaction_v2

_ISSUER=object()
_READERS=WeakSet()
_COLUMNS=WeakKeyDictionary()
_PREPARED=WeakSet()
_BOUND=ContextVar('sylanne_domain_background_read_v3',default=None)
_GENERAL_GROWTH_WRITE_METADATA_V1=ContextVar('sylanne_general_growth_write_metadata_v1',default=None)
_D07_WRITE_BOUND=ContextVar('sylanne_d07_background_actual_write_binding_v3',default=None)

# Only the registered fixed outbox/offline/Host/D07 algorithms may request these families.
_POINT_KEYS=MappingProxyType({
    'graph_contact_segment_originals_v1':('bot','persona','contact_id','segment_index'),
    'graph_contact_effect_originals_v1':('bot','persona','kind','original_ref'),
    'graph_contact_effect_accounting_attempts_v1':('bot','persona','operation_id'),
    'graph_atoms':('token','bot','persona'),
    'graph_history':('token','revision'),
    'graph_domain_production_outbox_v1':('bot','persona','dedupe_key'),
    'graph_domain_production_originals_v1':('bot','persona','operation_id'),
    'graph_domain_production_originals_v3':('bot','persona','operation_id'),
    'graph_bundle_operations':('bot','persona','operation_id'),
    'graph_d11_offline_originals_v1':('bot','persona','kind','original_ref'),
    'graph_d10_production_inputs_v1':('bot','persona','original_ref'),
    'graph_d01_production_inputs_v1':('bot','persona','original_ref'),
    'graph_d05_boundary_intents_v1':('bot','persona','original_ref'),
    'graph_d08_joint_plan_intents_v1':('bot','persona','original_ref'),
    'graph_d08_party_consents_v1':('bot','persona','original_ref'),
    'graph_d08_joint_node_originals_v1':('bot','persona','original_ref'),
    'graph_d07_execution_originals_v1':('bot','persona','kind','original_ref'),
    'graph_d07_attention_issuance_v1':('bot','persona','operation_id'),
    'graph_d02_action_components_v1':('bot','persona','original_ref'),
    'graph_contact_expression_plan_originals_v2':('bot','persona','contact_id'),
    'runtime_resource_quotes':('quote_id','version'),
    'runtime_budget_grants':('lease_id','version'),
    'runtime_budget_reservations':('lease_id','operation_id'),
    'runtime_budget_operations':('bot_id','persona_id','operation_id','phase'),
    'runtime_d11_owner_role_clock_originals_v1':('bot','persona','revision'),
    'graph_d04_semantic_installations_v3':('bot','persona','revision'),
    'runtime_clock_operations':('operation_id',),
    'graph_events':('bot','persona','session','event_id'),
    'graph_bundle_fences_v2':('bot','persona','operation_id'),
    'graph_d04_root_originals_v3':('bot','persona','operation_id'),
    'runtime_d11_d04_root_freezes_v3':('bot','persona','operation_id'),
    'graph_d04_originals_v3':('bot','persona','kind','original_ref'),
    'graph_d04_joint_advances_v2':('bot','persona','operation_id'),
    'graph_d04_joint_numeric_originals_v1':('bot','persona','operation_id'),
    'graph_d04_joint_output_originals_v1':('bot','persona','operation_id'),
    'graph_d04_joint_advance_members_v2':('bot','persona','operation_id','checkpoint_ref'),
    'graph_owner_issue_operations_v1':('bot','persona'),
    'graph_role_init_receipts_v1':('bot','persona'),
    'graph_migration_import_receipts_v1':('bot','persona','transfer_id'),
    'graph_c09_rebase_certificates_v1':('bot','persona','operation_id'),
    'graph_recovery_metadata_v2':('bot','persona'),
    'graph_d07_execution_originals_v1':('bot','persona','kind','original_ref'),
    'graph_d07_stage_attempts_v1':('bot','persona','stage_operation_id'),
    'graph_d07_attention_issuance_v1':('bot','persona','operation_id'),
    'graph_d07_attention_decisions_v2':('bot','persona','c02_operation_id'),
    'graph_first_ingress_identity_v1':('bot','persona','operation_id'),
    'runtime_jobs':('job_id',),
    'runtime_budget_leases':('lease_id',),
    'runtime_character_clocks':('mapping_id','version'),
    'runtime_resource_outcomes':('quote_id','operation_id','version'),
    'd02_fixed_body_policies_v1':('bot','persona','policy_id','version'),
    'd02_body_quotes_v1':('bot','persona','quote_id'),

})

_POINT_KEYS = MappingProxyType({**_POINT_KEYS,
    "graph_owner_goal_cancellation_projections_v1":("bot","persona","goal_ref","root_registration_ref"),
})

_D07_POINT_COLUMNS=MappingProxyType({
    'graph_d07_execution_originals_v1':frozenset({'payload_json','payload_digest','signature'}),
    'graph_d07_stage_attempts_v1':frozenset({'job_id','phase','request_digest','attempt_id','anchor_json',
        'graph_revision','graph_epoch','permit_json','receipt_json'}),
    'graph_d07_attention_issuance_v1':frozenset({'c02_operation_id','source_ref','quote_id','policy_digest','bundle_digest'}),
    'graph_d07_attention_decisions_v2':frozenset({'attention_operation_id','inbound_ticket_ref','selected_ticket_ref',
        'inbound_deferred','wake_at','bundle_digest'}),
    'graph_first_ingress_identity_v1':frozenset({'source_ref','platform_ref','conversation_ref','sender_ref','message_id',
        'visibility','identity_json','content_fingerprint','learned_at','bundle_digest'}),
    'runtime_jobs':frozenset({'operation_id','activity_id','effect_id','bot_id','persona_id','snapshot_ref','phase','work_kind',
        'continuation_json','wake_condition_json','deadline_utc','budget_ref','resource_ref','operator_versions_json',
        'lease_holder','lease_expires_utc','fence','cancel_epoch','usage_json','result_ref'}),
    'runtime_budget_leases':frozenset({'parent_id','bot_id','persona_id','currency','limits_json','used_json',
        'reserved_json','unconfirmed_json','version','state'}),
    'runtime_character_clocks':frozenset({'wall_origin_utc','character_origin','rate','valid_from_utc',
        'valid_until_utc','policy_ref','issuer_domain'}),
    'runtime_resource_outcomes':frozenset({'outcome_json','signature'}),
    'd02_fixed_body_policies_v1':frozenset({'policy_json','signature','status'}),
    'd02_body_quotes_v1':frozenset({'quote_version','policy_id','policy_version','operation_id',
        'resource_quote_digest','body_quote_json','signature'}),
})
_D07_LOCATOR_FIELDS=frozenset({'schema','namespace','job_id','operation_id','work_kind','owner_authority_json',
    'owner_guard_json','purpose','audience','activation_generation','activity_id','effect_id','attempt_id','call_id',
    'read_rows','parent_prepared_ref','parent_prepared_digest','parent_execution_ref','parent_execution_digest',
    'reflection_request_ref','reflection_request_digest','reflection_continuation_ref','reflection_continuation_digest',
    'checkpoint_ref','checkpoint_digest','ticket_id','source_refs','parent_budget_lease_ref','parent_grant_digest',
    'original_deadline_utc','cycle_ref','cycle_digest','call_plan_digest','c02_operation_id','cancel_generation'})

_FOLLOWUP_TYPES=MappingProxyType({
    'd01':('d01.persona_activation.v1','d01.persona_plan.v1','d07.current_interpretation.v1'),
    'd08':('d08.action_intent.v1','d08.action_outcome.v1','d08.commitment.v1','d08.goal.v1','d08.joint_plan.v1',
        'd08.action_schema.v1','d05.boundary_rule','d05.relationship_projection','d03.account_binding','d03.entity_anchor',
        'd10.contact_policy.v1','d10.proactive_opportunity.v1','d10.contact_claim.v1','d10.contact_claim.v2'),
    'd10':('d10.contact_policy.v1','d10.proactive_opportunity.v1','d10.contact_claim.v1','d10.contact_claim.v2',
        'd10.life_project.v1','d10.activity_recipe.v1','d03.account_binding','d03.entity_anchor','d05.boundary_rule'),
    'd06':(), 'd07':('d07.concern_round.v1','d07.reflection_checkpoint.v1','d07.attention_ticket.v1'),
})
_SIGNED_INPUT_KINDS=MappingProxyType({
    'graph_d05_production_policies_v1':'d11.d05-production-policy.v2',
    'runtime_d11_d04_root_freezes_v3':'d11.d04-authored-root-freeze.v3',
    'graph_d01_production_inputs_v1':'d11.d01-production-input.v1',
    'graph_d05_boundary_intents_v1':'d11.d05-boundary-intent.v1',
    'graph_d08_joint_plan_intents_v1':'d11.d08-joint-plan-intent.v1',
    'graph_d08_party_consents_v1':'d11.d08-party-consent.v1',
    'graph_d08_joint_node_originals_v1':'d11.d08-joint-node-original.v1',
    'graph_d10_production_inputs_v1':'d11.d10-production-input.v1',
    'graph_d02_action_components_v1':'d11.d02-completed-action-component.v1',
    'runtime_d11_owner_role_clock_originals_v1':'d11.owner-role-clock-installation.v1',
    'graph_d04_semantic_installations_v3':'d11.owner-selected-d04-semantic-installation.v3',
})
_JSON_NAMES=frozenset({'observation_json','value','reads','revisions','invalidated','dependencies','original_payload_json',
    'read_versions_json','receipt_json','payload_json','source_refs_json','policy_json','body_quote_json',
    'continuation_json','wake_condition_json','operator_versions_json','usage_json','grant_json','quote_json',
    'ceiling_json','actual_json','mapping_json','outcome_json'})

@dataclass(frozen=True,slots=True)
class D07StageReadSelectorV3:
    parent_job_id:str
    stage:str
    continuation_ref:str|None=None
    def __post_init__(self):
        from .jobs import _identifier
        _identifier(self.parent_job_id,'D07 actual parent job')
        if self.stage not in {'adopt','reflection_prepare','acquire','complete','result_read','egress_read','egress_seal'}:
            raise ValueError('unregistered actual D07 background stage')
        if (self.stage=='reflection_prepare')!=(self.continuation_ref is not None):
            raise ValueError('only reflection preparation carries its actual continuation locator')
        if self.continuation_ref is not None and (type(self.continuation_ref)is not str or not self.continuation_ref):
            raise ValueError('actual reflection continuation locator required')


def _require_background_d07_service_v3(graph,bootstrap,bundle,service):
    from .d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
    if (type(service)is not InstalledD07ExecutionServiceV1
            or service is not getattr(graph,'_GraphCoordinator__d07_execution_service_v1',None)
            or service.graph is not graph or service.bootstrap is not bootstrap or service.bundle is not bundle
            or service._store is not graph._GraphCoordinator__store or service._db is not service._store._db
            or service.d11_issuer is not graph._GraphCoordinator__d11_issuer
            or service.resource_issuer is not graph._GraphCoordinator__d02_issuer or service._closed):
        raise AuthorityUnavailable('D07 background read requires the actual installed same-W01 service/issuers')
    return service

class BackgroundReadNeededV3(Exception):
    """One explicitly registered local attachment, not an unavailable authority."""
    def __init__(self,request):self.request=request


def require_actual_background_attachment_owner_v3(owner,*,db):
    if (type(owner)is not BackgroundReadWorkV3 or owner not in _READERS or owner.db is not db
            or owner.operation.closed or owner.work is None or owner.work.state is not owner
            or owner.work.operation is not owner.operation or owner.work.kind!='domain_background_read_v3'
            or owner.graph._GraphCoordinator__store._db is not db):
        raise AuthorityUnavailable('actual originating background Work/database required')
    if runtime_storage_v3(db)is not owner.operation.handle:
        raise AuthorityUnavailable('background read lost its installed selected handle')
    return owner


def _active_v3(db):
    owner=_BOUND.get()
    if owner is None:return None
    require_actual_background_attachment_owner_v3(owner,db=db)
    return owner


@contextmanager
def bind_background_reads_v3(owner,*,db,scope=None,current_owner=None):
    require_actual_background_attachment_owner_v3(owner,db=db)
    if scope is not None:owner.require_write_data_v3(db,scope,current_owner)
    token=_BOUND.set(owner)
    write_token=_D07_WRITE_BOUND.set((owner,scope,current_owner))if owner.kind=='d07_stage'and scope is not None else None
    try:
        from .contact_joint_context_source_v3 import bind_contact_joint_observation_v3
        with bind_contact_joint_observation_v3(owner,db):yield owner
    finally:
        if write_token is not None:_D07_WRITE_BOUND.reset(write_token)
        _BOUND.reset(token)


def _require_json_column_owner_v3(owner,*,db):
    if type(owner)is BackgroundReadWorkV3:return require_actual_background_attachment_owner_v3(owner,db=db)
    from ..authority_service.model_reply_scope_observation_v3 import require_actual_model_reply_scope_column_owner_v3
    return require_actual_model_reply_scope_column_owner_v3(owner,db=db)


def _json_column_signer_v3(owner,table):
    if type(owner)is BackgroundReadWorkV3:
        require_actual_background_attachment_owner_v3(owner,db=owner.db)
        return(owner.graph._GraphCoordinator__d02_issuer._signer if table in('runtime_resource_quotes','runtime_resource_outcomes')
            else owner.graph._GraphCoordinator__d11_issuer._signer)
    _require_json_column_owner_v3(owner,db=owner.db)
    return owner.signer_v3(table)


class _BackgroundJSONStreamV3(C09CanonicalJSONStreamV2):
    """Reuse the canonical FSM; build decoded strings one input fragment at a time."""
    def __init__(self,column,*,ensure_ascii):
        self.column=column
        super().__init__(ensure_ascii=ensure_ascii)
    def _append_decoded_codepoint(self,codepoint):
        state=self._string
        if state is None or state['mode']!='value':
            return super()._append_decoded_codepoint(codepoint)
        c=self.column
        if type(c.owner)is not BackgroundReadWorkV3:
            _require_json_column_owner_v3(c.owner,db=c.db)
            c.owner.observe_column_codepoint_v3(c,state['path'],codepoint)
        if c.joint_contact_metadata_profile is not None:
            from .contact_joint_context_source_v3 import observe_contact_joint_locator_codepoint_v3
            observe_contact_joint_locator_codepoint_v3(c,state['path'],codepoint)
        if not c.retain_path_v3(state['path']):return
        high=c.text_high
        if high is not None:
            c.text_high=None
            if 0xdc00<=codepoint<=0xdfff:
                c.text_chars.append(chr(0x10000+((high-0xd800)<<10)+codepoint-0xdc00));return
            c.text_chars.append(chr(high))
        if 0xd800<=codepoint<=0xdbff:c.text_high=codepoint
        else:c.text_chars.append(chr(codepoint))


class BackgroundJSONColumnV3:
    """Actual raw column/cell EOF, optionally a metadata-only entry locator."""
    def __init__(self,issuer,owner,*,table,column,key_columns,key,cell_id=None,locator=False,
            signer=None,signature_kind=None,signature=None,general_metadata_profile=None,joint_contact_metadata_profile=None):
        if issuer is not _ISSUER:raise TypeError('background column issuer required')
        _require_json_column_owner_v3(owner,db=owner.db)
        self.owner,self.db,self.operation=owner,owner.db,owner.operation
        self.table,self.column,self.key_columns,self.key=table,column,tuple(key_columns),tuple(key)
        self.where=' AND '.join(_quote(n)+'=?'for n in self.key_columns)
        self.cell=begin_runtime_cell_read_v3(self.db,cell_id,erasure_owner_ref=self.key[0]if table in ('graph_history','graph_atoms') else None)if cell_id is not None else None
        codec=None if self.cell is None else self.cell.header[0]
        if codec is not None and codec not in ('canonical-json.ascii.v1','canonical-json.utf8.v1'):
            raise AuthorityUnavailable('background original has an unregistered JSON codec')
        if general_metadata_profile is not None:
            require_current_general_growth_trial_metadata_reader_v1(owner)
            if general_metadata_profile[0]!=table:raise AuthorityUnavailable('General metadata column/profile table differs')
        if joint_contact_metadata_profile is not None:
            from .contact_joint_context_source_v3 import require_contact_joint_locator_profile_v3
            require_contact_joint_locator_profile_v3(owner,joint_contact_metadata_profile,table,column,self.key)
        self.joint_contact_metadata_profile=joint_contact_metadata_profile
        self.joint_contact_hash_states={};self.joint_contact_field_hashes={}
        self.general_metadata_profile=general_metadata_profile
        self.general_metadata_fields_seen=set()
        self.locator=locator
        self.nodes={};self.value=None;self.scalar=bytearray()
        self.text_parts=[];self.text_chars=[];self.text_high=None
        self.fragment=b'';self.fragment_offset=0;self.offset=0;self.total=None
        self.complete=False;self.frozen=None;self.reserved=0;self.sha256=None;self.byte_count=None
        self.semantic_sha256=None;self.semantic_state=None;self.semantic_decoder=None
        if codec=='canonical-json.utf8.v1' and(type(owner)is not BackgroundReadWorkV3 or general_metadata_profile is not None or joint_contact_metadata_profile is not None):
            import codecs,hashlib
            self.semantic_state=hashlib.sha256()
            self.semantic_decoder=codecs.getincrementaldecoder('utf-8')('strict')
        self.signer,self.signature_kind,self.signature=signer,signature_kind,signature
        self.signature_state=None;self.signature_bytes=0;self.signature_verified=False
        self.parser=_BackgroundJSONStreamV3(self,ensure_ascii=codec!='canonical-json.utf8.v1')
        _COLUMNS[self]=(ref(owner),self.db,self.table,self.column,self.key_columns,self.key,self.cell,self.locator,
            self.signer,self.signature_kind,self.signature,self.general_metadata_profile,self.joint_contact_metadata_profile)
        if signer is not None:
            self.signature_state=signer.begin_original_stream_verification_v3(signature_kind,self)
        owner.columns.add(self)
        self._reserve_v3(65536)
    def _actual_v3(self):
        expected=_COLUMNS.get(self)
        actual=(ref(self.owner),self.db,self.table,self.column,self.key_columns,self.key,self.cell,self.locator,
            self.signer,self.signature_kind,self.signature,self.general_metadata_profile,self.joint_contact_metadata_profile)
        if expected!=actual:raise AuthorityUnavailable('background original column identity changed')
        _require_json_column_owner_v3(self.owner,db=self.db)
        return self
    def _reserve_v3(self,extra=0):
        self.owner.reserve_heap_v3(extra=extra+65536)
    def retain_path_v3(self,path):
        if type(self.owner)is BackgroundReadWorkV3 and self.owner.kind=='artifact_model_dispatch':
            from .artifact_host_signed_input_metadata_v3 import metadata_column_retains_v3
            retained=metadata_column_retains_v3(self,path)
            if retained is not None:return retained
        if self.joint_contact_metadata_profile is not None:
            from .contact_joint_context_source_v3 import contact_joint_locator_retains_path_v3
            return contact_joint_locator_retains_path_v3(self.owner,self.joint_contact_metadata_profile,self.table,self.column,self.key,path)
        if self.general_metadata_profile is not None:
            require_current_general_growth_trial_metadata_reader_v1(self.owner)
            from .d01_general_growth_v1 import general_growth_owner_metadata_retains_path_v1
            return general_growth_owner_metadata_retains_path_v1(*self.general_metadata_profile,path)
        if type(self.owner)is not BackgroundReadWorkV3:
            _require_json_column_owner_v3(self.owner,db=self.db)
            return self.owner.retain_column_path_v3(self,path)
        if self.locator and self.table in {'graph_contact_expression_plan_originals_v2'}:
            return not path or path[0]=='plan'
        return not self.locator or not path or path[0]in('authority','parent_budget','namespace','identity')
    def _put_v3(self,path,value):
        if not path:self.value=value
        else:
            parent=self.nodes[path[:-1]]
            if type(parent)is list:
                if path[-1]!=len(parent):raise ValueError('background original array cursor changed')
                parent.append(value)
            else:parent[path[-1]]=value
    def _flush_text_v3(self):
        if self.text_chars:
            self.text_parts.append(''.join(self.text_chars));self.text_chars=[]
    def _emit_v3(self,event):
        if self.joint_contact_metadata_profile is not None:
            from .contact_joint_context_source_v3 import observe_contact_joint_locator_event_v3
            observe_contact_joint_locator_event_v3(self,event)
        if(self.general_metadata_profile is not None and len(event.path)==1
                and event.kind in('object_start','array_start','scalar_start')):
            from sys import getsizeof
            # CPython set insertion may allocate a table up to four times its previous capacity.
            self._reserve_v3(4*getsizeof(self.general_metadata_fields_seen)+getsizeof(event.path[0]))
            self.general_metadata_fields_seen.add(event.path[0])
        if type(self.owner)is not BackgroundReadWorkV3:
            _require_json_column_owner_v3(self.owner,db=self.db)
            self.owner.observe_column_event_v3(self,event)
        if not self.retain_path_v3(event.path):return
        if event.kind in('object_start','array_start'):
            self._reserve_v3(4096);value={}if event.kind=='object_start'else[]
            self.nodes[event.path]=value;self._put_v3(event.path,value)
        elif event.kind=='scalar_start':
            self.scalar=bytearray();self.text_parts=[];self.text_chars=[];self.text_high=None
        elif event.kind=='scalar_chunk' and event.scalar_kind!='string':
            self._reserve_v3(len(event.raw)*4+1024);self.scalar.extend(event.raw)
        elif event.kind=='scalar_end':
            if event.scalar_kind=='string':
                if self.text_high is not None:self.text_chars.append(chr(self.text_high));self.text_high=None
                self._flush_text_v3();self._reserve_v3(sum(map(len,self.text_parts))*4+1024)
                value=''.join(self.text_parts);self.text_parts=[]
            else:value=json.loads(self.scalar)
            self.scalar=bytearray();self._put_v3(event.path,value)
    def advance(self,meter):
        self._actual_v3();self.owner.require_data_current_v3(meter)
        if self.complete:return True
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment));self._reserve_v3(131072)
            part=self.fragment[self.fragment_offset:end]
            self.parser.feed(part,self._emit_v3)
            if self.semantic_state is not None:
                text=self.semantic_decoder.decode(part,final=False)
                escaped=[]
                for character in text:
                    codepoint=ord(character)
                    if codepoint<127:
                        escaped.append(character)
                    elif codepoint<=0xffff:
                        escaped.append(chr(92)+'u'+format(codepoint,'04x'))
                    else:
                        scalar=codepoint-0x10000
                        escaped.append(chr(92)+'u'+format(0xd800+(scalar>>10),'04x')
                            +chr(92)+'u'+format(0xdc00+(scalar&0x3ff),'04x'))
                self.semantic_state.update(''.join(escaped).encode('ascii'))
            self.fragment_offset=end;self._flush_text_v3();return False
        if self.cell is not None:
            chunk=self.cell.read_fragment(meter=meter)
        else:
            with legacy_cell_read_transaction_v2(self.db):
                if self.total is None:
                    meter.require_available(1024)
                    row=self.db.execute('SELECT typeof('+_quote(self.column)+'),length(CAST('+_quote(self.column)+' AS BLOB)) FROM '+_quote(self.table)+' WHERE '+self.where,self.key).fetchone()
                    meter.charge_read(16)
                    if row is None or row[0]!='text':raise AuthorityUnavailable('background JSON column disappeared or changed kind')
                    self.total=row[1]
                if self.offset<self.total:
                    chunk,total,kind=read_legacy_sql_cell_fragment_v2(self.db,table=self.table,column=self.column,
                        where=self.where,parameters=self.key,start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                    if (total,kind)!=(self.total,'text'):raise AuthorityUnavailable('background original column length/kind changed')
                    self.offset+=len(chunk)
                else:chunk=None
        if chunk is not None:
            if type(self.owner)is not BackgroundReadWorkV3:
                _require_json_column_owner_v3(self.owner,db=self.db)
                self.owner.observe_column_fragment_v3(self,chunk,meter)
            if self.signature_state is not None:self.signature_state.update(chunk);self.signature_bytes+=len(chunk)
            self.fragment,self.fragment_offset=chunk,0;return False
        parsed=self.parser.finish()
        if self.cell is not None:
            digest=self.cell.finish(meter=meter)
            if (parsed.sha256,parsed.byte_count)!=(digest,self.cell.header[3]):raise AuthorityUnavailable('background original cell SHA/EOF changed')
        elif parsed.byte_count!=self.total:raise AuthorityUnavailable('background original column EOF changed')
        self._reserve_v3(_heap(self.value)+1024);self.frozen=_freeze_value_v3(self.value)
        self.sha256,self.byte_count=parsed.sha256,parsed.byte_count
        if self.semantic_state is None:
            self.semantic_sha256=self.sha256
        else:
            if self.semantic_decoder.decode(b'',final=True):
                raise AuthorityUnavailable('semantic canonical decoder has bytes after actual EOF')
            self.semantic_sha256=self.semantic_state.hexdigest()
        self.canonical_digest=self.semantic_sha256
        self.semantic_state=self.semantic_decoder=None
        self.value=None;self.nodes={};self.scalar=bytearray();self.text_parts=[];self.text_chars=[];self.fragment=b'';self.parser=None
        self.complete=True
        if self.signature_state is not None:
            self.signer.finish_original_stream_verification_v3(self.signature_kind,self.signature,self,self.signature_state)
            self.signature_verified=True
        if type(self.owner)is not BackgroundReadWorkV3:
            _require_json_column_owner_v3(self.owner,db=self.db)
            self.owner.observe_column_finish_v3(self)
        return True
    def json_v3(self):
        self._actual_v3()
        if not self.complete or self.locator or self.general_metadata_profile is not None or self.joint_contact_metadata_profile is not None:
            raise AuthorityUnavailable('complete full background JSON original required')
        from .dispatch_initial_source_read_v3 import _container_bytes_v3
        self.owner.reserve_heap_v3(extra=_container_bytes_v3(self.frozen)+1024)
        return _detach_value_v3(self.frozen)
    def matches_v3(self,value):
        self._actual_v3()
        from ..runtime_contracts import _canonical_value
        if not self.complete or self.locator:return False
        if self.general_metadata_profile is not None:raise AuthorityUnavailable('General metadata projection is not full payload equality')
        if type(self.owner)is not BackgroundReadWorkV3 and self.owner.metadata_only_column_v3(self):
            raise AuthorityUnavailable('model parentage metadata projection is not a full body equality proof')
        self.owner.reserve_heap_v3(extra=_heap(value)+65536)
        return _background_canonical_value_matches_v3(_canonical_value(value,set()),self.frozen)


def require_background_signature_column_v3(original,*,signer,kind,signature=None,verifier=None,complete=False):
    if type(original)is not BackgroundJSONColumnV3:raise AuthorityUnavailable('actual background signature column required')
    original._actual_v3()
    expected=(_SIGNED_INPUT_KINDS.get(original.table) if original.column in('payload_json','original_json') else
        'resource-quote.v1' if (original.table,original.column)==('runtime_resource_quotes','quote_json') else
        'resource-outcome.v1' if (original.table,original.column)==('runtime_resource_outcomes','outcome_json') else
        'budget-grant.v1' if (original.table,original.column)==('runtime_budget_grants','grant_json') else None)
    if (expected is None or original.signer is not signer or kind!=expected or original.signature_kind!=kind):
        raise AuthorityUnavailable('background signer/domain/column binding changed')
    if complete and (not original.complete or original.signature_state is not verifier
            or original.signature!=signature or original.signature_bytes!=original.byte_count):
        raise AuthorityUnavailable('background signature is not bound to complete actual raw-byte EOF')
    return original


def background_json_loads_v3(value):
    from ..authority_service.current_authority_graph_read_v3 import PreparedAuthorityJSONColumnV3,_AuthorityAtomJSONV3,authority_current_json_v3
    if type(value)in(PreparedAuthorityJSONColumnV3,_AuthorityAtomJSONV3):return authority_current_json_v3(value)
    if type(value)is BackgroundJSONColumnV3:return value.json_v3()
    from .current_method_learning_read_v3 import MethodJSONColumnV3
    if type(value)is MethodJSONColumnV3:return value.json_v3()
    return json.loads(value)


def background_json_matches_v3(encoded,value):
    from ..authority_service.current_authority_graph_read_v3 import PreparedAuthorityJSONColumnV3,_AuthorityAtomJSONV3
    if type(encoded)in(PreparedAuthorityJSONColumnV3,_AuthorityAtomJSONV3):return encoded.matches_v3(value)
    if type(encoded)is BackgroundJSONColumnV3:return encoded.matches_v3(value)
    from ..runtime_contracts import canonical_serialize
    return canonical_serialize(value)==encoded


def background_json_digest_v3(encoded,value):
    from ..authority_service.current_authority_graph_read_v3 import PreparedAuthorityJSONColumnV3,_AuthorityAtomJSONV3
    if type(encoded)in(PreparedAuthorityJSONColumnV3,_AuthorityAtomJSONV3):
        if not encoded.matches_v3(value):raise AuthorityUnavailable('Authority original decoded value changed')
        return canonical_digest(value)
    if type(encoded)is BackgroundJSONColumnV3:
        if not encoded.matches_v3(value):raise AuthorityUnavailable('background original decoded value changed')
        return encoded.sha256
    return canonical_digest(value)


def background_verify_signature_v3(signer,kind,payload,signature):
    from ..authority_service.current_authority_graph_read_v3 import PreparedAuthorityJSONColumnV3,_AuthorityAtomJSONV3,authority_current_json_v3
    if type(payload)in(PreparedAuthorityJSONColumnV3,_AuthorityAtomJSONV3):
        from ..runtime_contracts import canonical_serialize
        signer.verify(kind,canonical_serialize(authority_current_json_v3(payload)),signature)
        return
    if type(payload)is BackgroundJSONColumnV3:
        payload._actual_v3()
        if not payload.signature_verified or (payload.signer,payload.signature_kind,payload.signature)!=(signer,kind,signature):
            raise AuthorityUnavailable('background original signature was not verified at raw EOF')
        return
    signer.verify(kind,payload,signature)


class _BackgroundPointReadV3:
    def __init__(self,owner,request):
        _require_json_column_owner_v3(owner,db=owner.db)
        self.owner,self.request=owner,request
        self.table,self.columns,self.key_columns,self.key=request
        self.where=' AND '.join(_quote(n)+'=?'for n in self.key_columns)
        self.phase='metadata';self.metadata=None;self.row=None;self.small=None;self.pending=[];self.column=None;self.values={};self.complete=False
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        owner=self.owner;owner.require_data_current_v3(meter)
        if self.phase=='metadata':
            json_names=tuple(n for n in self.columns if n in _JSON_NAMES or n.endswith('_json'))
            metadata=tuple(n for n in self.columns if n not in json_names)
            if self.table in('graph_atoms','graph_history')and 'value'in json_names:metadata=(*metadata,'value_cell_id')
            self.metadata_columns=tuple(dict.fromkeys((*self.key_columns,*metadata)))
            self.metadata=_runtime_bounded_fixed_row_v3(owner.db,meter,self.table,self.metadata_columns,self.where,self.key)
            if self.metadata is None:self.complete=True;return
            self.small=dict(zip(self.metadata_columns,self.metadata));self.pending=list(json_names);self.phase='columns';return
        if self.column is not None:
            if self.column.advance(meter):
                self.values[self.column.column]=self.column;self.column=None
            return
        if self.pending:
            if owner.kind=='artifact_model_dispatch':
                from .artifact_host_dispatch_source_v3 import require_artifact_host_dispatch_body_v3
                require_artifact_host_dispatch_body_v3(owner,self.table,self.key)
            from .contact_joint_context_source_v3 import require_contact_joint_body_v3
            require_contact_joint_body_v3(owner,self.table,self.key)
            name=self.pending.pop(0);cell=self.small.get('value_cell_id')if name=='value'else None
            if owner.kind=="d07_stage" and self.table=="graph_atoms" and name=="value":
                token=dict(zip(self.key_columns,self.key))["token"]
                atom_key=AtomKey.from_token(token)
                if atom_key.type_name=="memory.source":
                    material=getattr(owner,"d07_source_material",None)
                    if type(material) is not PreparedD07StageSourceMaterialV3 or token not in material.witnesses:
                        self.pending.insert(0,name)
                        if owner.sealed:
                            raise AuthorityUnavailable("D07 sealed Source body was never qualified by its actual Work")
                        raise BackgroundReadNeededV3(("d07_source_rights",token))
                    material.require_for_prepared_v3(owner,owner.entry_metadata[0][0])
            if owner.kind=="d07_stage" and self.table=="graph_d07_execution_originals_v1" and name=="payload_json":
                material=getattr(owner,"d07_source_material",None)
                if type(material) is not PreparedD07StageSourceMaterialV3:
                    raise AuthorityUnavailable("D07 protected original cannot precede current Source qualification")
                material.require_for_prepared_v3(owner,owner.entry_metadata[0][0])
            if cell is None:
                meter.require_available(1024)
                kind=owner.db.execute('SELECT typeof('+_quote(name)+') FROM '+_quote(self.table)+' WHERE '+self.where,self.key).fetchone()
                meter.charge_read(8)
                if kind is None:raise AuthorityUnavailable('background point column disappeared')
                if kind[0]=='null':self.values[name]=None;return
                if kind[0]!='text':raise AuthorityUnavailable('background original JSON column changed kind')
            signature_kind=(_SIGNED_INPUT_KINDS[self.table] if self.table in _SIGNED_INPUT_KINDS and name in('payload_json','original_json') else
                'resource-quote.v1' if self.table=='runtime_resource_quotes' and name=='quote_json' else
                'resource-outcome.v1' if self.table=='runtime_resource_outcomes' and name=='outcome_json' else
                'budget-grant.v1' if self.table=='runtime_budget_grants' and name=='grant_json' else None)
            signed=signature_kind is not None
            self.column=BackgroundJSONColumnV3(_ISSUER,owner,table=self.table,column=name,key_columns=self.key_columns,key=self.key,cell_id=cell,
                signer=_json_column_signer_v3(owner,self.table)if signed else None,
                signature_kind=signature_kind,
                signature=self.small.get('signature')if signed else None)
            return
        self.row=tuple(self.values[n]if n in self.values else self.small[n]for n in self.columns);self.complete=True
    def require_row_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        if not self.complete:raise AuthorityUnavailable('background point is not prepared')
        current=_runtime_bounded_fixed_row_v3(self.owner.db,meter,self.table,self.metadata_columns,self.where,self.key)
        if current!=self.metadata:raise AuthorityUnavailable('background point identity changed after EOF')
        return self.row


class _BackgroundInventoryReadV3:
    def __init__(self,owner,type_id):
        owner.store._registry.spec(type_id)
        self.owner,self.type_id=owner,type_id
        self.after=None;self.rows=[];self.pending=None;self.complete=False
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        o=self.owner;o.require_data_current_v3(meter)
        if self.pending is not None:
            if not self.pending.complete:self.pending.advance(meter);return
            row=self.pending.require_row_v3(meter);key=AtomKey.from_token(self.pending.key[0])
            value=background_json_loads_v3(row[1]);o.store._validate_key(key)
            if row[2]==1:o.store._registry.spec(key.type_name).validator(value)
            atom=GraphAtom(key,row[0],value,bool(row[2]),_canonical_original=row[1]);o.reserve_heap_v3(extra=_heap(atom.value)+1024)
            self.rows.append(atom);o.heads[key.token]=atom;self.pending=None
            if self.type_id in('d04.numeric_checkpoint.v1','d04.numeric_checkpoint.v2'):
                from .joint_numeric_component import MAX_ROWS
                if len(self.rows)>MAX_ROWS:raise AuthorityUnavailable('RoleClock inventory exceeds its original MAX_ROWS')
            elif self.type_id!='d03.role_binding' and len(self.rows)>128:
                raise AuthorityUnavailable('background fixed inventory exceeds original 128-row contract')
            return
        where='bot=? AND persona=? AND type_name=?';args=(*o.namespace.as_tuple,self.type_id)
        if self.after is not None:where+=' AND token>?';args=(*args,self.after)
        row=_runtime_bounded_fixed_row_v3(o.db,meter,'graph_atoms',('token',),where+' ORDER BY token',args)
        if row is None:self.complete=True;return
        key=AtomKey.from_token(row[0])
        if NamespaceId.from_key(key)!=o.namespace or key.type_name!=self.type_id:raise AuthorityUnavailable('background inventory namespace/type changed')
        self.after=row[0];request=('graph_atoms',('revision','value','valid'),('token','bot','persona'),(key.token,*o.namespace.as_tuple))
        self.pending=o.points.get(request)
        if self.pending is None:self.pending=_BackgroundPointReadV3(o,request);o.points[request]=self.pending



def require_bound_d07_write_data_v3(db):
    """Existing actual WRITE Binder, never a scope factory or reuse of READ authorization."""
    owner=_active_v3(db);bound=_D07_WRITE_BOUND.get()
    if (owner is None or owner.kind!='d07_stage' or not owner.sealed
            or bound is None or bound[0]is not owner):
        raise AuthorityUnavailable('actual same-Work fresh D07 WRITE Binder required')
    _require_background_d07_service_v3(owner.graph,owner.bootstrap,owner.bundle,owner.d07_service)
    owner.require_write_data_v3(db,bound[1],bound[2])
    return bound


def read_bound_d07_mutable_runtime_row_v3(db,*,table,columns,key_columns,key):
    """Fixed current runtime row in the actual READ/WRITE transaction; never a cached point."""
    owner=_active_v3(db)
    if owner is None or owner.kind!='d07_stage':return False,None
    families={
        'runtime_jobs':_D07_POINT_COLUMNS['runtime_jobs']|{'job_id'},
        'runtime_budget_leases':_D07_POINT_COLUMNS['runtime_budget_leases']|{'lease_id'},
        'runtime_budget_reservations':frozenset({'lease_id','operation_id','state','digest','ceiling_json','actual_json'}),
    }
    if table not in families:return False,None
    keys=tuple(key_columns);values=tuple(key);fields=tuple(columns)
    if keys!=_POINT_KEYS[table]or len(values)!=len(keys)or not set(fields)<=families[table]:
        raise AuthorityUnavailable('D07 current runtime read changed its closed table/columns/key')
    _require_background_d07_service_v3(owner.graph,owner.bootstrap,owner.bundle,owner.d07_service)
    successor=False;binding=None;egress_seal=False
    if owner.sealed and owner.d07_selector.stage=='egress_seal':
        active=getattr(owner,'d07_active_egress_seal',None)
        egress_seal=(active is not None and active is getattr(owner,'d07_egress_pair',None))
        if egress_seal and (not db.in_transaction or not owner.store._lock._is_owned()):
            raise AuthorityUnavailable('D07 actual egress seal lost its SQL transaction/lock')
    if owner.sealed and not egress_seal:
        binding=_D07_WRITE_BOUND.get()
        if binding is None or binding[0]is not owner:
            raise AuthorityUnavailable('D07 mutable data lacks its actual fresh WRITE Binder')
        from .d07_graph_stages_v1 import require_d07_mutable_successor_v3
        successor=require_d07_mutable_successor_v3(owner,binding)
        if not successor:require_bound_d07_write_data_v3(db)
    elif not owner.sealed and (owner.fence is None or owner.read_scope is not owner.fence.scope
            or not db.in_transaction or not owner.store._lock._is_owned()):
        raise AuthorityUnavailable('D07 current runtime read lost its actual protected READ scope/transaction')
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    with runtime_storage_quantum_v3(db)as meter:
        if successor:
            owner.operation.handle.require_current(meter)
            if not require_d07_mutable_successor_v3(owner,binding):
                raise AuthorityUnavailable('D07 actual mutable successor relation disappeared')
        else:
            owner.require_data_current_v3(meter)
            if egress_seal and owner.d07_active_egress_seal is not owner.d07_egress_pair:
                raise AuthorityUnavailable('D07 actual egress seal relation changed before current SQL')
        subject_table='runtime_jobs'if table=='runtime_jobs'else'runtime_budget_leases'
        subject_key='job_id'if table=='runtime_jobs'else'lease_id'
        namespace=_runtime_bounded_fixed_row_v3(db,meter,subject_table,('bot_id','persona_id'),
            _quote(subject_key)+'=?',(values[0],))
        if namespace is None:return True,None
        if namespace!=owner.namespace.as_tuple:
            raise AuthorityUnavailable('D07 current runtime row belongs to another actual namespace')
        where=' AND '.join(_quote(name)+'=?'for name in keys)
        row=_runtime_bounded_fixed_row_v3(db,meter,table,fields,where,values)
        if successor:
            owner.operation.handle.require_current(meter)
            _require_background_d07_service_v3(owner.graph,owner.bootstrap,owner.bundle,owner.d07_service)
            if not require_d07_mutable_successor_v3(owner,binding):
                raise AuthorityUnavailable('D07 actual mutable successor changed during current SQL')
        else:
            owner.require_data_current_v3(meter)
            if egress_seal and owner.d07_active_egress_seal is not owner.d07_egress_pair:
                raise AuthorityUnavailable('D07 actual egress seal relation changed during current SQL')
    return True,row


def read_bound_background_graph_attachment_v3(db,*,table,columns,key_columns,key):
    from ..authority_service.model_reply_scope_observation_v3 import read_bound_model_reply_scope_point_v3
    observed,row=read_bound_model_reply_scope_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if observed:return True,row
    mutable,row=read_bound_d07_mutable_runtime_row_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if mutable:return True,row
    owner=_active_v3(db)
    if owner is None:return False,None
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    owner.require_request_v3(request)
    if owner.kind=='d07_stage' and owner.sealed:
        from .d07_graph_stages_v1 import read_bound_d07_authored_successor_attachment_v3
        successor,row=read_bound_d07_authored_successor_attachment_v3(owner,request)
        if successor:return True,row
    task=owner.points.get(request)
    if task is None or not task.complete:
        if owner.sealed:raise AuthorityUnavailable('background exact original was not prepared by this Work')
        raise BackgroundReadNeededV3(('point',request))
    if owner.kind=='d07_stage' and not owner.sealed and owner.phase=='algorithm':
        bound=owner.d07_algorithm_binding
        if (bound is None or bound[1]!=owner.graph_stamp or bound[2]is not owner.read_scope
                or owner.fence is None or owner.fence.scope is not owner.read_scope
                or not db.in_transaction or not owner.store._lock._is_owned()):
            raise AuthorityUnavailable('D07 EOF getter lost its actual protected READ quantum')
        if any(column is not None and not column.complete for column in task.values.values()):
            raise AuthorityUnavailable('D07 point has an incomplete original column EOF')
        return True,task.row
    if owner.kind=='d07_stage' and owner.sealed:
        bound=_D07_WRITE_BOUND.get()
        active=getattr(owner,'d07_active_egress_seal',None)
        egress=(owner.d07_selector.stage=='egress_seal' and active is not None
            and active is getattr(owner,'d07_egress_pair',None))
        if (not owner.d07_points_validated or (not egress and (bound is None or bound[0]is not owner))
                or not db.in_transaction or not owner.store._lock._is_owned()):
            raise AuthorityUnavailable('D07 EOF consumption lost its actual qualified WRITE/seal Binder')
        if any(column is not None and not column.complete for column in task.values.values()):
            raise AuthorityUnavailable('D07 qualified point has an incomplete original column EOF')
        # The actual fresh WRITE Binder qualified the same data stamp at entry.
        # After its own CAS the fixed successor hook above must handle every request or HOLD.
        return True,task.row
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as meter:
        owner.require_data_current_v3(meter);row=task.require_row_v3(meter)
    return True,row


def background_point_v3(db,*,table,columns,key_columns,key,legacy_reader):
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from ..authority_service.original_foreground_source_read_v3 import original_foreground_work_v3,read_original_foreground_point_v3
    original=_authority_attachment_owner_v3(db)
    if original is not None and original_foreground_work_v3(original)is not None:
        return read_original_foreground_point_v3(original,table=table,columns=columns,key_columns=key_columns,key=key)
    from ..authority_service.artifact_model_original_family_v3 import _reader_v3
    artifact=_reader_v3(db)
    if artifact is not None:
        from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
        handled,row=read_bound_authority_graph_attachment_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
        if not handled:raise AuthorityUnavailable('Artifact exact Original point has no actual Work attachment')
        return row
    from ..authority_service.named_joint_binding_body_v1 import named_joint_core_point_v1
    named,row=named_joint_core_point_v1(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if named:return row
    handled,row=read_bound_background_graph_attachment_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    return row if handled else legacy_reader()


def background_graph_head_v3(db,namespace,key):
    if type(key)is str:key=AtomKey.from_token(key)
    if NamespaceId.from_key(key)!=namespace:raise ValueError('background head crossed namespace')
    return background_point_v3(db,table='graph_atoms',columns=('revision','value','valid'),key_columns=('token','bot','persona'),
        key=(key.token,*namespace.as_tuple),legacy_reader=lambda:db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?',(key.token,*namespace.as_tuple)).fetchone())


def background_history_v3(db,key,revision,*,columns=('event_id','value','valid')):
    return background_point_v3(db,table='graph_history',columns=columns,key_columns=('token','revision'),key=(key,revision),
        legacy_reader=lambda:db.execute('SELECT '+','.join(columns)+' FROM graph_history WHERE token=? AND revision=?',(key,revision)).fetchone())


def background_inventory_v3(db,namespace,type_id,*,valid_only):
    from ..authority_service.original_foreground_source_read_v3 import read_bound_original_foreground_inventory_v3
    handled,atoms=read_bound_original_foreground_inventory_v3(db,namespace,type_id,valid_only=valid_only)
    if handled:return atoms
    from ..authority_service.artifact_model_source_read_v3 import read_bound_artifact_model_inventory_v3
    handled,atoms=read_bound_artifact_model_inventory_v3(db,namespace,type_id,valid_only=valid_only)
    if handled:return atoms
    from ..authority_service.named_joint_binding_body_v1 import named_joint_core_inventory_v1
    named=named_joint_core_inventory_v1(db,namespace,type_id,valid_only=valid_only)
    if named is not None:return named
    owner=_active_v3(db)
    if owner is None:
        from .current_method_learning_read_v3 import read_bound_method_type_rows_v3
        handled,rows=read_bound_method_type_rows_v3(db,namespace,type_id,('token','revision','value','valid'),valid_only=valid_only)
        if handled:return tuple(GraphAtom(AtomKey.from_token(k),r,json.loads(v),bool(ok))for k,r,v,ok in rows)
        if runtime_storage_v3(db)is not None:raise AuthorityUnavailable('actual prepared Background or Method inventory required')
        rows=db.execute('SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129',(*namespace.as_tuple,type_id)).fetchall()
        if len(rows)>128:raise AuthorityUnavailable('complete background inventory exceeds original 128-row contract')
        return tuple(GraphAtom(AtomKey.from_token(k),r,json.loads(v),bool(ok))for k,r,v,ok in rows if not valid_only or ok)
    if namespace!=owner.namespace:raise AuthorityUnavailable('background inventory crossed actual namespace')
    if type_id == 'memory.source' and owner.contact_active_component is not None:
        component = owner.contact_active_component
        if not component.complete or component.source_material is None:
            raise AuthorityUnavailable('Contact Source inventory cannot precede its independently qualified full material EOF')
        actual_refs = {ref for ref,head in component.heads.items() if AtomKey.from_token(ref).type_name == 'memory.source' and head[1]}
        if actual_refs != set(component.source_material.source_records):
            raise AuthorityUnavailable('Contact complete Source inventory lacks exact current material for every positive member')
        return tuple(component.projection.get(AtomKey.from_token(ref)) for ref in sorted(actual_refs))
    owner.require_family_v3(type_id)
    task=owner.inventories.get(type_id)
    if task is None or not task.complete:
        if owner.sealed:raise AuthorityUnavailable('background fixed family was not prepared to EOF')
        raise BackgroundReadNeededV3(('inventory',type_id))
    return tuple(atom for atom in task.rows if not valid_only or atom.valid)


class _BackgroundRowsReadV3:
    """Fixed indexed metadata keyset, with explicit row/JSON EOF."""
    def __init__(self,owner,request):
        self.owner,self.request=owner,request
        self.table,self.columns,self.group_columns,self.group,self.order_columns,self.limit=request
        self.after=None;self.rows=[];self.pending=None;self.complete=False
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        o=self.owner;o.require_data_current_v3(meter)
        if self.pending is not None:
            if not self.pending.complete:self.pending.advance(meter);return
            self.rows.append(self.pending.require_row_v3(meter));self.pending=None
            if self.limit is not None and len(self.rows)>=self.limit:self.complete=True
            return
        where=' AND '.join(_quote(n)+'=?'for n in self.group_columns);args=self.group
        if self.after is not None:
            after=' OR '.join('('+ ' AND '.join([*(_quote(self.order_columns[j])+'=?'for j in range(i)),_quote(self.order_columns[i])+'>?'])+')'for i in range(len(self.order_columns)))
            values=tuple(x for i in range(len(self.order_columns))for x in (*self.after[:i],self.after[i]))
            where+=' AND ('+after+')';args=(*args,*values)
        keys=_POINT_KEYS[self.table]
        metadata=tuple(dict.fromkeys((*keys,*self.order_columns)))
        row=_runtime_bounded_fixed_row_v3(o.db,meter,self.table,metadata,where+' ORDER BY '+','.join(map(_quote,self.order_columns)),args)
        if row is None:self.complete=True;return
        small=dict(zip(metadata,row));self.after=tuple(small[n]for n in self.order_columns)
        request=(self.table,self.columns,keys,tuple(small[n]for n in keys))
        self.pending=o.points.get(request)
        if self.pending is None:self.pending=_BackgroundPointReadV3(o,request);o.points[request]=self.pending


def background_rows_v3(db,*,table,columns,group_columns,group,order_columns,limit,legacy_reader):
    owner=_active_v3(db)
    if owner is None:return legacy_reader()
    request=(table,tuple(columns),tuple(group_columns),tuple(group),tuple(order_columns),limit)
    owner.require_rows_request_v3(request)
    task=owner.scans.get(request)
    if task is None or not task.complete:
        if owner.sealed:raise AuthorityUnavailable('background row family was not prepared to EOF')
        raise BackgroundReadNeededV3(('rows',request))
    return tuple(task.rows)


def background_physical_payload_v3(db,namespace,operation_id,row):
    owner=_active_v3(db)
    if owner is None:return None
    if namespace!=owner.namespace:raise AuthorityUnavailable('background physical original crossed namespace')
    request=('physical_payload',operation_id,tuple(row))
    task=owner.physical_payloads.get(operation_id)
    if task is None or not task.complete:
        if owner.sealed:raise AuthorityUnavailable('physical adopted original payload was not prepared')
        raise BackgroundReadNeededV3(request)
    if task.cell.cell_id!=row[4]or task.sha256!=row[3]:raise AuthorityUnavailable('physical adopted original changed exact payload EOF')
    return task


def require_background_graph_atom_json_v3(original,*,key,revision,value,valid):
    if type(original)is not BackgroundJSONColumnV3 or original.locator:
        raise AuthorityUnavailable('actual prepared background Graph JSON required')
    original._actual_v3();o=original.owner
    if original.table not in('graph_atoms','graph_history')or original.column!='value' or original.key[0]!=key.token:
        raise AuthorityUnavailable('background Graph atom original has another table/key')
    if NamespaceId.from_key(key)!=o.namespace or type(valid)is not bool:
        raise AuthorityUnavailable('background Graph atom namespace/valid differs')
    match=next((p for p in o.points.values()if p.complete and p.values.get('value')is original),None)
    if match is None:raise AuthorityUnavailable('background Graph atom has no actual completed point')
    actual_revision=match.small['revision']if original.table=='graph_atoms'else original.key[1]
    if (actual_revision,bool(match.small['valid']))!=(revision,valid)or not original.matches_v3(value):
        raise AuthorityUnavailable('background Graph atom revision/value differs from canonical EOF')
    o.store._validate_key(key)
    if valid:o.store._registry.spec(key.type_name).validator(value)
    return original.json_v3()


@dataclass(frozen=True,eq=False,init=False)
class PreparedBackgroundFrameInputsV3:
    owner:object
    plan:object
    envelope:object
    read_scope:object
    graph_stamp:object
    owner_rights:tuple
    def __init__(self,issuer,owner,plan,envelope,current_owner):
        if issuer is not _ISSUER:raise TypeError('actual background frame-input issuer required')
        require_actual_background_attachment_owner_v3(owner,db=owner.db)
        object.__setattr__(self,'owner',owner);object.__setattr__(self,'plan',plan)
        object.__setattr__(self,'envelope',envelope);object.__setattr__(self,'read_scope',owner.read_scope)
        object.__setattr__(self,'graph_stamp',owner.graph_stamp)
        object.__setattr__(self,'owner_rights',(current_owner.access_epoch,current_owner.delete_epoch))
        _PREPARED.add(self)
    def head_v3(self,key):
        o=self.owner
        if type(key)is not AtomKey or NamespaceId.from_key(key)!=o.namespace:raise AuthorityUnavailable('background frame head crossed namespace')
        if key.type_name == 'memory.source' and (o.contact_active_component is not None or o.contact_initial_component is not None):
            component = o.contact_active_component if o.contact_active_component is not None else o.contact_initial_component
            if not component.complete or component.source_material is None:
                raise AuthorityUnavailable('Contact frame Source body requires its independent current material EOF')
            return component.projection.get(key)
        row=background_graph_head_v3(o.db,o.namespace,key)
        if row is None:return GraphAtom(key,0,{},False)
        value=background_json_loads_v3(row[1])
        return GraphAtom(key,row[0],value,bool(row[2]),_canonical_original=row[1])
    def inventory_v3(self,type_id):
        if type_id not in self.plan.fixed_type_ids:raise AuthorityUnavailable('background frame family is outside actual plan')
        return background_inventory_v3(self.owner.db,self.owner.namespace,type_id,valid_only=False)
    def require_current_v3(self,db,scope,current_owner):
        if self not in _PREPARED:raise AuthorityUnavailable('background frame inputs were not privately issued')
        owner=self.owner
        if not owner.sealed:
            if (db is not owner.db or not db.in_transaction or not owner.store._lock._is_owned()
                    or owner.fence is None or scope is not owner.fence.scope or current_owner is not owner.owner):
                raise AuthorityUnavailable('background preparation lost its actual READ scope/Owner')
            from .c09_paged_sql_v2 import current_c09_sql_meter_v2
            owner.require_data_current_v3(current_c09_sql_meter_v2())
        else:owner.require_write_data_v3(db,scope,current_owner)
        return self


def require_background_prepared_frame_inputs_v3(db,*,graph,scope,plan,envelope,current_owner):
    owner=_active_v3(db)
    if owner is None:raise AuthorityUnavailable('actual background frame-input Binder required')
    if (owner.graph is not graph or envelope.authority.namespace!=owner.namespace
            or (scope.graph_revision,scope.graph_epoch)!= (owner.graph_stamp[0].graph_revision,owner.graph_stamp[1])):
        raise AuthorityUnavailable('background frame plan lost original current Graph stamp')
    if not owner.sealed:
        if scope is not owner.fence.scope or current_owner is not owner.owner:
            raise AuthorityUnavailable('background selected plan has another actual READ owner/scope')
        owner.selected_plan,owner.selected_envelope=plan,envelope
        owner.selected_plans[envelope.identity.operation_id]=plan;owner.selected_envelopes[envelope.identity.operation_id]=envelope
    elif plan!=owner.selected_plans.get(envelope.identity.operation_id):
        raise AuthorityUnavailable('child operation changed its selected background plan')
    if owner.kind=="d07_stage":
        from .d07_stage_content_scope_v3 import HostD07StageContentScopeV3
        source=owner.d07_source_scope
        if type(source)is not HostD07StageContentScopeV3 or source.require_for_v3(owner).effective_source_authority!=envelope.authority:
            raise AuthorityUnavailable("D07 current frame changed actual Source actor/purpose")
        return PreparedBackgroundFrameInputsV3(_ISSUER,owner,plan,envelope,current_owner)
    if (envelope.authority.purpose not in current_owner.purposes
            or not set(envelope.authority.audience)<=set(current_owner.audiences)):
        raise AuthorityUnavailable('current child Owner does not authorize background purpose/audience')
    return PreparedBackgroundFrameInputsV3(_ISSUER,owner,plan,envelope,current_owner)


class BackgroundReadWorkV3:
    def __init__(self,issuer,graph,bootstrap,bundle,operation,*,kind,dedupe_key,context):
        if issuer is not _ISSUER:raise TypeError('actual background Work issuer required')
        self.graph,self.bootstrap,self.bundle=graph,bootstrap,bundle
        self.store,self.db=graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
        self.namespace=bundle.installation_policy.namespace
        self.operation,self.kind,self.dedupe_key,self.context=operation,kind,dedupe_key,context
        self.work=None;self.fence=None;self.read_scope=None;self.authority=None;self.owner=None;self.owner_guard=None
        self.columns=WeakSet();self.reserved=0;self.offline_lookups={};self.typed_digests={};self.role_clocks={};self.predecessors={};self.embedded_json={};self.offline_row_sources={}
        self.graph_stamp=graph._v2_graph_stamp(self.namespace);self.selection_digest=operation.selection_digest
        self.phase='algorithm' if kind=='offline_close' else 'd07_entry_locator' if kind=='d07_stage' else 'owner_locator';self.sealed=False;self.complete=False;self.result=None
        self.points={};self.inventories={};self.scans={};self.physical_payloads={};self.heads={};self.contact_plan_locators={};self.contact_source_components={};self.contact_active_component=None;self.contact_initial_component=None
        self.contact_plan_write=None;self.contact_plan_result=None
        self.pending=None;self.entry=None;self.entry_column=None;self.entry_metadata=None
        self.general_trial_census=None;self.general_trial_metadata={}
        self.selected_plan=None;self.selected_envelope=None;self.selected_plans={};self.selected_envelopes={};self.local_result=None
        self.d07_owner_entry=self.d07_content_scope_task=None
        self.d07_source_scope=self.d07_content_authority=self.d07_model_authority=None
        self.d07_stage_clock_utc=None
        self.d07_algorithm_binding=None;self.d07_validation_points=None;self.d07_validation_pending=None;self.d07_points_validated=False
        _READERS.add(self)
    def reserve_heap_v3(self,extra=0):
        _reserve_background_heap_v3(self,extra)
    def require_data_current_v3(self,meter):
        require_actual_background_attachment_owner_v3(self,db=self.db)
        if self.kind=='offline_close':
            if (self.context._v2_coordinator is not self.graph or self.context._worker is None
                    or self.context._v2_bootstrap is not self.bootstrap or self.context._host_lifecycle_startup_receipt is not None
                    or self.context._offline_recovery_stopping):raise AuthorityUnavailable('historical closure lost its actual pre-reconnect Host')
        if self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
            raise AuthorityUnavailable('background selected namespace changed during read EOF')
        if self.kind=='d07_stage':
            _require_background_d07_service_v3(self.graph,self.bootstrap,self.bundle,self.d07_service)
            if self.d07_selector.stage=="egress_seal":
                self.d07_model_seal_binding.require_current_data_v3(self,meter)
        self.operation.handle.require_current(meter)
    def require_current(self, *, meter=None):
        if self.kind=='artifact_model_dispatch':
            from .artifact_host_dispatch_source_v3 import require_artifact_host_dispatch_current_v3
            return require_artifact_host_dispatch_current_v3(self,meter)
        from .semantic_recovery_source_v3 import semantic_recovery_require_current_v3
        if self.kind != 'semantic_recovery' or meter is None:
            raise AuthorityUnavailable('Exact semantic metadata READ quantum required')
        return semantic_recovery_require_current_v3(self,meter)

    def require_request_v3(self,request):
        if self.kind=='artifact_model_dispatch':
            from .artifact_host_dispatch_source_v3 import require_artifact_host_dispatch_request_v3
            return require_artifact_host_dispatch_request_v3(self,request)
        if self.kind == 'semantic_recovery':
            from .semantic_recovery_source_v3 import semantic_recovery_require_request_v3
            return semantic_recovery_require_request_v3(self,request)
        table,columns,keys,key=request
        if table not in _POINT_KEYS or keys!=_POINT_KEYS[table]:raise AuthorityUnavailable('unregistered background exact SQL family')
        if table in _D07_POINT_COLUMNS and self.kind=='d07_stage':
            if self.kind!='d07_stage':raise AuthorityUnavailable('D07 stage family is outside this Background business kind')
            _require_background_d07_service_v3(self.graph,self.bootstrap,self.bundle,self.d07_service)
            if keys[:2]==('bot','persona') and key[:2]!=self.namespace.as_tuple:
                raise AuthorityUnavailable('D07 exact original crossed its actual namespace')
            if not set(columns)<=_D07_POINT_COLUMNS[table]|set(keys) or len(key)!=len(keys):
                raise AuthorityUnavailable('unregistered D07 original columns/key')
            if table=='graph_d07_execution_originals_v1':
                from .d07_execution_v1 import KINDS
                if key[2]not in KINDS:raise AuthorityUnavailable('unregistered signed D07 original kind')
            return
        if table in('graph_atoms','graph_history'):
            if (self.kind=="d07_stage" and self.d07_selector.stage=="egress_seal"
                    and table=="graph_atoms" and columns==("token","revision")):
                recipe=self.d07_model_seal_recipe.require_for_v3(self)
                actual=AtomKey.from_token(key[0])
                if (keys!=("token","bot","persona") or key[1:]!=self.namespace.as_tuple
                        or NamespaceId.from_key(actual)!=self.namespace
                        or actual.type_name not in recipe.plan.fixed_type_ids):
                    raise AuthorityUnavailable("D07 model seal metadata row crossed its original namespace/type")
                return
            atom=AtomKey.from_token(key[0])
            if NamespaceId.from_key(atom)!=self.namespace:raise AuthorityUnavailable('background exact head/history crossed namespace')
            self.store._registry.spec(atom.type_name)
        elif table.startswith('runtime_'):
            if table in('runtime_d11_owner_role_clock_originals_v1','runtime_d11_d04_root_freezes_v3'):
                if key[:2]!=self.namespace.as_tuple:raise AuthorityUnavailable('actual RoleClock/Root signed original crossed namespace')
            elif table == 'runtime_budget_grants' and tuple(key) in getattr(self, 'joint_budget_selectors', ()):
                pass
            elif self.kind not in('offline','offline_close','d07_stage'):
                if table not in('runtime_budget_grants','runtime_budget_leases'):
                    raise AuthorityUnavailable('historical budget originals require actual offline reader')
                from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
                command=self.handoff.command if self.kind=='followup_child'else None
                if type(command)is GeneralGrowthTrialFollowupCommandV1:
                    require_background_followup_handoff_v3(self.handoff,self.graph,self.bundle)
                    allowed=set(command.original_budget_ancestor_refs)|{command.parent_budget_lease_ref}
                    if not key or key[0]not in allowed:
                        raise AuthorityUnavailable('General budget point exceeds the signed Start ancestor set')
                else:
                    from .d07_general_growth_attention_v1 import require_general_growth_background_budget_point_v1
                    require_general_growth_background_budget_point_v1(self,table,key)
            if table=='runtime_budget_operations' and key[:2]!=self.namespace.as_tuple:raise AuthorityUnavailable('historical budget operation crossed namespace')
        elif key[:2]!=self.namespace.as_tuple:raise AuthorityUnavailable('background original crossed namespace')
        if table=='graph_d07_execution_originals_v1':
            if self.kind not in('followup','followup_child') or self.entry is None or self.entry[2]!='general_growth_attention_available_for_service':
                raise AuthorityUnavailable('General D07 original requires its actual registered service event')
            if not ((key[2]=='general_growth_attention_v1' and key[3].startswith('general-growth-attention-original:'))
                    or (key[2]=='semantic_question' and key[3].startswith('general-growth-question:'))):
                raise AuthorityUnavailable('General service original crossed exact metadata kind/locator')
        if table=='graph_d07_attention_issuance_v1':
            from .d07_general_growth_attention_v1 import general_growth_background_parent_v1
            if general_growth_background_parent_v1(self) is None or self.entry[2]!='general_growth_attention_available_for_service':
                raise AuthorityUnavailable('fair inventory issuance needs its actual General metadata parent')
        if table in _SIGNED_INPUT_KINDS:
            allowed={'revision','operation_id','original_json','original_digest','kind','original_ref','producing_operation_id','payload_json','payload_digest','signature','source_refs_json'}
            if not set(columns)<=allowed or len(key)!=len(keys):raise AuthorityUnavailable('unregistered background signed input columns/key')
            return
        allowed={
            'graph_contact_segment_originals_v1':set(('bot','persona','contact_id','segment_index','operation_id','effect_id','payload_json','payload_digest','signature')),
            'graph_contact_effect_originals_v1':{'payload_json','payload_digest','signature'},
            'graph_contact_effect_accounting_attempts_v1':{'origin_digest','fact_digest','request_json','state'},
            'runtime_resource_quotes':{'quote_json','signature'},
            'runtime_budget_grants':{'grant_json','signature'},
            'runtime_budget_leases':{'lease_id','parent_id','bot_id','persona_id','currency','limits_json','used_json','reserved_json','unconfirmed_json','version','state'},
            'graph_d07_execution_originals_v1':{'payload_json','payload_digest','signature'},
            'graph_d07_attention_issuance_v1':{'operation_id','c02_operation_id','bundle_digest'},
            'runtime_budget_reservations':{'state','digest','ceiling_json','actual_json'},
            'graph_owner_domain_attempts_v3':{'request_digest','attempt_id','permit_json'},
            'runtime_budget_operations':{'digest','lease_id','receipt_json'},
            'runtime_clock_operations':{'digest','mapping_id','version','mapping_json'},
            'graph_owner_goal_cancellation_projections_v1':set(("bot","persona","operation_id","goal_ref","root_registration_ref","core_original_ref","core_original_digest","observation_json","observation_digest","receipt_json","receipt_digest","signature")),
            'graph_events':{'digest','reads','revisions','epoch_revision','invalidated'},
            'graph_bundle_fences_v2':{'permit_json','pre_graph_revision','pre_graph_epoch','post_graph_revision','post_graph_epoch','finish_request_id','finish_request_digest'},
            'graph_atoms':{'revision','value','valid','type_name'},
            'graph_history':{'event_bot','event_persona','event_session','event_id','value','valid','dependencies'},
            'graph_domain_production_outbox_v1':{'causal_operation_id','receiver_domain','event_kind','original_ref','original_digest','state','receipt_json'},
            'graph_domain_production_originals_v1':{'domain','operation_kind','request_digest','original_digest','original_payload_json','read_versions_json','bundle_digest','receipt_json','receipt_digest'},
            'graph_domain_production_originals_v3':{'domain','operation_kind','request_digest','original_digest','original_payload_cell_id','prepared_digest','read_versions_json','bundle_digest','receipt_json','receipt_digest'},
            'graph_bundle_operations':{'digest','activity_id','effect_id','commit_seq','receipt_json'},
            'graph_d11_offline_originals_v1':{'kind','original_ref','producing_operation_id','payload_json','payload_digest','signature'},
            'graph_d10_production_inputs_v1':{'kind','original_ref','producing_operation_id','payload_json','payload_digest','signature','source_refs_json'},
            'graph_d07_execution_originals_v1':{'payload_json','payload_digest','signature'},
            'graph_d07_attention_issuance_v1':{'source_ref','c02_operation_id','bundle_digest'},
            'graph_d04_root_originals_v3':{'original_json','original_digest'},
            'graph_d04_originals_v3':{'original_ref','payload_json','payload_digest'},
            'graph_d04_joint_advances_v2':{'evidence_json','evidence_digest','bundle_digest'},
            'graph_d04_joint_numeric_originals_v1':{'numeric_receipt_json','numeric_receipt_digest','verification_json','verification_digest','evidence_digest'},
            'graph_d04_joint_output_originals_v1':{'evidence_digest','original_json','original_digest','write_set_digest'},
            'graph_d04_joint_advance_members_v2':{'checkpoint_ref','process_id','role_start','role_end'},
            'graph_owner_issue_operations_v1':{'operation_id','request_digest','grant_id','grant_digest','graph_incarnation','graph_access_epoch','graph_epoch','graph_receipt_digest','proof_json'},
            'graph_role_init_receipts_v1':{'receipt_json'},
            'graph_migration_import_receipts_v1':{'snapshot_digest','closure_digest','source_graph_revision','target_graph_revision','receipt_json'},
            'graph_c09_rebase_certificates_v1':{'operation_id','certificate_json'},
            'graph_recovery_metadata_v2':{'schema','requirements_json','graph_revision'},
            'graph_contact_expression_plan_originals_v2':{'bot','persona','contact_id','payload_json','payload_digest','signature'},
        }[table]
        if not set(columns)<=allowed or len(key)!=len(keys):raise AuthorityUnavailable('unregistered background original columns/key')
    def require_family_v3(self,type_id):
        if self.kind=='artifact_model_dispatch':
            from .artifact_host_dispatch_source_v3 import require_artifact_host_dispatch_family_v3
            return require_artifact_host_dispatch_family_v3(self,type_id)
        if self.kind == 'semantic_recovery':
            from .semantic_recovery_source_v3 import semantic_recovery_require_family_v3
            return semantic_recovery_require_family_v3(self,type_id)
        allowed=set(_FOLLOWUP_TYPES[self.entry[1]])if self.kind in('followup','followup_child')and self.entry is not None else set()
        if self.entry is not None and self.entry[2]=='general_growth_attention_available_for_service':
            allowed.update(('d07.focus.v1','d01.persona_activation.v1','d01.persona_plan.v1'))
        from .joint_node_execution_v1 import JOINT_EVENTS
        if self.kind in ('followup', 'followup_child') and self.entry is not None and self.entry[2] in JOINT_EVENTS | {'joint_external_semantic_question_requires_fair_cognition'}:
            allowed.update(('d08.joint_plan.v1', 'd08.action_intent.v1', 'd08.action_schema.v1', 'd08.action_cancellation.v1',
                'd08.action_outcome.v1', 'd08.goal.v1', 'd08.commitment.v1', 'd07.current_interpretation.v1',
                'd03.entity_anchor', 'd03.account_binding', 'd03.role_binding', 'd05.boundary_rule',
                'd10.life_progress.v1', 'd10.life_project.v1', 'd10.activity_recipe.v1', 'runtime.cost_settlement',
                'd07.attention_ticket.v1', 'd07.focus.v1', 'd07.concern_round.v1', 'd02.body_profile.v1', 'd02.body_state.v1', 'd02.reservation.v1'))
        for plan in self.selected_plans.values():allowed.update(plan.fixed_type_ids)
        if self.kind=='offline':allowed.add('d10.offline_checkpoint.v1')
        if self.role_clocks:allowed.update(('d04.numeric_checkpoint.v1','d04.numeric_checkpoint.v2','d03.role_binding'))
        if type_id not in allowed:raise AuthorityUnavailable('background fixed family has no selected business plan')
    def require_rows_request_v3(self,request):
        if self.kind=='artifact_model_dispatch':
            from .artifact_host_dispatch_source_v3 import require_artifact_host_dispatch_rows_v3
            return require_artifact_host_dispatch_rows_v3(self,request)
        if self.kind == 'semantic_recovery':
            from .semantic_recovery_source_v3 import semantic_recovery_require_rows_v3
            return semantic_recovery_require_rows_v3(self,request)
        table,columns,groups,group,order,limit=request
        if self.kind=="d07_stage" and self.d07_selector.stage=="egress_seal" and table=="graph_atoms":
            recipe=self.d07_model_seal_recipe.require_for_v3(self)
            if (columns!=("token","revision") or groups!=("bot","persona","type_name")
                    or order!=("token",) or limit!=129 or len(group)!=3
                    or group[:2]!=self.namespace.as_tuple or group[2]not in recipe.plan.fixed_type_ids):
                raise AuthorityUnavailable("D07 model seal query changed its exact signed original inventory")
            return
        if self.kind=='d07_stage' and table in('graph_d07_attention_issuance_v1','graph_first_ingress_identity_v1'):
            if groups!=('bot','persona','source_ref') or order!=('operation_id',) or limit not in(None,2):
                raise AuthorityUnavailable('D07 attention/ingress metadata inventory changed its closed shape')
            if len(group)!=3 or group[:2]!=self.namespace.as_tuple:
                raise AuthorityUnavailable('D07 attention/ingress inventory crossed namespace')
            if table=='graph_d07_attention_issuance_v1':
                source=AtomKey.from_token(group[2])
                if source.type_name!='memory.source' or NamespaceId.from_key(source)!=self.namespace:
                    raise AuthorityUnavailable('D07 attention inventory lacks its actual namespace Source locator')
            elif type(group[2])is not str or not group[2]:
                raise AuthorityUnavailable('D07 ingress inventory lacks its actual original Source identity')
            self.require_request_v3((table,columns,_POINT_KEYS[table],(*self.namespace.as_tuple,'pending')))
            return
        role_shapes={
            ('graph_c09_rebase_certificates_v1',('operation_id',),('bot','persona'),('operation_id',)),
            ('graph_d04_originals_v3',('original_ref',),('bot','persona','kind'),('original_ref',)),
            ('graph_d04_joint_advance_members_v2',('checkpoint_ref','process_id','role_start','role_end'),('bot','persona','operation_id'),('checkpoint_ref',)),
        }
        if (table,columns,groups,order)in role_shapes:
            if not self.role_clocks or group[:2]!=self.namespace.as_tuple or limit is not None:
                raise AuthorityUnavailable('RoleClock library metadata request changed its actual family')
            return
        if table=='graph_d07_attention_issuance_v1':
            from .d07_general_growth_attention_v1 import general_growth_background_parent_v1
            if (general_growth_background_parent_v1(self) is None or self.entry[2]!='general_growth_attention_available_for_service'
                    or columns!=('operation_id','c02_operation_id','bundle_digest') or groups!=('bot','persona','source_ref')
                    or group[:2]!=self.namespace.as_tuple or order!=('operation_id',) or limit!=2):
                raise AuthorityUnavailable('General complete fairness changed the actual bounded C02 issuance selector')
            return
        if table not in('graph_d11_offline_originals_v1','graph_d10_production_inputs_v1','graph_d08_joint_node_originals_v1') or groups!=('bot','persona','kind'):
            raise AuthorityUnavailable('unregistered background signed-original inventory')
        if group[:2]!=self.namespace.as_tuple or order!=('original_ref',)or limit not in(2,32,129):
            raise AuthorityUnavailable('background signed-original inventory changed namespace/order/original limit')
        self.require_request_v3((table,columns,_POINT_KEYS[table],tuple(self.namespace.as_tuple)+((group[2],'pending')if table=='graph_d11_offline_originals_v1'else('pending',))))
    def require_write_data_v3(self,db,scope,current_owner):
        require_actual_background_attachment_owner_v3(self,db=db)
        if (not self.sealed or not db.in_transaction or not self.store._lock._is_owned()
                or scope.namespace!=self.namespace or self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp
                or current_owner is None or current_owner.namespace!=self.namespace
                or (current_owner.access_epoch,current_owner.delete_epoch)!=(self.owner.access_epoch,self.owner.delete_epoch)):
            raise AuthorityUnavailable('background READ evidence changed before fresh child WRITE qualification')
        if self.kind=="d07_stage" and self.d07_selector.stage!="egress_seal":
            from .d07_stage_content_scope_v3 import HostD07StageContentScopeV3
            if type(self.d07_source_scope)is not HostD07StageContentScopeV3:
                raise AuthorityUnavailable("fresh D07 WRITE lacks actual same retained Source scope")
            self.d07_source_scope.require_for_v3(self)
            if self.d07_content_scope_task.write_scope is not scope:
                raise AuthorityUnavailable("fresh D07 WRITE did not independently observe actual Source permission")
        # Only local data is reused. The caller supplies its newly observed actual WRITE scope/Owner.
        if (scope.graph_revision,scope.graph_epoch)!=(self.graph_stamp[0].graph_revision,self.graph_stamp[1]):
            raise AuthorityUnavailable('background child WRITE lost original data stamp')
    def release_payload_v3(self):
        if self.kind=='artifact_model_dispatch':
            from .artifact_host_dispatch_source_v3 import release_artifact_host_dispatch_payload_v3
            release_artifact_host_dispatch_payload_v3(self)
        if self.kind == 'semantic_recovery':
            from .semantic_recovery_source_v3 import release_semantic_recovery_payload_v3
            release_semantic_recovery_payload_v3(self)
        from .d07_general_growth_attention_v1 import release_general_growth_source_metadata_v1
        release_general_growth_source_metadata_v1(self)
        self.general_trial_census=None;self.general_trial_metadata.clear()
        if self.kind=="d07_stage":
            scope=getattr(self,"d07_source_scope",None)
            task=getattr(self,"d07_content_scope_task",None)
            if task is not None:
                if scope is not None:scope.release_v3()
                else:task.release_v3()
            entry=getattr(self,"d07_owner_entry",None)
            if entry is not None:entry.release_v3()
            self.d07_content_scope_task=self.d07_owner_entry=None
            source_task=getattr(self,"d07_source_qualification",None)
            material=getattr(self,"d07_source_material",None)
            if material is not None:_D07_SOURCE_MATERIALS_V3.pop(material,None)
            if source_task is not None:
                for witness in source_task.witnesses.values():_D07_SOURCE_METADATA_V3.pop(witness,None)
                if getattr(source_task,"witness",None) is not None:_D07_SOURCE_METADATA_V3.pop(source_task.witness,None)
            self.d07_source_material=self.d07_source_qualification=self.d07_suspended_source_point=None
            recipe=getattr(self,"d07_model_seal_recipe",None)
            if recipe is not None:recipe.release_v3()
            self.d07_model_seal_recipe=None
            model_binding=getattr(self,"d07_model_seal_binding",None)
            if model_binding is not None:model_binding.release_v3()
            self.d07_model_seal_binding=self.d07_egress_pair=None
            self.d07_source_scope=self.d07_content_authority=self.d07_model_authority=None
        self.d07_algorithm_binding=self.d07_validation_points=self.d07_validation_pending=None;self.d07_points_validated=False
        self.points.clear();self.inventories.clear();self.scans.clear();self.physical_payloads.clear();self.heads.clear()
        for locator in self.contact_plan_locators.values():locator.release_v3()
        self.contact_plan_locators.clear()
        for component in self.contact_source_components.values():component.release_payload_v3()
        self.contact_source_components.clear();self.contact_active_component=None
        if self.contact_initial_component is not None:self.contact_initial_component.release_payload_v3()
        self.contact_initial_component=None
        self.pending=self.entry_column=self.entry_metadata=self.local_result=self.result=None
        self.selected_plan=self.selected_envelope=None
        self.selected_plans.clear();self.selected_envelopes.clear();self.typed_digests.clear();self.offline_lookups.clear()
        for role in self.role_clocks.values():
            if role.steps is not None:role.steps.close()
        self.role_clocks.clear()
        for predecessor in self.predecessors.values():
            if predecessor.steps is not None:predecessor.steps.close()
        self.predecessors.clear();self.embedded_json.clear();self.offline_row_sources.clear()



def _frozen_heap_v3(value,seen):
    from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
    if id(value)in seen:return 0
    if type(value)is _FrozenObjectV3:
        size=_heap(value,seen)+_heap(tuple(k for k,_ in value.items),seen)
        return size+sum(_frozen_heap_v3(v,seen)for _,v in value.items)
    if type(value)is _FrozenArrayV3:
        return _heap(value,seen)+sum(_frozen_heap_v3(v,seen)for v in value.items)
    return _heap(value,seen)


def _reserve_background_heap_v3(owner,extra=0):
    seen=set();size=_heap((owner.entry,owner.entry_metadata,owner.heads,
        (owner.entry_column.metadata,owner.entry_column.job_metadata)if type(owner.entry_column)is _BackgroundD07EntryLocatorV3 else ()),seen)+65536+extra
    size+=sum(_heap((point.metadata,point.small,point.pending,point.request),seen)for point in owner.points.values())
    size+=sum(_heap((task.after,task.rows),seen)for task in owner.scans.values())
    if owner.general_trial_census is not None:
        task=owner.general_trial_census
        size+=_heap((task.criterion,task.after,task.matches,task.prior_points,task.prior_physical,task.root),seen)
    size+=sum(_general_growth_background_task_heap_v1(task,seen)for task in owner.general_trial_metadata.values())
    if owner.kind=='followup_child':size+=_general_growth_background_payload_heap_v1(owner.handoff.command,seen)
    size+=sum(_heap(tuple((atom.key,atom.revision,atom.valid,atom.value)for atom in task.rows),seen)for task in owner.inventories.values())
    size+=sum(_heap((task.material,task.value),seen) for task in owner.typed_digests.values())
    size+=sum(_heap((task.args,task.result),seen) for task in owner.predecessors.values())
    size+=sum(_heap((task.nodes,task.value,task.scalar,task.text_parts,task.text_chars),seen)+_frozen_heap_v3(task.frozen,seen) for task in owner.embedded_json.values())
    size+=sum(_heap((task.selections,None if task.proof is None else task.proof.inputs),seen) for task in owner.role_clocks.values())
    size+=sum(_heap((task.after,task.rows, None if task.pending is None else task.pending.metadata),seen) for task in owner.offline_lookups.values())
    for column in owner.columns:
        size+=_heap((column.nodes,column.value,column.scalar,column.text_parts,column.text_chars,column.fragment,
            column.fields_seen if type(column)is _D07PreparedLocatorColumnV3 else ()),seen)
        size+=_frozen_heap_v3(column.frozen,seen)
    if owner.local_result is not None:
        if owner.general_trial_census is not None:size+=_general_growth_background_payload_heap_v1(owner.local_result,seen)
        from dataclasses import is_dataclass,fields
        for item in owner.local_result if type(owner.local_result)is tuple else (owner.local_result,):
            if is_dataclass(item):size+=_heap(tuple(getattr(item,f.name)for f in fields(item)),seen)
            else:size+=_heap(item,seen)
    if size>owner.reserved:owner.operation.retain(size-owner.reserved);owner.reserved=size



class _BackgroundEntryLocatorV3:
    def __init__(self,owner):
        self.owner=owner;self.phase='outbox';self.column=None;self.complete=False;self.entry=None;self.metadata=None
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .domain_production_originals_v1 import TABLE,PHYSICAL_TABLE
        o=self.owner;o.require_data_current_v3(meter)
        if self.phase=='outbox':
            self.entry=_runtime_bounded_fixed_row_v3(o.db,meter,'graph_domain_production_outbox_v1',
                ('causal_operation_id','receiver_domain','event_kind','original_ref','original_digest','state'),
                'bot=? AND persona=? AND dedupe_key=?',(*o.namespace.as_tuple,o.dedupe_key))
            if self.entry is None or self.entry[5]not in('pending','waiting','completed'):
                raise AuthorityUnavailable('background entry has no actual durable outbox')
            self.phase='original';return
        if self.phase=='original':
            key=(*o.namespace.as_tuple,self.entry[0]);keys=('bot','persona','operation_id')
            self.metadata=_runtime_bounded_fixed_row_v3(o.db,meter,TABLE,('domain','operation_kind','original_digest'),
                'bot=? AND persona=? AND operation_id=?',key)
            table,column,cell=TABLE,'original_payload_json',None
            if self.metadata is None:
                physical=_runtime_bounded_fixed_row_v3(o.db,meter,PHYSICAL_TABLE,
                    ('domain','operation_kind','original_digest','original_payload_cell_id','prepared_digest'),
                    'bot=? AND persona=? AND operation_id=?',key)
                if physical is None:raise AuthorityUnavailable('background outbox lost causal adopted original')
                self.metadata=physical[:3];table,column,cell=PHYSICAL_TABLE,'original_payload_json',physical[3]
            self.column=BackgroundJSONColumnV3(_ISSUER,o,table=table,column=column,key_columns=keys,key=key,cell_id=cell,locator=True)
            self.phase='payload';return
        if self.column.advance(meter):
            if self.column.sha256!=self.metadata[2]:raise AuthorityUnavailable('background authority locator differs from causal original digest')
            projected=_detach_value_v3(self.column.frozen)
            if (projected.get('namespace')!={'bot_id':o.namespace.bot_id,'persona_id':o.namespace.persona_id}
                    or projected.get('identity',{}).get('operation_id')!=self.entry[0]):
                raise AuthorityUnavailable('background authority locator crossed actual causal namespace/operation')
            o.entry,o.entry_metadata=self.entry,(self.metadata,projected)
            self.complete=True



class _D07PreparedLocatorColumnV3(BackgroundJSONColumnV3):
    """Prepared identity/authority metadata only, with full original canonical byte EOF."""
    def __init__(self,issuer,owner,**kwargs):
        self.fields_seen=set()
        super().__init__(issuer,owner,**kwargs)
    def retain_path_v3(self,path):
        if not path:return True
        if path[0]=="read_rows":
            return len(path)<=2 or len(path)==3 and path[2] in {"ref","revision","valid"}
        return path[0]in _D07_LOCATOR_FIELDS
    def _emit_v3(self,event):
        if event.kind=='key' and len(event.path)==1:self.fields_seen.add(event.key)
        super()._emit_v3(event)


class _BackgroundD07EntryLocatorV3:
    def __init__(self,owner):
        self.owner=owner;self.phase='job';self.column=None;self.metadata=None;self.job_metadata=None;self.complete=False
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .d07_execution_v1 import TABLE,SIGN_KIND,D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3
        from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
        from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
        from dataclasses import fields
        o=self.owner;o.require_data_current_v3(meter)
        if self.phase=='job':
            self.job_metadata=_runtime_bounded_fixed_row_v3(o.db,meter,'runtime_jobs',
                ('job_id','operation_id','bot_id','persona_id','work_kind','phase','deadline_utc'),
                'job_id=?',(o.d07_selector.parent_job_id,))
            if self.job_metadata is None or self.job_metadata[2:4]!=o.namespace.as_tuple:
                raise AuthorityUnavailable('D07 actual parent job metadata is absent or crosses namespace')
            self.phase='original';return
        if self.phase=='original':
            key=(*o.namespace.as_tuple,'prepared',o.d07_selector.parent_job_id)
            self.metadata=_runtime_bounded_fixed_row_v3(o.db,meter,TABLE,('payload_digest','signature'),
                'bot=? AND persona=? AND kind=? AND original_ref=?',key)
            if self.metadata is None:raise AuthorityUnavailable('D07 stage lost its actual immutable parent prepared original')
            self.column=_D07PreparedLocatorColumnV3(_ISSUER,o,table=TABLE,column='payload_json',
                key_columns=('bot','persona','kind','original_ref'),key=key,locator=True)
            self.phase='payload';return
        if self.column.advance(meter):
            if self.column.sha256!=self.metadata[0]:
                raise AuthorityUnavailable('D07 prepared metadata locator differs from actual payload digest')
            o.d07_service.d11_issuer._signer.verify(SIGN_KIND,
                canonical_serialize((o.namespace,'prepared',o.d07_selector.parent_job_id,self.metadata[0])),self.metadata[1])
            projected=_detach_value_v3(self.column.frozen)
            classes={'d07.prepared-execution.v1':D07PreparedExecutionV1,
                'd07.relationship-prepared.v2':D07RelationshipPreparedV2,'d07.method-growth-prepared.v2':D07MethodGrowthPreparedV2,
                'd07.reflection-prepared.v3':D07ReflectionPreparedV3,
                'd07.general-growth-prepared.v1':D07GeneralGrowthPreparedV1}
            actual=classes.get(projected.get('schema'))
            if actual is None or self.column.fields_seen!={item.name for item in fields(actual)}:
                raise AuthorityUnavailable('D07 stage parent has another registered complete prepared schema')
            if (projected.get('namespace')!={'bot_id':o.namespace.bot_id,'persona_id':o.namespace.persona_id}
                    or projected.get('job_id')!=o.d07_selector.parent_job_id
                    or (projected.get('job_id'),projected.get('operation_id'))!=self.job_metadata[:2]
                    or self.job_metadata[4]!='d07.'+projected.get('work_kind','')):
                raise AuthorityUnavailable('D07 prepared locator crossed actual parent namespace/job/operation')
            if actual is D07ReflectionPreparedV3:
                _require_reflection_locator_metadata_v3(o,projected)
            o.entry_metadata=(self.metadata,projected);self.complete=True


class PreparedBackgroundOperationV3:
    def __init__(self,issuer,owner):
        if issuer is not _ISSUER or not owner.complete or not owner.sealed:
            raise TypeError('successful actual background preparation required')
        self.owner=owner;self.graph=owner.graph;self.db=owner.db;self.operation=owner.operation;self.kind=owner.kind
        self.local_result=owner.local_result
        _PREPARED.add(self)
    def require_v3(self,graph):
        if self not in _PREPARED or self.graph is not graph:raise AuthorityUnavailable('actual background preparation result required')
        require_actual_background_attachment_owner_v3(self.owner,db=self.db)
        return self
    def release_payload_v3(self):
        _PREPARED.discard(self);self.owner.release_payload_v3();self.local_result=None


def read_bound_background_frame_inputs_v3(db,**kwargs):
    if _active_v3(db)is None:return False,None
    return True,require_background_prepared_frame_inputs_v3(db,**kwargs)


def _background_authority_v3(reader):
    from ..runtime_contracts import AuthorityContext
    from ..authority_service.v2_owner_contract import OwnerPrincipalV1
    from ..graph_types import validate_owner_grant_v1
    o=reader
    if o.kind=="d07_stage":
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        original=decode_typed_production_value_v1(json.loads(o.entry_metadata[1]["owner_authority_json"]),AuthorityContext)
        if (original.namespace!=o.namespace or original.purpose!=o.entry_metadata[1]["purpose"]
                or tuple(original.audience)!=tuple(o.entry_metadata[1]["audience"])
                or original.activation_generation!=o.graph_stamp[0].requirements.activation_generation):
            raise AuthorityUnavailable("Host Stage READ admission differs from signed parent metadata")
        return original
    key=owner_grant_key(*o.namespace.as_tuple)
    request=('graph_atoms',('revision','value','valid'),('token','bot','persona'),(key.token,*o.namespace.as_tuple))
    point=o.points[request];row=point.row
    if row is None or row[2]!=1:raise AuthorityUnavailable('background current Owner locator is absent')
    grant=background_json_loads_v3(row[1]);validate_owner_grant_v1(grant)
    principal=OwnerPrincipalV1(**grant['principal']);metadata=o.graph_stamp[0]
    port=o.graph._GraphCoordinator__content_fence_v2
    pairing=port.current_owner_principal_binding(namespace=o.namespace,
        authority_namespace=metadata.requirements.authority_namespace,principal=principal)
    if pairing is None:raise AuthorityUnavailable('background current Owner locator has no actual pairing')
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    command=o.handoff.command if o.kind=='followup_child'else None
    if type(command)is GeneralGrowthTrialFollowupCommandV1:
        require_background_followup_handoff_v3(o.handoff,o.graph,o.bundle)
        origin=command.source_authority
        if (origin.namespace!=o.namespace or origin.actor!=pairing.actor_id
                or principal!=o.handoff.owner_principal or o.operation.deadline_utc!=command.original_deadline_utc):
            raise AuthorityUnavailable('General Start actor/principal/namespace/original deadline changed before its fresh READ')
        purpose=origin.purpose;audiences=origin.audience;domains=origin.owner_scope
    elif o.kind in('followup','followup_child'):
        raw=o.entry_metadata[1]['authority'];purpose=raw['purpose'];audiences=tuple(raw['audience']);domains=tuple(raw['owner_scope'])
    elif o.kind=='host_lifecycle':
        purpose=o.local_result[1][0];audiences=o.local_result[0];domains=('d06','d11')
    else:purpose=grant['purposes'][0];audiences=(grant['audiences'][0],);domains=('d02','d06','d10','d11')
    return AuthorityContext(pairing.actor_id,'d10'if o.kind=='offline'else'd11'if o.kind=='host_lifecycle'else'd12',
        'installed-background:'+o.operation.operation_id,o.namespace,domains,purpose,audiences,
        port.installation_grant.publisher_policy_ref,metadata.requirements.activation_generation)


def prepare_domain_background_read_v3(graph,bootstrap,installed_bundle,*,kind,operation_id,deadline_utc,dedupe_key=None,context=None,observer=None,observation=None,d07_selector=None,d07_service=None,d07_model_seal_binding=None):
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,finish_runtime_storage_operation_v3
    from ..runtime_context import RuntimeContext
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    if kind not in('followup','followup_child','offline','offline_close','host_lifecycle','d07_stage'):raise ValueError('unregistered background business kind')
    if kind=='d07_stage':
        if type(d07_selector)is not D07StageReadSelectorV3:
            raise TypeError('exact closed D07 stage selector required')
        _require_background_d07_service_v3(graph,bootstrap,installed_bundle,d07_service)
        if context is not None and context is not d07_service.context:
            raise AuthorityUnavailable('D07 stage cannot substitute the actual installed Host context')
    elif kind in('followup','followup_child'):
        assembly=graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None or assembly.admin_bundle is not installed_bundle:raise AuthorityUnavailable('actual installed followup bundle required')
        if type(dedupe_key)is not str or not dedupe_key:raise ValueError('actual outbox dedupe key required')
    else:
        if (type(context)is not RuntimeContext or context._v2_coordinator is not graph or context._v2_bootstrap is not bootstrap
                or context._v2_model_bundle is not installed_bundle or context._worker is None):
            raise AuthorityUnavailable('actual installed Host background constructor required')
        if kind=='offline'and(context._offline_recovery_stopping or context._host_lifecycle_startup_receipt is None):
            raise AuthorityUnavailable('offline recovery requires actual committed Host reconnect')
        if kind=='offline_close' and (context._host_lifecycle_startup_receipt is not None or context._offline_recovery_stopping):
            raise AuthorityUnavailable('historical closure requires exact pre-reconnect actual Host')
        if kind=='host_lifecycle':
            from .d11_host_lifecycle_v1 import InstalledHostLifecycleObserverV1
            if type(observer)is not InstalledHostLifecycleObserverV1 or observer.context is not context:
                raise AuthorityUnavailable('actual installed Host lifecycle observer required')
            observer.verify_observation_v1(observation)
    db=graph._GraphCoordinator__store._db
    operation=begin_runtime_storage_operation_v3(db,operation_id,deadline_utc)
    try:
        with bind_runtime_storage_operation_v3(operation,db):
            reader=BackgroundReadWorkV3(_ISSUER,graph,bootstrap,installed_bundle,operation,kind=kind,dedupe_key=dedupe_key,context=context)
            reader.observer,reader.observation=observer,observation
            reader.d07_selector,reader.d07_service=d07_selector,d07_service
            if kind=='d07_stage' and d07_selector.stage=="egress_seal":
                from ..authority_service.owner_location_read_v3 import D07ActualModelSealReadBindingV3
                if type(d07_model_seal_binding) is not D07ActualModelSealReadBindingV3:
                    raise AuthorityUnavailable("D07 seal Work requires its exact already-admitted model permit binding")
                d07_model_seal_binding.require_for_work_v3(graph,d07_service,installed_bundle,operation)
                reader.d07_model_seal_binding=d07_model_seal_binding
            from .first_ingress_v2 import trusted_upper
            reader.now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
            work=create_graph_storage_work_v3(graph,kind='domain_background_read_v3',operation_id=operation_id,
                selection_digest=operation.selection_digest,deadline_utc=deadline_utc,state=reader,operation=operation)
            reader.work=work
        return work
    except BaseException:
        finish_runtime_storage_operation_v3(operation);raise


def _prepare_background_algorithm_v3(reader):
    if reader.kind=='d07_stage':
        from .d07_graph_stages_v1 import prepare_d07_stage_read_data_v3
        return prepare_d07_stage_read_data_v3(reader)
    if reader.kind in('followup','followup_child'):
        from .domain_followup_consumer_v1 import prepare_background_followup_data_v3
        return prepare_background_followup_data_v3(reader)
    if reader.kind in('offline','offline_close'):
        from .d10_offline_recovery_driver_v1 import prepare_background_offline_data_v3
        return prepare_background_offline_data_v3(reader)
    from .d11_host_lifecycle_driver_v1 import prepare_background_host_lifecycle_data_v3
    return prepare_background_host_lifecycle_data_v3(reader)


def _advance_background_pending_v3(reader,meter):
    pending=reader.pending
    if pending is None:return
    if not pending.complete:
        if type(pending)is _GeneralGrowthStartMetadataCensusV1:
            try:pending.advance(meter)
            except BackgroundReadNeededV3 as needed:
                _start_background_request_v3(reader,needed.request)
                pending.dependency=reader.pending;reader.pending=pending
        else:
            if any(task is pending for task in reader.general_trial_metadata.values()):reader.reserve_heap_v3(extra=8192)
            pending.advance(meter)
    if pending.complete:reader.pending=None


def _start_background_request_v3(reader,request):
    kind=request[0]
    if reader.kind=='artifact_model_dispatch'and kind=='artifact_host_life_parent_metadata':
        from .artifact_host_dispatch_source_v3 import start_artifact_host_life_parent_metadata_v3
        return start_artifact_host_life_parent_metadata_v3(reader,request)
    if reader.kind=='artifact_model_dispatch'and kind=='artifact_host_signed_input_metadata':
        from .artifact_host_dispatch_source_v3 import start_artifact_host_signed_input_metadata_v3
        return start_artifact_host_signed_input_metadata_v3(reader,request)
    if reader.kind=='artifact_model_dispatch'and kind=='artifact_host_original_metadata':
        from .artifact_host_dispatch_source_v3 import start_artifact_host_original_metadata_v3
        return start_artifact_host_original_metadata_v3(reader,request)
    if kind=='contact_initial_source':
        from .contact_initial_plan_source_v3 import _ISSUER as CONTACT_INITIAL,InitialContactPlanSourceReadV3
        selector=request[1]
        task=reader.contact_initial_component
        if task is None:
            task=InitialContactPlanSourceReadV3(CONTACT_INITIAL,reader,selector)
            reader.contact_initial_component=task
        elif task.selector!=selector:
            raise AuthorityUnavailable('initial Contact Source request changed its authenticated causal selector')
        reader.pending=task
        return
    if kind == 'contact_domain_attachment':
        from .contact_domain_source_work_v3 import ContactDomainAttachmentReadV3
        _,contact_id,phase,actual = request
        component = reader.contact_source_components.get((contact_id,phase))
        if component is None or component is not reader.contact_active_component:
            raise AuthorityUnavailable('Contact domain attachment lost its actual qualified phase component')
        reader.pending = ContactDomainAttachmentReadV3(component,actual)
        return
    if kind == 'contact_domain_source':
        from .contact_domain_source_work_v3 import ContactDomainSelectorV3,prepare_contact_domain_source_read_v3
        _,contact_id,phase = request
        identity = (contact_id,phase)
        task = reader.contact_source_components.get(identity)
        if task is None:
            selector = ContactDomainSelectorV3(reader.namespace,contact_id,phase,reader.dedupe_key)
            task = prepare_contact_domain_source_read_v3(reader,selector)
            reader.contact_source_components[identity] = task
        reader.contact_active_component = task
        reader.pending = task
        return
    if kind == 'contact_plan_locator':
        task = reader.contact_plan_locators.get(request[1])
        if task is None:
            task = _ContactBackgroundPlanLocatorReadV3(reader,request)
            reader.contact_plan_locators[request[1]] = task
        reader.pending = task
        return
    if kind=='d01_general_input_metadata':
        require_current_general_growth_trial_metadata_reader_v1(reader)
        from .d01_general_growth_v1 import create_current_general_background_metadata_task_v1
        reader.reserve_heap_v3(extra=8192)
        task=create_current_general_background_metadata_task_v1(reader,request[1])
        reader.general_trial_metadata[request[1]]=task
    elif kind=='general_growth_start_metadata_census_v1':
        task=_GeneralGrowthStartMetadataCensusV1(reader,request[1]);reader.general_trial_census=task
    elif kind=='general_growth_source_metadata':
        from .d07_general_growth_attention_v1 import start_general_growth_source_metadata_task_v1
        task=start_general_growth_source_metadata_task_v1(reader,request[1])
    elif kind=='point':
        actual=request[1];reader.require_request_v3(actual)
        task=reader.points.get(actual)
        if task is None:task=_BackgroundPointReadV3(reader,actual);reader.points[actual]=task
    elif kind=='inventory':
        type_id=request[1];reader.require_family_v3(type_id)
        task=reader.inventories.get(type_id)
        if task is None:task=_BackgroundInventoryReadV3(reader,type_id);reader.inventories[type_id]=task
    elif kind=='rows':
        actual=request[1];reader.require_rows_request_v3(actual)
        task=reader.scans.get(actual)
        if task is None:task=_BackgroundRowsReadV3(reader,actual);reader.scans[actual]=task
    elif kind=='physical_payload':
        op,row=request[1:]
        task=reader.physical_payloads.get(op)
        if task is None:
            from .domain_production_originals_v1 import PHYSICAL_TABLE
            task=BackgroundJSONColumnV3(_ISSUER,reader,table=PHYSICAL_TABLE,column='original_payload_json',
                key_columns=('bot','persona','operation_id'),key=(*reader.namespace.as_tuple,op),cell_id=row[4])
            reader.physical_payloads[op]=task
    elif kind=='offline_lookup':
        task=_BackgroundOfflineLookupV3(reader,request[1:]);reader.offline_lookups[request[1:]]=task
    elif kind=='role_clock_inputs':
        actual_reader=request[1];task=reader.role_clocks.get(actual_reader)
        if task is None:task=_BackgroundRoleClockReadV3(_ISSUER,reader,actual_reader);reader.role_clocks[actual_reader]=task
    elif kind=='embedded_json':
        column,path=request[1:];identity=(column,path);task=reader.embedded_json.get(identity)
        if task is None:task=_BackgroundEmbeddedJSONV3(reader,column,path);reader.embedded_json[identity]=task
    elif kind=='authored_predecessor':
        identity,args=request[1:];task=reader.predecessors.get(identity)
        if task is None:task=_BackgroundAuthoredPredecessorReadV3(reader,args);reader.predecessors[identity]=task
    elif kind=='typed_digest':
        column,value=request[1:];task=_BackgroundTypedDigestV3(reader,column,value);reader.typed_digests[column]=task
    elif kind=="d07_source_rights":
        if reader.d07_selector.stage!="egress_seal" and reader.d07_source_scope is not None and request[1]not in reader.d07_source_scope.source_refs:
            raise AuthorityUnavailable("D07 body cannot expand the actual qualified Source family")
        if reader.kind!="d07_stage":raise AuthorityUnavailable("D07 Source body request has another Work")
        task=reader.d07_source_qualification
        token=request[1]
        atom=AtomKey.from_token(token)
        if NamespaceId.from_key(atom)!=reader.namespace or atom.type_name!="memory.source":
            raise AuthorityUnavailable("D07 derived plan Source root crossed its exact namespace")
        task.complete=False
        task.pending.append(token)
        reader.d07_suspended_source_point=reader.pending
        reader.pending=None
        reader.phase="d07_source_qualification"
        return
    else:raise AuthorityUnavailable('unregistered background local preparation request')
    reader.pending=task


def advance_domain_background_read_v3(graph,work):
    if work.state.kind=='artifact_model_dispatch':
        from .artifact_host_dispatch_source_v3 import advance_artifact_host_dispatch_read_v3
        return advance_artifact_host_dispatch_read_v3(graph,work)
    if work.state.kind == 'semantic_recovery':
        from .semantic_recovery_source_v3 import advance_semantic_recovery_read_v3
        return advance_semantic_recovery_read_v3(graph,work)
    from ..graph_worker import GraphStorageStepV3
    from .domain_followup_consumer_v1 import _observe_owner
    from .first_ingress_v2 import trusted_upper
    reader=work.state;require_actual_background_attachment_owner_v3(reader,db=reader.db)
    with bind_runtime_storage_operation_v3(reader.operation,reader.db):
        if reader.phase=='contact_plan_write':
            from .contact_plan_physical_write_v3 import advance_contact_plan_write_v3
            return advance_contact_plan_write_v3(graph,work)
        from .contact_domain_source_work_v3 import ContactDomainSourceReadV3
        from .contact_initial_plan_source_v3 import InitialContactPlanSourceReadV3
        if type(reader.pending) in (ContactDomainSourceReadV3,InitialContactPlanSourceReadV3) and reader.pending.phase in {'policy','protected'}:
            component = reader.pending
            component.observe_current_v3()
            if component.phase == 'policy':
                component.phase = 'source'
            else:
                component.complete = True
                reader.pending = None
            return GraphStorageStepV3('progress')
        if reader.phase=='authorize' and reader.kind=="d07_stage" and reader.d07_selector.stage=="egress_seal":
            binding=reader.d07_model_seal_binding
            binding.observe_current_for_work_v3(reader)
            reader.authority,reader.owner_guard,reader.owner=binding.owner_acl_authority,binding.owner_guard,binding.owner
            reader.d07_model_authority=binding.model_authority
            reader.d07_source_scope=binding.content_source_scope
            reader.d07_content_authority=reader.d07_source_scope.effective_source_authority
            reader.read_scope=binding.scope
            reader.graph_stamp=binding.graph_stamp
            reader.phase="d07_source_qualification"
            return GraphStorageStepV3("progress")
        if reader.phase=="authorize" and reader.kind=="d07_stage":
            from ..authority_service.owner_location_read_v3 import prepare_current_host_d07_stage_owner_entry_v3
            reader.authority=_background_authority_v3(reader)
            reader.fence=graph._begin_read_fence_v3(reader.authority,operation_id=reader.operation.operation_id)
            reader.read_scope=reader.fence.scope;reader.graph_stamp=(reader.fence.metadata,reader.fence.epoch)
            reader.d07_owner_entry=prepare_current_host_d07_stage_owner_entry_v3(reader)
            reader.owner=reader.d07_owner_entry.require_for_v3(reader)
            reader.owner_guard=reader.d07_owner_entry.current_owner_guard
            reader.authority=reader.d07_owner_entry.owner_acl_authority
            reader.phase="d07_content_scope"
            return GraphStorageStepV3("progress")
        if reader.phase=="d07_content_scope":
            from .d07_stage_content_scope_v3 import prepare_current_host_d07_stage_content_scope_v3
            reader.d07_source_scope=prepare_current_host_d07_stage_content_scope_v3(reader)
            reader.d07_content_authority=reader.d07_source_scope.effective_source_authority
            reader.phase="algorithm"
            return GraphStorageStepV3("progress")
        if reader.phase=='authorize':
            reader.authority=_background_authority_v3(reader)
            captured=[]
            def observe(scope):
                actual=_observe_owner(graph,reader.authority,scope);captured[:]=[actual];return actual
            reader.fence=graph._begin_read_fence_v3(reader.authority,operation_id=reader.operation.operation_id,fence_observer=observe)
            reader.owner_guard,reader.owner=captured[0]
            reader.read_scope=reader.fence.scope
            reader.graph_stamp=(reader.fence.metadata,reader.fence.epoch)
            reader.phase='d07_source_qualification' if reader.kind=="d07_stage" else 'algorithm'
            return GraphStorageStepV3('progress')
        if reader.phase=='protected':
            if reader.kind=='d07_stage' and not reader.d07_points_validated:
                raise AuthorityUnavailable('D07 final READ certificate lacks complete point validation')
            if reader.kind=='offline_close':
                reader.sealed=True;reader.complete=True
                reader.result=PreparedBackgroundOperationV3(_ISSUER,reader)
                return GraphStorageStepV3('complete',reader.result)
            if reader.kind=="d07_stage" and reader.d07_selector.stage=="egress_seal":
                binding=reader.d07_model_seal_binding
                binding.observe_current_for_work_v3(reader)
                guard,owner=binding.owner_guard,binding.owner
            else:
                graph._validate_read_fence_v3(reader.fence)
                if reader.kind=="d07_stage":
                    owner=reader.d07_owner_entry.require_for_v3(reader);guard=reader.d07_owner_entry.current_owner_guard
                else:guard,owner=_observe_owner(graph,reader.authority,reader.fence.scope)
            if (guard,owner)!=(reader.owner_guard,reader.owner):raise AuthorityUnavailable('background final actual Owner changed')
            reader.sealed=True;reader.complete=True
            reader.result=PreparedBackgroundOperationV3(_ISSUER,reader)
            command = reader.local_result[6] if reader.kind=='followup_child' else None
            if command is not None and command.operation_kind=='adopt_contact_expression_plan_v2':
                from .domain_followup_consumer_v1 import finish_background_followup_preparation_v3
                graph._finish_read_fence_v3(reader.fence)
                reader.fence = None
                reader.contact_plan_write = finish_background_followup_preparation_v3(graph,reader.result,
                    contact_plan_parent=reader)
                reader.complete,reader.phase = False,'contact_plan_write'
                return GraphStorageStepV3('progress')
            return GraphStorageStepV3('complete',reader.result)
        if reader.kind=="d07_stage" and reader.d07_selector.stage!="egress_seal" and reader.d07_content_scope_task is not None:
            from .d07_stage_content_scope_v3 import require_current_host_d07_stage_source_permission_v3
            require_current_host_d07_stage_source_permission_v3(reader)
        if reader.fence is not None:graph._validate_read_fence_v3(reader.fence)
        actual_reader=graph._GraphCoordinator__d04_semantic_mapping_reader
        role_progress=reader.role_clocks.get(actual_reader)
        host_fence=(actual_reader.current_fence(reader.fence.scope) if role_progress is not None
            and role_progress.phase!='selections' else nullcontext())
        d07_validation_eof=False;d07_validated_point=None
        with bind_background_reads_v3(reader,db=reader.db),host_fence,reader.store._lock,runtime_storage_quantum_v3(reader.db)as meter:
            reader.db.execute('BEGIN')
            try:
                reader.require_data_current_v3(meter)
                if reader.pending is not None:
                    try:_advance_background_pending_v3(reader,meter)
                    except BackgroundReadNeededV3 as needed:_start_background_request_v3(reader,needed.request)
                elif reader.phase=='owner_locator':
                    key=owner_grant_key(*reader.namespace.as_tuple)
                    request=('graph_atoms',('revision','value','valid'),('token','bot','persona'),(key.token,*reader.namespace.as_tuple))
                    task=reader.points.get(request)
                    if task is None:task=_BackgroundPointReadV3(reader,request);reader.points[request]=task
                    task.advance(meter)
                    if task.complete:reader.phase='d07_entry_locator'if reader.kind=='d07_stage'else'entry_locator'if reader.kind in('followup','followup_child')else'host_scope'if reader.kind=='host_lifecycle'else'authorize'
                elif reader.phase=='entry_locator':
                    if reader.entry_column is None:reader.entry_column=_BackgroundEntryLocatorV3(reader)
                    reader.entry_column.advance(meter)
                    if reader.entry_column.complete:reader.phase='authorize'
                elif reader.phase=='d07_entry_locator':
                    if reader.entry_column is None:reader.entry_column=_BackgroundD07EntryLocatorV3(reader)
                    reader.entry_column.advance(meter)
                    if reader.entry_column.complete:reader.phase='authorize'
                elif reader.phase=='host_scope':
                    with bind_background_reads_v3(reader,db=reader.db):
                        try:
                            from .d11_host_lifecycle_v1 import read_current_host_lifecycle_scope_v1
                            reader.local_result=read_current_host_lifecycle_scope_v1(reader.db,namespace=reader.namespace,
                                issuer=graph._GraphCoordinator__d11_issuer,now_utc=reader.now)
                            reader.phase='authorize'
                        except BackgroundReadNeededV3 as needed:_start_background_request_v3(reader,needed.request)
                elif reader.phase=="d07_source_qualification":
                    if reader.kind!="d07_stage":raise AuthorityUnavailable("D07 Source qualification has another installed Work")
                    if getattr(reader,"d07_source_qualification",None) is None:
                        reader.d07_source_qualification=_D07StageSourceQualificationV3(reader)
                    try:
                        reader.d07_source_qualification.advance(meter)
                        if reader.d07_source_qualification.complete:
                            reader.phase="algorithm"
                            suspended=getattr(reader,"d07_suspended_source_point",None)
                            if suspended is not None:
                                reader.pending=suspended
                                reader.d07_suspended_source_point=None
                    except BackgroundReadNeededV3 as needed:
                        _start_background_request_v3(reader,needed.request)
                elif reader.phase=='algorithm':
                    with bind_background_reads_v3(reader,db=reader.db):
                        if reader.kind=='d07_stage':reader.d07_algorithm_binding=(meter,reader.graph_stamp,reader.read_scope)
                        try:
                            reader.local_result=_prepare_background_algorithm_v3(reader)
                            if reader.kind=='d07_stage':
                                reader.d07_validation_points=iter(reader.points.values());reader.phase='d07_validate'
                            else:reader.phase='protected'
                        except BackgroundReadNeededV3 as needed:_start_background_request_v3(reader,needed.request)
                        finally:reader.d07_algorithm_binding=None
                elif reader.phase=='d07_validate':
                    if reader.kind!='d07_stage':raise AuthorityUnavailable('D07 final point validation has another business kind')
                    if reader.d07_validation_pending is None:
                        reader.d07_validation_pending=next(reader.d07_validation_points,None)
                    point=reader.d07_validation_pending
                    if point is None:d07_validation_eof=True
                    else:
                        if not point.complete or any(column is not None and not column.complete for column in point.values.values()):
                            raise AuthorityUnavailable('D07 final original coverage lacks canonical column EOF')
                        reader.require_request_v3(point.request);point.require_row_v3(meter)
                        d07_validated_point=point
                if reader.kind=='d07_stage':reader.require_data_current_v3(meter)
                reader.reserve_heap_v3()
            finally:reader.db.rollback()
        if reader.fence is not None:graph._validate_read_fence_v3(reader.fence)
        if d07_validated_point is not None:reader.d07_validation_pending=None
        if d07_validation_eof:
            reader.d07_validation_points=None;reader.d07_points_validated=True;reader.phase='protected'
    return GraphStorageStepV3('progress')


def finish_domain_background_read_v3(graph,work,error):
    if work.state.kind=='artifact_model_dispatch':
        from .artifact_host_dispatch_source_v3 import finish_artifact_host_dispatch_read_v3
        return finish_artifact_host_dispatch_read_v3(graph,work,error)
    from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
    reader=work.state
    try:
        from .contact_plan_physical_write_v3 import finish_contact_plan_write_v3
        with bind_runtime_storage_operation_v3(reader.operation,reader.db):
            finish_contact_plan_write_v3(reader,error)
        if reader.fence is not None:
            with bind_runtime_storage_operation_v3(reader.operation,reader.db):graph._finish_read_fence_v3(reader.fence)
            reader.fence=None
        if error is None:work.result_lease=work.operation
    except BaseException:
        reader.release_payload_v3();finish_runtime_storage_operation_v3(work.operation);raise
    if error is not None:reader.release_payload_v3();finish_runtime_storage_operation_v3(work.operation)



class _BackgroundTypedDigestV3:
    """The original Runtime type-tag algorithm, streamed by its existing codec."""
    def __init__(self,owner,column,value):
        from ..runtime_contracts import _canonical_value
        from .owner_material_source_storage_v3 import CanonicalValueStreamV3
        self.owner,self.column,self.value=owner,column,value
        column._actual_v3()
        owner.reserve_heap_v3(extra=_heap(getattr(value,'__dict__',{}))*4+65536)
        self.material=_canonical_value(value,set())
        owner.reserve_heap_v3(extra=_heap(self.material)+65536)
        self.stream=CanonicalValueStreamV3(self.material);self.complete=False;self.digest=None
    def advance(self,meter):
        self.owner.require_data_current_v3(meter)
        self.stream.read_fragment(meter)
        if self.stream.complete:self.digest=self.stream.hash.hexdigest();self.complete=True


def background_typed_original_digest_v3(db,column,value):
    if type(column)is not BackgroundJSONColumnV3:return canonical_digest(value)
    owner=_active_v3(db)
    if owner is not column.owner:raise AuthorityUnavailable('background typed digest has another actual column owner')
    column._actual_v3()
    task=owner.typed_digests.get(column)
    if task is None or not task.complete:
        if owner.sealed:raise AuthorityUnavailable('background typed original digest was not prepared')
        raise BackgroundReadNeededV3(('typed_digest',column,value))
    if type(value)is not type(task.value)or value!=task.value:raise AuthorityUnavailable('background typed original changed its unique decoded fields')
    return task.digest


class _BackgroundOfflineLookupV3:
    """Unbounded lifecycle keyset, retaining only the original at-most-two matches."""
    def __init__(self,owner,request):
        self.owner,self.request=owner,request
        self.kind,self.field,self.expected=request
        self.after=None;self.pending=None;self.rows=[];self.complete=False
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .d11_offline_originals_v1 import TABLE,SIGN_KIND,D11HostLifecycleOriginalV1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..runtime_contracts import canonical_serialize
        o=self.owner;o.require_data_current_v3(meter)
        if self.pending is not None:
            if not self.pending.complete:self.pending.advance(meter);return
            row=self.pending.require_row_v3(meter)
            kind,operation,column,digest,signature=row
            raw=background_json_loads_v3(column)
            if kind=='adoption_bridge':
                from ..authority_service.d11_offline_tick_bridge_v1 import offline_bridge_from_wire_v1
                value=offline_bridge_from_wire_v1(raw);namespace=value.binding.namespace;ref=value.binding.execution_id;actual_kind=kind;match=value.binding.prepared_original_ref
            elif kind=='accounting_prepared':
                from .d11_offline_accounting_v1 import D11OfflineAccountingPreparedV1
                value=decode_typed_production_value_v1(raw,D11OfflineAccountingPreparedV1)
                namespace=value.binding.namespace;ref=value.accounting_original_ref;actual_kind=kind;match=value.binding.execution_id
            else:
                value=decode_typed_production_value_v1(raw,D11HostLifecycleOriginalV1)
                namespace=value.namespace;ref=value.lifecycle_ref;actual_kind=value.kind;match=getattr(value,self.field)
            if (kind!=self.kind or namespace!=o.namespace or actual_kind!=kind or column.sha256!=digest
                    or ref!=self.pending.key[-1]):
                raise AuthorityUnavailable('offline lifecycle lookup differs from actual signed namespace/fields')
            o.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                canonical_serialize((o.namespace,kind,ref,digest)),signature)
            adopted=_runtime_bounded_fixed_row_v3(o.db,meter,'graph_bundle_operations',('commit_seq',),
                'bot=? AND persona=? AND operation_id=?',(*o.namespace.as_tuple,operation))
            if adopted is None or type(adopted[0])is not int or adopted[0]<1:
                raise AuthorityUnavailable('offline lifecycle lookup lost its actual W01 adoption')
            if match==self.expected:
                self.rows.append((ref,adopted[0]))
                if len(self.rows)>1:raise ValueError('actual offline lifecycle identity collides')
            self.pending=None;return
        where='bot=? AND persona=? AND kind=?';args=(*o.namespace.as_tuple,self.kind)
        if self.after is not None:where+=' AND original_ref>?';args=(*args,self.after)
        row=_runtime_bounded_fixed_row_v3(o.db,meter,TABLE,('original_ref',),where+' ORDER BY original_ref',args)
        if row is None:self.complete=True;return
        self.after=row[0]
        request=(TABLE,('kind','producing_operation_id','payload_json','payload_digest','signature'),
            ('bot','persona','kind','original_ref'),(*o.namespace.as_tuple,self.kind,row[0]))
        self.pending=_BackgroundPointReadV3(o,request)


def background_offline_lifecycle_lookup_v3(db,namespace,*,kind,field,value,legacy_reader):
    owner=_active_v3(db)
    if owner is None:return legacy_reader()
    if (owner.kind not in('offline','offline_close','host_lifecycle') or namespace!=owner.namespace
            or (kind,field) not in(('host_disconnect','source_ref'),('host_reconnect','source_ref'),
                ('host_reconnect','host_incarnation'),('accounting_prepared','execution_id'),('adoption_bridge','prepared_original_ref'))):
        raise AuthorityUnavailable('unregistered actual offline lifecycle lookup')
    request=(kind,field,value);task=owner.offline_lookups.get(request)
    if task is None or not task.complete:
        if owner.sealed:raise AuthorityUnavailable('actual lifecycle lookup was not prepared to namespace EOF')
        raise BackgroundReadNeededV3(('offline_lookup',*request))
    return tuple(task.rows)



def read_bound_background_offline_original_rows_v3(db,namespace,original_ref):
    owner=_active_v3(db)
    if owner is None:return False,None
    if namespace!=owner.namespace:raise AuthorityUnavailable('offline original crossed current background namespace')
    from .d11_offline_originals_v1 import TABLE,_KINDS
    rows=[]
    for kind in (*_KINDS,'prepared_tick','adopted_tick','accounting_prepared','adoption_bridge','adoption_receipt','historical_accounting_receipt','cancellation_receipt'):
        _,row=read_bound_background_graph_attachment_v3(db,table=TABLE,
            columns=('kind','producing_operation_id','payload_json','payload_digest','signature'),
            key_columns=('bot','persona','kind','original_ref'),key=(*namespace.as_tuple,kind,original_ref))
        if row is not None:rows.append(row)
    return True,tuple(rows)


def background_original_recipe_row_v3(db,namespace,original_ref,*,legacy_reader):
    return background_point_v3(db,table='graph_d10_production_inputs_v1',
        columns=('kind','producing_operation_id','payload_json','payload_digest','signature','source_refs_json'),
        key_columns=('bot','persona','original_ref'),key=(*namespace.as_tuple,original_ref),legacy_reader=legacy_reader)


def background_original_body_v3(column):
    if type(column)is not BackgroundJSONColumnV3:raise AuthorityUnavailable('actual complete raw-column original required')
    column._actual_v3()
    if not column.complete or column.locator:raise AuthorityUnavailable('background body is not full EOF')
    return column



def background_signed_input_row_v3(db,namespace,table,original_ref,kind,*,legacy_reader):
    from ..authority_service.named_joint_binding_body_v1 import _bound,named_joint_core_point_v1
    named=_bound(db)
    if named is not None:
        if namespace!=named.work.namespace or table not in _SIGNED_INPUT_KINDS:
            raise AuthorityUnavailable('Named Joint signed input crossed its actual namespace/fixed family')
        columns=('kind','producing_operation_id','payload_json','payload_digest','signature')if kind=='kind'else('producing_operation_id','payload_json','payload_digest','signature')
        _,row=named_joint_core_point_v1(db,table=table,columns=columns,key_columns=('bot','persona','original_ref'),key=(*namespace.as_tuple,original_ref))
        return row if row is None or kind=='kind'else(kind,*row)
    owner=_active_v3(db)
    if owner is None:return legacy_reader()
    if table not in _SIGNED_INPUT_KINDS:raise AuthorityUnavailable('unregistered signed input SQL family')
    columns=('kind','producing_operation_id','payload_json','payload_digest','signature')if kind=='kind'else('producing_operation_id','payload_json','payload_digest','signature')
    _,row=read_bound_background_graph_attachment_v3(db,table=table,columns=columns,key_columns=('bot','persona','original_ref'),
        key=(*namespace.as_tuple,original_ref))
    return row if row is None or kind=='kind'else(kind,*row)



def read_bound_background_graph_type_rows_v3(db,namespace,type_id,columns,*,valid_only=False):
    owner=_active_v3(db)
    if owner is None:return False,None
    if not set(columns)<={'token','revision','value','valid'}:raise AuthorityUnavailable('fixed background graph inventory columns required')
    atoms=background_inventory_v3(db,namespace,type_id,valid_only=valid_only)
    rows=[]
    for atom in atoms:
        _,point=read_bound_background_graph_attachment_v3(db,table='graph_atoms',columns=('revision','value','valid'),
            key_columns=('token','bot','persona'),key=(atom.key.token,*namespace.as_tuple))
        actual={'token':atom.key.token,'revision':point[0],'value':point[1],'valid':point[2]}
        rows.append(tuple(actual[name]for name in columns))
    return True,tuple(rows)


_HANDOFFS=WeakSet()
_PROGRESS=WeakSet()

@dataclass(frozen=True,eq=False,init=False)
class BackgroundFollowupChildHandoffV3:
    namespace:object
    dedupe_key:str
    causal_operation_id:str
    causal_original_digest:str
    trigger_original:object
    command:object
    owner_principal:object
    graph:object
    manifest_digest:str
    general_growth_parent_metadata:object
    def __init__(self,issuer,prepared,event,original,command,principal):
        if issuer is not _ISSUER:raise TypeError('actual derived followup handoff issuer required')
        prepared.require_v3(prepared.graph)
        reader=prepared.owner
        if reader.kind!='followup' or command not in prepared.local_result[5].commands:
            raise AuthorityUnavailable('followup handoff is not the actual current resolver proposal')
        for name,value in (('namespace',event.namespace),('dedupe_key',event.dedupe_key),
                ('causal_operation_id',event.causal_operation_id),('causal_original_digest',original['original_digest']),
                ('trigger_original',event.trigger_original),('command',command),('owner_principal',principal),
                ('graph',prepared.graph),('manifest_digest',reader.graph._GraphCoordinator__content_fence_v2.installation_grant.manifest_digest)):
            object.__setattr__(self,name,value)
        from .d07_general_growth_attention_v1 import general_growth_parent_from_prepared_v1
        from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
        object.__setattr__(self,'general_growth_parent_metadata',None if type(command)is GeneralGrowthTrialFollowupCommandV1
            else general_growth_parent_from_prepared_v1(prepared,event,command))
        _HANDOFFS.add(self)
    @classmethod
    def from_prepared_v3(cls,prepared,event,original,command,principal):
        return cls(_ISSUER,prepared,event,original,command,principal)


@dataclass(frozen=True,eq=False,init=False)
class BackgroundFollowupProgressV3:
    status:str
    receipt:object
    handoff:object
    def __init__(self,issuer,status,receipt,handoff):
        if issuer is not _ISSUER or status not in('completed','waiting','unchanged','child_ready','child_completed'):
            raise TypeError('actual closed followup driver progression required')
        if (status=='child_ready')!=(type(handoff)is BackgroundFollowupChildHandoffV3):
            raise ValueError('followup child progression lost its actual private proposal')
        object.__setattr__(self,'status',status);object.__setattr__(self,'receipt',receipt);object.__setattr__(self,'handoff',handoff)
        _PROGRESS.add(self)


def background_followup_progress_v3(status,receipt,handoff):
    return BackgroundFollowupProgressV3(_ISSUER,status,receipt,handoff)


def require_background_followup_progress_v3(value):
    if type(value)is not BackgroundFollowupProgressV3 or value not in _PROGRESS:
        raise AuthorityUnavailable('actual background followup driver progression required')
    return value


def require_background_followup_handoff_v3(value,graph,bundle):
    if (type(value)is not BackgroundFollowupChildHandoffV3 or value not in _HANDOFFS or value.graph is not graph
            or value.namespace!=bundle.installation_policy.namespace
            or value.manifest_digest!=graph._GraphCoordinator__content_fence_v2.installation_grant.manifest_digest):
        raise AuthorityUnavailable('actual followup proposal is not from this installed namespace')
    return value



def background_plain_original_digest_v3(encoded,value):
    from ..domains.d01.production_operations_v1 import plain_v1
    # D10 prepared/interval originals use plain_v1; CommitReceipt uses Runtime tags.
    return background_json_digest_v3(encoded,plain_v1(value))


def prepare_background_command_frame_v3(reader, *, operation_kind, request, operation_id, activity_id,
        audience_ref, parent_budget_lease_ref):
    """Prepare the actual command's independent plan using this READ Owner only."""
    import time
    from ..runtime_contracts import CommandEnvelope, OperationIdentity, RUNTIME_SCHEMA, VersionGuard, QueryEpoch, SourceQualification
    from .domain_production_registry_v1 import installed_operation_v1
    from .domain_production_read_plans_v1 import read_plan_current_domain_operation_v1
    from .domain_production_frame_v1 import freeze_domain_production_frame_v1
    from .domain_production_contracts_v1 import ProductionOperationLimitsV1
    o=reader;db=o.db;ns=o.namespace
    versions=dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' AND kind IN ('scheme','operator','policy')",ns.as_tuple))
    operation=installed_operation_v1(operation_kind)
    plan=read_plan_current_domain_operation_v1(db,namespace=ns,activity_id=activity_id,
        domain=operation.domain,operation_kind=operation.operation_kind,request=request,
        operation_id=operation_id,now_utc=o.now,audiences=o.authority.audience)
    envelope=CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(operation_id,None,activity_id,operation_kind,
        canonical_digest(request),canonical_digest({'input_refs':[]})),o.authority,
        VersionGuard((),(QueryEpoch(ns,'namespace',o.graph_stamp[1].revision),),o.owner.access_epoch,o.owner.delete_epoch,
            o.store._registry.catalogue_hash,versions['scheme'],versions['operator'],versions['policy'],(),(),()),
        SourceQualification((),'derived',None,o.now,'inference','ineligible',None,'not_applicable'),(),
        parent_budget_lease_ref,o.operation.deadline_utc,
        time.monotonic()+max(0,o.operation.deadline_utc-o.now),operation_id,())
    return freeze_domain_production_frame_v1(o.graph,db,envelope=envelope,current_owner=o.owner,
        scope=o.fence.scope,plan=plan,now_utc=o.now,observed_originals=(),limits=ProductionOperationLimitsV1())


def raise_background_work_error_v3(error):
    raise error


_ROLE_CLOCK_PROOFS=WeakSet()


def background_role_clock_call_v3(call):
    """Retry only an explicitly missing readonly attachment inside the same Work."""
    while True:
        try:return call()
        except BackgroundReadNeededV3 as needed:yield needed


class PreparedRoleClockCurrentInputsV3:
    def __init__(self,issuer,progress,inputs):
        if issuer is not _ISSUER or progress.steps is not None:raise TypeError('completed actual RoleClock inputs required')
        self.owner,self.reader,self.inputs=progress.owner,progress.reader,inputs
        self.graph_stamp=self.owner.graph_stamp;self.scope=self.owner.read_scope
        _ROLE_CLOCK_PROOFS.add(self)
    def require_current_v3(self,db,reader,namespace):
        if self not in _ROLE_CLOCK_PROOFS or reader is not self.reader or db is not self.owner.db or namespace!=self.owner.namespace:
            raise AuthorityUnavailable('RoleClock current inputs belong to another actual Background reader')
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        if self.owner.sealed:
            if self.owner.graph._v2_graph_stamp(namespace)!=self.graph_stamp:
                raise AuthorityUnavailable('RoleClock data stamp changed before fresh WRITE')
        else:self.owner.require_data_current_v3(current_c09_sql_meter_v2())
        scope,guard,profile=reader._current(db,namespace)
        if scope.namespace!=namespace or guard!=self.inputs['guard'] or profile!=self.inputs['profile']:
            raise AuthorityUnavailable('RoleClock current protected Owner/profile changed after component EOF')
        return {**self.inputs,'scope':scope,'guard':guard,'profile':profile}


class _BackgroundRoleClockReadV3:
    def __init__(self,issuer,owner,reader):
        if (issuer is not _ISSUER or reader is not owner.graph._GraphCoordinator__d04_semantic_mapping_reader
                or reader.graph is not owner.graph or owner.kind!='offline'):
            raise AuthorityUnavailable('actual installed Background RoleClock reader required')
        self.owner,self.reader=owner,reader;self.phase='selections';self.selection_index=0
        self.selections=[];self.steps=None;self.complete=False;self.proof=None
    def advance(self,meter):
        from .d04_semantic_installation_original_v3 import TABLE,SIGN_KIND,_read_signed,_current_inputs_steps_v3
        from .d11_role_clock_installation_v1 import TABLE as CLOCK_TABLE,SIGN_KIND as CLOCK_KIND
        o=self.owner;o.require_data_current_v3(meter)
        if self.phase=='selections':
            table,kind=((TABLE,SIGN_KIND),(CLOCK_TABLE,CLOCK_KIND))[self.selection_index]
            try:original=_read_signed(o.db,o.graph._GraphCoordinator__d11_issuer,table,kind,o.namespace)
            except BackgroundReadNeededV3 as needed:_start_background_request_v3(o,needed.request);return
            self.selections.append((table,kind,original));self.selection_index+=1
            if self.selection_index==2:self.phase='component'
            return
        if self.steps is None:self.steps=_current_inputs_steps_v3(self.reader,o.db,o.namespace)
        from .d04_series_initial_original_v1 import d04_series_original_read_scope_v1
        try:
            with d04_series_original_read_scope_v1(o.db):step=next(self.steps)
        except StopIteration as finished:
            self.steps=None;self.proof=PreparedRoleClockCurrentInputsV3(_ISSUER,self,finished.value);self.complete=True;return
        if type(step)is BackgroundReadNeededV3:_start_background_request_v3(o,step.request)


def read_bound_background_role_clock_inputs_v3(reader,db,namespace):
    owner=_active_v3(db)
    if owner is None:return False,None
    if namespace!=owner.namespace or reader is not owner.graph._GraphCoordinator__d04_semantic_mapping_reader:
        raise AuthorityUnavailable('RoleClock input request has another installed reader/namespace')
    progress=owner.role_clocks.get(reader)
    if progress is None or not progress.complete:
        if owner.sealed:raise AuthorityUnavailable('RoleClock actual component was not prepared to EOF')
        raise BackgroundReadNeededV3(('role_clock_inputs',reader))
    return True,progress.proof.require_current_v3(db,reader,namespace)


def read_bound_background_role_clock_selections_v3(db,reader,scope):
    owner=_active_v3(db)
    if owner is None:return False,None
    progress=owner.role_clocks.get(reader)
    if progress is None or progress.phase=='selections':raise AuthorityUnavailable('actual RoleClock accepting originals were not prepared')
    if reader is not owner.graph._GraphCoordinator__d04_semantic_mapping_reader or scope.namespace!=owner.namespace or owner.graph._v2_graph_stamp(owner.namespace)!=owner.graph_stamp:
        raise AuthorityUnavailable('RoleClock accepting originals lost their actual namespace/stamp')
    return True,tuple(progress.selections)


def read_bound_background_graph_attachment_rows_v3(db,*,table,columns,key_columns,key,order_column):
    owner=_active_v3(db)
    if owner is None:return False,None
    return True,list(background_rows_v3(db,table=table,columns=columns,group_columns=key_columns,group=key,
        order_columns=(order_column,),limit=None,legacy_reader=None))


class _BackgroundAuthoredPredecessorReadV3:
    def __init__(self,owner,args):
        from .joint_numeric_component import _authored_predecessor_steps_v3
        self.owner,self.args=owner,args;self.steps=_authored_predecessor_steps_v3(owner.db,*args)
        self.complete=False;self.result=None
    def advance(self,meter):
        from .d04_series_initial_original_v1 import d04_series_original_read_scope_v1
        self.owner.require_data_current_v3(meter)
        try:
            with d04_series_original_read_scope_v1(self.owner.db):step=next(self.steps)
        except StopIteration as finished:
            self.result=finished.value;self.steps=None;self.complete=True;return
        if type(step)is BackgroundReadNeededV3:_start_background_request_v3(self.owner,step.request)


def read_bound_background_authored_predecessor_v3(db,namespace,ref,revision,checkpoint,state):
    owner=_active_v3(db)
    if owner is None:return False,None
    if namespace!=owner.namespace or not owner.role_clocks:
        raise AuthorityUnavailable('authored predecessor requires this actual RoleClock Work')
    identity=(ref,revision);args=(namespace,ref,revision,checkpoint,state)
    task=owner.predecessors.get(identity)
    if task is None or not task.complete:
        if owner.sealed:raise AuthorityUnavailable('actual authored predecessor was not prepared to its root')
        raise BackgroundReadNeededV3(('authored_predecessor',identity,args))
    if task.args!=args:raise AuthorityUnavailable('authored predecessor changed exact original members')
    return True,task.result


_EMBEDDED_SOURCE_V3=ContextVar('background_offline_prepared_json_source_v3',default=None)


@contextmanager
def bind_background_offline_prepared_json_v3(column,raw):
    column._actual_v3()
    if(column.table!='graph_d11_offline_originals_v1' or column.column!='payload_json'
            or column.key_columns!=('bot','persona','kind','original_ref') or column.key[2]!='prepared_tick'
            or not column.matches_v3(raw)):
        raise AuthorityUnavailable('offline row canonical evidence needs the actual signed prepared_tick column')
    token=_EMBEDDED_SOURCE_V3.set((column,raw))
    try:yield
    finally:_EMBEDDED_SOURCE_V3.reset(token)


class _BackgroundEmbeddedJSONV3(BackgroundJSONColumnV3):
    """Canonical EOF of one exact value_json field in an actual prepared original."""
    def __init__(self,owner,column,path):
        self.owner,self.column,self.path=owner,column,path
        column._actual_v3()
        if column.owner is not owner or not column.complete:raise AuthorityUnavailable('embedded JSON lost same Work outer EOF')
        raw=column.json_v3()
        for step in path:raw=raw[step]
        if type(raw)is not str:raise AuthorityUnavailable('embedded canonical field is not actual JSON text')
        self.raw,self.offset,self.locator=raw,0,False;self.complete=False;self.frozen=None;self.sha256=None;self.byte_count=None
        self.nodes={};self.value=None;self.scalar=bytearray();self.text_parts=[];self.text_chars=[];self.text_high=None
        self.parser=_BackgroundJSONStreamV3(self,ensure_ascii=True)
    def advance(self,meter):
        self.column._actual_v3();self.owner.require_data_current_v3(meter)
        if self.offset<len(self.raw):
            part=self.raw[self.offset:self.offset+1024];encoded=part.encode('utf-8')
            meter.charge_encode(len(encoded));self._reserve_v3(131072)
            self.parser.feed(encoded,self._emit_v3);self.offset+=len(part);self._flush_text_v3();return
        result=self.parser.finish()
        if result.byte_count>4_194_304:
            from .domain_production_erasure_v1 import DomainProductionErasureHold
            raise DomainProductionErasureHold('domain production canonical JSON must be bounded')
        self._reserve_v3(_heap(self.value)+1024);self.frozen=_freeze_value_v3(self.value)
        self.sha256,self.byte_count=result.sha256,result.byte_count
        self.value=None;self.nodes={};self.scalar=bytearray();self.text_parts=[];self.text_chars=[];self.parser=None
        self.complete=True
    def json_v3(self):
        self.column._actual_v3()
        if not self.complete:raise AuthorityUnavailable('actual inner canonical JSON EOF required')
        self.owner.reserve_heap_v3(extra=_heap(self.frozen)+65536)
        return _detach_value_v3(self.frozen)


def background_offline_read_row_json_v3(row):
    source=_EMBEDDED_SOURCE_V3.get()
    if source is None:
        owner=_BOUND.get()
        if owner is None:return False,None
        recorded=owner.offline_row_sources.get(id(row))
        if recorded is None:return False,None
        actual,column,path=recorded
        if actual() is not row or _active_v3(column.db)is not owner:
            raise AuthorityUnavailable('offline canonical row lost its actual originating instance/Work')
        task=owner.embedded_json[(column,path)]
        if not task.complete or task.raw!=row.value_json:
            raise AuthorityUnavailable('offline canonical field EOF changed before validation')
        return True,task.json_v3()
    column,raw=source;owner=_active_v3(column.db)
    if owner is not column.owner:raise AuthorityUnavailable('offline prepared row decoder lost its same Work')
    rows=raw.get('read_rows')
    if type(rows)is not list:raise AuthorityUnavailable('actual offline prepared read_rows are absent')
    matches=[index for index,value in enumerate(rows) if type(value)is dict and value.get('ref')==row.ref]
    if len(matches)!=1:raise AuthorityUnavailable('offline canonical row is not a unique actual original field')
    index=matches[0]
    if rows[index]!={'ref':row.ref,'revision':row.revision,'valid':row.valid,'value_json':row.value_json}:
        raise AuthorityUnavailable('offline row constructor differs from actual prepared original')
    path=('read_rows',index,'value_json');task=owner.embedded_json.get((column,path))
    if task is None or not task.complete:
        if owner.sealed:raise AuthorityUnavailable('offline row canonical EOF was not prepared by this Work')
        raise BackgroundReadNeededV3(('embedded_json',column,path))
    if task.raw!=row.value_json:raise AuthorityUnavailable('offline row canonical field changed after EOF')
    row_id=id(row)
    owner_ref=ref(owner)
    def release_row(actual):
        live=owner_ref()
        if live is not None and live.offline_row_sources.get(row_id,(None,))[0] is actual:
            live.offline_row_sources.pop(row_id,None)
    owner.offline_row_sources[row_id]=(ref(row,release_row),column,path)
    return True,task.json_v3()


@contextmanager
def bind_fresh_offline_after_cas_v3(db,receipt):
    """Drop only pre-CAS attachments after independently matching this W01 receipt."""
    from ..runtime_storage_v3 import runtime_storage_v3,runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    handle=runtime_storage_v3(db)
    if not db.in_transaction:raise AuthorityUnavailable('fresh offline material requires its actual W01 transaction')
    if handle is not None:
        with runtime_storage_quantum_v3(db)as meter:
            handle.require_current(meter)
            actual=_runtime_bounded_fixed_row_v3(db,meter,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(receipt.invalidated_epochs[0].bot,receipt.invalidated_epochs[0].persona,receipt.operation_id))
    else:
        actual=db.execute('SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
            (receipt.invalidated_epochs[0].bot,receipt.invalidated_epochs[0].persona,receipt.operation_id)).fetchone()
    if receipt.status!='committed' or actual!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
        raise AuthorityUnavailable('fresh offline material lost its independently committed actual W01 receipt')
    token=_BOUND.set(None)
    try:yield
    finally:_BOUND.reset(token)


def read_bound_background_graph_atom_v3(db,namespace,key):
    """Return the actual independently read head, or its observed exact absence."""
    from ..authority_service.original_foreground_source_read_v3 import read_bound_original_foreground_graph_atom_v3
    original,atom=read_bound_original_foreground_graph_atom_v3(db,namespace,key)
    if original:return True,atom
    from ..authority_service.artifact_model_source_read_v3 import read_bound_artifact_model_graph_atom_v3
    artifact,atom=read_bound_artifact_model_graph_atom_v3(db,namespace,key)
    if artifact:return True,atom
    owner=_active_v3(db)
    if owner is None:return False,None
    if namespace!=owner.namespace or NamespaceId.from_key(key)!=namespace:
        raise AuthorityUnavailable('background head crossed its actual selected namespace')
    if key.type_name == 'memory.source' and (owner.contact_active_component is not None or owner.contact_initial_component is not None):
        component = owner.contact_active_component if owner.contact_active_component is not None else owner.contact_initial_component
        if not component.complete or component.source_material is None:
            raise AuthorityUnavailable('Contact Source head cannot precede its actual current material EOF')
        actual = component.projection.get(key)
        owner.heads[key.token] = actual
        return True,actual
    row=background_graph_head_v3(db,namespace,key)
    if row is None:return True,GraphAtom(key,0,{},False)
    original=row[1];value=background_json_loads_v3(original)
    owner.store._validate_key(key)
    if row[2]==1:owner.store._registry.spec(key.type_name).validator(value)
    actual=GraphAtom(key,row[0],value,bool(row[2]),_canonical_original=original)
    owner.heads[key.token]=actual
    return True,actual


def _background_canonical_value_matches_v3(value,frozen):
    """Compare canonical value nodes without another whole-value byte encoding."""
    from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
    if type(frozen)is _FrozenObjectV3:
        return type(value)is dict and len(value)==len(frozen.items) and all(
            key in value and _background_canonical_value_matches_v3(value[key],item)for key,item in frozen.items)
    if type(frozen)is _FrozenArrayV3:
        return type(value)is list and len(value)==len(frozen.items) and all(
            _background_canonical_value_matches_v3(part,item)for part,item in zip(value,frozen.items))
    if type(value)is not type(frozen):return False
    if type(value)is float:return value.hex()==frozen.hex()
    return value==frozen


def register_joint_budget_locator_v3(db, *, original, namespace, lease_id, version):
    owner = _active_v3(db)
    if owner is None:
        return
    require_actual_background_attachment_owner_v3(owner, db=db)
    if (type(original) is not BackgroundJSONColumnV3 or original.owner is not owner
            or original.table != "graph_d10_production_inputs_v1" or original.column != "payload_json"
            or namespace != owner.namespace or not original.complete or not original.signature_verified
            or original.signature_kind != "d11.d10-production-input.v1"):
        raise AuthorityUnavailable("Joint parent grant locator requires its actual signed binding EOF")
    raw = original.json_v3()
    if (raw.get("schema") not in ("d10.joint-node-execution-binding.v1", "d10.joint-artifact-prospective-binding.v1")
            or (raw["parent_budget_lease_ref"], raw["parent_grant_version"]) != (lease_id, version)):
        raise AuthorityUnavailable("Joint budget read changed its exact original parent locator")
    if not hasattr(owner, "joint_budget_selectors"):
        owner.joint_budget_selectors = set()
    owner.joint_budget_selectors.add((lease_id, version))


def register_joint_semantic_budget_locator_v3(db, *, original, namespace, kind, original_ref, digest, signature, lease_id, version, signer):
    owner = _active_v3(db)
    if owner is None:
        return
    require_actual_background_attachment_owner_v3(owner, db=db)
    if (type(original) is not BackgroundJSONColumnV3 or original.owner is not owner or not original.complete
            or original.locator or original.table != "graph_d07_execution_originals_v1" or original.column != "payload_json"
            or original.key != (*namespace.as_tuple, kind, original_ref) or namespace != owner.namespace
            or kind != "joint_external_semantic_basis_v1"):
        raise AuthorityUnavailable("Joint semantic parent locator requires its actual complete D07 Source")
    from ..runtime_contracts import canonical_serialize
    signer.verify("d07.execution-original.v1", canonical_serialize((namespace, kind, original_ref, digest)), signature)
    raw = original.json_v3()
    if (background_json_digest_v3(original, raw) != digest
            or (raw["parent_budget_lease_ref"], raw["parent_grant_version"]) != (lease_id, version)):
        raise AuthorityUnavailable("Joint semantic parent locator changed its signed basis")
    if not hasattr(owner, "joint_budget_selectors"):
        owner.joint_budget_selectors = set()
    owner.joint_budget_selectors.add((lease_id, version))

def require_current_d07_content_source_authority_v3(reader):
    """Require the effective Source actor, separately from Owner ACL and model executor."""
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    if reader.kind!="d07_stage":raise AuthorityUnavailable("D07 content requires actual D07 Stage Work")
    if reader.d07_selector.stage!="egress_seal":
        from .d07_stage_content_scope_v3 import HostD07StageContentScopeV3,require_pending_host_d07_source_authority_v3
        scope=reader.d07_source_scope
        if scope is None:return require_pending_host_d07_source_authority_v3(reader)
        if type(scope)is not HostD07StageContentScopeV3:
            raise AuthorityUnavailable("D07 body has no privately issued actual Host Source scope")
        return scope.require_for_v3(reader,body=False).effective_source_authority
    from ..authority_service.owner_location_read_v3 import D07ContentSourceScopeV3
    scope=reader.d07_source_scope
    if type(scope)is not D07ContentSourceScopeV3:
        raise AuthorityUnavailable("actual privately issued D07 model Source delegation required")
    scope.require_for_v3(reader.graph,reader.d07_service,reader.bundle,reader.operation,
        reader.d07_model_authority,reader.read_scope.permit)
    if (scope.effective_source_authority!=reader.d07_content_authority
            or scope.model_authority!=reader.d07_model_authority
            or scope.owner_acl_authority!=reader.authority):
        raise AuthorityUnavailable("D07 original Source/Owner/model authorities differ from their actual delegation")
    return reader.d07_content_authority


_D07_SOURCE_MATERIALS_V3=WeakKeyDictionary()
_D07_SOURCE_METADATA_V3=WeakKeyDictionary()


class _D07SourceMetadataV3:
    def __init__(self,issuer,reader,key,revision,cell,digest,metadata):
        if issuer is not _ISSUER or reader.kind!="d07_stage":
            raise TypeError("actual D07 Source metadata producer required")
        require_actual_background_attachment_owner_v3(reader,db=reader.db)
        self.reader,self.key,self.revision,self.valid=reader,key,revision,True
        self.cell_id,self.payload_sha256=cell,digest
        self.canonical_semantic_digest=reader.d07_source_qualification.semantic_digest
        self.metadata=MappingProxyType({name:tuple(value)if type(value)is list else value for name,value in metadata.items()})
        self.graph_stamp,self.scope=reader.graph_stamp,reader.read_scope
        _D07_SOURCE_METADATA_V3[self]=(reader,key,revision,cell,digest,self.metadata,self.graph_stamp,self.scope,self.canonical_semantic_digest)
    def require_current_v3(self):
        if _D07_SOURCE_METADATA_V3.get(self)!=(self.reader,self.key,self.revision,self.cell_id,self.payload_sha256,
                self.metadata,self.graph_stamp,self.scope,self.canonical_semantic_digest):
            raise AuthorityUnavailable("D07 Source metadata was not privately issued by this Work")
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        self.reader.require_data_current_v3(current_c09_sql_meter_v2())
        return self


class PreparedD07StageSourceMaterialV3:
    """Current Source qualification under this actual Host Work; never an Authority proof."""
    def __init__(self,issuer,task):
        reader=task.reader
        if issuer is not _ISSUER or not task.complete or reader.kind!="d07_stage":
            raise TypeError("actual complete D07 current Source family qualification required")
        require_actual_background_attachment_owner_v3(reader,db=reader.db)
        self.reader,self.scope,self.graph_stamp=reader,reader.read_scope,reader.graph_stamp
        source_authority=require_current_d07_content_source_authority_v3(reader)
        self.namespace,self.purpose,self.audience=reader.namespace,source_authority.purpose,tuple(source_authority.audience)
        self.actor,self.original_digest=source_authority.actor,reader.entry_metadata[0][0]
        self.source_scope=reader.d07_source_scope if reader.d07_selector.stage=="egress_seal" else None
        self.source_scope_commitment=None if self.source_scope is None else self.source_scope.commitment
        self.model_authority=reader.d07_model_authority if self.source_scope is not None else None
        self.source_versions=tuple(task.expected.items())
        self.witnesses=MappingProxyType(dict(task.witnesses))
        self.access_versions=tuple(task.access_versions)
        _D07_SOURCE_MATERIALS_V3[self]=(reader,self.scope,self.graph_stamp,self.namespace,self.actor,self.purpose,
            self.audience,self.original_digest,self.source_versions,self.witnesses,self.access_versions,
            self.source_scope,self.source_scope_commitment,self.model_authority)
    def require_for_prepared_v3(self,reader,digest):
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        source_authority=require_current_d07_content_source_authority_v3(reader)
        if (_D07_SOURCE_MATERIALS_V3.get(self)!=(self.reader,self.scope,self.graph_stamp,self.namespace,self.actor,self.purpose,
                self.audience,self.original_digest,self.source_versions,self.witnesses,self.access_versions,
            self.source_scope,self.source_scope_commitment,self.model_authority)
                or reader is not self.reader or digest!=self.original_digest
                or source_authority.actor!=self.actor or source_authority.purpose!=self.purpose
                or tuple(source_authority.audience)!=self.audience
                or (self.source_scope is not None and self.source_scope.commitment!=self.source_scope_commitment)):
            raise AuthorityUnavailable("D07 full prepared body has no exact current Source/Actor qualification")
        reader.require_data_current_v3(current_c09_sql_meter_v2())
        return self


class _D07StageSourceQualificationV3:
    def __init__(self,reader):
        self.reader=reader
        raw=reader.entry_metadata[1]["read_rows"]
        self.expected={item["ref"]:item["revision"] for item in raw
            if AtomKey.from_token(item["ref"]).type_name=="memory.source" and item["valid"]}
        if not self.expected or len(self.expected)>256:
            raise AuthorityUnavailable("D07 prepared locator has no bounded actual Source family")
        self.pending=list(self.expected);self.witnesses={};self.records={};self.access_versions=[]
        self.phase="next";self.current=None;self.cell=self.parser=None;self.fragment=b"";self.offset=0
        self.complete=False;self.reserved=0
        self.semantic_hash=self.semantic_decoder=None;self.semantic_digest=None
    def reserve_v3(self):
        retained=_heap((self.expected,self.pending,self.witnesses,self.records,self.access_versions,self.fragment))+65536
        if self.parser is not None:retained+=self.parser._source_heap_bytes()
        if retained>self.reserved:self.reader.operation.retain(retained-self.reserved);self.reserved=retained
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3,begin_runtime_cell_read_v3
        from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
        from ..memory_types import source_key,access_key
        from ..domains.d06 import source_correction_head_key
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        reader=self.reader;reader.require_data_current_v3(meter)
        source_authority=require_current_d07_content_source_authority_v3(reader)
        if self.phase=="next":
            if not self.pending:
                active,done=set(),set()
                def visit(ref):
                    if ref in active:raise AuthorityUnavailable("D07 actual Source ancestry is cyclic")
                    if ref in done:return
                    active.add(ref)
                    for parent in self.records[ref].parent_source_ids:visit(source_key(*reader.namespace.as_tuple,parent).token)
                    active.remove(ref);done.add(ref)
                for ref in self.witnesses:visit(ref)
                self.complete=True;reader.d07_source_material=PreparedD07StageSourceMaterialV3(_ISSUER,self);return
            ref=self.pending.pop()
            if ref in self.witnesses:return
            if len(self.witnesses)>=256:raise AuthorityUnavailable("D07 actual Source ancestry exceeds its original bound")
            key=AtomKey.from_token(ref)
            if key!=source_key(*reader.namespace.as_tuple,key.owner.subject):
                raise AuthorityUnavailable("D07 metadata Source ref crosses namespace or exact Source type")
            head=_runtime_bounded_fixed_row_v3(reader.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(ref,*reader.namespace.as_tuple))
            if head is None or head[1]!=1 or ref in self.expected and head[0]!=self.expected[ref]:
                raise AuthorityUnavailable("D07 frozen Source version is no longer current")
            self.current=(key,head[0],head[2])
            self.cell=begin_runtime_cell_read_v3(reader.db,head[2],erasure_owner_ref=ref)
            if self.cell.header[0]not in("canonical-json.ascii.v1","canonical-json.utf8.v1"):
                raise AuthorityUnavailable("D07 Source metadata has an unregistered canonical codec")
            self.parser=C09MemorySourceJSONStreamV3(ensure_ascii=self.cell.header[0]=="canonical-json.ascii.v1")
            if self.cell.header[0]=="canonical-json.utf8.v1":
                import codecs
                from hashlib import sha256
                self.semantic_decoder=codecs.getincrementaldecoder("utf-8")("strict")
                self.semantic_hash=sha256()
            self.phase="metadata";return
        if self.phase=="metadata":
            if self.offset<len(self.fragment):
                end=min(self.offset+1024,len(self.fragment))
                chunk=self.fragment[self.offset:end]
                self.parser.feed(chunk,lambda event:None)
                self.semantic_fragment_v3(chunk,meter)
                self.offset=end;self.reserve_v3();return
            fragment=self.cell.read_fragment(meter=meter)
            if fragment is not None:self.fragment,self.offset=fragment,0;return
            parsed=self.parser.finish();digest=self.cell.finish(meter=meter)
            if (parsed.byte_count,parsed.sha256)!=(self.cell.header[3],digest):
                raise AuthorityUnavailable("D07 Source metadata is erased or lacks complete original EOF")
            self.semantic_fragment_v3(b"",meter,final=True)
            self.semantic_digest=digest if self.semantic_hash is None else self.semantic_hash.hexdigest()
            self.semantic_hash=self.semantic_decoder=None
            key,revision,cell=self.current
            self.witness=_D07SourceMetadataV3(_ISSUER,reader,key,revision,cell,digest,self.parser._source_metadata)
            self.parser=self.cell=None;self.fragment=b"";self.offset=0;self.phase="rights";return
        key,revision,cell=self.current
        access=access_key(*reader.namespace.as_tuple,key.owner.subject)
        correction=source_correction_head_key(reader.namespace,key.owner.subject)
        access_row=background_graph_head_v3(reader.db,reader.namespace,access)
        correction_row=background_graph_head_v3(reader.db,reader.namespace,correction)
        access_atom=None if access_row is None else GraphAtom(access,access_row[0],background_json_loads_v3(access_row[1]),bool(access_row[2]))
        correction_atom=(GraphAtom(correction,0,{},False) if correction_row is None
            else GraphAtom(correction,correction_row[0],background_json_loads_v3(correction_row[1]),bool(correction_row[2])))
        record=None
        for audience in source_authority.audience:
            qualified=_qualify_source_rights_values_v3(reader.namespace,key.token,self.witness,access_atom,correction_atom,
                audience=audience,purpose=source_authority.purpose,metadata_only=True)
            if qualified is None:raise AuthorityUnavailable("D07 Source current access/correction/purpose/audience is unqualified")
            record=qualified
        self.witnesses[key.token]=self.witness;self.records[key.token]=record
        self.access_versions.extend((GraphVersion(key,revision),GraphVersion(access,access_atom.revision),GraphVersion(correction,0)))
        self.pending.extend(source_key(*reader.namespace.as_tuple,parent).token for parent in record.parent_source_ids)
        self.current=None;self.phase="next";self.reserve_v3()

    def semantic_fragment_v3(self,chunk,meter,*,final=False):
        if self.semantic_decoder is None:return
        decoded=self.semantic_decoder.decode(chunk,final=final)
        encoded=[]
        for character in decoded:
            point=ord(character)
            if point<127:encoded.append(character)
            elif point<=65535:encoded.append("\\u"+format(point,"04x"))
            else:
                point-=65536
                encoded.append("\\u"+format(55296+(point>>10),"04x")+"\\u"+format(56320+(point&1023),"04x"))
        wire="".join(encoded).encode("ascii")
        meter.charge_encode(len(wire));self.semantic_hash.update(wire)


def require_current_d07_frozen_source_material_v3(reader,prepared):
    from dataclasses import asdict
    from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1
    material=reader.d07_source_material
    if type(material) is not PreparedD07StageSourceMaterialV3:
        raise AuthorityUnavailable("D07 frozen body has no registered Host Source material producer")
    material.require_for_prepared_v3(reader,reader.entry_metadata[0][0])
    from .d07_graph_stages_v1 import _thaw_d07_stage_frozen_v3,_d07_stage_frozen_sources_v3
    frozen=_thaw_d07_stage_frozen_v3(prepared)
    for source in _d07_stage_frozen_sources_v3(prepared,frozen):
        witness=material.witnesses.get(source.source_ref.ref)
        if (witness is None or source.source_ref.version!=witness.revision
                or canonical_digest(asdict(source.record))!=witness.canonical_semantic_digest):
            raise AuthorityUnavailable("D07 frozen Source text differs from its exact currently qualified canonical original")
    return material

def _require_reflection_locator_metadata_v3(reader,raw):
    from ..graph_types import GraphVersion
    from .d07_execution_v1 import d07_execution_ids_v1
    if raw["schema"]!="d07.reflection-prepared.v3" or raw["work_kind"]!="reflection":
        raise AuthorityUnavailable("exact issued reflection prepared locator required")
    ids=d07_execution_ids_v1(reader.namespace,raw["operation_id"],"reflection")
    if (raw["job_id"],raw["call_id"])!=(ids["job"],ids["call"]):
        raise AuthorityUnavailable("reflection locator crossed its stable real operation/job/call identity")
    head=raw["checkpoint_ref"]
    if type(head)is not dict or set(head)!={"key","revision"} or type(head["key"])is not str:
        raise AuthorityUnavailable("reflection metadata changed its canonical v3 GraphVersion wire")
    key=AtomKey.from_token(head["key"])
    if (NamespaceId.from_key(key)!=reader.namespace or key.type_name!="d07.reflection_checkpoint.v1"
            or type(head["revision"])is not int or head["revision"]<1):
        raise AuthorityUnavailable("reflection metadata crossed its exact checkpoint namespace/type/birth")
    digests=("reflection_request_digest","reflection_continuation_digest","parent_prepared_digest",
        "parent_execution_digest","checkpoint_digest","parent_grant_digest")
    if any(type(raw[name])is not str or len(raw[name])!=64 or any(char not in "0123456789abcdef" for char in raw[name]) for name in digests):
        raise AuthorityUnavailable("reflection locator lost its exact original signed lineage digests")
    refs=("reflection_request_ref","reflection_continuation_ref","parent_prepared_ref","parent_execution_ref","ticket_id","parent_budget_lease_ref")
    if any(type(raw[name])is not str or not raw[name] for name in refs):
        raise AuthorityUnavailable("reflection locator has an incomplete actual parent/request/ticket/budget group")
    cycle_names=("cycle_ref","cycle_digest","call_plan_digest","c02_operation_id","cancel_generation")
    absent=tuple(raw[name]is None for name in cycle_names)
    if any(absent) and not all(absent):
        raise AuthorityUnavailable("reflection locator cannot carry partial Self parentage")
    if not all(absent):
        cycle=raw["cycle_ref"]
        if type(cycle)is not dict or set(cycle)!={"key","revision"} or type(cycle["key"])is not str:
            raise AuthorityUnavailable("reflection Self locator changed its canonical v3 cycle wire")
        cycle_key=AtomKey.from_token(cycle["key"])
        if NamespaceId.from_key(cycle_key)!=reader.namespace or cycle_key.type_name!="runtime.job":
            raise AuthorityUnavailable("reflection Self locator crossed its actual cycle namespace/type")
    # Body constructor and canonical frozen source checks run only after current Source qualification.
    return GraphVersion(key,head["revision"])


def read_bound_d07_model_seal_query_rows_v3(db,namespace,type_id):
    owner=_active_v3(db)
    if owner is None:return False,None
    if owner.kind!="d07_stage" or owner.d07_selector.stage!="egress_seal":return False,None
    recipe=owner.d07_model_seal_recipe.require_for_v3(owner)
    if namespace!=owner.namespace or type_id not in recipe.plan.fixed_type_ids:
        raise AuthorityUnavailable("D07 model seal query is outside its authenticated original page")
    rows=background_rows_v3(db,table="graph_atoms",columns=("token","revision"),
        group_columns=("bot","persona","type_name"),group=(*namespace.as_tuple,type_id),
        order_columns=("token",),limit=129,legacy_reader=lambda:None)
    return True,rows


class _ContactBackgroundPlanLocatorReadV3:
    def __init__(self,owner,request):
        from .contact_background_plan_metadata_v3 import (_ISSUER as CONTACT_METADATA,
            ContactBackgroundPlanMetadataSelectorV3,ContactBackgroundPlanMetadataWorkV3)
        from ..authority_service.contact_background_graph_v3 import ContactPlanLocatorEOFV3
        require_actual_background_attachment_owner_v3(owner,db=owner.db)
        _,self.contact_id=request
        self.owner,self.request,self.complete=owner,request,False
        selector=ContactBackgroundPlanMetadataSelectorV3(owner.namespace,self.contact_id)
        self.work=ContactBackgroundPlanMetadataWorkV3(CONTACT_METADATA,owner,selector)
        self.column=ContactPlanLocatorEOFV3(self.work)
        self.work.contact_locator=self.column
    def advance(self,meter):
        self.work.require_current(meter=meter)
        self.column.advance(meter)
        if not self.column.complete:return
        from ..domains.d08.contact_plan_v2 import decode_contact_plan_v2
        self.plan=decode_contact_plan_v2(self.column.plan_metadata)
        self.complete=True
    def require_for_v3(self,owner):
        if owner is not self.owner or not self.complete or owner.contact_plan_locators.get(self.contact_id)is not self:
            raise AuthorityUnavailable('Contact background metadata locator lost its actual complete same-Work EOF')
        self.column.require_v3(self.work)
        return self.plan
    def release_v3(self):
        self.work.release_v3()


def read_background_contact_plan_metadata_v3(db,namespace,contact_id):
    owner = _active_v3(db)
    if owner is None:
        return False,None
    if namespace != owner.namespace:
        raise AuthorityUnavailable('Contact Plan metadata crossed namespace')
    task = owner.contact_plan_locators.get(contact_id)
    if task is None or not task.complete:
        if owner.sealed:
            raise AuthorityUnavailable('Contact metadata locator was not prepared by this actual Work')
        raise BackgroundReadNeededV3(('contact_plan_locator',contact_id))
    return True,task.require_for_v3(owner)



def require_background_contact_source_component_v3(db,namespace,contact_id,phase):
    owner = _active_v3(db)
    if owner is None or owner.namespace!=namespace:
        raise AuthorityUnavailable('Contact domain protected reader has no actual background parent')
    read_background_contact_plan_metadata_v3(db,namespace,contact_id)
    component = owner.contact_source_components.get((contact_id,phase))
    if component is None or not component.complete:
        if owner.sealed:
            raise AuthorityUnavailable('Contact protected Source was not qualified by its original actual READ Work')
        raise BackgroundReadNeededV3(('contact_domain_source',contact_id,phase))
    owner.contact_active_component = component
    return component.require_actual_v3()

class _GeneralGrowthStartMetadataCensusV1:
    """Full metadata EOF, one retained pending Start and one fair candidate."""
    def __init__(self,owner,criterion):
        self.owner,self.criterion=owner,criterion
        self.after=None;self.pending=None;self.matches=[];self.complete=False
        self.incomplete_count=0;self.matched_count=0;self.root=canonical_digest(('general-start-census.v1',criterion))
        self.prior_points=None;self.prior_physical=None;self.dependency=None
    def _discard_v1(self):
        o=self.owner
        requests=set(o.points)-self.prior_points
        requests.add(self.pending.request)
        columns=[]
        for request in requests:
            point=o.points.pop(request,None)
            if point is not None:columns.extend(point.values.values())
        for key in set(o.physical_payloads)-self.prior_physical:
            columns.append(o.physical_payloads.pop(key))
        for column in columns:
            if type(column)is BackgroundJSONColumnV3:
                o.columns.discard(column);_COLUMNS.pop(column,None)
                column.nodes.clear();column.value=None;column.frozen=None
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .domain_production_followups_v1 import (general_growth_start_matches_metadata_v1,
            _verified_general_start_metadata_v1,_completed_general_trial_metadata_v1)
        from .d01_production_operations_v1 import SIGN_KIND
        o=self.owner;o.require_data_current_v3(meter)
        if self.dependency is not None:
            if not self.dependency.complete:self.dependency.advance(meter)
            if self.dependency.complete:self.dependency=None
            return
        if self.pending is not None:
            if not self.pending.complete:self.pending.advance(meter);return
            row=self.pending.require_row_v3(meter)
            raw=background_json_loads_v3(row[2]);retain=False
            if general_growth_start_matches_metadata_v1(raw,self.criterion):
                issuer=o.graph._GraphCoordinator__d11_issuer
                background_verify_signature_v3(issuer._signer,SIGN_KIND,row[2],row[4])
                if not background_json_matches_v3(row[2],raw)or background_json_digest_v3(row[2],raw)!=row[3]:
                    raise AuthorityUnavailable('General Start census changed canonical signed EOF')
                start,_,_=_verified_general_start_metadata_v1(o.db,o.namespace,self.pending.key[2],row,raw)
                completed=_completed_general_trial_metadata_v1(o.db,o.namespace,start,issuer)
                self.matched_count+=1
                if not completed:self.incomplete_count+=1
                self.root=canonical_digest((self.root,self.pending.key[2],row[3],completed))
                mode,cursor=self.criterion[7]
                selected=(self.pending.key[2]==cursor)if mode=='child'else(cursor is None or self.pending.key[2]>cursor)
                retain=not completed and selected and not self.matches
                if retain:
                    o.reserve_heap_v3(extra=1024)
                    self.matches.append((self.pending.key[2],row))
            if not retain:self._discard_v1()
            self.pending=None;self.prior_points=None;self.prior_physical=None;return
        where='bot=? AND persona=?';args=o.namespace.as_tuple
        if self.after is not None:where+=' AND original_ref>?';args=(*args,self.after)
        row=_runtime_bounded_fixed_row_v3(o.db,meter,'graph_d01_production_inputs_v1',
            ('original_ref','kind'),where+' ORDER BY original_ref',args)
        if row is None:self.complete=True;return
        self.after=row[0]
        if row[1]!='general_growth_trial_start_v1':
            if row[1].startswith('general_growth_trial_start'):
                raise AuthorityUnavailable('unknown General start metadata version')
            return
        request=('graph_d01_production_inputs_v1',
            ('kind','producing_operation_id','payload_json','payload_digest','signature','source_refs_json'),
            ('bot','persona','original_ref'),(*o.namespace.as_tuple,row[0]))
        o.require_request_v3(request);o.reserve_heap_v3(extra=8192)
        self.prior_points=set(o.points);self.prior_physical=set(o.physical_payloads)
        task=o.points.get(request)
        if task is None:task=_BackgroundPointReadV3(o,request);o.points[request]=task
        self.pending=task




def background_general_growth_start_census_v1(db,*,criterion):
    owner=_active_v3(db)
    if (owner is None or owner.kind not in('followup','followup_child')or owner.entry is None
            or owner.entry[1]!='d01'or owner.entry[2]not in('general_growth_action_outcome_available',
                'actual_life_outcome_available_for_growth')):
        raise AuthorityUnavailable('General start census requires its actual two closed outcome events')
    task=owner.general_trial_census
    if task is None or task.criterion!=criterion or not task.complete:
        if owner.sealed:raise AuthorityUnavailable('General start census lacks complete metadata EOF')
        raise BackgroundReadNeededV3(('general_growth_start_metadata_census_v1',criterion))
    return tuple(task.matches)


def require_current_general_growth_trial_metadata_reader_v1(reader):
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    if (reader.kind!='followup_child'
            or type(reader.handoff.command)is not GeneralGrowthTrialFollowupCommandV1
            or reader.handoff.command.source_authority.namespace!=reader.namespace
            or reader.authority.purpose!='consolidation'
            or reader.authority.audience!=reader.handoff.command.audience_refs):
        raise AuthorityUnavailable('General metadata requires its actual private derive-child READ')
    require_background_followup_handoff_v3(reader.handoff,reader.graph,reader.bundle)
    if reader.sealed:
        binding=_GENERAL_GROWTH_WRITE_METADATA_V1.get()
        if binding is None or binding[0]is not reader:
            raise AuthorityUnavailable('sealed General metadata requires its actual fresh WRITE binder')
        reader.require_write_data_v3(reader.db,binding[1],binding[2])
    elif reader.fence is None or reader.read_scope is not reader.fence.scope:
        raise AuthorityUnavailable('General metadata lost its actual active child READ scope')
    return reader


def prepare_current_general_growth_trial_metadata_column_v1(reader,*,table,column,key_columns,key,kind,
        cell_id=None,signature_kind=None,signature=None):
    require_current_general_growth_trial_metadata_reader_v1(reader)
    if table=='graph_d01_production_inputs_v1':
        if (column!='payload_json'or key_columns!=('bot','persona','original_ref')
                or key[:2]!=reader.namespace.as_tuple or kind not in('growth_proposal','growth_counterevidence',
                    'general_growth_intent_v1','general_growth_trial_start_v1','general_growth_trial_v1')):
            raise AuthorityUnavailable('General signed metadata column escaped its actual D01 family')
    elif table=='graph_atoms':
        atom=AtomKey.from_token(key[0])
        if (column!='value'or key_columns!=('token','bot','persona')or key[1:]!=reader.namespace.as_tuple
                or NamespaceId.from_key(atom)!=reader.namespace or kind not in('action','outcome',
                    'life_progress','life_progress_provenance','cost','job','goal','cancellation')):
            raise AuthorityUnavailable('General graph metadata column escaped its fixed derive family')
        kinds={'action':'d08.action_intent.v1','outcome':'d08.action_outcome.v1','life_progress':'d10.life_progress.v1',
            'life_progress_provenance':'d10.life_progress_provenance.v1','cost':'runtime.cost_settlement','job':'runtime.job',
            'goal':'d08.goal.v1','cancellation':'d08.action_cancellation.v1'}
        if atom.type_name!=kinds[kind]:raise AuthorityUnavailable('General metadata kind changed its exact registered Graph type')
    else:raise AuthorityUnavailable('General metadata cannot borrow D07/Method/Owner columns')
    return BackgroundJSONColumnV3(_ISSUER,reader,table=table,column=column,key_columns=key_columns,key=key,
        cell_id=cell_id,signer=reader.graph._GraphCoordinator__d11_issuer._signer if signature_kind is not None else None,
        signature_kind=signature_kind,signature=signature,general_metadata_profile=(table,kind))


def finish_current_general_growth_trial_metadata_column_v1(column,*,reader,kind):
    require_current_general_growth_trial_metadata_reader_v1(reader)
    column._actual_v3()
    if (column.owner is not reader or not column.complete
            or column.general_metadata_profile!=(column.table,kind)):
        raise AuthorityUnavailable('General metadata profile lacks its own complete original EOF')
    from .dispatch_initial_source_read_v3 import _container_bytes_v3
    reader.reserve_heap_v3(extra=_container_bytes_v3(column.frozen)+1024)
    return _detach_value_v3(column.frozen)


def _read_bound_general_growth_metadata_result_v1(db,identity):
    reader=_active_v3(db)
    if reader is None:return False,None
    require_current_general_growth_trial_metadata_reader_v1(reader)
    task=reader.general_trial_metadata.get(identity)
    if task is None or not task.complete:
        if reader.sealed:raise AuthorityUnavailable('General metadata lacks complete raw canonical signed EOF')
        raise BackgroundReadNeededV3(('d01_general_input_metadata',identity))
    task.require_reader_v1()
    return True,task.result


def read_bound_background_general_growth_input_metadata_v1(db,*,table,namespace,original_ref,kind=None):
    if table!='graph_d01_production_inputs_v1':raise AuthorityUnavailable('General derive signed metadata has another table')
    reader=_active_v3(db)
    if reader is None:return False,None
    require_current_general_growth_trial_metadata_reader_v1(reader)
    if namespace!=reader.namespace:raise AuthorityUnavailable('General metadata crossed actual namespace')
    if kind is None:raise AuthorityUnavailable('General metadata requires its fixed actual input kind')
    handled,result=_read_bound_general_growth_metadata_result_v1(db,('signed',table,kind,original_ref))
    if result is None:return handled,None
    from .dispatch_initial_source_read_v3 import _container_bytes_v3
    reader.reserve_heap_v3(extra=_container_bytes_v3(result[0])+1024)
    return handled,(_detach_value_v3(result[0]),result[1])


def read_bound_background_general_growth_graph_metadata_v1(db,*,namespace,key,kind):
    reader=_active_v3(db)
    if reader is None:return False,None
    require_current_general_growth_trial_metadata_reader_v1(reader)
    if namespace!=reader.namespace:raise AuthorityUnavailable('General graph metadata crossed actual namespace')
    if type(key)is str:key=AtomKey.from_token(key)
    handled,result=_read_bound_general_growth_metadata_result_v1(db,('graph',kind,key.token))
    if result is not None:result.require_for_v1(reader)
    return handled,result


def read_bound_background_general_growth_start_metadata_inventory_v1(db,*,namespace,issuer,limit=129):
    reader=_active_v3(db)
    if reader is None:return False,None
    require_current_general_growth_trial_metadata_reader_v1(reader)
    if(namespace!=reader.namespace or issuer is not reader.graph._GraphCoordinator__d11_issuer or limit!=129):
        raise AuthorityUnavailable('General start inventory changed its actual signer/namespace/original bound')
    handled,result=_read_bound_general_growth_metadata_result_v1(db,('starts',129))
    from .dispatch_initial_source_read_v3 import _container_bytes_v3
    reader.reserve_heap_v3(extra=sum(_container_bytes_v3(value)for value,_ in result[0])+1024)
    return handled,(tuple((_detach_value_v3(value),ref)for value,ref in result[0]),result[1])



def read_bound_background_general_growth_type_metadata_v1(db,*,namespace,type_id,limit=129):
    reader=_active_v3(db)
    if reader is None:return False,None
    require_current_general_growth_trial_metadata_reader_v1(reader)
    if namespace!=reader.namespace or type_id!='runtime.cost_settlement' or limit!=129:
        raise AuthorityUnavailable('General derive metadata inventory is the actual cost-only complete selector')
    handled,result=_read_bound_general_growth_metadata_result_v1(db,('type',type_id,129))
    for record in result[0]:record.require_for_v1(reader)
    return handled,result


def _general_growth_background_payload_heap_v1(value,seen):
    from dataclasses import fields
    from .d01_general_growth_v1 import GeneralOwnerGraphMetadataV1
    from .domain_production_followups_v1 import GeneralGrowthTrialFollowupCommandV1,DomainFollowupResolutionV1
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from ..runtime_contracts import AuthorityContext,CommitReceipt
    from ..graph_types import NamespaceEpoch
    from ..graph_types import Owner
    from sys import getsizeof
    from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
    if id(value)in seen:return 0
    if type(value)in(_FrozenObjectV3,_FrozenArrayV3):
        seen.add(id(value));return getsizeof(value)+_general_growth_background_payload_heap_v1(value.items,seen)
    if type(value)is GeneralOwnerGraphMetadataV1:
        seen.add(id(value))
        return getsizeof(value)+getsizeof(value.__dict__)+_general_growth_background_payload_heap_v1(
            (value.key,value.revision,value.valid,value.payload_digest,value._frozen_value),seen)
    if type(value)in(GeneralGrowthTrialFollowupCommandV1,ProductionOriginalRefV1,AuthorityContext,CommitReceipt,DomainFollowupResolutionV1,AtomKey,Owner,GraphVersion,NamespaceEpoch,NamespaceId):
        seen.add(id(value))
        return getsizeof(value)+(getsizeof(value.__dict__)if hasattr(value,'__dict__')else 0)+sum(_general_growth_background_payload_heap_v1(getattr(value,f.name),seen)for f in fields(value))
    if type(value)is dict:
        seen.add(id(value));return getsizeof(value)+sum(_general_growth_background_payload_heap_v1(k,seen)+
            _general_growth_background_payload_heap_v1(v,seen)for k,v in value.items())
    if type(value)in(tuple,list,set,frozenset):
        seen.add(id(value));return getsizeof(value)+sum(_general_growth_background_payload_heap_v1(v,seen)for v in value)
    return _frozen_heap_v3(value,seen)


def _general_growth_background_task_heap_v1(task,seen):
    from sys import getsizeof
    if id(task)in seen:return 0
    seen.add(id(task))
    size=getsizeof(task)+getsizeof(task.__dict__)
    for name in('identity','metadata','rows','cursor','result','key','kind','table','type_id','original_ref','phase','coverage_versions','value'):
        if name in task.__dict__:size+=_general_growth_background_payload_heap_v1(task.__dict__[name],seen)
    if task.child is not None:size+=_general_growth_background_task_heap_v1(task.child,seen)
    return size


@contextmanager
def bind_general_growth_trial_fresh_write_v1(reader,*,issued,scope,guard,current_owner):
    from .domain_followup_consumer_v1 import general_growth_trial_child_command_allowed_v1
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    if (not reader.sealed or reader.kind!='followup_child'or issued.command is not reader.handoff.command
            or not general_growth_trial_child_command_allowed_v1(issued,reader.graph,issued.command)
            or scope.operation!='write'or scope.permit.operation!='write'
            or scope.namespace!=reader.namespace or current_owner.namespace!=reader.namespace
            or guard.authorization_head!=current_owner.authorization_head
            or guard.authorization_revision!=current_owner.authorization_revision):
        raise AuthorityUnavailable('General metadata WRITE binder is not its actual current private child/Owner scope')
    token=_GENERAL_GROWTH_WRITE_METADATA_V1.set((reader,scope,current_owner))
    try:yield
    finally:_GENERAL_GROWTH_WRITE_METADATA_V1.reset(token)


@lru_cache(maxsize=1)
def _general_growth_metadata_dto_layout_v1():
    from dataclasses import is_dataclass,fields
    from sys import getsizeof
    from .. import runtime_contracts,graph_types
    from . import domain_production_contracts_v1,d01_general_growth_v1
    classes=tuple(value for module in(runtime_contracts,graph_types,domain_production_contracts_v1,d01_general_growth_v1)
        for value in vars(module).values()if isinstance(value,type)and is_dataclass(value))
    # An actual closed DTO plus its keyword dictionary and, where present, instance dictionary.
    return max(value.__basicsize__+getsizeof({field.name:None for field in fields(value)})*
        (2 if value.__dictoffset__ else 1)for value in classes)


def _general_growth_metadata_decode_peak_v1(raw):
    from sys import getsizeof
    from .dispatch_initial_source_read_v3 import _container_bytes_v3
    layout=_general_growth_metadata_dto_layout_v1()
    objects=0;slots=0;strings=0;characters=0;longest=0
    stack=[raw]
    while stack:
        value=stack.pop()
        if type(value)is dict:
            objects+=1;slots+=getsizeof(value);stack.extend(value.values())
        elif type(value)is list:
            slots+=getsizeof(())+8*len(value);stack.extend(value)
        elif type(value)is str:
            strings+=1;characters+=len(value);longest=max(longest,len(value))
    # AtomKey's closed six-string token: decoded strings/Owner/key plus one
    # canonical equality encoding peak; other scalar fields reuse their objects.
    return (_container_bytes_v3(raw)+objects*layout+slots+
        strings*(getsizeof([])+8*8+6*getsizeof('')+2*layout)+4*characters+36*longest)


def require_current_general_growth_trial_metadata_coverage_v1(prepared,*,db,graph,namespace,type_id):
    if (type(prepared)is not PreparedBackgroundFrameInputsV3 or prepared not in _PREPARED
            or prepared.owner.db is not db or prepared.owner.graph is not graph
            or prepared.owner.namespace!=namespace or type_id!='runtime.cost_settlement'
            or type_id not in prepared.plan.fixed_type_ids):
        raise AuthorityUnavailable('General query coverage requires its actual private child frame and cost-only family')
    reader=require_current_general_growth_trial_metadata_reader_v1(prepared.owner)
    handled,(records,complete)=read_bound_background_general_growth_type_metadata_v1(db,
        namespace=namespace,type_id=type_id,limit=129)
    if not handled or not complete or len(records)>128:
        from .d01_production_operations_v1 import MissingProductionOriginalV1
        raise MissingProductionOriginalV1('complete_general_trial_actual_cost_inventory')
    task=reader.general_trial_metadata[('type',type_id,129)]
    if 'coverage_versions'not in task.__dict__:
        from sys import getsizeof
        reader.reserve_heap_v3(extra=getsizeof(())+8*len(records)+len(records)*_general_growth_metadata_dto_layout_v1())
        task.coverage_versions=tuple(GraphVersion(record.key,record.revision)for record in records)
    return task.coverage_versions
