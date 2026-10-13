"""Same-operation, fixed-family background reads; never an execution grant."""
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass
from types import MappingProxyType
from weakref import WeakSet, WeakKeyDictionary, ref
import json

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphVersion, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest
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

# Only the actual outbox/offline algorithms below may request these SQL families.
_POINT_KEYS=MappingProxyType({
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
    'graph_d02_action_components_v1':('bot','persona','original_ref'),
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

})
_FOLLOWUP_TYPES=MappingProxyType({
    'd01':('d01.persona_activation.v1','d01.persona_plan.v1','d07.current_interpretation.v1'),
    'd08':('d08.action_intent.v1','d08.action_outcome.v1','d08.commitment.v1','d08.goal.v1','d08.joint_plan.v1',
        'd08.action_schema.v1','d05.boundary_rule','d05.relationship_projection'),
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
    'graph_d10_production_inputs_v1':'d11.d10-production-input.v1',
    'graph_d02_action_components_v1':'d11.d02-completed-action-component.v1',
    'runtime_d11_owner_role_clock_originals_v1':'d11.owner-role-clock-installation.v1',
    'graph_d04_semantic_installations_v3':'d11.owner-selected-d04-semantic-installation.v3',
})
_JSON_NAMES=frozenset({'value','reads','revisions','invalidated','dependencies','original_payload_json',
    'read_versions_json','receipt_json','payload_json','source_refs_json'})

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
    try:yield owner
    finally:_BOUND.reset(token)


def _require_json_column_owner_v3(owner,*,db):
    if type(owner)is BackgroundReadWorkV3:return require_actual_background_attachment_owner_v3(owner,db=db)
    from ..authority_service.model_reply_scope_observation_v3 import require_actual_model_reply_scope_column_owner_v3
    return require_actual_model_reply_scope_column_owner_v3(owner,db=db)


def _json_column_signer_v3(owner,table):
    if type(owner)is BackgroundReadWorkV3:
        require_actual_background_attachment_owner_v3(owner,db=owner.db)
        return(owner.graph._GraphCoordinator__d02_issuer._signer if table=='runtime_resource_quotes'
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
            signer=None,signature_kind=None,signature=None):
        if issuer is not _ISSUER:raise TypeError('background column issuer required')
        _require_json_column_owner_v3(owner,db=owner.db)
        self.owner,self.db,self.operation=owner,owner.db,owner.operation
        self.table,self.column,self.key_columns,self.key=table,column,tuple(key_columns),tuple(key)
        self.where=' AND '.join(_quote(n)+'=?'for n in self.key_columns)
        self.cell=begin_runtime_cell_read_v3(self.db,cell_id,erasure_owner_ref=self.key[0]if table=='graph_history'else None)if cell_id is not None else None
        codec=None if self.cell is None else self.cell.header[0]
        if codec is not None and codec not in ('canonical-json.ascii.v1','canonical-json.utf8.v1'):
            raise AuthorityUnavailable('background original has an unregistered JSON codec')
        self.locator=locator
        self.nodes={};self.value=None;self.scalar=bytearray()
        self.text_parts=[];self.text_chars=[];self.text_high=None
        self.fragment=b'';self.fragment_offset=0;self.offset=0;self.total=None
        self.complete=False;self.frozen=None;self.reserved=0;self.sha256=None;self.byte_count=None
        self.semantic_sha256=None;self.semantic_state=None;self.semantic_decoder=None
        if codec=='canonical-json.utf8.v1' and type(owner)is not BackgroundReadWorkV3:
            import codecs,hashlib
            self.semantic_state=hashlib.sha256()
            self.semantic_decoder=codecs.getincrementaldecoder('utf-8')('strict')
        self.signer,self.signature_kind,self.signature=signer,signature_kind,signature
        self.signature_state=None;self.signature_bytes=0;self.signature_verified=False
        self.parser=_BackgroundJSONStreamV3(self,ensure_ascii=codec!='canonical-json.utf8.v1')
        _COLUMNS[self]=(ref(owner),self.db,self.table,self.column,self.key_columns,self.key,self.cell,self.locator,
            self.signer,self.signature_kind,self.signature)
        if signer is not None:
            self.signature_state=signer.begin_original_stream_verification_v3(signature_kind,self)
        owner.columns.add(self)
        self._reserve_v3(65536)
    def _actual_v3(self):
        expected=_COLUMNS.get(self)
        actual=(ref(self.owner),self.db,self.table,self.column,self.key_columns,self.key,self.cell,self.locator,
            self.signer,self.signature_kind,self.signature)
        if expected!=actual:raise AuthorityUnavailable('background original column identity changed')
        _require_json_column_owner_v3(self.owner,db=self.db)
        return self
    def _reserve_v3(self,extra=0):
        self.owner.reserve_heap_v3(extra=extra+65536)
    def retain_path_v3(self,path):
        if type(self.owner)is not BackgroundReadWorkV3:
            _require_json_column_owner_v3(self.owner,db=self.db)
            return self.owner.retain_column_path_v3(self,path)
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
        if not self.complete or self.locator:raise AuthorityUnavailable('complete background JSON original required')
        from .dispatch_initial_source_read_v3 import _container_bytes_v3
        self.owner.reserve_heap_v3(extra=_container_bytes_v3(self.frozen)+1024)
        return _detach_value_v3(self.frozen)
    def matches_v3(self,value):
        self._actual_v3()
        from ..runtime_contracts import _canonical_value
        if not self.complete or self.locator:return False
        if type(self.owner)is not BackgroundReadWorkV3 and self.owner.metadata_only_column_v3(self):
            raise AuthorityUnavailable('model parentage metadata projection is not a full body equality proof')
        self.owner.reserve_heap_v3(extra=_heap(value)+65536)
        return _background_canonical_value_matches_v3(_canonical_value(value,set()),self.frozen)


def require_background_signature_column_v3(original,*,signer,kind,signature=None,verifier=None,complete=False):
    if type(original)is not BackgroundJSONColumnV3:raise AuthorityUnavailable('actual background signature column required')
    original._actual_v3()
    expected=(_SIGNED_INPUT_KINDS.get(original.table) if original.column in('payload_json','original_json') else
        'resource-quote.v1' if (original.table,original.column)==('runtime_resource_quotes','quote_json') else
        'budget-grant.v1' if (original.table,original.column)==('runtime_budget_grants','grant_json') else None)
    if (expected is None or original.signer is not signer or kind!=expected or original.signature_kind!=kind):
        raise AuthorityUnavailable('background signer/domain/column binding changed')
    if complete and (not original.complete or original.signature_state is not verifier
            or original.signature!=signature or original.signature_bytes!=original.byte_count):
        raise AuthorityUnavailable('background signature is not bound to complete actual raw-byte EOF')
    return original


def background_json_loads_v3(value):
    if type(value)is BackgroundJSONColumnV3:return value.json_v3()
    return json.loads(value)


def background_json_matches_v3(encoded,value):
    if type(encoded)is BackgroundJSONColumnV3:return encoded.matches_v3(value)
    from ..runtime_contracts import canonical_serialize
    return canonical_serialize(value)==encoded


def background_json_digest_v3(encoded,value):
    if type(encoded)is BackgroundJSONColumnV3:
        if not encoded.matches_v3(value):raise AuthorityUnavailable('background original decoded value changed')
        return encoded.sha256
    return canonical_digest(value)


def background_verify_signature_v3(signer,kind,payload,signature):
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
            name=self.pending.pop(0);cell=self.small.get('value_cell_id')if name=='value'else None
            if cell is None:
                meter.require_available(1024)
                kind=owner.db.execute('SELECT typeof('+_quote(name)+') FROM '+_quote(self.table)+' WHERE '+self.where,self.key).fetchone()
                meter.charge_read(8)
                if kind is None:raise AuthorityUnavailable('background point column disappeared')
                if kind[0]=='null':self.values[name]=None;return
                if kind[0]!='text':raise AuthorityUnavailable('background original JSON column changed kind')
            signature_kind=(_SIGNED_INPUT_KINDS[self.table] if self.table in _SIGNED_INPUT_KINDS and name in('payload_json','original_json') else
                'resource-quote.v1' if self.table=='runtime_resource_quotes' and name=='quote_json' else
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


def read_bound_background_graph_attachment_v3(db,*,table,columns,key_columns,key):
    from ..authority_service.model_reply_scope_observation_v3 import read_bound_model_reply_scope_point_v3
    observed,row=read_bound_model_reply_scope_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if observed:return True,row
    owner=_active_v3(db)
    if owner is None:return False,None
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    owner.require_request_v3(request)
    task=owner.points.get(request)
    if task is None or not task.complete:
        if owner.sealed:raise AuthorityUnavailable('background exact original was not prepared by this Work')
        raise BackgroundReadNeededV3(('point',request))
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as meter:
        owner.require_data_current_v3(meter);row=task.require_row_v3(meter)
    return True,row


def background_point_v3(db,*,table,columns,key_columns,key,legacy_reader):
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
        self.phase='algorithm' if kind=='offline_close' else 'owner_locator';self.sealed=False;self.complete=False;self.result=None
        self.points={};self.inventories={};self.scans={};self.physical_payloads={};self.heads={}
        self.pending=None;self.entry=None;self.entry_column=None;self.entry_metadata=None
        self.selected_plan=None;self.selected_envelope=None;self.selected_plans={};self.selected_envelopes={};self.local_result=None
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
        self.operation.handle.require_current(meter)
    def require_request_v3(self,request):
        table,columns,keys,key=request
        if table not in _POINT_KEYS or keys!=_POINT_KEYS[table]:raise AuthorityUnavailable('unregistered background exact SQL family')
        if table in('graph_atoms','graph_history'):
            atom=AtomKey.from_token(key[0])
            if NamespaceId.from_key(atom)!=self.namespace:raise AuthorityUnavailable('background exact head/history crossed namespace')
            self.store._registry.spec(atom.type_name)
        elif table.startswith('runtime_'):
            if table in('runtime_d11_owner_role_clock_originals_v1','runtime_d11_d04_root_freezes_v3'):
                if key[:2]!=self.namespace.as_tuple:raise AuthorityUnavailable('actual RoleClock/Root signed original crossed namespace')
            elif self.kind not in('offline','offline_close'):raise AuthorityUnavailable('historical budget originals require actual offline reader')
            if table=='runtime_budget_operations' and key[:2]!=self.namespace.as_tuple:raise AuthorityUnavailable('historical budget operation crossed namespace')
        elif key[:2]!=self.namespace.as_tuple:raise AuthorityUnavailable('background original crossed namespace')
        if table in _SIGNED_INPUT_KINDS:
            allowed={'revision','operation_id','original_json','original_digest','kind','original_ref','producing_operation_id','payload_json','payload_digest','signature','source_refs_json'}
            if not set(columns)<=allowed or len(key)!=len(keys):raise AuthorityUnavailable('unregistered background signed input columns/key')
            return
        allowed={
            'runtime_resource_quotes':{'quote_json','signature'},
            'runtime_budget_grants':{'grant_json','signature'},
            'runtime_budget_reservations':{'state','digest','ceiling_json','actual_json'},
            'runtime_budget_operations':{'digest','lease_id','receipt_json'},
            'runtime_clock_operations':{'digest','mapping_id','version','mapping_json'},
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
        }[table]
        if not set(columns)<=allowed or len(key)!=len(keys):raise AuthorityUnavailable('unregistered background original columns/key')
    def require_family_v3(self,type_id):
        allowed=set(_FOLLOWUP_TYPES[self.entry[1]])if self.kind in('followup','followup_child')and self.entry is not None else set()
        for plan in self.selected_plans.values():allowed.update(plan.fixed_type_ids)
        if self.kind=='offline':allowed.add('d10.offline_checkpoint.v1')
        if self.role_clocks:allowed.update(('d04.numeric_checkpoint.v1','d04.numeric_checkpoint.v2','d03.role_binding'))
        if type_id not in allowed:raise AuthorityUnavailable('background fixed family has no selected business plan')
    def require_rows_request_v3(self,request):
        table,columns,groups,group,order,limit=request
        role_shapes={
            ('graph_c09_rebase_certificates_v1',('operation_id',),('bot','persona'),('operation_id',)),
            ('graph_d04_originals_v3',('original_ref',),('bot','persona','kind'),('original_ref',)),
            ('graph_d04_joint_advance_members_v2',('checkpoint_ref','process_id','role_start','role_end'),('bot','persona','operation_id'),('checkpoint_ref',)),
        }
        if (table,columns,groups,order)in role_shapes:
            if not self.role_clocks or group[:2]!=self.namespace.as_tuple or limit is not None:
                raise AuthorityUnavailable('RoleClock library metadata request changed its actual family')
            return
        if table not in('graph_d11_offline_originals_v1','graph_d10_production_inputs_v1') or groups!=('bot','persona','kind'):
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
        # Only local data is reused. The caller supplies its newly observed actual WRITE scope/Owner.
        if (scope.graph_revision,scope.graph_epoch)!=(self.graph_stamp[0].graph_revision,self.graph_stamp[1]):
            raise AuthorityUnavailable('background child WRITE lost original data stamp')
    def release_payload_v3(self):
        self.points.clear();self.inventories.clear();self.scans.clear();self.physical_payloads.clear();self.heads.clear()
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
    seen=set();size=_heap((owner.entry,owner.entry_metadata,owner.heads),seen)+65536+extra
    size+=sum(_heap((point.metadata,point.small,point.pending,point.request),seen)for point in owner.points.values())
    size+=sum(_heap((task.after,task.rows),seen)for task in owner.scans.values())
    size+=sum(_heap(tuple((atom.key,atom.revision,atom.valid,atom.value)for atom in task.rows),seen)for task in owner.inventories.values())
    size+=sum(_heap((task.material,task.value),seen) for task in owner.typed_digests.values())
    size+=sum(_heap((task.args,task.result),seen) for task in owner.predecessors.values())
    size+=sum(_heap((task.nodes,task.value,task.scalar,task.text_parts,task.text_chars),seen)+_frozen_heap_v3(task.frozen,seen) for task in owner.embedded_json.values())
    size+=sum(_heap((task.selections,None if task.proof is None else task.proof.inputs),seen) for task in owner.role_clocks.values())
    size+=sum(_heap((task.after,task.rows, None if task.pending is None else task.pending.metadata),seen) for task in owner.offline_lookups.values())
    for column in owner.columns:
        size+=_heap((column.nodes,column.value,column.scalar,column.text_parts,column.text_chars,column.fragment),seen)
        size+=_frozen_heap_v3(column.frozen,seen)
    if owner.local_result is not None:
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
    o=reader;key=owner_grant_key(*o.namespace.as_tuple)
    request=('graph_atoms',('revision','value','valid'),('token','bot','persona'),(key.token,*o.namespace.as_tuple))
    point=o.points[request];row=point.row
    if row is None or row[2]!=1:raise AuthorityUnavailable('background current Owner locator is absent')
    grant=background_json_loads_v3(row[1]);validate_owner_grant_v1(grant)
    principal=OwnerPrincipalV1(**grant['principal']);metadata=o.graph_stamp[0]
    port=o.graph._GraphCoordinator__content_fence_v2
    pairing=port.current_owner_principal_binding(namespace=o.namespace,
        authority_namespace=metadata.requirements.authority_namespace,principal=principal)
    if pairing is None:raise AuthorityUnavailable('background current Owner locator has no actual pairing')
    if o.kind in('followup','followup_child'):
        raw=o.entry_metadata[1]['authority'];purpose=raw['purpose'];audiences=tuple(raw['audience']);domains=tuple(raw['owner_scope'])
    elif o.kind=='host_lifecycle':
        purpose=o.local_result[1][0];audiences=o.local_result[0];domains=('d06','d11')
    else:purpose=grant['purposes'][0];audiences=(grant['audiences'][0],);domains=('d02','d06','d10','d11')
    return AuthorityContext(pairing.actor_id,'d10'if o.kind=='offline'else'd11'if o.kind=='host_lifecycle'else'd12',
        'installed-background:'+o.operation.operation_id,o.namespace,domains,purpose,audiences,
        port.installation_grant.publisher_policy_ref,metadata.requirements.activation_generation)


def prepare_domain_background_read_v3(graph,bootstrap,installed_bundle,*,kind,operation_id,deadline_utc,dedupe_key=None,context=None,observer=None,observation=None):
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,finish_runtime_storage_operation_v3
    from ..runtime_context import RuntimeContext
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    if kind not in('followup','followup_child','offline','offline_close','host_lifecycle'):raise ValueError('unregistered background business kind')
    if kind in('followup','followup_child'):
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
            from .first_ingress_v2 import trusted_upper
            reader.now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
            work=create_graph_storage_work_v3(graph,kind='domain_background_read_v3',operation_id=operation_id,
                selection_digest=operation.selection_digest,deadline_utc=deadline_utc,state=reader,operation=operation)
            reader.work=work
        return work
    except BaseException:
        finish_runtime_storage_operation_v3(operation);raise


def _prepare_background_algorithm_v3(reader):
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
    if not pending.complete:pending.advance(meter)
    if pending.complete:reader.pending=None


def _start_background_request_v3(reader,request):
    kind=request[0]
    if kind=='point':
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
    else:raise AuthorityUnavailable('unregistered background local preparation request')
    reader.pending=task


def advance_domain_background_read_v3(graph,work):
    from ..graph_worker import GraphStorageStepV3
    from .domain_followup_consumer_v1 import _observe_owner
    from .first_ingress_v2 import trusted_upper
    reader=work.state;require_actual_background_attachment_owner_v3(reader,db=reader.db)
    with bind_runtime_storage_operation_v3(reader.operation,reader.db):
        if reader.phase=='authorize':
            reader.authority=_background_authority_v3(reader)
            captured=[]
            def observe(scope):
                actual=_observe_owner(graph,reader.authority,scope);captured[:]=[actual];return actual
            reader.fence=graph._begin_read_fence_v3(reader.authority,operation_id=reader.operation.operation_id,fence_observer=observe)
            reader.owner_guard,reader.owner=captured[0]
            reader.read_scope=reader.fence.scope
            reader.graph_stamp=(reader.fence.metadata,reader.fence.epoch)
            reader.phase='algorithm';return GraphStorageStepV3('progress')
        if reader.phase=='protected':
            if reader.kind=='offline_close':
                reader.sealed=True;reader.complete=True
                reader.result=PreparedBackgroundOperationV3(_ISSUER,reader)
                return GraphStorageStepV3('complete',reader.result)
            graph._validate_read_fence_v3(reader.fence)
            guard,owner=_observe_owner(graph,reader.authority,reader.fence.scope)
            if (guard,owner)!=(reader.owner_guard,reader.owner):raise AuthorityUnavailable('background final actual Owner changed')
            reader.sealed=True;reader.complete=True
            reader.result=PreparedBackgroundOperationV3(_ISSUER,reader)
            return GraphStorageStepV3('complete',reader.result)
        if reader.fence is not None:graph._validate_read_fence_v3(reader.fence)
        actual_reader=graph._GraphCoordinator__d04_semantic_mapping_reader
        role_progress=reader.role_clocks.get(actual_reader)
        host_fence=(actual_reader.current_fence(reader.fence.scope) if role_progress is not None
            and role_progress.phase!='selections' else nullcontext())
        with bind_background_reads_v3(reader,db=reader.db),host_fence,reader.store._lock,runtime_storage_quantum_v3(reader.db)as meter:
            reader.db.execute('BEGIN')
            try:
                reader.require_data_current_v3(meter)
                if reader.pending is not None:_advance_background_pending_v3(reader,meter)
                elif reader.phase=='owner_locator':
                    key=owner_grant_key(*reader.namespace.as_tuple)
                    request=('graph_atoms',('revision','value','valid'),('token','bot','persona'),(key.token,*reader.namespace.as_tuple))
                    task=reader.points.get(request)
                    if task is None:task=_BackgroundPointReadV3(reader,request);reader.points[request]=task
                    task.advance(meter)
                    if task.complete:reader.phase='entry_locator'if reader.kind in('followup','followup_child')else'host_scope'if reader.kind=='host_lifecycle'else'authorize'
                elif reader.phase=='entry_locator':
                    if reader.entry_column is None:reader.entry_column=_BackgroundEntryLocatorV3(reader)
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
                elif reader.phase=='algorithm':
                    with bind_background_reads_v3(reader,db=reader.db):
                        try:reader.local_result=_prepare_background_algorithm_v3(reader);reader.phase='protected'
                        except BackgroundReadNeededV3 as needed:_start_background_request_v3(reader,needed.request)
                reader.reserve_heap_v3()
            finally:reader.db.rollback()
        if reader.fence is not None:graph._validate_read_fence_v3(reader.fence)
    return GraphStorageStepV3('progress')


def finish_domain_background_read_v3(graph,work,error):
    from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
    reader=work.state
    try:
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
    owner=_active_v3(db)
    if owner is None:return False,None
    if namespace!=owner.namespace or NamespaceId.from_key(key)!=namespace:
        raise AuthorityUnavailable('background head crossed its actual selected namespace')
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
