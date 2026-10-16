
"""Actual Host D07 stage Source qualification before any prepared/request body.

The original Background Work owns retention and the admitted phase Scope.
Owner metadata admission and effective Source/Self authority are separate proofs.
"""
from __future__ import annotations
from dataclasses import fields,dataclass
from weakref import WeakKeyDictionary
from contextlib import contextmanager
from datetime import datetime
import json
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,AuthorityContext,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3,bind_runtime_storage_operation_v3,_runtime_bounded_fixed_row_v3
from .domain_background_read_v3 import BackgroundReadWorkV3,BackgroundJSONColumnV3,_ISSUER as _COLUMN_ISSUER,require_actual_background_attachment_owner_v3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .dispatch_current_inventory_v3 import _detach_value_v3
from .source_correction_read_v3 import _heap
from .domain_production_erasure_v1 import decode_typed_production_value_v1
_HOST_ISSUER=object()
_HOST_METADATA=WeakKeyDictionary()
_HOST_SCOPES=WeakKeyDictionary()
_HOST_PARENT_TASKS=WeakKeyDictionary()

class _HostMetadataNeededV3(Exception):
    def __init__(self,task):self.task=task

class _HostParentColumnV3(BackgroundJSONColumnV3):
    """The exact metadata modes share a pure field filter, never an Authority issuer."""
    def __init__(self,reader,*,table,column,key_columns,key,mode,cell_id=None,erasure_owner_ref=None):
        self.reader,self.mode=reader,mode
        self.fields_seen=set()
        super().__init__(_COLUMN_ISSUER,reader.work,table=table,column=column,key_columns=key_columns,
            key=key,cell_id=cell_id,locator=True)
        self.canonical_semantic_digest=None
        import codecs
        from hashlib import sha256
        self.semantic_decoder=codecs.getincrementaldecoder("utf8")("strict") if self.cell is not None and self.cell.header[0]=="canonical-json.utf8.v1" else None
        self.semantic_hash=sha256() if self.semantic_decoder is not None else None
    def retain_path_v3(self,path):
        from ..authority_service.d07_authority_model_source_read_v3 import _D07ParentMetadataColumnV3
        if self.mode=="request":
            return not path or path[0]not in {"inputs","payload"}
        if self.mode=="bundle":
            if not path:return True
            if path[0]=="first_ingress_c02":return len(path)==1
            return path[0] in {"status","operation_id","operation_digest","activity_id","effect_id","commit_seq",
                "read_versions","write_versions","invalidated_epochs","ledger_refs","outbox_refs",
                "schema","phase","prepared_digest","graph_receipt_digest","method_growth_c3","relationship_c3","reflection_c3"}
        if self.mode in {"source_commitment","terminal_result"}:return not path
        if self.mode=="prepare_commit":
            if not path:return True
            if path[0]=="post_read_rows":return len(path)<=2 or len(path)==3 and path[2]in {"ref","revision","valid"}
            return True
        if self.mode=="general_question":
            return not path or path[0] not in {"question","question_text","text","content"}
        return _D07ParentMetadataColumnV3._retain_v3(self,path)
    def _emit_v3(self,event):
        if event.kind=="key" and len(event.path)==1:self.fields_seen.add(event.key)
        super()._emit_v3(event)
    def advance(self,meter):
        self.reader.require_current_v3(meter)
        if self.complete:return True
        if self.semantic_decoder is not None and self.fragment_offset<len(self.fragment):
            self._semantic_v3(self.fragment[self.fragment_offset:min(self.fragment_offset+1024,len(self.fragment))],meter)
        done=super().advance(meter)
        if done:
            if self.semantic_decoder is None:self.canonical_semantic_digest=self.sha256
            else:
                self._semantic_v3(b"",meter,final=True);self.canonical_semantic_digest=self.semantic_hash.hexdigest()
            self.semantic_decoder=self.semantic_hash=None
        return done
    def _semantic_v3(self,fragment,meter,*,final=False):
        from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
        _D07AuthorityGraphMetadataColumnV3._semantic_v3(self,fragment,meter,final=final)
    def require_v3(self,work):
        self._actual_v3()
        if work is not self.owner or not self.complete:raise AuthorityUnavailable("same actual Host metadata column EOF required")
        return _detach_value_v3(self.frozen)

class _HostPreparedHeaderV3:
    def __init__(self,reader,job_id,expected_digest=None):
        self.reader,self.work,self.job_id=reader,reader.work,job_id
        self.expected_digest=expected_digest;self.phase="identity";self.complete=False
        self.metadata=self.column=self.value=None
    def advance_v3(self,meter):
        from .d07_execution_v1 import TABLE,SIGN_KIND
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,TABLE,("payload_digest","signature"),
                "bot=? AND persona=? AND kind='prepared' AND original_ref=?",(*w.namespace.as_tuple,self.job_id))
            if self.metadata is None or self.expected_digest is not None and self.metadata[0]!=self.expected_digest:
                raise AuthorityUnavailable("actual signed Host parent preparation differs")
            self.column=_HostPreparedLocatorColumnV3(r,table=TABLE,column="payload_json",
                key_columns=("bot","persona","kind","original_ref"),key=(*w.namespace.as_tuple,"prepared",self.job_id),mode="prepared")
            self.phase="bytes";return
        if not self.column.advance(meter):return
        if self.column.sha256!=self.metadata[0]:raise AuthorityUnavailable("Host preparation metadata lacks full canonical EOF")
        w.d07_service.d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((w.namespace,"prepared",self.job_id,self.metadata[0])),self.metadata[1])
        self.value=self.column.require_v3(w)
        self.prepared_class=_host_prepared_class_v3(self.value["schema"])
        if self.column.fields_seen!={field.name for field in fields(self.prepared_class)}:
            raise AuthorityUnavailable("Host preparation has unregistered metadata fields")
        if self.value["namespace"]!={"bot_id":w.namespace.bot_id,"persona_id":w.namespace.persona_id} or self.value["job_id"]!=self.job_id:
            raise AuthorityUnavailable("Host preparation metadata crossed actual namespace/job")
        self.authority=decode_typed_production_value_v1(json.loads(self.value["owner_authority_json"]),AuthorityContext)
        self.source_rows=tuple(row for row in self.value["read_rows"] if row["valid"] and AtomKey.from_token(row["ref"]).type_name=="memory.source")
        self.complete=True
    def require_v3(self,reader):
        reader.require_registered_v3()
        if reader is not self.reader or not self.complete:raise AuthorityUnavailable("actual Host parent header EOF required")
        return self

class _HostPreparedStreamV3(C09CanonicalJSONStreamV2):
    def __init__(self,column):
        self.column=column;super().__init__(ensure_ascii=True)
    def _append_decoded_codepoint(self,point):
        state=self._string
        if state is not None and state["mode"]=="value" and state["path"]==("frozen_json",):
            self.column.frozen_metadata.feed_codepoint_v3(point)
        elif state is not None and state["mode"]=="value":
            super()._append_decoded_codepoint(point)
            BackgroundString=self.column
            if BackgroundString.retain_path_v3(state["path"]):
                high=BackgroundString.text_high
                if high is not None:
                    BackgroundString.text_high=None
                    if 0xdc00<=point<=0xdfff:
                        BackgroundString.text_chars.append(chr(0x10000+((high-0xd800)<<10)+point-0xdc00));return
                    BackgroundString.text_chars.append(chr(high))
                if 0xd800<=point<=0xdbff:BackgroundString.text_high=point
                else:BackgroundString.text_chars.append(chr(point))
        else:super()._append_decoded_codepoint(point)
class _HostFrozenMetadataReadV3:
    def __init__(self):
        from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityFrozenMetadataReadV3
        self.kernel=_D07AuthorityFrozenMetadataReadV3()
        self.kernel._retain_v3=self._retain_v3
    def _retain_v3(self,path):
        if len(path)>1 and path[0]=="input" and path[1]in {"context_sources","support_sources"}:
            return len(path)<=3 or path[3]=="source_ref"
        from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityFrozenMetadataReadV3
        return _D07AuthorityFrozenMetadataReadV3._retain_v3(self.kernel,path)
    def feed_codepoint_v3(self,point):self.kernel.feed_codepoint_v3(point)
    def finish_v3(self):return self.kernel.finish_v3()
    @property
    def value(self):return self.kernel.value
class _HostPreparedLocatorColumnV3(_HostParentColumnV3):
    def __init__(self,reader,**kwargs):
        from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityFrozenMetadataReadV3
        self.frozen_metadata=_HostFrozenMetadataReadV3()
        super().__init__(reader,**kwargs);self.parser=_HostPreparedStreamV3(self)
    def retain_path_v3(self,path):
        if not path:return True
        if path[0]=="frozen_json":return False
        if path[0]=="read_rows":return len(path)<=2 or len(path)==3 and path[2] in {"ref","revision","valid"}
        return path[0] not in {"query_inventory_json","external_content_originals_json","clock_mapping_json"}
    def _emit_v3(self,event):
        if event.path==("frozen_json",) and event.kind=="scalar_end":self.frozen_metadata.finish_v3()
        super()._emit_v3(event)
def _host_prepared_class_v3(schema):
    from .d07_execution_v1 import D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3
    from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
    from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
    types={item.__dataclass_fields__["schema"].default:item for item in
        (D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3,D07MethodGrowthPreparedV2,D07GeneralGrowthPreparedV1)}
    if schema not in types:raise AuthorityUnavailable("unregistered actual Host prepared stage schema")
    return types[schema]

class _HostMetadataReaderV3:
    def __init__(self,issuer,owner,owner_entry):
        if issuer is not _HOST_ISSUER:raise AuthorityUnavailable("actual Host metadata producer required")
        self.work,self.bundle,self.owner_header_proof=owner,owner.bundle,owner_entry
        self.owner_acl_authority=owner_entry.owner_acl_authority
        self.header=None;self.parent_headers={};self.graph_points={};self.pending=None
        self.reserved=0;self.current_self=None;self.budget_states={};self.stage_job=None;self.container=None
        owner.operation.register_retained_state_v3(self)
        _HOST_METADATA[self]=(owner,owner_entry,owner.read_scope,owner.operation,owner.graph_stamp)
    def require_registered_v3(self):
        w=self.work
        if (_HOST_METADATA.get(self)!=(w,self.owner_header_proof,w.read_scope,w.operation,w.graph_stamp)
                or type(w) is not BackgroundReadWorkV3 or w.kind!="d07_stage"):
            raise AuthorityUnavailable("actual same originating Host D07 metadata Work required")
        require_actual_background_attachment_owner_v3(w,db=w.db)
        return self
    def require_current_v3(self,meter):
        self.require_registered_v3();w=self.work
        if not w.store._lock._is_owned() or not w.db.in_transaction:
            raise AuthorityUnavailable("Host stage metadata needs its actual bounded SQL quantum")
        w.require_data_current_v3(meter)
        if w.d07_selector.stage!="egress_seal":
            self.owner_header_proof.require_for_v3(w)
        return self
    def now_v3(self):return self.work.d07_stage_clock_utc
    def source_authority_v3(self,header):
        source=header.authority;w=self.work
        if (source.namespace!=w.namespace or source.purpose!=header.value["purpose"]
                or tuple(source.audience)!=tuple(header.value["audience"])
                or source.activation_generation!=w.read_scope.generation):
            raise AuthorityUnavailable("Host original effective Source authority metadata differs")
        if source.actor==self.owner_acl_authority.actor:return source
        from .d07_execution_v1 import D07PreparedExecutionV1,D07ReflectionPreparedV3
        if header.prepared_class is D07PreparedExecutionV1 or header.prepared_class is D07ReflectionPreparedV3 and header.value["cycle_ref"] is None:
            raise AuthorityUnavailable("ordinary Owner preparation cannot borrow current Self")
        if self.current_self is None or self.current_self.self_entity_ref!=source.actor:
            raise AuthorityUnavailable("Host effective Source actor has no actual current paired Self certificate")
        from ..domains.d03.self_perspective import self_mapping_key
        from ..domains.d03.self_identity_qualification import self_identity_mapping_from_current
        _,_,mapping=_host_parent_head_v3(self,self_mapping_key(w.namespace).token)
        from ..domains.d01.production_operations_v1 import plain_v1
        if mapping!=plain_v1(self_identity_mapping_from_current(self.current_self)):
            raise AuthorityUnavailable("Host Source actor differs from its actual current Self mapping")
        return source
    def graph_point_v3(self,ref):
        point=self.graph_points.get(ref)
        if point is None:point=_HostGraphParentMetadataReadV3(self,ref);self.graph_points[ref]=point
        if not point.complete:raise _HostMetadataNeededV3(point)
        return point
    def _runtime_retained_heap_bytes_v3(self):
        def header_payload(header):
            return (header.value,None if header.column is None else header.column.frozen_metadata.kernel.nodes)
        extra=[]
        if self.container is not None:
            for task in (self.container.parents,self.container.accounting):
                if task is not None:
                    for leaf in task.leaves.values():
                        extra.append(tuple(getattr(leaf,name,None)for name in
                            ("value","payload","read_versions","continuation","operator_versions","grant","metadata")))
            task=self.container.accounting
            if task is not None:extra.append((getattr(task,"quote",None),getattr(task,"reservation",None)))
        payload=(None if self.header is None else header_payload(self.header),
            tuple(header_payload(header)for header in self.parent_headers.values()),
            tuple(point.value if point.complete else None for point in self.graph_points.values()),
            tuple(task.value if task.complete else None for task in self.budget_states.values()),tuple(extra))
        return _heap(payload)+131072
    def reserve_v3(self):self.work.operation.refresh_retained_state_v3(self)

@dataclass(frozen=True)
class _HostParentQualifiedV3:
    issuer:object
    task:object
    kind:str
    effective_source_authority:AuthorityContext
    parent_originals:tuple
    original_deadline_utc:float
    source_versions:tuple
    def __init__(self,issuer,task,*,kind,authority,parent_originals,deadline,source_versions):
        if issuer is not _HOST_ISSUER or not task.complete:
            raise AuthorityUnavailable("completed actual Host parent metadata required")
        for name,value in (("issuer",issuer),("task",task),("kind",kind),("effective_source_authority",authority),
                ("parent_originals",tuple(parent_originals)),("original_deadline_utc",deadline),("source_versions",tuple(source_versions))):
            object.__setattr__(self,name,value)
def _host_parent_source_authority_v3(reader,header):return reader.source_authority_v3(header)
def _host_metadata_commitment_v3(reader,key):
    if key==owner_grant_key(*reader.work.namespace.as_tuple):
        owner=reader.work.owner
        return owner.grant_revision,True,owner.grant_digest.removeprefix("sha256:"),None
    point=reader.graph_point_v3(key.token)
    return point.revision,point.valid,point.semantic_digest,point.cell_id
def _host_parent_head_v3(reader,ref,*,revision=None,digest=None):
    key=AtomKey.from_token(ref)
    if key==owner_grant_key(*reader.work.namespace.as_tuple):
        owner=reader.work.owner
        observed_revision,observed_digest=owner.grant_revision,owner.grant_digest.removeprefix("sha256:")
        value={"grant_ref":key.token,"grant_revision":observed_revision,"grant_digest":observed_digest}
    else:
        point=reader.graph_point_v3(ref)
        observed_revision,observed_digest,value=point.revision,point.semantic_digest,point.value
    if revision is not None and revision!=observed_revision or digest is not None and digest!=observed_digest:
        raise AuthorityUnavailable("Host actual parent head metadata commitment changed")
    return observed_revision,observed_digest,value
class _HostSignedParentMetadataReadV3:
    def __init__(self,reader,*,family,kind,ref,expected_digest=None,mode=None):
        self.mode=mode
        self.reader,self.work=reader,reader.work
        self.family,self.kind,self.ref,self.expected_digest=family,kind,ref,expected_digest
        self.phase="identity";self.complete=False;self.column=None;self.value=None
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .d07_execution_v1 import TABLE as D07_TABLE,SIGN_KIND as D07_KIND
        from .d11_life_preparation_v1 import TABLE as LIFE_TABLE,SIGN_KIND as LIFE_KIND
        r=self.reader;w=self.work;r.require_current_v3(meter)
        table,sign_kind=(D07_TABLE,D07_KIND)if self.family=="d07"else(LIFE_TABLE,LIFE_KIND)
        if self.phase=="identity":
            columns=("payload_digest","signature")if self.family=="d07"else("payload_digest","signature","producing_operation_id")
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,table,columns,
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*w.namespace.as_tuple,self.kind,self.ref))
            if self.metadata is None or self.expected_digest is not None and self.metadata[0]!=self.expected_digest:
                raise AuthorityUnavailable("D07 special parent lost its actual signed original commitment")
            mode=("general_question" if self.kind=="semantic_question" and self.ref.startswith("d07-general-growth:") else self.kind) if self.kind in {"semantic_question","reflection_request","execution","prepare_commit"}else"terminal_result" if self.kind=="result" else"metadata"
            self.column=_HostParentColumnV3(r,table=table,column="payload_json",
                key_columns=("bot","persona","kind","original_ref"),key=(*w.namespace.as_tuple,self.kind,self.ref),mode=self.mode or mode)
            self.phase="bytes";return
        if self.phase=="bytes":
            if not self.column.advance(meter):return
            if self.column.sha256!=self.metadata[0]:
                raise AuthorityUnavailable("D07 special-parent signed metadata differs from complete canonical EOF")
            w.d07_service.d11_issuer._signer.verify(sign_kind,
                canonical_serialize((w.namespace,self.kind,self.ref,self.metadata[0])),self.metadata[1])
            self.value=self.column.require_v3(w)
            self.phase="producer"if self.family=="life"else"done";return
        if self.phase=="producer":
            row=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,self.metadata[2]))
            if row is None:raise AuthorityUnavailable("D07 special-parent Life metadata has no actual W01 producer")
            self.producing_operation_id=self.metadata[2];self.phase="done";return
        self.complete=True



class _HostAdoptedParentMetadataReadV3:
    def __init__(self,reader,operation_id,mode="domain"):
        self.reader,self.work=reader,reader.work
        self.operation_id,self.mode=operation_id,mode
        self.phase="identity";self.complete=False;self.columns={};self.index=0
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .domain_production_originals_v1 import TABLE,_receipt,_receipt_wire
        from ..runtime_contracts import canonical_digest
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,TABLE,
                ("domain","operation_kind","request_digest","original_digest","bundle_digest","receipt_digest"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,self.operation_id))
            if self.metadata is None:raise AuthorityUnavailable("D07 special-parent actual W01 adopted original absent")
            names=("original_payload_json","read_versions_json","receipt_json")
            for name in names:
                self.columns[name]=_HostParentColumnV3(r,table=TABLE,column=name,
                    key_columns=("bot","persona","operation_id"),key=(*w.namespace.as_tuple,self.operation_id),
                    mode=self.mode if name=="original_payload_json"else"metadata")
            self.names=names;self.phase="bytes";return
        if self.phase=="bytes":
            column=self.columns[self.names[self.index]]
            if not column.advance(meter):return
            self.index+=1
            if self.index==len(self.names):self.phase="receipt"
            return
        if self.phase=="receipt":
            domain,kind,request,digest,bundle,receipt_digest=self.metadata
            payload=self.columns["original_payload_json"]
            if payload.sha256!=digest:raise AuthorityUnavailable("D07 parent actual adoption payload EOF digest differs")
            self.payload=payload.require_v3(w);self.read_versions=self.columns["read_versions_json"].require_v3(w)
            if len(self.read_versions)>1024 or any(NamespaceId.from_key(AtomKey.from_token(ref))!=w.namespace
                    for ref,revision in self.read_versions):
                raise AuthorityUnavailable("D07 actual parent adoption read set crossed original namespace/bound")
            raw=self.columns["receipt_json"].require_v3(w);self.receipt=_receipt(raw)
            if (canonical_digest(self.receipt)!=receipt_digest or _receipt_wire(self.receipt)!=raw
                    or self.receipt.operation_id!=self.operation_id or self.receipt.operation_digest!=bundle
                    or self.receipt.status!="committed" or self.payload["namespace"]!={
                        "bot_id":w.namespace.bot_id,"persona_id":w.namespace.persona_id}
                    or self.payload["identity"]["operation_id"]!=self.operation_id):
                raise AuthorityUnavailable("D07 special parent actual adoption receipt/namespace/operation differs")
            self.phase="producer";return
        if self.phase=="producer":
            actual=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,self.operation_id))
            if actual!=(self.receipt.operation_digest,self.receipt.activity_id,self.receipt.effect_id,self.receipt.commit_seq):
                raise AuthorityUnavailable("D07 special-parent receipt has no matching actual shared W01 occurrence")
            self.complete=True



class _HostParentJobMetadataReadV3:
    _FIXED=("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref",
        "phase","work_kind","deadline_utc","budget_ref","resource_ref","lease_holder",
        "lease_expires_utc","fence","cancel_epoch","result_ref")
    def __init__(self,reader,job_id):
        self.reader,self.work,self.job_id=reader,reader.work,job_id
        self.phase="identity";self.complete=False;self.columns={};self.index=0
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .d11_types import runtime_job_key
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            row=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_jobs",self._FIXED,"job_id=?",(self.job_id,))
            if row is None or row[4:6]!=w.namespace.as_tuple:
                raise AuthorityUnavailable("D07 actual parent runtime job absent or crossed namespace")
            self.value=dict(zip(self._FIXED,row))
            self.names=("continuation_json","wake_condition_json","operator_versions_json","usage_json")
            for name in self.names:
                # NULL wake conditions are represented by their real SQL absence.
                if name=="wake_condition_json":
                    length=w.db.execute("SELECT length(wake_condition_json) FROM runtime_jobs WHERE job_id=?",(self.job_id,)).fetchone()
                    meter.charge_read(8)
                    if length is not None and length[0]is None:
                        self.columns[name]=None;continue
                self.columns[name]=_HostParentColumnV3(r,table="runtime_jobs",column=name,
                    key_columns=("job_id",),key=(self.job_id,),mode="continuation"if name=="continuation_json"else"metadata")
            self.phase="bytes";return
        if self.phase=="bytes":
            name=self.names[self.index];column=self.columns[name]
            if column is not None and not column.advance(meter):return
            self.index+=1
            if self.index==len(self.names):self.phase="projection"
            return
        job=self.value;key=runtime_job_key(*w.namespace.as_tuple,job["activity_id"],self.job_id)
        if not hasattr(self,"graph_head"):self.graph_head=_HostGraphParentMetadataReadV3(r,key.token)
        if not self.graph_head.complete:self.graph_head.advance_v3(meter);return
        atom_value=self.graph_head.value
        expected={name:job[name]for name in self._FIXED if name!="budget_ref"}
        expected["parent_budget_lease_ref"]=job["budget_ref"]
        for column,name in (("continuation_json","continuation_digest"),("wake_condition_json","wake_condition_digest"),
                ("operator_versions_json","operator_versions_digest"),("usage_json","usage_digest")):
            item=self.columns[column];expected[name]=None if item is None else item.sha256
        # RuntimeJobValue's registered projection has no Source body.
        if atom_value!=expected:raise AuthorityUnavailable("D07 runtime parent and actual Graph projection commitments differ")
        self.continuation=self.columns["continuation_json"].require_v3(w)
        self.operator_versions=self.columns["operator_versions_json"].require_v3(w)
        self.version=self.graph_head.revision
        from ..runtime_contracts import canonical_digest
        self.digest=canonical_digest(atom_value)
        self.complete=True

class _HostParentBudgetMetadataReadV3:
    def __init__(self,reader,lease_id,*,walk_ancestry=True):
        self.walk_ancestry=walk_ancestry;self.ancestor_index=1;self.ancestor_task=None
        self.reader,self.work,self.lease_id=reader,reader.work,lease_id
        self.phase="latest";self.complete=False;self.family=[];self.pending=lease_id
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .issuers import _decode_grant
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="latest":
            self.latest=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_budget_grants",
                ("version","status","signature"),"lease_id=? ORDER BY version DESC",(self.lease_id,))
            if self.latest is None or self.latest[1]!="active":
                raise AuthorityUnavailable("D07 original parent budget grant is no longer active")
            self.column=_HostParentColumnV3(r,table="runtime_budget_grants",column="grant_json",
                key_columns=("lease_id","version"),key=(self.lease_id,self.latest[0]),mode="metadata")
            self.phase="grant";return
        if self.phase=="grant":
            if not self.column.advance(meter):return
            raw=self.column.require_v3(w);wire=canonical_serialize(raw)
            w.d07_service.d11_issuer._signer.verify("budget-grant.v1",wire,self.latest[2])
            self.grant=_decode_grant(wire)
            if (self.grant.lease_id,self.grant.version,self.grant.bot_id,self.grant.persona_id)!=(
                    self.lease_id,self.latest[0],*w.namespace.as_tuple):
                raise AuthorityUnavailable("D07 current signed grant crossed its actual lease/version/namespace")
            if r.now_v3()>=self.grant.valid_until_utc:
                raise AuthorityUnavailable("Host original signed ancestor grant expired")
            if not self.walk_ancestry:self.complete=True;return
            self.phase="family";return
        if self.phase=="ancestor_grants":
            if self.ancestor_index==len(self.family):self.complete=True;return
            if self.ancestor_task is None:self.ancestor_task=_HostParentBudgetMetadataReadV3(r,self.family[self.ancestor_index],walk_ancestry=False)
            self.ancestor_task.advance_v3(meter)
            if self.ancestor_task.complete:self.ancestor_index+=1;self.ancestor_task=None
            return
        if self.pending is None:self.phase="ancestor_grants";return
        lease_id=self.pending
        if lease_id in self.family:raise AuthorityUnavailable("D07 original budget family is cyclic")
        row=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_budget_leases",
            ("parent_id","bot_id","persona_id","state"),"lease_id=?",(lease_id,))
        debt=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_budget_debt_blocks",
            ("lease_id",),"lease_id=?",(lease_id,))
        if row is None or row[1:3]!=w.namespace.as_tuple or row[3]!="active" or debt is not None:
            raise AuthorityUnavailable("D07 original parent budget family changed or has actual unresolved debt")
        self.family.append(lease_id);self.pending=row[0]



class _HostGraphParentMetadataReadV3:
    def __init__(self,reader,ref):
        self.reader,self.work,self.ref=reader,reader.work,ref
        self.phase="identity";self.complete=False;self.column=None
    def advance_v3(self,meter):
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            key=AtomKey.from_token(self.ref)
            if NamespaceId.from_key(key)!=w.namespace or key.type_name not in{
                    "runtime.job","d01.method_trial_proposal.v2","d07.reflection_checkpoint.v1",
                    "d03.self_identity_mapping.v1","memory.source"}:
                raise AuthorityUnavailable("D07 special-parent metadata leaf has an unregistered exact head schema")
            head=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(self.ref,*w.namespace.as_tuple))
            if head is None or not head[1]or head[2]is None:
                raise AuthorityUnavailable("D07 actual special-parent metadata head/cell absent")
            self.revision,self.valid,self.cell_id=head
            self.column=_HostParentColumnV3(r,table="graph_atoms",column="value",
                key_columns=("token",),key=(self.ref,),
                mode={"runtime.job":"graph_job","d01.method_trial_proposal.v2":"graph_proposal",
                    "d07.reflection_checkpoint.v1":"checkpoint","d03.self_identity_mapping.v1":"metadata","memory.source":"source_commitment"}[key.type_name],
                cell_id=self.cell_id,erasure_owner_ref=self.ref)
            self.phase="bytes";return
        if not self.column.advance(meter):return
        self.value=self.column.require_v3(w)
        expected_fields=({"reflection_id","meta_depth","no_progress_count","unresolved_slots","discriminating_refs","status"}if AtomKey.from_token(self.ref).type_name=="d07.reflection_checkpoint.v1"else set(self.value))
        if AtomKey.from_token(self.ref).type_name!="memory.source" and self.column.fields_seen!=expected_fields:
            raise AuthorityUnavailable("D07 current parent metadata head has fields outside its exact safe schema")
        from ..runtime_contracts import canonical_digest
        self.semantic_digest=self.column.canonical_semantic_digest;self.complete=True

class _HostHistoryParentMetadataReadV3:
    def __init__(self,reader,ref,revision,*,expected_operation,expected_digest=None):
        self.reader,self.work,self.ref,self.revision=reader,reader.work,ref,revision
        self.expected_operation,self.expected_digest=expected_operation,expected_digest
        self.phase="identity";self.complete=False
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_history",
                ("event_bot","event_persona","event_id","valid","value_cell_id"),
                "token=? AND revision=?",(self.ref,self.revision))
            if self.metadata is None or self.metadata[:4]!=(*w.namespace.as_tuple,self.expected_operation,1):
                raise AuthorityUnavailable("D07 special-parent immutable history lost actual W01 event/member")
            self.column=_HostParentColumnV3(r,table="graph_history",column="value",
                key_columns=("token","revision"),key=(self.ref,self.revision),
                mode="checkpoint"if AtomKey.from_token(self.ref).type_name=="d07.reflection_checkpoint.v1"else"graph_job",
                cell_id=self.metadata[4],erasure_owner_ref=self.ref)
            self.phase="bytes";return
        if not self.column.advance(meter):return
        self.value=self.column.require_v3(w)
        expected_fields=({"reflection_id","meta_depth","no_progress_count","unresolved_slots","discriminating_refs","status"}if AtomKey.from_token(self.ref).type_name=="d07.reflection_checkpoint.v1"else set(self.value))
        if AtomKey.from_token(self.ref).type_name!="memory.source" and self.column.fields_seen!=expected_fields:
            raise AuthorityUnavailable("D07 parent history metadata contains another head schema")
        from ..runtime_contracts import canonical_digest
        self.semantic_digest=self.column.canonical_semantic_digest
        if self.expected_digest is not None and self.semantic_digest!=self.expected_digest:
            raise AuthorityUnavailable("D07 special-parent immutable history full canonical semantic EOF digest changed")
        self.complete=True

class _HostBundleParentMetadataReadV3:
    def __init__(self,reader,operation_id):
        self.reader,self.work,self.operation_id=reader,reader.work,operation_id
        self.phase="identity";self.complete=False;self.event_columns={};self.index=0
    def advance_v3(self,meter):
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if self.phase=="identity":
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),
                "bot=? AND persona=? AND operation_id=?",(*w.namespace.as_tuple,self.operation_id))
            if self.metadata is None:raise AuthorityUnavailable("Host parent actual shared W01 bundle absent")
            self.column=_HostParentColumnV3(r,table="graph_bundle_operations",column="receipt_json",
                key_columns=("bot","persona","operation_id"),key=(*w.namespace.as_tuple,self.operation_id),mode="bundle")
            self.phase="bytes";return
        if self.phase=="bytes":
            if not self.column.advance(meter):return
            self.value=self.column.require_v3(w)
            if self.value.get("schema")=="d07.actual-graph-stage.v1":
                if (self.value["status"]!="committed" or self.value["commit_seq"]!=self.metadata[3]
                        or not self.value["prepared_digest"]):
                    raise AuthorityUnavailable("Host actual D07 stage receipt differs from its shared W01 metadata")
                self.complete=True;return
            self.phase="event_identity";return
        if self.phase=="event_identity":
            self.event_epoch=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_events",("epoch_revision",),
                "bot=? AND persona=? AND session=? AND event_id=?",(*w.namespace.as_tuple,self.metadata[1],self.operation_id))
            if self.event_epoch is None:raise AuthorityUnavailable("Host original committed bundle has no actual Graph event")
            for name in ("reads","revisions"):
                self.event_columns[name]=_HostParentColumnV3(r,table="graph_events",column=name,
                    key_columns=("bot","persona","session","event_id"),key=(*w.namespace.as_tuple,self.metadata[1],self.operation_id),mode="metadata")
            self.phase="events";return
        if self.phase=="events":
            name=("reads","revisions")[self.index]
            if not self.event_columns[name].advance(meter):return
            self.index+=1
            if self.index==2:self.phase="receipt"
            return
        from .domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1,_receipt_wire
        original=self.value
        self.receipt=reconstruct_graph_bundle_commit_receipt_v1(w.namespace,self.operation_id,
            (*self.metadata,canonical_serialize(original)),
            (canonical_serialize(self.event_columns["reads"].require_v3(w)),
             canonical_serialize(self.event_columns["revisions"].require_v3(w)),self.event_epoch[0]))
        self.value=_receipt_wire(self.receipt)
        if "first_ingress_c02"in original:self.value["first_ingress_c02"]={}
        self.complete=True

class _HostRelationshipParentPolicyReadV3:
    def __init__(self,reader,question):
        self.reader,self.work,self.question=reader,reader.work,question
        self.phase="identity";self.complete=False
    def advance_v3(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..domains.d05.relationship_revision_v2 import InstalledRelationshipPolicyV2,RelationshipScopeV2
        from ..runtime_contracts import canonical_digest
        r=self.reader;w=self.work;question=self.question;r.require_current_v3(meter)
        if self.phase=="identity":
            self.metadata=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_d05_production_policies_v1",
                ("revision","payload_digest","signature"),
                "bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC",
                (*w.namespace.as_tuple,question["policy_ref"]))
            if self.metadata is None or self.metadata[:2]!=(question["policy_revision"],question["policy_digest"]):
                raise AuthorityUnavailable("D07 Relationship actual latest policy metadata changed")
            self.column=_HostParentColumnV3(r,table="graph_d05_production_policies_v1",column="payload_json",
                key_columns=("bot","persona","policy_ref","revision"),
                key=(*w.namespace.as_tuple,question["policy_ref"],self.metadata[0]),mode="metadata")
            self.phase="bytes";return
        if not self.column.advance(meter):return
        value=self.column.require_v3(w)
        if self.column.sha256!=self.metadata[1]:
            raise AuthorityUnavailable("D07 Relationship policy full signed canonical EOF digest changed")
        w.d07_service.d11_issuer._signer.verify("d11.d05-production-policy.v2",canonical_serialize(value),self.metadata[2])
        policy=decode_typed_production_value_v1(value,InstalledRelationshipPolicyV2)
        scope=decode_typed_production_value_v1(question["scope"],RelationshipScopeV2)
        if canonical_digest(policy)!=question["policy_digest"]:
            raise AuthorityUnavailable("D07 Relationship policy exact typed commitment changed")
        policy.rule(scope);self.complete=True


class _HostSpecialParentMetadataReadV3:
    def __init__(self,reader):
        reader.require_registered_v3();reader.header.require_v3(reader)
        self.reader,self.work=reader,reader.work
        self.headers=[];self.phase="chain";self.complete=False;self.result=None
        self.pending=None;self.leaves={};self.index=0;self.deadlines=[];self.originals=[]
        self.current=reader.header;self.seen=set()
        _HOST_PARENT_TASKS[self]=(reader,self.work,self.work.operation,self.work.read_scope,self.work.graph_stamp)
    def _leaf_v3(self,name,leaf):
        existing=self.leaves.get(name)
        if existing is None:
            self.leaves[name]=leaf;self.pending=leaf;return None
        if not existing.complete:self.pending=existing;return None
        return existing
    def advance_v3(self,meter):
        from dataclasses import asdict
        from ..runtime_contracts import canonical_digest
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .domain_production_contracts_v1 import ProductionOwnerGuardV1
        from .d07_execution_v1 import D07ReflectionPreparedV3,D07RelationshipPreparedV2
        from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
        from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
        r=self.reader;w=self.work;r.require_current_v3(meter)
        if _HOST_PARENT_TASKS.get(self)!=(r,w,w.operation,w.read_scope,w.graph_stamp):
            raise AuthorityUnavailable("D07 special-parent metadata task lost original Work/retention/stamp")
        if self.complete:return
        if self.pending is not None:
            self.pending.advance_v3(meter)
            if self.pending.complete:self.pending=None
            return
        if self.phase=="chain":
            header=self.current.require_v3(r);raw=header.value
            if header.job_id in self.seen or len(self.headers)>=3:
                raise AuthorityUnavailable("D07 original Reflection parent chain is cyclic or exceeds original causal depth")
            self.seen.add(header.job_id);self.headers.append(header)
            if header.prepared_class is D07ReflectionPreparedV3:
                parent=r.parent_headers.get(raw["parent_prepared_ref"])
                if parent is None or not parent.complete:
                    raise AuthorityUnavailable("D07 Reflection requires its actual independently completed parent header")
                parent.require_v3(r)
                if parent.metadata[0]!=raw["parent_prepared_digest"]:
                    raise AuthorityUnavailable("D07 Reflection original parent prepared digest changed")
                self.current=parent;return
            self.headers.reverse();self.phase="parent";return
        if self.phase=="parent":
            if self.index==len(self.headers):
                self.phase="finish";return
            self.header=self.headers[self.index];self.raw=self.header.value;self.parent_kind=self.header.prepared_class
            self.source=_host_parent_source_authority_v3(r,self.header)
            if self.index:
                previous=self.headers[self.index-1]
                if (self.source.actor,self.source.purpose,self.source.audience,self.source.activation_generation)!=(
                        previous.authority.actor,previous.authority.purpose,previous.authority.audience,previous.authority.activation_generation):
                    raise AuthorityUnavailable("D07 Reflection cannot replace the original Source actor/purpose/audience/generation")
                if not {(row["ref"],row["revision"])for row in self.header.source_rows}<={
                        (row["ref"],row["revision"])for row in previous.source_rows}:
                    raise AuthorityUnavailable("D07 Reflection expanded its original parent Source versions")
            self.phase="owner";return
        raw=self.raw;header=self.header;kind=self.parent_kind
        if self.phase=="owner":
            owner=decode_typed_production_value_v1(json.loads(raw["owner_guard_json"]),ProductionOwnerGuardV1)
            _host_parent_head_v3(r,owner.grant_ref,revision=owner.grant_revision,digest=owner.grant_digest)
            actual_guard=r.owner_header_proof.current_owner_guard
            from ..graph_types import owner_grant_key
            if (owner.grant_ref!=owner_grant_key(*w.namespace.as_tuple).token
                    or owner.owner_head_digest!=actual_guard.authorization_head.removeprefix("sha256:")):
                raise AuthorityUnavailable("D07 special parent original Owner head differs from its current protected Core guard")
            self.owner=owner
            if kind is D07GeneralGrowthPreparedV1:self.phase="general"
            elif kind is D07ReflectionPreparedV3:self.phase="reflection"
            elif kind in {D07MethodGrowthPreparedV2,D07RelationshipPreparedV2}:self.phase="question"
            else:self.phase="ordinary_job"
            return
        if self.phase=="general":
            question=self._leaf_v3(("general-question",header.job_id),_HostSignedParentMetadataReadV3(r,
                family="d07",kind="semantic_question",ref=raw["semantic_question_ref"],
                expected_digest=raw["semantic_question_digest"],mode="general_question"))
            if question is None:return
            attention=self._leaf_v3(("general-attention",header.job_id),_HostSignedParentMetadataReadV3(r,
                family="d07",kind="general_growth_attention_v1",ref=raw["general_growth_attention_ref"],
                expected_digest=raw["general_growth_attention_digest"]))
            if attention is None:return
            q=question.value;a=attention.value
            matched=("outcome_original_ref","outcome_original_digest","outcome_trigger_ref","outcome_trigger_digest",
                "causal_operation_id","causal_receipt_digest","context_source_refs","support_source_refs","original_deadline_utc")
            if (q["schema"]!="d07.general-growth-semantic-question.v1"
                    or a["schema"]!="d07.general-growth-attention.v1"
                    or raw["depth_basis"]!="independent_outcome_stage.v1" or raw["stage_causal_depth"]!=0
                    or q["depth_basis"]!=raw["depth_basis"] or q["stage_causal_depth"]!=0
                    or q["general_growth_attention_ref"]!=raw["general_growth_attention_ref"]
                    or (a["semantic_question_ref"],a["semantic_question_digest"])!=(raw["semantic_question_ref"],raw["semantic_question_digest"])
                    or any(q[name]!=raw[name]for name in matched)
                    or any(a[name]!=q[name]for name in matched if name not in {"outcome_original_ref","outcome_original_digest"})
                    or any(a["source_authority"][name]!=json.loads(raw["owner_authority_json"])[name]
                        for name in ("actor","namespace","purpose","audience","activation_generation"))
                    or a["owner_guard"]!=json.loads(raw["owner_guard_json"])
                    or a["original_parent_budget_lease_ref"]!=q["original_parent_budget_lease_ref"]
                    or a["original_parent_grant_digest"]!=q["original_parent_grant_digest"]
                    or self.source.purpose!="consolidation"):
                raise AuthorityUnavailable("Host General changed its actual signed independent Outcome/Question/Attention/Source")
            roots=set(q["context_source_refs"])|set(q["support_source_refs"])
            frozen=header.column.frozen_metadata.value["input"]
            frozen_roots={item["source_ref"]["ref"]for name in ("context_sources","support_sources")for item in frozen[name]}
            if frozen_roots!=roots or not roots<={row["ref"]for row in header.source_rows}:
                raise AuthorityUnavailable("Host General frozen input changed exact Source columns")
            producer=self._leaf_v3(("general-registration",header.job_id),_HostBundleParentMetadataReadV3(r,a["registration_operation_id"]))
            if producer is None:return
            if canonical_digest(producer.receipt)!=a["registration_receipt_digest"]:
                raise AuthorityUnavailable("Host General ticket has no exact original registration W01 receipt")
            budget=self._leaf_v3(("general-root",header.job_id),_HostParentBudgetMetadataReadV3(r,q["original_parent_budget_lease_ref"]))
            if budget is None:return
            if canonical_digest(budget.grant)!=q["original_parent_grant_digest"] or r.stage_job.value["budget_ref"]!=q["original_parent_budget_lease_ref"]:
                raise AuthorityUnavailable("Host General cannot borrow another ticket original budget")
            self.deadlines.extend((q["original_deadline_utc"],budget.grant.valid_until_utc))
            self.originals.extend((("d07.general-growth-question",raw["semantic_question_ref"],raw["semantic_question_digest"]),
                ("d07.general-growth-attention",raw["general_growth_attention_ref"],raw["general_growth_attention_digest"])))
            self.phase="ordinary_job";return
        if self.phase=="ordinary_job":
            leaf=self._leaf_v3(("ordinary-job",header.job_id),_HostParentJobMetadataReadV3(r,header.job_id))
            if leaf is None:return
            job=leaf.value
            if ((job["operation_id"],job["activity_id"],job["effect_id"],job["work_kind"])!=
                    (raw["operation_id"],raw["activity_id"],raw["effect_id"],"d07."+raw["work_kind"])
                    or job["cancel_epoch"] or job["phase"]not in {"queued","running","completed"}):
                raise AuthorityUnavailable("Host exact original cognition job/cancel metadata changed")
            if header is r.header:
                stage=w.d07_selector.stage
                if stage=="acquire" and job["phase"]=="queued":
                    if job["fence"] or job["lease_holder"]is not None or job["lease_expires_utc"]is not None:
                        raise AuthorityUnavailable("Host queued acquire already carries a worker lease")
                elif stage in {"adopt","result_read","reflection_prepare"}:
                    if job["phase"]!="completed":
                        raise AuthorityUnavailable("Host terminal read has no actual completed parent")
                elif job["phase"]!="running" or job["fence"]<1 or job["lease_holder"]is None or job["lease_expires_utc"]is None:
                    raise AuthorityUnavailable("Host running stage has no actual original worker")
            self.ordinary_job=job
            self.deadlines.append(_host_parent_utc_v3(job["deadline_utc"]))
            if header is r.header and job["phase"]=="running":
                if job["lease_expires_utc"]is None:
                    raise AuthorityUnavailable("D07 ordinary original worker has no actual lease expiry")
                self.deadlines.append(_host_parent_utc_v3(job["lease_expires_utc"]))
            self.phase="ordinary_budget";return
        if self.phase=="ordinary_budget":
            leaf=self._leaf_v3(("ordinary-budget",header.job_id),
                _HostParentBudgetMetadataReadV3(r,self.ordinary_job["budget_ref"]))
            if leaf is None:return
            if "d07.cognition"not in leaf.grant.allowed_work_kinds or r.now_v3()>=leaf.grant.valid_until_utc:
                raise AuthorityUnavailable("D07 ordinary current original grant no longer permits cognition")
            self.deadlines.append(leaf.grant.valid_until_utc);self.phase="next";return
        if self.phase=="question":
            leaf=self._leaf_v3(("question",header.job_id),_HostSignedParentMetadataReadV3(r,family="d07",
                kind="semantic_question",ref=raw["semantic_question_ref"],expected_digest=raw["semantic_question_digest"]))
            if leaf is None:return
            question=leaf.value
            expected="d07.method-growth-semantic-question.v2"if kind is D07MethodGrowthPreparedV2 else"d07.relationship-semantic-question.v2"
            if question["schema"]!=expected:
                raise AuthorityUnavailable("D07 named C3 has another exact signed semantic kind")
            frozen=header.column.frozen_metadata.value["input"]
            if question["question_key"]!=frozen["question_key"] or question["target_ref"]["ref"]!=frozen["target_ref"]:
                raise AuthorityUnavailable("D07 named C3 signed semantic question differs from original frozen metadata")
            self.question=question;self.originals.append(("d07.semantic_question",raw["semantic_question_ref"],leaf.metadata[0]))
            if kind is D07MethodGrowthPreparedV2:self.phase="proposal"
            else:
                self.cycle_ref=_host_parent_version_key_v3(raw["cycle_ref"])
                self.phase="relationship_policy"
            return
        if self.phase=="relationship_policy":
            policy=self._leaf_v3(("relationship_policy",header.job_id),_HostRelationshipParentPolicyReadV3(r,self.question))
            if policy is None:return
            self.phase="cycle";return
        if self.phase=="proposal":
            from ..graph_types import GraphVersion
            from ..domains.d01.method_learning_v1 import MethodTrialProposalV2
            from .d01_method_learning_v1 import trial_question_v2
            version=decode_typed_production_value_v1(raw["proposal_head"],GraphVersion)
            source_version=decode_typed_production_value_v1(raw["source_head"],GraphVersion)
            proposal_leaf=self._leaf_v3(("proposal_head",header.job_id),_HostGraphParentMetadataReadV3(r,version.key.token))
            if proposal_leaf is None:return
            proposal_raw=proposal_leaf.value
            if proposal_leaf.revision!=version.revision or canonical_digest(proposal_raw)!=raw["proposal_digest"]:
                raise AuthorityUnavailable("D07 Method proposal actual current metadata EOF commitment changed")
            _host_parent_head_v3(r,source_version.key.token,revision=source_version.revision,digest=raw["source_digest"])
            proposal=decode_typed_production_value_v1(proposal_raw,MethodTrialProposalV2)
            history=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_history",("event_bot","event_persona","event_id","valid"),
                "token=? AND revision=?",(version.key.token,version.revision))
            if history is None or history[:2]!=w.namespace.as_tuple or history[3]!=1:
                raise AuthorityUnavailable("D07 Method proposal has no exact actual adopting history member")
            leaf=self._leaf_v3(("proposal",header.job_id),_HostAdoptedParentMetadataReadV3(r,history[2]))
            if leaf is None:return
            authority=decode_typed_production_value_v1(leaf.payload["authority"],AuthorityContext)
            if (leaf.metadata[:2]!=("d01","register_method_trial_proposal_v2")
                    or leaf.payload["provenance"]["method_trial_proposal"]!=proposal_raw
                    or version not in leaf.receipt.write_versions
                    or authority!=header.authority or self.question["question_key"]!=trial_question_v2(version.key.token,raw["proposal_digest"])
                    or set(self.question["source_refs"])!=set(proposal.source_refs)
                    or any(self.question[name]!=raw[name]for name in("proposal_head","proposal_digest","source_head",
                        "source_digest","parent_budget_lease_ref","original_deadline_utc","c02_operation_id"))
                    or not proposal.valid_from<=r.now_v3()<proposal.valid_until):
                raise AuthorityUnavailable("D07 Method actual adopted proposal authority/source/question/root deadline changed")
            self.proposal=proposal
            self.originals.append(("d01.actual-method-proposal",version.key.token,leaf.metadata[3]))
            self.deadlines.extend((raw["original_deadline_utc"],proposal.valid_until))
            self.cycle_ref=decode_typed_production_value_v1(raw["cycle_ref"],GraphVersion).key.token
            self.phase="cycle";return
        if self.phase=="cycle":
            leaf=self._leaf_v3(("cycle",header.job_id),_HostParentJobMetadataReadV3(r,AtomKey.from_token(self.cycle_ref).owner.subject))
            if leaf is None:return
            job=leaf.value;cycle=leaf.continuation
            if (job["work_kind"]!="d11.foreground_cycle.v1"
                    or job["phase"]in {"completed","failed","cancelled","draining","pending_confirmation"} or job["cancel_epoch"]
                    or cycle["cancel_generation"] or cycle["c02_operation_id"]!=raw["c02_operation_id"]
                    or cycle["call_plan"]["parent_budget_lease_ref"]!=job["budget_ref"]):
                raise AuthorityUnavailable("D07 special parent current cycle/cancel/C02/activity/root budget changed")
            if kind is D07MethodGrowthPreparedV2:
                from ..graph_types import GraphVersion
                source=decode_typed_production_value_v1(raw["source_head"],GraphVersion)
                if cycle["source_ref"]!=source.key.token or job["budget_ref"]!=raw["parent_budget_lease_ref"]:
                    raise AuthorityUnavailable("D07 Method actual cue/root paying lease changed")
            self.cycle,self.cycle_job,self.cycle_leaf=cycle,job,leaf
            self.deadlines.append(_host_parent_utc_v3(job["deadline_utc"]))
            self.phase="budget";return
        if self.phase=="budget":
            lease_id=self.cycle_job["budget_ref"]
            leaf=self._leaf_v3(("budget",header.job_id),_HostParentBudgetMetadataReadV3(r,lease_id))
            if leaf is None:return
            if "d07.cognition"not in leaf.grant.allowed_work_kinds:
                raise AuthorityUnavailable("D07 special parent original grant does not allow original cognition Work")
            if kind is D07MethodGrowthPreparedV2 and raw["original_deadline_utc"]!=min(
                    _host_parent_utc_v3(self.cycle_job["deadline_utc"]),leaf.grant.valid_until_utc):
                raise AuthorityUnavailable("D07 Method original deadline is not its original job/grant minimum")
            self.budget=leaf;self.deadlines.append(leaf.grant.valid_until_utc);self.phase="responsibility";return
        if self.phase=="responsibility":
            create=self._leaf_v3(("create",header.job_id),_HostAdoptedParentMetadataReadV3(r,self.cycle_job["operation_id"],"create"))
            if create is None:return
            from .foreground_cycle_v1 import ForegroundResponsibilityV1,foreground_responsibility_ref_v1
            responsibility=decode_typed_production_value_v1(create.payload["provenance"]["foreground_responsibility"],ForegroundResponsibilityV1)
            if (create.metadata[:2]!=("d11","create_foreground_cycle_v2")
                    or (self.cycle["responsibility_ref"],self.cycle["responsibility_digest"])!=(
                        foreground_responsibility_ref_v1(w.namespace,raw["c02_operation_id"]),responsibility.digest)
                    or responsibility.owner_guard!=self.owner or responsibility.c02_operation_id!=raw["c02_operation_id"]
                    or responsibility.parent_budget_lease_ref!=self.cycle_job["budget_ref"]
                    or (responsibility.parent_grant_id,responsibility.parent_grant_version,responsibility.parent_grant_digest)!=(
                        self.budget.grant.grant_id,self.budget.grant.version,canonical_digest(self.budget.grant))
                    or responsibility.foreground_policy_digest!=canonical_digest(asdict(r.bundle.foreground))
                    or responsibility.deadline_policy_digest!=canonical_digest(asdict(r.bundle.foreground.deadline_policy))
                    or responsibility.deadline_utc!=_host_parent_utc_v3(self.cycle_job["deadline_utc"])):
                raise AuthorityUnavailable("D07 actual create responsibility lost original Owner/C02/grant/policy/deadline")
            if kind is D07MethodGrowthPreparedV2 and responsibility.mode!="bounded_causal_window_v1":
                raise AuthorityUnavailable("D07 Method requires actual independent natural C02 responsibility")
            _,_,mapping=_host_parent_head_v3(r,responsibility.self_mapping_ref,digest=responsibility.self_mapping_digest)
            _host_parent_head_v3(r,responsibility.source_ref,revision=responsibility.source_revision,digest=responsibility.source_digest)
            if create.payload["authority"]["actor"]!=mapping["self_entity_ref"]:
                raise AuthorityUnavailable("D07 actual create responsibility actor differs from its certified Self mapping")
            self.responsibility,self.create=responsibility,create;self.deadlines.append(responsibility.deadline_utc)
            self.phase="create_birth";return
        if self.phase=="create_birth":
            from .foreground_cycle_v1 import decode_foreground_job_v1,foreground_cycle_from_wire_v1
            from .d11_types import job_graph_write
            from ..graph_types import GraphVersion
            created=decode_foreground_job_v1(self.create.payload["provenance"]["after_job"],namespace=w.namespace)
            birth=foreground_cycle_from_wire_v1(created.continuation)
            if (self.create.payload["provenance"]["before_job"]is not None or created.phase!="queued"or created.fence
                    or any(getattr(created,name)!=self.cycle_job[name]for name in(
                        "job_id","operation_id","activity_id","budget_ref","deadline_utc"))
                    or (birth.responsibility_ref,birth.responsibility_digest)!=(
                        self.cycle["responsibility_ref"],self.cycle["responsibility_digest"])):
                raise AuthorityUnavailable("D07 responsibility lost exact actual immutable create job/root/deadline")
            write=job_graph_write(created)
            versions=tuple(version for version in self.create.receipt.write_versions if version.key==write.key)
            if len(versions)!=1:
                raise AuthorityUnavailable("D07 responsibility actual create receipt has no unique original job member")
            history=self._leaf_v3(("create_birth",header.job_id),_HostHistoryParentMetadataReadV3(
                r,write.key.token,versions[0].revision,expected_operation=created.operation_id,
                expected_digest=canonical_digest(write.value)))
            if history is None:return
            if history.value!=write.value:
                raise AuthorityUnavailable("D07 responsibility actual create history differs from its real producer")
            responsibility=self.responsibility
            for ref,revision in ((responsibility.source_ref,responsibility.source_revision),
                    (responsibility.owner_guard.grant_ref,responsibility.owner_guard.grant_revision)):
                if [ref,revision]not in self.create.read_versions:
                    raise AuthorityUnavailable("D07 responsibility has no original positive Source/Owner read member")
            mapping_revision,valid,_,_=_host_metadata_commitment_v3(
                r,AtomKey.from_token(responsibility.self_mapping_ref))
            if not valid or [responsibility.self_mapping_ref,mapping_revision]not in self.create.read_versions:
                raise AuthorityUnavailable("D07 responsibility has no original certified Self read member")
            self.phase="cause";return
        if self.phase=="cause":
            responsibility=self.responsibility
            life_kind="foreground_post_c02_cause"if responsibility.mode=="bounded_causal_window_v1"else"draft_root_capability"
            ref=responsibility.cause_original_ref if responsibility.mode=="bounded_causal_window_v1"else responsibility.root_registration_ref
            digest=responsibility.cause_original_digest if responsibility.mode=="bounded_causal_window_v1"else responsibility.root_registration_digest
            leaf=self._leaf_v3(("cause",header.job_id),_HostSignedParentMetadataReadV3(r,family="life",
                kind=life_kind,ref=ref,expected_digest=digest))
            if leaf is None:return
            if responsibility.mode=="bounded_causal_window_v1":
                cause=leaf.value
                names=("installation_id","manifest_digest","ingress_operation_id","c02_operation_id","source_ref",
                    "source_revision","source_digest","c02_receipt_digest","foreground_policy_digest","deadline_policy_digest","cause_frozen_at_utc")
                if (any(cause[name]!=getattr(responsibility,name)for name in names)
                        or cause["commit_seq"]!=responsibility.c02_commit_seq
                        or leaf.producing_operation_id!=responsibility.cause_operation_id):
                    raise AuthorityUnavailable("D07 natural responsibility lost actual signed original causal transition")
            else:
                root=leaf.value
                if (leaf.producing_operation_id!=responsibility.root_setup_operation_id
                        or (root["owner_grant_ref"],root["owner_grant_revision"],root["owner_grant_digest"])!=(
                            self.owner.grant_ref,self.owner.grant_revision,self.owner.grant_digest)
                        or root["source_ref"]!=responsibility.source_ref
                        or responsibility.deadline_utc>_host_parent_utc_v3(root["valid_until_utc"])):
                    raise AuthorityUnavailable("D07 signed-scope responsibility lost its original Root grant/Source/deadline")
                self.deadlines.append(_host_parent_utc_v3(root["valid_until_utc"]))
            from .domain_production_contracts_v1 import ProductionOutboxStageV1,ProductionOriginalRefV1
            event_kind="foreground_post_c02_cause_available"if life_kind=="foreground_post_c02_cause"else"artifact_draft_root_registered"
            event=ProductionOutboxStageV1(w.namespace,leaf.producing_operation_id,"d11",event_kind,
                ProductionOriginalRefV1("d11.life_"+life_kind,ref,leaf.metadata[0]))
            row=_runtime_bounded_fixed_row_v3(w.db,meter,"graph_domain_production_outbox_v1",
                ("causal_operation_id","receiver_domain","event_kind","original_ref","original_digest","state"),
                "bot=? AND persona=? AND dedupe_key=?",(*w.namespace.as_tuple,event.dedupe_key))
            if row is None or row[:5]!=(leaf.producing_operation_id,"d11",event_kind,ref,leaf.metadata[0])or row[5]not in{"pending","consumed"}:
                raise AuthorityUnavailable("D07 parent cause has no actual same-producer durable locator event")
            self.originals.append((life_kind,ref,leaf.metadata[0]));self.phase="c02";return
        if self.phase=="c02":
            leaf=self._leaf_v3(("c02",header.job_id),_HostBundleParentMetadataReadV3(r,raw["c02_operation_id"]))
            if leaf is None:return
            from .domain_production_originals_v1 import _receipt
            from ..runtime_contracts import CommitReceipt
            receipt=leaf.receipt
            responsibility=self.responsibility
            if ("first_ingress_c02"not in leaf.value or (canonical_digest(receipt),receipt.commit_seq)!=(
                    responsibility.c02_receipt_digest,responsibility.c02_commit_seq)):
                raise AuthorityUnavailable("D07 special parent lost exact actual independent first-ingress C02 receipt")
            self.phase="attempt";return
        if self.phase=="attempt":
            r.require_named_member_v3(self,header,self.cycle,self.cycle_job,self.cycle_leaf,raw)
            self.phase="next";return

        if self.phase=="reflection":
            continuation=self._leaf_v3(("reflection",header.job_id),_HostSignedParentMetadataReadV3(r,family="d07",
                kind="reflection_continuation",ref=raw["reflection_continuation_ref"],expected_digest=raw["reflection_continuation_digest"]))
            if continuation is None:return
            value=continuation.value
            names=("reflection_request_ref","reflection_request_digest","parent_prepared_digest","parent_execution_ref",
                "parent_execution_digest","checkpoint_ref","checkpoint_digest","parent_budget_lease_ref","parent_grant_digest","original_deadline_utc")
            if (value["schema"]!="d07.reflection-continuation.v3"
                    or any(value[name]!=raw[name]for name in names)
                    or value["parent_job_id"]!=raw["parent_prepared_ref"]
                    or value["source_refs"]!=raw["source_refs"]
                    or value["namespace"]!={"bot_id":w.namespace.bot_id,"persona_id":w.namespace.persona_id}):
                raise AuthorityUnavailable("D07 Reflection actual signed continuation changed parent/source/checkpoint/deadline")
            self.reflection_continuation=value
            self.originals.append(("d07.reflection_continuation",raw["reflection_continuation_ref"],continuation.metadata[0]))
            self.deadlines.append(value["original_deadline_utc"]);self.phase="reflection_request";return
        if self.phase=="reflection_request":
            request=self._leaf_v3(("reflection_request",header.job_id),_HostSignedParentMetadataReadV3(r,family="d07",
                kind="reflection_request",ref=raw["reflection_request_ref"],expected_digest=raw["reflection_request_digest"]))
            if request is None:return
            value=request.value;continuation=self.reflection_continuation
            frozen=header.column.frozen_metadata.value["input"]
            if (value["reflection_ref"]!=_host_parent_version_key_v3(raw["checkpoint_ref"])
                    or value["source_refs"]!=continuation["source_refs"] or value["causal_depth"]>=2
                    or frozen["causal_depth"]!=value["causal_depth"]
                    or value["causal_depth_original_ref"]!=raw["parent_execution_ref"]):
                raise AuthorityUnavailable("D07 Reflection actual request/root-depth/source commitments changed")
            self.reflection_request=value;self.phase="reflection_execution";return
        if self.phase=="reflection_execution":
            execution=self._leaf_v3(("reflection_execution",header.job_id),_HostSignedParentMetadataReadV3(r,family="d07",
                kind="execution",ref=raw["parent_execution_ref"],expected_digest=raw["parent_execution_digest"]))
            if execution is None:return
            value=execution.value
            parent=r.parent_headers[raw["parent_prepared_ref"]].require_v3(r)
            parent_raw=parent.value
            if (value["source_refs"]!=raw["source_refs"] or value["work_kind"]=="simulation"
                    or any(value[name]!=parent_raw[name]for name in(
                        "operation_id","activity_id","effect_id","attempt_id","execution_id","work_kind","activation_generation"))
                    or value["input_digest"]!=parent_raw["stage_input_digest"]
                    or value["parent_budget_ref"]!=raw["parent_budget_lease_ref"] or value["status"]!="completed"
                    or value["terminal_ref"]!="d07-terminal:"+parent_raw["call_id"]
                    or value["causal_depth"]!=self.reflection_request["causal_depth"]):
                raise AuthorityUnavailable("D07 Reflection lost exact real parent execution/prepared/Source chain")
            self.reflection_execution=value;self.phase="reflection_paid";return
        if self.phase=="reflection_paid":
            paid=self._leaf_v3(("reflection_paid",header.job_id),_HostSignedParentMetadataReadV3(r,family="d07",
                kind="paid_cost",ref=raw["parent_prepared_ref"]))
            if paid is None:return
            if (paid.value["prepared_digest"]!=raw["parent_prepared_digest"] or paid.value["paid"]is not True
                    or paid.value["unknown_dimensions"] or paid.value["cost_ref"]not in self.reflection_execution["cost_receipt_refs"]):
                raise AuthorityUnavailable("D07 Reflection original parent has no exact fully settled paid preparation")
            self.phase="reflection_parent_job";return
        if self.phase=="reflection_parent_job":
            leaf=self._leaf_v3(("reflection_parent_job",header.job_id),_HostParentJobMetadataReadV3(r,raw["parent_prepared_ref"]))
            if leaf is None:return
            parent=leaf.value;continuation=self.reflection_continuation
            if (parent["phase"]!="completed" or parent["cancel_epoch"] or parent["result_ref"]!=raw["parent_execution_ref"]
                    or parent["operation_id"]!=r.parent_headers[raw["parent_prepared_ref"]].value["operation_id"]
                    or parent["budget_ref"]!=raw["parent_budget_lease_ref"]
                    or _host_parent_utc_v3(parent["deadline_utc"])!=raw["original_deadline_utc"]
                    or leaf.continuation["choice"]["ticket_id"]!=continuation["ticket_id"]
                    or leaf.continuation["request"]["category"]!=continuation["category"]):
                raise AuthorityUnavailable("D07 Reflection original parent paid job/root ticket/category/deadline changed")
            self.reflection_parent_job=parent;self.phase="reflection_budget";return
        if self.phase=="reflection_budget":
            budget=self._leaf_v3(("reflection_budget",header.job_id),_HostParentBudgetMetadataReadV3(r,raw["parent_budget_lease_ref"]))
            if budget is None:return
            if canonical_digest(budget.grant)!=raw["parent_grant_digest"] or "d07.cognition"not in budget.grant.allowed_work_kinds:
                raise AuthorityUnavailable("D07 Reflection changed original parent grant or Work authorization")
            self.deadlines.append(budget.grant.valid_until_utc);self.phase="reflection_checkpoint";return
        if self.phase=="reflection_checkpoint":
            from ..graph_types import GraphVersion
            version=decode_typed_production_value_v1(raw["checkpoint_ref"],GraphVersion)
            history=self._leaf_v3(("reflection_checkpoint",header.job_id),_HostHistoryParentMetadataReadV3(
                r,version.key.token,version.revision,expected_operation=self.reflection_parent_job["operation_id"],
                expected_digest=raw["checkpoint_digest"]))
            if history is None:return
            checkpoint=self._leaf_v3(("reflection_current_checkpoint",header.job_id),_HostGraphParentMetadataReadV3(r,version.key.token))
            if checkpoint is None:return
            if (history.value["status"]!="continue" or checkpoint.revision!=version.revision
                    or checkpoint.semantic_digest!=raw["checkpoint_digest"] or checkpoint.value!=history.value):
                raise AuthorityUnavailable("D07 before-call Reflection checkpoint lost its actual parent birth/current continuation")
            self.phase="reflection_cycle";return
        if self.phase=="reflection_cycle":
            cycle_ref=self.reflection_continuation["cycle_job_ref"]
            if cycle_ref is None:
                if raw["cycle_ref"]is not None:
                    raise AuthorityUnavailable("D07 Reflection introduced a new Self cycle")
                self.phase="next";return
            if raw["cycle_ref"]is None or _host_parent_version_key_v3(raw["cycle_ref"])!=cycle_ref:
                raise AuthorityUnavailable("D07 Reflection changed original Self cycle")
            leaf=self._leaf_v3(("reflection_cycle",header.job_id),_HostParentJobMetadataReadV3(r,AtomKey.from_token(cycle_ref).owner.subject))
            if leaf is None:return
            job=leaf.value;cycle=leaf.continuation
            if (job["phase"]not in {"queued","running","waiting"} or job["cancel_epoch"] or cycle["cancel_generation"]
                    or cycle["stage"]=="completed" or cycle["call_plan"]["parent_budget_lease_ref"]!=raw["parent_budget_lease_ref"]
                    or cycle["c02_operation_id"]!=raw["c02_operation_id"]):
                raise AuthorityUnavailable("D07 Reflection cannot revive its closed/cancelled original Self cycle")
            r.require_named_member_v3(self,header,cycle,job,leaf,raw,reflection=True)
            self.deadlines.append(_host_parent_utc_v3(job["deadline_utc"]));self.phase="next";return
        if self.phase=="next":
            self.originals.append(("d07.prepared",header.job_id,header.metadata[0]))
            self.index+=1;self.phase="parent";return
        if self.phase=="finish":
            original=r.header.require_v3(r);source=_host_parent_source_authority_v3(r,original)
            stage_job=r.stage_job.value
            if stage_job["phase"]=="running":
                if stage_job["lease_expires_utc"] is None:
                    raise AuthorityUnavailable("Host original running stage has no worker expiry")
                self.deadlines.append(_host_parent_utc_v3(stage_job["lease_expires_utc"]))
            deadline=min((w.operation.deadline_utc,*self.deadlines))
            if r.now_v3()>=deadline:
                raise AuthorityUnavailable("D07 special parent exceeded its original ancestor deadline minimum")
            source_versions=tuple(sorted({(row["ref"],row["revision"])for item in self.headers for row in item.source_rows}))
            names={D07MethodGrowthPreparedV2:"method_growth_self",
                D07ReflectionPreparedV3:"reflection",D07RelationshipPreparedV2:"relationship_self",D07GeneralGrowthPreparedV1:"general_growth_owner"}
            self.complete=True
            self.result=_HostParentQualifiedV3(_HOST_ISSUER,self,kind=names.get(original.prepared_class,"ordinary_owner"),
                authority=source,parent_originals=self.originals,deadline=deadline,source_versions=source_versions)
            return
        raise AuthorityUnavailable("D07 special-parent metadata task has an unregistered phase")

def _host_parent_utc_v3(value):
    from datetime import datetime
    return datetime.fromisoformat(value.replace("Z","+00:00")).timestamp()

def _host_parent_version_key_v3(raw):
    from ..graph_types import GraphVersion
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw,GraphVersion).key.token


def _host_require_named_member_v3(reader,task,header,cycle,job,cycle_leaf,raw,*,reflection=False):
    from .foreground_call_plan_v1 import foreground_call_plan_from_wire_v1,foreground_call_plan_from_wire_v2,ForegroundModelAttemptV1
    from dataclasses import replace
    plan_raw=cycle["call_plan"]
    plan=foreground_call_plan_from_wire_v2(plan_raw) if plan_raw["schema"]=="d11.foreground-call-plan.v2" else foreground_call_plan_from_wire_v1(plan_raw)
    workflow=reader.bundle.model_workflows.d07_cognition
    matched=tuple(row for row in plan.attempts if row.call_id==raw["call_id"])
    queued=reader.stage_job.value["phase"]=="queued" and header is reader.header and reader.work.d07_selector.stage=="acquire"
    if queued:
        if matched or cycle_leaf.version!=decode_typed_production_value_v1(raw["cycle_ref"],GraphVersion).revision or cycle_leaf.digest!=raw["cycle_digest"] or canonical_digest(plan)!=raw["call_plan_digest"]:
            raise AuthorityUnavailable("Host queued C3 changed its original absent member/cycle/callplan commitment")
        prospective=ForegroundModelAttemptV1("C3",raw["call_id"],None,raw["operation_id"],raw["reservation_digest"],
            job["budget_ref"],workflow.quote_ceiling["input_tokens"],workflow.quote_ceiling["output_tokens"],"reserved")
        replace(plan,attempts=(*plan.attempts,prospective))
        reader.require_remaining_reply_v3(task,plan)
        return
    if len(matched)!=1:raise AuthorityUnavailable("Host running C3 lacks its exact actual registered member")
    member=matched[0]
    if (member.slot!="C3" or member.original_call_id is not None
            or (member.reservation_operation_id,member.reservation_digest,member.budget_lease_ref)!=(raw["operation_id"],raw["reservation_digest"],job["budget_ref"])
            or (member.input_ceiling,member.output_ceiling)!=(workflow.quote_ceiling["input_tokens"],workflow.quote_ceiling["output_tokens"])):
        raise AuthorityUnavailable("Host original C3 changed its actual quote/reservation/root")
    acquire_id="d07-acquire:"+canonical_digest((reader.work.namespace,raw["operation_id"]))[:48]
    leaf=task._leaf_v3(("host-acquire",header.job_id),_HostBundleParentMetadataReadV3(reader,acquire_id))
    if leaf is None:raise _HostMetadataNeededV3(task.pending)
    name="reflection_c3" if reflection else "method_growth_c3" if raw["schema"]=="d07.method-growth-prepared.v2" else "relationship_c3"
    expected={"cycle_ref":decode_typed_production_value_v1(raw["cycle_ref"],GraphVersion).key.token,
        "before_cycle_digest":raw["cycle_digest"],"before_call_plan_digest":raw["call_plan_digest"],"call_id":raw["call_id"],
        ("reflection_request_digest"if reflection else"semantic_question_digest"):raw["reflection_request_digest"] if reflection else raw["semantic_question_digest"]}
    if (leaf.metadata[1:3]!=(raw["activity_id"],None)
            or leaf.value["phase"]!="execution_acquired" or leaf.value["prepared_digest"]!=header.metadata[0] or leaf.value[name]!=expected):
        raise AuthorityUnavailable("Host C3 member lacks its exact actual acquisition W01 receipt")

def _host_require_remaining_reply_v3(reader,task,plan):
    lease=task._leaf_v3(("protected-reply",plan.protected_reply_lease_ref),_HostParentBudgetMetadataReadV3(reader,plan.protected_reply_lease_ref))
    if lease is None:raise _HostMetadataNeededV3(task.pending)
    grant=lease.grant
    if grant.lease_id!=plan.protected_reply_lease_ref or not {"natural_generation","natural_review"}<=set(grant.allowed_work_kinds):
        raise AuthorityUnavailable("Host C3 lost its actual protected reply grant")
    required={}
    for slot,workflow in (("C5",reader.bundle.model_workflows.natural_generation),("C6",reader.bundle.model_workflows.natural_review)):
        members=tuple(row for row in plan.attempts if row.slot==slot)
        if any(row.state=="unknown" for row in members):raise AuthorityUnavailable("Host C3 cannot retry an unknown original reply")
        if any(row.state=="completed" for row in members):continue
        for dimension,amount in workflow.quote_ceiling.items():required[dimension]=required.get(dimension,0)+amount
    from .foreground_call_plan_v1 import ForegroundReplyAllocationV1
    allocation=decode_typed_production_value_v1(task.create.payload["provenance"]["reply_allocation"],ForegroundReplyAllocationV1)
    if (allocation.child_lease_id!=plan.protected_reply_lease_ref
            or allocation.parent_lease_ref!=task.cycle_job["budget_ref"] or allocation.child_grant()!=grant):
        raise AuthorityUnavailable("Host C3 protected child differs from actual original allocation")
    metadata=reader.budget_state_v3(plan.protected_reply_lease_ref)
    if ((metadata.parent_id,metadata.currency,dict(metadata.limits))!=
            (allocation.parent_lease_ref,allocation.currency,dict(allocation.child_limits))):
        raise AuthorityUnavailable("Host C3 protected child state changed original allocation")
    if any(metadata.available(dimension)<amount for dimension,amount in required.items()):
        raise AuthorityUnavailable("Host C3 cannot consume the original remaining C5/C6 obligation")

class _HostBudgetStateReadV3:
    def __init__(self,reader,lease_id):
        self.reader,self.lease_id=reader,lease_id
        self.phase="identity";self.complete=False;self.columns={};self.index=0
    def advance_v3(self,meter):
        r=self.reader;w=r.work;r.require_current_v3(meter)
        if self.phase=="identity":
            self.row=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_budget_leases",
                ("parent_id","bot_id","persona_id","currency","version","state"),"lease_id=?",(self.lease_id,))
            if self.row is None or self.row[1:3]!=w.namespace.as_tuple or self.row[-1]!="active":
                raise AuthorityUnavailable("Host original protected lease is not currently active")
            self.names=("limits_json","used_json","reserved_json","unconfirmed_json")
            for name in self.names:
                self.columns[name]=_HostParentColumnV3(r,table="runtime_budget_leases",column=name,
                    key_columns=("lease_id",),key=(self.lease_id,),mode="metadata")
            self.phase="bytes";return
        column=self.columns[self.names[self.index]]
        if not column.advance(meter):return
        self.index+=1
        if self.index==len(self.names):
            from .budget import BudgetLease
            parent,bot,persona,currency,version,state=self.row
            self.value=BudgetLease(self.lease_id,parent,bot,persona,currency,
                *(self.columns[name].require_v3(w)for name in self.names),version,state)
            self.complete=True
def _host_budget_state_v3(reader,lease_id):
    task=reader.budget_states.get(lease_id)
    if task is None:task=_HostBudgetStateReadV3(reader,lease_id);reader.budget_states[lease_id]=task
    if not task.complete:raise _HostMetadataNeededV3(task)
    return task.value
_HostMetadataReaderV3.budget_state_v3=_host_budget_state_v3
_HostMetadataReaderV3.require_named_member_v3=_host_require_named_member_v3
_HostMetadataReaderV3.require_remaining_reply_v3=_host_require_remaining_reply_v3

class _HostStageAccountingMetadataReadV3:
    def __init__(self,reader):
        self.reader=reader;self.phase="job";self.complete=False;self.leaves={};self.index=0
    def _leaf_v3(self,name,leaf):
        task=self.leaves.get(name)
        if task is None:task=leaf;self.leaves[name]=task
        if not task.complete:raise _HostMetadataNeededV3(task)
        return task
    def advance_v3(self,meter):
        r=self.reader;w=r.work;raw=r.header.value;r.require_current_v3(meter)
        if self.phase=="job":
            r.stage_job=self._leaf_v3("job",_HostParentJobMetadataReadV3(r,raw["job_id"]))
            job=r.stage_job.value
            if ((job["operation_id"],job["activity_id"],job["effect_id"],job["work_kind"])!=
                    (raw["operation_id"],raw["activity_id"],raw["effect_id"],"d07."+raw["work_kind"])
                    or job["cancel_epoch"]):
                raise AuthorityUnavailable("Host stage exact original job changed")
            if w.d07_selector.stage=="acquire" and job["phase"]=="queued":
                if job["fence"] or job["lease_holder"] is not None:
                    raise AuthorityUnavailable("Host queued acquire already has a worker")
            elif w.d07_selector.stage in {"result_read","adopt","reflection_prepare"}:
                if job["phase"]!="completed" or job["result_ref"] is None:
                    raise AuthorityUnavailable("Host terminal stage lacks actual completed result")
            elif job["phase"]!="running" or job["fence"]<1 or job["lease_holder"]is None:
                raise AuthorityUnavailable("Host running stage lacks its actual worker")
            self.phase="prepare_commit";return
        if self.phase=="prepare_commit":
            leaf=self._leaf_v3("commit",_HostSignedParentMetadataReadV3(r,family="d07",
                kind="prepare_commit",ref=raw["job_id"]))
            if (leaf.value["schema"]!="d07.preparation-commit.v1"
                    or leaf.value["prepared_digest"]!=r.header.metadata[0]
                    or leaf.value["prepare_operation_id"]!="d07-prepare:"+raw["operation_id"]):
                raise AuthorityUnavailable("Host preparation has no exact signed original CAS")
            self.phase="acquisition";return
        if self.phase=="acquisition":
            job=r.stage_job.value
            if job["phase"]=="queued":self.phase="quote_identity";return
            acquire_id="d07-acquire:"+canonical_digest((w.namespace,raw["operation_id"]))[:48]
            leaf=self._leaf_v3("acquisition",_HostBundleParentMetadataReadV3(r,acquire_id))
            if (leaf.metadata[1:3]!=(raw["activity_id"],None) or leaf.value["schema"]!="d07.actual-graph-stage.v1"
                    or leaf.value["phase"]!="execution_acquired" or leaf.value["prepared_digest"]!=r.header.metadata[0]):
                raise AuthorityUnavailable("Host running/terminal stage lacks actual same preparation acquisition")
            self.acquire_id=acquire_id;self.phase="request";return
        if self.phase=="request":
            leaf=self._leaf_v3("request",_HostSignedParentMetadataReadV3(r,family="d07",kind="request",ref=raw["job_id"],mode="request"))
            value=leaf.value;envelope=value["envelope"];job=r.stage_job.value
            from ..model_broker.d07_cognition_v1 import TEMPLATE_DIGEST
            if raw["schema"]=="d07.general-growth-prepared.v1":
                from ..model_broker.general_growth_cognition_v1 import TEMPLATE_DIGEST
            if (value["call_id"]!=raw["call_id"] or value["prompt_template_digest"]!=TEMPLATE_DIGEST
                    or envelope["identity"]["operation_id"]!=self.acquire_id
                    or envelope["authority"]["namespace"]!=raw["namespace"]
                    or (envelope["authority"]["worker_fence"],envelope["authority"]["actor"])!=(job["fence"],job["lease_holder"])
                    or envelope["parent_budget_lease_ref"]!=job["budget_ref"]):
                raise AuthorityUnavailable("Host original acquired request changed its actual worker/call/template/budget")
            self.phase="quote_identity";return
        if self.phase=="quote_identity":
            self.quote_row=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_resource_quotes",
                ("signature","status"),"quote_id=? AND version=?",(raw["quote_id"],raw["quote_version"]))
            if self.quote_row is None:raise AuthorityUnavailable("Host original resource quote absent")
            self.quote_column=_HostParentColumnV3(r,table="runtime_resource_quotes",column="quote_json",
                key_columns=("quote_id","version"),key=(raw["quote_id"],raw["quote_version"]),mode="metadata")
            self.phase="quote";return
        if self.phase=="quote":
            if not self.quote_column.advance(meter):return
            from .issuers import _decode_quote
            wire=canonical_serialize(self.quote_column.require_v3(w))
            w.d07_service.d11_issuer._signer.verify("resource-quote.v1",wire,self.quote_row[0])
            self.quote=_decode_quote(wire);job=r.stage_job.value
            if ((self.quote.quote_id,self.quote.version,self.quote.operation_id,self.quote.work_kind)!=
                    (raw["quote_id"],raw["quote_version"],raw["operation_id"],"d07.cognition")
                    or canonical_digest(self.quote)!=raw["quote_digest"]):
                raise AuthorityUnavailable("Host resource quote differs from its original prepared identity")
            if w.d07_selector.stage=="acquire" and (self.quote_row[1]!="active" or r.now_v3()>=self.quote.valid_until_utc):
                raise AuthorityUnavailable("Host queued acquire cannot revive expired quote")
            self.phase="reservation";return
        if self.phase=="reservation":
            job=r.stage_job.value
            self.reservation=_runtime_bounded_fixed_row_v3(w.db,meter,"runtime_budget_reservations",
                ("digest","state"),"lease_id=? AND operation_id=?",(job["budget_ref"],raw["operation_id"]))
            if self.reservation is None or self.reservation[0]!=raw["reservation_digest"]:
                raise AuthorityUnavailable("Host stage lost its exact original reservation")
            terminal=w.d07_selector.stage in {"result_read","adopt","reflection_prepare"}
            if self.reservation[1] != ("settled" if terminal else "reserved"):
                raise AuthorityUnavailable("Host stage reservation phase differs from original execution")
            self.phase="terminal" if terminal else "finish";return
        if self.phase=="terminal":
            kinds=(("execution","d07-terminal:"+raw["call_id"]),("paid_cost",raw["job_id"]),
                ("body_cost",raw["job_id"]),("result","d07-result:"+raw["call_id"]))
            kind,ref=kinds[self.index]
            leaf=self._leaf_v3(kind,_HostSignedParentMetadataReadV3(r,family="d07",kind=kind,ref=ref))
            if kind=="execution":
                value=leaf.value
                if (value["input_digest"]!=raw["stage_input_digest"] or value["call_id"]!=raw["call_id"]):
                    raise AuthorityUnavailable("Host terminal does not match original paid call")
            elif kind=="paid_cost":
                if leaf.value["paid"]is not True:raise AuthorityUnavailable("Host terminal cost is not actually paid")
            elif kind=="body_cost":
                if leaf.value["unpaid_cost"]is not False:raise AuthorityUnavailable("Host terminal Body settlement is unpaid")
            self.index+=1
            if self.index==len(kinds):self.phase="finish"
            return
        if self.phase=="finish":self.complete=True;return
        raise AuthorityUnavailable("unregistered Host stage accounting phase")

@dataclass(frozen=True,eq=False,init=False)
class HostD07StageContentScopeV3:
    effective_source_authority:AuthorityContext
    source_kind:str
    commitment:str
    original_deadline_utc:float
    source_refs:tuple[str,...]
    def __init__(self,issuer,task):
        if issuer is not _HOST_ISSUER or not task.complete:
            raise AuthorityUnavailable("Host Source scope requires actual complete Source and parent EOF")
        result=task.parents.result;w=task.reader.work
        values={"effective_source_authority":result.effective_source_authority,"source_kind":result.kind,
            "original_deadline_utc":result.original_deadline_utc,
            "source_refs":tuple(sorted(task.sources.witnesses))}
        values["commitment"]=canonical_digest((w.namespace,w.operation.operation_id,w.graph_stamp,
            result.parent_originals,result.source_versions,tuple(task.sources.access_versions),values))
        for name,value in values.items():object.__setattr__(self,name,value)
        _HOST_SCOPES[self]=task
    def require_for_v3(self,reader,*,body=True):
        task=_HOST_SCOPES.get(self)
        if task is None or task.reader.work is not reader or not task.complete or reader.operation.closed:
            raise AuthorityUnavailable("Host Source scope crossed its actual original Background Work")
        task.reader.require_registered_v3()
        if reader.graph_stamp!=task.graph_stamp or reader.read_scope is not task.read_scope:
            raise AuthorityUnavailable("Host Source scope changed original metadata or READ identity")
        if body:
            material=reader.d07_source_material
            if material is None:raise AuthorityUnavailable("Host body requires actual Source material EOF")
            if material.reader is not reader or material.actor!=self.effective_source_authority.actor or material.original_digest!=task.reader.header.metadata[0]:
                raise AuthorityUnavailable("Host body material changed actual Source identity")
        return self
    def release_v3(self):
        task=_HOST_SCOPES.pop(self,None)
        if task is not None:task.release_v3()

class _HostStageContentScopeReadV3:
    def __init__(self,reader,owner_entry):
        self.reader=_HostMetadataReaderV3(_HOST_ISSUER,reader,owner_entry)
        self.reader.container=self
        self.graph_stamp,self.read_scope=reader.graph_stamp,reader.read_scope
        self.phase="header";self.pending=None;self.parents=self.sources=self.accounting=None
        self.complete=False;self.result=None;self.write_scope=None
        self.reader.header=_HostPreparedHeaderV3(self.reader,reader.d07_selector.parent_job_id,
            expected_digest=reader.entry_metadata[0][0])
    def metadata_authority_v3(self):
        if self.parents is None or not self.parents.complete:
            raise AuthorityUnavailable("Host effective Source authority needs actual parent EOF")
        return self.parents.result.effective_source_authority
    def advance_v3(self,meter):
        r=self.reader;w=r.work;r.require_current_v3(meter)
        if self.pending is not None:
            self.pending.advance_v3(meter)
            if self.pending.complete:self.pending=None
            r.reserve_v3();return
        try:
            if self.phase=="header":
                if not r.header.complete:r.header.advance_v3(meter);return
                current=r.header
                while current.prepared_class.__name__=="D07ReflectionPreparedV3":
                    raw=current.value;ref=raw["parent_prepared_ref"]
                    parent=r.parent_headers.get(ref)
                    if parent is None:
                        parent=_HostPreparedHeaderV3(r,ref,raw["parent_prepared_digest"]);r.parent_headers[ref]=parent
                    if not parent.complete:parent.advance_v3(meter);return
                    if parent.job_id==current.job_id or len(r.parent_headers)>=3:
                        raise AuthorityUnavailable("Host original Reflection parent chain exceeds signed causal bound")
                    current=parent
                w.entry_metadata=(r.header.metadata,r.header.value)
                self.accounting=_HostStageAccountingMetadataReadV3(r);self.phase="accounting";return
            if self.phase=="accounting":
                self.accounting.advance_v3(meter)
                if self.accounting.complete:self.parents=_HostSpecialParentMetadataReadV3(r);self.phase="parent"
                return
            if self.phase=="parent":
                self.parents.advance_v3(meter)
                if self.parents.complete:
                    from .domain_background_read_v3 import _D07StageSourceQualificationV3
                    self.sources=_D07StageSourceQualificationV3(w)
                    if self.parents.result.kind=="general_growth_owner":
                        roots=set(r.header.value["context_source_refs"])|set(r.header.value["support_source_refs"])
                        self.sources.expected={ref:revision for ref,revision in self.sources.expected.items()if ref in roots}
                        if set(self.sources.expected)!=roots:
                            raise AuthorityUnavailable("Host General original input omitted exact source-column version")
                        self.sources.pending=list(self.sources.expected)
                    w.d07_source_qualification=self.sources
                    self.phase="sources"
                return
            if self.phase=="sources":
                self.sources.advance(meter)
                if self.sources.complete:
                    self.complete=True;self.result=HostD07StageContentScopeV3(_HOST_ISSUER,self)
                return
            raise AuthorityUnavailable("Host content qualification has no registered phase")
        except _HostMetadataNeededV3 as needed:self.pending=needed.task
        finally:r.reserve_v3()
    def release_v3(self):
        r=self.reader
        _HOST_METADATA.pop(r,None)
        if self.parents is not None:_HOST_PARENT_TASKS.pop(self.parents,None)
        r.work.operation.unregister_retained_state_v3(r)
        r.graph_points.clear();r.parent_headers.clear();r.budget_states.clear()

def require_pending_host_d07_source_authority_v3(reader):
    task=getattr(reader,"d07_content_scope_task",None)
    if type(task)is not _HostStageContentScopeReadV3 or task.reader.work is not reader:
        raise AuthorityUnavailable("actual Host Source metadata task required")
    return task.metadata_authority_v3()

def prepare_current_host_d07_stage_content_scope_v3(reader):
    """Consume the same admitted READ and retained Work; finish all metadata before body."""
    from .domain_background_read_v3 import bind_background_reads_v3,BackgroundReadNeededV3,\
        _start_background_request_v3,_advance_background_pending_v3
    from .first_ingress_v2 import trusted_upper
    if (type(reader)is not BackgroundReadWorkV3 or reader.kind!="d07_stage"
            or reader.d07_selector.stage=="egress_seal" or reader.fence is None
            or reader.read_scope is not reader.fence.scope or reader.read_scope.operation!="read"
            or reader.db.in_transaction):
        raise AuthorityUnavailable("Host content qualification requires actual ordinary Stage READ")
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    task=reader.d07_content_scope_task
    if task is None:
        task=_HostStageContentScopeReadV3(reader,reader.d07_owner_entry)
        reader.d07_content_scope_task=task
    port=reader.graph._GraphCoordinator__content_fence_v2
    original=decode_typed_production_value_v1(json.loads(reader.entry_metadata[1]["owner_authority_json"]),AuthorityContext)
    if original.actor!=reader.d07_owner_entry.owner_acl_authority.actor:
        current=reader.graph._GraphCoordinator__self_identity_port.current_self_identity(
            namespace=reader.namespace,authority_namespace=reader.read_scope.authority_namespace,
            request_operation_id=reader.read_scope.operation_id,permit=reader.read_scope.permit)
        if task.reader.current_self is None:task.reader.current_self=current
        elif task.reader.current_self!=current:raise AuthorityUnavailable("Host Source current Self changed")
    while not task.complete:
        reader.graph._validate_read_fence_v3(reader.fence)
        reader.d07_owner_entry.require_for_v3(reader)
        require_current_host_d07_stage_source_permission_v3(reader)
        reader.d07_stage_clock_utc=trusted_upper(port.read_ingress_clock(reader.bundle.ingress_clock))
        if reader.d07_stage_clock_utc>=reader.operation.deadline_utc:
            raise AuthorityUnavailable("Host content scope exceeded original Work deadline")
        with bind_background_reads_v3(reader,db=reader.db),reader.store._lock,runtime_storage_quantum_v3(reader.db)as meter:
            reader.db.execute("BEGIN")
            try:
                if reader.pending is not None:_advance_background_pending_v3(reader,meter)
                else:task.advance_v3(meter)
                reader.db.execute("COMMIT")
            except BackgroundReadNeededV3 as needed:
                reader.db.execute("COMMIT");_start_background_request_v3(reader,needed.request)
            except BaseException:
                reader.db.execute("ROLLBACK");raise
    reader.d07_source_scope=task.result
    return task.result

def freeze_current_host_d07_stage_read_frame_v3(reader,*,envelope,scope,plan,now_utc,observed_originals=()):
    from .domain_production_frame_v1 import _materialize_current_domain_frame_fields_v1
    from .domain_production_contracts_v1 import CurrentOperationFrameV1,ProductionOperationLimitsV1,ProductionOwnerGuardV1
    from .domain_background_read_v3 import require_background_prepared_frame_inputs_v3
    from .c09_paged_sql_v2 import current_c09_sql_meter_v2
    source=reader.d07_source_scope
    if type(source)is not HostD07StageContentScopeV3:
        raise AuthorityUnavailable("Host current READ frame has no actual Source issuer")
    source.require_for_v3(reader)
    if (scope is not reader.read_scope or envelope.authority!=source.effective_source_authority
            or envelope.authority.namespace!=reader.namespace or not reader.db.in_transaction):
        raise AuthorityUnavailable("Host current READ frame changed actual Source/Scope")
    reader.d07_content_scope_task.reader.require_current_v3(current_c09_sql_meter_v2())
    owner=reader.owner
    guard=ProductionOwnerGuardV1(owner_grant_key(*reader.namespace.as_tuple).token,owner.grant_revision,
        owner.grant_digest.removeprefix("sha256:"),owner.authorization_head.removeprefix("sha256:"))
    inputs=require_background_prepared_frame_inputs_v3(reader.db,graph=reader.graph,scope=scope,
        plan=plan,envelope=envelope,current_owner=owner)
    inputs.require_current_v3(reader.db,scope,owner)
    return CurrentOperationFrameV1(*_materialize_current_domain_frame_fields_v1(reader.graph,reader.db,
        envelope=envelope,scope=scope,plan=plan,now_utc=now_utc,expected_owner_guard=guard,
        expected_rights=(owner.access_epoch,owner.delete_epoch),observed_originals=observed_originals,
        installed_policy_refs=(),limits=ProductionOperationLimitsV1(),prepared_inputs=inputs))

def require_current_host_d07_stage_source_permission_v3(reader,*,write_scope=None):
    """Observe independent current Self outside SQL under the actual phase permit."""
    from dataclasses import asdict
    task=reader.d07_content_scope_task
    if task is None or task.reader.work is not reader or reader.db.in_transaction:
        raise AuthorityUnavailable("Host Source permission requires its actual task outside SQL")
    r=task.reader;scope=reader.read_scope if write_scope is None else write_scope
    port=reader.graph._GraphCoordinator__content_fence_v2
    if port.validate_fence(scope)!=scope.permit:
        raise AuthorityUnavailable("Host Source phase permit is no longer actual")
    original=decode_typed_production_value_v1(json.loads(reader.entry_metadata[1]["owner_authority_json"]),AuthorityContext)
    if original.actor!=r.owner_acl_authority.actor:
        current=reader.graph._GraphCoordinator__self_identity_port.current_self_identity(
            namespace=reader.namespace,authority_namespace=scope.authority_namespace,
            request_operation_id=scope.operation_id,permit=scope.permit)
        if r.current_self is None:r.current_self=current
        old,new=asdict(r.current_self),asdict(current)
        for value in (old,new):
            value.pop("request_operation_id");value.pop("permit")
        if old!=new or current.self_entity_ref!=original.actor:
            raise AuthorityUnavailable("Host effective Source Self certificate changed")
    if write_scope is not None:task.write_scope=write_scope
    return original
