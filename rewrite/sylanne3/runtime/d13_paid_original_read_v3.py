"""Actual D13 paid Work: frozen metadata, current Source closure, then original EOF."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import datetime
from types import MappingProxyType
from weakref import WeakKeyDictionary, WeakSet
import json
import secrets
from hashlib import sha256

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, owner_grant_key
from ..graph_worker import GraphStorageStepV3, create_graph_storage_work_v3, require_graph_storage_work_admission_v3
from ..memory_types import source_key, access_key
from ..runtime_contracts import NamespaceId
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, runtime_storage_quantum_v3, runtime_storage_v3, begin_runtime_cell_read_v3)
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3, C09MemoryAccessJSONStreamV3
from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
from ..authority_service.c09_authority_storage_rebase_v2 import _D13PaidIdentityStreamV3
from .dispatch_current_inventory_v3 import _heap

KIND = "d13_paid_original_read_v3"
_ISSUER = object()
_READERS = WeakSet()
_PROOFS = WeakKeyDictionary()
_BOUND = ContextVar("actual_d13_paid_original_read_v3", default=None)
_READING = ContextVar("actual_d13_paid_window_reader_v3",default=None)
_OPERATIONS = frozenset(("prepare_d13_paid_call_v1", "record_d13_paid_result_read_v1",
    "settle_d13_paid_precompression_v1", "complete_d13_paid_precompression_v1",
    "recover_d13_paid_precompression_v1", "schedule_d13_paid_precompression_v1",
    "read_current_d13_conversation_window_v1","read_current_d13_completed_paid_block_v3"))
_TABLES = (
    ("graph_d13_paid_intent_originals_v1", ("operation_id","original_json","original_digest"), "original_json"),
    ("graph_d13_paid_call_originals_v1", ("call_id","original_json","original_digest"), "original_json"),
    ("graph_d13_paid_result_reads_v1", ("read_attempt_id","payload_json","payload_digest"), "payload_json"),
    ("graph_d13_paid_cost_receipts_v1", ("payload_json","payload_digest"), "payload_json"),
)
_JOB_COLUMNS = ("job_id","operation_id","activity_id","bot_id","persona_id","phase","work_kind",
    "deadline_utc","budget_ref","lease_holder","lease_expires_utc","fence","cancel_epoch","result_ref")


def _utc(value):
    return datetime.fromisoformat(value.replace("Z","+00:00")).timestamp()


class _FrozenMetadataV3:
    """Only exact frozen scope/versions; no turn, model, canonical-input or message text."""
    def __init__(self):
        self.buffers, self.values = {}, {}
    def _select(self, path):
        if path[:2] == ("window","namespace"):return len(path)==3 and path[-1] in {"bot_id","persona_id"}
        if path in {("window","conversation_ref"),("window","access_epoch"),("window","delete_epoch"),
                ("window","activation_epoch"),("plan","expires_at_utc"),("plan","job_ref")}:return True
        if path[:2] in {("window","scene_ref"),("window","audience_ref"),("plan","scene_ref"),("plan","audience_ref")}:
            return len(path)==3 and path[-1] in {"ref","version"}
        if path[:2] in {("window","read_set"),("window","source_dependencies"),("plan","source_dependencies")}:
            return len(path)==4 and type(path[2]) is int and path[-1] in {"ref","version"}
        if path[:2] == ("window","turns"):
            return len(path)==5 and path[3] in {"source_ref","access_ref","raw_ref"} and path[-1] in {"ref","version"}
        if path[:1] == ("turns",):
            return len(path)==4 and path[2] in {"source_ref","access_ref","raw_ref"} and path[-1] in {"ref","version"}
        return False
    def emit(self,event):
        if not self._select(event.path):return
        if event.kind=="scalar_start":self.buffers[event.path]=bytearray()
        elif event.kind=="scalar_chunk":
            target=self.buffers[event.path]
            if len(target)+len(event.raw)>8192:raise AuthorityUnavailable("D13 frozen metadata scalar exceeds original bound")
            target.extend(event.raw)
        elif event.kind=="scalar_end":self.values[event.path]=json.loads(self.buffers.pop(event.path))


class _IntentMetadataV3(_D13PaidIdentityStreamV3):
    def __init__(self):
        super().__init__("intent",ensure_ascii=True)
        from ..authority_service.c09_authority_storage_rebase_v2 import _D13PaidEncodedStringStreamV3
        self.decoder=_D13PaidEncodedStringStreamV3(ensure_ascii=True)
        self.frozen_parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.frozen=_FrozenMetadataV3()
        self.scalars,self.buffers={},{}
        self.frozen_complete=False
    def emit(self,event):
        path=event.path
        if path==("frozen_json",):
            if event.kind=="scalar_chunk":
                self.decoder.feed(event.raw,lambda child:None)
                if self.decoder.pending:
                    self.frozen_parser.feed(bytes(self.decoder.pending),self.frozen.emit)
                    self.decoder.pending.clear()
            elif event.kind=="scalar_end":
                self.decoder.finish();self.frozen_parser.finish();self.frozen_complete=True
            return
        selected=(path[:1] in {("namespace",),("binding",)} or path in {
            ("quote_id",),("quote_version",),("grant_id",),("grant_version",),
            ("access_epoch",),("delete_epoch",),("activation_epoch",),("budget_operation_id",)})
        if not selected:return
        if event.kind=="scalar_start":self.buffers[path]=bytearray()
        elif event.kind=="scalar_chunk":
            target=self.buffers[path]
            if len(target)+len(event.raw)>8192:raise AuthorityUnavailable("D13 original metadata scalar exceeds original bound")
            target.extend(event.raw)
        elif event.kind=="scalar_end":self.scalars[path]=json.loads(self.buffers.pop(path))
    def finish(self):
        result=super().finish()
        if not self.frozen_complete:raise AuthorityUnavailable("D13 intent metadata lacks its actual nested frozen EOF")
        return result


class _ScheduleMetadataV3(C09CanonicalJSONStreamV2):
    def __init__(self):
        super().__init__(ensure_ascii=True)
        self.frozen=_FrozenMetadataV3();self.scalars={};self.buffers={}
    def emit(self,event):
        if event.path[:1]==("frozen",):
            self.frozen.emit(replace(event,path=event.path[1:]))
            return
        if event.path[:1]!=("binding",):return
        if event.kind=="scalar_start":self.buffers[event.path]=bytearray()
        elif event.kind=="scalar_chunk":
            target=self.buffers[event.path]
            if len(target)+len(event.raw)>8192:raise AuthorityUnavailable("D13 schedule metadata scalar exceeds original bound")
            target.extend(event.raw)
        elif event.kind=="scalar_end":self.scalars[event.path]=json.loads(self.buffers.pop(event.path))


class _ColumnV3:
    """One selected physical JSON column, with one bounded read/parse step."""
    def __init__(self,reader,*,table,column,key_columns,key,cell_id=None,metadata=False,source=False,access=False):
        reader.require_current_v3()
        if not metadata and not source and not access and not reader.qualified:
            raise AuthorityUnavailable("D13 protected column requires every actual current Source ancestor")
        if table=="graph_atoms" and not metadata and not source and not access:
            atom_key=AtomKey.from_token(key[0])
            if NamespaceId.from_key(atom_key)!=reader.namespace:
                raise AuthorityUnavailable("D13 selected Graph body crossed its actual namespace")
            if atom_key.type_name=="memory.source" and atom_key.token not in reader.sources:
                raise AuthorityUnavailable("D13 window body Source lacks its all-parent current READ qualification")
        if access:
            ref=reader.pending_sources[-1]
            actual=access_key(*reader.namespace.as_tuple,AtomKey.from_token(ref).owner.subject).token
            if (table,column,tuple(key_columns),tuple(key))!=("graph_atoms","value",("token",),(actual,)):
                raise AuthorityUnavailable("D13 access metadata column changed its actual pending Source")
        self.owner,self.table,self.column,self.key_columns,self.key=reader,table,column,tuple(key_columns),tuple(key)
        self.where=" AND ".join(name+"=?" for name in self.key_columns)
        self.cell=(begin_runtime_cell_read_v3(reader.db,cell_id,
            erasure_owner_ref=key[0]) if cell_id is not None else None)
        codec=None if self.cell is None else self.cell.header[0]
        if codec not in {None,"canonical-json.ascii.v1","canonical-json.utf8.v1"}:
            raise AuthorityUnavailable("D13 original has another actual JSON cell codec")
        self.metadata,self.source,self.access=metadata,source,access
        self.parser=(_ScheduleMetadataV3() if metadata=="schedule" else _IntentMetadataV3() if metadata else
            C09MemorySourceJSONStreamV3(ensure_ascii=codec!="canonical-json.utf8.v1") if source else
            C09MemoryAccessJSONStreamV3(ensure_ascii=codec!="canonical-json.utf8.v1") if access else
            C09CanonicalJSONStreamV2(ensure_ascii=codec!="canonical-json.utf8.v1"))
        self.total=None if self.cell is None else self.cell.header[3]
        self.offset,self.fragment=0,b""
        self.body=None if metadata or source or access else bytearray()
        self.complete,self.sha256,self.value=False,None,None
    def advance(self,meter):
        r=self.owner;r.require_current_v3(meter=meter)
        if self.fragment:
            part=self.fragment[:1024];r.reserve_v3(len(part)*16+65536)
            self.parser.feed(part,self.parser.emit if self.metadata else lambda event:None)
            if self.body is not None:self.body.extend(part)
            self.fragment=self.fragment[len(part):];r.reserve_v3()
            return
        if self.cell is not None:
            chunk=self.cell.read_fragment(meter=meter)
        else:
            if self.total is None:
                meter.require_available(1024)
                row=r.db.execute("SELECT typeof("+self.column+"),length(CAST("+self.column+" AS BLOB)) "
                    "FROM "+self.table+" WHERE "+self.where,self.key).fetchone()
                meter.charge_read(16)
                if row is None or row[0]!="text":raise AuthorityUnavailable("D13 original selected TEXT disappeared")
                self.total=row[1]
            if self.offset<self.total:
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table=self.table,column=self.column,
                    where=self.where,parameters=self.key,start=self.offset,
                    length=min(16384,self.total-self.offset),meter=meter)
                if (total,kind)!=(self.total,"text"):raise AuthorityUnavailable("D13 original physical byte identity changed")
                self.offset+=len(chunk)
            else:chunk=None
        if chunk is not None:
            r.reserve_v3(len(chunk)*2+65536);self.fragment=chunk;return
        result=self.parser.finish()
        if self.cell is not None:
            if (result.sha256,result.byte_count)!=(self.cell.finish(meter=meter),self.cell.header[3]):
                raise AuthorityUnavailable("D13 original canonical EOF differs from sealed cell")
        elif result.byte_count!=self.total:raise AuthorityUnavailable("D13 original selected TEXT EOF differs")
        self.sha256=result.sha256
        if self.source:
            r.reserve_v3(_heap(self.parser._source_metadata)*2+65536)
            self.value=MappingProxyType({name:tuple(value) if type(value)is list else value
                for name,value in self.parser._source_metadata.items()})
        elif self.access:
            r.reserve_v3(_heap(self.parser.metadata)*2+65536)
            self.value=dict(self.parser.metadata)
        elif not self.metadata:
            r.reserve_v3(len(self.body)*10+65536)
            self.value=bytes(self.body).decode("utf8")
            self.body=None
        self.complete=True;r.reserve_v3()


@dataclass(frozen=True)
class _SourceLeafV3:
    key: object
    revision: int
    valid: bool
    metadata: object


class D13PaidOriginalReadWorkV3:
    def __init__(self,issuer,graph,authority,lease,operation,fence,job_id,method,args,now):
        if issuer is not _ISSUER or method not in _OPERATIONS:
            raise AuthorityUnavailable("actual private D13 paid reader factory required")
        self.graph,self.authority,self.lease=graph,authority,lease
        self.operation,self.fence,self.namespace=operation,fence,authority.namespace
        self.db,self.store=graph._GraphCoordinator__store._db,graph._GraphCoordinator__store
        self.job_id,self.method,self.args=job_id,method,dict(args)
        self.scene_ref=args.get("scene_ref")
        self.window_policy=(graph._GraphCoordinator__d13_precompression_policy or graph._GraphCoordinator__d13_paid_precompression_policy
            if method=="read_current_d13_conversation_window_v1" else graph._GraphCoordinator__d13_paid_precompression_policy)
        self.current_window=self.window_metadata=self.window_body=None
        self.pending_schedule_head=self.pending_schedule_sha=self.paid_cost_atom=self.paid_cost_head=None
        self.initial_now,self.now_utc,self.deadline=now,now,operation.deadline_utc
        self.graph_stamp=(fence.metadata,fence.epoch)
        self.owner_guard_head=fence.fence_observation.authorization_head
        self.selection_digest=operation.selection_digest
        self.work=None;self.parent=None;self.phase="metadata";self.column=None;self.job=None
        self.owner_head=self.epochs=None
        self.intent_head,self.intent_metadata,self.frozen_metadata,self.intent_metadata_sha=None,None,None,None
        self.intent_digest_task=self.intent_projection=None
        self.completed_read=None
        self.original_deadline=None
        self.frozen_versions,self.sources,self.source_heads,self.access_atoms={},{},{},{}
        self.pending_sources=[];self.qualified=False
        self.rows,self.row_headers,self.body_columns={},{},{}
        self.table_index,self.pending_table,self.pending_header=0,None,None
        self.complete,self.proof,self.read_finished=False,None,False
        self.reserved=0
        _READERS.add(self);self.reserve_v3(65536)
    def reserve_v3(self,extra=0):
        values=(self.intent_metadata,self.frozen_metadata,self.frozen_versions,self.sources,
            self.source_heads,self.access_atoms,self.pending_sources,self.rows,self.row_headers,self.body_columns)
        if self.window_metadata is not None:values+= (vars(self.window_metadata),)
        if self.window_body is not None:values+= (vars(self.window_body),)
        size=_heap(values)+extra+65536
        size+=sum(_heap(tuple(source.metadata.items())) for source in self.sources.values())
        size+=sum(_heap(atom.value) for atom in self.access_atoms.values())
        if self.paid_cost_atom is not None:size+=_heap(self.paid_cost_atom.value)
        if self.completed_read is not None:size+=self.completed_read.heap_v3()
        if self.intent_digest_task is not None:
            size+=_heap(self.intent_digest_task.actions)
        metadata_column=self.column if self.column is not None else (
            self.intent_digest_task.column if self.intent_digest_task is not None else None)
        if metadata_column is not None and isinstance(metadata_column.parser,_IntentMetadataV3):
            p=metadata_column.parser
            size+=_heap((vars(p),vars(p.frozen_parser),vars(p.decoder),vars(p.frozen)))
        if self.column is not None:
            c=self.column;size+=_heap((c.key,c.fragment,c.body,c.value))
            if isinstance(c.value,MappingProxyType):size+=_heap(tuple(c.value.items()))
            if isinstance(c.parser,C09MemorySourceJSONStreamV3):size+=c.parser._source_heap_bytes()
            elif isinstance(c.parser,C09MemoryAccessJSONStreamV3):size+=c.parser._source_heap_bytes()
            elif isinstance(c.parser,(_IntentMetadataV3,_ScheduleMetadataV3)):
                size+=_heap((c.parser.scalars,c.parser.buffers,c.parser.frozen.values,c.parser.frozen.buffers,
                    getattr(getattr(c.parser,"decoder",None),"pending",None)))
        if size>self.reserved:self.operation.retain(size-self.reserved);self.reserved=size
    def require_current_v3(self,*,meter=None):
        if (self not in _READERS or self.operation.closed or self.work is None
                or self.work.state is not (self if self.parent is None else self.parent) or self.work.operation is not self.operation
                or self.work.coordinator is not self.graph or self.work.kind!=(KIND if self.parent is None else "d13_standby_read_v3")
                or self.work.selection_digest!=self.selection_digest
                or runtime_storage_v3(self.db) is not self.operation.handle
                or self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp):
            raise AuthorityUnavailable("D13 paid reader lost its actual Work/current scope/selection")
        self.work._require_invocation(self.graph)
        now=self.now_utc if self.parent is None or self.parent.read_finished else self.parent.now_utc
        if now>=min(self.deadline,self.original_deadline or self.deadline):
            raise AuthorityUnavailable("D13 paid READ original TTL/worker lease expired")
        with runtime_storage_quantum_v3(self.db) as current:
            if meter is not None and current is not meter:raise AuthorityUnavailable("D13 paid reader changed its actual quantum")
            epochs=current.read_fixed_row(self.db,"graph_authority_epochs",("access_epoch","delete_epoch"),
                "bot=? AND persona=?",self.namespace.as_tuple)
            owner=current.read_fixed_row(self.db,"graph_atoms",("revision","valid","value_cell_id"),
                "token=?",(owner_grant_key(*self.namespace.as_tuple).token,))
            if self.epochs is not None and (epochs!=self.epochs or owner!=self.owner_head):
                raise AuthorityUnavailable("D13 paid Source rights/Owner head changed")
        return self
    def refresh_scope_clock_v3(self):
        if self.db.in_transaction:
            raise AuthorityUnavailable("D13 scope clock observation must precede its read transaction")
        if not (self.read_finished or self.parent is not None and self.parent.read_finished):
            self.graph._validate_read_fence_v3(self.fence)
        from .first_ingress_v2 import trusted_upper
        self.now_utc=trusted_upper(self.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
            self.graph._GraphCoordinator__scene_clock_policy))
        self.require_current_v3()

    def _metadata(self,meter):
        ns=self.namespace
        if self.job_id is None:
            if self.method=="schedule_d13_paid_precompression_v1":
                jobs=tuple(ref for ref,row in self.parent.ledger_rows.items() if row[2] in {"queued","running"})
                if len(jobs)>1:raise AuthorityUnavailable("D13 scene metadata has multiple original pending jobs")
                if jobs:self.job_id=jobs[0]
            if self.job_id is None:
                if self.method=="schedule_d13_paid_precompression_v1":
                    if self.pending_schedule_head is None:
                        row=meter.read_fixed_row(self.db,"graph_d13_paid_schedule_inputs_v1",
                            ("job_ref","payload_digest"),"bot=? AND persona=? AND scene_ref=? AND pending=1",
                            (*ns.as_tuple,self.scene_ref))
                        if row is not None:
                            self.pending_schedule_head=tuple(row)
                            self.column=_ColumnV3(self,table="graph_d13_paid_schedule_inputs_v1",column="payload_json",
                                key_columns=("bot","persona","job_ref"),key=(*ns.as_tuple,row[0]),metadata="schedule")
                            return
                    elif self.column is not None:
                        self.column.advance(meter)
                        if not self.column.complete:return
                        self._seal_pending_schedule_metadata_v3()
                        return
                self.phase="window_metadata"
                return
        if self.job is None:
            self.job=meter.read_fixed_row(self.db,"runtime_jobs",_JOB_COLUMNS,"job_id=?",(self.job_id,))
            if self.job is None or self.job[3:5]!=ns.as_tuple or self.job[6]!="d13.precompress.paid.v1" or self.job[12]!=0:
                raise AuthorityUnavailable("D13 paid reader requires its actual uncancelled namespace job")
            self.intent_head=meter.read_fixed_row(self.db,_TABLES[0][0],("operation_id","original_digest"),
                "bot=? AND persona=? AND job_ref=?",(*ns.as_tuple,self.job_id))
            if self.intent_head is None:raise AuthorityUnavailable("D13 paid reader lacks its immutable original")
            self.column=_ColumnV3(self,table=_TABLES[0][0],column="original_json",
                key_columns=("bot","persona","job_ref"),key=(*ns.as_tuple,self.job_id),metadata=True)
            return
        self.column.advance(meter)
        if not self.column.complete:return
        outer=self.column.parser.scalars;frozen=self.column.parser.frozen.values
        if (outer.get(("namespace","bot_id")),outer.get(("namespace","persona_id")))!=ns.as_tuple:
            raise AuthorityUnavailable("D13 paid metadata original namespace differs")
        if (outer.get(("binding","job_ref"))!=self.job_id
                or outer.get(("binding","original_operation_id"))!=self.job[1]
                or self.intent_head[0]!=self.job[1]
                or frozen.get(("plan","job_ref"))!=self.job_id
                or (frozen.get(("window","namespace","bot_id")),frozen.get(("window","namespace","persona_id")))!=ns.as_tuple
                or frozen.get(("window","conversation_ref"))!=self.authority.audience[0]):
            raise AuthorityUnavailable("D13 paid metadata job/original/private scope differs")
        scene=frozen.get(("window","scene_ref","ref"))
        scene_key=AtomKey.from_token(scene)
        if (NamespaceId.from_key(scene_key)!=ns or scene_key.owner.kind!="scene"
                or self.parent is not None and scene_key.owner.subject!=self.parent.scene_ref):
            raise AuthorityUnavailable("D13 paid original scene crossed actual namespace")
        versions={}
        for path,ref in frozen.items():
            if path[-1:]!=("ref",):continue
            version=frozen.get((*path[:-1],"version"))
            if type(ref)is not str or type(version)is not int or version<0:
                raise AuthorityUnavailable("D13 frozen metadata requires exact ref/version pairs")
            if ref in versions and versions[ref]!=version:raise AuthorityUnavailable("D13 frozen duplicate versions differ")
            versions[ref]=version
        roots=tuple(sorted(ref for ref in versions if AtomKey.from_token(ref).type_name=="memory.source"))
        if not roots:raise AuthorityUnavailable("D13 paid original has no actual frozen Source roots")
        now=self.initial_now
        job_deadline=(outer[("binding","expires_at_utc")] if self.method=="read_current_d13_completed_paid_block_v3" else _utc(self.job[7]))
        if now>=min(frozen[("plan","expires_at_utc")],job_deadline):
            raise AuthorityUnavailable("D13 paid original Source/job TTL expired")
        if self.job[5]=="running" and (self.job[9]!=self.authority.actor or self.job[10] is None or now>=_utc(self.job[10])):
            raise AuthorityUnavailable("D13 paid original worker holder/lease changed")
        if (frozen[("window","access_epoch")],frozen[("window","delete_epoch")])!=self.epochs:
            raise AuthorityUnavailable("D13 frozen original rights epochs changed")
        if frozen[("window","activation_epoch")]!=self.authority.activation_generation:
            raise AuthorityUnavailable("D13 frozen original activation changed")
        self.original_deadline=min(frozen[("plan","expires_at_utc")],job_deadline,
            _utc(self.job[10]) if self.job[5]=="running" else self.deadline)
        self.frozen_versions=versions
        self.scene_ref=scene_key.owner.subject
        self.intent_metadata_sha=self.column.sha256
        self.intent_projection=self.column.parser
        self.intent_digest_task=_IntentDigestMetadataV3(self,self.column)
        self.column=None;self.phase="intent_digest"
        return

    def _seal_authenticated_intent_metadata_v3(self):
        outer=self.intent_projection.scalars;frozen=self.intent_projection.frozen.values
        roots=tuple(ref for ref in self.frozen_versions if AtomKey.from_token(ref).type_name=="memory.source")
        self.intent_metadata,self.frozen_metadata=MappingProxyType(outer),MappingProxyType(frozen)
        self.intent_digest_task=self.intent_projection=None
        self.pending_sources=list(roots);self.column=None;self.phase="window_metadata"
        if self.method=="read_current_d13_completed_paid_block_v3":
            from .d13_completed_paid_read_v3 import CompletedD13PaidReadV3
            self.completed_read=CompletedD13PaidReadV3(self);self.phase="completed_metadata"
        self.reserve_v3()
    def _seal_pending_schedule_metadata_v3(self):
        if self.column.sha256!=self.pending_schedule_head[1]:
            raise AuthorityUnavailable("D13 actual pending schedule payload digest differs before Source")
        values=self.column.parser.frozen.values
        ns=self.namespace
        if ((values.get(("window","namespace","bot_id")),values.get(("window","namespace","persona_id")))!=ns.as_tuple
                or values.get(("window","conversation_ref"))!=self.authority.audience[0]
                or values.get(("plan","job_ref"))!=self.pending_schedule_head[0]):
            raise AuthorityUnavailable("D13 pending schedule metadata crossed its actual scene/job/audience")
        key=AtomKey.from_token(values[("window","scene_ref","ref")])
        if NamespaceId.from_key(key)!=ns or key.owner.kind!="scene" or key.owner.subject!=self.scene_ref:
            raise AuthorityUnavailable("D13 pending schedule frozen scene differs")
        for path,ref in values.items():
            if path[-1:]!=("ref",):continue
            revision=values.get((*path[:-1],"version"))
            if type(ref)is not str or type(revision)is not int or revision<0:
                raise AuthorityUnavailable("D13 pending frozen metadata lacks exact ref/version")
            if ref in self.frozen_versions and self.frozen_versions[ref]!=revision:
                raise AuthorityUnavailable("D13 pending frozen duplicate versions differ")
            self.frozen_versions[ref]=revision
        roots=tuple(ref for ref in self.frozen_versions if AtomKey.from_token(ref).type_name=="memory.source")
        if not roots or (values[("window","access_epoch")],values[("window","delete_epoch")])!=self.epochs:
            raise AuthorityUnavailable("D13 pending schedule actual Source/rights closure differs")
        self.original_deadline=min(self.deadline,values[("plan","expires_at_utc")])
        self.pending_schedule_sha=self.column.sha256;self.column=None
        self.pending_sources=list(roots);self.phase="window_metadata"

    def _sources(self,meter):
        from ..domains.d06 import source_correction_head_key
        ns=self.namespace
        if self.column is not None:
            self.column.advance(meter)
            if not self.column.complete:return
            ref=self.pending_sources[-1];key=AtomKey.from_token(ref);head=self.source_heads[ref]
            source=_SourceLeafV3(key,head[0],bool(head[1]),self.column.value)
            if source.metadata["source_id"]!=key.owner.subject:
                raise AuthorityUnavailable("D13 actual Source metadata identity differs")
            self.sources[ref]=source
            akey=access_key(*ns.as_tuple,key.owner.subject);ahead=self.source_heads[akey.token]
            self.column=_ColumnV3(self,table="graph_atoms",column="value",
                key_columns=("token",),key=(akey.token,),cell_id=ahead[2],access=True)
            self.phase="access";return
        if self.pending_sources:
            ref=self.pending_sources[-1]
            if ref in self.sources:self.pending_sources.pop();return
            if len(self.sources)>=256:raise AuthorityUnavailable("D13 original Source ancestry exceeds bounded closure")
            key=AtomKey.from_token(ref)
            if key!=source_key(*ns.as_tuple,key.owner.subject or ""):
                raise AuthorityUnavailable("D13 paid original requires canonical Source refs")
            akey=access_key(*ns.as_tuple,key.owner.subject)
            correction=source_correction_head_key(ns,key.owner.subject)
            for exact in (key,akey,correction):
                self.source_heads[exact.token]=meter.read_fixed_row(self.db,"graph_atoms",
                    ("revision","valid","value_cell_id"),"token=? AND bot=? AND persona=?",(exact.token,*ns.as_tuple))
            head,ahead=self.source_heads[ref],self.source_heads[akey.token]
            if head is None or head[1]!=1 or ahead is None or ahead[1]!=1 or self.source_heads[correction.token] is not None:
                raise AuthorityUnavailable("D13 current Source/access/correction is unavailable")
            for exact,actual in ((ref,head[0]),(akey.token,ahead[0])):
                if exact in self.frozen_versions and self.frozen_versions[exact]!=actual:
                    raise AuthorityUnavailable("D13 current Source/access differs from its exact frozen version")
            self.column=_ColumnV3(self,table="graph_atoms",column="value",key_columns=("token",),key=(ref,),
                cell_id=head[2],source=True)
            return
        active,done=set(),set()
        def visit(ref):
            if ref in active:raise AuthorityUnavailable("D13 actual Source ancestry is cyclic")
            if ref in done:return
            active.add(ref)
            for parent in self.sources[ref].metadata["parent_source_ids"]:visit(source_key(*ns.as_tuple,parent).token)
            active.remove(ref);done.add(ref)
        for ref in self.sources:visit(ref)
        self.qualified,self.phase=True,"originals"
    def _access(self,meter):
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        self.column.advance(meter)
        if not self.column.complete:return
        token=self.column.key[0];head=self.source_heads[token]
        access=GraphAtom(AtomKey.from_token(token),head[0],self.column.value,bool(head[1]))
        ref=self.pending_sources[-1];source=self.sources[ref]
        record=_qualify_source_rights_values_v3(self.namespace,ref,source,access,None,
            audience=self.authority.audience[0],purpose="context",metadata_only=True)
        if record is None:raise AuthorityUnavailable("D13 Source purpose/audience/assertion is unavailable")
        self.access_atoms[token]=access
        self.pending_sources.pop();self.column=None;self.phase="sources"
        self.pending_sources.extend(source_key(*self.namespace.as_tuple,parent).token for parent in record.parent_source_ids
            if source_key(*self.namespace.as_tuple,parent).token not in self.sources)
        self.reserve_v3()
    def _originals(self,meter):
        if not self.qualified:raise AuthorityUnavailable("D13 paid body requires all current Source ancestors")
        if self.job_id is None:
            if self.pending_schedule_head is not None:
                if self.column is None:
                    self.column=_ColumnV3(self,table="graph_d13_paid_schedule_inputs_v1",column="payload_json",
                        key_columns=("bot","persona","job_ref"),
                        key=(*self.namespace.as_tuple,self.pending_schedule_head[0]))
                    return
                self.column.advance(meter)
                if not self.column.complete:return
                if self.column.sha256!=self.pending_schedule_sha:
                    raise AuthorityUnavailable("D13 pending schedule protected EOF changed its metadata")
                self.rows["graph_d13_paid_schedule_inputs_v1"]=(self.column.value,self.pending_schedule_head[1])
                self.body_columns["graph_d13_paid_schedule_inputs_v1"]=self.column;self.column=None
            self.phase="window_body";return
        if self.column is not None:
            self.column.advance(meter)
            if not self.column.complete:return
            table,columns,json_name=self.pending_table
            small=dict(zip(tuple(name for name in columns if name!=json_name),self.pending_header))
            if table==_TABLES[0][0] and self.column.sha256!=self.intent_metadata_sha:
                raise AuthorityUnavailable("D13 full original EOF changed its actual frozen metadata")
            self.rows[table]=tuple(self.column.value if name==json_name else small[name] for name in columns)
            self.body_columns[table]=self.column;self.column=None;self.table_index+=1;return
        if self.table_index==len(_TABLES):
            self.phase="paid_cost";return
        table,columns,json_name=_TABLES[self.table_index]
        small_columns=tuple(name for name in columns if name!=json_name)
        row=meter.read_fixed_row(self.db,table,small_columns,"bot=? AND persona=? AND job_ref=?",
            (*self.namespace.as_tuple,self.job_id))
        self.row_headers[table]=row
        if row is None:self.rows[table]=None;self.table_index+=1;return
        self.pending_table,self.pending_header=(table,columns,json_name),tuple(row)
        self.column=_ColumnV3(self,table=table,column=json_name,key_columns=("bot","persona","job_ref"),
            key=(*self.namespace.as_tuple,self.job_id))
    def _paid_cost(self,meter):
        row=self.rows[_TABLES[3][0]]
        if row is None:self.phase="window_body";return
        token=json.loads(row[0])["cost_write"]["key"]
        key=AtomKey.from_token(token)
        if NamespaceId.from_key(key)!=self.namespace or key.type_name!="runtime.cost_settlement":
            raise AuthorityUnavailable("D13 paid original cost graph selector differs")
        head=meter.read_fixed_row(self.db,"graph_atoms",("revision","valid","value_cell_id"),"token=?",(token,))
        if head is None or head[1]!=1:raise AuthorityUnavailable("D13 actual settled cost graph head is unavailable")
        if self.paid_cost_head is None:
            self.paid_cost_head=tuple(head)
            self.column=_ColumnV3(self,table="graph_atoms",column="value",key_columns=("token",),key=(token,),cell_id=head[2])
            return
        if tuple(head)!=self.paid_cost_head:raise AuthorityUnavailable("D13 settled cost graph changed before EOF")
        self.column.advance(meter)
        if not self.column.complete:return
        self.paid_cost_atom=GraphAtom(key,head[0],json.loads(self.column.value),True)
        self.column=None;self.phase="window_body"

    def window_atom_v3(self,key):
        self.require_current_v3()
        if not self.qualified or self.window_body is None:
            raise AuthorityUnavailable("D13 window body requires every actual Source ancestor first")
        return self.window_body.atom_v3(key)

    def window_family_v3(self,type_id):
        self.require_current_v3()
        if not self.qualified or self.window_body is None:
            raise AuthorityUnavailable("D13 window family requires its actual qualified metadata coverage")
        return self.window_body.family_v3(type_id)

    def window_original_point_v3(self,table,columns,key_columns,key):
        self.require_current_v3()
        if not self.qualified or self.window_body is None:
            raise AuthorityUnavailable("D13 window original requires its actual qualified same Work")
        return self.window_body.original_point_v3(table,columns,key_columns,key)

    def _window_metadata(self,meter):
        from .d13_current_window import begin_d13_paid_window_metadata_v3
        policy=self.window_policy
        if self.window_metadata is None:
            self.window_metadata=begin_d13_paid_window_metadata_v3(self,self.scene_ref,self.args.get("max_slots",policy.max_slots))
        self.window_metadata.advance_v3(meter)
        if not self.window_metadata.complete:return
        refs=self.window_metadata.refroots
        self.original_deadline=min(self.original_deadline or self.deadline,self.window_metadata.expires_at_utc)
        for ref,revision in self.window_metadata.source_versions:
            if ref in self.frozen_versions and self.frozen_versions[ref]!=revision:
                raise AuthorityUnavailable("D13 frozen/current window Source metadata versions differ")
            self.frozen_versions[ref]=revision
        self.pending_sources=list(sorted(set((*self.pending_sources,*refs))))
        self.phase="sources"

    def _window_body(self,meter):
        from .d13_current_window import begin_d13_paid_window_body_v3
        if self.window_body is None:
            self.window_body=begin_d13_paid_window_body_v3(self,self.window_metadata)
        self.window_body.advance_v3(meter)
        if not self.window_body.complete:return
        self.current_window=self.window_body.window
        if self.completed_read is not None:
            self.phase="completed_body"
        else:
            self.complete=True;self.proof=PreparedD13PaidOriginalReadV3(_ISSUER,self)

    def advance_v3(self,meter):
        if self.epochs is None:
            self.epochs=meter.read_fixed_row(self.db,"graph_authority_epochs",("access_epoch","delete_epoch"),
                "bot=? AND persona=?",self.namespace.as_tuple)
            self.owner_head=meter.read_fixed_row(self.db,"graph_atoms",("revision","valid","value_cell_id"),
                "token=?",(owner_grant_key(*self.namespace.as_tuple).token,))
        if self.phase=="metadata":self._metadata(meter)
        elif self.phase=="intent_digest":
            self.intent_digest_task.advance_v3(meter)
            if self.intent_digest_task.complete:self._seal_authenticated_intent_metadata_v3()
        elif self.phase=="sources":self._sources(meter)
        elif self.phase=="access":self._access(meter)
        elif self.phase=="originals":self._originals(meter)
        elif self.phase=="window_metadata":self._window_metadata(meter)
        elif self.phase=="window_body":self._window_body(meter)
        elif self.phase=="paid_cost":self._paid_cost(meter)
        elif self.phase=="completed_metadata":
            self.completed_read.metadata_advance_v3(meter)
            if self.completed_read.metadata_complete:self.phase="window_metadata"
        elif self.phase in {"completed_body","completed_verify"}:
            token=_READING.set(self)
            try:
                if self.phase=="completed_body":self.completed_read.body_advance_v3(meter)
                else:self.completed_read.verify_v3()
            finally:_READING.reset(token)
        else:raise AuthorityUnavailable("D13 paid reader has another actual phase")
        self.reserve_v3()


class PreparedD13PaidOriginalReadV3:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or not reader.complete or not reader.qualified:
            raise AuthorityUnavailable("actual D13 paid all-Source and protected original EOF required")
        self.reader=reader
        _PROOFS[self]=(reader,reader.work,reader.operation,reader.fence.scope,reader.job_id,
            reader.method,reader.selection_digest,tuple(sorted(reader.source_heads.items())),
            tuple(sorted(reader.frozen_versions.items())),reader.intent_metadata_sha)
    def require_current_v3(self,db=None):
        r=self.reader
        if (_PROOFS.get(self)!=(r,r.work,r.operation,r.fence.scope,r.job_id,r.method,r.selection_digest,
                tuple(sorted(r.source_heads.items())),tuple(sorted(r.frozen_versions.items())),r.intent_metadata_sha)
                or db is not None and db is not r.db):
            raise AuthorityUnavailable("D13 paid original EOF proof crossed its actual private caller")
        if not r.db.in_transaction:r.refresh_scope_clock_v3()
        r.require_current_v3()
        with runtime_storage_quantum_v3(r.db) as meter:
            for token,head in r.source_heads.items():
                if meter.read_fixed_row(r.db,"graph_atoms",("revision","valid","value_cell_id"),"token=?",(token,))!=head:
                    raise AuthorityUnavailable("D13 Source/access/correction changed after actual EOF")
        return r
    def release_payload_v3(self):
        _PROOFS.pop(self,None)
        r=self.reader;_READERS.discard(r)
        r.rows.clear();r.body_columns.clear();r.sources.clear();r.source_heads.clear();r.access_atoms.clear()
        r.column=r.intent_metadata=r.frozen_metadata=r.intent_digest_task=r.intent_projection=r.proof=None
        r.completed_read=None


@contextmanager
def bind_prepared_d13_paid_original_v3(proof):
    if type(proof) is not PreparedD13PaidOriginalReadV3:
        raise AuthorityUnavailable("actual issued D13 paid original proof required")
    proof.require_current_v3()
    token=_BOUND.set(proof)
    try:yield proof
    finally:_BOUND.reset(token)


def d13_paid_current_reader_v3(db):
    proof=_BOUND.get()
    if proof is not None:return proof.require_current_v3(db)
    reader=_READING.get()
    if reader is None:return None
    if reader.db is not db or not reader.qualified or reader.phase not in {"window_body","completed_body","completed_verify"}:
        raise AuthorityUnavailable("D13 current window binder crossed its qualified actual Work")
    return reader.require_current_v3()


def d13_paid_original_point_v3(db,*,table,columns,key_columns,key):
    r=d13_paid_current_reader_v3(db)
    if r is None:return False,None
    if table=="graph_d13_paid_schedule_inputs_v1":
        if (tuple(columns)!=("payload_json","payload_digest") or tuple(key_columns)!=("bot","persona","scene_ref")
                or tuple(key)!=(*r.namespace.as_tuple,r.scene_ref)):
            raise AuthorityUnavailable("D13 pending schedule crossed its actual original scene")
        return True,r.rows.get(table)
    item=next((item for item in _TABLES if item[0]==table),None)
    if (item is None or tuple(key_columns)!=("bot","persona","job_ref")
            or tuple(key)!=(*r.namespace.as_tuple,r.job_id) or not set(columns)<=set(item[1])):
        raise AuthorityUnavailable("D13 paid original selector escaped its actual immutable job family")
    row=r.rows[table]
    if row is None:return True,None
    values=dict(zip(item[1],row))
    return True,tuple(values[name] for name in columns)


def prepare_d13_paid_original_read_v3(graph,authority,lease,*,job_id,method,args):
    from .d13_paid_product_v1 import _authorize
    from .first_ingress_v2 import trusted_upper
    require_graph_storage_work_admission_v3(graph)
    if method=="read_current_d13_conversation_window_v1":
        graph._authorize(lease,authority,frozenset({"d11"}))
        store,port=graph._GraphCoordinator__store,graph._GraphCoordinator__content_fence_v2
        policy=graph._GraphCoordinator__d13_precompression_policy or graph._GraphCoordinator__d13_paid_precompression_policy
        if (policy is None or authority.namespace!=policy.namespace or authority.issuer_domain!="d11"
                or authority.purpose!="context" or authority.worker_fence is not None or len(authority.audience)!=1):
            raise AuthorityUnavailable("D13 current window requires its installed original technical scope")
    else:store,port,policy,_,_=_authorize(graph,authority,lease)
    if method not in _OPERATIONS or (job_id is not None and args.get("job_id")!=job_id):
        raise AuthorityUnavailable("D13 paid READ requires its exact registered original private caller")
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation=begin_runtime_storage_operation_v3(store._db,"d13-paid-read:"+secrets.token_hex(24),
        now+policy.deadline_after_seconds)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,store._db):
            fence=graph._begin_read_fence_v3(authority,operation_id=operation.operation_id,
                fence_observer=lambda scope: observe_d13_paid_owner_guard_v3(graph,authority,scope))
            reader=D13PaidOriginalReadWorkV3(_ISSUER,graph,authority,lease,operation,fence,job_id,method,args,now)
        work=create_graph_storage_work_v3(graph,kind=KIND,operation_id=operation.operation_id,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,
            state=reader,operation=operation)
        reader.work=work
        def completed(proof):
            with bind_runtime_storage_operation_v3(operation,store._db),bind_prepared_d13_paid_original_v3(proof):
                return getattr(graph,method)(authority,lease,**args)
        return work.map_terminal_v3("issuer",completed,lambda error:(_ for _ in ()).throw(error))
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise


def advance_d13_paid_original_read_v3(graph,work):
    r=work.state
    with bind_runtime_storage_operation_v3(work.operation,r.db):
        r.refresh_scope_clock_v3()
        with r.store._lock:
            r.require_current_v3()
            r.db.execute("BEGIN")
            try:
                with runtime_storage_quantum_v3(r.db) as meter:r.advance_v3(meter)
            finally:r.db.rollback()
            r.require_current_v3()
        r.refresh_scope_clock_v3()
        if r.phase=="completed_fact":
            r.completed_read.observe_terminal_v3()
            r.refresh_scope_clock_v3()
    return GraphStorageStepV3("complete",r.proof) if r.complete else GraphStorageStepV3("progress")


def finish_d13_paid_original_read_v3(graph,work,error):
    r=work.state
    try:
        graph._finish_read_fence_v3(r.fence);r.read_finished=True
        if error is None:work.result_lease=work.operation
    finally:
        if error is not None or work.result_lease is None:
            if r.proof is not None:r.proof.release_payload_v3()
            _READERS.discard(r);finish_runtime_storage_operation_v3(work.operation)


@contextmanager
def bind_d13_paid_window_reader_v3(reader):
    from ..authority_service.d13_authority_model_source_v3 import require_d13_authority_window_reader_v3
    authority=require_d13_authority_window_reader_v3(reader)
    if not authority and (type(reader)is not D13PaidOriginalReadWorkV3 or reader not in _READERS
            or not reader.qualified or reader.phase!="window_body" or reader.window_body is None):
        raise AuthorityUnavailable("D13 window preparation needs its actual all-Source gated Work")
    reader.require_current_v3()
    token=_READING.set(reader)
    try:yield reader
    finally:_READING.reset(token)


def begin_d13_paid_original_reader_in_work_v3(parent,*,job_id,method,args):
    from .d13_standby_read_v3 import _StandbyReadV3
    if (type(parent)is not _StandbyReadV3 or parent.work.state is not parent
            or parent.work.kind!="d13_standby_read_v3" or parent.work.operation is not parent.operation
            or parent.phase!="paid" or not parent.ledger_eof or parent.paid_original_read is not None
            or method!="schedule_d13_paid_precompression_v1" or args!={"scene_ref":parent.scene_ref}):
        raise AuthorityUnavailable("D13 scheduled original must join its actual same standby Work")
    if (parent.operation.closed or parent.fence.scope.operation!="read"
            or parent.fence.scope.namespace!=parent.authority.namespace
            or parent.work.selection_digest!=parent.operation.selection_digest):
        raise AuthorityUnavailable("D13 inline original metadata lost its actual READ Work")
    now=parent.now_utc
    reader=D13PaidOriginalReadWorkV3(_ISSUER,parent.graph,parent.authority,parent.lease,parent.operation,
        parent.fence,job_id,method,args,now)
    reader.parent,parent.paid_original_read=parent,reader
    reader.work=parent.work
    return reader


def observe_d13_paid_owner_guard_v3(graph,authority,scope):
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    port=graph._GraphCoordinator__content_fence_v2
    observed=port.get_current_owner_guard_for_fence(namespace=authority.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit)
    installation=port.installation_grant
    if (type(observed)is not tuple or len(observed)!=2 or type(observed[0])is not OwnerAuthorizationGuardV1
            or observed[1]!=scope.permit):
        raise AuthorityUnavailable("D13 actual current Owner guard/permit differs")
    guard=observed[0]
    if (guard.namespace!=authority.namespace or guard.authority_id!=installation.authority_id
            or guard.installation_id!=installation.installation_id or guard.authorization_revision!=1
            or guard.pending_revoke_operation_id is not None or guard.minimum_revocation_revision!=0
            or guard.minimum_revocation_epoch!=0):
        raise AuthorityUnavailable("D13 original Owner authorization is unavailable")
    return guard


def require_d13_paid_original_write_clock_v3(graph,scope,clock):
    proof=_BOUND.get()
    if proof is None:return
    r=proof.reader
    if (graph is not r.graph or scope.operation!="write" or scope.namespace!=r.namespace
            or not (r.read_finished or r.parent is not None and r.parent.read_finished)
            or graph._GraphCoordinator__content_fence_v2.validate_fence(scope)!=scope.permit):
        raise AuthorityUnavailable("D13 cached current facts require their actual fresh business WRITE")
    from .first_ingress_v2 import trusted_upper
    r.now_utc=trusted_upper(clock)
    proof.require_current_v3(r.db)


class _IntentDigestMetadataV3:
    """Replay exact outer ranges with the original typed canonical hash algorithm."""
    def __init__(self,reader,column):
        self.reader,self.column=reader,column
        parser=column.parser
        self.hash=sha256();self.actions=[];self.index=self.offset=0;self.complete=False
        def literal(raw):self.actions.append(("literal",raw))
        names=sorted((parser.expected-{"original_digest"})|{"schema"})
        literal(b"{")
        from ..runtime_contracts import canonical_serialize
        for index,name in enumerate(names):
            literal((b"," if index else b"")+canonical_serialize(name).encode("ascii")+b":")
            if name=="schema":
                literal(b'"d13.paid_intent_original.v1"')
                continue
            start,end=parser.ranges[(name,)]
            typed=parser.typed_offsets.get((name,))
            if typed is None:self.actions.append(("range",start,end))
            else:
                offset,cls=typed
                self.actions.append(("range",start,offset))
                literal(b'"$type":'+canonical_serialize(cls.__module__+"."+cls.__qualname__).encode("ascii")+b",")
                self.actions.append(("range",offset,end))
        literal(b"}")
        reader.reserve_v3(_heap(self.actions)+65536)
    def advance_v3(self,meter):
        r=self.reader;r.require_current_v3(meter=meter)
        if self.index==len(self.actions):
            if self.hash.hexdigest()!=r.intent_head[1]:
                raise AuthorityUnavailable("D13 signed original typed canonical digest differs before Source")
            from .d11_types import runtime_job_key
            token=runtime_job_key(*r.namespace.as_tuple,r.job[2],r.job_id).token
            history=meter.read_fixed_row(r.db,"graph_history",("event_id","valid"),
                "token=? AND revision=1",(token,))
            committed=meter.read_fixed_row(r.db,"graph_bundle_operations",("commit_seq",),
                "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,r.job[1]))
            if history!=(r.job[1],1) or committed is None or committed[0]<1:
                raise AuthorityUnavailable("D13 metadata original lacks its actual committed queued job")
            self.complete=True
            return
        action=self.actions[self.index]
        if action[0]=="literal":
            raw=action[1];meter.charge_encode(len(raw));self.hash.update(raw);self.index+=1;return
        start,end=action[1:]
        if start+self.offset==end:
            self.offset=0;self.index+=1;return
        size=min(8192,end-start-self.offset)
        raw,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table=self.column.table,column=self.column.column,
            where=self.column.where,parameters=self.column.key,start=start+self.offset,length=size,meter=meter)
        if (total,kind)!=(self.column.total,"text"):
            raise AuthorityUnavailable("D13 typed canonical metadata range lost its actual original TEXT")
        r.reserve_v3(len(raw)*2+65536);meter.charge_encode(len(raw))
        self.hash.update(raw);self.offset+=len(raw)
