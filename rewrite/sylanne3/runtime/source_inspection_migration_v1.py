"""Bounded legacy Source inspection maintenance on the selected production Graph.

The only Body opener is an actual issued paused-Owner scope. Persistent Graph
originals, metadata output, event receipt and cursor publish in one transaction.
"""
import codecs
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from uuid import uuid5, UUID

from ..authority_service.contract import AuthorityUnavailable
from ..contracts import canonical_json
from ..domains.d06.inspection_metadata_v1 import (
    SOURCE_TYPE, INTERPRETATION_TYPE, inspection_key_v1, validate_inspection_metadata_v1)
from ..graph_types import AtomKey
from ..memory_types import source_key, access_key
from ..runtime_contracts import canonical_digest
from ..runtime_storage_v3 import (
    install_selected_runtime_storage_v3, begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3,
    runtime_storage_quantum_v3, begin_runtime_cell_read_v3,
    seal_runtime_cell_in_transaction_v3, _runtime_bounded_fixed_row_v3)
from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3, C09MemoryAccessJSONStreamV3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .source_correction_read_v3 import _heap

SESSION = "d06.source-inspection-migration.v1"
OPERATIONS = "graph_source_inspection_migrations_v1"
MEMBERS = "graph_source_inspection_migration_members_v1"
DDL = {
    OPERATIONS: f"CREATE TABLE {OPERATIONS}(bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,request_digest TEXT NOT NULL,request_json TEXT NOT NULL,owner_head TEXT NOT NULL,requirements_json TEXT NOT NULL,expected_graph_revision INTEGER NOT NULL,expected_graph_epoch INTEGER NOT NULL,cursor TEXT NOT NULL,batch_index INTEGER NOT NULL,migrated INTEGER NOT NULL,retired INTEGER NOT NULL,state TEXT NOT NULL,last_receipt_json TEXT,accepted_digest TEXT NOT NULL,PRIMARY KEY(bot,persona,operation_id))",
    MEMBERS: f"CREATE TABLE {MEMBERS}(bot TEXT NOT NULL,persona TEXT NOT NULL,producer_operation_id TEXT NOT NULL,migration_operation_id TEXT NOT NULL,request_digest TEXT NOT NULL,batch_index INTEGER NOT NULL,target_token TEXT NOT NULL,target_revision INTEGER NOT NULL,metadata_token TEXT,outcome TEXT NOT NULL,event_digest TEXT NOT NULL,original_json TEXT NOT NULL,receipt_json TEXT NOT NULL,PRIMARY KEY(bot,persona,producer_operation_id),UNIQUE(bot,persona,migration_operation_id,batch_index))",
}
COLUMNS = {
    OPERATIONS: ("bot","persona","operation_id","request_digest","request_json","owner_head",
        "requirements_json","expected_graph_revision","expected_graph_epoch","cursor","batch_index",
        "migrated","retired","state","last_receipt_json","accepted_digest"),
    MEMBERS: ("bot","persona","producer_operation_id","migration_operation_id","request_digest","batch_index",
        "target_token","target_revision","metadata_token","outcome","event_digest","original_json","receipt_json"),
}


def validate_source_inspection_migration_schema_v1(db):
    present = set()
    for name, ddl in DDL.items():
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
        if row is not None:
            present.add(name)
            if row != (ddl,) or tuple(r[1] for r in db.execute("PRAGMA table_info("+name+")")) != COLUMNS[name]:
                raise AuthorityUnavailable("inspection maintenance registered Graph schema differs")
    if present and present != set(DDL):
        raise AuthorityUnavailable("inspection maintenance Graph family is incomplete")
    return bool(present)



def install_source_inspection_runtime_v1(db,*,control,context):
    """Two exact business provenance arms; no physical-maintenance fallback."""
    from ..authority_service.c09_initial_segmented_genesis_v4 import (
        INITIAL_MANIFEST_SCHEMA_V4,VerifiedInitialSegmentedStorageV4)
    from ..authority_service.c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
    from ..authority_service.c09_storage_control_v1 import VerifiedStorageOpenContextV1
    from ..runtime_storage_v3 import install_initial_runtime_storage_v4
    if type(context) is not VerifiedStorageOpenContextV1 or context._reader is not control:
        raise AuthorityUnavailable("inspection runtime needs its actual current business storage context")
    context.require_current("business")
    if context.manifest["schema"]==INITIAL_MANIFEST_SCHEMA_V4:
        initial=getattr(control,"_initial_segmented_storage_v4",None)
        if type(initial) is not VerifiedInitialSegmentedStorageV4 or initial.control is not control:
            raise AuthorityUnavailable("inspection READY initial storage requires its actual signed genesis proof")
        return install_initial_runtime_storage_v4(db,role="graph",initial=initial,context=context)
    selected=getattr(control,"_selected_history_read_v3",None)
    if type(selected) is not VerifiedSelectedHistoryReadV3 or selected.basis.control is not control:
        raise AuthorityUnavailable("inspection selected storage requires its actual selected-history proof")
    return install_selected_runtime_storage_v3(db,role="graph",selected=selected,context=context)


def _fixed(db,meter,table,columns,where,key):
    return _runtime_bounded_fixed_row_v3(db,meter,table,columns,where,key)


def _stamp(db,ns,meter):
    metadata = _fixed(db,meter,"graph_recovery_metadata_v2",("requirements_json","graph_revision"),
        "bot=? AND persona=?",ns.as_tuple)
    epoch = _fixed(db,meter,"graph_epochs",("revision",),"bot=? AND persona=?",ns.as_tuple)
    if metadata is None or epoch is None:
        raise AuthorityUnavailable("actual inspection migration Graph stamp is absent")
    return (*metadata,epoch[0])


def _head(db,ns,key,meter):
    return _fixed(db,meter,"graph_atoms",("revision","valid","value_cell_id"),
        "bot=? AND persona=? AND token=?",(*ns.as_tuple,key.token))


def _history(db,key,revision,meter):
    return _fixed(db,meter,"graph_history",("event_bot","event_persona","event_session","event_id","valid","value_cell_id"),
        "token=? AND revision=?",(key.token,revision))


class _InterpretationMetadataJSONV1(C09MemorySourceJSONStreamV3):
    """Full canonical claim semantics with no retained or returned claim string."""
    def _append_decoded_codepoint(self,codepoint):
        state=self._string
        if state is None or state["mode"]!="value" or state["path"]!=("claim",):
            return C09CanonicalJSONStreamV2._append_decoded_codepoint(self,codepoint)
        high=self._source_text_high
        if high is not None:
            self._source_text_high=None
            if 0xdc00<=codepoint<=0xdfff:
                self._source_character(0x10000+((high-0xd800)<<10)+codepoint-0xdc00)
                return
            self._source_character(high)
        if 0xd800<=codepoint<=0xdbff:
            self._source_text_high=codepoint
        else:
            self._source_character(codepoint)

    def _emit(self,emit,kind,path,start,end,**values):
        from ..memory_types import _INTERPRETATION_FIELDS
        if kind=="key":
            if len(path)!=1 or values["key"] not in _INTERPRETATION_FIELDS:
                raise ValueError("interpretation migration fields differ")
            self._source_fields.add(values["key"])
        elif kind=="object_start" and path:
            raise ValueError("interpretation field cannot be an object")
        elif kind=="array_start":
            if path!=("source_ids",):
                raise ValueError("interpretation array must be source_ids")
            self._source_metadata["source_ids"]=[]
        elif kind=="scalar_start":
            if (not path or len(path)>2 or path[0] not in _INTERPRETATION_FIELDS
                    or path==("source_ids",) or len(path)==2 and path[0]!="source_ids"):
                raise ValueError("interpretation scalar path differs")
            if path==("claim",):
                if values["scalar_kind"]!="string":
                    raise ValueError("interpretation claim must be a string")
            else:
                self._source_scalar=bytearray()
        elif kind=="scalar_chunk" and path!=("claim",):
            self._source_require_arena(len(values["raw"])*4+16384)
            self._source_scalar.extend(values["raw"])
        elif kind=="scalar_end":
            if path==("claim",):
                if self._source_text_high is not None:
                    self._source_character(self._source_text_high)
                    self._source_text_high=None
                if not self._source_text_nonempty:
                    raise ValueError("interpretation claim must be nonempty")
            else:
                self._source_require_arena(len(self._source_scalar)*4+16384)
                decoded=json.loads(self._source_scalar)
                self._source_decoded_bytes+=__import__("sys").getsizeof(decoded)
                if len(path)==1:
                    self._source_metadata[path[0]]=decoded
                else:
                    self._source_metadata["source_ids"].append(decoded)
                self._source_scalar=bytearray()
        C09CanonicalJSONStreamV2._emit(self,emit,kind,path,start,end,**values)

    def finish(self):
        from ..memory_types import _INTERPRETATION_FIELDS, _INTERPRETATION_STATUSES, _text, _string_tuple, _time, _enum
        result=C09CanonicalJSONStreamV2.finish(self)
        if self._source_fields!=_INTERPRETATION_FIELDS:
            raise ValueError("interpretation migration requires its complete registered fieldset")
        data=self._source_metadata
        _text(data["interpretation_id"],"interpretation_id")
        _text(data["subject_id"],"subject_id")
        _string_tuple(tuple(data["source_ids"]),"source_ids",require_one=True)
        _enum(data["status"],_INTERPRETATION_STATUSES,"interpretation status")
        for field in ("valid_from","recorded_at"):
            _time(data[field],field)
        _time(data["valid_to"],"valid_to",optional=True)
        if data["valid_to"] is not None and data["valid_to"]<data["valid_from"]:
            raise ValueError("interpretation valid_to precedes valid_from")
        return result


class _SourceEOFV1:
    def __init__(self,work,cell,*,access=False,interpretation=False):
        self.work,self.cell=work,cell
        if cell.header[0] not in {"canonical-json.ascii.v1","canonical-json.utf8.v1"}:
            raise AuthorityUnavailable("inspection maintenance requires its registered canonical codec")
        self.parser = (C09MemoryAccessJSONStreamV3 if access else _InterpretationMetadataJSONV1 if interpretation else C09MemorySourceJSONStreamV3)(
            ensure_ascii=cell.header[0]=="canonical-json.ascii.v1")
        self.semantic=sha256()
        self.decoder=codecs.getincrementaldecoder("utf8")("strict")
        self.fragment=b""
        self.offset=0

    def step_v1(self,meter):
        if self.offset < len(self.fragment):
            end=min(self.offset+1024,len(self.fragment))
            chunk=self.fragment[self.offset:end]
            self.parser.feed(chunk,lambda event:None)
            text=self.decoder.decode(chunk)
            ascii_json="".join(char if ord(char)<127 else json.dumps(char,ensure_ascii=True)[1:-1] for char in text)
            self.semantic.update(ascii_json.encode("ascii"))
            self.offset=end
            return False
        fragment=self.cell.read_fragment(meter=meter)
        if fragment is not None:
            self.fragment,self.offset=fragment,0
            return False
        result=self.parser.finish()
        digest=self.cell.finish(meter=meter)
        if (result.sha256,result.byte_count)!=(digest,self.cell.header[3]) or self.decoder.decode(b"",final=True):
            raise AuthorityUnavailable("inspection maintenance Source did not reach actual canonical semantic EOF")
        return True

    def _heap_v1(self):
        return _heap((self.fragment,self.parser.__dict__,self.parser._stack,self.parser._string))+8192


class SourceInspectionMigrationWorkV1:
    """One private service Work retains at most one selected cell's nontext state."""
    def __init__(self,scope):
        from ..authority_service.graph_catalogue_upgrade_v1 import require_no_pending_catalogue_upgrade_in_tx_v1
        scope.require_current_v1()
        require_no_pending_catalogue_upgrade_in_tx_v1(scope.service.lifecycle.core._db,
            scope.service.lifecycle.namespace)
        self.scope,self.namespace,self.service=scope,scope.namespace,scope.service
        self.work=self
        self.request_digest,self.operation_id=scope.request_digest,scope.operation_id
        path=next(m["resolved_path"] for m in scope.storage["members"] if m["role"]=="graph")
        self.db=sqlite3.connect(Path(path).as_uri()+"?mode=rw",uri=True,isolation_level=None)
        self.handle=self.operation=None
        try:
            self.db.execute("PRAGMA busy_timeout=1000")
            self.db.execute("PRAGMA synchronous=FULL")
            self.handle=install_source_inspection_runtime_v1(self.db,control=self.service.lifecycle.control,context=scope.context)
            self.operation=begin_runtime_storage_operation_v3(self.db,self.operation_id,scope.request["deadline_utc"])
            self.operation.register_retained_state_v3(self)
        except BaseException:
            self.db.close()
            raise
        self.phase="select"
        self.target=self.target_head=self.target_header=self.metadata_key=None
        self.access_head=self.access_key=self.access_metadata=None
        self.old_history=self.old_bundle=self.old_event=None
        self.column=self.eof=None
        self.existing_head=self.existing_proof=None
        self.original={}
        self._old_columns={}
        self.outcome=None

    def require_external_inspection_metadata_owner_v1(self):
        from ..runtime_storage_v3 import runtime_storage_v3
        if (self.service._active.get(self.operation_id) is not self or self.operation is None or self.operation.closed
                or self.db is None or self.db.in_transaction or self.service.lifecycle.core._db.in_transaction
                or self.work is not self or runtime_storage_v3(self.db) is not self.handle
                or self.operation.handle is not self.handle or self.operation.selection_digest!=self.handle.selection_digest
                or self.scope.request_digest!=self.request_digest or self.scope.operation_id!=self.operation_id):
            raise AuthorityUnavailable("actual external inspection metadata Work/selection required")
        self.scope.context.require_current("business")
        return self

    def require_current_inspection_metadata_owner_v1(self):
        from ..runtime_storage_v3 import runtime_storage_v3
        self.scope.require_current_v1()
        if (self.service._active.get(self.operation_id) is not self or self.work is not self
                or self.operation is None or self.operation.closed or self.operation.handle is not self.handle
                or runtime_storage_v3(self.db) is not self.handle
                or self.operation.selection_digest!=self.handle.selection_digest):
            raise AuthorityUnavailable("actual issued inspection metadata maintenance Work required")
        return self

    def _runtime_retained_heap_bytes_v3(self):
        return 32768+_heap((getattr(self,"original",{}),getattr(self,"target_header",None),
            getattr(self,"access_metadata",None)))+(0 if getattr(self,"eof",None) is None else self.eof._heap_v1())

    def _require_v1(self,scope):
        from ..authority_service.source_inspection_migration_v1 import require_issued_source_inspection_batch_v1
        require_issued_source_inspection_batch_v1(scope)
        if scope.service is not self.service or scope.operation_id!=self.operation_id or scope.request_digest!=self.request_digest:
            raise AuthorityUnavailable("inspection continuation changed its actual accepted scope")
        self.scope=scope

    def _operation_v1(self,meter):
        row=_fixed(self.db,meter,OPERATIONS,COLUMNS[OPERATIONS],
            "bot=? AND persona=? AND operation_id=?",(*self.namespace.as_tuple,self.operation_id))
        if row is None:
            stamp=_stamp(self.db,self.namespace,meter)
            row=(*self.namespace.as_tuple,self.operation_id,self.request_digest,canonical_json(self.scope.request),
                self.scope.owner_head,*stamp,"",0,0,0,"pending",None,self.scope.accepted_digest)
            self.db.execute(f"INSERT INTO {OPERATIONS} VALUES({','.join('?' for _ in row)})",row)
        if (row[3]!=self.request_digest or row[4]!=canonical_json(self.scope.request)
                or row[5]!=self.scope.owner_head or row[15]!=self.scope.accepted_digest or _stamp(self.db,self.namespace,meter)!=tuple(row[6:9])):
            raise AuthorityUnavailable("inspection continuation lost its accepted request/Owner/Graph receipt chain")
        return row

    def _start_column_v1(self,table,column,key_columns,key,cell_id=None):
        self.column=DispatchOriginalJSONReadV3(self,table=table,column=column,key_columns=key_columns,key=key,cell_id=cell_id)

    def _column_v1(self,meter):
        if not self.column.advance(meter):
            return False,None
        value=self.column.require_v3(self)
        if self.phase in {"old_reads","old_writes","old_invalidated"}:
            self._old_columns[self.phase]=self.column
        self.column=None
        return True,value

    def _select_v1(self,row,meter):
        request=self.scope.request
        if request["scope_kind"]=="exact_parent_closed_targets":
            next_ref=next((ref for ref in request["target_refs"] if ref>row[9]),None)
        else:
            target=_fixed(self.db,meter,"graph_atoms",("token",),
                "bot=? AND persona=? AND type_name IN ('memory.source','memory.interpretation') AND token>? ORDER BY token",
                (*self.namespace.as_tuple,row[9]))
            next_ref=None if target is None else target[0]
        if next_ref is None:
            return self._commit_v1(row,meter,completed=True)
        self.target=AtomKey.from_token(next_ref)
        self.target_head=_head(self.db,self.namespace,self.target,meter)
        if self.target_head is None:
            raise AuthorityUnavailable("explicit inspection target is unknown; HOLD")
        self.original["target_head"]=list(self.target_head)
        erased=self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_c09_erased_keys_v1'").fetchone()
        marker=None if not erased else _fixed(self.db,meter,"graph_c09_erased_keys_v1",("maintenance_generation","operation_id"),
                "bot=? AND persona=? AND key_digest=?",(*self.namespace.as_tuple,canonical_digest(next_ref)))
        self.original["erasure_marker"]=None if marker is None else list(marker)
        if marker is not None:
            self.outcome="erased"
            self.phase="commit"
        elif self.target_head[1]!=1:
            self.outcome="retired"
            self.phase="commit"
        elif self.target.type_name=="memory.interpretation":
            if self.scope.request["interpretation_status_discovery"] is not True:
                raise AuthorityUnavailable("legacy Interpretation requires explicit maintenance-only status discovery; HOLD")
            self._prepare_target_origin_v1(meter)
        else:
            from ..domains.d06 import source_correction_head_key
            correction=source_correction_head_key(self.namespace,self.target.owner.subject)
            correction_head=_head(self.db,self.namespace,correction,meter)
            self.original["correction_head"]=None if correction_head is None else list(correction_head)
            if correction_head is not None:
                self.outcome="retired_by_correction"
                self.phase="commit"
            else:
                self.access_key=access_key(*self.namespace.as_tuple,self.target.owner.subject)
                self.access_head=_head(self.db,self.namespace,self.access_key,meter)
                if self.access_head is None or self.access_head[1]!=1:
                    raise AuthorityUnavailable("legacy Source has no actual current Access metadata; HOLD")
                cell=begin_runtime_cell_read_v3(self.db,self.access_head[2],erasure_owner_ref=self.access_key.token)
                self.eof=_SourceEOFV1(self,cell,access=True)
                self.phase="access"
        return None

    def _prepare_target_origin_v1(self,meter):
        self.metadata_key=inspection_key_v1(self.target,self.target_head[0])
        self.existing_head=_head(self.db,self.namespace,self.metadata_key,meter)
        self.target_header=begin_runtime_cell_read_v3(self.db,self.target_head[2],erasure_owner_ref=self.target.token).header
        if self.existing_head is not None:
            from .source_inspection_metadata_read_v3 import InspectionMetadataReadV3
            self.existing_proof=InspectionMetadataReadV3(self,self.target)
            self.phase="existing_provenance"
            return
        self.old_history=_history(self.db,self.target,self.target_head[0],meter)
        if (self.old_history is None or self.old_history[:2]!=self.namespace.as_tuple
                or self.old_history[3]!=self.target_header[2] or self.old_history[4:]!=(1,self.target_head[2])):
            raise AuthorityUnavailable("legacy Source lost actual current producing history; HOLD")
        self.old_bundle=_fixed(self.db,meter,"graph_bundle_operations",
            ("digest","activity_id","effect_id","commit_seq"),
            "bot=? AND persona=? AND operation_id=?",(*self.namespace.as_tuple,self.old_history[3]))
        if self.old_bundle is None or self.old_bundle[1]!=self.old_history[2] or self.old_bundle[3]<1:
            raise AuthorityUnavailable("legacy Source lacks its actual old producing bundle receipt; HOLD")
        self.old_event=(*self.old_history[:2],self.old_history[2],self.old_history[3])
        event_header=_fixed(self.db,meter,"graph_events",("digest","epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?",self.old_event)
        if event_header is None or event_header[0]!=self.old_bundle[0]:
            raise AuthorityUnavailable("legacy Source event/bundle receipt digest differs; HOLD")
        self.original.update(target_head=list(self.target_head),target_header=list(self.target_header),
            target_history=list(self.old_history),old_bundle=list(self.old_bundle),old_event=list(event_header))
        if self.access_key is not None:
            self.original.update(access_ref=self.access_key.token,access_head=list(self.access_head),access_metadata=self.access_metadata)
        self._start_column_v1("graph_events","reads",("bot","persona","session","event_id"),self.old_event)
        self.phase="old_reads"

    def _step_v1(self,row,meter):
        if self.phase=="select":
            return self._select_v1(row,meter)
        if self.phase=="access":
            if self.eof.step_v1(meter):
                self.access_metadata=dict(self.eof.parser.metadata)
                self.eof=None
                self.original.update(access_ref=self.access_key.token,access_head=list(self.access_head),
                    access_metadata=self.access_metadata)
                if self.access_metadata["source_id"]!=self.target.owner.subject:
                    raise AuthorityUnavailable("inspection migration Access identity differs")
                if self.access_metadata["status"]!="active":
                    self.outcome="retired_access"
                    self.phase="commit"
                else:
                    self._prepare_target_origin_v1(meter)
            return None
        if self.phase in {"old_reads","old_writes","old_invalidated"}:
            done,value=self._column_v1(meter)
            if not done:
                return None
            if self.phase=="old_reads":
                if [self.target.token,self.target_head[0]-1] not in value:
                    raise AuthorityUnavailable("legacy producing event lacks actual target CAS read; HOLD")
                self.original["old_reads_commitment"]={"sha256":self._old_columns[self.phase].sha256,"bytes":self._old_columns[self.phase].byte_count}
                self._start_column_v1("graph_events","revisions",("bot","persona","session","event_id"),self.old_event)
                self.phase="old_writes"
            elif self.phase=="old_writes":
                if [self.target.token,self.target_head[0]] not in value:
                    raise AuthorityUnavailable("legacy producing event lacks actual target write; HOLD")
                self.original["old_writes_commitment"]={"sha256":self._old_columns[self.phase].sha256,"bytes":self._old_columns[self.phase].byte_count}
                self._start_column_v1("graph_events","invalidated",("bot","persona","session","event_id"),self.old_event)
                self.phase="old_invalidated"
            else:
                self.original["old_invalidated_commitment"]={"sha256":self._old_columns[self.phase].sha256,"bytes":self._old_columns[self.phase].byte_count}
                self.original["target_cas_read"]=[self.target.token,self.target_head[0]-1]
                self.original["target_write"]=[self.target.token,self.target_head[0]]
                self.eof=_SourceEOFV1(self,begin_runtime_cell_read_v3(self.db,self.target_head[2],erasure_owner_ref=self.target.token),
                    interpretation=self.target.type_name=="memory.interpretation")
                self.phase="source"
            return None
        if self.phase=="existing_provenance":
            if self.existing_proof.advance(meter):
                self.existing_proof.require_current_v3(meter)
                self.existing_proof.release_v3()
                self.existing_proof=None
                self.outcome="already_current"
                self.phase="commit"
            return None
        if self.phase=="source":
            if self.eof.step_v1(meter):
                metadata=dict(self.eof.parser._source_metadata)
                source=self.target.type_name=="memory.source"
                if metadata["source_id" if source else "interpretation_id"]!=self.target.owner.subject:
                    raise AuthorityUnavailable("legacy inspection metadata differs from canonical target identity")
                if not source:
                    metadata={name:metadata[name] for name in ("interpretation_id","status","source_ids")}
                for sid in metadata["parent_source_ids" if source else "source_ids"]:
                    parent=source_key(*self.namespace.as_tuple,sid)
                    if (self.scope.request["scope_kind"]=="exact_parent_closed_targets"
                            and parent.token not in self.scope.request["target_refs"]):
                        raise AuthorityUnavailable("Source parent leaves the explicitly accepted parent closure; HOLD")
                    parent_head=_head(self.db,self.namespace,parent,meter)
                    if parent_head is None or parent_head[1]!=1:
                        raise AuthorityUnavailable("Source parent is unknown/retired; HOLD")
                self.original["metadata"]=metadata
                self.original["semantic_digest"]=self.eof.semantic.hexdigest()
                self.eof=None
                self.outcome="migrated"
                self.phase="commit"
            return None
        if self.phase=="commit":
            return self._commit_v1(row,meter)
        raise AuthorityUnavailable("unknown inspection migration production phase")

    def require_target_producer_commit_header_v1(self):
        """A signature issuer consumes real completed column witnesses of this Work."""
        self.require_current_inspection_metadata_owner_v1()
        if self.phase!="commit" or self.outcome!="migrated" or set(self._old_columns)!={"old_reads","old_writes","old_invalidated"}:
            raise AuthorityUnavailable("member certificate needs actual completed old producer EOF")
        for phase in ("old_reads","old_writes","old_invalidated"):
            column=self._old_columns[phase]
            column.require_v3(self)
            if self.original[phase+"_commitment"]!={"sha256":column.sha256,"bytes":column.byte_count}:
                raise AuthorityUnavailable("old producer column certificate changed")
        return {name:self.original[name] for name in ("target_head","target_header","target_history",
            "old_bundle","old_event","old_reads_commitment","old_writes_commitment",
            "old_invalidated_commitment","target_cas_read","target_write")}

    def _commit_v1(self,row,meter,*,completed=False):
        self.scope.require_current_v1()
        if _stamp(self.db,self.namespace,meter)!=tuple(row[6:9]):
            raise AuthorityUnavailable("inspection output lost its exact before Graph stamp")
        if not completed and _head(self.db,self.namespace,self.target,meter)!=self.target_head:
            raise AuthorityUnavailable("inspection target changed before metadata publication")
        if self.outcome=="already_current" and _head(self.db,self.namespace,self.metadata_key,meter)!=self.existing_head:
            raise AuthorityUnavailable("verified current inspection metadata changed before classification")
        index=row[10]
        producer=str(uuid5(UUID(self.operation_id),"source-inspection-batch:"+str(index)))
        # UUID5 derives an exact internal producer identity from accepted UUID4;
        # the accepted public operation remains unchanged across continuation.
        reads=[] if completed else [[self.target.token,self.target_head[0]]]
        writes=[]
        value=None
        if self.outcome=="migrated":
            if ((self.access_key is not None and _head(self.db,self.namespace,self.access_key,meter)!=self.access_head)
                    or _head(self.db,self.namespace,self.metadata_key,meter) is not None):
                raise AuthorityUnavailable("inspection output Access/projection CAS changed")
            reads.append([self.metadata_key.token,0])
            if self.access_key is not None:
                reads.append([self.access_key.token,self.access_head[0]])
            value=dict(schema=SOURCE_TYPE if self.target.type_name=="memory.source" else INTERPRETATION_TYPE,target_ref=self.target.token,target_revision=self.target_head[0],
                target_codec=self.target_header[0],target_sha256=self.target_header[5],
                target_bytes=self.target_header[3],target_semantic_digest=self.original["semantic_digest"],
                producer_operation_id=producer,metadata=self.original["metadata"])
            validate_inspection_metadata_v1(value,source=self.target.type_name=="memory.source")
            writes=[[self.metadata_key.token,1]]
        after=[row[6],row[7]+1,row[8]+1]
        original=dict(schema="sylanne.source-inspection-migration-original.v1",
            migration_operation_id=self.operation_id,producer_operation_id=producer,
            request_digest=self.request_digest,accepted_digest=self.scope.accepted_digest,
            batch_index=index,
            before_stamp=list(row[6:9]),after_stamp=after,outcome="completed" if completed else self.outcome,
            target_ref=None if completed else self.target.token,target_revision=0 if completed else self.target_head[0],
            metadata_ref=None if value is None else self.metadata_key.token,reads=reads,writes=writes,
            target_original=self.original,admission=None)
        if self.outcome=="migrated":
            parents=[source_key(*self.namespace.as_tuple,sid).token for sid in
                self.original["metadata"]["parent_source_ids" if self.target.type_name=="memory.source" else "source_ids"]]
            original["admission"]=self.scope.sign_member_admission_v1(producer_operation_id=producer,
                target=self.target,target_head=self.target_head,target_header=self.target_header,
                metadata_key=self.metadata_key,parents=parents)
        event_digest=canonical_digest(original)
        if value is not None:
            encoded=canonical_json(value)
            cell=seal_runtime_cell_in_transaction_v3(self.db,
                locator=dict(table="graph_atoms",key=self.metadata_key.token,revision=1,column="value"),
                erasure_owner_ref=self.metadata_key.token,operation_id=producer,event_digest=event_digest,
                namespace=self.namespace.as_tuple,read_proof=dict(request_digest=self.request_digest,
                    accepted_operation_id=self.operation_id,reads=reads,before_stamp=list(row[6:9])),payload=encoded)
            key=self.metadata_key
            self.db.execute("INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,type_name,name,revision,value_cell_id,valid) VALUES(?,?,?,?,?,?,?,1,?,1)",
                (key.token,*self.namespace.as_tuple,key.owner.kind,key.owner.subject,key.type_name,key.name,cell))
            dependencies=canonical_json([[self.target.token,self.target_head[0]]])
            self.db.execute("INSERT INTO graph_history(token,revision,value_cell_id,valid,dependencies,event_bot,event_persona,event_session,event_id) VALUES(?,1,?,1,?,?,?,?,?)",
                (key.token,cell,dependencies,*self.namespace.as_tuple,SESSION,producer))
            self.db.execute("INSERT INTO graph_dependencies(dependent_token,dependency_token,dependency_revision) VALUES(?,?,?)",
                (key.token,self.target.token,self.target_head[0]))
        self.db.execute("INSERT INTO graph_events(bot,persona,session,event_id,digest,reads,epoch_reads,revisions,invalidated,epoch_revision) VALUES(?,?,?,?,?,?,?,?,'[]',?)",
            (*self.namespace.as_tuple,SESSION,producer,event_digest,canonical_json(reads),"[]",canonical_json(writes),after[2]))
        if self.db.execute("UPDATE graph_recovery_metadata_v2 SET graph_revision=? WHERE bot=? AND persona=? AND requirements_json=? AND graph_revision=?",
                (after[1],*self.namespace.as_tuple,row[6],row[7])).rowcount!=1:
            raise AuthorityUnavailable("inspection maintenance recovery stamp CAS changed")
        if self.db.execute("UPDATE graph_epochs SET revision=? WHERE bot=? AND persona=? AND revision=?",
                (after[2],*self.namespace.as_tuple,row[8])).rowcount!=1:
            raise AuthorityUnavailable("inspection maintenance Graph epoch CAS changed")
        receipt=dict(schema="sylanne.source-inspection-migration-receipt.v1",operation_id=self.operation_id,
            request_digest=self.request_digest,producer_operation_id=producer,batch_index=index,
            phase="completed" if completed else "pending",cursor=row[9] if completed else self.target.token,
            migrated=row[11]+int(self.outcome=="migrated"),retired=row[12]+int(not completed and self.outcome not in {"migrated","already_current"}),
            before_stamp=list(row[6:9]),after_stamp=after,event_digest=event_digest)
        encoded=canonical_json(receipt)
        member_receipt=dict(schema="sylanne.source-inspection-member-receipt.v1",
            operation_id=self.operation_id,request_digest=self.request_digest,accepted_digest=self.scope.accepted_digest,
            producer_operation_id=producer,batch_index=index,outcome=original["outcome"],
            before_stamp=list(row[6:9]),after_stamp=after,event_digest=event_digest)
        self.db.execute(f"INSERT INTO {MEMBERS} VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (*self.namespace.as_tuple,producer,self.operation_id,self.request_digest,index,
             "" if completed else self.target.token,0 if completed else self.target_head[0],
             None if value is None else self.metadata_key.token,original["outcome"],event_digest,
             canonical_json(original),canonical_json(member_receipt)))
        self.db.execute(f"UPDATE {OPERATIONS} SET expected_graph_revision=?,expected_graph_epoch=?,cursor=?,batch_index=batch_index+1,migrated=?,retired=?,state=?,last_receipt_json=? WHERE bot=? AND persona=? AND operation_id=? AND batch_index=?",
            (after[1],after[2],receipt["cursor"],receipt["migrated"],receipt["retired"],receipt["phase"],encoded,
             *self.namespace.as_tuple,self.operation_id,index))
        self.phase="finished"
        return receipt

    def _adopt_committed_receipt_v1(self,row,meter):
        receipt=json.loads(row[14])
        producer=str(uuid5(UUID(self.operation_id),"source-inspection-batch:"+str(row[10]-1)))
        member=_fixed(self.db,meter,MEMBERS,("migration_operation_id","request_digest","batch_index",
            "target_token","target_revision","metadata_token","outcome","event_digest","receipt_json"),
            "bot=? AND persona=? AND producer_operation_id=?",(*self.namespace.as_tuple,producer))
        if (canonical_json(receipt)!=row[14] or receipt["operation_id"]!=self.operation_id
                or receipt["request_digest"]!=self.request_digest or receipt["producer_operation_id"]!=producer
                or receipt["batch_index"]!=row[10]-1 or receipt["after_stamp"]!=list(row[6:9])
                or member is None or member[:3]!=(self.operation_id,self.request_digest,row[10]-1)
                or member[7]!=receipt["event_digest"]):
            raise AuthorityUnavailable("inspection crash-gap adoption lacks its actual committed member receipt")
        member_receipt=json.loads(member[8])
        if (canonical_json(member_receipt)!=member[8] or member_receipt["event_digest"]!=receipt["event_digest"]
                or member_receipt["accepted_digest"]!=row[15] or member_receipt["producer_operation_id"]!=producer
                or member_receipt["before_stamp"]!=receipt["before_stamp"] or member_receipt["after_stamp"]!=receipt["after_stamp"]):
            raise AuthorityUnavailable("inspection adopted independent member receipt differs")
        event=_fixed(self.db,meter,"graph_events",("digest","epoch_revision","reads","revisions"),
            "bot=? AND persona=? AND session=? AND event_id=?",(*self.namespace.as_tuple,SESSION,producer))
        if event is None or event[:2]!=(member[7],row[8]):
            raise AuthorityUnavailable("inspection crash-gap receipt lacks its actual committed Graph event")
        if member[6]=="migrated":
            target=AtomKey.from_token(member[3])
            metadata=AtomKey.from_token(member[5])
            target_head=_head(self.db,self.namespace,target,meter)
            metadata_head=_head(self.db,self.namespace,metadata,meter)
            if (target_head is None or target_head[:2]!=(member[4],1) or metadata_head is None
                    or metadata_head[:2]!=(1,1) or json.loads(event[3])!=[[metadata.token,1]]
                    or [target.token,member[4]] not in json.loads(event[2])
                    or [metadata.token,0] not in json.loads(event[2])
                    or begin_runtime_cell_read_v3(self.db,metadata_head[2],erasure_owner_ref=metadata.token).header[2]!=producer):
                raise AuthorityUnavailable("inspection crash-gap receipt does not bind its actual target/output CAS")
        elif json.loads(event[3])!=[]:
            raise AuthorityUnavailable("inspection classification receipt unexpectedly writes Graph metadata")
        return receipt

    def advance_v1(self,scope,previous):
        self._require_v1(scope)
        with bind_runtime_storage_operation_v3(self.operation,self.db):
            with runtime_storage_quantum_v3(self.db) as meter:
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    if not validate_source_inspection_migration_schema_v1(self.db):
                        for ddl in DDL.values():
                            self.db.execute(ddl)
                    row=self._operation_v1(meter)
                    # Adopt the independently committed actual Graph receipt after
                    # a Core crash gap, without reopening the prior Source cell.
                    adopted=0 if previous is None else previous.get("batch_index",-1)+1
                    if row[10] > adopted:
                        result=self._adopt_committed_receipt_v1(row,meter)
                    else:
                        result=self._step_v1(row,meter)
                        if result is None:
                            result=dict(schema="sylanne.source-inspection-migration-progress.v1",
                                operation_id=self.operation_id,request_digest=self.request_digest,
                                phase="pending",batch_index=row[10]-1,cursor=row[9],
                                migrated=row[11],retired=row[12],local_phase=self.phase)
                    self.operation.refresh_retained_state_v3(self)
                    self.db.execute("COMMIT")
                    return result
                except BaseException:
                    self.db.execute("ROLLBACK")
                    raise

    def close_v1(self):
        self.column=self.eof=None
        self._old_columns.clear()
        if self.existing_proof is not None:
            self.existing_proof.release_v3()
            self.existing_proof=None
        if self.operation is not None:
            finish_runtime_storage_operation_v3(self.operation)
            self.operation=None
        if self.handle is not None:
            self.handle.close()
            self.handle=None
        if self.db is not None:
            self.db.close()
            self.db=None


# This proof is consumed only by the explicit legacy-maintenance arm of the
# inspection kernel; an absent normal W01 producer never authorizes this arm.
_PROVENANCE_TASKS = __import__("weakref").WeakKeyDictionary()
_MEMBER_LOCATOR_COLUMNS = COLUMNS[MEMBERS][2:11]


def _require_provenance_owner_v1(owner,meter):
    if type(owner) is SourceInspectionMigrationWorkV1:
        owner.scope.require_current_v1()
        if (owner.service._active.get(owner.operation_id) is not owner or owner.operation.closed
                or owner.handle.db is not owner.db):
            raise AuthorityUnavailable("inspection provenance lost its actual private maintenance Work")
    else:
        from .source_inspection_metadata_read_v3 import _owner_v3
        _owner_v3(owner,meter)


def begin_source_inspection_migration_provenance_v1(owner, *, target, metadata_key,
        target_head, target_header, metadata_head, metadata_header, value, meter):
    _require_provenance_owner_v1(owner,meter)
    if not validate_source_inspection_migration_schema_v1(owner.db):
        return None
    row=_fixed(owner.db,meter,MEMBERS,_MEMBER_LOCATOR_COLUMNS,
        "bot=? AND persona=? AND producer_operation_id=?",
        (*owner.namespace.as_tuple,value["producer_operation_id"]))
    if row is None:
        return None
    return SourceInspectionMigrationProvenanceReadV1(owner,target,metadata_key,
        target_head,target_header,metadata_head,metadata_header,value,row)


class SourceInspectionMigrationProvenanceReadV1:
    def __init__(self,owner,target,metadata_key,target_head,target_header,metadata_head,metadata_header,value,row):
        self.owner,self.target,self.metadata_key=owner,target,metadata_key
        self.target_head,self.target_header=target_head,target_header
        self.metadata_head,self.metadata_header=metadata_head,metadata_header
        self.value,self.row=value,row
        self.phase="original"
        self.column=None
        self.original=self.receipt=self.authority_proof=None
        self.complete=False
        _PROVENANCE_TASKS[self]=(owner,owner.operation,target,metadata_key,row)
        owner.operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        return 16384+_heap((self.value,self.row,self.original,self.receipt))

    def require_member_admission_binding_v1(self,owner,admission):
        if (_PROVENANCE_TASKS.get(self)!=(owner,owner.operation,self.target,self.metadata_key,self.row)
                or owner is not self.owner or owner.operation.closed or self.original is None
                or self.original["admission"]!=admission
                or self.row[0]!=admission["producer_operation_id"]
                or self.row[1]!=admission["migration_operation_id"] or self.row[2]!=admission["request_digest"]):
            raise AuthorityUnavailable("member verification lost its original private task/Work binding")
        return self

    def pending_member_admission_v1(self,owner):
        if self.phase!="pending_authority" or self.authority_proof is not None:
            return None
        self.require_member_admission_binding_v1(owner,self.original["admission"])
        return self.original["admission"]

    def bind_authority_member_verification_v1(self,owner,proof):
        from .source_inspection_member_admission_v1 import require_verified_member_admission_v1
        admission=self.pending_member_admission_v1(owner)
        if admission is None:raise AuthorityUnavailable("member verification was not pending")
        require_verified_member_admission_v1(proof,owner=owner,task=self,admission=admission)
        self.authority_proof=proof

    def _actual_v1(self,meter):
        _require_provenance_owner_v1(self.owner,meter)
        if _PROVENANCE_TASKS.get(self)!=(self.owner,self.owner.operation,self.target,self.metadata_key,self.row):
            raise AuthorityUnavailable("inspection migration provenance lost its actual originating Work")
        actual=_fixed(self.owner.db,meter,MEMBERS,_MEMBER_LOCATOR_COLUMNS,
            "bot=? AND persona=? AND producer_operation_id=?",
            (*self.owner.namespace.as_tuple,self.value["producer_operation_id"]))
        if actual!=self.row:
            raise AuthorityUnavailable("inspection migration member changed after exact producer selection")
        return self.owner

    def _open_v1(self,table,column,key_columns,key):
        from .source_inspection_metadata_read_v3 import _InspectionColumnV3
        self.column=_InspectionColumnV3(self.owner,table=table,column=column,key_columns=key_columns,key=key)

    def _finish_v1(self,meter):
        if not self.column.advance(meter):return False,None
        value=self.column.value_v3(self.owner)
        self.column.release_v3();self.column=None
        return True,value

    def _validate_original_v1(self,meter):
        original,row=self.original,self.row
        if (set(original)!=_ORIGINAL_FIELDS or canonical_digest(original)!=row[8]
                or original["schema"]!="sylanne.source-inspection-migration-original.v1"
                or (original["producer_operation_id"],original["migration_operation_id"],
                    original["request_digest"],original["batch_index"],original["outcome"])!=
                    (row[0],row[1],row[2],row[3],"migrated")
                or (row[4],row[5],row[6],row[7])!=(self.target.token,self.target_head[0],self.metadata_key.token,"migrated")
                or original["target_ref"]!=self.target.token or original["target_revision"]!=self.target_head[0]
                or original["metadata_ref"]!=self.metadata_key.token):
            raise AuthorityUnavailable("inspection member differs from actual registered target/producer")
        admission=validate_member_admission_v1(original["admission"])
        old=original["target_original"]
        header=_target_commit_header_v1(old)
        if (admission["namespace"]!={"bot_id":self.owner.namespace.bot_id,"persona_id":self.owner.namespace.persona_id}
                or admission["producer_operation_id"]!=row[0] or admission["migration_operation_id"]!=row[1]
                or admission["request_digest"]!=row[2] or admission["accepted_digest"]!=original["accepted_digest"]
                or admission["target_ref"]!=self.target.token or admission["target_revision"]!=self.target_head[0]
                or admission["metadata_ref"]!=self.metadata_key.token
                or admission["target_header_digest"]!=canonical_digest(self.target_header)
                or admission["original_target_commit_header_digest"]!=canonical_digest(header)
                or old["target_head"]!=list(self.target_head) or old["target_header"]!=list(self.target_header)
                or old["metadata"]!=self.value["metadata"] or old["semantic_digest"]!=self.value["target_semantic_digest"]
                or self.metadata_header[2]!=row[0] or self.metadata_header[1]!=self.metadata_key.token
                or self.target_header[2]==row[0]):
            raise AuthorityUnavailable("independent signed member/current target commitments differ")
        parents=sorted(source_key(*self.owner.namespace.as_tuple,sid).token for sid in
            self.value["metadata"]["parent_source_ids" if self.target.type_name=="memory.source" else "source_ids"])
        if admission["parent_source_refs"]!=parents:
            raise AuthorityUnavailable("signed member dependencies differ from actual metadata")
        history=_history(self.owner.db,self.metadata_key,1,meter)
        event=_fixed(self.owner.db,meter,"graph_events",("digest","epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?",(*self.owner.namespace.as_tuple,SESSION,row[0]))
        if (history!=(*self.owner.namespace.as_tuple,SESSION,row[0],1,self.metadata_head[2])
                or event!=(row[8],original["after_stamp"][2])):
            raise AuthorityUnavailable("inspection member lacks actual new producing history/event")

    def advance(self,meter):
        self._actual_v1(meter)
        ns=self.owner.namespace.as_tuple
        if self.complete:
            self.require_current_v1(meter);return True
        if self.phase=="pending_authority":
            if self.authority_proof is None:return False
            from .source_inspection_member_admission_v1 import require_verified_member_admission_v1
            require_verified_member_admission_v1(self.authority_proof,owner=self.owner,task=self,
                admission=self.original["admission"])
            self._open_v1("graph_events","reads",("bot","persona","session","event_id"),(*ns,SESSION,self.row[0]))
            self.phase="new_reads"
        if self.column is None:
            self._open_v1(MEMBERS,"original_json",("bot","persona","producer_operation_id"),(*ns,self.row[0]))
        done,value=self._finish_v1(meter)
        if not done:return False
        if self.phase=="original":
            self.original=value
            self._validate_original_v1(meter)
            self._open_v1(MEMBERS,"receipt_json",("bot","persona","producer_operation_id"),(*ns,self.row[0]))
            self.phase="receipt"
        elif self.phase=="receipt":
            self.receipt=_validate_member_receipt_v1(value,self.original,self.row[8])
            self.phase="pending_authority"
        elif self.phase=="new_reads":
            if (value!=self.original["reads"] or [self.target.token,self.target_head[0]] not in value
                    or [self.metadata_key.token,0] not in value):
                raise AuthorityUnavailable("migration new event lost target-r/meta0 CAS")
            self._open_v1("graph_events","revisions",("bot","persona","session","event_id"),(*ns,SESSION,self.row[0]))
            self.phase="new_writes"
        elif self.phase=="new_writes":
            if value!=[[self.metadata_key.token,1]] or value!=self.original["writes"]:
                raise AuthorityUnavailable("migration new event rewrites target or unrelated Graph rows")
            self._open_v1("graph_events","invalidated",("bot","persona","session","event_id"),(*ns,SESSION,self.row[0]))
            self.phase="new_invalidated"
        elif self.phase=="new_invalidated":
            if value!=[]:raise AuthorityUnavailable("migration new event invalidates unrelated Graph rows")
            self._open_v1("graph_history","dependencies",("token","revision"),(self.metadata_key.token,1))
            self.phase="dependencies"
        else:
            if value!=[[self.target.token,self.target_head[0]]]:
                raise AuthorityUnavailable("migration metadata lost exact target-r dependency")
            self.complete=True
            self.require_current_v1(meter)
        self.owner.operation.refresh_retained_state_v3(self)
        return self.complete

    def require_current_v1(self,meter):
        self._actual_v1(meter)
        from .source_inspection_member_admission_v1 import require_verified_member_admission_v1
        if (not self.complete or _head(self.owner.db,self.owner.namespace,self.target,meter)!=self.target_head
                or _head(self.owner.db,self.owner.namespace,self.metadata_key,meter)!=self.metadata_head):
            raise AuthorityUnavailable("migration provenance lost actual current target/projection")
        require_verified_member_admission_v1(self.authority_proof,owner=self.owner,task=self,
            admission=self.original["admission"])
        return self

    def release_v1(self):
        if _PROVENANCE_TASKS.pop(self,None) is None:return
        if self.column is not None:self.column.release_v3();self.column=None
        self.owner.operation.unregister_retained_state_v3(self)
        self.original=self.receipt=self.value=self.authority_proof=None


_ORIGINAL_FIELDS=frozenset({"schema","migration_operation_id","producer_operation_id","request_digest","accepted_digest",
    "batch_index","before_stamp","after_stamp","outcome","target_ref","target_revision","metadata_ref","reads","writes",
    "target_original","admission"})
_OUTCOMES=frozenset({"migrated","already_current","retired","erased","retired_by_correction","retired_access","completed"})
_TARGET_COMMIT_FIELDS=("target_head","target_header","target_history","old_bundle","old_event",
    "old_reads_commitment","old_writes_commitment","old_invalidated_commitment","target_cas_read","target_write")
_MEMBER_RECEIPT_FIELDS=frozenset({"schema","operation_id","request_digest","accepted_digest","producer_operation_id",
    "batch_index","outcome","before_stamp","after_stamp","event_digest"})


def _target_commit_header_v1(old):
    from ..authority_service.source_inspection_migration_v1 import _sha_v1
    header={name:old[name] for name in _TARGET_COMMIT_FIELDS}
    for name in ("old_reads_commitment","old_writes_commitment","old_invalidated_commitment"):
        value=header[name]
        if type(value) is not dict or set(value)!={"sha256","bytes"} or type(value["bytes"]) is not int or value["bytes"]<2:
            raise AuthorityUnavailable("historical producer column commitment differs")
        _sha_v1(value["sha256"])
    target=header["target_header"][1]
    revision=header["target_head"][0]
    if (header["target_cas_read"]!=[target,revision-1] or header["target_write"]!=[target,revision]
            or header["target_history"][3]!=header["target_header"][2]
            or header["target_history"][4:]!=[1,header["target_head"][2]]
            or header["old_bundle"][0]!=header["old_event"][0]
            or header["old_bundle"][1]!=header["target_history"][2]
            or type(header["old_bundle"][3]) is not int or header["old_bundle"][3]<1):
        raise AuthorityUnavailable("historical target-only producer certificate differs")
    return header


def _validate_member_receipt_v1(receipt,original,event_digest):
    if (type(receipt) is not dict or set(receipt)!=_MEMBER_RECEIPT_FIELDS
            or receipt["schema"]!="sylanne.source-inspection-member-receipt.v1"
            or receipt["operation_id"]!=original["migration_operation_id"]
            or receipt["event_digest"]!=event_digest
            or any(receipt[name]!=original[name] for name in ("request_digest","accepted_digest","producer_operation_id",
                "batch_index","outcome","before_stamp","after_stamp"))
            or original["after_stamp"]!=[original["before_stamp"][0],original["before_stamp"][1]+1,original["before_stamp"][2]+1]):
        raise AuthorityUnavailable("independent inspection member receipt differs")
    return receipt


def validate_source_inspection_migration_row_v1(table,columns,row,*,authority_namespace):
    """Decode exact C09 rows; member validity never depends on retained OPS/scope."""
    from ..authority_service.source_inspection_migration_v1 import (
        decode_source_inspection_migration_request_v1,decode_source_inspection_migration_progress_v1,_sha_v1,_uuid_v1)
    from ..runtime_contracts import NamespaceId
    from ..graph_store import GraphStore
    if columns!=COLUMNS.get(table) or len(row)!=len(columns):
        raise AuthorityUnavailable("inspection Graph technical row columns differ")
    ns=NamespaceId(*row[:2])
    if table==OPERATIONS:
        request=decode_source_inspection_migration_request_v1(row[4],authority_namespace=authority_namespace)
        if (request["namespace"]!={"bot_id":ns.bot_id,"persona_id":ns.persona_id}
                or request["operation_id"]!=row[2] or canonical_digest(request)!=row[3] or row[13] not in {"pending","completed"}):
            raise AuthorityUnavailable("inspection Graph accepted operation differs")
        _sha_v1(row[5].removeprefix("sha256:"));_sha_v1(row[15])
        for index in (7,8,10,11,12):
            if type(row[index]) is not int or row[index]<0:raise AuthorityUnavailable("inspection cursor counter differs")
        GraphStore._decode_recovery(("sylanne3.authority.v2",row[6],row[7]),ns)
        refs=set(request["target_refs"])
        if row[9]:refs.add(row[9])
        receipt=None if row[14] is None else decode_source_inspection_migration_progress_v1(row[14],operation_id=row[2],request_digest=row[3])
        if ((row[10]==0)!=(receipt is None) or receipt is not None and (
                receipt["schema"]!="sylanne.source-inspection-migration-receipt.v1"
                or receipt["batch_index"]!=row[10]-1 or receipt["after_stamp"]!=list(row[6:9])
                or receipt["cursor"]!=row[9] or receipt["migrated"]!=row[11] or receipt["retired"]!=row[12]
                or receipt["phase"]!=row[13])):
            raise AuthorityUnavailable("inspection cursor has no actual last committed receipt")
        return dict(operation_id=row[2],state=row[13],request_digest=row[3],accepted_digest=row[15],
            request=request,receipt=receipt,graph_refs=tuple(sorted(refs)))
    _uuid_v1(row[3]);_sha_v1(row[4]);_sha_v1(row[10])
    if type(row[5]) is not int or row[5]<0 or row[9] not in _OUTCOMES:
        raise AuthorityUnavailable("inspection member batch/outcome differs")
    if row[2]!=str(uuid5(UUID(row[3]),"source-inspection-batch:"+str(row[5]))):
        raise AuthorityUnavailable("inspection member producer derivation differs")
    original=json.loads(row[11])
    if (type(original) is not dict or set(original)!=_ORIGINAL_FIELDS or canonical_json(original)!=row[11]
            or original["schema"]!="sylanne.source-inspection-migration-original.v1" or canonical_digest(original)!=row[10]
            or (original["migration_operation_id"],original["producer_operation_id"],original["request_digest"],
                original["batch_index"],original["outcome"])!=(row[3],row[2],row[4],row[5],row[9])):
        raise AuthorityUnavailable("inspection member closed original differs")
    _sha_v1(original["accepted_digest"])
    receipt=json.loads(row[12])
    if canonical_json(receipt)!=row[12]:raise AuthorityUnavailable("inspection member receipt is not canonical")
    _validate_member_receipt_v1(receipt,original,row[10])
    refs=set()
    admission=original["admission"]
    if row[9]=="completed":
        if (row[6:9]!=("",0,None) or original["target_ref"] is not None or original["target_revision"]!=0
                or original["metadata_ref"] is not None or original["reads"]!=[] or original["writes"]!=[]
                or original["target_original"]!={} or admission is not None):
            raise AuthorityUnavailable("inspection completion falsely carries member data")
    else:
        target=AtomKey.from_token(row[6]);refs.add(row[6])
        if ((target.owner.bot,target.owner.persona)!=ns.as_tuple or target.type_name not in {"memory.source","memory.interpretation"}
                or type(row[7]) is not int or row[7]<1 or original["target_ref"]!=row[6]
                or original["target_revision"]!=row[7] or [row[6],row[7]] not in original["reads"]):
            raise AuthorityUnavailable("inspection member target differs")
        old=original["target_original"]
        fields={"target_head","erasure_marker"}
        if target.type_name=="memory.source" and row[9] not in {"retired","erased"}:fields.add("correction_head")
        if row[9] in {"migrated","already_current","retired_access"} and target.type_name=="memory.source":
            fields|={"access_ref","access_head","access_metadata"};refs.add(old["access_ref"])
        if row[9]=="already_current":fields.add("target_header")
        if row[9]=="migrated":
            fields|=set(_TARGET_COMMIT_FIELDS)|{"metadata","semantic_digest"}
            header=_target_commit_header_v1(old)
            admission=validate_member_admission_v1(admission)
            if (admission["authority_namespace"]!=authority_namespace
                    or admission["namespace"]!={"bot_id":ns.bot_id,"persona_id":ns.persona_id}
                    or (admission["migration_operation_id"],admission["producer_operation_id"],admission["request_digest"],
                        admission["accepted_digest"],admission["target_ref"],admission["target_revision"],admission["metadata_ref"])!=
                        (row[3],row[2],row[4],original["accepted_digest"],row[6],row[7],row[8])
                    or admission["target_header_digest"]!=canonical_digest(old["target_header"])
                    or admission["original_target_commit_header_digest"]!=canonical_digest(header)
                    or row[8]!=inspection_key_v1(target,row[7]).token or original["metadata_ref"]!=row[8]
                    or original["writes"]!=[[row[8],1]] or [row[8],0] not in original["reads"]):
                raise AuthorityUnavailable("inspection independent member certificate linkage differs")
            value=dict(schema=SOURCE_TYPE if target.type_name=="memory.source" else INTERPRETATION_TYPE,
                target_ref=target.token,target_revision=row[7],target_codec=old["target_header"][0],
                target_sha256=old["target_header"][5],target_bytes=old["target_header"][3],
                target_semantic_digest=old["semantic_digest"],producer_operation_id=row[2],metadata=old["metadata"])
            validate_inspection_metadata_v1(value,source=target.type_name=="memory.source")
            parents=sorted(source_key(*ns.as_tuple,sid).token for sid in
                old["metadata"]["parent_source_ids" if target.type_name=="memory.source" else "source_ids"])
            if parents!=admission["parent_source_refs"]:
                raise AuthorityUnavailable("inspection member own parent dependencies differ")
            refs.update(parents);refs.add(row[8])
        elif admission is not None or row[8] is not None or original["metadata_ref"] is not None or original["writes"]!=[]:
            raise AuthorityUnavailable("inspection classification falsely claims signed output")
        if type(old) is not dict or set(old)!=fields:
            raise AuthorityUnavailable("inspection member target-only original fields differ")
        if old["target_head"][0]!=row[7]:
            raise AuthorityUnavailable("inspection member original revision differs")
        allowed_reads={row[6],*(([row[8]]) if row[8] is not None else []),*(([old["access_ref"]]) if "access_ref" in old else [])}
        if any(type(item) is not list or len(item)!=2 or item[0] not in allowed_reads for item in original["reads"]):
            raise AuthorityUnavailable("inspection event carries unrelated reads")
    for ref in refs:
        key=AtomKey.from_token(ref)
        if key.token!=ref or (key.owner.bot,key.owner.persona)!=ns.as_tuple:
            raise AuthorityUnavailable("inspection member references another namespace")
    return dict(operation_id=row[3],producer_operation_id=row[2],request_digest=row[4],accepted_digest=original["accepted_digest"],
        batch_index=row[5],outcome=row[9],admission=admission,original=original,receipt=receipt,graph_refs=tuple(sorted(refs)))

MEMBER_ADMISSION_SCHEMA="sylanne.source-inspection-member-admission.v1"
_MEMBER_ADMISSION_FIELDS=frozenset({"schema","namespace","authority_id","authority_namespace","installation_id",
    "control_store_id","migration_operation_id","producer_operation_id","request_digest","accepted_digest",
    "owner_head_digest","storage_identity_digest","selected_pointer_version","selected_manifest_digest",
    "selected_storage_generation","pause_operation_id","paused_lifecycle_epoch","pause_receipt_digest",
    "effective_deadline_utc","metadata_schema_digest","target_ref","target_revision","target_header_digest",
    "metadata_ref","interpretation_status_discovery","parent_source_refs","attestation_kind",
    "original_target_commit_header_digest","key_id","admission_digest","signature"})


def validate_member_admission_v1(value):
    from ..authority_service.source_inspection_migration_v1 import _sha_v1,_uuid_v1
    from ..runtime_contracts import NamespaceId
    if type(value) is not dict or set(value)!=_MEMBER_ADMISSION_FIELDS or value["schema"]!=MEMBER_ADMISSION_SCHEMA:
        raise AuthorityUnavailable("inspection member admission closed schema differs")
    ns=NamespaceId(**value["namespace"])
    if value["attestation_kind"]!="verified_target_producer_membership_v1":
        raise AuthorityUnavailable("inspection signed historical target attestation differs")
    _sha_v1(value["original_target_commit_header_digest"])
    _uuid_v1(value["migration_operation_id"]);_uuid_v1(value["pause_operation_id"])
    producer=UUID(value["producer_operation_id"])
    if producer.version!=5 or str(producer)!=value["producer_operation_id"]:
        raise AuthorityUnavailable("inspection member actual producer is not canonical")
    for name in ("request_digest","accepted_digest","owner_head_digest","storage_identity_digest","selected_manifest_digest",
            "pause_receipt_digest","metadata_schema_digest","admission_digest","signature"):
        _sha_v1(value[name])
    for name in ("authority_id","authority_namespace","installation_id","control_store_id","key_id"):
        if type(value[name]) is not str or not value[name]:raise AuthorityUnavailable("inspection signed member identity absent")
    for name in ("selected_pointer_version","selected_storage_generation","paused_lifecycle_epoch","target_revision"):
        if type(value[name]) is not int or value[name]<0:raise AuthorityUnavailable("inspection signed member version differs")
    target=AtomKey.from_token(value["target_ref"])
    if (target.token!=value["target_ref"] or (target.owner.bot,target.owner.persona)!=ns.as_tuple
            or target.type_name not in {"memory.source","memory.interpretation"}):
        raise AuthorityUnavailable("inspection signed member target differs")
    from ..domains.d06.inspection_metadata_v1 import inspection_metadata_type_specs_v1
    if (value["target_revision"]<1 or value["metadata_schema_digest"]!=canonical_digest(
            [(spec.name,spec.schema_hash) for spec in inspection_metadata_type_specs_v1()])):
        raise AuthorityUnavailable("inspection signed target/schema version differs")
    _sha_v1(value["target_header_digest"])
    if value["metadata_ref"]!=inspection_key_v1(target,value["target_revision"]).token:
        raise AuthorityUnavailable("inspection signed metadata version key differs")
    parents=value["parent_source_refs"]
    if type(parents) is not list or parents!=sorted(set(parents)) or type(value["interpretation_status_discovery"]) is not bool:
        raise AuthorityUnavailable("inspection signed member discovery/parent fields differ")
    for ref in parents:
        key=AtomKey.from_token(ref)
        if key.type_name!="memory.source" or (key.owner.bot,key.owner.persona)!=ns.as_tuple or key.token!=ref:
            raise AuthorityUnavailable("inspection signed member parent crosses namespace")
    return value
