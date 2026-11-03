"""Closed canonical metadata readers for the actual D07 fair cohort.

These readers retain no question, claim, prompt, result or Source text.
"""
from __future__ import annotations
from dataclasses import fields
from datetime import datetime
import json
from ..graph_types import AtomKey,GraphAtom,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1

_D07="graph_d07_execution_originals_v1"
_LIFE="graph_d11_life_originals_v1"
_D01="graph_d01_production_inputs_v1"
_D10="graph_d10_production_inputs_v1"
_DOMAIN="graph_domain_production_originals_v1"

def _reader(r,meter=None):
    from .d07_fair_service_dispatch_v1 import require_actual_d07_concern_metadata_reader_v1
    require_actual_d07_concern_metadata_reader_v1(r,meter=meter)
    if meter is not None:r.require_current_v1(meter)
    return r

def _profile(profile):
    if profile=="general_attention":
        from .d07_general_growth_attention_v1 import D07GeneralGrowthAttentionOriginalV1 as cls
    elif profile=="ordinary_attention":
        from .d07_ordinary_continuity_attention_v1 import D07OrdinaryContinuityAttentionOriginalV1 as cls
    elif profile=="review_attention":
        from .d07_single_event_review_v1 import SingleEventReviewAttentionOriginalV1 as cls
    elif profile=="general_question":
        from .d07_general_growth_attention_v1 import D07GeneralGrowthQuestionV1 as cls
    elif profile=="ordinary_question":
        from .d07_ordinary_continuity_attention_v1 import D07OrdinaryContinuityQuestionV1 as cls
    elif profile in {"review_question","joint_question"}:
        from .d07_execution_v1 import D07SemanticQuestionV1 as cls
    elif profile=="artifact_question":
        from .artifact_phase_observation_v1 import ArtifactPhaseObservationQuestionV1 as cls
    elif profile=="artifact_basis":
        from .artifact_phase_observation_v1 import ArtifactPhaseObservationBasisV1 as cls
    elif profile=="general_trigger":
        from .d07_general_growth_attention_v1 import D10GeneralGrowthOutcomeTriggerV1 as cls
    elif profile=="ordinary_basis":
        from ..domains.d01.ordinary_cumulative_growth_v1 import OrdinaryContinuityBasisOriginalV1 as cls
    elif profile=="review_case":
        from ..domains.d01.single_event_review_case_v1 import RegisteredSingleEventReviewCaseV1 as cls
    elif profile=="joint_basis":
        from .joint_external_observation_v1 import JointExternalSemanticBasisV1 as cls
    else:raise ValueError("unregistered fair cause metadata projection")
    return cls

def fair_cause_metadata_retains_path_v1(profile,path):
    cls=_profile(profile)
    top={f.name for f in fields(cls)}
    if path and path[0] not in top:return False
    if profile=="ordinary_question":
        from .d07_ordinary_continuity_cognition_v1 import ordinary_continuity_metadata_retains_path_v1
        return ordinary_continuity_metadata_retains_path_v1("semantic_question",path)
    if profile=="ordinary_basis":
        from .d07_ordinary_continuity_cognition_v1 import ordinary_continuity_metadata_retains_path_v1
        return not path or path==("schema",) or ordinary_continuity_metadata_retains_path_v1("semantic_question",("basis",*path))
    if profile=="review_case":
        return not path or path[0] in {"schema","case_ref","namespace","registration_operation_id","policy_original",
            "adoption_original","adoption_version","review_version","input_original","scope_ref","scope_version",
            "context_source_refs","support_source_refs","source_versions","causal_original","causal_operation_id",
            "causal_receipt_digest","original_parent_budget_lease_ref","original_parent_grant_digest",
            "original_deadline_utc","review_not_before_utc","review_due_utc","readout_valid_until_utc"}
    if profile=="artifact_basis":
        return path!=("question","question") and not(path[:2]==("question","question"))
    return not path or path[0]!="question"

class _D07FairSignedMetadataColumnV1:
    def __init__(self,task,table,kind,ref,profile):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        self.task,self.reader,self.table,self.kind,self.ref,self.profile=task,task.reader,table,kind,ref,profile
        allowed={
            "general_attention":(_D07,"general_growth_attention_v1"),
            "ordinary_attention":(_D07,"ordinary_continuity_attention_v1"),
            "review_attention":(_D07,"single_event_review_attention_v1"),
            "general_question":(_D07,"semantic_question"),
            "ordinary_question":(_D07,"semantic_question"),
            "review_question":(_D07,"semantic_question"),
            "joint_question":(_D07,"semantic_question"),
            "joint_basis":(_D07,"joint_external_semantic_basis_v1"),
            "artifact_question":(_D07,"semantic_question"),
            "artifact_basis":(_LIFE,"artifact_phase_observation_basis_v1"),
            "general_trigger":(_D10,"general_growth_outcome_trigger_v1"),
            "ordinary_basis":(_D01,"ordinary_continuity_basis_v1"),
            "review_case":(_D01,"single_event_review_case_v1"),
        }
        if allowed.get(profile)!=(table,kind):raise ValueError("fair cause changed its registered signature/column profile")
        self.parser=C09CanonicalJSONStreamV2()
        self.builder=_CanonicalJSONValueBuilderV3();self.builder.operation=self.reader.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
        self.header=self.total=None;self.offset=0;self.fragment=b"";self.fragment_offset=0
        self.seen=set();self.value=None;self.complete=False;self.sha256=None;self.byte_count=0
        self.signature_state=None;self.signature=None;self.signature_kind=None;self.signature_bytes=0
        self.columns=("payload_digest","signature") if table==_D07 else ("payload_digest","signature","producing_operation_id")
        self.key=(*self.reader.namespace.as_tuple,kind,ref)
        task.register_column_v1(self)
    def _emit(self,event):
        if len(event.path)==1:self.seen.add(event.path[0])
        if fair_cause_metadata_retains_path_v1(self.profile,event.path):self.builder._emit(event)
    def require_current_v1(self):
        self.task.require_column_v1(self);return self
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        from .dispatch_current_inventory_v3 import _detach_value_v3
        r=_reader(self.reader,meter);self.require_current_v1()
        header=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,self.columns,
            "bot=? AND persona=? AND kind=? AND original_ref=?",self.key)
        if header is None:
            from .d01_production_operations_v1 import MissingProductionOriginalV1
            raise MissingProductionOriginalV1("actual_signed_fair_cause_metadata:"+self.profile)
        if self.header is not None and self.header!=header:raise ValueError("fair original metadata changed across EOF")
        self.header=header;self.signature=header[1]
        if self.complete:return True
        if self.table in {_D01,_D10} and self.signature_state is None:
            self.signature_kind="d11.d01-production-input.v1" if self.table==_D01 else "d11.d10-production-input.v1"
            self.signature_state=r.graph._GraphCoordinator__d11_issuer._signer.begin_original_stream_verification_v3(self.signature_kind,self)
            return False
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment))
            part=self.fragment[self.fragment_offset:end]
            if self.signature_state is not None:
                self.signature_state.update(part);self.signature_bytes+=len(part)
            self.parser.feed(part,self._emit);self.fragment_offset=end;return False
        with legacy_cell_read_transaction_v2(r.db):
            if self.total is None:
                row=r.db.execute("SELECT length(CAST(payload_json AS BLOB)) FROM "+self.table+
                    " WHERE bot=? AND persona=? AND kind=? AND original_ref=?",self.key).fetchone()
                meter.charge_read(16);self.total=row[0]
            if self.offset<self.total:
                part,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table=self.table,column="payload_json",
                    where="bot=? AND persona=? AND kind=? AND original_ref=?",parameters=self.key,
                    start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                if(total,kind)!=(self.total,"text"):raise ValueError("fair canonical original column changed")
                self.offset+=len(part);self.fragment=part;self.fragment_offset=0;return False
        parsed=self.parser.finish();self.sha256,self.byte_count=parsed.sha256,parsed.byte_count
        if (parsed.sha256,parsed.byte_count)!=(header[0],self.total) or self.builder.nodes:
            raise ValueError("fair signed metadata failed whole canonical EOF")
        cls=_profile(self.profile)
        if self.seen!={f.name for f in fields(cls)}:raise ValueError("fair original has another closed schema")
        value=_detach_value_v3(self.builder.value)
        if value["schema"]!=cls.__dataclass_fields__["schema"].default:raise ValueError("fair original changed its registered schema")
        signer=r.graph._GraphCoordinator__d11_issuer._signer
        if self.signature_state is not None:
            signer.finish_original_stream_verification_v3(self.signature_kind,self.signature,self,self.signature_state)
        else:
            sign_kind="d07.execution-original.v1" if self.table==_D07 else "d11.life-original.v1"
            signer.verify(sign_kind,canonical_serialize((r.namespace,self.kind,self.ref,header[0])),header[1])
        if self.profile in {"general_attention","ordinary_attention","review_attention","general_trigger","joint_basis"}:
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            typed=decode_typed_production_value_v1(value,cls)
            if plain_v1(typed)!=value:raise ValueError("fair signed native metadata differs from its closed typed producer")
        self.value=value;self.complete=True;self.fragment=b"";self.parser=self.builder=self.signature_state=None
        return True
    @property
    def original(self):
        if not self.complete:raise ValueError("fair original metadata has not reached authenticated EOF")
        prefix="d07." if self.table==_D07 else "d11.life_" if self.table==_LIFE else "d01." if self.table==_D01 else "d10."
        return ProductionOriginalRefV1(prefix+self.kind,self.ref,self.header[0])

def require_d07_fair_metadata_signature_column_v1(column,*,signer,kind,signature=None,verifier=None,complete=False):
    if type(column) is not _D07FairSignedMetadataColumnV1:
        raise TypeError("exact fair canonical signature column required")
    r=_reader(column.reader);column.require_current_v1()
    if (column.table not in {_D01,_D10} or signer is not r.graph._GraphCoordinator__d11_issuer._signer
            or kind!=column.signature_kind or column.header is None or column.signature!=column.header[1]):
        raise ValueError("fair metadata signature changed its actual registered issuer")
    if complete and (column.sha256!=column.header[0] or column.byte_count!=column.total
            or column.signature_bytes!=column.byte_count or column.signature_state is not verifier or signature!=column.signature):
        raise ValueError("fair metadata signature is not bound to complete canonical EOF")
    return column


class _FairJSONMetadataColumnV1:
    """One bounded canonical column/cell stream issued by its private census."""
    def __init__(self,task,table,column,key_columns,key,retains,*,cell_id=None):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        self.task,self.reader=task,task.reader
        self.table,self.column,self.key_columns,self.key=table,column,tuple(key_columns),tuple(key)
        self.where=" AND ".join(name+"=?" for name in self.key_columns)
        self.retains=retains;self.cell=None if cell_id is None else begin_runtime_cell_read_v3(self.reader.db,cell_id,
            erasure_owner_ref=key[0] if table in {"graph_atoms","graph_history"} else None)
        codec="canonical-json.ascii.v1"if self.cell is None else self.cell.header[0]
        if codec not in {"canonical-json.ascii.v1","canonical-json.utf8.v1"}:
            raise ValueError("fair metadata requires its registered canonical codec")
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=codec=="canonical-json.ascii.v1")
        self.builder=_CanonicalJSONValueBuilderV3();self.builder.operation=self.reader.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)
        self.total=None;self.offset=0;self.fragment=b"";self.fragment_offset=0
        self.complete=False;self.value=None;self.sha256=None;self.byte_count=None
        self.fields_seen=set()
        task.register_column_v1(self)
    def _emit(self,event):
        if len(event.path)==1:self.fields_seen.add(event.path[0])
        if self.retains(event.path):self.builder._emit(event)
    def advance(self,meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        from .dispatch_current_inventory_v3 import _detach_value_v3
        r=_reader(self.reader,meter);self.task.require_column_v1(self)
        if self.complete:return True
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment))
            self.parser.feed(self.fragment[self.fragment_offset:end],self._emit)
            self.fragment_offset=end;return False
        if self.cell is not None:
            part=self.cell.read_fragment(meter=meter)
            if part is not None:self.fragment=part;self.fragment_offset=0;return False
        else:
            with legacy_cell_read_transaction_v2(r.db):
                if self.total is None:
                    row=r.db.execute("SELECT length(CAST("+self.column+" AS BLOB)) FROM "+self.table+" WHERE "+self.where,self.key).fetchone()
                    meter.charge_read(16)
                    if row is None or type(row[0])is not int:raise ValueError("fair selected metadata column disappeared")
                    self.total=row[0];return False
                if self.offset<self.total:
                    part,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table=self.table,column=self.column,
                        where=self.where,parameters=self.key,start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                    if(total,kind)!=(self.total,"text"):raise ValueError("fair metadata legacy column changed before EOF")
                    self.offset+=len(part);self.fragment=part;self.fragment_offset=0;return False
        parsed=self.parser.finish();self.sha256,self.byte_count=parsed.sha256,parsed.byte_count
        if self.cell is not None:
            digest=self.cell.finish(meter=meter)
            if(parsed.sha256,parsed.byte_count)!=(digest,self.cell.header[3]):raise ValueError("fair cell/canonical metadata EOF differ")
        elif parsed.byte_count!=self.total:raise ValueError("fair legacy canonical EOF length differs")
        if self.builder.nodes:raise ValueError("fair metadata projection did not close its canonical containers")
        self.value=_detach_value_v3(self.builder.value);self.complete=True
        self.fragment=b"";self.parser=self.builder=None;return True
    def release_v1(self):
        self.value=self.cell=self.parser=self.builder=None;self.fragment=b""

class _FairDomainRegistrationMetadataV1:
    def __init__(self,task,operation_id):
        self.task,self.reader,self.operation_id=task,task.reader,operation_id
        self.phase="header";self.column=None;self.header=None;self.receipt=None;self.payload=None
        self.complete=False;self.columns={};self.bundle=None;self.event=None
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .domain_production_originals_v1 import TABLE,PHYSICAL_TABLE,_receipt
        r=_reader(self.reader,meter);key=(*r.namespace.as_tuple,self.operation_id)
        if self.phase=="header":
            cols=("domain","operation_kind","request_digest","original_digest","bundle_digest","receipt_digest")
            row=_runtime_bounded_fixed_row_v3(r.db,meter,TABLE,cols,"bot=? AND persona=? AND operation_id=?",key)
            table=TABLE;cell=None
            if row is None:
                row=_runtime_bounded_fixed_row_v3(r.db,meter,PHYSICAL_TABLE,(*cols,"original_payload_cell_id","prepared_digest"),
                    "bot=? AND persona=? AND operation_id=?",key)
                table=PHYSICAL_TABLE
                if row is None:raise ValueError("fair ticket lost its actual adopted domain registration")
                cell=row[6];row=row[:6]
            self.header=row;self.table=table
            keep=frozenset({"schema","namespace","identity","authority","parent_budget","now_utc","owner_guard"})
            self.column=_FairJSONMetadataColumnV1(self.task,table,"original_payload_json",("bot","persona","operation_id"),key,
                lambda path:not path or path[0]in keep,cell_id=cell)
            self.phase="payload";return
        if self.column is not None:
            if not self.column.advance(meter):return
            self.columns[self.phase]=self.column
            if self.phase=="payload":
                self.payload=self.column.value
                required={"schema","request","namespace","identity","authority","parent_budget","now_utc","owner_guard",
                    "policy_refs","read_versions","query_coverage","observed_originals","provenance","writes",
                    "coverage","missing_inputs","continuation_ref"}
                if self.column.fields_seen!=required or self.column.sha256!=self.header[3]:
                    raise ValueError("fair registration is not its exact canonical producer payload")
                if(self.payload["namespace"]!=plain_v1(r.namespace)or self.payload["identity"]["operation_id"]!=self.operation_id):
                    raise ValueError("fair registration crossed its actual operation or namespace")
                self.column=_FairJSONMetadataColumnV1(self.task,self.table,"receipt_json",("bot","persona","operation_id"),
                    key,lambda path:True)
                self.phase="receipt";return
            if self.phase=="receipt":
                self.receipt=_receipt(self.column.value)
                if(self.receipt.status!="committed"or self.receipt.operation_id!=self.operation_id
                        or canonical_digest(self.receipt)!=self.header[5]or self.receipt.operation_digest!=self.header[4]):
                    raise ValueError("fair registration lost its official typed W01 CommitReceipt")
                self.column=None;self.phase="bundle";return
            if self.phase=="event_reads":
                self.event_reads=tuple(GraphVersion(AtomKey.from_token(t),v)for t,v in self.column.value)
                self.column=None;self.phase="event_revisions";return
            if self.phase=="event_revisions":
                self.event_revisions=tuple(GraphVersion(AtomKey.from_token(t),v)for t,v in self.column.value)
                if(self.event_reads!=self.receipt.read_versions or not set(self.event_revisions)<=set(self.receipt.write_versions)):
                    raise ValueError("fair registration receipt differs from its actual graph event read/write vectors")
                self.column=None;self.phase="finish";return
        if self.phase=="bundle":
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",key)
            if row!=(self.receipt.operation_digest,self.receipt.activity_id,self.receipt.effect_id,self.receipt.commit_seq):
                raise ValueError("fair registration receipt has no matching actual W01 bundle")
            self.bundle=row;self.phase="event";return
        if self.phase=="event":
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_events",("digest","epoch_revision"),
                "bot=? AND persona=? AND session=? AND event_id=?",(*r.namespace.as_tuple,self.receipt.activity_id,self.operation_id))
            if row is None:raise ValueError("fair registration lacks actual immutable graph event")
            self.event=row
            self.column=_FairJSONMetadataColumnV1(self.task,"graph_events","reads",("bot","persona","session","event_id"),
                (*r.namespace.as_tuple,self.receipt.activity_id,self.operation_id),lambda path:True);self.phase="event_reads";return
        if self.phase=="event_revisions":
            self.column=_FairJSONMetadataColumnV1(self.task,"graph_events","revisions",("bot","persona","event_id"),
                key,lambda path:True);return
        if self.phase=="finish":
            if(len(self.receipt.invalidated_epochs)!=1 or
                    self.receipt.invalidated_epochs[0].revision!=self.event[1]):
                raise ValueError("fair registration receipt epoch differs from actual event")
            self.complete=True
    def require_current_v1(self,meter):
        _reader(self.reader,meter)
        if not self.complete:raise ValueError("fair registration metadata has not reached actual whole EOF")
        return self


class _FairGraphMetadataReadV1:
    def __init__(self,task,key,*,revision=None,focus=False):
        self.task,self.reader,self.key=task,task.reader,key
        self.revision=revision;self.focus=focus
        self.head=None;self.column=None;self.complete=False;self.atom=None;self.digest=None
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        r=_reader(self.reader,meter)
        if self.column is None:
            table="graph_atoms"if self.revision is None else"graph_history"
            keycols=("token","bot","persona")if self.revision is None else("token","revision")
            key=(self.key.token,*r.namespace.as_tuple)if self.revision is None else(self.key.token,self.revision)
            headercols=("revision","valid","value_cell_id")if self.revision is None else("valid","value_cell_id","event_bot","event_persona","event_id")
            where=" AND ".join(x+"=?"for x in keycols)
            row=_runtime_bounded_fixed_row_v3(r.db,meter,table,headercols,where,key)
            if row is None:
                if self.revision is not None:raise ValueError("fair ticket lost its actual immutable birth history")
                self.head=(0,False,None);self.atom=GraphAtom(self.key,0,{},False);self.complete=True;return
            self.head=tuple(row)
            self.column=_FairJSONMetadataColumnV1(self.task,table,"value",keycols,key,
                lambda path:not path or not self.focus or path[0]in{"schema","persona_id","focus_epoch"},
                cell_id=row[2]if self.revision is None else row[1])
            return
        if not self.column.advance(meter):return
        value=self.column.value;revision=self.head[0]if self.revision is None else self.revision
        valid=self.head[1]==1 if self.revision is None else self.head[0]==1
        if valid:
            if self.focus:
                from ..domains.d07 import FocusState
                if self.column.fields_seen!={"schema",*FocusState.__dataclass_fields__}or value["schema"]!=self.key.type_name:
                    raise ValueError("fair metadata focus has another closed canonical schema")
                if value["persona_id"]!=r.namespace.persona_id or type(value["focus_epoch"])is not int or value["focus_epoch"]<0:
                    raise ValueError("fair focus lost its actual persona epoch")
            else:r.store._registry.spec(self.key.type_name).validator(value)
        self.digest=self.column.sha256;self.atom=GraphAtom(self.key,revision,value,valid);self.complete=True

class D07FairCauseCensusTaskV1:
    def __init__(self,reader):
        _reader(reader)
        self.reader=reader;self.binding=reader.identity_v1()
        self.columns=set();self.complete=False;self.phase="trigger";self.trigger_task=None;self.pending=None;self.pending_type=None
        self.after="";self.type_index=0
        self.types=("d07.attention_ticket.v1","d07.focus.v1","d07.concern_round.v1","d07.concern_dispatch.v1")
        self.atoms={};self.ticket_atoms=();self.focus=None;self.rounds=();self.slots=();self.policy=None
        self.causes=();self.dispositions=();self.read_versions=();self.census_digest=None;self.policy_task=None
        self.ticket_index=0;self.ticket_task=None;self.resolved=[];self.native_after="";self.native_kind="prepared"
        self.prepared={};self.joint_bases=[];self.native_columns={};self.generic_prepared={};self.native_recovery=None;self.count=0;self.native_header=None
        self.native_column=None;self.native_phase="scan"
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return _heap((self.binding,self.atoms,self.resolved,self.prepared,self.joint_bases,
            self.native_columns,self.columns,self.pending,self.ticket_task))+65536
    def register_column_v1(self,column):
        _reader(self.reader)
        if column.task is not self or column in self.columns:raise ValueError("fair metadata column issuer changed")
        self.columns.add(column);self.reader.operation.refresh_retained_state_v3(self)
    def require_column_v1(self,column):
        _reader(self.reader)
        if self.binding!=self.reader.identity_v1()or column not in self.columns or column.task is not self:
            raise ValueError("fair metadata column lost its actual census/Work/selection")
    def _native_prepared_paths_v1(self,path):
        from .d07_execution_v1 import D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3,D07IngressRecallPreparedV1
        from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
        from .d07_ordinary_continuity_cognition_v1 import D07OrdinaryContinuityPreparedV1
        from .d07_single_event_review_v1 import D07SingleEventReviewPreparedV1
        from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
        from .artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
        classes=(D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3,D07IngressRecallPreparedV1,
            D07GeneralGrowthPreparedV1,D07OrdinaryContinuityPreparedV1,D07SingleEventReviewPreparedV1,
            D07MethodGrowthPreparedV2,D07ArtifactObservationPreparedV3)
        top=set().union(*(cls.__dataclass_fields__ for cls in classes))
        omit={"frozen_json","query_inventory_json","external_content_originals_json"}
        if not path:return True
        if path[0]=="read_rows":return len(path)<=2 or len(path)==3 and path[2]in{"ref","revision","valid"}
        return path[0]in top-omit
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..domains.d07 import AttentionTicket
        r=_reader(self.reader,meter)
        if self.binding!=r.identity_v1():raise ValueError("fair census changed its original Work identity")
        if self.complete:return
        if self.phase=="trigger":
            if self.trigger_task is None:self.trigger_task=_D07FairTriggerCauseReadV1(self)
            self.trigger_task.advance(meter)
            if self.trigger_task.complete:self.phase="graph"
            return
        if self.phase=="graph":
            if self.pending is not None:
                self.pending.advance(meter)
                if self.pending.complete:
                    atom=self.pending.atom
                    if atom.key.type_name=="d07.attention_ticket.v1"and len([a for a in self.atoms.values()if a.key.type_name==atom.key.type_name])>=128:
                        raise ValueError("complete fair ticket inventory exceeds its original 128 heads")
                    self.atoms[atom.key.token]=atom;self.pending=None
                return
            if self.type_index==len(self.types):
                self.ticket_atoms=tuple(a for a in self.atoms.values()if a.key.type_name=="d07.attention_ticket.v1"and a.valid)
                focus=tuple(a for a in self.atoms.values()if a.key.type_name=="d07.focus.v1"and a.valid)
                if len(focus)!=1:raise ValueError("fair scheduling requires its unique actual current focus")
                self.focus=focus[0]
                self.rounds=tuple(a for a in self.atoms.values()if a.key.type_name=="d07.concern_round.v1")
                self.slots=tuple(a for a in self.atoms.values()if a.key.type_name=="d07.concern_dispatch.v1")
                self.phase="policy";return
            typename=self.types[self.type_index]
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_atoms",("token",),
                "bot=? AND persona=? AND type_name=? AND token>? ORDER BY token",
                (*r.namespace.as_tuple,typename,self.after))
            if row is None:self.type_index+=1;self.after="";return
            key=AtomKey.from_token(row[0])
            if NamespaceId.from_key(key)!=r.namespace or key.type_name!=typename:raise ValueError("fair census crossed namespace/type")
            self.after=row[0];self.pending=_FairGraphMetadataReadV1(self,key,focus=typename=="d07.focus.v1");return
        if self.phase=="policy":
            if self.policy_task is None:self.policy_task=_D07FairPolicyMetadataV1(self)
            self.policy_task.advance(meter)
            if self.policy_task.complete:self.policy=self.policy_task.result;self.phase="native"
            return
        if self.phase=="native":
            if self.native_recovery is not None:
                self.native_recovery.advance(meter)
                if self.native_recovery.complete:
                    choice=self.native_recovery.continuation["choice"]
                    if choice is not None:
                        ticket_id=choice["ticket_id"]
                        if ticket_id in self.generic_prepared:raise ValueError("ticket has conflicting actual generic preparation originals")
                        self.generic_prepared[ticket_id]=self.native_recovery
                    self.native_recovery=None
                return
            if self.native_column is not None:
                if not self.native_column.advance(meter):return
                self._finish_native_v1(meter);self.native_column=None;return
            if self.native_kind is None:self.phase="tickets";return
            row=_runtime_bounded_fixed_row_v3(r.db,meter,_D07,("original_ref","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
                (*r.namespace.as_tuple,self.native_kind,self.native_after))
            if row is None:
                self.native_kind="joint_external_semantic_basis_v1"if self.native_kind=="prepared"else None
                self.native_after="";return
            self.count+=1
            if self.native_kind=="prepared"and self.count>128:raise ValueError("complete original fair Prepared census exceeds 128")
            self.native_header=row;self.native_after=row[0]
            if self.native_kind=="prepared":
                self.native_column=_FairJSONMetadataColumnV1(self,_D07,"payload_json",("bot","persona","kind","original_ref"),
                    (*r.namespace.as_tuple,self.native_kind,row[0]),self._native_prepared_paths_v1)
            else:
                self.native_column=_D07FairSignedMetadataColumnV1(self,_D07,self.native_kind,row[0],"joint_basis")
            return
        if self.phase=="tickets":
            if self.ticket_task is not None:
                self.ticket_task.advance(meter)
                if self.ticket_task.complete:
                    self.resolved.append(self.ticket_task.result);self.ticket_task=None;self.ticket_index+=1
                return
            if self.ticket_index==len(self.ticket_atoms):
                self.phase="finish";return
            self.ticket_task=_D07FairTicketCauseReadV1(self,self.ticket_atoms[self.ticket_index]);return
        if self.phase=="finish":
            from ..domains.d07.concern_round import concern_round_key
            from .d07_fair_service_dispatch_v1 import concern_dispatch_key_v1
            for category in ("required","interaction","background"):
                for key in (concern_round_key(r.namespace,category),concern_dispatch_key_v1(r.namespace,category)):
                    if key.token not in self.atoms:self.atoms[key.token]=GraphAtom(key,0,{},False)
            self.rounds=tuple(a for a in self.atoms.values()if a.key.type_name=="d07.concern_round.v1")
            self.slots=tuple(a for a in self.atoms.values()if a.key.type_name=="d07.concern_dispatch.v1")
            self.read_versions=tuple(sorted({GraphVersion(a.key,a.revision)for a in self.atoms.values()}|
                {self.policy.active_head_ref}|{v for result in self.resolved for v in result[3]},key=lambda v:v.key.token))
            self.causes=tuple(result[1]for result in self.resolved if result[1]is not None)
            self.dispositions=tuple((GraphVersion(result[0].key,result[0].revision),canonical_digest(result[0].value),result[2],result[4])
                for result in self.resolved)
            self.census_digest=canonical_digest((r.namespace,r.graph_stamp,self.ticket_atoms,self.focus,
                self.policy,self.rounds,self.slots,self.causes,self.dispositions,self.read_versions))
            self.complete=True;r.operation.refresh_retained_state_v3(self);return
        raise ValueError("unregistered actual fair metadata census phase")
    def _finish_native_v1(self,meter):
        from .d07_stage_content_scope_v3 import _host_prepared_class_v3
        from .d07_execution_v1 import D07IngressRecallPreparedV1,SIGN_KIND
        column=self.native_column;r=self.reader
        if self.native_kind!="prepared":
            self.joint_bases.append((column.value,column.original));return
        ref,digest,signature=self.native_header
        if column.sha256!=digest:raise ValueError("fair Prepared census failed full canonical EOF")
        r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((r.namespace,"prepared",ref,digest)),signature)
        value=column.value
        cls=D07IngressRecallPreparedV1 if value["schema"]=="d07.ingress-recall-prepared.v1"else _host_prepared_class_v3(value["schema"])
        if(column.fields_seen!={f.name for f in fields(cls)}or value["namespace"]!=plain_v1(r.namespace)or value["job_id"]!=ref):
            raise ValueError("fair Prepared census has another exact registered schema/namespace/job")
        self.prepared[ref]=(value,ProductionOriginalRefV1("d07.prepared",ref,digest))
        if value["work_kind"]in{"concern","reflection"}:
            self.native_recovery=_D07FairPreparedRecoveryV1(self,value,self.prepared[ref][1])
    def release_v1(self):
        self.reader.operation.unregister_retained_state_v3(self)
        for column in self.columns:
            if type(column)is _FairJSONMetadataColumnV1:column.release_v1()
        if self.ticket_task is not None:self.ticket_task.release_v1()
        self.columns.clear();self.atoms.clear();self.prepared.clear();self.native_columns.clear()
        self.resolved.clear();self.joint_bases.clear();self.pending=self.ticket_task=self.native_column=None


class _D07FairSourceMetadataV1:
    def __init__(self,reader,roots,groups):
        from .source_correction_read_v3 import SourceCorrectionContextReadV3
        from ..domains.d06 import source_correction_head_key
        from ..memory_types import access_key
        class _Family(SourceCorrectionContextReadV3):
            def __init__(family,purpose,audiences):
                super().__init__(reader.db,namespace=reader.namespace,source_id=AtomKey.from_token(roots[0]).owner.subject,
                    storage_lease=reader.operation,read_scope=reader.read_scope,graph_stamp=reader.graph_stamp,
                    purpose=purpose,audiences=audiences)
                family.inspection_owner=reader;family.allowed=True;family.denied_access=set()
            def _step(family,meter):
                if family.cell is None and family.inspection_pending is None and family.phase=="epochs":
                    family.epochs=family._epochs(meter);family._family(roots,"fair");return
                if family.cell is None and family.inspection_pending is None and family.phase=="scan":
                    family.scan_complete=True;family.final_tokens=tuple(sorted(family.heads));family.phase="recheck";return
                super()._step(meter)
                if family.complete:family.qualification=None
            def _family_step(family,meter):
                if family.jobs and family.jobs[-1][0]=="enter":
                    _,token=family.jobs[-1]
                    if token not in family.done and token not in family.active:
                        head=family._head(token,meter)
                        if head[0]>0 and head[1]!=1:
                            if len(family.done)+len(family.active)>=family.source_limit_v3:raise ValueError("fair Source closure exceeds its original 32-member family")
                            family.jobs.pop();family.allowed=False;family.done.add(token);family.family_keys.add(token);return
                if family.jobs and family.jobs[-1][0]=="access":
                    _,token=family.jobs[-1];sid=family.sources[token][0]["source_id"]
                    access_ref=access_key(*reader.namespace.as_tuple,sid).token
                    head=family._head(access_ref,meter)
                    if head[0]>0 and head[1]!=1:
                        family.jobs.pop();family.family_keys.add(access_ref);family.denied_access.add(access_ref);family.allowed=False;return
                if family.jobs and family.jobs[-1][0]=="correct":
                    _,token=family.jobs.pop();data=family.sources[token][0];sid=data["source_id"]
                    ref=source_correction_head_key(reader.namespace,sid).token
                    family.family_keys.add(ref);head=family._head(ref,meter)
                    access_ref=access_key(*reader.namespace.as_tuple,sid).token
                    if access_ref in family.denied_access:
                        family.allowed=False;return
                    access=family.accesses[access_ref]
                    if(head[0]or access["source_id"]!=sid or access["status"]!="active"
                            or family.purpose not in data["purposes"]or family.purpose not in access["purposes"]
                            or not set(family.audiences)<=set(data["audiences"])
                            or not set(family.audiences)<=set(access["audiences"])):
                        family.allowed=False
                    family._reserve();return
                super()._family_step(meter)
        self.reader=reader;self.roots=tuple(roots);self.groups=tuple(groups)
        if not roots or len(roots)>32 or len(set(roots))!=len(roots):
            raise ValueError("fair Source metadata preserves each original 32-root family")
        self.tasks=tuple(_Family(purpose,auds)for purpose,auds in self.groups)
        self.index=0;self.complete=False;self.allowed=False;self.versions=()
    def advance(self,meter):
        _reader(self.reader,meter)
        if self.index<len(self.tasks):
            task=self.tasks[self.index];task._step(meter)
            if task.complete:self.index+=1
            return
        self.versions=tuple(sorted({v for task in self.tasks for v in task.readset},key=lambda v:v.key.token))
        self.allowed=all(task.allowed for task in self.tasks);self.complete=True
    def release_v1(self):
        for task in self.tasks:task.release_v3()

class _D07FairBudgetMetadataV1:
    def __init__(self,task,lease_ref,grant_digest,deadline,ceiling):
        self.task,self.reader=task,task.reader;self.lease_ref=lease_ref
        self.expected_grant_digest=grant_digest;self.original_deadline=deadline;self.ceiling=ceiling
        self.amounts={};self.amount_names=("limits_json","used_json","reserved_json","unconfirmed_json");self.amount_index=0
        self.current=lease_ref;self.phase="lease";self.column=None;self.columns={};self.ancestors=[]
        self.complete=False;self.allowed=True;self.grant=None;self.ancestry=();self.deadline=deadline
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .issuers import _decode_grant,_payload
        r=_reader(self.reader,meter)
        if self.phase=="lease":
            if self.current in {row[0]for row in self.ancestors}:raise ValueError("fair original budget ancestry is cyclic")
            self.lease=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_leases",
                ("lease_id","parent_id","bot_id","persona_id","currency","version","state"),"lease_id=?",(self.current,))
            if self.lease is None or self.lease[2:4]!=r.namespace.as_tuple:
                raise ValueError("fair native cause lost its actual original budget namespace")
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_grants",
                ("version","status","signature"),"lease_id=? ORDER BY version DESC",(self.current,))
            if row is None:raise ValueError("fair native cause lost its actual signed grant")
            self.grant_header=row
            if not self.ancestors:
                self.phase="amounts";return
            self.column=_FairJSONMetadataColumnV1(self.task,"runtime_budget_grants","grant_json",("lease_id","version"),
                (self.current,row[0]),lambda path:True)
            self.phase="grant";return
        if self.phase=="amounts":
            if self.column is None:
                name=self.amount_names[self.amount_index]
                self.column=_FairJSONMetadataColumnV1(self.task,"runtime_budget_leases",name,("lease_id",),(self.current,),lambda path:True)
                return
            if not self.column.advance(meter):return
            value=self.column.value
            if type(value)is not dict or any(type(k)is not str or type(v)is not int or v<0 for k,v in value.items()):
                raise ValueError("fair actual budget counters have another closed numeric mapping")
            self.amounts[self.amount_names[self.amount_index]]=value;self.column=None;self.amount_index+=1
            if self.amount_index<len(self.amount_names):return
            if self.ceiling is None:self.allowed=False
            else:
                for name,amount in self.ceiling.items():
                    available=self.amounts["limits_json"].get(name,0)-sum(self.amounts[n].get(name,0)for n in ("used_json","reserved_json","unconfirmed_json"))
                    if amount>available:self.allowed=False
            self.column=_FairJSONMetadataColumnV1(self.task,"runtime_budget_grants","grant_json",("lease_id","version"),
                (self.current,self.grant_header[0]),lambda path:True)
            self.phase="grant";return
        if self.phase=="grant":
            if not self.column.advance(meter):return
            wire=canonical_serialize(self.column.value);grant=_decode_grant(wire)
            if(grant.lease_id!=self.current or (grant.bot_id,grant.persona_id)!=r.namespace.as_tuple
                    or grant.currency!=self.lease[4]or grant.version!=self.grant_header[0]
                    or canonical_serialize(_payload(grant))!=wire):
                raise ValueError("fair budget grant changed its exact original typed wire")
            r.graph._GraphCoordinator__d11_issuer._signer.verify("budget-grant.v1",wire,self.grant_header[2])
            digest=canonical_digest(grant)
            if not self.ancestors and digest!=self.expected_grant_digest:
                self.allowed=False
            if self.lease[6]!="active"or self.grant_header[1]!="active"or r.now_utc>=grant.valid_until_utc:
                self.allowed=False
            if not self.ancestors:
                self.grant=grant
                if("d07.cognition"not in grant.allowed_work_kinds or self.ceiling is not None
                        and any(v>grant.max_ceiling.get(k,0)for k,v in self.ceiling.items())):self.allowed=False
            self.deadline=min(self.deadline,grant.valid_until_utc)
            self.ancestors.append((self.current,grant.version,digest,grant.valid_until_utc))
            self.columns[self.current]=self.column;self.column=None
            if self.lease[1]is None:
                self.ancestry=tuple(self.ancestors);self.complete=True;return
            self.current=self.lease[1];self.phase="lease";return

class _D07FairTicketCauseReadV1:
    def __init__(self,task,atom):
        self.task,self.reader,self.atom=task,task.reader,atom
        self.phase="identify";self.column=None;self.attention=None;self.question=None;self.registration=None
        self.source_task=self.budget_task=None;self.birth=None;self.complete=False;self.result=None
        self.profile=self.family=None;self.roots=();self.groups=();self.expected_digest=None
        self.question_original=None;self.native_original=None;self.execution_original=None
        self.recovery=None
    def _decode(self,raw,cls):
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        value=decode_typed_production_value_v1(raw,cls)
        if plain_v1(value)!=raw:raise ValueError("fair cause has another exact typed wire")
        return value
    def _start_column(self,table,kind,ref,profile):
        self.column=_D07FairSignedMetadataColumnV1(self.task,table,kind,ref,profile)
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..domains.d07 import AttentionTicket
        from .d07_fair_service_dispatch_v1 import D07SelectedConcernCauseV1
        from ..runtime_contracts import AuthorityContext
        r=_reader(self.reader,meter);raw=self.atom.value
        if self.phase=="identify":
            self.ticket=self._decode({k:v for k,v in raw.items()if k!="schema"},AttentionTicket)
            ticket_id=self.ticket.ticket_id
            selectors=(
                ("attention:general-growth:","general_attention","general_growth","general-growth-attention-original:","general_growth_attention_v1"),
                ("attention:ordinary-continuity:","ordinary_attention","ordinary_continuity","ordinary-continuity-attention:","ordinary_continuity_attention_v1"),
                ("attention:single-event-review:","review_attention","single_event_review","single-event-review-attention:","single_event_review_attention_v1"),
                ("attention:artifact-observation:","artifact_basis","artifact_observation","artifact-phase-observation-basis:","artifact_phase_observation_basis_v1"),
            )
            matches=tuple(row for row in selectors if ticket_id.startswith(row[0]))
            if matches:
                prefix,self.profile,self.family,refprefix,kind=matches[0]
                self._start_column(_LIFE if self.family=="artifact_observation"else _D07,kind,
                    refprefix+ticket_id[len(prefix):],self.profile)
                self.phase="attention";return
            self.c02_after="";self.c02_matches=[];self.phase="c02_issuance";return
        if self.phase=="attention":
            if not self.column.advance(meter):return
            self.attention=self.column.value;self.native_original=self.column.original;self.column=None
            a=self.attention
            if self.family=="artifact_observation":
                q=a["question"]
                from .artifact_phase_observation_v1 import artifact_observation_ids_v1,PrepareArtifactPhaseObservationRequestV1
                request=self._decode(a["request"],PrepareArtifactPhaseObservationRequestV1)
                self.question_ref=artifact_observation_ids_v1(request.selector,request.condition_id)["question"]
                self.expected_digest=a["ticket_digest"];self.roots=tuple(q["source_refs"])
                self.registration_operation=a["registration_operation_id"];self.registration_digest=None
                self.birth_version=GraphVersion(self.atom.key,1)
                self.parent_ref=a["parent_budget_lease_ref"];self.parent_digest=a["parent_grant_digest"]
                self.deadline=a["original_deadline_utc"]
                self.question_expected_digest=None
            else:
                if a["namespace"]!=plain_v1(r.namespace)or a["original_ref"]!=self.native_original.original_ref:
                    raise ValueError("fair attention changed actual namespace or native locator")
                self.question_ref=a["semantic_question_ref"];self.question_expected_digest=a["semantic_question_digest"]
                self.expected_digest=a["ticket_digest"]if self.family=="general_growth"else a["ticket_value_digest"]
                self.registration_operation=a["registration_operation_id"];self.registration_digest=a["registration_receipt_digest"]
                self.birth_version=self._decode(a["ticket_ref"],GraphVersion)
                roots=(*a["context_source_refs"],*(a["consolidation_source_refs"]if self.family=="single_event_review"else a["support_source_refs"]))
                self.roots=tuple(dict.fromkeys(roots))
                self.parent_ref=a["original_parent_budget_lease_ref"];self.parent_digest=a["original_parent_grant_digest"]
                self.deadline=a["original_deadline_utc"]
            if(self.birth_version.key!=self.atom.key or self.birth_version.revision<1
                    or self.ticket.source_refs!=self.roots):
                raise ValueError("fair native ticket differs from its exact actual signed Source roots/birth")
            profile={"general_growth":"general_question","ordinary_continuity":"ordinary_question",
                "single_event_review":"review_question","artifact_observation":"artifact_question"}[self.family]
            self._start_column(_D07,"semantic_question",self.question_ref,profile);self.phase="question";return
        if self.phase=="question":
            if not self.column.advance(meter):return
            self.question=self.column.value;self.question_original=self.column.original
            if(self.question_expected_digest is not None and self.question_original.original_digest!=self.question_expected_digest
                    or tuple(self.question["source_refs"])!=self.roots or self.question["question_key"]!=self.ticket.question_key):
                raise ValueError("fair ticket changed its actual registered question and whole Source commitment")
            if self.family=="general_growth":
                self._start_column(_D10,"general_growth_outcome_trigger_v1",self.attention["outcome_trigger_ref"],"general_trigger")
                self.phase="general_cause";return
            if self.family=="ordinary_continuity":
                original=self._decode(self.attention["basis_original"],ProductionOriginalRefV1)
                self._start_column(_D01,"ordinary_continuity_basis_v1",original.original_ref,"ordinary_basis")
                self.execution_original=original;self.phase="named_cause";return
            if self.family=="single_event_review":
                original=self._decode(self.attention["case_original"],ProductionOriginalRefV1)
                self._start_column(_D01,"single_event_review_case_v1",original.original_ref,"review_case")
                self.execution_original=original;self.phase="named_cause";return
            self.execution_original=self.native_original;self.column=None;self.phase="registration";return
        if self.phase=="general_cause":
            if not self.column.advance(meter):return
            if self.column.original.original_digest!=self.attention["outcome_trigger_digest"]:
                raise ValueError("fair General attention changed its actual outcome cause")
            self.cause=self.column.value;self.execution_original=self.column.original
            self.column=None;self.phase="registration";return
        if self.phase=="named_cause":
            if not self.column.advance(meter):return
            if self.column.original.original_digest!=self.execution_original.original_digest:
                raise ValueError("fair named attention changed its signed phase/Case cause")
            self.cause=self.column.value;self.column=None;self.phase="registration";return
        if self.phase=="registration":
            if self.registration is None:self.registration=_FairDomainRegistrationMetadataV1(self.task,self.registration_operation)
            self.registration.advance(meter)
            if not self.registration.complete:return
            p=self.registration.payload;receipt=self.registration.receipt
            expected={"general_growth":"register_general_growth_attention_v1","ordinary_continuity":"register_ordinary_continuity_attention_v1",
                "single_event_review":"register_single_event_review_attention_v1","artifact_observation":"prepare_artifact_phase_observation_v1"}[self.family]
            if(self.registration.header[:2]!=("d07",expected)
                    or self.registration_digest is not None and canonical_digest(receipt)!=self.registration_digest
                    or self.birth_version not in receipt.write_versions
                    or p["parent_budget"]!=self.parent_ref):
                raise ValueError("fair ticket has another actual registration receipt/type/parent")
            self.authority=self._decode(p["authority"],AuthorityContext)
            if self.family=="general_growth"and plain_v1(self.authority)!=self.attention["source_authority"]:
                raise ValueError("General signed Authority differs from its actual registration")
            self.birth=_FairGraphMetadataReadV1(self.task,self.atom.key,revision=self.birth_version.revision)
            self.phase="birth";return
        if self.phase=="birth":
            self.birth.advance(meter)
            if not self.birth.complete:return
            if(not self.birth.atom.valid or self.birth.digest!=self.expected_digest
                    or self.birth.head[2:]!=(*r.namespace.as_tuple,self.registration_operation)):
                raise ValueError("fair ticket lost its complete same-event typed birth")
            born=self.birth.atom.value
            if any(born[name]!=raw[name]for name in born if name not in{"eligible","resources_available","cancel_refs","served_fraction"}):
                raise ValueError("fair current ticket changed its immutable original question/Source identity")
            self.groups=((self.authority.purpose,self.authority.audience),)
            if self.family=="single_event_review":
                self.groups=(("context",self.authority.audience),("consolidation",self.authority.audience))
            owner=r.owner_binding
            self.owner_allowed=(self.authority.namespace==r.namespace and self.authority.actor==owner.actor
                and self.authority.activation_generation==r.authority.activation_generation
                and all(purpose in owner.purposes and set(auds)<=set(owner.audiences)for purpose,auds in self.groups))
            self.source_task=_D07FairSourceMetadataV1(r,self.roots,self.groups)
            self.budget_task=_D07FairBudgetMetadataV1(self.task,self.parent_ref,self.parent_digest,self.deadline,self._workflow_ceiling_v1())
            self.phase="sources";return
        if self.phase=="sources":
            self.source_task.advance(meter)
            if self.source_task.complete:self.phase="budget"
            return
        if self.phase=="budget":
            self.budget_task.advance(meter)
            if self.budget_task.complete:self.phase="recovery"
            return
        if self.phase=="recovery":
            matches=tuple((value,original)for value,original in self.task.prepared.values()
                if value.get("semantic_question_ref")==self.question_original.original_ref
                and value.get("semantic_question_digest")==self.question_original.original_digest)
            if len(matches)>1:raise ValueError("fair ticket has conflicting actual signed preparations")
            if matches:
                value,original=matches[0]
                self.recovery=_D07FairPreparedRecoveryV1(self.task,value,original,self)
                self.phase="recovery_metadata";return
            self.recovery=self.task.generic_prepared.get(self.ticket.ticket_id)
            self.phase="result";return
        if self.phase=="recovery_metadata":
            self.recovery.advance(meter)
            if self.recovery.complete:self.phase="result"
            return
        if self.phase=="result":
            self._finish_v1();return
        if self.phase=="c02_issuance":
            self._advance_c02_v1(meter);return
        if self.phase=="c02_receipt":
            self.issuance_receipt.advance(meter)
            if not self.issuance_receipt.complete:return
            receipt=self.issuance_receipt.receipt
            if receipt.operation_digest!=self.issuance[2]:
                raise ValueError("fair C02 issuance changed actual adopted bundle digest")
            versions=tuple(v for v in receipt.write_versions if v.key==self.atom.key)
            if len(versions)!=1:raise ValueError("fair C02 issuance has no unique actual ticket birth member")
            self.birth_version=versions[0];self.birth=_FairGraphMetadataReadV1(self.task,self.atom.key,revision=versions[0].revision)
            self.phase="c02_birth";return
        if self.phase=="c02_birth":
            self.birth.advance(meter)
            if not self.birth.complete:return
            if not self.birth.atom.valid or self.birth.head[2:]!=(*r.namespace.as_tuple,self.issuance[0]):
                raise ValueError("fair C02 ticket has no actual same-event typed birth history")
            if any(self.birth.atom.value[name]!=raw[name]for name in raw if name not in{"eligible","resources_available","cancel_refs","served_fraction"}):
                raise ValueError("fair C02 current ticket changed immutable issuance fields")
            candidates=tuple((basis,original)for basis,original in self.task.joint_bases
                if self._decode(basis["request"]["attention_ticket"],GraphVersion)==self.birth_version)
            if len(candidates)>1:raise ValueError("fair C02 ticket has competing actual signed Joint causes")
            if candidates:
                self.attention,self.native_original=candidates[0];a=self.attention
                if(a["namespace"]!=plain_v1(r.namespace)or a["request"]["attention_issuance_operation_id"]!=self.issuance[0]
                        or a["request"]["c02_operation_id"]!=self.issuance[1]or tuple(a["source_refs"])!=self.ticket.source_refs):
                    raise ValueError("Joint signed cause changed its actual C02 issuance or Source mapping")
                self.family="joint_external";self.question_ref=a["question_ref"];self.question_expected_digest=a["question_digest"]
                self.execution_original=self.native_original;self.roots=tuple(a["source_refs"])
                self.parent_ref=a["parent_budget_lease_ref"];self.parent_digest=a["parent_grant_digest"];self.deadline=a["original_deadline_utc"]
                self.registration_operation=a["producing_operation_id"];self.registration_digest=None
                self._start_column(_D07,"semantic_question",self.question_ref,"joint_question");self.phase="joint_question";return
            recovery=self.task.generic_prepared.get(self.ticket.ticket_id)
            if recovery is not None:
                self.recovery=recovery;self.family="c02_foreground";self.native_original=ProductionOriginalRefV1(
                    "d07.attention_issuance_v1","d07-attention:"+self.issuance[0],self.issuance[2])
                self.execution_original=recovery.original;self.question_original=None
                self.roots=self.ticket.source_refs;self.parent_ref=recovery.born.parent_budget_lease_ref
                self.parent_digest=None;self.deadline=datetime.fromisoformat(recovery.born.deadline_utc.replace("Z","+00:00")).timestamp()
                self.authority=self._decode(json.loads(recovery.prepared["owner_authority_json"]),AuthorityContext)
                self.registration=self.issuance_receipt
                self.phase="existing_grant";return
            status="no_execution_cause";reason="actual_issuance_has_no_signed_C3_preparation_or_Joint_allocation"
            if self.ticket.cancel_refs or not self.ticket.eligible:status,reason="cancelled","actual_current_ticket_cancel_or_ineligible"
            elif r.now_utc>=self.ticket.valid_until:status,reason="expired","actual_original_ticket_deadline"
            self.result=(self.atom,None,status,(),reason);self.complete=True;return
        if self.phase=="joint_question":
            if not self.column.advance(meter):return
            self.question=self.column.value;self.question_original=self.column.original
            if(self.question_original.original_digest!=self.question_expected_digest or tuple(self.question["source_refs"])!=self.roots):
                raise ValueError("Joint selected cause changed actual fixed question or Sources")
            # Joint question_key is its signed plan predicate, not the inbound
            # ticket's question_key. The signed attention_ticket mapping above
            # is its exact relation to this C02 issuance.
            self.registration=_FairDomainRegistrationMetadataV1(self.task,self.registration_operation)
            self.column=None;self.phase="joint_registration";return
        if self.phase=="joint_registration":
            self.registration.advance(meter)
            if not self.registration.complete:return
            if(self.registration.header[:2]!=("d07","input:prepare_joint_external_semantic_question_v1")
                    or self.registration.payload["parent_budget"]!=self.parent_ref):
                raise ValueError("Joint cause lost actual signed producer parent/operation")
            self.authority=self._decode(self.registration.payload["authority"],AuthorityContext)
            self.groups=((self.authority.purpose,self.authority.audience),)
            owner=r.owner_binding
            self.owner_allowed=(self.authority.actor==owner.actor and self.authority.namespace==r.namespace
                and all(p in owner.purposes and set(a)<=set(owner.audiences)for p,a in self.groups))
            self.source_task=_D07FairSourceMetadataV1(r,self.roots,self.groups)
            self.budget_task=_D07FairBudgetMetadataV1(self.task,self.parent_ref,self.parent_digest,self.deadline)
            self.phase="sources";return
        if self.phase=="existing_grant":
            # A signed existing preparation is restored under its actual old
            # parent. An absent allocation is never filled from this trigger.
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_grants",("version",),
                "lease_id=? ORDER BY version DESC",(self.parent_ref,))
            if row is None:raise ValueError("existing fair preparation lost actual original parent grant")
            self.column=_FairJSONMetadataColumnV1(self.task,"runtime_budget_grants","grant_json",("lease_id","version"),
                (self.parent_ref,row[0]),lambda path:True);self.phase="existing_grant_value";return
        if self.phase=="existing_grant_value":
            if not self.column.advance(meter):return
            from .issuers import _decode_grant
            self.parent_digest=canonical_digest(_decode_grant(canonical_serialize(self.column.value)))
            self.groups=((self.authority.purpose,self.authority.audience),)
            owner=r.owner_binding
            self.owner_allowed=(self.authority.actor==owner.actor and self.authority.namespace==r.namespace
                and all(p in owner.purposes and set(a)<=set(owner.audiences)for p,a in self.groups))
            self.source_task=_D07FairSourceMetadataV1(r,self.roots,self.groups)
            self.budget_task=_D07FairBudgetMetadataV1(self.task,self.parent_ref,self.parent_digest,self.deadline)
            self.column=None;self.phase="sources";return
        raise ValueError("unregistered fair ticket cause metadata phase")
    def _workflow_ceiling_v1(self):
        from ..host.model_workflows_v6 import AdminModelWorkflowsV6
        from ..host.model_workflows_v9 import AdminModelWorkflowsV9
        from ..host.model_workflows_v10 import AdminModelWorkflowsV10
        if self.ticket.ticket_id in self.task.generic_prepared:return {}
        w=self.reader.bundle.model_workflows
        if w is None:return None
        if self.family=="ordinary_continuity":
            if type(w)is not AdminModelWorkflowsV10:return None
            workflow=w.ordinary_continuity_screen if self.attention["phase"]=="ordinary_screen"else w.ordinary_continuity_deep
        elif self.family=="general_growth":
            if not isinstance(w,AdminModelWorkflowsV6):return None
            workflow=w.growth_cognition
        elif self.family=="artifact_observation":
            if not isinstance(w,AdminModelWorkflowsV9):return None
            workflow=w.artifact_observation_cognition
        else:workflow=w.d07_cognition
        return None if workflow is None else dict(workflow.quote_ceiling)
    def _finish_v1(self):
        from .d07_fair_service_dispatch_v1 import D07SelectedConcernCauseV1
        r=self.reader;t=self.ticket
        status="waiting";reason="actual_complete_executable_cause"
        if t.cancel_refs or not t.eligible:status,reason="cancelled","actual_current_ticket_cancel_or_ineligible"
        elif r.now_utc>=min(t.valid_until,self.budget_task.deadline):status,reason="expired","actual_original_ticket_or_parent_deadline"
        elif not t.resources_available or not self.owner_allowed or not self.source_task.allowed or not self.budget_task.allowed:
            status,reason="resource_blocked","actual_current_Source_Owner_or_parent_resource_metadata"
        if self.family=="general_growth"and self.cause["authorization_status"]!="qualified":
            status,reason="resource_blocked","actual_signed_outcome_authorization_status"
        if self.recovery is not None:operation,activity,prepared,job=self.recovery.result
        else:
            from .d07_single_event_review_v1 import single_event_review_service_operation_id_v1
            if self.family=="general_growth":
                q=self.question
                activity="general-growth-cognition:"+canonical_digest((r.namespace,q["outcome_original_digest"],q["target_block"],q["scope"]))[:48]
                operation="general-growth-serve:"+canonical_digest((r.namespace,activity))[:48]
            elif self.family=="ordinary_continuity":
                from .d07_ordinary_continuity_attention_v1 import ordinary_continuity_attention_ids_v1
                activity=ordinary_continuity_attention_ids_v1(r.namespace,self.question["question_key"])["activity"]
                operation="ordinary-continuity-serve:"+self.question_original.original_ref.removeprefix("ordinary-continuity-question:")
            elif self.family=="single_event_review":
                from .d07_single_event_review_v1 import single_event_review_attention_ids_v1
                a=self._decode(self.attention,_profile("review_attention"));operation=single_event_review_service_operation_id_v1(a)
                activity=single_event_review_attention_ids_v1(r.namespace,a.case_original)["activity"]
            elif self.family=="joint_external":
                activity="joint-cognition:"+canonical_digest((r.namespace,self.question_original.original_ref))[:48]
                operation=activity
            else:
                from .artifact_phase_observation_v1 import artifact_observation_ids_v1,PrepareArtifactPhaseObservationRequestV1
                req=self._decode(self.attention["request"],PrepareArtifactPhaseObservationRequestV1)
                ids=artifact_observation_ids_v1(req.selector,req.condition_id);operation=ids["operation"];activity=AtomKey.from_token(req.selector.task.cycle_job_ref).owner.subject
            prepared=job=None
        cause=D07SelectedConcernCauseV1(r.namespace,t.category,GraphVersion(self.atom.key,self.atom.revision),
            canonical_digest(self.atom.value),self.native_original,canonical_digest(self.registration.receipt),
            self.family,self.execution_original,self.question_original,
            None if self.recovery is None else ProductionOriginalRefV1("d07.prepare_commit",self.recovery.original.original_ref,self.recovery.commit_header[0]),
            self.roots,self.source_task.versions,
            self.authority,activity,operation,"concern",self.parent_ref,self.parent_digest,
            self.budget_task.ancestry,min(t.valid_until,self.budget_task.deadline),prepared,job)
        self.result=(self.atom,cause,status,self.source_task.versions,reason);self.complete=True
    def _advance_c02_v1(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..host.post_c02_attention_driver import post_c02_attention_operation_id
        r=self.reader
        row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d07_attention_issuance_v1",
            ("operation_id","c02_operation_id","bundle_digest"),"bot=? AND persona=? AND source_ref=? AND operation_id>? ORDER BY operation_id",
            (*r.namespace.as_tuple,self.ticket.causal_root,self.c02_after))
        if row is not None:
            self.c02_after=row[0]
            if(self.ticket.ticket_id=="attention:"+canonical_digest({"operation_id":row[0]})[:48]
                    and row[0]==post_c02_attention_operation_id(row[1],self.ticket.causal_root)):
                self.c02_matches.append(row)
            return
        if len(self.c02_matches)!=1:raise ValueError("unknown fair ticket has no actual adopted typed issuance")
        self.issuance=self.c02_matches[0];self.issuance_receipt=_FairBundleReceiptMetadataV1(self.task,self.issuance[0])
        self.phase="c02_receipt"
    def release_v1(self):
        if self.source_task is not None:self.source_task.release_v1()


class _D07FairPreparedRecoveryV1:
    def __init__(self,task,prepared,original,cause=None):
        self.task,self.reader,self.prepared,self.original,self.cause=task,task.reader,prepared,original,cause
        self.phase="commit_header";self.column=None;self.complete=False;self.result=None;self.columns={}
        self.commit_header=self.commit=self.bundle=self.receipt=self.birth=None;self.current_job=None
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
        from .d11_types import RuntimeJobValue,runtime_job_key
        from .d07_execution_v1 import SIGN_KIND,d07_execution_ids_v1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        r=_reader(self.reader,meter);p=self.prepared;ref=self.original.original_ref
        key=(*r.namespace.as_tuple,"prepare_commit",ref);operation="d07-prepare:"+p["operation_id"]
        if self.phase=="commit_header":
            self.commit_header=_runtime_bounded_fixed_row_v3(r.db,meter,_D07,("payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",key)
            if self.commit_header is None:raise ValueError("fair existing Prepared has no actual signed prepare_commit")
            keep={"schema","prepared_digest","prepare_operation_id","graph_receipt_digest","writes_digest"}
            self.column=_FairJSONMetadataColumnV1(self.task,_D07,"payload_json",("bot","persona","kind","original_ref"),key,
                lambda path:not path or path[0]in keep);self.phase="commit";return
        if self.column is not None:
            if not self.column.advance(meter):return
            column=self.column;self.columns[self.phase]=column;self.column=None
            if self.phase=="commit":
                if(column.sha256!=self.commit_header[0]or column.fields_seen!={"schema","prepared_digest","prepare_operation_id",
                        "graph_receipt_digest","writes_digest","post_read_rows","post_query_inventory_json"}):
                    raise ValueError("fair prepare_commit has another canonical closed metadata schema")
                r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                    canonical_serialize((r.namespace,"prepare_commit",ref,self.commit_header[0])),self.commit_header[1])
                self.commit=column.value
                if(self.commit["schema"]!="d07.preparation-commit.v1"or self.commit["prepared_digest"]!=self.original.original_digest
                        or self.commit["prepare_operation_id"]!=operation):
                    raise ValueError("fair existing preparation changed its original signed commit identity")
                self.phase="bundle";return
            if self.phase=="receipt":self.phase="event";return
            if self.phase=="reads":self.phase="revisions";return
            if self.phase=="revisions":
                self.receipt=reconstruct_graph_bundle_commit_receipt_v1(r.namespace,operation,
                    (*self.bundle,canonical_serialize(self.columns["receipt"].value)),
                    (canonical_serialize(self.columns["reads"].value),canonical_serialize(column.value),self.event_epoch))
                if canonical_digest(self.receipt)!=self.commit["graph_receipt_digest"]:
                    raise ValueError("fair signed prepare_commit differs from official actual CommitReceipt")
                jobs=tuple(v for v in self.receipt.write_versions if v.key.type_name=="runtime.job"and v.key.name==p["job_id"])
                if len(jobs)!=1:raise ValueError("fair Prepared lacks unique actual job birth in its W01 receipt")
                self.birth=jobs[0];self.phase="birth_header";return
            if self.phase=="birth":
                if column.fields_seen!={f.name for f in fields(RuntimeJobValue)}:
                    raise ValueError("fair job birth has another exact typed metadata schema")
                self.born=decode_typed_production_value_v1(column.value,RuntimeJobValue)
                if((self.born.bot_id,self.born.persona_id,self.born.operation_id,self.born.activity_id,self.born.job_id,self.born.phase,
                        self.born.work_kind,self.born.fence,self.born.cancel_epoch)!=
                        (*r.namespace.as_tuple,p["operation_id"],p["activity_id"],p["job_id"],"queued","d07."+p["work_kind"],0,0)):
                    raise ValueError("fair signed Prepared has another actual typed job birth")
                if self.cause is not None and self.born.parent_budget_lease_ref!=self.cause.parent_ref:
                    raise ValueError("fair existing Prepared borrowed another ticket's parent")
                self.phase="job";return
            if self.phase=="continuation":
                if column.sha256!=self.current_projection.value["continuation_digest"]:
                    raise ValueError("fair current job continuation differs from actual typed Graph projection")
                data=column.value
                if(data["input_digest"]!=p["stage_input_digest"]or data["prepared_job_id"]!=p["job_id"]
                        or data["call_id"]!=p["call_id"]or data["work_kind"]!=p["work_kind"]):
                    raise ValueError("fair current job continuation changed signed preparation identity")
                self.continuation=data
                if self.cause is not None:
                    choice=data["choice"]
                    if choice is None or choice["ticket_id"]!=self.cause.ticket.ticket_id:
                        raise ValueError("fair recovery belongs to another actual chosen ticket")
                self.result=(p["operation_id"],p["activity_id"],self.original,
                    GraphVersion(self.current_projection.key,self.current_projection.revision))
                self.complete=True;return
        if self.phase=="bundle":
            self.bundle=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",
                (*r.namespace.as_tuple,operation))
            if self.bundle is None or self.bundle[1:3]!=(p["activity_id"],None):
                raise ValueError("fair Prepared has no actual preparation bundle ledger")
            self.column=_FairJSONMetadataColumnV1(self.task,"graph_bundle_operations","receipt_json",
                ("bot","persona","operation_id"),(*r.namespace.as_tuple,operation),lambda path:True)
            self.phase="receipt";return
        if self.phase=="event":
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_events",("epoch_revision",),
                "bot=? AND persona=? AND session=? AND event_id=?",(*r.namespace.as_tuple,p["activity_id"],operation))
            if row is None:raise ValueError("fair Prepared lost its actual graph event")
            self.event_epoch=row[0];self.phase="reads";return
        if self.phase in{"reads","revisions"}:
            self.column=_FairJSONMetadataColumnV1(self.task,"graph_events",self.phase,("bot","persona","session","event_id"),
                (*r.namespace.as_tuple,p["activity_id"],operation),lambda path:True);return
        if self.phase=="birth_header":
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_history",("valid","event_bot","event_persona","event_id","value_cell_id"),
                "token=? AND revision=?",(self.birth.key.token,self.birth.revision))
            if row is None or row[:4]!=(1,*r.namespace.as_tuple,operation):
                raise ValueError("fair Prepared lost actual same-event queued job history")
            self.column=_FairJSONMetadataColumnV1(self.task,"graph_history","value",("token","revision"),
                (self.birth.key.token,self.birth.revision),lambda path:True,cell_id=row[4])
            self.phase="birth";return
        if self.phase=="job":
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_jobs",
                ("operation_id","activity_id","bot_id","persona_id","work_kind","budget_ref","deadline_utc","phase"),
                "job_id=?",(p["job_id"],))
            if(row is None or row[:7]!=(p["operation_id"],p["activity_id"],*r.namespace.as_tuple,"d07."+p["work_kind"],
                    self.born.parent_budget_lease_ref,self.born.deadline_utc)):
                raise ValueError("fair recovery lost actual current persistent job/parent identity")
            self.current_job=row
            self.projection_task=_FairGraphMetadataReadV1(self.task,runtime_job_key(*r.namespace.as_tuple,p["activity_id"],p["job_id"]))
            self.phase="projection";return
        if self.phase=="projection":
            self.projection_task.advance(meter)
            if not self.projection_task.complete:return
            self.current_projection=self.projection_task.atom
            if(not self.current_projection.valid or self.current_projection.value["phase"]!=self.current_job[7]
                    or self.current_projection.value["operation_id"]!=p["operation_id"]
                    or self.current_projection.value["parent_budget_lease_ref"]!=self.born.parent_budget_lease_ref):
                raise ValueError("fair existing job metadata diverged from its Graph current control head")
            keep={"choice","request","input_digest","prepared_job_id","call_id","work_kind","original_ref"}
            self.column=_FairJSONMetadataColumnV1(self.task,"runtime_jobs","continuation_json",("job_id",),(p["job_id"],),
                lambda path:not path or path[0]in keep and(path[0]!="request"or len(path)<=1
                    or path[1]in{"category","trigger_original_ref","reflection_ref","cognitive_terminal_ref","simulation_request_ref"}))
            self.phase="continuation";return
        raise ValueError("unregistered fair Prepared recovery metadata phase")


class _FairBundleReceiptMetadataV1:
    def __init__(self,task,operation_id):
        self.task,self.reader,self.operation_id=task,task.reader,operation_id
        self.phase="bundle";self.column=None;self.columns={};self.complete=False;self.receipt=None
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
        r=_reader(self.reader,meter);key=(*r.namespace.as_tuple,self.operation_id)
        if self.phase=="bundle":
            self.bundle=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",key)
            if self.bundle is None:raise ValueError("fair original lost its actual W01 bundle")
            self.phase="receipt";return
        if self.column is not None:
            if not self.column.advance(meter):return
            self.columns[self.phase]=self.column;self.column=None
            self.phase={"receipt":"event","reads":"revisions","revisions":"finish"}[self.phase];return
        if self.phase=="event":
            row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_events",("epoch_revision",),
                "bot=? AND persona=? AND session=? AND event_id=?",(*r.namespace.as_tuple,self.bundle[1],self.operation_id))
            if row is None:raise ValueError("fair original lost its actual graph event")
            self.event_epoch=row[0];self.phase="reads";return
        if self.phase in{"receipt","reads","revisions"}:
            if self.phase=="receipt":table="graph_bundle_operations";keys=("bot","persona","operation_id");values=key;column="receipt_json"
            else:table="graph_events";keys=("bot","persona","session","event_id");values=(*r.namespace.as_tuple,self.bundle[1],self.operation_id);column=self.phase
            self.column=_FairJSONMetadataColumnV1(self.task,table,column,keys,values,lambda path:True);return
        if self.phase=="finish":
            self.receipt=reconstruct_graph_bundle_commit_receipt_v1(r.namespace,self.operation_id,
                (*self.bundle,canonical_serialize(self.columns["receipt"].value)),
                (canonical_serialize(self.columns["reads"].value),canonical_serialize(self.columns["revisions"].value),self.event_epoch))
            if self.receipt.status!="committed":raise ValueError("fair original has no actual committed receipt")
            self.complete=True;return
        raise ValueError("unregistered fair bundle receipt metadata phase")


class _D07FairTriggerCauseReadV1:
    def __init__(self,task):
        from .d07_fair_service_dispatch_v1 import _require_concern_trigger_v1
        self.task,self.reader=task,task.reader
        self.trigger=_require_concern_trigger_v1(task.reader.private_trigger,task.reader.graph,task.reader.bundle)[7]
        profiles={
            "general_growth_attention_available_for_service":(_D07,"general_growth_attention_v1","general_attention"),
            "ordinary_continuity_attention_available_for_service":(_D07,"ordinary_continuity_attention_v1","ordinary_attention"),
            "single_event_review_attention_available_for_service":(_D07,"single_event_review_attention_v1","review_attention"),
            "artifact_phase_observation_available":(_LIFE,"artifact_phase_observation_basis_v1","artifact_basis"),
            "joint_external_semantic_question_requires_fair_cognition":(_D07,"joint_external_semantic_basis_v1","joint_basis"),
        }
        spec=profiles.get(self.trigger.event_kind)
        if spec is None:raise ValueError("actual_registered_fair_terminal_wake_metadata_required")
        self.column=_D07FairSignedMetadataColumnV1(task,spec[0],spec[1],self.trigger.trigger_original.original_ref,spec[2])
        self.registration=None;self.birth=None;self.category=None;self.complete=False
    def category_v1(self):
        if not self.complete or self.category is None:raise ValueError("fair trigger category lacks actual completed native metadata")
        return self.category
    def advance(self,meter):
        _reader(self.reader,meter)
        if not self.column.complete:
            self.column.advance(meter);return
        if self.column.original.original_digest!=self.trigger.trigger_original.original_digest:
            raise ValueError("fair scheduling trigger changed its actual signed original digest")
        value=self.column.value
        operation=value["producing_operation_id"]if self.column.profile=="joint_basis"else value["registration_operation_id"]
        if operation!=self.trigger.causal_operation_id:
            raise ValueError("fair trigger changed its actual immutable registration operation")
        if self.registration is None:self.registration=_FairDomainRegistrationMetadataV1(self.task,operation)
        self.registration.advance(meter)
        if not self.registration.complete:return
        if("registration_receipt_digest"in value and canonical_digest(self.registration.receipt)!=value["registration_receipt_digest"]):
            raise ValueError("fair trigger signed original does not match its actual W01 registration receipt")
        expected={
            "general_attention":("d07","register_general_growth_attention_v1"),
            "ordinary_attention":("d07","register_ordinary_continuity_attention_v1"),
            "review_attention":("d07","register_single_event_review_attention_v1"),
            "artifact_basis":("d07","prepare_artifact_phase_observation_v1"),
            "joint_basis":("d07","input:prepare_joint_external_semantic_question_v1"),
        }[self.column.profile]
        if self.registration.header[:2]!=expected:
            raise ValueError("fair trigger changed its actual registered producer operation")
        if self.column.profile=="joint_basis":
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            gv=decode_typed_production_value_v1(value["request"]["attention_ticket"],GraphVersion)
            if self.birth is None:self.birth=_FairGraphMetadataReadV1(self.task,gv.key,revision=gv.revision)
            self.birth.advance(meter)
            if not self.birth.complete:return
            if not self.birth.atom.valid or self.birth.head[4]!=value["request"]["attention_issuance_operation_id"]:
                raise ValueError("Joint fairness trigger lost actual same-issuance typed ticket")
            self.category=self.birth.atom.value["category"]
        else:self.category="background"
        self.complete=True


class _D07FairPolicyMetadataV1:
    def __init__(self,task):
        from ..domains.d12.types import active_scheme_head_key
        self.task,self.reader=task,task.reader;self.key=active_scheme_head_key(task.reader.namespace)
        self.graph_task=_FairGraphMetadataReadV1(task,self.key);self.phase="head"
        self.complete=False;self.result=None;self.column=None;self.version=None;self.expected_digest=None;self.steps=0
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..domains.d07 import AttentionPolicy
        from ..domains.d12.types import ActiveSchemeHeadV1
        from .d12_current_d07_policy_v1 import D12CurrentD07PolicyReadV1
        from .d12_domain_scheme_compile_v1 import ATTENTION_POLICY_FIELD,D12AttentionPolicyCandidateV1
        from ..domains.d12.scheme_command import D12DomainCompileReceiptV1
        from .scheme_original_store_v1 import _compiled,_compilation_binding,CompilationOriginalV1
        r=_reader(self.reader,meter)
        if self.phase in{"head","history"}:
            self.graph_task.advance(meter)
            if not self.graph_task.complete:return
            atom=self.graph_task.atom
            if self.version is None:
                self.version=GraphVersion(self.key,atom.revision)
                if atom.revision==0:
                    self.result=D12CurrentD07PolicyReadV1(AttentionPolicy.default(),self.version,None,None);self.complete=True;return
                self.current_digest=self.graph_task.digest
                self.graph_task=_FairGraphMetadataReadV1(self.task,self.key,revision=atom.revision)
                self.phase="history";return
            if not atom.valid:raise ValueError("fair policy adopted scheme history is unavailable")
            raw=atom.value;self.head=ActiveSchemeHeadV1(**{k:v for k,v in raw.items()if k!="schema"})
            if(self.head.scope!=r.namespace.persona_id or self.head.generation!=atom.revision
                    or self.expected_digest is not None and self.head.compiled_digest!=self.expected_digest):
                raise ValueError("fair policy changed its actual inherited scheme metadata chain")
            if self.steps==0 and self.graph_task.digest!=self.current_digest:
                raise ValueError("fair policy head lacks its matching whole canonical history")
            self.steps+=1
            if self.steps>4096:raise ValueError("fair inherited policy exceeds its existing 4096-adoption bound")
            if self.head.adoption_kind=="initial":
                self.result=D12CurrentD07PolicyReadV1(AttentionPolicy.default(),self.version,None,None);self.complete=True;return
            self.phase="compiled_header";return
        if self.phase=="compiled_header":
            self.original_header=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d12_compilation_originals_v1",("original_sha256",),
                "bot=? AND persona=? AND compiled_digest=?",(*r.namespace.as_tuple,self.head.compiled_digest))
            self.operation_header=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d12_compilation_operations_v1",
                ("operation_id","source_input_digest","budget_receipt_digest","binding_digest"),
                "bot=? AND persona=? AND compiled_digest=? ORDER BY operation_id",
                (*r.namespace.as_tuple,self.head.compiled_digest))
            if self.original_header is None or self.operation_header is None:raise ValueError("fair D07 policy lacks actual compilation original")
            self.column=_FairJSONMetadataColumnV1(self.task,"graph_d12_compilation_originals_v1","original_json",
                ("bot","persona","compiled_digest"),(*r.namespace.as_tuple,self.head.compiled_digest),lambda path:True)
            self.phase="compiled";return
        if self.phase=="compiled":
            if not self.column.advance(meter):return
            if self.column.sha256!=self.original_header[0]:raise ValueError("fair compiled policy failed whole canonical EOF")
            compiled=_compiled(canonical_serialize(self.column.value));op,input_digest,budget_digest,binding=self.operation_header
            original=CompilationOriginalV1(op,compiled,input_digest,budget_digest)
            if(compiled.namespace!=r.namespace or _compilation_binding(original)!=binding
                    or (compiled.draft_ref,compiled.draft_revision,compiled.draft_digest,compiled.active_head_revision+1)!=
                    (self.head.draft_ref,self.head.draft_revision,self.head.draft_digest,self.head.generation)
                    or len({item.domain for item in compiled.domain_receipts})!=len(compiled.domain_receipts)):
                raise ValueError("fair policy compilation differs from its actual inherited head")
            selected=tuple(x for x in compiled.domain_receipts if x.domain=="d07")
            if not selected:
                self.expected_digest=self.head.previous_compiled_digest
                self.graph_task=_FairGraphMetadataReadV1(self.task,self.key,revision=self.head.generation-1)
                self.phase="history";self.column=None;return
            if len(selected)!=1 or selected[0].field_names!=(ATTENTION_POLICY_FIELD,):
                raise ValueError("fair D07 policy has another actual compiled field selection")
            self.selected=selected[0];self.compiled=compiled;self.phase="candidate_header";self.column=None;return
        if self.phase=="candidate_header":
            self.candidate_header=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d12_domain_candidates_v1",
                ("domain","field_input_digest","proposal_schema_hash","candidate_digest","candidate_sha256"),
                "bot=? AND persona=? AND candidate_ref=?",(*r.namespace.as_tuple,self.selected.candidate_ref))
            if self.candidate_header is None:raise ValueError("fair current D07 policy candidate is missing")
            self.column=_FairJSONMetadataColumnV1(self.task,"graph_d12_domain_candidates_v1","candidate_json",
                ("bot","persona","candidate_ref"),(*r.namespace.as_tuple,self.selected.candidate_ref),lambda path:True)
            self.phase="candidate";return
        if self.phase=="candidate":
            if not self.column.advance(meter):return
            raw=dict(self.column.value);namespace=dict(raw["namespace"]);policy=dict(raw["policy"])
            if(raw.pop("$type",None)!="sylanne3.runtime.d12_domain_scheme_compile_v1.D12AttentionPolicyCandidateV1"
                    or namespace.pop("$type",None)!="sylanne3.runtime_contracts.NamespaceId"
                    or policy.pop("$type",None)!="sylanne3.domains.d07.AttentionPolicy"
                    or self.column.sha256!=self.candidate_header[4]):
                raise ValueError("fair D07 policy candidate has another whole canonical typed schema")
            candidate=D12AttentionPolicyCandidateV1(NamespaceId(**namespace),raw["domain"],tuple(raw["field_names"]),
                raw["field_input_digest"],raw["proposal_schema_hash"],AttentionPolicy(**policy),raw["candidate_digest"],raw["status"])
            expected=D12DomainCompileReceiptV1(candidate.domain,candidate.field_names,candidate.field_input_digest,
                "d12-domain-candidate:"+candidate.candidate_digest,candidate.proposal_schema_hash)
            if(candidate.namespace!=r.namespace or self.selected!=expected
                    or canonical_serialize(candidate)!=canonical_serialize(self.column.value)
                    or self.candidate_header[:4]!=(candidate.domain,candidate.field_input_digest,candidate.proposal_schema_hash,candidate.candidate_digest)):
                raise ValueError("fair policy is not the actual persisted compiled D07 selection")
            self.result=D12CurrentD07PolicyReadV1(candidate.policy,self.version,self.compiled.compiled_digest,candidate.candidate_digest)
            self.complete=True;return
        raise ValueError("unregistered fair current policy metadata phase")
