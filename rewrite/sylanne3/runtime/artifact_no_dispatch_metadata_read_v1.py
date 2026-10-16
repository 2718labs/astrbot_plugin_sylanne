"""Whole EOF over the original C4 financial leaves; no Goal or Source body."""
from dataclasses import dataclass,asdict
from weakref import WeakKeyDictionary
from contextvars import ContextVar
from contextlib import contextmanager

_FINANCIAL_ORIGINALS=WeakKeyDictionary()
_FINANCIAL_COMMIT=ContextVar('artifact-no-dispatch-financial-commit.v1',default=None)
from hashlib import sha256
import json
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.c09_selected_history_v3 import _read_one
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,finish_runtime_storage_operation_v3
from .artifact_no_dispatch_metadata_invocation_v1 import (
    ActualArtifactNoDispatchMetadataInvocationV1,require_artifact_no_dispatch_metadata_invocation_v1)


class _FinancialCanonicalColumnV1:
    def __init__(self,work,*,table,column,where,parameters,expected_digest=None,cell_id=None,owner_ref=None):
        if type(work) is not ArtifactNoDispatchMetadataReadWorkV1 or work.closed:
            raise AuthorityUnavailable("actual fixed Artifact financial Work required")
        work.require_column_recipe_v1(table,column,where,parameters)
        self.work,self.table,self.column,self.where,self.parameters=work,table,column,where,parameters
        self.expected_digest,self.cell_id,self.owner_ref=expected_digest,cell_id,owner_ref
        self.offset,self.ordinal,self.length=0,0,None
        self.header,self.root,self.parser=None,None,None
        self.data=bytearray();self.complete=False;self.sha256=None
    def advance_v1(self,meter):
        i=self.work.invocation;db=i.actual_db
        require_artifact_no_dispatch_metadata_invocation_v1(i,phase="before")
        if self.length is None:
            if self.cell_id is not None:
                from ..runtime_storage_v3 import read_selected_runtime_cell_origin_v3
                self.header=meter.read_fixed_row(db,"segmented_cells_v1",
                    ("codec_id","erasure_owner_ref","producer_operation_id","total_bytes","segment_count",
                     "payload_sha256","ordered_segment_root","origin_scope_digest"),"cell_id=?",(self.cell_id,))
                if self.header is None or self.header[0] not in {"canonical-json.ascii.v1","canonical-json.utf8.v1"} or self.header[1]!=self.owner_ref:
                    raise AuthorityUnavailable("actual original financial cell metadata differs")
                read_selected_runtime_cell_origin_v3(db,selected_basis=self.work.owner_work.view,role="graph",
                    cell_id=self.cell_id,header=self.header,meter=meter)
                self.length=self.header[3];self.root=canonical_digest(("sylanne3.segmented-cell-genesis.v1",self.cell_id))
                self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.header[0]=="canonical-json.ascii.v1")
            else:
                with legacy_cell_read_transaction_v2(db):
                    _,self.length,kind=read_legacy_sql_cell_fragment_v2(db,table=self.table,column=self.column,
                        where=self.where,parameters=self.parameters,start=0,length=0,meter=meter)
                if kind!="text":raise AuthorityUnavailable("financial original column is not canonical text")
                self.parser=C09CanonicalJSONStreamV2(ensure_ascii=self.table=="runtime_jobs")
            if self.length>131072:raise AuthorityUnavailable("fixed financial original exceeds its installed metadata range")
        if self.offset<self.length:
            if self.cell_id is not None:
                row=meter.read_fixed_row(db,"segmented_cell_segments_v1",("byte_offset","payload","payload_sha256"),
                    "cell_id=? AND ordinal=?",(self.cell_id,self.ordinal))
                if row is None or row[0]!=self.offset or type(row[1]) is not bytes or not 0<len(row[1])<=16384 or sha256(row[1]).hexdigest()!=row[2]:
                    raise AuthorityUnavailable("financial canonical segment changed")
                chunk=row[1];self.root=canonical_digest(("sylanne3.segmented-cell-link.v1",self.root,
                    self.cell_id,self.ordinal,self.offset,len(chunk),row[2]));self.ordinal+=1
            else:
                with legacy_cell_read_transaction_v2(db):
                    chunk,length,kind=read_legacy_sql_cell_fragment_v2(db,table=self.table,column=self.column,
                        where=self.where,parameters=self.parameters,start=self.offset,
                        length=min(16384,self.length-self.offset),meter=meter)
                if length!=self.length or kind!="text":raise AuthorityUnavailable("financial column changed during EOF")
            self.parser.feed(chunk,lambda event:None)
            self.data.extend(chunk);self.offset+=len(chunk);return
        result=self.parser.finish()
        if (result.byte_count!=self.length or self.expected_digest is not None and result.sha256!=self.expected_digest
                or self.cell_id is not None and (self.ordinal!=self.header[4] or self.root!=self.header[6]
                    or result.sha256!=self.header[5]
                    or _read_one(db,"SELECT 1 FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1",
                        (self.cell_id,self.ordinal),meter) is not None)):
            raise AuthorityUnavailable("financial whole canonical EOF/root/digest differs")
        self.sha256,self.complete=result.sha256,True
    def value_v1(self):
        if not self.complete:raise AuthorityUnavailable("financial column EOF not complete")
        value=json.loads(bytes(self.data))
        encoded=(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False)
            if self.table=="runtime_jobs" else canonical_serialize(value))
        if encoded.encode("utf8")!=bytes(self.data):
            raise AuthorityUnavailable("financial canonical original roundtrip differs")
        return value


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class ArtifactNoDispatchFinancialOriginalsV1:
    prepared: object
    prepared_signature: str
    intent: object
    settlement: object | None
    quote_wire: object
    quote_signature: str
    reservation: tuple
    lease_wire: object
    job_metadata: tuple
    cancelled_request: object | None
    cost_receipt: object | None
    original_job: object
    immutable_rows: tuple


class ArtifactNoDispatchMetadataReadWorkV1:
    def __init__(self,invocation,*,owner_proof,owner_work,owner_facts):
        require_artifact_no_dispatch_metadata_invocation_v1(invocation,phase="before")
        owner_facts.require_for_v3(owner_proof)
        self.invocation,self.owner_proof,self.owner_work,self.owner_facts=invocation,owner_proof,owner_work,owner_facts
        self.phase,self.column,self.complete,self.closed="prepared_locator",None,False,False
        self.prepared,self.prepared_signature,self.intent,self.settlement=None,None,None,None
        self.quote_wire,self.quote_signature,self.reservation,self.lease_wire,self.job_metadata=None,None,None,{},None
        self.cost_receipt=None;self.lease_column_index=0
        self.pending,self.result,self.allowed_columns=None,None,set()
        self.payload_row=None
        self.original_job=None;self.job_row=None;self.job_column_index=0;self.job_values={};self.immutable_rows=[]
        invocation.retained_operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        import sys
        from .artifact_no_dispatch_metadata_invocation_v1 import _actual_metadata_heap_v1
        from ..authority_service.owner_location_read_v3 import _owner_location_parser_heap_v3
        seen={id(self)}
        amount=sys.getsizeof(self)+sys.getsizeof(self.__dict__)
        for name,value in self.__dict__.items():
            amount+=_actual_metadata_heap_v1(name,seen)
            if name not in {"invocation","owner_proof","owner_work","owner_facts","column"}:
                amount+=_actual_metadata_heap_v1(value,seen)
        if self.column is not None:
            seen.add(id(self.column))
            amount+=sys.getsizeof(self.column)+sys.getsizeof(self.column.__dict__)
            for name,value in self.column.__dict__.items():
                amount+=_actual_metadata_heap_v1(name,seen)
                if name not in {"work","parser"}:amount+=_actual_metadata_heap_v1(value,seen)
            if self.column.parser is not None:
                amount+=_owner_location_parser_heap_v3(self.column.parser,seen)
        return amount
    def require_column_recipe_v1(self,table,column,where,parameters):
        if (table,column,where,tuple(parameters)) not in self.allowed_columns:
            raise AuthorityUnavailable("unregistered financial original column recipe")
    def _column_v1(self,**kwargs):
        self.allowed_columns.add((kwargs["table"],kwargs["column"],kwargs["where"],tuple(kwargs["parameters"])))
        self.column=_FinancialCanonicalColumnV1(self,**kwargs)
    def advance_v1(self,meter):
        if self.closed or self.complete:raise AuthorityUnavailable("financial Work is not in an advancing phase")
        operation=self.invocation.retained_operation
        operation.reserve_retained_state_growth_v3(self,524288)
        try:return self._advance_reserved_v1(meter)
        finally:operation.finish_retained_state_growth_v3(self)
    def _advance_reserved_v1(self,meter):
        i=self.invocation;db=i.actual_db;ns=i.namespace.as_tuple;intent=i.original_intent
        i.require_current_v1(phase="before")
        self.owner_facts.require_for_v3(self.owner_proof)
        if self.column is not None:
            self.column.advance_v1(meter)
            if not self.column.complete:return
            raw=self.column.value_v1();self.column=None
            if self.phase=="prepared":
                from .d11_artifact_draft_model_v1 import (ArtifactDraftModelPreparedV1,ArtifactDraftModelPreparedV2,
                    artifact_draft_model_from_wire_v1,artifact_draft_model_from_wire_v2)
                phase=self.payload_row[0]=="c4_phase_prepared"
                self.prepared=(artifact_draft_model_from_wire_v2(raw,ArtifactDraftModelPreparedV2)
                    if phase else artifact_draft_model_from_wire_v1(raw,ArtifactDraftModelPreparedV1))
                from .d11_life_preparation_v1 import SIGN_KIND
                i.runtime.issuer._signer.verify(SIGN_KIND,canonical_serialize((i.namespace,self.payload_row[0],
                    self.prepared.job_id,self.prepared.digest)),self.payload_row[3])
                if (self.prepared.namespace,self.prepared.job_id,self.prepared.call_id,self.prepared.digest,
                        self.prepared.parent_budget_lease_ref,self.prepared.reservation_digest)!=(
                        i.namespace,intent.job_id,intent.call_id,intent.binding_digest,
                        intent.budget_lease_id,intent.budget_reservation_digest):
                    raise AuthorityUnavailable("financial prepared EOF changed its actual original Core tuple")
                self.prepared_signature=self.payload_row[3];self.phase="call_locator"
            elif self.phase=="call":
                from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
                from ..authority_service.v2_model_egress_wire import from_wire
                self.intent=from_wire(raw,ModelEgressIntentV1)
                if self.intent!=intent:raise AuthorityUnavailable("financial Graph call differs from original Core call")
                self.phase="settlement_locator"
            elif self.phase=="settlement":
                from .d11_artifact_draft_model_v1 import decode_artifact_model_no_dispatch_v1
                self.settlement=decode_artifact_model_no_dispatch_v1(raw)
                from ..authority_service.v2_model_egress_wire import from_wire
                from ..authority_service.v2_model_egress_contract import ModelNoDispatchWitnessV1
                witness=from_wire(json.loads(self.settlement.witness_json),ModelNoDispatchWitnessV1)
                witness.require_signature_v1(i.runtime.issuer._signer)
                if witness.request.intent!=intent:raise AuthorityUnavailable("financial unsent witness targets another call")
                self.phase="quote_locator"
            elif self.phase=="quote":self.quote_wire=raw;self.phase="reservation_locator"
            elif self.phase=="lease":
                name=("limits","used","reserved","unconfirmed")[self.lease_column_index]
                self.lease_wire[name]=raw;self.lease_column_index+=1;self.phase="lease_columns"
            elif self.phase=="job_column":
                name=("continuation_json","wake_condition_json","operator_versions_json","usage_json")[self.job_column_index]
                self.job_values[name]=raw;self.job_column_index+=1;self.phase="job_columns"
            elif self.phase=="cost":
                self.cost_receipt=raw;self.phase="publish"
            else:raise AuthorityUnavailable("unregistered financial canonical column phase")
            return
        if self.phase=="prepared_locator":
            row=_read_one(db,"SELECT kind,producing_operation_id,payload_digest,signature FROM graph_d11_life_originals_v1 "
                "WHERE bot=? AND persona=? AND original_ref=? AND kind IN ('c4_prepared','c4_phase_prepared') ORDER BY kind LIMIT 1",
                (*ns,intent.job_id),meter)
            if row is None:raise AuthorityUnavailable("actual Core intent has no registered financial C4 original")
            self.payload_row=row
            self.immutable_rows.append((row[0],intent.job_id,row[1],row[2],row[3]))
            self._column_v1(table="graph_d11_life_originals_v1",column="payload_json",
                where="bot=? AND persona=? AND kind=? AND original_ref=?",parameters=(*ns,row[0],intent.job_id),expected_digest=row[2])
            self.phase="prepared";return
        if self.phase in {"call_locator","settlement_locator"}:
            phase=self.prepared.schema=="d11.artifact-draft-phase-model-prepared.v2"
            kind=("c4_phase_call" if phase else "c4_call") if self.phase=="call_locator" else ("c4_phase_no_dispatch" if phase else "c4_no_dispatch")
            ref=intent.call_id
            if self.phase=="settlement_locator":
                from .d11_artifact_draft_model_v1 import artifact_model_no_dispatch_original_ref_v1
                ref=artifact_model_no_dispatch_original_ref_v1(self.prepared)
            row=_read_one(db,"SELECT producing_operation_id,payload_digest,signature FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind=? AND original_ref=?",
                (*ns,kind,ref),meter)
            if row is None:
                if self.phase=="call_locator":raise AuthorityUnavailable("actual sealed C4 call financial original absent")
                self.phase="quote_locator";return
            from .d11_life_preparation_v1 import SIGN_KIND
            i.runtime.issuer._signer.verify(SIGN_KIND,canonical_serialize((i.namespace,kind,ref,row[1])),row[2])
            self.immutable_rows.append((kind,ref,*row))
            self._column_v1(table="graph_d11_life_originals_v1",column="payload_json",
                where="bot=? AND persona=? AND kind=? AND original_ref=?",parameters=(*ns,kind,ref),expected_digest=row[1])
            self.phase="call" if self.phase=="call_locator" else "settlement";return
        if self.phase=="quote_locator":
            row=_read_one(db,"SELECT signature FROM runtime_resource_quotes WHERE quote_id=? AND version=1",(self.prepared.quote_id,),meter)
            if row is None:raise AuthorityUnavailable("original financial quote absent")
            self.quote_signature=row[0]
            self._column_v1(table="runtime_resource_quotes",column="quote_json",where="quote_id=? AND version=1",
                parameters=(self.prepared.quote_id,));self.phase="quote";return
        if self.phase=="reservation_locator":
            self.reservation=_read_one(db,"SELECT digest,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (intent.budget_lease_id,self.prepared.operation_id),meter)
            if self.reservation is None or self.reservation[0]!=intent.budget_reservation_digest:
                raise AuthorityUnavailable("original financial reservation metadata changed")
            row=_read_one(db,"SELECT lease_id,parent_id,bot_id,persona_id,currency,version,state FROM runtime_budget_leases "
                "WHERE lease_id=?",(intent.budget_lease_id,),meter)
            if row is None or row[0]!=intent.budget_lease_id or row[2:4]!=ns:
                raise AuthorityUnavailable("actual original financial parent lease metadata absent")
            self.lease_wire.update(dict(zip(("lease_id","parent_id","bot_id","persona_id","currency","version","state"),row)))
            self.phase="lease_columns";return
        if self.phase=="lease_columns":
            if self.lease_column_index==4:self.phase="job_locator";return
            column=("limits_json","used_json","reserved_json","unconfirmed_json")[self.lease_column_index]
            self._column_v1(table="runtime_budget_leases",column=column,where="lease_id=?",parameters=(intent.budget_lease_id,))
            self.phase="lease";return
        if self.phase=="job_locator":
            self.job_metadata=_read_one(db,"SELECT job_id,operation_id,phase,work_kind,fence,lease_holder,deadline_utc,result_ref "
                "FROM runtime_jobs WHERE job_id=? AND bot_id=? AND persona_id=?",(intent.job_id,*ns),meter)
            if self.job_metadata is None or self.job_metadata[0:2]!=(intent.job_id,self.prepared.operation_id) or self.job_metadata[3]!="artifact_draft_v1":
                raise AuthorityUnavailable("original financial job metadata changed")
            if canonical_digest(self.quote_wire)!=self.prepared.quote_digest or self.job_metadata[6]!=self.prepared.deadline_utc:
                raise AuthorityUnavailable("financial quote/original deadline differs")
            from .issuers import _decode_quote
            quote_json=canonical_serialize(self.quote_wire)
            i.runtime.issuer.resource_issuer._signer.verify("resource-quote.v1",quote_json,self.quote_signature)
            quote=_decode_quote(quote_json)
            if tuple(sorted(quote.ceiling.items()))!=intent.budget_ceiling:
                raise AuthorityUnavailable("financial quote ceiling differs from original Core call")
            self.job_row=_read_one(db,"SELECT job_id,operation_id,activity_id,effect_id,bot_id,persona_id,snapshot_ref,"
                "phase,work_kind,deadline_utc,budget_ref,resource_ref,lease_holder,lease_expires_utc,fence,cancel_epoch,result_ref "
                "FROM runtime_jobs WHERE job_id=? AND bot_id=? AND persona_id=?",(intent.job_id,*ns),meter)
            self.phase="job_columns";return
        if self.phase=="job_columns":
            names=("continuation_json","wake_condition_json","operator_versions_json","usage_json")
            if self.job_column_index<len(names):
                name=names[self.job_column_index]
                if name=="wake_condition_json":
                    presence=_read_one(db,"SELECT wake_condition_json IS NULL FROM runtime_jobs WHERE job_id=?",
                        (intent.job_id,),meter)
                    if presence==(1,):
                        self.job_values[name]=None;self.job_column_index+=1;return
                self._column_v1(table="runtime_jobs",column=name,where="job_id=?",parameters=(intent.job_id,))
                self.phase="job_column";return
            from .jobs import PersistentJob
            r=self.job_row;v=self.job_values
            self.original_job=PersistentJob(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],
                v["continuation_json"],v["wake_condition_json"],r[9],r[10],r[11],v["operator_versions_json"],
                r[12],r[13],r[14],r[15],v["usage_json"],r[16])
            cont=self.original_job.continuation
            from ..domains.d01.production_operations_v1 import plain_v1
            if (cont["prepared_digest"]!=self.prepared.digest or cont["selector"]!=plain_v1(self.prepared.selector)
                    or self.original_job.budget_ref!=intent.budget_lease_id):
                raise AuthorityUnavailable("financial job EOF changed its exact C4 schema/selector/parent")
            self.phase="cost_locator";return
        if self.phase=="cost_locator":
            from .model_cost_settlement import original_model_cost_operation_id_v1
            operation_id=original_model_cost_operation_id_v1(i.namespace,intent.call_id)
            row=_read_one(db,"SELECT operation_id FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*ns,operation_id),meter)
            if row is None:self.phase="publish";return
            self._column_v1(table="graph_bundle_operations",column="receipt_json",
                where="bot=? AND persona=? AND operation_id=?",parameters=(*ns,operation_id))
            self.phase="cost";return
        if self.phase!="publish":raise AuthorityUnavailable("unregistered financial Work phase")
    def complete_quantum_v1(self):
        if self.phase!="publish":return
        i=self.invocation;i.require_current_v1(phase="after")
        cancellation=i.port.read_current_artifact_no_dispatch_cancellation_v1(bundle=i.bundle,grant=i.grant,
            prepared=self.prepared,prepared_signature=self.prepared_signature)
        self.result=ArtifactNoDispatchFinancialOriginalsV1(self.prepared,self.prepared_signature,self.intent,
            self.settlement,self.quote_wire,self.quote_signature,self.reservation,self.lease_wire,self.job_metadata,cancellation,self.cost_receipt,self.original_job,tuple(self.immutable_rows))
        _FINANCIAL_ORIGINALS[self.result]=(i.runtime,i.grant)
        i.retained_operation.refresh_retained_state_v3(self)
        self.complete=True
    def require_result_v1(self):
        if self.closed or not self.complete:raise AuthorityUnavailable("actual financial metadata EOF required")
        self.invocation.require_current_v1(phase="after")
        return self.result
    def close_v1(self):
        if not self.closed:
            self.invocation.retained_operation.unregister_retained_state_v3(self);self.closed=True
            self.column=None
    def cancel_v1(self,error):
        self.close_v1()


@contextmanager
def retain_actual_artifact_no_dispatch_financial_originals_v1(graph, *, runtime, grant):
    from ..authority_service.owner_location_read_v3 import (create_artifact_no_dispatch_owner_caller_proof_v3,
        prepare_owner_location_read_work_v3,owner_location_read_quantum_v3)
    from .artifact_no_dispatch_metadata_invocation_v1 import prepare_artifact_no_dispatch_metadata_invocation_v1
    port=graph._GraphCoordinator__content_fence_v2
    invocation=prepare_artifact_no_dispatch_metadata_invocation_v1(graph,runtime=runtime,port=port,grant=grant)
    proof=owner_work=financial=None
    try:
        proof=create_artifact_no_dispatch_owner_caller_proof_v3(invocation)
        owner_work=prepare_owner_location_read_work_v3(proof)
        while True:
            with owner_location_read_quantum_v3(proof) as meter:
                progress=owner_work.advance(meter=meter)
            if type(progress) is dict and progress.get("phase")=="owner_location_quantum_commit":
                progress=owner_work.complete_reserved_quantum_v3(proof)
            if type(progress) is not dict:break
        facts=progress.require_for_v3(proof)
        financial=ArtifactNoDispatchMetadataReadWorkV1(invocation,owner_proof=proof,owner_work=owner_work,owner_facts=facts)
        while not financial.complete:
            with owner_location_read_quantum_v3(proof) as meter:
                with bind_runtime_storage_operation_v3(invocation.retained_operation,invocation.actual_db):
                    invocation.actual_db.execute("BEGIN")
                    try:financial.advance_v1(meter)
                    finally:invocation.actual_db.rollback()
            financial.complete_quantum_v1()
        yield financial.require_result_v1()
    finally:
        try:
            if financial is not None:financial.close_v1()
            if owner_work is not None:owner_work.close_v3()
        finally:
            try:
                if proof is not None:proof.release_v3()
            finally:
                invocation.release_v1()
                finish_runtime_storage_operation_v3(invocation.retained_operation)


def derive_artifact_no_dispatch_basis_from_financial_originals_v1(originals, *, now):
    from ..authority_service.contract import AuthorityUnavailable
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from .d11_offline_originals_v1 import _utc
    from .d11_artifact_draft_model_v1 import ArtifactNoDispatchCancellationBasisV1
    prepared=originals.prepared
    if originals.settlement is not None:return originals.settlement.cancellation
    if originals.cost_receipt is not None:
        raise AuthorityUnavailable("original financial call already has a different cost CAS")
    if now>=_utc(prepared.deadline_utc).timestamp():
        return ArtifactNoDispatchCancellationBasisV1(prepared.namespace,prepared.job_id,prepared.digest,prepared.deadline_utc,
            "original_model_deadline_expired",prepared.job_id,1,prepared.digest,now)
    original=originals.cancelled_request
    if original is None:raise MissingProductionOriginalV1("actual_current_core_goal_cancel_requested_original")
    task=prepared.selector.task if prepared.schema=="d11.artifact-draft-phase-model-prepared.v2" else prepared.selector
    from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
    goal=artifact_goal_plan_keys_v1(task.namespace,c02_operation_id=task.c02_operation_id,root_registration_ref=task.root_registration_ref)[0]
    if (original.state!="cancel_requested" or original.request.namespace!=prepared.namespace
            or original.request.goal_ref!=goal.token or original.request.c02_operation_id!=task.c02_operation_id
            or original.request.root_registration_ref!=task.root_registration_ref):
        raise AuthorityUnavailable("actual Core cancellation does not target this original financial C4 call")
    return ArtifactNoDispatchCancellationBasisV1(prepared.namespace,prepared.job_id,prepared.digest,prepared.deadline_utc,
        "actual_core_goal_cancel_requested",original.original_ref,original.metadata.goal_atom_revision,original.digest,now)


def require_original_artifact_financial_snapshot_v1(originals, *, runtime, intent):
    registered=_FINANCIAL_ORIGINALS.get(originals)
    if (type(originals) is not ArtifactNoDispatchFinancialOriginalsV1
            or registered is None or registered[0] is not runtime
            or registered[1].intent!=intent or originals.intent!=intent
            or originals.prepared.digest!=intent.binding_digest):
        raise AuthorityUnavailable("actual registered financial EOF/original installed controller required")
    return originals


def prepare_current_original_artifact_financial_snapshot_v1(graph, *, runtime, job_id=None, after_call_id=None):
    from uuid import uuid4
    from ..authority_service.artifact_no_dispatch_metadata_contract_v1 import ModelNoDispatchMetadataRequestV1
    policy=runtime.bundle.installation_policy
    request=ModelNoDispatchMetadataRequestV1(policy.namespace,policy.authority_namespace,
        policy.installation_id,str(uuid4()),job_id,after_call_id)
    grant=graph._GraphCoordinator__content_fence_v2.read_current_artifact_no_dispatch_metadata_v1(
        bundle=runtime.bundle,request=request)
    if grant is None:return None
    return read_actual_artifact_no_dispatch_financial_originals_v1(graph,runtime=runtime,grant=grant)

@contextmanager
def bind_artifact_no_dispatch_financial_snapshot_v1(graph, *, runtime, intent, originals):
    require_original_artifact_financial_snapshot_v1(originals,runtime=runtime,intent=intent)
    if graph is not runtime.graph or graph._GraphCoordinator__store._db.in_transaction:
        raise AuthorityUnavailable("financial commit binding must precede actual same Graph SQL")
    token=_FINANCIAL_COMMIT.set((graph,runtime,intent,originals))
    try:yield originals
    finally:_FINANCIAL_COMMIT.reset(token)


def require_bound_artifact_no_dispatch_financial_snapshot_v1(db, *, runtime, witness, basis, now):
    from dataclasses import fields
    bound=_FINANCIAL_COMMIT.get()
    if (bound is None or bound[:3]!=(runtime.graph,runtime,witness.request.intent)
            or db is not runtime.graph._GraphCoordinator__store._db or not db.in_transaction):
        raise AuthorityUnavailable("actual closed financial commit binding required")
    originals=require_original_artifact_financial_snapshot_v1(bound[3],runtime=runtime,intent=bound[2])
    current=derive_artifact_no_dispatch_basis_from_financial_originals_v1(originals,now=now)
    if any(getattr(current,f.name)!=getattr(basis,f.name) for f in fields(basis) if f.name!="observed_at_utc"):
        raise AuthorityUnavailable("financial cancellation cause changed after actual EOF")
    witness.require_signature_v1(runtime.issuer._signer)
    if (witness.request.requested_deadline_utc!=originals.prepared.deadline_utc
            or witness.request.requested_cancel_cause_ref!=basis.cause_ref):
        raise AuthorityUnavailable("Core unsent witness changed exact signed preparation/cancel cause")
    for kind,ref,producer,digest,signature in originals.immutable_rows:
        actual=db.execute("SELECT producing_operation_id,payload_digest,signature FROM graph_d11_life_originals_v1 "
            "WHERE bot=? AND persona=? AND kind=? AND original_ref=?",
            (*basis.namespace.as_tuple,kind,ref)).fetchone()
        if actual!=(producer,digest,signature):
            raise AuthorityUnavailable("financial canonical original metadata changed after its whole EOF")
    job=originals.original_job
    columns=("job_id","operation_id","activity_id","effect_id","bot_id","persona_id","snapshot_ref",
        "phase","work_kind","deadline_utc","budget_ref","resource_ref","lease_holder","lease_expires_utc",
        "fence","cancel_epoch","result_ref")
    actual=db.execute("SELECT "+",".join(columns)+" FROM runtime_jobs WHERE job_id=?",(job.job_id,)).fetchone()
    if actual!=tuple(getattr(job,name) for name in columns):
        raise AuthorityUnavailable("actual once C4 job metadata changed after financial EOF")
    return originals


def require_bound_artifact_no_dispatch_job_v1(db, *, runtime, witness, basis, now):
    return require_bound_artifact_no_dispatch_financial_snapshot_v1(
        db,runtime=runtime,witness=witness,basis=basis,now=now).original_job

def bound_artifact_no_dispatch_financial_originals_v1(graph, *, runtime, intent):
    bound=_FINANCIAL_COMMIT.get()
    if bound is None or bound[:3]!=(graph,runtime,intent):
        raise AuthorityUnavailable("actual original financial commit scope required")
    return require_original_artifact_financial_snapshot_v1(bound[3],runtime=runtime,intent=intent)

def read_actual_artifact_no_dispatch_financial_originals_v1(graph, *, runtime, grant):
    with retain_actual_artifact_no_dispatch_financial_originals_v1(graph,runtime=runtime,grant=grant) as originals:
        return originals


@contextmanager
def retain_current_original_artifact_financial_snapshot_v1(graph, *, runtime, job_id):
    from uuid import uuid4
    from ..authority_service.artifact_no_dispatch_metadata_contract_v1 import ModelNoDispatchMetadataRequestV1
    policy=runtime.bundle.installation_policy
    request=ModelNoDispatchMetadataRequestV1(policy.namespace,policy.authority_namespace,
        policy.installation_id,str(uuid4()),job_id,None)
    grant=graph._GraphCoordinator__content_fence_v2.read_current_artifact_no_dispatch_metadata_v1(
        bundle=runtime.bundle,request=request)
    if grant is None:raise AuthorityUnavailable("actual original Core financial metadata permission absent")
    with retain_actual_artifact_no_dispatch_financial_originals_v1(graph,runtime=runtime,grant=grant) as originals:
        yield originals
