"""D07 metadata-only fair selection and a single current slot per category."""
from __future__ import annotations
from dataclasses import dataclass, fields, replace
from weakref import WeakKeyDictionary
from contextvars import ContextVar
import math
from ..runtime_contracts import AuthorityContext, CommitReceipt, NamespaceId, canonical_digest, canonical_serialize, schema_hash
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeSpec
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d07.concern_round import ConcernServiceChoiceV1
from .domain_production_contracts_v1 import ProductionOriginalRefV1

DISPATCH_TYPE = "d07.concern_dispatch.v1"
DECISION_KIND = "concern_dispatch_v1"
DISPATCH_OPERATION = "dispatch_selected_concern_v1"
SELECTED_EVENT = "concern_selected_for_dispatch"
READY_EVENT = "concern_round_ready_for_selection"
METADATA_WORK_KIND = "d07_concern_dispatch_metadata_v1"
METADATA_PROFILE = "d07.concern-dispatch-metadata.v1"
_CATEGORIES = frozenset({"required", "interaction", "background"})
_FAMILIES = frozenset({"general_growth", "ordinary_continuity", "single_event_review",
    "artifact_observation", "joint_external", "c02_foreground", "reflection"})
_ISSUER = object()
_READERS = WeakKeyDictionary()
_TRIGGERS = WeakKeyDictionary()
_COHORTS = WeakKeyDictionary()
_SELECTED = WeakKeyDictionary()
_SELECTIONS = WeakKeyDictionary()
_BOUND = ContextVar("d07_selected_concern_v1", default=None)

def _text(value):
    if type(value) is not str or not value:
        raise ValueError("fair dispatch requires an actual nonempty identity")
def _sha(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("fair dispatch requires an exact canonical SHA256")
def _time(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("fair dispatch retains finite original UTC bounds")
def _original(value):
    if type(value) is not ProductionOriginalRefV1:
        raise TypeError("fair dispatch requires an actual typed original")
    _text(value.kind); _text(value.original_ref); _sha(value.original_digest)
def _version(namespace, value, kind=None, positive=True):
    if (type(value) is not GraphVersion or NamespaceId.from_key(value.key) != namespace
            or value.revision < (1 if positive else 0)
            or kind is not None and value.key.type_name != kind):
        raise ValueError("fair dispatch changed an exact Graph commitment")
def _decode(raw, cls):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw) is not dict or set(raw) != {f.name for f in fields(cls)}:
        raise ValueError("fair dispatch closed wire fields differ")
    result = decode_typed_production_value_v1(raw, cls)
    if plain_v1(result) != raw:
        raise ValueError("fair dispatch changed its official canonical wire")
    return result

@dataclass(frozen=True, slots=True)
class DispatchSelectedConcernRequestV1:
    decision_ref: str
    decision_digest: str
    def __post_init__(self):
        _text(self.decision_ref); _sha(self.decision_digest)

@dataclass(frozen=True, slots=True)
class D07SelectedConcernCauseV1:
    namespace: NamespaceId
    category: str
    ticket_version: GraphVersion
    ticket_digest: str
    issuance_original: ProductionOriginalRefV1
    issuance_receipt_digest: str
    family: str
    execution_cause_original: ProductionOriginalRefV1
    question_original: ProductionOriginalRefV1 | None
    native_phase_original: ProductionOriginalRefV1 | None
    source_refs: tuple[str, ...]
    source_versions: tuple[GraphVersion, ...]
    source_authority: AuthorityContext
    activity_id: str
    operation_id: str
    phase_key: str
    parent_budget_lease_ref: str
    parent_grant_digest: str
    original_budget_ancestry: tuple[tuple[str, int, str, float], ...]
    original_deadline_utc: float
    prepared_original: ProductionOriginalRefV1 | None = None
    job_version: GraphVersion | None = None
    schema: str = "d07.selected-concern-cause.v1"
    def __post_init__(self):
        if (self.schema != "d07.selected-concern-cause.v1" or type(self.namespace) is not NamespaceId
                or self.category not in _CATEGORIES or self.family not in _FAMILIES
                or type(self.source_authority) is not AuthorityContext
                or self.source_authority.namespace != self.namespace):
            raise ValueError("selected concern requires its closed family and original authority")
        _version(self.namespace, self.ticket_version, "d07.attention_ticket.v1")
        for v in (self.ticket_digest, self.issuance_receipt_digest, self.parent_grant_digest): _sha(v)
        for v in (self.issuance_original, self.execution_cause_original): _original(v)
        if self.question_original is None and self.native_phase_original is None:
            raise ValueError("selected concern has no actual question or native phase")
        for v in (self.question_original, self.native_phase_original, self.prepared_original):
            if v is not None: _original(v)
        for v in (self.activity_id, self.operation_id, self.phase_key, self.parent_budget_lease_ref): _text(v)
        if (type(self.source_refs) is not tuple or not self.source_refs or len(set(self.source_refs)) != len(self.source_refs)
                or type(self.source_versions) is not tuple
                or len({v.key for v in self.source_versions}) != len(self.source_versions)):
            raise ValueError("selected concern requires its complete Source commitments")
        for ref in self.source_refs:
            key = AtomKey.from_token(ref)
            if key.type_name != "memory.source" or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("selected concern Source roots crossed namespace")
        for v in self.source_versions:
            _version(self.namespace, v, positive=False)
            if v.key.type_name not in {"memory.source", "memory.access", "d06.source_correction_head.v1"}:
                raise ValueError("selected concern Source commitment has another type")
        if (type(self.original_budget_ancestry) is not tuple or not self.original_budget_ancestry
                or self.original_budget_ancestry[0][0] != self.parent_budget_lease_ref
                or len({r[0] for r in self.original_budget_ancestry}) != len(self.original_budget_ancestry)):
            raise ValueError("selected concern lost its original budget ancestry")
        for ref, version, digest, deadline in self.original_budget_ancestry:
            _text(ref); _sha(digest); _time(deadline)
            if type(version) is not int or version < 1:
                raise ValueError("selected concern grant version is invalid")
        _time(self.original_deadline_utc)
        if self.original_deadline_utc > min(r[3] for r in self.original_budget_ancestry):
            raise ValueError("selected concern cannot outlive an original parent grant")
        if (self.prepared_original is None) != (self.job_version is None):
            raise ValueError("selected concern recovery retains both Prepared and job")
        if self.job_version is not None: _version(self.namespace, self.job_version, "runtime.job")
    @property
    def execution_key(self):
        return canonical_digest((self.namespace, self.family, self.operation_id,
            self.activity_id, self.phase_key, self.execution_cause_original))

@dataclass(frozen=True, slots=True)
class D07ConcernDispatchSlotV1:
    namespace: NamespaceId
    category: str
    revision: int
    state: str
    decision_ref: str
    selection_operation_id: str
    ticket_version: GraphVersion
    choice_digest: str
    execution_key: str
    execution_operation_id: str
    prepared_ref: str | None = None
    job_ref: str | None = None
    terminal_original_ref: str | None = None
    terminal_effect_id: str | None = None
    schema: str = DISPATCH_TYPE
    def __post_init__(self):
        if (self.schema != DISPATCH_TYPE or type(self.namespace) is not NamespaceId
                or self.category not in _CATEGORIES or self.state not in {"selected","admitted","completed","blocked","cancelled"}
                or type(self.revision) is not int or self.revision < 1):
            raise ValueError("fair dispatch slot has another category/state/revision")
        for v in (self.decision_ref, self.selection_operation_id, self.execution_operation_id): _text(v)
        for v in (self.choice_digest, self.execution_key): _sha(v)
        _version(self.namespace, self.ticket_version, "d07.attention_ticket.v1")
        if (self.prepared_ref is None) != (self.job_ref is None):
            raise ValueError("fair slot must retain Prepared and job together")
        for v in (self.prepared_ref, self.job_ref, self.terminal_original_ref, self.terminal_effect_id):
            if v is not None: _text(v)
        if self.state in {"admitted","completed"} and self.job_ref is None:
            raise ValueError("admitted slot cannot omit its actual execution")
        if self.state in {"completed","blocked","cancelled"} and self.terminal_original_ref is None:
            raise ValueError("terminal slot requires an actual disposition original")
        if self.state == "completed" and self.terminal_effect_id is None:
            raise ValueError("completed slot requires its adopted effect")
        if self.state in {"selected","admitted"} and self.terminal_original_ref is not None:
            raise ValueError("unfinished slot cannot claim a terminal disposition")

def concern_dispatch_key_v1(namespace, category):
    if type(namespace) is not NamespaceId or category not in _CATEGORIES:
        raise ValueError("fair dispatch key requires its exact namespace/category")
    return AtomKey(Owner("persona", *namespace.as_tuple), DISPATCH_TYPE, category)
def decode_concern_dispatch_slot_v1(raw):
    return _decode(raw, D07ConcernDispatchSlotV1)
def concern_dispatch_type_spec_v1():
    return TypeSpec(DISPATCH_TYPE, ("persona",), "state", decode_concern_dispatch_slot_v1,
        writer_domain="d07", schema_hash=schema_hash({"type":DISPATCH_TYPE,
            "fields":tuple(f.name for f in fields(D07ConcernDispatchSlotV1))}))
def concern_dispatch_slot_write_v1(slot):
    if type(slot) is not D07ConcernDispatchSlotV1:
        raise TypeError("exact registered fair dispatch slot required")
    return GraphWrite(concern_dispatch_key_v1(slot.namespace, slot.category), plain_v1(slot))

@dataclass(frozen=True, slots=True)
class D07ConcernDispatchDecisionV1:
    namespace: NamespaceId
    category: str
    original_ref: str
    operation_id: str
    trigger_original: ProductionOriginalRefV1
    trigger_causal_operation_id: str
    trigger_receipt_digest: str
    cohort_digest: str
    ticket_dispositions: tuple[tuple[GraphVersion, str, str, str | None], ...]
    choice: ConcernServiceChoiceV1 | None
    prior_slot_version: GraphVersion
    round_version: GraphVersion
    selected_cause: D07SelectedConcernCauseV1 | None
    selection_receipt_digest: str
    selected_at_utc: float
    schema: str = "d07.concern-dispatch-decision.v1"
    def __post_init__(self):
        if (self.schema != "d07.concern-dispatch-decision.v1" or type(self.namespace) is not NamespaceId
                or self.category not in _CATEGORIES or (self.choice is None)!=(self.selected_cause is None)
                or self.choice is not None and (type(self.choice)is not ConcernServiceChoiceV1
                    or type(self.selected_cause)is not D07SelectedConcernCauseV1
                    or (self.selected_cause.namespace,self.selected_cause.category)!=(self.namespace,self.category)
                    or self.choice.ticket_id!=self.selected_cause.ticket_version.key.name)):
            raise ValueError("fair decision lost its exact complete cohort and actual selected cause")
        for v in (self.original_ref,self.operation_id,self.trigger_causal_operation_id): _text(v)
        _original(self.trigger_original)
        for v in (self.trigger_receipt_digest,self.cohort_digest,self.selection_receipt_digest): _sha(v)
        _version(self.namespace,self.prior_slot_version,DISPATCH_TYPE,positive=False)
        _version(self.namespace,self.round_version,"d07.concern_round.v1",positive=False)
        _time(self.selected_at_utc)
        if (type(self.ticket_dispositions) is not tuple
                or len(self.ticket_dispositions)>128
                or len({v[0].key for v in self.ticket_dispositions}) != len(self.ticket_dispositions)):
            raise ValueError("fair decision requires the original complete bounded ticket dispositions")
        for version,digest,status,reason in self.ticket_dispositions:
            _version(self.namespace,version,"d07.attention_ticket.v1"); _sha(digest)
            if status not in {"selected","waiting","expired","cancelled","resource_blocked","no_execution_cause"}:
                raise ValueError("fair decision has an unregistered ticket disposition")
            if reason is not None: _text(reason)
        selected=tuple(row for row in self.ticket_dispositions if row[2]=="selected")
        if self.choice is None:
            if selected:raise ValueError("fair waiting decision has an invented selected member")
        elif len(selected)!=1 or selected[0][:2]!=(self.selected_cause.ticket_version,self.selected_cause.ticket_digest):
            raise ValueError("fair decision changed the actual selected ticket")
def concern_dispatch_decision_from_wire_v1(raw):
    return _decode(raw,D07ConcernDispatchDecisionV1)

@dataclass(frozen=True,eq=False)
class _BackgroundConcernTriggerV1:
    marker: object
@dataclass(frozen=True,eq=False)
class _NativeConcernTriggerV1:
    marker: object

_BACKGROUND_EVENTS = frozenset({"general_growth_attention_available_for_service",
    "ordinary_continuity_attention_available_for_service",
    "single_event_review_attention_available_for_service",
    "artifact_phase_observation_available",
    "joint_external_semantic_question_requires_fair_cognition",READY_EVENT})

def issue_background_concern_trigger_v1(prepared_or_owner):
    from .domain_background_read_v3 import PreparedBackgroundOperationV3,BackgroundReadWorkV3,require_actual_background_attachment_owner_v3
    from .domain_production_contracts_v1 import ProductionOutboxStageV1
    if type(prepared_or_owner)is PreparedBackgroundOperationV3:
        prepared_or_owner.require_v3(prepared_or_owner.graph)
        r=prepared_or_owner.owner;prepared=prepared_or_owner
    elif type(prepared_or_owner)is BackgroundReadWorkV3:
        r=prepared_or_owner;prepared=None
    else:raise TypeError("actual Background preparation or originating metadata Work required")
    require_actual_background_attachment_owner_v3(r,db=r.db)
    column=r.entry_column
    if(r.kind not in {"followup","followup_child"}or r.entry is None
            or r.entry[1]!="d07"or r.entry[2]not in _BACKGROUND_EVENTS
            or column is None or not column.complete or column.metadata is None
            or column.column.sha256!=column.metadata[2]or r.entry_metadata is None
            or r.owner is None or r.owner_guard is None or r.authority is None
            or r.read_scope is None or r.graph._v2_graph_stamp(r.namespace)!=r.graph_stamp):
        raise ValueError("fair trigger lacks its real receiver, complete producer metadata and current Owner")
    kind={
        "general_growth_attention_available_for_service":"d07.general_growth_attention_v1",
        "ordinary_continuity_attention_available_for_service":"d07.ordinary_continuity_attention_v1",
        "single_event_review_attention_available_for_service":"d07.single_event_review_attention_v1",
        "artifact_phase_observation_available":"d11.life_artifact_phase_observation_basis_v1",
        "joint_external_semantic_question_requires_fair_cognition":"d07.joint_external_semantic_basis_v1",
        READY_EVENT:"d07.concern_dispatch_completion_v1",
    }[r.entry[2]]
    event=ProductionOutboxStageV1(r.namespace,r.entry[0],r.entry[1],r.entry[2],
        ProductionOriginalRefV1(kind,r.entry[3],r.entry[4]))
    # The receiver's actual current READ issues only this scheduling handoff.
    # The new Work authenticates its native signed cause and W01 receipt itself.
    r.work._require_invocation(r.graph)
    trigger=_BackgroundConcernTriggerV1(_ISSUER)
    _TRIGGERS[trigger]=(r.graph,r.bundle,r,prepared,r.work,r.operation,r.graph_stamp,
        event,event.trigger_original,r.authority,r.owner,r.owner_guard,
        r.operation.deadline_utc,r.read_scope,column,r.entry_metadata)
    r.operation.retain(4096)
    return trigger

def _require_concern_trigger_v1(trigger,graph,bundle):
    from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
    state=_TRIGGERS.get(trigger)
    if(type(trigger)not in {_BackgroundConcernTriggerV1,_NativeConcernTriggerV1}
            or trigger.marker is not _ISSUER or state is None or state[:2]!=(graph,bundle)):
        raise ValueError("actual private scheduling trigger required")
    if type(trigger)is _BackgroundConcernTriggerV1:
        r=state[2];require_actual_background_attachment_owner_v3(r,db=r.db)
        if(r.work is not state[4]or r.work.state is not r or r.operation is not state[5]
                or state[5].closed or r.graph_stamp!=state[6]or r.entry_column is not state[14]
                or r.entry_metadata!=state[15]or r.owner!=state[10]or r.owner_guard!=state[11]
                or r.authority!=state[9]or r.read_scope is not state[13]):
            raise ValueError("fair trigger changed its actual originating metadata Work")
        if state[3]is not None:state[3].require_v3(graph)
    return state

def release_concern_trigger_v1(trigger):
    _TRIGGERS.pop(trigger,None)

def _reader_registered_v1(r):
    from ..runtime_storage_v3 import runtime_storage_v3
    if (type(r) is not D07ConcernDispatchMetadataReadV1 or _READERS.get(r)!=r.identity_v1()
            or r.closed or r.operation.closed or r.work.state is not r or r.work.operation is not r.operation
            or r.work.coordinator is not r.graph or r.work.kind!=METADATA_WORK_KIND
            or r.db is not r.graph._GraphCoordinator__store._db
            or runtime_storage_v3(r.db) is not r.operation.handle):
        raise ValueError("actual registered D07 fair metadata Work required")
    _require_concern_trigger_v1(r.private_trigger,r.graph,r.bundle)
    return r

def require_actual_d07_concern_metadata_reader_v1(reader,meter=None):
    r=_reader_registered_v1(reader)
    if r.complete or r.read_finished:
        raise ValueError("fair metadata READ already reached its original EOF")
    r.work._require_invocation(r.graph)
    if meter is not None: r.operation.handle.require_current(meter)
    return (r.graph,r.graph._GraphCoordinator__content_fence_v2,r.bundle,r.fence.scope,
        ((r.authority.purpose,r.authority.audience),))

def require_actual_d07_concern_metadata_retained_reader_v1(reader,meter=None):
    r=_reader_registered_v1(reader)
    actual=_COHORTS.get(r.result)
    if (not r.complete or actual is None or actual[0] is not r or r.work.result_lease is not r.operation
            or actual[1]!=r.identity_v1()):
        raise ValueError("actual complete retained fair cohort ownership required")
    if meter is not None: r.operation.handle.require_current(meter)
    return (r.graph,r.graph._GraphCoordinator__content_fence_v2,r.bundle,r.fence.scope,
        ((r.authority.purpose,r.authority.audience),))

def d07_concern_metadata_owner_identity_v1(reader):
    r=_reader_registered_v1(reader)
    return (r.work,r.operation,r.private_trigger,r.original_owner_binding,r.authority,
        r.fence.scope,r.graph_stamp,r.selection_digest,r.original_deadline_utc,METADATA_PROFILE)


def _owner_commitment_v1(binding):
    return tuple(getattr(binding,name) for name in (
        "principal","actor","namespace","purpose","audience","grant_id","scope","issuer_ref",
        "capabilities","purposes","audiences","grant_digest","grant_revision","access_epoch",
        "delete_epoch","graph_incarnation","authorization_head","authorization_revision","revocation_epoch"))

class D07ConcernDispatchMetadataReadV1:
    def __init__(self,graph,bootstrap,bundle,trigger):
        from time import monotonic
        from uuid import uuid4
        from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3
        from .first_ingress_v2 import trusted_upper_at_v4
        state=_require_concern_trigger_v1(trigger,graph,bundle)
        self.graph,self.bootstrap,self.bundle=graph,bootstrap,bundle
        self.private_trigger=trigger
        self.store=graph._GraphCoordinator__store; self.db=self.store._db
        self.namespace=bundle.installation_policy.namespace
        self.authority=state[9]; self.original_owner_binding=state[10]
        if self.authority.namespace!=self.namespace:
            raise ValueError("fair metadata trigger crossed the actual installed namespace")
        self.original_deadline_utc=state[12]
        self.initial_clock=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
        self.monotonic_sample=monotonic()
        self.now_utc=trusted_upper_at_v4(self.initial_clock,self.monotonic_sample)
        if self.now_utc>=self.original_deadline_utc:
            raise ValueError("fair metadata cannot renew its original trigger deadline")
        self.monotonic_deadline=self.monotonic_sample+self.original_deadline_utc-self.now_utc
        self.operation=self.fence=self.work=self.owner_entry=self.owner_task=None
        self.owner_binding=self.current_guard=self.current_self=None
        self.closed=self.complete=self.read_finished=False
        self.task=self.result=None
        self.reserved=0
        try:
            self.operation=begin_runtime_storage_operation_v3(self.db,
                METADATA_WORK_KIND+":"+uuid4().hex,self.original_deadline_utc)
            with bind_runtime_storage_operation_v3(self.operation,self.db):
                self.fence=graph._begin_read_fence_v3(self.authority,operation_id=self.operation.operation_id,
                    owner_principal=self.original_owner_binding.principal,
                    owner_binding=self.original_owner_binding)
                self.graph_stamp=(self.fence.metadata,self.fence.epoch)
                self.selection_digest=self.operation.selection_digest
                self.operation.retain(32768)
        except BaseException:
            if self.fence is not None: graph._finish_read_fence_v3(self.fence)
            if self.operation is not None:
                from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
                finish_runtime_storage_operation_v3(self.operation)
            raise
    def identity_v1(self):
        return (self.graph,self.work,self.operation,self.private_trigger,self.original_owner_binding,
            self.authority,self.fence.scope,self.graph_stamp,self.selection_digest,
            self.original_deadline_utc,METADATA_PROFILE)
    def clock_v1(self):
        from time import monotonic
        from .first_ingress_v2 import trusted_upper_at_v4
        now=monotonic()
        self.now_utc=trusted_upper_at_v4(self.initial_clock,now)
        if now>=self.monotonic_deadline or self.now_utc>=self.original_deadline_utc:
            raise ValueError("fair metadata original deadline expired")
        return self.now_utc
    def clock_v3(self):
        return self.clock_v1()
    @property
    def read_scope(self):
        return self.fence.scope
    def reserve_v3(self,amount=32768):
        if amount>self.reserved:
            self.operation.retain(amount-self.reserved);self.reserved=amount
    def require_current_v1(self,meter):
        require_actual_d07_concern_metadata_reader_v1(self,meter=meter)
        self.clock_v1()
        if self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
            raise ValueError("fair cohort changed its original complete metadata epoch")
        if self.owner_entry is None:
            raise ValueError("fair metadata requires its actual completed independent Owner entry")
        binding=self.owner_entry.require_for_v3(self)
        if (_owner_commitment_v1(binding)!=_owner_commitment_v1(self.original_owner_binding)
                or binding.actor!=self.authority.actor or self.authority.purpose not in binding.purposes
                or not set(self.authority.audience)<=set(binding.audiences)):
            raise ValueError("fair metadata changed its actual trigger Owner authority")
        self.owner_binding=binding
        self.current_guard=self.owner_entry.current_owner_guard
        self.current_self=self.owner_entry.current_self
        return self
    def release_payload_v3(self):
        if self.closed:return
        self.closed=True
        if self.result is not None:_COHORTS.pop(self.result,None)
        _READERS.pop(self,None)
        if self.task is not None:self.task.release_v1()
        from .source_inspection_metadata_read_v3 import release_inspection_metadata_owner_v3
        release_inspection_metadata_owner_v3(self)
        if self.owner_task is not None:self.owner_task.release_v3()
        self.task=self.result=self.owner_task=self.owner_entry=self.current_self=None

def begin_current_d07_concern_metadata_v1(graph,bootstrap,bundle,private_trigger):
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    r=D07ConcernDispatchMetadataReadV1(graph,bootstrap,bundle,private_trigger)
    try:
        r.work=create_graph_storage_work_v3(graph,kind=METADATA_WORK_KIND,
            operation_id=r.operation.operation_id,selection_digest=r.selection_digest,
            deadline_utc=r.original_deadline_utc,state=r,operation=r.operation)
        _READERS[r]=r.identity_v1()
        return r.work
    except BaseException:
        graph._finish_read_fence_v3(r.fence)
        r.release_payload_v3()
        from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
        finish_runtime_storage_operation_v3(r.operation)
        raise

def advance_current_d07_concern_metadata_v1(graph,work):
    from ..graph_worker import GraphStorageStepV3
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,runtime_storage_quantum_v3
    from ..authority_service.owner_location_read_v3 import create_current_host_d07_concern_metadata_owner_task_v1
    r=work.state
    require_actual_d07_concern_metadata_reader_v1(r)
    if r.graph is not graph:raise ValueError("fair metadata crossed its actual Graph worker")
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        r.clock_v1();graph._validate_read_fence_v3(r.fence)
        if r.owner_entry is None:
            if r.owner_task is None:r.owner_task=create_current_host_d07_concern_metadata_owner_task_v1(r)
            r.owner_task.advance()
            if r.owner_task.complete:r.owner_entry=r.owner_task.result
            return GraphStorageStepV3("progress")
        with r.store._lock:
            if r.db.in_transaction:raise ValueError("fair metadata continuation retained SQL")
            r.db.execute("BEGIN")
            try:
                with runtime_storage_quantum_v3(r.db) as meter:
                    r.require_current_v1(meter)
                    if r.task is None:
                        from .d07_fair_cause_metadata_v1 import D07FairCauseCensusTaskV1
                        r.task=D07FairCauseCensusTaskV1(r)
                    r.task.advance(meter)
                    if r.task.complete:
                        r.result=_VerifiedConcernCohortV1(_ISSUER,r,r.task)
                        r.complete=True
            finally:r.db.rollback()
        graph._validate_read_fence_v3(r.fence);r.clock_v1()
    return GraphStorageStepV3("complete",r.result) if r.complete else GraphStorageStepV3("progress")

def finish_current_d07_concern_metadata_v1(graph,work,error):
    from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
    r=work.state
    if type(r) is not D07ConcernDispatchMetadataReadV1 or r.graph is not graph:
        raise ValueError("fair metadata finish changed its actual reader")
    failed=error is not None
    try:
        graph._finish_read_fence_v3(r.fence)
        r.read_finished=True
        if not failed:work.result_lease=r.operation
    except BaseException:
        failed=True;raise
    finally:
        if failed:
            try:r.release_payload_v3()
            finally:finish_runtime_storage_operation_v3(r.operation)

class _VerifiedConcernCohortV1:
    def __init__(self,issuer,reader,task):
        if issuer is not _ISSUER or reader.task is not task or not task.complete:
            raise TypeError("actual complete fair metadata census required")
        self.reader=reader
        self.ticket_atoms=task.ticket_atoms
        self.causes=task.causes
        self.dispositions=task.dispositions
        self.policy=task.policy
        self.focus=task.focus
        self.rounds=task.rounds
        self.slots=task.slots
        self.read_versions=task.read_versions
        self.census_digest=task.census_digest
        _COHORTS[self]=(reader,reader.identity_v1(),self.commitment_v1())
    def commitment_v1(self):
        return canonical_digest((self.ticket_atoms,self.causes,self.dispositions,self.policy,
            self.focus,self.rounds,self.slots,self.read_versions,self.census_digest))
    def require_current_v1(self,graph,*,db=None,meter=None):
        r=self.reader
        actual=_COHORTS.get(self)
        if (actual is None or actual[0] is not r or actual[1]!=r.identity_v1()
                or actual[2]!=self.commitment_v1() or graph is not r.graph
                or db is not None and db is not r.db):
            raise ValueError("fair cohort lost its actual complete Work commitments")
        require_actual_d07_concern_metadata_retained_reader_v1(r,meter=meter)
        r.clock_v1()
        if r.graph._v2_graph_stamp(r.namespace)!=r.graph_stamp:
            raise ValueError("fair cohort changed before its selected decision CAS")
        return self
    def release_payload_v3(self):
        r=self.reader
        _COHORTS.pop(self,None)
        if r is not None:r.release_payload_v3()
        self.reader=None


@dataclass(frozen=True,slots=True)
class SelectCurrentConcernRequestV1:
    category:str
    def __post_init__(self):
        if self.category not in _CATEGORIES:raise ValueError("unknown actual concern category")

def _fair_tickets_v1(cohort):
    from ..domains.d07 import AttentionTicket
    status={version.key.token:disposition for version,_,disposition,_ in cohort.dispositions}
    result=[]
    for atom in cohort.ticket_atoms:
        ticket=_decode({k:v for k,v in atom.value.items()if k!="schema"},AttentionTicket)
        if status[atom.key.token]!="waiting":
            ticket=replace(ticket,resources_available=False)
        result.append(ticket)
    return tuple(result)

def _selection_values_v1(cohort,category):
    from ..domains.d07.concern_round import ConcernRoundV1,decode_concern_round,concern_round_key,choose_concern_segment,begin_concern_round
    r=cohort.reader;ns=r.namespace
    slot_atom=next(a for a in cohort.slots if a.key==concern_dispatch_key_v1(ns,category))
    slot=None if slot_atom.revision==0 else decode_concern_dispatch_slot_v1(slot_atom.value)
    if slot is not None and slot.state in{"selected","admitted"}:
        return slot_atom,slot,None,None,None,None
    round_atom=next(a for a in cohort.rounds if a.key==concern_round_key(ns,category))
    state=ConcernRoundV1(ns.persona_id,category,0,0,(),(),(),())if round_atom.revision==0 else decode_concern_round(round_atom.value)
    tickets=_fair_tickets_v1(cohort);now=r.now_utc;policy=cohort.policy.policy;epoch=cohort.focus.value["focus_epoch"]
    choice=choose_concern_segment(state,tickets,policy,now=now,focus_epoch=epoch)
    next_round=state
    if choice is None:
        runnable={t.concern_ref or t.causal_root for t in tickets if t.category==category
            and t.eligible and t.resources_available and not t.cancel_refs and t.valid_until>now}
        parked=dict(state.parked)
        for group in state.groups:
            if group not in runnable:parked[group]=now
        candidate=replace(state,parked=tuple(sorted(parked.items())))
        next_round=begin_concern_round(candidate,tickets,now=now).next_round
        choice=choose_concern_segment(next_round,tickets,policy,now=now,focus_epoch=epoch)
    cause=None if choice is None else next((c for c in cohort.causes if c.ticket_version.key.name==choice.ticket_id),None)
    if choice is not None and cause is None:raise ValueError("fair choice lacks its actual authenticated execution cause")
    return slot_atom,None,round_atom,state,next_round,(choice,cause)

def current_concern_selection_operation_v1(cohort,category):
    cohort.require_current_v1(cohort.reader.graph)
    values=_selection_values_v1(cohort,category)
    slot_atom,slot=values[:2]
    if slot is not None:return slot.selection_operation_id
    choice,cause=values[5];trigger=_require_concern_trigger_v1(cohort.reader.private_trigger,cohort.reader.graph,cohort.reader.bundle)[7]
    return "concern-select:"+canonical_digest((trigger,GraphVersion(slot_atom.key,slot_atom.revision),choice))[:48]

class _CurrentConcernSelectionV1:
    def __init__(self,issuer,frame,cohort,request,staged,values,decision_ref):
        if issuer is not _ISSUER:raise TypeError("actual fair selection issuer required")
        self.frame,self.cohort,self.request,self.staged=frame,cohort,request,staged
        self.values,self.decision_ref=values,decision_ref
        _SELECTIONS[self]=(frame,cohort,request,staged.original_digest,
            values,decision_ref,cohort.commitment_v1())
    def require_current_v1(self,graph):
        actual=_SELECTIONS.get(self)
        if(actual is None or actual[:3]!=(self.frame,self.cohort,self.request)
                or actual[3]!=self.staged.original_digest or actual[4:]!=(self.values,self.decision_ref,self.cohort.commitment_v1())):
            raise ValueError("fair selection lost its private actual stage/cohort seal")
        self.cohort.require_current_v1(graph)
        return self
    def release_payload_v3(self):
        _SELECTIONS.pop(self,None);self.cohort=None

def prepare_current_concern_selection_v1(frame,cohort,request):
    from ..domains.d07 import D07DomainProvider
    from ..domains.d07.concern_round import concern_round_write
    from ..domains.d01.production_operations_v1 import stage_result_v1
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    from ..graph_types import owner_grant_key
    if type(cohort)is not _VerifiedConcernCohortV1 or type(request)is not SelectCurrentConcernRequestV1:
        raise TypeError("selection requires its actual private completed metadata cohort")
    r=cohort.reader;cohort.require_current_v1(r.graph)
    trigger=r.task.trigger_task.trigger
    category=r.task.trigger_task.category_v1()
    if request.category!=category:raise ValueError("fair selection changed actual triggering category")
    expected=current_concern_selection_operation_v1(cohort,request.category)
    binding=r.owner_binding
    guard=ProductionOwnerGuardV1(owner_grant_key(*r.namespace.as_tuple).token,binding.grant_revision,
        binding.grant_digest.removeprefix("sha256:"),binding.authorization_head.removeprefix("sha256:"))
    if(frame.envelope.authority!=r.authority or frame.envelope.authority.namespace!=r.namespace
            or frame.envelope.identity.operation_id!=expected or frame.owner_guard!=guard
            or frame.envelope.deadline_utc>r.original_deadline_utc
            or not set(cohort.read_versions)<=set(frame.envelope.version_guard.read_versions)
            or frame.snapshot.epochs!=(r.graph_stamp[1],)):
        raise ValueError("fair selection is outside its actual fresh metadata WRITE/current Owner/readset")
    values=_selection_values_v1(cohort,request.category)
    slot_atom,existing,round_atom,prior,next_round,selected=values
    if existing is not None:
        raise ValueError("actual_unfinished_concern_dispatch_slot_requires_same_decision_recovery")
    choice,cause=selected;writes=[]
    if next_round!=prior:writes.append(concern_round_write(r.namespace,next_round))
    decision_ref="concern-dispatch:"+canonical_digest((r.namespace,request.category,expected))[:48]
    if choice is not None:
        slot=D07ConcernDispatchSlotV1(r.namespace,request.category,slot_atom.revision+1,"selected",
            decision_ref,expected,cause.ticket_version,choice.choice_digest,cause.execution_key,cause.operation_id)
        writes.append(concern_dispatch_slot_write_v1(slot))
    dispositions=tuple((version,digest,"selected"if choice is not None and version==cause.ticket_version else state,reason)
        for version,digest,state,reason in cohort.dispositions)
    provenance={"profile":METADATA_PROFILE,"trigger":trigger,"cohort_digest":cohort.census_digest,
        "ticket_dispositions":dispositions,"choice":choice,"selected_cause":cause,
        "prior_slot":GraphVersion(slot_atom.key,slot_atom.revision),
        "prior_round":GraphVersion(round_atom.key,round_atom.revision),"next_round":next_round,
        "decision_ref":decision_ref}
    provider=D07DomainProvider()
    staged=stage_result_v1(frame,"d07","select_concern_for_dispatch_v1",request,writes=tuple(writes),provenance=provenance,
        receiver_events=()if choice is None else(("d07",SELECTED_EVENT),),
        proposal_schema="d07.proposal.v1",proposal_hash=provider.descriptor.request_schema_hash)
    return _CurrentConcernSelectionV1(_ISSUER,frame,cohort,request,staged,values,decision_ref)

def require_current_concern_selection_write_v1(prepared,*,graph,db,scope,owner):
    if type(prepared)is not _CurrentConcernSelectionV1:raise TypeError("actual fair metadata selection required")
    prepared.require_current_v1(graph);r=prepared.cohort.reader
    if(db is not r.db or not db.in_transaction or scope.operation!="write"or scope.namespace!=r.namespace
            or _owner_commitment_v1(owner)!=_owner_commitment_v1(r.original_owner_binding)):
        raise ValueError("fair decision changed its actual fresh WRITE/current Owner")
    return prepared.staged

def record_current_concern_selection_after_cas_v1(db,issuer,prepared,receipt):
    from .d07_execution_v1 import record_d07_original_in_transaction_v1
    if(type(prepared)is not _CurrentConcernSelectionV1 or type(receipt)is not CommitReceipt
            or receipt.status!="committed"or receipt.operation_id!=prepared.staged.operation_id
            or db is not prepared.cohort.reader.db or not db.in_transaction):
        raise ValueError("fair decision requires its actual same-W01 official CommitReceipt")
    r=prepared.cohort.reader
    if issuer is not r.graph._GraphCoordinator__d11_issuer:raise ValueError("fair decision changed its actual installed issuer")
    slot_atom,existing,round_atom,prior,next_round,selected=prepared.values;choice,cause=selected
    expected_writes=tuple(w for p in prepared.staged.proposals for w in p.typed_writes)
    if any(GraphVersion(w.key,w.value["revision"]if w.key.type_name in{"d07.concern_dispatch.v1","d07.concern_round.v1"}else 0)not in receipt.write_versions for w in expected_writes):
        raise ValueError("fair decision receipt lacks its exact slot/round CAS members")
    round_versions=tuple(v for v in receipt.write_versions if v.key==round_atom.key)
    round_version=round_versions[0]if round_versions else GraphVersion(round_atom.key,round_atom.revision)
    trigger=r.task.trigger_task.trigger
    dispositions=tuple((version,digest,"selected"if cause is not None and version==cause.ticket_version else state,reason)
        for version,digest,state,reason in prepared.cohort.dispositions)
    decision=D07ConcernDispatchDecisionV1(r.namespace,prepared.request.category,prepared.decision_ref,
        receipt.operation_id,trigger.trigger_original,trigger.causal_operation_id,
        canonical_digest(r.task.trigger_task.registration.receipt),prepared.cohort.census_digest,
        dispositions,choice,GraphVersion(slot_atom.key,slot_atom.revision),round_version,cause,canonical_digest(receipt),prepared.frame.now_utc)
    digest=record_d07_original_in_transaction_v1(db,issuer,r.namespace,DECISION_KIND,prepared.decision_ref,plain_v1(decision))
    return ProductionOriginalRefV1("d07."+DECISION_KIND,prepared.decision_ref,digest,receipt.write_versions)

