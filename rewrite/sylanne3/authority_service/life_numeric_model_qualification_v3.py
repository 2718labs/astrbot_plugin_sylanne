"""Readonly Numeric candidate qualification under its original active MODEL permit."""
from dataclasses import asdict,dataclass,fields
import math

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .v2_model_egress_contract import ModelEgressIntentV1
from ..runtime_contracts import canonical_digest

NUMERIC_MODEL_CANDIDATE_CASES_V3=frozenset({"original","worker_subject","worker_fence","budget_lease","reservation"})
_CASE_FIELDS={
    "original":frozenset(),"worker_subject":frozenset({"subject"}),
    "worker_fence":frozenset({"worker_fence"}),"budget_lease":frozenset({"budget_lease_id"}),
    "reservation":frozenset({"budget_reservation_operation_id","budget_reservation_digest","budget_ceiling"}),
}
_WORKER_REASON="Life model installed workflow/current worker/input identity changed"
_BUDGET_REASON="Life model actual signed quote/once reserve/settlement ledger changed"

def require_numeric_model_candidate_case_v3(original,permit,case,candidate):
    if type(original)is not ModelEgressIntentV1 or type(candidate)is not ModelEgressIntentV1 or type(permit)is not FencePermitV2:
        raise TypeError("exact original/candidate Numeric MODEL intent and permit required")
    if case not in NUMERIC_MODEL_CANDIDATE_CASES_V3:
        raise ValueError("unknown Numeric MODEL qualification case")
    allowed=_CASE_FIELDS[case]
    changed={f.name for f in fields(ModelEgressIntentV1)if getattr(candidate,f.name)!=getattr(original,f.name)}
    if changed-allowed or case=="original"and changed or case!="original"and not changed:
        raise ValueError("Numeric MODEL candidate changed fields outside its exact named case")
    if (permit.operation,permit.operation_id,permit.subject,permit.authority_id,permit.namespace)!=(
            "model_egress",original.operation_id,original.subject,original.authority_id,original.namespace):
        raise ValueError("Numeric MODEL candidate crossed its original active permit")
    return case

@dataclass(frozen=True,slots=True)
class NumericModelCandidateQualificationV3:
    case:str
    status:str
    rule:str
    reason:str
    observed_utc:float
    valid_until_utc:float
    authority_id:str
    authority_namespace:str
    installation_id:str
    job_id:str
    operation_id:str
    original_intent_digest:str
    candidate_intent_digest:str
    original_permit_digest:str
    source_scope_digest:str
    owner_authorization_head:str
    deadline_bounds:tuple
    occurrence_bounds:tuple
    schema:str="d06.numeric-model-candidate-qualification.v3"

    def __post_init__(self):
        if (self.schema!="d06.numeric-model-candidate-qualification.v3"or self.case not in NUMERIC_MODEL_CANDIDATE_CASES_V3
                or self.status not in {"qualified","refused"}or self.rule not in {"original","worker","budget"}
                or self.rule!=("original"if self.case=="original"else"worker"if self.case in {"worker_subject","worker_fence"}else"budget")
                or type(self.observed_utc)not in (int,float)or type(self.valid_until_utc)not in (int,float)
                or not math.isfinite(self.observed_utc)or not math.isfinite(self.valid_until_utc)
                or self.observed_utc>=self.valid_until_utc
                or self.status=="qualified"and self.reason!=""
                or self.status=="refused"and self.reason!=(_WORKER_REASON if self.rule=="worker"else _BUDGET_REASON)):
            raise ValueError("Numeric MODEL qualification metadata differs from its exact result")
        deadline_names=("binding","request","job","worker_lease","quote_valid","quote_deadline","parent_grant","model_read")
        occurrence_names=("occurrence_completed_at","source_recorded_at")
        if (type(self.deadline_bounds)is not tuple or tuple(n for n,_ in self.deadline_bounds)!=deadline_names
                or type(self.occurrence_bounds)is not tuple or tuple(n for n,_ in self.occurrence_bounds)!=occurrence_names
                or any(type(v)not in(int,float)or not math.isfinite(v)for _,v in (*self.deadline_bounds,*self.occurrence_bounds))
                or self.valid_until_utc!=min(v for _,v in self.deadline_bounds)):
            raise ValueError("Numeric MODEL qualification actual time bounds differ")
        for value in (self.original_intent_digest,self.candidate_intent_digest,self.original_permit_digest,self.source_scope_digest):
            if type(value)is not str or len(value)!=64 or any(c not in "0123456789abcdef"for c in value):
                raise ValueError("Numeric MODEL qualification commitment differs")

    def require_for_v3(self,original,permit,case,candidate,installation_id):
        require_numeric_model_candidate_case_v3(original,permit,case,candidate)
        expected=(case,original.authority_id,original.namespace,installation_id,original.job_id,original.operation_id,
            canonical_digest(asdict(original)),canonical_digest(asdict(candidate)),canonical_digest(asdict(permit)))
        actual=(self.case,self.authority_id,self.authority_namespace,self.installation_id,self.job_id,self.operation_id,
            self.original_intent_digest,self.candidate_intent_digest,self.original_permit_digest)
        if actual!=expected:raise ValueError("Numeric MODEL qualification crossed original/candidate/installation identity")
        return self

def numeric_model_qualification_to_wire_v3(value):
    if type(value)is not NumericModelCandidateQualificationV3:raise TypeError("typed Numeric MODEL qualification required")
    return asdict(value)

def numeric_model_qualification_from_wire_v3(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(NumericModelCandidateQualificationV3)}:
        raise ValueError("Numeric MODEL qualification wire fields differ")
    values=dict(raw)
    values["deadline_bounds"]=tuple(tuple(pair)for pair in raw["deadline_bounds"])
    values["occurrence_bounds"]=tuple(tuple(pair)for pair in raw["occurrence_bounds"])
    return NumericModelCandidateQualificationV3(**values)

def _require_original_model_current_v3(model,*,credential,subject,holder,original,permit):
    fences=model._fences
    if fences is None or subject!=original.subject or holder!=permit.holder:
        raise AuthorityUnavailable("Numeric MODEL qualification lacks its actual installed subject/holder")
    fences.core._require(credential,"model_egress",fences.namespace,holder)
    fences.validate_fence(credential=credential,subject=subject,permit=permit)
    with fences._frozen()as(db,deletion,execution,_):
        anchor=fences._current_locked(db,deletion,execution,holder=holder,generation=permit.generation)
        fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
        record=model._store.read_locked(db,original)
        row=fences.fences._row(db,original.operation_id)
        if (record.state!="prepared"or record.intent!=original or row is None or row[6]!="active"
                or fences.fences._permit(row)!=permit or anchor!=permit.pinned_anchor
                or not model._store.is_fence_bound_locked(db,original)):
            raise AuthorityUnavailable("Numeric MODEL qualification original prepared/fence changed")
    return record

def qualify_current_life_numeric_model_candidate_v3(model,*,credential,subject,holder,
        original_intent,original_permit,case,candidate_intent,installation_id):
    require_numeric_model_candidate_case_v3(original_intent,original_permit,case,candidate_intent)
    from .current_life_numeric_v1 import (InstalledLifeNumericModelGraphReaderV1,
        _qualify_numeric_worker_candidate_v3,_qualify_numeric_configuration_candidate_v3,
        _qualify_numeric_budget_candidate_v3,life_numeric_deadline_bounds_v3)
    reader=getattr(model._graph_verifier,"_life_numeric_reader_v1",None)
    if (type(reader)is not InstalledLifeNumericModelGraphReaderV1
            or reader.bundle.installation_policy.installation_id!=installation_id
            or reader.owner_storage.holder!=holder or reader.read_subject!=subject):
        raise AuthorityUnavailable("Numeric MODEL qualification actual installed reader differs")
    before=_require_original_model_current_v3(model,credential=credential,subject=subject,holder=holder,
        original=original_intent,permit=original_permit)
    from .life_numeric_source_read_v3 import prepare_authority_numeric_model_work_v3
    from .current_authority_graph_read_v3 import (read_authority_graph_current_v3,
        read_authority_current_point_v3,finish_authority_graph_read_work_v3)
    work=prepare_authority_numeric_model_work_v3(model,installed_reader=reader,credential=credential,
        subject=subject,intent=original_intent,permit=original_permit,now_utc=model._graph_verifier._clock())
    try:
        def qualify(db):
            # Actual original first proves installation, Scope, ALL Source, Owner and every live worker/budget condition.
            current=reader.read(db,original_intent,work.now_utc)
            p,b,request,job=current.prepared,current.binding,current.request,current.job
            quote=reader.readers.resource_issuer.original_signed_quote(db,p.quote_id,p.quote_version)
            reservation=read_authority_current_point_v3(db,table="runtime_budget_reservations",
                columns=("digest","ceiling_json","state"),key_columns=("lease_id","operation_id"),
                key=(quote.parent_budget_lease_ref,p.prepare_operation_id),legacy_reader=None)
            reserve=read_authority_current_point_v3(db,table="runtime_budget_operations",columns=("digest",),
                key_columns=("bot_id","persona_id","operation_id","phase"),
                key=(*p.namespace.as_tuple,p.prepare_operation_id,"reserve"),legacy_reader=None)
            _qualify_numeric_worker_candidate_v3(p,b,request,job,original_intent)
            _qualify_numeric_configuration_candidate_v3(p,b,request,job,reader.workflows.life_numeric,original_intent,work.now_utc)
            _qualify_numeric_budget_candidate_v3(p,quote,reservation,reserve,original_intent,work.now_utc)
            if model._admin_model_matches(original_intent,request)is not True:
                raise AuthorityUnavailable("Numeric MODEL qualification actual administrator policy unavailable")
            parent=reader.readers.issuer.current_budget_grant(db,quote.parent_budget_lease_ref)
            deadline_bounds=life_numeric_deadline_bounds_v3(p,b,request,job,quote=quote,parent=parent)
            deadline_bounds+=(("model_read",work.deadline_utc),)
            actual=p.frozen.appraisal.input
            occurrence_bounds=(("occurrence_completed_at",actual.event.occurred_until),
                ("source_recorded_at",actual.sources[0].record.recorded_at))
            from ..runtime.d06_life_numeric_context_v1 import require_life_numeric_occurrence_time_v3
            require_life_numeric_occurrence_time_v3(work.now_utc,**dict(occurrence_bounds))
            status,reason="qualified",""
            rule="original"if case=="original"else"worker"if case in {"worker_subject","worker_fence"}else"budget"
            if case!="original":
                expected=_WORKER_REASON if rule=="worker"else _BUDGET_REASON
                try:
                    if rule=="worker":_qualify_numeric_worker_candidate_v3(p,b,request,job,candidate_intent)
                    else:_qualify_numeric_budget_candidate_v3(p,quote,reservation,reserve,candidate_intent,work.now_utc)
                except ValueError as exc:
                    if str(exc)!=expected:raise
                    status,reason="refused",str(exc)
            return NumericModelCandidateQualificationV3(case,status,rule,reason,float(work.now_utc),
                min(v for _,v in deadline_bounds),original_intent.authority_id,original_intent.namespace,
                installation_id,original_intent.job_id,original_intent.operation_id,
                canonical_digest(asdict(original_intent)),canonical_digest(asdict(candidate_intent)),
                canonical_digest(asdict(original_permit)),current.current_scope_digest,current.owner_guard.authorization_head,deadline_bounds,occurrence_bounds)
        result=read_authority_graph_current_v3(work,qualify)
        after=_require_original_model_current_v3(model,credential=credential,subject=subject,holder=holder,
            original=original_intent,permit=original_permit)
        if after!=before:raise AuthorityUnavailable("Numeric MODEL qualification original prepared record changed")
        return result
    finally:
        finish_authority_graph_read_work_v3(work)
