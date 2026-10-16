"""Closed Artifact business/control read carrier. These values grant no authority."""
from __future__ import annotations
from dataclasses import dataclass,fields
from ..graph_types import GraphVersion,AtomKey
from ..runtime_contracts import NamespaceId
from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2,artifact_draft_from_wire_v2
from .domain_production_contracts_v1 import ProductionQueryCoverageV1,ProductionOperationLimitsV1
from .domain_production_erasure_v1 import decode_typed_production_value_v1

ARTIFACT_MODEL_CONTROL_PROVENANCE_V1="artifact_model_control_reads_v1"
ARTIFACT_MODEL_CONTROL_KINDS_V1=frozenset({"prepare_artifact_draft_model_v2","acquire_artifact_draft_model_v2"})

def _digest_v1(value):
    if type(value)is not str or len(value)!=64 or any(c not in "0123456789abcdef"for c in value):
        raise ValueError("Artifact control requires its actual SHA256 commitment")

@dataclass(frozen=True,slots=True)
class ArtifactHabitClassificationV3:
    kind:str
    phase_selector:ArtifactDraftPhaseSelectorV2
    selector_commitment:str
    metadata_eof_commitment:str
    selection_operation_id:str
    selection_original_digest:str
    selection_receipt_digest:str
    prepared_candidates_operation_id:str
    prepared_candidates_original_digest:str
    prepared_candidates_receipt_digest:str
    qualification_original:object|None
    core_current:object|None
    schema:str="d10.artifact-habit-classification.v3"
    def __post_init__(self):
        if(self.schema!="d10.artifact-habit-classification.v3"or self.kind not in {"ordinary","habit"}
                or type(self.phase_selector)is not ArtifactDraftPhaseSelectorV2
                or any(type(v)is not str or not v for v in(self.selection_operation_id,self.prepared_candidates_operation_id))):
            raise ValueError("Artifact classification requires its exact original selected generation/producer")
        for value in(self.selector_commitment,self.metadata_eof_commitment,self.selection_original_digest,
                self.selection_receipt_digest,self.prepared_candidates_original_digest,self.prepared_candidates_receipt_digest):_digest_v1(value)
        from ..authority_service.d10_habit_contract_v1 import HabitOccurrenceQualificationOriginalV1
        from ..authority_service.current_habit_occurrence_v1 import HabitOccurrenceCurrentV1
        from ..authority_service.current_habit_artifact_restriction_v1 import HabitArtifactModelReadSelectorV3
        q,current=self.qualification_original,self.core_current
        if self.kind=="ordinary":
            if q is not None or current is not None:raise ValueError("Ordinary Artifact cannot borrow Habit birth evidence")
        elif(not self.phase_selector.generation or type(q)is not HabitOccurrenceQualificationOriginalV1 or type(current)is not HabitOccurrenceCurrentV1
                or type(current.request)is not HabitArtifactModelReadSelectorV3
                or current.qualification_original!=q or current.request.qualification_selector!=q.selector
                or current.request.artifact_phase_selector!=self.phase_selector
                or q.namespace!=self.phase_selector.task.namespace):
            raise ValueError("Habit Artifact classification changed its exact old qualification/current-read selector")

def artifact_habit_classification_from_wire_v3(raw):
    from ..authority_service.d10_habit_contract_v1 import habit_occurrence_qualification_from_wire_v1
    from ..authority_service.current_habit_occurrence_v1 import habit_current_from_wire_v1
    if type(raw)is not dict or set(raw)!={f.name for f in fields(ArtifactHabitClassificationV3)}:
        raise ValueError("Artifact Habit classification exact fields differ")
    value=ArtifactHabitClassificationV3(**{**raw,
        "phase_selector":artifact_draft_from_wire_v2(raw["phase_selector"],ArtifactDraftPhaseSelectorV2),
        "qualification_original":None if raw["qualification_original"]is None else habit_occurrence_qualification_from_wire_v1(raw["qualification_original"]),
        "core_current":None if raw["core_current"]is None else habit_current_from_wire_v1(raw["core_current"])})
    from ..domains.d01.production_operations_v1 import plain_v1
    if plain_v1(value)!=raw:raise ValueError("Artifact classification canonical typed wire differs")
    return value

def _versions_v1(value,namespace):
    if(type(value)is not tuple or len(value)>ProductionOperationLimitsV1().max_graph_heads
            or any(type(v)is not GraphVersion or NamespaceId.from_key(v.key)!=namespace
                or type(v.revision)is not int or v.revision<0 for v in value)
            or len({v.key for v in value})!=len(value)):
        raise ValueError("Artifact control exact namespace/current-or-negative version tuple differs")
    return {v.key:v.revision for v in value}

def _coverage_v1(value,namespace,versions):
    if(type(value)is not tuple or any(type(v)is not ProductionQueryCoverageV1 for v in value)
            or len({v.type_id for v in value})!=len(value)):
        raise ValueError("Artifact control requires its exact typed complete query coverage")
    for page in value:
        if(page.epoch.namespace!=namespace or not page.complete or page.continuation_ref is not None
                or len(page.row_versions)>ProductionOperationLimitsV1().max_query_rows
                or any(versions.get(v.key)!=v.revision for v in page.row_versions)):
            raise ValueError("Artifact control coverage differs from actual selected versions")

@dataclass(frozen=True,slots=True)
class ArtifactModelControlReadsV1:
    operation_kind:str
    request_digest:str
    business_read_versions:tuple[GraphVersion,...]
    business_query_coverage:tuple[ProductionQueryCoverageV1,...]
    control_read_versions:tuple[GraphVersion,...]
    control_query_coverage:tuple[ProductionQueryCoverageV1,...]
    control_body_versions:tuple[GraphVersion,...]
    control_metadata_versions:tuple[GraphVersion,...]
    control_source_purpose_groups:tuple[tuple[str,tuple[str,...],tuple[str,...],tuple[str,...]],...]
    habit_classification:ArtifactHabitClassificationV3
    schema:str="d11.artifact-model-control-reads.v1"
    def __post_init__(self):
        if(self.schema!="d11.artifact-model-control-reads.v1"or self.operation_kind not in ARTIFACT_MODEL_CONTROL_KINDS_V1
                or type(self.habit_classification)is not ArtifactHabitClassificationV3):
            raise ValueError("Artifact B/C carrier is reserved for exact prepare/acquire V2 operations")
        _digest_v1(self.request_digest);ns=self.habit_classification.phase_selector.task.namespace
        b=_versions_v1(self.business_read_versions,ns);c=_versions_v1(self.control_read_versions,ns)
        body=_versions_v1(self.control_body_versions,ns);meta=_versions_v1(self.control_metadata_versions,ns)
        if(any(key in b and b[key]!=rev for key,rev in c.items())
                or set(body)&set(meta)or {**body,**meta}!=c
                or len(set(b)|set(c))>ProductionOperationLimitsV1().max_graph_heads):
            raise ValueError("Artifact B/C overlap or actual Body/metadata partition differs")
        _coverage_v1(self.business_query_coverage,ns,b);_coverage_v1(self.control_query_coverage,ns,c)
        epochs={page.epoch for page in(*self.business_query_coverage,*self.control_query_coverage)}
        if len(epochs)>1:raise ValueError("Artifact B/C queries must share their original actual epoch")
        if type(self.control_source_purpose_groups)is not tuple:
            raise TypeError("Artifact control Source groups require their fixed tuple")
        names=set()
        for group in self.control_source_purpose_groups:
            if type(group)is not tuple or len(group)!=4:
                raise ValueError("Artifact control Source group has another exact shape")
            name,roots,purposes,audiences=group
            from ..memory_types import _PURPOSES
            allowed={"habit_context":frozenset({"context"}),"business_consolidation":frozenset({"consolidation"}),
                "joint_longterm_plan":_PURPOSES,
                "joint_window_node":frozenset({"context","expression","consolidation"})}.get(name)
            if(allowed is None or name in names or type(purposes)is not tuple or len(purposes)!=1
                    or purposes[0]not in allowed or type(roots)is not tuple
                    or not roots or len(roots)>ProductionOperationLimitsV1().max_source_roots
                    or len(set(roots))!=len(roots)or type(audiences)is not tuple or not audiences
                    or len(set(audiences))!=len(audiences)or any(type(v)is not str or not v for v in audiences)):
                raise ValueError("Artifact control Source group changed actual fixed purpose/audience/roots")
            names.add(name)
            for ref in roots:
                key=AtomKey.from_token(ref)
                if NamespaceId.from_key(key)!=ns or key.type_name!="memory.source"or key not in c:
                    raise ValueError("Artifact control group root is outside its exact current control reads")

def artifact_model_control_reads_to_wire_v1(value):
    if type(value)is not ArtifactModelControlReadsV1:raise TypeError("Exact Artifact control typed value required")
    from ..domains.d01.production_operations_v1 import plain_v1
    return plain_v1(value)

def artifact_model_control_reads_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(ArtifactModelControlReadsV1)}:
        raise ValueError("Artifact control carrier exact fields differ")
    data=dict(raw)
    for name in("business_read_versions","control_read_versions","control_body_versions","control_metadata_versions"):
        data[name]=tuple(decode_typed_production_value_v1(v,GraphVersion)for v in raw[name])
    for name in("business_query_coverage","control_query_coverage"):
        data[name]=tuple(decode_typed_production_value_v1(v,ProductionQueryCoverageV1)for v in raw[name])
    data["control_source_purpose_groups"]=tuple((row[0],tuple(row[1]),tuple(row[2]),tuple(row[3]))for row in raw["control_source_purpose_groups"])
    data["habit_classification"]=artifact_habit_classification_from_wire_v3(raw["habit_classification"])
    value=ArtifactModelControlReadsV1(**data)
    if artifact_model_control_reads_to_wire_v1(value)!=raw:raise ValueError("Artifact control canonical typed wire differs")
    return value

def validate_artifact_model_control_provenance_v1(domain,kind,provenance):
    if type(provenance)is not dict or ARTIFACT_MODEL_CONTROL_PROVENANCE_V1 not in provenance:return None
    if domain!="d11"or kind not in ARTIFACT_MODEL_CONTROL_KINDS_V1:
        raise ValueError("Artifact control provenance belongs only to actual prepare/acquire V2")
    value=artifact_model_control_reads_from_wire_v1(provenance[ARTIFACT_MODEL_CONTROL_PROVENANCE_V1])
    if value.operation_kind!=kind:raise ValueError("Artifact control carrier changed its actual operation")
    selected=value.habit_classification;p=selected.phase_selector
    refs={v.key.token for v in(*value.business_read_versions,*value.control_read_versions)}
    refs.update((p.decision_ref,p.plan_ref,p.task.cycle_job_ref,p.task.root_registration_ref,
        selected.selection_operation_id,selected.prepared_candidates_operation_id))
    if selected.qualification_original is not None:
        q=selected.qualification_original;s=q.selector;current=selected.core_current
        refs.update((q.original_ref,s.occurrence_original_ref,s.cue_original_ref,s.standing_authorization_original_ref,
            s.policy_ref,s.recipe_ref,s.parent_root_grant_ref,*s.source_refs,current.request.occurrence_ref))
        refs.update(v.key.token for v in current.read_versions)
    return({key:row for key,row in provenance.items()if key!=ARTIFACT_MODEL_CONTROL_PROVENANCE_V1},tuple(sorted(refs)))
