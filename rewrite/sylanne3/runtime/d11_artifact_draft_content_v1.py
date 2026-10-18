"""Adopt paid C4 text as D06 authored/unknown Source in the actual W01 CAS."""

from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
from dataclasses import asdict,dataclass,fields
import json

from ..domains.d01.production_operations_v1 import plain_v1,stage_result_v1
from ..graph_types import AtomKey,GraphWrite,GraphVersion
from ..memory_types import SourceRecord,source_key,access_key,validate_access
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..model_broker.artifact_draft_v1 import (artifact_draft_task_selector_v1,artifact_draft_model_ids_v1,
    parse_artifact_draft_output_v1,MAX_TEXT_BYTES,ArtifactDraftTaskSelectorV1)
from .d11_artifact_draft_contract_v1 import FrozenDraftContentV1,DraftFileTargetV1,DraftActivityScopeV1,draft_from_wire_v1
from .d11_life_contract_v1 import LifeInputRefV1,life_from_wire_v1
from .d11_life_preparation_v1 import _read,_record,TABLE
from .d11_artifact_draft_model_v1 import (InstalledArtifactDraftModelReadersV1,
    read_artifact_draft_prepared_v1,read_artifact_draft_frozen_v1,_current_task)
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1


@dataclass(frozen=True,slots=True)
class AdoptArtifactDraftContentRequestV1:
    selector:ArtifactDraftTaskSelectorV1

    def __post_init__(self):
        if type(self.selector) is not ArtifactDraftTaskSelectorV1:raise TypeError("exact C4 content adoption locator required")


@dataclass(frozen=True,slots=True)
class ArtifactDraftContentAdoptionV1:
    selector:ArtifactDraftTaskSelectorV1
    prepared_digest:str
    content:FrozenDraftContentV1
    target:DraftFileTargetV1
    task_source:LifeInputRefV1
    recorded_at_utc:float
    paid_original_ref:str
    paid_original_digest:str
    result_original_ref:str
    result_original_digest:str
    model_terminal_digest:str
    activity_scope_ref:str
    activity_scope_digest:str
    original_deadline_utc:str
    algorithm_build_digest:str
    postcondition_build_digest:str
    adoption_operation_id:str
    schema:str="d11.artifact-draft-content-adoption.v1"

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import _digest
        if (self.schema!="d11.artifact-draft-content-adoption.v1" or type(self.selector) is not ArtifactDraftTaskSelectorV1
                or type(self.content) is not FrozenDraftContentV1 or type(self.target) is not DraftFileTargetV1
                or type(self.task_source) is not LifeInputRefV1 or self.content.content.ref not in self.content.source_refs
                or self.content.content_length>MAX_TEXT_BYTES):raise ValueError("exact adopted authored draft content required")
        for name in ("prepared_digest","paid_original_digest","result_original_digest","model_terminal_digest",
                "activity_scope_digest","algorithm_build_digest","postcondition_build_digest"):_digest(getattr(self,name))
        ids=artifact_draft_model_ids_v1(self.selector)
        if (self.paid_original_ref,self.result_original_ref,self.adoption_operation_id)!=(ids["paid"],ids["result"],ids["adopt"]):
            raise ValueError("C4 content changed its original paid/result/adoption identities")
        if len(canonical_serialize(plain_v1(self)).encode())>65536:raise ValueError("C4 adoption metadata exceeds64KiB")


def artifact_draft_content_from_wire_v1(raw,kind):
    from ..model_broker.artifact_draft_v1 import artifact_draft_from_wire_v1
    if kind not in {AdoptArtifactDraftContentRequestV1,ArtifactDraftContentAdoptionV1} or type(raw) is not dict or set(raw)!={f.name for f in fields(kind)}:
        raise ValueError("closed C4 content fields differ")
    data=dict(raw);data["selector"]=artifact_draft_from_wire_v1(data["selector"],ArtifactDraftTaskSelectorV1)
    if kind is ArtifactDraftContentAdoptionV1:
        data["content"]=draft_from_wire_v1(data["content"],FrozenDraftContentV1)
        data["target"]=draft_from_wire_v1(data["target"],DraftFileTargetV1)
        data["task_source"]=life_from_wire_v1(data["task_source"],LifeInputRefV1)
    value=kind(**data)
    if plain_v1(value)!=raw:raise ValueError("noncanonical C4 content wire")
    return value


@dataclass(frozen=True,slots=True)
class ArtifactDraftContentStageV1:
    frame:object
    stage:object
    prepared:object
    frozen:object
    source:SourceRecord
    output:object
    result_digest:str
    terminal_digest:str
    before_job:object
    after_job:object


def _adopt_current_artifact_draft_content(db,*,frame,request,installed_readers,phase):
    from ..authority_service.d11_artifact_draft_model_v1 import ArtifactDraftModelResultReadV1,artifact_draft_model_result_to_wire_v1
    from .model_cost_settlement import OriginalModelCostCommitV1
    from ..authority_service.d11_artifact_draft_model_v1 import ArtifactDraftModelResultReadV2, artifact_draft_model_result_to_wire_v2
    request_type = AdoptArtifactDraftContentRequestV2 if phase else AdoptArtifactDraftContentRequestV1
    result_type = ArtifactDraftModelResultReadV2 if phase else ArtifactDraftModelResultReadV1
    result_wire = artifact_draft_model_result_to_wire_v2 if phase else artifact_draft_model_result_to_wire_v1
    if type(request) is not request_type or type(installed_readers) is not InstalledArtifactDraftModelReadersV1:
        raise TypeError("actual C4 content adoption request/readers required")
    readers=installed_readers; selector = request.selector.task if phase else request.selector
    model_ids = artifact_draft_model_ids_v2 if phase else artifact_draft_model_ids_v1
    read_prepared = read_artifact_draft_prepared_v2 if phase else read_artifact_draft_prepared_v1
    read_frozen = read_artifact_draft_frozen_v2 if phase else read_artifact_draft_frozen_v1
    parse_output = parse_artifact_draft_output_v2 if phase else parse_artifact_draft_output_v1
    kind_prefix = 'c4_phase_' if phase else 'c4_'
    read,cycle,cont,root,family,mapping_atom,mapping=_current_task(db,frame=frame,selector=selector,readers=readers)
    ids=model_ids(request.selector)
    if frame.envelope.identity.operation_id!=ids["adopt"]:raise ValueError("C4 content adoption cannot change its original operation")
    prepared=read_prepared(db,namespace=selector.namespace,issuer=readers.issuer,selector=request.selector)
    if prepared is None:raise MissingProductionOriginalV1("actual_c4_prepared_before_content_adoption")
    frozen=read_frozen(db,prepared=prepared,issuer=readers.issuer)
    from ..host.authority_profile import require_installed_artifact_target_v2
    require_installed_artifact_target_v2(readers.installed_bundle.artifact_draft, root, frozen.target)
    from .jobs import get_job
    before_job=get_job(db,prepared.job_id)
    if (before_job.phase,before_job.fence,before_job.cancel_epoch,before_job.lease_holder,before_job.result_ref)!= (
            "running",1,0,prepared.worker_subject,None):raise ValueError("C4 authored source cannot adopt from a cancelled/unknown or different worker")
    if readers.model_runtime is None:raise MissingProductionOriginalV1("actual_paired_c4_result_and_once_cost_consumer")
    stored_paid=_read(db,issuer=readers.issuer,namespace=selector.namespace,kind=kind_prefix+"paid",ref=ids["paid"])
    stored_result=_read(db,issuer=readers.issuer,namespace=selector.namespace,kind=kind_prefix+"result",ref=ids["result"])
    if stored_paid is None or stored_result is None:
        raise MissingProductionOriginalV1("actual_committed_c4_result_and_paid_originals")
    from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v1, decode_artifact_draft_original_v2
    decode_original = decode_artifact_draft_original_v2 if phase else decode_artifact_draft_original_v1
    result=decode_original(kind_prefix+'result',stored_result[0])
    paid=decode_original(kind_prefix+'paid',stored_paid[0])
    if (type(result) is not result_type or type(paid) is not OriginalModelCostCommitV1
            or paid.status!="committed" or result.request.binding_digest!=prepared.digest
            or (paid.call_id,paid.quote_id,paid.quote_version,paid.terminal_receipt_digest)!=
                (prepared.call_id,prepared.quote_id,1,canonical_digest(asdict(result.terminal_receipt)))):
        raise ValueError("C4 content is not the actual paid once terminal/result")
    if stored_paid[0]!=plain_v1(paid) or stored_result[0]!=result_wire(result):
        raise MissingProductionOriginalV1("actual_committed_c4_result_and_paid_originals")
    read.original(ids["paid"],kind="d11.life_"+kind_prefix+"paid",digest=canonical_digest(stored_paid[0]))
    read.original(ids["result"],kind="d11.life_"+kind_prefix+"result",digest=canonical_digest(stored_result[0]))
    if result.observation.result_json is None:raise MissingProductionOriginalV1("actual_c4_result_body")
    provider=json.loads(result.observation.result_json)
    if type(provider) is not dict or set(provider)!={"text"}:raise ValueError("C4 actual provider response is not the registered text envelope")
    output=parse_output(provider["text"],frozen)
    if output.needs_clarification:raise MissingProductionOriginalV1("artifact_draft_needs_clarification:"+canonical_digest(output.gaps))
    if ((root.registration_ref,canonical_digest(plain_v1(root)),root.root_identity,root.resource_id,root.filenames)!=(
            frozen.target.root_registration_ref,frozen.target.root_registration_digest,frozen.target.root_identity,
            frozen.target.root_resource_id,(frozen.target.filename,))):raise ValueError("C4 adopted target changed from frozen model task")
    parent_refs=tuple(source.ref for source in frozen.sources)
    current=read.source_family(db,parent_refs,purpose="consolidation")
    audiences=set(frame.envelope.authority.audience);purposes={"context","expression","consolidation","audit"}
    for ref,record in current.items():
        access=read.head(db,access_key(*selector.namespace.as_tuple,record.source_id),required=True).value
        audiences.intersection_update(record.audiences,access["audiences"])
        purposes.intersection_update(record.purposes,access["purposes"])
        original=next((s for s in frozen.sources if s.ref==ref),None)
        if original is None or canonical_digest(record.to_dict())!=original.value_digest:
            raise ValueError("C4 actual complete parent source closure changed")
    if not audiences or not {"context","consolidation"}<=purposes:
        raise MissingProductionOriginalV1("actual_authored_draft_parent_scope_intersection")
    source=SourceRecord(ids["source"],output.draft_text,mapping.persona_ref,"authored","unknown",None,
        frame.now_utc,"c4-model:"+prepared.call_id,tuple(sorted(audiences)),tuple(sorted(purposes)),
        tuple(record.source_id for _,record in sorted(current.items())),"same_root")
    sk,ak=source_key(*selector.namespace.as_tuple,source.source_id),access_key(*selector.namespace.as_tuple,source.source_id)
    if read.head(db,sk).revision or read.head(db,ak).revision:raise ValueError("C4 authored content already exists; recover its original adoption")
    access={"source_id":source.source_id,"audiences":list(source.audiences),"purposes":list(source.purposes),
        "status":"active","recorded_at":source.recorded_at};validate_access(access)
    from ..domains.d06 import D06DomainProvider,_D06_PROPOSAL_SCHEMA
    stage=stage_result_v1(frame,"d06","adopt_artifact_draft_content_v2" if phase else "adopt_artifact_draft_content",request,
        writes=(GraphWrite(sk,source.to_dict()),GraphWrite(ak,access)),
        provenance={"schema":"d06.artifact-draft-phase-authored-source.v2" if phase else "d06.artifact-draft-authored-source.v1","prepared_digest":prepared.digest,
            "result_original_ref":ids["result"],"paid_original_ref":ids["paid"],"parent_source_refs":parent_refs,
            "content_digest":output.content_digest},costs=(read.original(ids["paid"]),),
        receiver_events=(("d11","artifact_draft_phase_content_adopted" if phase else "artifact_draft_content_adopted"),),proposal_schema=_D06_PROPOSAL_SCHEMA,
        proposal_hash=D06DomainProvider().descriptor.request_schema_hash)
    from dataclasses import replace
    from .d11_types import job_graph_write
    from .d11_artifact_draft_model_v1 import C4_MODEL_PROPOSAL_SCHEMA,C4_MODEL_PROPOSAL_HASH,C4_PHASE_MODEL_PROPOSAL_SCHEMA_V2,C4_PHASE_MODEL_PROPOSAL_HASH_V2
    after_job=replace(before_job,phase="completed",lease_holder=None,lease_expires_utc=None,result_ref=ids["adopt"])
    runtime_stage=stage_result_v1(frame,"d11","adopt_artifact_draft_content_v2" if phase else "adopt_artifact_draft_content",request,writes=(job_graph_write(after_job),),
        provenance={"prepared_digest":prepared.digest,"actual_source_ref":sk.token,"actual_paid_ref":ids["paid"]},
        proposal_schema=C4_PHASE_MODEL_PROPOSAL_SCHEMA_V2 if phase else C4_MODEL_PROPOSAL_SCHEMA,
        proposal_hash=C4_PHASE_MODEL_PROPOSAL_HASH_V2 if phase else C4_MODEL_PROPOSAL_HASH)
    stage=replace(stage,proposals=(*stage.proposals,*runtime_stage.proposals))
    return (ArtifactDraftContentStageV2 if phase else ArtifactDraftContentStageV1)(frame,stage,prepared,frozen,source,output,canonical_digest(stored_result[0]),canonical_digest(result.terminal_receipt),before_job,after_job)



def adopt_current_artifact_draft_content_v1(db, *, frame, request, installed_readers):
    return _adopt_current_artifact_draft_content(db, frame=frame, request=request, installed_readers=installed_readers, phase=False)


def adopt_current_artifact_draft_content_v2(db, *, frame, request, installed_readers):
    return _adopt_current_artifact_draft_content(db, frame=frame, request=request, installed_readers=installed_readers, phase=True)


def validate_artifact_draft_content_job_proposal_v1(proposal,snapshot,stage):
    from .d11_types import job_graph_write
    from .d11_artifact_draft_model_v1 import C4_MODEL_PROPOSAL_SCHEMA,C4_MODEL_PROPOSAL_HASH,C4_PHASE_MODEL_PROPOSAL_SCHEMA_V2,C4_PHASE_MODEL_PROPOSAL_HASH_V2
    from dataclasses import replace
    if (type(stage) not in {ArtifactDraftContentStageV1, ArtifactDraftContentStageV2} or proposal.domain!="d11"
            or (proposal.proposal_schema,proposal.proposal_schema_hash)!=(C4_PHASE_MODEL_PROPOSAL_SCHEMA_V2 if type(stage) is ArtifactDraftContentStageV2 else C4_MODEL_PROPOSAL_SCHEMA,
                C4_PHASE_MODEL_PROPOSAL_HASH_V2 if type(stage) is ArtifactDraftContentStageV2 else C4_MODEL_PROPOSAL_HASH)
            or proposal.envelope!=stage.frame.envelope or proposal.envelope.authority.actor!=stage.prepared.actor_ref
            or proposal.typed_writes!=(job_graph_write(stage.after_job),)):
        raise ValueError("C4 completed job is not its actual paid/source adoption bundle")
    before=snapshot.get(job_graph_write(stage.before_job).key)
    if before is None or not before.valid or before.value!=job_graph_write(stage.before_job).value:
        raise ValueError("C4 completed job lost its actual acquired predecessor")
    expected=replace(stage.before_job,phase="completed",lease_holder=None,lease_expires_utc=None,
        result_ref=_artifact_model_ids(stage.prepared)["adopt"])
    if expected!=stage.after_job:raise ValueError("C4 content adoption changed unrelated worker fields")
    return proposal


def apply_artifact_draft_content_stage_v1(witness,graph,db,installed_readers):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE,_FOREGROUND_VALIDATED,_FOREGROUND_APPLIED,_require_foreground_witness_v1
    from .jobs import get_job,_save_job,_record_operation
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or _FOREGROUND_VALIDATED.get(id(witness)) is not witness or id(witness) in _FOREGROUND_APPLIED
            or type(witness.stage) not in {ArtifactDraftContentStageV1, ArtifactDraftContentStageV2} or witness.graph is not graph
            or db is not graph._GraphCoordinator__store._db or not db.in_transaction):
        raise ValueError("C4 source/job adoption requires actual privately validated once W01 apply")
    _require_foreground_witness_v1(witness,graph,db,witness.bundle)
    stage=witness.stage
    rebuilt=_adopt_current_artifact_draft_content(db,frame=stage.frame,request=witness.request,installed_readers=installed_readers,phase=type(stage) is ArtifactDraftContentStageV2)
    if rebuilt!=stage or get_job(db,stage.before_job.job_id)!=stage.before_job:
        raise ValueError("C4 paid/current-source/worker changed at final source adoption CAS")
    _save_job(db,stage.after_job)
    _record_operation(db,stage.after_job,stage.frame.envelope.identity.operation_id,"checkpoint",canonical_digest(plain_v1(stage.after_job)))
    _FOREGROUND_APPLIED[id(witness)]=witness
    return True


def read_plan_artifact_draft_content_adoption_v1(db,*,namespace,request):
    from .d11_artifact_draft_model_v1 import read_plan_artifact_draft_model_v1,AcquireArtifactDraftModelRequestV1
    from .d01_production_operations_v1 import production_read_plan_v1
    if type(request) is not AdoptArtifactDraftContentRequestV1:raise TypeError("exact C4 content adoption readplan required")
    base=read_plan_artifact_draft_model_v1(db,namespace=namespace,operation_kind="acquire_artifact_draft_model",
        request=AcquireArtifactDraftModelRequestV1(request.selector))
    ids=artifact_draft_model_ids_v1(request.selector)
    return production_read_plan_v1(base.fixed_type_ids,(*base.exact_keys,source_key(*namespace.as_tuple,ids["source"]),
        access_key(*namespace.as_tuple,ids["source"])),base.source_roots,(*base.required_original_refs,ids["paid"],ids["result"]))


def record_artifact_draft_content_after_cas_v1(db,*,stage,receipt,installed_readers):
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    if type(stage) not in {ArtifactDraftContentStageV1, ArtifactDraftContentStageV2} or receipt.operation_id!=stage.frame.envelope.identity.operation_id:
        raise TypeError("C4 content original requires the actual same-transaction CAS receipt")
    read=CurrentDomainReadV1(stage.frame);read.committed_operation(db,receipt.operation_id)
    p,f=stage.prepared,stage.frozen;ids=_artifact_model_ids(p)
    phase = _artifact_model_phase_v2(p)
    task_selector = p.selector.task if phase else p.selector
    adoption_type = ArtifactDraftContentAdoptionV2 if phase else ArtifactDraftContentAdoptionV1
    metadata = {}
    if phase:
        from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
        _, chosen, _ = _read_artifact_phase_selected_originals_v2(db, selector=p.selector, issuer=installed_readers.issuer)
        if type(chosen.binding) not in {ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3}:
            raise MissingProductionOriginalV1('actual_registered_whole_method_extent')
        metadata = dict(extent=f.extent, full_extent=chosen.binding.full_extent,
            extent_original_ref=chosen.binding.extent_original_ref, extent_original_digest=chosen.binding.extent_original_digest)
    sk=source_key(*p.namespace.as_tuple,stage.source.source_id)
    revisions={v.key.token:v.revision for v in receipt.write_versions}
    actual=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",(sk.token,)).fetchone()
    if actual!=(revisions.get(sk.token),canonical_serialize(stage.source.to_dict()),1):
        raise ValueError("C4 authored Source is not a real member of this adoption CAS")
    from .d11_types import job_graph_write
    jw=job_graph_write(stage.after_job)
    if db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(jw.key.token,)).fetchone()!= (canonical_serialize(jw.value),1):
        raise ValueError("C4 completed job is not in the same actual authored Source CAS")
    scope_rows=db.execute("SELECT original_ref FROM "+TABLE+" WHERE bot=? AND persona=? AND kind='activity_scope' AND producing_operation_id=? LIMIT 2",
        (*p.namespace.as_tuple,receipt.operation_id)).fetchall()
    if len(scope_rows)!=1:raise MissingProductionOriginalV1("actual_self_foreground_scope_recorded_in_c4_adoption_CAS")
    scope_raw=_read(db,issuer=installed_readers.issuer,namespace=p.namespace,kind="activity_scope",ref=scope_rows[0][0])
    scope=draft_from_wire_v1(scope_raw[0],DraftActivityScopeV1)
    task=next(s for s in f.sources if s.ref==f.task_source_ref)
    if (scope.actor_ref,scope.source.ref,scope.c02_original_ref,scope.root_registration_ref,scope.parent_budget_lease_ref)!= (
            p.actor_ref,f.task_source_ref,task_selector.c02_operation_id,f.target.root_registration_ref,p.parent_budget_lease_ref):
        raise ValueError("C4 adopted activity scope belongs to another actual task/root/self")
    paid=_read(db,issuer=installed_readers.issuer,namespace=p.namespace,kind=_artifact_model_original_kind(p,"paid"),ref=ids["paid"])
    runtime=installed_readers.model_runtime
    build=read_installed_d11_life_build_v1(runtime.authority_client._package_root,p.manifest_digest,recipe_id="artifact_draft_v1")
    content_ref=LifeInputRefV1(sk.token,actual[0],canonical_digest(stage.source.to_dict()))
    content=FrozenDraftContentV1(content_ref,stage.output.content_digest,len(stage.source.text.encode()),
        (sk.token,*(s.ref for s in f.sources)))
    adopted=adoption_type(p.selector,p.digest,content,f.target,
        LifeInputRefV1(task.ref,task.revision,task.value_digest),stage.source.recorded_at,
        ids["paid"],canonical_digest(paid[0]),ids["result"],stage.result_digest,stage.terminal_digest,
        scope_rows[0][0],canonical_digest(scope_raw[0]),p.deadline_utc,build["algorithm_build_digest"],
        build["postcondition_build_digest"],receipt.operation_id, **metadata)
    return _record(db,issuer=installed_readers.issuer,namespace=p.namespace,kind=_artifact_model_original_kind(p,"adopted"),ref=ids["adopt"],operation_id=receipt.operation_id,value=adopted)


def _read_current_adopted_artifact_draft_content(db, *, frame, selector, installed_readers, phase):
    task_selector = selector.task if phase else selector
    namespace = task_selector.namespace
    ids = (artifact_draft_model_ids_v2 if phase else artifact_draft_model_ids_v1)(selector)
    kind_prefix = 'c4_phase_' if phase else 'c4_'
    adoption_type = ArtifactDraftContentAdoptionV2 if phase else ArtifactDraftContentAdoptionV1
    decode_content = artifact_draft_content_from_wire_v2 if phase else artifact_draft_content_from_wire_v1
    read_prepared = read_artifact_draft_prepared_v2 if phase else read_artifact_draft_prepared_v1
    raw=_read(db,issuer=installed_readers.issuer,namespace=namespace,kind=kind_prefix+"adopted",ref=ids["adopt"])
    if raw is None:raise MissingProductionOriginalV1("actual_adopted_c4_authored_content")
    adopted=decode_content(raw[0],adoption_type)
    if adopted.selector!=selector or raw[1]!=adopted.adoption_operation_id:raise ValueError("C4 adopted selector/producing CAS differs")
    read=CurrentDomainReadV1(frame);read.check(db)
    _,_,_,_,_,_,mapping=_current_task(db,frame=frame,selector=task_selector,readers=installed_readers)
    read.source_family(db,adopted.content.source_refs,purpose="consolidation")
    source=read.head(db,adopted.content.content.ref,required=True)
    record=SourceRecord.from_dict(source.value)
    import hashlib
    if (source.revision,canonical_digest(source.value),record.source_kind,record.assertion_status,record.recorded_at,
            hashlib.sha256(record.text.encode()).hexdigest(),len(record.text.encode()))!= (
            adopted.content.content.revision,adopted.content.content.digest,"authored","unknown",adopted.recorded_at_utc,
            adopted.content.content_digest,adopted.content.content_length):raise ValueError("C4 actual adopted authored Source changed")
    if record.speaker_id!=mapping.persona_ref:raise ValueError("C4 authored content speaker is not the actual current self")
    p=read_prepared(db,namespace=namespace,issuer=installed_readers.issuer,selector=selector)
    if p is None or p.digest!=adopted.prepared_digest:raise ValueError("C4 adopted content lost original prepared seal")
    for kind,ref,digest in ((kind_prefix+"paid",adopted.paid_original_ref,adopted.paid_original_digest),
            (kind_prefix+"result",adopted.result_original_ref,adopted.result_original_digest),
            ("activity_scope",adopted.activity_scope_ref,adopted.activity_scope_digest)):
        original=_read(db,issuer=installed_readers.issuer,namespace=namespace,kind=kind,ref=ref)
        if original is None or canonical_digest(original[0])!=digest:raise ValueError("C4 adopted content lost actual signed predecessor:"+kind)
        read.original(ref,kind="d11.life_"+kind,digest=digest)
    read.original(ids["adopt"],kind="d11.life_"+kind_prefix+"adopted",digest=canonical_digest(raw[0]))
    return adopted



def read_current_adopted_artifact_draft_content_v1(db, *, frame, c02_operation_id, root_registration_ref, installed_readers):
    selector = artifact_draft_task_selector_v1(frame.envelope.authority.namespace,
        c02_operation_id=c02_operation_id, root_registration_ref=root_registration_ref)
    return _read_current_adopted_artifact_draft_content(db, frame=frame, selector=selector, installed_readers=installed_readers, phase=False)


def read_current_adopted_artifact_draft_content_v2(db, *, frame, selector, installed_readers):
    if type(selector) is not ArtifactDraftPhaseSelectorV2 or not selector.generation:
        raise TypeError('exact generation phase content selector required')
    return _read_current_adopted_artifact_draft_content(db, frame=frame, selector=selector, installed_readers=installed_readers, phase=True)


def read_plan_artifact_draft_content_v1(db,*,namespace,c02_operation_id,root_registration_ref):
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    selector=artifact_draft_task_selector_v1(namespace,c02_operation_id=c02_operation_id,root_registration_ref=root_registration_ref)
    ids=artifact_draft_model_ids_v1(selector)
    row=_artifact_receipt_sql_v1(db,"SELECT payload_json FROM "+TABLE+" WHERE bot=? AND persona=? AND kind='c4_adopted' AND original_ref=?",
        (*namespace.as_tuple,ids["adopt"])).fetchone()
    if row is None:return (),(),(ids["adopt"],)
    a=artifact_draft_content_from_wire_v1(background_json_loads_v3(row[0]),ArtifactDraftContentAdoptionV1)
    return ((AtomKey.from_token(a.content.content.ref),AtomKey.from_token(a.task_source.ref)),a.content.source_refs,
        (ids["job"],ids["frozen"],ids["adopt"],a.paid_original_ref,a.result_original_ref,a.activity_scope_ref,root_registration_ref))


from dataclasses import field, replace
from ..model_broker.artifact_draft_v1 import (ArtifactDraftPhaseSelectorV2, ArtifactDraftTextExtentV2,
    ArtifactDraftPriorContentCommitmentV2, artifact_draft_from_wire_v2, artifact_draft_model_ids_v2,
    artifact_draft_file_ids_v2, artifact_draft_phase_original_ref_v2, artifact_draft_phase_sequence_v2,
    artifact_draft_character_count_v2, parse_artifact_draft_output_v2)
from .d11_artifact_draft_model_v1 import (ArtifactDraftModelPreparedV2, read_artifact_draft_prepared_v2,
    read_artifact_draft_frozen_v2, _artifact_model_ids, _artifact_model_phase_v2,
    _artifact_model_original_kind, _read_artifact_phase_selected_originals_v2)

@dataclass(frozen=True,slots=True)
class AdoptArtifactDraftContentRequestV2:
    selector:ArtifactDraftPhaseSelectorV2

    def __post_init__(self):
        if type(self.selector) is not ArtifactDraftPhaseSelectorV2:raise TypeError("exact C4 content adoption locator required")


@dataclass(frozen=True,slots=True)
class ArtifactDraftContentAdoptionV2:
    selector:ArtifactDraftPhaseSelectorV2
    prepared_digest:str
    content:FrozenDraftContentV1
    target:DraftFileTargetV1
    task_source:LifeInputRefV1
    recorded_at_utc:float
    paid_original_ref:str
    paid_original_digest:str
    result_original_ref:str
    result_original_digest:str
    model_terminal_digest:str
    activity_scope_ref:str
    activity_scope_digest:str
    original_deadline_utc:str
    algorithm_build_digest:str
    postcondition_build_digest:str
    adoption_operation_id:str
    extent:ArtifactDraftTextExtentV2 = field(kw_only=True)
    full_extent:ArtifactDraftTextExtentV2 = field(kw_only=True)
    extent_original_ref:str = field(kw_only=True)
    extent_original_digest:str = field(kw_only=True)
    schema:str="d11.artifact-draft-phase-content-adoption.v2"

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import _digest
        if (self.schema!="d11.artifact-draft-phase-content-adoption.v2" or type(self.selector) is not ArtifactDraftPhaseSelectorV2
                or type(self.content) is not FrozenDraftContentV1 or type(self.target) is not DraftFileTargetV1
                or type(self.task_source) is not LifeInputRefV1 or self.content.content.ref not in self.content.source_refs
                or self.content.content_length>MAX_TEXT_BYTES):raise ValueError("exact adopted authored draft content required")
        for name in ("prepared_digest","paid_original_digest","result_original_digest","model_terminal_digest",
                "activity_scope_digest","algorithm_build_digest","postcondition_build_digest"):_digest(getattr(self,name))
        if (type(self.extent) is not ArtifactDraftTextExtentV2 or type(self.full_extent) is not ArtifactDraftTextExtentV2
                or not self.selector.generation or self.selector.phase_kind == 'full' and self.extent != self.full_extent):
            raise ValueError('phase adoption must preserve exact registered whole-method extent')
        from ..model_broker.artifact_draft_v1 import _text
        _text(self.extent_original_ref, 'extent original'); _digest(self.extent_original_digest)
        ids=artifact_draft_model_ids_v2(self.selector)
        if (self.paid_original_ref,self.result_original_ref,self.adoption_operation_id)!=(ids["paid"],ids["result"],ids["adopt"]):
            raise ValueError("C4 content changed its original paid/result/adoption identities")
        if len(canonical_serialize(plain_v1(self)).encode())>65536:raise ValueError("C4 adoption metadata exceeds64KiB")



@dataclass(frozen=True, slots=True)
class ArtifactDraftContentStageV2:
    frame:object
    stage:object
    prepared:object
    frozen:object
    source:SourceRecord
    output:object
    result_digest:str
    terminal_digest:str
    before_job:object
    after_job:object


def artifact_draft_content_from_wire_v2(raw, kind):
    if (kind not in {AdoptArtifactDraftContentRequestV2, ArtifactDraftContentAdoptionV2}
            or type(raw) is not dict or set(raw) != {item.name for item in fields(kind)}):
        raise ValueError('closed phase content fields differ')
    data = dict(raw)
    data['selector'] = artifact_draft_from_wire_v2(data['selector'], ArtifactDraftPhaseSelectorV2)
    if kind is ArtifactDraftContentAdoptionV2:
        data['content'] = draft_from_wire_v1(data['content'], FrozenDraftContentV1)
        data['target'] = draft_from_wire_v1(data['target'], DraftFileTargetV1)
        data['task_source'] = life_from_wire_v1(data['task_source'], LifeInputRefV1)
        for name in ('extent', 'full_extent'):
            data[name] = artifact_draft_from_wire_v2(data[name], ArtifactDraftTextExtentV2)
    value = kind(**data)
    if plain_v1(value) != raw: raise ValueError('noncanonical phase content wire')
    return value


def validate_artifact_draft_content_job_proposal_v2(proposal, snapshot, stage):
    if type(stage) is not ArtifactDraftContentStageV2: raise TypeError('exact phase content stage required')
    return validate_artifact_draft_content_job_proposal_v1(proposal, snapshot, stage)


def apply_artifact_draft_content_stage_v2(witness, graph, db, installed_readers):
    if type(witness.stage) is not ArtifactDraftContentStageV2: raise TypeError('exact phase content stage required')
    return apply_artifact_draft_content_stage_v1(witness, graph, db, installed_readers)


def record_artifact_draft_content_after_cas_v2(db, *, stage, receipt, installed_readers):
    if type(stage) is not ArtifactDraftContentStageV2: raise TypeError('exact phase content stage required')
    return record_artifact_draft_content_after_cas_v1(db, stage=stage, receipt=receipt, installed_readers=installed_readers)


def read_plan_artifact_draft_content_adoption_v2(db, *, namespace, request, installed_readers=None):
    from .d11_artifact_draft_model_v1 import read_plan_artifact_draft_model_v2, AcquireArtifactDraftModelRequestV2
    from .d01_production_operations_v1 import production_read_plan_v1
    if type(request) is not AdoptArtifactDraftContentRequestV2: raise TypeError('exact phase content adoption request required')
    base = read_plan_artifact_draft_model_v2(db, namespace=namespace, operation_kind='acquire_artifact_draft_model_v2',
        request=AcquireArtifactDraftModelRequestV2(request.selector), installed_readers=installed_readers)
    ids = artifact_draft_model_ids_v2(request.selector)
    return production_read_plan_v1(base.fixed_type_ids, (*base.exact_keys, source_key(*namespace.as_tuple, ids['source']),
        access_key(*namespace.as_tuple, ids['source'])), base.source_roots, (*base.required_original_refs, ids['paid'], ids['result']))


from .d11_artifact_draft_contract_v1 import DraftFileReadbackV1
from .domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionOwnerGuardV1


@dataclass(frozen=True, slots=True)
class VerifyArtifactDraftPhaseRequestV2:
    selector: ArtifactDraftPhaseSelectorV2
    file_result_ref: str
    postcondition_original_refs: tuple[str, ...] = ()

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import _text
        if type(self.selector) is not ArtifactDraftPhaseSelectorV2:
            raise TypeError('phase verification accepts only its actual closed selector')
        _text(self.file_result_ref, 'actual file result')
        if (type(self.postcondition_original_refs) is not tuple or len(self.postcondition_original_refs) > 8
                or len(set(self.postcondition_original_refs)) != len(self.postcondition_original_refs)):
            raise ValueError('phase verification accepts bounded original locators')
        for ref in self.postcondition_original_refs: _text(ref, 'postcondition original')
        if self.selector.generation and self.postcondition_original_refs:
            raise ValueError('generation structural verification cannot claim method qualification')


@dataclass(frozen=True, slots=True)
class ArtifactDraftPhaseVerifiedOriginalV2:
    selector: ArtifactDraftPhaseSelectorV2
    content_selector: ArtifactDraftPhaseSelectorV2
    content_adoption_ref: str
    content_adoption_digest: str
    source_head: GraphVersion
    source_value_digest: str
    readback: DraftFileReadbackV1
    readback_original_ref: str
    readback_original_digest: str
    extent: ArtifactDraftTextExtentV2
    full_extent: ArtifactDraftTextExtentV2
    extent_original_ref: str
    extent_original_digest: str
    original_deadline_utc: str
    prev_verified_original_ref: str | None
    prev_verified_original_digest: str | None
    postcondition_originals: tuple[ProductionOriginalRefV1, ...]
    owner_guard: ProductionOwnerGuardV1
    actor_ref: str
    current_self_digest: str
    producing_operation_id: str
    observed_at_utc: float
    structurally_verified: bool = True
    method_qualified: bool = False
    schema: str = 'd11.artifact-draft-phase-verified-original.v2'

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import _digest, _text
        from .d11_offline_originals_v1 import _utc
        import math
        if (self.schema != 'd11.artifact-draft-phase-verified-original.v2'
                or type(self.selector) is not ArtifactDraftPhaseSelectorV2
                or type(self.content_selector) is not ArtifactDraftPhaseSelectorV2 or not self.content_selector.generation
                or type(self.source_head) is not GraphVersion or self.source_head.revision < 1
                or self.source_head.key.type_name != 'memory.source'
                or NamespaceId.from_key(self.source_head.key) != self.selector.task.namespace
                or type(self.readback) is not DraftFileReadbackV1
                or type(self.extent) is not ArtifactDraftTextExtentV2 or type(self.full_extent) is not ArtifactDraftTextExtentV2
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or self.structurally_verified is not True or type(self.method_qualified) is not bool
                or self.method_qualified != (not self.selector.generation)
                or type(self.observed_at_utc) not in {float, int} or not math.isfinite(self.observed_at_utc)):
            raise ValueError('exact structurally verified phase with independent method qualification required')
        phases = artifact_draft_phase_sequence_v2(self.selector.method_ref)
        from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
        if (foreground_artifact_phase_group_identity_v2(self.selector) != foreground_artifact_phase_group_identity_v2(self.content_selector)
                or self.content_selector.phase_index != self.selector.phase_index - (0 if self.selector.generation else 1)
                or self.selector.generation and self.content_selector != self.selector
                or self.extent != (ArtifactDraftTextExtentV2(120, 180) if phases[self.content_selector.phase_index] == 'tone_sample' else self.full_extent)):
            raise ValueError('verification changed the actual previous generation or registered extent')
        if (self.prev_verified_original_ref, self.prev_verified_original_digest) != (
                self.selector.prev_phase_original_ref, self.selector.prev_phase_original_digest):
            raise ValueError('phase verified lost its immediately preceding original')
        for name in ('content_adoption_digest', 'source_value_digest', 'readback_original_digest',
                'extent_original_digest', 'current_self_digest'):
            _digest(getattr(self, name))
        for name in ('content_adoption_ref', 'readback_original_ref', 'extent_original_ref', 'actor_ref', 'producing_operation_id'):
            _text(getattr(self, name), name)
        if (self.content_adoption_ref != artifact_draft_model_ids_v2(self.content_selector)['adopt']
                or self.producing_operation_id != artifact_draft_phase_original_ref_v2(self.selector) + ':verify'
                or not self.observed_at_utc < _utc(self.original_deadline_utc).timestamp()
                or (self.readback.effect_id, self.readback.execution_call_id) !=
                    (artifact_draft_file_ids_v2(self.content_selector)['effect'], artifact_draft_file_ids_v2(self.content_selector)['execution_call'])):
            raise ValueError('verified original changed its actual adoption/file once identity/deadline')
        if (type(self.postcondition_originals) is not tuple
                or any(type(original) is not ProductionOriginalRefV1 for original in self.postcondition_originals)
                or self.selector.generation and self.postcondition_originals
                or not self.selector.generation and not self.postcondition_originals):
            raise ValueError('method qualification requires actual registered postcondition originals')
        if len(canonical_serialize(plain_v1(self)).encode()) > 65536:
            raise ValueError('phase verified metadata exceeds exact bound')

    @property
    def namespace(self): return self.selector.task.namespace

    @property
    def original_ref(self): return artifact_draft_phase_original_ref_v2(self.selector) + ':verified'

    @property
    def digest(self): return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class ArtifactDraftPhaseVerificationStageV2:
    frame: object
    stage: object
    verified: ArtifactDraftPhaseVerifiedOriginalV2


def artifact_draft_phase_verification_from_wire_v2(raw, kind):
    if (kind not in {VerifyArtifactDraftPhaseRequestV2, ArtifactDraftPhaseVerifiedOriginalV2}
            or type(raw) is not dict or set(raw) != {item.name for item in fields(kind)}):
        raise ValueError('closed phase verification fields differ')
    data = dict(raw)
    data['selector'] = artifact_draft_from_wire_v2(data['selector'], ArtifactDraftPhaseSelectorV2)
    if kind is VerifyArtifactDraftPhaseRequestV2:
        data['postcondition_original_refs'] = tuple(data['postcondition_original_refs'])
    else:
        data['content_selector'] = artifact_draft_from_wire_v2(data['content_selector'], ArtifactDraftPhaseSelectorV2)
        data['source_head'] = GraphVersion(AtomKey.from_token(data['source_head']['key']), data['source_head']['revision'])
        data['readback'] = draft_from_wire_v1(data['readback'], DraftFileReadbackV1)
        for name in ('extent', 'full_extent'):
            data[name] = artifact_draft_from_wire_v2(data[name], ArtifactDraftTextExtentV2)
        data['owner_guard'] = ProductionOwnerGuardV1(**data['owner_guard'])
        originals = []
        for original in data['postcondition_originals']:
            row = dict(original)
            row['read_versions'] = tuple(GraphVersion(AtomKey.from_token(version['key']), version['revision']) for version in row['read_versions'])
            originals.append(ProductionOriginalRefV1(**row))
        data['postcondition_originals'] = tuple(originals)
    value = kind(**data)
    if plain_v1(value) != raw: raise ValueError('noncanonical phase verification wire')
    return value


def decode_artifact_draft_phase_content_original_v2(kind, raw):
    if kind == 'c4_phase_adopted': return artifact_draft_content_from_wire_v2(raw, ArtifactDraftContentAdoptionV2)
    if kind == 'c4_phase_verified': return artifact_draft_phase_verification_from_wire_v2(raw, ArtifactDraftPhaseVerifiedOriginalV2)
    raise ValueError('unregistered phase content original')


def _read_phase_content_adoption_original_v2(db, *, namespace, selector, issuer):
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3, background_json_matches_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_event_point_v3,artifact_model_graph_point_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .jobs import get_job
    from .d11_types import job_graph_write
    from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v2
    import hashlib
    ids = artifact_draft_model_ids_v2(selector)
    row = _read(db, issuer=issuer, namespace=namespace, kind='c4_phase_adopted', ref=ids['adopt'])
    if row is None: raise MissingProductionOriginalV1('actual_phase_adopted_paid_content')
    value = artifact_draft_content_from_wire_v2(row[0], ArtifactDraftContentAdoptionV2)
    if value.selector != selector or row[1] != value.adoption_operation_id:
        raise ValueError('phase content adoption changed actual producing operation')
    original = read_adopted_domain_operation_v1(db, namespace, row[1])
    if (original is None or (original['domain'], original['operation_kind']) != ('d06', 'adopt_artifact_draft_content_v2')
            or original['payload']['request'] != plain_v1(AdoptArtifactDraftContentRequestV2(selector))
            or original['payload']['provenance']['prepared_digest'] != value.prepared_digest):
        raise ValueError('phase content was not adopted by its actual paid Source/job W01 stage')
    source = artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=value.content.content.ref)
    history = artifact_model_graph_point_v3(db,('event_id', 'value', 'valid'),token=value.content.content.ref,revision=value.content.content.revision)
    if (source is None or source[0] != value.content.content.revision or source[2] != 1
            or background_json_digest_v3(source[1],background_json_loads_v3(source[1])) != value.content.content.digest
            or history is None or (history[0],history[2])!=(value.adoption_operation_id,1)
            or background_json_digest_v3(history[1],background_json_loads_v3(history[1]))!=value.content.content.digest
            or GraphVersion(AtomKey.from_token(value.content.content.ref), source[0]) not in original['receipt'].write_versions):
        raise ValueError('phase authored Source is not its exact current adoption CAS member')
    record = SourceRecord.from_dict(background_json_loads_v3(source[1]))
    if (record.source_kind != 'authored' or record.assertion_status != 'unknown'
            or record.recorded_at != value.recorded_at_utc
            or (hashlib.sha256(record.text.encode()).hexdigest(), len(record.text.encode())) !=
                (value.content.content_digest, value.content.content_length)):
        raise ValueError('phase adopted Source bytes/provenance changed')
    prepared = read_artifact_draft_prepared_v2(db, namespace=namespace, selector=selector, issuer=issuer)
    if prepared is None or prepared.digest != value.prepared_digest:
        raise ValueError('phase content lost its signed original prepared binding')
    paid = _read(db, issuer=issuer, namespace=namespace, kind='c4_phase_paid', ref=value.paid_original_ref)
    result = _read(db, issuer=issuer, namespace=namespace, kind='c4_phase_result', ref=value.result_original_ref)
    scope = _read(db, issuer=issuer, namespace=namespace, kind='activity_scope', ref=value.activity_scope_ref)
    if (paid is None or result is None or scope is None
            or canonical_digest(paid[0]) != value.paid_original_digest
            or canonical_digest(result[0]) != value.result_original_digest
            or canonical_digest(scope[0]) != value.activity_scope_digest
            or scope[1] != value.adoption_operation_id):
        raise ValueError('phase content lost real signed paid/result/Scope predecessors')
    terminal = decode_artifact_draft_original_v2('c4_phase_result', result[0])
    cost = decode_artifact_draft_original_v2('c4_phase_paid', paid[0])
    actual_scope = draft_from_wire_v1(scope[0], DraftActivityScopeV1)
    if (terminal.request.selector != selector or terminal.request.binding_digest != prepared.digest
            or canonical_digest(terminal.terminal_receipt) != value.model_terminal_digest
            or cost.terminal_receipt_digest != canonical_digest(asdict(terminal.terminal_receipt))
            or cost.call_id != prepared.call_id or cost.quote_id != prepared.quote_id
            or (actual_scope.actor_ref, actual_scope.c02_original_ref, actual_scope.source.ref,
                actual_scope.root_registration_ref, actual_scope.parent_budget_lease_ref) !=
                (prepared.actor_ref, selector.task.c02_operation_id, value.task_source.ref,
                 selector.task.root_registration_ref, prepared.parent_budget_lease_ref)):
        raise ValueError('phase content changed its real original terminal/cost/Source/task scope')
    job = get_job(db, prepared.job_id)
    if (job.phase, job.result_ref, job.cancel_epoch, job.lease_holder, job.lease_expires_utc) != (
            'completed', ids['adopt'], 0, None, None):
        raise ValueError('phase paid content lost actual completed worker')
    job_history = artifact_model_graph_event_point_v3(db,('value', 'valid'),token=job_graph_write(job).key.token,event_id=value.adoption_operation_id,legacy_reader=lambda:_artifact_receipt_sql_v1(db,'SELECT value,valid FROM graph_history WHERE token=? AND event_id=? ORDER BY revision DESC LIMIT 1',
        (job_graph_write(job).key.token, value.adoption_operation_id)).fetchone())
    if job_history is None or job_history[1]!=1 or not background_json_matches_v3(job_history[0],job_graph_write(job).value):
        raise ValueError('phase completed job is not in original authored Source CAS')
    return value, row, record, actual_scope


def _read_actual_phase_file_v2(db, *, namespace, selector, adoption, result_ref, issuer):
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_preparation_v1 import read_prepared_life_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1, D11DraftTerminalV1
    from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
    from .d11_offline_originals_v1 import _utc
    adopted = read_adopted_life_original_v1(db, namespace=namespace, result_ref=result_ref, issuer=issuer)
    if adopted is None: raise MissingProductionOriginalV1('actual_phase_file_completed_effect_readback')
    terminal = life_from_wire_v1(adopted['terminal'], D11LifeTerminalV1)
    if type(terminal) is not D11DraftTerminalV1 or terminal.status != 'completed':
        raise MissingProductionOriginalV1('actual_known_completed_phase_file_effect')
    prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
    if prepared is None: raise MissingProductionOriginalV1('actual_phase_file_signed_preparation')
    readback = require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal)
    ids = artifact_draft_file_ids_v2(selector)
    plan = prepared.plan
    if ((plan.operation_id, plan.attempt_id, plan.effect_id, plan.execution_call_id) !=
            (ids['action_operation'], ids['attempt'], ids['effect'], ids['execution_call'])
            or (plan.target, plan.content) != (adoption.target, adoption.content)
            or plan.activity_scope_ref != adoption.activity_scope_ref or plan.activity_scope_digest != adoption.activity_scope_digest
            or _utc(plan.deadline_utc) > _utc(adoption.original_deadline_utc)
            or (readback.content_digest, readback.content_length, readback.root_registration_digest) !=
                (adoption.content.content_digest, adoption.content.content_length, adoption.target.root_registration_digest)):
        raise ValueError('phase file/readback belongs to different content/root/once action/deadline')
    return prepared, terminal, adopted, readback


def _require_phase_extent_original_v2(db, *, namespace, adoption, issuer):
    from .artifact_task_text_extent_v1 import require_artifact_task_text_extent_history_v1, KIND
    row = _read(db, issuer=issuer, namespace=namespace, kind=KIND, ref=adoption.extent_original_ref)
    if row is None or canonical_digest(row[0]) != adoption.extent_original_digest:
        raise MissingProductionOriginalV1('actual_phase_whole_method_task_extent_original')
    value = require_artifact_task_text_extent_history_v1(db, namespace=namespace,
        original_ref=adoption.extent_original_ref, producing_operation_id=row[1], raw=row[0])
    if (value.full_extent != adoption.full_extent or value.task_c02_operation_id != adoption.selector.task.c02_operation_id
            or (value.task_source_head.key.token, value.task_source_head.revision, value.task_source_digest) !=
                (adoption.task_source.ref, adoption.task_source.revision, adoption.task_source.digest)):
        raise ValueError('phase full extent lost actual original task/Source')
    return value


def actual_artifact_phase_content_selector_v2(db, *, namespace, selector, issuer):
    if selector.generation:
        return selector
    previous = _read(db, issuer=issuer, namespace=namespace, kind='c4_phase_verified', ref=selector.prev_phase_original_ref)
    if previous is None or canonical_digest(previous[0]) != selector.prev_phase_original_digest:
        raise MissingProductionOriginalV1('actual_previous_generation_phase_verification')
    original = artifact_draft_phase_verification_from_wire_v2(previous[0], ArtifactDraftPhaseVerifiedOriginalV2)
    verified = read_current_artifact_phase_verified_v2(db, namespace=namespace, selector=original.selector, issuer=issuer)
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    if (not verified.selector.generation or verified.selector.phase_index + 1 != selector.phase_index
            or foreground_artifact_phase_group_identity_v2(verified.selector) != foreground_artifact_phase_group_identity_v2(selector)):
        raise ValueError('phase check lost its immediately preceding actual same-method generation')
    return verified.selector


def _require_actual_artifact_phase_assessment_v1(*, selector, content_selector, contract, assessment, adoption, file_result_ref, file_result_digest, readback):
    from .artifact_phase_postconditions_v1 import ArtifactPhaseAssessmentOriginalV1, ArtifactPhasePostconditionContractV1
    if type(contract) is not ArtifactPhasePostconditionContractV1 or type(assessment) is not ArtifactPhaseAssessmentOriginalV1:
        raise TypeError('phase qualification requires its actual closed contract and assessment')
    if (assessment.request.selector != selector or assessment.content_selector != content_selector
            or (assessment.request.contract_ref, assessment.contract_digest) != (contract.original_ref, contract.digest)
            or assessment.request.file_result_ref != file_result_ref or assessment.file_result_digest != file_result_digest
            or (assessment.source_head.key.token, assessment.source_head.revision, assessment.source_value_digest) !=
                (adoption.content.content.ref, adoption.content.content.revision, adoption.content.content.digest)
            or assessment.readback != readback or assessment.owner_guard != contract.owner_guard):
        raise ValueError('phase assessment changed its preregistered contract or actual Source/file witness')
    conditions = tuple(row for row in contract.conditions if row.phase_kind == selector.phase_kind)
    expected = {row.condition_id for row in conditions}
    if (not expected or len(expected) != len(conditions) or len(assessment.results) != len(expected)
            or {row.condition_id for row in assessment.results} != expected):
        raise ValueError('phase assessment omitted or replaced a preregistered required condition')
    for result in assessment.results:
        if result.status == 'unknown':
            raise MissingProductionOriginalV1('artifact_phase_postcondition_unknown:' + result.condition_id)
        if result.status != 'satisfied':
            raise ValueError('artifact_phase_postcondition_' + result.status + ':' + result.condition_id)
    return assessment


def require_artifact_draft_phase_verified_history_v2(db, *, namespace, original_ref, producing_operation_id, raw):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    value = artifact_draft_phase_verification_from_wire_v2(raw, ArtifactDraftPhaseVerifiedOriginalV2)
    if (value.namespace != namespace or value.original_ref != original_ref
            or value.producing_operation_id != producing_operation_id):
        raise ValueError('phase verified original crossed namespace/ref/producer')
    actual = read_adopted_domain_operation_v1(db, namespace, producing_operation_id)
    if (actual is None or (actual['domain'], actual['operation_kind']) != ('d11', 'verify_artifact_draft_phase_v2')
            or actual['payload']['coverage'] != 'complete'
            or actual['payload']['provenance'] != {'phase_verified':raw}
            or actual['payload']['now_utc'] != value.observed_at_utc
            or actual['payload']['owner_guard'] != plain_v1(value.owner_guard)
            or actual['payload']['authority']['actor'] != value.actor_ref
            or actual['payload']['request'] != plain_v1(VerifyArtifactDraftPhaseRequestV2(value.selector,
                value.readback_original_ref, tuple(original.original_ref for original in value.postcondition_originals)))):
        raise ValueError('phase verified has no actual adopted private W01 verifier')
    return value


def read_current_artifact_phase_verified_v2(db, *, namespace, selector, issuer):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    from .issuers import D11BudgetJobIssuer
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    from ..domains.d03.self_perspective import self_mapping_key
    if (not db.in_transaction or type(issuer) is not D11BudgetJobIssuer
            or type(selector) is not ArtifactDraftPhaseSelectorV2 or selector.task.namespace != namespace):
        raise TypeError('phase verified reads require exact installed signed namespace reader')
    ref = artifact_draft_phase_original_ref_v2(selector) + ':verified'
    row = _read(db, issuer=issuer, namespace=namespace, kind='c4_phase_verified', ref=ref)
    if row is None: raise MissingProductionOriginalV1('actual_independently_verified_phase_original')
    value = require_artifact_draft_phase_verified_history_v2(db, namespace=namespace, original_ref=ref,
        producing_operation_id=row[1], raw=row[0])
    if value.selector != selector: raise ValueError('phase verified selector differs from actual signed original')
    adoption, original, record, scope = _read_phase_content_adoption_original_v2(db, namespace=namespace,
        selector=value.content_selector, issuer=issuer)
    _, _, file_original, readback = _read_actual_phase_file_v2(db, namespace=namespace,
        selector=value.content_selector, adoption=adoption, result_ref=value.readback_original_ref, issuer=issuer)
    _require_phase_extent_original_v2(db, namespace=namespace, adoption=adoption, issuer=issuer)
    from .d11_artifact_draft_model_v1 import (read_artifact_draft_prepared_v2, read_artifact_draft_frozen_v2,
        require_artifact_phase_frozen_contract_history_v3)
    from .artifact_phase_postconditions_v1 import (CONTRACT_KIND, ASSESSMENT_KIND,
        artifact_phase_assessment_original_ref_v1, require_artifact_phase_assessment_history_v1)
    prepared = read_artifact_draft_prepared_v2(db, namespace=namespace, selector=value.content_selector, issuer=issuer)
    if prepared is None: raise MissingProductionOriginalV1('actual_phase_frozen_material_predecessor')
    frozen = read_artifact_draft_frozen_v2(db, prepared=prepared, issuer=issuer)
    contract = require_artifact_phase_frozen_contract_history_v3(db, namespace=namespace, frozen=frozen, issuer=issuer)
    signed_contract = _read(db, issuer=issuer, namespace=namespace, kind=CONTRACT_KIND, ref=contract.original_ref)
    if signed_contract is None or canonical_digest(signed_contract[0]) != contract.digest:
        raise ValueError('phase verified lost its actual signed preregistered contract')
    if not selector.generation:
        expected_ref = artifact_phase_assessment_original_ref_v1(selector)
        if len(value.postcondition_originals) != 1:
            raise ValueError('phase qualification has no exact immutable assessment original')
        proof = value.postcondition_originals[0]
        if (proof.kind, proof.original_ref) != (ASSESSMENT_KIND, expected_ref):
            raise ValueError('phase qualification replaced its deterministic assessment original')
        assessment_row = _read(db, issuer=issuer, namespace=namespace, kind=ASSESSMENT_KIND, ref=expected_ref)
        if assessment_row is None or canonical_digest(assessment_row[0]) != proof.original_digest:
            raise MissingProductionOriginalV1('actual_signed_phase_assessment_original')
        assessment = require_artifact_phase_assessment_history_v1(db, namespace=namespace, original_ref=expected_ref,
            producing_operation_id=assessment_row[1], raw=assessment_row[0], issuer=issuer)
        _require_actual_artifact_phase_assessment_v1(selector=selector, content_selector=value.content_selector,
            contract=contract, assessment=assessment, adoption=adoption, file_result_ref=value.readback_original_ref,
            file_result_digest=value.readback_original_digest, readback=readback)
        if proof.read_versions != (assessment.source_head,):
            raise ValueError('phase qualification changed its actual assessment Source read commitment')
    if (value.content_adoption_ref != adoption.adoption_operation_id or value.content_adoption_digest != canonical_digest(original[0])
            or (value.source_head.key.token, value.source_head.revision, value.source_value_digest) !=
                (adoption.content.content.ref, adoption.content.content.revision, adoption.content.content.digest)
            or value.readback != readback or value.readback_original_digest != canonical_digest(file_original)
            or (value.extent, value.full_extent, value.extent_original_ref, value.extent_original_digest, value.original_deadline_utc) !=
                (adoption.extent, adoption.full_extent, adoption.extent_original_ref, adoption.extent_original_digest, adoption.original_deadline_utc)
            or (scope.owner_grant_ref, scope.owner_grant_revision, scope.owner_grant_digest, scope.actor_ref) !=
                (value.owner_guard.grant_ref, value.owner_guard.grant_revision, value.owner_guard.grant_digest, value.actor_ref)):
        raise ValueError('phase verified lost actual paid content/file/extent/current Scope')
    owner = artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=value.owner_guard.grant_ref)
    mapping = artifact_model_graph_point_v3(db,('value', 'valid'),token=self_mapping_key(namespace).token)
    if (owner is None or owner[0] != value.owner_guard.grant_revision or owner[2] != 1
            or canonical_digest(json.loads(owner[1])) != value.owner_guard.grant_digest
            or mapping is None or mapping[1] != 1 or canonical_digest(json.loads(mapping[0])) != value.current_self_digest
            or json.loads(mapping[0])['self_entity_ref'] != value.actor_ref):
        raise ValueError('phase verified current upstream Owner/Self changed')
    _source_family_current_sql_v1(db, namespace=namespace, roots=adoption.content.source_refs,
        purpose='consolidation', audiences=record.audiences)
    if selector.phase_index:
        prior = _read(db, issuer=issuer, namespace=namespace, kind='c4_phase_verified', ref=selector.prev_phase_original_ref)
        if prior is None or canonical_digest(prior[0]) != selector.prev_phase_original_digest:
            raise ValueError('phase verified lost previous authenticated original')
        previous = artifact_draft_phase_verification_from_wire_v2(prior[0], ArtifactDraftPhaseVerifiedOriginalV2)
        read_current_artifact_phase_verified_v2(db, namespace=namespace, selector=previous.selector, issuer=issuer)
    return value


def _read_current_artifact_method_cycle_v2(db, *, namespace, selector, issuer, now_utc):
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .foreground_cycle_v1 import foreground_cycle_ids_v1, foreground_cycle_from_wire_v1, ForegroundCycleContinuationV2
    from .foreground_call_plan_v1 import ForegroundCallPlanV2
    from .d11_artifact_draft_model_v1 import require_current_artifact_phase_group_v2
    from .d11_types import job_graph_write
    from .jobs import get_job
    from .d11_offline_originals_v1 import _utc
    from .issuers import D11BudgetJobIssuer
    import math
    if (not db.in_transaction or type(issuer) is not D11BudgetJobIssuer
            or type(selector) is not ArtifactDraftPhaseSelectorV2 or selector.task.namespace != namespace
            or type(now_utc) not in {int, float} or not math.isfinite(now_utc)):
        raise TypeError('actual current namespace phase reader and trusted time required')
    cycle = get_job(db, foreground_cycle_ids_v1(namespace, selector.task.c02_operation_id)[1])
    if cycle is None:
        raise MissingProductionOriginalV1('actual_current_artifact_method_cycle')
    actual = foreground_cycle_from_wire_v1(cycle.continuation)
    projection = job_graph_write(cycle)
    row = _artifact_receipt_sql_v1(db,'SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*namespace.as_tuple, projection.key.token)).fetchone()
    if (type(actual) is not ForegroundCycleContinuationV2 or type(actual.call_plan) not in {ForegroundCallPlanV2,ForegroundCallPlanV3}
            or actual.call_plan.phase_group.selector != selector or selector.task.cycle_job_ref != projection.key.token
            or actual.c02_operation_id != selector.task.c02_operation_id
            or row is None or row[2] != 1 or background_json_loads_v3(row[1]) != projection.value
            or cycle.cancel_epoch or cycle.phase not in {'running', 'queued', 'waiting'}
            or now_utc >= _utc(cycle.deadline_utc).timestamp()):
        raise MissingProductionOriginalV1('actual_uncancelled_current_method_cycle_and_original_deadline')
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    responsibility = read_original_foreground_responsibility_for_c09_v1(db, namespace=namespace, job=cycle, issuer=issuer)
    if responsibility is None or (responsibility.c02_operation_id, responsibility.source_ref, responsibility.root_registration_ref) != (
            selector.task.c02_operation_id, actual.source_ref, selector.task.root_registration_ref):
        raise MissingProductionOriginalV1('actual_signed_method_cycle_responsibility')
    require_current_artifact_phase_group_v2(db, namespace=namespace, group=actual.call_plan.phase_group, issuer=issuer)
    return cycle, actual


def read_current_artifact_phase_check_inputs_v2(db, *, namespace, selector, issuer, now_utc, owner_guard, installed_bundle):
    from .artifact_phase_postconditions_v1 import (ASSESSMENT_KIND, ObserveArtifactPhasePostconditionsRequestV1,
        artifact_phase_assessment_original_ref_v1, readonly_current_artifact_phase_postcondition_contract_v1,
        read_current_artifact_phase_assessment_v1)
    if type(selector) is not ArtifactDraftPhaseSelectorV2 or selector.generation:
        raise TypeError('check inputs require the actual current check phase')
    _, continuation = _read_current_artifact_method_cycle_v2(db, namespace=namespace, selector=selector, issuer=issuer, now_utc=now_utc)
    if continuation.pending_effect_refs:
        raise MissingProductionOriginalV1('actual_method_file_effect_terminal_before_assessment')
    content_selector = actual_artifact_phase_content_selector_v2(db, namespace=namespace, selector=selector, issuer=issuer)
    verified = read_current_artifact_phase_verified_v2(db, namespace=namespace, selector=content_selector, issuer=issuer)
    contract = readonly_current_artifact_phase_postcondition_contract_v1(db, namespace=namespace, selector=selector,
        issuer=issuer, now_utc=now_utc, owner_guard=owner_guard, installed_bundle=installed_bundle)
    from .d11_offline_originals_v1 import _utc
    if now_utc >= min(_utc(verified.original_deadline_utc).timestamp(), contract.original_deadline_utc):
        raise MissingProductionOriginalV1('original_artifact_phase_check_deadline')
    from .artifact_phase_postconditions_v1 import artifact_phase_expected_observer_refs_v1
    request = ObserveArtifactPhasePostconditionsRequestV1(selector, verified.readback_original_ref, contract.original_ref,
        artifact_phase_expected_observer_refs_v1(contract,selector))
    ref = artifact_phase_assessment_original_ref_v1(selector)
    original = _read(db, issuer=issuer, namespace=namespace, kind=ASSESSMENT_KIND, ref=ref)
    assessment = None if original is None else read_current_artifact_phase_assessment_v1(db, namespace=namespace,
        original_ref=ref, issuer=issuer, now_utc=now_utc, owner_guard=owner_guard, installed_bundle=installed_bundle)
    if assessment is not None and assessment.request != request:
        raise ValueError('actual current assessment changed the original check request and file/contract')
    return request, assessment


def artifact_method_settlement_operation_id_v2(selector):
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    return 'artifact-method-settlement:' + canonical_digest(foreground_artifact_phase_group_identity_v2(selector))[:48]


def artifact_method_final_operation_ids_v2(selector):
    from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
    marker=canonical_digest(foreground_artifact_phase_group_identity_v2(selector))[:48]
    outcome='artifact-method-outcome:'+marker
    return {'outcome_ref':outcome,'outcome_register':outcome+':register',
        'advance':'artifact-method-progress:'+marker,'project_settle':'artifact-method-project-settlement:'+marker,
        'goal':artifact_method_settlement_operation_id_v2(selector)}


def require_current_artifact_method_completion_v2(db, *, namespace, continuation, issuer, now_utc, owner_guard, installed_bundle):
    from .foreground_cycle_v1 import ForegroundCycleContinuationV2, read_observed_foreground_call_plan_v2
    from .foreground_call_plan_v1 import ForegroundCallPlanV2, ForegroundModelAttemptV2
    from .artifact_phase_postconditions_v1 import readonly_current_artifact_phase_postcondition_contract_v1
    from .d11_offline_originals_v1 import _utc
    if type(continuation) is not ForegroundCycleContinuationV2 or type(continuation.call_plan) not in {ForegroundCallPlanV2,ForegroundCallPlanV3}:
        raise TypeError('method completion requires the actual adopted phase continuation')
    group = continuation.call_plan.phase_group; selector = group.selector
    _, actual = _read_current_artifact_method_cycle_v2(db, namespace=namespace, selector=selector, issuer=issuer, now_utc=now_utc)
    if actual != continuation or actual.pending_effect_refs or actual.wait is not None:
        raise MissingProductionOriginalV1('actual_current_method_completion_without_pending_unknown_effects')
    phases = artifact_draft_phase_sequence_v2(selector.method_ref)
    if (selector.phase_index != len(phases) - 1 or selector.phase_kind != 'check'
            or len(group.completed_phase_originals) != len(phases)):
        raise MissingProductionOriginalV1('actual_complete_ordered_artifact_method_verified_prefix')
    observed = read_observed_foreground_call_plan_v2(db, namespace=namespace, continuation=actual, issuer=issuer)
    physical = tuple(row for row in observed.attempts if type(row) is ForegroundModelAttemptV2)
    expected = {index for index, kind in enumerate(phases) if kind in {'tone_sample', 'full'}}
    if ({row.phase_selector.phase_index for row in physical} != expected or len(physical) != len(expected)
            or any(row.state != 'completed' for row in physical) or any(row.state == 'unknown' for row in observed.attempts)):
        raise MissingProductionOriginalV1('actual_finite_completed_method_physical_calls_without_unknown')
    verified = read_current_artifact_phase_verified_v2(db, namespace=namespace, selector=selector, issuer=issuer)
    contract = readonly_current_artifact_phase_postcondition_contract_v1(db, namespace=namespace, selector=selector,
        issuer=issuer, now_utc=now_utc, owner_guard=owner_guard, installed_bundle=installed_bundle)
    if (verified.method_qualified is not True or verified.content_selector.phase_kind != 'full'
            or verified.extent != verified.full_extent or (verified.original_ref, verified.digest) != group.completed_phase_originals[-1]
            or now_utc >= min(_utc(verified.original_deadline_utc).timestamp(), contract.original_deadline_utc)):
        raise MissingProductionOriginalV1('actual_final_full_file_and_registered_method_postconditions_within_original_scope')
    return verified


def require_current_artifact_prior_content_v2(db, *, namespace, selector, prior, issuer):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    from .issuers import D11BudgetJobIssuer
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    import hashlib
    if (not db.in_transaction or type(issuer) is not D11BudgetJobIssuer
            or type(selector) is not ArtifactDraftPhaseSelectorV2 or selector.task.namespace != namespace
            or type(prior) is not ArtifactDraftPriorContentCommitmentV2):
        raise TypeError('prior content must be its actual signed positive Source/file commitment')
    if prior.verified_original_ref.startswith('artifact-draft-phase-original-v2:'):
        row = _read(db, issuer=issuer, namespace=namespace, kind='c4_phase_verified', ref=prior.verified_original_ref)
        if row is None or canonical_digest(row[0]) != prior.verified_original_digest:
            raise MissingProductionOriginalV1('actual_prior_verified_phase_content')
        previous = artifact_draft_phase_verification_from_wire_v2(row[0], ArtifactDraftPhaseVerifiedOriginalV2)
        verified = read_current_artifact_phase_verified_v2(db, namespace=namespace, selector=previous.selector, issuer=issuer)
        from .foreground_call_plan_v1 import foreground_artifact_phase_group_identity_v2
        if (selector.phase_index and (foreground_artifact_phase_group_identity_v2(selector) !=
                foreground_artifact_phase_group_identity_v2(previous.selector)
                or previous.selector.phase_index != selector.phase_index - 1
                or selector.prev_phase_original_ref != prior.verified_original_ref
                or selector.prev_phase_original_digest != prior.verified_original_digest)
                or (verified.source_head.key.token, verified.source_head.revision, verified.source_value_digest, verified.readback) !=
                    (prior.source_head.ref, prior.source_head.version, prior.source_value_digest, prior.verified_readback)):
            raise ValueError('prior content changed its immediate verified phase/source/readback')
    else:
        if selector.phase_index:
            raise ValueError('later method phase cannot borrow an unrelated historical file')
        from .d11_life_terminal_v1 import read_adopted_life_original_v1
        from .d11_life_preparation_v1 import read_prepared_life_v1
        from .d11_life_contract_v1 import D11LifeTerminalV1, D11DraftTerminalV1
        from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
        original = read_adopted_life_original_v1(db, namespace=namespace, result_ref=prior.verified_original_ref, issuer=issuer)
        if original is None or canonical_digest(original) != prior.verified_original_digest:
            raise MissingProductionOriginalV1('actual_historical_completed_prior_file')
        terminal = life_from_wire_v1(original['terminal'], D11LifeTerminalV1)
        if type(terminal) is not D11DraftTerminalV1 or terminal.status != 'completed':
            raise MissingProductionOriginalV1('actual_historical_prior_readback')
        prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
        if prepared is None or require_draft_terminal_readback_v1(prepared=prepared, terminal=terminal) != prior.verified_readback:
            raise ValueError('historical prior file changed actual signed completion/readback')
        if (prepared.plan.content.content.ref, prepared.plan.content.content.revision, prepared.plan.content.content.digest) != (
                prior.source_head.ref, prior.source_head.version, prior.source_value_digest):
            raise ValueError('historical prior content changed original Source head')
    source = artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=prior.source_head.ref)
    if source is None or source[0] != prior.source_head.version or source[2] != 1 or canonical_digest(json.loads(source[1])) != prior.source_value_digest:
        raise ValueError('actual prior content Source is no longer current')
    record = SourceRecord.from_dict(json.loads(source[1]))
    if (hashlib.sha256(record.text.encode()).hexdigest(), len(record.text.encode())) != (
            prior.verified_readback.content_digest, prior.verified_readback.content_length):
        raise ValueError('prior verified file bytes differ from actual current Source')
    _source_family_current_sql_v1(db, namespace=namespace, roots=(prior.source_head.ref,),
        purpose='consolidation', audiences=record.audiences)
    return prior


def read_plan_artifact_draft_phase_verification_v2(db, *, namespace, request, installed_readers=None):
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .d01_production_operations_v1 import production_read_plan_v1
    from .d11_artifact_draft_model_v1 import read_plan_artifact_draft_model_v2, AcquireArtifactDraftModelRequestV2
    from .d11_life_contract_v1 import D11LifeTerminalV1
    if type(request) is not VerifyArtifactDraftPhaseRequestV2:
        raise TypeError('exact registered phase verification readplan required')
    selector = request.selector
    content_selector = actual_artifact_phase_content_selector_v2(db, namespace=namespace, selector=selector, issuer=installed_readers.issuer)
    ids = artifact_draft_model_ids_v2(content_selector)
    base = read_plan_artifact_draft_model_v2(db, namespace=namespace, operation_kind='verify_artifact_draft_phase_v2',
        request=AcquireArtifactDraftModelRequestV2(content_selector), installed_readers=installed_readers)
    from .artifact_phase_postconditions_v1 import (read_plan_current_artifact_phase_postcondition_contract_v1,
        read_plan_artifact_phase_assessment_v1)
    plans = [base, read_plan_current_artifact_phase_postcondition_contract_v1(db, namespace=namespace,
        selector=selector, installed_readers=installed_readers)]
    if not selector.generation:
        plans.append(read_plan_artifact_phase_assessment_v1(db, namespace=namespace, selector=selector, installed_readers=installed_readers))
    base = production_read_plan_v1(tuple(k for plan in plans for k in plan.fixed_type_ids),
        tuple(k for plan in plans for k in plan.exact_keys), tuple(k for plan in plans for k in plan.source_roots),
        tuple(k for plan in plans for k in plan.required_original_refs))
    keys, roots = list(base.exact_keys), list(base.source_roots)
    originals = [*base.required_original_refs, ids['adopt'], ids['paid'], ids['result'], request.file_result_ref]
    adoption_row = _artifact_receipt_sql_v1(db,"SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='c4_phase_adopted' AND original_ref=?",
        (*namespace.as_tuple, ids['adopt'])).fetchone()
    if adoption_row is not None:
        adoption = artifact_draft_content_from_wire_v2(background_json_loads_v3(adoption_row[0]), ArtifactDraftContentAdoptionV2)
        keys.extend((AtomKey.from_token(adoption.content.content.ref), AtomKey.from_token(adoption.task_source.ref)))
        roots.extend(adoption.content.source_refs)
        originals.extend((adoption.activity_scope_ref, adoption.extent_original_ref))
    file_row = _artifact_receipt_sql_v1(db,"SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='adopted_life' AND original_ref=?",
        (*namespace.as_tuple, request.file_result_ref)).fetchone()
    if file_row is not None:
        file_original = background_json_loads_v3(file_row[0])
        terminal = life_from_wire_v1(file_original['terminal'], D11LifeTerminalV1)
        originals.extend((terminal.binding.prepared_original_ref, terminal.original_ref))
        roots.extend(file_original['source_refs'])
        keys.extend(AtomKey.from_token(row['ref']) for row in file_original['write_commitments'])
    if selector.prev_phase_original_ref is not None: originals.append(selector.prev_phase_original_ref)
    return production_read_plan_v1(base.fixed_type_ids, keys, roots, originals)


def stage_verify_current_artifact_draft_phase_v2(db, *, frame, request, installed_readers):
    from .artifact_continuation_originals_v1 import read_completed_draft_predecessor_v1
    from .d11_artifact_draft_model_v1 import require_current_artifact_phase_group_v2
    from .foreground_call_plan_v1 import ForegroundCallPlanV2
    from .d11_offline_originals_v1 import _utc
    if type(request) is not VerifyArtifactDraftPhaseRequestV2 or type(installed_readers) is not InstalledArtifactDraftModelReadersV1:
        raise TypeError('phase verification requires actual installed closed request/readers')
    selector = request.selector; task = selector.task; readers = installed_readers
    if frame.envelope.identity.operation_id != artifact_draft_phase_original_ref_v2(selector) + ':verify':
        raise ValueError('phase verification changed its deterministic original once operation')
    _, _, continuation, root, _, mapping_atom, _ = _current_task(db, frame=frame, selector=task, readers=readers)
    if (type(continuation.call_plan) not in {ForegroundCallPlanV2,ForegroundCallPlanV3} or continuation.call_plan.phase_group.selector != selector
            or len(continuation.call_plan.phase_group.completed_phase_originals) != selector.phase_index):
        raise ValueError('phase verification cannot replace or skip an independently verified prefix')
    require_current_artifact_phase_group_v2(db, namespace=task.namespace, group=continuation.call_plan.phase_group, issuer=readers.issuer)
    content_selector = actual_artifact_phase_content_selector_v2(db, namespace=task.namespace, selector=selector, issuer=readers.issuer)
    from .artifact_phase_postconditions_v1 import read_current_artifact_phase_postcondition_contract_v1
    contract = read_current_artifact_phase_postcondition_contract_v1(db, frame=frame, selector=selector, installed_readers=readers)
    adoption = read_current_adopted_artifact_draft_content_v2(db, frame=frame, selector=content_selector, installed_readers=readers)
    _, adopted_row, record, scope = _read_phase_content_adoption_original_v2(db, namespace=task.namespace, selector=content_selector, issuer=readers.issuer)
    _require_phase_extent_original_v2(db, namespace=task.namespace, adoption=adoption, issuer=readers.issuer)
    from .d11_artifact_draft_model_v1 import (read_artifact_draft_prepared_v2, read_artifact_draft_frozen_v2,
        require_artifact_phase_frozen_contract_history_v3)
    prepared = read_artifact_draft_prepared_v2(db, namespace=task.namespace, selector=content_selector, issuer=readers.issuer)
    if prepared is None: raise MissingProductionOriginalV1('actual_phase_frozen_material_predecessor')
    frozen = read_artifact_draft_frozen_v2(db, prepared=prepared, issuer=readers.issuer)
    if require_artifact_phase_frozen_contract_history_v3(db, namespace=task.namespace, frozen=frozen, issuer=readers.issuer) != contract:
        raise ValueError('phase verification changed the contract committed before actual generation')
    if selector.phase_index:
        previous_row = _read(db, issuer=readers.issuer, namespace=task.namespace, kind='c4_phase_verified', ref=selector.prev_phase_original_ref)
        if previous_row is None: raise MissingProductionOriginalV1('actual_previous_phase_verified')
        previous = artifact_draft_phase_verification_from_wire_v2(previous_row[0], ArtifactDraftPhaseVerifiedOriginalV2)
        read_current_artifact_phase_verified_v2(db, namespace=task.namespace, selector=previous.selector, issuer=readers.issuer)
    file_prepared, file_terminal, file_original, readback = read_completed_draft_predecessor_v1(db, frame=frame,
        result_ref=request.file_result_ref, issuer=readers.issuer)
    qualified = _read_actual_phase_file_v2(db, namespace=task.namespace, selector=content_selector, adoption=adoption,
        result_ref=request.file_result_ref, issuer=readers.issuer)
    if qualified != (file_prepared, file_terminal, file_original, readback):
        raise ValueError('phase file reader differed from actual current authenticated W01 view')
    if (frame.now_utc >= min(_utc(adoption.original_deadline_utc).timestamp(), _utc(scope.valid_until_utc).timestamp(),
            _utc(root.valid_until_utc).timestamp()) or _utc(readback.verified_at_utc).timestamp() > frame.now_utc
            or not adoption.extent.minimum <= artifact_draft_character_count_v2(record.text) <= adoption.extent.maximum
            or len(record.text.encode()) > min(MAX_TEXT_BYTES, adoption.target.max_bytes)):
        raise MissingProductionOriginalV1('actual_phase_structural_postconditions_within_original_scope')
    postconditions = ()
    if not selector.generation:
        from .artifact_phase_postconditions_v1 import (ASSESSMENT_KIND, artifact_phase_assessment_original_ref_v1,
            read_current_artifact_phase_assessment_v1)
        assessment_ref = artifact_phase_assessment_original_ref_v1(selector)
        if request.postcondition_original_refs != (assessment_ref,):
            raise ValueError('phase verification must consume its exact actual immutable assessment')
        assessment = read_current_artifact_phase_assessment_v1(db, namespace=task.namespace,
            original_ref=assessment_ref, issuer=readers.issuer, now_utc=frame.now_utc,
            owner_guard=frame.owner_guard, installed_bundle=readers.installed_bundle)
        _require_actual_artifact_phase_assessment_v1(selector=selector, content_selector=content_selector,
            contract=contract, assessment=assessment, adoption=adoption, file_result_ref=request.file_result_ref,
            file_result_digest=canonical_digest(file_original), readback=readback)
        postconditions = (ProductionOriginalRefV1(ASSESSMENT_KIND, assessment.original_ref, assessment.digest, (assessment.source_head,)),)
    value = ArtifactDraftPhaseVerifiedOriginalV2(selector, content_selector, adoption.adoption_operation_id,
        canonical_digest(adopted_row[0]), GraphVersion(AtomKey.from_token(adoption.content.content.ref), adoption.content.content.revision),
        adoption.content.content.digest, readback, request.file_result_ref, canonical_digest(file_original), adoption.extent,
        adoption.full_extent, adoption.extent_original_ref, adoption.extent_original_digest, adoption.original_deadline_utc,
        selector.prev_phase_original_ref, selector.prev_phase_original_digest, postconditions, frame.owner_guard,
        frame.envelope.authority.actor, canonical_digest(mapping_atom.value), frame.envelope.identity.operation_id,
        frame.now_utc, True, not selector.generation)
    stage = stage_result_v1(frame, 'd11', 'verify_artifact_draft_phase_v2', request,
        provenance={'phase_verified':value}, receiver_events=(('d11','artifact_draft_phase_structurally_verified'),))
    from ..runtime_contracts import DomainProposal, DependencySet
    from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA
    proposal = DomainProposal('d11', D11_PROPOSAL_SCHEMA, D11RuntimeProvider().descriptor.request_schema_hash,
        frame.envelope, (), DependencySet(), (), ())
    stage = replace(stage, proposals=(proposal,))
    return ArtifactDraftPhaseVerificationStageV2(frame, stage, value)


def apply_artifact_draft_phase_verification_stage_v2(witness, graph, db, installed_readers):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE, _FOREGROUND_VALIDATED, _FOREGROUND_APPLIED, _require_foreground_witness_v1
    if (type(witness) is not _ProductionCommitWitnessV1 or type(witness.stage) is not ArtifactDraftPhaseVerificationStageV2
            or _ACTIVE.get(id(witness)) is not witness or _FOREGROUND_VALIDATED.get(id(witness)) is not witness
            or id(witness) in _FOREGROUND_APPLIED or witness.graph is not graph
            or db is not graph._GraphCoordinator__store._db or not db.in_transaction):
        raise ValueError('phase verification requires actual privately validated once W01 witness')
    _require_foreground_witness_v1(witness, graph, db, witness.bundle)
    rebuilt = stage_verify_current_artifact_draft_phase_v2(db, frame=witness.stage.frame,
        request=witness.request, installed_readers=installed_readers)
    if rebuilt != witness.stage: raise ValueError('actual phase file/source/Scope changed at final verification CAS')
    _FOREGROUND_APPLIED[id(witness)] = witness
    return True


def record_artifact_draft_phase_verified_after_cas_v2(db, *, stage, receipt, installed_readers):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    if type(stage) is not ArtifactDraftPhaseVerificationStageV2 or receipt.status != 'committed' or receipt.operation_id != stage.verified.producing_operation_id:
        raise TypeError('phase verified signature requires actual same-transaction W01 CAS')
    value = stage.verified
    original = read_adopted_domain_operation_v1(db, value.namespace, receipt.operation_id)
    if original is None or original['receipt'] != receipt or original['original_digest'] != stage.stage.original_digest:
        raise ValueError('phase verifier original is not its actual W01 adopted receipt')
    require_artifact_draft_phase_verified_history_v2(db, namespace=value.namespace, original_ref=value.original_ref,
        producing_operation_id=value.producing_operation_id, raw=plain_v1(value))
    recorded = _record(db, issuer=installed_readers.issuer, namespace=value.namespace, kind='c4_phase_verified',
        ref=value.original_ref, operation_id=receipt.operation_id, value=value)
    if read_current_artifact_phase_verified_v2(db, namespace=value.namespace, selector=value.selector, issuer=installed_readers.issuer) != value:
        raise ValueError('recorded phase verified original differs from actual current file/Source proof')
    return recorded


@dataclass(frozen=True,slots=True)
class ArtifactDraftMethodSettlementMemberV2:
    before: GraphVersion
    before_value_digest: str
    after: GraphVersion
    after_value_digest: str

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import _digest
        if (type(self.before) is not GraphVersion or type(self.after) is not GraphVersion
                or self.before.key!=self.after.key or self.before.revision<1 or self.after.revision!=self.before.revision+1):
            raise ValueError('method settlement member must be one exact before-to-after CAS')
        _digest(self.before_value_digest);_digest(self.after_value_digest)


@dataclass(frozen=True,slots=True)
class ArtifactDraftMethodSettlementHistoryV2:
    selector: ArtifactDraftPhaseSelectorV2
    ordered_phase_originals: tuple[tuple[str,str],...]
    milestone_original_ref: str
    milestone_original_digest: str
    file_result_ref: str
    file_result_digest: str
    source_head: GraphVersion
    source_value_digest: str
    progress_head: GraphVersion
    progress_value_digest: str
    progress_operation_id: str
    progress_original_digest: str
    project_settlement_operation_id: str
    project_settlement_original_digest: str
    members: tuple[ArtifactDraftMethodSettlementMemberV2,...]
    goal_ref: str
    plan_ref: str
    project_ref: str
    state: str
    owner_guard: ProductionOwnerGuardV1
    actor_ref: str
    completed_at_utc: float
    original_deadline_utc: float
    settlement_operation_id: str
    schema: str='d11.artifact-method-settlement-history.v2'

    @property
    def namespace(self):return self.selector.task.namespace

    @property
    def digest(self):return canonical_digest(plain_v1(self))

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import _digest,_text
        import math
        if (self.schema!='d11.artifact-method-settlement-history.v2' or type(self.selector) is not ArtifactDraftPhaseSelectorV2
                or self.selector.phase_kind!='check' or self.selector.phase_index!=len(artifact_draft_phase_sequence_v2(self.selector.method_ref))-1
                or len(self.ordered_phase_originals)!=len(artifact_draft_phase_sequence_v2(self.selector.method_ref))
                or self.plan_ref!=self.selector.plan_ref or self.state not in {'partial','satisfied'}
                or type(self.members) is not tuple or len(self.members) not in {2,3}
                or any(type(member) is not ArtifactDraftMethodSettlementMemberV2 for member in self.members)
                or len({member.before.key for member in self.members})!=len(self.members)
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or self.settlement_operation_id!=artifact_method_settlement_operation_id_v2(self.selector)
                or type(self.completed_at_utc) not in {int,float} or not math.isfinite(self.completed_at_utc)
                or type(self.original_deadline_utc) not in {int,float} or not math.isfinite(self.original_deadline_utc)
                or not self.completed_at_utc<self.original_deadline_utc):
            raise ValueError('completed method history requires its actual final-check same-CAS transition')
        for head in (self.source_head,self.progress_head):
            if type(head) is not GraphVersion or head.revision<1 or NamespaceId.from_key(head.key)!=self.namespace:
                raise ValueError('method completed history crossed its actual positive namespace head')
        for value in (self.milestone_original_digest,self.file_result_digest,self.source_value_digest,self.progress_value_digest,
                self.progress_original_digest,self.project_settlement_original_digest):_digest(value)
        for ref in (self.milestone_original_ref,self.file_result_ref,self.progress_operation_id,self.project_settlement_operation_id,
                self.goal_ref,self.plan_ref,self.project_ref,self.actor_ref):_text(ref,'method completion original')


def bind_artifact_method_settlement_stage_v2(db, *, frame, request, stage, issuer):
    from .artifact_task_observer_v1 import ArtifactTaskSettlementStageV1,ArtifactTaskObservationV2
    from .d10_project_checkpoint_v1 import _current_artifact_task_final_selector_v2
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .foreground_cycle_v1 import foreground_cycle_ids_v1,foreground_cycle_from_wire_v1
    from .jobs import get_job
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    ns=frame.envelope.authority.namespace
    primary=stage.stage if type(stage) is ArtifactTaskSettlementStageV1 else stage
    if primary.coverage!='complete':return stage
    raw=json.loads(primary.original_payload_json)
    observation=raw['provenance'].get('task_observation')
    if observation is None or observation.get('schema')!='d08.artifact-task-observation.v2':return stage
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    observed=decode_typed_production_value_v1(observation,ArtifactTaskObservationV2)
    milestone=observed.milestones[-1];selector=milestone.selector
    if (selector!=_current_artifact_task_final_selector_v2(db,namespace=ns,plan_ref=request.plan_ref)
            or frame.envelope.identity.operation_id!=artifact_method_settlement_operation_id_v2(selector)):
        raise ValueError('method Goal transition changed its actual selected group or deterministic settlement operation')
    cycle=get_job(db,foreground_cycle_ids_v1(ns,selector.task.c02_operation_id)[1]);continuation=foreground_cycle_from_wire_v1(cycle.continuation)
    if continuation.call_plan.phase_group.completed_phase_originals!=milestone.ordered_phase_originals:
        raise ValueError('method Goal transition changed actual full ordered phase verification')
    read=CurrentDomainReadV1(frame);read.check(db)
    progress=read.head(db,request.progress_ref,required=True)
    progress_history=db.execute('SELECT event_id FROM graph_history WHERE token=? AND revision=?',(progress.key.token,progress.revision)).fetchone()
    progress_original=None if progress_history is None else read_adopted_domain_operation_v1(db,ns,progress_history[0])
    cp=read.head(db,project_checkpoint_key_v1(ns,observed.project_ref),required=True)
    cp_history=db.execute('SELECT event_id FROM graph_history WHERE token=? AND revision=?',(cp.key.token,cp.revision)).fetchone()
    project_original=None if cp_history is None else read_adopted_domain_operation_v1(db,ns,cp_history[0])
    if (progress_original is None or (progress_original['domain'],progress_original['operation_kind'])!=('d10','advance_life')
            or project_original is None or (project_original['domain'],project_original['operation_kind'])!=('d10','settle_project_checkpoint')):
        raise MissingProductionOriginalV1('actual_method_D10_progress_and_selected_project_settlement')
    proposals=(*stage.stage.proposals,*stage.checkpoint_stage.proposals) if type(stage) is ArtifactTaskSettlementStageV1 else stage.proposals
    writes=tuple(write for proposal in proposals for write in proposal.typed_writes)
    allowed={AtomKey.from_token(request.goal_ref),AtomKey.from_token(request.plan_ref),cp.key}
    if {write.key for write in writes}!=allowed or len(writes)!=3:
        raise ValueError('method Goal transition must contain exactly its actual Goal/Plan/taskCheckpoint CAS members')
    members=[]
    for write in writes:
        before=read.head(db,write.key,required=True)
        members.append(ArtifactDraftMethodSettlementMemberV2(GraphVersion(write.key,before.revision),canonical_digest(before.value),
            GraphVersion(write.key,before.revision+1),canonical_digest(write.value)))
    value=ArtifactDraftMethodSettlementHistoryV2(selector,milestone.ordered_phase_originals,milestone.original_ref,milestone.digest,
        milestone.file_result_ref,milestone.file_result_digest,milestone.source_head,milestone.source_value_digest,
        GraphVersion(progress.key,progress.revision),canonical_digest(progress.value),progress_original['receipt'].operation_id,progress_original['original_digest'],
        project_original['receipt'].operation_id,project_original['original_digest'],tuple(sorted(members,key=lambda value:value.before.key.token)),
        request.goal_ref,request.plan_ref,observed.project_ref,observed.phase,frame.owner_guard,frame.envelope.authority.actor,
        frame.now_utc,milestone.original_deadline_utc,frame.envelope.identity.operation_id)
    raw['provenance']['artifact_method_completion']=plain_v1(value)
    primary=replace(primary,original_payload_json=canonical_serialize(raw),original_digest=canonical_digest(raw))
    return replace(stage,stage=primary) if type(stage) is ArtifactTaskSettlementStageV1 else primary


def require_artifact_method_settlement_history_v2(db, *, namespace, original, raw):
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .artifact_task_observer_v1 import require_artifact_task_milestone_history_v2
    from .d11_life_preparation_v1 import TABLE
    value=decode_typed_production_value_v1(raw,ArtifactDraftMethodSettlementHistoryV2)
    if (value.namespace!=namespace or (original['domain'],original['operation_kind'])!=('d08','settle_personal_goal')
            or original['receipt'].operation_id!=value.settlement_operation_id
            or original['payload']['coverage']!='complete' or original['payload']['now_utc']!=value.completed_at_utc
            or original['payload']['provenance'].get('artifact_method_completion')!=raw
            or original['payload']['request']['goal_ref']!=value.goal_ref or original['payload']['request']['plan_ref']!=value.plan_ref
            or plain_v1(value.owner_guard)!=original['payload']['owner_guard']
            or original['payload']['authority']['actor']!=value.actor_ref):
        raise ValueError('completed method proof has no actual same-W01 Goal settlement producer')
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    required_keys={AtomKey.from_token(value.goal_ref),AtomKey.from_token(value.plan_ref),project_checkpoint_key_v1(namespace,value.project_ref)}
    if {member.before.key for member in value.members}!=required_keys or len(value.members)!=3:
        raise ValueError('completed method history changed its exact Goal/Plan/taskCheckpoint member keys')
    plan_member=next(member for member in value.members if member.before.key.token==value.plan_ref)
    if (plan_member.before.revision,plan_member.before_value_digest)!=(value.selector.plan_revision,value.selector.plan_digest):
        raise ValueError('completed method history changed the selected original Plan before its same-CAS settlement')
    if value.source_head.key.type_name!='memory.source' or value.progress_head.key.type_name!='d10.life_progress.v1':
        raise ValueError('completed method history replaced its actual typed Source or D10 progress')
    expected=tuple(member.after for member in value.members)
    if set(original['receipt'].write_versions)!=set(expected) or len(original['receipt'].write_versions)!=len(expected):
        raise ValueError('completed method Goal settlement changed actual exact CAS member set')
    for member in value.members:
        if member.before not in original['read_versions']:
            raise ValueError('completed method Goal settlement omitted a before CAS read')
        before=_artifact_receipt_sql_v1(db,'SELECT value,valid FROM graph_history WHERE token=? AND revision=?',(member.before.key.token,member.before.revision)).fetchone()
        after=_artifact_receipt_sql_v1(db,'SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',(member.after.key.token,member.after.revision)).fetchone()
        if (before is None or before[1]!=1 or background_json_digest_v3(before[0],background_json_loads_v3(before[0]))!=member.before_value_digest
                or after is None or after[0]!=value.settlement_operation_id or after[2]!=1
                or background_json_digest_v3(after[1],background_json_loads_v3(after[1]))!=member.after_value_digest):
            raise ValueError('completed method Goal settlement lost exact signed before-to-after history')
    for member in value.members:
        row=_artifact_receipt_sql_v1(db,'SELECT value FROM graph_history WHERE token=? AND revision=?',(member.after.key.token,member.after.revision)).fetchone()
        after_value=background_json_loads_v3(row[0])
        if member.after.key.token==value.goal_ref:
            expected_state='active' if value.state=='partial' else 'satisfied'
        elif member.after.key.token==value.plan_ref:
            expected_state='waiting' if value.state=='partial' else 'satisfied'
        else:
            expected_state='waiting' if value.state=='partial' else 'completed'
        if after_value['state']!=expected_state:
            raise ValueError('completed method history changed actual partial/satisfied after-state semantics')
    milestone_row=_artifact_receipt_sql_v1(db,'SELECT payload_json,payload_digest,producing_operation_id FROM '+TABLE+
        ' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',(*namespace.as_tuple,'artifact_task_milestone_v2',value.milestone_original_ref)).fetchone()
    if milestone_row is None or milestone_row[1]!=value.milestone_original_digest:
        raise MissingProductionOriginalV1('actual_completed_method_semantic_milestone_original')
    milestone=require_artifact_task_milestone_history_v2(db,namespace=namespace,original_ref=value.milestone_original_ref,
        producing_operation_id=milestone_row[2],raw=background_json_loads_v3(milestone_row[0]))
    if ((milestone.selector,milestone.ordered_phase_originals,milestone.file_result_ref,milestone.file_result_digest,
            milestone.source_head,milestone.source_value_digest,milestone.owner_guard,milestone.original_deadline_utc)!=
            (value.selector,value.ordered_phase_originals,value.file_result_ref,value.file_result_digest,value.source_head,
            value.source_value_digest,value.owner_guard,value.original_deadline_utc)):
        raise ValueError('completed method Goal transition replaced its actual full method and semantic milestone')
    for op,digest,kind in ((value.progress_operation_id,value.progress_original_digest,'advance_life'),
            (value.project_settlement_operation_id,value.project_settlement_original_digest,'settle_project_checkpoint')):
        producer=read_adopted_domain_operation_v1(db,namespace,op)
        if producer is None or producer['original_digest']!=digest or (producer['domain'],producer['operation_kind'])!=('d10',kind):
            raise ValueError('completed method Goal transition lost actual D10 progress/project settlement')
    progress=_artifact_receipt_sql_v1(db,'SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',
        (value.progress_head.key.token,value.progress_head.revision)).fetchone()
    if (progress is None or progress[0]!=value.progress_operation_id or progress[2]!=1
            or background_json_digest_v3(progress[1],background_json_loads_v3(progress[1]))!=value.progress_value_digest
            or background_json_loads_v3(progress[1])['artifact_ref']!=value.file_result_ref):
        raise ValueError('completed method Goal transition changed its actual full-file D10 progress')
    return value


def read_current_completed_artifact_method_history_v2(db, *, namespace, selector, issuer, owner_guard, installed_bundle):
    """Return disclosed completed history and its original receipt; never a live Contract."""
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    original=read_adopted_domain_operation_v1(db,namespace,artifact_method_settlement_operation_id_v2(selector))
    if original is None: raise MissingProductionOriginalV1('actual_signed_completed_method_Goal_settlement')
    raw=original['payload']['provenance'].get('artifact_method_completion')
    if raw is None:raise MissingProductionOriginalV1('actual_completed_method_same_W01_history_bridge')
    value=require_artifact_method_settlement_history_v2(db,namespace=namespace,original=original,raw=raw)
    from ..host.authority_profile import AdminInstallationBundle
    from .d11_artifact_draft_model_v1 import read_artifact_draft_prepared_v2,read_artifact_draft_frozen_v2,require_artifact_phase_frozen_contract_history_v3
    from .artifact_phase_postconditions_v1 import POLICY_KIND
    if type(installed_bundle) is not AdminInstallationBundle or installed_bundle.installation_policy.namespace!=namespace:
        raise ValueError('completed method disclosure requires the actual matching installed namespace bundle')
    pins=(installed_bundle.installation_policy.installation_id,installed_bundle.installation_policy.manifest_digest)
    root_row=_read(db,issuer=issuer,namespace=namespace,kind='draft_root_capability',ref=selector.task.root_registration_ref)
    if root_row is None:raise MissingProductionOriginalV1('actual_completed_method_registered_root')
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1,draft_from_wire_v1
    root=draft_from_wire_v1(root_row[0],DraftRootCapabilityV1)
    full_row=_read(db,issuer=issuer,namespace=namespace,kind='c4_phase_verified',ref=value.ordered_phase_originals[-1][0])
    if full_row is None:raise MissingProductionOriginalV1('actual_completed_method_full_check')
    full=artifact_draft_phase_verification_from_wire_v2(full_row[0],ArtifactDraftPhaseVerifiedOriginalV2)
    prepared=read_artifact_draft_prepared_v2(db,namespace=namespace,selector=full.content_selector,issuer=issuer)
    if prepared is None or (root.installation_id,root.manifest_digest)!=pins or (prepared.installation_id,prepared.manifest_digest)!=pins:
        raise ValueError('completed method history mixed another installation Root or actual paid model')
    frozen=read_artifact_draft_frozen_v2(db,prepared=prepared,issuer=issuer)
    contract=require_artifact_phase_frozen_contract_history_v3(db,namespace=namespace,frozen=frozen, issuer=issuer)
    policy_row=_read(db,issuer=issuer,namespace=namespace,kind=POLICY_KIND,ref=contract.policy_ref)
    if policy_row is None or (policy_row[0]['installation_id'],policy_row[0]['manifest_digest'])!=pins:
        raise ValueError('completed method history mixed another preDecision policy installation')
    if value.selector!=selector or value.owner_guard!=owner_guard:
        raise ValueError('completed method history changed actual disclosed selector or current Owner')
    owner=_artifact_receipt_sql_v1(db,'SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*namespace.as_tuple,owner_guard.grant_ref)).fetchone()
    if owner is None or owner[2]!=1 or (owner[0],background_json_digest_v3(owner[1],background_json_loads_v3(owner[1])))!=(owner_guard.grant_revision,owner_guard.grant_digest):
        raise MissingProductionOriginalV1('current_owner_access_to_completed_method_history')
    for member in value.members:
        after=_artifact_receipt_sql_v1(db,'SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple,member.after.key.token)).fetchone()
        if after is None or after[2]!=1 or (after[0],background_json_digest_v3(after[1],background_json_loads_v3(after[1])))!=(member.after.revision,member.after_value_digest):
            raise MissingProductionOriginalV1('actual_completed_method_after_heads_without_foreign_successor')
    milestone=read_current_artifact_task_milestone_v2(db,namespace=namespace,original_ref=value.milestone_original_ref,issuer=issuer)
    source=_artifact_receipt_sql_v1(db,'SELECT value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
        (*namespace.as_tuple,value.source_head.key.token)).fetchone()
    if source is None or source[1]!=1:raise MissingProductionOriginalV1('current_source_access_to_completed_method_history')
    _source_family_current_sql_v1(db,namespace=namespace,roots=(value.source_head.key.token,),purpose='consolidation',
        audiences=tuple(background_json_loads_v3(source[0])['audiences']))
    return value,original['receipt']


def validate_artifact_method_settlement_joins_v2(db):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .domain_production_originals_v1 import TABLE,read_adopted_domain_operation_v1
    if _artifact_receipt_sql_v1(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone() is None:return
    for bot,persona,operation_id in _artifact_receipt_sql_v1(db,"SELECT bot,persona,operation_id FROM "+TABLE+" WHERE domain='d08' AND operation_kind='settle_personal_goal'"):
        namespace=NamespaceId(bot,persona);original=read_adopted_domain_operation_v1(db,namespace,operation_id)
        raw=original['payload']['provenance'].get('artifact_method_completion')
        if raw is not None:require_artifact_method_settlement_history_v2(db,namespace=namespace,original=original,raw=raw)
