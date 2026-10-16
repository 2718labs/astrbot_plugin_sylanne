"""Installed Artifact MODEL read profile; current facts confer no content permit."""
from __future__ import annotations
from dataclasses import dataclass,fields
from datetime import datetime
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..graph_types import AtomKey,GraphVersion

_READERS=WeakKeyDictionary()
_CORE=WeakKeyDictionary()
_BODIES=WeakKeyDictionary()
_KEY=object()
_CONTROL_FRAMES={}

@dataclass(frozen=True,slots=True)
class ArtifactModelSelfFactsV1:
    namespace:object
    installation_id:str
    self_entity_ref:str
    mapping_head:GraphVersion
    mapping_digest:str
    prepared_digest:str
    frozen_digest:str
    model_request_digest:str
    original_model_scope_binding_digest:str
    current_graph_stamp:tuple
    schema:str="artifact-model-self-facts.v1"
    def __post_init__(self):
        if self.schema!="artifact-model-self-facts.v1" or self.mapping_head.key.type_name!="d03.self_identity_mapping.v1":
            raise ValueError("Artifact model Self facts require the actual current mapping")
        for name in ("mapping_digest","prepared_digest","frozen_digest","model_request_digest","original_model_scope_binding_digest"):
            value=getattr(self,name)
            if type(value)is not str or len(value)!=64:raise ValueError("actual model Self digest required")

@dataclass(frozen=True,slots=True)
class ArtifactCurrentModelGraphV3:
    prepared:object
    frozen:object
    job:object
    request:object
    self_facts:ArtifactModelSelfFactsV1
    deadline_utc:float

class InstalledArtifactDraftModelGraphReaderV3:
    def __init__(self,*,owner_storage,bundle,issuer,model_service,worker_service,habit_service):
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        from .v2_model_egress_service import AuthorityV2ModelEgressService
        from .v2_worker_model_result_read_service import AuthorityV2WorkerModelResultReadService
        from ..host.authority_profile import AdminInstallationBundle
        from ..runtime.issuers import D11BudgetJobIssuer
        if(type(owner_storage)is not InstalledD12OwnerStorageAdmissionServiceV1
                or type(bundle)is not AdminInstallationBundle or type(issuer)is not D11BudgetJobIssuer
                or type(model_service)is not AuthorityV2ModelEgressService
                or type(worker_service)is not AuthorityV2WorkerModelResultReadService):
            raise TypeError("actual Artifact model/paired worker/Owner/issuer installation required")
        policy=bundle.installation_policy
        if(owner_storage.namespace_id!=policy.namespace or owner_storage.namespace!=policy.authority_namespace
                or owner_storage.installation_id!=policy.installation_id
                or owner_storage.holder!=policy.administrator_holder
                or model_service._fences is not owner_storage.fences
                or worker_service._fences is not owner_storage.fences
                or worker_service._store is not model_service._store
                or worker_service._installation_id!=policy.installation_id or worker_service._holder!=owner_storage.holder
                or model_service._store._db is not owner_storage.core._db
                or model_service._graph_verifier._artifact_draft_bundle is not bundle
                or model_service._graph_verifier._issuer is not issuer
                or model_service._graph_verifier._path!=owner_storage.graph_path):
            raise AuthorityUnavailable("Artifact model installation crossed actual Core/Graph/Owner identities")
        if habit_service is not None:
            from .current_habit_occurrence_v1 import InstalledCurrentHabitOccurrenceV1
            if(type(habit_service)is not InstalledCurrentHabitOccurrenceV1
                    or habit_service.policy_service.owner_service is not owner_storage
                    or habit_service.issuer is not issuer or habit_service.installed_bundle is not bundle):
                raise AuthorityUnavailable("Artifact managed profile crossed actual installed Habit service")
        self.owner_storage,self.bundle,self.installed_bundle,self.issuer=owner_storage,bundle,bundle,issuer
        self.model_service,self.worker_service,self.habit_service=model_service,worker_service,habit_service
        self.read_subject=worker_service._read_subject;self.result_service=None
        _READERS[self]=(owner_storage,bundle,issuer,model_service,worker_service,habit_service,self.read_subject)
    def install_result_service_v3(self,service):
        from .d11_artifact_draft_model_v1 import AuthorityArtifactDraftModelResultServiceV1
        if(type(service)is not AuthorityArtifactDraftModelResultServiceV1 or self.result_service is not None
                or service._graph_reader is not self or service._fences is not self.owner_storage.fences
                or service._store is not self.model_service._store or service._read_subject!=self.read_subject
                or service._holder!=self.owner_storage.holder):
            raise AuthorityUnavailable('Artifact result profile requires actual paired model/worker credential tuple')
        self.result_service=service
    def require_installed_v3(self):
        if(_READERS.get(self)!=(self.owner_storage,self.bundle,self.issuer,self.model_service,self.worker_service,self.habit_service,self.read_subject)
                or self.worker_service._read_subject!=self.read_subject
                or self.worker_service._installation_id!=self.bundle.installation_policy.installation_id
                or self.worker_service._holder!=self.owner_storage.holder
                or self.worker_service._store is not self.model_service._store):
            raise AuthorityUnavailable("Artifact model reader changed its actual installed instances")
        return self
    def read(self,db,intent,now,*,allow_unsealed_prepare=False,allow_accounted_result=False):
        self.require_installed_v3()
        from .artifact_model_source_read_v3 import require_artifact_model_body_v3,artifact_model_namespace_recipe_v3,artifact_model_graph_point_v3
        cap=require_artifact_model_body_v3(db,self,intent);r=cap.reader;w=cap.work
        from .artifact_model_result_source_v3 import require_artifact_result_source_bridge_v3
        result_bridge=require_artifact_result_source_bridge_v3(w)
        expected_subject=intent.subject if result_bridge is None else self.read_subject
        if w.service is not self.model_service or(w.subject,w.permit.subject)!=(expected_subject,expected_subject):
            raise AuthorityUnavailable("Artifact MODEL subject differs from original actual permit and intent")
        from math import isfinite
        current_now=w.controller.clock()
        if type(current_now)not in(int,float)or not isfinite(current_now)or current_now<now:
            raise AuthorityUnavailable("Artifact actual trusted model clock changed during current Source read")
        now=float(current_now)
        from .d11_artifact_draft_model_v1 import _read_current_artifact_draft_model_graph
        p,job,frozen=_read_current_artifact_draft_model_graph(db,intent,self.issuer,now,installed_bundle=self.bundle,
            phase=r.phase_variant,allow_unsealed_prepare=allow_unsealed_prepare,allow_accounted_result=allow_accounted_result)
        from ..runtime.d11_artifact_draft_model_v1 import read_artifact_draft_model_request_v1,read_artifact_draft_model_request_v2
        request=(read_artifact_draft_model_request_v2 if r.phase_variant else read_artifact_draft_model_request_v1)(
            db,prepared=p,issuer=self.issuer)
        from ..domains.d03.self_perspective import self_mapping_key,SelfIdentityMapping
        key=self_mapping_key(w.namespace)
        row=artifact_model_graph_point_v3(db,("revision","value","valid"),token=key.token)
        from .current_authority_graph_read_v3 import authority_current_json_v3
        value=authority_current_json_v3(row[1])if row is not None else None
        if(row is None or row[2]!=1 or type(value)is not dict or set(value)!={f.name for f in fields(SelfIdentityMapping)}
                or value["status"]!="active" or value["self_entity_ref"]!=p.actor_ref
                or canonical_digest(value)!=frozen.current_self_digest):
            raise AuthorityUnavailable("Artifact model actual current Self mapping/entity/digest differs")
        facts=ArtifactModelSelfFactsV1(w.namespace,self.bundle.installation_policy.installation_id,p.actor_ref,
            GraphVersion(key,row[0]),canonical_digest(value),p.digest,frozen.digest,request.digest,
            canonical_digest((intent.operation_id,intent.binding_digest,intent.request_digest,intent.anchor_digest)),tuple(w.graph_stamp))
        control_frame=_artifact_control_frame_v3(_KEY,r,p,request,frozen,facts,now)
        require_artifact_model_classification_v3(r,p,request,frozen,facts,now)
        _require_artifact_joint_model_gate_v3(r,control_frame,p,request,facts)
        from .artifact_model_finished_producer_v3 import require_artifact_model_producer_finished_v3
        for operation,(header,raw,bundle)in r.producer_metadata.items():
            require_artifact_model_producer_finished_v3(r,operation=operation,expected_kind=header[1],
                original_digest=header[2],receipt_digest=header[3])
        result=ArtifactCurrentModelGraphV3(p,frozen,job,request,facts,
            min(w.deadline_utc,frozen.deadline_utc,datetime.fromisoformat(p.deadline_utc.replace("Z","+00:00")).timestamp()))
        old=_BODIES.get(w)
        if old is not None and old!=result:raise AuthorityUnavailable("Artifact same model Work changed actual verified body")
        _BODIES[w]=result;return cap.seal_v3(result)

def observe_artifact_model_core_state_v3(work,installed):
    """Observe only the actual current Core originals under the MODEL permit."""
    from .artifact_model_source_read_v3 import artifact_model_namespace_recipe_v3
    installed.require_installed_v3();r=artifact_model_namespace_recipe_v3(work)
    if r is None or r.control is None:return
    h=r.control.habit_classification
    if h.kind=="ordinary":
        if work in _CORE:raise AuthorityUnavailable("Artifact same Work changed managed classification")
        return
    service=installed.habit_service
    if service is None:raise AuthorityUnavailable("Managed Artifact model has no actual installed Habit runtime")
    p=service.policy_service;q=h.qualification_original;selection=q.selector
    from .owner_location_read_v3 import _OWNER_MODEL_LOCATION_ENTRIES_V3
    entry=_OWNER_MODEL_LOCATION_ENTRIES_V3[work][4]
    from .d10_habit_ledger_v1 import (OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,habit_ledger_decode_v1,
        habit_identity_commitment_v1,habit_scope_identity_commitment_v1)
    from .d10_habit_contract_v1 import HabitOccurrenceQualificationOriginalV1,HabitWindowCueOriginalV1
    with p.fences._frozen()as(db,deletion,execution,_):
        anchor=p.fences._current_locked(db,deletion,execution)
        p.fences.fences.validate_fence_locked(db,work.permit,subject=work.subject,current_anchor=anchor)
        head=p.owner_service._head_in_tx(db)
        policy=p._head_v1(db,AtomKey.from_token(selection.policy_ref).name)
        if(head!=entry.head or policy is None or policy.action=="revoke" or policy.definition.state!="enabled"
                or policy.authority_id!=p.core._id(db) or policy.owner_principal!=head.issue_operation.principal
                or policy.owner_head_digest!=head.guard.authorization_head
                or policy.owner_authorization_revision!=head.guard.authorization_revision
                or policy.owner_principal_epoch!=p._epoch_v1(db,head)
                or work.controller.clock()>=min(policy.definition.original_valid_until_utc,q.original_deadline_utc,selection.original_deadline_utc)
                or(policy.original_ref,policy.digest,policy.definition.revision,policy.definition.cancellation_generation)!=(
                    selection.standing_authorization_original_ref,selection.standing_authorization_original_digest,
                    selection.policy_revision,selection.cancellation_generation)):
            raise AuthorityUnavailable("Artifact model actual current Core standing policy/Owner was revoked/revised/expired")
        row=db.execute("SELECT * FROM "+OCCURRENCE_TABLE+" WHERE authority_namespace=? AND installation_id=? AND operation_commitment=?",
            (p.fences.namespace,p.installation_id,habit_identity_commitment_v1(service._key,"operation",selection.operation_id))).fetchone()
        if row is None:raise AuthorityUnavailable("Artifact model old qualification ledger row absent")
        actual=habit_ledger_decode_v1(OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,row,key=service._key,
            authority_namespace=p.fences.namespace,authority_id=p.core._id(db),installation_id=p.installation_id)
        if type(actual)is not HabitOccurrenceQualificationOriginalV1 or actual!=q:
            raise AuthorityUnavailable("Artifact model old qualification retired or exact immutable tuple differs")
        target=habit_scope_identity_commitment_v1(service._key,"target",work.namespace,p.installation_id,policy.definition.target_ref)
        project=habit_scope_identity_commitment_v1(service._key,"project",work.namespace,p.installation_id,policy.definition.project_ref)
        obligations=[]
        cursor=db.execute("SELECT * FROM "+OCCURRENCE_TABLE+" WHERE authority_namespace=? AND installation_id=? "
            "AND effect_commitment IS NOT NULL AND(target_commitment=? OR project_commitment=?) ORDER BY operation_commitment",
            (p.fences.namespace,p.installation_id,target,project))
        for raw in cursor:
            value=habit_ledger_decode_v1(OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,raw,key=service._key,
                authority_namespace=p.fences.namespace,authority_id=p.core._id(db),installation_id=p.installation_id)
            work.operation.retain(2048)
            obligations.append((value,raw[OCCURRENCE_COLUMNS.index("original_commitment")]))
        cue=None
        if policy.definition.cue_predicate.observation_provider=="d11.habit-window-cue.v1":
            cue_row=db.execute("SELECT * FROM "+OCCURRENCE_TABLE+" WHERE authority_namespace=? AND installation_id=? AND original_commitment=?",
                (p.fences.namespace,p.installation_id,habit_identity_commitment_v1(service._key,"original",selection.cue_original_ref))).fetchone()
            if cue_row is None:raise AuthorityUnavailable("Artifact model actual signed clock cue absent")
            cue=habit_ledger_decode_v1(OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,cue_row,key=service._key,
                authority_namespace=p.fences.namespace,authority_id=p.core._id(db),installation_id=p.installation_id)
            if type(cue)is not HabitWindowCueOriginalV1 or(cue.original_ref,cue.digest)!=(selection.cue_original_ref,selection.cue_original_digest):
                raise AuthorityUnavailable("Artifact model actual clock cue retired or exact tuple differs")
    value=(installed,work.permit,work.request,work.scope,entry.head,policy,actual,tuple(obligations),cue)
    prior=_CORE.get(work)
    if prior is not None and prior!=value:raise AuthorityUnavailable("Artifact model Core standing/qualification/obligations changed within original Work")
    _CORE[work]=value

def require_artifact_model_classification_v3(r,prepared,request,frozen,self_facts,now):
    r.capability.require_v3();w=r.work
    if self_facts.model_request_digest!=request.digest or self_facts.self_entity_ref!=prepared.actor_ref:
        raise AuthorityUnavailable("Artifact classification has no exact actual MODEL Self facts")
    from ..runtime.b3_managed_metadata_v1 import HABIT_TABLE,JOINT_TABLE,metadata_columns_v1
    habits=tuple(dict(zip(metadata_columns_v1(HABIT_TABLE),row))for row in r.managed[HABIT_TABLE])
    if not r.phase_variant:
        # V1 has its own actual signed task/Root/cycle producer; a phase Decision cannot be borrowed.
        if any(not row["retired"] and row["decision_ref"] in r.graph_tokens for row in habits):
            raise AuthorityUnavailable("Legacy C4 actual business set contains managed phase selection")
        return
    from ..runtime.d11_artifact_draft_model_v1 import _read_artifact_phase_selected_originals_v2,_artifact_phase_selection_locator_v2
    candidates,chosen,preparation=_read_artifact_phase_selected_originals_v2(w.db,selector=r.selector,issuer=r.installed.issuer)
    selected=_artifact_phase_selection_locator_v2(w.db,selector=r.selector)[1]
    from ..runtime.d10_habit_v1 import habit_draft_selector_commitment_v1
    commitment=habit_draft_selector_commitment_v1(w.namespace,decision_ref=r.selector.decision_ref,
        decision_digest=r.selector.decision_digest,phase_selector=r.selector,
        future_identity=chosen.future_identity,issuer=r.installed.issuer)
    h=r.control.habit_classification
    if(h.selector_commitment!=commitment or h.phase_selector!=r.selector
            or h.selection_operation_id!=selected["receipt"].operation_id
            or(h.selection_original_digest,h.selection_receipt_digest)!=(selected["original_digest"],canonical_digest(selected["receipt"]))
            or h.prepared_candidates_operation_id!=candidates.preparation_operation_id):
        raise AuthorityUnavailable("Artifact classification differs from actual signed D08 choice/preparation")
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    original=read_adopted_domain_operation_v1(w.db,w.namespace,h.prepared_candidates_operation_id)
    if original is None or(original["original_digest"],canonical_digest(original["receipt"]))!=(
            h.prepared_candidates_original_digest,h.prepared_candidates_receipt_digest):
        raise AuthorityUnavailable("Artifact classification changed actual complete candidate producer")
    current=tuple(row for row in habits if row["selector_commitment"]==commitment)
    occurrences=tuple((key,rev,o,digest)for key,(rev,o,digest)in r.occurrences.items()
        if o.occurrence_operation_id==chosen.future_identity.action_operation_id or
            o.action_intent_ref==chosen.future_identity.action_ref)
    if h.kind=="ordinary":
        invalid=tuple(value for value in r.invalid_occurrences.values()if value.get("occurrence_operation_id")==chosen.future_identity.action_operation_id
            or value.get("action_intent_ref")==chosen.future_identity.action_ref)
        if current or occurrences or invalid:raise AuthorityUnavailable("Artifact ordinary choice matches actual managed or retired/visible Habit metadata")
        return
    if len(current)!=1 or current[0]["retired"] or current[0]["current_state"]!="enabled" or len(occurrences)!=1:
        raise AuthorityUnavailable("Artifact managed phase has no unique enabled actual HMAC row and occurrence EOF")
    row=current[0];key,revision,occurrence,_=occurrences[0];state=_CORE.get(w)
    if state is None:raise AuthorityUnavailable("Artifact managed MODEL lacks independent actual current Core original observation")
    policy,q,obligations,cue=state[5:]
    definition=policy.definition
    mirror=r.policies.get(AtomKey.from_token(q.selector.policy_ref))
    if(mirror is None or mirror[1].definition!=definition or mirror[1].core_original_ref!=policy.original_ref
            or mirror[1].core_original_digest!=policy.digest or mirror[1].digest!=q.selector.policy_digest
            or occurrence.state!="qualified" or occurrence.actual_started_at_utc is not None
            or occurrence.qualification_original_ref!=q.original_ref
            or(row["decision_ref"],row["decision_digest"],row["phase_selector_digest"],row["future_identity_digest"],
                row["policy_ref"],row["policy_revision"],row["core_original_ref"],row["core_original_digest"])!=(
                    r.selector.decision_ref,r.selector.decision_digest,canonical_digest(r.selector),canonical_digest(chosen.future_identity),
                    q.selector.policy_ref,definition.revision,policy.original_ref,policy.digest)
            or prepared.parent_budget_lease_ref!=occurrence.parent_root_grant_ref
            or tuple(prepared.audiences)!=definition.audience
            or q.self_entity_ref!=self_facts.self_entity_ref
            or(definition.parent_root_grant_ref,definition.parent_root_grant_digest)!=(occurrence.parent_root_grant_ref,occurrence.parent_root_grant_digest)
            or policy.root_lease_id!=prepared.parent_budget_lease_ref
            or now>=min(occurrence.original_deadline_utc,definition.original_valid_until_utc)
            or (q.target_commitment,q.project_commitment)!=(policy.target_commitment,policy.project_commitment)):
        raise AuthorityUnavailable("Artifact MODEL current policy/occurrence/Root/target/executor window differs")
    from ..model_broker.artifact_draft_v1 import artifact_draft_file_ids_v2
    ids=artifact_draft_file_ids_v2(r.selector);selection=q.selector
    if(definition.executor_kind!="draft_file" or r.selector.decision_ref!=definition.target_ref
            or(occurrence.occurrence_operation_id,occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id)!=(
                ids["action_operation"],ids["activity_id"],ids["effect"],ids["attempt"])
            or(selection.execution_operation_id,selection.activity_id,selection.effect_id,selection.attempt_id)!=(
                occurrence.occurrence_operation_id,occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id)):
        raise AuthorityUnavailable("Artifact MODEL actual selected generation and qualified effect differ")
    relevant=tuple((k,o)for k,(_,o,_)in r.occurrences.items()if o.policy_ref==selection.policy_ref)
    if len(tuple(k for k,o in relevant if o.window_id==occurrence.window_id))>definition.maximum_occurrences_per_window:
        raise AuthorityUnavailable("Artifact MODEL complete cross-revision window census exceeds signed maximum")
    times=tuple(o.actual_started_at_utc if o.actual_started_at_utc is not None else o.admitted_at_utc
        for k,o in relevant if k!=key and(o.actual_started_at_utc is not None or o.admitted_at_utc is not None))
    if times and now-max(times)<definition.minimum_interval_seconds:
        raise AuthorityUnavailable("Artifact MODEL actual minimum interval is not ready")
    from .artifact_model_source_read_v3 import artifact_model_source_family_v3
    artifact_model_source_family_v3(w.db,namespace=w.namespace,roots=tuple(r.habit_context_roots),purpose="context",audiences=definition.audience)
    _require_model_obligations_v3(r,key,policy,obligations)
    _require_model_cue_and_stop_v3(r,policy,q,cue,now)
    producer=read_adopted_domain_operation_v1(w.db,w.namespace,selection.operation_id)
    from ..domains.d01.production_operations_v1 import plain_v1
    if producer is None or producer["operation_kind"]!="qualify_habit_occurrence_v1" or producer["payload"]["provenance"]["core_qualification"]!=plain_v1(q):
        raise AuthorityUnavailable("Artifact MODEL old Core qualification lacks actual positive Graph producer")
    from .artifact_model_finished_producer_v3 import require_artifact_model_producer_finished_v3
    require_artifact_model_producer_finished_v3(r,operation=selection.operation_id,expected_kind="qualify_habit_occurrence_v1",
        original_digest=producer["original_digest"],receipt_digest=canonical_digest(producer["receipt"]))

def _require_model_obligations_v3(r,selected,policy,obligations):
    from .d10_habit_ledger_v1 import habit_scope_identity_commitment_v1,habit_identity_commitment_v1
    service=r.installed.habit_service;p=service.policy_service;ns=r.work.namespace
    locators={}
    for key,(_,o,_)in r.occurrences.items():
        if o.effect_id is None or o.qualification_original_ref is None:continue
        pair=(habit_scope_identity_commitment_v1(service._key,"effect",ns,p.installation_id,o.effect_id),
            habit_identity_commitment_v1(service._key,"original",o.qualification_original_ref))
        if pair in locators:raise AuthorityUnavailable("Artifact MODEL occurrence EOF has conflicting effect/original bindings")
        locators[pair]=key
    for original,original_commitment in obligations:
        key=locators.get((original.effect_commitment,original_commitment))
        if key is None:raise AuthorityUnavailable("Artifact MODEL opaque prior target/project effect lacks actual authenticated visible settlement")
        if key==selected:continue
        o=r.occurrences[key][1]
        if o.state in {"active","unknown"} or o.state=="cancelled"and o.actual_started_at_utc is not None:
            raise AuthorityUnavailable("Artifact MODEL actual prior obligation remains unresolved")
        if o.state in {"completed_verified","failed_verified"}:_require_model_terminal_v3(r,key,o)
        elif o.state not in {"registered","waiting","qualified","cancelled"}:
            raise AuthorityUnavailable("Artifact MODEL prior obligation has no actual no-start or verified terminal")
    for key,(_,o,_)in r.occurrences.items():
        if key==selected or o.state not in {"active","unknown"}:continue
        mirror=r.policies.get(AtomKey.from_token(o.policy_ref))
        if mirror is not None and mirror[1].definition.target_ref==policy.definition.target_ref:
            raise AuthorityUnavailable("Artifact MODEL visible same-target obligation remains active or unknown")

def _require_model_terminal_v3(r,key,occurrence):
    from .artifact_model_source_read_v3 import artifact_model_graph_point_v3
    revision=r.occurrences[key][0]
    r.metadata_history_versions.add((key.token,revision))
    history=artifact_model_graph_point_v3(r.work.db,("event_id","value","valid"),token=key.token,revision=revision)
    from .current_authority_graph_read_v3 import authority_current_json_v3
    from ..domains.d01.production_operations_v1 import plain_v1
    if history is None or history[2]!=1 or authority_current_json_v3(history[1])!=plain_v1(occurrence):
        raise AuthorityUnavailable("Artifact MODEL terminal occurrence differs from exact current history")
    operation=history[0];r.original_operations.add(operation)
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    producer=read_adopted_domain_operation_v1(r.work.db,r.work.namespace,operation)
    if producer is None or producer["operation_kind"]!="adopt_habit_outcome_v1" or GraphVersion(key,revision)not in producer["receipt"].write_versions:
        raise AuthorityUnavailable("Artifact MODEL terminal occurrence has no actual positive outcome COMMIT")
    from .artifact_model_finished_producer_v3 import require_artifact_model_producer_finished_v3
    require_artifact_model_producer_finished_v3(r,operation=operation,expected_kind="adopt_habit_outcome_v1",
        original_digest=producer["original_digest"],receipt_digest=canonical_digest(producer["receipt"]))

def _require_model_cue_and_stop_v3(r,policy,q,cue,now):
    d=policy.definition;selection=q.selector
    from .artifact_model_source_read_v3 import artifact_model_graph_point_v3
    from .current_authority_graph_read_v3 import authority_current_json_v3
    def interpretation(ref,digest,question,proposition):
        row=artifact_model_graph_point_v3(r.work.db,("revision","value","valid"),token=ref)
        if row is None or row[2]!=1:raise AuthorityUnavailable("Artifact MODEL actual scoped interpretation absent")
        value=authority_current_json_v3(row[1])
        if(canonical_digest(value)!=digest or value["question_key"]!=question or value["stance"]!="support"
                or value["evidence_status"]!="supported" or value["meaningful_unknowns"]
                or value["current"]is not True or value["proposition"]!=proposition):
            raise AuthorityUnavailable("Artifact MODEL scoped interpretation changed or unsupported")
        key=AtomKey.from_token(ref);r.graph_versions.add((ref,row[0]))
        history=artifact_model_graph_point_v3(r.work.db,("event_id","valid"),token=ref,revision=row[0])
        if history is None or history[1]!=1:raise AuthorityUnavailable("Artifact MODEL interpretation has no actual adoption history")
        r.original_operations.add(history[0])
        from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
        original=read_adopted_domain_operation_v1(r.work.db,r.work.namespace,history[0])
        if original is None or GraphVersion(key,row[0])not in original["receipt"].write_versions:
            raise AuthorityUnavailable("Artifact MODEL interpretation lacks actual positive COMMIT member")
        return value
    if d.cue_predicate.observation_provider=="d11.habit-window-cue.v1":
        if(cue is None or cue.selector.policy_ref!=selection.policy_ref or cue.selector.policy_revision!=selection.policy_revision
                or cue.selector.cue_stable_key!=selection.cue_stable_key or cue.execution_state!="due"):
            raise AuthorityUnavailable("Artifact MODEL actual signed clock cue differs")
        operation="habit-window-cue-write:"+selection.cue_stable_key[:48];r.original_operations.add(operation)
        from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
        original=read_adopted_domain_operation_v1(r.work.db,r.work.namespace,operation)
        from ..domains.d01.production_operations_v1 import plain_v1
        if original is None or original["operation_kind"]!="record_habit_window_cue_v1" or original["payload"]["provenance"]["core_cue"]!=plain_v1(cue):
            raise AuthorityUnavailable("Artifact MODEL clock cue lacks actual positive committed producer")
    else:
        value=interpretation(selection.cue_original_ref,selection.cue_original_digest,
            "d10.habit-cue:"+canonical_digest((d.namespace,d.policy_id,d.revision,d.cue_predicate)),"cue_present")
        from ..memory_types import source_key
        selected=set();pending=list(value["source_refs"])
        while pending:
            ref=pending.pop()
            if ref in selected:continue
            if ref not in r.qualified:raise AuthorityUnavailable("Artifact MODEL cue Source lacks independent context ALL")
            selected.add(ref);pending.extend(source_key(*d.namespace.as_tuple,parent).token for parent in r.qualified[ref][1].parent_source_ids)
        stable=canonical_digest(tuple((ref,r.qualified[ref][1].source_id,r.qualified[ref][1].recorded_at)for ref in sorted(selected)))
        recorded=max(r.qualified[ref][1].recorded_at for ref in selected)
        if(stable!=selection.cue_stable_key or recorded>now or recorded<d.cue_predicate.valid_from
                or d.cue_predicate.valid_until is not None and recorded>d.cue_predicate.valid_until):
            raise AuthorityUnavailable("Artifact MODEL semantic cue Source identity/time differs")
    if d.stop_predicate.observation_provider=="d07.habit-stop.v1":
        parameters=dict(d.stop_predicate.parameters);ref=parameters["interpretation_ref"]
        row=artifact_model_graph_point_v3(r.work.db,("value","valid"),token=ref)
        if row is None or row[1]!=1:raise AuthorityUnavailable("Artifact MODEL actual current stop observation absent")
        interpretation(ref,canonical_digest(authority_current_json_v3(row[0])),
            "d10.habit-stop:"+canonical_digest((policy.namespace,d.policy_id,d.revision)),"continue")

def release_artifact_model_graph_v3(work):
    _CORE.pop(work,None);_BODIES.pop(work,None)
    for key,state in tuple(_CONTROL_FRAMES.items()):
        if state[1].work is work:_CONTROL_FRAMES.pop(key,None)

def _artifact_control_frame_v3(key,r,prepared,request,frozen,facts,now):
    """Actual B plus qualified control Body view; never a model input or issuance."""
    if key is not _KEY:raise AuthorityUnavailable("actual installed Artifact model frame factory required")
    r.capability.require_v3()
    if(prepared.digest!=r.prepared.header[1]or request.digest!=r.work.request.request_digest
            or frozen.digest!=r.frozen.header[1]or facts.self_entity_ref!=prepared.actor_ref):
        raise AuthorityUnavailable("Artifact private control view changed actual verified model originals/Self")
    if r.control_frame is not None:
        require_artifact_control_frame_v3(r.control_frame);return r.control_frame
    from .artifact_model_source_read_v3 import read_bound_artifact_model_graph_atom_v3,artifact_model_current_type_versions_v3
    from ..graph_types import GraphSnapshot,NamespaceEpoch
    from ..runtime_contracts import QueryEpoch
    from ..runtime.domain_production_contracts_v1 import CurrentOperationFrameV1,ProductionQueryCoverageV1,ProductionOwnerGuardV1
    from dataclasses import replace
    from .owner_location_read_v3 import require_owner_location_for_model_graph_read_v3
    w=r.work;owner=require_owner_location_for_model_graph_read_v3(w.db,installed_reader=r.installed,intent=w.request)
    owner_guard=ProductionOwnerGuardV1(prepared.owner_guard.grant_ref,prepared.owner_guard.grant_revision,
        canonical_digest(owner.grant),owner.head.guard.authorization_head.removeprefix("sha256:"))
    if owner_guard!=prepared.owner_guard:
        raise AuthorityUnavailable("Artifact actual current Owner17 grant/head differs from original preparation")
    atoms=[]
    for token in sorted(r.body_graph_tokens):
        _,atom=read_bound_artifact_model_graph_atom_v3(w.db,w.namespace,AtomKey.from_token(token));atoms.append(atom)
    snapshot=GraphSnapshot(tuple(atoms),(NamespaceEpoch(*w.namespace.as_tuple,w.graph_stamp[0]),))
    pages=[]
    coverages=()if r.control is None else(*r.control.business_query_coverage,*r.control.control_query_coverage)
    for type_id in sorted({page.type_id for page in coverages}):
        rows=artifact_model_current_type_versions_v3(w.db,w.namespace,type_id,limit=1025)
        if len(rows)>1024:raise AuthorityUnavailable("Artifact complete current control inventory exceeds original bound")
        pages.append(ProductionQueryCoverageV1(QueryEpoch(w.namespace,"namespace",w.graph_stamp[0]),type_id,
            tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in rows),True,None))
    envelope=replace(request.envelope,authority=replace(request.envelope.authority,actor=facts.self_entity_ref),
        version_guard=replace(request.envelope.version_guard,read_versions=snapshot.versions,
            query_epochs=(QueryEpoch(w.namespace,"namespace",w.graph_stamp[0]),),
            access_epoch=w.graph_stamp[1],delete_epoch=w.graph_stamp[2]))
    frame=CurrentOperationFrameV1(envelope,snapshot,now,owner_guard,prepared.activation_generation,tuple(pages),(),())
    r.control_frame=frame
    _CONTROL_FRAMES[id(frame)]=(frame,r,facts,request,w.operation,w.scope,w.permit,tuple(w.graph_stamp))
    return frame

def require_artifact_control_frame_v3(frame):
    state=_CONTROL_FRAMES.get(id(frame))
    if state is None:return None
    actual,r,facts,request,operation,scope,permit,stamp=state;r.capability.require_v3();w=r.work
    if(actual is not frame or r.control_frame is not frame or operation is not w.operation or scope is not w.scope
            or permit is not w.permit or stamp!=tuple(w.graph_stamp)or facts.model_request_digest!=request.digest
            or request.digest!=w.request.request_digest or frame.envelope.authority.actor!=facts.self_entity_ref):
        raise AuthorityUnavailable("Artifact private current view lost exact actual Model/Source/Owner/Self binding")
    return r,facts,request

def _require_artifact_joint_model_gate_v3(r,frame,prepared,request,facts):
    from ..runtime.joint_node_execution_v1 import joint_artifact_binding_for_selector_v1,require_current_joint_binding_gate_v1
    from ..runtime.current_joint_window_source_read_v3 import _artifact_scope_recipe,_classification,read_current_joint_window_execution_classification_v3,_guard_inventory
    from ..runtime.joint_window_management_v1 import _require_classification
    from ..runtime.d01_production_operations_v1 import CurrentDomainReadV1
    from ..runtime.owner_goal_projection_v1 import require_joint_artifact_goal_projection_gate_v1
    require_artifact_control_frame_v3(frame)
    binding=joint_artifact_binding_for_selector_v1(r.work.db,selector=r.selector,issuer=r.installed.issuer)
    if binding is None:
        task=r.selector.task if r.phase_variant else r.selector
        read=CurrentDomainReadV1(frame);read.check(r.work.db)
        kind,ref,digest,ordinary_ref,ordinary_digest=_artifact_scope_recipe(r.work.db,read,task.root_registration_ref,r.installed.issuer)
        with _guard_inventory(r.work.db,r.work.namespace,r.installed.issuer)as inventory:
            classification=_classification(r.work.db,frame,inventory,executor_kind=kind,input_ref=ref,input_digest=digest,
                ordinary_original_ref=ordinary_ref,ordinary_original_digest=ordinary_digest,argument=None,preparing=False,
                issuer=r.installed.issuer)
    else:
        classification=read_current_joint_window_execution_classification_v3(r.work.db,namespace=r.work.namespace,
            issuer=r.installed.issuer,binding=binding,frame=frame)
        from ..runtime.joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
        if type(binding)is JointArtifactProspectiveBindingV1:
            require_joint_artifact_goal_projection_gate_v1(r.work.db,namespace=r.work.namespace,binding=binding,issuer=r.installed.issuer)
        require_current_joint_binding_gate_v1(r.work.db,frame=frame,binding=binding,issuer=r.installed.issuer)
    _require_classification(classification,namespace=r.work.namespace,execution=True)

def read_bound_artifact_model_frame_inventory_v3(frame,db,type_name):
    state=require_artifact_control_frame_v3(frame)
    if state is None:return False,None
    r=state[0]
    if db is not r.work.db or not db.in_transaction:
        raise AuthorityUnavailable("Artifact private complete inventory crossed actual bound Graph snapshot")
    from .artifact_model_source_read_v3 import artifact_model_current_type_versions_v3,read_bound_artifact_model_graph_atom_v3
    rows=artifact_model_current_type_versions_v3(db,r.work.namespace,type_name,limit=frame.limits.max_query_rows+1)
    if len(rows)>frame.limits.max_query_rows:raise AuthorityUnavailable("Artifact complete inventory exceeds installed original bound")
    values=[]
    for token,revision in rows:
        _,atom=read_bound_artifact_model_graph_atom_v3(db,r.work.namespace,AtomKey.from_token(token))
        if atom.revision!=revision or frame.snapshot.get(atom.key)!=atom:
            raise AuthorityUnavailable("Artifact exact complete inventory is not in actual control Body view")
        values.append(atom)
    return True,tuple(values)

def require_artifact_model_frame_source_family_v3(frame,db,roots,*,purpose,audience):
    state=require_artifact_control_frame_v3(frame)
    if state is None:return
    r=state[0]
    if db is not r.work.db:raise AuthorityUnavailable("Artifact Source-family callee crossed its actual Model Work")
    purposes=(purpose or frame.envelope.authority.purpose,)
    audiences=(audience,)if audience is not None else frame.envelope.authority.audience
    from ..memory_types import source_key
    seen=set()
    def visit(ref):
        if ref in seen:return
        actual=r.qualified.get(ref)
        if actual is None or any(not any(identity[1:]==(ref,p,a)for identity in r.checked)for p in purposes for a in audiences):
            raise AuthorityUnavailable("Artifact Source-family Body precedes its independent exact purpose/audience ALL")
        seen.add(ref)
        for parent in actual[1].parent_source_ids:visit(source_key(*r.work.namespace.as_tuple,parent).token)
    for ref in roots:visit(ref)

def artifact_model_frame_committed_operation_v3(frame,db,operation_id):
    state=require_artifact_control_frame_v3(frame)
    if state is None:return False,None
    r=state[0]
    if db is not r.work.db or operation_id not in r.original_operations:
        raise AuthorityUnavailable("Artifact positive COMMIT callee escaped actual selected producer family")
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    original=read_adopted_domain_operation_v1(db,r.work.namespace,operation_id)
    if original is None or original["receipt"].status!="committed":
        raise AuthorityUnavailable("Artifact current original producer has no actual positive COMMIT")
    receipt=original["receipt"]
    return True,(receipt.operation_digest,canonical_serialize(receipt),receipt.commit_seq)
