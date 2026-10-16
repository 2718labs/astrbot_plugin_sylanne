"""Independent installed Core Habit standing, occurrence and durable clock observations."""
from dataclasses import asdict,dataclass
import hashlib,hmac
from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .v2_self_identity_contract import SelfIdentityCurrentRequestV1,AuthorityCurrentSelfIdentityV1
from .v2_self_identity_service import AuthorityV2SelfIdentityService
from .d10_habit_contract_v1 import (HabitStandingPolicyOriginalV1,HabitOccurrenceQualificationOriginalV1,
    HabitWindowCueSelectorV1,HabitWindowCueOriginalV1,HabitOccurrenceBirthSelectorV1,habit_occurrence_qualification_to_wire_v1,
    habit_window_cue_original_to_wire_v1)
from .d10_habit_policy_service_v1 import InstalledD10HabitPolicyServiceV1
from .d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
from .habit_body_preparation_v3 import HabitBodyPreparationSelectorV3
from .current_habit_artifact_restriction_v1 import HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3
from .d10_habit_ledger_v1 import (OCCURRENCE_TABLE as TABLE,OCCURRENCE_DDL as DDL,OCCURRENCE_COLUMNS,
    HabitRetirementV1,habit_ledger_triggers_v1,habit_ledger_decode_v1,habit_identity_commitment_v1,habit_scope_identity_commitment_v1,MAX_PAYLOAD_BYTES)
from .habit_authority_source_read_v3 import HabitStandingDefinitionInputV1,prepare_habit_authority_inputs_v3,require_habit_authority_work_v3
from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1,habit_occurrence_id_v1,habit_occurrence_key_v1,habit_value_from_wire_v1
from ..domains.d10.habit_policy_v1 import (HabitPolicyDefinitionV1,habit_policy_key_v1,graph_adopted_habit_policy_from_wire_v1,
    habit_policy_dependency_refs_v1)
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,QueryEpoch,canonical_digest,canonical_serialize
from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
from ..runtime.issuers import D11BudgetJobIssuer

TRIGGERS=habit_ledger_triggers_v1(TABLE)

def current_habit_fence_operation_id_v1(request):
    from .current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
    if type(request)is HabitOriginalMaintenanceSelectorV1:return request.operation_id
    if type(request)in{HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3}:
        from .current_foreground_activity_v1 import foreground_fence_operation_id_v1
        return foreground_fence_operation_id_v1(request.foreground_request)
    if type(request)not in{HabitOccurrenceSelectorV1,HabitWindowCueSelectorV1,HabitOccurrenceBirthSelectorV1,HabitOccurrenceExecutionSelectorV1,HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3}:raise TypeError("fixed current Habit selector required")
    return request.operation_id

@dataclass(frozen=True,slots=True)
class HabitOccurrenceCurrentV1:
    request:HabitOccurrenceSelectorV1|HabitWindowCueSelectorV1|HabitOccurrenceBirthSelectorV1|HabitOccurrenceExecutionSelectorV1|HabitArtifactAdditionalSelectorV1|HabitArtifactModelReadSelectorV3
    policy_original:HabitStandingPolicyOriginalV1
    qualification_original:HabitOccurrenceQualificationOriginalV1|None
    timecue_original:HabitWindowCueOriginalV1|None
    current_self:AuthorityCurrentSelfIdentityV1
    owner_guard:ProductionOwnerGuardV1
    read_versions:tuple[GraphVersion,...]
    query_epoch:QueryEpoch
    access_epoch:int
    delete_epoch:int
    current_job_digest:str|None
    observed_at_utc:float
    valid_until_utc:float
    schema:str="d10.current-habit-occurrence.v1"
    def __post_init__(self):
        if(self.schema!="d10.current-habit-occurrence.v1"or type(self.request)not in{HabitOccurrenceSelectorV1,HabitWindowCueSelectorV1,HabitOccurrenceBirthSelectorV1,HabitOccurrenceExecutionSelectorV1,HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3}
                or type(self.policy_original)is not HabitStandingPolicyOriginalV1 or type(self.current_self)is not AuthorityCurrentSelfIdentityV1
                or type(self.owner_guard)is not ProductionOwnerGuardV1 or type(self.query_epoch)is not QueryEpoch
                or self.request.namespace!=self.current_self.namespace or self.observed_at_utc>=self.valid_until_utc
                or self.qualification_original is not None and self.qualification_original.selector!=(self.request.qualification_selector if type(self.request)in{HabitOccurrenceExecutionSelectorV1,HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3}else self.request)
                or type(self.request)in{HabitOccurrenceSelectorV1,HabitOccurrenceExecutionSelectorV1,HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3}and self.qualification_original is None
                or type(self.request)is HabitWindowCueSelectorV1 and self.timecue_original is None
                or self.timecue_original is not None and(type(self.request)is not HabitOccurrenceBirthSelectorV1
                    and self.timecue_original.selector!=self.request or type(self.request)is HabitOccurrenceBirthSelectorV1
                    and(self.timecue_original.original_ref,self.timecue_original.digest)!=(self.request.cue_original_ref,self.request.cue_original_digest))):
            raise ValueError("Habit current evidence lost exact selector/Owner/Self/original bounds")
    def require_for_v3(self,*,request,permit,installation_id,authority_namespace):
        if(self.request!=request or self.current_self.permit!=permit or self.current_self.installation_id!=installation_id
                or self.current_self.authority_namespace!=authority_namespace):
            raise AuthorityUnavailable("Habit current evidence differs from same original permit/installation")
        return self

class InstalledCurrentHabitOccurrenceV1:
    def __init__(self,*,self_identity_service,budget_issuer,clock_provider,installed_bundle,policy_service,create=False):
        from ..host.authority_profile import AdminInstallationBundle
        from .linux_clock_v1 import LinuxKernelClockProviderV1
        if(type(self_identity_service)is not AuthorityV2SelfIdentityService or type(budget_issuer)is not D11BudgetJobIssuer
                or type(installed_bundle)is not AdminInstallationBundle or type(policy_service)is not InstalledD10HabitPolicyServiceV1
                or policy_service.owner_service is not self_identity_service._owner_storage
                or policy_service.fences is not self_identity_service._fences
                or policy_service.installation_id!=installed_bundle.installation_policy.installation_id
                or installed_bundle.installation_policy.namespace!=self_identity_service._namespace_id
                or installed_bundle.installation_policy.manifest_digest!=self_identity_service._manifest_digest):
            raise TypeError("Habit current needs actual shared installed Self/Owner/Root/clock tuple")
        # Same concrete provider contract as the existing current Owner activity service.
        if type(clock_provider)is not LinuxKernelClockProviderV1:raise TypeError("Habit requires installed real paired kernel clock")
        self.self_identity,self.issuer,self.clock=self_identity_service,budget_issuer,clock_provider
        self.installed_bundle,self.policy_service=installed_bundle,policy_service
        self._path=self_identity_service._graph._path
        self._key=policy_service._key
        with policy_service.core._tx()as db:
            for kind,name,ddl in(("table",TABLE,DDL),*(("trigger",n,d)for n,d in TRIGGERS)):
                row=db.execute("SELECT sql FROM sqlite_master WHERE type=? AND name=?",(kind,name)).fetchone()
                if row is None and create:db.execute(ddl)
                elif row!=(ddl,):raise AuthorityUnavailable("Habit current immutable ledger schema differs")
        from .current_authority_graph_read_v3 import install_authority_graph_read_controller_v3
        install_authority_graph_read_controller_v3(self,service=self,source_location=self_identity_service._source_location)
        policy_service.install_current_v1(self)
    def policy_ref_v1(self,policy_id):return habit_policy_key_v1(self.self_identity._namespace_id,policy_id).token
    def selected_keys_v1(self,request,definition):
        from .current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
        if type(request)is HabitOriginalMaintenanceSelectorV1:
            from .habit_maintenance_source_read_v3 import habit_maintenance_selected_keys_v1
            return habit_maintenance_selected_keys_v1(request)
        execution=request if type(request)in {HabitOccurrenceExecutionSelectorV1,HabitBodyPreparationSelectorV3} else None
        additional=request if type(request)in{HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3} else None
        request=request.qualification_selector if execution is not None or additional is not None else request
        refs=set(habit_policy_dependency_refs_v1(definition))
        if additional is not None:
            refs.update((additional.foreground_request.cycle_job_ref,additional.artifact_phase_selector.decision_ref,additional.artifact_phase_selector.plan_ref))
        if type(request)is not HabitStandingDefinitionInputV1:refs.add(self.policy_ref_v1(definition.policy_id))
        if type(request)is HabitWindowCueSelectorV1:refs.add(request.subscription_job_ref)
        if type(request)is HabitOccurrenceSelectorV1:
            identity=habit_occurrence_id_v1(definition.namespace,definition.policy_id,definition.revision,request.window_id,request.cue_stable_key)
            refs.add(habit_occurrence_key_v1(definition.namespace,identity).token)
            if definition.cue_predicate.observation_provider=="d07.habit-cue.v1":refs.add(request.cue_original_ref)
        if type(request)is HabitOccurrenceBirthSelectorV1 and definition.cue_predicate.observation_provider=="d07.habit-cue.v1":
            refs.add(request.cue_original_ref)
        if definition.executor_kind=="source_note"and(type(request)is HabitStandingDefinitionInputV1 or execution is not None):
            from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
            refs.add(project_checkpoint_key_v1(definition.namespace,definition.project_ref).token)
        if execution is not None and execution.operation_kind!='instantiate_current_habit_source_note_context_v1':
            from ..runtime.d10_habit_v1 import habit_source_note_context_keys_v1
            identity=habit_occurrence_id_v1(definition.namespace,definition.policy_id,definition.revision,request.window_id,request.cue_stable_key)
            refs.update(key.token for key in habit_source_note_context_keys_v1(definition.namespace,identity,request.activity_id).values())
            from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
            refs.add(project_checkpoint_key_v1(definition.namespace,definition.project_ref).token)
            if execution.operation_kind not in {'instantiate_current_habit_source_note_context_v1','prepare_current_habit_source_note_action_v1'}:
                from ..runtime.d08_source_note_action_v1 import _keys,PrepareSourceNoteActionRequestV1
                source=definition.source_note_input
                context=habit_source_note_context_keys_v1(definition.namespace,identity,request.activity_id)
                derived=PrepareSourceNoteActionRequestV1(definition.project_ref,definition.recipe_ref,source.source_ref,context['goal'].token,definition.target_ref,source.role_binding_ref)
                _,action,cancel=_keys(definition.namespace,request.activity_id,request.execution_operation_id,derived)
                refs.update((action.token,cancel.token))
                if execution.operation_kind in {'register_current_habit_source_note_life_plan_v1','prepare_life'}:
                    from ..runtime.d02_life_body_preparation_v1 import _refs as body_refs
                    refs.add(body_refs(definition.namespace,request.activity_id,'d02-life-body:'+request.execution_operation_id)[0].token)
        return frozenset(AtomKey.from_token(ref)for ref in refs if AtomKey.from_token(ref).type_name!="memory.source")
    def _self_v1(self,credential,subject,permit,operation_id):
        s=self.self_identity
        if(type(permit)is not FencePermitV2 or permit.operation not in{"read","write"}or subject!=s._read_subject):
            raise AuthorityUnavailable("Habit needs actual installed Host read/write permit")
        request=SelfIdentityCurrentRequestV1(permit.authority_id,s._fences.namespace,s._namespace_id,
            s._installation_id,s._manifest_digest,operation_id,permit)
        value=s.current(credential=credential,subject=subject,request=request)
        if value is None:raise AuthorityUnavailable("Habit current independently registered Self absent")
        return value
    def qualify_standing_definition_v1(self,*,credential,subject,permit,definition,operation_id):
        if type(definition)is not HabitPolicyDefinitionV1:raise TypeError("actual Habit Definition required")
        habit_policy_dependency_refs_v1(definition)
        current=self._self_v1(credential,subject,permit,operation_id)
        inputs=prepare_habit_authority_inputs_v3(self,credential=credential,subject=subject,permit=permit,
            request=HabitStandingDefinitionInputV1(definition,operation_id),definition=definition,current_self=current)
        try:
            from .current_habit_execution_v1 import require_current_habit_source_note_input_v1
            require_current_habit_source_note_input_v1(inputs,definition)
            return inputs
        except BaseException:inputs.release_v3();raise
    def require_standing_root_v1(self,inputs,*,definition,permit,owner):
        state=require_habit_authority_work_v3(inputs.work)
        if(state is not inputs or not state.complete or state.definition!=definition or state.work.permit!=permit
                or state.owner_entry.head!=owner or state.root_grant!=self.installed_bundle.installation_policy.root_grant
                or state.root_lease.lease_id!=definition.parent_root_grant_ref):
            raise AuthorityUnavailable("Habit actual prepared Root/Owner/permit differs inside Core WRITE")
        return state
    def _prepare_v1(self,*,credential,subject,permit,request,require_write=True):
        if type(request)not in{HabitOccurrenceSelectorV1,HabitWindowCueSelectorV1,HabitOccurrenceBirthSelectorV1,HabitOccurrenceExecutionSelectorV1,HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3,HabitBodyPreparationSelectorV3}:raise TypeError("fixed existing Habit selector required")
        if require_write and(permit.operation!="write"or permit.operation_id!=current_habit_fence_operation_id_v1(request)):
            raise AuthorityUnavailable("Habit stage requires its exact newly issued named WRITE permit")
        if type(request)in{HabitWindowCueSelectorV1,HabitOccurrenceBirthSelectorV1}and request.installation_id!=self.policy_service.installation_id:
            raise AuthorityUnavailable("Habit selector changed actual installed identity")
        selection=request.qualification_selector if type(request)in{HabitOccurrenceExecutionSelectorV1,HabitArtifactAdditionalSelectorV1,HabitArtifactModelReadSelectorV3,HabitBodyPreparationSelectorV3}else request
        policy_id=AtomKey.from_token(selection.policy_ref).name
        policy=self.policy_service.read_current(credential=credential,subject=subject,permit=permit,policy_id=policy_id)
        if(policy is None or policy.definition.state!="enabled"or policy.original_ref!=selection.standing_authorization_original_ref
                or policy.digest!=selection.standing_authorization_original_digest or policy.definition.revision!=selection.policy_revision
                or policy.definition.cancellation_generation!=selection.cancellation_generation):
            raise AuthorityUnavailable("Habit standing original was paused/revised/revoked/retired")
        current=self._self_v1(credential,subject,permit,permit.operation_id if type(request)is HabitBodyPreparationSelectorV3 else request.operation_id)
        inputs=prepare_habit_authority_inputs_v3(self,credential=credential,subject=subject,permit=permit,
            request=request,definition=policy.definition,current_self=current)
        try:
            mirror=graph_adopted_habit_policy_from_wire_v1(inputs.bodies[AtomKey.from_token(selection.policy_ref)].value)
            if(mirror.definition!=policy.definition or mirror.core_original_ref!=policy.original_ref or mirror.core_original_digest!=policy.digest):
                raise AuthorityUnavailable("Habit Graph mirror differs from independently issued current Core original")
            if selection.policy_digest!=mirror.digest:raise AuthorityUnavailable("Habit selector changed actual adopted Graph policy digest")
            project=inputs.bodies[AtomKey.from_token(policy.definition.project_ref)]
            recipe=inputs.bodies[AtomKey.from_token(policy.definition.recipe_ref)]
            if(project.value["reality"]!="real_execution"or recipe.value["reality"]!="real_execution"
                    or recipe.revision!=policy.definition.recipe_revision):
                raise AuthorityUnavailable("Habit current project/recipe is not its original real execution recipe")
            stop=policy.definition.stop_predicate
            if stop.observation_provider=="d07.habit-stop.v1":
                atom=inputs.bodies[AtomKey.from_token(dict(stop.parameters)["interpretation_ref"])];value=atom.value
                if(value["question_key"]!="d10.habit-stop:"+canonical_digest((policy.namespace,policy.definition.policy_id,policy.definition.revision))
                        or value["stance"]!="support"or value["evidence_status"]!="supported"or value["meaningful_unknowns"]
                        or value["current"]is not True or value["proposition"]!="continue"):
                    raise AuthorityUnavailable("Habit stop predicate has no exact supported current continue observation")
                from .habit_authority_source_read_v3 import require_habit_current_adoption_v3
                require_habit_current_adoption_v3(inputs,atom)
            return policy,inputs
        except BaseException:inputs.release_v3();raise
    def _store_v1(self,*,credential,subject,permit,request,policy,inputs,kind,material,wire_material,value_type,wire_function):
        core=self.policy_service.core;fences=self.policy_service.fences
        inputs.require_for_v3(service=self,permit=permit)
        signature=hmac.new(self._key,canonical_serialize(wire_material).encode("utf8"),hashlib.sha256).hexdigest()
        value=value_type(**material,signature=signature)
        op=habit_identity_commitment_v1(self._key,"operation",request.operation_id)
        identity=habit_identity_commitment_v1(self._key,"policy",policy.definition.policy_id)
        with fences._frozen()as(db,deletion,execution,_):
            anchor=fences._current_locked(db,deletion,execution)
            fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
            head=self.policy_service.tickets.current_migration_head_in_tx(db,authority_namespace=fences.namespace)
            self.require_standing_root_v1(inputs,definition=policy.definition,permit=permit,owner=head)
            if self.policy_service._head_v1(db,policy.definition.policy_id)!=policy:raise AuthorityUnavailable("Habit current policy changed before immutable stage")
            old=db.execute("SELECT * FROM "+TABLE+" WHERE authority_namespace=? AND installation_id=? AND operation_commitment=?",
                (fences.namespace,self.policy_service.installation_id,op)).fetchone()
            if old is not None:
                original=habit_ledger_decode_v1(TABLE,OCCURRENCE_COLUMNS,old,key=self._key,
                    authority_namespace=fences.namespace,authority_id=core._id(db),installation_id=self.policy_service.installation_id)
                if type(original)is HabitRetirementV1:raise AuthorityUnavailable("Habit old operation was retired by accepted deletion")
                if type(original)is not value_type or original.selector!=request:raise AuthorityUnavailable("Habit exact operation replay changed selector")
                return original
            wire=wire_function(value)
            if len(canonical_serialize(wire).encode("utf8"))>MAX_PAYLOAD_BYTES:raise AuthorityUnavailable("Habit immutable occurrence/cue payload exceeds original fixed row resource admission")
            db.execute("INSERT INTO "+TABLE+" VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(fences.namespace,self.policy_service.installation_id,
                identity,policy.definition.revision,policy.definition.cancellation_generation,op,kind,
                habit_identity_commitment_v1(self._key,"original",value.original_ref),canonical_serialize(wire),value.digest,value.signature,
                value.target_commitment,value.project_commitment,getattr(value,"effect_commitment",None)))
            return value
    def _evidence_v1(self,request,policy,inputs,*,qualification=None,cue=None,now,job_digest=None):
        key=owner_grant_key(*request.namespace.as_tuple);entry=inputs.owner_entry
        guard=ProductionOwnerGuardV1(key.token,inputs.work.heads[key.token][0],canonical_digest(entry.grant),entry.head.guard.authorization_head.removeprefix("sha256:"))
        return HabitOccurrenceCurrentV1(request,policy,qualification,cue,inputs.current_self,guard,inputs.read_versions,
            QueryEpoch(request.namespace,"all",inputs.work.graph_stamp[0]),inputs.work.graph_stamp[1],inputs.work.graph_stamp[2],
            job_digest,now,min(request.original_deadline_utc,policy.definition.original_valid_until_utc))
    def observe_window_cue(self,*,credential,subject,permit,request):
        if type(request)is not HabitWindowCueSelectorV1:raise TypeError("actual window cue selector required")
        if request.operation_id!="habit-window-cue-write:"+request.cue_stable_key[:48]:
            raise AuthorityUnavailable("Habit timer WRITE must use its actual stable immutable clock operation")
        policy,inputs=self._prepare_v1(credential=credential,subject=subject,permit=permit,request=request)
        try:
            d=policy.definition
            from ..runtime.habit_schedule_driver_v1 import habit_window_cue_request_v1
            _require_habit_typed_request_digest_v1(request,"record_habit_window_cue_v1",habit_window_cue_request_v1(request))
            if d.cue_predicate.observation_provider!="d11.habit-window-cue.v1":raise AuthorityUnavailable("timer cannot authorize semantic Habit predicate")
            from ..domains.d10.habit_occurrence_v1 import habit_window_v1
            if habit_window_v1(d,request.due_at_utc)!=(request.window_id,request.window_start_utc,request.window_end_utc):
                raise AuthorityUnavailable("Habit timer selected a different original anchored window")
            job=inputs.bodies[AtomKey.from_token(request.subscription_job_ref)]
            if job.revision!=request.subscription_job_revision:raise AuthorityUnavailable("Habit actual subscription job revision changed")
            from .habit_authority_source_read_v3 import read_habit_subscription_job_v3
            from ..runtime.d11_types import job_graph_write
            actual=read_habit_subscription_job_v3(inputs,request.subscription_job_ref)
            if job_graph_write(actual).value!=job.value:raise AuthorityUnavailable("Habit durable subscription differs from actual Graph current head")
            from ..runtime.habit_schedule_driver_v1 import HabitSubscriptionV1
            from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
            subscription=decode_typed_production_value_v1(dict(actual.continuation),HabitSubscriptionV1)
            if(subscription.namespace,subscription.policy_ref,subscription.policy_revision,subscription.policy_digest,
                    subscription.standing_original_ref,subscription.standing_original_digest,subscription.window_id,
                    subscription.window_start_utc,subscription.window_end_utc,subscription.due_at_utc,
                    subscription.original_deadline_utc,subscription.cancellation_generation)!=(
                    request.namespace,request.policy_ref,request.policy_revision,request.policy_digest,
                    request.standing_authorization_original_ref,request.standing_authorization_original_digest,request.window_id,
                    request.window_start_utc,request.window_end_utc,request.due_at_utc,request.original_deadline_utc,request.cancellation_generation):
                raise AuthorityUnavailable("Habit policy generation differs from original subscription continuation")
            value=job.value
            if(value["work_kind"]!="habit_subscription_v1"or value["phase"]!="waiting"or value["fence"]!=request.expected_job_fence
                    or value["cancel_epoch"]!=request.expected_job_cancel_epoch or value["lease_holder"]!=request.expected_lease_holder
                    or value["parent_budget_lease_ref"]!=request.parent_root_grant_ref):
                raise AuthorityUnavailable("Habit actual durable subscription job/fence/cancel/Root changed")
            reading=self.clock();lower=reading.utc_seconds-reading.utc_error_seconds;upper=reading.utc_seconds+reading.utc_error_seconds
            deadline=min(request.window_end_utc,request.due_at_utc+d.execution_seconds,d.original_valid_until_utc)
            if lower<request.due_at_utc or upper>=request.original_deadline_utc:raise AuthorityUnavailable("Habit clock interval is early or original Root expired")
            if lower<deadline<=upper:raise AuthorityUnavailable("Habit clock interval straddles original execution boundary")
            state="due"if upper<deadline else d.miss_policy
            material=dict(authority_namespace=self.policy_service.fences.namespace,authority_id=permit.authority_id,
                installation_id=self.policy_service.installation_id,selector=request,target_commitment=policy.target_commitment,
                project_commitment=policy.project_commitment,owner_head_digest=inputs.owner_entry.head.guard.authorization_head,
                owner_authorization_revision=inputs.owner_entry.head.guard.authorization_revision,
                owner_principal_epoch=policy.owner_principal_epoch,self_entity_ref=inputs.current_self.self_entity_ref,
                read_versions=inputs.read_versions,clock_lower_utc=lower,clock_upper_utc=upper,execution_state=state,schema="d11.habit-window-cue-original.v1")
            # The original signature is computed over the exact canonical wire, not a DTO-asdict surrogate.
            from .d10_habit_contract_v1 import habit_window_cue_selector_to_wire_v1
            wire={**material,"selector":habit_window_cue_selector_to_wire_v1(request),"read_versions":asdict_versions_v1(inputs.read_versions)}
            cue=self._store_v1(credential=credential,subject=subject,permit=permit,request=request,policy=policy,inputs=inputs,
                kind="window_cue",material=material,wire_material=wire,value_type=HabitWindowCueOriginalV1,wire_function=habit_window_cue_original_to_wire_v1)
            return self._evidence_v1(request,policy,inputs,cue=cue,now=upper,job_digest=canonical_digest(value)),permit
        finally:inputs.release_v3()

    def qualify_birth(self,*,credential,subject,permit,request):
        if type(request)is not HabitOccurrenceBirthSelectorV1:raise TypeError("actual Habit registration selector required")
        policy,inputs=self._prepare_v1(credential=credential,subject=subject,permit=permit,request=request)
        try:
            d=policy.definition;identity=habit_occurrence_id_v1(d.namespace,d.policy_id,d.revision,request.window_id,request.cue_stable_key)
            from ..runtime.d10_habit_v1 import RegisterHabitOccurrenceRequestV1
            _require_habit_typed_request_digest_v1(request,"register_habit_occurrence_v1",RegisterHabitOccurrenceRequestV1(
                request.policy_ref,inputs.bodies[AtomKey.from_token(request.policy_ref)].revision,request.cue_original_ref,request.cue_original_digest))
            key=habit_occurrence_key_v1(d.namespace,identity)
            if key.token in inputs.work.heads:raise AuthorityUnavailable("Habit occurrence already durably exists; use existing qualification")
            from ..runtime.d10_habit_v1 import habit_registration_operation_id_v1
            if request.operation_id!=habit_registration_operation_id_v1(d.namespace,identity):
                raise AuthorityUnavailable("Habit birth changed its fixed registration operation")
            reading=self.clock();now=reading.utc_seconds+reading.utc_error_seconds
            self._require_cue_v1(inputs,policy,request,now)
            if d.cue_predicate.observation_provider=="d11.habit-window-cue.v1":
                from .habit_authority_source_read_v3 import require_habit_committed_original_v3
                digest=require_habit_committed_original_v3(inputs,operation_id="habit-window-cue-write:"+request.cue_stable_key[:48],
                    expected_kind="record_habit_window_cue_v1",expected_core_cue=self._stored_cue_v1(request.cue_original_ref,request.cue_original_digest))
                if("d11-current:"+digest[:48],digest)!=(request.wake_original_ref,request.wake_original_digest):
                    raise AuthorityUnavailable("Habit registration changed actual committed Graph wake original")
            elif request.wake_original_ref is not None:raise AuthorityUnavailable("semantic Habit cue cannot borrow a timer Graph wake")
            inputs.require_for_v3(service=self,permit=permit)
            cue=self._stored_cue_v1(request.cue_original_ref,request.cue_original_digest)if d.cue_predicate.observation_provider=="d11.habit-window-cue.v1"else None
            return self._evidence_v1(request,policy,inputs,cue=cue,now=now),permit
        finally:inputs.release_v3()

    def current(self,*,credential,subject,permit,request):
        if type(request)is not HabitOccurrenceSelectorV1:raise TypeError("actual committed occurrence selector required")
        policy,inputs=self._prepare_v1(credential=credential,subject=subject,permit=permit,request=request)
        try:
            d=policy.definition
            identity=habit_occurrence_id_v1(d.namespace,d.policy_id,d.revision,request.window_id,request.cue_stable_key)
            key=habit_occurrence_key_v1(d.namespace,identity);atom=inputs.bodies[key]
            occurrence=habit_value_from_wire_v1("d10.habit_occurrence.v1",atom.value)
            from ..runtime.d10_habit_v1 import QualifyHabitOccurrenceRequestV1
            _require_habit_typed_request_digest_v1(request,"qualify_habit_occurrence_v1",QualifyHabitOccurrenceRequestV1(atom.key.token,atom.revision))
            from ..runtime.d10_habit_v1 import habit_registration_operation_id_v1
            from .habit_authority_source_read_v3 import require_habit_committed_original_v3
            original=require_habit_committed_original_v3(inputs,operation_id=habit_registration_operation_id_v1(d.namespace,identity),
                expected_kind="register_habit_occurrence_v1",member=atom)
            if("d10-current:"+original[:48],original)!=(request.occurrence_original_ref,request.occurrence_original_digest):
                raise AuthorityUnavailable("Habit occurrence selector is not its actual committed registration original")
            if(occurrence.policy_ref,occurrence.policy_revision,occurrence.policy_digest,occurrence.window_id,occurrence.cue_stable_key,
                    occurrence.occurrence_operation_id,occurrence.activity_id,occurrence.effect_id,occurrence.attempt_id,
                    occurrence.recipe_ref,occurrence.recipe_revision,occurrence.executor_kind,occurrence.parent_root_grant_ref,
                    occurrence.parent_root_grant_digest,occurrence.original_deadline_utc,occurrence.cancellation_generation)!=(
                    request.policy_ref,request.policy_revision,request.policy_digest,request.window_id,request.cue_stable_key,
                    request.execution_operation_id,request.activity_id,request.effect_id,request.attempt_id,
                    request.recipe_ref,request.recipe_revision,request.executor_kind,request.parent_root_grant_ref,
                    request.parent_root_grant_digest,request.original_deadline_utc,request.cancellation_generation)or request.operation_id==request.execution_operation_id:
                raise AuthorityUnavailable("Habit occurrence changed its original policy/window/recipe/Root/cancellation identity")
            if occurrence.state not in{"registered","waiting","qualified"}:
                raise AuthorityUnavailable("Habit active/unknown/terminal occurrence cannot be admitted again")
            from .habit_authority_source_read_v3 import require_habit_no_other_obligation_v1
            require_habit_no_other_obligation_v1(inputs,occurrence_key=key,context=False)
            census=tuple((key,revision,digest,value)for key,(revision,digest,value)in inputs.census.items()
                if value["policy_ref"]==request.policy_ref)
            counted=tuple(sorted(key.token for key,_,_,value in census if value["window_id"]==request.window_id))
            if len(counted)>d.maximum_occurrences_per_window:raise AuthorityUnavailable("Habit original cross-revision window bound reached")
            if key.token not in counted:raise AuthorityUnavailable("Habit selected occurrence absent from complete current window census")
            times=[value["actual_started_at_utc"]if value["actual_started_at_utc"]is not None else value["admitted_at_utc"]
                for other,_,_,value in census if other!=key and(value["actual_started_at_utc"]is not None or value["admitted_at_utc"]is not None)]
            reading=self.clock();now=reading.utc_seconds+reading.utc_error_seconds
            if(now>=occurrence.original_deadline_utc or now>=request.original_deadline_utc
                    or times and now-max(times)<d.minimum_interval_seconds):
                raise AuthorityUnavailable("Habit original execution deadline/minimum interval does not admit occurrence")
            self._require_cue_v1(inputs,policy,request,now)
            digest=canonical_digest(tuple(sorted((other.token,revision,digest)for other,revision,digest,_ in census)))
            head=inputs.owner_entry.head
            material=dict(authority_namespace=self.policy_service.fences.namespace,authority_id=permit.authority_id,
                installation_id=self.policy_service.installation_id,namespace=d.namespace,selector=request,
                standing_original_ref=policy.original_ref,standing_original_digest=policy.digest,
                target_commitment=policy.target_commitment,project_commitment=policy.project_commitment,
                effect_commitment=habit_scope_identity_commitment_v1(self._key,"effect",d.namespace,self.policy_service.installation_id,request.effect_id),
                owner_principal=head.issue_operation.principal,owner_head_digest=head.guard.authorization_head,
                owner_authorization_revision=head.guard.authorization_revision,owner_principal_epoch=policy.owner_principal_epoch,
                self_entity_ref=inputs.current_self.self_entity_ref,self_identity_original_ref=inputs.current_self.registration_operation_id,
                occurrence_head=GraphVersion(key,atom.revision),occurrence_digest=canonical_digest(atom.value),
                read_versions=inputs.read_versions,window_census_digest=digest,counted_occurrence_refs=counted,
                current_job_digest=None,cancellation_generation=d.cancellation_generation,
                original_deadline_utc=occurrence.original_deadline_utc,issued_at_utc=now,schema="d10.habit-occurrence-qualification-original.v1")
            from ..domains.d10.habit_occurrence_v1 import habit_value_to_wire_v1
            wire={**material,"namespace":asdict(d.namespace),"selector":habit_value_to_wire_v1(request),
                "owner_principal":asdict(head.issue_operation.principal),"occurrence_head":asdict(material["occurrence_head"]),
                "read_versions":asdict_versions_v1(inputs.read_versions)}
            qualification=self._store_v1(credential=credential,subject=subject,permit=permit,request=request,policy=policy,inputs=inputs,
                kind="occurrence_qualification",material=material,wire_material=wire,value_type=HabitOccurrenceQualificationOriginalV1,
                wire_function=habit_occurrence_qualification_to_wire_v1)
            return self._evidence_v1(request,policy,inputs,qualification=qualification,now=now),permit
        finally:inputs.release_v3()

    def current_artifact_restriction(self,*,foreground_service,credential,subject,permit,request):
        from .current_habit_artifact_restriction_v1 import current_habit_artifact_restriction_v1
        return current_habit_artifact_restriction_v1(self,foreground_service=foreground_service,credential=credential,subject=subject,permit=permit,request=request)

    def current_artifact_model_read_restriction_v3(self,*,foreground_service,credential,subject,permit,request):
        from .current_habit_artifact_restriction_v1 import current_habit_artifact_model_read_restriction_v3
        return current_habit_artifact_model_read_restriction_v3(self,foreground_service=foreground_service,
            credential=credential,subject=subject,permit=permit,request=request)

    def current_execution(self,*,credential,subject,permit,request):
        from .current_habit_execution_v1 import current_habit_execution_v1
        return current_habit_execution_v1(self,credential=credential,subject=subject,permit=permit,request=request)

    def current_existing(self,*,credential,subject,permit,request):
        if type(request)is not HabitOccurrenceSelectorV1:raise TypeError("exact existing Habit occurrence selector required")
        policy,inputs=self._prepare_v1(credential=credential,subject=subject,permit=permit,request=request,require_write=False)
        try:
            p=self.policy_service;operation=habit_identity_commitment_v1(self._key,"operation",request.operation_id)
            with p.core._tx()as db:
                row=db.execute("SELECT * FROM "+TABLE+" WHERE authority_namespace=? AND installation_id=? AND operation_commitment=?",
                    (p.fences.namespace,p.installation_id,operation)).fetchone()
                if row is None:raise AuthorityUnavailable("Habit current qualification original absent")
                original=habit_ledger_decode_v1(TABLE,OCCURRENCE_COLUMNS,row,key=self._key,authority_namespace=p.fences.namespace,
                    authority_id=p.core._id(db),installation_id=p.installation_id)
            if type(original)is not HabitOccurrenceQualificationOriginalV1 or original.selector!=request:
                raise AuthorityUnavailable("Habit current qualification retired or selected another original")
            reading=self.clock();now=reading.utc_seconds+reading.utc_error_seconds
            if now>=original.original_deadline_utc:raise AuthorityUnavailable("Habit original occurrence qualification expired")
            self._require_cue_v1(inputs,policy,request,now)
            inputs.require_for_v3(service=self,permit=permit)
            return self._evidence_v1(request,policy,inputs,qualification=original,now=now),permit
        finally:inputs.release_v3()

    def _require_cue_v1(self,inputs,policy,request,now):
        d=policy.definition
        if d.cue_predicate.observation_provider=="d11.habit-window-cue.v1":
            cue=self._stored_cue_v1(request.cue_original_ref,request.cue_original_digest)
            if(cue.selector.policy_ref!=request.policy_ref or cue.selector.policy_revision!=request.policy_revision
                    or cue.selector.cue_stable_key!=request.cue_stable_key or cue.execution_state!="due"):
                raise AuthorityUnavailable("Habit occurrence changed actual persisted clock cue")
            from .habit_authority_source_read_v3 import require_habit_committed_original_v3
            require_habit_committed_original_v3(inputs,operation_id="habit-window-cue-write:"+request.cue_stable_key[:48],
                expected_kind="record_habit_window_cue_v1",expected_core_cue=cue)
            return
        key=AtomKey.from_token(request.cue_original_ref);atom=inputs.bodies[key];value=atom.value
        question="d10.habit-cue:"+canonical_digest((d.namespace,d.policy_id,d.revision,d.cue_predicate))
        if(value["question_key"]!=question or value["stance"]!="support"or value["evidence_status"]!="supported"
                or value["meaningful_unknowns"]or value["current"]is not True or value["proposition"]!="cue_present"
                or canonical_digest(value)!=request.cue_original_digest):
            raise AuthorityUnavailable("Habit semantic cue is not current supported exact scoped D07 interpretation")
        from .habit_authority_source_read_v3 import require_habit_current_adoption_v3
        require_habit_current_adoption_v3(inputs,atom)
        records=inputs.materials[0].metadata_records
        from ..memory_types import source_key
        family=set();pending=list(value["source_refs"])
        while pending:
            ref=pending.pop()
            if ref in family:continue
            family.add(ref)
            pending.extend(source_key(*d.namespace.as_tuple,parent).token for parent in records[ref].parent_source_ids)
        selected=tuple(sorted(family))
        stable=canonical_digest(tuple((ref,records[ref].source_id,records[ref].recorded_at)for ref in selected))
        recorded=max(records[ref].recorded_at for ref in selected)
        if stable!=request.cue_stable_key or recorded>now or recorded<d.cue_predicate.valid_from or d.cue_predicate.valid_until is not None and recorded>d.cue_predicate.valid_until:
            raise AuthorityUnavailable("Habit semantic cue actual Source recorded time/key differs")

    def current_window_cue(self,*,credential,subject,permit,request):
        if type(request)is not HabitWindowCueSelectorV1:raise TypeError("actual persisted window cue selector required")
        policy,inputs=self._prepare_v1(credential=credential,subject=subject,permit=permit,request=request,require_write=False)
        try:
            # Immutable observation bytes remain the original clock; this READ obtains new current facts only.
            identity=habit_identity_commitment_v1(self._key,"original",request.cue_original_ref)
            p=self.policy_service
            with p.core._tx()as db:
                row=db.execute("SELECT * FROM "+TABLE+" WHERE authority_namespace=? AND installation_id=? AND original_commitment=?",
                    (p.fences.namespace,p.installation_id,identity)).fetchone()
                if row is None:raise AuthorityUnavailable("Habit persisted current cue absent")
                cue=habit_ledger_decode_v1(TABLE,OCCURRENCE_COLUMNS,row,key=self._key,authority_namespace=p.fences.namespace,
                    authority_id=p.core._id(db),installation_id=p.installation_id)
            if type(cue)is not HabitWindowCueOriginalV1 or cue.selector!=request:
                raise AuthorityUnavailable("Habit persisted cue was retired or selected another original")
            reading=self.clock();now=reading.utc_seconds+reading.utc_error_seconds
            inputs.require_for_v3(service=self,permit=permit)
            return self._evidence_v1(request,policy,inputs,cue=cue,now=now),permit
        finally:inputs.release_v3()

    def _stored_cue_v1(self,original_ref,original_digest):
        identity=habit_identity_commitment_v1(self._key,"original",original_ref)
        p=self.policy_service
        with p.core._tx()as db:
            row=db.execute("SELECT * FROM "+TABLE+" WHERE authority_namespace=? AND installation_id=? AND original_commitment=?",
                (p.fences.namespace,p.installation_id,identity)).fetchone()
            if row is None:raise AuthorityUnavailable("Habit actual persisted clock original absent")
            value=habit_ledger_decode_v1(TABLE,OCCURRENCE_COLUMNS,row,key=self._key,authority_namespace=p.fences.namespace,
                authority_id=p.core._id(db),installation_id=p.installation_id)
        if type(value)is not HabitWindowCueOriginalV1 or(value.original_ref,value.digest)!=(original_ref,original_digest):
            raise AuthorityUnavailable("Habit clock original retired or immutable commitment differs")
        return value

def asdict_versions_v1(versions):return [asdict(value)for value in versions]

def habit_current_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value)is not HabitOccurrenceCurrentV1:raise TypeError("actual current Habit evidence required")
    return {"schema":"d10.current-habit-wire.v1","value":plain_v1(value)}

def habit_current_from_wire_v1(raw):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(raw)is not dict or set(raw)!={"schema","value"}or raw["schema"]!="d10.current-habit-wire.v1":
        raise ValueError("Habit current wire differs")
    value=decode_typed_production_value_v1(raw["value"],HabitOccurrenceCurrentV1)
    if habit_current_to_wire_v1(value)!=raw:raise ValueError("Habit current wire canonical fields differ")
    return value


def _require_habit_typed_request_digest_v1(selector,kind,command):
    from ..runtime.domain_production_registry_v1 import installed_operation_v1
    from ..runtime.habit_activity_issuance_v1 import habit_typed_command_digest_v1
    if selector.request_digest!=habit_typed_command_digest_v1(installed_operation_v1(kind),command):
        raise AuthorityUnavailable('Habit Core stage differs from its actual fixed typed bookkeeping command')
