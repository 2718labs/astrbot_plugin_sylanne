"""Actual installed Habit port; wire originals never substitute a private WRITE fact."""
from weakref import WeakSet
from ..runtime_contracts import FenceScope,canonical_digest
from ..authority_service.d10_habit_contract_v1 import HabitStandingPolicyOriginalV1
from ..domains.d10.habit_policy_v1 import HabitPolicyDefinitionV1
from .v2_fence_port import V2FencePort

_PORTS=WeakSet()
class InstalledCurrentHabitOccurrencePortV1:
    def __init__(self,context):
        from ..runtime_context import RuntimeContext
        from ..graph_coordinator import GraphCoordinator
        from ..host.authority_profile import AdminInstallationBundle
        if(type(context)is not RuntimeContext or type(context._v2_coordinator)is not GraphCoordinator
                or type(context._v2_port)is not V2FencePort or type(context._v2_model_bundle)is not AdminInstallationBundle
                or context._v2_coordinator._GraphCoordinator__content_fence_v2 is not context._v2_port
                or "habit_subscription_v1"not in context._v2_model_bundle.installation_policy.root_grant.allowed_work_kinds):
            raise TypeError("Habit port needs actual installed Context/Graph/paired fence and explicit original Root kind")
        from .habit_runtime_policy_v1 import HabitRuntimePolicyV1
        if type(context._v2_model_bundle.habit_runtime_policy)is not HabitRuntimePolicyV1:
            raise TypeError("Habit port requires explicit administrator-installed runtime policy")
        context._v2_model_bundle.habit_runtime_policy.require_installation_v1(context._v2_model_bundle.installation_policy)
        self.context,self.graph,self.base,self.bundle=context,context._v2_coordinator,context._v2_port,context._v2_model_bundle
        self._issued={}
        self._activities={}
        self._body_preparations={}
        _PORTS.add(self)
        context._habit_occurrence_port_v1=self
        self.graph._GraphCoordinator__habit_occurrence_port_v1=self
    def require_installed_v1(self):
        if(self not in _PORTS or self.context._habit_occurrence_port_v1 is not self
                or self.graph._GraphCoordinator__habit_occurrence_port_v1 is not self
                or self.context._v2_coordinator is not self.graph or self.context._v2_port is not self.base
                or self.context._v2_model_bundle is not self.bundle):
            raise ValueError("Habit port changed actual installation")
        return self
    def _scope_v1(self,scope,*,write):
        self.require_installed_v1()
        if(type(scope)is not FenceScope or scope.namespace!=self.bundle.installation_policy.namespace
                or scope.operation!=("write"if write else"read")or self.base.validate_fence(scope)!=scope.permit
                or self.graph._GraphCoordinator__store._db.in_transaction):
            raise ValueError("Habit actual same-permit observation must precede Graph SQL")
    def change_current_habit_policy_v1(self,*,scope,owner_actor_id,owner_session_token,owner_session_request,
            operation_id,action,definition):
        self._scope_v1(scope,write=True)
        if(type(definition)is not HabitPolicyDefinitionV1 or definition.namespace!=scope.namespace
                or action not in{"issue","revise","revoke"}or type(operation_id)is not str or not operation_id.startswith("habit-policy:")or not operation_id.removeprefix("habit-policy:")):
            raise ValueError("Habit policy requires exact typed Definition/action and its original WRITE operation")
        method={"issue":"d10_habit_policy_issue_v1","revise":"d10_habit_policy_revise_v1","revoke":"d10_habit_policy_revoke_v1"}[action]
        value,inventory=self.base._submit(self.base._with_session_repair(lambda:self._policy_rpc_v1(scope=scope,method=method,
            owner_actor_id=owner_actor_id,owner_session_token=owner_session_token,owner_session_request=owner_session_request,
            operation_id=operation_id,definition=definition)))
        if(type(value)is not HabitStandingPolicyOriginalV1 or value.definition!=definition or value.operation_id!=operation_id
                or value.action!=action or value.owner_actor_id!=owner_actor_id):raise ValueError("Habit actual Owner-issued original differs")
        record=(scope,definition,operation_id,action,value,canonical_digest(value),inventory)
        prior=self._issued.get(id(scope))
        if prior is not None and prior!=record:raise ValueError("Habit original changed within one actual WRITE Scope")
        self._issued[id(scope)]=record
        return value
    async def _policy_rpc_v1(self,*,scope,method,**values):
        from .d10_habit_policy_transport_v1 import transport_d10_habit_policy_v1
        await self.base._mapped(scope.namespace,scope.authority_namespace)
        handshake,grant=self.base._identity()
        return await transport_d10_habit_policy_v1(self.base._transport,self.base._request,handshake,grant,
            namespace=scope.authority_namespace,namespace_id=scope.namespace,permit=scope.permit,method=method,**values)
    def read_current_habit_policy_for_fence_v1(self,*,scope,policy_id):
        self._scope_v1(scope,write=scope.operation=="write")
        value=self.base._submit(self.base._with_session_repair(lambda:self._policy_rpc_v1(scope=scope,
            method="d10_habit_policy_read_current_v1",policy_id=policy_id)))
        if value is not None and value.definition.policy_id!=policy_id:raise ValueError("Habit current policy selector differs")
        return value
    def require_issued_policy_v3(self,*,scope,definition,operation_id,action,original):
        self.require_installed_v1()
        saved=self._issued.get(id(scope))
        if(saved is None or saved[0]is not scope or saved[1:6]!=(definition,operation_id,action,original,canonical_digest(original))
                or type(original)is not HabitStandingPolicyOriginalV1):
            raise ValueError("Habit policy original lacks this port's actual sameScope issuance")
        return original

    def require_issued_policy_window_cue_inventory_v1(self,*,scope,definition,operation_id,action,original):
        self.require_issued_policy_v3(scope=scope,definition=definition,operation_id=operation_id,action=action,original=original)
        inventory=self._issued[id(scope)][6]
        if(inventory.permit_token,inventory.definition_digest,inventory.operation_id,inventory.standing_original_ref,inventory.standing_original_digest)!=(
                scope.permit.token,canonical_digest(definition),operation_id,original.original_ref,original.digest):
            raise ValueError('Habit original current-window inventory lost actual sameScope issuance')
        return inventory

    async def _activity_rpc_v1(self,*,scope,method,request):
        from ..authority_service.current_habit_occurrence_v1 import habit_current_from_wire_v1
        from ..authority_service.d10_habit_contract_v1 import (HabitWindowCueSelectorV1,HabitOccurrenceBirthSelectorV1,
            habit_window_cue_selector_to_wire_v1,habit_occurrence_birth_to_wire_v1)
        from ..domains.d10.habit_occurrence_v1 import habit_value_to_wire_v1
        from ..authority_service.v2_contract import SCHEMA,to_wire,from_wire
        await self.base._mapped(scope.namespace,scope.authority_namespace)
        handshake,grant=self.base._identity()
        from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1,habit_occurrence_execution_to_wire_v1
        from ..authority_service.current_habit_artifact_restriction_v1 import HabitArtifactAdditionalSelectorV1,habit_artifact_additional_to_wire_v1
        from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1,habit_maintenance_selector_to_wire_v1,habit_maintenance_current_from_wire_v1
        from ..authority_service.current_habit_artifact_restriction_v1 import HabitArtifactModelReadSelectorV3,habit_artifact_model_read_to_wire_v3
        encoded=habit_artifact_model_read_to_wire_v3(request)if type(request)is HabitArtifactModelReadSelectorV3 else habit_maintenance_selector_to_wire_v1(request)if type(request)is HabitOriginalMaintenanceSelectorV1 else habit_artifact_additional_to_wire_v1(request)if type(request)is HabitArtifactAdditionalSelectorV1 else habit_occurrence_execution_to_wire_v1(request)if type(request)is HabitOccurrenceExecutionSelectorV1 else habit_window_cue_selector_to_wire_v1(request)if type(request)is HabitWindowCueSelectorV1 else habit_occurrence_birth_to_wire_v1(request)if type(request)is HabitOccurrenceBirthSelectorV1 else habit_value_to_wire_v1(request)
        response=await self.base._transport._content_rpc(self.base._request,handshake,method,
            {"namespace":scope.authority_namespace,"permit":to_wire(scope.permit),"request":encoded},protocol=SCHEMA)
        if(type(response)is not dict or response.pop("channel_binding_sha256",None)!=handshake.channel_binding_sha256
                or set(response)!={"evidence","permit"}):raise ValueError("Habit activity paired response channel/fields differ")
        evidence=(habit_maintenance_current_from_wire_v1(response['evidence'])if type(request)is HabitOriginalMaintenanceSelectorV1 else habit_current_from_wire_v1(response['evidence']));permit=from_wire(response['permit'])
        evidence.require_for_v3(request=request,permit=scope.permit,installation_id=grant.installation_id,
            authority_namespace=scope.authority_namespace)
        if permit!=scope.permit:raise ValueError("Habit current stage changed original permit")
        return evidence,permit
    def _stage_v1(self,*,scope,method,request):
        self._scope_v1(scope,write=True)
        from ..authority_service.current_habit_occurrence_v1 import current_habit_fence_operation_id_v1
        if scope.operation_id!=current_habit_fence_operation_id_v1(request):raise ValueError("Habit stage requires exact named newly issued WRITE scope")
        result=self.base._submit(self.base._with_session_repair(lambda:self._activity_rpc_v1(scope=scope,method=method,request=request)))
        evidence,permit=result
        prior=self._activities.get(id(scope))
        if prior is None:self._activities[id(scope)]=(scope,request,evidence,canonical_digest(evidence))
        else:
            from dataclasses import replace
            if(prior[0]is not scope or prior[1]!=request
                    or replace(evidence,observed_at_utc=prior[2].observed_at_utc)!=prior[2]):
                raise ValueError("Habit actual repeated stage changed this retained scope's original facts")
        return result
    def observe_habit_window_cue_for_fence_v1(self,*,scope,request):
        from ..authority_service.d10_habit_contract_v1 import HabitWindowCueSelectorV1
        if type(request)is not HabitWindowCueSelectorV1:raise TypeError("actual window cue selector required")
        return self._stage_v1(scope=scope,method="habit_window_cue_observe_v1",request=request)
    def admit_habit_occurrence_registration_for_fence_v1(self,*,scope,request):
        from ..authority_service.d10_habit_contract_v1 import HabitOccurrenceBirthSelectorV1
        if type(request)is not HabitOccurrenceBirthSelectorV1:raise TypeError("actual registration selector required")
        return self._stage_v1(scope=scope,method="habit_occurrence_register_v1",request=request)
    def qualify_habit_occurrence_for_fence_v1(self,*,scope,request):
        from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1
        if type(request)is not HabitOccurrenceSelectorV1:raise TypeError("actual existing occurrence selector required")
        return self._stage_v1(scope=scope,method="habit_occurrence_qualify_v1",request=request)
    def observe_current_habit_execution_for_fence_v1(self,*,scope,request):
        from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
        if type(request)is not HabitOccurrenceExecutionSelectorV1:raise TypeError("actual closed Habit execution phase selector required")
        return self._stage_v1(scope=scope,method="habit_occurrence_execution_v1",request=request)

    def observe_current_habit_artifact_restriction_for_fence_v1(self,*,scope,request):
        from ..authority_service.current_habit_artifact_restriction_v1 import HabitArtifactAdditionalSelectorV1
        if type(request)is not HabitArtifactAdditionalSelectorV1:raise TypeError('actual closed additional Draft selector required')
        return self._stage_v1(scope=scope,method='habit_artifact_additional_current_v1',request=request)

    def require_issued_artifact_restriction_v1(self,*,scope,request,evidence):
        from ..authority_service.current_habit_artifact_restriction_v1 import HabitArtifactAdditionalSelectorV1
        if type(request)is not HabitArtifactAdditionalSelectorV1:raise TypeError('actual additional Draft observation required')
        return self.require_issued_activity_v3(scope=scope,request=request,evidence=evidence)

    def observe_current_habit_artifact_model_read_for_fence_v3(self,*,scope,request):
        from ..authority_service.current_habit_artifact_restriction_v1 import HabitArtifactModelReadSelectorV3
        if type(request)is not HabitArtifactModelReadSelectorV3:raise TypeError('exact Artifact model READ restriction selector required')
        return self._stage_v1(scope=scope,method='habit_artifact_model_read_current_v3',request=request)

    def require_issued_artifact_model_read_v3(self,*,scope,request,evidence):
        from ..authority_service.current_habit_artifact_restriction_v1 import HabitArtifactModelReadSelectorV3
        if type(request)is not HabitArtifactModelReadSelectorV3:raise TypeError('exact Artifact model READ restriction selector required')
        return self.require_issued_activity_v3(scope=scope,request=request,evidence=evidence)

    def observe_current_habit_maintenance_for_fence_v1(self,*,scope,request):
        from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
        if type(request)is not HabitOriginalMaintenanceSelectorV1:raise TypeError('actual closed Habit maintenance selector required')
        return self._stage_v1(scope=scope,method='habit_original_maintenance_current_v1',request=request)

    def require_issued_maintenance_v1(self,*,scope,request,evidence):
        from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1,HabitOriginalMaintenanceCurrentV1
        if type(request)is not HabitOriginalMaintenanceSelectorV1 or type(evidence)is not HabitOriginalMaintenanceCurrentV1:
            raise TypeError('actual independent Habit maintenance observation required')
        return self.require_issued_activity_v3(scope=scope,request=request,evidence=evidence)

    def read_current_habit_window_cue_for_fence_v1(self,*,scope,original_request):
        self._scope_v1(scope,write=scope.operation=="write")
        return self.base._submit(self.base._with_session_repair(lambda:self._activity_rpc_v1(scope=scope,
            method="habit_window_cue_current_v1",request=original_request)))
    def read_current_habit_occurrence_for_fence_v1(self,*,scope,original_request):
        self._scope_v1(scope,write=scope.operation=="write")
        return self.base._submit(self.base._with_session_repair(lambda:self._activity_rpc_v1(scope=scope,
            method="habit_occurrence_current_v1",request=original_request)))
    def require_issued_activity_v3(self,*,scope,request,evidence):
        self.require_installed_v1();saved=self._activities.get(id(scope))
        if saved is None or saved[0]is not scope or saved[1:]!=(request,evidence,canonical_digest(evidence)):
            raise ValueError("Habit activity has no actual installed sameScope private issuance")
        return evidence
    def release_scope_v3(self,scope):
        self._body_preparations.pop(id(scope),None)
        saved=self._issued.get(id(scope))
        if saved is not None and saved[0]is scope:self._issued.pop(id(scope))
        activity=self._activities.get(id(scope))
        if activity is not None and activity[0]is scope:self._activities.pop(id(scope))
    def close(self):
        self._body_preparations.clear()
        self._issued.clear();self._activities.clear();_PORTS.discard(self)
        self.graph._GraphCoordinator__habit_occurrence_port_v1=None
        self.context._habit_occurrence_port_v1=None


    async def _body_cpu_rpc_v3(self,*,scope,request):
        from dataclasses import asdict
        from ..authority_service.habit_body_preparation_v3 import preparation_from_wire_v3
        from ..authority_service.v2_contract import SCHEMA,to_wire,from_wire
        await self.base._mapped(scope.namespace,scope.authority_namespace)
        handshake,grant=self.base._identity()
        response=await self.base._transport._content_rpc(self.base._request,handshake,'habit_body_cpu_prepare_v3',
            {'namespace':scope.authority_namespace,'permit':to_wire(scope.permit),'request':asdict(request)},protocol=SCHEMA)
        if(type(response)is not dict or response.pop('channel_binding_sha256',None)!=handshake.channel_binding_sha256
                or set(response)!={'evidence','permit'}):raise ValueError('Habit CPU preparation response channel/fields differ')
        evidence=preparation_from_wire_v3(response['evidence']);permit=from_wire(response['permit'])
        if(evidence.selector!=request or evidence.read_permit!=scope.permit or permit!=scope.permit
                or request.installation_id!=grant.installation_id or request.namespace!=scope.namespace):
            raise ValueError('Habit CPU preparation changed actual paired READ/installation/selector')
        return evidence,permit

    def prepare_habit_body_cpu_for_fence_v3(self,*,scope,request):
        from ..authority_service.habit_body_preparation_v3 import HabitBodyPreparationSelectorV3
        self._scope_v1(scope,write=False)
        if type(request)is not HabitBodyPreparationSelectorV3:raise TypeError('exact fixed Habit Body preparation selector required')
        result=self.base._submit(self.base._with_session_repair(lambda:self._body_cpu_rpc_v3(scope=scope,request=request)))
        evidence,permit=result
        record=(scope,request,evidence,canonical_digest(evidence))
        prior=self._body_preparations.get(id(scope))
        if prior is not None and prior!=record:raise ValueError('Habit CPU preparation changed one actual READ basis')
        self._body_preparations[id(scope)]=record
        return result

    def require_issued_body_preparation_v3(self,*,scope,request,evidence):
        self.require_installed_v1()
        if self._body_preparations.get(id(scope))!=(scope,request,evidence,canonical_digest(evidence)):
            raise ValueError('Habit Body CPU preparation lacks actual private paired READ issuance')
        return evidence
