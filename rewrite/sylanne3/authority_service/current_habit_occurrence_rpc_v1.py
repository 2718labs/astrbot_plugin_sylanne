"""Closed current Habit stages; every RPC borrows its actual paired permit."""
from .contract import AuthorityUnavailable,identifier
from .current_habit_occurrence_v1 import InstalledCurrentHabitOccurrenceV1,habit_current_to_wire_v1
from .d10_habit_contract_v1 import habit_window_cue_selector_from_wire_v1,habit_occurrence_birth_from_wire_v1
from .v2_contract import FencePermitV2,from_wire,to_wire
from .d10_habit_execution_contract_v1 import habit_occurrence_execution_from_wire_v1
from .current_habit_artifact_restriction_v1 import habit_artifact_additional_from_wire_v1,habit_artifact_model_read_from_wire_v3
from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1

METHODS=frozenset({"habit_body_cpu_prepare_v3","habit_occurrence_qualify_v1","habit_occurrence_current_v1","habit_window_cue_observe_v1","habit_window_cue_current_v1","habit_occurrence_register_v1","habit_occurrence_execution_v1","habit_artifact_additional_current_v1","habit_artifact_model_read_current_v3","habit_original_maintenance_current_v1"})
def dispatch_current_habit_occurrence_v1(server,method,credential,profile_id,manifest_digest,command):
    if method not in METHODS:return None
    if type(command)is not dict or set(command)!={"namespace","permit","request"}:raise AuthorityUnavailable("current Habit RPC fields differ")
    namespace=identifier(command["namespace"],"namespace")
    fences=server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installation=server._installations_v2[(credential.certificate_sha256,profile_id)]
    service=server._current_habit_occurrence_v1.get((namespace,installation.installation_id))
    permit=from_wire(command["permit"])
    if(type(service)is not InstalledCurrentHabitOccurrenceV1 or service.self_identity._fences is not fences
            or type(permit)is not FencePermitV2 or permit.holder!=installation.administrator_holder):
        raise AuthorityUnavailable("Habit current service differs from actual installed paired fence")
    if method=='habit_body_cpu_prepare_v3':
        from .habit_body_preparation_v3 import preparation_selector_from_wire_v3,observe_current_body_cpu_v3,preparation_to_wire_v3
        request=preparation_selector_from_wire_v3(command['request'])
        evidence,observed=observe_current_body_cpu_v3(service,credential=credential,
            subject='mtls:sha256:'+credential.certificate_sha256,permit=permit,request=request)
        if observed!=permit:raise AuthorityUnavailable('Habit CPU preparation changed its actual READ permit')
        return {'evidence':preparation_to_wire_v3(evidence),'permit':to_wire(observed)}
    if method=='habit_original_maintenance_current_v1':
        from .current_habit_maintenance_v1 import habit_maintenance_selector_from_wire_v1,current_habit_maintenance_v1,habit_maintenance_current_to_wire_v1
        request=habit_maintenance_selector_from_wire_v1(command['request'])
        evidence,observed=current_habit_maintenance_v1(service,credential=credential,
            subject='mtls:sha256:'+credential.certificate_sha256,permit=permit,request=request)
        if observed!=permit:raise AuthorityUnavailable('Habit maintenance observation changed fresh control permit')
        return {'evidence':habit_maintenance_current_to_wire_v1(evidence),'permit':to_wire(observed)}
    if method=='habit_artifact_model_read_current_v3':
        request=habit_artifact_model_read_from_wire_v3(command['request'])
        evidence,observed=service.current_artifact_model_read_restriction_v3(
            foreground_service=server._v2_foreground_activity.get(namespace),credential=credential,
            subject='mtls:sha256:'+credential.certificate_sha256,permit=permit,request=request)
        if observed!=permit:raise AuthorityUnavailable('Artifact model restriction changed actual original Foreground permit')
        return {'evidence':habit_current_to_wire_v1(evidence),'permit':to_wire(observed)}
    cue=method in{"habit_window_cue_observe_v1","habit_window_cue_current_v1"}
    request=habit_artifact_additional_from_wire_v1(command["request"])if method=="habit_artifact_additional_current_v1"else habit_occurrence_execution_from_wire_v1(command["request"])if method=="habit_occurrence_execution_v1"else habit_occurrence_birth_from_wire_v1(command["request"])if method=="habit_occurrence_register_v1"else habit_window_cue_selector_from_wire_v1(command["request"])if cue else habit_value_from_wire_v1("d10.habit-occurrence-selector.v1",command["request"])
    if method=="habit_artifact_additional_current_v1":
        evidence,observed=service.current_artifact_restriction(foreground_service=server._v2_foreground_activity.get(namespace),
            credential=credential,subject="mtls:sha256:"+credential.certificate_sha256,permit=permit,request=request)
        if observed!=permit:raise AuthorityUnavailable("Habit additional Draft observation changed the original Foreground permit")
        return {"evidence":habit_current_to_wire_v1(evidence),"permit":to_wire(observed)}
    entry={"habit_occurrence_execution_v1":service.current_execution,"habit_occurrence_register_v1":service.qualify_birth,"habit_occurrence_qualify_v1":service.current,"habit_occurrence_current_v1":service.current_existing,
        "habit_window_cue_observe_v1":service.observe_window_cue,"habit_window_cue_current_v1":service.current_window_cue}[method]
    evidence,observed=entry(credential=credential,subject="mtls:sha256:"+credential.certificate_sha256,permit=permit,request=request)
    if observed!=permit:raise AuthorityUnavailable("Habit current RPC changed original borrowed permit")
    return {"evidence":habit_current_to_wire_v1(evidence),"permit":to_wire(observed)}
