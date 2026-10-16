"""Closed installed Habit policy commands on the paired Owner mTLS channel."""
from .contract import AuthorityUnavailable,identifier
from .d10_habit_policy_service_v1 import InstalledD10HabitPolicyServiceV1
from .d10_habit_contract_v1 import habit_standing_policy_original_to_wire_v1
from .v2_contract import FencePermitV2,from_wire
from ..domains.d10.habit_policy_v1 import habit_policy_definition_from_wire_v1

METHODS=frozenset({"d10_habit_policy_issue_v1","d10_habit_policy_revise_v1","d10_habit_policy_pause_v1",
    "d10_habit_policy_resume_v1","d10_habit_policy_revoke_v1","d10_habit_policy_read_current_v1"})
def dispatch_d10_habit_policy_v1(server,method,credential,profile_id,manifest_digest,command):
    if method not in METHODS:return None
    read=method=="d10_habit_policy_read_current_v1"
    expected={"namespace","permit","policy_id"}if read else{"namespace","permit","owner_actor_id",
        "owner_session_token","owner_session_request","operation_id","definition"}
    if type(command)is not dict or set(command)!=expected:raise AuthorityUnavailable("Habit policy RPC fields differ")
    namespace=identifier(command["namespace"],"namespace")
    fences=server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
    permit=from_wire(command["permit"])
    service=server._d10_habit_policy_services_v1.get((namespace,installed.installation_id))
    if(type(service)is not InstalledD10HabitPolicyServiceV1 or service.fences is not fences
            or type(permit)is not FencePermitV2 or permit.holder!=installed.administrator_holder):
        raise AuthorityUnavailable("Habit policy service differs from actual paired installation")
    subject="mtls:sha256:"+credential.certificate_sha256
    if read:
        value=service.read_current(credential=credential,subject=subject,permit=permit,policy_id=identifier(command["policy_id"],"policy_id"))
    else:
        definition=habit_policy_definition_from_wire_v1(command["definition"])
        action={"d10_habit_policy_issue_v1":"issue","d10_habit_policy_revoke_v1":"revoke"}.get(method,"revise")
        if(method=="d10_habit_policy_pause_v1"and definition.state!="paused"
                or method=="d10_habit_policy_resume_v1"and definition.state!="enabled"):
            raise AuthorityUnavailable("Habit pause/resume requires its actual next Definition state")
        kwargs=server._owner_session_kwargs(command,namespace,installed.installation_id)
        value,inventory=service.change(credential=credential,subject=subject,permit=permit,
            actor=identifier(command["owner_actor_id"],"owner_actor_id"),**kwargs,
            operation_id=identifier(command["operation_id"],"operation_id"),action=action,definition=definition)
    if value is None:return{"status":"unavailable","original":None,"original_ref":None,"original_digest":None}
    response={"status":"current"if read else{"issue":"issued","revise":"revised","revoke":"revoked"}[value.action],
        "original":habit_standing_policy_original_to_wire_v1(value),"original_ref":value.original_ref,"original_digest":value.digest}
    if not read:
        from dataclasses import asdict
        response["cue_inventory"]=asdict(inventory)
    return response
