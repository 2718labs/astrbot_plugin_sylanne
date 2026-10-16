"""Named Habit policy transport with exact channel, permit and Definition binding."""
from ..authority_service.d10_habit_policy_rpc_v1 import METHODS
from ..authority_service.d10_habit_contract_v1 import habit_standing_policy_original_from_wire_v1,habit_policy_window_cue_inventory_from_wire_v1
from ..authority_service.v2_contract import SCHEMA,FencePermitV2,to_wire
from ..domains.d10.habit_policy_v1 import habit_policy_definition_to_wire_v1
from ..runtime_contracts import canonical_digest

async def transport_d10_habit_policy_v1(transport,request,handshake,grant,*,namespace,namespace_id,permit,method,**values):
    if(method not in METHODS or type(permit)is not FencePermitV2 or permit.namespace!=namespace
            or permit.authority_id!=grant.authority_id or permit.holder!=grant.administrator_holder):
        raise ValueError("Habit policy transport requires its current paired installation fence")
    encoded=dict(values)
    if"definition"in encoded:encoded["definition"]=habit_policy_definition_to_wire_v1(encoded["definition"])
    if"owner_session_request"in encoded:
        from ..authority_service.v2_owner_session import to_wire as session_to_wire
        encoded["owner_session_request"]=session_to_wire(encoded["owner_session_request"])
    response=await transport._content_rpc(request,handshake,method,{"namespace":namespace,"permit":to_wire(permit),**encoded},protocol=SCHEMA)
    read=method=="d10_habit_policy_read_current_v1"
    if(type(response)is not dict or response.pop("channel_binding_sha256",None)!=handshake.channel_binding_sha256
            or set(response)!=({"status","original","original_ref","original_digest"}if read else
                {"status","original","original_ref","original_digest","cue_inventory"})):
        raise ValueError("Habit policy original response channel/fields differ")
    if response["status"]=="unavailable":
        if not read or any(response[x]is not None for x in("original","original_ref","original_digest")):
            raise ValueError("Habit unavailable original response differs")
        return None
    expected="current"if read else"issued"if method.endswith("issue_v1")else"revoked"if method.endswith("revoke_v1")else"revised"
    if response["status"]!=expected:raise ValueError("Habit policy response action differs")
    value=habit_standing_policy_original_from_wire_v1(response["original"])
    if((value.authority_id,value.authority_namespace,value.installation_id,value.namespace)!=(
            grant.authority_id,namespace,grant.installation_id,namespace_id)
            or value.original_ref!=response["original_ref"]or value.digest!=response["original_digest"]
            or not read and(value.definition!=values["definition"]or value.operation_id!=values["operation_id"]
                or value.owner_actor_id!=values["owner_actor_id"])):
        raise ValueError("Habit original crossed its actual Definition/operation/Owner/installation")
    if read:return value
    inventory=habit_policy_window_cue_inventory_from_wire_v1(response["cue_inventory"])
    if(inventory.namespace,inventory.installation_id,inventory.definition_digest,inventory.operation_id,inventory.permit_token,
            inventory.standing_original_ref,inventory.standing_original_digest)!=(namespace_id,grant.installation_id,
            canonical_digest(value.definition),value.operation_id,permit.token,value.original_ref,value.digest):
        raise ValueError("Habit actual Core cue inventory changed its same mutation/permit/Definition head")
    return value,inventory
