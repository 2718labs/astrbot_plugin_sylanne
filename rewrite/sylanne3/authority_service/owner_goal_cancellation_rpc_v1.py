"""Paired installed Goal management RPC; no business read or model-fence finish."""
from dataclasses import asdict
from .contract import AuthorityUnavailable, identifier
from .owner_goal_cancellation_contract_v1 import (
    OwnerGoalCancellationRequestV1, owner_goal_cancellation_from_wire_v1)
METHODS = frozenset({"owner_goal_cancel_submit_v1","owner_goal_cancel_status_v1","owner_goal_cancellation_projection_observe_v1","owner_goal_cancellation_projection_next_v1"})


def dispatch_owner_goal_cancellation_v1(server, method, command, *, credential, profile_id, manifest_digest):
    if method=="owner_goal_cancellation_projection_next_v1":
        if type(command) is not dict or set(command)!={"namespace","after_cancel_operation_id"}:
            raise AuthorityUnavailable("exact Goal projection cursor RPC required")
        namespace=identifier(command["namespace"],"namespace")
        server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
        installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
        service=server._owner_goal_cancellation_services_v1.get((namespace,installed.installation_id))
        if service is None:raise AuthorityUnavailable("actual installed Goal projection service unavailable")
        original=service.read_next_projection_cause_v1(credential=credential,subject="mtls:sha256:"+credential.certificate_sha256,
            after_cancel_operation_id=command["after_cancel_operation_id"])
        return {"original":None if original is None else asdict(original)}
    if method=="owner_goal_cancellation_projection_observe_v1":
        if type(command) is not dict or set(command)!={"namespace","cancel_operation_id","original_ref","permit"}:
            raise AuthorityUnavailable("exact cold Goal projection RPC fields required")
        namespace=identifier(command["namespace"],"namespace")
        server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
        installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
        service=server._owner_goal_cancellation_services_v1.get((namespace,installed.installation_id))
        if service is None:raise AuthorityUnavailable("actual installed Goal projection service unavailable")
        from .v2_contract import from_wire as fence_from_wire
        from .owner_goal_projection_contract_v1 import goal_projection_to_wire_v1
        observed=service.observe_projection_metadata_v1(credential=credential,
            subject="mtls:sha256:"+credential.certificate_sha256,permit=fence_from_wire(command["permit"]),
            cancel_operation_id=command["cancel_operation_id"],original_ref=command["original_ref"])
        return {"observation":goal_projection_to_wire_v1(observed)}
    required={"namespace","owner_actor_id","owner_session_token","owner_session_request"}
    if method=="owner_goal_cancel_submit_v1":required.add("cancel_request")
    elif method=="owner_goal_cancel_status_v1":required.add("cancel_operation_id")
    else:raise AuthorityUnavailable("unregistered Goal management RPC")
    if type(command) is not dict or set(command)!=required:
        raise AuthorityUnavailable("Goal management exact command fields differ")
    namespace=identifier(command["namespace"],"namespace")
    server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
    service=server._owner_goal_cancellation_services_v1.get((namespace,installed.installation_id))
    if service is None:raise AuthorityUnavailable("actual installed Goal management service unavailable")
    kwargs=server._owner_session_kwargs(command,namespace,installed.installation_id)
    kwargs.update(credential=credential,subject="mtls:sha256:"+credential.certificate_sha256,
        actor=identifier(command["owner_actor_id"],"owner_actor_id"))
    if method=="owner_goal_cancel_submit_v1":
        request=owner_goal_cancellation_from_wire_v1(command["cancel_request"],OwnerGoalCancellationRequestV1)
        if request.installation_id!=installed.installation_id:
            raise AuthorityUnavailable("Goal cancellation crossed its actual paired installation")
        original=service.submit_v1(request=request,**kwargs)
    else:
        original=service.read_status_v1(operation_id=command["cancel_operation_id"],**kwargs)
    return {"original":asdict(original)}
