"""Authenticated fixed-installation private Owner artifact read RPC adapter."""
import json
from .contract import AuthorityUnavailable
from .v2_contract import from_wire, FencePermitV2
from ..runtime.d12_owner_artifact_read_v1 import request_from_wire_v1, binding_from_wire_v1, observation_to_wire_v1, BODY_RESPONSE_MAX_BYTES, METADATA_RESPONSE_MAX_BYTES
from ..graph_coordinator import namespace_ref

BODY_METHOD = "owner_artifact_read_for_fence_v1"
BINDING_METHOD = "owner_artifact_read_binding_for_fence_v1"
METHODS = frozenset({BODY_METHOD,BINDING_METHOD})

def dispatch_owner_artifact_read_v1(server, method, command, *, credential, profile_id, manifest_digest):
    fields={"namespace","permit","request","owner_actor_id","owner_session_token","owner_session_request"}
    if method==BINDING_METHOD: fields.add("expected_binding")
    if method not in METHODS or type(command) is not dict or set(command)!=fields: raise AuthorityUnavailable("exact private Owner artifact read command required")
    namespace=command['namespace']
    if type(namespace) is not str or not namespace: raise AuthorityUnavailable("actual private artifact authority namespace required")
    server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
    service=server._d11_life_services_v1.get(namespace)
    request=request_from_wire_v1(command['request']);permit=from_wire(command['permit'])
    if (service is None or service.installation_id!=installed.installation_id or request.installation_id!=installed.installation_id
            or namespace_ref(request.namespace)!=namespace or type(permit) is not FencePermitV2 or permit.operation!='read'
            or permit.holder!=installed.administrator_holder): raise AuthorityUnavailable("actual paired artifact reader installation required")
    actor=command['owner_actor_id']
    if type(actor) is not str or not 1<=len(actor)<=4096: raise AuthorityUnavailable("actual artifact Owner actor required")
    kwargs=server._owner_session_kwargs(command,namespace,installed.installation_id)
    observed=service.observe_owner_artifact_for_fence_v1(credential=credential,subject='mtls:sha256:'+credential.certificate_sha256,
        permit=permit,request=request,actor=actor,expected_binding=None if method==BODY_METHOD else binding_from_wire_v1(command['expected_binding']),**kwargs)
    wire=observation_to_wire_v1(observed)
    # The actual Host channel uses a 32-character request ID; its authenticated channel commitment is 64 ASCII bytes.
    # Match serve_connection's complete response encoder, including LF; do not truncate a verified body.
    frame={"request_id":"0"*32,"ok":True,"result":{"observation":wire,"channel_binding_sha256":"0"*64}}
    if wire['result'] is not None:
        encoded_body=wire['result']['body_base64'];wire['result']['body_base64']=''
        metadata_size=len(json.dumps(frame,separators=(',',':'),sort_keys=True).encode('utf-8'))+1
        wire['result']['body_base64']=encoded_body
        if metadata_size>METADATA_RESPONSE_MAX_BYTES:raise AuthorityUnavailable('artifact private metadata exceeds existing response range')
    size=len(json.dumps(frame,separators=(',',':'),sort_keys=True).encode('utf-8'))+1
    if size>(BODY_RESPONSE_MAX_BYTES if method==BODY_METHOD else METADATA_RESPONSE_MAX_BYTES):raise AuthorityUnavailable('artifact complete encoded response exceeds its named bound')
    return {"observation":wire}
