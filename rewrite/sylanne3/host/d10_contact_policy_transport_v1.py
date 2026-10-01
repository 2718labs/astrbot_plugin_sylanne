"""Current policy originals authenticated by the installed mTLS channel."""
from dataclasses import asdict

from ..authority_service.d10_contact_policy_rpc_v1 import METHODS
from ..authority_service.d10_contact_policy_service_v1 import contact_policy_original_from_wire_v1
from ..authority_service.v2_contract import SCHEMA, FencePermitV2, to_wire


async def transport_d10_contact_policy_v1(transport, request, handshake, grant, *,
        namespace, namespace_id, permit, method, **values):
    if (method not in METHODS or type(permit) is not FencePermitV2
            or permit.namespace != namespace or permit.authority_id != grant.authority_id
            or permit.holder != grant.administrator_holder):
        raise ValueError("contact-policy transport requires its current installation fence")
    encoded = dict(values)
    if "policy" in encoded:
        encoded["policy"] = asdict(encoded["policy"])
    if "owner_session_request" in encoded:
        from ..authority_service.v2_owner_session import to_wire as session_to_wire
        encoded["owner_session_request"] = session_to_wire(encoded["owner_session_request"])
    command = {"namespace": namespace, "permit": to_wire(permit), **encoded}
    response = await transport._content_rpc(request, handshake, method, command, protocol=SCHEMA)
    if (type(response) is not dict
            or response.pop("channel_binding_sha256", None) != handshake.channel_binding_sha256
            or set(response) != {"status", "original", "original_ref", "original_digest"}):
        raise ValueError("contact-policy original response channel/fields differ")
    if response["status"] == "unavailable":
        if (method != "d10_contact_policy_read_current_v1" or response["original"] is not None
                or response["original_ref"] is not None or response["original_digest"] is not None):
            raise ValueError("contact-policy unavailable response differs")
        return None
    expected = ("current" if method == "d10_contact_policy_read_current_v1" else
                "issued" if method == "d10_contact_policy_issue_v1" else "revoked")
    if response["status"] != expected:
        raise ValueError("contact-policy response has another action")
    original = contact_policy_original_from_wire_v1(response["original"])
    if ((original.authority_id, original.authority_namespace, original.installation_id, original.namespace)
            != (grant.authority_id, namespace, grant.installation_id, namespace_id)
            or original.original_ref != response["original_ref"] or original.digest != response["original_digest"]):
        raise ValueError("contact-policy original crossed its paired installation")
    return original
