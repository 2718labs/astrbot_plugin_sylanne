"""Closed policy RPCs: only a signed-in Owner can issue or revoke consent."""
from .contract import AuthorityUnavailable, identifier
from .d10_contact_policy_service_v1 import (
    InstalledD10ContactPolicyServiceV1, contact_policy_original_to_wire_v1,
)
from .v2_contract import FencePermitV2, from_wire
from ..domains.d10 import ContactPolicy
from ..runtime_contracts import NamespaceId

METHODS = frozenset({"d10_contact_policy_issue_v1", "d10_contact_policy_revoke_v1",
                     "d10_contact_policy_read_current_v1"})


def dispatch_d10_contact_policy_v1(server, method, credential, profile_id, manifest_digest, command):
    if method not in METHODS:
        return None
    read = method == "d10_contact_policy_read_current_v1"
    expected = {"namespace", "permit", "policy_id"} if read else {
        "namespace", "permit", "owner_actor_id", "owner_session_token", "owner_session_request",
        "operation_id", "policy"}
    if type(command) is not dict or set(command) != expected:
        raise AuthorityUnavailable("contact-policy RPC fields differ")
    namespace = identifier(command["namespace"], "namespace")
    fences = server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installed = server._installations_v2[(credential.certificate_sha256, profile_id)]
    permit = from_wire(command["permit"])
    service = getattr(server, "_d10_contact_policy_services_v1", {}).get((namespace, installed.installation_id))
    if (type(service) is not InstalledD10ContactPolicyServiceV1 or service.fences is not fences
            or type(permit) is not FencePermitV2 or permit.holder != installed.administrator_holder):
        raise AuthorityUnavailable("contact-policy service differs from the paired installation")
    subject = "mtls:sha256:" + credential.certificate_sha256
    if read:
        value = service.read_current(credential=credential, subject=subject, permit=permit,
                                     policy_id=identifier(command["policy_id"], "policy_id"))
    else:
        raw = command["policy"]
        if type(raw) is not dict or set(raw) != set(ContactPolicy.__dataclass_fields__):
            raise AuthorityUnavailable("contact-policy candidate has another schema")
        policy = ContactPolicy(**{**raw, "namespace": NamespaceId(**raw["namespace"])})
        kwargs = server._owner_session_kwargs(command, namespace, installed.installation_id)
        value = service.change(credential=credential, subject=subject, permit=permit,
            actor=identifier(command["owner_actor_id"], "owner_actor_id"), **kwargs,
            operation_id=identifier(command["operation_id"], "operation_id"),
            action="issue" if method.endswith("issue_v1") else "revoke", policy=policy)
    if value is None:
        return {"status": "unavailable", "original": None, "original_ref": None, "original_digest": None}
    return {"status": "current" if read else "issued" if value.action == "issue" else "revoked",
            "original": contact_policy_original_to_wire_v1(value),
            "original_ref": value.original_ref, "original_digest": value.digest}
