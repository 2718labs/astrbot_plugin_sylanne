"""An actual current policy read, scoped to the caller's still-live W01 fence."""
from contextlib import contextmanager
from dataclasses import dataclass

from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
from ..authority_service.d10_contact_policy_service_v1 import D10ContactPolicyOriginalV1
from ..domains.d10 import decode_contact_policy
from ..runtime_contracts import FenceScope

_CURRENT = {}


@dataclass(frozen=True, slots=True)
class IssuedCurrentContactPolicyV1:
    original: D10ContactPolicyOriginalV1
    scope: FenceScope
    port: InstalledC04AuthorityPortV3


@contextmanager
def read_installed_current_contact_policy_v1(port, scope, policy_id):
    if type(port) is not InstalledC04AuthorityPortV3 or type(scope) is not FenceScope:
        raise TypeError("actual installed policy port and current fence required")
    original = port.contact_policy(scope.permit, "read_current", policy_id=policy_id)
    if original is None:
        yield None
        return
    if (type(original) is not D10ContactPolicyOriginalV1 or original.action != "issue"
            or original.namespace != scope.namespace or original.authority_namespace != scope.authority_namespace
            or original.authority_id != scope.pinned_anchor.authority_id
            or original.installation_id != port._grant.installation_id):
        raise ValueError("contact policy qualification crossed its installed fence")
    issued = IssuedCurrentContactPolicyV1(original, scope, port)
    _CURRENT[id(issued)] = issued
    try:
        yield issued
    finally:
        _CURRENT.pop(id(issued), None)


def require_current_contact_policy_v1(issued, scope, graph_policy, *, now):
    if (type(issued) is not IssuedCurrentContactPolicyV1 or _CURRENT.get(id(issued)) is not issued
            or type(scope) is not FenceScope or issued.scope != scope):
        raise ValueError("actual current contact-policy qualification is absent")
    original = issued.original
    policy = decode_contact_policy(graph_policy, scope.namespace)
    if (original.policy != policy or graph_policy["approval_ref"] != original.original_ref
            or graph_policy["approval_authority_id"] != original.authority_id
            or graph_policy["installation_id"] != original.installation_id
            or graph_policy["owner_grant_revision"] != original.owner_authorization_revision
            or not policy.window_start <= now < policy.window_end):
        raise ValueError("Graph contact policy differs from the current Owner-issued original")
    return original
