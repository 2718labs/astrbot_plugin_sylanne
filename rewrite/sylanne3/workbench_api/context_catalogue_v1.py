"""The signed Owner workbench route for static D03 catalogue adoption."""
from ..domains.d03.context import ContextProvider
from ..runtime_contracts import canonical_digest

ACTION = "d03_context_catalogue"
INPUT_FIELDS = frozenset({"roles", "norms", "budget_ref"})


def validate_context_catalogue_input_v1(data):
    if type(data) is not dict or set(data) != INPUT_FIELDS:
        raise ValueError("Context catalogue requires its exact Owner intent fields")
    if (type(data["roles"]) is not list or type(data["norms"]) is not list
            or len(data["roles"]) > 128 or len(data["norms"]) > 128
            or type(data["budget_ref"]) is not str or not 1 <= len(data["budget_ref"]) <= 4096):
        raise ValueError("Context catalogue requires bounded role/norm arrays and an actual budget locator")
    ContextProvider().compile_scheme({"schema": "d03.context.scheme.v1",
        "roles": tuple(data["roles"]), "norms": tuple(data["norms"])}, None)


def execute_context_catalogue_v1(issuer, *, session, scope, purpose, audience, operation_id, input_data):
    from .issuer import _unavailable
    from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    if (audience != "owner" or not session.allows(scope, "workbench.activate", purpose, audience)
            or type(session.owner_session_request) is not OwnerSessionLoginRequestV1 or not session.owner_session_token):
        return _unavailable("signed_owner_session_unavailable")
    data = dict(input_data)
    validate_context_catalogue_input_v1(data)
    grant = issuer._resolve(session, scope, purpose, audience, domains=("d03", "d11", "d12"))
    if grant is None or "workbench.activate" not in grant.capabilities:
        return _unavailable("context_catalogue_authority_unavailable")
    result = issuer._coordinator.adopt_current_context_catalogue_v1(grant.authority, grant.lease,
        operation_id=operation_id, roles=tuple(data["roles"]), norms=tuple(data["norms"]), budget_ref=data["budget_ref"])
    return {"status": "ready", "receipt": {"schema": "d12.context-catalogue-receipt.v1", "action": ACTION,
        "operation_id": operation_id, "input_digest": canonical_digest(data),
        "original_digest": canonical_digest(result), "original": result}}
