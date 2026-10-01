"""Explicit signed-Owner initialization commands for the installed D04 chain."""
from __future__ import annotations
import math
import re
from ..runtime_contracts import canonical_digest

ACTIONS = {
    "d04_root_draft": ("initialize_current_d04_root_draft_v3", "workbench.create", frozenset({"root_field"})),
    "d04_root_budget": ("allocate_current_d04_root_budget_v3", "workbench.activate", frozenset({"parent_budget_lease_ref", "ceiling"})),
    "d04_root_coupling": ("adopt_current_d04_root_coupling_v3", "workbench.activate", frozenset({"root_operation_id", "effective_until"})),
    "d04_semantic_mapping": ("adopt_current_d04_semantic_mapping_v3", "workbench.activate", frozenset({"profile_digest", "expected_revision"})),
    "d11_role_clock": ("register_current_d11_role_clock_v1", "workbench.activate", frozenset({"expected_version", "character_origin", "rate", "wall_origin_utc", "valid_from_utc", "valid_until_utc"})),
}


def validate_input_v3(action, data):
    if type(data) is not dict or set(data) != ACTIONS[action][2]:
        raise ValueError("D04 initialization requires its exact versioned input")
    if action == "d04_root_draft":
        if type(data["root_field"]) is not dict or not data["root_field"]:
            raise ValueError("D04 root requires explicit authored field choices")
    if action == "d04_root_budget":
        if (type(data["parent_budget_lease_ref"]) is not str or not data["parent_budget_lease_ref"]
                or type(data["ceiling"]) is not dict or set(data["ceiling"]) != {"thread_cpu_ms"}
                or type(data["ceiling"]["thread_cpu_ms"]) is not int or not 0 < data["ceiling"]["thread_cpu_ms"] <= 9_000_000_000_000_000):
            raise ValueError("D04 root budget requires an explicit positive CPU ceiling")
    if action == "d04_root_coupling" and (type(data["root_operation_id"]) is not str
            or not data["root_operation_id"] or type(data["effective_until"]) not in (int, float)
            or not math.isfinite(data["effective_until"])):
        raise ValueError("D04 topology requires exact root and finite role interval")
    if action == "d04_semantic_mapping" and (type(data["expected_revision"]) is not int or data["expected_revision"] < 0
            or type(data["profile_digest"]) is not str or re.fullmatch(r"[0-9a-f]{64}", data["profile_digest"]) is None):
        raise ValueError("D04 semantic selection requires installed profile and revision CAS")
    if action == "d11_role_clock":
        if type(data["expected_version"]) is not int or data["expected_version"] < 0:
            raise ValueError("D11 role clock requires version CAS")
        if any(type(data[name]) is not str or not 1 <= len(data[name]) <= 128 for name in ACTIONS[action][2] - {"expected_version"}):
            raise ValueError("D11 role clock requires exact decimal and UTC strings")


def execute_initialization_v3(issuer, *, session, action, scope, purpose, audience, operation_id, input_data):
    from .issuer import _unavailable
    from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    method, capability, _ = ACTIONS[action]
    if (audience != "owner" or not session.allows(scope, capability, purpose, audience)
            or type(session.owner_session_request) is not OwnerSessionLoginRequestV1
            or not session.owner_session_token):
        return _unavailable("signed_owner_session_unavailable")
    validate_input_v3(action, dict(input_data))
    grant = issuer._resolve(session, scope, purpose, audience, domains=("d01", "d04", "d11", "d12"))
    if grant is None or capability not in grant.capabilities:
        return _unavailable("authority_unavailable")
    submit = getattr(issuer._coordinator, method, None)
    if not callable(submit):
        return _unavailable("installed_d04_initialization_unavailable")
    result = submit(grant.authority, grant.lease, operation_id=operation_id, **dict(input_data))
    if type(result) is not dict or result.get("operation_id") != operation_id:
        raise ValueError("D04 initialization returned another operation original")
    return {"status": "ready", "receipt": {"schema": "d12.d04_initialization_receipt.v3",
        "operation_id": operation_id, "action": action, "phase": "owner_operation_committed",
        "input_digest": canonical_digest(dict(input_data)), "original_digest": canonical_digest(result),
        "original": result}}


def read_initialization_profile_v3(issuer, *, session, scope, purpose, audience):
    from .issuer import _unavailable
    grant = issuer._resolve(session, scope, purpose, audience, domains=("d01", "d04", "d11", "d12"))
    reader = getattr(issuer._coordinator, "_GraphCoordinator__d04_semantic_mapping_reader", None)
    if grant is None or reader is None or audience != "owner":
        return _unavailable("installed_d04_initialization_unavailable")
    profile = reader.profile()
    current = issuer._coordinator.read_current_d04_initialization_metadata_v3(grant.authority, grant.lease)
    return {"status": "ready", "projection": {"schema": "d12.d04_initialization_profile.v3",
        "current": current,
        "profile_digest": profile.profile_digest, "profile": profile.raw,
        "clock_requires_explicit_rate_and_interval": True,
        "root_budget_dimension": "thread_cpu_ms"}}
