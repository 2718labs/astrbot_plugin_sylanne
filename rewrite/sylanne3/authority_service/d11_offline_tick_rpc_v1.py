"""Paired finite clock tick RPC: callers select an original, never a result."""
from .contract import AuthorityUnavailable, identifier
from .d11_offline_tick_contract_v1 import (
    D11OfflineTickBindingV1, offline_tick_from_wire_v1, offline_tick_to_wire_v1,
)


METHODS = frozenset({"d11_offline_tick_execute_v1", "d11_offline_tick_original_v1", "d11_offline_tick_bridge_v1",
    "d11_offline_tick_historical_accounting_v1", "d11_offline_tick_historical_original_v1",
    "d11_offline_tick_recover_claimed_v1", "d11_offline_tick_unstarted_cancellation_v1"})


def dispatch_d11_offline_tick_v1(server, method, credential, profile_id, manifest_digest, command):
    if method not in METHODS:
        return None
    bridge_fields = {"namespace", "binding", "action", "gate", "outcome"}
    expected_fields = (bridge_fields if method == "d11_offline_tick_bridge_v1" else
        {"namespace", "binding", "action", "gate"} if method in {"d11_offline_tick_historical_accounting_v1",
            "d11_offline_tick_unstarted_cancellation_v1"} else {"namespace", "binding"})
    if type(command) is not dict or set(command) != expected_fields:
        raise AuthorityUnavailable("offline tick RPC accepts only namespace and binding")
    namespace = identifier(command["namespace"], "namespace")
    server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installation = server._installations_v2[(credential.certificate_sha256, profile_id)]
    service = getattr(server, "_d11_offline_tick_services_v1", {}).get(namespace)
    binding = offline_tick_from_wire_v1(command["binding"], D11OfflineTickBindingV1)
    if (service is None or service.installation_id != installation.installation_id
            or binding.installation_id != installation.installation_id
            or binding.authority_namespace != namespace):
        raise AuthorityUnavailable("offline tick service differs from paired installation")
    from .d11_offline_tick_service_v1 import AuthorityD11OfflineTickServiceV1
    if type(service) is not AuthorityD11OfflineTickServiceV1:
        raise AuthorityUnavailable("actual installed offline tick authority required")
    if method == "d11_offline_tick_unstarted_cancellation_v1":
        from .d11_offline_unstarted_cancellation_v1 import unstarted_cancellation_from_wire_v1, unstarted_cancellation_to_wire_v1
        action, raw = command["action"], command["gate"]
        if action == "begin" and raw is not None:
            raise AuthorityUnavailable("offline cancellation begin selects its original binding only")
        gate = None if raw is None else unstarted_cancellation_from_wire_v1(raw)
        result = service.offline_unstarted_cancellation_v1(binding, action=action, gate=gate)
        return {"result": unstarted_cancellation_to_wire_v1(result) if action in {"begin", "validate"} else result}
    if method == "d11_offline_tick_historical_accounting_v1":
        from .d11_offline_historical_accounting_v1 import historical_accounting_from_wire_v1, historical_accounting_to_wire_v1
        action, raw = command["action"], command["gate"]
        if action == "begin" and raw is not None:
            raise AuthorityUnavailable("offline historical begin selects an original only")
        gate = None if raw is None else historical_accounting_from_wire_v1(raw)
        result = service.offline_historical_accounting_v1(binding, action=action, gate=gate)
        return {"result": historical_accounting_to_wire_v1(result) if action in {"begin", "validate"} else result}
    if method == "d11_offline_tick_bridge_v1":
        from .d11_offline_tick_bridge_v1 import offline_bridge_from_wire_v1, offline_bridge_to_wire_v1
        action, raw, outcome = command["action"], command["gate"], command["outcome"]
        if ((action == "begin" and raw is not None) or (action != "finish" and outcome is not None)):
            raise AuthorityUnavailable("offline bridge operation fields differ")
        gate = None if raw is None else offline_bridge_from_wire_v1(raw)
        result = service.offline_adoption_bridge_v1(binding, action=action, gate=gate, outcome=outcome)
        return {"result": offline_bridge_to_wire_v1(result) if action in {"begin", "validate"} else result}
    if method == "d11_offline_tick_execute_v1":
        claim, terminal = service.execute_d11_offline_tick_v1(binding)
    elif method == "d11_offline_tick_historical_original_v1":
        claim, terminal = service.read_historical_d11_offline_tick_original_v1(binding)
    elif method == "d11_offline_tick_recover_claimed_v1":
        claim, terminal = service.recover_claimed_d11_offline_tick_v1(binding)
    else:
        claim, terminal = service.read_d11_offline_tick_original_v1(binding)
    return {"claim": None if claim is None else offline_tick_to_wire_v1(claim),
            "terminal": None if terminal is None else offline_tick_to_wire_v1(terminal)}
