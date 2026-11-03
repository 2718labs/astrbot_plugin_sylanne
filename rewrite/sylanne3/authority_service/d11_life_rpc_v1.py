"""Closed installed Life RPC dispatch: execute selectors and durable originals."""
from .contract import AuthorityUnavailable, identifier
from ..runtime.d11_life_contract_v1 import D11LifeExecutionBindingV1, life_from_wire_v1, life_to_wire_v1

METHODS = frozenset({"d11_character_labor_segment_page_v1","d11_character_labor_census_v1", "d11_character_work_segment_v1","d11_life_execution_inventory_v1","d11_life_execute_v1", "d11_life_original_v1", "d11_life_own_execution_original_v1", "d11_draft_own_execution_original_v1", "d11_life_recover_claimed_v1",
    "d11_life_bridge_v1", "d11_life_accounting_v1", "d11_draft_observe_v1", "d11_draft_observation_original_v1"})


def dispatch_d11_life_v1(server, method, credential, profile_id, manifest_digest, command):
    if method not in METHODS:
        return None
    if method in {"d11_character_labor_segment_page_v1","d11_character_labor_census_v1", "d11_character_work_segment_v1"}:
        from .v2_contract import FencePermitV2, from_wire
        expected=({"namespace","permit","census","cursor","limit"} if method=="d11_character_labor_segment_page_v1" else
            {"namespace","permit","body_profile_id"} if method=="d11_character_labor_census_v1"
            else {"namespace","permit","binding"})
        if type(command)is not dict or set(command)!=expected:
            raise AuthorityUnavailable("character labor metadata selector fields differ")
        namespace=identifier(command["namespace"],"namespace")
        server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
        installation=server._installations_v2[(credential.certificate_sha256,profile_id)]
        service=server._d11_life_services_v1.get(namespace)
        from .d11_life_service_v1 import AuthorityD11LifeServiceV1
        if (type(service)is not AuthorityD11LifeServiceV1
                or service.installation_id!=installation.installation_id
                or service.manifest_digest!=manifest_digest):
            raise AuthorityUnavailable("character labor metadata crossed its paired installation")
        permit=from_wire(command["permit"])
        if type(permit)is not FencePermitV2 or permit.namespace!=namespace or permit.operation!="write":
            raise AuthorityUnavailable("character labor metadata requires its original namespace WRITE")
        if method=="d11_character_labor_segment_page_v1":
            from .character_labor_census_v1 import (
                character_labor_census_from_wire_v1, character_labor_segment_page_to_wire_v1)
            census=character_labor_census_from_wire_v1(command["census"])
            if (census.namespace!=service.namespace or census.authority_namespace!=namespace
                    or census.installation_id!=installation.installation_id or census.manifest_digest!=manifest_digest):
                raise AuthorityUnavailable("labor segment page crossed its actual installed census namespace")
            value=service.character_labor_census_v1.read_character_labor_segment_page_v1(
                permit=permit,namespace=service.namespace,census=census,
                cursor=command["cursor"],limit=command["limit"])
            return {"page":character_labor_segment_page_to_wire_v1(value)}
        if method=="d11_character_labor_census_v1":
            from .character_labor_census_v1 import character_labor_census_to_wire_v1
            value=service.character_labor_census_v1.read_character_labor_census_v1(
                permit=permit,namespace=service.namespace,profile_id=identifier(command["body_profile_id"],"body_profile_id"))
            return {"census":character_labor_census_to_wire_v1(value)}
        binding=life_from_wire_v1(command["binding"],D11LifeExecutionBindingV1)
        if (binding.namespace!=service.namespace or binding.authority_namespace!=namespace
                or binding.installation_id!=installation.installation_id):
            raise AuthorityUnavailable("character segment crossed its actual Life binding")
        from ..domains.d01.production_operations_v1 import plain_v1
        value=service.read_d11_character_work_segment_for_fence_v1(binding=binding,permit=permit)
        return {"segment":plain_v1(value)}
    if method == "d11_life_execution_inventory_v1":
        from .v2_contract import FencePermitV2,from_wire
        from .d11_life_execution_inventory_v1 import life_execution_inventory_to_wire_v1
        if type(command) is not dict or set(command) != {"namespace","permit"}:
            raise AuthorityUnavailable("Life inventory selector fields differ")
        namespace=identifier(command["namespace"],"namespace")
        server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
        installation=server._installations_v2[(credential.certificate_sha256,profile_id)]
        service=server._d11_life_services_v1.get(namespace)
        from .d11_life_service_v1 import AuthorityD11LifeServiceV1
        if type(service) is not AuthorityD11LifeServiceV1 or service.installation_id != installation.installation_id:
            raise AuthorityUnavailable("actual Life inventory installation differs")
        return {"inventory":life_execution_inventory_to_wire_v1(service.read_d11_life_execution_inventory_v1(permit=from_wire(command["permit"])))}
    expected = ({"namespace", "binding", "request"} if method == "d11_draft_observe_v1" else
        {"namespace", "binding", "request", "outcome"} if method == "d11_draft_observation_original_v1" else
        {"namespace", "binding", "action", "gate", "outcome"} if method == "d11_life_bridge_v1" else
        {"namespace", "binding", "action", "gate"} if method == "d11_life_accounting_v1" else {"namespace", "binding"})
    if type(command) is not dict or set(command) != expected:
        raise AuthorityUnavailable("Life RPC fields differ from fixed selector protocol")
    namespace = identifier(command["namespace"], "namespace")
    server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installation = server._installations_v2[(credential.certificate_sha256, profile_id)]
    service = server._d11_life_services_v1.get(namespace)
    binding = life_from_wire_v1(command["binding"], D11LifeExecutionBindingV1)
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    if (type(service) is not AuthorityD11LifeServiceV1 or service.installation_id != installation.installation_id
            or binding.installation_id != installation.installation_id or binding.authority_namespace != namespace):
        raise AuthorityUnavailable("Life actual installed authority differs from paired request")
    if method in {"d11_draft_observe_v1", "d11_draft_observation_original_v1"}:
        from ..runtime.d11_artifact_draft_contract_v1 import (DraftFileObservationRequestV1,
            DraftObservationOutcomeV1, draft_from_wire_v1, draft_to_wire_v1)
        request = draft_from_wire_v1(command["request"], DraftFileObservationRequestV1)
        if method == "d11_draft_observe_v1":
            result = service.observe_artifact_draft_v1(binding, request)
        else:
            outcome = None if command["outcome"] is None else draft_from_wire_v1(command["outcome"], DraftObservationOutcomeV1)
            result = service.read_draft_observation_original_v1(binding, request, outcome=outcome)
        return {"result": None if result is None else draft_to_wire_v1(result)}
    if method in {"d11_life_bridge_v1", "d11_life_accounting_v1"}:
        action, raw = command["action"], command["gate"]
        if action == "begin" and raw is not None:
            raise AuthorityUnavailable("Life begin accepts the original binding only")
        if method == "d11_life_bridge_v1":
            from .d11_life_bridge_v1 import life_bridge_from_wire_v1, life_bridge_to_wire_v1
            gate = None if raw is None else life_bridge_from_wire_v1(raw)
            if action != "finish" and command["outcome"] is not None:
                raise AuthorityUnavailable("Life bridge outcome belongs to actual finish only")
            result = service.life_adoption_bridge_v1(binding, action=action, gate=gate, outcome=command["outcome"])
            encode = life_bridge_to_wire_v1
        else:
            from .d11_life_historical_accounting_v1 import historical_accounting_from_wire_v1, historical_accounting_to_wire_v1
            gate = None if raw is None else historical_accounting_from_wire_v1(raw)
            result = service.life_historical_accounting_v1(binding, action=action, gate=gate)
            encode = historical_accounting_to_wire_v1
        return {"result": encode(result) if action in {"begin", "validate"} else result}
    if method == "d11_life_execute_v1":
        claim, terminal = service.execute_d11_life_v1(binding)
    elif method == "d11_life_recover_claimed_v1":
        claim, terminal = service.recover_claimed_d11_life_v1(binding)
    elif method == "d11_life_own_execution_original_v1":
        claim, terminal = service.read_own_d11_life_execution_original_v1(binding)
    elif method == "d11_draft_own_execution_original_v1":
        claim, terminal = service.read_own_d11_draft_execution_original_v1(binding)
    else:
        claim, terminal = service.read_d11_life_original_v1(binding)
    return {"claim": None if claim is None else life_to_wire_v1(claim), "terminal": None if terminal is None else life_to_wire_v1(terminal)}
