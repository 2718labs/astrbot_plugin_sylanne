"""Life operations on the actual paired mTLS fence port; no caller result channel."""
from ..runtime.d11_life_contract_v1 import LIFE_BINDING_TYPES, LIFE_CLAIM_TYPES, LIFE_TERMINAL_TYPES
from concurrent.futures import TimeoutError as FutureTimeout

from .v2_fence_port import V2FencePort, V2FenceOutcomeUnknown
from .mtls_transport import MtlsAuthorityTransport
from ..authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from ..runtime.d11_life_contract_v1 import (D11LifeExecutionBindingV1, D11LifeClaimV1, D11LifeTerminalV1,
    life_to_wire_v1, life_from_wire_v1)


class InstalledD11LifePortV1:
    def __init__(self, port):
        if type(port) is not V2FencePort or type(port._transport) is not MtlsAuthorityTransport:
            raise TypeError("Life needs the actual installed paired mTLS fence port")
        self.port = port

    async def _draft_observation_call_v1(self, binding, request, method, outcome=None):
        from ..runtime.d11_artifact_draft_contract_v1 import (DraftFileObservationRequestV1,
            DraftObservationOutcomeV1, draft_to_wire_v1, draft_from_wire_v1)
        if type(binding) not in LIFE_BINDING_TYPES or type(request) is not DraftFileObservationRequestV1:
            raise TypeError("closed installed draft observation selectors required")
        handshake, grant = self.port._identity()
        if (binding.authority_id, binding.installation_id) != (grant.authority_id, grant.installation_id):
            raise RuntimeError("draft observation paired installation differs")
        command = {"namespace": binding.authority_namespace, "binding": life_to_wire_v1(binding), "request": draft_to_wire_v1(request)}
        if method == "d11_draft_observation_original_v1":
            command["outcome"] = None if outcome is None else draft_to_wire_v1(outcome)
        response = await self.port._transport._content_rpc(self.port._request, handshake, method, command, protocol=AUTHORITY_V2_PROTOCOL)
        if set(response) != {"result", "channel_binding_sha256"} or response["channel_binding_sha256"] != handshake.channel_binding_sha256:
            raise RuntimeError("draft observation authenticated response differs")
        result = None if response["result"] is None else draft_from_wire_v1(response["result"], DraftObservationOutcomeV1)
        if result is not None and (result.call_id != request.call_id or result.original_effect_id != binding.effect_id
                or result.original_binding_digest != binding.digest):
            raise RuntimeError("draft observation response belongs to another original call/effect")
        return result

    def observe_artifact_draft_v1(self, *, binding, request):
        try:
            return self.port._submit(self._draft_observation_call_v1(binding, request, "d11_draft_observe_v1"))
        except (RuntimeError, FutureTimeout) as exc:
            raise V2FenceOutcomeUnknown("observation ACK lost; inspect the original read call, never reread its file automatically") from exc

    def read_draft_observation_original_v1(self, *, binding, request, outcome=None):
        return self.port._submit(self.port._with_session_repair(
            lambda: self._draft_observation_call_v1(binding, request, "d11_draft_observation_original_v1", outcome)))

    def read_d11_life_execution_inventory_v1(self, *, namespace, permit):
        from ..authority_service.v2_contract import to_wire
        from ..authority_service.d11_life_execution_inventory_v1 import life_execution_inventory_from_wire_v1
        async def read():
            handshake,grant=self.port._identity()
            response=await self.port._transport._content_rpc(self.port._request,handshake,"d11_life_execution_inventory_v1",
                {"namespace":namespace,"permit":to_wire(permit)},protocol=AUTHORITY_V2_PROTOCOL)
            if set(response) != {"inventory","channel_binding_sha256"} or response["channel_binding_sha256"] != handshake.channel_binding_sha256:
                raise RuntimeError("Life inventory authenticated channel differs")
            value=life_execution_inventory_from_wire_v1(response["inventory"])
            from ..runtime_contracts import canonical_digest
            if (value.authority_namespace != namespace or value.anchor != permit.pinned_anchor or value.permit_digest != canonical_digest(permit)
                    or value.installation_id != grant.installation_id or value.authority_id != grant.authority_id):
                raise RuntimeError("Life inventory differs from actual paired fence")
            return value
        return self.port._submit(self.port._with_session_repair(read))

    async def _call(self, binding, method, *, action=None, gate=None, outcome=None):
        if type(binding) not in LIFE_BINDING_TYPES:
            raise TypeError("Life accepts its fixed actual prepared execution selector only")
        port = self.port
        handshake, grant = port._identity()
        if ((binding.authority_id, binding.installation_id) != (grant.authority_id, grant.installation_id)
                or grant.channel_binding_sha256 != handshake.channel_binding_sha256):
            raise RuntimeError("Life paired installation identity differs")
        command = {"namespace": binding.authority_namespace, "binding": life_to_wire_v1(binding)}
        if method in {"d11_life_bridge_v1", "d11_life_accounting_v1"}:
            if action not in {"begin", "validate", "finish", "status"}:
                raise ValueError("Life bridge/accounting uses closed actions")
            if method == "d11_life_bridge_v1":
                from ..authority_service.d11_life_bridge_v1 import life_bridge_to_wire_v1, life_bridge_from_wire_v1
                encode, decode = life_bridge_to_wire_v1, life_bridge_from_wire_v1
                command["outcome"] = outcome
            else:
                from ..authority_service.d11_life_historical_accounting_v1 import historical_accounting_to_wire_v1, historical_accounting_from_wire_v1
                encode, decode = historical_accounting_to_wire_v1, historical_accounting_from_wire_v1
            command.update(action=action, gate=None if gate is None else encode(gate))
        response = await port._transport._content_rpc(port._request, handshake, method, command, protocol=AUTHORITY_V2_PROTOCOL)
        expected = {"result", "channel_binding_sha256"} if action is not None else {"claim", "terminal", "channel_binding_sha256"}
        if type(response) is not dict or set(response) != expected or response["channel_binding_sha256"] != handshake.channel_binding_sha256:
            raise RuntimeError("Life response fields or authenticated channel differ")
        if action is not None:
            result = response["result"]
            if action in {"begin", "validate"}:
                result = decode(result)
                if result.binding != binding or action == "validate" and result != gate:
                    raise RuntimeError("Life bridge original changed")
            elif action == "finish" and result is not True:
                raise RuntimeError("Life finish ACK remains unknown")
            elif action == "status" and result not in {"active", "finished"}:
                raise RuntimeError("Life original gate state differs")
            return result
        claim = None if response["claim"] is None else life_from_wire_v1(response["claim"], D11LifeClaimV1)
        terminal = None if response["terminal"] is None else life_from_wire_v1(response["terminal"], D11LifeTerminalV1)
        if claim is not None and claim.binding != binding or terminal is not None and (terminal.binding != binding or terminal.claim != claim):
            raise RuntimeError("Life actual original response crossed its binding")
        return claim, terminal

    def read_d11_life_original_v1(self, *, binding):
        return self.port._submit(self.port._with_session_repair(lambda: self._call(binding, "d11_life_original_v1")))

    def recover_claimed_d11_life_v1(self, *, binding):
        return self.port._submit(self.port._with_session_repair(lambda: self._call(binding, "d11_life_recover_claimed_v1")))

    def execute_d11_life_v1(self, *, binding):
        self.port._submit(self.port._with_session_repair(lambda: self.port._mapped(binding.namespace, binding.authority_namespace)))
        try:
            return self.port._submit(self._call(binding, "d11_life_execute_v1"))
        except (RuntimeError, FutureTimeout) as exc:
            raise V2FenceOutcomeUnknown("Life execute ACK lost; inspect the same consumed identity") from exc

    def life_adoption_bridge_v1(self, *, binding, action, gate=None, outcome=None):
        return self.port._submit(self.port._with_session_repair(lambda: self._call(binding, "d11_life_bridge_v1",
            action=action, gate=gate, outcome=outcome)))

    def life_historical_accounting_v1(self, *, binding, action, gate=None):
        return self.port._submit(self.port._with_session_repair(lambda: self._call(binding, "d11_life_accounting_v1", action=action, gate=gate)))
