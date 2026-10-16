"""Exact installed mTLS transport for bodyless Contact effect accounting."""
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.contact_effect_accounting_contract_v1 import (
    ContactEffectCostFactV1, ContactEffectMeasurementReceiptV1, ContactEffectAccountingGrantV1,
    ContactEffectAccountingRequestV1, SignedContactEffectBudgetOriginV1, to_wire, from_wire,
)
from ..authority_service.v2_contract import to_wire as authority_wire
from .v2_fence_port import V2FencePort
from .authority_profile import AdminInstallationBundle

_KEY = object()


class InstalledContactEffectAccountingPortV1:
    def __init__(self, key, port, bundle):
        if (key is not _KEY or type(port) is not V2FencePort or type(bundle) is not AdminInstallationBundle
                or port.installation_grant.installation_id != bundle.installation_policy.installation_id
                or port.installation_grant.manifest_digest != bundle.installation_policy.manifest_digest):
            raise AuthorityUnavailable("actual installed Contact accounting port required")
        self.port, self.bundle = port, bundle
        self.namespace = bundle.installation_policy.namespace
        self.authority_namespace = bundle.installation_policy.authority_namespace

    def _call(self, method, payload, output=None):
        return self.port._submit(self.port._with_session_repair(
            lambda: self._rpc(method, payload, output)))

    async def _rpc(self, method, payload, output):
        from ..authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
        await self.port._mapped(self.namespace, self.authority_namespace)
        handshake, grant = self.port._identity()
        policy = self.bundle.installation_policy
        if (grant.installation_id, grant.administrator_holder, grant.manifest_digest) != (
                policy.installation_id, policy.administrator_holder, policy.manifest_digest):
            raise AuthorityUnavailable("Contact accounting installation changed")
        response = await self.port._transport._content_rpc(self.port._request, handshake, method,
            {"namespace": self.authority_namespace, **payload}, protocol=AUTHORITY_V2_PROTOCOL)
        if (type(response) is not dict or set(response) != {"result", "channel_binding_sha256"}
                or response["channel_binding_sha256"] != handshake.channel_binding_sha256):
            raise AuthorityUnavailable("Contact accounting crossed its authenticated channel")
        return response["result"] if output is None else from_wire(response["result"], output)

    def record_measurement(self, origin, measurement, observation, claimed_receipt):
        return self._call("contact_effect_measurement_record_v1",
            {"origin": to_wire(origin), "measurement": to_wire(measurement),
                "observation": authority_wire(observation), "claimed_receipt": authority_wire(claimed_receipt)},
            ContactEffectMeasurementReceiptV1)

    def read_fact(self, origin):
        if type(origin) is not SignedContactEffectBudgetOriginV1:
            raise TypeError("signed original Contact budget required")
        return self._call("contact_effect_cost_fact_v1", {"origin": to_wire(origin)}, ContactEffectCostFactV1)

    def begin(self, request):
        if type(request) is not ContactEffectAccountingRequestV1: raise TypeError("actual Contact accounting request required")
        return self._call("contact_effect_accounting_begin_v1", {"request": to_wire(request)}, ContactEffectAccountingGrantV1)

    def validate(self, request, grant):
        if self._call("contact_effect_accounting_validate_v1", {"request": to_wire(request), "grant": to_wire(grant)}) is not True:
            raise AuthorityUnavailable("Contact accounting validation was not confirmed")

    def finish(self, request, grant):
        if self._call("contact_effect_accounting_finish_v1", {"request": to_wire(request), "grant": to_wire(grant)}) is not True:
            raise AuthorityUnavailable("Contact accounting finish was not confirmed")

    def recover_finish(self, request):
        if self._call("contact_effect_accounting_recover_finish_v1", {"request": to_wire(request)}) is not True:
            raise AuthorityUnavailable("Contact accounting recovery finish was not confirmed")


def install_contact_effect_accounting_port_v1(port, bundle):
    return InstalledContactEffectAccountingPortV1(_KEY, port, bundle)
