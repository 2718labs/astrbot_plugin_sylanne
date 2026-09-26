"""Private, pinned Authority query for an original terminal C02 handoff.

The adapter owns the exact request and installed mTLS session. It supplies a
finished fact only by querying Authority; no caller-provided fact is accepted.
Call it before taking the graph transaction lock.
"""

from __future__ import annotations

from ..authority_service.v2_terminal_c02_recovery_contract import (
    TerminalRecoveryReadFactV1, TerminalRecoveryReadRequestV1,
)
from ..runtime_contracts import InstallationGrantV2
from .authority_client import AuthorityHandshake, AuthorityProvisioningRequest
from .mtls_transport import MtlsAuthorityTransport


class PinnedTerminalC02RecoveryQueryV1:
    """One exact original attempt, resolved through the installed mTLS peer."""

    __slots__ = ("_transport", "_provisioning", "_handshake", "_grant",
                 "_namespace", "_request")

    def __init__(
        self, *, transport: MtlsAuthorityTransport,
        provisioning: AuthorityProvisioningRequest,
        handshake: AuthorityHandshake, grant: InstallationGrantV2,
        namespace: str, request: TerminalRecoveryReadRequestV1,
    ) -> None:
        if (type(transport) is not MtlsAuthorityTransport
                or type(provisioning) is not AuthorityProvisioningRequest
                or type(handshake) is not AuthorityHandshake
                or type(grant) is not InstallationGrantV2
                or type(request) is not TerminalRecoveryReadRequestV1):
            raise TypeError("installed terminal C02 query inputs required")
        transport.profile_for(provisioning.profile_id)
        key = request.original_key
        if (not handshake.valid_pairing()
                or grant.channel_binding_sha256 != handshake.channel_binding_sha256
                or grant.authority_id != handshake.installation_authority_id
                or (key.authority_id, key.authority_namespace, key.installation_id) !=
                   (grant.authority_id, namespace, grant.installation_id)):
            raise RuntimeError("terminal C02 query installation binding differs")
        self._transport = transport
        self._provisioning = provisioning
        self._handshake = handshake
        self._grant = grant
        self._namespace = namespace
        self._request = request

    @property
    def request(self) -> TerminalRecoveryReadRequestV1:
        return self._request

    async def query_finished(self) -> TerminalRecoveryReadFactV1:
        attempt, fact = await self._transport.terminal_c02_recovery_query_v1(
            self._provisioning, self._handshake, self._grant,
            namespace=self._namespace, read_request=self._request)
        if (attempt is None or attempt.state != "finished"
                or attempt.request != self._request
                or type(fact) is not TerminalRecoveryReadFactV1
                or fact.request != self._request
                or fact.permit_digest != attempt.permit_digest
                or fact.result_digest != attempt.result_digest
                or fact.result_digest != self._request.original_key.stable_result_digest):
            raise RuntimeError("pinned terminal C02 read is not finished")
        return fact


__all__ = ("PinnedTerminalC02RecoveryQueryV1",)
