"""Narrow, in-process Owner command port for an installed v2 Authority peer.

This is not a cold-install CLI or a private-key loader.  A caller must supply
the live, installed V2FencePort and an Owner user Ed25519 key held outside the
ordinary plugin database.  Authority, not this port, verifies that key against
its current pairing.  No Authority database path or self-asserted proof enters.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..graph_coordinator import namespace_ref
from ..host.owner_issue_orchestration import FirstOwnerIssueOrchestrator
from ..host.owner_revoke_orchestration import OwnerRevokeOrchestrator
from ..host.v2_fence_port import V2FencePort
from ..runtime_contracts import NamespaceId
from .v2_owner_contract import (
    OwnerAuthorizationOperationV1, OwnerAuthorizationReceiptV1, OwnerClaimTicketV1,
)
from .v2_owner_session import (
    OwnerSessionLoginChallengeV1, OwnerSessionLoginRequestV1,
)


class OwnerCommandHold(RuntimeError):
    """The installed Owner command prerequisites are unavailable."""


class InstalledOwnerCommandPortV1:
    """Sign one-use login challenges and invoke existing installed graph flows.

    The key object is caller-owned and never serialized or persisted here.  An
    installer-owned user-key loader is still needed before a standalone command
    can construct this port without a frontend.
    """

    def __init__(self, *, port: V2FencePort, namespace: NamespaceId,
                 login_request: OwnerSessionLoginRequestV1,
                 owner_user_key: Ed25519PrivateKey,
                 issue_flow: FirstOwnerIssueOrchestrator | None = None,
                 revoke_flow: OwnerRevokeOrchestrator | None = None) -> None:
        if (type(port) is not V2FencePort or type(namespace) is not NamespaceId
                or type(login_request) is not OwnerSessionLoginRequestV1
                or not isinstance(owner_user_key, Ed25519PrivateKey)):
            raise OwnerCommandHold("installed Owner peer and user signing key required")
        grant = port.installation_grant
        if (login_request.authority_namespace != namespace_ref(namespace)
                or login_request.authority_id != grant.authority_id
                or login_request.installation_id != grant.installation_id
                or login_request.audience != "sylanne-owner-console"):
            raise OwnerCommandHold("Owner login differs from installed Authority identity")
        self._port = port
        self._namespace = namespace
        self._request = login_request
        self._key = owner_user_key
        self._issue = issue_flow
        self._revoke = revoke_flow
        self._token: str | None = None

    def login(self) -> bool:
        """Acquire a fresh Authority challenge; never print or persist its token."""
        self._token = None
        namespace = self._namespace
        authority_namespace = namespace_ref(namespace)
        challenge = self._port.begin_owner_session(
            namespace=namespace, authority_namespace=authority_namespace,
            request=self._request)
        if (type(challenge) is not OwnerSessionLoginChallengeV1
                or challenge.request != self._request):
            raise OwnerCommandHold("Authority challenge identity differs")
        signature = self._key.sign(challenge.signed_bytes())
        if type(signature) is not bytes or len(signature) != 64:
            raise OwnerCommandHold("Owner user key did not produce an Ed25519 signature")
        token = self._port.accept_owner_session(
            namespace=namespace, authority_namespace=authority_namespace,
            challenge=challenge, signature=signature)
        if not self._port.current_owner_session(
                namespace=namespace, authority_namespace=authority_namespace,
                request=self._request, token=token):
            raise OwnerCommandHold("Authority did not establish a current Owner session")
        self._token = token
        return True

    def inspect(self) -> bool:
        """Read current session state from Authority; a stale token is discarded."""
        token = self._token
        if token is None:
            return False
        current = self._port.current_owner_session(
            namespace=self._namespace, authority_namespace=namespace_ref(self._namespace),
            request=self._request, token=token)
        if current:
            described = self._port.describe_owner_session(
                namespace=self._namespace,
                authority_namespace=namespace_ref(self._namespace), token=token)
            if described != self._request:
                self._token = None
                raise OwnerCommandHold("Authority Owner session description differs")
        else:
            self._token = None
        return current is True

    def _current_token(self) -> str:
        if not self.inspect() or self._token is None:
            raise OwnerCommandHold("current Authority Owner session required")
        return self._token

    async def issue(self, *, ticket: OwnerClaimTicketV1,
                    operation: OwnerAuthorizationOperationV1,
                    grant_value: dict) -> OwnerAuthorizationReceiptV1:
        """Use the installed Authority→graph→Authority first-issue flow."""
        token = self._current_token()
        flow = self._issue
        if (type(flow) is not FirstOwnerIssueOrchestrator
                or flow._namespace != self._namespace
                or flow._claimant is not self._port
                or flow._registration is not self._port):
            raise OwnerCommandHold("installed first-Owner issue flow required")
        receipt = await flow.issue(
            ticket=ticket, operation=operation, grant_value=grant_value,
            owner_session_token=token, owner_session_request=self._request)
        if (type(receipt) is not OwnerAuthorizationReceiptV1
                or receipt.operation != operation or receipt.phase != "committed"):
            raise OwnerCommandHold("first-Owner issue did not commit")
        return receipt

    async def revoke(self, *, operation_id: str) -> OwnerAuthorizationReceiptV1:
        """Use the installed original-identity revoke flow."""
        token = self._current_token()
        flow = self._revoke
        if (type(flow) is not OwnerRevokeOrchestrator
                or flow._namespace != self._namespace
                or flow._port is not self._port):
            raise OwnerCommandHold("installed Owner revoke flow required")
        receipt = await flow.revoke(
            operation_id=operation_id, owner_session_token=token,
            owner_session_request=self._request)
        if (type(receipt) is not OwnerAuthorizationReceiptV1
                or receipt.operation.operation_id != operation_id
                or receipt.phase != "committed"):
            raise OwnerCommandHold("Owner revoke did not commit")
        return receipt


__all__ = ("InstalledOwnerCommandPortV1", "OwnerCommandHold")
