"""Trusted first-Owner issue sequence across Authority and the graph worker.

Authority owns both claimant verification and final graph-proof verification.
This module never accepts a caller's proof verdict or makes a pending grant active.
The same ticket, operation and grant must be replayed after an uncertain outcome.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Callable

from ..authority_service.v2_owner_contract import (
    OwnerAuthorizationOperationV1, OwnerAuthorizationReceiptV1, OwnerClaimTicketV1,
    OwnerGraphCommitProofV1,
)
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_coordinator import namespace_ref
from ..graph_types import owner_grant_policy_digest_v1, validate_owner_grant_v1
from ..graph_worker import GraphWorker
from ..runtime_contracts import NamespaceId, canonical_digest
from .v2_fence_port import V2FencePort


class FirstOwnerIssueOrchestrator:
    """Issue one independently paired first Owner from trusted host composition.

    ``graph_commit`` is a host-bound synchronous closure that captures the
    GraphCoordinator bootstrap. Neither this class nor an HTTP request obtains
    that bootstrap or supplies an Authority verifier callback.
    """

    def __init__(self, *, namespace: NamespaceId, graph_worker: GraphWorker,
                 graph_commit: Callable[[object, str, dict], OwnerGraphCommitProofV1],
                 registration_port: V2FencePort, claimant_port: V2FencePort) -> None:
        if type(namespace) is not NamespaceId or not isinstance(graph_worker, GraphWorker):
            raise TypeError("first Owner issue requires a namespace and graph worker")
        if not callable(graph_commit):
            raise TypeError("first Owner issue requires a trusted graph commit")
        if (not isinstance(registration_port, V2FencePort)
                or not isinstance(claimant_port, V2FencePort)):
            raise TypeError("first Owner issue requires Authority v2 ports")
        self._namespace = namespace
        self._authority_namespace = namespace_ref(namespace)
        self._worker = graph_worker
        self._graph_commit = graph_commit
        self._registration = registration_port
        self._claimant = claimant_port

    async def issue(self, *, ticket: OwnerClaimTicketV1,
                    operation: OwnerAuthorizationOperationV1,
                    grant_value: dict,
                    owner_session_token: str | None = None,
                    owner_session_request: OwnerSessionLoginRequestV1 | None = None,
                    ) -> OwnerAuthorizationReceiptV1:
        """Register, reserve, commit and finalize one exact issue identity.

        Every phase is durable and replayable with the same inputs. Exceptions
        retain their source, including graph rejection and unknown fence outcome.
        A failed finalization leaves the graph proof pending at Authority until
        this exact operation is retried.
        """
        if (type(ticket) is not OwnerClaimTicketV1
                or type(operation) is not OwnerAuthorizationOperationV1
                or operation.action != "issue" or operation.ticket != ticket
                or ticket.namespace != self._namespace):
            raise ValueError("first Owner ticket and operation identity differ")
        if (owner_session_token is None) != (owner_session_request is None):
            raise ValueError("Owner session token and request must be supplied together")
        if owner_session_request is not None:
            if (type(owner_session_token) is not str or not owner_session_token
                    or type(owner_session_request) is not OwnerSessionLoginRequestV1
                    or owner_session_request.authority_id != ticket.authority_id
                    or owner_session_request.authority_namespace != self._authority_namespace
                    or owner_session_request.installation_id != ticket.installation_id
                    or owner_session_request.principal != ticket.principal
                    or owner_session_request.audience != "sylanne-owner-console"):
                raise ValueError("Owner session differs from first Owner issue identity")
        # The no-session path remains the Authority's paired-claimant proof mode.
        # A signed-session deployment requires both values and validates the
        # credential and token again inside each Authority write transaction.
        validate_owner_grant_v1(grant_value)
        if (grant_value["authority_id"] != operation.authority_id
                or grant_value["installation_id"] != operation.installation_id
                or grant_value["grant_id"] != operation.grant_id
                or grant_value["ticket_id"] != ticket.ticket_id
                or grant_value["creation_operation_id"] != ticket.creation_operation_id
                or grant_value["creation_digest"] != ticket.creation_digest
                or grant_value["issue_operation_id"] != operation.operation_id
                or grant_value["principal"] != {
                    "identity_provider": ticket.principal.identity_provider,
                    "account_ref": ticket.principal.account_ref,
                    "account_incarnation": ticket.principal.account_incarnation,
                }
                or operation.grant_digest != "sha256:" + canonical_digest(grant_value)
                or ticket.policy_digest != owner_grant_policy_digest_v1(
                    grant_value, bot=self._namespace.bot_id,
                    persona=self._namespace.persona_id)):
            raise ValueError("first Owner graph grant differs from paired claim")
        value = deepcopy(grant_value)
        namespace = self._namespace
        authority_namespace = self._authority_namespace
        registered = await self._worker.call(
            lambda _graph: self._registration.register_owner_ticket(
                namespace=namespace, authority_namespace=authority_namespace,
                ticket=ticket))
        if registered != ticket:
            raise RuntimeError("Authority registered a different Owner ticket")
        pending = await self._worker.call(
            lambda _graph: self._claimant.reserve_owner_issue(
                namespace=namespace, authority_namespace=authority_namespace,
                operation=operation, owner_session_token=owner_session_token,
                owner_session_request=owner_session_request))
        if (type(pending) is not OwnerAuthorizationReceiptV1
                or pending.operation != operation or pending.phase != "pending"):
            raise RuntimeError("Authority returned a different pending Owner issue")
        proof = await self._worker.call(self._graph_commit, operation.operation_id, value)
        if (type(proof) is not OwnerGraphCommitProofV1
                or proof.namespace != namespace
                or proof.operation_id != operation.operation_id
                or proof.request_digest != operation.request_digest
                or proof.grant_digest != operation.grant_digest):
            raise RuntimeError("graph returned a different Owner issue proof")
        committed = await self._worker.call(
            lambda _graph: self._claimant.finalize_owner_issue(
                namespace=namespace, authority_namespace=authority_namespace,
                operation=operation, proof=proof,
                owner_session_token=owner_session_token,
                owner_session_request=owner_session_request))
        if (type(committed) is not OwnerAuthorizationReceiptV1
                or committed.operation != operation or committed.phase != "committed"):
            raise RuntimeError("Authority returned a different Owner issue commit")
        return committed


__all__ = ("FirstOwnerIssueOrchestrator",)
