"""One original Owner revoke across the paired Authority and graph worker."""

from __future__ import annotations

from copy import deepcopy
from typing import Callable

from ..authority_service.v2_owner_contract import (
    OwnerAuthorizationOperationV1, OwnerAuthorizationReceiptV1,
    OwnerGraphCommitProofV1,
)
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_coordinator import GraphCoordinator, namespace_ref
from ..graph_worker import GraphWorker
from ..runtime_contracts import NamespaceId, canonical_digest
from .v2_fence_port import V2FencePort


class OwnerRevokeOrchestrator:
    """Use only installation-bound graph closures; callers supply an ID, not proof.

    ``freeze_original`` must read the current rev1 grant or its persisted
    original revoke intent after the graph has already committed rev2.
    ``graph_commit`` must obtain the current pending receipt under its own write
    fence, then commit the rev2 tombstone and return the graph's original proof.
    """

    def __init__(
        self, *, namespace: NamespaceId, graph_worker: GraphWorker,
        revoke_port: V2FencePort,
        freeze_original: Callable[[object, str], tuple[OwnerAuthorizationOperationV1, dict]],
        graph_commit: Callable[[object, str, dict], OwnerGraphCommitProofV1],
    ) -> None:
        if (type(namespace) is not NamespaceId
                or type(graph_worker) is not GraphWorker
                or type(revoke_port) is not V2FencePort
                or not callable(freeze_original) or not callable(graph_commit)):
            raise TypeError("installed Owner revoke composition is required")
        self._namespace = namespace
        self._authority_namespace = namespace_ref(namespace)
        self._worker = graph_worker
        self._port = revoke_port
        self._freeze_original = freeze_original
        self._graph_commit = graph_commit

    async def revoke(
        self, *, operation_id: str,
        owner_session_token: str | None = None,
        owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ) -> OwnerAuthorizationReceiptV1:
        if type(operation_id) is not str or not operation_id:
            raise ValueError("original Owner revoke operation ID is required")
        if (owner_session_token is None) != (owner_session_request is None):
            raise ValueError("Owner session token and request must be paired")
        namespace, authority_namespace = self._namespace, self._authority_namespace

        def read_committed(_graph):
            return self._port.get_committed_owner_revoke(
                namespace=namespace, authority_namespace=authority_namespace,
                operation_id=operation_id)

        committed_before = await self._worker.call(read_committed)
        if committed_before is not None:
            if (type(committed_before) is not OwnerAuthorizationReceiptV1
                    or committed_before.phase != "committed"
                    or committed_before.operation.action != "revoke"
                    or committed_before.operation.operation_id != operation_id
                    or committed_before.operation.namespace != namespace):
                raise RuntimeError("Authority committed Owner revoke differs")
            return committed_before
        if owner_session_token is None:
            pending_before = await self._worker.call(lambda _graph:
                self._port.get_pending_owner_revoke(
                    namespace=namespace, authority_namespace=authority_namespace,
                    operation_id=operation_id))
            if pending_before is None:
                raise RuntimeError(
                    "first Owner revoke reserve requires a current Owner session")
            if (type(pending_before) is not OwnerAuthorizationReceiptV1
                    or pending_before.phase != "pending"
                    or pending_before.operation.action != "revoke"
                    or pending_before.operation.operation_id != operation_id
                    or pending_before.operation.namespace != namespace):
                raise RuntimeError("Authority pending Owner revoke differs")
        frozen = await self._worker.call(self._freeze_original, operation_id)
        if type(frozen) is not tuple or len(frozen) != 2:
            raise RuntimeError("trusted Owner revoke freeze is unavailable")
        operation, tombstone = frozen
        if (type(operation) is not OwnerAuthorizationOperationV1
                or operation.action != "revoke" or operation.ticket is not None
                or operation.namespace != self._namespace
                or operation.operation_id != operation_id
                or operation.expected_grant_revision != 1
                or type(tombstone) is not dict
                or tombstone.get("grant_id") != operation.grant_id
                or tombstone.get("grant_revision") != 2
                or tombstone.get("state") != "revoked"
                or operation.grant_digest != "sha256:" + canonical_digest(tombstone)):
            raise RuntimeError("trusted Owner revoke tombstone differs")
        value = deepcopy(tombstone)
        def reserve(_graph):
            try:
                return self._port.reserve_owner_revoke(
                    namespace=namespace, authority_namespace=authority_namespace,
                    operation=operation, owner_session_token=owner_session_token,
                    owner_session_request=owner_session_request)
            except Exception:
                pending = self._port.get_pending_owner_revoke(
                    namespace=namespace, authority_namespace=authority_namespace,
                    operation_id=operation_id)
                if pending is None:
                    raise
                return pending

        pending = await self._worker.call(reserve)
        if (type(pending) is not OwnerAuthorizationReceiptV1
                or pending.operation != operation or pending.phase != "pending"
                or pending.guard.pending_revoke_operation_id != operation_id):
            raise RuntimeError("Authority pending Owner revoke differs")
        proof = await self._worker.call(self._graph_commit, operation_id, value)
        if (type(proof) is not OwnerGraphCommitProofV1
                or (proof.namespace, proof.operation_id, proof.request_digest,
                    proof.grant_id, proof.grant_digest, proof.grant_revision) != (
                    namespace, operation_id, operation.request_digest,
                    operation.grant_id, operation.grant_digest, 2)):
            raise RuntimeError("graph Owner revoke proof differs")

        def finalize(_graph):
            try:
                return self._port.finalize_owner_revoke(
                    namespace=namespace, authority_namespace=authority_namespace,
                    operation=operation, proof=proof,
                    owner_session_token=owner_session_token,
                    owner_session_request=owner_session_request)
            except Exception:
                committed = self._port.get_committed_owner_revoke(
                    namespace=namespace, authority_namespace=authority_namespace,
                    operation_id=operation_id)
                if committed is None:
                    raise
                return committed

        committed = await self._worker.call(finalize)
        if (type(committed) is not OwnerAuthorizationReceiptV1
                or committed.phase != "committed"
                or committed.operation != operation
                or committed.grant_revision != 2
                or committed.graph_access_epoch != proof.graph_access_epoch):
            raise RuntimeError("Authority committed Owner revoke differs")
        return committed


def installed_owner_revoke_orchestrator_v2(
    *, graph: GraphCoordinator, bootstrap: object, namespace: NamespaceId,
    graph_worker: GraphWorker, revoke_port: V2FencePort,
) -> OwnerRevokeOrchestrator:
    """Bind the actual coordinator, bootstrap and paired port once at install."""
    if (type(graph) is not GraphCoordinator
            or getattr(graph, "_GraphCoordinator__content_fence_v2", None)
               is not revoke_port):
        raise ValueError("Owner revoke requires the installed graph fence port")

    def freeze(current_graph, operation_id):
        if current_graph is not graph:
            raise RuntimeError("Owner revoke graph worker changed")
        return graph.freeze_current_owner_revoke_v2(
            bootstrap, namespace=namespace, operation_id=operation_id)

    def commit(current_graph, operation_id, tombstone):
        if current_graph is not graph:
            raise RuntimeError("Owner revoke graph worker changed")
        return graph.commit_owner_revoke_v2(
            bootstrap, namespace=namespace, operation_id=operation_id,
            grant_value=tombstone)

    return OwnerRevokeOrchestrator(
        namespace=namespace, graph_worker=graph_worker,
        revoke_port=revoke_port, freeze_original=freeze, graph_commit=commit)


__all__ = ("OwnerRevokeOrchestrator", "installed_owner_revoke_orchestrator_v2")
