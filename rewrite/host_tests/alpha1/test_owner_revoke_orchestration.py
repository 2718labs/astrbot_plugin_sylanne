"""A committed Owner revoke replays without requiring its vanished rev1 head."""

import asyncio

import pytest

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerAuthorizationOperationV1,
    OwnerAuthorizationReceiptV1, OwnerPrincipalV1,
)
from sylanne3.host.owner_revoke_orchestration import OwnerRevokeOrchestrator
from sylanne3.runtime_contracts import NamespaceId


def test_committed_owner_revoke_recovers_before_old_graph_freeze():
    namespace = NamespaceId("bot-replay", "persona-replay")
    active = OwnerAuthorizationGuardV1(
        "authority-replay", "installation-replay", namespace, 1,
        "sha256:" + "a" * 64, 0, 0)
    operation = OwnerAuthorizationOperationV1(
        "revoke", "owner-revoke-replay", "authority-replay",
        "installation-replay", namespace,
        OwnerPrincipalV1("provider", "account", "incarnation"),
        "grant-replay", "sha256:" + "b" * 64, 1, active)
    revoked = OwnerAuthorizationGuardV1(
        "authority-replay", "installation-replay", namespace, 2,
        "sha256:" + "c" * 64, 2, 2)
    receipt = OwnerAuthorizationReceiptV1(
        operation, "committed", "owner-revoke-receipt", revoked, 2, 2)

    class Worker:
        async def call(self, callback, *args):
            return callback(object(), *args)

    class Port:
        def get_committed_owner_revoke(self, **kwargs):
            assert kwargs["operation_id"] == operation.operation_id
            assert "owner_session_token" not in kwargs
            assert "owner_session_request" not in kwargs
            return receipt

    orchestrator = object.__new__(OwnerRevokeOrchestrator)
    orchestrator._namespace = namespace
    orchestrator._authority_namespace = "/".join(namespace.as_tuple)
    orchestrator._worker = Worker()
    orchestrator._port = Port()
    orchestrator._freeze_original = lambda *_: (_ for _ in ()).throw(
        AssertionError("committed replay must not require original rev1 graph"))
    assert asyncio.run(orchestrator.revoke(operation_id=operation.operation_id)) == receipt

    class NoOriginalPort:
        def get_committed_owner_revoke(self, **_kwargs):
            return None

        def get_pending_owner_revoke(self, **_kwargs):
            return None

    orchestrator._port = NoOriginalPort()
    with pytest.raises(RuntimeError, match="current Owner session"):
        asyncio.run(orchestrator.revoke(operation_id="fresh-owner-revoke"))
