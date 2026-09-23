"""The trusted host passes one Owner session through both issue phases."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from rewrite.tests.alpha1.authority.test_local_owner_round_trip import _owner_issue
from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationReceiptV1, OwnerGraphCommitProofV1, OwnerPrincipalV1,
)
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.graph_worker import GraphWorker
from sylanne3.host.owner_issue_orchestration import FirstOwnerIssueOrchestrator
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.runtime_contracts import NamespaceId


NAMESPACE = NamespaceId("bot", "persona")
AUTHORITY_NAMESPACE = namespace_ref(NAMESPACE)


class _Store:
    def close(self):
        pass


def _inputs():
    principal = OwnerPrincipalV1("dashboard", "account", "incarnation")
    creation = SimpleNamespace(
        operation_id="create", input_digest="a" * 64,
        graph_incarnation="graph-incarnation",
    )
    ticket, operation, value = _owner_issue(creation, "authority", principal)
    session = OwnerSessionLoginRequestV1(
        "authority", AUTHORITY_NAMESPACE, "installation", principal,
        "credential", 1, "sylanne-owner-console", "https://localhost:6185",
    )
    return ticket, operation, value, session


def test_session_is_forwarded_to_both_authority_phases(monkeypatch):
    ticket, operation, value, session = _inputs()
    calls = []
    registration = object.__new__(V2FencePort)
    claimant = object.__new__(V2FencePort)
    pending = OwnerAuthorizationReceiptV1(
        operation, "pending", "pending-ref", operation.expected_guard)
    committed_guard = replace(
        operation.expected_guard, authorization_revision=1,
        authorization_head="sha256:" + "b" * 64)
    committed = OwnerAuthorizationReceiptV1(
        operation, "committed", "committed-ref", committed_guard, 1, 1)
    proof = OwnerGraphCommitProofV1(
        NAMESPACE, operation.operation_id, operation.request_digest,
        operation.grant_id, operation.grant_digest, "graph-incarnation",
        1, 1, 1, "sha256:" + "c" * 64)

    def register(**kwargs):
        calls.append(("register", kwargs))
        return ticket

    def reserve(**kwargs):
        calls.append(("reserve", kwargs))
        return pending

    def finalize(**kwargs):
        calls.append(("finalize", kwargs))
        return committed

    monkeypatch.setattr(registration, "register_owner_ticket", register)
    monkeypatch.setattr(claimant, "reserve_owner_issue", reserve)
    monkeypatch.setattr(claimant, "finalize_owner_issue", finalize)

    async def scenario():
        worker = await GraphWorker.start(_Store, lambda _store: object())
        try:
            def graph_commit(_graph, operation_id, grant_value):
                assert operation_id == operation.operation_id
                assert grant_value == value
                calls.append(("graph", {}))
                return proof

            orchestrator = FirstOwnerIssueOrchestrator(
                namespace=NAMESPACE, graph_worker=worker,
                graph_commit=graph_commit, registration_port=registration,
                claimant_port=claimant)
            assert await orchestrator.issue(
                ticket=ticket, operation=operation, grant_value=value,
                owner_session_token="session-token",
                owner_session_request=session) == committed
            assert [name for name, _ in calls] == [
                "register", "reserve", "graph", "finalize"]
            for phase in (1, 3):
                assert calls[phase][1]["owner_session_token"] == "session-token"
                assert calls[phase][1]["owner_session_request"] == session

            calls.clear()
            for wrong_token, wrong_request in (
                ("session-token", None),
                (None, session),
                ("session-token", replace(session, principal=OwnerPrincipalV1(
                    "dashboard", "other-account", "incarnation"))),
                ("session-token", replace(session, authority_namespace="other")),
                ("session-token", replace(session, authority_id="other")),
                ("session-token", replace(session, installation_id="other")),
                ("session-token", replace(session, audience="other")),
            ):
                with pytest.raises(ValueError, match="Owner session"):
                    await orchestrator.issue(
                        ticket=ticket, operation=operation, grant_value=value,
                        owner_session_token=wrong_token,
                        owner_session_request=wrong_request)
            assert calls == []

            # The legacy path remains a paired claimant proof operation.
            assert await orchestrator.issue(
                ticket=ticket, operation=operation, grant_value=value) == committed
            assert calls[1][1]["owner_session_token"] is None
            assert calls[3][1]["owner_session_request"] is None
        finally:
            await worker.close()

    asyncio.run(scenario())
