from __future__ import annotations

from dataclasses import replace

import pytest
import pytest_asyncio

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerPrincipalV1,
)
from sylanne3.authority_service.v2_owner_session import (
    OwnerSessionLoginChallengeV1, OwnerSessionLoginRequestV1,
)
from sylanne3.graph_coordinator import (
    CurrentOwnerViewV1, OwnerLeaseBindingV1, namespace_ref,
)
from sylanne3.graph_worker import GraphWorker
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api.http_transport import CurrentOwnerDashboardSessions
from sylanne3.workbench_api.owner_session_resolver import BoundOwnerSessions


NAMESPACE = NamespaceId("bot-alpha", "persona-alpha")
PRINCIPAL = OwnerPrincipalV1("paired-idp", "owner-account", "incarnation-1")
ORIGIN = "https://dashboard.local"
TOKEN = "T" * 43
REQUEST = OwnerSessionLoginRequestV1(
    "authority", namespace_ref(NAMESPACE), "installation", PRINCIPAL,
    "credential", 1, "owner", ORIGIN)
CHALLENGE = OwnerSessionLoginChallengeV1(
    REQUEST, "N" * 43, 0, "B" * 43,
    "2026-09-24T00:00:00Z", "2026-09-24T00:05:00Z")
GUARD = OwnerAuthorizationGuardV1(
    "authority", "installation", NAMESPACE,
    1, "sha256:" + "a" * 64, 0, 0)
BINDING = OwnerLeaseBindingV1(
    principal=PRINCIPAL, actor="owner-actor", namespace=NAMESPACE,
    purpose="workbench_view", audience="owner", grant_id="grant-1",
    scope="/".join(NAMESPACE.as_tuple), issuer_ref="issuer", capabilities=frozenset({
        "workbench.read", "workbench.create"}),
    purposes=frozenset({"workbench_view", "workbench_user_action"}),
    audiences=frozenset({"owner"}), grant_digest="sha256:" + "b" * 64,
    grant_revision=1, access_epoch=1, delete_epoch=0,
    graph_incarnation="graph:one", authorization_head=GUARD.authorization_head,
    authorization_revision=1, revocation_epoch=0)


class Request:
    def __init__(self, *, username="dashboard-a", origin=ORIGIN):
        self.username = username
        self.headers = {"origin": origin}


class Authority:
    def __init__(self):
        self.current = True
        self.logout_failure = False
        self.begun = 0
        self.accepted = 0
        self.described = 0

    def begin_owner_session(self, *, namespace, authority_namespace, request):
        assert (namespace, authority_namespace, request) == (
            NAMESPACE, namespace_ref(NAMESPACE), REQUEST)
        self.begun += 1
        return CHALLENGE

    def accept_owner_session(self, *, namespace, authority_namespace,
                             challenge, signature):
        assert (namespace, authority_namespace) == (NAMESPACE, namespace_ref(NAMESPACE))
        assert challenge == CHALLENGE
        if signature != b"s" * 64:
            raise RuntimeError("signature rejected")
        self.accepted += 1
        return TOKEN

    def describe_owner_session(self, *, namespace, authority_namespace, token):
        assert (namespace, authority_namespace) == (NAMESPACE, namespace_ref(NAMESPACE))
        self.described += 1
        if not self.current or token != TOKEN:
            raise RuntimeError("Owner session revoked")
        return REQUEST

    def logout_owner_session(self, *, namespace, authority_namespace, request, token):
        assert (namespace, authority_namespace, request, token) == (
            NAMESPACE, namespace_ref(NAMESPACE), REQUEST, TOKEN)
        if self.logout_failure:
            raise RuntimeError("Authority logout unavailable")
        self.current = False


class Coordinator:
    def __init__(self, bootstrap):
        self.bootstrap = bootstrap
        self.view = CurrentOwnerViewV1(GUARD, BINDING)
        self.reads = 0

    def read_current_owner_view(self, bootstrap, *, actor, namespace, purpose,
                                audience, expected_principal,
                                owner_session_token, owner_session_request):
        assert bootstrap is self.bootstrap
        assert (actor, namespace, purpose, audience, expected_principal) == (
            "owner-actor", NAMESPACE, "workbench_view", "owner", PRINCIPAL)
        assert (owner_session_token, owner_session_request) == (TOKEN, REQUEST)
        self.reads += 1
        return self.view


class Store:
    def close(self):
        pass


@pytest_asyncio.fixture
async def installed():
    authority, bootstrap = Authority(), object()
    coordinator = Coordinator(bootstrap)
    worker = await GraphWorker.start(Store, lambda _: coordinator)
    resolver = BoundOwnerSessions(
        authority=authority, worker=worker, bootstrap=bootstrap,
        owner_actor=lambda principal, namespace: "owner-actor"
        if (principal, namespace) == (PRINCIPAL, NAMESPACE) else None,
        namespace=NAMESPACE, authority_id="authority",
        installation_id="installation", origin=ORIGIN)
    try:
        yield resolver, authority, coordinator
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_signed_login_binds_current_owner_facts_to_one_dashboard_user(installed):
    resolver, authority, coordinator = installed
    assert await resolver.resolve_current_owner_session(
        username="dashboard-a", owner_session_token=TOKEN) is None
    assert await resolver.begin_signed_login(request=Request(), login_request=REQUEST) == CHALLENGE
    token = await resolver.complete_signed_login(
        request=Request(), challenge=CHALLENGE, signature=b"s" * 64)
    assert token == TOKEN and authority.accepted == 1
    paired = await resolver.resolve_current_owner_session(
        username="dashboard-a", owner_session_token=token)
    assert paired is not None
    assert paired.principal == PRINCIPAL and paired.guard == GUARD
    assert paired.session.actor_id == "owner-actor"
    assert paired.session.host_username == "dashboard-a"
    assert paired.session.owner_session_token == TOKEN
    assert paired.session.owner_session_request == REQUEST
    assert TOKEN not in repr(paired.session)
    assert paired.session.scope_capabilities["bot-alpha/persona-alpha"] == BINDING.capabilities
    assert coordinator.reads == 2 and authority.described == 2
    assert await resolver.resolve_current_owner_session(
        username="dashboard-b", owner_session_token=token) is None
    assert await resolver.resolve_current_owner_session(
        username="dashboard-a", owner_session_token="X" * 43) is None


@pytest.mark.asyncio
async def test_each_resolution_rechecks_authority_and_fenced_graph(installed):
    resolver, authority, coordinator = installed
    await resolver.begin_signed_login(request=Request(), login_request=REQUEST)
    await resolver.complete_signed_login(
        request=Request(), challenge=CHALLENGE, signature=b"s" * 64)
    paired = CurrentOwnerDashboardSessions(resolver)
    assert await paired.resolve(username="dashboard-a", session_hint=TOKEN) is not None
    coordinator.view = CurrentOwnerViewV1(
        replace(GUARD, pending_revoke_operation_id="revoke-1"), BINDING)
    assert await paired.resolve(username="dashboard-a", session_hint=TOKEN) is None
    coordinator.view = CurrentOwnerViewV1(GUARD, BINDING)
    authority.current = False
    assert await paired.resolve(username="dashboard-a", session_hint=TOKEN) is None


@pytest.mark.asyncio
async def test_local_logout_revokes_binding_even_if_authority_rpc_fails(installed):
    resolver, authority, _ = installed
    await resolver.begin_signed_login(request=Request(), login_request=REQUEST)
    await resolver.complete_signed_login(
        request=Request(), challenge=CHALLENGE, signature=b"s" * 64)
    authority.logout_failure = True
    with pytest.raises(RuntimeError, match="logout unavailable"):
        await resolver.revoke_bound_session(
            username="dashboard-a", owner_session_token=TOKEN)
    assert await resolver.resolve_current_owner_session(
        username="dashboard-a", owner_session_token=TOKEN) is None
    with pytest.raises(ValueError, match="same Dashboard user"):
        await resolver.complete_signed_login(
            request=Request(), challenge=CHALLENGE, signature=b"s" * 64)


@pytest.mark.asyncio
async def test_login_requires_authenticated_host_origin_and_real_graph_head(installed):
    resolver, authority, coordinator = installed
    with pytest.raises(ValueError, match="authenticated"):
        await resolver.complete_signed_login(
            request=Request(username=None), challenge=CHALLENGE,
            signature=b"s" * 64)
    with pytest.raises(ValueError, match="authenticated"):
        await resolver.complete_signed_login(
            request=Request(origin="https://evil.invalid"), challenge=CHALLENGE,
            signature=b"s" * 64)
    assert authority.accepted == 0
    await resolver.begin_signed_login(request=Request(), login_request=REQUEST)
    coordinator.view = CurrentOwnerViewV1(
        GUARD, replace(BINDING, principal=OwnerPrincipalV1(
            "other", "account", "incarnation")))
    with pytest.raises(RuntimeError, match="graph grant"):
        await resolver.complete_signed_login(
            request=Request(), challenge=CHALLENGE, signature=b"s" * 64)
    assert authority.current is False
    assert await resolver.resolve_current_owner_session(
        username="dashboard-a", owner_session_token=TOKEN) is None


@pytest.mark.asyncio
async def test_signed_challenge_cannot_be_redeemed_by_another_dashboard_user(installed):
    resolver, authority, _ = installed
    await resolver.begin_signed_login(request=Request(), login_request=REQUEST)
    with pytest.raises(ValueError, match="same Dashboard user"):
        await resolver.complete_signed_login(
            request=Request(username="dashboard-b"), challenge=CHALLENGE,
            signature=b"s" * 64)
    assert authority.accepted == 0
    assert await resolver.complete_signed_login(
        request=Request(), challenge=CHALLENGE, signature=b"s" * 64) == TOKEN
