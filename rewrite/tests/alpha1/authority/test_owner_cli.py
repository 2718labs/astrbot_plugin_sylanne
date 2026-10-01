"""Controlled installed-port tests; no OS key loader or cold installation is claimed."""

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.owner_cli import (
    InstalledOwnerCommandPortV1, OwnerCommandHold,
)
from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginChallengeV1,
    OwnerSessionLoginRequestV1,
)
from sylanne3.authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
)
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")
REQUEST = OwnerSessionLoginRequestV1(
    "authority", namespace_ref(NS), "installation",
    OwnerPrincipalV1("local-owner", "account", "incarnation"),
    "owner-key", 1, "sylanne-owner-console", "http://localhost:8765",
)
CHALLENGE = OwnerSessionLoginChallengeV1(
    REQUEST, "A" * 43, 0, "B" * 43,
    "2029-01-01T00:00:00Z", "2029-01-01T00:01:00Z",
)


def _controlled_port(monkeypatch, *, challenge=CHALLENGE):
    port = object.__new__(V2FencePort)
    state = {"current": True, "accepted": False}
    monkeypatch.setattr(V2FencePort, "installation_grant", property(
        lambda _self: SimpleNamespace(authority_id="authority",
                                      installation_id="installation")))
    monkeypatch.setattr(V2FencePort, "begin_owner_session", lambda _self, **kw: challenge)

    def accept(_self, **kw):
        state["key"].public_key().verify(
            kw["signature"], kw["challenge"].signed_bytes())
        state["accepted"] = True
        return "C" * 43

    monkeypatch.setattr(V2FencePort, "accept_owner_session", accept)
    monkeypatch.setattr(V2FencePort, "current_owner_session",
                        lambda _self, **kw: state["current"])
    monkeypatch.setattr(V2FencePort, "describe_owner_session",
                        lambda _self, **kw: state.get("description", REQUEST))
    return port, state


def test_installed_owner_login_signs_exact_authority_challenge_and_checks_current(
        monkeypatch):
    port, state = _controlled_port(monkeypatch)
    key = Ed25519PrivateKey.generate()
    state["key"] = key
    command = InstalledOwnerCommandPortV1(
        port=port, namespace=NS, login_request=REQUEST, owner_user_key=key)
    assert command.inspect() is False
    assert command.login() is True
    assert state["accepted"] is True
    assert command.inspect() is True
    state["description"] = OwnerSessionLoginRequestV1(
        REQUEST.authority_id, REQUEST.authority_namespace, REQUEST.installation_id,
        REQUEST.principal, "other-key", REQUEST.credential_epoch,
        REQUEST.audience, REQUEST.dashboard_origin)
    with pytest.raises(OwnerCommandHold, match="description differs"):
        command.inspect()
    assert command._token is None
    command.login()
    state["description"] = REQUEST
    state["current"] = False
    assert command.inspect() is False
    assert command._token is None


def test_owner_command_rejects_crossed_challenge_and_installation(monkeypatch):
    wrong_request = OwnerSessionLoginRequestV1(
        REQUEST.authority_id, REQUEST.authority_namespace, REQUEST.installation_id,
        REQUEST.principal, "other-key", REQUEST.credential_epoch,
        REQUEST.audience, REQUEST.dashboard_origin)
    wrong_challenge = OwnerSessionLoginChallengeV1(
        wrong_request, CHALLENGE.nonce, CHALLENGE.principal_epoch,
        CHALLENGE.boot_id, CHALLENGE.issued_at_utc, CHALLENGE.expires_at_utc)
    port, state = _controlled_port(monkeypatch, challenge=wrong_challenge)
    key = Ed25519PrivateKey.generate()
    state["key"] = key
    command = InstalledOwnerCommandPortV1(
        port=port, namespace=NS, login_request=REQUEST, owner_user_key=key)
    with pytest.raises(OwnerCommandHold, match="challenge identity"):
        command.login()
    assert state["accepted"] is False
    with pytest.raises(OwnerCommandHold, match="installed Authority identity"):
        InstalledOwnerCommandPortV1(
            port=port, namespace=NS, login_request=wrong_request.__class__(
                wrong_request.authority_id, wrong_request.authority_namespace,
                "other-installation", wrong_request.principal,
                wrong_request.credential_id, wrong_request.credential_epoch,
                wrong_request.audience, wrong_request.dashboard_origin),
            owner_user_key=key)


def test_issue_and_revoke_hold_without_installed_graph_flows(monkeypatch):
    port, state = _controlled_port(monkeypatch)
    key = Ed25519PrivateKey.generate()
    state["key"] = key
    command = InstalledOwnerCommandPortV1(
        port=port, namespace=NS, login_request=REQUEST, owner_user_key=key)
    command.login()
    with pytest.raises(OwnerCommandHold, match="issue flow"):
        asyncio.run(command.issue(ticket=None, operation=None, grant_value={}))
    with pytest.raises(OwnerCommandHold, match="revoke flow"):
        asyncio.run(command.revoke(operation_id="original-revoke"))


def test_owner_command_rejects_uninstalled_peer_and_key(monkeypatch):
    port, state = _controlled_port(monkeypatch)
    state["key"] = Ed25519PrivateKey.generate()
    with pytest.raises(OwnerCommandHold, match="installed Owner peer"):
        InstalledOwnerCommandPortV1(
            port=object(), namespace=NS, login_request=REQUEST,
            owner_user_key=state["key"])
    with pytest.raises(OwnerCommandHold, match="installed Owner peer"):
        InstalledOwnerCommandPortV1(
            port=port, namespace=NS, login_request=REQUEST,
            owner_user_key=object())


def test_owner_command_login_against_initialized_authority_session_store(
        tmp_path, monkeypatch):
    """Real Authority challenge/key verification; transport bridge is controlled."""
    authority_ns = namespace_ref(NS)
    core = AuthorityServiceCore(
        tmp_path / "authority.sqlite", create=True,
        authorizer=lambda credential, action, namespace, _holder: (
            credential == "installed-peer" and namespace == authority_ns
            and action in {"owner_pair", "owner_session"}),
        deletion_verifier=lambda *_: True, execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True, dispatch_verifier=lambda *_: True)
    try:
        with core._tx() as db:
            db.execute("INSERT INTO authority_meta(key,value) VALUES('service_mode','v2-only')")
            db.execute("INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (authority_ns, "holder", 1, "active", None, None, 0,
                        "deletion", 0, "genesis", "clear", "execution", 0,
                        "genesis", "nonce"))
            authority_id = core._id(db)
        key = Ed25519PrivateKey.generate()
        proof = AuthorityV2OwnerProofStore(
            core, pairing_verifier=lambda *_: True, create=True)
        request = OwnerSessionLoginRequestV1(
            authority_id, authority_ns, "installation", REQUEST.principal,
            "owner-key", 1, "sylanne-owner-console", REQUEST.dashboard_origin)
        registration = OwnerCredentialRegistrationV1(
            authority_id, authority_ns, "installation", REQUEST.principal,
            "owner-key", 1,
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "enroll-1")
        proof.register_credential(
            transport_credential="installed-peer", registration=registration)
        sessions = AuthorityV2OwnerSessionStore(
            core, utc_clock=lambda: datetime.now(timezone.utc), create=True)
        port = object.__new__(V2FencePort)
        monkeypatch.setattr(V2FencePort, "installation_grant", property(
            lambda _self: SimpleNamespace(authority_id=authority_id,
                                          installation_id="installation")))
        monkeypatch.setattr(V2FencePort, "begin_owner_session", lambda _self, **kw:
                            sessions.begin_login(
                                transport_credential="installed-peer",
                                request=kw["request"]))
        monkeypatch.setattr(V2FencePort, "accept_owner_session", lambda _self, **kw:
                            sessions.accept_login(
                                transport_credential="installed-peer",
                                challenge=kw["challenge"], signature=kw["signature"]))

        def current(_self, **kw):
            try:
                sessions.require_current(
                    transport_credential="installed-peer", token=kw["token"],
                    request=kw["request"])
            except AuthorityUnavailable:
                return False
            return True

        monkeypatch.setattr(V2FencePort, "current_owner_session", current)
        monkeypatch.setattr(V2FencePort, "describe_owner_session", lambda _self, **kw:
                            sessions.describe_current(
                                transport_credential="installed-peer",
                                namespace=authority_ns,
                                installation_id="installation", token=kw["token"]))
        wrong = InstalledOwnerCommandPortV1(
            port=port, namespace=NS, login_request=request,
            owner_user_key=Ed25519PrivateKey.generate())
        with pytest.raises(AuthorityUnavailable):
            wrong.login()
        command = InstalledOwnerCommandPortV1(
            port=port, namespace=NS, login_request=request, owner_user_key=key)
        assert command.login() is True
        assert command.inspect() is True
    finally:
        core.close()
