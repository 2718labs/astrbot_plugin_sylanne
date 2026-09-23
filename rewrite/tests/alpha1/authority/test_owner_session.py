"""Independent Owner login, revocation and transaction-scoped admission."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import os
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_proof import (
    AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1,
)
from sylanne3.authority_service.v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
)


NAMESPACE = "bot:owner-session"
PRINCIPAL = OwnerPrincipalV1("dashboard", "account-17", "incarnation-3")


class Clock:
    now = datetime(2029, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def core_at(path, *, create=False):
    core = AuthorityServiceCore(
        path,
        authorizer=lambda credential, action, namespace, _: (
            credential == "installed-peer" and namespace == NAMESPACE
            and action in {"owner_pair", "owner_session", "owner_session_revoke"}
        ),
        deletion_verifier=lambda *_: True,
        execution_verifier=lambda *_: True,
        effect_verifier=lambda *_: True,
        dispatch_verifier=lambda *_: True,
        create=create,
    )
    if create:
        with core._tx() as db:
            db.execute("INSERT INTO authority_meta(key,value) VALUES('service_mode','v2-only')")
            db.execute(
                "INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (NAMESPACE, "holder", 1, "active", None, None, 0,
                 "deletion", 0, "genesis", "clear", "execution", 0, "genesis", "nonce"),
            )
    return core


def setup(path):
    core = core_at(path, create=True)
    clock = Clock()
    key = Ed25519PrivateKey.generate()
    proof = AuthorityV2OwnerProofStore(
        core, utc_clock=clock, pairing_verifier=lambda *_: True, create=True,
    )
    with core._tx() as db:
        authority_id = core._id(db)
    registration = OwnerCredentialRegistrationV1(
        authority_id, NAMESPACE, "installation-a", PRINCIPAL, "owner-key-1", 1,
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "enroll-1",
    )
    proof.register_credential(transport_credential="installed-peer", registration=registration)
    request = OwnerSessionLoginRequestV1(
        authority_id, NAMESPACE, "installation-a", PRINCIPAL, "owner-key-1", 1,
        "sylanne-owner-console", "http://localhost:6185",
    )
    sessions = AuthorityV2OwnerSessionStore(core, utc_clock=clock, create=True)
    return core, clock, key, proof, request, sessions


def login(sessions, key, request):
    challenge = sessions.begin_login(transport_credential="installed-peer", request=request)
    token = sessions.accept_login(
        transport_credential="installed-peer", challenge=challenge,
        signature=key.sign(challenge.signed_bytes()),
    )
    return challenge, token


def test_login_requires_registered_key_and_single_use_challenge(tmp_path):
    core, _, key, _, request, sessions = setup(tmp_path / "authority.db")
    try:
        challenge, token = login(sessions, key, request)
        assert sessions.require_current(transport_credential="installed-peer", token=token,
                                        request=request) == request
        with pytest.raises(AuthorityUnavailable):
            sessions.accept_login(transport_credential="installed-peer", challenge=challenge,
                                  signature=key.sign(challenge.signed_bytes()))
        with pytest.raises(AuthorityUnavailable):
            sessions.accept_login(transport_credential="installed-peer", challenge=challenge,
                                  signature=Ed25519PrivateKey.generate().sign(challenge.signed_bytes()))
        for changed in (
            replace(request, principal=OwnerPrincipalV1("dashboard", "account-17", "incarnation-4")),
            replace(request, dashboard_origin="https://other.example"),
            replace(request, audience="other-console"),
        ):
            with pytest.raises(AuthorityUnavailable):
                sessions.require_current(transport_credential="installed-peer", token=token,
                                         request=changed)
        with pytest.raises(AuthorityUnavailable):
            sessions.begin_login(transport_credential="installed-peer",
                                 request=replace(request, credential_id="unregistered"))
    finally:
        core.close()


def test_logout_revoke_all_and_key_revoke_apply_in_same_transaction(tmp_path):
    core, _, key, _, request, sessions = setup(tmp_path / "authority.db")
    try:
        _, first = login(sessions, key, request)
        sessions.logout(transport_credential="installed-peer", token=first, request=request)
        with pytest.raises(AuthorityUnavailable):
            sessions.require_current(transport_credential="installed-peer", token=first,
                                     request=request)
        _, second = login(sessions, key, request)
        assert sessions.describe_current(
            transport_credential="installed-peer", namespace=NAMESPACE,
            installation_id="installation-a", token=second) == request
        with pytest.raises(AuthorityUnavailable):
            sessions.describe_current(
                transport_credential="installed-peer", namespace=NAMESPACE,
                installation_id="other-installation", token=second)
        pending = sessions.begin_login(transport_credential="installed-peer", request=request)
        sessions.revoke_all(transport_credential="installed-peer", token=second,
                            request=request)
        with pytest.raises(AuthorityUnavailable):
            sessions.accept_login(transport_credential="installed-peer", challenge=pending,
                                  signature=key.sign(pending.signed_bytes()))
        with pytest.raises(AuthorityUnavailable):
            with core._tx() as db:
                sessions.require_current_in_tx(db, token=second, request=request)
        with pytest.raises(AuthorityUnavailable):
            sessions.describe_current(
                transport_credential="installed-peer", namespace=NAMESPACE,
                installation_id="installation-a", token=second)
        _, third = login(sessions, key, request)
        sessions.revoke_credential(transport_credential="installed-peer", token=third,
                                   request=request)
        with pytest.raises(AuthorityUnavailable):
            sessions.require_current(transport_credential="installed-peer", token=third,
                                     request=request)
        with pytest.raises(AuthorityUnavailable):
            sessions.begin_login(transport_credential="installed-peer", request=request)
    finally:
        core.close()


def test_expired_challenge_rotation_and_restart_fail_closed(tmp_path):
    path = tmp_path / "authority.db"
    core, clock, key, proof, request, sessions = setup(path)
    try:
        challenge = sessions.begin_login(transport_credential="installed-peer", request=request,
                                         ttl_seconds=2)
        clock.now += timedelta(seconds=3)
        with pytest.raises(AuthorityUnavailable):
            sessions.accept_login(transport_credential="installed-peer", challenge=challenge,
                                  signature=key.sign(challenge.signed_bytes()))
        _, token = login(sessions, key, request)
        rotated = Ed25519PrivateKey.generate()
        registration = OwnerCredentialRegistrationV1(
            request.authority_id, NAMESPACE, request.installation_id, request.principal,
            "owner-key-2", 2,
            rotated.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "enroll-2",
        )
        proof.register_credential(
            transport_credential="installed-peer", registration=registration,
            rotation_signature=key.sign(registration.rotation_bytes()),
        )
        with pytest.raises(AuthorityUnavailable):
            sessions.require_current(transport_credential="installed-peer", token=token,
                                     request=request)
        new_request = replace(request, credential_id="owner-key-2", credential_epoch=2)
        _, new_token = login(sessions, rotated, new_request)
    finally:
        core.close()
    script = """
import sys
from datetime import datetime, timezone
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1
core = AuthorityServiceCore(
    sys.argv[1], authorizer=lambda credential, action, namespace, _: credential == 'installed-peer',
    deletion_verifier=lambda *_: True, execution_verifier=lambda *_: True,
    effect_verifier=lambda *_: True, dispatch_verifier=lambda *_: True,
)
try:
    with core._tx() as db:
        authority_id = core._id(db)
    store = AuthorityV2OwnerSessionStore(core, utc_clock=lambda: datetime(2029, 1, 1, 0, 0, 3, tzinfo=timezone.utc))
    request = OwnerSessionLoginRequestV1(
        authority_id, 'bot:owner-session', 'installation-a',
        OwnerPrincipalV1('dashboard', 'account-17', 'incarnation-3'),
        'owner-key-2', 2, 'sylanne-owner-console', 'http://localhost:6185',
    )
    try:
        store.require_current(transport_credential='installed-peer', token=sys.stdin.read(), request=request)
    except AuthorityUnavailable:
        sys.exit(0)
    sys.exit(9)
finally:
    core.close()
"""
    child = subprocess.run(
        [sys.executable, "-c", script, str(path)], input=new_token, text=True,
        capture_output=True, check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[3])},
    )
    assert child.returncode == 0, child.stderr
    core = core_at(path)
    try:
        AuthorityV2OwnerSessionStore(core, utc_clock=clock)
        with pytest.raises(AuthorityUnavailable):
            AuthorityV2OwnerSessionStore(core, utc_clock=clock).require_current(
                transport_credential="installed-peer", token=new_token, request=new_request,
            )
    finally:
        core.close()


def test_final_check_serializes_with_revoke_and_challenge_race(tmp_path):
    core, _, key, _, request, sessions = setup(tmp_path / "authority.db")
    try:
        challenge = sessions.begin_login(transport_credential="installed-peer", request=request)

        def accept():
            return sessions.accept_login(
                transport_credential="installed-peer", challenge=challenge,
                signature=key.sign(challenge.signed_bytes()),
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = [pool.submit(accept) for _ in range(2)]
            results = []
            for outcome in outcomes:
                try:
                    results.append(outcome.result())
                except AuthorityUnavailable:
                    pass
        assert len(results) == 1
        token = results[0]
        started = Event()

        def revoke():
            started.set()
            sessions.revoke_all(transport_credential="installed-peer", token=token,
                                request=request)

        with ThreadPoolExecutor(max_workers=1) as pool:
            with core._tx() as db:
                sessions.require_current_in_tx(db, token=token, request=request)
                future = pool.submit(revoke)
                assert started.wait(timeout=5)
                assert not future.done()
                db.execute("INSERT INTO authority_meta(key,value) VALUES('race-write','committed')")
            future.result(timeout=5)
        with pytest.raises(AuthorityUnavailable):
            sessions.require_current(transport_credential="installed-peer", token=token,
                                     request=request)
    finally:
        core.close()
