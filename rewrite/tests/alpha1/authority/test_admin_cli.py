"""Controlled CLI method tests over an actual initialized Authority SQLite DB.

The daemon object is assembled without an OS lock or listener here, and the
Windows-token probe is replaced. This proves command/DB behavior, not a cold
installed administrator process or Windows token qualification.
"""

from dataclasses import replace
from datetime import datetime, timezone
import io
import json
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from sylanne3.authority_service import admin_cli
from sylanne3.authority_service.admin_cli import (
    AdminCliHold, AdminOwnerCommandV1, run_installed_admin_command_v1,
)
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.daemon import AuthorityDaemon
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
from sylanne3.authority_service.v2_owner_contract import (
    OwnerActorBindingV1, OwnerClaimTicketV1, OwnerPrincipalV1, to_wire,
)
from sylanne3.authority_service.v2_owner_proof import OwnerCredentialRegistrationV1
from sylanne3.authority_service.v2_owner_proof import to_wire as proof_to_wire
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")
AUTH_NS = namespace_ref(NS)
PROFILE = "installed-profile"
INSTALLATION = "installation"
CERT = "b" * 64
ADMIN = object()
NOW = datetime(2029, 1, 1, tzinfo=timezone.utc)
EXPIRY = datetime(2030, 1, 1, tzinfo=timezone.utc)
PRINCIPAL = OwnerPrincipalV1("local-owner", "account-1", "incarnation-1")


def _authorizer(credential, action, namespace, holder):
    return (credential is ADMIN and namespace == AUTH_NS and holder is None
            and action in {"owner_identity_pair", "owner_identity_revoke"})


@pytest.fixture
def installed_controlled_daemon(tmp_path, monkeypatch):
    path = tmp_path / "authority.sqlite"
    core = AuthorityServiceCore(
        path, create=True, authorizer=_authorizer,
        deletion_verifier=lambda *_: False, execution_verifier=lambda *_: False,
        effect_verifier=lambda *_: False, dispatch_verifier=lambda *_: False,
    )
    with core._tx() as db:
        db.execute("INSERT INTO authority_meta(key,value) VALUES('service_mode','v2-only')")
        db.execute("INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (AUTH_NS, "holder", 1, "active", None, None, 0, "deletion", 0,
                    "genesis", "clear", "execution", 0, "genesis", "nonce"))
        authority_id = core._id(db)
    AuthorityOwnerPairingSource(core, utc_clock=lambda: NOW, create=True)
    core.close()
    # The administration slice must reopen existing state; it never initializes
    # a replacement Authority or pairing schema from CLI input.
    core = AuthorityServiceCore(
        path, create=False, authorizer=_authorizer,
        deletion_verifier=lambda *_: False, execution_verifier=lambda *_: False,
        effect_verifier=lambda *_: False, dispatch_verifier=lambda *_: False,
    )
    pairing = AuthorityOwnerPairingSource(core, utc_clock=lambda: NOW, create=False)
    daemon = object.__new__(AuthorityDaemon)
    daemon.core = core
    daemon.owner_pairings = pairing
    daemon.config = SimpleNamespace(local_administrator_credential=(
        lambda action, namespace: ADMIN if action in {
            "owner_identity_pair", "owner_identity_revoke"
        } and namespace == AUTH_NS else object()))
    daemon.installations_v2 = {
        (CERT, PROFILE): AdministratorInstallationV2(
            INSTALLATION, "holder", "publisher", "v2", "c" * 64),
    }
    daemon.namespace_bindings_v2 = {(CERT, PROFILE, NS): AUTH_NS}
    daemon._lock_handle = object()  # Controlled method test, not an OS lock.
    daemon._maintenance_lock = threading.RLock()
    daemon._closed = False
    daemon._starting = False
    daemon._listener = None
    monkeypatch.setattr(admin_cli, "_require_windows_administrator_token", lambda: None)
    try:
        yield daemon, path, authority_id
    finally:
        core.close()


def _command(action, payload=None, expiry=None, *, installation=INSTALLATION):
    return AdminOwnerCommandV1(action, AUTH_NS, PROFILE, installation, payload, expiry)


def test_installed_admin_cli_pairs_credential_actor_and_revokes_in_existing_db(
        installed_controlled_daemon):
    daemon, path, authority_id = installed_controlled_daemon
    registration = OwnerCredentialRegistrationV1(
        authority_id, AUTH_NS, INSTALLATION, PRINCIPAL,
        "key-1", 1, bytes(range(32)), "enroll-1",
    )
    binding = OwnerActorBindingV1(
        authority_id, INSTALLATION, NS, "owner-actor", PRINCIPAL, 1,
    )
    assert run_installed_admin_command_v1(
        daemon, _command("pair-credential", registration, EXPIRY)) == {
            "status": "applied", "action": "pair-credential", "authority_namespace": AUTH_NS,
        }
    run_installed_admin_command_v1(daemon, _command("pair-actor", binding))
    inspected = run_installed_admin_command_v1(
        daemon, _command("inspect", PRINCIPAL))
    assert inspected["creation_paired"] is False
    assert inspected["credential_paired"] is True
    assert daemon.owner_pairings.current_actor_binding(
        authority_namespace=AUTH_NS, installation_id=INSTALLATION,
        actor_id="owner-actor") == binding
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM authority_owner_credential_pairings_v1"
                          ).fetchone() == (1,)
    run_installed_admin_command_v1(daemon, _command("revoke-actor", binding))
    run_installed_admin_command_v1(daemon, _command("revoke-credential", PRINCIPAL))
    run_installed_admin_command_v1(daemon, _command("revoke-creation"))
    assert run_installed_admin_command_v1(
        daemon, _command("inspect", PRINCIPAL))["credential_paired"] is False
    assert daemon.owner_pairings.current_creation_pairing(AUTH_NS) is None


def test_cli_rejects_non_admin_wrong_installation_and_uninstalled_path(
        installed_controlled_daemon, monkeypatch):
    daemon, path, authority_id = installed_controlled_daemon
    registration = OwnerCredentialRegistrationV1(
        authority_id, AUTH_NS, INSTALLATION, PRINCIPAL,
        "key-1", 1, bytes(range(32)), "enroll-1",
    )
    with pytest.raises(Exception, match="installed Owner peer identity"):
        run_installed_admin_command_v1(
            daemon, _command("pair-credential", registration, EXPIRY,
                             installation="uninstalled"))
    with pytest.raises(AdminCliHold, match="payload differs"):
        run_installed_admin_command_v1(
            daemon, _command("pair-credential",
                             replace(registration, installation_id="other"), EXPIRY))
    monkeypatch.setattr(admin_cli, "_require_windows_administrator_token",
                        lambda: (_ for _ in ()).throw(AdminCliHold("OS token HOLD")))
    with pytest.raises(AdminCliHold, match="OS token HOLD"):
        run_installed_admin_command_v1(
            daemon, _command("pair-credential", registration, EXPIRY))
    assert daemon.owner_pairings.current_owner_pairing(AUTH_NS, PRINCIPAL) is None
    output = io.StringIO()
    assert admin_cli.main([
        "inspect", "--namespace", AUTH_NS, "--profile-id", PROFILE,
        "--installation-id", INSTALLATION,
    ], output_stream=output) == 3
    assert json.loads(output.getvalue())["status"] == "HOLD"
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM authority_owner_credential_pairings_v1"
                          ).fetchone() == (0,)


def test_embedded_cli_reads_bounded_typed_input_after_admin_gate(
        installed_controlled_daemon):
    daemon, _, authority_id = installed_controlled_daemon
    registration = OwnerCredentialRegistrationV1(
        authority_id, AUTH_NS, INSTALLATION, PRINCIPAL,
        "key-1", 1, bytes(range(32)), "enroll-1",
    )
    payload = json.dumps({
        "registration": proof_to_wire(registration),
        "valid_until_utc": "2030-01-01T00:00:00Z",
    })
    output = io.StringIO()
    assert admin_cli.main([
        "pair-credential", "--namespace", AUTH_NS, "--profile-id", PROFILE,
        "--installation-id", INSTALLATION,
    ], daemon=daemon, input_stream=io.StringIO(payload), output_stream=output) == 0
    assert json.loads(output.getvalue())["status"] == "applied"
    assert daemon.owner_pairings.current_owner_pairing(AUTH_NS, PRINCIPAL) is not None


def test_creation_ticket_json_cannot_be_promoted_without_pinned_w01_original(
        installed_controlled_daemon):
    daemon, path, authority_id = installed_controlled_daemon
    ticket = OwnerClaimTicketV1(
        authority_id, INSTALLATION, NS, PRINCIPAL, "ticket-1", "create-1",
        "sha256:" + "1" * 64, "sha256:" + "2" * 64, "C" * 43,
        "2030-01-01T00:00:00Z",
    )
    with pytest.raises(AdminCliHold, match="pinned W01 original"):
        run_installed_admin_command_v1(
            daemon, _command("pair-creation", ticket, EXPIRY))
    payload = json.dumps({
        "ticket": to_wire(ticket), "valid_until_utc": "2030-01-01T00:00:00Z",
    })
    output = io.StringIO()
    assert admin_cli.main([
        "pair-creation", "--namespace", AUTH_NS, "--profile-id", PROFILE,
        "--installation-id", INSTALLATION,
    ], daemon=daemon, input_stream=io.StringIO(payload), output_stream=output) == 3
    assert json.loads(output.getvalue())["status"] == "HOLD"
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM authority_owner_creation_pairings_v1"
                          ).fetchone() == (0,)
