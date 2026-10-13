"""Real independent Authority, installer policy, signed Owner and management.

SYLANNE_ALPHA1_PACKAGE points to the actual platform candidate ZIP, as in the
installed bootstrap acceptance. Only UTC is controlled; no fake Owner resolver,
management grant callback, business SQL setup or production database is used.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import ssl
import uuid
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as cert_donor
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
from sylanne3.authority_service.installed_policy import InstalledPeerScopeV1
from sylanne3.authority_service.installed_policy_v2 import InstalledAuthorityPolicyV2
from sylanne3.authority_service.installation_management_v1 import (
    InstallationManagementServiceV1, ManagementProblem, PERMISSIONS, REQUEST_SCHEMA,
)
from sylanne3.authority_service.mtls_server import MtlsPeerCredential
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_proof import AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1
from sylanne3.authority_service.v2_owner_session import AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1
from sylanne3.host.owner_deployment import OwnerDeploymentVerifier
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.runtime.deletion import DeletionJournal


NAMESPACE = "bot:management-acceptance"
CANARY = "secret-canary-management-73f1"
PRINCIPAL = OwnerPrincipalV1("dashboard", CANARY, "incarnation-1")


class Clock:
    def __init__(self):
        self.now = datetime(2029, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


@pytest.fixture(scope="module")
def installed_package(tmp_path_factory):
    package = os.environ.get("SYLANNE_ALPHA1_PACKAGE")
    if not package:
        pytest.skip("actual alpha1 platform package is required")
    root = tmp_path_factory.mktemp("management-package")
    with zipfile.ZipFile(package) as archive:
        archive.extractall(root)
    return root, hashlib.sha256((root / "release-manifest.json").read_bytes()).hexdigest()


@pytest.fixture
def installed(tmp_path, installed_package):
    root, pin = installed_package
    certs = tmp_path / "certs"
    certs.mkdir()
    certificates = cert_donor.AuthorityMtlsLoopbackTests._certificates(certs)
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        certificates["client.pem"].read_text("ascii"))).hexdigest()
    peer = MtlsPeerCredential(digest)
    policy = InstalledAuthorityPolicyV2(
        peer_scopes={digest: InstalledPeerScopeV1(NAMESPACE, "host")},
        profile_peers={"installed": digest}, package_root=root,
        trusted_manifest_sha256=pin, authority_uid=os.geteuid() if os.name == "posix" else 0)
    clock = Clock()
    deletion_seed = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_seed.close()
    deletion = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(tmp_path / "execution.db", namespace=NAMESPACE,
                                           journal_id="execution:management", create=True)
    verifiers = installed_core_verifier_factory(deletion, {NAMESPACE: execution})
    core = AuthorityServiceCore(tmp_path / "authority.db", create=True,
        authorizer=policy.core_authorizer, deletion_verifier=verifiers.deletion,
        execution_verifier=verifiers.execution, effect_verifier=verifiers.effect,
        dispatch_verifier=verifiers.dispatch)
    try:
        with deletion.freeze_writes():
            head = deletion.verified_head()
        core.register_namespace(policy.local_administrator_credential("install", NAMESPACE),
                                NAMESPACE, "host", head, execution.verified_head())
        core.seal_v2_only(policy.local_administrator_credential("seal_v2_only", NAMESPACE))
        pairing = AuthorityOwnerPairingSource(core, utc_clock=clock, create=True)
        verifier = OwnerDeploymentVerifier(pairing, clock)
        proofs = AuthorityV2OwnerProofStore(core, utc_clock=clock,
            pairing_verifier=verifier.pair_credential, current_pairing_source=pairing, create=True)
        key = Ed25519PrivateKey.generate()
        with core._tx() as db:
            authority_id = core._id(db)
        registration = OwnerCredentialRegistrationV1(
            authority_id, NAMESPACE, "management-installation", PRINCIPAL,
            CANARY + "-key", 1, key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw), "enroll-management")
        pairing.pair_credential(administrator_credential=policy.local_administrator_credential(
            "owner_identity_pair", NAMESPACE), registration=registration,
            client_certificate_sha256=digest, valid_until_utc=clock.now + timedelta(hours=2))
        proofs.register_credential(transport_credential=peer, registration=registration)
        sessions = AuthorityV2OwnerSessionStore(core, utc_clock=clock,
            current_pairing_source=pairing, create=True)
        request = OwnerSessionLoginRequestV1(authority_id, NAMESPACE, "management-installation",
            PRINCIPAL, registration.credential_id, 1, "sylanne-owner-console", "https://localhost:6185")
        challenge = sessions.begin_login(transport_credential=peer, request=request)
        token = sessions.accept_login(transport_credential=peer, challenge=challenge,
            signature=key.sign(challenge.signed_bytes()), session_ttl_seconds=7200)
        service = InstallationManagementServiceV1(core, sessions, namespace=NAMESPACE,
            installation_id="management-installation", authority_profile="installed", utc_clock=clock,
            administrator_authorizer=policy.administrator_authorizer)
        admin = lambda action: policy.local_administrator_credential(action, NAMESPACE)
        service.initialize(admin("installation_management_install"), True)
        yield service, peer, token, clock, admin, sessions, request, core
    finally:
        core.close()
        execution.close()
        deletion.close()


def payload(capabilities=None, **extra):
    result = {"schema_version": REQUEST_SCHEMA, "operation_id": str(uuid.uuid4())}
    if capabilities is not None:
        result.update(installation_id=capabilities["installation_id"],
                      access_generation=capabilities["access_generation"])
    return {**result, **extra}


def call(env, operation, request):
    service, peer, token, *_ = env
    response = service.handle(peer, token, operation, request)
    assert response["http_status"] == 200
    return response["json"]


def grant(env, permissions=PERMISSIONS, *, minutes=30):
    service, _, _, clock, admin, *_ = env
    service.grant_management(admin("installation_management_grant"), PRINCIPAL,
                             permissions, clock.now + timedelta(minutes=minutes))
    return call(env, "capabilities", payload())


def problem(code, status, function):
    with pytest.raises(ManagementProblem) as caught:
        function()
    assert (caught.value.code, caught.value.status) == (code, status)
    assert set(caught.value.json()) == {"schema_version", "problem"}


def test_real_owner_permissions_expiry_generation_and_startup(installed):
    service, peer, token, clock, admin, sessions, request, core = installed
    unavailable = call(installed, "capabilities", payload())
    assert unavailable["capabilities"]["logs"]["available"] is False
    assert unavailable["capabilities"]["settings"]["writable_fields"] == []
    readonly = grant(installed, {"installation.settings.read"})
    assert readonly["access_generation"] == unavailable["access_generation"] + 1
    settings = call(installed, "settings/read", payload(readonly))
    assert settings["values"] == {"enabled": True, "authority_profile": "installed"}
    assert settings["apply_semantics"] == "read_only"
    problem("capability_unavailable", 409, lambda: call(installed, "settings/update",
        payload(readonly, expected_revision=settings["revision"], patch={"enabled": False})))
    full = grant(installed)
    assert full["access_generation"] == readonly["access_generation"] + 1
    problem("capabilities_changed", 409, lambda: call(installed, "settings/read", payload(readonly)))
    problem("installation_mismatch", 403, lambda: call(installed, "settings/read",
        payload(full, installation_id="another-installation")))
    with pytest.raises(AuthorityUnavailable):
        service.grant_management(peer, PRINCIPAL, PERMISSIONS, clock.now + timedelta(minutes=30))
    with pytest.raises(AuthorityUnavailable):
        service.startup_settings(admin("installation_management_grant"))
    assert service.startup_settings(peer)["enabled"] is True
    clock.now += timedelta(minutes=31)
    # The first observation can be a refused old-generation operation. Its
    # single grant retirement must persist despite the public 409 response.
    problem("capabilities_changed", 409, lambda: call(installed, "settings/read", payload(full)))
    with core._tx() as db:
        assert db.execute("SELECT access_epoch FROM authority_installation_management_v1 "
                          "WHERE installation_id=?", (service.installation_id,)).fetchone() == (full["access_generation"] + 1,)
        assert db.execute("SELECT COUNT(*) FROM authority_installation_management_grants_v1 "
                          "WHERE installation_id=?", (service.installation_id,)).fetchone() == (0,)
    expired = call(installed, "capabilities", payload())
    assert expired["access_generation"] == full["access_generation"] + 1
    assert call(installed, "capabilities", payload())["access_generation"] == expired["access_generation"]
    assert expired["capabilities"]["settings"]["available"] is False
    assert service.startup_settings(peer)["revision"] == settings["revision"]
    problem("capabilities_changed", 409, lambda: call(installed, "settings/read", payload(full)))
    grant(installed)
    service.revoke_management(admin("installation_management_revoke"), PRINCIPAL)
    assert call(installed, "capabilities", payload())["capabilities"]["logs"]["available"] is False
    sessions.logout(transport_credential=peer, token=token, request=request)
    problem("owner_session_invalid", 401, lambda: call(installed, "capabilities", payload()))


def test_exact_schema_fields_and_size_limits(installed):
    caps = grant(installed)
    bad_requests = [payload(extra="CANARY"), payload(schema_version="future.v2"),
                    payload(operation_id=str(uuid.uuid1())), payload(operation_id=str(uuid.uuid4()).upper())]
    for bad in bad_requests:
        expected = "unsupported_schema" if bad["schema_version"] != REQUEST_SCHEMA else "invalid_request"
        problem(expected, 400, lambda bad=bad: call(installed, "capabilities", bad))
    base = payload(caps, filter={"level": "ALL", "query": ""}, cursor=None, limit=50)
    for bad in ({**base, "limit": True}, {**base, "filter": {"level": "ALL", "query": "", "raw": CANARY}},
                {**base, "filter": {"level": "ALL", "query": "x" * 129}}, {**base, "cursor": "x" * 2049}):
        problem("invalid_request", 400, lambda bad=bad: call(installed, "logs/query", bad))
    problem("request_too_large", 413, lambda: call(installed, "logs/query",
        {**base, "filter": {"level": "ALL", "query": "x" * 65536}}))
    settings = call(installed, "settings/read", payload(caps))
    problem("invalid_request", 400, lambda: call(installed, "settings/update",
        payload(caps, expected_revision=settings["revision"], patch={"enabled": False, "authority_profile": "other"})))
    problem("validation_failed", 422, lambda: call(installed, "settings/update",
        payload(caps, expected_revision=settings["revision"], patch={"enabled": 1})))


def test_atomic_cas_receipt_idempotency_concurrency_and_readback(installed):
    service, peer, _, _, _, _, _, core = installed
    caps = grant(installed)
    initial = call(installed, "settings/read", payload(caps))
    write = payload(caps, expected_revision=initial["revision"], patch={"enabled": False})
    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(lambda _: call(installed, "settings/update", write), range(2)))
    assert receipts[0] == receipts[1]
    receipt = receipts[0]
    assert set(receipt) == {"schema_version", "installation_id", "access_generation", "operation_id", "revision", "applied"}
    after = call(installed, "settings/read", payload(caps))
    assert after["revision"] == receipt["revision"] and after["values"]["enabled"] is False
    assert service.startup_settings(peer)["enabled"] is False
    problem("operation_conflict", 409, lambda: call(installed, "settings/update", {**write, "patch": {"enabled": True}}))
    problem("revision_conflict", 409, lambda: call(installed, "settings/update",
        payload(caps, expected_revision=initial["revision"], patch={"enabled": True})))
    writes = [payload(caps, expected_revision=after["revision"], patch={"enabled": True}) for _ in range(2)]
    def perform(request):
        try:
            return call(installed, "settings/update", request)
        except ManagementProblem as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(perform, writes))
    assert sum(type(outcome) is dict for outcome in outcomes) == 1
    assert outcomes.count("revision_conflict") == 1
    # Read-only inspection verifies exactly one audit event per committed CAS.
    with core._tx() as db:
        assert db.execute("SELECT COUNT(*) FROM authority_installation_management_receipts_v1").fetchone() == (2,)
        assert db.execute("SELECT COUNT(*) FROM authority_installation_management_events_v1 "
                          "WHERE event_code='settings.enabled.updated'").fetchone() == (2,)


def test_snapshot_pagination_redaction_context_expiry_and_retention(installed):
    service, _, token, clock, admin, *_ = installed
    caps = grant(installed)
    # Real CAS operations create real audit events; no artificial historic rows.
    for index in range(52):
        clock.now += timedelta(seconds=1)
        settings = call(installed, "settings/read", payload(caps))
        call(installed, "settings/update", payload(caps, expected_revision=settings["revision"],
                                                   patch={"enabled": bool(index % 2)}))
    first_request = payload(caps, filter={"level": "ALL", "query": ""}, cursor=None, limit=50)
    first = call(installed, "logs/query", first_request)
    assert len(first["entries"]) == 50 and first["next_cursor"]
    repeated_first = call(installed, "logs/query", first_request)
    assert repeated_first["entries"] == first["entries"]
    newest = call(installed, "settings/read", payload(caps))
    clock.now += timedelta(seconds=1)
    call(installed, "settings/update", payload(caps, expected_revision=newest["revision"], patch={"enabled": False}))
    second_request = {**first_request, "operation_id": str(uuid.uuid4()), "cursor": first["next_cursor"]}
    second = call(installed, "logs/query", second_request)
    assert second["snapshot_id"] == first["snapshot_id"] and second["next_cursor"] is None
    assert len(second["entries"]) == 4
    event_ids = [entry["event_id"] for entry in first["entries"] + second["entries"]]
    assert len(set(event_ids)) == 54
    assert second == call(installed, "logs/query", second_request)
    serialized = json.dumps([first, second, call(installed, "settings/read", payload(caps))]).encode()
    for secret in (CANARY, token, CANARY + "-key"):
        assert secret.encode() not in serialized
    assert all(set(entry) == {"event_id", "occurred_at", "level", "event_code", "summary", "redacted"}
               and entry["redacted"] is True for entry in first["entries"] + second["entries"])
    problem("snapshot_changed", 409, lambda: call(installed, "logs/query",
        {**second_request, "filter": {"level": "WARNING", "query": ""}}))
    problem("invalid_cursor", 400, lambda: call(installed, "logs/query", {**second_request, "cursor": "forged"}))
    empty = call(installed, "logs/query", {**first_request, "filter": {"level": "ALL", "query": CANARY}})
    assert empty["entries"] == [] and empty["next_cursor"] is None
    clock.now += timedelta(minutes=11)
    problem("cursor_expired", 410, lambda: call(installed, "logs/query", second_request))
    fresh = call(installed, "logs/query", first_request)
    service.retain_logs(admin("installation_management_install"), clock.now - timedelta(seconds=1))
    problem("snapshot_changed", 409, lambda: call(installed, "logs/query", {**second_request, "cursor": fresh["next_cursor"]}))
