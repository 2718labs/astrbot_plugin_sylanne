"""Real Authority mTLS plus real AstrBot JWT/SDK HTTP management integration.

The HTTP side is an ASGI TestClient running the actual AstrBot auth and plugin
routers, not a browser or a qualification of the HTTPS host. The independent
Authority side uses real TLS sockets, pinned installed policy, journals,
administrator pairing and signed Owner admission. No graph or provider exists.
"""
import asyncio
import base64
from datetime import timedelta
import hashlib
import os
import secrets
import ssl
from threading import Thread
from types import SimpleNamespace

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astrbot.core.config.astrbot_config import AstrBotConfig
from astrbot.core.db.sqlite import SQLiteDatabase
from astrbot.dashboard.api import auth as dashboard_auth, plugins as dashboard_plugins
from astrbot.dashboard.password_state import set_dashboard_password_hashes
from astrbot.dashboard.responses import ApiError
from astrbot.dashboard.services.auth_service import AuthService, DASHBOARD_JWT_COOKIE_NAME

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as cert_donor
from rewrite.tests.alpha1.authority import test_installation_management_v1 as unit
from rewrite.tests.alpha1.authority.test_installation_management_v1 import installed_package
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
from sylanne3.authority_service.installed_policy import InstalledPeerScopeV1
from sylanne3.authority_service.installed_policy_v2 import InstalledAuthorityPolicyV2
from sylanne3.authority_service.installation_management_rpc_v1 import install_installation_management_v1
from sylanne3.authority_service.installation_management_v1 import InstallationManagementServiceV1, PERMISSIONS
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, AuthorityServerTlsConfig, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_owner_proof import AuthorityV2OwnerProofStore, OwnerCredentialRegistrationV1
from sylanne3.authority_service.v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
    from_wire as owner_from_wire, to_wire as owner_to_wire,
)
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.authority_client import AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.owner_deployment import OwnerDeploymentVerifier
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.host.workbench_mount import WorkbenchHostMount
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api.http_transport import BoundCsrfTokens, SYLANNE_OWNER_SESSION_COOKIE, TransportConfig
from sylanne3.workbench_api.installation_owner_sessions_v1 import InstallationOwnerSessionsV1
from sylanne3.workbench_api.management_transport_v1 import InstallationManagementTransportV1


ORIGIN = "https://localhost:6185"
BASE = "/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1"


class RouteRegistry:
    """Only the host route-registration seam; no identity/auth implementation."""
    def __init__(self):
        self.registered_web_apis = []

    def register_web_api(self, route, handler, methods, description):
        self.registered_web_apis.append((route, handler, methods, description))


@pytest.fixture
def tls_installation(tmp_path, installed_package):
    package, pin = installed_package
    role = NamespaceId("management-bot", "management-persona")
    namespace = namespace_ref(role)
    certs = tmp_path / "certs"
    certs.mkdir()
    certificates = cert_donor.AuthorityMtlsLoopbackTests._certificates(certs)
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        certificates["client.pem"].read_text("ascii"))).hexdigest()
    peer = MtlsPeerCredential(digest)
    policy = InstalledAuthorityPolicyV2(peer_scopes={digest: InstalledPeerScopeV1(namespace, "host")},
        profile_peers={"installed": digest}, package_root=package, trusted_manifest_sha256=pin,
        authority_uid=os.geteuid() if os.name == "posix" else 0)
    clock = unit.Clock()
    seed = DeletionJournal(tmp_path / "deletion.db", create=True)
    seed.close()
    deletion = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(tmp_path / "execution.db", namespace=namespace,
        journal_id="execution:http-management", create=True)
    verifiers = installed_core_verifier_factory(deletion, {namespace: execution})
    core = AuthorityServiceCore(tmp_path / "authority.db", create=True,
        authorizer=policy.core_authorizer, deletion_verifier=verifiers.deletion,
        execution_verifier=verifiers.execution, effect_verifier=verifiers.effect,
        dispatch_verifier=verifiers.dispatch)
    server = port = listener = None
    loop = asyncio.new_event_loop()
    thread = Thread(target=lambda: (asyncio.set_event_loop(loop), loop.run_forever()),
                    name="management-real-authority-tls", daemon=True)
    thread.start()
    try:
        admin = lambda action: policy.local_administrator_credential(action, namespace)
        with deletion.freeze_writes():
            head = deletion.verified_head()
        core.register_namespace(admin("install"), namespace, "host", head, execution.verified_head())
        core.seal_v2_only(admin("seal_v2_only"))
        fences = AuthorityV2FenceStore(core._db, lock=core._lock, create=True)
        fence = AuthorityV2FenceService(core=core, fences=fences, deletion=deletion,
            execution=execution, namespace=namespace)
        pairing = AuthorityOwnerPairingSource(core, utc_clock=clock, create=True)
        verifier = OwnerDeploymentVerifier(pairing, clock)
        proofs = AuthorityV2OwnerProofStore(core, utc_clock=clock, pairing_verifier=verifier.pair_credential,
            current_pairing_source=pairing, create=True)
        key = Ed25519PrivateKey.generate()
        with core._tx() as db:
            authority_id = core._id(db)
        registration = OwnerCredentialRegistrationV1(authority_id, namespace, "management-installation",
            unit.PRINCIPAL, unit.CANARY + "-key", 1, key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw), "enroll-http-management")
        pairing.pair_credential(administrator_credential=admin("owner_identity_pair"),
            registration=registration, client_certificate_sha256=digest,
            valid_until_utc=clock.now + timedelta(hours=2))
        proofs.register_credential(transport_credential=peer, registration=registration)
        sessions = AuthorityV2OwnerSessionStore(core, utc_clock=clock, current_pairing_source=pairing, create=True)
        service = InstallationManagementServiceV1(core, sessions, namespace=namespace,
            installation_id=registration.installation_id, authority_profile="installed", utc_clock=clock,
            administrator_authorizer=policy.administrator_authorizer)
        service.initialize(admin("installation_management_install"), False)
        server = AuthorityRpcServer(core, v2_fences={namespace: fence}, v2_owner_sessions=sessions,
            v2_owner_pairings=pairing, administrator_authorizer=policy.administrator_authorizer,
            publisher_manifest_verifier=policy.publisher_manifest_verifier,
            installations_v2={(digest, "installed"): AdministratorInstallationV2(
                registration.installation_id, "host", "pinned", "2", pin)},
            namespace_bindings_v2={(digest, "installed", role): namespace})
        install_installation_management_v1(server, service)
        listener = asyncio.run_coroutine_threadsafe(server.start("127.0.0.1", 0, AuthorityServerTlsConfig(
            str(certificates["server.pem"]), str(certificates["server.key"]), str(certificates["ca.pem"]),
            timeout_seconds=5, max_message_bytes=512 * 1024)), loop).result(timeout=15)
        profile = AuthorityTlsProfile("installed", "127.0.0.1", listener.sockets[0].getsockname()[1],
            "localhost", authority_id, certificates["ca.pem"], certificates["client.pem"],
            certificates["client.key"], timeout_seconds=5, max_message_bytes=512 * 1024)
        provisioning = AuthorityProvisioningRequest(AUTHORITY_PROTOCOL, "installed",
            "astrbot_plugin_sylanne", "4.28.1", tmp_path, tmp_path, PublisherPackageIdentity(pin))

        async def actual_grant():
            transport = MtlsAuthorityTransport({"installed": profile})
            try:
                handshake = await transport.handshake(provisioning, protocol="sylanne3.authority.v2")
                return await transport.installation_grant_v2(provisioning, handshake)
            finally:
                await transport.close()
        grant = asyncio.run(actual_grant())
        port = V2FencePort(provisioning, {"installed": profile}, grant)
        identity = InstallationOwnerSessionsV1(authority=port, namespace=role, authority_id=authority_id,
            installation_id=registration.installation_id, origin=ORIGIN)
        csrf = BoundCsrfTokens()
        transport = InstallationManagementTransportV1(identity=identity, csrf=csrf, port=port,
            config=TransportConfig(ORIGIN, package / "resources/workbench"))
        mount = WorkbenchHostMount()
        mount.attach_owner_sessions(identity)
        mount.attach_management(transport)
        registry = RouteRegistry()
        mount.register(registry)
        login_request = OwnerSessionLoginRequestV1(authority_id, namespace, registration.installation_id,
            unit.PRINCIPAL, registration.credential_id, 1, "owner", ORIGIN)
        yield SimpleNamespace(service=service, admin=admin, clock=clock, port=port, identity=identity,
            core=core, server=server, key=key, login_request=login_request, registry=registry, mount=mount)
    finally:
        if port is not None:
            port.close()
        if listener is not None:
            listener.close()
            asyncio.run_coroutine_threadsafe(listener.wait_closed(), loop).result(timeout=15)
        if server is not None:
            asyncio.run_coroutine_threadsafe(server.aclose(), loop).result(timeout=15)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=15)
        loop.close()
        core.close()
        execution.close()
        deletion.close()


@pytest.fixture
def dashboard(tls_installation, tmp_path):
    # Fresh test bootstrap configuration, using AstrBot's official password
    # hash writer. All subsequent authentication and setup uses real HTTP APIs.
    initial_password = "MgtBootstrap!" + secrets.token_hex(16)
    final_password = "MgtOwner!" + secrets.token_hex(16)
    defaults = {"dashboard": {"username": "bootstrap-admin", "jwt_secret": secrets.token_hex(32),
                              "password_change_required": True}}
    set_dashboard_password_hashes(defaults, initial_password)
    config = AstrBotConfig(str(tmp_path / "astrbot-config.json"), default_config=defaults)
    db = SQLiteDatabase(str(tmp_path / "astrbot-dashboard.db"))
    asyncio.run(db.initialize())
    auth = AuthService(db, config)
    app = FastAPI()
    app.state.jwt_secret = config["dashboard"]["jwt_secret"]
    app.state.services = SimpleNamespace(auth=auth)
    app.state.core_lifecycle = SimpleNamespace(star_context=tls_installation.registry)
    app.include_router(dashboard_auth.router, prefix="/api/v1")
    app.include_router(dashboard_auth.legacy_router)
    app.include_router(dashboard_plugins.router, prefix="/api/v1")
    app.include_router(dashboard_plugins.legacy_router)

    @app.exception_handler(ApiError)
    async def api_error(_request: Request, error: ApiError):
        return JSONResponse({"status": "error", "message": error.message}, status_code=error.status_code)

    try:
        with TestClient(app, base_url=ORIGIN) as client, TestClient(app, base_url=ORIGIN) as bootstrap:
            assert client.get(BASE + "/session", headers={"sec-fetch-site": "same-origin"}).status_code == 401
            for candidate in (client, bootstrap):
                logged = candidate.post("/api/v1/auth/login", json={"username": "bootstrap-admin", "password": initial_password})
                assert logged.status_code == 200 and logged.json()["status"] == "ok"
                assert candidate.cookies.get(DASHBOARD_JWT_COOKIE_NAME)
                assert "secure" in logged.headers["set-cookie"].lower()
            # Cookie authentication uses AstrBot's authenticated setup route;
            # v1 optional_system_auth considers explicit header credentials.
            setup = client.post("/api/auth/setup-authenticated", json={"username": "management-admin",
                "password": final_password, "confirm_password": final_password})
            assert setup.status_code == 200 and setup.json()["status"] == "ok"
            logged = client.post("/api/v1/auth/login", json={"username": "management-admin", "password": final_password})
            assert logged.status_code == 200 and logged.json()["status"] == "ok"
            # This actual AstrBot legacy router uses require_dashboard_user;
            # the v1 extension router independently validates the real JWT.
            assert bootstrap.get("/api/plug/astrbot_plugin_sylanne/workbench/v1/status").status_code == 503
            yield tls_installation, client, bootstrap
    finally:
        tls_installation.mount.close()
        asyncio.run(db.engine.dispose())


def challenge(env, client):
    response = client.post(BASE + "/owner/challenge", headers={"origin": ORIGIN},
                           json={"request": owner_to_wire(env.login_request)})
    assert response.status_code == 200
    issued = owner_from_wire(response.json()["challenge"])
    assert base64.b64decode(response.json()["signing_payload_base64"]) == issued.signed_bytes()
    return issued


def complete(env, client, issued):
    return client.post(BASE + "/owner/complete", headers={"origin": ORIGIN},
        json={"challenge": owner_to_wire(issued),
              "signature_base64": base64.b64encode(env.key.sign(issued.signed_bytes())).decode("ascii")})


def unlock(env, client):
    response = complete(env, client, challenge(env, client))
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert all(flag in cookie for flag in ("httponly", "secure", "samesite=strict", "max-age=3600"))
    assert "path=" + BASE.lower() in cookie
    token = client.cookies.get(SYLANNE_OWNER_SESSION_COOKIE)
    opened = client.get(BASE + "/session", headers={"sec-fetch-site": "same-origin"})
    assert opened.status_code == 200
    current = opened.json()
    assert set(current) == {"status", "dashboard_session", "owner_session", "csrf_token"}
    assert current["status"] == "ready" and current["owner_session"] == "unlocked"
    return token, current["csrf_token"]


def management(client, csrf, operation, payload):
    return client.post(BASE + "/management/v1/" + operation, json=payload,
        headers={"origin": ORIGIN, "sec-fetch-site": "same-origin", "x-csrf-token": csrf})


def test_real_mtls_dashboard_owner_http_management_and_canary(dashboard):
    env, client, _ = dashboard
    assert client.get(BASE + "/session", headers={"sec-fetch-site": "same-origin"}).status_code == 401
    token, csrf = unlock(env, client)
    denied = management(client, "invalid-csrf", "capabilities", unit.payload())
    assert denied.status_code == 403 and denied.json()["problem"]["code"] == "csrf_denied"
    unavailable = management(client, csrf, "capabilities", unit.payload())
    assert unavailable.status_code == 200
    before = unavailable.json()
    assert before["capabilities"]["settings"]["available"] is False
    assert client.get(BASE + "/session", headers={"sec-fetch-site": "same-origin"}).status_code == 200
    env.service.grant_management(env.admin("installation_management_grant"), unit.PRINCIPAL,
        PERMISSIONS, env.clock.now + timedelta(minutes=30))
    changed = management(client, csrf, "settings/read", unit.payload(before))
    assert changed.status_code == 409 and changed.json()["problem"]["code"] == "capabilities_changed"
    discovered = management(client, csrf, "capabilities", unit.payload())
    caps = discovered.json()
    assert discovered.status_code == 200 and caps["access_generation"] == before["access_generation"] + 1
    malformed_responses = []
    for malformed, expected in ((unit.payload(extra=unit.CANARY), "invalid_request"),
                                (unit.payload(schema_version="future.v2"), "unsupported_schema")):
        response = management(client, csrf, "capabilities", malformed)
        assert response.status_code == 400 and response.json()["problem"]["code"] == expected
        malformed_responses.append(response)
    initial = management(client, csrf, "settings/read", unit.payload(caps))
    assert initial.status_code == 200 and initial.json()["values"]["enabled"] is False
    write = unit.payload(caps, expected_revision=initial.json()["revision"], patch={"enabled": True})
    saved = management(client, csrf, "settings/update", write)
    assert saved.status_code == 200
    receipt = saved.json()
    replay = management(client, csrf, "settings/update", write)
    assert replay.status_code == 200 and replay.json() == receipt
    readback = management(client, csrf, "settings/read", unit.payload(caps))
    assert readback.status_code == 200 and readback.json()["revision"] == receipt["revision"]
    assert readback.json()["values"]["enabled"] is True
    conflict = management(client, csrf, "settings/update", {**write, "patch": {"enabled": False}})
    assert conflict.status_code == 409 and conflict.json()["problem"]["code"] == "operation_conflict"
    stale = management(client, csrf, "settings/update", unit.payload(caps,
        expected_revision=initial.json()["revision"], patch={"enabled": False}))
    assert stale.status_code == 409 and stale.json()["problem"]["code"] == "revision_conflict"
    logs = management(client, csrf, "logs/query", unit.payload(caps,
        filter={"level": "ALL", "query": ""}, cursor=None, limit=50))
    assert logs.status_code == 200 and len(logs.json()["entries"]) == 3
    canaries = [unit.CANARY, token, csrf, client.cookies.get(DASHBOARD_JWT_COOKIE_NAME),
                unit.CANARY + "-key", "invalid-csrf"]
    for response in (unavailable, changed, discovered, denied, initial, saved, replay, readback,
                     conflict, stale, logs, *malformed_responses):
        assert response.headers["cache-control"] == "no-store"
        public_http_bytes = response.content + repr(dict(response.headers)).encode()
        for secret in canaries:
            assert secret.encode() not in public_http_bytes
    startup = env.port.installation_management_startup_v1(namespace=env.identity.namespace,
        authority_namespace=namespace_ref(env.identity.namespace))
    assert startup["enabled"] is True
    assert startup["revision"] == receipt["revision"]
    assert env.server._v2_model_egress == {}
    assert not hasattr(env, "graph") and not hasattr(env, "provider")


def test_real_installation_owner_identity_dashboard_binding_and_logout(dashboard):
    env, client, bootstrap = dashboard
    issued = challenge(env, client)
    crossed = complete(env, bootstrap, issued)
    assert crossed.status_code == 400
    assert not bootstrap.cookies.get(SYLANNE_OWNER_SESSION_COOKIE)
    # A cross-user completion must never issue identity; use a fresh challenge.
    token, csrf = unlock(env, client)
    identity = asyncio.run(env.identity.resolve_current_identity(username="management-admin", owner_session_token=token))
    assert identity is not None and identity.request == env.login_request
    assert asyncio.run(env.identity.resolve_current_identity(username="bootstrap-admin", owner_session_token=token)) is None
    assert identity.username == "management-admin"
    assert client.post(BASE + "/owner/logout", headers={"origin": ORIGIN}, json={}).status_code == 200
    assert asyncio.run(env.identity.resolve_current_identity(username="management-admin", owner_session_token=token)) is None
    assert client.get(BASE + "/session", headers={"sec-fetch-site": "same-origin"}).status_code == 401
    after = management(client, csrf, "capabilities", unit.payload())
    assert after.status_code == 401 and after.json()["problem"]["code"] == "owner_session_invalid"
