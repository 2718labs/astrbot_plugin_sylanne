"""mTLS peer and installed reader roles govern self identity RPC methods."""

import asyncio
from dataclasses import replace

import pytest

from rewrite.tests.alpha1.authority.test_v2_self_identity_service import (
    NS, SUBJECT, _case, _close,
)
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_self_identity_contract import (
    SelfIdentityCurrentRequestV1, from_wire, to_wire,
)


def _wire():
    return {
        "protocol": AUTHORITY_V2_PROTOCOL,
        "profile_id": "installed", "plugin_name": "astrbot_plugin_sylanne",
        "host_api_version": "4.28.1", "manifest_sha256": "c" * 64,
    }


def test_admin_mutation_and_reader_current_are_separate_mtls_capabilities(tmp_path, monkeypatch):
    service, mutation, anchor, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    reader = MtlsPeerCredential("a" * 64)
    admin = MtlsPeerCredential("b" * 64)
    core._authorize_callback = lambda credential, action, namespace, holder: (
        credential in {reader, admin} and namespace == "ns-a"
        and action in {"read", "current", "self_identity_read"})
    # Only the distinct administrator peer may mutate, even though both have
    # an installed namespace binding and a valid paired TLS session.
    service._admin_authorizer = lambda credential, action, namespace, installation: (
        credential == admin and action == "self_identity_mutate"
        and namespace == "ns-a" and installation == "installation-a")
    installed = {
        (reader.certificate_sha256, "installed"):
            AdministratorInstallationV2(
                "installation-a", "holder-a", "policy", "v2", "c" * 64),
        (admin.certificate_sha256, "installed"):
            AdministratorInstallationV2(
                "admin-installation", "holder-a", "policy", "v2", "c" * 64),
    }
    bindings = {
        (reader.certificate_sha256, "installed", NS): "ns-a",
        (admin.certificate_sha256, "installed", NS): "ns-a",
    }
    server = AuthorityRpcServer(
        core, v2_fences={"ns-a": service._fences},
        v2_owner_tickets=service._tickets,
        v2_self_identity={"ns-a": service},
        self_identity_readers_v2={"ns-a": (reader.certificate_sha256, "installed")},
        administrator_authorizer=lambda credential, action, _, profile:
            credential in {reader, admin} and action == "pair" and profile == "installed",
        publisher_manifest_verifier=lambda profile, name, version, digest:
            (profile, name, version, digest) == (
                "installed", "astrbot_plugin_sylanne", "4.28.1", "c" * 64),
        installations_v2=installed, namespace_bindings_v2=bindings)
    wire = _wire()

    def paired(peer, channel):
        return server._dispatch_for_test(
            "handshake", wire, peer, channel)["channel_binding_sha256"]

    def call(method, peer, channel, binding, command):
        return server._dispatch_for_test(
            method, wire, peer, channel,
            handshake_binding=binding, command=command)

    try:
        reader_channel = b"reader-channel"
        admin_channel = b"admin-channel"
        reader_binding = paired(reader, reader_channel)
        admin_binding = paired(admin, admin_channel)
        command = {"namespace": "ns-a", "mutation": to_wire(mutation)}
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("self_identity_mutate_v1", reader, reader_channel,
                 reader_binding, command)
        receipt = call("self_identity_mutate_v1", admin, admin_channel,
                       admin_binding, command)["receipt"]
        assert receipt["revision"] == 1
        permit = service._fences.begin_fence(
            credential=reader, subject=SUBJECT, holder="holder-a",
            operation="read", operation_id="read-self-a", expected_anchor=anchor)
        request = SelfIdentityCurrentRequestV1(
            anchor.authority_id, "ns-a", NS, "installation-a", "c" * 64,
            "d03-self-perspective-a", permit)
        result = call("self_identity_current_v1", reader, reader_channel,
                      reader_binding,
                      {"namespace": "ns-a", "current_request": to_wire(request)})
        current = from_wire(result["current"])
        assert current.self_entity_ref == mutation.self_entity_ref
        assert current.permit == permit
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("self_identity_current_v1", admin, admin_channel,
                 admin_binding,
                 {"namespace": "ns-a", "current_request": to_wire(request)})
        with pytest.raises(RuntimeError, match="authority unavailable"):
            call("self_identity_current_v1", reader, reader_channel,
                 reader_binding,
                 {"namespace": "ns-a", "current_request": to_wire(replace(
                     request, request_operation_id="different-operation",
                     installation_id="different-installation"))})
    finally:
        asyncio.run(server.aclose())
        _close(core, deletion, guard, execution)


def test_local_composition_pins_self_reader_to_existing_authority_and_graph(tmp_path):
    from datetime import datetime, timezone
    from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed

    fences, core, _, deletion, guard, execution, _ = installed(tmp_path)
    graph_path = tmp_path / "graph.db"
    graph_path.touch()
    peer = "a" * 64
    installed_peers = {(peer, "installed"): AdministratorInstallationV2(
        "installation-a", "holder-a", "policy", "v2", "c" * 64)}
    server = None
    try:
        server = compose_local_owner_authority(
            core=core, v2_fences={"ns-a": fences}, graph_db_path=graph_path,
            utc_clock=lambda: datetime.now(timezone.utc),
            first_claim_verifier=lambda *_: False,
            claimant_verifier=lambda *_: False,
            administrator_authorizer=lambda *_: False,
            publisher_manifest_verifier=lambda *_: False,
            installations_v2=installed_peers,
            namespace_bindings_v2={(peer, "installed", NS): "ns-a"},
            self_identity_readers_v2={"ns-a": (peer, "installed")},
            create_owner_schema=True, create_self_identity_schema=True)
        service = server._v2_self_identity["ns-a"]
        assert service._core is core
        assert service._fences is fences
        assert service._tickets is server._v2_owner_tickets
        assert service._graph._path == graph_path.resolve()
    finally:
        if server is not None:
            asyncio.run(server.aclose())
        _close(core, deletion, guard, execution)
