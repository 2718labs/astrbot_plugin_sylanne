"""Terminal C02 body handoff needs a parsed same-channel ACK."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import ssl
import tempfile

from rewrite.host_tests.alpha1.test_authority_mtls_loopback import (
    AuthorityMtlsLoopbackTests,
)
from rewrite.tests.alpha1.authority.test_v2_terminal_c02_recovery_read_service import _case
from sylanne3.authority_service.mtls_server import (
    AuthorityRpcServer, AuthorityServerTlsConfig, _DeferredWorkerDelivery,
)
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_terminal_c02_recovery_contract import to_wire
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityHandshake, AuthorityProvisioningRequest,
    PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import (
    AuthorityTlsProfile, MtlsAuthorityTransport, _Session,
)
from sylanne3.runtime_contracts import InstallationGrantV2


def test_terminal_c02_ack_is_required_on_pinned_mtls_channel(tmp_path, monkeypatch):
    service, request, _, core, deletion, guard, execution = _case(tmp_path, monkeypatch)

    async def exercise():
        with tempfile.TemporaryDirectory() as directory:
            files = AuthorityMtlsLoopbackTests._certificates(Path(directory))
            peer_der = ssl.PEM_cert_to_DER_cert(
                files["client.pem"].read_text(encoding="ascii"))
            peer_digest = hashlib.sha256(peer_der).hexdigest()
            server = object.__new__(AuthorityRpcServer)

            async def dispatch(method, wire_request, credential, binding,
                               handshake_binding, command):
                assert credential.certificate_sha256 == peer_digest
                assert command == {"namespace": request.original_key.authority_namespace,
                                   "read_request": to_wire(request)}
                if method == "terminal_c02_recovery_query_v1":
                    attempt, fact = service.query(credential="ok", request=request)
                    return {
                        "attempt": None if attempt is None else to_wire(attempt),
                        "read_fact": None if fact is None else to_wire(fact),
                        "channel_binding_sha256": hashlib.sha256(binding).hexdigest(),
                    }
                assert method == "terminal_c02_recovery_read_v1"
                delivery = service.prepare(credential="ok", request=request)
                return _DeferredWorkerDelivery(
                    {"result": {"request": to_wire(request),
                                "observation": asdict(delivery.observation)},
                     "channel_binding_sha256": hashlib.sha256(binding).hexdigest()},
                    service, "ok", delivery)

            server._dispatch_on_worker = dispatch
            listener = await server.start(
                "127.0.0.1", 0,
                AuthorityServerTlsConfig(
                    str(files["server.pem"]), str(files["server.key"]),
                    str(files["ca.pem"]), timeout_seconds=1,
                    max_message_bytes=16_384))
            port = listener.sockets[0].getsockname()[1]
            profile = AuthorityTlsProfile(
                "test", "127.0.0.1", port, "localhost", request.original_key.authority_id,
                files["ca.pem"], files["client.pem"], files["client.key"],
                timeout_seconds=1, max_message_bytes=16_384)
            command = {"namespace": request.original_key.authority_namespace,
                       "read_request": to_wire(request)}
            wire_request = {
                "protocol": AUTHORITY_V2_PROTOCOL, "profile_id": "test",
                "plugin_name": "astrbot_plugin_sylanne", "host_api_version": "4.28.1",
                "manifest_sha256": "a" * 64,
            }
            transport = MtlsAuthorityTransport({"test": profile})
            try:
                # Neither a disconnect after receiving the full body nor an
                # incorrect ACK may turn local socket drain into a fact.
                for bad_ack in (None, b'{"kind":"terminal_c02_recovery_drain_ack_v1"}\n'):
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", port, ssl=profile.ssl_context(),
                        server_hostname="localhost")
                    initial = {
                        "protocol": AUTHORITY_V2_PROTOCOL,
                        "request_id": "disconnected" if bad_ack is None else "wrong-ack",
                        "method": "terminal_c02_recovery_read_v1",
                        "request": wire_request, "command": command,
                    }
                    writer.write(json.dumps(initial).encode() + b"\n")
                    await writer.drain()
                    response = json.loads(await reader.readline())
                    assert response["ok"] is True
                    if bad_ack is not None:
                        writer.write(bad_ack)
                        await writer.drain()
                        assert await reader.readline() == b""
                    writer.close()
                    await writer.wait_closed()
                    for _ in range(100):
                        if not service._inflight:
                            break
                        await asyncio.sleep(0.01)
                    assert not service._inflight
                    attempt, fact = service.query(credential="ok", request=request)
                    assert attempt.state == "active" and fact is None

                # Exact retry over a new pinned channel parses and ACKs the
                # original result; the durable fact is then queryable.
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port, ssl=profile.ssl_context(),
                    server_hostname="localhost")
                binding = hashlib.sha256(
                    writer.get_extra_info("ssl_object").get_channel_binding(
                        "tls-unique")).hexdigest()
                wire_digest = hashlib.sha256(json.dumps(
                    wire_request, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True).encode()).hexdigest()
                transport._sessions["test"] = _Session(
                    reader, writer, binding, wire_digest)
                provision = AuthorityProvisioningRequest(
                    AUTHORITY_PROTOCOL, "test", "astrbot_plugin_sylanne", "4.28.1",
                    Path(directory), Path(directory), PublisherPackageIdentity("a" * 64))
                handshake = AuthorityHandshake(
                    "paired", request.original_key.authority_id, "installed", binding, True)
                grant = InstallationGrantV2(
                    request.original_key.authority_id, "mtls:sha256:" + peer_digest,
                    "holder-a", request.original_key.installation_id, "a" * 64,
                    "policy", "v2", binding)
                queried_attempt, queried_fact = await transport.terminal_c02_recovery_query_v1(
                    provision, handshake, grant,
                    namespace=request.original_key.authority_namespace,
                    read_request=request)
                assert queried_attempt.state == "active" and queried_fact is None
                observation, result_fact = await transport.terminal_c02_recovery_read_v1(
                    provision, handshake, grant,
                    namespace=request.original_key.authority_namespace,
                    read_request=request)
                assert observation.result_json == "{}"
                assert result_fact.request == request
                attempt, fact = service.query(credential="ok", request=request)
                assert attempt.state == "finished" and fact is not None
                assert result_fact == fact
                queried_attempt, queried_fact = await transport.terminal_c02_recovery_query_v1(
                    provision, handshake, grant,
                    namespace=request.original_key.authority_namespace,
                    read_request=request)
                assert queried_attempt == attempt and queried_fact == fact
                writer.close()
                await writer.wait_closed()
            finally:
                listener.close()
                await listener.wait_closed()

    try:
        asyncio.run(exercise())
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()
