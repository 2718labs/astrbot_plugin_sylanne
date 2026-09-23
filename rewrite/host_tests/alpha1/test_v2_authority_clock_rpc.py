"""A configured Authority clock is available only to its paired installation."""

from dataclasses import asdict
from pathlib import Path

import pytest

from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.mtls_server import (
    AUTHORITY_V2_PROTOCOL, AdministratorInstallationV2, AuthorityRpcServer,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_clock import (
    AuthorityClockReadingV2, IngressClockSampleV2,
)
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityHandshake, AuthorityProvisioningRequest,
    PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport


PEER = MtlsPeerCredential("a" * 64)
MANIFEST = "b" * 64
REQUEST = {
    "protocol": AUTHORITY_V2_PROTOCOL,
    "profile_id": "installed",
    "plugin_name": "astrbot_plugin_sylanne",
    "host_api_version": "4.28.1",
    "manifest_sha256": MANIFEST,
}


def _server(tmp_path, *, source_id="admin:ntp-a", max_error=0.5, reading=None):
    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True,
        authorizer=lambda *args: True,
        deletion_verifier=lambda *args: True,
        execution_verifier=lambda *args: True,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    reads = []

    def provider():
        reads.append(1)
        return reading if reading is not None else AuthorityClockReadingV2(
            source_id="admin:ntp-a", utc_seconds=1_800_000_000.25,
            monotonic_seconds=123.5, epoch="boot-a", healthy=True,
            utc_error_seconds=0.25,
        )

    server = AuthorityRpcServer(
        core, administrator_authorizer=lambda *args: True,
        publisher_manifest_verifier=lambda *args: True,
        installations_v2={
            (PEER.certificate_sha256, "installed"): AdministratorInstallationV2(
                "install-a", "holder-a", "policy-a", "capabilities-v2", MANIFEST,
                source_id, max_error,
            ),
        },
        clock_provider=provider,
    )
    return server, core, reads


_DEFAULT_COMMAND = object()


def _paired(server, request=REQUEST, peer=PEER):
    channel = b"channel-a"
    handshake = server._dispatch_for_test("handshake", request, peer, channel)

    def call(command=_DEFAULT_COMMAND, *, method="ingress_clock_sample_v2", binding=None):
        return server._dispatch_for_test(
            method, request, peer, channel,
            handshake_binding=(handshake["channel_binding_sha256"]
                               if binding is None else binding),
            command={} if command is _DEFAULT_COMMAND else command,
        )

    return call, handshake


def test_clock_rpc_returns_one_bound_versioned_sample(tmp_path):
    server, core, reads = _server(tmp_path)
    try:
        call, handshake = _paired(server)
        response = call()
        assert response == {
            **asdict(IngressClockSampleV2(
                authority_id=server._authority_id(), installation_id="install-a",
                source_id="admin:ntp-a", utc_seconds=1_800_000_000.25,
                monotonic_seconds=123.5, epoch="boot-a", utc_error_seconds=0.25,
            )),
            "channel_binding_sha256": handshake["channel_binding_sha256"],
        }
        assert reads == [1]
    finally:
        core.close()


@pytest.mark.parametrize("source_id,max_error,reading", [
    (None, None, None),
    ("admin:ntp-b", 0.5, None),
    ("admin:ntp-a", 0.2, None),
    ("admin:ntp-a", 0.5, AuthorityClockReadingV2(
        "admin:ntp-a", 1_800_000_000.25, 123.5, "boot-a", False, 0.25,
    )),
])
def test_clock_rpc_fails_closed_for_unconfigured_or_unhealthy_source(
    tmp_path, source_id, max_error, reading,
):
    server, core, _ = _server(
        tmp_path, source_id=source_id, max_error=max_error, reading=reading,
    )
    try:
        call, _ = _paired(server)
        with pytest.raises(RuntimeError, match="unavailable"):
            call()
    finally:
        core.close()


def test_clock_rpc_requires_exact_v2_command_and_paired_manifest(tmp_path):
    server, core, reads = _server(tmp_path)
    try:
        call, _ = _paired(server)
        for bad in ({"source_id": "admin:ntp-a"}, [], None):
            with pytest.raises(RuntimeError, match="unavailable"):
                call(bad)
        with pytest.raises(RuntimeError, match="unavailable"):
            call(binding="0" * 64)
        with pytest.raises(RuntimeError, match="unavailable"):
            _paired(server, {**REQUEST, "manifest_sha256": "c" * 64})[0]()
        with pytest.raises(RuntimeError, match="unavailable"):
            _paired(server, {**REQUEST, "protocol": "sylanne3.authority.v1"})[0]()
        with pytest.raises(RuntimeError, match="unavailable"):
            _paired(server, peer=MtlsPeerCredential("c" * 64))[0]()
        assert reads == []
    finally:
        core.close()


def test_old_v2_installation_retains_grant_without_clock(tmp_path):
    server, core, reads = _server(tmp_path)
    try:
        server._installations_v2[(PEER.certificate_sha256, "installed")] = (
            AdministratorInstallationV2(
                "install-a", "holder-a", "policy-a", "capabilities-v2", MANIFEST,
            )
        )
        call, _ = _paired(server)
        assert call(method="installation_grant_v2")["installation_id"] == "install-a"
        with pytest.raises(RuntimeError, match="unavailable"):
            call()
        assert reads == []
    finally:
        core.close()


def test_clock_provider_failure_is_unavailable(tmp_path):
    server, core, _ = _server(tmp_path)
    try:
        def broken_provider():
            raise OSError("private clock detail")

        server._clock_provider = broken_provider
        call, _ = _paired(server)
        with pytest.raises(RuntimeError, match="^authority unavailable$"):
            call()
    finally:
        core.close()


@pytest.mark.asyncio
async def test_transport_accepts_only_exact_bound_clock_response(tmp_path):
    server, core, _ = _server(tmp_path)
    try:
        call, paired = _paired(server)
        profile = AuthorityTlsProfile(
            "installed", "localhost", 443, "localhost", server._authority_id(),
            tmp_path / "ca.pem", tmp_path / "client.pem", tmp_path / "client.key",
        )
        transport = MtlsAuthorityTransport({"installed": profile})
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "installed", "astrbot_plugin_sylanne", "4.28.1",
            Path(tmp_path), Path(tmp_path), PublisherPackageIdentity(MANIFEST),
        )
        handshake = AuthorityHandshake(
            paired["state"], paired["installation_authority_id"],
            paired["installation_identity_ref"], paired["channel_binding_sha256"], True,
        )
        response = call()

        async def rpc(_request, _handshake, method, command, *, protocol):
            assert (method, command, protocol) == (
                "ingress_clock_sample_v2", {}, AUTHORITY_V2_PROTOCOL,
            )
            return response

        transport._content_rpc = rpc
        sample = await transport.ingress_clock_sample_v2(request, handshake, "install-a")
        assert sample == IngressClockSampleV2(
            server._authority_id(), "install-a", "admin:ntp-a",
            1_800_000_000.25, 123.5, "boot-a", 0.25,
        )
        for change in (
            {"channel_binding_sha256": "0" * 64},
            {"installation_id": "install-b"},
            {"authority_id": "other"},
            {"schema": "sylanne3.authority.v1"},
            {"extra": True},
            {"utc_error_seconds": float("nan")},
        ):
            response = {**call(), **change}
            with pytest.raises(RuntimeError, match="clock response"):
                await transport.ingress_clock_sample_v2(request, handshake, "install-a")
    finally:
        core.close()
