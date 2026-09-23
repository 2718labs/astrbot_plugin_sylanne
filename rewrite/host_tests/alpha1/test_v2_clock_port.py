"""The synchronous graph worker accepts only a bounded paired Authority clock."""

import asyncio
from dataclasses import replace
import math
from pathlib import Path

import pytest

from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityHandshake, AuthorityProvisioningRequest,
    PublisherPackageIdentity,
)
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.mtls_transport import AuthorityTlsProfile
from sylanne3.host.v2_fence_port import V2FencePort, VerifiedIngressClockV2
from sylanne3.runtime_contracts import InstallationGrantV2


def _port(tmp_path, *, sample=None, delay=0):
    authority = "authority-a"
    manifest = "a" * 64
    binding = "b" * 64
    profile = AuthorityTlsProfile(
        "installed", "localhost", 443, "localhost", authority,
        tmp_path / "ca.pem", tmp_path / "client.pem", tmp_path / "client.key",
    )
    request = AuthorityProvisioningRequest(
        AUTHORITY_PROTOCOL, "installed", "astrbot_plugin_sylanne", "4.28.1",
        Path(tmp_path), Path(tmp_path), PublisherPackageIdentity(manifest),
    )
    grant = InstallationGrantV2(
        authority, "mtls:sha256:peer", "holder-a", "install-a", manifest,
        "policy-a", "capabilities-v2", binding,
    )
    handshake = AuthorityHandshake("paired", authority, grant.subject, binding, True)
    valid_sample = IngressClockSampleV2(
        authority, grant.installation_id, "admin:ntp-a", 1_800_000_000.25,
        123.5, "boot-a", 0.25,
    )

    class Transport:
        calls = 0

        async def handshake(self, observed_request, *, protocol):
            assert observed_request is request
            assert protocol == "sylanne3.authority.v2"
            return handshake

        async def installation_grant_v2(self, observed_request, observed_handshake):
            assert observed_request is request
            assert observed_handshake is handshake
            return grant

        async def ingress_clock_sample_v2(self, observed_request, observed_handshake,
                                          installation_id):
            self.calls += 1
            assert (observed_request, observed_handshake, installation_id) == (
                request, handshake, grant.installation_id,
            )
            if delay:
                await asyncio.sleep(delay)
            return valid_sample if sample is None else sample

        async def close(self):
            pass

    transport = Transport()
    port = V2FencePort(request, {"installed": profile}, grant,
                       transport_factory=lambda _: transport)
    return port, transport, valid_sample


def test_read_ingress_clock_returns_conservative_bound(tmp_path):
    port, transport, sample = _port(tmp_path)
    try:
        observed = port.read_ingress_clock(AdminIngressClockPolicy("admin:ntp-a", 0.5, 2))
        assert type(observed) is VerifiedIngressClockV2
        assert observed.sample is sample
        assert observed.monotonic_before_seconds <= observed.monotonic_after_seconds
        assert observed.utc_upper_bound_seconds == math.nextafter(math.fsum((
            sample.utc_seconds, sample.utc_error_seconds,
            observed.monotonic_after_seconds - observed.monotonic_before_seconds,
        )), math.inf)
        assert transport.calls == 1
    finally:
        port.close()


@pytest.mark.parametrize("change", [
    {"authority_id": "other"},
    {"installation_id": "other"},
    {"source_id": "admin:ntp-b"},
    {"utc_error_seconds": 0.75},
])
def test_clock_identity_source_and_error_fail_closed(tmp_path, change):
    sample = IngressClockSampleV2(
        "authority-a", "install-a", "admin:ntp-a", 1_800_000_000.25,
        123.5, "boot-a", 0.25,
    )
    port, _, _ = _port(tmp_path, sample=replace(sample, **change))
    try:
        with pytest.raises(RuntimeError, match="unqualified"):
            port.read_ingress_clock(AdminIngressClockPolicy("admin:ntp-a", 0.5, 2))
    finally:
        port.close()


def test_clock_requires_policy_and_exact_response_type(tmp_path):
    port, transport, _ = _port(tmp_path, sample={"utc_seconds": 1_800_000_000})
    try:
        with pytest.raises(RuntimeError, match="policy"):
            port.read_ingress_clock(None)
        assert transport.calls == 0
        with pytest.raises(RuntimeError, match="unqualified"):
            port.read_ingress_clock(AdminIngressClockPolicy("admin:ntp-a", 0.5, 2))
    finally:
        port.close()


def test_clock_rejects_excessive_round_trip(tmp_path):
    port, _, _ = _port(tmp_path, delay=0.02)
    try:
        with pytest.raises(RuntimeError, match="unqualified"):
            port.read_ingress_clock(AdminIngressClockPolicy("admin:ntp-a", 0.5, 0.001))
    finally:
        port.close()


@pytest.mark.asyncio
async def test_clock_cannot_block_host_event_loop(tmp_path):
    port, _, _ = await asyncio.to_thread(_port, tmp_path)
    try:
        with pytest.raises(RuntimeError, match="event loop thread"):
            port.read_ingress_clock(AdminIngressClockPolicy("admin:ntp-a", 0.5, 2))
    finally:
        await asyncio.to_thread(port.close)
