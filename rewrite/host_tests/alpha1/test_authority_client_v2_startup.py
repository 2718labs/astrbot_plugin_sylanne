"""The host accepts only an installation grant from its paired v2 session."""

from dataclasses import replace
import hashlib
from pathlib import Path

import pytest

from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.host.authority_client import (
    AuthorityClient, AuthorityHandshake, AuthoritySelection,
)
from sylanne3.runtime_contracts import InstallationGrantV2


class V2Transport:
    def __init__(self, *, mismatch: str = "", unavailable: bool = False) -> None:
        self.mismatch = mismatch
        self.unavailable = unavailable
        self.protocols: list[str] = []
        self.capability_grant_called = False

    async def handshake(self, request, *, protocol):
        self.protocols.append(protocol)
        if self.unavailable:
            raise OSError("service unavailable")
        assert request.profile_id == "installed"
        return AuthorityHandshake(
            "paired", "authority-a", "mtls:sha256:" + "a" * 64, "b" * 64, True,
        )

    async def installation_grant_v2(self, request, handshake):
        grant = InstallationGrantV2(
            authority_id=handshake.installation_authority_id,
            subject=handshake.installation_identity_ref,
            administrator_holder="holder-a",
            installation_id="installation-a",
            manifest_digest=request.publisher_package.manifest_sha256,
            publisher_policy_ref="policy-a",
            service_capability_version="capabilities-v2",
            channel_binding_sha256=handshake.channel_binding_sha256,
        )
        mismatch = "c" * 64 if self.mismatch in {
            "manifest_digest", "channel_binding_sha256",
        } else "other"
        return replace(grant, **({self.mismatch: mismatch} if self.mismatch else {}))

    async def capability_grant(self, request, handshake):
        self.capability_grant_called = True
        raise AssertionError("v1 grant must not be used for v2 startup")


def client(tmp_path: Path, transport: V2Transport) -> AuthorityClient:
    package = tmp_path / "package"
    package.mkdir()
    (package / "release-manifest.json").write_text("{}", encoding="utf-8")
    return AuthorityClient(
        AuthoritySelection("installed"), package_root=package,
        data_dir=tmp_path, transport=transport,
    )


@pytest.mark.asyncio
async def test_v2_installation_grant_is_bound_without_global_activation(tmp_path):
    transport = V2Transport()
    authority = client(tmp_path, transport)
    assert (await authority.status_v2()).state == "paired"
    grant = await authority.installation_grant_v2()
    assert grant is not None
    assert grant.manifest_digest == hashlib.sha256(b"{}").hexdigest()
    assert grant.administrator_holder == "holder-a"
    assert not hasattr(grant, "activation_generation")
    assert transport.protocols == [AUTHORITY_V2_PROTOCOL]
    assert not transport.capability_grant_called


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ["authority_id", "subject", "manifest_digest", "channel_binding_sha256"],
)
async def test_mismatched_installation_grant_is_rejected(tmp_path, field):
    authority = client(tmp_path, V2Transport(mismatch=field))
    assert (await authority.status_v2()).state == "paired"
    assert await authority.installation_grant_v2() is None


@pytest.mark.asyncio
async def test_unavailable_v2_pairing_stays_blocked(tmp_path):
    authority = client(tmp_path, V2Transport(unavailable=True))
    assert (await authority.status_v2()).state == "unavailable"
    assert await authority.installation_grant_v2() is None


@pytest.mark.asyncio
async def test_manifest_change_after_pairing_invalidates_grant(tmp_path):
    authority = client(tmp_path, V2Transport())
    assert (await authority.status_v2()).state == "paired"
    (tmp_path / "package" / "release-manifest.json").write_text("{ }", encoding="utf-8")
    assert await authority.installation_grant_v2() is None
