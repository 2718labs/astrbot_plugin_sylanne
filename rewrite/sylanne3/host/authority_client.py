from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Protocol

from ..authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from ..authority_service.v2_contract import FencePermitV2
from ..authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressRecoveryV1,
)
from ..model_broker.broker import ModelCallRequest
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import InstallationGrantV2


AUTHORITY_PROTOCOL = "sylanne3.authority.v1"
REQUIRED_AUTHORITY_CAPABILITIES = frozenset(
    {
        "activate_target",
        "admit_dispatch",
        "begin_content_operation",
        "begin_transfer",
        "check",
        "current",
        "current_anchor",
        "end_content_operation",
        "observe_deletion_head",
        "observe_execution_head",
        "recover_transfer",
        "revoke_source",
        "verify_current",
    }
)
_PROFILE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class AuthoritySelection:
    """An administrator-created profile name, never authority credentials."""

    profile_id: str = "default"

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, str) or not _PROFILE.fullmatch(self.profile_id):
            raise ValueError("authority_profile must be a bounded profile identifier")


@dataclass(frozen=True)
class PublisherPackageIdentity:
    """Observed package bytes; the companion authority decides whether to trust them."""

    manifest_sha256: str

    def __post_init__(self) -> None:
        if not _SHA256.fullmatch(self.manifest_sha256):
            raise ValueError("publisher manifest digest must be lowercase SHA-256")


@dataclass(frozen=True)
class AuthorityProvisioningRequest:
    protocol: str
    profile_id: str
    plugin_name: str
    host_api_version: str
    package_root: Path
    data_dir: Path
    publisher_package: PublisherPackageIdentity

    def __post_init__(self) -> None:
        if self.protocol != AUTHORITY_PROTOCOL:
            raise ValueError("unsupported authority protocol")
        if not _PROFILE.fullmatch(self.profile_id):
            raise ValueError("invalid authority profile")
        if self.plugin_name != "astrbot_plugin_sylanne":
            raise ValueError("authority request targets the wrong plugin")
        if self.host_api_version != "4.28.1":
            raise ValueError("authority request host API is not the tested version")
        if not self.package_root.is_absolute() or not self.data_dir.is_absolute():
            raise ValueError("authority request paths must be absolute")


@dataclass(frozen=True)
class AuthorityHandshake:
    """Authenticated companion response, separate from publisher package trust."""

    state: str
    installation_authority_id: str = ""
    installation_identity_ref: str = ""
    channel_binding_sha256: str = ""
    publisher_trusted: bool = False

    def valid_pairing(self) -> bool:
        return (
            self.state == "paired"
            and bool(self.installation_authority_id)
            and bool(self.installation_identity_ref)
            and _SHA256.fullmatch(self.channel_binding_sha256) is not None
            and self.publisher_trusted is True
        )


@dataclass(frozen=True)
class AuthorityClientStatus:
    state: str
    authority_id: str = ""
    detail: str = ""


@dataclass(frozen=True)
class AuthorityEnrollmentGrant:
    """A paired-installation fact that cannot open a Sylanne runtime."""

    grant_id: str
    authority_id: str
    installation_identity_ref: str
    capabilities: tuple[str, ...]

    def valid_for(self, handshake: AuthorityHandshake) -> bool:
        return (
            bool(self.grant_id)
            and self.authority_id == handshake.installation_authority_id
            and self.installation_identity_ref == handshake.installation_identity_ref
            and self.capabilities == ("enrollment",)
        )


@dataclass(frozen=True)
class AuthorityCapabilityGrant:
    """Runtime authority facts used to construct local authenticated adapters."""

    grant_id: str
    authority_id: str
    installation_identity_ref: str
    activation_generation: int
    revocation_epoch: int
    capabilities: tuple[str, ...]

    def valid_for(self, handshake: AuthorityHandshake) -> bool:
        return (
            bool(self.grant_id)
            and self.authority_id == handshake.installation_authority_id
            and self.installation_identity_ref == handshake.installation_identity_ref
            and type(self.activation_generation) is int
            and self.activation_generation >= 0
            and type(self.revocation_epoch) is int
            and self.revocation_epoch >= 0
            and bool(self.capabilities)
            and tuple(sorted(set(self.capabilities))) == self.capabilities
            and REQUIRED_AUTHORITY_CAPABILITIES.issubset(self.capabilities)
        )


class AuthorityTransport(Protocol):
    """Port implemented only by an administrator-installed companion client.

    The implementation must authenticate a remote service with mutually
    authenticated transport, or an OS-protected local service identity. It must
    bind the handshake and provisioning response to the same authenticated
    channel. Content adapters must hold begin_content_operation through
    end_content_operation; a point-in-time check cannot implement the fence.
    Journal adapters must verify the current independent chain head even when
    the caller's previous and current heads are equal. AstrBot chat
    configuration is outside this trust boundary.
    """

    async def handshake(
        self, request: AuthorityProvisioningRequest, *, protocol: str = AUTHORITY_PROTOCOL,
    ) -> AuthorityHandshake: ...

    async def capability_grant(
        self,
        request: AuthorityProvisioningRequest,
        handshake: AuthorityHandshake,
    ) -> AuthorityEnrollmentGrant | AuthorityCapabilityGrant: ...

    async def installation_grant_v2(
        self, request: AuthorityProvisioningRequest, handshake: AuthorityHandshake,
    ) -> InstallationGrantV2: ...

    async def model_prepare_fenced_v1(self, request, handshake, grant, *, namespace,
                                      holder, draft, expected_anchor): ...

    async def model_admit_dispatch_once_v1(self, request, handshake, grant, *, namespace,
                                           holder, intent, expected_anchor,
                                           model_request): ...

    async def model_recover_fenced_v1(self, request, handshake, grant, *, namespace,
                                     holder, intent): ...


class AuthorityClient:
    """Fail-closed enrollment client for the separately installed authority."""

    def __init__(
        self,
        selection: AuthoritySelection,
        *,
        package_root: Path,
        data_dir: Path,
        transport: AuthorityTransport | None = None,
    ) -> None:
        if not isinstance(selection, AuthoritySelection):
            raise TypeError("selection must be AuthoritySelection")
        self._selection = selection
        self._package_root = Path(package_root)
        self._data_dir = Path(data_dir)
        if not self._package_root.is_absolute() or not self._data_dir.is_absolute():
            raise ValueError("authority client paths must be absolute")
        self._transport = transport
        self._request: AuthorityProvisioningRequest | None = None
        self._handshake: AuthorityHandshake | None = None
        self._v2_request: AuthorityProvisioningRequest | None = None
        self._v2_handshake: AuthorityHandshake | None = None

    def _build_request(self) -> AuthorityProvisioningRequest:
        manifest_path = self._package_root / "release-manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise FileNotFoundError("publisher release-manifest.json is unavailable or unsafe")
        identity = PublisherPackageIdentity(hashlib.sha256(manifest_path.read_bytes()).hexdigest())
        return AuthorityProvisioningRequest(
            protocol=AUTHORITY_PROTOCOL,
            profile_id=self._selection.profile_id,
            plugin_name="astrbot_plugin_sylanne",
            host_api_version="4.28.1",
            package_root=self._package_root,
            data_dir=self._data_dir,
            publisher_package=identity,
        )

    async def status(self) -> AuthorityClientStatus:
        if self._transport is None:
            return AuthorityClientStatus(
                "enrollment_required",
                detail="install and pair a Sylanne Authority companion service",
            )
        try:
            request = await asyncio.to_thread(self._build_request)
            handshake = await self._transport.handshake(request)
        except Exception:
            return AuthorityClientStatus("unavailable", detail="authority handshake failed")
        if not isinstance(handshake, AuthorityHandshake) or not handshake.valid_pairing():
            return AuthorityClientStatus(
                "enrollment_required",
                detail="authority profile is not paired or publisher package is not trusted",
            )
        self._request = request
        self._handshake = handshake
        return AuthorityClientStatus("paired", handshake.installation_authority_id)

    async def status_v2(self) -> AuthorityClientStatus:
        """Pair this installation using the v2 protocol on its authenticated channel."""
        self._v2_request = None
        self._v2_handshake = None
        if self._transport is None:
            return AuthorityClientStatus(
                "enrollment_required",
                detail="install and pair a Sylanne Authority companion service",
            )
        try:
            request = await asyncio.to_thread(self._build_request)
            handshake = await self._transport.handshake(
                request, protocol=AUTHORITY_V2_PROTOCOL,
            )
        except Exception:
            return AuthorityClientStatus("unavailable", detail="authority v2 handshake failed")
        if not isinstance(handshake, AuthorityHandshake) or not handshake.valid_pairing():
            return AuthorityClientStatus(
                "enrollment_required",
                detail="authority profile is not paired or publisher package is not trusted",
            )
        self._v2_request = request
        self._v2_handshake = handshake
        return AuthorityClientStatus("paired", handshake.installation_authority_id)

    async def installation_grant_v2(self) -> InstallationGrantV2 | None:
        """Return v2 installation facts only; no namespace activation is implied."""
        if self._transport is None:
            return None
        if self._v2_request is None or self._v2_handshake is None:
            if (await self.status_v2()).state != "paired":
                return None
        assert self._v2_request is not None and self._v2_handshake is not None
        try:
            current_request = await asyncio.to_thread(self._build_request)
            if current_request != self._v2_request:
                return None
            grant = await self._transport.installation_grant_v2(
                self._v2_request, self._v2_handshake,
            )
        except Exception:
            return None
        if not isinstance(grant, InstallationGrantV2):
            return None
        return grant if (
            grant.authority_id == self._v2_handshake.installation_authority_id
            and grant.subject == self._v2_handshake.installation_identity_ref
            and grant.manifest_digest == self._v2_request.publisher_package.manifest_sha256
            and grant.channel_binding_sha256 == self._v2_handshake.channel_binding_sha256
        ) else None

    async def _model_installation_context(self, bundle, grant: InstallationGrantV2):
        """Recheck installed facts and package bytes before each passive model RPC."""
        from .authority_profile import AdminInstallationBundle
        if (type(bundle) is not AdminInstallationBundle
                or type(grant) is not InstallationGrantV2
                or self._transport is None
                or self._v2_request is None or self._v2_handshake is None):
            raise RuntimeError("authority model installation is unavailable")
        policy = bundle.installation_policy
        request = self._v2_request
        handshake = self._v2_handshake
        current = await asyncio.to_thread(self._build_request)
        installed_profile = getattr(self._transport, "profile_for", None)
        if (current != request or not handshake.valid_pairing()
                or installed_profile is None
                or installed_profile(request.profile_id) != bundle.tls_profile
                or bundle.tls_profile.profile_id != request.profile_id
                or bundle.tls_profile.expected_authority_id != grant.authority_id
                or (policy.expected_authority_id, policy.installation_id,
                    policy.manifest_digest, policy.administrator_holder) !=
                   (grant.authority_id, grant.installation_id,
                    grant.manifest_digest, grant.administrator_holder)
                or grant.authority_id != handshake.installation_authority_id
                or grant.subject != handshake.installation_identity_ref
                or grant.channel_binding_sha256 != handshake.channel_binding_sha256
                or grant.manifest_digest != request.publisher_package.manifest_sha256):
            raise RuntimeError("authority model installation binding is invalid")
        return request, handshake, policy

    async def model_prepare_fenced_v1(
        self, bundle, grant: InstallationGrantV2, *, draft: ModelEgressDraftV1,
        expected_anchor: RestoreAnchor,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2]:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_prepare_fenced_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, draft=draft,
            expected_anchor=expected_anchor)

    async def model_admit_dispatch_once_v1(
        self, bundle, grant: InstallationGrantV2, *, intent: ModelEgressIntentV1,
        expected_anchor: RestoreAnchor, model_request: ModelCallRequest,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2]:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        if model_request.envelope.authority.namespace != policy.namespace:
            raise RuntimeError("authority model namespace binding is invalid")
        return await self._transport.model_admit_dispatch_once_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, intent=intent,
            expected_anchor=expected_anchor, model_request=model_request)

    async def model_recover_fenced_v1(
        self, bundle, grant: InstallationGrantV2, *, intent: ModelEgressIntentV1,
    ) -> tuple[ModelEgressRecoveryV1, FencePermitV2]:
        request, handshake, policy = await self._model_installation_context(bundle, grant)
        return await self._transport.model_recover_fenced_v1(
            request, handshake, grant, namespace=policy.authority_namespace,
            holder=policy.administrator_holder, intent=intent)

    async def capability_grant(self) -> AuthorityCapabilityGrant | None:
        """Return a complete runtime grant; enrollment-only facts remain blocked."""
        grant = await self.enrollment_grant()
        return (
            grant
            if isinstance(grant, AuthorityCapabilityGrant)
            and self._handshake is not None
            and grant.valid_for(self._handshake)
            else None
        )

    async def enrollment_grant(
        self,
    ) -> AuthorityEnrollmentGrant | AuthorityCapabilityGrant | None:
        """Fetch a paired-installation fact without treating it as runtime-ready."""
        if self._transport is None:
            return None
        if self._request is None or self._handshake is None:
            status = await self.status()
            if status.state != "paired":
                return None
        assert self._request is not None and self._handshake is not None
        try:
            grant = await self._transport.capability_grant(
                self._request, self._handshake
            )
        except Exception:
            return None
        if isinstance(grant, AuthorityEnrollmentGrant):
            return grant if grant.valid_for(self._handshake) else None
        if isinstance(grant, AuthorityCapabilityGrant):
            return grant if grant.valid_for(self._handshake) else None
        return None


__all__ = (
    "AUTHORITY_PROTOCOL",
    "AuthorityClient",
    "AuthorityClientStatus",
    "AuthorityEnrollmentGrant",
    "AuthorityCapabilityGrant",
    "AuthorityHandshake",
    "AuthorityProvisioningRequest",
    "AuthoritySelection",
    "AuthorityTransport",
    "PublisherPackageIdentity",
    "REQUIRED_AUTHORITY_CAPABILITIES",
)
