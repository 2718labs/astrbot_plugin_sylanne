"""Content-free Authority channel identities and administrator TLS material.

These contracts describe the pinned installation and paired channel. They never
open a runtime or replace the independent Authority's authorization decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import ssl

from ..authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL


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
_AUTHORITY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


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


@dataclass(frozen=True)
class AuthorityTlsProfile:
    """Installation-owned connection material; no key bytes are retained here."""

    profile_id: str
    host: str
    port: int
    server_name: str
    expected_authority_id: str
    trust_root: Path
    client_certificate: Path
    client_private_key: Path
    timeout_seconds: float = 5.0
    max_message_bytes: int = 65_536
    prepared_ssl_context: ssl.SSLContext | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not _PROFILE.fullmatch(self.profile_id):
            raise ValueError("invalid authority profile")
        if (not isinstance(self.host, str) or not self.host or len(self.host) > 255
                or not isinstance(self.server_name, str) or not self.server_name):
            raise ValueError("authority endpoint is invalid")
        if not isinstance(self.expected_authority_id, str) or not _AUTHORITY_ID.fullmatch(
            self.expected_authority_id
        ):
            raise ValueError("authority identity is invalid")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("authority port is invalid")
        if (not isinstance(self.timeout_seconds, (int, float))
                or not 0 < self.timeout_seconds <= 30):
            raise ValueError("authority timeout is invalid")
        if type(self.max_message_bytes) is not int or not 512 <= self.max_message_bytes <= 1_048_576:
            raise ValueError("authority message limit is invalid")
        for name in ("trust_root", "client_certificate", "client_private_key"):
            value = Path(getattr(self, name))
            if not value.is_absolute():
                raise ValueError(f"{name} must be an absolute administrator path")
            object.__setattr__(self, name, value)

    def ssl_context(self) -> ssl.SSLContext:
        """Use the verified context; direct profiles retain a test-only path seam.

        build_admin_authority_transport prepares the context from pinned file
        descriptors before creating this profile. Its production path cannot
        reach the pathname fallback below.
        """
        if self.prepared_ssl_context is not None:
            return self.prepared_ssl_context
        for path in (self.trust_root, self.client_certificate, self.client_private_key):
            if not path.is_file() or path.is_symlink():
                raise FileNotFoundError("administrator TLS material is unavailable or unsafe")
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(self.trust_root))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(str(self.client_certificate), str(self.client_private_key))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context


__all__ = (
    "AUTHORITY_PROTOCOL", "AUTHORITY_V2_PROTOCOL", "REQUIRED_AUTHORITY_CAPABILITIES",
    "AuthorityTlsProfile", "PublisherPackageIdentity", "AuthorityProvisioningRequest",
    "AuthorityHandshake", "AuthorityEnrollmentGrant", "AuthorityCapabilityGrant",
    "C09MaintenanceStatusReadV3",
)


@dataclass(frozen=True,slots=True)
class C09MaintenanceStatusReadV3:
    """Authenticated progress metadata; this value never opens selected storage."""
    operation_id: str
    status: str
    phase: str
    stage: str | None
    manifest_digest: str | None
    pointer_version: int | None
    storage_generation: int | None
    restart_required: bool
    channel_binding_sha256: str
    active_operation_id: str | None = None
    manifest_schema: str | None = None
    role: str | None = None
    bytes_processed: int | None = None
    producer_phase: str | None = None
    prepared_digest: str | None = None
    reason: str | None = None
    verified_event_seq: int | None = None
    actual_meter_bytes: int | None = None
    file_index: int | None = None
    byte_offset: int | None = None
    family: str | None = None
    schema: str = "sylanne3.c09.maintenance-status.v1"

    def __post_init__(self):
        from ..authority_service.contract import identifier
        identifier(self.operation_id,"operation_id")
        if (self.schema!="sylanne3.c09.maintenance-status.v1" or self.status not in {"progress","complete","failed"}
                or type(self.phase) is not str or not self.phase or type(self.restart_required) is not bool
                or _SHA256.fullmatch(self.channel_binding_sha256) is None
                or self.stage not in {None,"READY","INTENT","PREPARED","SWITCHED","CLEANED","RELEASED"}):
            raise ValueError("actual maintenance status/phase/channel metadata required")
        for name in ("pointer_version","storage_generation","bytes_processed","verified_event_seq","actual_meter_bytes","file_index","byte_offset"):
            value=getattr(self,name)
            if value is not None and (type(value) is not int or value<0):
                raise ValueError("maintenance progress counter must be an exact nonnegative integer")
        for name in ("role","producer_phase","reason","family","manifest_schema"):
            value=getattr(self,name)
            if value is not None and type(value) is not str:
                raise ValueError("maintenance progress text must retain its actual producer value")
        if self.active_operation_id is not None:identifier(self.active_operation_id,"active_operation_id")
        for name in ("manifest_digest","prepared_digest"):
            value=getattr(self,name)
            if value is not None and (type(value) is not str or _SHA256.fullmatch(value) is None):
                raise ValueError("maintenance metadata requires its actual canonical digest")
        if ((self.stage is None)!=(self.manifest_digest is None) or (self.stage is None)!=(self.pointer_version is None)
                or self.status=="failed" and self.reason is None):
            raise ValueError("maintenance status changed EOF metadata or first failure")

    def to_wire(self):
        from dataclasses import asdict
        return asdict(self)

    @classmethod
    def from_wire(cls,value):
        if type(value) is not dict or set(value)!=set(cls.__dataclass_fields__):
            raise ValueError("maintenance status response fields differ")
        result=cls(**value)
        if result.to_wire()!=value:raise ValueError("maintenance status wire is not canonical")
        return result
