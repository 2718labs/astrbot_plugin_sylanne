"""Load a separately installed, administrator-owned Authority TLS profile.

The chat-facing value is only a bounded profile identifier. Deployment owns
the endpoint, expected TLS server identity, Authority ID, trust root and client
credential. POSIX material is opened through verified descriptors before TLS
consumes it. Windows keeps checked handles pinned while OpenSSL reads paths.
"""

from __future__ import annotations

import errno
import ctypes
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field, replace
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import ssl
import stat
from types import MappingProxyType
from typing import Iterator, Mapping, TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .mtls_transport import MtlsAuthorityTransport
    from ..authority_service.d12_package_files_v2 import PackageSelectionV2
    from .model_workflows_v3 import AdminModelWorkflowsV3
    from .model_workflows_v4 import AdminModelWorkflowsV4
    from .model_workflows_v5 import AdminModelWorkflowsV5
    from .model_workflows_v6 import AdminModelWorkflowsV6
    from .model_workflows_v7 import AdminModelWorkflowsV7
    from .model_workflows_v8 import AdminModelWorkflowsV8
    from .model_workflows_v9 import AdminModelWorkflowsV9

from ..installation_policy import AdminInstallationPolicy
from ..runtime.budget import BudgetLease
from ..runtime.d04_semantic_policy import (
    AdminD04SemanticDrivePolicyV1, MECHANISMS as D04_MECHANISMS,
    WORK_KIND as D04_SEMANTIC_WORK_KIND,
)
from ..runtime.d13_technical_policy import (
    AdminD13PaidPrecompressionPolicyV1, AdminD13PrecompressionPolicyV1,
)
from ..model_broker.d13_precompression import D13PrecompressionInstallationV1
from ..runtime_contracts import NamespaceId, canonical_digest
from ..model_broker.provider_billing_receipt_v1 import ProviderBillingPolicyV1, provider_billing_policy_from_wire_v1
from ..model_broker.artifact_phase_count_v1 import ArtifactPhaseCountPolicyV1
from ..runtime_contracts import (
    CONTEXT_REPLY_WORKFLOW_V1 as CONTEXT_REPLY_TEMPLATE_VERSION,
    NATURAL_REPLY_GENERATION_WORKFLOW_V2 as NATURAL_GENERATION_TEMPLATE_VERSION,
    NATURAL_REPLY_GENERATION_WORKFLOW_V3 as NATURAL_GENERATION_TEMPLATE_VERSION_V3,
    NATURAL_REPLY_GENERATION_WORKFLOW_V4 as NATURAL_GENERATION_TEMPLATE_VERSION_V4,
    NATURAL_REPLY_GENERATION_WORKFLOW_V5 as NATURAL_GENERATION_TEMPLATE_VERSION_V5,
    NATURAL_REPLY_REVIEW_WORKFLOW_V1 as REVIEW_TEMPLATE_VERSION,
    NATURAL_REPLY_REVIEW_WORKFLOW_V2 as REVIEW_TEMPLATE_VERSION_V2,
    CONTACT_GENERATION_WORKFLOW_V1 as CONTACT_GENERATION_TEMPLATE_VERSION,
    CONTACT_REVIEW_WORKFLOW_V1 as CONTACT_REVIEW_TEMPLATE_VERSION,
    D04_APPRAISAL_TEMPLATE_V1 as APPRAISAL_TEMPLATE_VERSION,
    D04_APPRAISAL_WORK_KIND as APPRAISAL_WORK_KIND,
)
from .authority_transport_contract import AuthorityTlsProfile


_PROFILE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_PROFILE_FIELDS_V1 = frozenset({
    "schema", "host", "port", "server_name", "expected_authority_id",
})
_PROFILE_FIELDS_V2 = _PROFILE_FIELDS_V1 | {"installation_policy"}
_INGRESS_CLOCK_FIELDS = frozenset({
    "source_id", "max_utc_error_seconds", "max_round_trip_seconds",
})
_INGRESS_ENCODING_FIELDS = frozenset({
    "deadline_after_seconds", "quote_ceiling", "snapshot_ref", "resource_ref",
    "character_interval_ref",
})
_D03_ARRIVAL_FIELDS = frozenset({
    "deadline_after_seconds", "quote_ceiling", "snapshot_ref", "resource_ref",
})
_D04_BASELINE_FIELDS = _D03_ARRIVAL_FIELDS
_D03_SELF_PROJECTION_FIELDS = _D03_ARRIVAL_FIELDS
_D06_FIRST_INGRESS_C02_FIELDS = _D03_ARRIVAL_FIELDS
_D06_SOURCE_CORRECTION_FIELDS = _D03_ARRIVAL_FIELDS
_D06_PRIVATE_REPLY_SOURCE_FIELDS = frozenset({
    "version", "scope", "grant_expression",
})
_D07_ATTENTION_FIELDS = _D03_ARRIVAL_FIELDS
_PRIVATE_REPLY_DISPATCH_FIELDS = _D03_ARRIVAL_FIELDS | {
    "segment_max_chars", "host_takeover_wait_seconds",
}
_D13_PRECOMPRESSION_FIELDS = frozenset({
    "history_token_budget", "quote_ceiling", "deadline_after_seconds",
    "max_slots", "resource_ref",
})
_D13_PAID_PRECOMPRESSION_FIELDS = _D13_PRECOMPRESSION_FIELDS
_D04_SEMANTIC_DRIVE_FIELDS = frozenset({
    "version", "mapping_version", "basis_version",
    "mechanism_max_abs_doses", "mechanism_max_family_share",
})
_INGRESS_MODEL_FIELDS = frozenset({
    "provider_id", "model_id", "provider_config_ref", "provider_config_digest",
    "timeout_seconds", "max_output_tokens", "required_capabilities", "privacy_tier",
})
_INGRESS_MODEL_SCOPE_FIELDS = frozenset({
    "allowed_purposes", "allowed_audiences", "allowed_privacy_tiers",
})
_MODEL_WORKFLOW_FIELDS = frozenset({
    "work_kind", "provider_id", "model_id", "provider_config_ref",
    "provider_config_digest", "purpose", "audiences", "privacy_tier",
    "template_version", "required_capabilities", "timeout_seconds",
    "max_output_tokens", "quote_ceiling",
})
_RESOURCE_DIMENSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_INSTALLATION_FIELDS = frozenset({
    "namespace", "authority_namespace", "installation_id", "manifest_digest",
    "administrator_holder", "expected_authority_id", "catalogue_hash",
    "scheme_version", "operator_version", "policy_version", "root_lease",
    "root_grant",
})
_LEASE_FIELDS = frozenset({
    "lease_id", "parent_id", "bot_id", "persona_id", "currency", "limits",
    "used", "reserved", "unconfirmed", "version", "state",
})
_GRANT_FIELDS = frozenset({
    "grant_id", "version", "bot_id", "persona_id", "lease_id", "currency",
    "max_ceiling", "allowed_work_kinds", "valid_until_utc", "policy_ref",
})
_MATERIAL = ("trust-root.pem", "client-cert.pem", "client-key.pem")
_REVERSE_MATERIAL = ("reverse-trust-root.pem", "reverse-cert.pem", "reverse-key.pem")
_REVERSE_FIELDS = frozenset({
    "profile_id", "listen_host", "endpoint_host", "port", "server_name",
    "expected_authority_certificate_sha256",
})
_D11_SIGNING_KEY = "d11-signing.key"
_D11_SIGNING_KEY_BYTES = 32
_D02_SIGNING_KEY = "d02-signing.key"
_C04_SIGNING_KEY = "c04-signing.key"
_MAX_PROFILE_BYTES = 32768
_MAX_MATERIAL_BYTES = 1_048_576
_WIN_GENERIC_READ = 0x80000000
_WIN_SHARE_READ = 0x00000001
_WIN_OPEN_EXISTING = 3
_WIN_BACKUP_SEMANTICS = 0x02000000
_WIN_OPEN_REPARSE_POINT = 0x00200000
_WIN_REPARSE_POINT = 0x00000400
_WIN_DIRECTORY = 0x00000010


def installed_model_config_ref(provider_id: str, model_id: str,
                               config_digest: str) -> str:
    """Content address for an exact installed AstrBot model configuration."""
    return "astrbot-config:" + canonical_digest({
        "schema": "sylanne.astrbot.model-config.v1",
        "provider_id": provider_id, "model_id": model_id,
        "config_digest": config_digest,
    })


class _Filetime(ctypes.Structure):
    _fields_ = (("low", ctypes.c_uint32), ("high", ctypes.c_uint32))


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = (
        ("attributes", ctypes.c_uint32),
        ("created", _Filetime), ("accessed", _Filetime), ("written", _Filetime),
        ("volume_serial", ctypes.c_uint32), ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32), ("links", ctypes.c_uint32),
        ("index_high", ctypes.c_uint32), ("index_low", ctypes.c_uint32),
    )


class AuthorityProfileUnavailable(RuntimeError):
    """The host cannot establish the installed-profile trust boundary."""


@dataclass(frozen=True, slots=True)
class AdminIngressClockPolicy:
    """Administrator-provided clock bounds for a future real ingress."""

    source_id: str
    max_utc_error_seconds: float
    max_round_trip_seconds: float

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise ValueError("ingress clock source_id must be non-empty")
        for name in ("max_utc_error_seconds", "max_round_trip_seconds"):
            value = getattr(self, name)
            if (type(value) not in {int, float} or value <= 0
                    or type(value) is float and not math.isfinite(value)):
                raise ValueError(f"ingress clock {name} must be finite and positive")


@dataclass(frozen=True, slots=True)
class AdminIngressEncodingPolicy:
    """Administrator bounds and provenance for a future source encoder."""

    deadline_after_seconds: float
    quote_ceiling: Mapping[str, int]
    snapshot_ref: str
    resource_ref: str
    character_interval_ref: str

    def __post_init__(self) -> None:
        from ..runtime.issuers import MAX_DIMENSIONS, MAX_QUANTITY

        deadline = self.deadline_after_seconds
        try:
            valid_deadline = (type(deadline) in {int, float} and deadline > 0
                              and math.isfinite(deadline))
        except OverflowError:
            valid_deadline = False
        if not valid_deadline:
            raise ValueError("ingress encoding deadline must be finite and positive")
        ceiling = self.quote_ceiling
        if not isinstance(ceiling, Mapping) or not 0 < len(ceiling) <= MAX_DIMENSIONS:
            raise ValueError("ingress encoding quote ceiling must be nonempty and bounded")
        snapshot: dict[str, int] = {}
        for name, amount in ceiling.items():
            if (type(name) is not str or _RESOURCE_DIMENSION.fullmatch(name) is None
                    or type(amount) is not int or not 0 < amount <= MAX_QUANTITY):
                raise ValueError("ingress encoding quote ceiling contains an invalid amount")
            snapshot[name] = amount
        object.__setattr__(self, "quote_ceiling", MappingProxyType(snapshot))
        for name in ("snapshot_ref", "resource_ref", "character_interval_ref"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise ValueError(f"ingress encoding {name} must be nonempty")


@dataclass(frozen=True, slots=True)
class AdminD03ArrivalPolicy:
    """Installed per-arrival price; the root grant remains only an upper bound."""

    deadline_after_seconds: float
    quote_ceiling: Mapping[str, int]
    snapshot_ref: str
    resource_ref: str

    def __post_init__(self) -> None:
        from ..runtime.issuers import MAX_DIMENSIONS, MAX_QUANTITY

        deadline = self.deadline_after_seconds
        if (type(deadline) not in {int, float} or not math.isfinite(deadline)
                or deadline <= 0):
            raise ValueError("D03 arrival deadline must be finite and positive")
        ceiling = self.quote_ceiling
        if not isinstance(ceiling, Mapping) or not 0 < len(ceiling) <= MAX_DIMENSIONS:
            raise ValueError("D03 arrival quote ceiling must be nonempty and bounded")
        normalized: dict[str, int] = {}
        for name, amount in ceiling.items():
            if (type(name) is not str or _RESOURCE_DIMENSION.fullmatch(name) is None
                    or type(amount) is not int or not 0 < amount <= MAX_QUANTITY):
                raise ValueError("D03 arrival quote ceiling contains an invalid amount")
            normalized[name] = amount
        object.__setattr__(self, "quote_ceiling", MappingProxyType(normalized))
        for name in ("snapshot_ref", "resource_ref"):
            value = getattr(self, name)
            if (type(value) is not str or _RESOURCE_DIMENSION.fullmatch(value) is None):
                raise ValueError(f"D03 arrival {name} must be a canonical resource ID")

    def digest_payload(self) -> dict[str, object]:
        return {
            "deadline_after_seconds": self.deadline_after_seconds,
            "quote_ceiling": dict(self.quote_ceiling),
            "snapshot_ref": self.snapshot_ref,
            "resource_ref": self.resource_ref,
        }


@dataclass(frozen=True, slots=True)
class AdminPrivateReplyDispatchPolicy:
    """Installed price and segment bound for a private K03 message dispatch."""

    deadline_after_seconds: float
    quote_ceiling: Mapping[str, int]
    snapshot_ref: str
    resource_ref: str
    segment_max_chars: int
    host_takeover_wait_seconds: float

    def __post_init__(self) -> None:
        from ..runtime.issuers import MAX_DIMENSIONS, MAX_QUANTITY

        deadline = self.deadline_after_seconds
        if (type(deadline) not in {int, float} or not math.isfinite(deadline)
                or not 0 < deadline <= 300):
            raise ValueError("private reply dispatch deadline must be bounded")
        ceiling = self.quote_ceiling
        if not isinstance(ceiling, Mapping) or not 0 < len(ceiling) <= MAX_DIMENSIONS:
            raise ValueError("private reply dispatch quote ceiling must be nonempty")
        normalized: dict[str, int] = {}
        for name, amount in ceiling.items():
            if (type(name) is not str or _RESOURCE_DIMENSION.fullmatch(name) is None
                    or type(amount) is not int or not 0 < amount <= MAX_QUANTITY):
                raise ValueError("private reply dispatch quote ceiling is invalid")
            normalized[name] = amount
        object.__setattr__(self, "quote_ceiling", MappingProxyType(normalized))
        for name in ("snapshot_ref", "resource_ref"):
            value = getattr(self, name)
            if type(value) is not str or _RESOURCE_DIMENSION.fullmatch(value) is None:
                raise ValueError(f"private reply dispatch {name} is invalid")
        if type(self.segment_max_chars) is not int or not 1 <= self.segment_max_chars <= 2048:
            raise ValueError("private reply dispatch segment_max_chars must be 1..2048")
        wait = self.host_takeover_wait_seconds
        if (type(wait) not in {int, float} or not math.isfinite(wait)
                or not 0 < wait <= 300):
            raise ValueError("private reply dispatch host takeover wait must be bounded")

    def digest_payload(self) -> dict[str, object]:
        return {
            "deadline_after_seconds": self.deadline_after_seconds,
            "quote_ceiling": dict(self.quote_ceiling),
            "snapshot_ref": self.snapshot_ref,
            "resource_ref": self.resource_ref,
            "segment_max_chars": self.segment_max_chars,
            "host_takeover_wait_seconds": self.host_takeover_wait_seconds,
        }


@dataclass(frozen=True, slots=True)
class AdminD07AttentionPolicy:
    """Administrator-bounded CPU price for one source-bound D07 selection."""

    deadline_after_seconds: float
    quote_ceiling: Mapping[str, int]
    snapshot_ref: str
    resource_ref: str

    def __post_init__(self) -> None:
        from ..runtime.issuers import MAX_DIMENSIONS, MAX_QUANTITY

        if (type(self.deadline_after_seconds) not in (int, float)
                or not math.isfinite(self.deadline_after_seconds)
                or not 0 < self.deadline_after_seconds <= 300):
            raise ValueError("D07 attention deadline must be bounded")
        ceiling = self.quote_ceiling
        if (not isinstance(ceiling, Mapping) or not 0 < len(ceiling) <= MAX_DIMENSIONS
                or any(type(name) is not str
                       or _RESOURCE_DIMENSION.fullmatch(name) is None
                       or type(amount) is not int or not 0 < amount <= MAX_QUANTITY
                       for name, amount in ceiling.items())):
            raise ValueError("D07 attention quote ceiling is invalid")
        object.__setattr__(self, "quote_ceiling", MappingProxyType(dict(ceiling)))
        for name in ("snapshot_ref", "resource_ref"):
            if (type(getattr(self, name)) is not str
                    or _RESOURCE_DIMENSION.fullmatch(getattr(self, name)) is None):
                raise ValueError(f"D07 attention {name} is invalid")

    def digest_payload(self) -> dict[str, object]:
        return {
            "deadline_after_seconds": self.deadline_after_seconds,
            "quote_ceiling": dict(self.quote_ceiling),
            "snapshot_ref": self.snapshot_ref,
            "resource_ref": self.resource_ref,
        }


@dataclass(frozen=True, slots=True)
class AdminD04EncodingBaselinePolicy:
    """Installed price for a separate D04 baseline stage."""

    deadline_after_seconds: float
    quote_ceiling: Mapping[str, int]
    snapshot_ref: str
    resource_ref: str

    def __post_init__(self) -> None:
        from ..runtime.issuers import MAX_DIMENSIONS, MAX_QUANTITY

        deadline = self.deadline_after_seconds
        if (type(deadline) not in {int, float} or not math.isfinite(deadline)
                or deadline <= 0):
            raise ValueError("D04 baseline deadline must be finite and positive")
        ceiling = self.quote_ceiling
        if not isinstance(ceiling, Mapping) or not 0 < len(ceiling) <= MAX_DIMENSIONS:
            raise ValueError("D04 baseline quote ceiling must be nonempty and bounded")
        normalized: dict[str, int] = {}
        for name, amount in ceiling.items():
            if (type(name) is not str or _RESOURCE_DIMENSION.fullmatch(name) is None
                    or type(amount) is not int or not 0 < amount <= MAX_QUANTITY):
                raise ValueError("D04 baseline quote ceiling contains an invalid amount")
            normalized[name] = amount
        object.__setattr__(self, "quote_ceiling", MappingProxyType(normalized))
        for name in ("snapshot_ref", "resource_ref"):
            value = getattr(self, name)
            if type(value) is not str or _RESOURCE_DIMENSION.fullmatch(value) is None:
                raise ValueError(f"D04 baseline {name} must be a canonical resource ID")

    def digest_payload(self) -> dict[str, object]:
        return {
            "deadline_after_seconds": self.deadline_after_seconds,
            "quote_ceiling": dict(self.quote_ceiling),
            "snapshot_ref": self.snapshot_ref,
            "resource_ref": self.resource_ref,
        }


@dataclass(frozen=True, slots=True)
class AdminD03SelfIdentityProjectionPolicy:
    """Installed price for the separate D03 identity projection stage."""

    deadline_after_seconds: float
    quote_ceiling: Mapping[str, int]
    snapshot_ref: str
    resource_ref: str

    def __post_init__(self) -> None:
        from ..runtime.issuers import MAX_DIMENSIONS, MAX_QUANTITY

        deadline = self.deadline_after_seconds
        if (type(deadline) not in {int, float} or not math.isfinite(deadline)
                or deadline <= 0):
            raise ValueError("D03 projection deadline must be finite and positive")
        ceiling = self.quote_ceiling
        if not isinstance(ceiling, Mapping) or not 0 < len(ceiling) <= MAX_DIMENSIONS:
            raise ValueError("D03 projection quote ceiling must be nonempty and bounded")
        normalized: dict[str, int] = {}
        for name, amount in ceiling.items():
            if (type(name) is not str or _RESOURCE_DIMENSION.fullmatch(name) is None
                    or type(amount) is not int or not 0 < amount <= MAX_QUANTITY):
                raise ValueError("D03 projection quote ceiling contains an invalid amount")
            normalized[name] = amount
        object.__setattr__(self, "quote_ceiling", MappingProxyType(normalized))
        for name in ("snapshot_ref", "resource_ref"):
            value = getattr(self, name)
            if type(value) is not str or _RESOURCE_DIMENSION.fullmatch(value) is None:
                raise ValueError(f"D03 projection {name} must be a canonical resource ID")

    def digest_payload(self) -> dict[str, object]:
        return {
            "deadline_after_seconds": self.deadline_after_seconds,
            "quote_ceiling": dict(self.quote_ceiling),
            "snapshot_ref": self.snapshot_ref,
            "resource_ref": self.resource_ref,
        }


@dataclass(frozen=True, slots=True)
class AdminD06FirstIngressC02Policy:
    """Installed price for adopting one completed first-ingress encoding."""

    deadline_after_seconds: float
    quote_ceiling: Mapping[str, int]
    snapshot_ref: str
    resource_ref: str

    def __post_init__(self) -> None:
        from ..runtime.issuers import MAX_DIMENSIONS, MAX_QUANTITY

        deadline = self.deadline_after_seconds
        if (type(deadline) not in {int, float} or not math.isfinite(deadline)
                or deadline <= 0):
            raise ValueError("D06 C02 deadline must be finite and positive")
        ceiling = self.quote_ceiling
        if not isinstance(ceiling, Mapping) or not 0 < len(ceiling) <= MAX_DIMENSIONS:
            raise ValueError("D06 C02 quote ceiling must be nonempty and bounded")
        normalized: dict[str, int] = {}
        for name, amount in ceiling.items():
            if (type(name) is not str or _RESOURCE_DIMENSION.fullmatch(name) is None
                    or type(amount) is not int or not 0 < amount <= MAX_QUANTITY):
                raise ValueError("D06 C02 quote ceiling contains an invalid amount")
            if name in {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}:
                raise ValueError("D06 C02 cannot quote the already-settled model call")
            normalized[name] = amount
        object.__setattr__(self, "quote_ceiling", MappingProxyType(normalized))
        for name in ("snapshot_ref", "resource_ref"):
            value = getattr(self, name)
            if type(value) is not str or _RESOURCE_DIMENSION.fullmatch(value) is None:
                raise ValueError(f"D06 C02 {name} must be a canonical resource ID")

    def digest_payload(self) -> dict[str, object]:
        return {
            "deadline_after_seconds": self.deadline_after_seconds,
            "quote_ceiling": dict(self.quote_ceiling),
            "snapshot_ref": self.snapshot_ref,
            "resource_ref": self.resource_ref,
        }


@dataclass(frozen=True, slots=True)
class AdminD06SourceCorrectionPolicy:
    """Installed price for correcting a source without pricing user input."""

    deadline_after_seconds: float
    quote_ceiling: Mapping[str, int]
    snapshot_ref: str
    resource_ref: str

    def __post_init__(self) -> None:
        from ..runtime.issuers import MAX_DIMENSIONS, MAX_QUANTITY

        deadline = self.deadline_after_seconds
        if (type(deadline) not in {int, float} or not math.isfinite(deadline)
                or deadline <= 0):
            raise ValueError("D06 source correction deadline must be finite and positive")
        ceiling = self.quote_ceiling
        if not isinstance(ceiling, Mapping) or not 0 < len(ceiling) <= MAX_DIMENSIONS:
            raise ValueError("D06 source correction quote ceiling must be nonempty and bounded")
        normalized: dict[str, int] = {}
        for name, amount in ceiling.items():
            if (type(name) is not str or _RESOURCE_DIMENSION.fullmatch(name) is None
                    or type(amount) is not int or not 0 < amount <= MAX_QUANTITY):
                raise ValueError("D06 source correction quote ceiling contains an invalid amount")
            normalized[name] = amount
        object.__setattr__(self, "quote_ceiling", MappingProxyType(normalized))
        for name in ("snapshot_ref", "resource_ref"):
            value = getattr(self, name)
            if type(value) is not str or _RESOURCE_DIMENSION.fullmatch(value) is None:
                raise ValueError(f"D06 source correction {name} must be a canonical resource ID")

    def digest_payload(self) -> dict[str, object]:
        return {
            "deadline_after_seconds": self.deadline_after_seconds,
            "quote_ceiling": dict(self.quote_ceiling),
            "snapshot_ref": self.snapshot_ref,
            "resource_ref": self.resource_ref,
        }


@dataclass(frozen=True, slots=True)
class AdminIngressModelPolicy:
    """Exact administrator selection; it does not grant model egress."""

    provider_id: str
    model_id: str
    provider_config_ref: str
    provider_config_digest: str
    timeout_seconds: float
    max_output_tokens: int
    required_capabilities: tuple[str, ...]
    privacy_tier: str
    allowed_purposes: tuple[str, ...] = ()
    allowed_audiences: tuple[str, ...] = ()
    allowed_privacy_tiers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("provider_id", "model_id", "privacy_tier"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip() or len(value) > 256:
                raise ValueError(f"ingress model {name} must be a bounded string")
        digest = self.provider_config_digest
        if (type(digest) is not str or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)):
            raise ValueError("ingress model config digest must be lowercase SHA-256")
        if self.provider_config_ref != installed_model_config_ref(
                self.provider_id, self.model_id, digest):
            raise ValueError("ingress model config ref differs from content identity")
        timeout = self.timeout_seconds
        try:
            valid_timeout = (type(timeout) in {int, float}
                             and math.isfinite(timeout) and 0 < timeout <= 300)
        except OverflowError:
            valid_timeout = False
        if not valid_timeout:
            raise ValueError("ingress model timeout must be in (0, 300]")
        if type(self.max_output_tokens) is not int or self.max_output_tokens < 1:
            raise ValueError("ingress model output token ceiling must be positive")
        capabilities = self.required_capabilities
        if (type(capabilities) is not tuple or not capabilities
                or len(capabilities) > 16
                or any(type(item) is not str or not item.strip() or len(item) > 128
                       for item in capabilities)
                or len(set(capabilities)) != len(capabilities)):
            raise ValueError("ingress model capabilities must be unique bounded strings")
        scopes = (self.allowed_purposes, self.allowed_audiences,
                  self.allowed_privacy_tiers)
        if any(scopes) and not all(scopes):
            raise ValueError("ingress model egress scope must be complete")
        for scope in scopes:
            if (type(scope) is not tuple or len(scope) > 16
                    or any(type(item) is not str or not item.strip()
                           or len(item) > 128 for item in scope)
                    or len(set(scope)) != len(scope)):
                raise ValueError("ingress model egress scope is invalid")


@dataclass(frozen=True, slots=True)
class AdminModelWorkflowV2:
    """One administrator-selected model work item, without an egress grant."""

    work_kind: str
    provider_id: str
    model_id: str
    provider_config_ref: str
    provider_config_digest: str
    purpose: str
    audiences: tuple[str, ...]
    privacy_tier: str
    template_version: str
    required_capabilities: tuple[str, ...]
    timeout_seconds: float
    max_output_tokens: int
    quote_ceiling: Mapping[str, int]

    def __post_init__(self) -> None:
        from ..runtime.issuers import MAX_DIMENSIONS, MAX_QUANTITY

        for name in ("work_kind", "provider_id", "model_id", "purpose",
                     "privacy_tier", "template_version"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip() or len(value) > 256:
                raise ValueError(f"model workflow {name} must be bounded")
        digest = self.provider_config_digest
        if (type(digest) is not str or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
                or self.provider_config_ref != installed_model_config_ref(
                    self.provider_id, self.model_id, digest)):
            raise ValueError("model workflow configuration identity is invalid")
        for name in ("audiences", "required_capabilities"):
            values = getattr(self, name)
            if (type(values) is not tuple or not 0 < len(values) <= 16
                    or len(set(values)) != len(values)
                    or any(type(value) is not str or not value.strip()
                           or len(value) > 128 for value in values)):
                raise ValueError(f"model workflow {name} is invalid")
        if (type(self.timeout_seconds) not in (int, float)
                or not math.isfinite(self.timeout_seconds)
                or not 0 < self.timeout_seconds <= 300
                or type(self.max_output_tokens) is not int
                or self.max_output_tokens < 1):
            raise ValueError("model workflow timeout or output bound is invalid")
        ceiling = self.quote_ceiling
        if (not isinstance(ceiling, Mapping) or not 0 < len(ceiling) <= MAX_DIMENSIONS
                or any(type(name) is not str
                       or _RESOURCE_DIMENSION.fullmatch(name) is None
                       or type(amount) is not int or not 0 < amount <= MAX_QUANTITY
                       for name, amount in ceiling.items())
                or ceiling.get("output_tokens", 0) < self.max_output_tokens):
            raise ValueError("model workflow quote ceiling is invalid")
        object.__setattr__(self, "quote_ceiling", MappingProxyType(dict(ceiling)))


@dataclass(frozen=True, slots=True)
class AdminModelWorkflowsV2:
    """Separate installed model work kinds in one checked profile snapshot."""

    version: int
    encode: AdminModelWorkflowV2
    reply: AdminModelWorkflowV2
    context_reply: AdminModelWorkflowV2 | None = None
    natural_generation: AdminModelWorkflowV2 | None = None
    natural_review: AdminModelWorkflowV2 | None = None
    appraisal: AdminModelWorkflowV2 | None = None
    d07_cognition: AdminModelWorkflowV2 | None = None
    contact_generation: AdminModelWorkflowV2 | None = None
    contact_review: AdminModelWorkflowV2 | None = None

    def __post_init__(self) -> None:
        from ..model_broker.d07_cognition_v1 import RECALL_TEMPLATE_VERSION_V1
        if (type(self.version) is not int or self.version != 2
                or type(self.encode) is not AdminModelWorkflowV2
                or type(self.reply) is not AdminModelWorkflowV2
                or (self.encode.work_kind, self.encode.purpose)
                != ("d06.encode_source", "consolidation")
                or (self.reply.work_kind, self.reply.purpose)
                != ("reply", "proposal")
                or any(workflow is not None and (
                    type(workflow) is not AdminModelWorkflowV2
                    or (workflow.work_kind, workflow.purpose,
                        workflow.template_version) not in (
                            (expected, ("natural_generation", "proposal", NATURAL_GENERATION_TEMPLATE_VERSION_V3),
                                       ("natural_generation", "proposal", NATURAL_GENERATION_TEMPLATE_VERSION_V4),
                                       ("natural_generation", "proposal", NATURAL_GENERATION_TEMPLATE_VERSION_V5))
                            if expected[0] == "natural_generation" else
                            (expected, ("natural_review", "proposal", REVIEW_TEMPLATE_VERSION_V2))
                            if expected[0] == "natural_review" else
                            (expected, ("d07.cognition", "proposal", RECALL_TEMPLATE_VERSION_V1))
                            if expected[0] == "d07.cognition" else (expected,)))
                    for workflow, expected in (
                        (self.context_reply, ("context_reply", "proposal",
                                              CONTEXT_REPLY_TEMPLATE_VERSION)),
                        (self.natural_generation, ("natural_generation", "proposal",
                                                   NATURAL_GENERATION_TEMPLATE_VERSION)),
                        (self.natural_review, ("natural_review", "proposal",
                                               REVIEW_TEMPLATE_VERSION)),
                        (self.appraisal, (APPRAISAL_WORK_KIND, "proposal",
                                          APPRAISAL_TEMPLATE_VERSION)),
                        (self.d07_cognition, ("d07.cognition", "proposal",
                                             "sylanne.d07.cognition_template.v1")),
                        (self.contact_generation, ("contact_generation", "proposal", CONTACT_GENERATION_TEMPLATE_VERSION)),
                        (self.contact_review, ("contact_review", "proposal", CONTACT_REVIEW_TEMPLATE_VERSION))))):
            raise ValueError("model workflows need distinct version-2 encode and reply authority")
        if ((self.natural_generation is not None and self.natural_generation.template_version == NATURAL_GENERATION_TEMPLATE_VERSION_V5)
                != (self.natural_review is not None and self.natural_review.template_version == REVIEW_TEMPLATE_VERSION_V2)):
            raise ValueError("semantic natural generation v5 requires its independent review v2 workflow")
        if (self.contact_generation is None) != (self.contact_review is None):
            raise ValueError("contact needs both installed generation and independent review workflows")
        if self.contact_generation is not None:
            selected = self.natural_generation if self.natural_generation is not None else self.reply
            identity = lambda workflow: (workflow.provider_id, workflow.model_id, workflow.provider_config_digest)
            if identity(self.contact_generation) != identity(selected) or identity(self.contact_review) != identity(selected):
                raise ValueError("contact must use the actual installed dialogue model")


@dataclass(frozen=True, slots=True)
class AdminD06PrivateReplySourcePolicy:
    """Explicit administrator opt-in to expression on one private ingress source."""

    version: int
    scope: str
    grant_expression: bool

    def __post_init__(self) -> None:
        if (type(self.version) is not int or self.version != 1
                or self.scope != "private_conversation"
                or self.grant_expression is not True):
            raise ValueError("private reply source policy must be version-1 private opt-in")


@dataclass(frozen=True, slots=True)
class AdminForegroundNaturalDeadlinePolicyV1:
    mode: str
    window_seconds: float
    anchor: str

    def __post_init__(self):
        if (self.mode != "bounded_causal_window_v1"
                or self.anchor != "original_post_c02_cause_v1"
                or type(self.window_seconds) not in (int, float)
                or not math.isfinite(self.window_seconds) or not 0 < self.window_seconds <= 86400):
            raise ValueError("explicit bounded causal foreground deadline required")


@dataclass(frozen=True, slots=True)
class AdminForegroundDeadlinePolicyV1:
    schema: str
    natural: AdminForegroundNaturalDeadlinePolicyV1 | None
    draft_mode: str | None

    def __post_init__(self):
        if (self.schema != "sylanne.foreground-deadline-policy.v1"
                or self.natural is not None and type(self.natural) is not AdminForegroundNaturalDeadlinePolicyV1
                or self.draft_mode not in (None, "signed_scope_intersection_v1")):
            raise ValueError("foreground responsibility deadline policy differs")


@dataclass(frozen=True, slots=True)
class AdminForegroundPolicyV1:
    schema: str
    version: int
    call_plan_schema: str
    max_calls: int
    max_auxiliary_calls: int
    selected_steps: int
    policy_ref: str
    policy_version: int
    deadline_policy: AdminForegroundDeadlinePolicyV1

    def __post_init__(self):
        from ..runtime.foreground_call_plan_v1 import SCHEMA
        if (self.schema != "sylanne.foreground-policy.v1" or type(self.version) is not int or self.version != 1
                or self.call_plan_schema != SCHEMA or (self.max_calls, self.max_auxiliary_calls, self.selected_steps) != (6, 2, 1)
                or any(type(value) is not int for value in (self.max_calls, self.max_auxiliary_calls, self.selected_steps))
                or type(self.policy_ref) is not str or not 0 < len(self.policy_ref) <= 256
                or type(self.policy_version) is not int or self.policy_version < 1
                or type(self.deadline_policy) is not AdminForegroundDeadlinePolicyV1):
            raise ValueError("explicit finite foreground policy required")


@dataclass(frozen=True, slots=True)
class AdminArtifactDraftToolScopeV1:
    resource_id: str
    filename: str
    mode: str
    max_file_bytes: int
    generated_text_bytes: int
    readback_chunk_bytes: int
    execution_timeout_seconds: float

    def __post_init__(self):
        if (self.resource_id != "export" or self.mode != "create" or type(self.filename) is not str
                or not 0 < len(self.filename) <= 255 or self.filename in (".", "..")
                or "/" in self.filename or "\\" in self.filename or "\0" in self.filename
                or type(self.max_file_bytes) is not int or not 0 < self.max_file_bytes <= 524288
                or type(self.generated_text_bytes) is not int or not 0 < self.generated_text_bytes <= 32768
                or self.generated_text_bytes > self.max_file_bytes
                or type(self.readback_chunk_bytes) is not int or self.readback_chunk_bytes != 65536
                or type(self.execution_timeout_seconds) not in (int, float)
                or not math.isfinite(self.execution_timeout_seconds) or not 0 < self.execution_timeout_seconds <= 300):
            raise ValueError("draft requires one explicit installed export/create target")


@dataclass(frozen=True, slots=True)
class AdminArtifactDraftToolScopeV2:
    """Explicit finite create plus authenticated predecessor replacement policy."""
    resource_id: str
    filename: str
    max_file_bytes: int
    generated_text_bytes: int
    readback_chunk_bytes: int
    execution_timeout_seconds: float
    maximum_artifact_version: int
    operations: tuple[str, ...]
    schema: str = "sylanne.artifact-draft-tool-scope.v2"

    def __post_init__(self):
        AdminArtifactDraftToolScopeV1(self.resource_id, self.filename, "create",
            self.max_file_bytes, self.generated_text_bytes, self.readback_chunk_bytes,
            self.execution_timeout_seconds)
        if (self.schema != "sylanne.artifact-draft-tool-scope.v2"
                or self.operations != ("create", "replace_verified_predecessor")
                or type(self.operations) is not tuple
                or type(self.maximum_artifact_version) is not int
                or not 2 <= self.maximum_artifact_version <= 8):
            raise ValueError("explicit finite verified-replacement policy required")


@dataclass(frozen=True, slots=True)
class AdminArtifactDraftBodyPolicyV1:
    policy_ref: str
    policy_version: int
    effect_component_policy_ref: str
    effect_component_policy_version: int
    cpu_ceiling_ms: int
    resource_id: str

    def __post_init__(self):
        if (any(type(value) is not str or not 0 < len(value) <= 256
                for value in (self.policy_ref, self.effect_component_policy_ref))
                or any(type(value) is not int or value < 1
                    for value in (self.policy_version, self.effect_component_policy_version, self.cpu_ceiling_ms))
                or self.resource_id != "export"):
            raise ValueError("explicit draft Body policy registration input required")


@dataclass(frozen=True, slots=True)
class AdminArtifactDraftObservationPolicyV1:
    policy_ref: str
    policy_version: int
    timeout_seconds: float
    cpu_ceiling_ms: int
    read_bytes_ceiling: int

    def __post_init__(self):
        if (type(self.policy_ref) is not str or not 0 < len(self.policy_ref) <= 256
                or any(type(value) is not int or value < 1
                    for value in (self.policy_version, self.cpu_ceiling_ms, self.read_bytes_ceiling))
                or self.read_bytes_ceiling > 524288 or type(self.timeout_seconds) not in (int, float)
                or not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 300):
            raise ValueError("explicit independent draft observation policy required")


@dataclass(frozen=True, slots=True)
class AdminArtifactDraftPolicyV1:
    model_workflow: AdminModelWorkflowV2
    tool_scope: AdminArtifactDraftToolScopeV1 | AdminArtifactDraftToolScopeV2
    body_policy: AdminArtifactDraftBodyPolicyV1
    observation_policy: AdminArtifactDraftObservationPolicyV1 | None

    def __post_init__(self):
        if (type(self.model_workflow) is not AdminModelWorkflowV2
                or (self.model_workflow.work_kind, self.model_workflow.purpose, self.model_workflow.template_version)
                != ("artifact_draft_v1", "consolidation", "sylanne.artifact_draft_template.v1")
                or type(self.tool_scope) not in {AdminArtifactDraftToolScopeV1, AdminArtifactDraftToolScopeV2}
                or type(self.body_policy) is not AdminArtifactDraftBodyPolicyV1
                or self.observation_policy is not None and type(self.observation_policy) is not AdminArtifactDraftObservationPolicyV1):
            raise ValueError("explicit installed draft policy variants required")


@dataclass(frozen=True, slots=True)
class AdminArtifactStandingScopeV1:
    """Initial signed envelope for one finite private-ingress artifact task family."""
    policy_ref: str
    policy_version: int
    platform_ref: str
    allowed_sender_refs: tuple[str, ...]
    valid_until_utc: float
    task_lifetime_seconds: int
    root_window_seconds: int
    maximum_active_tasks: int
    social_role: str
    norm_refs: tuple[str, ...]
    schema: str = "sylanne.artifact-standing-scope.v1"

    def __post_init__(self):
        import json
        if (self.schema != "sylanne.artifact-standing-scope.v1"
                or type(self.policy_ref) is not str or not 1 <= len(self.policy_ref) <= 256
                or type(self.policy_version) is not int or self.policy_version < 1
                or type(self.allowed_sender_refs) is not tuple or not 1 <= len(self.allowed_sender_refs) <= 8
                or len(set(self.allowed_sender_refs)) != len(self.allowed_sender_refs)
                or type(self.valid_until_utc) not in (int,float) or not math.isfinite(self.valid_until_utc)
                or self.valid_until_utc <= 0
                or type(self.task_lifetime_seconds) is not int or not 1 <= self.task_lifetime_seconds <= 1209600
                or type(self.root_window_seconds) is not int or not 1 <= self.root_window_seconds <= 600
                or type(self.maximum_active_tasks) is not int or not 1 <= self.maximum_active_tasks <= 3
                or type(self.social_role) is not str or not 1 <= len(self.social_role) <= 128
                or type(self.norm_refs) is not tuple or len(self.norm_refs) > 32
                or len(set(self.norm_refs)) != len(self.norm_refs)
                or any(type(ref) is not str or not ref for ref in self.norm_refs)):
            raise ValueError("explicit finite standing artifact scope required")
        platform=json.loads(self.platform_ref)
        if (type(platform) is not list or len(platform)!=3 or platform[1]!='aiocqhttp'
                or any(type(item) is not str or not item for item in platform)
                or json.dumps(platform,ensure_ascii=True,separators=(',',':'))!=self.platform_ref):
            raise ValueError("standing scope needs its exact installed platform account")
        for sender in self.allowed_sender_refs:
            value=json.loads(sender)
            if (type(value) is not list or len(value)!=2 or value[0]!=platform[0]
                    or any(type(item) is not str or not item for item in value)
                    or json.dumps(value,ensure_ascii=True,separators=(',',':'))!=sender):
                raise ValueError("standing sender must be an exact account-scoped identity")


STANDING_PREDECISION_OPERATIONS_V2 = (
    "input:register_artifact_task_text_extent",
    "input:register_artifact_phase_postcondition_policy_v1",
    "prepare_personal_candidates_v1", "select_personal_step_v2")
STANDING_RUBRIC_KINDS_V2 = frozenset({"length", "literal", "sections", "tone", "task_semantics"})
STANDING_OBJECTIVE_OBSERVER_V2 = "d11.explicit-task-objective"


@dataclass(frozen=True, slots=True)
class AdminArtifactStandingScopeV2(AdminArtifactStandingScopeV1):
    predecision_operations: tuple[str, ...] = field(kw_only=True)
    method_refs: tuple[str, ...] = field(kw_only=True)
    rubric_scope: tuple[str, ...] = field(kw_only=True)
    observer_scope: tuple[str, ...] = field(kw_only=True)
    self_actor_ref: str = field(kw_only=True)
    approval_original_ref: str = field(kw_only=True)
    schema: str = "sylanne.artifact-standing-scope.v2"

    def __post_init__(self):
        from dataclasses import fields
        from ..domains.d01 import FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1
        AdminArtifactStandingScopeV1(**{f.name: getattr(self, f.name)
            for f in fields(AdminArtifactStandingScopeV1) if f.name != "schema"})
        if (self.schema != "sylanne.artifact-standing-scope.v2"
                or type(self.predecision_operations) is not tuple or len(self.predecision_operations) != 4
                or set(self.predecision_operations) != set(STANDING_PREDECISION_OPERATIONS_V2)
                or type(self.method_refs) is not tuple or not 1 <= len(self.method_refs) <= 2
                or len(set(self.method_refs)) != len(self.method_refs)
                or not set(self.method_refs) <= {FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1}
                or type(self.rubric_scope) is not tuple or not 1 <= len(self.rubric_scope) <= 5
                or len(set(self.rubric_scope)) != len(self.rubric_scope)
                or not set(self.rubric_scope) <= STANDING_RUBRIC_KINDS_V2
                or type(self.observer_scope) is not tuple or not 1 <= len(self.observer_scope) <= 2
                or len(set(self.observer_scope)) != len(self.observer_scope)
                or any(type(ref) is not str or not ref or len(ref) > 1024
                    or ref != STANDING_OBJECTIVE_OBSERVER_V2 and not ref.startswith("/")
                    for ref in self.observer_scope)
                or type(self.self_actor_ref) is not str or not self.self_actor_ref.startswith("entity:")
                or self.self_actor_ref.startswith("entity:account-v1:")
                or type(self.approval_original_ref) is not str
                or not self.approval_original_ref.startswith("artifact-standing-approval:")):
            raise ValueError("standing V2 requires its finite explicit Self predecision approval declaration")



@dataclass(frozen=True, slots=True)
class ArtifactCandidatePreparationDependencyContractV1:
    parent_operation: str = "prepare_personal_candidates_v1"
    internal_children: tuple[tuple[str, str], ...] = (("freeze", "input:freeze_values"), ("evaluate", "evaluate_values"))
    schema: str = "d08.artifact-candidate-preparation-dependency-contract.v1"

    def __post_init__(self):
        if (self.schema != "d08.artifact-candidate-preparation-dependency-contract.v1"
                or self.parent_operation != "prepare_personal_candidates_v1"
                or self.internal_children != (("freeze", "input:freeze_values"), ("evaluate", "evaluate_values"))):
            raise ValueError("candidate preparation has exactly two internal D01 dependencies")

    @property
    def digest(self):
        from ..domains.d01.production_operations_v1 import plain_v1
        return canonical_digest(plain_v1(self))

    @property
    def original_ref(self):
        return "artifact-candidate-preparation-contract:" + self.digest[:48]


def artifact_candidate_preparation_dependency_contract_v1():
    return ArtifactCandidatePreparationDependencyContractV1()


@dataclass(frozen=True, slots=True)
class AdminArtifactStandingScopeV3(AdminArtifactStandingScopeV2):
    preparation_dependency_contract_ref: str = field(kw_only=True)
    preparation_dependency_contract_digest: str = field(kw_only=True)
    schema: str = "sylanne.artifact-standing-scope.v3"

    def __post_init__(self):
        from dataclasses import fields
        AdminArtifactStandingScopeV2(**{f.name: getattr(self, f.name)
            for f in fields(AdminArtifactStandingScopeV2) if f.name != "schema"})
        contract = artifact_candidate_preparation_dependency_contract_v1()
        if (self.schema != "sylanne.artifact-standing-scope.v3"
                or self.preparation_dependency_contract_ref != contract.original_ref
                or self.preparation_dependency_contract_digest != contract.digest):
            raise ValueError("fresh standing V3 explicitly declares its preparation dependency contract")


def artifact_standing_scope_approval_ref_v2(scope, *, namespace, installation_id, manifest_digest, profile_id):
    from ..runtime_contracts import NamespaceId
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(scope) not in {AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3} or type(namespace) is not NamespaceId:
        raise TypeError("approval reference requires the exact installed standing V2 declaration")
    material = plain_v1(scope)
    del material["approval_original_ref"]
    return "artifact-standing-approval:" + canonical_digest({"scope": material,
        "namespace": namespace, "installation_id": installation_id,
        "manifest_digest": manifest_digest, "profile_id": profile_id})[:48]


def artifact_standing_scope_from_payload_v2(raw):
    from dataclasses import fields
    if type(raw) is not dict:
        raise ValueError("standing scope requires its closed JSON object")
    kind = {"sylanne.artifact-standing-scope.v1": AdminArtifactStandingScopeV1,
        "sylanne.artifact-standing-scope.v2": AdminArtifactStandingScopeV2,
        "sylanne.artifact-standing-scope.v3": AdminArtifactStandingScopeV3}.get(raw.get("schema"))
    if kind is None:
        raise ValueError("unregistered standing scope schema")
    values = dict(_exact_object(raw, {f.name for f in fields(kind)}, "artifact standing scope"))
    arrays = ("allowed_sender_refs", "norm_refs") + (("predecision_operations", "method_refs",
        "rubric_scope", "observer_scope") if kind in {AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3} else ())
    for name in arrays:
        if type(values[name]) is not list:
            raise ValueError("standing scope requires exact explicit JSON arrays")
        values[name] = tuple(values[name])
    return kind(**values)


@dataclass(frozen=True, slots=True)
class AdminArtifactDraftPolicyV2:
    model_workflow: AdminModelWorkflowV2
    tool_scope: AdminArtifactDraftToolScopeV2
    body_policy: AdminArtifactDraftBodyPolicyV1
    observation_policy: AdminArtifactDraftObservationPolicyV1 | None
    standing_scope: AdminArtifactStandingScopeV1 | AdminArtifactStandingScopeV2 | AdminArtifactStandingScopeV3
    schema: str = "sylanne.artifact-draft-policy.v2"

    def __post_init__(self):
        AdminArtifactDraftPolicyV1(self.model_workflow,self.tool_scope,self.body_policy,self.observation_policy)
        if (self.schema!="sylanne.artifact-draft-policy.v2"
                or type(self.tool_scope) is not AdminArtifactDraftToolScopeV2
                or type(self.standing_scope) not in {AdminArtifactStandingScopeV1, AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3}):
            raise ValueError("automatic artifact tasks require the exact new installed scope variant")


@dataclass(frozen=True, slots=True)
class AdminArtifactDraftPolicyV3:
    model_workflow: AdminModelWorkflowV2
    tool_scope: AdminArtifactDraftToolScopeV1 | AdminArtifactDraftToolScopeV2
    body_policy: AdminArtifactDraftBodyPolicyV1
    observation_policy: AdminArtifactDraftObservationPolicyV1 | None
    standing_scope: AdminArtifactStandingScopeV1 | AdminArtifactStandingScopeV2 | AdminArtifactStandingScopeV3
    phase_model_workflow: AdminModelWorkflowV2 = field(kw_only=True)
    schema: str = "sylanne.artifact-draft-policy.v3"

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import WORK_KIND, TEMPLATE_VERSION_V2
        AdminArtifactDraftPolicyV1(self.model_workflow, self.tool_scope, self.body_policy, self.observation_policy)
        if (self.schema != "sylanne.artifact-draft-policy.v3"
                or type(self.standing_scope) not in {AdminArtifactStandingScopeV1, AdminArtifactStandingScopeV2, AdminArtifactStandingScopeV3}
                or type(self.phase_model_workflow) is not AdminModelWorkflowV2):
            raise ValueError("phase artifact policy requires its exact installed V3 fields")
        main, phase = self.model_workflow, self.phase_model_workflow
        if ((phase.work_kind, phase.purpose, phase.template_version) != (WORK_KIND, "consolidation", TEMPLATE_VERSION_V2)
                or (phase.provider_id, phase.model_id, phase.provider_config_ref, phase.provider_config_digest,
                    phase.privacy_tier, phase.audiences, phase.required_capabilities) !=
                   (main.provider_id, main.model_id, main.provider_config_ref, main.provider_config_digest,
                    main.privacy_tier, main.audiences, main.required_capabilities)
                or set(phase.quote_ceiling) != {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
                or phase.quote_ceiling["input_tokens"] > 10000 or phase.quote_ceiling["output_tokens"] > 2000
                or phase.max_output_tokens > min(2000, main.max_output_tokens)
                or phase.timeout_seconds > main.timeout_seconds
                or any(amount > main.quote_ceiling.get(name, 0) for name, amount in phase.quote_ceiling.items())):
            raise ValueError("phase workflow exceeds the exact original C4 selection or bounds")


@dataclass(frozen=True, slots=True)
class AdminD06RecallProfileV1:
    name: str
    max_rounds: int
    max_candidates: int
    max_nodes: int
    max_hops: int

    def __post_init__(self):
        ceilings = {"light": (1, 32, 128, 0), "normal": (3, 64, 128, 1), "deep": (4, 64, 128, 2)}
        if self.name not in ceilings:
            raise ValueError("unknown installed recall profile")
        for field, ceiling in zip(("max_rounds", "max_candidates", "max_nodes", "max_hops"), ceilings[self.name]):
            value = getattr(self, field)
            if type(value) is not int or not (0 if field == "max_hops" else 1) <= value <= ceiling:
                raise ValueError("installed recall profile exceeds its bounded work allowance")


@dataclass(frozen=True, slots=True)
class AdminD06RecallPolicyV1:
    """Explicit read/traversal limits and existing C04 policy identities, never a grant."""

    policy_ref: str
    policy_version: int
    body_policy_id: str
    body_policy_version: int
    cognition_body_policy_id: str
    cognition_body_policy_version: int
    cpu_policy_id: str
    cpu_policy_version: int
    interpretation_policy_id: str
    interpretation_policy_version: str
    profiles: tuple[AdminD06RecallProfileV1, ...]
    max_search_plans: int
    max_candidates_per_channel: int
    max_ledger_pages: int
    max_ledger_nodes: int
    read_timeout_seconds: float
    max_edges: int
    max_iterations: int
    max_recollection_candidates: int
    recall_token_ceiling: int
    working_ref_ceiling: int
    working_token_ceiling: int
    schema: str = "sylanne.d06.installed-recall-policy.v1"

    def __post_init__(self):
        if self.schema != "sylanne.d06.installed-recall-policy.v1":
            raise ValueError("unknown installed recall policy schema")
        for name in ("policy_ref", "body_policy_id", "cognition_body_policy_id", "cpu_policy_id", "interpretation_policy_id", "interpretation_policy_version"):
            value = getattr(self, name)
            if type(value) is not str or not 0 < len(value) <= 128:
                raise ValueError("recall policy requires explicit bounded policy identities")
        for name in ("policy_version", "body_policy_version", "cognition_body_policy_version", "cpu_policy_version"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError("recall policy versions must be positive integers")
        if (type(self.profiles) is not tuple or len(self.profiles) != 3
                or any(type(profile) is not AdminD06RecallProfileV1 for profile in self.profiles)
                or tuple(profile.name for profile in self.profiles) != ("light", "normal", "deep")):
            raise ValueError("explicit light, normal and deep recall profiles required")
        for name, ceiling in (("max_search_plans", 5), ("max_candidates_per_channel", 32),
                ("max_ledger_pages", 128), ("max_ledger_nodes", 8192), ("max_edges", 128),
                ("max_iterations", 64), ("max_recollection_candidates", 32),
                ("recall_token_ceiling", 2048), ("working_ref_ceiling", 16), ("working_token_ceiling", 4096)):
            if type(getattr(self, name)) is not int or not 1 <= getattr(self, name) <= ceiling:
                raise ValueError("installed recall allowance exceeds its finite ceiling")
        if (type(self.read_timeout_seconds) not in (int, float)
                or not math.isfinite(self.read_timeout_seconds) or not 0 < self.read_timeout_seconds <= 300):
            raise ValueError("installed recall read timeout must be finite and bounded")

    @property
    def policy_digest(self):
        from dataclasses import asdict
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class AdminInstallationBundle:
    """One verified installation snapshot for Authority client assembly."""

    tls_profile: AuthorityTlsProfile
    installation_policy: AdminInstallationPolicy
    d11_signing_key: bytes
    d02_signing_key: bytes
    ingress_clock: AdminIngressClockPolicy | None = None
    ingress_encoding: AdminIngressEncodingPolicy | None = None
    workbench_origin: str | None = None
    ingress_model: AdminIngressModelPolicy | None = None
    d03_arrival: AdminD03ArrivalPolicy | None = None
    model_workflows: AdminModelWorkflowsV2 | AdminModelWorkflowsV3 | AdminModelWorkflowsV4 | AdminModelWorkflowsV5 | AdminModelWorkflowsV6 | AdminModelWorkflowsV7 | AdminModelWorkflowsV8 | AdminModelWorkflowsV9 | None = None
    d04_encoding_baseline: AdminD04EncodingBaselinePolicy | None = None
    d06_first_ingress_c02: AdminD06FirstIngressC02Policy | None = None
    d03_self_identity_projection: AdminD03SelfIdentityProjectionPolicy | None = None
    d06_source_correction: AdminD06SourceCorrectionPolicy | None = None
    reverse_handoff: object | None = None
    d06_private_reply_source: AdminD06PrivateReplySourcePolicy | None = None
    d07_attention: AdminD07AttentionPolicy | None = None
    private_reply_dispatch: AdminPrivateReplyDispatchPolicy | None = None
    d13_precompression: AdminD13PrecompressionPolicyV1 | None = None
    d04_semantic_drive: AdminD04SemanticDrivePolicyV1 | None = None
    d13_paid_precompression: AdminD13PaidPrecompressionPolicyV1 | None = None
    d13_wire_policy: object | None = None
    d13_wire_counter: object | None = None
    d04_joint_numeric: object | None = None
    package_selection: PackageSelectionV2 | None = None
    # Explicit prospective Root selector; current Owner and Root originals
    # remain the production authority for the actual capture.
    life_d04_before_capture_policy: object | None = None
    foreground: AdminForegroundPolicyV1 | None = None
    artifact_draft: AdminArtifactDraftPolicyV1 | AdminArtifactDraftPolicyV2 | AdminArtifactDraftPolicyV3 | None = None
    provider_billing_policy_v1: ProviderBillingPolicyV1 | None = None
    d06_recall: AdminD06RecallPolicyV1 | None = None
    artifact_phase_counter: ArtifactPhaseCountPolicyV1 | None = None
    method_measurement_policy: object | None = field(default=None, kw_only=True)
    contact_effect_accounting: object | None = field(default=None, kw_only=True)
    habit_runtime_policy: object | None = field(default=None, kw_only=True)
    artifact_phase_observer: object | None = field(default=None, kw_only=True)

    def __post_init__(self):
        if self.artifact_phase_observer is not None:
            from .artifact_phase_observer_policy_v2 import ArtifactPhaseObserverPolicyV2
            from .model_workflows_v9 import AdminModelWorkflowsV9
            observer=self.artifact_phase_observer
            if (type(observer)is not ArtifactPhaseObserverPolicyV2 or type(self.model_workflows)is not AdminModelWorkflowsV9
                    or self.model_workflows.artifact_observation_cognition is None
                    or canonical_digest(self.model_workflows.artifact_observation_cognition)!=observer.workflow_digest
                    or 'd07.cognition'not in self.installation_policy.root_grant.allowed_work_kinds):
                raise ValueError('independent Artifact observer requires its actual V9 workflow and signed Root work kind')
        if self.habit_runtime_policy is not None:
            from .habit_runtime_policy_v1 import HabitRuntimePolicyV1
            if type(self.habit_runtime_policy)is not HabitRuntimePolicyV1:raise TypeError("exact Habit runtime policy required")
            self.habit_runtime_policy.require_installation_v1(self.installation_policy)
        if self.life_d04_before_capture_policy is not None:
            from ..runtime.d04_life_before_original_v1 import D04LifeBeforeCapturePolicyV1
            selected=self.life_d04_before_capture_policy;installed=self.installation_policy
            if (type(selected) is not D04LifeBeforeCapturePolicyV1
                    or (selected.namespace,selected.installation_id,selected.manifest_digest)!=(
                        installed.namespace,installed.installation_id,installed.manifest_digest)):
                raise ValueError("prospective Life before selector differs from its actual installed policy")
        if self.contact_effect_accounting is not None:
            from ..authority_service.contact_effect_accounting_contract_v1 import ContactEffectPricingPolicyV1
            if type(self.contact_effect_accounting) is not ContactEffectPricingPolicyV1:
                raise TypeError("Contact effect pricing requires its exact installed policy")
            if self.private_reply_dispatch is None:
                raise ValueError("Contact effect pricing requires an installed message quote policy")
        if self.method_measurement_policy is not None:
            from ..runtime.d11_method_observation_v1 import MethodMeasurementPolicyV1
            from ..domains.d01.production_operations_v1 import plain_v1
            if (type(self.method_measurement_policy) is not MethodMeasurementPolicyV1
                    or self.provider_billing_policy_v1 is None
                    or self.method_measurement_policy.billing_policy_digest != canonical_digest(plain_v1(self.provider_billing_policy_v1))):
                raise ValueError("method measurement needs its exact installed policy and original billing contract")
        if self.d06_recall is not None:
            if type(self.d06_recall) is not AdminD06RecallPolicyV1 or type(self.foreground) is not AdminForegroundPolicyV1:
                raise ValueError("installed recall requires its exact policy and original foreground policy")
            from ..model_broker.d07_cognition_v1 import RECALL_TEMPLATE_VERSION_V1
            workflow = None if self.model_workflows is None else self.model_workflows.d07_cognition
            if (type(workflow) is not AdminModelWorkflowV2
                    or (workflow.work_kind, workflow.purpose, workflow.template_version) !=
                    ("d07.cognition", "proposal", RECALL_TEMPLATE_VERSION_V1)):
                raise ValueError("installed ingress recall requires its explicit exact C3 routing workflow")
        if type(self.artifact_draft) is AdminArtifactDraftPolicyV3:
            from .model_workflows_v4 import AdminModelWorkflowsV4
            from .model_workflows_v5 import AdminModelWorkflowsV5
            from .model_workflows_v6 import AdminModelWorkflowsV6
            from .model_workflows_v7 import AdminModelWorkflowsV7
            from .model_workflows_v8 import AdminModelWorkflowsV8
            from .model_workflows_v9 import AdminModelWorkflowsV9
            artifact = self.artifact_draft
            phase = artifact.phase_model_workflow
            policy = self.installation_policy
            if (type(self.model_workflows) not in {AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
                    or artifact.model_workflow != self.model_workflows.artifact_draft
                    or type(self.foreground) is not AdminForegroundPolicyV1
                    or self.foreground.deadline_policy.draft_mode != "signed_scope_intersection_v1"
                    or not {"artifact_draft_v1", "d10.life.artifact_draft.v1"} <= set(policy.root_grant.allowed_work_kinds)
                    or artifact.observation_policy is not None and "d11.life.artifact_observation.v1" not in policy.root_grant.allowed_work_kinds
                    or any(amount > policy.root_grant.max_ceiling.get(name, 0)
                        or amount > policy.root_lease.limits.get(name, 0) for name, amount in phase.quote_ceiling.items())):
                raise ValueError("phase workflow lacks its actual installed foreground/root grant/lease")
        counter = self.artifact_phase_counter
        if counter is not None:
            _require_artifact_phase_counter_binding_v1(counter, self.installation_policy, self.artifact_draft)
            if counter.profile_id != self.tls_profile.profile_id:
                raise ValueError("phase counter differs from its actual installed TLS profile")
        billing = self.provider_billing_policy_v1
        if billing is None:
            return
        if type(billing) is not ProviderBillingPolicyV1:
            raise TypeError("installed provider billing policy must be its exact typed contract")
        policy = self.installation_policy
        if (billing.namespace, billing.installation_id, billing.manifest_digest) != (
                policy.namespace, policy.installation_id, policy.manifest_digest):
            raise ValueError("provider billing policy differs from its installed namespace/package")
        from dataclasses import fields
        from .model_workflows_v3 import AdminModelWorkflowsV3
        from .model_workflows_v4 import AdminModelWorkflowsV4
        from .model_workflows_v5 import AdminModelWorkflowsV5
        from .model_workflows_v6 import AdminModelWorkflowsV6
        from .model_workflows_v7 import AdminModelWorkflowsV7
        from .model_workflows_v8 import AdminModelWorkflowsV8
        from .model_workflows_v9 import AdminModelWorkflowsV9
        if type(self.model_workflows) not in {AdminModelWorkflowsV2, AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}:
            raise ValueError("provider billing requires the actual installed workflow container")
        workflows = tuple(getattr(self.model_workflows, field.name) for field in fields(self.model_workflows)
            if field.name != "version")
        if type(self.artifact_draft) is AdminArtifactDraftPolicyV3:
            workflows += (self.artifact_draft.phase_model_workflow,)
        if not any(workflow is not None and (workflow.provider_id, workflow.model_id, workflow.provider_config_digest) ==
                (billing.provider_id, billing.model_id, billing.provider_config_digest) for workflow in workflows):
            raise ValueError("provider billing selection is absent from the installed workflows")



def is_installed_life_numeric_slot_v1(bundle, workflow):
    """Recognize only the original actual installed Numeric workflow object."""
    from .model_workflows_v3 import AdminModelWorkflowsV3
    from .model_workflows_v4 import AdminModelWorkflowsV4
    from .model_workflows_v5 import AdminModelWorkflowsV5
    from .model_workflows_v6 import AdminModelWorkflowsV6
    from .model_workflows_v7 import AdminModelWorkflowsV7
    from .model_workflows_v8 import AdminModelWorkflowsV8
    from .model_workflows_v9 import AdminModelWorkflowsV9
    return (type(bundle) is AdminInstallationBundle and type(workflow) is AdminModelWorkflowV2
        and type(bundle.model_workflows) in {AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
        and workflow is bundle.model_workflows.life_numeric
        and (workflow.work_kind, workflow.purpose, workflow.template_version) ==
            ('d06.encode_internal_life_numeric', 'consolidation', 'sylanne.d06.internal_life_numeric.v1'))


def is_installed_artifact_draft_slot_v1(bundle,workflow):
    # Version dispatch is followed by exact class and object identity checks.
    # Old containers are never interpreted as the new slot.
    from ..host.model_workflows_v4 import AdminModelWorkflowsV4
    from ..host.model_workflows_v5 import AdminModelWorkflowsV5
    from ..host.model_workflows_v6 import AdminModelWorkflowsV6
    from ..host.model_workflows_v7 import AdminModelWorkflowsV7
    from ..host.model_workflows_v8 import AdminModelWorkflowsV8
    from ..host.model_workflows_v9 import AdminModelWorkflowsV9
    return (type(bundle.model_workflows) in {AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
        and workflow is bundle.model_workflows.artifact_draft)


def is_installed_artifact_draft_phase_slot_v2(bundle, workflow):
    """Recognize the actual installed phase object; this grants no model call."""
    from .artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
    return (type(bundle) is AdminInstallationBundle
        and type(bundle.artifact_draft) in {AdminArtifactDraftPolicyV3, AdminArtifactDraftPairedPolicyV4}
        and workflow is bundle.artifact_draft.phase_model_workflow)


def _check_profile_id(profile_id: str) -> None:
    if not isinstance(profile_id, str) or _PROFILE_ID.fullmatch(profile_id) is None:
        raise ValueError("authority profile identifier is invalid")


def _check_posix_tree(profile_dir: Path) -> None:
    """Check each ancestor and every consumed file before TLS uses its paths.

    A root-owned, non-writable parent prevents an unprivileged process from
    replacing a checked descendant. Administrators remain trusted by design.
    """
    if not profile_dir.is_absolute():
        raise ValueError("administrator profile root must be absolute")
    chain = tuple(reversed(profile_dir.parents)) + (profile_dir,)
    for path in chain:
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            raise PermissionError("administrator profile directory is unsafe")
    for name in ("profile.json",) + _MATERIAL:
        info = os.lstat(profile_dir / name)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or info.st_nlink != 1):
            raise PermissionError("administrator profile file is unsafe")
        if name == "client-key.pem" and info.st_mode & 0o007:
            raise PermissionError("administrator private key is exposed")
        if name == "client-key.pem" and info.st_mode & 0o040:
            effective_group = getattr(os, "getegid", None)
            if effective_group is None or info.st_gid != effective_group() and os.geteuid() != 0:
                raise PermissionError("administrator private key group is unsafe")


def _check_linux_acl_tree(profile_dir: Path) -> None:
    """Reject ACLs on the entire trusted path; mode bits alone are insufficient."""
    if not hasattr(os, "getxattr"):
        raise AuthorityProfileUnavailable("Linux POSIX ACL verification is unavailable")
    directories = tuple(reversed(profile_dir.parents)) + (profile_dir,)
    for path in directories + tuple(profile_dir / name for name in ("profile.json",) + _MATERIAL):
        names = ("system.posix_acl_access", "system.posix_acl_default") \
            if path in directories else ("system.posix_acl_access",)
        for name in names:
            try:
                os.getxattr(path, name, follow_symlinks=False)
            except OSError as exc:
                if exc.errno in {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}:
                    continue
                raise AuthorityProfileUnavailable("Linux POSIX ACL verification failed") from exc
            raise PermissionError("administrator profile ACL is unsafe")


def _check_linux_acl_fd(fd: int, *, directory: bool) -> None:
    if not hasattr(os, "getxattr"):
        raise AuthorityProfileUnavailable("Linux POSIX ACL verification is unavailable")
    names = ("system.posix_acl_access", "system.posix_acl_default") if directory \
        else ("system.posix_acl_access",)
    for name in names:
        try:
            os.getxattr(fd, name)
        except OSError as exc:
            if exc.errno in {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}:
                continue
            raise AuthorityProfileUnavailable("Linux POSIX ACL verification failed") from exc
        raise PermissionError("administrator profile ACL is unsafe")


def _check_opened(fd: int, *, directory: bool, key: bool, system: str) -> None:
    info = os.fstat(fd)
    if ((not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or info.st_uid != 0 or info.st_mode & 0o022):
        raise PermissionError("administrator profile object is unsafe")
    if not directory:
        if info.st_nlink != 1 or info.st_size > _MAX_MATERIAL_BYTES:
            raise PermissionError("administrator profile file is unsafe")
        if key and info.st_mode & 0o007:
            raise PermissionError("administrator private key is exposed")
        if key and info.st_mode & 0o040 and info.st_gid != os.getegid() and os.geteuid() != 0:
            raise PermissionError("administrator private key group is unsafe")
    if system == "Darwin":
        from .macos_profile_security import reject_extended_acl
        reject_extended_acl(fd)
    elif system == "Linux":
        _check_linux_acl_fd(fd, directory=directory)
    else:
        raise AuthorityProfileUnavailable("POSIX profile verification is unavailable")


class _OpenedProfileFilesV2(dict):
    selected_package: PackageSelectionV2 | None = None


@contextmanager
def _opened_profile(profile_dir: Path, system: str, *, signing_key: bool = False,
                    c04_signing_key: bool = False,
                    reverse_material: bool = False
                    ) -> Iterator[dict[str, int]]:
    """Pin every path component and consumed file before inspecting either."""
    if not profile_dir.is_absolute() or os.open not in os.supports_dir_fd:
        raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, flag) for flag in required):
        raise AuthorityProfileUnavailable("POSIX no-follow open is unavailable")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        current = os.open("/", directory_flags)
        stack.callback(os.close, current)
        _check_opened(current, directory=True, key=False, system=system)
        for part in profile_dir.parts[1:]:
            if part in {"", ".", ".."}:
                raise ValueError("administrator profile path is invalid")
            child = os.open(part, directory_flags, dir_fd=current)
            stack.callback(os.close, child)
            _check_opened(child, directory=True, key=False, system=system)
            current = child
        files: dict[str, int] = _OpenedProfileFilesV2()
        names = ("profile.json",) + _MATERIAL + ((
            _D11_SIGNING_KEY, _D02_SIGNING_KEY,
        ) if signing_key else ()) + ((_C04_SIGNING_KEY,)
            if c04_signing_key else ()) + (_REVERSE_MATERIAL if reverse_material else ())
        for name in names:
            fd = os.open(name, file_flags, dir_fd=current)
            stack.callback(os.close, fd)
            _check_opened(fd, directory=False,
                          key=name in {"client-key.pem", "reverse-key.pem",
                                       _D11_SIGNING_KEY, _D02_SIGNING_KEY,
                                       _C04_SIGNING_KEY}, system=system)
            files[name] = fd
        from .selected_profile_cohort_v2 import selected_profile_payload_v2
        with selected_profile_payload_v2(profile_dir, system) as selected:
            if selected is not None:
                files['profile.json'] = selected.descriptor
                files.selected_package = selected.selection
            yield files


def _read_fd_bounded(fd: int, limit: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, limit + 1)
    if len(raw) > limit:
        raise ValueError("administrator profile file is too large")
    return raw


def _tls_fd_path(fd: int, system: str) -> str:
    """Check the OS descriptor alias before passing it to OpenSSL's path API."""
    base = "/dev/fd" if system == "Darwin" else "/proc/self/fd"
    alias = f"{base}/{fd}"
    try:
        original = os.fstat(fd)
        opened = os.open(alias, os.O_RDONLY | os.O_CLOEXEC)
        try:
            duplicate = os.fstat(opened)
        finally:
            os.close(opened)
    except OSError as exc:
        raise AuthorityProfileUnavailable("TLS descriptor alias is unavailable") from exc
    if (original.st_dev, original.st_ino) != (duplicate.st_dev, duplicate.st_ino):
        raise AuthorityProfileUnavailable("TLS descriptor alias did not preserve identity")
    return alias


def _prepared_ssl_context(files: dict[str, int], system: str) -> ssl.SSLContext:
    trust = _read_fd_bounded(files["trust-root.pem"], _MAX_MATERIAL_BYTES)
    try:
        cadata = trust.decode("ascii")
    except UnicodeError as exc:
        raise ValueError("administrator trust root is not PEM text") from exc
    cert = _tls_fd_path(files["client-cert.pem"], system)
    key = _tls_fd_path(files["client-key.pem"], system)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=cadata)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    os.lseek(files["client-cert.pem"], 0, os.SEEK_SET)
    os.lseek(files["client-key.pem"], 0, os.SEEK_SET)
    context.load_cert_chain(cert, key)
    return context


@contextmanager
def _opened_windows_profile(profile_dir: Path, *, signing_key: bool = False,
                            c04_signing_key: bool = False,
                            reverse_material: bool = False
                            ) -> Iterator[dict[Path, int]]:
    """Pin the whole path while pathname-only OpenSSL loads the same objects.

    FILE_SHARE_READ denies write/delete opens, including rename, until all
    handles close. Existing conflicting handles make CreateFile fail closed.
    """
    if os.name != "nt" or not profile_dir.is_absolute():
        raise AuthorityProfileUnavailable("Windows profile handle gate is unavailable")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    )
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.GetFileInformationByHandle.argtypes = (
        ctypes.c_void_p, ctypes.POINTER(_ByHandleFileInformation),
    )
    kernel.GetFileInformationByHandle.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel.CloseHandle.restype = ctypes.c_int
    invalid = ctypes.c_void_p(-1).value
    directories = tuple(reversed(profile_dir.parents)) + (profile_dir,)
    names = ("profile.json",) + _MATERIAL + ((
        _D11_SIGNING_KEY, _D02_SIGNING_KEY,
    ) if signing_key else ()) + ((_C04_SIGNING_KEY,)
        if c04_signing_key else ()) + (_REVERSE_MATERIAL if reverse_material else ())
    paths = directories + tuple(profile_dir / name for name in names)
    with ExitStack() as stack:
        handles: dict[Path, int] = {}
        for path in paths:
            directory = path in directories
            flags = _WIN_OPEN_REPARSE_POINT | (_WIN_BACKUP_SEMANTICS if directory else 0)
            handle = kernel.CreateFileW(
                str(path), _WIN_GENERIC_READ,
                _WIN_SHARE_READ, None, _WIN_OPEN_EXISTING, flags, None,
            )
            if handle is None or handle == invalid:
                if ctypes.get_last_error() in {2, 3}:
                    raise FileNotFoundError("administrator Authority profile is not installed")
                raise AuthorityProfileUnavailable("Windows profile handle open failed")
            stack.callback(kernel.CloseHandle, ctypes.c_void_p(handle))
            info = _ByHandleFileInformation()
            if not kernel.GetFileInformationByHandle(
                ctypes.c_void_p(handle), ctypes.byref(info)
            ):
                raise AuthorityProfileUnavailable("Windows profile handle inspection failed")
            if (info.attributes & _WIN_REPARSE_POINT
                    or bool(info.attributes & _WIN_DIRECTORY) != directory
                    or not directory and info.links != 1):
                raise PermissionError("administrator Authority profile object is unsafe")
            if not directory and (info.size_high << 32 | info.size_low) > _MAX_MATERIAL_BYTES:
                raise PermissionError("administrator Authority profile file is too large")
            handles[path] = handle
        yield handles


class _HandleSecurityView:
    """Adapt the existing DACL policy checker to a pinned Win32 handle."""

    def __init__(self, security: object, handle: int):
        self._security = security
        self._handle = handle

    def GetNamedSecurityInfo(self, _path: str, object_type: int, flags: int):
        return self._security.GetSecurityInfo(self._handle, object_type, flags)

    def __getattr__(self, name: str):
        return getattr(self._security, name)


def _check_windows_handles(profile_dir: Path, handles: dict[Path, int]) -> None:
    """Apply the existing owner/DACL policy to each held object itself."""
    from . import windows_profile_security as security_gate
    try:
        import win32security  # type: ignore[import-not-found]
        runtime_user, runtime_sids = security_gate._runtime_token_sids(win32security)
        protected_root = profile_dir.parents[2]
        key_paths = {profile_dir / name for name in (
            "client-key.pem", "reverse-key.pem", _D11_SIGNING_KEY,
            _D02_SIGNING_KEY, _C04_SIGNING_KEY,
        )}
        for path, handle in handles.items():
            security_gate._check_security_descriptor(
                path, runtime_user, runtime_sids,
                _HandleSecurityView(win32security, handle),
                key=path in key_paths,
                protected=path == protected_root or protected_root in path.parents,
            )
    except PermissionError:
        raise
    except (security_gate.WindowsProfileSecurityUnavailable,
            OSError, ValueError, TypeError, AttributeError, ImportError) as exc:
        raise AuthorityProfileUnavailable("Windows handle DACL verification failed") from exc


def _read_profile_json(path: Path | int) -> dict[str, object]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate authority profile field")
            result[key] = value
        return result

    if isinstance(path, int):
        descriptor = path
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_PROFILE_BYTES:
            raise ValueError("authority profile is not a bounded regular file")
        raw = _read_fd_bounded(descriptor, _MAX_PROFILE_BYTES)
    else:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_PROFILE_BYTES:
                raise ValueError("authority profile is not a bounded regular file")
            raw = os.read(descriptor, _MAX_PROFILE_BYTES + 1)
        finally:
            os.close(descriptor)
    if len(raw) > _MAX_PROFILE_BYTES:
        raise ValueError("authority profile is too large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    except UnicodeError as exc:
        raise ValueError("authority profile is not UTF-8") from exc
    if (not isinstance(value, dict) or type(value.get("schema")) is not int
            or value["schema"] not in {1, 2}
            or (set(value) != _PROFILE_FIELDS_V1 if value["schema"] == 1 else
                not _valid_schema2_fields(value))):
        raise ValueError("authority profile schema is invalid")
    _workbench_origin_from_payload(value)
    return value


def current_owner_metadata_installation_v3(graph,*,expected_bundle=None):
    from ..graph_coordinator import GraphCoordinator
    from .v2_installation import V2InstallationAssembly
    if type(graph)is not GraphCoordinator:
        raise ValueError('Owner metadata bundle requires the actual Graph')
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if (type(assembly)is not V2InstallationAssembly or type(assembly.admin_bundle)is not AdminInstallationBundle
            or expected_bundle is not None and expected_bundle is not assembly.admin_bundle):
        raise ValueError('Owner metadata requires the actual installed assembly and identical administrator bundle')
    return assembly.admin_bundle,assembly.package_root,None


def require_current_owner_metadata_installation_v3(graph,*,expected_bundle):
    if graph._GraphCoordinator__store._db.in_transaction:
        raise ValueError('Owner metadata protected installation observation must precede Graph SQL')
    return current_owner_metadata_installation_v3(graph,expected_bundle=expected_bundle)



def _require_artifact_phase_counter_binding_v1(counter, installation, artifact):
    from .artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
    if (type(counter) is not ArtifactPhaseCountPolicyV1 or counter.source_scope != "production"
            or type(installation) is not AdminInstallationPolicy
            or type(artifact) not in {AdminArtifactDraftPolicyV3, AdminArtifactDraftPairedPolicyV4}):
        raise ValueError("phase counter requires its actual production installation and V3 artifact policy")
    workflow = artifact.phase_model_workflow
    if (counter.namespace, counter.installation_id, counter.manifest_digest, counter.provider_id,
            counter.model_id, counter.provider_config_digest, counter.template_version) != (
            installation.namespace, installation.installation_id, installation.manifest_digest,
            workflow.provider_id, workflow.model_id, workflow.provider_config_digest, workflow.template_version):
        raise ValueError("phase counter changed installed namespace/package/provider/model/template selection")


def _method_measurement_policy_from_payload_v1(payload):
    from ..runtime.d11_method_observation_v1 import method_measurement_policy_from_payload_v1
    return method_measurement_policy_from_payload_v1(payload.get("method_measurement_policy"))


def _artifact_phase_counter_from_payload(payload, policy):
    raw = payload.get("artifact_phase_counter")
    if raw is None:
        return None
    from ..model_broker.artifact_phase_count_v1 import artifact_phase_counter_policy_from_payload_v1
    counter = artifact_phase_counter_policy_from_payload_v1(raw)
    _require_artifact_phase_counter_binding_v1(counter, policy, _artifact_draft_for_policy_from_payload_v1(payload, policy))
    return counter


def _d13_wire_counter_from_payload(payload):
    raw = payload.get("d13_wire_counter")
    if raw is None:
        return None
    if type(payload.get("d13_wire_policy")) is dict and payload["d13_wire_policy"].get("schema")=="sylanne3.d13.installed-core-wire-policy.v7":
        raise ValueError("V7 Core full-wire counter does not accept a Host executable counter")
    from ..authority_service.d13_installed_counter_v1 import installed_d13_counter_from_payload_v1
    counter = installed_d13_counter_from_payload_v1(raw)
    if payload.get("d13_wire_policy") is None:
        raise ValueError("installed D13 counter requires its signed full-wire policy")
    return counter


def _d13_wire_policy_from_payload(payload, policy):
    raw = payload.get("d13_wire_policy")
    if raw is None:
        return None
    from ..authority_service.d13_wire_evidence_v1 import installed_d13_wire_policy_from_payload_v1
    workflows = _model_workflows_from_payload(payload)
    if type(raw) is dict and raw.get("schema") == "sylanne3.d13.installed-core-wire-policy.v7":
        from .model_workflows_v7 import AdminModelWorkflowsV7
        from .model_workflows_v8 import AdminModelWorkflowsV8
        from .model_workflows_v9 import AdminModelWorkflowsV9
        from ..authority_service.d13_core_counter_contract_v1 import installed_d13_wire_policy_from_payload_v7
        from ..model_broker.natural_reply_history_v7 import TEMPLATE_VERSION
        if type(workflows) not in {AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9} or workflows.natural_generation is None or workflows.natural_generation.template_version != TEMPLATE_VERSION:
            raise ValueError("D13 Core wire V7 requires the actual named V7 natural workflow")
        configured = installed_d13_wire_policy_from_payload_v7(raw)
    elif type(raw) is dict and raw.get("schema") == "sylanne3.d13.installed-wire-policy.v6":
        from .model_workflows_v6 import AdminModelWorkflowsV6
        from ..authority_service.d13_wire_evidence_v6 import installed_d13_wire_policy_from_payload_v6
        from ..model_broker.natural_reply_history_v6 import TEMPLATE_VERSION
        if type(workflows) is not AdminModelWorkflowsV6 or workflows.natural_generation is None or workflows.natural_generation.template_version != TEMPLATE_VERSION:
            raise ValueError("D13 wire V6 requires the actual named V6 natural workflow")
        configured = installed_d13_wire_policy_from_payload_v6(raw)
    else:
        configured = installed_d13_wire_policy_from_payload_v1(raw)
    main = workflows.natural_generation if workflows is not None else None
    actual = configured.installation
    if main is None or (actual.installation_id, actual.provider_id, actual.model_id,
            actual.provider_config_digest, actual.max_output_tokens) != (policy.installation_id,
            main.provider_id, main.model_id, main.provider_config_digest, main.max_output_tokens):
        raise ValueError("D13 full-wire policy differs from actual foreground installation")
    return configured


def _valid_schema2_fields(payload: dict[str, object]) -> bool:
    return _PROFILE_FIELDS_V2 <= set(payload) <= (
        _PROFILE_FIELDS_V2 | {"ingress_clock", "ingress_encoding", "ingress_model", "workbench_origin", "d03_arrival", "d03_self_identity_projection", "d04_encoding_baseline", "d04_semantic_drive", "d06_first_ingress_c02", "d06_source_correction", "d06_private_reply_source", "d07_attention", "private_reply_dispatch", "d13_precompression", "d13_paid_precompression", "d13_wire_policy", "d13_wire_counter", "d04_joint_numeric", "model_workflows", "reverse_handoff", "foreground", "artifact_draft", "provider_billing_policy_v1", "d06_recall", "astrbot_namespace_v1", "artifact_phase_counter", "artifact_phase_observer", "method_measurement_policy", "contact_effect_accounting", "life_d04_before_capture_policy", "habit_runtime_policy"}
    )


def _reverse_material_present(profile_dir: Path) -> bool:
    return any((profile_dir / name).exists() for name in _REVERSE_MATERIAL)


def _reverse_handoff_from_payload(
    payload: dict[str, object], profile_dir: Path,
    policy: AdminInstallationPolicy, *, material_present: bool,
):
    configured = payload.get("reverse_handoff")
    if configured is None and "reverse_handoff" not in payload:
        if material_present:
            raise ValueError("unconfigured reverse TLS material is present")
        return None
    if not material_present:
        raise ValueError("configured reverse TLS material is absent")
    from .final_handoff_pairing import TrustedFinalHandoffBindingV1
    from .reverse_handoff import AdministratorHostReverseProfile

    values = _exact_object(configured, _REVERSE_FIELDS, "reverse handoff")
    digest = values["expected_authority_certificate_sha256"]
    if (type(digest) is not str or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)):
        raise ValueError("reverse Authority certificate pin is invalid")
    profile = AdministratorHostReverseProfile(
        profile_id=values["profile_id"],
        installation_id=policy.installation_id,
        namespace=policy.authority_namespace,
        expected_authority_certificate_sha256=digest,
        certificate=profile_dir / "reverse-cert.pem",
        private_key=profile_dir / "reverse-key.pem",
        authority_trust_root=profile_dir / "reverse-trust-root.pem",
    )
    profile.ssl_context()  # Verify the administrator's installed cert/key now.
    return TrustedFinalHandoffBindingV1(
        profile=profile, listen_host=values["listen_host"],
        endpoint_host=values["endpoint_host"], port=values["port"],
        server_name=values["server_name"])


def _workbench_origin_from_payload(payload: dict[str, object]) -> str | None:
    value = payload.get("workbench_origin")
    if value is None and "workbench_origin" not in payload:
        return None
    if type(payload.get("schema")) is not int or payload["schema"] != 2:
        raise ValueError("workbench origin requires profile schema 2")
    if type(value) is not str or len(value) > 253:
        raise ValueError("workbench origin must be a canonical HTTP or HTTPS origin")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if (parsed.scheme not in {"http", "https"} or host is None or parsed.username is not None
                or parsed.password is not None or parsed.path or parsed.query
                or parsed.fragment or "%" in host
                or (port is not None and not 1 <= port <= 65535)):
            raise ValueError("workbench origin must be a canonical HTTP or HTTPS origin")
        _endpoint_name(host)
        canonical_host = f"[{host}]" if ":" in host else host.lower()
        canonical = parsed.scheme + "://" + canonical_host + (f":{port}" if port is not None else "")
    except (ValueError, TypeError) as exc:
        raise ValueError("workbench origin must be a canonical HTTP or HTTPS origin") from exc
    if canonical != value:
        raise ValueError("workbench origin must be a canonical HTTP or HTTPS origin")
    return value


def _endpoint_name(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("authority endpoint identity is invalid")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not all(_DNS_LABEL.fullmatch(label) for label in value.split(".")):
        raise ValueError("authority endpoint identity is invalid")
    return value


def _profile_from_payload(profile_id: str, profile_dir: Path,
                          payload: dict[str, object],
                          prepared: ssl.SSLContext | None = None) -> AuthorityTlsProfile:
    if type(payload["schema"]) is not int or payload["schema"] not in {1, 2}:
        raise ValueError("authority profile schema is invalid")
    if type(payload["port"]) is not int or not 1 <= payload["port"] <= 65535:
        raise ValueError("authority profile port is invalid")
    if payload["schema"] == 2:
        _policy_from_payload(payload)
    authority_id = payload["expected_authority_id"]
    if not isinstance(authority_id, str):
        raise ValueError("expected Authority identity is invalid")
    return AuthorityTlsProfile(
        profile_id=profile_id,
        host=_endpoint_name(payload["host"]),
        port=payload["port"],
        server_name=_endpoint_name(payload["server_name"]),
        expected_authority_id=authority_id,
        trust_root=profile_dir / "trust-root.pem",
        client_certificate=profile_dir / "client-cert.pem",
        client_private_key=profile_dir / "client-key.pem",
        prepared_ssl_context=prepared,
    )


def _exact_object(value: object, expected: frozenset[str], name: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(f"{name} schema is invalid")
    return value


def _ingress_clock_from_payload(payload: dict[str, object]) -> AdminIngressClockPolicy | None:
    if "ingress_clock" not in payload:
        return None
    if payload.get("schema") != 2:
        raise ValueError("ingress clock requires profile schema 2")
    values = _exact_object(payload["ingress_clock"], _INGRESS_CLOCK_FIELDS,
                           "ingress clock")
    return AdminIngressClockPolicy(**values)


def _ingress_encoding_from_payload(payload: dict[str, object]) -> AdminIngressEncodingPolicy | None:
    if "ingress_encoding" not in payload:
        return None
    if type(payload.get("schema")) is not int or payload["schema"] != 2:
        raise ValueError("ingress encoding requires profile schema 2")
    values = _exact_object(payload["ingress_encoding"], _INGRESS_ENCODING_FIELDS,
                           "ingress encoding")
    if type(values["quote_ceiling"]) is not dict:
        raise ValueError("ingress encoding quote ceiling must be an object")
    return AdminIngressEncodingPolicy(**values)


def _d03_arrival_from_payload(payload: dict[str, object]) -> AdminD03ArrivalPolicy | None:
    if "d03_arrival" not in payload:
        return None
    if type(payload.get("schema")) is not int or payload["schema"] != 2:
        raise ValueError("D03 arrival requires profile schema 2")
    values = _exact_object(payload["d03_arrival"], _D03_ARRIVAL_FIELDS,
                           "D03 arrival")
    if type(values["quote_ceiling"]) is not dict:
        raise ValueError("D03 arrival quote ceiling must be an object")
    return AdminD03ArrivalPolicy(**values)


def _private_reply_dispatch_from_payload(
        payload: dict[str, object]) -> AdminPrivateReplyDispatchPolicy | None:
    if "private_reply_dispatch" not in payload:
        return None
    if type(payload.get("schema")) is not int or payload["schema"] != 2:
        raise ValueError("private reply dispatch requires profile schema 2")
    values = _exact_object(payload["private_reply_dispatch"],
                           _PRIVATE_REPLY_DISPATCH_FIELDS, "private reply dispatch")
    if type(values["quote_ceiling"]) is not dict:
        raise ValueError("private reply dispatch quote ceiling must be an object")
    return AdminPrivateReplyDispatchPolicy(**values)


def _d07_attention_from_payload(payload: dict[str, object]) -> AdminD07AttentionPolicy | None:
    if "d07_attention" not in payload:
        return None
    if payload.get("schema") != 2:
        raise ValueError("D07 attention requires profile schema 2")
    values = _exact_object(payload["d07_attention"], _D07_ATTENTION_FIELDS,
                           "D07 attention")
    if type(values["quote_ceiling"]) is not dict:
        raise ValueError("D07 attention quote ceiling must be an object")
    return AdminD07AttentionPolicy(**values)


def _d04_baseline_from_payload(payload: dict[str, object]) -> AdminD04EncodingBaselinePolicy | None:
    if "d04_encoding_baseline" not in payload:
        return None
    if type(payload.get("schema")) is not int or payload["schema"] != 2:
        raise ValueError("D04 baseline requires profile schema 2")
    values = _exact_object(payload["d04_encoding_baseline"], _D04_BASELINE_FIELDS,
                           "D04 baseline")
    if type(values["quote_ceiling"]) is not dict:
        raise ValueError("D04 baseline quote ceiling must be an object")
    return AdminD04EncodingBaselinePolicy(**values)


def _life_d04_before_capture_policy_from_payload_v1(payload,installation):
    from ..runtime.d04_life_before_original_v1 import D04LifeBeforeCapturePolicyV1
    if "life_d04_before_capture_policy" not in payload:
        return None
    raw=_exact_object(payload["life_d04_before_capture_policy"],
        frozenset({"namespace","installation_id","manifest_digest","root_operation_id"}),
        "prospective Life before Root selector")
    namespace=_exact_object(raw["namespace"],frozenset({"bot_id","persona_id"}),
        "prospective Life before namespace")
    selected=D04LifeBeforeCapturePolicyV1(NamespaceId(**namespace),raw["installation_id"],
        raw["manifest_digest"],raw["root_operation_id"])
    if (selected.namespace,selected.installation_id,selected.manifest_digest)!=(
            installation.namespace,installation.installation_id,installation.manifest_digest):
        raise ValueError("prospective Life before selector changed its protected installation")
    return selected


def _d04_joint_numeric_from_payload(payload, installation):
    from ..runtime.d04_numeric_policy_v3 import numeric_policy_from_payload_v3
    return numeric_policy_from_payload_v3(payload, installation)


def _d04_semantic_drive_from_payload(
        payload: dict[str, object],
        installation: AdminInstallationPolicy,
) -> AdminD04SemanticDrivePolicyV1 | None:
    if "d04_semantic_drive" not in payload:
        return None
    raw = _exact_object(payload["d04_semantic_drive"],
                        _D04_SEMANTIC_DRIVE_FIELDS, "D04 semantic drive")
    limits = _exact_object(raw["mechanism_max_abs_doses"],
                           frozenset(D04_MECHANISMS),
                           "D04 semantic mechanism dose limits")
    family_shares = _exact_object(raw["mechanism_max_family_share"],
                                  frozenset(D04_MECHANISMS),
                                  "D04 semantic mechanism family shares")
    if any(type(values) is not list or len(values) != 3
           or any(type(value) not in (int, float) for value in values)
                  for values in limits.values()):
        raise ValueError("D04 semantic policy needs three dose limits per mechanism")
    policy = AdminD04SemanticDrivePolicyV1(
        namespace=installation.namespace,
        installation_id=installation.installation_id,
        grant_id=installation.root_grant.grant_id,
        grant_version=installation.root_grant.version,
        lease_id=installation.root_lease.lease_id,
        mapping_version=raw["mapping_version"],
        basis_version=raw["basis_version"],
        mechanism_max_abs_doses={key: tuple(value) for key, value in limits.items()},
        mechanism_max_family_share=family_shares,
        version=raw["version"],
    )
    if D04_SEMANTIC_WORK_KIND not in installation.root_grant.allowed_work_kinds:
        raise ValueError("D04 semantic drive requires an explicit root grant work kind")
    return policy


def _d06_c02_from_payload(payload: dict[str, object]) -> AdminD06FirstIngressC02Policy | None:
    if "d06_first_ingress_c02" not in payload:
        return None
    if type(payload.get("schema")) is not int or payload["schema"] != 2:
        raise ValueError("D06 C02 requires profile schema 2")
    values = _exact_object(payload["d06_first_ingress_c02"],
                           _D06_FIRST_INGRESS_C02_FIELDS, "D06 C02")
    if type(values["quote_ceiling"]) is not dict:
        raise ValueError("D06 C02 quote ceiling must be an object")
    return AdminD06FirstIngressC02Policy(**values)


def _d06_source_correction_from_payload(
    payload: dict[str, object],
) -> AdminD06SourceCorrectionPolicy | None:
    if "d06_source_correction" not in payload:
        return None
    if type(payload.get("schema")) is not int or payload["schema"] != 2:
        raise ValueError("D06 source correction requires profile schema 2")
    values = _exact_object(payload["d06_source_correction"],
                           _D06_SOURCE_CORRECTION_FIELDS, "D06 source correction")
    if type(values["quote_ceiling"]) is not dict:
        raise ValueError("D06 source correction quote ceiling must be an object")
    return AdminD06SourceCorrectionPolicy(**values)


def _d03_projection_from_payload(payload: dict[str, object]) -> AdminD03SelfIdentityProjectionPolicy | None:
    if "d03_self_identity_projection" not in payload:
        return None
    if type(payload.get("schema")) is not int or payload["schema"] != 2:
        raise ValueError("D03 projection requires profile schema 2")
    values = _exact_object(payload["d03_self_identity_projection"],
                           _D03_SELF_PROJECTION_FIELDS, "D03 projection")
    if type(values["quote_ceiling"]) is not dict:
        raise ValueError("D03 projection quote ceiling must be an object")
    return AdminD03SelfIdentityProjectionPolicy(**values)


def _ingress_model_from_payload(payload: dict[str, object]) -> AdminIngressModelPolicy | None:
    if "ingress_model" not in payload:
        return None
    if type(payload.get("schema")) is not int or payload["schema"] != 2:
        raise ValueError("ingress model requires profile schema 2")
    raw = payload["ingress_model"]
    if type(raw) is not dict or set(raw) not in (
            _INGRESS_MODEL_FIELDS,
            _INGRESS_MODEL_FIELDS | _INGRESS_MODEL_SCOPE_FIELDS):
        raise ValueError("ingress model schema is invalid")
    values = raw
    if type(values["required_capabilities"]) is not list:
        raise ValueError("ingress model capabilities must be an array")
    for field in _INGRESS_MODEL_SCOPE_FIELDS & set(values):
        if type(values[field]) is not list or not values[field]:
            raise ValueError("ingress model egress scope must be a nonempty array")
    return AdminIngressModelPolicy(**{
        **values, "required_capabilities": tuple(values["required_capabilities"]),
        **{field: tuple(values[field]) for field in _INGRESS_MODEL_SCOPE_FIELDS & set(values)},
    })


def _model_workflows_from_payload(payload: dict[str, object]) -> AdminModelWorkflowsV2 | AdminModelWorkflowsV3 | AdminModelWorkflowsV4 | AdminModelWorkflowsV5 | AdminModelWorkflowsV6 | AdminModelWorkflowsV7 | AdminModelWorkflowsV8 | AdminModelWorkflowsV9 | None:
    if "model_workflows" not in payload:
        return None
    if payload.get("schema") != 2 or "ingress_model" in payload:
        raise ValueError("model workflows require an unambiguous schema-2 profile")
    raw_value = payload["model_workflows"]
    if type(raw_value) is not dict:
        raise ValueError("model workflows must be an object")
    if raw_value.get("version") == 9:
        if not {"foreground", "artifact_draft", "artifact_phase_observer"} <= set(payload):
            raise ValueError("version-9 workflows require foreground, artifact, and phase-observer policies")
        from .model_workflows_v9 import model_workflows_v9_from_payload
        return model_workflows_v9_from_payload(raw_value)
    if raw_value.get("version") == 8:
        if not {"foreground", "artifact_draft"} <= set(payload):
            raise ValueError("version-8 workflows require explicit foreground and artifact policy objects")
        from .model_workflows_v8 import model_workflows_v8_from_payload
        return model_workflows_v8_from_payload(raw_value)
    if raw_value.get("version") == 7:
        if not {"foreground","artifact_draft"}<=set(payload):
            raise ValueError("version7 workflows require explicit foreground and artifact policy objects")
        from .model_workflows_v7 import model_workflows_v7_from_payload
        return model_workflows_v7_from_payload(raw_value)
    if raw_value.get("version") == 6:
        if not {"foreground", "artifact_draft"} <= set(payload):
            raise ValueError("version-6 workflows require their explicit foreground and artifact policy objects")
        from .model_workflows_v6 import model_workflows_v6_from_payload
        return model_workflows_v6_from_payload(raw_value)
    if raw_value.get("version") == 5:
        if not {"foreground", "artifact_draft"} <= set(payload):
            raise ValueError("version-5 workflows require their explicit foreground and artifact policy objects")
        from .model_workflows_v5 import model_workflows_v5_from_payload
        return model_workflows_v5_from_payload(raw_value)
    if raw_value.get("version") == 4:
        if not {"foreground", "artifact_draft"} <= set(payload):
            raise ValueError("version-4 workflows require their explicit policy objects")
        from .model_workflows_v4 import model_workflows_v4_from_payload
        return model_workflows_v4_from_payload(raw_value)
    if raw_value.get("version") == 3:
        from .model_workflows_v3 import model_workflows_v3_from_payload
        return model_workflows_v3_from_payload(raw_value)
    raw = _exact_object(raw_value,
                        frozenset({"version", "encode", "reply"}) |
                        {name for name in ("context_reply", "natural_generation",
                                           "natural_review", "appraisal", "d07_cognition", "contact_generation", "contact_review") if name in raw_value},
                        "model workflows")
    workflows = {}
    for name in ("encode", "reply", "context_reply", "natural_generation",
                 "natural_review", "appraisal", "d07_cognition", "contact_generation", "contact_review"):
        if name not in raw:
            continue
        item = _exact_object(raw[name], _MODEL_WORKFLOW_FIELDS,
                             f"model {name} workflow")
        if (type(item["audiences"]) is not list
                or type(item["required_capabilities"]) is not list
                or type(item["quote_ceiling"]) is not dict):
            raise ValueError(f"model {name} workflow arrays or quote are invalid")
        workflows[name] = AdminModelWorkflowV2(**{
            **item, "audiences": tuple(item["audiences"]),
            "required_capabilities": tuple(item["required_capabilities"]),
        })
    return AdminModelWorkflowsV2(raw["version"], **workflows)


def foreground_policy_from_payload_v1(raw):
    from dataclasses import fields
    values = dict(_exact_object(raw, {f.name for f in fields(AdminForegroundPolicyV1)}, "foreground policy"))
    deadline = dict(_exact_object(values["deadline_policy"],
        {f.name for f in fields(AdminForegroundDeadlinePolicyV1)}, "foreground deadline policy"))
    if deadline["natural"] is not None:
        deadline["natural"] = AdminForegroundNaturalDeadlinePolicyV1(**_exact_object(deadline["natural"],
            {f.name for f in fields(AdminForegroundNaturalDeadlinePolicyV1)}, "natural deadline policy"))
    values["deadline_policy"] = AdminForegroundDeadlinePolicyV1(**deadline)
    return AdminForegroundPolicyV1(**values)


def d06_recall_policy_from_payload_v1(raw):
    from dataclasses import fields
    values = dict(_exact_object(raw, {field.name for field in fields(AdminD06RecallPolicyV1)}, "D06 recall policy"))
    if type(values["profiles"]) is not list:
        raise ValueError("D06 recall profiles must be an explicit array")
    values["profiles"] = tuple(AdminD06RecallProfileV1(**_exact_object(profile,
        {field.name for field in fields(AdminD06RecallProfileV1)}, "D06 recall profile")) for profile in values["profiles"])
    return AdminD06RecallPolicyV1(**values)


def _d06_recall_from_payload(payload):
    if "d06_recall" not in payload:
        return None
    if _foreground_from_payload(payload) is None:
        raise ValueError("D06 recall requires explicit installed foreground configuration")
    return d06_recall_policy_from_payload_v1(payload["d06_recall"])


def artifact_draft_policy_from_payload_v1(raw):
    from dataclasses import fields
    from .model_workflows_v4 import model_workflow_v4_from_payload
    if type(raw) is dict and raw.get("schema") == "sylanne.artifact-draft-policy.v4":
        from .artifact_draft_paired_policy_v4 import artifact_draft_paired_policy_v4_from_payload
        return artifact_draft_paired_policy_v4_from_payload(raw)
    policy_type = ({"sylanne.artifact-draft-policy.v2": AdminArtifactDraftPolicyV2,
        "sylanne.artifact-draft-policy.v3": AdminArtifactDraftPolicyV3}.get(raw.get("schema"), AdminArtifactDraftPolicyV1)
        if isinstance(raw, dict) else AdminArtifactDraftPolicyV1)
    values = dict(_exact_object(raw, {f.name for f in fields(policy_type)}, "artifact draft policy"))
    if policy_type in {AdminArtifactDraftPolicyV2, AdminArtifactDraftPolicyV3}:
        values["standing_scope"] = artifact_standing_scope_from_payload_v2(values["standing_scope"])
    values["model_workflow"] = model_workflow_v4_from_payload(values["model_workflow"])
    if policy_type is AdminArtifactDraftPolicyV3:
        values["phase_model_workflow"] = model_workflow_v4_from_payload(values["phase_model_workflow"])
    scope = values["tool_scope"]
    scope_type = (AdminArtifactDraftToolScopeV2
        if isinstance(scope, dict) and scope.get("schema") == "sylanne.artifact-draft-tool-scope.v2"
        else AdminArtifactDraftToolScopeV1)
    scope = dict(_exact_object(scope, {f.name for f in fields(scope_type)}, "draft tool scope"))
    if scope_type is AdminArtifactDraftToolScopeV2:
        if type(scope["operations"]) is not list:
            raise ValueError("draft v2 operations must be the exact JSON array")
        scope["operations"] = tuple(scope["operations"])
    values["tool_scope"] = scope_type(**scope)
    values["body_policy"] = AdminArtifactDraftBodyPolicyV1(**_exact_object(values["body_policy"],
        {f.name for f in fields(AdminArtifactDraftBodyPolicyV1)}, "draft Body policy"))
    if values["observation_policy"] is not None:
        values["observation_policy"] = AdminArtifactDraftObservationPolicyV1(**_exact_object(values["observation_policy"],
            {f.name for f in fields(AdminArtifactDraftObservationPolicyV1)}, "draft observation policy"))
    return policy_type(**values)


def require_installed_artifact_target_v2(policy, root, target):
    """Intersect current signed Root parameters with the installed tool policy.

    Predecessor authenticity remains independently checked by the existing
    selection/readback readers. A V2 policy alone cannot authorize replacement.
    """
    from ..runtime.d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, DraftFileTargetV1
    from ..runtime_contracts import canonical_digest; from ..domains.d01.production_operations_v1 import plain_v1
    from .artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4, select_paired_tool_scope_v3
    if (type(policy) not in {AdminArtifactDraftPolicyV1,AdminArtifactDraftPolicyV2,AdminArtifactDraftPolicyV3,AdminArtifactDraftPairedPolicyV4}
            or type(root) is not DraftRootCapabilityV1 or type(target) is not DraftFileTargetV1):
        raise ValueError("installed draft policy and actual typed root/target required")
    if type(policy) is AdminArtifactDraftPairedPolicyV4:
        if root.filenames != (target.filename,):
            raise ValueError("paired target requires its exact signed single-file Root")
        scope = select_paired_tool_scope_v3(policy, target.filename)
    else:
        scope = policy.tool_scope
    if (root.resource_id != scope.resource_id or root.filenames != (scope.filename,)
            or target.root_resource_id != scope.resource_id or target.filename != scope.filename
            or target.root_registration_ref != root.registration_ref
            or target.root_registration_digest != canonical_digest(plain_v1(root))
            or target.root_identity != root.root_identity
            or target.max_bytes > min(root.max_bytes, scope.max_file_bytes)):
        raise ValueError("draft target exceeds the intersection of installed and registered root scope")
    if type(scope) is AdminArtifactDraftToolScopeV1:
        if target.mode != "create":
            raise ValueError("installed create-only policy does not authorize replacement")
    elif target.mode == "replace":
        if not 1 <= target.expected_prior_version < scope.maximum_artifact_version:
            raise ValueError("verified replacement exceeds the installed finite version boundary")
    elif target.mode != "create":
        raise ValueError("unregistered draft effect mode")
    return target


def _provider_billing_policy_from_payload_v1(payload):
    if "provider_billing_policy_v1" not in payload:
        return None
    return provider_billing_policy_from_wire_v1(payload["provider_billing_policy_v1"])


def _foreground_for_policy_from_payload_v1(payload, policy):
    if "foreground" not in payload:
        if "artifact_draft" in payload:
            raise ValueError("draft configuration requires explicit foreground policy")
        return None
    if type(payload["model_workflows"]["version"]) is not int or payload["model_workflows"]["version"] not in {4, 5, 6, 7, 8, 9}:
        raise ValueError("foreground requires an explicit supported workflow container")
    if "d11.foreground_cycle.v1" not in policy.root_grant.allowed_work_kinds:
        raise ValueError("foreground requires its explicit installed root work kind")
    return foreground_policy_from_payload_v1(payload["foreground"])


def _foreground_from_payload(payload):
    if "foreground" not in payload:
        if "artifact_draft" in payload:
            raise ValueError("draft configuration requires explicit foreground policy")
        return None
    return _foreground_for_policy_from_payload_v1(payload, _policy_from_payload(payload))


def _artifact_draft_for_policy_from_payload_v1(payload, policy):
    if "artifact_draft" not in payload:
        return None
    foreground = _foreground_for_policy_from_payload_v1(payload, policy)
    from .model_workflows_v4 import AdminModelWorkflowsV4
    from .model_workflows_v5 import AdminModelWorkflowsV5
    from .model_workflows_v6 import AdminModelWorkflowsV6
    from .model_workflows_v7 import AdminModelWorkflowsV7
    from .model_workflows_v8 import AdminModelWorkflowsV8
    from .model_workflows_v9 import AdminModelWorkflowsV9
    workflows = _model_workflows_from_payload(payload)
    if type(workflows) not in {AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}:
        raise ValueError("draft requires version-4 workflows")
    if payload["artifact_draft"] is None:
        if workflows.artifact_draft is not None or foreground.deadline_policy.draft_mode is not None:
            raise ValueError("unconfigured draft cannot retain its workflow or deadline mode")
        return None
    configured = artifact_draft_policy_from_payload_v1(payload["artifact_draft"])
    if (configured.model_workflow != workflows.artifact_draft
            or foreground.deadline_policy.draft_mode != "signed_scope_intersection_v1"):
        raise ValueError("draft policy, C4 slot and signed-scope deadline differ")
    required = {"artifact_draft_v1", "d10.life.artifact_draft.v1"}
    if configured.observation_policy is not None:
        required.add("d11.life.artifact_observation.v1")
    if not required <= set(policy.root_grant.allowed_work_kinds):
        raise ValueError("draft requires its explicit installed root work kinds")
    return configured


def _artifact_draft_from_payload(payload):
    if "artifact_draft" not in payload:
        return None
    return _artifact_draft_for_policy_from_payload_v1(payload, _policy_from_payload(payload))


def _d06_private_reply_source_from_payload(
    payload: dict[str, object],
) -> AdminD06PrivateReplySourcePolicy | None:
    if "d06_private_reply_source" not in payload:
        return None
    if _model_workflows_from_payload(payload) is None:
        raise ValueError("private reply expression requires installed reply workflow")
    raw = _exact_object(payload["d06_private_reply_source"],
                        _D06_PRIVATE_REPLY_SOURCE_FIELDS,
                        "private reply source policy")
    return AdminD06PrivateReplySourcePolicy(**raw)


def _d13_precompression_from_payload(
    payload: dict[str, object], policy: AdminInstallationPolicy,
) -> AdminD13PrecompressionPolicyV1 | None:
    if "d13_precompression" not in payload:
        return None

    raw = _exact_object(payload["d13_precompression"],
                        _D13_PRECOMPRESSION_FIELDS, "D13 precompression")
    installed = AdminD13PrecompressionPolicyV1(
        namespace=policy.namespace,
        installation_id=policy.installation_id,
        grant_id=policy.root_grant.grant_id,
        grant_version=policy.root_grant.version,
        lease_id=policy.root_lease.lease_id,
        **raw,
    )
    if "d13.precompress" not in policy.root_grant.allowed_work_kinds:
        raise ValueError("D13 precompression requires an explicit root grant work kind")
    if any(amount > policy.root_grant.max_ceiling.get(name, 0)
           or amount > policy.root_lease.limits.get(name, 0)
           for name, amount in installed.quote_ceiling.items()):
        raise ValueError("D13 precompression quote exceeds signed root budget")
    return installed


def _d13_paid_precompression_from_payload(
    payload: dict[str, object], policy: AdminInstallationPolicy,
) -> AdminD13PaidPrecompressionPolicyV1 | None:
    """Install a distinct paid D13 allowance on the signed parent budget."""
    if "d13_paid_precompression" not in payload:
        return None
    raw = _exact_object(payload["d13_paid_precompression"],
                        _D13_PAID_PRECOMPRESSION_FIELDS,
                        "D13 paid precompression")
    workflows = _model_workflows_from_payload(payload)
    from .model_workflows_v3 import AdminModelWorkflowsV3
    from .model_workflows_v4 import AdminModelWorkflowsV4
    from .model_workflows_v5 import AdminModelWorkflowsV5
    from .model_workflows_v6 import AdminModelWorkflowsV6
    from .model_workflows_v7 import AdminModelWorkflowsV7
    from .model_workflows_v8 import AdminModelWorkflowsV8
    from .model_workflows_v9 import AdminModelWorkflowsV9
    if (type(workflows) not in (AdminModelWorkflowsV2, AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9)
            or type(workflows.reply) is not AdminModelWorkflowV2
            or "d13.precompress.paid.v1"
               not in policy.root_grant.allowed_work_kinds):
        raise ValueError("D13 paid compression needs a signed work kind and main model")
    main = workflows.reply
    selected = D13PrecompressionInstallationV1(
        policy.installation_id, main.provider_id, main.model_id,
        main.provider_config_digest, main.max_output_tokens)
    installed = AdminD13PaidPrecompressionPolicyV1(
        namespace=policy.namespace, installation_id=policy.installation_id,
        grant_id=policy.root_grant.grant_id,
        grant_version=policy.root_grant.version,
        lease_id=policy.root_lease.lease_id,
        selected_main=selected, **raw)
    if (any(amount > policy.root_grant.max_ceiling.get(name, 0)
            or amount > policy.root_lease.limits.get(name, 0)
            or amount > main.quote_ceiling.get(name, 0)
            for name, amount in installed.quote_ceiling.items())):
        raise ValueError("D13 paid quote exceeds signed parent or main model")
    return installed


def _policy_from_payload(payload: dict[str, object]) -> AdminInstallationPolicy:
    """Parse schema 2 after the enclosing profile passed its trusted read gate."""
    from ..runtime.issuers import BudgetLeaseGrant

    if (type(payload.get("schema")) is not int or payload["schema"] != 2
            or not _valid_schema2_fields(payload)):
        raise ValueError("administrator installation policy requires profile schema 2")
    _ingress_clock_from_payload(payload)
    encoding = _ingress_encoding_from_payload(payload)
    arrival = _d03_arrival_from_payload(payload)
    private_reply_dispatch = _private_reply_dispatch_from_payload(payload)
    attention = _d07_attention_from_payload(payload)
    baseline = _d04_baseline_from_payload(payload)
    c02 = _d06_c02_from_payload(payload)
    correction = _d06_source_correction_from_payload(payload)
    projection = _d03_projection_from_payload(payload)
    model = _ingress_model_from_payload(payload)
    workflows = _model_workflows_from_payload(payload)
    _d06_private_reply_source_from_payload(payload)
    _workbench_origin_from_payload(payload)
    values = _exact_object(payload["installation_policy"], _INSTALLATION_FIELDS,
                           "installation policy")
    namespace = _exact_object(values["namespace"], frozenset({"bot_id", "persona_id"}),
                              "installation namespace")
    if "astrbot_namespace_v1" in payload:
        from .identity import astrbot_namespace_from_configuration_v1
        declared = astrbot_namespace_from_configuration_v1(payload["astrbot_namespace_v1"])
        if NamespaceId(**namespace) != declared:
            raise ValueError("installed profile changed its configured AstrBot namespace identity")
    lease = _exact_object(values["root_lease"], _LEASE_FIELDS, "root lease")
    grant = _exact_object(values["root_grant"], _GRANT_FIELDS, "root grant")
    if values["expected_authority_id"] != payload["expected_authority_id"]:
        raise ValueError("installation Authority identity differs from TLS profile")
    if type(lease["version"]) is not int or type(grant["version"]) is not int:
        raise ValueError("root budget version must be an exact integer")
    if (type(lease["limits"]) is not dict or not lease["limits"]
            or any(type(value) is not int or value <= 0
                   for value in lease["limits"].values())):
        raise ValueError("root lease requires explicit positive limits")
    if type(grant["allowed_work_kinds"]) is not list:
        raise ValueError("root grant work kinds must be a list")
    policy = AdminInstallationPolicy(
        namespace=NamespaceId(**namespace),
        authority_namespace=values["authority_namespace"],
        installation_id=values["installation_id"],
        manifest_digest=values["manifest_digest"],
        administrator_holder=values["administrator_holder"],
        expected_authority_id=values["expected_authority_id"],
        catalogue_hash=values["catalogue_hash"],
        scheme_version=values["scheme_version"],
        operator_version=values["operator_version"],
        policy_version=values["policy_version"],
        root_lease=BudgetLease(**lease),
        root_grant=BudgetLeaseGrant(**{
            **grant, "allowed_work_kinds": tuple(grant["allowed_work_kinds"]),
        }),
    )
    _d04_semantic_drive_from_payload(payload, policy)
    _d04_joint_numeric_from_payload(payload, policy)
    if arrival is not None:
        if "d03.message_received" not in policy.root_grant.allowed_work_kinds:
            raise ValueError("D03 arrival requires an explicit root grant work kind")
        if any(amount > policy.root_grant.max_ceiling.get(name, 0)
               for name, amount in arrival.quote_ceiling.items()):
            raise ValueError("D03 arrival quote exceeds the signed root grant")
    if private_reply_dispatch is not None:
        if "message" not in policy.root_grant.allowed_work_kinds:
            raise ValueError("private reply dispatch requires message root grant work kind")
        if any(amount > policy.root_grant.max_ceiling.get(name, 0)
               or amount > policy.root_lease.limits.get(name, 0)
               for name, amount in private_reply_dispatch.quote_ceiling.items()):
            raise ValueError("private reply dispatch quote exceeds signed root budget")
    if attention is not None:
        if "d07.attention" not in policy.root_grant.allowed_work_kinds:
            raise ValueError("D07 attention requires an explicit root grant work kind")
        if any(amount > policy.root_grant.max_ceiling.get(name, 0)
               or amount > policy.root_lease.limits.get(name, 0)
               for name, amount in attention.quote_ceiling.items()):
            raise ValueError("D07 attention quote exceeds the signed root budget")
    if baseline is not None:
        if "d04.encoding_baseline" not in policy.root_grant.allowed_work_kinds:
            raise ValueError("D04 baseline requires an explicit root grant work kind")
        if any(amount > policy.root_grant.max_ceiling.get(name, 0)
               or amount > policy.root_lease.limits.get(name, 0)
               for name, amount in baseline.quote_ceiling.items()):
            raise ValueError("D04 baseline quote exceeds the signed root budget")
    if c02 is not None:
        if "d06.first_ingress_c02" not in policy.root_grant.allowed_work_kinds:
            raise ValueError("D06 C02 requires an explicit root grant work kind")
        if any(amount > policy.root_grant.max_ceiling.get(name, 0)
               or amount > policy.root_lease.limits.get(name, 0)
               for name, amount in c02.quote_ceiling.items()):
            raise ValueError("D06 C02 quote exceeds the signed root budget")
    if correction is not None:
        if "d06.source_correction" not in policy.root_grant.allowed_work_kinds:
            raise ValueError("D06 source correction requires an explicit root grant work kind")
        if any(amount > policy.root_grant.max_ceiling.get(name, 0)
               or amount > policy.root_lease.limits.get(name, 0)
               for name, amount in correction.quote_ceiling.items()):
            raise ValueError("D06 source correction quote exceeds the signed root budget")
    if projection is not None:
        if "d03.self_identity_projection" not in policy.root_grant.allowed_work_kinds:
            raise ValueError("D03 projection requires an explicit root grant work kind")
        if any(amount > policy.root_grant.max_ceiling.get(name, 0)
               or amount > policy.root_lease.limits.get(name, 0)
               for name, amount in projection.quote_ceiling.items()):
            raise ValueError("D03 projection quote exceeds the signed root budget")
    if model is not None and encoding is not None:
        output = model.max_output_tokens
        if (encoding.quote_ceiling.get("output_tokens", 0) < output
                or policy.root_lease.limits.get("output_tokens", 0) < output
                or policy.root_grant.max_ceiling.get("output_tokens", 0) < output):
            raise ValueError("ingress output_tokens exceeds quote or root budget")
    if workflows is not None:
        if encoding is None:
            raise ValueError("encoding workflow requires an installed encoding quote")
        for workflow in (workflows.encode, workflows.reply) + tuple(
                item for item in (workflows.context_reply,
                                  workflows.natural_generation,
                                  workflows.natural_review,
                                  workflows.appraisal, workflows.d07_cognition,
                                  workflows.contact_generation, workflows.contact_review,
                                  getattr(workflows, "life_content", None),
                                  getattr(workflows, "life_numeric", None),
                                  getattr(workflows, "d07_relationship_cognition", None),
                                  getattr(workflows, "general_growth_cognition", None)) if item is not None):
            if workflow.work_kind not in policy.root_grant.allowed_work_kinds:
                raise ValueError("model workflow lacks its own root grant work kind")
            if any(amount > policy.root_grant.max_ceiling.get(name, 0)
                   or amount > policy.root_lease.limits.get(name, 0)
                   for name, amount in workflow.quote_ceiling.items()):
                raise ValueError("model workflow quote exceeds root budget")
        if any(amount > encoding.quote_ceiling.get(name, 0)
               for name, amount in workflows.encode.quote_ceiling.items()):
            raise ValueError("encoding workflow exceeds installed encoding quote")
    _d13_precompression_from_payload(payload, policy)
    _d13_paid_precompression_from_payload(payload, policy)
    _artifact_phase_counter_from_payload(payload, policy)
    _method_measurement_policy_from_payload_v1(payload)
    _contact_effect_accounting_from_payload_v1(payload)
    _habit_runtime_policy_from_payload_v1(payload,policy)
    return policy


def _load_profile_from_root(profile_id: str, profile_root: Path,
                            *, prepare_tls: bool = False) -> AuthorityTlsProfile:
    """Internal schema-test seam; production requires prepare_tls=True."""
    _check_profile_id(profile_id)
    profile_root = Path(profile_root)
    if not profile_root.is_absolute():
        raise ValueError("administrator profile root must be absolute")
    profile_dir = profile_root / profile_id
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        with _opened_profile(profile_dir, system) as files:
            payload = _read_profile_json(files["profile.json"])
            prepared = _prepared_ssl_context(files, system) if prepare_tls else None
    else:
        # Internal schema-test seam only. Production Windows uses pinned handles.
        _check_posix_tree(profile_dir)
        payload = _read_profile_json(profile_dir / "profile.json")
        prepared = None
    return _profile_from_payload(profile_id, profile_dir, payload, prepared)


def _build_transport_from_root(profile_id: str, profile_root: Path) -> MtlsAuthorityTransport:
    from .mtls_transport import MtlsAuthorityTransport
    profile = _load_profile_from_root(profile_id, profile_root, prepare_tls=True)
    if platform.system() in {"Linux", "Darwin"} and profile.prepared_ssl_context is None:
        raise AuthorityProfileUnavailable("verified TLS context was not prepared")
    return MtlsAuthorityTransport({profile_id: profile})


def _build_windows_admin_transport(profile_id: str) -> MtlsAuthorityTransport:
    from .mtls_transport import MtlsAuthorityTransport
    from .windows_profile_security import programdata_profile_root

    profile_dir = programdata_profile_root() / profile_id
    with _opened_windows_profile(profile_dir) as handles:
        _check_windows_handles(profile_dir, handles)
        profile = _profile_from_payload(
            profile_id, profile_dir, _read_profile_json(profile_dir / "profile.json")
        )
        # CPython/OpenSSL currently accepts paths only for client cert/key.
        # Every object and ancestor stays pinned against write/delete while
        # this synchronous call reopens the paths. The SSLContext then holds
        # the loaded material independently of the filesystem paths.
        profile = replace(profile, prepared_ssl_context=profile.ssl_context())
    return MtlsAuthorityTransport({profile_id: profile})


def build_admin_authority_transport(profile_id: str) -> MtlsAuthorityTransport:
    """Construct the real mTLS client only from the OS administrator root.

    Darwin has a conservative fd/ACL gate, but macOS platform qualification
    still requires native ACL and fd-alias tests plus cold installation.
    Windows pins every object with read-only sharing during handle-based
    owner/DACL checks and the subsequent synchronous OpenSSL file loads.
    Platform qualification still requires a real administrator installation.
    """
    _check_profile_id(profile_id)
    system = platform.system()
    if system in {"Linux", "Darwin"} and os.name != "posix":
        raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
    if system in {"Linux", "Darwin"} and os.geteuid() == 0:
        raise AuthorityProfileUnavailable("Authority client must run without administrator identity")
    if system == "Linux":
        root = Path("/etc/sylanne/client/profiles")
    elif system == "Darwin":
        root = Path("/Library/Application Support/Sylanne/client/profiles")
    elif system == "Windows":
        return _build_windows_admin_transport(profile_id)
    else:
        raise AuthorityProfileUnavailable("unsupported Authority profile platform")
    return _build_transport_from_root(profile_id, root)


def load_admin_installation_policy(profile_id: str) -> AdminInstallationPolicy:
    """Read schema-2 policy only through the real administrator profile gate.

    This returns a value, not an authorization capability. Callers must still
    match the separately authenticated Authority installation and namespace.
    """
    _check_profile_id(profile_id)
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        if os.name != "posix":
            raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
        if os.geteuid() == 0:
            raise AuthorityProfileUnavailable("Authority client must run without administrator identity")
        root = (Path("/etc/sylanne/client/profiles") if system == "Linux" else
                Path("/Library/Application Support/Sylanne/client/profiles"))
        with _opened_profile(root / profile_id, system) as files:
            payload = _read_profile_json(files["profile.json"])
            return _policy_from_payload(payload)
    if system == "Windows":
        from .windows_profile_security import programdata_profile_root

        profile_dir = programdata_profile_root() / profile_id
        with _opened_windows_profile(profile_dir) as handles:
            _check_windows_handles(profile_dir, handles)
            payload = _read_profile_json(profile_dir / "profile.json")
            return _policy_from_payload(payload)
    raise AuthorityProfileUnavailable("unsupported Authority profile platform")


def _read_windows_signing_key(handle: int) -> bytes:
    """Read the pinned object itself; reopening its pathname would break the gate."""
    if os.name != "nt":
        raise AuthorityProfileUnavailable("Windows signing-key handle is unavailable")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ReadFile.argtypes = (
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p,
    )
    kernel.ReadFile.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(_D11_SIGNING_KEY_BYTES + 1)
    count = ctypes.c_uint32()
    if not kernel.ReadFile(ctypes.c_void_p(handle), buffer, len(buffer),
                           ctypes.byref(count), None):
        raise AuthorityProfileUnavailable("Windows signing-key handle read failed")
    return bytes(buffer[:count.value])


def _checked_signing_key(raw: bytes, domain: str) -> bytes:
    if len(raw) != _D11_SIGNING_KEY_BYTES:
        raise ValueError(f"administrator {domain} signing key must be exactly 32 bytes")
    return raw


def _load_installation_bundle_from_root(
    profile_id: str, profile_root: Path, system: str,
) -> AdminInstallationBundle:
    """Load a POSIX installation through one pinned directory and file set."""
    _check_profile_id(profile_id)
    if system not in {"Linux", "Darwin"} or os.name != "posix":
        raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
    profile_dir = Path(profile_root) / profile_id
    reverse_material = _reverse_material_present(profile_dir)
    with _opened_profile(profile_dir, system, signing_key=True,
                         reverse_material=reverse_material) as files:
        payload = _read_profile_json(files["profile.json"])
        policy = _policy_from_payload(payload)
        prepared = _prepared_ssl_context(files, system)
        profile = _profile_from_payload(profile_id, profile_dir, payload, prepared)
        d11_key = _checked_signing_key(
            _read_fd_bounded(files[_D11_SIGNING_KEY], _D11_SIGNING_KEY_BYTES), "D11"
        )
        d02_key = _checked_signing_key(
            _read_fd_bounded(files[_D02_SIGNING_KEY], _D11_SIGNING_KEY_BYTES), "D02"
        )
        reverse_handoff = _reverse_handoff_from_payload(
            payload, profile_dir, policy, material_present=reverse_material)
    return AdminInstallationBundle(profile, policy, d11_key, d02_key,
                                   _ingress_clock_from_payload(payload),
                                   _ingress_encoding_from_payload(payload),
                                   _workbench_origin_from_payload(payload),
                                   _ingress_model_from_payload(payload),
                                   _d03_arrival_from_payload(payload),
                                   _model_workflows_from_payload(payload),
                                   _d04_baseline_from_payload(payload),
                                   _d06_c02_from_payload(payload),
                                   _d03_projection_from_payload(payload),
                                   _d06_source_correction_from_payload(payload),
                                   reverse_handoff,
                                   _d06_private_reply_source_from_payload(payload),
                                    _d07_attention_from_payload(payload),
                                    _private_reply_dispatch_from_payload(payload),
                                    _d13_precompression_from_payload(payload, policy),
                                    _d04_semantic_drive_from_payload(payload, policy),
                                    _d13_paid_precompression_from_payload(payload, policy),
                                    _d13_wire_policy_from_payload(payload, policy),
                                    _d13_wire_counter_from_payload(payload),
                                    _d04_joint_numeric_from_payload(payload, policy),
                                     package_selection=getattr(files, 'selected_package', None),
                                     foreground=_foreground_from_payload(payload),
                                     artifact_draft=_artifact_draft_from_payload(payload),
                                      provider_billing_policy_v1=_provider_billing_policy_from_payload_v1(payload),
                                      d06_recall=_d06_recall_from_payload(payload),
                                      artifact_phase_counter=_artifact_phase_counter_from_payload(payload, policy),
                                      method_measurement_policy=_method_measurement_policy_from_payload_v1(payload),
                                      contact_effect_accounting=_contact_effect_accounting_from_payload_v1(payload),
                                      life_d04_before_capture_policy=_life_d04_before_capture_policy_from_payload_v1(payload,policy),
                                   habit_runtime_policy=_habit_runtime_policy_from_payload_v1(payload,policy),
                                   artifact_phase_observer=_artifact_phase_observer_from_payload_v2(payload))


def _load_windows_installation_bundle(
    profile_id: str, profile_root: Path,
) -> AdminInstallationBundle:
    """Keep every checked Windows handle pinned until TLS and key reads finish."""
    _check_profile_id(profile_id)
    profile_dir = Path(profile_root) / profile_id
    reverse_material = _reverse_material_present(profile_dir)
    with _opened_windows_profile(profile_dir, signing_key=True,
                                 reverse_material=reverse_material) as handles:
        _check_windows_handles(profile_dir, handles)
        payload = _read_profile_json(profile_dir / "profile.json")
        policy = _policy_from_payload(payload)
        profile = _profile_from_payload(profile_id, profile_dir, payload)
        profile = replace(profile, prepared_ssl_context=profile.ssl_context())
        d11_key = _checked_signing_key(
            _read_windows_signing_key(handles[profile_dir / _D11_SIGNING_KEY]), "D11"
        )
        d02_key = _checked_signing_key(
            _read_windows_signing_key(handles[profile_dir / _D02_SIGNING_KEY]), "D02"
        )
        reverse_handoff = _reverse_handoff_from_payload(
            payload, profile_dir, policy, material_present=reverse_material)
    return AdminInstallationBundle(profile, policy, d11_key, d02_key,
                                   _ingress_clock_from_payload(payload),
                                   _ingress_encoding_from_payload(payload),
                                   _workbench_origin_from_payload(payload),
                                   _ingress_model_from_payload(payload),
                                   _d03_arrival_from_payload(payload),
                                   _model_workflows_from_payload(payload),
                                   _d04_baseline_from_payload(payload),
                                   _d06_c02_from_payload(payload),
                                   _d03_projection_from_payload(payload),
                                   _d06_source_correction_from_payload(payload),
                                   reverse_handoff,
                                   _d06_private_reply_source_from_payload(payload),
                                    _d07_attention_from_payload(payload),
                                    _private_reply_dispatch_from_payload(payload),
                                    _d13_precompression_from_payload(payload, policy),
                                    _d04_semantic_drive_from_payload(payload, policy),
                                    _d13_paid_precompression_from_payload(payload, policy),
                                    _d13_wire_policy_from_payload(payload, policy),
                                    _d13_wire_counter_from_payload(payload),
                                     _d04_joint_numeric_from_payload(payload, policy),
                                     foreground=_foreground_from_payload(payload),
                                     artifact_draft=_artifact_draft_from_payload(payload),
                                      provider_billing_policy_v1=_provider_billing_policy_from_payload_v1(payload),
                                      d06_recall=_d06_recall_from_payload(payload),
                                      artifact_phase_counter=_artifact_phase_counter_from_payload(payload, policy),
                                      method_measurement_policy=_method_measurement_policy_from_payload_v1(payload),
                                      contact_effect_accounting=_contact_effect_accounting_from_payload_v1(payload),
                                      life_d04_before_capture_policy=_life_d04_before_capture_policy_from_payload_v1(payload,policy),
                                   habit_runtime_policy=_habit_runtime_policy_from_payload_v1(payload,policy),
                                   artifact_phase_observer=_artifact_phase_observer_from_payload_v2(payload))


def load_admin_installation_bundle(profile_id: str) -> AdminInstallationBundle:
    """Load schema-2 TLS, policy and D11/D02 keys from one administrator snapshot."""
    _check_profile_id(profile_id)
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        if os.name != "posix":
            raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
        if os.geteuid() == 0:
            raise AuthorityProfileUnavailable("Authority client must run without administrator identity")
        root = (Path("/etc/sylanne/client/profiles") if system == "Linux" else
                Path("/Library/Application Support/Sylanne/client/profiles"))
        return _load_installation_bundle_from_root(profile_id, root, system)
    if system == "Windows":
        from .windows_profile_security import programdata_profile_root

        return _load_windows_installation_bundle(profile_id, programdata_profile_root())
    raise AuthorityProfileUnavailable("unsupported Authority profile platform")


def load_admin_d11_signing_key(profile_id: str) -> bytes:
    """Read a schema-2 installation's separate 32-byte administrator D11 key."""
    _check_profile_id(profile_id)
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        if os.name != "posix":
            raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
        if os.geteuid() == 0:
            raise AuthorityProfileUnavailable("Authority client must run without administrator identity")
        root = (Path("/etc/sylanne/client/profiles") if system == "Linux" else
                Path("/Library/Application Support/Sylanne/client/profiles"))
        with _opened_profile(root / profile_id, system, signing_key=True) as files:
            _policy_from_payload(_read_profile_json(files["profile.json"]))
            raw = _read_fd_bounded(files[_D11_SIGNING_KEY], _D11_SIGNING_KEY_BYTES)
    elif system == "Windows":
        from .windows_profile_security import programdata_profile_root

        profile_dir = programdata_profile_root() / profile_id
        with _opened_windows_profile(profile_dir, signing_key=True) as handles:
            _check_windows_handles(profile_dir, handles)
            _policy_from_payload(_read_profile_json(profile_dir / "profile.json"))
            raw = _read_windows_signing_key(handles[profile_dir / _D11_SIGNING_KEY])
    else:
        raise AuthorityProfileUnavailable("unsupported Authority profile platform")
    if len(raw) != _D11_SIGNING_KEY_BYTES:
        raise ValueError("administrator D11 signing key must be exactly 32 bytes")
    return raw


def load_admin_c04_signing_key(profile_id: str) -> bytes:
    """Read the independent persistent C04 key through the installed handle gate."""
    _check_profile_id(profile_id)
    system = platform.system()
    if system in {"Linux", "Darwin"}:
        if os.name != "posix":
            raise AuthorityProfileUnavailable("POSIX directory-descriptor traversal is unavailable")
        if os.geteuid() == 0:
            raise AuthorityProfileUnavailable("Authority client must run without administrator identity")
        root = (Path("/etc/sylanne/client/profiles") if system == "Linux" else
                Path("/Library/Application Support/Sylanne/client/profiles"))
        with _opened_profile(root / profile_id, system, c04_signing_key=True) as files:
            _policy_from_payload(_read_profile_json(files["profile.json"]))
            raw = _read_fd_bounded(files[_C04_SIGNING_KEY], _D11_SIGNING_KEY_BYTES)
    elif system == "Windows":
        from .windows_profile_security import programdata_profile_root

        profile_dir = programdata_profile_root() / profile_id
        with _opened_windows_profile(profile_dir, c04_signing_key=True) as handles:
            _check_windows_handles(profile_dir, handles)
            _policy_from_payload(_read_profile_json(profile_dir / "profile.json"))
            raw = _read_windows_signing_key(handles[profile_dir / _C04_SIGNING_KEY])
    else:
        raise AuthorityProfileUnavailable("unsupported Authority profile platform")
    return _checked_signing_key(raw, "C04")


__all__ = (
    "AdminD03ArrivalPolicy", "AdminD03SelfIdentityProjectionPolicy", "AdminD04EncodingBaselinePolicy", "AdminD06FirstIngressC02Policy", "AdminD06SourceCorrectionPolicy", "AdminIngressClockPolicy", "AdminIngressEncodingPolicy", "AdminIngressModelPolicy",
    "AdminModelWorkflowV2", "AdminModelWorkflowsV2",
    "AdminD06PrivateReplySourcePolicy",
    "AdminD07AttentionPolicy",
    "AdminD04SemanticDrivePolicyV1",
    "AdminPrivateReplyDispatchPolicy",
    "AdminD13PrecompressionPolicyV1",
    "AdminD13PaidPrecompressionPolicyV1",
    "AdminInstallationBundle", "AdminArtifactDraftPolicyV3",
    "is_installed_life_numeric_slot_v1", "is_installed_artifact_draft_slot_v1", "is_installed_artifact_draft_phase_slot_v2",
    "AdminInstallationPolicy",
    "AuthorityProfileUnavailable",
    "build_admin_authority_transport", "load_admin_installation_policy",
    "installed_model_config_ref",
    "load_admin_d11_signing_key", "load_admin_c04_signing_key",
    "load_admin_installation_bundle",
)


def _contact_effect_accounting_from_payload_v1(payload):
    from ..authority_service.contact_effect_accounting_contract_v1 import ContactEffectPricingPolicyV1, from_wire
    raw = payload.get("contact_effect_accounting")
    return None if raw is None else from_wire(raw, ContactEffectPricingPolicyV1)


def _habit_runtime_policy_from_payload_v1(payload,policy):
    from .habit_runtime_policy_v1 import habit_runtime_policy_from_payload_v1
    return habit_runtime_policy_from_payload_v1(payload.get("habit_runtime_policy"),policy)


def _artifact_phase_observer_from_payload_v2(payload):
    from .artifact_phase_observer_policy_v2 import load_artifact_phase_observer_policy_v2
    return load_artifact_phase_observer_policy_v2(payload)
