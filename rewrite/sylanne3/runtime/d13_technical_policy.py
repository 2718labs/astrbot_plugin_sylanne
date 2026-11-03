"""Installed D11 technical limits for deterministic D13 precompression."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from ..domains.d13.precompression import COMPILER_VERSION
from ..model_broker.d13_precompression import D13PrecompressionInstallationV1
from ..runtime_contracts import NamespaceId


@dataclass(frozen=True, slots=True)
class AdminD13PrecompressionPolicyV1:
    namespace: NamespaceId
    installation_id: str
    grant_id: str
    grant_version: int
    lease_id: str
    history_token_budget: int
    quote_ceiling: Mapping[str, int]
    deadline_after_seconds: int
    max_slots: int
    resource_ref: str

    @property
    def work_kind(self) -> str:
        return "d13.precompress"

    @property
    def compiler_version(self) -> str:
        return COMPILER_VERSION

    @property
    def model_assist(self) -> bool:
        return False

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId:
            raise TypeError("D13 policy needs a typed namespace")
        for field in ("installation_id", "grant_id", "lease_id", "resource_ref"):
            if type(getattr(self, field)) is not str or not getattr(self, field):
                raise ValueError(f"D13 policy {field} is required")
        if (type(self.grant_version) is not int or self.grant_version < 1 or
                type(self.history_token_budget) is not int or
                self.history_token_budget < 1 or
                type(self.deadline_after_seconds) is not int or
                not 1 <= self.deadline_after_seconds <= 72 * 3600 or
                type(self.max_slots) is not int or not 3 <= self.max_slots <= 64):
            raise ValueError("invalid installed D13 technical limits")
        if self.quote_ceiling != {"d13_compute_units": 1}:
            raise ValueError("deterministic D13 requires one technical compute unit")
        object.__setattr__(self, "quote_ceiling",
                           MappingProxyType(dict(self.quote_ceiling)))


@dataclass(frozen=True, slots=True)
class AdminD13PaidPrecompressionPolicyV1:
    """Separate D11 allowance for calls using the installed main model."""

    namespace: NamespaceId
    installation_id: str
    grant_id: str
    grant_version: int
    lease_id: str
    history_token_budget: int
    quote_ceiling: Mapping[str, int]
    deadline_after_seconds: int
    max_slots: int
    resource_ref: str
    selected_main: D13PrecompressionInstallationV1

    @property
    def work_kind(self) -> str:
        return "d13.precompress.paid.v1"

    @property
    def model_assist(self) -> bool:
        return True

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId or
                type(self.selected_main) is not D13PrecompressionInstallationV1 or
                self.installation_id != self.selected_main.installation_id):
            raise ValueError("paid D13 needs a typed installed main model")
        for field in ("grant_id", "lease_id", "resource_ref"):
            if type(getattr(self, field)) is not str or not getattr(self, field):
                raise ValueError(f"paid D13 {field} is required")
        if (type(self.grant_version) is not int or self.grant_version < 1 or
                type(self.history_token_budget) is not int or
                self.history_token_budget < 1 or
                type(self.deadline_after_seconds) is not int or
                not 1 <= self.deadline_after_seconds <= 72 * 3600 or
                type(self.max_slots) is not int or not 3 <= self.max_slots <= 64 or
                type(self.quote_ceiling) is not dict or
                self.quote_ceiling.get("output_tokens", 0) <
                self.selected_main.max_output_tokens or
                (self.quote_ceiling.get("input_tokens", 0) <= 0 and
                 self.quote_ceiling.get("model_tokens", 0) <=
                 self.selected_main.max_output_tokens) or
                any(type(v) is not int or v <= 0
                    for v in self.quote_ceiling.values())):
            raise ValueError("paid D13 requires independent positive model bounds")
        object.__setattr__(self, "quote_ceiling",
                           MappingProxyType(dict(self.quote_ceiling)))


@dataclass(frozen=True, slots=True)
class D13ScheduleRecoveryItemV2:
    """Namespace-local metadata needed to obtain the real D11 audience."""

    original_operation_id: str
    conversation_ref: str
    scene_ref: str

    def __post_init__(self) -> None:
        if (type(self.original_operation_id) is not str or
                not self.original_operation_id or
                type(self.conversation_ref) is not str or
                not self.conversation_ref or
                type(self.scene_ref) is not str or
                not self.scene_ref.startswith("scene:")):
            raise ValueError("invalid D13 schedule recovery metadata")


def d13_cache_interval_v2(*policies):
    intervals = [p.deadline_after_seconds for p in policies if p is not None]
    if not intervals:
        raise ValueError("D13 cache policies need their actual installed D13 interval")
    return min(intervals)


def require_d13_cache_policy_installation_v2(use, maintenance, installation, *, d13_interval):
    from ..authority_service.d13_cache_use_contract_v2 import (
        AdminD13CacheUseControlPolicyV2, cache_policy_pair_digest_v2)
    from .d13_derived_cache_maintenance_v2 import AdminD13DerivedCacheMaintenancePolicyV2
    if use is None and maintenance is None:
        return
    if (type(use) is not AdminD13CacheUseControlPolicyV2
            or type(maintenance) is not AdminD13DerivedCacheMaintenancePolicyV2):
        raise ValueError("D13 cache use and maintenance policies require their complete typed pair")
    if (use.namespace != installation.namespace or maintenance.namespace != installation.namespace
            or use.authority_namespace != installation.authority_namespace
            or use.installation_id != installation.installation_id
            or maintenance.installation_id != installation.installation_id
            or use.peer_maintenance_policy_ref != maintenance.link_ref
            or maintenance.use_control_policy_ref != use.policy_ref
            or use.consumer_cohort_digest != maintenance.consumer_cohort_digest
            or use.policy_pair_digest != maintenance.policy_pair_digest
            or use.policy_pair_digest != cache_policy_pair_digest_v2(use, maintenance)):
        raise ValueError("D13 cache policy pair differs from its protected installation")
    root = installation.root_grant
    if ((maintenance.grant_id, maintenance.grant_version, maintenance.lease_id)
            != (root.grant_id, root.version, root.lease_id)
            or maintenance.deadline_after_seconds > d13_interval):
        raise ValueError("D13 maintenance differs from its actual Root or D13 interval")
    if maintenance.capacity_eviction_enabled or maintenance.cold_maintenance_enabled:
        if (not use.enabled or maintenance.work_kind not in root.allowed_work_kinds
                or root.policy_ref != maintenance.policy_ref
                or root.max_ceiling.get("d13_compute_units", 0) < 1
                or installation.root_lease.limits.get("d13_compute_units", 0) < 1):
            raise ValueError("D13 maintenance needs its explicit enabled use pair and new signed Root")


def d13_cache_policy_pair_from_payload_v2(payload, installation, *, d13_policies):
    names = ("d13_cache_use_control_v2", "d13_derived_cache_maintenance_v2")
    if not any(name in payload for name in names):
        return None, None
    if not all(name in payload for name in names):
        raise ValueError("D13 cache policies require both exact originals")
    from ..authority_service.d13_cache_use_contract_v2 import use_policy_from_payload_v2
    from .d13_derived_cache_maintenance_v2 import maintenance_policy_from_payload_v2
    interval = d13_cache_interval_v2(*d13_policies)
    use = use_policy_from_payload_v2(payload[names[0]])
    maintenance = maintenance_policy_from_payload_v2(payload, installation, interval)
    require_d13_cache_policy_installation_v2(use, maintenance, installation, d13_interval=interval)
    return use, maintenance


@dataclass(frozen=True, slots=True)
class InstalledD13CacheUseAssetsV2:
    """Protected package pins for existing signed Core policy originals."""

    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    package_manifest_sha256: str
    use_policy_ref: str
    use_policy_digest: str
    maintenance_policy_ref: str
    maintenance_policy_digest: str
    consumer_cohort_digest: str
    policy_pair_digest: str

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId:
            raise ValueError("D13 cache assets require their typed Graph namespace")
        for name in ("authority_namespace", "installation_id", "use_policy_ref", "maintenance_policy_ref"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError("D13 cache asset identity required: " + name)
        for name in ("package_manifest_sha256", "use_policy_digest", "maintenance_policy_digest",
                     "consumer_cohort_digest", "policy_pair_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("D13 cache asset SHA256 required: " + name)

    def require_installation_v2(self, bundle):
        from ..host.authority_profile import AdminInstallationBundle
        if type(bundle) is not AdminInstallationBundle:
            raise ValueError("D13 cache assets require the actual protected installation bundle")
        installation = bundle.installation_policy
        use, maintenance = bundle.d13_cache_use_control_v2, bundle.d13_derived_cache_maintenance_v2
        if use is None or maintenance is None:
            raise ValueError("D13 cache assets have no explicit installed policy pair")
        if (self.namespace, self.authority_namespace, self.installation_id, self.package_manifest_sha256,
                self.use_policy_ref, self.use_policy_digest, self.maintenance_policy_ref,
                self.maintenance_policy_digest, self.consumer_cohort_digest, self.policy_pair_digest) != (
                installation.namespace, installation.authority_namespace, installation.installation_id,
                installation.manifest_digest, use.policy_ref, use.digest, maintenance.link_ref,
                maintenance.digest, use.consumer_cohort_digest, use.policy_pair_digest):
            raise ValueError("D13 cache assets differ from actual package and policy originals")


__all__ = ("InstalledD13CacheUseAssetsV2", "d13_cache_interval_v2",
           "require_d13_cache_policy_installation_v2", "d13_cache_policy_pair_from_payload_v2",
           "AdminD13PrecompressionPolicyV1",
           "AdminD13PaidPrecompressionPolicyV1", "D13ScheduleRecoveryItemV2")
