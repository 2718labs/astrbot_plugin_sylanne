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


__all__ = ("AdminD13PrecompressionPolicyV1",
           "AdminD13PaidPrecompressionPolicyV1", "D13ScheduleRecoveryItemV2")
