"""Administrator-installed limits for D04 semantic-to-numeric mapping.

This policy bounds caller supplied shares. It does not establish current graph
state, authorize adoption by itself, or replace D11's budget and transaction
records.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from types import MappingProxyType
from typing import Mapping

from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from ..native_runtime.d04_semantic_drive_candidate import MAPPING_VERSION, MECHANISMS
from ..runtime_contracts import NamespaceId


POLICY_VERSION = "d04.semantic-drive-dose-policy.v1"
WORK_KIND = "d04.semantic_drive.adopt"
BASIS_VERSION = SCHEME_VERSION
LAYER_NAMES = ("fast", "residual", "slow")
EXPECTED_AXES = REGISTERED_AXIS_IDS


@dataclass(frozen=True, slots=True)
class AdminD04SemanticDrivePolicyV1:
    namespace: NamespaceId
    installation_id: str
    grant_id: str
    grant_version: int
    lease_id: str
    mapping_version: str
    basis_version: str
    mechanism_max_abs_doses: Mapping[str, tuple[float, float, float]]
    mechanism_max_family_share: Mapping[str, float]
    version: int = 1

    @property
    def policy_version(self) -> str:
        return POLICY_VERSION

    @property
    def axes(self) -> tuple[str, ...]:
        return EXPECTED_AXES

    @property
    def work_kind(self) -> str:
        return WORK_KIND

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId:
            raise TypeError("D04 semantic policy needs a typed namespace")
        for field in ("installation_id", "grant_id", "lease_id"):
            value = getattr(self, field)
            if type(value) is not str or not value:
                raise ValueError(f"D04 semantic policy {field} is required")
        if type(self.grant_version) is not int or self.grant_version < 1:
            raise ValueError("D04 semantic policy grant version is invalid")
        if (type(self.version) is not int or self.version != 1
                or self.mapping_version != MAPPING_VERSION
                or self.basis_version != BASIS_VERSION
                or len(EXPECTED_AXES) != 24):
            raise ValueError("D04 semantic policy version, mapping or 24D basis differs")

        expected = set(MECHANISMS)
        doses = self.mechanism_max_abs_doses
        shares = self.mechanism_max_family_share
        if (not isinstance(doses, Mapping) or set(doses) != expected
                or not isinstance(shares, Mapping) or set(shares) != expected):
            raise ValueError("D04 semantic policy must define every registered mechanism")
        normalized_doses: dict[str, tuple[float, float, float]] = {}
        normalized_shares: dict[str, float] = {}
        for mechanism in MECHANISMS:
            limits = doses[mechanism]
            if type(limits) is not tuple or len(limits) != 3:
                raise ValueError("D04 semantic policy needs three layer dose limits")
            values = tuple(float(value) for value in limits)
            if any(type(value) not in (int, float) or not math.isfinite(value)
                   or not 0.0 <= value <= 1.0 for value in limits):
                raise ValueError("D04 semantic policy dose limits must be in [0,1]")
            share = shares[mechanism]
            if (type(share) not in (int, float) or not math.isfinite(share)
                    or not 0.0 <= share <= 1.0):
                raise ValueError("D04 semantic policy family share must be in [0,1]")
            normalized_doses[mechanism] = values
            normalized_shares[mechanism] = float(share)
        object.__setattr__(self, "mechanism_max_abs_doses",
                           MappingProxyType(normalized_doses))
        object.__setattr__(self, "mechanism_max_family_share",
                           MappingProxyType(normalized_shares))

    def validate_share(self, mechanism: str, layer_doses: tuple[float, float, float],
                       family_share: float) -> None:
        """Reject shares that exceed the installed mechanism-specific bounds."""
        if mechanism not in self.mechanism_max_abs_doses:
            raise ValueError("D04 semantic mechanism is not installed")
        if type(layer_doses) is not tuple or len(layer_doses) != 3:
            raise ValueError("D04 semantic share needs three layer doses")
        limits = self.mechanism_max_abs_doses[mechanism]
        if any(type(value) not in (int, float) or not math.isfinite(value)
               or abs(value) > bound
               for value, bound in zip(layer_doses, limits)):
            raise ValueError("D04 semantic share exceeds installed layer dose")
        if (type(family_share) not in (int, float) or not math.isfinite(family_share)
                or not 0.0 <= family_share <= self.mechanism_max_family_share[mechanism]):
            raise ValueError("D04 semantic share exceeds installed family share")


__all__ = (
    "AdminD04SemanticDrivePolicyV1", "BASIS_VERSION", "EXPECTED_AXES",
    "LAYER_NAMES", "MAPPING_VERSION", "MECHANISMS", "POLICY_VERSION",
    "WORK_KIND",
)
