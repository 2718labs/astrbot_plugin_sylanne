"""Required host evidence for a future current group-audience graph head.

AstrBot's generic group metadata cannot attest an atomic, versioned member
set.  This type is an adapter contract, not a group snapshot or admission.
W09 must obtain the fields from a trusted platform read before W01 can store
or consume a ``group_audience_snapshot`` graph value.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...runtime_contracts import NamespaceId


@dataclass(frozen=True, slots=True)
class GroupAudienceHostReadV1:
    namespace: NamespaceId
    platform_ref: str
    conversation_ref: str
    scene_ref: str
    group_ref: str
    member_account_refs: tuple[str, ...]
    platform_member_count: int
    platform_membership_version: str
    observed_at_utc: float
    valid_until_utc: float
    completeness: str

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId:
            raise TypeError("namespace required")
        for name in ("platform_ref", "conversation_ref", "scene_ref",
                     "group_ref", "platform_membership_version"):
            value = getattr(self, name)
            if type(value) is not str or not value or len(value) > 512:
                raise ValueError(f"{name} required")
        if not self.scene_ref.startswith("scene:"):
            raise ValueError("scene_ref required")
        refs = self.member_account_refs
        if (type(refs) is not tuple or not refs
                or any(type(ref) is not str or not ref or len(ref) > 512
                       for ref in refs)
                or len(refs) != len(set(refs))):
            raise ValueError("complete distinct member account refs required")
        if (type(self.platform_member_count) is not int
                or self.platform_member_count != len(refs)):
            raise ValueError("independent platform member count must match")
        if self.completeness != "atomic_complete":
            raise ValueError("platform must attest an atomic complete list")
        if (type(self.observed_at_utc) not in (int, float)
                or type(self.valid_until_utc) not in (int, float)
                or not math.isfinite(self.observed_at_utc)
                or not math.isfinite(self.valid_until_utc)
                or self.observed_at_utc <= 0
                or self.valid_until_utc <= self.observed_at_utc):
            raise ValueError("bounded observation interval required")


__all__ = ["GroupAudienceHostReadV1"]
