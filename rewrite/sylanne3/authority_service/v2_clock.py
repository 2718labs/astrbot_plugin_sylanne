"""Versioned Authority ingress clock observation, without physical UTC attestation."""

from __future__ import annotations

from dataclasses import dataclass
import math


CLOCK_SCHEMA = "sylanne3.authority.ingress-clock.v2"


def _seconds(value: object, name: str, *, positive: bool = False) -> None:
    if (type(value) not in {int, float} or not math.isfinite(value)
            or value < 0 or positive and value == 0):
        raise ValueError(f"invalid {name}")


def _name(value: object, name: str) -> None:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True)
class AuthorityClockReadingV2:
    """One atomic observation returned by an administrator-managed provider."""

    source_id: str
    utc_seconds: float
    monotonic_seconds: float
    epoch: str
    healthy: bool
    utc_error_seconds: float

    def __post_init__(self) -> None:
        _name(self.source_id, "clock source")
        _seconds(self.utc_seconds, "UTC seconds", positive=True)
        _seconds(self.monotonic_seconds, "monotonic seconds")
        _name(self.epoch, "clock epoch")
        if type(self.healthy) is not bool:
            raise ValueError("invalid clock health")
        _seconds(self.utc_error_seconds, "UTC error bound")


@dataclass(frozen=True, slots=True)
class IngressClockSampleV2:
    """Clock data bound by the RPC envelope to a paired mTLS installation."""

    authority_id: str
    installation_id: str
    source_id: str
    utc_seconds: float
    monotonic_seconds: float
    epoch: str
    utc_error_seconds: float
    schema: str = CLOCK_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CLOCK_SCHEMA or type(self.schema) is not str:
            raise ValueError("unknown clock schema")
        _name(self.authority_id, "authority identity")
        _name(self.installation_id, "installation identity")
        _name(self.source_id, "clock source")
        _seconds(self.utc_seconds, "UTC seconds", positive=True)
        _seconds(self.monotonic_seconds, "monotonic seconds")
        _name(self.epoch, "clock epoch")
        _seconds(self.utc_error_seconds, "UTC error bound")
