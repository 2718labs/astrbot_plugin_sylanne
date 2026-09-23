"""Typed persistent-memory values and graph type registration."""

from dataclasses import dataclass
import math
from typing import Self

from .contracts import json_object, nonempty
from .graph_types import AtomKey, Owner, TypeRegistry, TypeSpec
from .runtime_contracts import schema_hash


_SOURCE_KINDS = frozenset({"observed", "reported", "authored", "internal", "simulated"})
_ASSERTION_STATUSES = frozenset({"confirmed", "reported", "disputed", "unknown"})
_INTERPRETATION_STATUSES = _ASSERTION_STATUSES | {"retracted"}
_INDEPENDENCE_VALUES = frozenset({"same_root", "independent", "unknown"})
_PURPOSES = frozenset({"context", "expression", "consolidation", "audit"})
_ACCESS_STATUSES = frozenset({"active", "withdrawn"})
_MAX_TEXT_LENGTH = 65_536

_SOURCE_FIELDS = frozenset({
    "source_id",
    "text",
    "speaker_id",
    "source_kind",
    "assertion_status",
    "occurred_at",
    "recorded_at",
    "provenance_root",
    "audiences",
    "purposes",
    "parent_source_ids",
    "independence",
})
_INTERPRETATION_FIELDS = frozenset({
    "interpretation_id",
    "source_ids",
    "subject_id",
    "claim",
    "status",
    "valid_from",
    "recorded_at",
    "valid_to",
})
_ACCESS_FIELDS = frozenset({"source_id", "audiences", "purposes", "status", "recorded_at"})

_SOURCE_SCHEMA_HASH = schema_hash({
    "type": "memory.source",
    "version": 1,
    "fields": sorted(_SOURCE_FIELDS),
    "immutable": True,
})
_ACCESS_SCHEMA_HASH = schema_hash({
    "type": "memory.access",
    "version": 1,
    "fields": sorted(_ACCESS_FIELDS),
    "immutable": False,
})
_INTERPRETATION_SCHEMA_HASH = schema_hash({
    "type": "memory.interpretation",
    "version": 1,
    "fields": sorted(_INTERPRETATION_FIELDS),
    "immutable": False,
})


def _enum(value: object, allowed: frozenset[str], label: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"unknown {label}: {value!r}")


def _time(value: object, label: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be a finite nonnegative real number")


def _text(value: object, label: str, *, bounded: bool = False) -> None:
    nonempty(value, label)
    if bounded and len(value) > _MAX_TEXT_LENGTH:
        raise ValueError(f"{label} must contain at most {_MAX_TEXT_LENGTH} characters")


def _string_tuple(
    value: object,
    label: str,
    *,
    require_one: bool = False,
    allowed: frozenset[str] | None = None,
    reject_wildcard: bool = False,
) -> None:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be a tuple")
    if require_one and not value:
        raise ValueError(f"{label} must not be empty")
    for item in value:
        nonempty(item, f"{label} item")
        if allowed is not None and item not in allowed:
            raise ValueError(f"unknown {label} item: {item!r}")
        if reject_wildcard and item == "*":
            raise ValueError(f"{label} must not contain a wildcard")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must contain unique strings")


def _exact_object(value: object, fields: frozenset[str], label: str) -> dict:
    detached = json_object(value)
    actual = frozenset(detached)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        details = []
        if missing:
            details.append(f"missing={missing!r}")
        if extra:
            details.append(f"extra={extra!r}")
        raise ValueError(f"{label} fields must match exactly ({', '.join(details)})")
    return detached


def _tuple_from_json(value: object, label: str) -> tuple:
    if type(value) is not list:
        raise TypeError(f"{label} must be a JSON array")
    return tuple(value)


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    text: str
    speaker_id: str
    source_kind: str
    assertion_status: str
    occurred_at: float | None
    recorded_at: float
    provenance_root: str
    audiences: tuple[str, ...]
    purposes: tuple[str, ...]
    parent_source_ids: tuple[str, ...] = ()
    independence: str = "unknown"

    def __post_init__(self) -> None:
        _text(self.source_id, "source_id")
        _text(self.text, "text", bounded=True)
        _text(self.speaker_id, "speaker_id")
        _enum(self.source_kind, _SOURCE_KINDS, "source_kind")
        _enum(self.assertion_status, _ASSERTION_STATUSES, "assertion_status")
        _time(self.occurred_at, "occurred_at", optional=True)
        _time(self.recorded_at, "recorded_at")
        _text(self.provenance_root, "provenance_root")
        _string_tuple(self.audiences, "audiences", reject_wildcard=True)
        _string_tuple(self.purposes, "purposes", allowed=_PURPOSES)
        _string_tuple(self.parent_source_ids, "parent_source_ids")
        _enum(self.independence, _INDEPENDENCE_VALUES, "independence")

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "text": self.text,
            "speaker_id": self.speaker_id,
            "source_kind": self.source_kind,
            "assertion_status": self.assertion_status,
            "occurred_at": self.occurred_at,
            "recorded_at": self.recorded_at,
            "provenance_root": self.provenance_root,
            "audiences": list(self.audiences),
            "purposes": list(self.purposes),
            "parent_source_ids": list(self.parent_source_ids),
            "independence": self.independence,
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        data = _exact_object(value, _SOURCE_FIELDS, "source record")
        data["audiences"] = _tuple_from_json(data["audiences"], "audiences")
        data["purposes"] = _tuple_from_json(data["purposes"], "purposes")
        data["parent_source_ids"] = _tuple_from_json(
            data["parent_source_ids"], "parent_source_ids"
        )
        return cls(**data)


@dataclass(frozen=True)
class InterpretationRecord:
    interpretation_id: str
    source_ids: tuple[str, ...]
    subject_id: str
    claim: str
    status: str
    valid_from: float
    recorded_at: float
    valid_to: float | None = None

    def __post_init__(self) -> None:
        _text(self.interpretation_id, "interpretation_id")
        _string_tuple(self.source_ids, "source_ids", require_one=True)
        _text(self.subject_id, "subject_id")
        _text(self.claim, "claim", bounded=True)
        _enum(self.status, _INTERPRETATION_STATUSES, "interpretation status")
        _time(self.valid_from, "valid_from")
        _time(self.recorded_at, "recorded_at")
        _time(self.valid_to, "valid_to", optional=True)
        if self.valid_to is not None and self.valid_to < self.valid_from:
            raise ValueError("valid_to must be greater than or equal to valid_from")

    def to_dict(self) -> dict:
        return {
            "interpretation_id": self.interpretation_id,
            "source_ids": list(self.source_ids),
            "subject_id": self.subject_id,
            "claim": self.claim,
            "status": self.status,
            "valid_from": self.valid_from,
            "recorded_at": self.recorded_at,
            "valid_to": self.valid_to,
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        data = _exact_object(value, _INTERPRETATION_FIELDS, "interpretation record")
        data["source_ids"] = _tuple_from_json(data["source_ids"], "source_ids")
        return cls(**data)


def source_key(bot: str, persona: str, source_id: str) -> AtomKey:
    return AtomKey(Owner("event", bot, persona, source_id), "memory.source", "record")


def access_key(bot: str, persona: str, source_id: str) -> AtomKey:
    return AtomKey(Owner("event", bot, persona, source_id), "memory.access", "access")


def interpretation_key(bot: str, persona: str, iid: str) -> AtomKey:
    return AtomKey(Owner("event", bot, persona, iid), "memory.interpretation", "current")


def validate_access(value: object) -> None:
    data = _exact_object(value, _ACCESS_FIELDS, "memory access")
    _text(data["source_id"], "source_id")
    audiences = _tuple_from_json(data["audiences"], "audiences")
    purposes = _tuple_from_json(data["purposes"], "purposes")
    _string_tuple(audiences, "audiences", reject_wildcard=True)
    _string_tuple(purposes, "purposes", allowed=_PURPOSES)
    _enum(data["status"], _ACCESS_STATUSES, "access status")
    _time(data["recorded_at"], "recorded_at")


def _validate_source(value: object) -> None:
    SourceRecord.from_dict(value)


def _validate_interpretation(value: object) -> None:
    InterpretationRecord.from_dict(value)


def register_memory_types(registry: TypeRegistry) -> None:
    if not isinstance(registry, TypeRegistry):
        raise TypeError("registry must be TypeRegistry")
    registry.register(TypeSpec(
        "memory.source", ("event",), "source", _validate_source,
        immutable=True, writer_domain="d06", schema_hash=_SOURCE_SCHEMA_HASH,
    ))
    registry.register(TypeSpec(
        "memory.access", ("event",), "state", validate_access,
        writer_domain="d06", schema_hash=_ACCESS_SCHEMA_HASH,
    ))
    registry.register(TypeSpec(
        "memory.interpretation", ("event",), "state", _validate_interpretation,
        writer_domain="d06", schema_hash=_INTERPRETATION_SCHEMA_HASH,
    ))
