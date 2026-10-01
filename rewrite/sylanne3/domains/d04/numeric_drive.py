"""Durable, source-pinned D04 drive candidate for one numeric checkpoint interval.

The graph row records a compiled drive's claimed provenance. W01 must still
verify the semantic mapping issuer and D06 current source/access heads before
adoption; this type alone cannot certify a numeric solve.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math

from ...graph_types import AtomKey, GraphWrite, Owner, TypeSpec
from ...memory_types import access_key
from ...runtime_contracts import canonical_digest, schema_hash
from .numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION


TYPE_NAME = "d04.sourced_numeric_drive.v1"


@dataclass(frozen=True, slots=True)
class SourcedNumericDrive:
    drive_id: str
    drive_version: int
    checkpoint_ref: str
    checkpoint_revision: int
    source_ref: str
    source_revision: int
    access_ref: str
    access_revision: int
    mapping_version: str
    mapping_compiler_ref: str
    scheme_version: str
    role_start: float
    role_end: float
    axis_ids: tuple[str, ...]
    drive: tuple[float, ...]
    schema: str = TYPE_NAME

    def __post_init__(self) -> None:
        if self.schema != TYPE_NAME or self.scheme_version != SCHEME_VERSION:
            raise ValueError("numeric drive scheme or schema differs")
        checkpoint = AtomKey.from_token(self.checkpoint_ref)
        source = AtomKey.from_token(self.source_ref)
        access = AtomKey.from_token(self.access_ref)
        if (checkpoint.type_name not in {
                "d04.numeric_checkpoint.v1", "d04.numeric_checkpoint.v2"}
                or checkpoint.owner.kind != "persona"
                or source.type_name != "memory.source" or source.name != "record"
                or source.owner.kind != "event"
                or access != access_key(source.owner.bot, source.owner.persona,
                                        source.owner.subject)
                or any((key.owner.bot, key.owner.persona) != (
                    checkpoint.owner.bot, checkpoint.owner.persona)
                       for key in (source, access))):
            raise ValueError("numeric drive dependencies cross namespace or type")
        for name in ("drive_version", "checkpoint_revision", "source_revision",
                     "access_revision"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive graph revision")
        if self.drive_version != 1:
            raise ValueError("sourced drive is immutable at revision one")
        if (type(self.mapping_version) is not str or not self.mapping_version
                or type(self.mapping_compiler_ref) is not str or not self.mapping_compiler_ref):
            raise ValueError("numeric drive needs mapping provenance")
        if (type(self.role_start) not in (int, float)
                or type(self.role_end) not in (int, float)
                or not math.isfinite(self.role_start)
                or not math.isfinite(self.role_end)
                or self.role_end <= self.role_start):
            raise ValueError("numeric drive interval must increase")
        if tuple(self.axis_ids) != REGISTERED_AXIS_IDS:
            raise ValueError("numeric drive requires the ordered 24 axes")
        if (type(self.drive) is not tuple or len(self.drive) != 24
                or any(type(value) not in (int, float) or not math.isfinite(value)
                       for value in self.drive)):
            raise ValueError("numeric drive requires 24 finite coordinates")
        if self.drive_id != numeric_drive_id(self.checkpoint_ref, self.source_ref,
                                             self.role_start, self.role_end):
            raise ValueError("numeric drive identity differs from its source and interval")


def numeric_drive_id(checkpoint_ref: str, source_ref: str,
                     role_start: float, role_end: float) -> str:
    return "drive:" + canonical_digest({
        "schema": TYPE_NAME, "checkpoint": checkpoint_ref, "source": source_ref,
        "interval": (role_start, role_end),
    })


def decode_sourced_numeric_drive(value: object) -> SourcedNumericDrive:
    if type(value) is not dict or set(value) != set(SourcedNumericDrive.__dataclass_fields__):
        raise ValueError("numeric drive fields differ from v1 schema")
    return SourcedNumericDrive(**{
        **value, "axis_ids": tuple(value["axis_ids"]), "drive": tuple(value["drive"]),
    })


def sourced_numeric_drive_type_spec() -> TypeSpec:
    return TypeSpec(
        TYPE_NAME, ("persona",), "state", decode_sourced_numeric_drive,
        immutable=True, writer_domain="d04", schema_hash=schema_hash({
            "type": TYPE_NAME, "fields": tuple(SourcedNumericDrive.__dataclass_fields__),
            "scheme": SCHEME_VERSION, "status": "source_pinned_candidate_only",
        }),
    )


def sourced_numeric_drive_write(drive: SourcedNumericDrive) -> GraphWrite:
    if type(drive) is not SourcedNumericDrive:
        raise TypeError("numeric drive write requires SourcedNumericDrive")
    checkpoint = AtomKey.from_token(drive.checkpoint_ref)
    value = asdict(drive)
    value["axis_ids"] = list(drive.axis_ids)
    value["drive"] = list(drive.drive)
    return GraphWrite(
        AtomKey(Owner("persona", checkpoint.owner.bot, checkpoint.owner.persona),
                TYPE_NAME, drive.drive_id), value,
        # An immutable historical candidate cannot have invalidating Graph
        # dependencies. The installed adopter retains historical_provenance
        # edges in its commit transaction and requalifies current D06 rights.
        (),
    )
