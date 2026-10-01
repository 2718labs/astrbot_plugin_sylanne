"""Versioned W10 request DTO for one source-scoped C09 pending operation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


SCOPED_ERASURE_REQUEST_SCHEMA_V2 = "d12.scoped_erasure_request.v2"


@dataclass(frozen=True, slots=True)
class D12ScopedErasureRequestV2:
    source_id: str
    schema: str = SCOPED_ERASURE_REQUEST_SCHEMA_V2

    def __post_init__(self) -> None:
        if (self.schema != SCOPED_ERASURE_REQUEST_SCHEMA_V2
                or type(self.source_id) is not str
                or not 1 <= len(self.source_id) <= 256
                or self.source_id != self.source_id.strip()):
            raise ValueError("invalid D12 scoped-erasure request")

    @classmethod
    def from_wire(cls, value: object) -> "D12ScopedErasureRequestV2":
        if (not isinstance(value, Mapping)
                or set(value) != {"schema", "source_id"}):
            raise ValueError("D12 scoped-erasure request fields differ")
        return cls(source_id=value["source_id"], schema=value["schema"])

    def to_wire(self) -> dict[str, str]:
        return {"schema": self.schema, "source_id": self.source_id}


__all__ = ["SCOPED_ERASURE_REQUEST_SCHEMA_V2", "D12ScopedErasureRequestV2"]
