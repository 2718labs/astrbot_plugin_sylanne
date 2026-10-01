"""Identity-only natural generation result read and original paid output shape.

The request grants no content access. A pinned Authority service must load the
original graph call and its own terminal observation before issuing a result.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import re

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contract import identifier


SCHEMA = "sylanne3.authority.natural-generation-output-read.v2"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def natural_generation_output_attempt_id_v2(
    original_operation_id: str, attempt: int,
) -> str:
    identifier(original_operation_id, "original_operation_id")
    if type(attempt) is not int or not 1 <= attempt <= 64:
        raise ValueError("natural generation result read attempt out of range")
    return "natural-generation-output-read-" + canonical_digest({
        "schema": SCHEMA,
        "original_operation_id": original_operation_id,
        "attempt": attempt,
    })[:48]


@dataclass(frozen=True, slots=True)
class NaturalGenerationOutputReadRequestV2:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    c02_operation_id: str
    source_ref: str
    installation_id: str
    job_id: str
    original_operation_id: str
    acquire_operation_id: str
    call_id: str
    typed_model_request_digest: str
    read_attempt_id: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or type(self.namespace) is not NamespaceId:
            raise ValueError("unknown natural generation result read workflow")
        for name in (
            "authority_id", "authority_namespace", "c02_operation_id",
            "installation_id", "job_id", "original_operation_id",
            "acquire_operation_id", "call_id", "read_attempt_id",
        ):
            identifier(getattr(self, name), name)
        source = AtomKey.from_token(self.source_ref)
        if (source.type_name != "memory.source" or source.owner.kind != "event"
                or (source.owner.bot, source.owner.persona)
                   != self.namespace.as_tuple):
            raise ValueError("natural generation source crosses namespace")
        if (type(self.typed_model_request_digest) is not str
                or not _SHA256.fullmatch(self.typed_model_request_digest)):
            raise ValueError("invalid acquired typed model request digest")
        if self.read_attempt_id not in {
            natural_generation_output_attempt_id_v2(
                self.original_operation_id, attempt) for attempt in range(1, 65)
        }:
            raise ValueError("unknown original natural generation read attempt")


@dataclass(frozen=True, slots=True)
class NaturalGenerationOriginalOutputV2:
    """Content-free original output digest; this grants no expression read."""

    request: NaturalGenerationOutputReadRequestV2
    original_seal_digest: str
    typed_model_request_digest: str
    original_intent_digest: str
    terminal_receipt_digest: str
    observation_digest: str
    output_digest: str
    status: str  # untrusted_content_candidate | no_reply_hold
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA
                or type(self.request) is not NaturalGenerationOutputReadRequestV2
                or self.typed_model_request_digest !=
                   self.request.typed_model_request_digest
                or self.status not in {
                    "untrusted_content_candidate", "no_reply_hold"}):
            raise ValueError("natural generation original output identity differs")
        for name in (
            "original_seal_digest", "typed_model_request_digest",
            "original_intent_digest", "terminal_receipt_digest",
            "observation_digest", "output_digest",
        ):
            value = getattr(self, name)
            if type(value) is not str or not _SHA256.fullmatch(value):
                raise ValueError(f"invalid {name}")


def to_wire(value: NaturalGenerationOutputReadRequestV2 |
            NaturalGenerationOriginalOutputV2) -> dict:
    if type(value) not in {
            NaturalGenerationOutputReadRequestV2,
            NaturalGenerationOriginalOutputV2}:
        raise TypeError("typed natural generation output wire required")
    return json.loads(canonical_serialize(asdict(value)))


def from_wire(raw: object, kind: type):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("natural generation output wire fields differ")
    data = dict(raw)
    if kind is NaturalGenerationOutputReadRequestV2:
        namespace = data["namespace"]
        if (type(namespace) is not dict or
                set(namespace) != {field.name for field in fields(NamespaceId)}):
            raise ValueError("natural generation output namespace differs")
        data["namespace"] = NamespaceId(**namespace)
        value = kind(**data)
    elif kind is NaturalGenerationOriginalOutputV2:
        data["request"] = from_wire(
            data["request"], NaturalGenerationOutputReadRequestV2)
        value = kind(**data)
    else:
        raise ValueError("unsupported natural generation output wire type")
    if to_wire(value) != raw:
        raise ValueError("noncanonical natural generation output wire")
    return value


__all__ = (
    "SCHEMA", "NaturalGenerationOutputReadRequestV2",
    "NaturalGenerationOriginalOutputV2",
    "natural_generation_output_attempt_id_v2",
    "from_wire", "to_wire",
)
