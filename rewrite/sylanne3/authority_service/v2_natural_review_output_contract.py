"""Identity-only read of one original paid natural-language review result."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import re

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contract import identifier


SCHEMA = "sylanne3.authority.natural-review-output-read.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def natural_review_output_attempt_id_v2(
    original_operation_id: str, attempt: int,
) -> str:
    identifier(original_operation_id, "original_operation_id")
    if type(attempt) is not int or not 1 <= attempt <= 64:
        raise ValueError("natural review result read attempt out of range")
    return "natural-review-output-read-" + canonical_digest({
        "schema": SCHEMA, "original_operation_id": original_operation_id,
        "attempt": attempt,
    })[:48]


@dataclass(frozen=True, slots=True)
class NaturalReviewOutputReadRequestV2:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    parent_original_id: str
    generation_original_operation_id: str
    generation_call_id: str
    generation_output_digest: str
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
            raise ValueError("unknown natural review result workflow")
        for name in (
            "authority_id", "authority_namespace", "parent_original_id",
            "generation_original_operation_id", "generation_call_id",
            "installation_id", "job_id", "original_operation_id",
            "acquire_operation_id", "call_id", "read_attempt_id",
        ):
            identifier(getattr(self, name), name)
        for name in ("generation_output_digest", "typed_model_request_digest"):
            if type(getattr(self, name)) is not str or not _DIGEST.fullmatch(
                    getattr(self, name)):
                raise ValueError(f"invalid {name}")
        if (self.generation_original_operation_id == self.original_operation_id
                or self.generation_call_id == self.call_id
                or self.read_attempt_id not in {
                    natural_review_output_attempt_id_v2(
                        self.original_operation_id, attempt)
                    for attempt in range(1, 65)
                }):
            raise ValueError("natural review original/read attempt differs")


@dataclass(frozen=True, slots=True)
class NaturalReviewOriginalOutputV2:
    """Content-free paid review digest; verdict does not authorize sending."""

    request: NaturalReviewOutputReadRequestV2
    original_seal_digest: str
    typed_model_request_digest: str
    original_intent_digest: str
    terminal_receipt_digest: str
    observation_digest: str
    output_digest: str
    verdict: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA
                or type(self.request) is not NaturalReviewOutputReadRequestV2
                or self.typed_model_request_digest !=
                   self.request.typed_model_request_digest
                or self.verdict not in {"pass", "rewrite", "hold"}):
            raise ValueError("natural review paid result identity differs")
        for name in (
            "original_seal_digest", "typed_model_request_digest",
            "original_intent_digest", "terminal_receipt_digest",
            "observation_digest", "output_digest",
        ):
            if type(getattr(self, name)) is not str or not _DIGEST.fullmatch(
                    getattr(self, name)):
                raise ValueError(f"invalid {name}")


def to_wire(value: NaturalReviewOutputReadRequestV2 |
            NaturalReviewOriginalOutputV2) -> dict:
    if type(value) not in {
            NaturalReviewOutputReadRequestV2, NaturalReviewOriginalOutputV2}:
        raise TypeError("typed natural review output wire required")
    return json.loads(canonical_serialize(asdict(value)))


def from_wire(raw: object, kind: type):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("natural review output wire fields differ")
    data = dict(raw)
    if kind is NaturalReviewOutputReadRequestV2:
        namespace = data["namespace"]
        if (type(namespace) is not dict or
                set(namespace) != {field.name for field in fields(NamespaceId)}):
            raise ValueError("natural review output namespace differs")
        data["namespace"] = NamespaceId(**namespace)
        value = kind(**data)
    elif kind is NaturalReviewOriginalOutputV2:
        data["request"] = from_wire(
            data["request"], NaturalReviewOutputReadRequestV2)
        value = kind(**data)
    else:
        raise ValueError("unsupported natural review output wire type")
    if to_wire(value) != raw:
        raise ValueError("noncanonical natural review output wire")
    return value


__all__ = (
    "SCHEMA", "NaturalReviewOutputReadRequestV2",
    "NaturalReviewOriginalOutputV2", "natural_review_output_attempt_id_v2",
    "to_wire", "from_wire",
)
