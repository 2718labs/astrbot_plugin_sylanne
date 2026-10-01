"""Identity-only final read of two settled natural-language model calls."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import math
import re

from ..graph_types import AtomKey, GraphVersion
from ..model_broker.natural_review import UntrustedNaturalReplyReviewOutputV1
from ..runtime_contracts import (
    NaturalReplyPaidReviewReceiptV2, NamespaceId, canonical_digest,
    canonical_serialize,
)
from .contract import identifier
from .v2_natural_generation_content_contract import (
    NaturalGenerationContentReadRequestV2,
    from_wire as generation_content_from_wire,
)
from .v2_natural_review_output_contract import (
    NaturalReviewOutputReadRequestV2,
    from_wire as review_output_from_wire,
)


SCHEMA = "sylanne3.authority.natural-paid-review-current-read.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def natural_paid_review_current_scope_digest_v2(
    *, generation_scope_digest: str, review_seal_digest: str,
    review_terminal_receipt_digest: str,
    read_versions: tuple[GraphVersion, ...], graph_epoch: int,
    access_epoch: int, delete_epoch: int,
) -> str:
    for value in (generation_scope_digest, review_seal_digest,
                  review_terminal_receipt_digest):
        if type(value) is not str or not _DIGEST.fullmatch(value):
            raise ValueError("natural paid review scope identity differs")
    if (type(read_versions) is not tuple or not read_versions
            or tuple(sorted(read_versions, key=lambda item: item.key.token))
               != read_versions
            or len({item.key.token for item in read_versions}) != len(read_versions)
            or any(type(item) is not int or item < 0 for item in (
                graph_epoch, access_epoch, delete_epoch))):
        raise ValueError("natural paid review scope versions differ")
    return canonical_digest({
        "schema": SCHEMA, "generation_scope_digest": generation_scope_digest,
        "review_seal_digest": review_seal_digest,
        "review_terminal_receipt_digest": review_terminal_receipt_digest,
        "read_versions": [(item.key.token, item.revision)
                          for item in read_versions],
        "graph_epoch": graph_epoch, "access_epoch": access_epoch,
        "delete_epoch": delete_epoch,
    })


def natural_paid_review_attempt_id_v2(
    review_original_operation_id: str, attempt: int,
) -> str:
    identifier(review_original_operation_id, "review_original_operation_id")
    if type(attempt) is not int or not 1 <= attempt <= 64:
        raise ValueError("natural paid review read attempt out of range")
    return "natural-paid-review-current-read-" + canonical_digest({
        "schema": SCHEMA,
        "review_original_operation_id": review_original_operation_id,
        "attempt": attempt,
    })[:48]


@dataclass(frozen=True, slots=True)
class NaturalPaidReviewCurrentReadRequestV2:
    generation_content_request: NaturalGenerationContentReadRequestV2
    review_output_request: NaturalReviewOutputReadRequestV2
    review_original_seal_digest: str
    review_terminal_receipt_digest: str
    review_output_digest: str
    read_attempt_id: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        gen, review = self.generation_content_request, self.review_output_request
        if (self.schema != SCHEMA
                or type(gen) is not NaturalGenerationContentReadRequestV2
                or type(review) is not NaturalReviewOutputReadRequestV2
                or (gen.authority_id, gen.authority_namespace, gen.namespace,
                    gen.original_operation_id, gen.call_id, gen.output_digest)
                   != (review.authority_id, review.authority_namespace,
                       review.namespace, review.generation_original_operation_id,
                       review.generation_call_id,
                       review.generation_output_digest)
                or gen.purpose != "review"
                or self.read_attempt_id not in {
                    natural_paid_review_attempt_id_v2(
                        review.original_operation_id, attempt)
                    for attempt in range(1, 65)
                }):
            raise ValueError("natural paid review read identity differs")
        for name in (
            "review_original_seal_digest", "review_terminal_receipt_digest",
            "review_output_digest",
        ):
            value = getattr(self, name)
            if type(value) is not str or not _DIGEST.fullmatch(value):
                raise ValueError(f"invalid {name}")

    @property
    def namespace(self) -> NamespaceId:
        return self.generation_content_request.namespace


@dataclass(frozen=True, slots=True)
class NaturalPaidReviewCurrentReadV2:
    """Paid semantic evidence for a new W01 current final write fence."""

    request: NaturalPaidReviewCurrentReadRequestV2
    generation_output: dict
    parsed_review: UntrustedNaturalReplyReviewOutputV1
    paid_receipt: NaturalReplyPaidReviewReceiptV2
    current_read_versions: tuple[GraphVersion, ...]
    current_scope_digest: str
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    expires_at_utc: float
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        request = self.request
        if (self.schema != SCHEMA
                or type(request) is not NaturalPaidReviewCurrentReadRequestV2
                or type(self.generation_output) is not dict
                or type(self.parsed_review) is not
                   UntrustedNaturalReplyReviewOutputV1
                or type(self.paid_receipt) is not NaturalReplyPaidReviewReceiptV2
                or self.paid_receipt.namespace != request.namespace
                or self.paid_receipt.generation_output_digest !=
                   request.generation_content_request.output_digest
                or self.paid_receipt.review_output_digest !=
                   request.review_output_digest
                or self.paid_receipt.review_terminal_receipt_digest !=
                   request.review_terminal_receipt_digest
                or self.parsed_review.output_digest != request.review_output_digest
                or self.paid_receipt.verdict != self.parsed_review.verdict
                or type(self.current_read_versions) is not tuple
                or not self.current_read_versions
                or tuple(sorted(self.current_read_versions,
                                key=lambda item: item.key.token)) !=
                   self.current_read_versions
                or len({item.key.token for item in self.current_read_versions})
                   != len(self.current_read_versions)
                or canonical_digest(self.generation_output) !=
                   request.generation_content_request.output_digest
                or self.current_scope_digest !=
                   self.paid_receipt.current_graph_guard_digest):
            raise ValueError("natural paid review current evidence differs")
        if (type(self.current_scope_digest) is not str
                or not _DIGEST.fullmatch(self.current_scope_digest)
                or any(type(item) is not int or item < 0 for item in (
                    self.graph_epoch, self.access_epoch, self.delete_epoch))
                or type(self.expires_at_utc) not in (int, float)
                or not math.isfinite(self.expires_at_utc)):
            raise ValueError("natural paid review current barrier differs")


def to_wire(value: NaturalPaidReviewCurrentReadRequestV2 |
            NaturalPaidReviewCurrentReadV2) -> dict:
    if type(value) not in {
            NaturalPaidReviewCurrentReadRequestV2,
            NaturalPaidReviewCurrentReadV2}:
        raise TypeError("typed natural paid review wire required")
    return json.loads(canonical_serialize(asdict(value)))


def from_wire(raw: object, kind: type):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("natural paid review wire fields differ")
    data = dict(raw)
    if kind is NaturalPaidReviewCurrentReadRequestV2:
        data["generation_content_request"] = generation_content_from_wire(
            data["generation_content_request"],
            NaturalGenerationContentReadRequestV2)
        data["review_output_request"] = review_output_from_wire(
            data["review_output_request"], NaturalReviewOutputReadRequestV2)
        value = kind(**data)
    elif kind is NaturalPaidReviewCurrentReadV2:
        data["request"] = from_wire(
            data["request"], NaturalPaidReviewCurrentReadRequestV2)
        parsed = dict(data["parsed_review"])
        parsed["issues"] = tuple(tuple(item) for item in parsed["issues"])
        data["parsed_review"] = UntrustedNaturalReplyReviewOutputV1(**parsed)
        paid = dict(data["paid_receipt"])
        paid["namespace"] = NamespaceId(**paid["namespace"])
        data["paid_receipt"] = NaturalReplyPaidReviewReceiptV2(**paid)
        data["current_read_versions"] = tuple(
            GraphVersion(AtomKey.from_token(item["key"]), item["revision"])
            for item in data["current_read_versions"])
        value = kind(**data)
    else:
        raise ValueError("unsupported natural paid review wire type")
    if to_wire(value) != raw:
        raise ValueError("noncanonical natural paid review wire")
    return value


__all__ = (
    "SCHEMA", "NaturalPaidReviewCurrentReadRequestV2",
    "NaturalPaidReviewCurrentReadV2", "natural_paid_review_attempt_id_v2",
    "natural_paid_review_current_scope_digest_v2",
    "to_wire", "from_wire",
)
