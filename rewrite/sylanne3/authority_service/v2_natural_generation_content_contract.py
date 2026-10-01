"""Identity-only request and scoped Authority content for natural review.

The original output selector has a separate read-attempt domain and never
releases text. This contract alone grants neither review nor final sending.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import math
import re

from ..graph_types import AtomKey, GraphVersion, Owner
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contract import identifier


SCHEMA = "sylanne3.authority.natural-generation-content-read.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def natural_generation_current_scope_digest_v2(
    *, original_seal_digest: str, scoped_proof_digest: str,
    adopted_plan_digest: str, read_versions: tuple[GraphVersion, ...],
    graph_epoch: int, access_epoch: int, delete_epoch: int,
    scene_id: str, audience_id: str,
) -> str:
    """Canonical identity for one current private review projection."""
    for value in (original_seal_digest, scoped_proof_digest,
                  adopted_plan_digest):
        if type(value) is not str or not _DIGEST.fullmatch(value):
            raise ValueError("natural review scope digest input differs")
    if (type(read_versions) is not tuple
            or any(type(item) is not GraphVersion for item in read_versions)
            or tuple(sorted(read_versions, key=lambda item: item.key.token))
               != read_versions
            or len({item.key.token for item in read_versions})
               != len(read_versions)
            or any(type(value) is not int or value < 0 for value in (
                graph_epoch, access_epoch, delete_epoch))
            or type(scene_id) is not str or not scene_id
            or type(audience_id) is not str or not audience_id):
        raise ValueError("natural review current scope incomplete")
    return canonical_digest({
        "original_seal_digest": original_seal_digest,
        "scoped_proof_digest": scoped_proof_digest,
        "adopted_plan_digest": adopted_plan_digest,
        "read_versions": [(item.key.token, item.revision)
                          for item in read_versions],
        "graph_epoch": graph_epoch, "access_epoch": access_epoch,
        "delete_epoch": delete_epoch,
        "scene_id": scene_id, "audience_id": audience_id,
    })


def natural_generation_content_attempt_id_v2(
    original_operation_id: str, attempt: int,
) -> str:
    identifier(original_operation_id, "original_operation_id")
    if type(attempt) is not int or not 1 <= attempt <= 64:
        raise ValueError("natural content read attempt out of range")
    return "natural-generation-content-read-" + canonical_digest({
        "schema": SCHEMA,
        "original_operation_id": original_operation_id,
        "attempt": attempt,
    })[:48]


@dataclass(frozen=True, slots=True)
class NaturalGenerationContentReadRequestV2:
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
    original_seal_digest: str
    terminal_receipt_digest: str
    output_digest: str
    scene_id: str
    audience_id: str
    purpose: str
    read_attempt_id: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA or type(self.namespace) is not NamespaceId
                or self.purpose != "review"):
            raise ValueError("unknown natural content review workflow")
        for name in (
            "authority_id", "authority_namespace", "c02_operation_id",
            "installation_id", "job_id", "original_operation_id",
            "acquire_operation_id", "call_id", "read_attempt_id",
        ):
            identifier(getattr(self, name), name)
        if (type(self.scene_id) is not str or not self.scene_id
                or type(self.audience_id) is not str or not self.audience_id):
            raise ValueError("natural content scene and audience required")
        source = AtomKey.from_token(self.source_ref)
        if (source.type_name != "memory.source" or source.owner.kind != "event"
                or (source.owner.bot, source.owner.persona)
                   != self.namespace.as_tuple):
            raise ValueError("natural content source crosses namespace")
        for name in (
            "typed_model_request_digest", "original_seal_digest",
            "terminal_receipt_digest", "output_digest",
        ):
            value = getattr(self, name)
            if type(value) is not str or not _DIGEST.fullmatch(value):
                raise ValueError(f"invalid {name}")
        if self.read_attempt_id not in {
            natural_generation_content_attempt_id_v2(
                self.original_operation_id, attempt) for attempt in range(1, 65)
        }:
            raise ValueError("natural content read attempt differs")


@dataclass(frozen=True, slots=True)
class NaturalGenerationCurrentContentV2:
    """Paid original text after a fresh graph/Authority read, for review only."""

    request: NaturalGenerationContentReadRequestV2
    text: str
    observation_digest: str
    output_digest: str
    current_scope_digest: str
    current_read_versions: tuple[GraphVersion, ...]
    current_graph_epoch: int
    current_access_epoch: int
    current_delete_epoch: int
    expires_at_utc: float
    status: str = "content_current_review_only"
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA or self.status != "content_current_review_only"
                or type(self.request) is not NaturalGenerationContentReadRequestV2
                or type(self.text) is not str or not self.text
                or self.output_digest != self.request.output_digest
                or type(self.current_read_versions) is not tuple
                or not self.current_read_versions
                or any(type(item) is not GraphVersion
                       for item in self.current_read_versions)
                or len({item.key.token for item in self.current_read_versions})
                   != len(self.current_read_versions)
                or tuple(sorted(self.current_read_versions,
                                key=lambda item: item.key.token))
                   != self.current_read_versions
                or any(type(value) is not int or value < 0 for value in (
                    self.current_graph_epoch, self.current_access_epoch,
                    self.current_delete_epoch))
                or type(self.expires_at_utc) not in (int, float)
                or not math.isfinite(self.expires_at_utc)):
            raise ValueError("natural current review content differs")
        for name in ("observation_digest", "output_digest", "current_scope_digest"):
            value = getattr(self, name)
            if type(value) is not str or not _DIGEST.fullmatch(value):
                raise ValueError(f"invalid {name}")


def to_wire(value: NaturalGenerationContentReadRequestV2 |
            NaturalGenerationCurrentContentV2) -> dict:
    if type(value) not in {
            NaturalGenerationContentReadRequestV2,
            NaturalGenerationCurrentContentV2}:
        raise TypeError("typed natural content read wire required")
    return json.loads(canonical_serialize(asdict(value)))


def from_wire(raw: object, kind: type):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("natural content read wire fields differ")
    data = dict(raw)
    if kind is NaturalGenerationContentReadRequestV2:
        namespace = data["namespace"]
        if (type(namespace) is not dict or
                set(namespace) != {field.name for field in fields(NamespaceId)}):
            raise ValueError("natural content read namespace differs")
        data["namespace"] = NamespaceId(**namespace)
        value = kind(**data)
    elif kind is NaturalGenerationCurrentContentV2:
        data["request"] = from_wire(data["request"],
                                    NaturalGenerationContentReadRequestV2)
        rows = data["current_read_versions"]
        if type(rows) is not list:
            raise ValueError("natural content graph versions differ")
        if any(type(row) is not dict or set(row) != {"key", "revision"}
               or type(row["key"]) is not dict
               or set(row["key"]) != {"owner", "type_name", "name"}
               or type(row["key"]["owner"]) is not dict
               or set(row["key"]["owner"]) != {
                   "kind", "bot", "persona", "subject"} for row in rows):
            raise ValueError("natural content graph version fields differ")
        data["current_read_versions"] = tuple(
            GraphVersion(AtomKey(Owner(**row["key"]["owner"]),
                                 row["key"]["type_name"],
                                 row["key"]["name"]), row["revision"])
            for row in rows)
        value = kind(**data)
    else:
        raise ValueError("unsupported natural content read wire type")
    if to_wire(value) != raw:
        raise ValueError("noncanonical natural content read wire")
    return value


__all__ = (
    "SCHEMA", "NaturalGenerationContentReadRequestV2",
    "NaturalGenerationCurrentContentV2",
    "natural_generation_current_scope_digest_v2",
    "natural_generation_content_attempt_id_v2", "from_wire", "to_wire",
)
