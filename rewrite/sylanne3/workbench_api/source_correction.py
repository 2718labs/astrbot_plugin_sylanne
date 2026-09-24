"""D12's typed boundary for an Owner-submitted source correction.

These values are transport and receipt contracts. Constructing either value
does not grant permission or commit a domain mutation; W01 must verify and
persist the operation before it can return a receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from uuid import UUID

from ..runtime_contracts import NamespaceId


REQUEST_SCHEMA = "d12.source_correction.v1"
RECEIPT_SCHEMA = "d12.source_correction_receipt.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _refs(value: tuple[str, ...], name: str) -> None:
    if (type(value) is not tuple or not 1 <= len(value) <= 100
            or any(type(ref) is not str or not 1 <= len(ref) <= 4096
                   or not ref.strip() for ref in value)
            or len(set(value)) != len(value)):
        raise ValueError(f"{name} requires unique bounded references")


@dataclass(frozen=True, slots=True)
class SourceCorrectionRequestV1:
    namespace: NamespaceId
    operation_id: str
    request_digest: str
    statement: str
    source_refs: tuple[str, ...]
    target_refs: tuple[str, ...]
    access_epoch: int
    deletion_epoch: int
    impact_preview_ref: str | None = None
    schema: str = REQUEST_SCHEMA

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or self.schema != REQUEST_SCHEMA:
            raise ValueError("source correction requires a namespace and current schema")
        try:
            UUID(self.operation_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("source correction requires a UUID operation") from exc
        if type(self.request_digest) is not str or _DIGEST.fullmatch(self.request_digest) is None:
            raise ValueError("source correction requires a request digest")
        if type(self.statement) is not str or not 1 <= len(self.statement.strip()) <= 4096:
            raise ValueError("source correction requires a bounded statement")
        _refs(self.source_refs, "source_refs")
        _refs(self.target_refs, "target_refs")
        for name in ("access_epoch", "deletion_epoch"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative exact integer")
        if self.impact_preview_ref is not None and (
                type(self.impact_preview_ref) is not str
                or not 1 <= len(self.impact_preview_ref) <= 4096):
            raise ValueError("impact_preview_ref must be a bounded reference")


@dataclass(frozen=True, slots=True)
class SourceCorrectionCommitReceiptV1:
    """A W01-issued durable commit witness, never a D12 preview result."""

    namespace: NamespaceId
    operation_id: str
    request_digest: str
    correction_source_ref: str
    source_refs: tuple[str, ...]
    invalidated_target_refs: tuple[str, ...]
    reevaluation_outbox_ref: str
    audit_event_ref: str
    graph_revision: int
    access_epoch: int
    deletion_epoch: int
    phase: str = "source_correction_committed"
    schema: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or self.schema != RECEIPT_SCHEMA:
            raise ValueError("correction receipt requires a namespace and current schema")
        try:
            UUID(self.operation_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("correction receipt requires a UUID operation") from exc
        if (type(self.request_digest) is not str or _DIGEST.fullmatch(self.request_digest) is None
                or self.phase != "source_correction_committed"):
            raise ValueError("correction receipt requires a committed request digest")
        for name in ("correction_source_ref", "reevaluation_outbox_ref", "audit_event_ref"):
            value = getattr(self, name)
            if type(value) is not str or not value:
                raise ValueError(f"{name} is required")
        _refs(self.source_refs, "source_refs")
        _refs(self.invalidated_target_refs, "invalidated_target_refs")
        for name in ("graph_revision", "access_epoch", "deletion_epoch"):
            value = getattr(self, name)
            if type(value) is not int or value < (1 if name == "graph_revision" else 0):
                raise ValueError(f"{name} must be an exact committed version")


__all__ = ("SourceCorrectionRequestV1", "SourceCorrectionCommitReceiptV1")
