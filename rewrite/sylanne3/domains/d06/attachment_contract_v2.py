"""Uncommitted D06 attachment admission values for a future atomic source v2.

These values carry verified bytes. They grant no graph write or read authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from . import SourceAdmission


MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024
MAX_ATTACHMENTS = 4
SOURCE_ATTACHMENT_SCHEMA_V2 = "d06.source-attachment.v2"


@dataclass(frozen=True)
class SourceAttachmentV2:
    order: int
    media_kind: str
    mime_type: str
    content: bytes
    sha256: str

    def __post_init__(self) -> None:
        if type(self.order) is not int or not 0 <= self.order < MAX_ATTACHMENTS:
            raise ValueError("attachment order is out of range")
        if self.media_kind not in {"image", "audio", "video", "file"}:
            raise ValueError("unsupported attachment kind")
        if (type(self.mime_type) is not str or not self.mime_type
                or len(self.mime_type) > 127 or "/" not in self.mime_type):
            raise ValueError("attachment MIME type is invalid")
        if type(self.content) is not bytes or not 0 < len(self.content) <= MAX_ATTACHMENT_BYTES:
            raise ValueError("attachment bytes are absent or exceed the limit")
        if self.sha256 != hashlib.sha256(self.content).hexdigest():
            raise ValueError("attachment digest does not match bytes")


@dataclass(frozen=True)
class SourceAdmissionV2:
    source: SourceAdmission
    attachments: tuple[SourceAttachmentV2, ...]
    schema: str = SOURCE_ATTACHMENT_SCHEMA_V2

    def __post_init__(self) -> None:
        if type(self.source) is not SourceAdmission or self.schema != SOURCE_ATTACHMENT_SCHEMA_V2:
            raise TypeError("versioned D06 source admission is required")
        if (type(self.attachments) is not tuple or not 1 <= len(self.attachments) <= MAX_ATTACHMENTS
                or any(type(item) is not SourceAttachmentV2 for item in self.attachments)):
            raise ValueError("versioned source requires bounded verified attachments")
        if tuple(item.order for item in self.attachments) != tuple(range(len(self.attachments))):
            raise ValueError("attachment order must be contiguous")

    @property
    def content_fingerprint(self) -> str:
        """Bind source identity and text to the exact ordered attachment bytes."""
        payload = {
            "schema": self.schema,
            "source_id": self.source.source_id,
            "text": self.source.text,
            "attachments": [
                (item.order, item.media_kind, item.mime_type, len(item.content), item.sha256)
                for item in self.attachments
            ],
        }
        return hashlib.sha256(json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
