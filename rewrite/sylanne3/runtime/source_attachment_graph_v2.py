"""Graph companion and byte store for a captioned D06 source admission."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import sqlite3

from ..domains.d06.attachment_contract_v2 import SourceAdmissionV2
from ..graph_types import AtomKey, Owner, TypeSpec
from ..runtime_contracts import NamespaceId, schema_hash


SOURCE_MEDIA_TYPE_V2 = "memory.source.v2"
SOURCE_MEDIA_SCHEMA_V2 = "sylanne3.memory.source.v2"
_FIELDS = frozenset({
    "schema", "source_id", "source_ref", "content_fingerprint", "attachments",
})
_ATTACHMENT_FIELDS = frozenset({
    "order", "media_kind", "mime_type", "byte_length", "sha256",
})


@dataclass(frozen=True)
class CurrentSourceMediaV2:
    namespace: NamespaceId
    source_id: str
    value: dict
    contents: tuple[bytes, ...]
    read_versions: tuple
    graph_epoch: int
    access_epoch: int
    delete_epoch: int


def media_source_key(namespace: NamespaceId, source_id: str) -> AtomKey:
    return AtomKey(Owner("event", *namespace.as_tuple, source_id),
                   SOURCE_MEDIA_TYPE_V2, "record")


def media_source_value(admission: SourceAdmissionV2, source_ref: str) -> dict:
    return {
        "schema": SOURCE_MEDIA_SCHEMA_V2,
        "source_id": admission.source.source_id,
        "source_ref": source_ref,
        "content_fingerprint": admission.content_fingerprint,
        "attachments": [
            {"order": item.order, "media_kind": item.media_kind,
             "mime_type": item.mime_type, "byte_length": len(item.content),
             "sha256": item.sha256}
            for item in admission.attachments
        ],
    }


def media_content_fingerprint(source_id: str, text: str, value: dict) -> str:
    validate_media_source_value(value)
    payload = {
        "schema": "d06.source-attachment.v2", "source_id": source_id,
        "text": text,
        "attachments": [
            (row["order"], row["media_kind"], row["mime_type"],
             row["byte_length"], row["sha256"])
            for row in value["attachments"]
        ],
    }
    return hashlib.sha256(json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def validate_media_source_value(value: dict) -> None:
    if type(value) is not dict or set(value) != _FIELDS:
        raise ValueError("media source fields differ")
    if (value["schema"] != SOURCE_MEDIA_SCHEMA_V2
            or type(value["source_id"]) is not str or not value["source_id"]
            or type(value["source_ref"]) is not str or not value["source_ref"]
            or type(value["content_fingerprint"]) is not str
            or len(value["content_fingerprint"]) != 64
            or any(ch not in "0123456789abcdef"
                   for ch in value["content_fingerprint"])):
        raise ValueError("media source identity differs")
    rows = value["attachments"]
    if type(rows) is not list or not 1 <= len(rows) <= 4:
        raise ValueError("media source requires bounded attachments")
    for order, row in enumerate(rows):
        if (type(row) is not dict or set(row) != _ATTACHMENT_FIELDS
                or row["order"] != order
                or row["media_kind"] not in {"image", "audio", "video", "file"}
                or type(row["mime_type"]) is not str or "/" not in row["mime_type"]
                or type(row["byte_length"]) is not int
                or not 0 < row["byte_length"] <= 8 * 1024 * 1024
                or type(row["sha256"]) is not str or len(row["sha256"]) != 64
                or any(ch not in "0123456789abcdef" for ch in row["sha256"])):
            raise ValueError("media attachment descriptor differs")


def media_source_spec() -> TypeSpec:
    return TypeSpec(
        SOURCE_MEDIA_TYPE_V2, ("event",), "source",
        validate_media_source_value, immutable=True, schema_version=2,
        writer_domain="d06", schema_hash=schema_hash({
            "type": SOURCE_MEDIA_TYPE_V2, "version": 2,
            "fields": sorted(_FIELDS), "attachment_fields": sorted(_ATTACHMENT_FIELDS),
            "immutable": True,
        }),
    )


def install_media_blob_schema(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_source_attachment_blobs_v2(
        bot TEXT NOT NULL, persona TEXT NOT NULL, source_id TEXT NOT NULL,
        attachment_order INTEGER NOT NULL, media_kind TEXT NOT NULL,
        mime_type TEXT NOT NULL, sha256 TEXT NOT NULL, content BLOB NOT NULL,
        PRIMARY KEY(bot,persona,source_id,attachment_order))""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_source_attachment_blobs_v2_no_update
        BEFORE UPDATE ON graph_source_attachment_blobs_v2
        BEGIN SELECT RAISE(ABORT, 'media bytes are immutable'); END""")


def insert_media_blobs(db: sqlite3.Connection, namespace: NamespaceId,
                       admission: SourceAdmissionV2) -> None:
    for item in admission.attachments:
        db.execute(
            "INSERT INTO graph_source_attachment_blobs_v2"
            "(bot,persona,source_id,attachment_order,media_kind,mime_type,sha256,content)"
            " VALUES(?,?,?,?,?,?,?,?)",
            namespace.as_tuple + (admission.source.source_id, item.order,
                                  item.media_kind, item.mime_type, item.sha256,
                                  item.content),
        )


def read_media_blobs(db: sqlite3.Connection, namespace: NamespaceId,
                     source_id: str, value: dict) -> tuple[bytes, ...]:
    validate_media_source_value(value)
    rows = db.execute(
        "SELECT attachment_order,media_kind,mime_type,sha256,content "
        "FROM graph_source_attachment_blobs_v2 WHERE bot=? AND persona=? "
        "AND source_id=? ORDER BY attachment_order",
        namespace.as_tuple + (source_id,),
    ).fetchall()
    if len(rows) != len(value["attachments"]):
        raise ValueError("media bytes are absent")
    result = []
    for row, expected in zip(rows, value["attachments"]):
        content = row[4]
        if (tuple(row[:4]) != (expected["order"], expected["media_kind"],
                              expected["mime_type"], expected["sha256"])
                or len(content) != expected["byte_length"]
                or hashlib.sha256(content).hexdigest() != expected["sha256"]):
            raise ValueError("media bytes differ from graph source")
        result.append(content)
    return tuple(result)


def scrub_media_blobs(db: sqlite3.Connection, namespace: NamespaceId,
                      source_id: str) -> None:
    db.execute(
        "DELETE FROM graph_source_attachment_blobs_v2 "
        "WHERE bot=? AND persona=? AND source_id=?",
        namespace.as_tuple + (source_id,),
    )
