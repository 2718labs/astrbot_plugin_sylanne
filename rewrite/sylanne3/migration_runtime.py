"""Isolated, review-only migration previews for verified legacy archives.

This module never opens an old runtime, activates a draft, or writes a graph.
It accepts only one source shape whose implementation is pinned to a Git blob,
and requires a caller-provided verifier for the archive deletion watermark.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Protocol

from .domains.d12 import CharacterDraft


LEGACY_PERSON_PROFILE_MIGRATION_ID = "sylanne-2.5-person-profile-preview.v1"
_LEGACY_SOURCE_SCHEMA = "sylanne-2.5.person-profile.v1"
_LEGACY_SOURCE_REVISION = "72de068bf6f97a70086abdddc8cc487933350c5c"
_LEGACY_SOURCE_BLOB = "ddfd064a06940c28cac3deb390fd71721443c548"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_BLOB = re.compile(r"[0-9a-f]{40}\Z")
_LEGACY_PROFILE_FIELDS = frozenset({
    "preference_count", "boundary_count", "progress_count", "repair_count", "phase",
    "six_snapshot", "warmth_baseline", "warmth_transient", "volatility_transient",
    "valence", "arousal", "tension", "last_interaction_ts",
    "last_applied_transient", "last_applied_volatility_transient", "schema_ver",
})


class MigrationRejected(RuntimeError):
    """The source remains isolated and cannot produce even a draft preview."""


class ArchiveEvidenceVerifier(Protocol):
    """Trust boundary supplied by D11/Authority, never by the archive itself."""

    def verify(self, evidence: "LegacyArchiveEvidence") -> bool: ...


@dataclass(frozen=True)
class LegacyArchiveEvidence:
    archive_digest: str
    deletion_receipt_ref: str
    deletion_watermark: int
    verifier_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.archive_digest, str) or not _DIGEST.fullmatch(self.archive_digest):
            raise ValueError("archive_digest must be a lowercase SHA-256 digest")
        if any(not isinstance(value, str) or not value for value in
               (self.deletion_receipt_ref, self.verifier_id)):
            raise ValueError("deletion receipt and verifier identity are required")
        if type(self.deletion_watermark) is not int or self.deletion_watermark < 0:
            raise ValueError("deletion_watermark must be a nonnegative exact integer")


@dataclass(frozen=True)
class LegacyRecord:
    source_schema: str
    source_revision: str
    source_blob_id: str
    record_id: str
    payload: dict[str, object]
    evidence: LegacyArchiveEvidence

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value for value in
               (self.source_schema, self.source_revision, self.source_blob_id, self.record_id)):
            raise ValueError("legacy source identities are required")
        if not _BLOB.fullmatch(self.source_blob_id):
            raise ValueError("source_blob_id must be a Git object identifier")
        if type(self.payload) is not dict:
            raise TypeError("legacy payload must be an exact object")
        if not isinstance(self.evidence, LegacyArchiveEvidence):
            raise TypeError("legacy archive evidence is required")


@dataclass(frozen=True)
class MigrationPreview:
    migration_id: str
    draft: CharacterDraft
    activation_allowed: bool
    warnings: tuple[str, ...]


class PreviewMigrator(Protocol):
    migration_id: str
    source_schema: str

    def preview(self, record: LegacyRecord, *, target_scope: str,
                target_revision: int) -> MigrationPreview: ...


def _canonical_digest(value: object) -> str:
    try:
        material = json.dumps(value, ensure_ascii=True, allow_nan=False,
                              sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise MigrationRejected("legacy payload must be finite JSON data") from exc
    return sha256(material.encode("utf-8")).hexdigest()


class LegacyPersonProfilePreviewMigrator:
    """Quarantine the v2.5 PersonProfile as a D12 review candidate.

    The legacy value mixed relationship counters, emotion and learned profile
    data. Its fields therefore have no automatic target meaning.  The only
    new-schema artifact is an administrative CharacterDraft containing opaque
    provenance and a list of unmapped field names.
    """

    migration_id = LEGACY_PERSON_PROFILE_MIGRATION_ID
    source_schema = _LEGACY_SOURCE_SCHEMA

    def __init__(self, evidence_verifier: ArchiveEvidenceVerifier) -> None:
        if not callable(getattr(evidence_verifier, "verify", None)):
            raise TypeError("an archive evidence verifier is required")
        self._evidence_verifier = evidence_verifier

    def preview(self, record: LegacyRecord, *, target_scope: str,
                target_revision: int) -> MigrationPreview:
        if not isinstance(record, LegacyRecord):
            raise TypeError("record must be LegacyRecord")
        if record.source_schema != self.source_schema:
            raise MigrationRejected("no registered migrator for legacy source schema")
        if (record.source_revision != _LEGACY_SOURCE_REVISION
                or record.source_blob_id != _LEGACY_SOURCE_BLOB):
            raise MigrationRejected("legacy source revision is not the registered implementation")
        try:
            deletion_verified = self._evidence_verifier.verify(record.evidence)
        except Exception:
            deletion_verified = False
        if deletion_verified is not True:
            raise MigrationRejected("legacy deletion state could not be independently verified")
        fields = set(record.payload)
        if fields != _LEGACY_PROFILE_FIELDS:
            detail = "unknown fields" if fields - _LEGACY_PROFILE_FIELDS else "required fields"
            raise MigrationRejected(f"legacy profile has {detail}")
        if type(record.payload["schema_ver"]) is not int or record.payload["schema_ver"] != 1:
            raise MigrationRejected("legacy profile schema version is not supported")
        if not isinstance(target_scope, str) or not target_scope:
            raise ValueError("target_scope is required")
        if type(target_revision) is not int or target_revision < 0:
            raise ValueError("target_revision must be a nonnegative exact integer")
        payload_digest = _canonical_digest(record.payload)
        candidate = {
            "migration_id": self.migration_id,
            "source_schema": record.source_schema,
            "source_revision": record.source_revision,
            "source_blob_id": record.source_blob_id,
            "record_id": record.record_id,
            "archive_digest": record.evidence.archive_digest,
            "deletion_watermark": record.evidence.deletion_watermark,
            "payload_digest": payload_digest,
            "unmapped_fields": sorted(_LEGACY_PROFILE_FIELDS),
            "status": "requires_user_review",
        }
        draft = CharacterDraft(
            target_scope, target_revision,
            {"legacy_import_candidate": candidate},
            {"legacy_import_candidate": "legacy_unverified_candidate"},
        )
        return MigrationPreview(
            self.migration_id, draft, False,
            ("legacy profile values are not trust, shared experience, or active state",
             "candidate remains isolated until a domain-owned user review and adoption"),
        )


class MigrationRegistry:
    """Explicit registry; absent source schemas fail closed rather than guessing."""

    def __init__(self) -> None:
        self._migrators: dict[str, PreviewMigrator] = {}
        self._by_source: dict[str, PreviewMigrator] = {}

    def register(self, migrator: PreviewMigrator) -> None:
        if not isinstance(getattr(migrator, "migration_id", None), str) or not migrator.migration_id:
            raise TypeError("migrator requires an identifier")
        if not isinstance(getattr(migrator, "source_schema", None), str) or not migrator.source_schema:
            raise TypeError("migrator requires a source schema")
        if not callable(getattr(migrator, "preview", None)):
            raise TypeError("migrator requires preview")
        if migrator.migration_id in self._migrators or migrator.source_schema in self._by_source:
            raise ValueError("migrator is already registered")
        self._migrators[migrator.migration_id] = migrator
        self._by_source[migrator.source_schema] = migrator

    def migrator(self, migration_id: str) -> PreviewMigrator:
        try:
            return self._migrators[migration_id]
        except KeyError as exc:
            raise MigrationRejected("no registered migrator identifier") from exc

    def preview(self, record: LegacyRecord, *, target_scope: str,
                target_revision: int) -> MigrationPreview:
        if not isinstance(record, LegacyRecord):
            raise TypeError("record must be LegacyRecord")
        migrator = self._by_source.get(record.source_schema)
        if migrator is None:
            raise MigrationRejected("no registered migrator for legacy source schema")
        return migrator.preview(record, target_scope=target_scope,
                                target_revision=target_revision)


def default_registry(evidence_verifier: ArchiveEvidenceVerifier) -> MigrationRegistry:
    registry = MigrationRegistry()
    registry.register(LegacyPersonProfilePreviewMigrator(evidence_verifier))
    return registry


__all__ = (
    "ArchiveEvidenceVerifier", "LEGACY_PERSON_PROFILE_MIGRATION_ID",
    "LegacyArchiveEvidence", "LegacyPersonProfilePreviewMigrator", "LegacyRecord",
    "MigrationPreview", "MigrationRejected", "MigrationRegistry", "default_registry",
)
