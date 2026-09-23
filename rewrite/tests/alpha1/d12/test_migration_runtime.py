from __future__ import annotations

import json
from pathlib import Path

import pytest

from sylanne3.migration_runtime import (
    LEGACY_PERSON_PROFILE_MIGRATION_ID,
    LegacyArchiveEvidence,
    LegacyRecord,
    MigrationRejected,
    MigrationRegistry,
    default_registry,
)


SOURCE_REVISION = "72de068bf6f97a70086abdddc8cc487933350c5c"
SOURCE_BLOB = "ddfd064a06940c28cac3deb390fd71721443c548"


class VerifiedArchive:
    def verify(self, evidence: LegacyArchiveEvidence) -> bool:
        return evidence.deletion_receipt_ref == "authority/delete-head/42"


class UnavailableAuthority:
    def verify(self, evidence: LegacyArchiveEvidence) -> bool:
        raise OSError("authority unreachable")


def legacy_record(**changes: object) -> LegacyRecord:
    payload = {
        "preference_count": 5,
        "boundary_count": 1,
        "progress_count": 2,
        "repair_count": 0,
        "phase": "forming_continuity",
        "six_snapshot": {"warmth_bias": 0.8},
        "warmth_baseline": 0.6,
        "warmth_transient": -0.1,
        "volatility_transient": 0.1,
        "valence": -0.2,
        "arousal": 0.3,
        "tension": 0.4,
        "last_interaction_ts": 1700000000.0,
        "last_applied_transient": 0.0,
        "last_applied_volatility_transient": 0.0,
        "schema_ver": 1,
    }
    values = {
        "source_schema": "sylanne-2.5.person-profile.v1",
        "source_revision": SOURCE_REVISION,
        "source_blob_id": SOURCE_BLOB,
        "record_id": "legacy-profile-001",
        "payload": payload,
        "evidence": LegacyArchiveEvidence(
            archive_digest="a" * 64,
            deletion_receipt_ref="authority/delete-head/42",
            deletion_watermark=42,
            verifier_id="authority-a",
        ),
    }
    values.update(changes)
    return LegacyRecord(**values)


def test_registered_legacy_profile_migrator_creates_only_a_reviewable_d12_draft():
    preview = default_registry(VerifiedArchive()).preview(
        legacy_record(), target_scope="bot/persona", target_revision=3,
    )
    assert preview.migration_id == LEGACY_PERSON_PROFILE_MIGRATION_ID
    assert preview.activation_allowed is False
    assert preview.draft.scope == "bot/persona"
    candidate = preview.draft.fields["legacy_import_candidate"]
    assert candidate["source_schema"] == "sylanne-2.5.person-profile.v1"
    assert candidate["record_id"] == "legacy-profile-001"
    assert "preference_count" in candidate["unmapped_fields"]
    assert "warmth_baseline" in candidate["unmapped_fields"]
    assert "trust" not in candidate
    assert "affinity" not in candidate
    assert "shared_experience" not in candidate
    assert preview.draft.field_sources == {"legacy_import_candidate": "legacy_unverified_candidate"}


def test_unregistered_schema_and_unverified_deletion_state_are_rejected_before_preview():
    registry = default_registry(VerifiedArchive())
    with pytest.raises(MigrationRejected, match="no registered migrator"):
        registry.preview(
            legacy_record(source_schema="unknown.legacy.v1"),
            target_scope="bot/persona", target_revision=0,
        )
    with pytest.raises(MigrationRejected, match="deletion"):
        registry.preview(
            legacy_record(evidence=LegacyArchiveEvidence(
                archive_digest="a" * 64, deletion_receipt_ref="unverified",
                deletion_watermark=42, verifier_id="authority-a",
            )),
            target_scope="bot/persona", target_revision=0,
        )


def test_authority_failure_fails_closed_as_a_migration_rejection():
    with pytest.raises(MigrationRejected, match="deletion"):
        default_registry(UnavailableAuthority()).preview(
            legacy_record(), target_scope="bot/persona", target_revision=0,
        )


def test_migrator_refuses_legacy_identity_fields_and_schema_drift():
    registry = default_registry(VerifiedArchive())
    contaminated = legacy_record()
    contaminated.payload["sender_id"] = "raw-identity"
    with pytest.raises(MigrationRejected, match="unknown fields"):
        registry.preview(contaminated, target_scope="bot/persona", target_revision=0)
    drifted = legacy_record()
    drifted.payload["schema_ver"] = 2
    with pytest.raises(MigrationRejected, match="schema version"):
        registry.preview(drifted, target_scope="bot/persona", target_revision=0)


def test_registry_rejects_duplicate_registration_and_resource_declares_preview_hold():
    registry = default_registry(VerifiedArchive())
    with pytest.raises(ValueError, match="already registered"):
        registry.register(registry.migrator(LEGACY_PERSON_PROFILE_MIGRATION_ID))
    resource = Path(__file__).resolve().parents[4] / "resources" / "migrations" / "v1.json"
    declared = json.loads(resource.read_text(encoding="utf-8"))
    assert declared["legacy_data_policy"] == "registered_migrators"
    assert declared["release_eligibility"].startswith("HOLD:")
    assert declared["migrations"][0]["id"] == LEGACY_PERSON_PROFILE_MIGRATION_ID
    assert declared["migrations"][0]["activation"] == "prohibited_preview_only"
