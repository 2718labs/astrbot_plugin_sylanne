from __future__ import annotations

from dataclasses import replace
import sqlite3

import pytest

from sylanne3.domains.d12.scheme_command import (
    D12CompiledSchemeV1, D12DomainCompileReceiptV1, D12IsolatedPreviewV1,
    D12PreviewCertificateV1,
    D12SchemeAdoptionIntentV1, compiled_scheme_digest_v1,
)
from sylanne3.domains.d12.types import character_draft_key
from sylanne3.runtime.scheme_port_v1 import (
    D12SchemeAdoptionCandidateV1,
    install_scheme_originals_schema_v1, record_compilation_original_v1,
    record_preview_original_v1,
    read_current_scheme_adoption_candidate_v1,
)
from sylanne3.runtime_contracts import canonical_digest
from tests.alpha1.d12.test_owner_graph_lease import NAMESPACE, owner_graph
from tests.alpha1.runtime.test_current_creator_draft_port_v1 import _creator_case


def test_real_graph_adoption_preflight_holds_without_durable_original_and_never_writes(
        owner_graph):
    graph, coordinator, _, authority, lease = _creator_case(owner_graph)
    draft_key = character_draft_key(NAMESPACE)
    frame = coordinator.with_current_creator_draft_v1(
        authority, lease, draft_ref=draft_key.token,
        required_capability="workbench.create", project=lambda current: current,
    )
    receipt = D12DomainCompileReceiptV1(
        "d01", ("d01.voice",), "a" * 64, "candidate:d01", "b" * 64,
    )
    compiled = D12CompiledSchemeV1(
        frame.namespace, frame.draft_ref, frame.draft_revision,
        canonical_digest(frame.draft), frame.active_head_ref,
        frame.active_head_revision, frame.graph_revision,
        frame.access_epoch, frame.delete_epoch, (receipt,), "", "untrusted",
    )
    compiled = replace(compiled, compiled_digest=compiled_scheme_digest_v1(compiled))
    intent = D12SchemeAdoptionIntentV1(
        "00000000-0000-4000-8000-000000000001", frame.namespace,
        compiled.compiled_digest, frame.draft_ref, frame.draft_revision,
        frame.active_head_ref, frame.active_head_revision,
        frame.graph_revision, frame.access_epoch, frame.delete_epoch,
        "untrusted-preview", "untrusted-adoption",
    )

    with graph._lock:
        db = graph._db
        before = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token IN (?,?) ORDER BY token",
            tuple(sorted((frame.draft_ref, frame.active_head_ref))),
        ).fetchall()
        db.execute("BEGIN IMMEDIATE")
        try:
            result = read_current_scheme_adoption_candidate_v1(
                db, frame.namespace, compiled, intent,
                expected_graph_epoch=frame.graph_revision,
                expected_access_epoch=frame.access_epoch,
                expected_delete_epoch=frame.delete_epoch,
            )
            assert result.status == "hold_missing_durable_scheme_original"
            assert result.hold_reason == "compiled_and_preview_original_rows_unavailable"
            assert result.read_versions
            assert result.writes == ()
        finally:
            db.execute("ROLLBACK")
        after = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token IN (?,?) ORDER BY token",
            tuple(sorted((frame.draft_ref, frame.active_head_ref))),
        ).fetchall()
    assert after == before


def test_scheme_preflight_requires_caller_owned_write_transaction():
    db = sqlite3.connect(":memory:")
    with pytest.raises(RuntimeError, match="BEGIN IMMEDIATE"):
        read_current_scheme_adoption_candidate_v1(
            db, NAMESPACE, None, None,
            expected_graph_epoch=0, expected_access_epoch=0,
            expected_delete_epoch=0,
        )


def test_durable_originals_restart_stale_and_tamper(owner_graph, tmp_path):
    graph, coordinator, _, authority, lease = _creator_case(owner_graph)
    draft_key = character_draft_key(NAMESPACE)
    frame = coordinator.with_current_creator_draft_v1(
        authority, lease, draft_ref=draft_key.token,
        required_capability="workbench.create", project=lambda current: current,
    )
    receipt = D12DomainCompileReceiptV1(
        "d01", ("d01.voice",), "a" * 64, "candidate:d01", "b" * 64)
    compiled = D12CompiledSchemeV1(
        frame.namespace, frame.draft_ref, frame.draft_revision,
        canonical_digest(frame.draft), frame.active_head_ref,
        frame.active_head_revision, frame.graph_revision,
        frame.access_epoch, frame.delete_epoch, (receipt,), "", "issuer-compilation")
    compiled = replace(compiled, compiled_digest=compiled_scheme_digest_v1(compiled))
    result = D12IsolatedPreviewV1(
        compiled.compiled_digest, type(NAMESPACE)("sandbox", "preview"),
        compiled.draft_digest, compiled.graph_revision, compiled.graph_revision,
        (), (), (), "cost:one")
    certificate = D12PreviewCertificateV1(
        compiled.compiled_digest, result.sandbox_namespace,
        result.actual_cost_receipt_ref, "issuer-preview")
    intent = D12SchemeAdoptionIntentV1(
        "00000000-0000-4000-8000-000000000002", frame.namespace,
        compiled.compiled_digest, frame.draft_ref, frame.draft_revision,
        frame.active_head_ref, frame.active_head_revision,
        frame.graph_revision, frame.access_epoch, frame.delete_epoch,
        certificate.issuer_seal, "issuer-adoption")
    path = tmp_path / "business.db"
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        install_scheme_originals_schema_v1(db)
        record_compilation_original_v1(db, compiled)
        record_preview_original_v1(db, compiled, result, certificate)
        db.commit()

    # A new connection proves the original outlives its Python issuer.
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        candidate = read_current_scheme_adoption_candidate_v1(
            db, frame.namespace, compiled, intent,
            expected_graph_epoch=frame.graph_revision,
            expected_access_epoch=frame.access_epoch,
            expected_delete_epoch=frame.delete_epoch)
        assert isinstance(candidate, D12SchemeAdoptionCandidateV1)
        assert candidate.preview == certificate
        assert candidate.previous_head.generation >= 1
        stale = read_current_scheme_adoption_candidate_v1(
            db, frame.namespace, compiled, intent,
            expected_graph_epoch=frame.graph_revision + 1,
            expected_access_epoch=frame.access_epoch,
            expected_delete_epoch=frame.delete_epoch)
        assert stale.status == "hold_stale_scheme_read_set"
        db.rollback()

    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("UPDATE graph_d12_preview_originals_v1 SET result_json='{}' "
                   "WHERE bot=? AND persona=? AND preview_seal=?",
                   (*frame.namespace.as_tuple, certificate.issuer_seal))
        db.commit()
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        tampered = read_current_scheme_adoption_candidate_v1(
            db, frame.namespace, compiled, intent,
            expected_graph_epoch=frame.graph_revision,
            expected_access_epoch=frame.access_epoch,
            expected_delete_epoch=frame.delete_epoch)
        assert tampered.status == "hold_tampered_scheme_original"
        db.rollback()
