from dataclasses import replace
import sqlite3

import pytest

from sylanne3.domains.d12.scheme_command import (
    D12CompiledSchemeV1, D12DomainCompileReceiptV1,
    D12IsolatedPreviewV1, D12PreviewCertificateV1,
    compiled_scheme_digest_v1,
)
from sylanne3.domains.d12.types import active_scheme_head_key, character_draft_key
from sylanne3.runtime.scheme_original_store_v1 import (
    CompilationOriginalV1, PreviewOriginalV1,
    install_scheme_original_store_v1,
    record_compilation_original_for_operation_v1,
    record_preview_original_for_operation_v1,
    read_compilation_original_for_operation_v1,
    read_preview_original_for_operation_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


NAMESPACE = NamespaceId("bot", "persona")
COMPILE_OP = "00000000-0000-4000-8000-000000000011"
PREVIEW_OP = "00000000-0000-4000-8000-000000000012"


def _originals():
    receipt = D12DomainCompileReceiptV1(
        "d01", ("d01.voice",), "a" * 64, "candidate:d01", "b" * 64)
    compiled = D12CompiledSchemeV1(
        NAMESPACE, character_draft_key(NAMESPACE).token, 2,
        "c" * 64, active_scheme_head_key(NAMESPACE).token,
        1, 4, 3, 2, (receipt,), "", "issuer-compilation")
    compiled = replace(compiled, compiled_digest=compiled_scheme_digest_v1(compiled))
    result = D12IsolatedPreviewV1(
        compiled.compiled_digest, NamespaceId("sandbox", "preview"),
        compiled.draft_digest, compiled.graph_revision, compiled.graph_revision,
        (), (), (), "cost:one")
    certificate = D12PreviewCertificateV1(
        compiled.compiled_digest, result.sandbox_namespace,
        result.actual_cost_receipt_ref, "issuer-preview")
    return (
        CompilationOriginalV1(COMPILE_OP, compiled, "d" * 64, "e" * 64),
        PreviewOriginalV1(PREVIEW_OP, certificate, result, "f" * 64,
                          "1" * 64, canonical_digest(result)),
    )


def test_originals_survive_restart_and_same_operation_is_exactly_idempotent(tmp_path):
    path = tmp_path / "graph.db"
    compilation, preview = _originals()
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        install_scheme_original_store_v1(db)
        record_compilation_original_for_operation_v1(db, compilation)
        record_compilation_original_for_operation_v1(db, compilation)
        record_preview_original_for_operation_v1(db, compilation.compiled, preview)
        record_preview_original_for_operation_v1(db, compilation.compiled, preview)
        db.commit()
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        assert read_compilation_original_for_operation_v1(
            db, NAMESPACE, compiled_digest=compilation.compiled.compiled_digest) == compilation
        assert read_preview_original_for_operation_v1(
            db, NAMESPACE, preview_seal=preview.certificate.issuer_seal) == preview
        db.rollback()


def test_changed_operation_or_tampered_original_fails_closed():
    compilation, preview = _originals()
    with sqlite3.connect(":memory:") as db:
        db.execute("BEGIN IMMEDIATE")
        install_scheme_original_store_v1(db)
        record_compilation_original_for_operation_v1(db, compilation)
        with pytest.raises(ValueError, match="operation changed"):
            record_compilation_original_for_operation_v1(
                db, replace(compilation, budget_receipt_digest="0" * 64))
        record_preview_original_for_operation_v1(db, compilation.compiled, preview)
        with pytest.raises(ValueError, match="operation changed"):
            record_preview_original_for_operation_v1(
                db, compilation.compiled,
                replace(preview, source_input_digest="0" * 64))
        db.execute("UPDATE graph_d12_preview_originals_v1 SET result_json='{}' "
                   "WHERE bot=? AND persona=? AND preview_seal=?",
                   (*NAMESPACE.as_tuple, preview.certificate.issuer_seal))
        with pytest.raises(ValueError, match="changed"):
            read_preview_original_for_operation_v1(
                db, NAMESPACE, preview_seal=preview.certificate.issuer_seal)
        db.rollback()


def test_requires_w01_transaction_and_prior_compilation():
    compilation, preview = _originals()
    with sqlite3.connect(":memory:") as db:
        with pytest.raises(RuntimeError, match="BEGIN IMMEDIATE"):
            install_scheme_original_store_v1(db)
        db.execute("BEGIN IMMEDIATE")
        install_scheme_original_store_v1(db)
        with pytest.raises(ValueError, match="trusted compilation original"):
            record_preview_original_for_operation_v1(db, compilation.compiled, preview)
        db.rollback()
