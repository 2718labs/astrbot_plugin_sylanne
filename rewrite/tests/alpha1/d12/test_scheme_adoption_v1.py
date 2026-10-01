"""W01 adoption helper reads durable originals across SQLite connections."""

from dataclasses import replace
import sqlite3

from sylanne3.domains.d12.scheme_command import (
    D12CompiledSchemeV1, D12DomainCompileReceiptV1, D12IsolatedPreviewV1,
    D12PreviewCertificateV1, D12SchemeAdoptionIntentV1,
    compiled_scheme_digest_v1,
)
from sylanne3.domains.d12.types import character_draft_key, active_scheme_head_key
from sylanne3.runtime.scheme_adoption_v1 import (
    CurrentSchemeInputsV1, SchemeAdoptionHoldV1,
    read_current_scheme_adoption_for_w01_v1,
)
from sylanne3.runtime.scheme_original_store_v1 import (
    CompilationOriginalV1, PreviewOriginalV1,
    install_scheme_original_store_v1,
    record_compilation_original_for_operation_v1,
    record_preview_original_for_operation_v1,
)
from sylanne3.runtime.scheme_port_v1 import D12SchemeAdoptionCandidateV1
from sylanne3.runtime_contracts import NamespaceId, canonical_digest
from tests.alpha1.d12.test_owner_graph_lease import NAMESPACE, owner_graph
from tests.alpha1.runtime.test_current_creator_draft_port_v1 import _creator_case


def test_cross_connection_originals_and_current_head_cas(owner_graph, tmp_path):
    graph, coordinator, _, authority, lease = _creator_case(owner_graph)
    frame = coordinator.with_current_creator_draft_v1(
        authority, lease, draft_ref=character_draft_key(NAMESPACE).token,
        required_capability="workbench.create", project=lambda value: value)
    receipt = D12DomainCompileReceiptV1(
        "d01", ("d01.voice",), "a" * 64, "candidate:d01", "b" * 64)
    compiled = D12CompiledSchemeV1(
        NAMESPACE, frame.draft_ref, frame.draft_revision,
        canonical_digest(frame.draft), frame.active_head_ref,
        frame.active_head_revision, frame.graph_revision, frame.access_epoch,
        frame.delete_epoch, (receipt,), "", "issuer-compilation")
    compiled = replace(compiled, compiled_digest=compiled_scheme_digest_v1(compiled))
    isolated = D12IsolatedPreviewV1(
        compiled.compiled_digest, NamespaceId("sandbox", "preview"),
        compiled.draft_digest, compiled.graph_revision, compiled.graph_revision,
        (), (), (), "cost:one")
    certificate = D12PreviewCertificateV1(
        compiled.compiled_digest, isolated.sandbox_namespace,
        isolated.actual_cost_receipt_ref, "issuer-preview")
    intent = D12SchemeAdoptionIntentV1(
        "00000000-0000-4000-8000-000000000021", NAMESPACE,
        compiled.compiled_digest, compiled.draft_ref, compiled.draft_revision,
        compiled.active_head_ref, compiled.active_head_revision,
        compiled.graph_revision, compiled.access_epoch, compiled.delete_epoch,
        certificate.issuer_seal, "issuer-adoption")
    inputs = CurrentSchemeInputsV1("c" * 64, "d" * 64, "e" * 64,
                                   (("d01", receipt.proposal_schema_hash),))
    path = tmp_path / "business.db"
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        install_scheme_original_store_v1(db)
        record_compilation_original_for_operation_v1(db, CompilationOriginalV1(
            "00000000-0000-4000-8000-000000000022", compiled,
            inputs.compilation_source_input_digest, "f" * 64))
        record_preview_original_for_operation_v1(db, compiled, PreviewOriginalV1(
            "00000000-0000-4000-8000-000000000023", certificate, isolated,
            inputs.preview_source_input_digest, "1" * 64,
            canonical_digest(isolated)))
        db.commit()

    # No process-local issuer seal or Python object is read from the recording
    # connection. W01 supplies its own authenticated, current callbacks.
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        result = read_current_scheme_adoption_for_w01_v1(
            db, authority, lease, intent,
            authorize_owner=lambda current, current_lease:
                current == authority and current_lease is lease,
            read_current_inputs=lambda _: inputs)
        assert isinstance(result, D12SchemeAdoptionCandidateV1)
        assert result.read_versions[1].revision == frame.active_head_revision
        assert result.preview == certificate
        missing_asset = read_current_scheme_adoption_for_w01_v1(
            db, authority, lease, intent,
            authorize_owner=lambda *_: True,
            read_current_inputs=lambda _: replace(inputs, asset_snapshot_digest=""))
        assert isinstance(missing_asset, SchemeAdoptionHoldV1)
        assert missing_asset.code == "current_source_asset_schema_missing"
        denied = read_current_scheme_adoption_for_w01_v1(
            db, authority, lease, intent,
            authorize_owner=lambda *_: False,
            read_current_inputs=lambda _: inputs)
        assert denied.code == "owner_lease_not_current"
        db.rollback()

    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("UPDATE graph_atoms SET revision=revision+1 WHERE token=?",
                   (active_scheme_head_key(NAMESPACE).token,))
        db.commit()
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        stale = read_current_scheme_adoption_for_w01_v1(
            db, authority, lease, intent,
            authorize_owner=lambda *_: True,
            read_current_inputs=lambda _: inputs)
        assert isinstance(stale, SchemeAdoptionHoldV1)
        assert stale.code == "hold_stale_scheme_read_set"
        db.rollback()


def test_invalid_authority_holds_before_original_read(tmp_path):
    with sqlite3.connect(tmp_path / "empty.db") as db:
        db.execute("BEGIN IMMEDIATE")
        result = read_current_scheme_adoption_for_w01_v1(
            db, None, object(), None,
            authorize_owner=None, read_current_inputs=None)
        assert result.code == "authority_or_intent_invalid"
        db.rollback()
