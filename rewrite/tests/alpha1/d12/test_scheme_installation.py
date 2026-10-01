"""D12's adoption write shape against the real GraphStore CAS."""

from dataclasses import replace

import pytest

from sylanne3.contracts import StaleRead
from sylanne3.domains.d12.scheme_command import (
    D12CompiledSchemeV1, D12DomainCompileReceiptV1, D12IsolatedPreviewV1,
    D12PreviewCertificateV1, D12SchemeAdoptionIntentV1,
    compiled_scheme_digest_v1,
)
from sylanne3.domains.d12.scheme_installation import (
    scheme_adoption_graph_candidate_v1, scheme_adoption_receipt_v1,
)
from sylanne3.domains.d12.types import active_scheme_head_key, character_draft_key
from sylanne3.graph_types import GraphReceipt, GraphVersion, NamespaceEpoch
from sylanne3.graph_store import GraphStore
from sylanne3.runtime.scheme_port_v1 import (
    D12SchemeAdoptionCandidateV1, install_scheme_originals_schema_v1,
    read_current_scheme_adoption_candidate_v1, record_compilation_original_v1,
    record_preview_original_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest

from tests.alpha1.d12.test_owner_graph_lease import NAMESPACE, owner_graph
from tests.alpha1.runtime.test_current_creator_draft_port_v1 import _creator_case


def _durable_candidate(graph, coordinator, authority, lease):
    frame = coordinator.with_current_creator_draft_v1(
        authority, lease, draft_ref=character_draft_key(NAMESPACE).token,
        required_capability="workbench.create", project=lambda current: current)
    domain = D12DomainCompileReceiptV1(
        "d01", ("d01.voice",), "a" * 64, "candidate:d01", "b" * 64)
    compiled = D12CompiledSchemeV1(
        NAMESPACE, frame.draft_ref, frame.draft_revision,
        canonical_digest(frame.draft), frame.active_head_ref,
        frame.active_head_revision, frame.graph_revision, frame.access_epoch,
        frame.delete_epoch, (domain,), "", "issuer-compilation")
    compiled = replace(compiled, compiled_digest=compiled_scheme_digest_v1(compiled))
    isolated = D12IsolatedPreviewV1(
        compiled.compiled_digest, NamespaceId("sandbox", "preview"),
        compiled.draft_digest, compiled.graph_revision, compiled.graph_revision,
        (), (), (), "cost:one")
    preview = D12PreviewCertificateV1(
        compiled.compiled_digest, isolated.sandbox_namespace,
        isolated.actual_cost_receipt_ref, "issuer-preview")
    intent = D12SchemeAdoptionIntentV1(
        "00000000-0000-4000-8000-000000000101", NAMESPACE,
        compiled.compiled_digest, compiled.draft_ref, compiled.draft_revision,
        compiled.active_head_ref, compiled.active_head_revision,
        compiled.graph_revision, compiled.access_epoch, compiled.delete_epoch,
        preview.issuer_seal, "issuer-adoption")
    with graph._lock:
        db = graph._db
        db.execute("BEGIN IMMEDIATE")
        try:
            install_scheme_originals_schema_v1(db)
            record_compilation_original_v1(db, compiled)
            record_preview_original_v1(db, compiled, isolated, preview)
            candidate = read_current_scheme_adoption_candidate_v1(
                db, NAMESPACE, compiled, intent,
                expected_graph_epoch=frame.graph_revision,
                expected_access_epoch=frame.access_epoch,
                expected_delete_epoch=frame.delete_epoch)
            assert type(candidate) is D12SchemeAdoptionCandidateV1
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return candidate


def test_durable_candidate_advances_one_active_head_with_real_graph_cas(owner_graph):
    graph, coordinator, _, authority, lease = _creator_case(owner_graph)
    adoption = _durable_candidate(graph, coordinator, authority, lease)
    candidate = scheme_adoption_graph_candidate_v1(adoption, occurred_at=1.0)
    receipt = GraphStore.graph_commit(
        graph, candidate, _capability=graph._coordinator_capability)
    result = scheme_adoption_receipt_v1(adoption, receipt)
    assert result.active_head_revision == adoption.compiled.active_head_revision + 1
    assert result.graph_revision == adoption.graph_epoch + 1
    with graph._lock:
        row = graph._db.execute(
            "SELECT revision,value FROM graph_atoms WHERE token=?",
            (active_scheme_head_key(NAMESPACE).token,)).fetchone()
    assert row[0] == result.active_head_revision
    assert adoption.compiled.compiled_digest in row[1]

    with pytest.raises((StaleRead, ValueError)):
        GraphStore.graph_commit(
            graph, replace(candidate, event=replace(
                candidate.event, event_id="00000000-0000-4000-8000-000000000102")),
            _capability=graph._coordinator_capability)


def test_installation_adapter_rejects_incomplete_read_set_and_false_receipt(owner_graph):
    graph, coordinator, _, authority, lease = _creator_case(owner_graph)
    adoption = _durable_candidate(graph, coordinator, authority, lease)
    with pytest.raises(ValueError, match="read set"):
        scheme_adoption_graph_candidate_v1(
            replace(adoption, read_versions=adoption.read_versions[:1]),
            occurred_at=1.0)
    with pytest.raises(ValueError, match="did not commit"):
        scheme_adoption_receipt_v1(adoption, GraphReceipt(
            "duplicate", (GraphVersion(active_scheme_head_key(NAMESPACE), 2),),
            (), NamespaceEpoch(*NAMESPACE.as_tuple, adoption.graph_epoch + 1)))
