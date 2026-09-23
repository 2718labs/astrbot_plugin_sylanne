"""Deletion DTO/codec checks only; they confer no verifier authority."""

from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_contract import (
    DeletionEvidenceV1, DeletionMutationReceiptV1, DeletionPendingV1,
    FencePermitV2, canonical_bytes, decode_bytes, deletion_scope_digest,
    from_wire, to_wire,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor


def digest(char):
    return "sha256:" + char * 64


def anchor():
    return RestoreAnchor(
        authority_id="authority-a", namespace="ns-a", activation_generation=2,
        deletion_journal_id="deletion-a", deletion_seq=0,
        deletion_digest="genesis", execution_journal_id="execution-a",
        execution_seq=0, execution_digest="genesis", revocation_epoch=3,
        proof="proof-a")


def permit():
    return FencePermitV2(
        authority_id="authority-a", namespace="ns-a", subject="subject-a",
        holder="holder-a", generation=2, operation="delete",
        operation_id="fence-operation-a", token="A" * 43,
        fence_epoch=4, revision=0, pinned_anchor=anchor())


def evidence(*, kind="request_authorized", **changes):
    fields = dict(
        authority_id="authority-a", namespace="ns-a",
        deletion_operation_id="deletion-operation-a", kind=kind,
        issuer_id="issuer-a", evidence_id="evidence-a",
        bound_anchor=anchor(), request_digest=digest("a"),
        scope_digest=deletion_scope_digest(("root-a",), 1, "policy-a"),
        proof_digest=digest("b"),
    )
    if kind != "request_authorized":
        fields.update(graph_version="graph-v1", incarnation="incarnation-a",
                      access_epoch=2, deletion_epoch=1,
                      barrier_scope_digest=digest("c"))
    if kind == "cleanup_complete":
        fields["cleanup_digest"] = digest("d")
    fields.update(changes)
    return DeletionEvidenceV1(**fields)


def pending(**changes):
    fields = dict(
        permit=permit(), mutation_id="deletion-mutation-a",
        request_digest=digest("a"),
        deletion_operation_id="deletion-operation-a",
        source_phase="absent", target_phase="pending",
        closure_roots=("root-a",), deletion_epoch=1,
        policy_ref="policy-a", before_anchor=anchor(),
        evidence=evidence(), expected_append_id="deletion-append-a",
        expected_append_digest=digest("e"),
    )
    fields.update(changes)
    return DeletionPendingV1(**fields)


def receipt(**changes):
    fields = dict(
        pending=pending(),
        after_anchor=replace(anchor(), deletion_seq=1,
                             deletion_digest=digest("e"),
                             revocation_epoch=4, proof="proof-b"),
        updated_revision=1,
    )
    fields.update(changes)
    return DeletionMutationReceiptV1(**fields)


def test_strict_deletion_roundtrip_and_phase_bound_evidence():
    for item in (evidence(), pending(), receipt(),
                 evidence(kind="barrier_installed"),
                 evidence(kind="cleanup_complete")):
        assert decode_bytes(canonical_bytes(item)) == item
    assert pending().expected_deletion_seq == 1
    assert evidence().kind == "request_authorized"
    assert pending().target_phase == "pending"


@pytest.mark.parametrize("change", [
    {"permit": replace(permit(), operation="read")},
    {"source_phase": "pending"},
    {"target_phase": "closed"},
    {"closure_roots": ("root-a", "root-a")},
    {"deletion_epoch": True},
    {"policy_ref": ""},
    {"request_digest": digest("f")},
    {"deletion_operation_id": "fence-operation-a"},
    {"before_anchor": replace(anchor(), proof="different")},
    {"evidence": evidence(kind="barrier_installed")},
    {"evidence": evidence(scope_digest=digest("f"))},
])
def test_deletion_pending_rejects_identity_phase_and_scope_mismatch(change):
    with pytest.raises(ValueError):
        pending(**change)


def test_evidence_kind_requires_phase_specific_fields():
    with pytest.raises(ValueError):
        evidence(kind="request_authorized", graph_version="graph-v1")
    with pytest.raises(ValueError):
        evidence(kind="barrier_installed", cleanup_digest=digest("d"))
    with pytest.raises(ValueError):
        evidence(kind="cleanup_complete", cleanup_digest=None)
    with pytest.raises(ValueError):
        evidence(kind="unknown")


@pytest.mark.parametrize("change", [
    {"updated_revision": 2},
    {"durable_state": "cancelled_unappended"},
    {"after_anchor": replace(anchor(), deletion_seq=1,
                              deletion_digest=digest("e"),
                              revocation_epoch=3)},
    {"after_anchor": replace(anchor(), deletion_seq=1,
                              deletion_digest=digest("f"),
                              revocation_epoch=4)},
    {"after_anchor": replace(anchor(), deletion_seq=1,
                              deletion_digest=digest("e"),
                              revocation_epoch=4, execution_seq=1,
                              execution_digest=digest("f"))},
])
def test_deletion_receipt_rejects_nonunique_or_unrelated_head(change):
    with pytest.raises(ValueError):
        receipt(**change)


def test_wire_rejects_extra_fields_wrong_nested_kind_and_duplicates():
    wire = to_wire(pending())
    for edited in (
        {**wire, "extra": 1},
        {**wire, "evidence": to_wire(permit())},
        {**wire, "closure_roots": "root-a"},
        {**wire, "evidence": {**wire["evidence"], "scope_digest": digest("f")}},
        {**wire, "target_phase": "accepted"},
    ):
        with pytest.raises(ValueError):
            from_wire(edited)
    encoded = canonical_bytes(pending())
    with pytest.raises(ValueError, match="duplicate"):
        decode_bytes(encoded.replace(b'"mutation_id":', b'"mutation_id":"x","mutation_id":', 1))
