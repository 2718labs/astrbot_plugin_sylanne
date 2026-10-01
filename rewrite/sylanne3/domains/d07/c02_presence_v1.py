"""Current D07 presence of an actually committed C02, with meaning left unknown.

This installed branch states only that an inbound source was encoded. It does
not infer a proposition about its speaker, a feeling, or an external fact.
"""
from __future__ import annotations
from . import CurrentInterpretationCandidate, D07DomainProvider, EvidenceStatus, Stance
from ...runtime_contracts import canonical_digest

POLICY = ("d07.c02.input_presence.v1", "1", "meaning_unassessed")


def issue_current_c02_presence_v1(*, envelope, snapshot, source, c02_receipt, perspective_ref):
    if (c02_receipt.status != "committed" or c02_receipt.operation_id not in envelope.causation
            or c02_receipt.activity_id != envelope.identity.activity_id
            or envelope.source_qualification.source_refs != (source.source_ref,)
            or source.source.assertion_status not in {"reported", "confirmed"}):
        raise ValueError("D07 presence requires one actual qualified committed C02")
    candidate = CurrentInterpretationCandidate(
        "replaced-by-d07", envelope.identity.activity_id,
        "c02-presence:" + canonical_digest((source.source_ref, c02_receipt.operation_id))[:48],
        "本次入站来源已完成编码；具体语义及他人意图尚未判定。",
        Stance.SUSPEND, 0.0, EvidenceStatus.INSUFFICIENT,
        (source.source_ref,), (source.source.provenance_root,),
        ("meaning_unassessed", "speaker_intent_unknown", "external_truth_not_reassessed"))
    proposal = D07DomainProvider().first_source_interpretation_proposal(
        envelope, snapshot, candidate, perspective_ref=perspective_ref)
    provenance = {"schema": "d07.c02_presence_original.v1", "policy": POLICY,
        "c02_operation_id": c02_receipt.operation_id, "c02_receipt_digest": canonical_digest(c02_receipt),
        "source_ref": source.source_ref, "source_revision": source.source_revision,
        "perspective_ref": perspective_ref, "proposal_digest": canonical_digest(proposal)}
    return proposal, provenance
