"""Recompute a D06 source check against a current, fenced graph read.

This is one RequiredCheck verifier, not a final D11 admission or send permit.
The graph coordinator must establish the current Authority/deletion barrier
before passing ``current_barrier_confirmed=True``.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ..domains.d06 import D06DomainProvider, SourceGrantRead
from ..domains.d08 import ActionIntent, RequiredCheckSpec
from ..graph_types import GraphSnapshot
from ..runtime_contracts import CheckReceipt, canonical_digest
from .dispatch_candidate import DispatchCandidateEvidenceV1


@dataclass(frozen=True)
class RequiredCheckVerificationV1:
    status: str
    verified: bool
    reason: str
    recomputed_digest: str | None = None


def verify_current_d06_source_grant(
    snapshot: GraphSnapshot, intent: ActionIntent, spec: RequiredCheckSpec,
    receipt: CheckReceipt, candidate: DispatchCandidateEvidenceV1, *,
    audience: tuple[str, ...], now_utc: float,
    current_barrier_confirmed: bool = False,
) -> RequiredCheckVerificationV1:
    """Compare an existing receipt with D06's freshly computed source check.

    A receipt's issuer field is only a comparison value.  The qualified
    candidate's pinned source-value digest prevents same-revision value drift.
    No other RequiredCheck kind is approved by this function.
    """

    def hold(reason: str) -> RequiredCheckVerificationV1:
        return RequiredCheckVerificationV1("hold", False, reason)

    if (type(snapshot) is not GraphSnapshot or type(intent) is not ActionIntent
            or type(spec) is not RequiredCheckSpec or type(receipt) is not CheckReceipt
            or type(candidate) is not DispatchCandidateEvidenceV1):
        return hold("typed_current_evidence_missing")
    if (type(now_utc) not in (int, float) or not math.isfinite(now_utc)
            or type(audience) is not tuple or not audience
            or any(type(item) is not str or not item for item in audience)):
        return hold("time_or_audience_invalid")
    if current_barrier_confirmed is not True:
        return hold("current_authority_barrier_unconfirmed")
    if len(snapshot.epochs) != 1:
        return hold("current_graph_epoch_missing")
    if (spec.check_kind != "source_grant" or spec.provider_id != "d06.source_grant"
            or tuple(item for item in intent.required_checks
                     if item.check_kind == "source_grant") != (spec,)
            or spec.subject_ref != "persona:" + snapshot.epochs[0].persona
            or spec.action_ref != intent.action_id or spec.purpose != "expression"):
        return hold("d06_check_scope_differs")
    if (candidate.status != "source_qualified"
            or candidate.operation_id != intent.identity.operation_id
            or candidate.query_epoch != snapshot.epochs[0].revision
            or candidate.source_refs != intent.source_refs
            or candidate.source_audience != audience):
        return hold("qualified_candidate_or_epoch_differs")
    if (receipt.check_kind, receipt.issuer, receipt.subject_ref,
            receipt.action_ref, receipt.purpose, receipt.input_versions) != (
            spec.check_kind, spec.provider_id, spec.subject_ref,
            spec.action_ref, spec.purpose, spec.required_input_versions):
        return hold("receipt_scope_or_versions_differ")
    if (receipt.result != "pass" or receipt.coverage != "full"
            or receipt.valid_until < now_utc):
        return hold("receipt_incomplete_or_expired")
    try:
        recomputed = D06DomainProvider.provide_required_check(
            intent, SourceGrantRead(snapshot, audience, "expression", True, True),
            valid_until=receipt.valid_until,
        )
    except (TypeError, ValueError):
        return hold("d06_recomputation_unavailable")
    if (recomputed.result != "pass" or recomputed.coverage != "full"
            or recomputed != receipt):
        return hold("current_d06_check_differs")
    atoms = {atom.key.token: atom for atom in snapshot.atoms}
    proof = []
    for item in recomputed.input_versions:
        atom = atoms.get(item.ref)
        if (atom is None or atom.revision != item.version or not atom.valid
                or atom.key.type_name not in {"memory.source", "memory.access"}):
            return hold("source_proof_incomplete")
        proof.append((item.ref, item.version, canonical_digest(atom.value)))
    if (not proof or candidate.source_proof_versions != tuple(
            (ref, version) for ref, version, _ in proof)
            or candidate.source_proof_digest != canonical_digest(proof)):
        return hold("source_proof_digest_differs")
    return RequiredCheckVerificationV1(
        "verified", True, "current_d06_source_grant",
        canonical_digest(recomputed),
    )


__all__ = ["RequiredCheckVerificationV1", "verify_current_d06_source_grant"]
