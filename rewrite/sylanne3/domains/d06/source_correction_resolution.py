"""Pure resolved-head candidate for a previously committed D06 correction.

This module does not grant a resolved graph write. W01 must
verify each cited durable receipt in its current fenced graph/Authority read,
then perform the head-version CAS in the same atomic bundle before lifting the
current-recollection barrier. Historical source and feeling atoms stay intact.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import re

from ...graph_types import AtomKey, GraphVersion
from ...runtime_contracts import NamespaceId, canonical_digest
from . import (
    SOURCE_CORRECTION_RESOLUTION_SCHEMA, validate_source_correction_head,
    validate_source_correction_head_transition_v1,
)


SCHEMA = SOURCE_CORRECTION_RESOLUTION_SCHEMA
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_DOMAINS = frozenset({"d04", "d05", "d07"})


def _id(value: str, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be nonempty")
    return value


def _digest(value: str, name: str) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value


def _integer(value: int, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0):
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def _time(value: float, name: str) -> float:
    if type(value) not in {int, float} or not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return float(value)


@dataclass(frozen=True, slots=True)
class ReevaluationReceiptRefV1:
    domain: str
    receipt_ref: str
    receipt_digest: str
    correction_operation_id: str
    correction_source_ref: str

    def __post_init__(self) -> None:
        if self.domain not in _DOMAINS:
            raise ValueError("correction reevaluation domain differs")
        _id(self.receipt_ref, "reevaluation receipt ref")
        _digest(self.receipt_digest, "reevaluation receipt digest")
        _id(self.correction_operation_id, "correction operation")
        AtomKey.from_token(self.correction_source_ref)


@dataclass(frozen=True, slots=True)
class ActualCorrectionCostV1:
    receipt_ref: str
    receipt_digest: str
    correction_operation_id: str
    quote_id: str
    quote_version: int
    quote_deadline_utc: float
    actual_amounts: tuple[tuple[str, int], ...]
    state: str = "settled_actual"

    def __post_init__(self) -> None:
        _id(self.receipt_ref, "D02 cost receipt ref")
        _digest(self.receipt_digest, "D02 cost receipt digest")
        _id(self.correction_operation_id, "correction operation")
        _id(self.quote_id, "original quote")
        _integer(self.quote_version, "quote version", positive=True)
        _time(self.quote_deadline_utc, "original quote deadline")
        if (self.state != "settled_actual" or type(self.actual_amounts) is not tuple
                or not self.actual_amounts):
            raise ValueError("actual D02 settlement receipt required")
        seen = set()
        for amount in self.actual_amounts:
            if type(amount) is not tuple or len(amount) != 2:
                raise ValueError("actual D02 amount pair differs")
            dimension, value = amount
            _id(dimension, "cost dimension")
            _integer(value, "actual cost")
            if dimension in seen:
                raise ValueError("actual D02 cost dimensions repeat")
            seen.add(dimension)


@dataclass(frozen=True, slots=True)
class CorrectionJobOutboxSettlementV1:
    correction_operation_id: str
    job_id: str
    job_receipt_ref: str
    job_receipt_digest: str
    outbox_id: str
    outbox_receipt_ref: str
    outbox_receipt_digest: str
    job_state: str = "completed"
    outbox_state: str = "settled"

    def __post_init__(self) -> None:
        for name in ("correction_operation_id", "job_id", "job_receipt_ref",
                     "outbox_id", "outbox_receipt_ref"):
            _id(getattr(self, name), name)
        _digest(self.job_receipt_digest, "D11 job receipt digest")
        _digest(self.outbox_receipt_digest, "D11 outbox receipt digest")
        if self.job_state != "completed" or self.outbox_state != "settled":
            raise ValueError("D11 correction job and outbox must be settled")


@dataclass(frozen=True, slots=True)
class CurrentCorrectionSourceV1:
    source_ref: str
    source_revision: int
    correction_source_ref: str
    correction_source_revision: int
    access_epoch: int
    deletion_epoch: int
    source_access_status: str
    correction_access_status: str

    def __post_init__(self) -> None:
        for name in ("source_ref", "correction_source_ref"):
            AtomKey.from_token(getattr(self, name))
        for name in ("source_revision", "correction_source_revision"):
            _integer(getattr(self, name), name, positive=True)
        for name in ("access_epoch", "deletion_epoch"):
            _integer(getattr(self, name), name)
        if (self.source_access_status not in {"active", "withdrawn"}
                or self.correction_access_status not in {"active", "withdrawn"}):
            raise ValueError("current correction source access status differs")


@dataclass(frozen=True, slots=True)
class ResolvedSourceCorrectionHeadCandidateV1:
    head_key: AtomKey
    expected_head: GraphVersion
    current: CurrentCorrectionSourceV1
    reevaluations: tuple[ReevaluationReceiptRefV1, ...]
    cost: ActualCorrectionCostV1
    d11: CorrectionJobOutboxSettlementV1
    next_value: dict
    proof_digest: str
    status: str = "requires_w01_atomic_receipt_verification"
    schema: str = SCHEMA


@dataclass(frozen=True, slots=True)
class SourceCorrectionResolutionHoldV1:
    reason: str
    status: str = "HOLD"
    schema: str = SCHEMA


def compile_resolved_source_correction_head_v1(
    *, head_key: AtomKey, pending_head: dict, pending_revision: int,
    current: CurrentCorrectionSourceV1,
    reevaluations: tuple[ReevaluationReceiptRefV1, ...],
    cost: ActualCorrectionCostV1 | None,
    d11: CorrectionJobOutboxSettlementV1 | None,
    now_utc: float,
) -> ResolvedSourceCorrectionHeadCandidateV1 | SourceCorrectionResolutionHoldV1:
    """Prepare an untrusted next value; never authenticate its receipt refs."""
    validate_source_correction_head(head_key, pending_head)
    if pending_head["state"] != "pending_reevaluation":
        raise ValueError("resolution requires a pending correction head")
    _integer(pending_revision, "pending head revision", positive=True)
    if type(current) is not CurrentCorrectionSourceV1:
        raise TypeError("typed current source/access snapshot required")
    if type(reevaluations) is not tuple or any(
            type(item) is not ReevaluationReceiptRefV1 for item in reevaluations):
        raise TypeError("typed reevaluation receipt refs required")
    now = _time(now_utc, "resolution time")
    namespace = NamespaceId.from_key(head_key)
    if (current.source_ref != pending_head["source_ref"]
            or current.source_revision != pending_head["source_revision"]
            or current.correction_source_ref != pending_head["correction_source_ref"]
            or any(NamespaceId.from_key(AtomKey.from_token(ref)) != namespace
                   for ref in (current.source_ref, current.correction_source_ref))):
        return SourceCorrectionResolutionHoldV1("current_source_identity_changed")
    if (current.source_access_status != "active"
            or current.correction_access_status != "active"
            or current.access_epoch < pending_head["access_epoch"]
            or current.deletion_epoch < pending_head["deletion_epoch"]):
        return SourceCorrectionResolutionHoldV1("source_access_or_epoch_unavailable")
    by_domain = {item.domain: item for item in reevaluations}
    if (len(by_domain) != len(reevaluations) or set(by_domain) != _DOMAINS):
        return SourceCorrectionResolutionHoldV1("reevaluation_receipts_incomplete")
    if any(item.correction_operation_id != pending_head["operation_id"]
           or item.correction_source_ref != current.correction_source_ref
           for item in reevaluations):
        return SourceCorrectionResolutionHoldV1("reevaluation_identity_changed")
    if cost is None or type(cost) is not ActualCorrectionCostV1:
        return SourceCorrectionResolutionHoldV1("actual_d02_cost_missing")
    if cost.correction_operation_id != pending_head["operation_id"]:
        return SourceCorrectionResolutionHoldV1("original_quote_identity_changed")
    if d11 is None or type(d11) is not CorrectionJobOutboxSettlementV1:
        return SourceCorrectionResolutionHoldV1("d11_settlement_missing")
    if d11.correction_operation_id != pending_head["operation_id"]:
        return SourceCorrectionResolutionHoldV1("d11_settlement_identity_changed")
    evidence = {
        "schema": SCHEMA,
        "current": asdict(current),
        "reevaluations": [asdict(by_domain[domain]) for domain in sorted(_DOMAINS)],
        "actual_d02_cost": asdict(cost),
        "d11_job_outbox": asdict(d11),
    }
    next_value = {
        **pending_head,
        "state": "resolved_reevaluation",
        "access_epoch": current.access_epoch,
        "deletion_epoch": current.deletion_epoch,
        "resolution_schema": SCHEMA,
        "resolution_proof_digest": canonical_digest(evidence),
        "resolved_at_utc": now,
    }
    validate_source_correction_head_transition_v1(
        head_key, pending_head, next_value, expected_revision=pending_revision)
    return ResolvedSourceCorrectionHeadCandidateV1(
        head_key, GraphVersion(head_key, pending_revision), current,
        tuple(by_domain[domain] for domain in sorted(_DOMAINS)), cost, d11,
        next_value,
        canonical_digest(evidence))


def validate_resolved_source_correction_head_candidate_v1(
    candidate: ResolvedSourceCorrectionHeadCandidateV1, *,
    pending_head: dict, pending_revision: int,
) -> None:
    """Recompute the DTO exactly; W01 must still authenticate its receipts."""
    if type(candidate) is not ResolvedSourceCorrectionHeadCandidateV1:
        raise TypeError("typed resolved correction candidate required")
    if (type(candidate.next_value) is not dict
            or "resolved_at_utc" not in candidate.next_value):
        raise ValueError("resolved correction candidate value differs")
    rebuilt = compile_resolved_source_correction_head_v1(
        head_key=candidate.head_key, pending_head=pending_head,
        pending_revision=pending_revision, current=candidate.current,
        reevaluations=candidate.reevaluations, cost=candidate.cost,
        d11=candidate.d11,
        now_utc=candidate.next_value["resolved_at_utc"])
    if rebuilt != candidate:
        raise ValueError("resolved correction candidate differs from pending head")


__all__ = (
    "SCHEMA", "ReevaluationReceiptRefV1", "ActualCorrectionCostV1",
    "CorrectionJobOutboxSettlementV1", "CurrentCorrectionSourceV1",
    "ResolvedSourceCorrectionHeadCandidateV1", "SourceCorrectionResolutionHoldV1",
    "compile_resolved_source_correction_head_v1",
    "validate_resolved_source_correction_head_candidate_v1",
)
