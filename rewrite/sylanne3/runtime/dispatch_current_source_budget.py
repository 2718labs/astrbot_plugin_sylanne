"""Current D06 source and D11 reservation read for future final dispatch authority."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math

from ..graph_types import AtomKey
from ..memory_types import access_key, source_key
from ..runtime_contracts import NamespaceId, canonical_digest
from .budget import get_budget_lease
from .dispatch_admission import load_admission


class CurrentDispatchHold(RuntimeError):
    """The durable admission cannot be reused against current graph/ledger state."""


@dataclass(frozen=True)
class CurrentSourceBudgetV1:
    admission_ref: str
    candidate_digest: str
    source_proof_digest: str
    budget_reservation_digest: str
    access_epoch: int
    delete_epoch: int


def read_current_source_budget(
    db, namespace: NamespaceId, admission_ref: str, *, now_utc: float,
) -> CurrentSourceBudgetV1:
    """Read a current subset under the caller's SQLite write transaction.

    This is never a claim, permit, or authority to hand off. The caller must
    keep its write transaction open through its own final decision.
    """
    if not db.in_transaction:
        raise CurrentDispatchHold("current dispatch needs a held business transaction")
    if type(now_utc) not in (int, float) or not math.isfinite(now_utc):
        raise CurrentDispatchHold("current dispatch clock is invalid")
    receipt = load_admission(db, namespace, admission_ref)
    if receipt is None:
        raise CurrentDispatchHold("durable dispatch admission is absent")
    admission = receipt.admission
    try:
        admission.require_current(now_utc)
    except ValueError as exc:
        raise CurrentDispatchHold("dispatch admission expired") from exc
    row = db.execute(
        "SELECT receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (admission.operation_id,),
    ).fetchone()
    if row is None:
        raise CurrentDispatchHold("candidate operation is absent")
    candidate = json.loads(row[0]).get("dispatch_candidate")
    if (type(candidate) is not dict or candidate.get("status") != "source_qualified"
            or candidate.get("digest") != admission.candidate_digest
            or candidate.get("source_audience") != list(admission.audience)
            or type(candidate.get("source_refs")) is not list
            or type(candidate.get("source_proof_versions")) is not list):
        raise CurrentDispatchHold("admission lacks its qualified D06 candidate")
    epoch_row = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if (epoch_row or (0, 0)) != (admission.access_epoch, admission.delete_epoch):
        raise CurrentDispatchHold("D06 access or delete epoch moved")
    proof = []
    for item in candidate["source_proof_versions"]:
        if (type(item) is not list or len(item) != 2
                or type(item[0]) is not str or type(item[1]) is not int
                or item[1] < 1):
            raise CurrentDispatchHold("D06 proof version is invalid")
        key = AtomKey.from_token(item[0])
        if (key.owner.bot, key.owner.persona) != namespace.as_tuple or key.type_name not in {
                "memory.source", "memory.access"}:
            raise CurrentDispatchHold("D06 proof key is outside source/access scope")
        current = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (item[0],),
        ).fetchone()
        if current is None or current[0] != item[1] or current[2] != 1:
            raise CurrentDispatchHold("D06 source or access changed")
        proof.append((item[0], item[1], canonical_digest(json.loads(current[1]))))
    if (not proof or candidate.get("source_proof_digest") != canonical_digest(proof)):
        raise CurrentDispatchHold("D06 source proof digest changed")
    covered = {ref for ref, _, _ in proof}
    for ref in candidate["source_refs"]:
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise CurrentDispatchHold("D06 candidate source identity changed")
        if ref not in covered or access_key(
                *namespace.as_tuple, key.owner.subject or "").token not in covered:
            raise CurrentDispatchHold("D06 candidate source or access is not proven")
    lease = get_budget_lease(db, admission.budget_lease_ref)
    reservation = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (admission.budget_lease_ref, admission.budget_reservation_operation_id),
    ).fetchone()
    if (lease.state != "active" or lease.version != admission.budget_version
            or lease.currency != admission.budget_currency
            or (lease.bot_id, lease.persona_id) != namespace.as_tuple
            or reservation is None or reservation[0] != admission.budget_reservation_digest
            or reservation[2] != "reserved"
            or json.loads(reservation[1]) != dict(admission.budget_ceiling)
            or any(lease.reserved.get(key, 0) < amount
                   for key, amount in admission.budget_ceiling.items())):
        raise CurrentDispatchHold("D11 budget reservation changed")
    return CurrentSourceBudgetV1(
        admission_ref, admission.candidate_digest, candidate["source_proof_digest"],
        admission.budget_reservation_digest, admission.access_epoch,
        admission.delete_epoch,
    )


__all__ = ["CurrentDispatchHold", "CurrentSourceBudgetV1", "read_current_source_budget"]
