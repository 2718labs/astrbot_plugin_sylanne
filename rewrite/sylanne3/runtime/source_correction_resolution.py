"""Fail-closed W01 preflight for a D06 source-correction resolution.

Only graph/authority rows read in the caller's pinned transaction contribute
to this snapshot. No current implementation issues durable D04/D05/D07
reevaluation, D02 actual-cost, and D11 completion/outbox receipts. Therefore
this module deliberately has no resolved-head write or caller-receipt input.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3

from ..domains.d06 import source_correction_head_key, validate_source_correction_head
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import access_key
from ..runtime_contracts import NamespaceId
from ..domains.d06.source_correction_resolution import CurrentCorrectionSourceV1


class SourceCorrectionResolutionHold(RuntimeError):
    """The correction barrier must remain pending."""


@dataclass(frozen=True, slots=True)
class SourceCorrectionResolutionPreflightV1:
    head: GraphVersion
    pending_head: dict
    current: CurrentCorrectionSourceV1
    status: str = "HOLD"
    missing_authorities: tuple[str, ...] = (
        "d04_reevaluation_receipt", "d05_reevaluation_receipt",
        "d07_reevaluation_receipt", "d02_actual_cost_receipt",
        "d11_job_outbox_settlement_receipt", "w01_atomic_commit",
    )


def _atom(db: sqlite3.Connection, namespace: NamespaceId,
          key: AtomKey) -> tuple[int, dict]:
    if NamespaceId.from_key(key) != namespace:
        raise SourceCorrectionResolutionHold("correction atom crosses namespace; HOLD")
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms "
        "WHERE token=? AND bot=? AND persona=?",
        (key.token, *namespace.as_tuple),
    ).fetchone()
    if row is None or row[2] != 1 or type(row[0]) is not int or row[0] < 1:
        raise SourceCorrectionResolutionHold("current correction atom unavailable; HOLD")
    try:
        value = json.loads(row[1])
    except (TypeError, ValueError) as exc:
        raise SourceCorrectionResolutionHold("current correction atom invalid; HOLD") from exc
    if type(value) is not dict:
        raise SourceCorrectionResolutionHold("current correction atom invalid; HOLD")
    return row[0], value


def read_source_correction_resolution_preflight(
        db: sqlite3.Connection, namespace: NamespaceId, source_id: str,
) -> SourceCorrectionResolutionPreflightV1:
    """Re-read current facts under a transaction; never accept a receipt DTO.

    The coordinator must use an Authority V2 read fence before this read and
    repeat it under the future write fence. This preflight cannot lift a head.
    """
    if not db.in_transaction:
        raise SourceCorrectionResolutionHold("resolution needs pinned transaction; HOLD")
    if type(namespace) is not NamespaceId:
        raise TypeError("typed namespace required")
    head_key = source_correction_head_key(namespace, source_id)
    head_revision, head = _atom(db, namespace, head_key)
    try:
        validate_source_correction_head(head_key, head)
    except (TypeError, ValueError) as exc:
        raise SourceCorrectionResolutionHold("current correction head invalid; HOLD") from exc
    if head["state"] != "pending_reevaluation":
        raise SourceCorrectionResolutionHold("correction head is not pending; HOLD")
    source_key = AtomKey.from_token(head["source_ref"])
    correction_key = AtomKey.from_token(head["correction_source_ref"])
    source_revision, source = _atom(db, namespace, source_key)
    correction_revision, correction = _atom(db, namespace, correction_key)
    _, source_access = _atom(db, namespace, access_key(
        *namespace.as_tuple, source_key.owner.subject))
    _, correction_access = _atom(db, namespace, access_key(
        *namespace.as_tuple, correction_key.owner.subject))
    epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if (source_revision != head["source_revision"]
            or source.get("source_id") != source_key.owner.subject
            or correction.get("source_id") != correction_key.owner.subject
            or source_access.get("source_id") != source_key.owner.subject
            or correction_access.get("source_id") != correction_key.owner.subject
            or source_access.get("status") != "active"
            or correction_access.get("status") != "active"
            or epochs is None or len(epochs) != 2
            or type(epochs[0]) is not int or type(epochs[1]) is not int
            or epochs[0] < head["access_epoch"]
            or epochs[1] < head["deletion_epoch"]):
        raise SourceCorrectionResolutionHold("current source access or epoch changed; HOLD")
    current = CurrentCorrectionSourceV1(
        source_key.token, source_revision, correction_key.token,
        correction_revision, epochs[0], epochs[1], "active", "active",
    )
    return SourceCorrectionResolutionPreflightV1(
        GraphVersion(head_key, head_revision), head, current)


def plan_source_correction_resolution_v1(
        preflight: SourceCorrectionResolutionPreflightV1,
) -> None:
    """Explicit HOLD until every receipt has a durable trusted verifier.

    A caller-provided candidate or receipt cannot satisfy this boundary.
    """
    if type(preflight) is not SourceCorrectionResolutionPreflightV1:
        raise TypeError("typed W01 preflight required")
    raise SourceCorrectionResolutionHold(
        "reevaluation, actual cost and D11 settlement issuers absent; HOLD")


__all__ = (
    "SourceCorrectionResolutionHold", "SourceCorrectionResolutionPreflightV1",
    "read_source_correction_resolution_preflight",
    "plan_source_correction_resolution_v1",
)
