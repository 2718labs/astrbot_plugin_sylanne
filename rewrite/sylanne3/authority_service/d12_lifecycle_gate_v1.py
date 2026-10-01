"""Durable installation lifecycle epoch inside the existing Authority Core.

Shared callers invoke this in the SAME transaction as a new admission/claim.
An original-claimed exception must come from their own persisted claim lookup,
never from RPC JSON. Business activation generation is deliberately unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass

from .contract import AuthorityUnavailable

HEAD_TABLE = "authority_d12_lifecycle_heads_v1"
HEAD_DDL = """CREATE TABLE IF NOT EXISTS authority_d12_lifecycle_heads_v1(
 namespace TEXT PRIMARY KEY, installation_id TEXT NOT NULL, state TEXT NOT NULL,
 epoch INTEGER NOT NULL, operation_id TEXT, head_digest TEXT NOT NULL,
 current_receipt_ref TEXT)"""


@dataclass(frozen=True, slots=True)
class D12LifecycleAdmissionV1:
    namespace: str
    installation_id: str
    epoch: int
    state: str
    operation_id: str | None
    head_digest: str


def read_lifecycle_head_in_tx_v1(db, namespace):
    if not db.in_transaction:
        raise AuthorityUnavailable("lifecycle admission requires the current Core transaction")
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (HEAD_TABLE,)).fetchone() is None:
        return None
    row = db.execute("SELECT installation_id,state,epoch,operation_id,head_digest FROM " + HEAD_TABLE + " WHERE namespace=?",
                     (namespace,)).fetchone()
    if row is None:
        return None
    if (row[1] not in {"active", "quiescing", "drained", "paused", "resuming"}
            or type(row[2]) is not int or row[2] < 0):
        raise AuthorityUnavailable("installed lifecycle head is malformed")
    return D12LifecycleAdmissionV1(namespace, row[0], row[2], row[1], row[3], row[4])


def require_lifecycle_admission_in_tx_v1(db, namespace, *, action,
                                        original_claimed=False, bootstrap=False,
                                        expected_epoch=None):
    """Return the actual current epoch, or deny before a new effect is granted.

    No configured lifecycle head means this optional controller is absent.
    It does not manufacture a controller or advertise pause/resume support.
    """
    head = read_lifecycle_head_in_tx_v1(db, namespace)
    if head is None:
        if expected_epoch is not None:
            raise AuthorityUnavailable("expected installed lifecycle epoch is absent")
        return None
    if expected_epoch is not None and expected_epoch != head.epoch:
        raise AuthorityUnavailable("installed lifecycle admission epoch changed")
    if action in {"lifecycle_status", "lifecycle_control"}:
        return head
    if head.state == "active":
        return head
    if original_claimed is True and action in {"terminal", "accounting", "original_inspection"}:
        return head
    if bootstrap is True and head.state == "resuming" and action in {
            "host_bootstrap", "recovery_read", "recovery_accounting"}:
        return head
    raise AuthorityUnavailable("installation lifecycle " + head.state + " denies new " + action)


def require_lifecycle_exclusion_in_tx_v1(db, namespace, *, operation):
    """C09/migration/upgrade/revoke must not bypass a running host control."""
    head = read_lifecycle_head_in_tx_v1(db, namespace)
    if head is not None and head.state != "active":
        raise AuthorityUnavailable("lifecycle " + head.state + " excludes " + operation)
    return head


__all__ = ("HEAD_TABLE", "HEAD_DDL", "D12LifecycleAdmissionV1", "read_lifecycle_head_in_tx_v1",
           "require_lifecycle_admission_in_tx_v1", "require_lifecycle_exclusion_in_tx_v1")
