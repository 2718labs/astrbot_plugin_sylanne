"""Actual Authority SQLite state shared by live and pre-Core C09 readers."""
from __future__ import annotations

from .contract import AuthorityUnavailable
from ..runtime.restore_anchor import RestoreAnchor


def authority_id_in_tx_v1(db):
    if not db.in_transaction:
        raise AuthorityUnavailable("C09 state requires pinned Authority transaction")
    row = db.execute("SELECT value FROM authority_meta WHERE key='authority_id'").fetchone()
    if row is None:
        raise AuthorityUnavailable("Authority identity original absent")
    return row[0]


def namespace_row_in_tx_v1(db, namespace):
    authority_id_in_tx_v1(db)
    row = db.execute(
        "SELECT holder,generation,phase,transfer_id,target,revocation_epoch,"
        "deletion_journal_id,deletion_seq,deletion_digest,deletion_phase,"
        "execution_journal_id,execution_seq,execution_digest,anchor_nonce "
        "FROM authority_namespaces WHERE namespace=?", (namespace,)).fetchone()
    if row is None:
        raise AuthorityUnavailable("namespace is not registered")
    return row


def anchor_in_tx_v1(db, namespace, row=None):
    row = namespace_row_in_tx_v1(db, namespace) if row is None else row
    return RestoreAnchor(authority_id_in_tx_v1(db), namespace, row[1],
                         row[6], row[7], row[8], row[10], row[11], row[12],
                         row[5], row[13])
