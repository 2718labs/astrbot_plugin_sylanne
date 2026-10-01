"""Durable, exact graph original for one C04 association execution.

Only W01's fenced graph transaction may record this row.  The row itself is
not a D04 salience issuer, an Authority claim, or execution permission.
"""

from __future__ import annotations

import sqlite3

from ..authority_service.internal_work_contract import InternalWorkBindingV1
from ..domains.d06.c04_work_input_v2 import AssociationWorkInputV2
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1


def _transaction(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise RuntimeError("C04 frozen input needs a caller-owned graph transaction")


def install_c04_frozen_association_original_v2(db: sqlite3.Connection) -> None:
    _transaction(db)
    db.execute("""CREATE TABLE IF NOT EXISTS graph_c04_association_inputs_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        binding_digest TEXT NOT NULL, input_digest TEXT NOT NULL,
        algorithm_build_digest TEXT NOT NULL, work_json TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id),
        UNIQUE(bot,persona,binding_digest))""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS
            graph_c04_association_input_no_{action.lower()}_v2
            BEFORE {action} ON graph_c04_association_inputs_v2
            BEGIN SELECT RAISE(ABORT, 'C04 frozen input is immutable'); END""")


def verify_current_association_input_heads_v2(
    db: sqlite3.Connection, work: AssociationWorkInputV2,
) -> None:
    """Check full original bytes, explicit absence and bounded edge coverage."""
    _transaction(db)
    if type(work) is not AssociationWorkInputV2:
        raise TypeError("typed frozen association work required")
    namespace = work.namespace
    for read in work.reads:
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms "
            "WHERE token=? AND bot=? AND persona=?",
            (read.key.token, *namespace.as_tuple),
        ).fetchone()
        if read.revision == 0:
            if row is not None:
                raise ValueError("frozen absent graph head appeared")
        elif row != (read.revision, read.value_json, int(read.valid)):
            raise ValueError("frozen graph original changed")
    for query in work.edge_queries:
        source = AtomKey.from_token(query.source_ref)
        rows = db.execute(
            "SELECT token FROM graph_atoms WHERE bot=? AND persona=? "
            "AND owner_kind='event' AND subject=? "
            "AND type_name='memory.association.v1' ORDER BY token LIMIT ?",
            (*namespace.as_tuple, source.owner.subject, work.budget.max_edges + 1),
        ).fetchall()
        actual = tuple(row[0] for row in rows)
        expected = tuple(sorted(query.edge_refs))
        if query.next_after is None:
            if actual != expected:
                raise ValueError("frozen association page changed")
        elif (query.next_after != expected[-1]
              or actual[:len(expected)] != expected
              or len(actual) <= len(expected)):
            raise ValueError("frozen association continuation changed")


def record_c04_frozen_association_original_v2(
    db: sqlite3.Connection, namespace: NamespaceId,
    binding: InternalWorkBindingV1, work: AssociationWorkInputV2,
) -> AssociationWorkInputV2:
    """Insert once after the exact prepared binding and graph heads are proven."""
    _transaction(db)
    if (type(namespace) is not NamespaceId
            or type(binding) is not InternalWorkBindingV1
            or type(work) is not AssociationWorkInputV2):
        raise TypeError("typed C04 binding and association input required")
    from ..graph_coordinator import namespace_ref

    prepared = read_c04_internal_work_prepared_v1(
        db, namespace, binding.operation_id)
    if (prepared is None or prepared.binding != binding
            or work.namespace != namespace
            or namespace_ref(namespace) != binding.namespace
            or (work.activity_id, work.operation_id)
               != (binding.activity_id, binding.operation_id)
            or work.algorithm_id != binding.algorithm_ref
            or work.input_digest != "sha256:" + binding.input_digest
            or binding.algorithm_build_digest is None):
        raise ValueError("C04 frozen input differs from prepared original")
    epoch = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if epoch != (work.graph_epoch.revision,):
        raise ValueError("C04 frozen input observation epoch changed")
    verify_current_association_input_heads_v2(db, work)
    row = (binding.binding_digest, binding.input_digest,
           binding.algorithm_build_digest, work.to_json())
    key = (*namespace.as_tuple, binding.operation_id)
    prior = db.execute(
        "SELECT binding_digest,input_digest,algorithm_build_digest,work_json "
        "FROM graph_c04_association_inputs_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?", key,
    ).fetchone()
    if prior is not None and prior != row:
        raise ValueError("C04 frozen input changed on operation replay")
    if prior is None:
        db.execute("INSERT INTO graph_c04_association_inputs_v2 VALUES(?,?,?,?,?,?,?)",
                   (*key, *row))
    return work


def read_c04_frozen_association_original_v2(
    db: sqlite3.Connection, namespace: NamespaceId,
    binding: InternalWorkBindingV1,
) -> AssociationWorkInputV2 | None:
    """Recover original bytes; the caller still owns the current Owner fence."""
    _transaction(db)
    if type(namespace) is not NamespaceId or type(binding) is not InternalWorkBindingV1:
        raise TypeError("typed C04 namespace and binding required")
    row = db.execute(
        "SELECT binding_digest,input_digest,algorithm_build_digest,work_json "
        "FROM graph_c04_association_inputs_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, binding.operation_id),
    ).fetchone()
    if row is None:
        return None
    work = AssociationWorkInputV2.from_json(row[3])
    from ..graph_coordinator import namespace_ref

    prepared = read_c04_internal_work_prepared_v1(
        db, namespace, binding.operation_id)
    if (prepared is None or prepared.binding != binding
            or row[:3] != (binding.binding_digest, binding.input_digest,
                           binding.algorithm_build_digest)
            or work.namespace != namespace
            or namespace_ref(namespace) != binding.namespace
            or (work.activity_id, work.operation_id, work.algorithm_id)
               != (binding.activity_id, binding.operation_id, binding.algorithm_ref)
            or work.input_digest != "sha256:" + binding.input_digest):
        raise ValueError("C04 frozen input identity changed")
    verify_current_association_input_heads_v2(db, work)
    return work


__all__ = [
    "install_c04_frozen_association_original_v2",
    "record_c04_frozen_association_original_v2",
    "read_c04_frozen_association_original_v2",
    "verify_current_association_input_heads_v2",
]
