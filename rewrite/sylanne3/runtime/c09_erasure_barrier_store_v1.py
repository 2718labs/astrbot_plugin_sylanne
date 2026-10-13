"""Atomic graph-side storage for a C09 deletion barrier.

This module records a graph mutation already admitted by W01. It does not
authenticate an Owner request, an Authority deletion pending receipt, or a
complete cross-domain erasure closure. The public coordinator must establish
those facts before calling it from the GraphStore receipt hook.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
import sqlite3

from ..graph_types import (AtomKey, GraphReceipt, GraphVersion, NamespaceEpoch)
from ..memory_types import SourceRecord, access_key, source_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


_HEX = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class C09GraphBarrierReceiptV1:
    namespace: NamespaceId
    operation_id: str
    request_digest: str
    pending_receipt_digest: str
    closure_digest: str
    root_source_refs: tuple[str, ...]
    affected_source_refs: tuple[str, ...]
    graph_incarnation: str
    graph_epoch_before: int
    graph_epoch_after: int
    access_epoch_before: int
    access_epoch_after: int
    delete_epoch_before: int
    delete_epoch_after: int
    event_session: str
    graph_event_digest: str
    graph_receipt_digest: str
    schema: str = "sylanne3.graph.c09_erasure_barrier.v1"

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or type(self.operation_id) is not str or not self.operation_id
                or type(self.graph_incarnation) is not str
                or not self.graph_incarnation
                or type(self.event_session) is not str or not self.event_session
                or self.schema != "sylanne3.graph.c09_erasure_barrier.v1"):
            raise ValueError("C09 graph barrier identity is invalid")
        for name in ("request_digest", "pending_receipt_digest",
                     "closure_digest", "graph_event_digest",
                     "graph_receipt_digest"):
            if type(getattr(self, name)) is not str or not _HEX.fullmatch(
                    getattr(self, name)):
                raise ValueError("C09 graph barrier digest is invalid")
        for name in ("graph_epoch_before", "access_epoch_before",
                     "delete_epoch_before"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError("C09 graph barrier epoch is invalid")
        if (self.graph_epoch_after != self.graph_epoch_before + 1
                or self.access_epoch_after != self.access_epoch_before + 1
                or self.delete_epoch_after != self.delete_epoch_before + 1):
            raise ValueError("C09 graph barrier must advance each epoch once")
        roots = self.root_source_refs
        affected = self.affected_source_refs
        if (type(roots) is not tuple or type(affected) is not tuple
                or not roots or not affected
                or tuple(sorted(set(roots))) != roots
                or tuple(sorted(set(affected))) != affected
                or not set(roots).issubset(affected)):
            raise ValueError("C09 source closure is not canonical")
        for token in affected:
            key = AtomKey.from_token(token)
            if (key.type_name != "memory.source" or key.owner.kind != "event"
                    or key.name != "record"
                    or (key.owner.bot, key.owner.persona)
                       != self.namespace.as_tuple
                    or key != source_key(*self.namespace.as_tuple,
                                         key.owner.subject)):
                raise ValueError("C09 source closure crosses namespace or type")


def install_c09_erasure_barrier_store_v1(db: sqlite3.Connection) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS graph_c09_erasure_barriers_v1 (
            bot TEXT NOT NULL, persona TEXT NOT NULL,
            operation_id TEXT NOT NULL, receipt_json TEXT NOT NULL,
            PRIMARY KEY (bot, persona, operation_id)
        )
    """)
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""
            CREATE TRIGGER IF NOT EXISTS graph_c09_erasure_barriers_v1_{action.lower()}_immutable
            BEFORE {action} ON graph_c09_erasure_barriers_v1
            BEGIN SELECT RAISE(ABORT, 'C09 graph barrier is immutable'); END
        """)


def read_c09_erasure_barrier_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
) -> C09GraphBarrierReceiptV1 | None:
    row = db.execute(
        "SELECT receipt_json FROM graph_c09_erasure_barriers_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone()
    if row is None:
        return None
    raw = json.loads(row[0])
    if type(raw) is not dict or type(raw.get("namespace")) is not dict:
        raise ValueError("C09 graph barrier original is unreadable")
    raw["namespace"] = NamespaceId(**raw["namespace"])
    raw["root_source_refs"] = tuple(raw["root_source_refs"])
    raw["affected_source_refs"] = tuple(raw["affected_source_refs"])
    receipt = C09GraphBarrierReceiptV1(**raw)
    if (receipt.namespace != namespace or receipt.operation_id != operation_id
            or canonical_serialize(asdict(receipt)) != row[0]):
        raise ValueError("C09 graph barrier original differs")
    return receipt


def record_c09_erasure_barrier_after_graph_v1(
    db: sqlite3.Connection, namespace: NamespaceId, *,
    operation_id: str, request_digest: str, pending_receipt_digest: str,
    closure_digest: str, root_source_refs: tuple[str, ...],
    affected_source_refs: tuple[str, ...], graph_incarnation: str,
    graph_epoch_before: int, access_epoch_before: int,
    delete_epoch_before: int, event_session: str,
    graph_receipt: GraphReceipt,
) -> C09GraphBarrierReceiptV1:
    """Run inside the exact graph receipt hook and caller-owned write tx.

    All affected source access atoms must have just been rewritten as revoked.
    The caller still proves closure completeness and the Authority pending.
    """
    if (not isinstance(db, sqlite3.Connection) or not db.in_transaction
            or type(graph_receipt) is not GraphReceipt
            or graph_receipt.status != "committed"
            or graph_receipt.epoch.revision != graph_epoch_before + 1
            or (graph_receipt.epoch.bot, graph_receipt.epoch.persona)
               != namespace.as_tuple):
        raise ValueError("C09 barrier requires committed same-transaction graph write")
    event = db.execute(
        "SELECT digest,epoch_revision FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, event_session, operation_id),
    ).fetchone()
    if event is None or event[1] != graph_receipt.epoch.revision:
        raise ValueError("C09 graph event is absent or has another epoch")
    receipt = C09GraphBarrierReceiptV1(
        namespace, operation_id, request_digest, pending_receipt_digest,
        closure_digest, root_source_refs, affected_source_refs,
        graph_incarnation, graph_epoch_before, graph_receipt.epoch.revision,
        access_epoch_before, access_epoch_before + 1,
        delete_epoch_before, delete_epoch_before + 1,
        event_session, event[0], canonical_digest(graph_receipt),
    )
    try:
        prior = read_c09_erasure_barrier_v1(db, namespace, operation_id)
    except sqlite3.OperationalError as exc:
        raise ValueError("C09 immutable barrier schema is unavailable") from exc
    if prior is not None:
        if prior != receipt:
            raise ValueError("C09 barrier operation replay differs")
        return prior
    written = {version.key: version.revision for version in graph_receipt.revisions}
    for token in affected_source_refs:
        source = AtomKey.from_token(token)
        key = access_key(*namespace.as_tuple, source.owner.subject)
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?", (key.token, *namespace.as_tuple),
        ).fetchone()
        if (row is None or row[2] != 1 or written.get(key) != row[0]
                or json.loads(row[1]).get("status") != "withdrawn"):
            raise ValueError("C09 source access was not revoked in this graph event")
    current = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if current != (graph_epoch_before + 1,):
        raise ValueError("C09 graph epoch differs from committed event")
    changed = db.execute(
        "UPDATE graph_authority_epochs SET access_epoch=?,delete_epoch=? "
        "WHERE bot=? AND persona=? AND access_epoch=? AND delete_epoch=?",
        (access_epoch_before + 1, delete_epoch_before + 1,
         *namespace.as_tuple, access_epoch_before, delete_epoch_before),
    ).rowcount
    if changed != 1:
        raise ValueError("C09 authority epoch CAS failed")
    db.execute(
        "INSERT INTO graph_c09_erasure_barriers_v1 VALUES(?,?,?,?)",
        (*namespace.as_tuple, operation_id,
         canonical_serialize(asdict(receipt))),
    )
    return receipt


def verify_c09_graph_barrier_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
    *, request_digest: str, pending_receipt_digest: str,
) -> C09GraphBarrierReceiptV1 | None:
    """Independently reread one current graph barrier and its source closure.

    The caller must obtain the expected pending digest from the live Authority
    pending reader. This local verifier cannot authenticate that Authority fact.
    """
    receipt = read_c09_erasure_barrier_v1(db, namespace, operation_id)
    if receipt is None:
        return None
    if ((receipt.request_digest, receipt.pending_receipt_digest)
            != (request_digest, pending_receipt_digest)):
        raise ValueError("C09 barrier differs from Authority pending original")
    event = db.execute(
        "SELECT digest,revisions,invalidated,epoch_revision FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, receipt.event_session, operation_id),
    ).fetchone()
    if (event is None or event[0] != receipt.graph_event_digest
            or event[3] != receipt.graph_epoch_after):
        raise ValueError("C09 barrier graph event differs")
    revisions = tuple(GraphVersion(AtomKey.from_token(token), revision)
                      for token, revision in json.loads(event[1]))
    invalidated = tuple(GraphVersion(AtomKey.from_token(token), revision)
                        for token, revision in json.loads(event[2]))
    graph_receipt = GraphReceipt(
        "committed", revisions, invalidated,
        NamespaceEpoch(*namespace.as_tuple, receipt.graph_epoch_after),
    )
    if canonical_digest(graph_receipt) != receipt.graph_receipt_digest:
        raise ValueError("C09 barrier graph receipt differs")
    epoch = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    rights = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if (epoch != (receipt.graph_epoch_after,)
            or rights != (receipt.access_epoch_after,
                          receipt.delete_epoch_after)):
        raise ValueError("C09 barrier is not the current graph/rights head")
    sources = {}
    for token, value, valid in db.execute(
            "SELECT token,value,valid FROM graph_atoms "
            "WHERE bot=? AND persona=? AND type_name='memory.source'",
            namespace.as_tuple):
        if valid != 1:
            continue
        key = AtomKey.from_token(token)
        record = SourceRecord.from_dict(json.loads(value))
        if key != source_key(*namespace.as_tuple, record.source_id):
            raise ValueError("C09 source identity differs")
        sources[token] = record
    affected = set(receipt.root_source_refs)
    if not affected.issubset(sources):
        raise ValueError("C09 root source is absent")
    while True:
        expanded = affected | {
            token for token, record in sources.items()
            if any(source_key(*namespace.as_tuple, parent).token in affected
                   for parent in record.parent_source_ids)
        }
        if expanded == affected:
            break
        affected = expanded
    if tuple(sorted(affected)) != receipt.affected_source_refs:
        raise ValueError("C09 source descendant closure differs")
    written = {version.key.token: version.revision for version in revisions}
    for token in receipt.affected_source_refs:
        source = AtomKey.from_token(token)
        access = access_key(*namespace.as_tuple, source.owner.subject)
        head = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (access.token,),
        ).fetchone()
        historical = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
            (access.token, written.get(access.token), *namespace.as_tuple,
             receipt.event_session, operation_id),
        ).fetchone()
        if (head is None or head[2] != 1
                or head[0] != written.get(access.token)
                or historical != (head[1], 1)
                or json.loads(head[1]).get("status") != "withdrawn"):
            raise ValueError("C09 current access revocation lacks event history")
    return receipt


__all__ = [
    "C09GraphBarrierReceiptV1", "install_c09_erasure_barrier_store_v1",
    "read_c09_erasure_barrier_v1", "record_c09_erasure_barrier_after_graph_v1",
    "verify_c09_graph_barrier_v1",
]



SOURCE_BARRIER_ORIGINAL_DDL_V2 = 'CREATE TABLE graph_c09_erasure_barriers_v2 (bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,receipt_json TEXT NOT NULL,PRIMARY KEY(bot,persona,operation_id))'


def install_c09_erasure_barrier_store_v2(db):
    db.execute(SOURCE_BARRIER_ORIGINAL_DDL_V2.replace("CREATE TABLE ","CREATE TABLE IF NOT EXISTS ",1))
    for action in ("UPDATE","DELETE"):
        db.execute("CREATE TRIGGER IF NOT EXISTS graph_c09_erasure_barriers_v2_"+action.lower()+"_immutable BEFORE "+action+" ON graph_c09_erasure_barriers_v2 BEGIN SELECT RAISE(ABORT,'C09 V2 Source barrier immutable'); END")


def read_c09_erasure_barrier_v2(db,namespace,operation_id):
    from .c09_source_plan_barrier_v2 import C09GraphBarrierReceiptV2
    row=db.execute('SELECT receipt_json FROM graph_c09_erasure_barriers_v2 WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    if row is None:return None
    original=C09GraphBarrierReceiptV2.from_wire(json.loads(row[0]))
    if original.namespace!=namespace or original.operation_id!=operation_id or canonical_serialize(asdict(original))!=row[0]:
        raise ValueError('C09 V2 barrier original canonical identity differs')
    return original


def record_c09_erasure_barrier_complete_v2(db,receipt,*,plan):
    from .c09_source_plan_barrier_v2 import C09GraphBarrierReceiptV2,read_c09_source_work_v2,require_c09_source_stamp_v2
    if not db.in_transaction or type(receipt) is not C09GraphBarrierReceiptV2 or receipt.plan_digest!=plan.digest:
        raise ValueError('C09 V2 completed Source barrier requires actual transaction and plan')
    state=read_c09_source_work_v2(db,receipt.namespace,receipt.operation_id)
    require_c09_source_stamp_v2(db,receipt.namespace,state)
    if (state['phase']!='barrier_complete' or not state.get('recovery_closed') or state['barrier_count']!=receipt.affected_count
            or state['verify_count']!=receipt.withdrawn_count or state['verify_root']!=receipt.withdrawn_root
            or state['barrier_pages']!=receipt.page_count or state['barrier_page_root']!=receipt.page_root):
        raise ValueError('C09 V2 barrier has no completed actual EOF/page/history sweep')
    prior=read_c09_erasure_barrier_v2(db,receipt.namespace,receipt.operation_id)
    if prior is not None:
        if prior!=receipt:raise ValueError('C09 V2 Source barrier replay differs')
        return prior
    db.execute('INSERT INTO graph_c09_erasure_barriers_v2 VALUES(?,?,?,?)',(*receipt.namespace.as_tuple,receipt.operation_id,canonical_serialize(asdict(receipt))))
    return receipt


def read_c09_erasure_barrier_versioned_v2(db,namespace,operation_id):
    new=read_c09_erasure_barrier_v2(db,namespace,operation_id)
    old=read_c09_erasure_barrier_v1(db,namespace,operation_id)
    if new is not None and old is not None:raise ValueError('C09 operation has two barrier versions')
    return new if new is not None else old
