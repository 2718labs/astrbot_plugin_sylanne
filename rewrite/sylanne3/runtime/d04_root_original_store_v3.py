"""Immutable authored-lineage V3 root original in the root graph transaction."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import sqlite3

from ..contracts import canonical_json
from ..domains.d04.authored_lineage_v3 import (
    AuthoredRootCandidateV3, AuthoredRootWritesCandidateV3,
    AuthoredInitialBoxProofV3, authored_root_write_rows_v3,
    encode_authored_root_candidate_v3,
)
from ..graph_types import AtomKey, GraphReceipt
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d11_d04_root_freeze_v3 import D11RootFreezeOriginalV3


class D04RootOriginalV3Hold(ValueError):
    """The V3 root original or its committed graph history differs."""


@dataclass(frozen=True, slots=True)
class D04RootOriginalV3:
    namespace: NamespaceId
    operation_id: str
    candidate_json: str
    initial_box_json: str
    output_json: str
    signed_freeze_digest: str
    graph_event_digest: str
    graph_receipt_digest: str
    write_set_digest: str
    original_digest: str
    status: str = "authored_root_committed_no_observed_sources"


def install_d04_root_original_store_v3(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or db.in_transaction:
        raise D04RootOriginalV3Hold("V3 root schema needs an idle connection")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS graph_d04_root_originals_v3(
            bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
            original_json TEXT NOT NULL, original_digest TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS graph_d04_root_original_no_update_v3
          BEFORE UPDATE ON graph_d04_root_originals_v3
          BEGIN SELECT RAISE(ABORT, 'D04 V3 root original is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_d04_root_original_no_delete_v3
          BEFORE DELETE ON graph_d04_root_originals_v3
          BEGIN SELECT RAISE(ABORT, 'D04 V3 root original is immutable'); END;
    """)


def _body(original: D04RootOriginalV3) -> dict:
    return {name: getattr(original, name) for name in (
        "namespace", "operation_id", "candidate_json", "initial_box_json",
        "output_json", "signed_freeze_digest", "graph_event_digest",
        "graph_receipt_digest", "write_set_digest", "status",
    )}


def _event_and_history(db: sqlite3.Connection, original: D04RootOriginalV3) -> None:
    from .domain_background_read_v3 import background_point_v3,background_history_v3,background_json_loads_v3,background_json_matches_v3
    output = json.loads(original.output_json)
    rows = output.get("rows")
    if (type(rows) is not list or not rows
            or canonical_digest(tuple(tuple(row) for row in rows))
               != original.write_set_digest):
        raise D04RootOriginalV3Hold("V3 root write set differs")
    event=background_point_v3(db,table='graph_events',columns=('digest','revisions','epoch_revision'),
        key_columns=('bot','persona','session','event_id'),key=(*original.namespace.as_tuple,'d04.authored_root.v3',original.operation_id),
        legacy_reader=lambda:db.execute('SELECT digest,revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',
            (*original.namespace.as_tuple,'d04.authored_root.v3',original.operation_id)).fetchone())
    if event is None or event[0] != original.graph_event_digest:
        raise D04RootOriginalV3Hold("V3 root graph event is absent")
    revisions = background_json_loads_v3(event[1])
    if revisions != [[row[0], 1] for row in rows]:
        raise D04RootOriginalV3Hold("V3 root graph revisions differ")
    receipt = {"status": "committed", "revisions": revisions,
               "invalidated": [], "epoch": {
                   "bot": original.namespace.bot_id,
                   "persona": original.namespace.persona_id,
                   "revision": event[2],
               }}
    if canonical_digest(receipt) != original.graph_receipt_digest:
        raise D04RootOriginalV3Hold("V3 root graph receipt differs")
    for ref, revision, value in rows:
        key = AtomKey.from_token(ref)
        if (revision != 1 or key.owner.kind != "persona"
                or NamespaceId.from_key(key) != original.namespace):
            raise D04RootOriginalV3Hold("V3 root address differs")
        history=background_history_v3(db,ref,1,columns=('value','valid','event_bot','event_persona','event_session','event_id'))
        if (history is None or history[1:]!=(1,*original.namespace.as_tuple,'d04.authored_root.v3',original.operation_id)
                or not background_json_matches_v3(history[0],value)):
            raise D04RootOriginalV3Hold("V3 root graph history differs")

def record_d04_root_original_v3(
    db: sqlite3.Connection, *, namespace: NamespaceId, operation_id: str,
    candidate: AuthoredRootCandidateV3, initial_box: AuthoredInitialBoxProofV3,
    output: AuthoredRootWritesCandidateV3, freeze: D11RootFreezeOriginalV3,
    receipt: GraphReceipt,
) -> D04RootOriginalV3:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise D04RootOriginalV3Hold("V3 root original needs the graph transaction")
    if (type(namespace) is not NamespaceId or candidate.namespace != namespace.as_tuple
            or output.candidate_digest != candidate.digest
            or initial_box.candidate_digest != candidate.digest
            or freeze.namespace != namespace or freeze.operation_id != operation_id
            or output.operation_id != operation_id or receipt.status != "committed"):
        raise D04RootOriginalV3Hold("V3 root original identities differ")
    rows = authored_root_write_rows_v3(output.members)
    if (canonical_digest(rows) != output.write_set_digest
            or tuple((item.key.token, item.revision) for item in receipt.revisions)
               != tuple((ref, 1) for ref, _, _ in rows)
            or receipt.invalidated):
        raise D04RootOriginalV3Hold("V3 root receipt does not cover exact writes")
    event = db.execute(
        "SELECT digest FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, "d04.authored_root.v3", operation_id),
    ).fetchone()
    if event is None:
        raise D04RootOriginalV3Hold("V3 root event was not committed")
    graph_receipt = {"status": receipt.status,
                     "revisions": [[item.key.token, item.revision] for item in receipt.revisions],
                     "invalidated": [], "epoch": asdict(receipt.epoch)}
    body = dict(
        namespace=namespace, operation_id=operation_id,
        candidate_json=canonical_serialize(encode_authored_root_candidate_v3(candidate)),
        initial_box_json=canonical_serialize(asdict(initial_box)),
        output_json=canonical_serialize({"rows": rows, "issuance_digest": output.issuance_digest}),
        signed_freeze_digest=freeze.original_digest, graph_event_digest=event[0],
        graph_receipt_digest=canonical_digest(graph_receipt),
        write_set_digest=output.write_set_digest,
        status="authored_root_committed_no_observed_sources",
    )
    original = D04RootOriginalV3(**body, original_digest=canonical_digest(body))
    _event_and_history(db, original)
    encoded = canonical_serialize(_body(original))
    row = db.execute(
        "SELECT original_json,original_digest FROM graph_d04_root_originals_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone()
    if row is not None:
        if row != (encoded, original.original_digest):
            raise D04RootOriginalV3Hold("V3 root original retry differs")
    else:
        db.execute("INSERT INTO graph_d04_root_originals_v3 VALUES(?,?,?,?,?)",
                   (*namespace.as_tuple, operation_id, encoded, original.original_digest))
    return original


def read_d04_root_original_v3(db: sqlite3.Connection, *,
                              namespace: NamespaceId,
                              operation_id: str) -> D04RootOriginalV3:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise D04RootOriginalV3Hold("V3 root read needs a fenced graph transaction")
    from .domain_background_read_v3 import background_point_v3,background_json_loads_v3,background_json_matches_v3,background_typed_original_digest_v3
    row=background_point_v3(db,table='graph_d04_root_originals_v3',columns=('original_json','original_digest'),
        key_columns=('bot','persona','operation_id'),key=(*namespace.as_tuple,operation_id),legacy_reader=lambda:db.execute(
            'SELECT original_json,original_digest FROM graph_d04_root_originals_v3 WHERE bot=? AND persona=? AND operation_id=?',
            (*namespace.as_tuple,operation_id)).fetchone())
    if row is None:
        raise D04RootOriginalV3Hold("V3 root original is absent")
    try:
        body = background_json_loads_v3(row[0])
        if not background_json_matches_v3(row[0],body) or body["namespace"] != json.loads(canonical_serialize(namespace)):
            raise ValueError("V3 root original bytes differ")
        original = D04RootOriginalV3(**{**body, "namespace": namespace,
                                       "original_digest": row[1]})
        if (original.operation_id != operation_id
                or background_typed_original_digest_v3(db,row[0],_body(original)) != original.original_digest):
            raise ValueError("V3 root original digest differs")
        _event_and_history(db, original)
        return original
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise D04RootOriginalV3Hold("V3 root original failed replay") from exc
