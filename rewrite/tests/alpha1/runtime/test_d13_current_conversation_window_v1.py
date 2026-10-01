"""D11's fenced window reads only current, committed inbound source text."""

import json

import pytest

from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.contracts import Event, Scope
from sylanne3.domains.d09.turn_order import reserve_turn_slot_v1
from sylanne3.domains.d13.raw_slice import assemble_raw_slice
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphCandidate, GraphVersion, Owner,
)
from sylanne3.memory_types import access_key
from sylanne3.runtime_contracts import (
    ConversationWindowProjectionV1, ShortContextRequestV1,
)

from test_d13_confirmed_inbound_turn_v1 import _writer
from test_d13_current_ingress_inventory_v1 import _context_reader
from test_reply_entity_route_v2 import _current_join
from test_reply_entity_route_v2 import canonical_private_case  # noqa: F401
from test_post_c02_reply_model_job_v1 import private_reply_c02_case  # noqa: F401
from test_first_ingress_c02_commit import c02_case  # noqa: F401


def _committed(case):
    store, graph, _, namespace, *_ = case
    c02, source_ref = _current_join(case)
    source_id = AtomKey.from_token(source_ref).owner.subject
    ingress_operation_id = store._db.execute(
        "SELECT operation_id FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?",
        namespace.as_tuple + (source_id,),
    ).fetchone()[0]
    writer, writer_lease = _writer(case)
    receipt = graph.commit_confirmed_d13_inbound_turn_v1(
        writer, writer_lease, ingress_operation_id=ingress_operation_id,
        c02_operation_id=c02.operation_id)
    reader, reader_lease = _context_reader(case)
    return receipt, reader, reader_lease, source_id


def test_current_inbound_window_uses_d06_text_and_complete_read_set(canonical_private_case):
    case = canonical_private_case
    store, graph, _, namespace, *_ = case
    receipt, reader, reader_lease, source_id = _committed(case)
    scene = json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (receipt.slot_ref,),
    ).fetchone()[0])["scene_ref"]
    window = graph.read_current_d13_conversation_window_v1(
        reader, reader_lease, scene_ref=scene, max_slots=4)
    assert type(window) is ConversationWindowProjectionV1
    assert window.order_watermark == 0
    assert window.activation_epoch == reader.activation_generation == 1
    assert window.missing_ranges == ()
    assert [turn.sequence for turn in window.turns] == [0]
    turn = window.turns[0]
    source = json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (turn.source_ref.ref,),
    ).fetchone()[0])
    assert turn.text == source["text"] and source_id == source["source_id"]
    assert turn.delivery_state == "confirmed"
    assert turn.raw_ref.ref == receipt.completion_ref
    assert set(window.source_dependencies) == {
        turn.raw_ref, turn.source_ref, turn.access_ref}
    assert set(window.source_dependencies).issubset(window.read_set)
    assert window.scene_ref in window.read_set
    assert window.audience_ref in window.read_set
    request = ShortContextRequestV1(
        "d11", "reply.context", window.conversation_ref,
        window.scene_ref, window.audience_ref, "query:current", None,
        4096, "provider:installed", "model:installed", "template:v1",
        "tools:v1", "lease:current", True,
    )
    context_slice = assemble_raw_slice(window, request)
    assert context_slice.blocks == ()
    assert context_slice.raw_tail == window.turns
    assert context_slice.source_dependencies == window.source_dependencies
    assert context_slice.missing_ranges == ()
    assert context_slice.evidence_eligibility == "ineligible"


def test_revoked_access_blocks_window_even_when_completion_remains(canonical_private_case):
    case = canonical_private_case
    store, graph, _, namespace, *_ = case
    receipt, reader, reader_lease, source_id = _committed(case)
    scene = json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (receipt.slot_ref,),
    ).fetchone()[0])["scene_ref"]
    access_ref = access_key(*namespace.as_tuple, source_id).token
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        store._db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (access_ref,))
        store._db.execute("COMMIT")
    try:
        assert store._db.execute(
            "SELECT valid FROM graph_atoms WHERE token=?",
            (receipt.completion_ref,),
        ).fetchone() == (1,)
        with pytest.raises(UnavailableGuard):
            graph.read_current_d13_conversation_window_v1(
                reader, reader_lease, scene_ref=scene)
    finally:
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            store._db.execute("UPDATE graph_atoms SET valid=1 WHERE token=?", (access_ref,))
            store._db.execute("COMMIT")


def test_pending_outbound_slot_is_a_gap_in_bounded_page(canonical_private_case):
    case = canonical_private_case
    store, graph, _, namespace, *_ = case
    receipt, reader, reader_lease, _ = _committed(case)
    slot_value = json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (receipt.slot_ref,),
    ).fetchone()[0])
    scene, conversation = slot_value["scene_ref"], slot_value["conversation_ref"]
    order_key = AtomKey.from_token(receipt.order_ref)
    outbox_key = AtomKey(
        Owner("activity", *namespace.as_tuple, "test:pending"),
        "runtime.outbox", "pending")
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            metadata, epoch = graph._v2_graph_stamp(namespace)
            order_row = db.execute(
                "SELECT revision,value FROM graph_atoms WHERE token=?",
                (order_key.token,),
            ).fetchone()
            order = GraphAtom(order_key, order_row[0], json.loads(order_row[1]))
            pending = reserve_turn_slot_v1(
                namespace, scene, conversation, "outbound", outbox_key.token,
                current_order=order)
            candidate = GraphCandidate(
                Event(Scope(*namespace.as_tuple, "test-pending-outbound"),
                      "test-pending-outbound", 0.0, "test.pending", {}),
                (GraphVersion(order_key, order.revision),
                 GraphVersion(pending.absent_slot, 0)),
                pending.writes, (epoch,),
            )
            GraphStore._graph_commit_in_transaction(
                store, candidate,
                _receipt_hook=lambda _db, _receipt: store.cas_graph_recovery_metadata(
                    metadata, metadata.requirements,
                    _capability=graph._GraphCoordinator__graph_capability),
                _capability=graph._GraphCoordinator__graph_capability,
            )
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    window = graph.read_current_d13_conversation_window_v1(
        reader, reader_lease, scene_ref=scene, max_slots=2)
    assert window.order_watermark == 1
    assert [turn.sequence for turn in window.turns] == [0]
    assert window.missing_ranges == ((1, 1),)
    older_page = graph.read_current_d13_conversation_window_v1(
        reader, reader_lease, scene_ref=scene, max_slots=1,
        before_sequence=1)
    assert [turn.sequence for turn in older_page.turns] == [0]
    assert older_page.missing_ranges == ((1, 1),)
    with pytest.raises(UnavailableGuard):
        graph.read_current_d13_conversation_window_v1(
            reader, reader_lease, scene_ref=scene, max_slots=1)
