"""A committed original private ingress becomes one D09 inbound turn."""

from dataclasses import replace
import time

import pytest

from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.domains.d09 import D09ExpressionProvider
from sylanne3.graph_coordinator import (
    D13InboundTurnReceiptV1, EventConflict, UnavailableGuard,
)
from sylanne3.graph_types import AtomKey
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.runtime_contracts import AuthorityContext

from test_reply_entity_route_v2 import CANONICAL_CONVERSATION, _current_join
from test_reply_entity_route_v2 import canonical_private_case  # noqa: F401
from test_post_c02_reply_model_job_v1 import private_reply_c02_case  # noqa: F401
from test_first_ingress_c02_commit import c02_case  # noqa: F401


def _writer(case):
    store, graph, bootstrap, namespace, _, policy, *_ = case
    provider = D09ExpressionProvider()
    graph.register_provider(
        bootstrap, "d09", provider, "d09.proposal.v1",
        provider.descriptor.request_schema_hash)
    lease, capability = graph.grant(
        bootstrap, actor="d13-turn-writer", issuer_domain="d09",
        namespace=namespace, domains=("d09",), activation_generation=1,
        operation_id="d13-inbound-turn-write")
    authority = AuthorityContext(
        "d13-turn-writer", "d09", capability, namespace, ("scene",),
        "context", (CANONICAL_CONVERSATION,), "policy-1", 1)
    port = graph._GraphCoordinator__content_fence_v2
    grant = port.installation_grant

    def paired_clock(_policy):
        before = time.monotonic()
        utc = time.time()
        after = time.monotonic()
        return VerifiedIngressClockV2(
            IngressClockSampleV2(
                grant.authority_id, grant.installation_id, policy.source_id,
                utc, after, "fixture-clock-epoch", 0.001),
            before, after, utc + 0.001)

    port.read_ingress_clock = paired_clock
    return authority, lease


def test_original_c02_d03_d06_ingress_commits_one_inbound_turn(canonical_private_case):
    case = canonical_private_case
    store, graph, _, namespace, *_ = case
    c02, source_ref = _current_join(case)
    source_id = AtomKey.from_token(source_ref).owner.subject
    ingress_operation_id = store._db.execute(
        "SELECT operation_id FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?",
        namespace.as_tuple + (source_id,),
    ).fetchone()[0]
    authority, lease = _writer(case)

    result = graph.commit_confirmed_d13_inbound_turn_v1(
        authority, lease, ingress_operation_id=ingress_operation_id,
        c02_operation_id=c02.operation_id)
    assert type(result) is D13InboundTurnReceiptV1
    assert result.sequence == 0
    assert graph.commit_confirmed_d13_inbound_turn_v1(
        authority, lease, ingress_operation_id=ingress_operation_id,
        c02_operation_id=c02.operation_id) == result
    rows = store._db.execute(
        "SELECT type_name,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name IN ('d09.turn_order.v1','d09.turn_slot.v1',"
        "'d09.turn_completion.v1') ORDER BY type_name",
        namespace.as_tuple,
    ).fetchall()
    assert len(rows) == 3 and all(row[2] == 1 for row in rows)
    assert b'outbound' not in str(rows).encode()
    with pytest.raises(EventConflict):
        graph.commit_confirmed_d13_inbound_turn_v1(
            authority, lease, ingress_operation_id=ingress_operation_id,
            c02_operation_id="different-c02")
    with pytest.raises(UnavailableGuard):
        graph.commit_confirmed_d13_inbound_turn_v1(
            replace(authority, audience=("different",)), lease,
            ingress_operation_id=ingress_operation_id,
            c02_operation_id=c02.operation_id)


def test_revoked_access_cannot_replay_inbound_turn(canonical_private_case):
    case = canonical_private_case
    store, graph, _, namespace, *_ = case
    c02, source_ref = _current_join(case)
    source_id = AtomKey.from_token(source_ref).owner.subject
    ingress_operation_id = store._db.execute(
        "SELECT operation_id FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?",
        namespace.as_tuple + (source_id,),
    ).fetchone()[0]
    authority, lease = _writer(case)
    receipt = graph.commit_confirmed_d13_inbound_turn_v1(
        authority, lease, ingress_operation_id=ingress_operation_id,
        c02_operation_id=c02.operation_id)
    from sylanne3.memory_types import access_key
    access_ref = access_key(*namespace.as_tuple, source_id).token
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        store._db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (access_ref,))
        store._db.execute("COMMIT")
    try:
        with pytest.raises(UnavailableGuard):
            graph.commit_confirmed_d13_inbound_turn_v1(
                authority, lease, ingress_operation_id=ingress_operation_id,
                c02_operation_id=c02.operation_id)
        from test_d13_current_ingress_inventory_v1 import _context_reader
        reader_authority, reader_lease = _context_reader(case)
        with pytest.raises(UnavailableGuard):
            graph.read_current_d13_ingress_inventory_v1(
                reader_authority, reader_lease,
                ingress_operation_id=ingress_operation_id,
                c02_operation_id=c02.operation_id)
    finally:
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            store._db.execute("UPDATE graph_atoms SET valid=1 WHERE token=?", (access_ref,))
            store._db.execute("COMMIT")
    assert receipt.sequence == 0
