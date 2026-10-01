"""W01's current ingress inventory is not a D13 completed-turn issuer."""

from dataclasses import replace
import time

import pytest

from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.graph_coordinator import (
    CurrentD13IngressInventoryV1, UnavailableGuard,
)
from sylanne3.graph_types import AtomKey
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.runtime_contracts import AuthorityContext, ConversationWindowProjectionV1

from test_reply_entity_route_v2 import CANONICAL_CONVERSATION, _current_join
from test_reply_entity_route_v2 import canonical_private_case  # noqa: F401
from test_post_c02_reply_model_job_v1 import private_reply_c02_case  # noqa: F401
from test_first_ingress_c02_commit import c02_case  # noqa: F401


def _context_reader(case):
    store, graph, bootstrap, namespace, _, policy, *_ = case
    lease, capability = graph.grant(
        bootstrap, actor="d13-window-reader", issuer_domain="d11",
        namespace=namespace, domains=("d11",), activation_generation=1,
        operation_id="d13-current-ingress-read",
    )
    authority = AuthorityContext(
        "d13-window-reader", "d11", capability, namespace, ("persona",),
        "context", (CANONICAL_CONVERSATION,), "policy-1", 1,
    )
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
            before, after, utc + 0.001,
        )

    port.read_ingress_clock = paired_clock
    return authority, lease


def test_current_c02_arrival_inventory_has_no_fabricated_turn(
        canonical_private_case):
    case = canonical_private_case
    store, graph, _, namespace, *_ = case
    c02, source_ref = _current_join(case)
    source_id = AtomKey.from_token(source_ref).owner.subject
    ingress_operation_id = store._db.execute(
        "SELECT operation_id FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?",
        namespace.as_tuple + (source_id,),
    ).fetchone()[0]
    authority, lease = _context_reader(case)

    inventory = graph.read_current_d13_ingress_inventory_v1(
        authority, lease, ingress_operation_id=ingress_operation_id,
        c02_operation_id=c02.operation_id)
    assert type(inventory) is CurrentD13IngressInventoryV1
    assert inventory.route_binding.conversation_ref == CANONICAL_CONVERSATION
    assert inventory.route_binding.source_ref == source_ref
    assert inventory.route_binding.binding_version.revision == 1
    assert inventory.source_expires_at_utc > inventory.trusted_utc
    assert inventory.turn_order_status == "not_verified"
    assert not isinstance(inventory, ConversationWindowProjectionV1)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name='d09.turn_order.v1'", namespace.as_tuple,
    ).fetchone() == (0,)
    with pytest.raises(UnavailableGuard, match="C02 seal"):
        graph.read_current_d13_ingress_inventory_v1(
            authority, lease, ingress_operation_id=ingress_operation_id,
            c02_operation_id="unrelated-c02")
    with pytest.raises(UnavailableGuard):
        graph.read_current_d13_ingress_inventory_v1(
            replace(authority, audience=("another-conversation",)), lease,
            ingress_operation_id=ingress_operation_id,
            c02_operation_id=c02.operation_id)

    # Fault-injected SQL revocation checks the reader's fail-closed current row.
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        store._db.execute(
            "UPDATE graph_atoms SET valid=0 WHERE token=?",
            (inventory.route_binding.access_version.key.token,),
        )
        store._db.execute("COMMIT")
    try:
        with pytest.raises(UnavailableGuard):
            graph.read_current_d13_ingress_inventory_v1(
                authority, lease, ingress_operation_id=ingress_operation_id,
                c02_operation_id=c02.operation_id)
    finally:
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            store._db.execute(
                "UPDATE graph_atoms SET valid=1 WHERE token=?",
                (inventory.route_binding.access_version.key.token,),
            )
            store._db.execute("COMMIT")
