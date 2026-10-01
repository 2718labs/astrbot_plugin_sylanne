"""The installed host wrapper uses the original ingress identity for D13."""

import pytest

from sylanne3.graph_coordinator import D13InboundTurnReceiptV1
from sylanne3.graph_types import AtomKey
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime.first_ingress_v2 import ingress_ids

from test_reply_entity_route_v2 import CANONICAL_CONVERSATION, _current_join
from test_reply_entity_route_v2 import canonical_private_case  # noqa: F401
from test_post_c02_reply_model_job_v1 import private_reply_c02_case  # noqa: F401
from test_first_ingress_c02_commit import c02_case  # noqa: F401
from test_d13_confirmed_inbound_turn_v1 import _writer


class _Worker:
    def __init__(self, graph):
        self.graph = graph

    async def call(self, function, *args):
        return function(self.graph, *args)


@pytest.mark.asyncio
async def test_host_wrapper_commits_once_and_rejects_unrelated_ingress(
        canonical_private_case):
    store, graph, bootstrap, namespace, policy, *_ = canonical_private_case
    c02, source_token = _current_join(canonical_private_case)
    source_id = AtomKey.from_token(source_token).owner.subject
    original = store._db.execute(
        "SELECT operation_id FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?",
        namespace.as_tuple + (source_id,),
    ).fetchone()[0]
    assert ingress_ids(source_id)[2] == original
    _writer(canonical_private_case)
    port = graph._GraphCoordinator__content_fence_v2
    runtime = object.__new__(RuntimeContext)
    runtime._v2_policy = policy
    runtime._v2_installation_grant = port.installation_grant
    runtime._v2_port = port
    runtime._worker = _Worker(graph)
    runtime._v2_bootstrap = bootstrap
    runtime._v2_namespace_provisioned = True
    runtime._v2_namespace = namespace
    envelope = HostIngressEnvelope(
        namespace, "platform", CANONICAL_CONVERSATION, "sender", "message",
        "hello", None, 1.0, "private",
        SourceLineage(source_id, "reported", "host", "external_report",
                      "reported_claim"))

    first = await runtime.commit_confirmed_d13_inbound_turn_v1(
        ingress_operation_id=original, c02_operation_id=c02.operation_id,
        envelope=envelope)
    assert type(first) is D13InboundTurnReceiptV1
    assert await runtime.commit_confirmed_d13_inbound_turn_v1(
        ingress_operation_id=original, c02_operation_id=c02.operation_id,
        envelope=envelope) == first
    assert await runtime.commit_confirmed_d13_inbound_turn_v1(
        ingress_operation_id="unrelated", c02_operation_id=c02.operation_id,
        envelope=envelope) is None
    runtime._v2_model_bundle = None
    assert await runtime.schedule_d13_deterministic_precompression_v2(
        ingress_operation_id=original, envelope=envelope) is None
    rows = store._db.execute(
        "SELECT type_name FROM graph_atoms WHERE bot=? AND persona=? AND "
        "type_name IN ('d09.turn_order.v1','d09.turn_slot.v1',"
        "'d09.turn_completion.v1')", namespace.as_tuple).fetchall()
    assert len(rows) == 3
