"""Shared permanent natural-V4 fixture assembly using the real D13 turn issuer."""
from dataclasses import replace
import time
from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.domains.d09 import D09ExpressionProvider
from sylanne3.graph_types import AtomKey
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.runtime_contracts import AuthorityContext


def commit_natural_fixture_inbound_turn_v4(*, graph, bootstrap, namespace, source_ref,
                                         c02_operation_id, now_utc):
    provider = D09ExpressionProvider()
    if "d09" not in graph._GraphCoordinator__providers:
        graph.register_provider(bootstrap, "d09", provider, "d09.proposal.v1", provider.descriptor.request_schema_hash)
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    source_id = AtomKey.from_token(source_ref).owner.subject
    ingress, conversation = store._db.execute("SELECT operation_id,conversation_ref FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?", namespace.as_tuple + (source_id,)).fetchone()
    generation = graph._v2_graph_stamp(namespace)[0].requirements.activation_generation
    lease, cap = graph.grant(bootstrap, actor="d13-natural-fixture", issuer_domain="d09", namespace=namespace,
        domains=("d09",), activation_generation=generation, operation_id="d13-natural-inbound-fixture")
    authority = AuthorityContext("d13-natural-fixture", "d09", cap, namespace, ("scene",),
        "context", (conversation,), "fixture-policy", generation)
    original_clock = port.read_ingress_clock
    installation = port.installation_grant
    clock_policy = graph._GraphCoordinator__scene_clock_policy
    def clock(_policy):
        before, after = time.monotonic(), time.monotonic()
        return VerifiedIngressClockV2(IngressClockSampleV2(installation.authority_id,
            installation.installation_id, clock_policy.source_id, now_utc, after,
            "fixture-natural-d13", 0.001), before, after, now_utc + 0.001)
    try:
        port.read_ingress_clock = clock
        return graph.commit_confirmed_d13_inbound_turn_v1(authority, lease,
            ingress_operation_id=ingress, c02_operation_id=c02_operation_id)
    finally:
        port.read_ingress_clock = original_clock
        graph.release_authority_lease(bootstrap, lease)
