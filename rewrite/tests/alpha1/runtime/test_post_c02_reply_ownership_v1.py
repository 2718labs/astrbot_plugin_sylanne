"""Original host default is durable and bars a late reply write attempt."""

import pytest

from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.graph_types import AtomKey
from sylanne3.domains.d08 import GoalExecutionProvider
from sylanne3.domains.d09 import D09ExpressionProvider
from sylanne3.host.authority_profile import AdminInstallationBundle
from sylanne3.runtime.first_ingress_v2 import ingress_ids
from sylanne3.runtime_contracts import AuthorityContext

from test_reply_entity_route_v2 import canonical_private_case, _current_join
from test_post_c02_reply_model_job_v1 import private_reply_c02_case
from test_first_ingress_c02_commit import c02_case


def test_host_default_is_idempotent_and_bars_late_reply(canonical_private_case):
    store, graph, bootstrap, namespace, policy, *_ = canonical_private_case
    _, source_ref = _current_join(canonical_private_case)
    ingress_operation_id = ingress_ids(AtomKey.from_token(source_ref).owner.subject)[2]
    for domain, provider in (("d08", GoalExecutionProvider()),
                             ("d09", D09ExpressionProvider())):
        graph.register_provider(
            bootstrap, domain, provider, f"{domain}.proposal.v1",
            provider.descriptor.request_schema_hash)
    lease, capability = graph.grant(
        bootstrap, actor=policy.administrator_holder,
        issuer_domain="d11", namespace=namespace,
        domains=("d08", "d09", "d11"),
        activation_generation=1, operation_id="host-takeover:" + ingress_operation_id,
    )
    authority = AuthorityContext(
        policy.administrator_holder, "d11", capability, namespace,
        ("activity",), "expression", ("conversation",),
        policy.root_grant.policy_ref, 1,
    )
    try:
        first = graph.close_host_default_v1(
            authority, lease, ingress_operation_id=ingress_operation_id,
            handler_invocation_id="handler-1")
        replay = graph.close_host_default_v1(
            authority, lease, ingress_operation_id=ingress_operation_id,
            handler_invocation_id="handler-1")
        assert first == replay
        assert graph.read_reply_ownership_v1(
            authority, lease, ingress_operation_id=ingress_operation_id,
            handler_invocation_id="handler-1") == first
        assert first.state == "host_default"
        assert first.reply_operation_id is None
        with pytest.raises(UnavailableGuard, match="ownership is closed"):
            with store._lock:
                graph._require_reply_host_available_locked(
                    namespace, ingress_operation_id, "handler-1")
        with store._lock:
            metadata, epoch = graph._v2_graph_stamp(namespace)
        anchor = graph._GraphCoordinator__content_fence_v2.current_anchor(
            namespace=namespace,
            authority_namespace=metadata.requirements.authority_namespace)
        with store._lock:
            with pytest.raises(UnavailableGuard, match="ownership is closed"):
                graph._open_post_c02_reply_dispatch_attempt_locked(
                    namespace=namespace, operation_id="late-reply",
                    ingress_operation_id=ingress_operation_id,
                    handler_invocation_id="handler-1",
                    request_digest="a" * 64, input_digest="b" * 64,
                    handler_deadline_utc=1e12,
                    frozen_deadline_utc=1e12,
                    metadata=metadata, epoch=epoch, anchor=anchor)
            assert store._db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND "
                "name='graph_post_c02_reply_dispatch_attempts_v2'").fetchone() is None
        with pytest.raises(Exception):
            graph.close_host_default_v1(
                authority, lease, ingress_operation_id=ingress_operation_id,
                handler_invocation_id="handler-2")
        assert graph.wait_for_durable_admission_v1(
            authority, lease, ingress_operation_id=ingress_operation_id,
            handler_invocation_id="handler-1") is None
        with pytest.raises(UnavailableGuard, match="not durably owned"):
            graph.require_reply_owned_before_dispatch_p2_v1(
                authority, lease, ingress_operation_id=ingress_operation_id,
                admission_ref="admission:late", effect_id="effect:late")
        installed = AdminInstallationBundle(None, policy, b"", b"")
        grants_before = len(graph._GraphCoordinator__leases)
        with pytest.raises(UnavailableGuard, match="ownership or route differs"):
            graph.grant_owned_reply_dispatch_scope_v1(
                bootstrap, installed, ingress_operation_id=ingress_operation_id,
                handler_invocation_id="handler-1")
        with pytest.raises(UnavailableGuard, match="ownership or route differs"):
            graph.grant_owned_reply_dispatch_scope_v1(
                bootstrap, installed, ingress_operation_id=ingress_operation_id,
                handler_invocation_id="handler-2")
        assert len(graph._GraphCoordinator__leases) == grants_before
    finally:
        graph.release_authority_lease(bootstrap, lease)
