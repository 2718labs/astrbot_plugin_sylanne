"""A durable first-ingress baseline can be handed back to the installed host."""

import sys
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.host.authority_profile import AdminD04EncodingBaselinePolicy
from sylanne3.host.authority_profile import (
    AdminD03ArrivalPolicy, AdminD03SelfIdentityProjectionPolicy,
)
from sylanne3.domains.d04 import AffectAxis, AffectProvider, AffectScheme
from sylanne3.host.first_ingress_c02_driver import (
    original_acquired_handoff_v1, original_unacquired_handoff_v1,
)
from sylanne3.host.ingress import IngressReceipt
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.host.current_scene import CurrentHostScene
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_contracts import QueryEpoch

# The runtime integration fixtures establish a real C01 queued job and D03/D04
# baseline. Their modules use sibling imports, so expose that fixture directory.
_RUNTIME_TESTS = Path(__file__).resolve().parents[2] / "tests" / "alpha1" / "runtime"
sys.path.insert(0, str(_RUNTIME_TESTS))
from test_d03_self_projection_commit import FixtureCurrentSelf, _commit  # noqa: E402
from test_first_ingress_job_acquire_v2 import _op, _worker, FixedEncodingRequestIssuer  # noqa: E402
from test_first_ingress_v2 import _ingress_inputs  # noqa: E402
from test_scene_binding_v2 import _scene_case, _session  # noqa: E402


class _GraphWorker:
    def __init__(self, graph):
        self.graph = graph

    async def call(self, operation):
        return operation(self.graph)


@pytest.fixture
def host_projection_case(tmp_path):
    d04 = AffectProvider(active_scheme=AffectScheme(
        "d04.affect.scheme.v1", "scheme-1", "operator-1",
        "parameter:fixture", "coupling:fixture",
        (AffectAxis("care", "normalized", "care"),), ()))
    case = _scene_case(
        tmp_path, enable_ingress=True, arrival_allowed=True,
        extra_specs=d04.type_specs(),
        extra_work_kinds=("d03.self_identity_projection", "d04.encoding_baseline"))
    store, authority_db, port, coordinator, namespace, principal, prior, policy, bootstrap = case
    try:
        coordinator.register_provider(
            bootstrap, "d04", d04, "d04.proposal.v1",
            d04.descriptor.request_schema_hash)
        host, clock, encoding = _ingress_inputs(namespace)
        host = replace(host, conversation_ref=json.dumps(["trusted:conversation", "chat"]))
        scene_ref = scene_ref_for_conversation(
            namespace, host.platform_ref, host.conversation_ref)
        scene = CurrentHostScene(
            namespace, host.platform_ref, host.conversation_ref, "private", scene_ref)
        coordinator._GraphCoordinator__scene_identity_port = SimpleNamespace(
            verify=lambda current, ref, visibility: scene if (
                current, ref, visibility) == (
                namespace, scene_ref, "private") else None)
        coordinator._GraphCoordinator__scene_clock_policy = clock
        prior = replace(prior, request=replace(prior.request, scene_ref=scene_ref))
        prior = replace(prior, query_epoch=QueryEpoch(namespace, "d03.role_binding", 2))
        original_clock = port.read_ingress_clock
        port.read_ingress_clock = lambda _: SimpleNamespace(utc_upper_bound_seconds=1000.0)
        token, request = _session(case)
        try:
            coordinator.commit_scene_binding_v2(
                namespace=namespace, operation_id="scene-bind-1", scene=scene,
                prior=prior, principal=principal, actor_id="paired-owner",
                request_digest="sha256:" + "a" * 64,
                owner_session_token=token, owner_session_request=request)
        finally:
            port.read_ingress_clock = original_clock
        coordinator.commit_first_ingress_v2(
            bootstrap, host, policy, clock, encoding)
        coordinator.commit_d03_message_arrival_v2(
            bootstrap, namespace, host.lineage.source_ref, policy,
            AdminD03ArrivalPolicy(
                30.0, {"cpu_ms": 3}, "arrival-snapshot", "arrival-resource"),
            clock)
        fixture_port = FixtureCurrentSelf(store, coordinator, port, policy)
        coordinator._GraphCoordinator__self_identity_port = fixture_port
        job_id, original_operation_id = store._db.execute(
            "SELECT job_id,operation_id FROM runtime_jobs").fetchone()
        stage_policy = AdminD03SelfIdentityProjectionPolicy(
            30.0, {"cpu_ms": 4}, "projection-snapshot", "projection-resource")
        yield (store, coordinator, bootstrap, namespace, job_id,
               original_operation_id, policy, stage_policy, clock, fixture_port)
    finally:
        store.close()
        authority_db.close()


@pytest.mark.asyncio
async def test_sqlite_restart_rehands_only_original_queued_ingress(host_projection_case, tmp_path):
    (store, coordinator, bootstrap, namespace, job_id, original_operation_id,
     policy, _, clock, _) = host_projection_case
    _commit(host_projection_case)
    coordinator.commit_d04_encoding_baseline_v1(
        bootstrap, namespace, job_id, original_operation_id, policy,
        AdminD04EncodingBaselinePolicy(
            30.0, {"cpu_ms": 2}, "baseline-snapshot", "baseline-resource"),
        clock,
    )
    before = coordinator.discover_first_ingress_unacquired_v1(bootstrap, namespace)
    assert len(before.items) == 1
    original_item = before.items[0]
    original_row = store._db.execute(
        "SELECT job_id, operation_id, phase FROM runtime_jobs WHERE job_id=?",
        (job_id,),
    ).fetchone()
    assert original_row == (job_id, original_operation_id, "queued")

    graph_path = tmp_path / "owner-business.db"
    registry = store._registry
    port = coordinator._GraphCoordinator__content_fence_v2
    d02 = coordinator._GraphCoordinator__d02_issuer
    d11 = coordinator._GraphCoordinator__d11_issuer
    store.close()
    reopened = ProductionGraphStore(graph_path, registry)
    port.store = reopened
    next_bootstrap = object()
    graph = GraphCoordinator(
        reopened, next_bootstrap, holder="administrator",
        content_fence_v2=port, d02_issuer=d02, d11_issuer=d11,
    )
    for domain, (provider, schema, schema_hash) in (
            coordinator._GraphCoordinator__providers.items()):
        graph.register_provider(
            next_bootstrap, domain, provider, schema, schema_hash)
    graph._GraphCoordinator__scene_clock_policy = clock
    try:
        assert graph.discover_first_ingress_unacquired_v1(
            next_bootstrap, namespace).items == (original_item,)
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker = _GraphWorker(graph)
        runtime._v2_bootstrap = next_bootstrap
        runtime._v2_namespace_provisioned = True
        runtime._v2_policy = policy
        runtime._v2_namespace = namespace
        runtime._v2_installation_grant = port.installation_grant
        page = await runtime.discover_first_ingress_unacquired_v1()
        assert page is not None and page.items == (original_item,)
        assert page.next_after_job_id is None
        assert reopened._db.execute(
            "SELECT job_id, operation_id, phase FROM runtime_jobs"
        ).fetchall() == [original_row]

        installation = V2InstallationAssembly(
            policy, port.installation_grant, b"d11", b"d02", lambda: None,
            tmp_path, tmp_path,
        )
        handoff = original_unacquired_handoff_v1(page.items[0], installation)
        assert handoff is not None
        trusted_umo, envelope, receipt = handoff
        assert trusted_umo == "trusted:conversation"
        assert envelope == original_item.envelope
        assert receipt == IngressReceipt("accepted", original_operation_id)
        assert page.items[0].job_id == job_id

        graph._GraphCoordinator__scene_clock_policy = clock
        graph._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
        original_clock = port.read_ingress_clock

        def paired_clock(policy):
            reading = original_clock(policy)
            reading.sample = SimpleNamespace(
                epoch="fixture-clock-epoch", source_id=clock.source_id)
            return reading

        port.read_ingress_clock = paired_clock
        acquire_id = _op(graph, job_id)
        authority, lease = _worker(
            graph, next_bootstrap, namespace, operation_id=acquire_id)
        graph.acquire_first_ingress_encoding_job_v3(
            authority, lease, job_id, acquire_id, lease_seconds=30)
        assert (await runtime.discover_first_ingress_unacquired_v1()).items == ()
        assert reopened._db.execute(
            "SELECT COUNT(*) FROM runtime_jobs"
        ).fetchone() == (1,)

        reopened.close()
        reopened = ProductionGraphStore(graph_path, registry)
        port.store = reopened
        acquired_bootstrap = object()
        acquired_graph = GraphCoordinator(
            reopened, acquired_bootstrap, holder="administrator",
            content_fence_v2=port, d02_issuer=d02, d11_issuer=d11,
        )
        for domain, (provider, schema, schema_hash) in (
                graph._GraphCoordinator__providers.items()):
            acquired_graph.register_provider(
                acquired_bootstrap, domain, provider, schema, schema_hash)
        acquired_graph._GraphCoordinator__scene_clock_policy = clock
        acquired = acquired_graph.discover_first_ingress_recovery_v1(
            acquired_bootstrap, namespace).items
        assert len(acquired) == 1
        assert acquired[0].recovery_state == "original_fence"
        recovered, original_envelope = (
            acquired_graph.read_first_ingress_acquired_handoff_v1(
                acquired_bootstrap, namespace, acquire_id))
        assert recovered == acquired[0]
        assert original_envelope == envelope
        runtime._worker = _GraphWorker(acquired_graph)
        runtime._v2_bootstrap = acquired_bootstrap
        assert await runtime.read_first_ingress_acquired_handoff_v1(
            acquire_id) == (recovered, envelope)
        assert original_acquired_handoff_v1(
            recovered, original_envelope, installation) == (
                trusted_umo, envelope, receipt)
    finally:
        reopened.close()
