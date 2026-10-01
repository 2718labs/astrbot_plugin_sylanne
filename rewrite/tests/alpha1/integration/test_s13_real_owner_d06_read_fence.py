"""S13 K06 slice: real Owner revoke serializes with a current D06 read fence."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.integration.test_owner_signed_chain import (
    ADMIN, PEER, ROLE, _real_owner_chain,
)
from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.graph_types import (
    GraphCandidate, GraphWrite, TypeRegistry, owner_grant_spec,
)
from sylanne3.memory_types import SourceRecord, access_key, source_key


def test_real_owner_revoke_waits_for_d06_read_then_denies_same_lease(tmp_path):
    chain = _real_owner_chain(
        tmp_path, extra_purpose="context",
        extra_specs=D06DomainProvider.type_specs(),
    )
    registry = TypeRegistry()
    registry.register(owner_grant_spec())
    for spec in D06DomainProvider.type_specs():
        registry.register(spec)
    graph = None
    try:
        graph = ProductionGraphStore(tmp_path / "business.db", registry)
        coordinator = GraphCoordinator(
            graph, chain.bootstrap, holder="administrator",
            content_fence_v2=chain.port,
            owner_principal_resolver=chain.current_principal,
        )
        d06 = D06DomainProvider()
        coordinator.register_provider(
            chain.bootstrap, "d06", d06, "d06.contract.v1",
            d06.descriptor.request_schema_hash,
        )
        source = source_key(*ROLE.as_tuple, "source-1")
        access = access_key(*ROLE.as_tuple, "source-1")
        record = SourceRecord(
            "source-1", "private", "speaker", "reported", "reported",
            1.0, 2.0, "family", ("owner",), ("context",),
        )
        snapshot = GraphStore.graph_snapshot(
            graph, (source, access), _capability=graph._coordinator_capability)
        GraphStore.graph_commit(
            graph, GraphCandidate(
                Event(Scope(*ROLE.as_tuple, "seed"), "seed-s13-source", 2.0,
                      "seed", {}), snapshot.versions,
                (GraphWrite(source, record.to_dict()),
                 GraphWrite(access, {
                     "source_id": "source-1", "audiences": ["owner"],
                     "purposes": ["context"], "status": "active", "recorded_at": 2.0,
                 }, (source,))), snapshot.epochs,
            ), _capability=graph._coordinator_capability,
        )
        with graph._lock:
            graph._db.execute("BEGIN IMMEDIATE")
            try:
                metadata = graph.graph_recovery_metadata(
                    ROLE, _capability=graph._coordinator_capability)
                graph.cas_graph_recovery_metadata(
                    metadata, metadata.requirements,
                    _capability=graph._coordinator_capability)
                graph._db.execute("COMMIT")
            except BaseException:
                graph._db.execute("ROLLBACK")
                raise

        login_request = replace(chain.issue_request, audience="owner")
        challenge = chain.sessions.begin_login(
            transport_credential=PEER, request=login_request)
        token = chain.sessions.accept_login(
            transport_credential=PEER, challenge=challenge,
            signature=chain.key.sign(challenge.signed_bytes()))
        authority, lease, _ = coordinator.grant_current_owner(
            chain.bootstrap, actor="owner-actor", namespace=ROLE,
            domains=("d06",), purpose="context", audience="owner",
            activation_generation=1, owner_session_token=token,
            owner_session_request=login_request,
        )
        original_guard = chain.port.get_current_owner_guard_for_fence
        observed = []

        def guard_during_read(**kwargs):
            current = original_guard(**kwargs)
            observed.append(current[0])
            if len(observed) == 1:
                with pytest.raises(Exception, match="busy/not_applied"):
                    chain.source.revoke_actor(
                        administrator_credential=ADMIN,
                        binding=chain.actor_binding)
            return current

        chain.port.get_current_owner_guard_for_fence = guard_during_read
        try:
            page = coordinator.read_current_memory_evidence_v1(authority, lease)
            assert page.status == "candidate_page_complete"
            assert len(page.candidates) == 1
            assert page.candidates[0].record.text == "private"
            assert len(observed) >= 2  # Owner guard checked on both sides of read.
            chain.source.revoke_actor(
                administrator_credential=ADMIN, binding=chain.actor_binding)
            with pytest.raises(UnavailableGuard):
                coordinator.read_current_memory_evidence_v1(authority, lease)
            assert graph._db.execute(
                "SELECT revision,valid FROM graph_atoms WHERE token=?",
                (source.token,),
            ).fetchone() == (1, 1)
        finally:
            chain.port.get_current_owner_guard_for_fence = original_guard
            coordinator.release_current_owner_lease(chain.bootstrap, lease)
    finally:
        if graph is not None:
            graph.close()
        for resource in chain.resources:
            resource.close()
