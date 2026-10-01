"""One-source C09 plan original under a real signed Owner installation."""

from dataclasses import replace
from uuid import uuid4

import pytest

from rewrite.tests.alpha1.integration.test_owner_signed_chain import (
    PEER, ROLE, _real_owner_chain,
)
from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.graph_store import GraphStore, ProductionGraphStore, TypeRegistry
from sylanne3.graph_types import GraphCandidate, GraphWrite, owner_grant_spec
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.c09_erasure_plan_original_v1 import (
    read_c09_erasure_plan_original_v1,
)
from sylanne3.authority_service.c09_owner_pairing_rows_v1 import (
    SCHEMAS as OWNER_PAIRING_SCHEMAS, verify_owner_pairing_schema_v1,
    validate_owner_pairing_row_v1,
)


def test_signed_owner_plan_persists_and_rejects_changed_access(tmp_path):
    chain = _real_owner_chain(
        tmp_path, extra_purpose="context",
        extra_capability="workbench.erase",
        extra_specs=D06DomainProvider.type_specs(),
    )
    registry = TypeRegistry()
    registry.register(owner_grant_spec())
    for spec in D06DomainProvider.type_specs():
        registry.register(spec)
    graph = None
    try:
        # The real Ed25519-paired Owner installation must be classified in
        # C09's four-file inventory, including current/revoked identity facts.
        with chain.service.core._tx() as db:
            verify_owner_pairing_schema_v1(db)
            for table in OWNER_PAIRING_SCHEMAS:
                columns = tuple(row[1] for row in db.execute(f"PRAGMA table_info({table})"))
                originals = db.execute(f"SELECT * FROM {table}").fetchall()
                assert originals
                for row in originals:
                    assert validate_owner_pairing_row_v1(table, columns, row,
                        authority_id=chain.authority_id) == chain.service.namespace
        graph = ProductionGraphStore(tmp_path / "business.db", registry)
        coordinator = GraphCoordinator(
            graph, chain.bootstrap, holder="administrator",
            content_fence_v2=chain.port,
            owner_principal_resolver=chain.current_principal,
        )
        provider = D06DomainProvider()
        coordinator.register_provider(
            chain.bootstrap, "d06", provider, "d06.contract.v1",
            provider.descriptor.request_schema_hash,
        )
        source = source_key(*ROLE.as_tuple, "source-c09")
        access = access_key(*ROLE.as_tuple, "source-c09")
        record = SourceRecord(
            "source-c09", "private", "speaker", "reported", "reported",
            1.0, 2.0, "family", ("owner",), ("context",),
        )
        access_value = {
            "source_id": "source-c09", "audiences": ["owner"],
            "purposes": ["context"], "status": "active", "recorded_at": 2.0,
        }
        snapshot = GraphStore.graph_snapshot(
            graph, (source, access), _capability=graph._coordinator_capability)
        GraphStore.graph_commit(
            graph, GraphCandidate(
                Event(Scope(*ROLE.as_tuple, "seed"), "seed-c09-source", 2.0,
                      "seed", {}), snapshot.versions,
                (GraphWrite(source, record.to_dict()),
                 GraphWrite(access, access_value, (source,))), snapshot.epochs,
            ), _capability=graph._coordinator_capability,
        )
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
        try:
            operation_id = str(uuid4())
            original = coordinator.issue_current_c09_erasure_plan_v1(
                authority, lease, operation_id=operation_id,
                source_ref=source.token)
            assert original.root_source_ids == ("source-c09",)
            assert original.scope_kind == "one_source"
            assert original.source_ref == source.token
            assert coordinator.read_current_c09_erasure_plan_v1(
                authority, lease, operation_id=operation_id) == original
            assert coordinator.issue_current_c09_erasure_plan_v1(
                authority, lease, operation_id=operation_id,
                source_ref=source.token) == original
            assert read_c09_erasure_plan_original_v1(
                graph._db, ROLE, operation_id) == original
            changed = {**access_value, "status": "withdrawn", "recorded_at": 3.0}
            snapshot = GraphStore.graph_snapshot(
                graph, (source, access),
                _capability=graph._coordinator_capability)
            GraphStore.graph_commit(
                graph, GraphCandidate(
                    Event(Scope(*ROLE.as_tuple, "seed"), "withdraw-c09-source",
                          3.0, "seed", {}), snapshot.versions,
                    (GraphWrite(access, changed, (source,)),), snapshot.epochs,
                ), _capability=graph._coordinator_capability,
            )
            with pytest.raises(UnavailableGuard):
                coordinator.read_current_c09_erasure_plan_v1(
                    authority, lease, operation_id=operation_id)
        finally:
            coordinator.release_current_owner_lease(chain.bootstrap, lease)
    finally:
        if graph is not None:
            graph.close()
        for resource in chain.resources:
            resource.close()
