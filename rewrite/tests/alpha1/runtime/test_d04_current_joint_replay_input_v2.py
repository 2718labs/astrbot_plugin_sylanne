"""A complete graph component supplies typed replay inputs, never a certificate."""

import pytest
from dataclasses import replace

from rewrite.tests.alpha1.integration.test_owner_signed_chain import (
    ADMIN, PEER, ROLE, _real_owner_chain,
)
from sylanne3.domains.d04 import AffectAxis, AffectProvider, AffectScheme
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry, owner_grant_spec
from sylanne3.native_runtime.d04_snapshot_compiler import PARAMETER_BOUNDS
from sylanne3.runtime.authoritative_coupling_snapshot import (
    FIXED_COUPLING_VERSION, FIXED_OPERATOR_VERSION, FIXED_PARAMETER_VERSION,
)

from sylanne3.runtime.d04_current_joint_replay_input_v2 import (
    read_current_joint_replay_input_in_transaction_v2,
)
from sylanne3.runtime.joint_numeric_component import JointNumericHold
from sylanne3.runtime_contracts import QueryEpoch

from rewrite.tests.alpha1.numerics.test_joint_numeric_component import _component


def _read(store, namespace, scheme, root):
    db = store._db
    db.execute("BEGIN")
    try:
        return read_current_joint_replay_input_in_transaction_v2(
            db, namespace=namespace, registry=store._registry, scheme=scheme,
            root_ref=root.token, role_start=1.0, role_end=2.0,
            expected_query_epoch=QueryEpoch(namespace, "all", 1),
            expected_graph_incarnation="graph:one", expected_graph_revision=1,
            expected_access_epoch=0, expected_delete_epoch=0,
            audience=("owner",), purpose="context",
        )
    finally:
        db.rollback()


def test_complete_component_decodes_original_replay_inputs(tmp_path):
    store, namespace, scheme, root, other, _edge = _component(tmp_path)
    try:
        result = _read(store, namespace, scheme, root)
        assert result.component.checkpoint_refs == tuple(sorted((root.token, other.token)))
        assert len(result.checkpoints) == len(result.drives) == 2
        assert len(result.families) == 1
        assert result.families[0].source_ref == result.drives[0].source_ref
        assert result.status == "current_owner_fenced_input_pending_installed_replay"
        assert result.component.status == "hold"
    finally:
        store.close()


def test_changed_graph_or_source_fails_before_replay(tmp_path):
    store, namespace, scheme, root, _other, _edge = _component(tmp_path)
    try:
        source_ref = _read(store, namespace, scheme, root).drives[0].source_ref
        store._db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (source_ref,))
        with pytest.raises(JointNumericHold, match="source"):
            _read(store, namespace, scheme, root)
        store._db.execute("UPDATE graph_epochs SET revision=2")
        with pytest.raises(JointNumericHold, match="epoch"):
            _read(store, namespace, scheme, root)
    finally:
        store.close()


def test_signed_owner_fence_reaches_component_and_revocation_denies_read(tmp_path):
    scheme = AffectScheme(
        "d04.affect.scheme.v1", SCHEME_VERSION, FIXED_OPERATOR_VERSION,
        FIXED_PARAMETER_VERSION, FIXED_COUPLING_VERSION,
        tuple(AffectAxis(axis, "normalized", axis) for axis in REGISTERED_AXIS_IDS),
        PARAMETER_BOUNDS,
    )
    provider = AffectProvider(active_scheme=scheme)
    specs = D06DomainProvider.type_specs() + provider.type_specs()
    chain = _real_owner_chain(tmp_path, extra_purpose="context", extra_specs=specs)
    registry = TypeRegistry()
    registry.register(owner_grant_spec())
    for spec in specs:
        registry.register(spec)
    graph = None
    try:
        graph = ProductionGraphStore(tmp_path / "business.db", registry)
        coordinator = GraphCoordinator(
            graph, chain.bootstrap, holder="administrator",
            content_fence_v2=chain.port,
            owner_principal_resolver=chain.current_principal,
        )
        coordinator.register_provider(
            chain.bootstrap, "d04", provider,
            provider.descriptor.contract_version,
            provider.descriptor.request_schema_hash,
        )
        request = replace(chain.issue_request, audience="owner")
        challenge = chain.sessions.begin_login(
            transport_credential=PEER, request=request)
        token = chain.sessions.accept_login(
            transport_credential=PEER, challenge=challenge,
            signature=chain.key.sign(challenge.signed_bytes()))
        authority, lease, _ = coordinator.grant_current_owner(
            chain.bootstrap, actor="owner-actor", namespace=ROLE,
            domains=("d04",), purpose="context", audience="owner",
            activation_generation=1, owner_session_token=token,
            owner_session_request=request,
        )
        root = AtomKey(Owner("persona", *ROLE.as_tuple),
                       "d04.numeric_checkpoint.v1", "root").token
        try:
            with pytest.raises(UnavailableGuard) as absent:
                coordinator.read_current_d04_joint_replay_input_v2(
                    authority, lease, root_ref=root, role_start=1.0,
                    role_end=2.0, audience=("owner",), purpose="context")
            assert isinstance(absent.value.__cause__, JointNumericHold)
            chain.source.revoke_actor(
                administrator_credential=ADMIN, binding=chain.actor_binding)
            with pytest.raises(UnavailableGuard) as revoked:
                coordinator.read_current_d04_joint_replay_input_v2(
                    authority, lease, root_ref=root, role_start=1.0,
                    role_end=2.0, audience=("owner",), purpose="context")
            assert not isinstance(revoked.value.__cause__, JointNumericHold)
        finally:
            coordinator.release_current_owner_lease(chain.bootstrap, lease)
    finally:
        if graph is not None:
            graph.close()
        for resource in chain.resources:
            resource.close()
