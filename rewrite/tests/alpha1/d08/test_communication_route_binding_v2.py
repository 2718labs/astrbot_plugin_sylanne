"""The private-reply target is an account entity, while delivery is a route."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.d08.test_dispatch_check_scope_v2 import _case, _read, _route
from rewrite.tests.alpha1.d08.test_goal_execution_domain import _receipt
from sylanne3.domains.d08 import (
    CommunicationGrantRequest, CommunicationSegmentSpec,
    RequiredCheckRegistry, verify_route_bound_grant_v2,
)
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, Owner
from sylanne3.runtime_contracts import canonical_serialize


def _request(audience: str) -> CommunicationGrantRequest:
    return CommunicationGrantRequest(
        "communication:reply-1", "contact:reply-1", 1, (audience,),
        (), ("reported_claim",), (),
        (CommunicationSegmentSpec(
            "segment:reply-1", "effect:reply-segment-1", 0,
            "a" * 64, 200, (), None,
        ),), 0,
    )


def test_entity_target_and_json_audience_freeze_only_with_current_binding():
    case = _case()
    db, snapshot, _, scope, _, _, intent, schema = case
    try:
        route = _route(case)
        assert "\\u" in route.conversation_ref
        registry = RequiredCheckRegistry()
        registry.register(schema)
        decision = registry.qualify(
            intent, tuple(_receipt(spec) for spec in intent.required_checks),
            now=5.0,
        )
        request = _request(route.conversation_ref)
        grant = registry.freeze_communication_grant_v2(
            intent, decision, request, route_binding=route, db=db,
            snapshot=snapshot, scope=scope, now=6.0,
        )
        assert grant.target_ref == intent.target_ref == route.target_entity_ref
        assert grant.audiences == (route.conversation_ref,)
        assert grant.target_ref not in grant.audiences
        assert grant.route_binding_digest is not None
        verify_route_bound_grant_v2(grant, intent, request, route)
        assert _read(case).receipt.result == "pass"
        with pytest.raises(ValueError, match="current W01 entity route"):
            registry.freeze_communication_grant_v2(
                intent, decision, request, route_binding=None, db=db,
                snapshot=snapshot, scope=scope, now=6.0,
            )
        with pytest.raises(ValueError, match="private reply entity"):
            registry.freeze_communication_grant_v2(
                intent, decision, _request('["host","other"]'),
                route_binding=route, db=db, snapshot=snapshot, scope=scope,
                now=6.0,
            )
        with pytest.raises(ValueError, match="graph version is not current"):
            _read(case, route_binding=replace(
                route, binding_version=GraphVersion(route.binding_version.key, 2)))
        with pytest.raises(ValueError, match="negative query closure"):
            _read(case, route_binding=replace(route, binding_scan_versions=()))
        with pytest.raises(ValueError, match="entity route"):
            verify_route_bound_grant_v2(
                grant, intent, request,
                replace(route, conversation_ref='["host","other"]'))
    finally:
        db.close()


def test_future_account_binding_is_scanned_but_not_current_duplicate():
    case = _case()
    db, snapshot, query, _, _, _, _, _ = case
    try:
        route = _route(case)
        future_key = AtomKey(
            Owner("persona", *query.namespace.as_tuple),
            "d03.account_binding", "account:future")
        current = snapshot.get(route.binding_version.key)
        value = dict(current.value, account_id="account:future", valid_from=50.0)
        future = GraphAtom(future_key, 1, value)
        db.execute(
            "INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?)",
            (future_key.token, *query.namespace.as_tuple,
             future_key.type_name, future_key.name, 1,
             canonical_serialize(value), 1))
        expanded = GraphSnapshot(snapshot.atoms + (future,), snapshot.epochs)
        route = replace(route, binding_scan_versions=tuple(sorted(
            (*route.binding_scan_versions, GraphVersion(future_key, 1)),
            key=lambda item: item.key.token)))
        assert _read(case, route_binding=route, snapshot=expanded).receipt.result == "pass"
    finally:
        db.close()
