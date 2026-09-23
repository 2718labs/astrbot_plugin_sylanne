from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.domains.d01 import PersonaBlock, PersonaDomain, PersonaPlan
from sylanne3.graph_types import (
    GraphAtom, GraphSnapshot, NamespaceEpoch, TypeRegistry, owner_grant_key,
)
from sylanne3.runtime_contracts import NamespaceId


NAMESPACE = NamespaceId("bot", "persona")


def _plan():
    return PersonaPlan(
        "chosen", NAMESPACE, 1,
        (PersonaBlock("identity", "semantic_identity", "authored", "read_only"),),
        (), True,
    )


def _grant():
    return GraphAtom(owner_grant_key("bot", "persona"), 1, {
        "schema": "sylanne3.graph.owner_grant.v1",
        "authority_id": "authority", "installation_id": "installation",
        "grant_id": "grant", "principal": {
            "identity_provider": "local", "account_ref": "account",
            "account_incarnation": "incarnation",
        },
        "ticket_id": "ticket", "creation_operation_id": "create",
        "creation_digest": "sha256:" + "a" * 64,
        "issue_operation_id": "issue", "grant_revision": 1,
        "state": "pending_authority", "scope": "bot/persona",
        "issuer_ref": "authority:installation",
        "capabilities": ["workbench.read"], "purposes": ["workbench_view"],
        "audiences": ["owner"], "activation_generation": 1,
        "graph_incarnation": "graph-one",
    })


def _guard(**changes):
    return replace(OwnerAuthorizationGuardV1(
        "authority", "installation", NAMESPACE, 1,
        "sha256:" + "b" * 64, 0, 0,
    ), **changes)


def _snapshot(*, include_plan=True, include_activation=True, grant=None, guard=None):
    plan = _plan()
    owner_grant = grant if grant is not None else _grant()
    current_guard = guard if guard is not None else _guard()
    activation = PersonaDomain.activation_write(plan, owner_grant, current_guard)
    plan_write = PersonaDomain.plan_write(plan)
    atoms = [owner_grant]
    if include_plan:
        atoms.append(GraphAtom(plan_write.key, 1, plan_write.value))
    if include_activation:
        atoms.append(GraphAtom(activation.key, 1, activation.value))
    return GraphSnapshot(tuple(atoms), (NamespaceEpoch("bot", "persona", 3),))


def test_activation_is_registered_and_qualified_only_with_current_owner_and_plan():
    domain = PersonaDomain()
    registry = TypeRegistry()
    for spec in domain.type_specs():
        registry.register(spec)
    activation = domain.activation_write(_plan(), _grant(), _guard())
    registry.validate(activation.key, activation.value)
    assert activation.dependencies == (_grant().key, domain.plan_write(_plan()).key)
    result = domain.resolve_active_role(_snapshot(), namespace=NAMESPACE, current_guard=_guard())
    assert result.head_id == "chosen@1"
    assert result.graph_epoch == 3
    assert tuple(ref.revision for ref in result.read_versions) == (1, 1, 1)


@pytest.mark.parametrize("include_plan, include_activation", [(False, True), (True, False)])
def test_candidates_or_incomplete_graph_are_not_active(include_plan, include_activation):
    with pytest.raises(ValueError):
        PersonaDomain.resolve_active_role(
            _snapshot(include_plan=include_plan, include_activation=include_activation),
            namespace=NAMESPACE, current_guard=_guard(),
        )


def test_stale_or_revoking_owner_blocks_active_role():
    snapshot = _snapshot()
    for guard in (
        _guard(pending_revoke_operation_id="revoke"),
        _guard(authorization_revision=2),
        _guard(minimum_revocation_revision=1),
        _guard(minimum_revocation_epoch=1),
        _guard(installation_id="other"),
    ):
        with pytest.raises(ValueError):
            PersonaDomain.resolve_active_role(snapshot, namespace=NAMESPACE, current_guard=guard)


def test_activation_rejects_owner_from_another_namespace_or_uncommitted_guard():
    grant = _grant()
    with pytest.raises(ValueError):
        PersonaDomain.activation_write(
            _plan(), replace(grant, key=owner_grant_key("bot", "other")), _guard())
    with pytest.raises(ValueError):
        PersonaDomain.activation_write(
            _plan(), grant, replace(_guard(), authorization_revision=0,
                                    authorization_head="genesis"))
