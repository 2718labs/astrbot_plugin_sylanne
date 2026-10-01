from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.domains.d01 import GrowthProposal, PersonaBlock, PersonaDomain, PersonaPlan
from sylanne3.graph_types import (
    GraphAtom, GraphSnapshot, NamespaceEpoch, TypeRegistry, owner_grant_key,
)
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.domains.d06 import source_correction_head_key


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


def test_growth_candidate_uses_current_head_and_graph_source_consumption():
    domain = PersonaDomain()
    growth_plan = PersonaPlan(
        "chosen", NAMESPACE, 1,
        (_plan().blocks[0], PersonaBlock("care", "value", "be caring", "growth")),
        (), True,
    )
    grant = _grant()
    plan_write = domain.plan_write(growth_plan)
    activation = domain.activation_write(growth_plan, grant, _guard())
    atoms = [grant, GraphAtom(plan_write.key, 1, plan_write.value),
             GraphAtom(activation.key, 1, activation.value)]
    for source_id, root in (("observed:one", "family:one"), ("observed:two", "family:two")):
        source = SourceRecord(source_id, "observed outcome", "user", "observed", "confirmed",
                              1.0, 1.0, root, ("owner",), ("consolidation",), (), "independent")
        atoms.append(GraphAtom(source_key("bot", "persona", source_id), 1, source.to_dict()))
        atoms.append(GraphAtom(access_key("bot", "persona", source_id), 1, {
            "source_id": source_id, "audiences": ["owner"], "purposes": ["consolidation"],
            "status": "active", "recorded_at": 1.0,
        }))
        atoms.append(GraphAtom(source_correction_head_key(NAMESPACE, source_id), 0, {}, False))
    snapshot = GraphSnapshot(tuple(atoms), (NamespaceEpoch("bot", "persona", 3),))
    growth = GrowthProposal("growth:one", "chosen@1", "care", "care with consent",
                            ("family:one", "family:two"), True, "core")
    candidate = domain.issue_growth_candidate(
        snapshot, namespace=NAMESPACE, current_guard=_guard(), proposal=growth,
        source_ids=("observed:one", "observed:two"),
    )
    assert candidate.head_id == "chosen@2"
    assert {write.key.type_name for write in candidate.typed_writes} == {
        "d01.persona_plan.v1", "d01.persona_revision.v1",
        "d01.persona_activation.v1", "d01.growth_contribution.v1",
    }
    assert len(candidate.read_versions) == 13  # head/grant, source/access/correction, absent contributions, revision/activation
    assert tuple(ref.revision for ref in candidate.read_versions[-4:-2]) == (0, 0)
    assert domain.validate_growth_candidate(
        candidate, snapshot, namespace=NAMESPACE, current_guard=_guard(),
        proposal=growth, source_ids=("observed:one", "observed:two"),
    ) is candidate
    with pytest.raises(ValueError, match="differs"):
        domain.validate_growth_candidate(
            replace(candidate, read_versions=candidate.read_versions[:-1]), snapshot,
            namespace=NAMESPACE, current_guard=_guard(), proposal=growth,
            source_ids=("observed:one", "observed:two"),
        )
    consumed = candidate.typed_writes[-1]
    with pytest.raises(ValueError, match="already been consumed"):
        domain.issue_growth_candidate(
            replace(snapshot, atoms=snapshot.atoms + (GraphAtom(consumed.key, 1, consumed.value),)),
            namespace=NAMESPACE, current_guard=_guard(), proposal=growth,
            source_ids=("observed:one", "observed:two"),
        )
    with pytest.raises(ValueError, match="stale persona head"):
        domain.issue_growth_candidate(
            snapshot, namespace=NAMESPACE, current_guard=_guard(),
            proposal=replace(growth, base_head="chosen@0"),
            source_ids=("observed:one", "observed:two"),
        )
    authored_source = replace(SourceRecord.from_dict(atoms[3].value), source_kind="authored")
    with pytest.raises(ValueError, match="cannot support natural growth"):
        domain.issue_growth_candidate(
            replace(snapshot, atoms=tuple(
                GraphAtom(atom.key, atom.revision, authored_source.to_dict()) if atom.key == atoms[3].key else atom
                for atom in snapshot.atoms
            )), namespace=NAMESPACE, current_guard=_guard(), proposal=growth,
            source_ids=("observed:one", "observed:two"),
        )
    corrected_head = source_correction_head_key(NAMESPACE, "observed:one")
    with pytest.raises(ValueError, match="growth evidence or access"):
        domain.issue_growth_candidate(
            replace(snapshot, atoms=tuple(
                replace(atom, valid=True, revision=1) if atom.key == corrected_head else atom
                for atom in snapshot.atoms
            )), namespace=NAMESPACE, current_guard=_guard(), proposal=growth,
            source_ids=("observed:one", "observed:two"),
        )
