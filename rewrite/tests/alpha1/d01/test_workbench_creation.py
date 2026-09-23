import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domain_registry import DomainRegistration, DomainRegistry
from sylanne3.domains.d01 import PersonaBlock, PersonaDomain, PersonaPlan, ValueRule
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (AtomKey, GraphAtom, GraphCandidate, GraphPage, GraphSnapshot,
                                  GraphVersion, GraphWrite, NamespaceEpoch, Owner, TypeRegistry)
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId
from sylanne3.workbench_api import AuthenticatedSession, CoordinatorGrant, CurrentDomainViewRegistry, GraphWorkbenchIssuer


NAMESPACE = NamespaceId("bot", "persona")
AUTHORITY = AuthorityContext("actor", "d12", "capability", NAMESPACE, ("persona",),
                             "workbench_view", ("owner",), "policy", 4)
SESSION = AuthenticatedSession("actor", "session", {"bot/persona": frozenset({"workbench.read"})},
                               {"bot/persona": frozenset({"owner"})},
                               {"bot/persona": frozenset({"workbench_view"})})


def plan(plan_id="candidate"):
    return PersonaPlan(plan_id, NAMESPACE, 2,
                       (PersonaBlock("identity", "semantic_identity", "private claim", "read_only"),),
                       (ValueRule("rule", "private label", ("context",), (), ()),), True)


def atom(plan_id="candidate", *, revision=3):
    return {"type": "d01.persona_plan.v1", "name": plan_id,
            "revision": revision, "value": PersonaDomain.plan_write(plan(plan_id)).value}


def registry():
    provider = PersonaDomain()
    types = TypeRegistry()
    for spec in provider.type_specs():
        types.register(spec)
    registration = DomainRegistration("d01", provider, "d01.proposal.v1",
                                      provider.descriptor.request_schema_hash, provider.type_specs())
    current = DomainRegistry({"d01": registration}, {}, types.freeze())
    return CurrentDomainViewRegistry(lambda: current)


def test_creation_contract_is_declared_and_empty_stays_empty():
    current = registry()
    assert current.view_types(AUTHORITY) == {"creation": ("d01.persona_plan.v1",)}
    assert current.project_workbench(AUTHORITY, "creation", ()) == {"candidates": []}


def test_creation_lists_candidates_without_claims_labels_or_active_guess():
    output = registry().project_workbench(AUTHORITY, "creation", (atom("first"), atom("second")))
    assert output == {"candidates": [
        {"plan_id": "first", "version": 2, "authored": True,
         "block_count": 1, "value_rule_count": 1},
        {"plan_id": "second", "version": 2, "authored": True,
         "block_count": 1, "value_rule_count": 1},
    ]}
    assert "private" not in str(output)
    assert "current" not in str(output)


@pytest.mark.parametrize("mutate", [
    lambda item: item.update(type="d01.persona_revision.v1"),
    lambda item: item.update(revision=True),
    lambda item: item.update(revision=0),
    lambda item: item.update(name="wrong"),
    lambda item: item["value"].update(version="2"),
    lambda item: item["value"].update(secret="private"),
    lambda item: item["value"]["blocks"][0].update(claim=""),
    lambda item: item.update(secret="private"),
])
def test_creation_rejects_malformed_or_undeclared_atom(mutate):
    item = atom()
    mutate(item)
    with pytest.raises((TypeError, ValueError)):
        registry().project_workbench(AUTHORITY, "creation", (item,))


class _Resolver:
    def __init__(self, grant):
        self.grant = grant

    def resolve(self, **_):
        return self.grant


class _Coordinator:
    def __init__(self, page):
        self.page = page
        self.calls = []

    def query(self, authority, lease, **kwargs):
        self.calls.append(kwargs)
        return self.page


def test_issuer_preserves_coverage_and_does_not_project_unreturned_candidates():
    item = atom()
    graph_atom = GraphAtom(AtomKey(Owner("persona", "bot", "persona"), item["type"], item["name"]),
                           item["revision"], item["value"])
    cursor = graph_atom.key
    page = GraphPage(GraphSnapshot((graph_atom,), (NamespaceEpoch("bot", "persona", 8),)), cursor)
    coordinator = _Coordinator(page)
    issuer = GraphWorkbenchIssuer(coordinator,
                                  _Resolver(CoordinatorGrant("bot/persona", AUTHORITY, object())), registry())
    result = issuer.read_projection(session=SESSION, scope="bot/persona", view_type="creation",
                                    purpose="workbench_view", audience="owner")
    assert result["status"] == "ready"
    assert result["projection"]["data"]["candidates"][0]["plan_id"] == "candidate"
    assert result["projection"]["coverage"]["truncated"] is True
    assert result["projection"]["next_cursor"] == cursor.token
    assert coordinator.calls == [{"type_names": ("d01.persona_plan.v1",),
                                   "owner_kind": "persona", "limit": 100}]


def test_issuer_denies_missing_grant_before_query():
    coordinator = _Coordinator(None)
    issuer = GraphWorkbenchIssuer(coordinator, _Resolver(None), registry())
    result = issuer.read_projection(session=SESSION, scope="bot/persona", view_type="creation",
                                    purpose="workbench_view", audience="owner")
    assert result["problem"]["code"] == "authority_unavailable"
    assert coordinator.calls == []


def test_real_graph_query_projects_persisted_plan_with_actual_epoch_and_authority(tmp_path):
    provider = PersonaDomain()
    types = TypeRegistry()
    for spec in provider.type_specs():
        types.register(spec)
    store = GraphStore(tmp_path / "creation.db", types)
    try:
        bootstrap = object()
        coordinator = GraphCoordinator(store, bootstrap)
        coordinator.register_provider(bootstrap, "d01", provider, "d01.proposal.v1",
                                      provider.descriptor.request_schema_hash)
        lease, capability = coordinator.grant(
            bootstrap, actor="actor", issuer_domain="d12", namespace=NAMESPACE,
            domains=("d01",), activation_generation=4)
        authority = AuthorityContext("actor", "d12", capability, NAMESPACE,
                                     ("persona",), "workbench_view", ("owner",), "policy", 4)
        write = provider.plan_write(plan())
        receipt = store.graph_commit(GraphCandidate(
            Event(Scope("bot", "persona", "setup"), "plan-write", 1.0,
                  "test_plan_setup", {}),
            (GraphVersion(write.key, 0),), (GraphWrite(write.key, write.value),),
            (NamespaceEpoch("bot", "persona", 0),),
        ))
        assert receipt.status == "committed"
        actual_page = coordinator.query(authority, lease,
                                        type_names=("d01.persona_plan.v1",), owner_kind="persona")
        assert actual_page.snapshot.atoms[0].revision == 1
        assert actual_page.snapshot.epochs[0].revision == 1
        issuer = GraphWorkbenchIssuer(coordinator,
                                      _Resolver(CoordinatorGrant("bot/persona", authority, lease)),
                                      registry())
        result = issuer.read_projection(session=SESSION, scope="bot/persona", view_type="creation",
                                        purpose="workbench_view", audience="owner")
        assert result["status"] == "ready"
        projection = result["projection"]
        assert projection["snapshot_epoch"] == receipt.epoch.revision == 1
        assert projection["coverage"] == {"requested_types": ("d01.persona_plan.v1",),
                                          "returned_atoms": 1, "truncated": False}
        assert projection["data"] == {"candidates": [{
            "plan_id": "candidate", "version": 2, "authored": True,
            "block_count": 1, "value_rule_count": 1,
        }]}
        assert "private claim" not in str(result)
        assert "private label" not in str(result)
        with pytest.raises(PermissionError):
            coordinator.query(authority, object(), type_names=("d01.persona_plan.v1",),
                              owner_kind="persona")
        denied_issuer = GraphWorkbenchIssuer(
            coordinator, _Resolver(CoordinatorGrant("bot/persona", authority, object())), registry())
        with pytest.raises(PermissionError):
            denied_issuer.read_projection(session=SESSION, scope="bot/persona",
                                          view_type="creation", purpose="workbench_view",
                                          audience="owner")
    finally:
        store.close()
