"""D03 role resolution uses the authorised graph query and carries its CAS guard."""

from dataclasses import asdict

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d03 import ContextProvider, RoleBinding, RoleBindingRequest
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry,
)
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId


def _binding(*, version=1, status="active"):
    return RoleBinding(
        "binding:project", "persona:persona", "collaborator", None, None,
        "scene:project", "scene", "project", ("norm:project",), 1.0,
        None, 10, ("source:role",), version, status,
    )


def _request(*, scene="scene:project"):
    return RoleBindingRequest(
        "persona:persona", None, None, scene, "respond", "respond", 5.0, True,
    )


def test_graph_resolution_requires_current_binding_and_returns_guard(tmp_path):
    provider = ContextProvider()
    provider.compile_scheme({
        "schema": "d03.context.scheme.v1",
        "roles": ("collaborator",), "norms": ("norm:project",),
    }, None)
    registry = TypeRegistry()
    for spec in provider.type_specs():
        registry.register(spec)
    store = GraphStore(tmp_path / "graph.db", registry)
    try:
        bootstrap = object()
        coordinator = GraphCoordinator(store, bootstrap)
        coordinator.register_provider(
            bootstrap, "d03", provider, "d03.proposal.v1", "d" * 64,
        )
        namespace = NamespaceId("bot", "persona")
        lease, ref = coordinator.grant(
            bootstrap, actor="host", issuer_domain="d03", namespace=namespace,
            domains=("d03",), activation_generation=1,
        )
        authority = AuthorityContext(
            "host", "d03", ref, namespace, ("persona", "scene"), "respond",
            ("internal",), "policy", 1,
        )
        absent = provider.resolve_role_binding_from_graph(
            _request(), coordinator, authority, lease,
        )
        assert absent.status == "no_applicable_binding"
        assert absent.query_epoch is not None and absent.query_epoch.revision == 0
        assert absent.read_versions == ()

        key = AtomKey(
            Owner("scene", "bot", "persona", "scene:project"),
            "d03.role_binding", "binding:project",
        )
        def commit(binding, revision, event_id):
            value = asdict(binding)
            value["norm_refs"] = list(binding.norm_refs)
            value["source_refs"] = list(binding.source_refs)
            candidate = GraphCandidate(
                Event(Scope("bot", "persona", "test"), event_id, 2.0,
                      "test", {"binding": event_id}),
                (GraphVersion(key, revision),),
                (GraphWrite(key, value),),
            )
            store.graph_commit(candidate)

        commit(_binding(), 0, "create")
        resolved = provider.resolve_role_binding_from_graph(
            _request(), coordinator, authority, lease,
        )
        assert resolved.status == "complete"
        assert resolved.matched_bindings == ("binding:project",)
        assert resolved.read_versions == (GraphVersion(key, 1),)
        assert resolved.query_epoch is not None and resolved.query_epoch.revision == 1
        assert provider.resolve_role_binding_from_graph(
            _request(scene="scene:other"), coordinator, authority, lease,
        ).status == "no_applicable_binding"

        commit(_binding(version=2, status="revoked"), 1, "revoke")
        revoked = provider.resolve_role_binding_from_graph(
            _request(), coordinator, authority, lease,
        )
        assert revoked.status == "no_applicable_binding"
        assert revoked.query_epoch is not None and revoked.query_epoch.revision == 2
        assert revoked.read_versions == (GraphVersion(key, 2),)

        commit(_binding(version=4), 2, "bad-version")
        stale = provider.resolve_role_binding_from_graph(
            _request(), coordinator, authority, lease,
        )
        assert stale.status == "stale"
        assert stale.missing_items == ("binding_version",)
    finally:
        store.close()


def test_pure_binding_resolution_rejects_unknown_social_role():
    provider = ContextProvider()
    provider.compile_scheme({
        "schema": "d03.context.scheme.v1",
        "roles": ("collaborator",), "norms": ("norm:project",),
    }, None)
    binding = RoleBinding(**{**asdict(_binding()), "social_role": "owner"})
    result = provider.resolve_role_binding(_request(), (binding,))
    assert result.status == "partial"
    assert result.missing_items == ("role_catalogue",)
