from __future__ import annotations

from uuid import uuid4
from types import MappingProxyType
import pytest

from sylanne3.domain_registry import DomainRegistration, DomainRegistry
from sylanne3.graph_types import AtomKey, GraphAtom, GraphPage, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.graph_types import TypeRegistry, TypeSpec
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId
from sylanne3.workbench_api import (
    AuthenticatedSession, CoordinatorGrant, CurrentDomainViewRegistry, GraphWorkbenchIssuer,
    RequestContext, WorkbenchService,
)
from sylanne3.workbench_api.domain_registry import PROJECTION_CONTEXT_V1


SCOPE = "bot/persona"
SESSION = AuthenticatedSession(
    "actor", "session", {SCOPE: frozenset({"workbench.read"})},
    {SCOPE: frozenset({"owner"})}, {SCOPE: frozenset({"workbench_view"})},
)
CONTEXT = RequestContext(origin_verified=True, csrf_verified=True, session_bound=True)


def authority(*, purpose="workbench_view", audience=("owner",), owner_scope=("persona", "event")):
    return AuthorityContext("actor", "d12", "capability", NamespaceId("bot", "persona"),
                            owner_scope, purpose, audience, "policy", 4)


class Resolver:
    def __init__(self, grant):
        self.grant = grant
        self.calls = []

    def resolve(self, **kwargs):
        self.calls.append(kwargs)
        return self.grant


class Coordinator:
    def __init__(self, page):
        self.page = page
        self.calls = []

    def query(self, authority_context, lease, **kwargs):
        self.calls.append((authority_context, lease, kwargs))
        if kwargs["owner_kind"] == "event" and isinstance(self.page, GraphPage):
            return GraphPage(GraphSnapshot((), self.page.snapshot.epochs), None)
        return self.page


class Registry:
    def __init__(self, views=None):
        self.views = views or {"overview": ("d01.persona_plan.v1",), "memory": ("d06.recollection.v1",)}
        self.calls = []

    def view_types(self, authority_context):
        self.calls.append(authority_context)
        return self.views

    def view_owner_kind(self, authority_context, view_type):
        return "event" if view_type == "memory" else "persona"

    def project_workbench(self, authority_context, view_type, atoms):
        return {"summary": f"{view_type}:{len(atoms)}"}


def request(action="read_character_view", **input_data):
    body = {"view_type": "overview"} if action == "read_character_view" else {"client_protocol": "d12.contract.v1"}
    body.update(input_data)
    return {"schema_version": "d12.contract.v1", "action": action, "scope": SCOPE,
            "purpose": "workbench_view", "audience": "owner", "operation_id": str(uuid4()),
            "input": body}


def issuer(*, resolver_grant=None, page=None):
    resolver = Resolver(resolver_grant or CoordinatorGrant(SCOPE, authority(), object()))
    atom = GraphAtom(AtomKey(Owner("persona", "bot", "persona"), "d01.persona_plan.v1", "current"),
                     3, {"schema": "d01.persona_plan.v1", "head_id": "head", "namespace": "persona",
                         "blocks": [], "values": [], "authored": {}})
    page = page or GraphPage(GraphSnapshot((atom,), (NamespaceEpoch("bot", "persona", 9),)), None)
    coordinator = Coordinator(page)
    return GraphWorkbenchIssuer(coordinator, resolver, Registry()), coordinator, resolver


def test_character_view_uses_single_coordinator_snapshot_and_server_grant():
    provider, coordinator, resolver = issuer()
    answer = WorkbenchService(provider).handle(request(), session=SESSION, context=CONTEXT)
    assert answer.status == "ready"
    assert answer.projection["snapshot_epoch"] == 9
    assert answer.projection["access_generation"] == 4
    assert answer.projection["data"] == {"summary": "overview:1"}
    assert answer.projection["coverage"]["truncated"] is False
    assert coordinator.calls[0][2]["owner_kind"] == "persona"
    assert resolver.calls[0]["scope"] == SCOPE


def test_memory_view_reads_event_owned_graph_atoms_with_event_grant():
    provider, coordinator, _ = issuer()
    atom = GraphAtom(AtomKey(Owner("event", "bot", "persona", "source-1"),
                             "memory.source", "record"), 2, {"source_id": "source-1"})
    page = GraphPage(GraphSnapshot((atom,), (NamespaceEpoch("bot", "persona", 12),)), None)

    def query(authority_context, lease, **kwargs):
        coordinator.calls.append((authority_context, lease, kwargs))
        return page

    coordinator.query = query
    provider._view_registry = Registry({"memory": ("memory.source",)})
    answer = WorkbenchService(provider).handle(
        request(view_type="memory"), session=SESSION, context=CONTEXT)
    assert answer.status == "ready"
    assert answer.projection["data"] == {"summary": "memory:1"}
    assert answer.projection["snapshot_epoch"] == 12
    assert coordinator.calls[0][2]["owner_kind"] == "event"


def test_memory_view_without_event_scope_does_not_query_or_expose_atoms():
    provider, coordinator, _ = issuer(
        resolver_grant=CoordinatorGrant(SCOPE, authority(owner_scope=("persona",)), object()))
    answer = WorkbenchService(provider).handle(
        request(view_type="memory"), session=SESSION, context=CONTEXT)
    assert answer.status == "unavailable"
    assert answer.projection is None
    assert not coordinator.calls


def test_memory_view_rejects_mismatched_graph_owner_before_projection():
    provider, coordinator, _ = issuer()
    provider._view_registry = Registry({"memory": ("memory.source",)})

    def query(authority_context, lease, **kwargs):
        coordinator.calls.append((authority_context, lease, kwargs))
        return coordinator.page

    coordinator.query = query
    answer = WorkbenchService(provider).handle(
        request(view_type="memory"), session=SESSION, context=CONTEXT)
    assert answer.status == "unavailable"
    assert answer.problem["code"] == "invalid_graph_snapshot"
    assert answer.projection is None


def test_missing_or_mismatched_authority_never_queries_or_leaks_projection():
    provider, coordinator, _ = issuer(resolver_grant=None)
    # A resolver that returns no coordinator grant is a normal unavailable state.
    provider._grants.grant = None
    answer = WorkbenchService(provider).handle(request(), session=SESSION, context=CONTEXT)
    assert answer.status == "unavailable"
    assert answer.problem["code"] == "authority_unavailable"
    assert not coordinator.calls

    bad = CoordinatorGrant(SCOPE, authority(audience=("another",)), object())
    provider, coordinator, _ = issuer(resolver_grant=bad)
    answer = WorkbenchService(provider).handle(request(), session=SESSION, context=CONTEXT)
    assert answer.status == "unavailable"
    assert not coordinator.calls


def test_query_failure_and_invalid_snapshot_fail_closed():
    provider, coordinator, _ = issuer(page=object())
    answer = WorkbenchService(provider).handle(request(), session=SESSION, context=CONTEXT)
    assert answer.status == "unavailable"
    assert answer.projection is None
    assert answer.problem["code"] == "invalid_graph_snapshot"


def test_open_workspace_is_a_real_read_catalogue_without_a_durable_receipt():
    provider, coordinator, _ = issuer()
    answer = WorkbenchService(provider).handle(request("open_workspace"), session=SESSION, context=CONTEXT)
    assert answer.status == "ready"
    assert answer.receipt is None
    assert {entry["view_type"] for entry in answer.projection["views"]} == {"overview", "memory"}
    assert all(entry["status"] == "available" for entry in answer.projection["views"])
    assert len(coordinator.calls) == 2
    assert {call[2]["owner_kind"] for call in coordinator.calls} == {"persona", "event"}


def test_workspace_marks_each_unqueryable_registry_view_unavailable_without_content():
    provider, coordinator, resolver = issuer()
    provider._view_registry = Registry({"overview": ("d01.persona_plan.v1",), "broken": ("d99.unknown",)})

    def query(authority_context, lease, **kwargs):
        coordinator.calls.append((authority_context, lease, kwargs))
        if kwargs["type_names"] == ("d99.unknown",):
            raise RuntimeError("registry/type mismatch")
        return coordinator.page

    coordinator.query = query
    answer = WorkbenchService(provider).handle(request("open_workspace"), session=SESSION, context=CONTEXT)
    views = {entry["view_type"]: entry for entry in answer.projection["views"]}
    assert views["overview"]["status"] == "available"
    assert views["broken"] == {"view_type": "broken", "status": "unavailable"}


class PublicProvider:
    workbench_view_contract = {"overview": {"types": ("d01.public.v1",), "fields": ("summary",)}}

    @staticmethod
    def project_workbench(view_type, atoms):
        return {"summary": view_type}


class PrivateProvider:
    pass


def domain_registry(*, provider, domain="d01", spec_name="d01.public.v1", owner_kind="persona"):
    spec = TypeSpec(spec_name, (owner_kind,), "state", lambda value: None, writer_domain=domain,
                    schema_hash="0" * 64)
    types = TypeRegistry(); types.register(spec)
    registration = DomainRegistration(domain, provider, "schema", "1" * 64, (spec,))
    return DomainRegistry(MappingProxyType({domain: registration}), MappingProxyType({}), types.freeze())


def test_current_registry_exposes_only_provider_declared_public_projection_contracts():
    public = CurrentDomainViewRegistry(lambda: domain_registry(provider=PublicProvider()))
    assert public.view_types(authority()) == {"overview": ("d01.public.v1",)}
    assert public.view_owner_kind(authority(), "overview") == "persona"
    assert public.project_workbench(authority(), "overview", ()) == {"summary": "overview"}

    private = CurrentDomainViewRegistry(lambda: domain_registry(provider=PrivateProvider()))
    assert private.view_types(authority()) == {}
    assert private.catalogue(authority()).unavailable_domains == {"d01": "no_public_projection_contract"}


def test_current_registry_derives_event_owner_from_registered_type_and_scope():
    class EventProvider:
        workbench_view_contract = {"memory": {"types": ("memory.source",), "fields": ("count",)}}

        @staticmethod
        def project_workbench(view_type, atoms):
            return {"count": len(atoms)}

    current = CurrentDomainViewRegistry(lambda: domain_registry(
        provider=EventProvider(), domain="d06", spec_name="memory.source", owner_kind="event"))
    assert current.view_types(authority()) == {"memory": ("memory.source",)}
    assert current.view_owner_kind(authority(), "memory") == "event"
    assert current.view_types(authority(owner_scope=("persona",))) == {}
    assert current.view_owner_kind(authority(owner_scope=("persona",)), "memory") is None
    assert current.catalogue(authority(owner_scope=("persona",))).unavailable_domains == {
        "d06": "owner_scope_denied"}


def test_current_registry_rejects_view_that_mixes_owner_kinds():
    class MixedProvider:
        workbench_view_contract = {"memory": {
            "types": ("memory.source", "d06.recollection.v1"), "fields": ("count",)}}

        @staticmethod
        def project_workbench(view_type, atoms):
            return {"count": len(atoms)}

    event_spec = TypeSpec("memory.source", ("event",), "source", lambda value: None,
                          writer_domain="d06", schema_hash="0" * 64)
    activity_spec = TypeSpec("d06.recollection.v1", ("activity",), "source",
                             lambda value: None, writer_domain="d06", schema_hash="1" * 64)
    types = TypeRegistry()
    types.register(event_spec)
    types.register(activity_spec)
    registration = DomainRegistration("d06", MixedProvider(), "schema", "2" * 64,
                                      (event_spec, activity_spec))
    registry = DomainRegistry(MappingProxyType({"d06": registration}), MappingProxyType({}),
                              types.freeze())
    current = CurrentDomainViewRegistry(lambda: registry)
    assert current.view_types(authority()) == {}
    assert current.catalogue(authority()).unavailable_domains == {
        "d06": "invalid_public_projection_contract"}


def test_current_registry_rejects_undeclared_atom_type_even_if_it_exists_in_catalogue():
    class UnsafeProvider:
        workbench_view_contract = {"overview": {"types": ("d01.secret.v1",), "fields": ("summary",)}}

        @staticmethod
        def project_workbench(view_type, atoms):
            return {"summary": view_type}

    registry = CurrentDomainViewRegistry(lambda: domain_registry(provider=UnsafeProvider()))
    assert registry.view_types(authority()) == {}
    assert registry.catalogue(authority()).unavailable_domains == {"d01": "invalid_public_projection_contract"}


def test_c01_and_c04_do_not_promote_private_registry_types_to_views():
    current = CurrentDomainViewRegistry(lambda: domain_registry(provider=PrivateProvider()))
    resolver = Resolver(CoordinatorGrant(SCOPE, authority(), object()))
    coordinator = Coordinator(object())
    provider = GraphWorkbenchIssuer(coordinator, resolver, current)
    opened = WorkbenchService(provider).handle(request("open_workspace"), session=SESSION, context=CONTEXT)
    assert opened.status == "ready"
    assert opened.projection["views"] == ()
    assert opened.projection["unavailable_domains"] == (
        {"domain": "d01", "reason": "no_public_projection_contract"},
    )
    viewed = WorkbenchService(provider).handle(request(), session=SESSION, context=CONTEXT)
    assert viewed.status == "unavailable"
    assert viewed.problem["code"] == "view_unsupported"
    assert not coordinator.calls


def test_grant_scope_must_match_the_server_bound_browser_scope():
    provider, coordinator, _ = issuer(resolver_grant=CoordinatorGrant("other/scope", authority(), object()))
    answer = WorkbenchService(provider).handle(request(), session=SESSION, context=CONTEXT)
    assert answer.status == "unavailable"
    assert answer.problem["code"] == "authority_unavailable"
    assert not coordinator.calls


def test_type_metadata_without_explicit_field_projector_never_returns_secret_atom_value():
    class MetadataOnlyProvider:
        workbench_view_contract = {"overview": {"types": ("d01.public.v1",), "fields": ("label",)}}

    current = CurrentDomainViewRegistry(lambda: domain_registry(provider=MetadataOnlyProvider()))
    assert current.view_types(authority()) == {}
    assert current.catalogue(authority()).unavailable_domains == {"d01": "no_field_projection_contract"}


def test_context_v1_filters_with_server_grant_and_hides_raw_page_metadata():
    class FilteredProvider:
        workbench_view_contract = {"memory": {
            "types": ("memory.source",), "fields": ("items",),
            "projection_context": PROJECTION_CONTEXT_V1,
        }}

        @staticmethod
        def project_workbench(view_type, atoms, *, context):
            assert view_type == "memory"
            assert context.schema_version == PROJECTION_CONTEXT_V1
            assert context.authority.actor == "actor"
            assert context.purpose == "workbench_view"
            return {"items": [atom["value"]["label"] for atom in atoms
                              if context.audience in atom["value"]["audiences"]]}

    current = CurrentDomainViewRegistry(lambda: domain_registry(
        provider=FilteredProvider(), domain="d06", spec_name="memory.source",
        owner_kind="event"))
    session = AuthenticatedSession(
        "actor", "session", {SCOPE: frozenset({"workbench.read"})},
        {SCOPE: frozenset({"public"})}, {SCOPE: frozenset({"workbench_view"})})
    grant = CoordinatorGrant(SCOPE, authority(audience=("public",)), object())
    public = GraphAtom(AtomKey(Owner("event", "bot", "persona", "source-1"),
                               "memory.source", "public"), 1,
                       {"label": "visible", "audiences": ["public"]})
    private = GraphAtom(AtomKey(Owner("event", "bot", "persona", "source-2"),
                                "memory.source", "private"), 1,
                        {"label": "hidden", "audiences": ["owner"]})
    page = GraphPage(GraphSnapshot((public, private),
                                   (NamespaceEpoch("bot", "persona", 13),)), private.key)
    coordinator = Coordinator(page)
    coordinator.query = lambda *_args, **_kwargs: page
    issuer = GraphWorkbenchIssuer(coordinator, Resolver(grant), current)

    read = request(view_type="memory")
    read["audience"] = "public"
    response = WorkbenchService(issuer).handle(
        read, session=session, context=CONTEXT)
    assert response.status == "ready"
    assert response.projection["data"] == {"items": ["visible"]}
    assert "coverage" not in response.projection
    assert "next_cursor" not in response.projection
    assert "snapshot_epoch" not in response.projection
    assert "hidden" not in str(response.as_dict())

    open_request = request("open_workspace")
    open_request["audience"] = "public"
    workspace = WorkbenchService(issuer).handle(
        open_request, session=session, context=CONTEXT)
    assert workspace.status == "ready"
    assert workspace.projection["views"] == (
        {"view_type": "memory", "status": "available"},)

    # A hidden record, raw continuation, and changed namespace epoch must not
    # change either public response.
    page = GraphPage(GraphSnapshot((public,), (NamespaceEpoch("bot", "persona", 12),)), None)
    same_visible = WorkbenchService(issuer).handle(read, session=session, context=CONTEXT)
    assert same_visible.projection == response.projection
    same_workspace = WorkbenchService(issuer).handle(
        open_request, session=session, context=CONTEXT)
    assert same_workspace.projection == workspace.projection

    denied = WorkbenchService(issuer).handle(
        request(view_type="memory"), session=session, context=CONTEXT)
    assert denied.status == "unauthorized"
    assert denied.projection is None
    with pytest.raises(PermissionError):
        current.project_workbench(grant.authority, "memory", (),
                                  audience="owner", purpose="workbench_view")


def test_unsupported_context_version_does_not_fall_back_to_legacy_projection():
    class UnsupportedProvider:
        workbench_view_contract = {"memory": {
            "types": ("memory.source",), "fields": ("items",),
            "projection_context": "d12.projection_context.v2",
        }}

        @staticmethod
        def project_workbench(view_type, atoms):
            raise AssertionError("unsupported contract must not project")

    current = CurrentDomainViewRegistry(lambda: domain_registry(
        provider=UnsupportedProvider(), domain="d06", spec_name="memory.source",
        owner_kind="event"))
    assert current.view_types(authority()) == {}
    assert current.catalogue(authority()).unavailable_domains == {
        "d06": "invalid_public_projection_contract"}
