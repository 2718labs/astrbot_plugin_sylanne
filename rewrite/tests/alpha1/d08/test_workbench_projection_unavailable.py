"""D08 stays closed until source and audience grants reach its projector."""

from sylanne3.domain_registry import DomainRegistration, DomainRegistry
from sylanne3.domains.d08 import GoalExecutionProvider
from sylanne3.graph_types import TypeRegistry
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId
from sylanne3.workbench_api import (
    AuthenticatedSession, CoordinatorGrant, CurrentDomainViewRegistry, GraphWorkbenchIssuer,
)


def test_d08_action_view_has_no_public_projection_or_graph_query():
    provider = GoalExecutionProvider()
    types = TypeRegistry()
    specs = provider.register_types()
    for spec in specs:
        types.register(spec)
    registry = DomainRegistry({"d08": DomainRegistration(
        "d08", provider, "d08.proposal.v1", provider.descriptor.request_schema_hash, specs,
    )}, {}, types.freeze())
    views = CurrentDomainViewRegistry(lambda: registry)
    authority = AuthorityContext("actor", "d12", "capability", NamespaceId("bot", "persona"),
                                 ("persona",), "workbench_view", ("owner",), "policy", 4)

    class Resolver:
        def resolve(self, **_):
            return CoordinatorGrant("bot/persona", authority, object())

    class Coordinator:
        def query(self, *_args, **_kwargs):
            raise AssertionError("uncontracted D08 content must not be queried")

    session = AuthenticatedSession(
        "actor", "session", {"bot/persona": frozenset({"workbench.read"})},
        {"bot/persona": frozenset({"owner"})},
        {"bot/persona": frozenset({"workbench_view"})},
    )
    assert views.catalogue(authority).unavailable_domains["d08"] == "no_public_projection_contract"
    result = GraphWorkbenchIssuer(Coordinator(), Resolver(), views).read_projection(
        session=session, scope="bot/persona", view_type="action",
        purpose="workbench_view", audience="owner",
    )
    assert result["status"] == "unavailable"
    assert result["problem"]["code"] == "view_unsupported"
    assert "projection" not in result
