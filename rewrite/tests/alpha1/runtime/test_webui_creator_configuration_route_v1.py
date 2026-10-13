"""W09 configuration commands reach the actual permanent W01 Owner fixture."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

from sylanne3.workbench_api.issuer import CoordinatorGrant, GraphWorkbenchIssuer
from sylanne3.workbench_api.service import AuthenticatedSession, RequestContext, WorkbenchService
from tests.alpha1.d12.test_owner_graph_lease import NAMESPACE, OWNER_REQUEST, OWNER_TOKEN, owner_graph
from tests.alpha1.runtime.test_current_creator_draft_port_v1 import _creator_case
from tests.alpha1.runtime.test_d12_creator_configuration_v1 import POLICY, _arguments


def test_webui_creator_discovery_save_readback_and_refusals(owner_graph):
    graph, coordinator, port, authority, lease = _creator_case(
        owner_graph, fields={"d09.expression_policy": POLICY})
    scope = "/".join(NAMESPACE.as_tuple)
    capabilities = frozenset({"workbench.read", "workbench.create"})
    grant = CoordinatorGrant(scope, authority, lease, capabilities)
    resolver = SimpleNamespace(resolve=lambda **kwargs: grant)
    views = SimpleNamespace(view_types=lambda context: {})
    issuer = GraphWorkbenchIssuer(coordinator, resolver, views, scheme_port=coordinator)
    service = WorkbenchService(issuer)
    session = AuthenticatedSession(
        authority.actor, "creator-fixture", {scope: capabilities},
        {scope: frozenset({"owner"})}, {scope: frozenset({"workbench_user_action"})},
        owner_session_token=OWNER_TOKEN, owner_session_request=OWNER_REQUEST)
    transport = RequestContext(True, True, True)

    def command(action, fields, operation=None):
        return {"schema_version": "d12.contract.v1", "action": action, "scope": scope,
                "purpose": "workbench_user_action", "audience": "owner",
                "operation_id": operation or str(uuid4()), "input": fields}

    def read():
        response = service.handle(command("read_configuration_draft", {}),
                                  session=session, context=transport)
        assert response.status == "ready", response.problem
        assert response.projection["budget_ref"] is None
        assert response.projection["action_permissions"] == {
            "save": True, "compile": False, "preview": False, "activate": False}
        return response.projection

    before = read()
    from sylanne3.runtime.d12_creator_configuration_v1 import edited_configuration_draft_v1
    from sylanne3.domains.d12.types import CharacterDraft
    templates = before["field_templates"]
    assert len(templates) == 10 and "d04.authored_root" not in templates
    candidate = edited_configuration_draft_v1(NAMESPACE, CharacterDraft(NAMESPACE.persona_id, 0, {}, {}), templates)
    assert candidate.fields == templates and before["fields"] != templates
    proposed = {"d09.expression_policy": {**POLICY, "max_visible_chars": 73}}
    arguments = _arguments(before, proposed)
    operation = arguments.pop("operation_id")
    request = command("save_creator_draft", arguments, operation)
    blocked = service.handle(request, session=session, context=RequestContext(True, False, True))
    assert blocked.status == "unauthorized"
    forged = deepcopy(request)
    forged["input"]["grant"] = {"allowed": True}
    assert service.handle(forged, session=session, context=transport).status == "unavailable"
    root = deepcopy(request)
    root["input"]["fields"]["d04.authored_root"] = {"replace": True}
    assert service.handle(root, session=session, context=transport).status == "unavailable"
    denied = replace(session, scope_capabilities={scope: frozenset({"workbench.read"})})
    assert service.handle(request, session=denied, context=transport).status == "unauthorized"
    assert read()["draft_digest"] == before["draft_digest"]

    saved = service.handle(request, session=session, context=transport)
    assert saved.status == "ready", saved.problem
    assert saved.receipt["status"] == "draft_saved_not_adopted"
    after = read()
    assert after["fields"] == proposed
    assert after["draft_digest"] == saved.receipt["draft_digest"]
    assert after["draft_revision"] == before["draft_revision"] + 1
    assert after["active_head_revision"] == before["active_head_revision"]
    replay = service.handle(request, session=session, context=transport)
    assert replay.receipt == saved.receipt
    stale = service.handle(command("save_creator_draft", arguments), session=session, context=transport)
    assert stale.status != "ready"
    assert read()["draft_digest"] == after["draft_digest"]
