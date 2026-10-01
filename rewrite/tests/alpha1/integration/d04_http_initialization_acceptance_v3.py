"""Reusable real signed-Owner W09 route acceptance for the installed D04 chain."""
import asyncio
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

from astrbot.api.web import bind_request_context
from astrbot.dashboard.api.plugins import _match_registered_web_api
from sylanne3.graph_worker import GraphWorker
from sylanne3.host.installed_d04_root_resources import InstalledD04RootResources, load_installed_d04_root_preset_v3
from sylanne3.host.workbench_mount import WorkbenchHostMount
from sylanne3.workbench_api.async_service import AsyncGraphWorkbenchService
from sylanne3.workbench_api.domain_registry import CurrentDomainViewRegistry
from sylanne3.workbench_api.http_transport import (
    BoundCsrfTokens, CurrentOwnerDashboardSessions, TransportConfig, WorkbenchHttpTransport,
    COMMAND_ROUTE, SESSION_ROUTE, SYLANNE_OWNER_SESSION_COOKIE,
)
from sylanne3.workbench_api.owner_grant import DurableOwnerGrantResolver, GraphCurrentOwnerGrantPort
from sylanne3.workbench_api.owner_session_resolver import BoundOwnerSessions
from sylanne3.domains.d04.authored_lineage_v3 import AuthoredRootBlockInputV3, RootAuthoredFacetV3
from sylanne3.domains.d12.types import character_draft_key
from sylanne3.runtime.d11_role_clock_installation_v1 import read_current_role_clock_installation_v1
from test_d04_owner_semantic_initialization_v3 import install_d04_test_composition, current_owner, current_mapping_read

ORIGIN = "https://dashboard.local"


class Request:
    username = "dashboard-admin"
    content_type = "application/json"
    def __init__(self, body=b"", *, owner_token=None, csrf=None, session=False):
        self.cookies = {SYLANNE_OWNER_SESSION_COOKIE: owner_token}
        self.headers = {"origin": ORIGIN, "referer": ORIGIN + "/workbench"}
        if csrf is not None:
            self.headers["x-csrf-token"] = csrf
        self._body = body
    async def body(self):
        return self._body


class Routes:
    def __init__(self):
        self.registered_web_apis = []
    def register_web_api(self, *entry):
        self.registered_web_apis.append(entry)


async def initialize_via_actual_workbench_v3(case, *, role_clock_rate="1"):
    """Execute all seven registered HTTP commands, once, on this actual root."""
    graph, ns, store = case["graph"], case["namespace"], case["store"]
    reader = await asyncio.to_thread(install_d04_test_composition, case)
    registration = case["domain_registry"].registrations["d01"]
    if "d01" not in graph._GraphCoordinator__providers:
        graph.register_provider(case["bootstrap"], "d01", registration.provider,
            registration.proposal_schema, registration.proposal_schema_hash)
    worker = await GraphWorker.start(lambda: store, lambda actual: graph)
    case["http_worker"] = worker
    sessions = BoundOwnerSessions(authority=case["port"], worker=worker, bootstrap=case["bootstrap"],
        owner_actor=lambda principal, namespace: "owner-actor-reply" if (principal, namespace) == (case["principal"], ns) else None,
        namespace=ns, authority_id=case["policy"].expected_authority_id,
        installation_id=case["policy"].installation_id, origin=ORIGIN)
    login = replace(case["owner_session_request"], dashboard_origin=ORIGIN)
    challenge = await sessions.begin_signed_login(request=Request(), login_request=login)
    token = await sessions.complete_signed_login(request=Request(), challenge=challenge,
        signature=case["owner_key"].sign(challenge.signed_bytes()))
    case.update(owner_session_request=login, owner_session_token=token)
    grants = GraphCurrentOwnerGrantPort(graph, case["bootstrap"], namespace=ns,
        activation_generation=1, domains=tuple(sorted(graph._GraphCoordinator__providers)))
    service = AsyncGraphWorkbenchService(worker, DurableOwnerGrantResolver(grants),
        CurrentDomainViewRegistry(lambda: case["domain_registry"]), scheme_port=graph,
        d04_root_resource_resolver=InstalledD04RootResources(namespace=ns, package_root=case["package_root"],
            trusted_manifest_sha256=case["manifest_digest"],
            read_current_dedicated_lease=graph.read_current_d04_root_budget_lease_v3))
    transport = WorkbenchHttpTransport(service, CurrentOwnerDashboardSessions(sessions), BoundCsrfTokens(),
        TransportConfig(ORIGIN, case["package_root"] / "resources/workbench"))
    mount, routes = WorkbenchHostMount(), Routes()
    mount.attach_transport(transport); mount.attach_owner_sessions(sessions); mount.register(routes)
    command, _ = _match_registered_web_api(routes.registered_web_apis, COMMAND_ROUTE, "POST")
    session_route, _ = _match_registered_web_api(routes.registered_web_apis, SESSION_ROUTE, "GET")
    with bind_request_context(Request(owner_token=token, session=True)):
        response = await session_route()
    assert response.status_code == 200, response.body
    csrf = json.loads(response.body)["csrf_token"]
    scope = "/".join(ns.as_tuple)
    commands = []
    async def post(action, data, *, operation=None, expected_phase=None, purpose="workbench_user_action", selected_scope=scope):
        operation = operation or str(uuid4())
        payload = {"schema_version": "d12.contract.v1", "action": action, "scope": selected_scope,
            "purpose": purpose, "audience": "owner", "operation_id": operation, "input": data}
        with bind_request_context(Request(json.dumps(payload).encode(), owner_token=token, csrf=csrf)):
            response = await command()
        decoded = json.loads(response.body)
        if selected_scope != scope:
            assert response.status_code in (400, 403, 503), decoded
            assert decoded.get("projection") is None and decoded.get("receipt") is None
            return decoded
        assert response.status_code == 200 and decoded["status"] == "ready", decoded
        if expected_phase:
            assert decoded["receipt"]["operation_id"] == operation
            assert decoded["receipt"]["phase"] == expected_phase
            commands.append((action, operation, data, decoded["receipt"]))
        return decoded
    before = await post("read_d04_initialization_profile", {}, purpose="workbench_view")
    profile = before["projection"]
    assert profile["schema"] == "d12.d04_initialization_profile.v3"
    assert profile["current"]["mapping_revision"] == profile["current"]["clock_version"] == 0
    preset = load_installed_d04_root_preset_v3(case["package_root"], case["manifest_digest"])
    assert profile["current"]["root_preset_digest"] == preset.digest
    blocks = tuple(AuthoredRootBlockInputV3(RootAuthoredFacetV3("owner-block:" + str(i), template.template_id,
        template.kind, "owner-facet:" + str(i)), preset.axes, (0.5,) * 24, ((0.5, 0.5),) * 24,
        "owner-initial-box:" + str(i)) for i, template in enumerate(preset.block_templates))
    field = {"candidate_id": "owner-authored-initial", "cursor": 0.0, "preset_digest": preset.digest,
        "asset_digest": preset.assets.digest, "blocks": json.loads(json.dumps([asdict(block) for block in blocks]))}
    await post("d04_root_draft", {"root_field": field}, expected_phase="owner_operation_committed")
    await post("d04_root_budget", {"parent_budget_lease_ref": case["policy"].root_grant.lease_id,
        "ceiling": {"thread_cpu_ms": 60000}}, expected_phase="owner_operation_committed")
    compiled = await post("compile_scheme", {"draft_ref": character_draft_key(ns).token,
        "budget_ref": case["policy"].root_grant.lease_id}, expected_phase="compiled_candidate_recorded")
    root_op = str(uuid4())
    root_input = {"compiled_digest": compiled["receipt"]["compiled_digest"]}
    activated = await post("activate_scheme", root_input, operation=root_op, expected_phase="scheme_adopted")
    from sylanne3.runtime.budget import get_budget_lease
    parent_used = dict(get_budget_lease(store._db, case["policy"].root_grant.lease_id).used)
    assert (await post("activate_scheme", root_input, operation=root_op))["receipt"] == activated["receipt"]
    assert dict(get_budget_lease(store._db, case["policy"].root_grant.lease_id).used) == parent_used
    topology = await post("d04_root_coupling", {"root_operation_id": root_op, "effective_until": 86400.0},
        expected_phase="owner_operation_committed")
    mapped = await post("d04_semantic_mapping", {"profile_digest": profile["profile_digest"], "expected_revision": 0},
        expected_phase="owner_operation_committed")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    clock = await post("d11_role_clock", {"expected_version": 0, "character_origin": "0", "rate": role_clock_rate,
        "wall_origin_utc": now.isoformat().replace("+00:00", "Z"),
        "valid_from_utc": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "valid_until_utc": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z")}, expected_phase="owner_operation_committed")
    async def assert_current():
        current = (await post("read_d04_initialization_profile", {}, purpose="workbench_view"))["projection"]["current"]
        assert (current["mapping_revision"], current["clock_version"]) == (1, 1)
        assert current["mapping_original_digest"] == mapped["receipt"]["original"]["acceptance_digest"]
        assert current["registered_clock"]["rate"] == role_clock_rate
        await post("read_d04_initialization_profile", {}, purpose="workbench_view", selected_scope="bot/persona")
    await assert_current()
    # The exact last operation is replayed through HTTP; no second clock exists.
    last_action, last_op, last_input, last_receipt = commands[-1]
    replayed = await post(last_action, last_input, operation=last_op)
    assert replayed["receipt"] == last_receipt
    def read_originals():
        with current_owner(case) as (authority, lease):
            original = graph.read_current_d04_authored_root_v3(authority, lease, operation_id=root_op)
        with current_mapping_read(case) as db:
            return original, reader(db, ns), read_current_role_clock_installation_v1(reader, db, ns)
    original, mapping, installed_clock = await asyncio.to_thread(read_originals)
    async def assert_revoked():
        await asyncio.to_thread(case["port"].logout_owner_session, namespace=ns,
            authority_namespace=case["authority_namespace"], request=login, token=token)
        payload = {"schema_version": "d12.contract.v1", "action": "read_d04_initialization_profile",
            "scope": scope, "purpose": "workbench_view", "audience": "owner", "operation_id": str(uuid4()), "input": {}}
        with bind_request_context(Request(json.dumps(payload).encode(), owner_token=token, csrf=csrf)):
            refused = await command()
        assert refused.status_code == 401, refused.body
        assert json.loads(refused.body).get("projection") is None
    case.update(root_operation_id=root_op, root_original=original, topology=topology["receipt"]["original"],
        mapping_acceptance=mapped["receipt"]["original"], clock_acceptance=clock["receipt"]["original"],
        installed_mapping=mapping, installed_clock=installed_clock, assert_http_initialization_current=assert_current,
        http_initialization_commands=tuple(commands), assert_http_session_revoked=assert_revoked)
    assert len(commands) == 7
    return mapping, installed_clock
