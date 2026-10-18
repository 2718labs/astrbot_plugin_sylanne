"""Real SDK persistence and Dashboard cookie HTTP; no provider/model calls."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import os
from pathlib import Path
import secrets
from types import SimpleNamespace
import uuid

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
import pytest

from astrbot.core.config.astrbot_config import AstrBotConfig
from astrbot.core.db.sqlite import SQLiteDatabase
from astrbot.dashboard.api import auth as dashboard_auth, plugins as dashboard_plugins
from astrbot.dashboard.password_state import set_dashboard_password_hashes
from astrbot.dashboard.responses import ApiError
from astrbot.dashboard.services.auth_service import AuthService
from astrbot.dashboard.asgi_runtime import FastAPIAppAdapter

from rewrite.host_tests.alpha1 import test_host_model_selection as model_cases
from sylanne3.host.webui_configuration_v1 import (
    CSRF_HEADER, FIELDS, OPTIONAL_SLOTS, SCHEMA, SLOTS, WebuiConfigurationV1,
    default_model_selection_v1,
)
from sylanne3.host.workbench_mount import WorkbenchHostMount
from sylanne3.host.webui_listener_v1 import WebuiListenerV1


@pytest.fixture
def sdk_models():
    fixture = model_cases.sdk_models.__wrapped__()
    yield next(fixture)
    with pytest.raises(StopIteration):
        next(fixture)


@pytest.mark.parametrize("scheme", ("http", "https"))
def test_configuration_http_sdk_save_cas_safe_slots_and_unknown_outcome(sdk_models, tmp_path, monkeypatch, scheme):
    context, primary, other, calls = sdk_models
    workbench_origin = scheme + "://" + model_cases.ORIGIN.split("://", 1)[1]
    startup = {"enabled": False, "authority_profile": "ui25", "llm_provider_id": "main-provider",
               "model_selection": default_model_selection_v1()}
    schema_path = Path(__file__).resolve().parents[3] / "_conf_schema.json"
    plugin_config = AstrBotConfig(str(tmp_path / "plugin.json"), schema=json.loads(schema_path.read_text()))
    plugin_config.save_config(startup)
    bundle = model_cases.bundle_for(primary, tmp_path)
    service = WebuiConfigurationV1(plugin_config, context, startup_values=startup, installation_bundle=bundle)
    routes_before = list(context.registered_web_apis)
    mount = WorkbenchHostMount()
    mount.attach_configuration(service)
    mount.register(context)
    password = "SdkConfig9!" + secrets.token_hex(16)
    defaults = {"dashboard": {"username": "sdk-config-admin", "jwt_secret": secrets.token_hex(32),
                              "password_change_required": False}}
    set_dashboard_password_hashes(defaults, password)
    dashboard_config = AstrBotConfig(str(tmp_path / "dashboard.json"), default_config=defaults)
    db = SQLiteDatabase(str(tmp_path / "dashboard.db"))
    app = FastAPI()
    adapter = FastAPIAppAdapter(app)
    assert adapter.debug is False and adapter.testing is False and adapter.config == {}
    gateway = WebuiListenerV1(context, enabled=False)
    monkeypatch.setattr(gateway, "_dashboard", lambda: app)
    app.state.jwt_secret = dashboard_config["dashboard"]["jwt_secret"]
    app.state.services = SimpleNamespace(auth=AuthService(db, dashboard_config))
    app.state.core_lifecycle = SimpleNamespace(star_context=context)
    app.include_router(dashboard_auth.router, prefix="/api/v1")
    app.include_router(dashboard_plugins.router, prefix="/api/v1")

    @app.exception_handler(ApiError)
    async def error(_request, problem):
        return JSONResponse({"status": "error", "message": problem.message}, status_code=problem.status_code)

    path = model_cases.BASE + "/configuration/v1"
    try:
        with TestClient(gateway, base_url=workbench_origin) as client:
            origin = {"Origin": workbench_origin}
            assert client.get(path, headers=origin).status_code == 401
            login = client.post("/api/v1/auth/login", json={"username": "sdk-config-admin", "password": password}, headers=origin)
            assert login.status_code == 200
            assert ("; Secure" in login.headers["set-cookie"]) is (scheme == "https")
            assert adapter.config == {} and adapter.debug is False and adapter.testing is False
            first = client.get(path, headers={"Sec-Fetch-Site": "same-origin"})
            assert first.status_code == 200 and first.headers["cache-control"] == "no-store"
            dto = first.json()
            assert set(dto) == {"schema_version", "revision", "csrf_token", "values", "startup_values",
                                "writable_fields", "model_slots", "installed_policy", "apply_semantics"}
            assert dto["values"] == dto["startup_values"] == startup
            assert dto["apply_semantics"] == "next_reload" and dto["writable_fields"] == list(FIELDS)
            assert [row["slot"] for row in dto["model_slots"]] == list(SLOTS)
            assert dto["model_slots"][0]["state"] == "installed"
            assert dto["installed_policy"]["provider_options"] == [
                {"provider_id": primary.meta().id, "model_id": primary.get_model()},
                {"provider_id": other.meta().id, "model_id": other.get_model()}]
            assert set(dto["installed_policy"]) == {
                "profile_id", "installation_id", "workflow_version", "configured_model_slots", "limits", "provider_options"}
            headers = {**origin, CSRF_HEADER: dto["csrf_token"]}

            def command(patch, revision=None, operation=None):
                return {"schema_version": SCHEMA, "operation_id": operation or str(uuid.uuid4()),
                        "expected_revision": dto["revision"] if revision is None else revision, "patch": patch}

            saved_request = command({"enabled": True})
            assert client.post(path, json=saved_request, headers=origin).status_code == 403
            assert client.post(path, json=saved_request, headers={CSRF_HEADER: dto["csrf_token"],
                                                                  "Sec-Fetch-Site": "same-origin"}).status_code == 403
            assert client.post(path, json=saved_request, headers={**headers, "Origin": "https://foreign.invalid"}).status_code == 403
            assert client.get(path, headers={"Origin": "https://foreign.invalid"}).status_code == 403
            assert client.get(path, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
            assert client.get(path, headers={**origin, "Sec-Fetch-Site": "cross-site"}).status_code == 403
            for header in ("Forwarded", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-For", "X-Real-IP"):
                rejected = client.post(path, json=saved_request, headers={**headers, header: "https"})
                assert rejected.status_code == 403 and rejected.json()["reason_code"] == "forwarded_headers_denied"
            assert client.get(path).status_code == 403
            assert client.get(path, headers={"Referer": "https://foreign.invalid/workbench"}).status_code == 403
            assert client.get(path, headers={"Referer": workbench_origin + "/workbench"}).status_code == 200
            bad_cases = [command({"raw_provider_config": {"key": model_cases.CANARY}}),
                         command({"enabled": 1}), command({"authority_profile": "../private"}),
                         command({"model_selection": {"version": 1}}),
                         {**saved_request, "budget": 999}, {**saved_request, "schema_version": "wrong"},
                         {**saved_request, "operation_id": str(uuid.uuid1())}]
            for bad in bad_cases:
                rejected = client.post(path, json=bad, headers=headers)
                assert rejected.status_code == 400
                assert rejected.json()["problem"]["code"] == "validation_failed"
            assert client.post(path, content=b"{" + b" " * 65536, headers=headers).status_code == 413
            assert client.post(path, content=b'{"patch":{},"patch":{}}', headers=headers).status_code == 400
            saved = client.post(path, json=saved_request, headers=headers)
            assert saved.status_code == 200
            dto = saved.json()
            assert dto["revision"] == 2 and dto["values"]["enabled"] is True
            assert dto["startup_values"] == startup
            assert json.loads(Path(plugin_config.config_path).read_text(encoding="utf-8-sig"))["enabled"] is True
            assert client.post(path, json=saved_request, headers=headers).json() == dto
            conflict = {**saved_request, "patch": {"enabled": False}}
            assert client.post(path, json=conflict, headers=headers).status_code == 409
            assert client.post(path, json=command({"enabled": False}, revision=1), headers=headers).status_code == 409
            assert client.get(path, headers=origin).json()["values"] == dto["values"]

            revision = dto["revision"]
            requests = [command({"authority_profile": "ui25-a"}, revision=revision),
                        command({"authority_profile": "ui25-b"}, revision=revision)]
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(lambda request: client.post(path, json=request, headers=headers), requests))
            assert sorted(response.status_code for response in outcomes) == [200, 409]
            dto = client.get(path, headers=origin).json()
            selection = deepcopy(dto["values"]["model_selection"])
            selection["overrides"]["encode"] = "other-provider"
            unmatched = client.post(path, json=command({"authority_profile": "ui25", "model_selection": selection},
                                                      revision=dto["revision"]), headers=headers)
            assert unmatched.status_code == 200
            dto = unmatched.json()
            row = next(row for row in dto["model_slots"] if row["slot"] == "encode")
            assert row["state"] == "pending" and row["reason_code"] == "model_provider_mismatch"
            # SDK changes are observed anew; neither config nor installed bundle is rewritten.
            primary.set_model("changed-sdk-model")
            reread = client.get(path, headers=origin)
            assert reread.json()["model_slots"][0]["reason_code"] == "model_id_mismatch"
            primary.set_model("main-model")
            for wire in [first.content, saved.content, unmatched.content, reread.content]:
                assert model_cases.CANARY.encode() not in wire and b"api_base" not in wire and b"client.key" not in wire

            actual_save = AstrBotConfig.save_config
            def committed_then_failed(config, value=None):
                actual_save(config, value)
                if config is plugin_config:
                    raise OSError("private-error-canary")
            monkeypatch.setattr(AstrBotConfig, "save_config", committed_then_failed)
            failed_request = command({"enabled": False}, revision=dto["revision"])
            failed = client.post(path, json=failed_request, headers=headers)
            assert failed.status_code == 503 and failed.json()["problem"]["code"] == "unknown_outcome"
            assert b"private-error-canary" not in failed.content
            assert client.post(path, json=failed_request, headers=headers).json() == failed.json()
            assert client.get(path, headers=origin).json()["values"]["enabled"] is False
            assert calls == []
    finally:
        mount.close()
        context.registered_web_apis[:] = routes_before
        asyncio.run(db.engine.dispose())


@pytest.mark.parametrize("workflow_version", (4, 9))
def test_v4_configuration_reports_real_slots_and_mismatched_installed_config_stays_pending(sdk_models, tmp_path, workflow_version):
    from dataclasses import fields, replace
    from sylanne3.host.model_workflows_v4 import AdminModelWorkflowsV4
    context, primary, _, calls = sdk_models
    startup = {"enabled": False, "authority_profile": "ui25", "llm_provider_id": "main-provider",
               "model_selection": default_model_selection_v1()}
    schema = json.loads((Path(__file__).resolve().parents[3] / "_conf_schema.json").read_text())
    config = AstrBotConfig(str(tmp_path / "v4-plugin.json"), schema=schema)
    config.save_config(startup)
    base = model_cases.bundle_for(primary, tmp_path, version=3)
    from sylanne3.host.model_workflows_v9 import AdminModelWorkflowsV9
    from sylanne3.model_broker.d07_cognition_v1 import WORK_KIND, TEMPLATE_VERSION
    values = {field.name: getattr(base.model_workflows, field.name)
        for field in fields(base.model_workflows) if field.name != "version"}
    if workflow_version == 9:
        observation = replace(base.model_workflows.reply, work_kind=WORK_KIND, purpose="proposal",
            template_version=TEMPLATE_VERSION, max_output_tokens=1000,
            quote_ceiling={"input_tokens": 6000, "output_tokens": 1000, "model_tokens": 7000, "model_microusd": 1})
        from sylanne3.model_broker.natural_reply_history_v7 import TEMPLATE_VERSION as GENERATION_TEMPLATE
        from sylanne3.runtime_contracts import NATURAL_REPLY_REVIEW_WORKFLOW_V2
        values["natural_generation"] = replace(base.model_workflows.reply, work_kind="natural_generation",
            purpose="proposal", template_version=GENERATION_TEMPLATE)
        values["natural_review"] = replace(base.model_workflows.reply, work_kind="natural_review",
            purpose="proposal", template_version=NATURAL_REPLY_REVIEW_WORKFLOW_V2)
        workflows = AdminModelWorkflowsV9(9, **values, artifact_observation_cognition=observation)
    else:
        workflows = AdminModelWorkflowsV4(4, **values)
    bundle = replace(base, model_workflows=workflows)
    service = WebuiConfigurationV1(config, context, startup_values=startup, installation_bundle=bundle)
    try:
        dto = service._response("controlled-dashboard-session", startup)
        slots = {row["slot"]: row for row in dto["model_slots"]}
        installed = [slot for slot in service._public_model_slots() if getattr(workflows, slot, None) is not None]
        assert dto["installed_policy"]["workflow_version"] == workflow_version
        if workflow_version == 9:
            assert list(slots)[-1] == "artifact_observation_cognition"
            assert "artifact_observation_cognition" not in dto["values"]["model_selection"]["overrides"]
        assert dto["installed_policy"]["configured_model_slots"] == installed
        for slot in installed:
            workflow = getattr(workflows, slot)
            assert slots[slot]["state"] == "installed"
            assert slots[slot]["installed"]["provider_config_digest"] == workflow.provider_config_digest
            assert dto["installed_policy"]["limits"][slot] == workflow.max_output_tokens
        assert workflows.artifact_draft is None
        assert "artifact_draft" not in slots  # No additional installed model capability is invented.
        primary.provider_config["controlled_revision"] = 2
        changed = service._response("controlled-dashboard-session", startup)
        changed_slots = {row["slot"]: row for row in changed["model_slots"]}
        for slot in installed:
            assert changed_slots[slot]["state"] == "pending"
            assert changed_slots[slot]["reason_code"] == "model_config_mismatch"
            assert changed_slots[slot]["installed"] == slots[slot]["installed"]
        assert calls == []
    finally:
        service.close()


@pytest.mark.skipif(not all(os.environ.get(name) for name in ("SYLANNE_HTTP_BROWSER_NODE", "SYLANNE_HTTP_PLAYWRIGHT", "SYLANNE_HTTP_CHROME")), reason="explicit local browser tools required; skip is not runtime PASS")
def test_http_packaged_browser_login_and_config_in_insecure_context(sdk_models, tmp_path, monkeypatch):
    """Actual HTTP browser origin: no localhost secure-context exception."""
    import os
    import subprocess

    node = os.environ["SYLANNE_HTTP_BROWSER_NODE"]
    playwright = os.environ["SYLANNE_HTTP_PLAYWRIGHT"]
    chrome = os.environ["SYLANNE_HTTP_CHROME"]
    context, primary, _other, calls = sdk_models
    startup = {"enabled": False, "authority_profile": "ui25", "llm_provider_id": "main-provider",
               "model_selection": default_model_selection_v1()}
    schema_path = Path(__file__).resolve().parents[3] / "_conf_schema.json"
    config = AstrBotConfig(str(tmp_path / "browser-plugin.json"), schema=json.loads(schema_path.read_text()))
    config.save_config(startup)
    service = WebuiConfigurationV1(config, context, startup_values=startup,
                                  installation_bundle=model_cases.bundle_for(primary, tmp_path))
    routes_before = list(context.registered_web_apis)
    mount = WorkbenchHostMount()
    mount.attach_configuration(service)
    mount.register(context)
    password = "Browser9!" + secrets.token_hex(16)
    defaults = {"dashboard": {"username": "http-browser-admin", "jwt_secret": secrets.token_hex(32),
                              "password_change_required": False}}
    set_dashboard_password_hashes(defaults, password)
    dashboard_config = AstrBotConfig(str(tmp_path / "browser-dashboard.json"), default_config=defaults)
    db = SQLiteDatabase(str(tmp_path / "browser-dashboard.db"))
    app = FastAPI()
    adapter = FastAPIAppAdapter(app)
    assert adapter.config == {} and adapter.debug is False and adapter.testing is False
    app.state.jwt_secret = dashboard_config["dashboard"]["jwt_secret"]
    app.state.services = SimpleNamespace(auth=AuthService(db, dashboard_config))
    app.state.core_lifecycle = SimpleNamespace(star_context=context)
    app.include_router(dashboard_auth.router, prefix="/api/v1")
    app.include_router(dashboard_plugins.router, prefix="/api/v1")

    @app.exception_handler(ApiError)
    async def error(_request, problem):
        return JSONResponse({"status": "error", "message": problem.message}, status_code=problem.status_code)

    js = r"""
const assert=require('node:assert/strict');
const {chromium}=require(process.env.SYLANNE_HTTP_PLAYWRIGHT);
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.SYLANNE_HTTP_CHROME,
  args:['--no-sandbox','--no-proxy-server','--host-resolver-rules=MAP sylanne-http.test 127.0.0.1']});
 try{
  const ctx=await browser.newContext(),page=await ctx.newPage(),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto(process.env.SYLANNE_HTTP_BROWSER_ORIGIN,{waitUntil:'domcontentloaded'});
  assert.deepEqual(await page.evaluate(()=>({secure:isSecureContext,subtle:typeof crypto.subtle,uuid:typeof crypto.randomUUID})),
    {secure:false,subtle:'undefined',uuid:'undefined'});
  await page.getByRole('button',{name:'跳过片头',exact:true}).click({timeout:15000});
  await page.getByRole('button',{name:'高级配置 / LLM',exact:true}).click({timeout:15000});
  await page.locator('.dashboard-access summary').filter({hasText:'AstrBot 后台登录'}).click();
  await page.getByLabel('账户',{exact:true}).fill('http-browser-admin');
  await page.getByLabel('密码',{exact:true}).fill(process.env.SYLANNE_HTTP_BROWSER_PASSWORD);
  await page.getByRole('button',{name:'登录当前后台',exact:true}).click();
  await page.waitForFunction(()=>{const s=document.querySelector('#configuration-host-enabled');return s&&!s.disabled&&s.value==='false'},{},{timeout:15000});
  await page.locator('#configuration-host-enabled').selectOption('true');
  const response=page.waitForResponse(r=>r.url().endsWith('/configuration/v1')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'保存本机配置并回读',exact:true}).click();
  const saved=await response;assert.equal(saved.status(),200);
  const dto=await saved.json();assert.equal(dto.values.enabled,true);assert.equal(dto.startup_values.enabled,false);
  assert.match(saved.request().postDataJSON().operation_id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  const cookies=await ctx.cookies();assert.ok(cookies.some(c=>c.httpOnly&&!c.secure));
  assert.equal(await page.getByText('SESSION VERIFIED',{exact:true}).count(),0);
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({browser:'actual HTTP non-localhost origin',secure_context:false,
    login:'real SDK JWT cookie',configuration:'saved and read back; startup unchanged',
    owner:'not fabricated',page_errors:errors}));
 }finally{await browser.close()}
})().catch(e=>{console.error(e.stack);process.exitCode=1});
"""

    async def exercise():
        listener = WebuiListenerV1(context, enabled=True, bind="127.0.0.1", port=0)
        monkeypatch.setattr(listener, "_dashboard", lambda: app)
        try:
            assert (await listener.start())["state"] == "listening"
            port = listener.status_v1()["bound_addresses"][0]["port"]
            env = dict(os.environ)
            env["SYLANNE_HTTP_BROWSER_ORIGIN"] = f"http://sylanne-http.test:{port}"
            env["SYLANNE_HTTP_BROWSER_PASSWORD"] = password
            result = await asyncio.to_thread(subprocess.run, [node, "-"], input=js, text=True,
                                             env=env, capture_output=True, timeout=60)
            assert result.returncode == 0, result.stdout + result.stderr
            print(result.stdout)
            assert config["enabled"] is True
            assert json.loads((tmp_path / "browser-plugin.json").read_text(encoding="utf-8-sig"))["enabled"] is True
            assert calls == []
            assert adapter.config == {} and adapter.debug is False and adapter.testing is False
        finally:
            await listener.close()

    try:
        asyncio.run(exercise())
    finally:
        mount.close()
        context.registered_web_apis[:] = routes_before
        service.close()
        asyncio.run(db.engine.dispose())
