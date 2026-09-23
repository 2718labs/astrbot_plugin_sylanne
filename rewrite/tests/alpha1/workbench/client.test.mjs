import test from "node:test";
import assert from "node:assert/strict";
import { ACTIONS, D12_SCHEMA_VERSION, makeOwnerLoginRequest, makeRequest } from "../../../../resources/workbench/src/api/contract.js";
import { DEFAULT_WORKBENCH_API_BASE, WorkbenchApi, WorkbenchApiError } from "../../../../resources/workbench/src/api/client.js";
import { applyProblem, applyResponse, initialState, switchRole, VIEW_STATES } from "../../../../resources/workbench/src/state.js";
import { needsFreshProjection, workflowForPage } from "../../../../resources/workbench/src/workflows.js";

test("client posts to the AstrBot plugin extension route with host cookie and CSRF", async () => {
  const requested = [];
  const api = new WorkbenchApi({ fetchImpl: async (url, init) => {
    requested.push({ url, init });
    return { ok: true, json: async () => init.method === "GET"
      ? { status: "ready", dashboard_session: "authenticated", owner_session: "unlocked", csrf_token: "server-issued" }
      : { status: "unavailable", problem: { code: "provider_unavailable" } } };
  } });
  await api.command(ACTIONS.openWorkspace, { scope: "role-1", purpose: "workbench_view", input: { client_protocol: D12_SCHEMA_VERSION } });
  assert.equal(DEFAULT_WORKBENCH_API_BASE, "/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1");
  assert.equal(requested[0].url, `${DEFAULT_WORKBENCH_API_BASE}/session`);
  assert.equal(requested[0].init.method, "GET");
  assert.equal(requested[0].init.credentials, "same-origin");
  assert.equal(requested[0].init.headers.origin, undefined);
  assert.equal(requested[1].url, `${DEFAULT_WORKBENCH_API_BASE}/commands`);
  assert.equal(requested[1].init.credentials, "same-origin");
  assert.equal(requested[1].init.headers["x-csrf-token"], "server-issued");
});

test("installation status uses the host session without opening Owner session", async () => {
  const requested = [];
  const api = new WorkbenchApi({ fetchImpl: async (url, init) => {
    requested.push({ url, init });
    return { ok: true, json: async () => ({ schema_version: "sylanne.install-status.v1", runtime_stage: "enrollment_required", reason_code: "authority_profile" }) };
  } });
  assert.deepEqual(await api.installationStatus(), { stage: "enrollment_required", reason: "authority_profile" });
  assert.equal(requested[0].url, `${DEFAULT_WORKBENCH_API_BASE}/status`);
  assert.equal(requested[0].init.credentials, "same-origin");
  assert.equal(api.hasSession, false);
});

test("Owner login request uses the registered installation fields and exact browser Origin", () => {
  const values = {
    authority_id: "authority-a", authority_namespace: "authority-ns", installation_id: "install-a",
    identity_provider: "local", account_ref: "owner-a", account_incarnation: "first",
    credential_id: "key-a", credential_epoch: "2"
  };
  const request = makeOwnerLoginRequest(values, "https://localhost:6185");
  assert.deepEqual(request, {
    kind: "owner_session_login_request_v1", schema: "sylanne3.authority.owner-session.v1",
    authority_id: "authority-a", authority_namespace: "authority-ns", installation_id: "install-a",
    principal: { identity_provider: "local", account_ref: "owner-a", account_incarnation: "first" },
    credential_id: "key-a", credential_epoch: 2, audience: "owner",
    dashboard_origin: "https://localhost:6185"
  });
  assert.throws(() => makeOwnerLoginRequest({ ...values, credential_epoch: "0" }, "https://localhost:6185"));
  assert.throws(() => makeOwnerLoginRequest(values, "http://localhost:6185"), /HTTPS/);
});

test("Owner challenge, completion, and logout use the host cookie without an unlocked CSRF", async () => {
  const requested = [];
  const challenge = { kind: "owner_session_login_challenge_v1", request: { kind: "owner_session_login_request_v1" } };
  const api = new WorkbenchApi({ fetchImpl: async (url, init) => {
    requested.push({ url, init });
    const body = url.endsWith("/owner/challenge")
      ? { schema_version: "sylanne.owner-login.v1", challenge, signing_payload_base64: "cGF5bG9hZA==" }
      : url.endsWith("/owner/complete")
        ? { status: "authenticated", owner_session: "unlocked" }
        : { status: "ok", owner_session: "locked" };
    return { ok: true, status: 200, json: async () => body };
  } });
  const request = { kind: "owner_session_login_request_v1" };
  assert.deepEqual(await api.ownerChallenge(request), { challenge, signingPayloadBase64: "cGF5bG9hZA==" });
  await api.ownerComplete(challenge, "c2lnbmF0dXJl");
  await api.ownerLogout();
  assert.deepEqual(requested.map(({ url }) => url), [
    `${DEFAULT_WORKBENCH_API_BASE}/owner/challenge`,
    `${DEFAULT_WORKBENCH_API_BASE}/owner/complete`,
    `${DEFAULT_WORKBENCH_API_BASE}/owner/logout`
  ]);
  for (const { init } of requested) {
    assert.equal(init.method, "POST");
    assert.equal(init.credentials, "same-origin");
    assert.equal(init.headers["content-type"], "application/json");
    assert.equal(init.headers["x-csrf-token"], undefined);
    assert.equal(init.headers.origin, undefined);
  }
  assert.deepEqual(JSON.parse(requested[0].init.body), { request });
  assert.deepEqual(JSON.parse(requested[1].init.body), { challenge, signature_base64: "c2lnbmF0dXJl" });
  assert.deepEqual(JSON.parse(requested[2].init.body), {});
  assert.equal(api.hasSession, false);
});

test("client displays a D12 problem from an HTTP error", async () => {
  const api = new WorkbenchApi({ fetchImpl: async (_url, init) => init.method === "GET"
    ? { ok: true, json: async () => ({ status: "ready", dashboard_session: "authenticated", owner_session: "unlocked", csrf_token: "server-issued" }) }
    : { ok: false, status: 403, json: async () => ({ status: "unauthorized", problem: { code: "csrf_denied", message: "防跨站校验未通过。", retryable: false } }) } });
  await assert.rejects(api.command(ACTIONS.openWorkspace, { scope: "role-1", purpose: "workbench_view" }),
    (error) => error instanceof WorkbenchApiError && error.status === 403 && error.code === "csrf_denied" && error.message === "防跨站校验未通过。");
  assert.equal(api.hasSession, false);
});

test("locked Owner session prevents POST and can be retried after login", async () => {
  let paired = false;
  const requests = [];
  const api = new WorkbenchApi({ fetchImpl: async (_url, init) => {
    requests.push(init.method);
    if (init.method === "GET") return paired
      ? { ok: true, json: async () => ({ status: "ready", dashboard_session: "authenticated", owner_session: "unlocked", csrf_token: "fresh" }) }
      : { ok: false, status: 401, json: async () => ({ status: "unauthorized", problem: { code: "owner_session_locked", message: "Owner 会话未解锁。" } }) };
    assert.equal(init.headers["x-csrf-token"], "fresh");
    return { ok: true, json: async () => ({ status: "ready", projection: {} }) };
  } });
  await assert.rejects(api.command(ACTIONS.openWorkspace, { scope: "role-1" }), (error) => error.code === "owner_session_locked");
  assert.deepEqual(requests, ["GET"]);
  paired = true;
  await api.command(ACTIONS.openWorkspace, { scope: "role-1" });
  assert.deepEqual(requests, ["GET", "GET", "POST"]);
});

test("a session response arriving after Owner logout cannot restore the old CSRF token", async () => {
  let finishOld;
  let calls = 0;
  const api = new WorkbenchApi({ fetchImpl: async () => {
    ++calls;
    if (calls === 1) return new Promise((resolve) => { finishOld = resolve; });
    return { ok: true, json: async () => ({ status: "ready", dashboard_session: "authenticated",
      owner_session: "unlocked", csrf_token: "new-session" }) };
  } });
  const oldRequest = api.openSession();
  api.clearSession();
  const newRequest = api.openSession();
  finishOld({ ok: true, json: async () => ({ status: "ready", dashboard_session: "authenticated",
    owner_session: "unlocked", csrf_token: "old-session" }) });
  await assert.rejects(oldRequest, (error) => error.code === "session_changed");
  await newRequest;
  assert.equal(calls, 2);
  assert.equal(api.csrfToken, "new-session");
});

test("expired CSRF clears in-memory token and the next attempt gets a new one", async () => {
  let issues = 0;
  const api = new WorkbenchApi({ fetchImpl: async (_url, init) => {
    if (init.method === "GET") return { ok: true, json: async () => ({ status: "ready", dashboard_session: "authenticated", owner_session: "unlocked", csrf_token: `token-${++issues}` }) };
    if (issues === 1) return { ok: false, status: 403, json: async () => ({ status: "unauthorized", problem: { code: "csrf_denied" } }) };
    assert.equal(init.headers["x-csrf-token"], "token-2");
    return { ok: true, json: async () => ({ status: "ready", projection: {} }) };
  } });
  await assert.rejects(api.command(ACTIONS.openWorkspace, { scope: "role-1" }), (error) => error.code === "csrf_denied");
  assert.equal(api.hasSession, false);
  await api.command(ACTIONS.openWorkspace, { scope: "role-1" });
  assert.equal(issues, 2);
});

test("a legacy ready response without independent Owner proof stays locked", async () => {
  const api = new WorkbenchApi({ fetchImpl: async () => ({ ok: true, status: 200,
    json: async () => ({ status: "ready", csrf_token: "old-dashboard-only" }) }) });
  await assert.rejects(api.openSession(), (error) => error.code === "invalid_session");
  assert.equal(api.hasSession, false);
});

test("D12 command request declares contract, scoped action, and an operation id", () => {
  const request = makeRequest(ACTIONS.compileScheme, { scope: "role-1", purpose: "workbench_user_action", operationId: "operation-1" });
  assert.equal(request.schema_version, D12_SCHEMA_VERSION);
  assert.equal(request.action, "compile_scheme");
  assert.equal(request.scope, "role-1");
  assert.equal(request.operation_id, "operation-1");
});

test("role switching clears projection and previous receipt before the next read", () => {
  const before = { ...initialState(), role: "role-a", projection: { private: "must-clear" }, receipt: { operation_id: "old" }, status: "ready" };
  const after = switchRole(before, "role-b");
  assert.equal(after.role, "role-b");
  assert.equal(after.projection, null);
  assert.equal(after.receipt, null);
  assert.equal(after.status, "loading");
});

test("authorization failures never preserve an old projection", () => {
  const before = { ...initialState(), projection: { visible: "old" }, status: "ready" };
  const after = applyProblem(before, { code: "unauthorized", message: "denied" });
  assert.equal(after.status, "unauthorized");
  assert.equal(after.projection, null);
});

test("all D12 projection states are preserved and an unknown server state fails closed", () => {
  for (const status of VIEW_STATES) {
    const next = applyResponse(initialState(), { status, projection: { status } });
    assert.equal(next.status, status);
  }
  const failedClosed = applyResponse(initialState(), { status: "invented_server_state", projection: { unsafe: true } });
  assert.equal(failedClosed.status, "unavailable");
});

test("degraded server responses clear content and stale receipts", () => {
  const before = { ...initialState(), projection: { private: "old" }, receipt: { operation_id: "persisted" }, status: "ready" };
  for (const status of ["partial", "stale", "unavailable", "unauthorized"]) {
    const next = applyResponse(before, { status, projection: { must: "not-render" } });
    assert.equal(next.projection, null);
    assert.equal(next.receipt, null);
  }
});

test("nine-page workflows map user inputs only to W10 action schemas", () => {
  const [bind, binding] = workflowForPage("setup", { scene_ref: `scene:conversation-v1:${"a".repeat(64)}`, visibility: "private", acknowledgement: "on" });
  assert.equal(bind, ACTIONS.bindScene);
  assert.deepEqual(binding, { scene_ref: `scene:conversation-v1:${"a".repeat(64)}`, visibility: "private", acknowledgement: true });
  assert.throws(() => workflowForPage("setup", { scene_ref: "scene:fake", visibility: "private" }), /conversation-v1/);
  assert.throws(() => workflowForPage("setup", { scene_ref: "scene:other:42", visibility: "private", acknowledgement: "on" }), /conversation-v1/);
  const [compile, compileInput] = workflowForPage("creation", { mode: "compile", draft_ref: "draft:1" });
  const [correct, correction] = workflowForPage("memory", { correction_kind: "source_correction", statement: "修正", source_refs: "source:1,source:2" });
  const [erase, eraseInput] = workflowForPage("lifecycle", { mode: "erase", scope_selection: "all", data_choice: "delete" });
  assert.equal(compile, ACTIONS.compileScheme); assert.deepEqual(compileInput, { draft_ref: "draft:1", intent: "user_requested_candidate" });
  assert.equal(correct, ACTIONS.correctOrEdit); assert.deepEqual(correction.source_refs, ["source:1", "source:2"]);
  assert.equal(erase, ACTIONS.eraseOrRetire); assert.equal(eraseInput.mode, "erase");
  assert.equal(needsFreshProjection(compile), true); assert.equal(needsFreshProjection(ACTIONS.readCharacterView), false);
  const [, created] = workflowForPage("creation", { mode: "compile", draft_json: '{"fields":{},"field_sources":{}}' });
  assert.deepEqual(created.draft, { fields: {}, field_sources: {} });
});
