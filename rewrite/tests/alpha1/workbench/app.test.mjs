import test from "node:test";
import assert from "node:assert/strict";

async function mountWorkbench({ sessionResponses = [], statusResponses = [], ownerFields = {}, origin = "https://localhost:6185" } = {}) {
  const previousDocument = globalThis.document;
  const previousFetch = globalThis.fetch;
  const previousFormData = globalThis.FormData;
  const previousLocation = globalThis.location;
  const requests = [];
  const app = {
    innerHTML: "",
    addEventListener(type, listener) { if (type === "click") this.click = listener; }
  };
  let roleInput = "";
  let ownerSignature = "";
  let sessionRequests = 0;
  let statusRequests = 0;
  let pageFields = {};
  let createFields = {};
  globalThis.document = {
    querySelector(selector) {
      if (selector === "#app") return app;
      if (selector === "#role-input") return { value: roleInput };
      if (selector === "#owner-login-form") return { id: "owner-login-form" };
      if (selector === "#page-form") return { id: "page-form" };
      if (selector === "#create-character-form") return { id: "create-character-form" };
      if (selector === "#owner-signature") return { value: ownerSignature };
      return null;
    }
  };
  globalThis.location = { origin };
  globalThis.FormData = class {
    constructor(form) { this.form = form; }
    entries() {
      const values = this.form.id === "owner-login-form" ? ownerFields
        : this.form.id === "create-character-form" ? createFields : pageFields;
      return Object.entries(values)[Symbol.iterator]();
    }
  };
  globalThis.fetch = async (url, init) => {
    if (init.method === "GET") {
      if (url.endsWith("/status")) {
        const body = statusResponses[statusRequests++] ?? { schema_version: "sylanne.install-status.v1", runtime_stage: "limited", reason_code: "runtime_unavailable" };
        return { ok: true, status: 200, json: async () => body };
      }
      const body = sessionResponses[sessionRequests++] ?? { status: "ready", dashboard_session: "authenticated", owner_session: "unlocked", csrf_token: "issued" };
      return { ok: body.status === "ready", status: body.status === "ready" ? 200 : 401, json: async () => body };
    }
    return new Promise((resolve) => {
      requests.push({ url, init, payload: JSON.parse(init.body), resolve: (body) => resolve({
        ok: body.status !== "unauthorized", status: body.status === "unauthorized" ? 401 : 200,
        json: async () => body
      }) });
    });
  };
  await import(`../../../../resources/workbench/src/app.js?test=${Date.now()}-${Math.random()}`);
  async function nextRequest(index) {
    for (let attempt = 0; attempt < 10 && requests.length <= index; attempt++) await new Promise((resolve) => setImmediate(resolve));
    assert.ok(requests[index], `expected command request ${index}`);
    return requests[index];
  }
  return {
    app, requests, nextRequest,
    get sessionRequests() { return sessionRequests; },
    get statusRequests() { return statusRequests; },
    setRole(value) { roleInput = value; },
    setOwnerSignature(value) { ownerSignature = value; },
    setPageFields(value) { pageFields = value; },
    setCreateFields(value) { createFields = value; },
    clickCommand(command) { return app.click({ target: { closest(selector) { return selector === "[data-command]" ? { dataset: { command } } : null; } } }); },
    clickView(view) { return app.click({ target: { closest(selector) { return selector === "[data-view]" ? { dataset: { view } } : null; } } }); },
    restore() {
      globalThis.document = previousDocument;
      globalThis.fetch = previousFetch;
      globalThis.FormData = previousFormData;
      globalThis.location = previousLocation;
    }
  };
}

test("an older same-role view response cannot replace the selected page", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("role-a");
    const initial = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { label: "overview" } });
    await initial;

    const older = ui.clickView("creation");
    const newer = ui.clickView("memory");
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "ready", projection: { label: "memory-current" } });
    await newer;
    ui.requests[1].resolve({ status: "ready", projection: { label: "creation-obsolete" } });
    await older;

    assert.match(ui.app.innerHTML, /memory-current/);
    assert.doesNotMatch(ui.app.innerHTML, /creation-obsolete/);
  } finally { ui.restore(); }
});

test("locked startup distinguishes Dashboard login from Owner unlock", async () => {
  const ui = await mountWorkbench({ sessionResponses: [
    { status: "unauthorized", problem: { code: "owner_session_locked", message: "Sylanne Owner 会话未解锁。" } },
    { status: "ready", dashboard_session: "authenticated", owner_session: "unlocked", csrf_token: "paired" }
  ] });
  try {
    await new Promise((resolve) => setImmediate(resolve));
    assert.match(ui.app.innerHTML, /AstrBot 控制台.*已登录/s);
    assert.match(ui.app.innerHTML, /Sylanne Owner.*锁定/s);
    assert.match(ui.app.innerHTML, /重新核验 Owner 会话/);
    assert.doesNotMatch(ui.app.innerHTML, /aria-label="服务返回的权限过滤投影"/);
    await ui.clickCommand("retry-session");
    assert.equal(ui.sessionRequests, 2);
    assert.match(ui.app.innerHTML, /Sylanne Owner.*已解锁/s);
    assert.doesNotMatch(ui.app.innerHTML, /Owner 尚未解锁/);
  } finally { ui.restore(); }
});

test("signed Owner login stays locked until session verification and logout clears it", async () => {
  const ui = await mountWorkbench({
    ownerFields: {
      authority_id: "authority-a", authority_namespace: "authority-ns", installation_id: "install-a",
      identity_provider: "local", account_ref: "owner-a", account_incarnation: "first",
      credential_id: "key-a", credential_epoch: "1"
    },
    sessionResponses: [
      { status: "unauthorized", problem: { code: "owner_session_locked", message: "Owner 未解锁。" } },
      { status: "ready", dashboard_session: "authenticated", owner_session: "unlocked", csrf_token: "fresh" }
    ]
  });
  try {
    await new Promise((resolve) => setImmediate(resolve));
    assert.match(ui.app.innerHTML, /获取签名挑战/);
    assert.equal(ui.requests.length, 0);
    const begin = ui.clickCommand("owner-challenge");
    const requested = await ui.nextRequest(0);
    assert.match(requested.url, /\/owner\/challenge$/);
    assert.equal(requested.init.credentials, "same-origin");
    assert.equal(requested.payload.request.dashboard_origin, "https://localhost:6185");
    assert.deepEqual(requested.payload.request.principal, {
      identity_provider: "local", account_ref: "owner-a", account_incarnation: "first"
    });
    const challenge = {
      kind: "owner_session_login_challenge_v1", request: requested.payload.request,
      expires_at_utc: "2026-09-24T00:05:00Z"
    };
    requested.resolve({ schema_version: "sylanne.owner-login.v1", challenge, signing_payload_base64: "cGF5bG9hZA==" });
    await begin;
    assert.match(ui.app.innerHTML, /cGF5bG9hZA==/);
    assert.match(ui.app.innerHTML, /Sylanne Owner.*锁定/s);
    assert.doesNotMatch(ui.app.innerHTML, /aria-label="服务返回的权限过滤投影"/);

    ui.setOwnerSignature("c2lnbmF0dXJl");
    const complete = ui.clickCommand("owner-complete");
    const completed = await ui.nextRequest(1);
    assert.match(completed.url, /\/owner\/complete$/);
    assert.deepEqual(completed.payload, { challenge, signature_base64: "c2lnbmF0dXJl" });
    completed.resolve({ status: "authenticated", owner_session: "unlocked" });
    await complete;
    assert.equal(ui.sessionRequests, 2);
    assert.match(ui.app.innerHTML, /Sylanne Owner.*已解锁/s);

    const logout = ui.clickCommand("owner-logout");
    const loggedOut = await ui.nextRequest(2);
    assert.match(loggedOut.url, /\/owner\/logout$/);
    assert.deepEqual(loggedOut.payload, {});
    assert.match(ui.app.innerHTML, /Sylanne Owner.*锁定/s);
    loggedOut.resolve({ status: "ok", owner_session: "locked" });
    await logout;
    assert.doesNotMatch(ui.app.innerHTML, /aria-label="服务返回的权限过滤投影"/);
  } finally { ui.restore(); }
});

test("HTTP setup keeps the Owner signing flow unavailable", async () => {
  const ui = await mountWorkbench({
    origin: "http://localhost:6185",
    sessionResponses: [{ status: "unauthorized", problem: { code: "owner_session_locked" } }]
  });
  try {
    await new Promise((resolve) => setImmediate(resolve));
    assert.match(ui.app.innerHTML, /Owner 待配对/);
    assert.match(ui.app.innerHTML, /受信 HTTPS/);
    assert.doesNotMatch(ui.app.innerHTML, /获取签名挑战/);
    assert.equal(ui.requests.length, 0);
  } finally { ui.restore(); }
});

test("unpaired setup shows authenticated installation stage without role content", async () => {
  const ui = await mountWorkbench({
    statusResponses: [{ schema_version: "sylanne.install-status.v1", runtime_stage: "enrollment_required", reason_code: "authority_profile" }],
    sessionResponses: [{ status: "unauthorized", problem: { code: "owner_session_locked" } }]
  });
  try {
    await new Promise((resolve) => setImmediate(resolve));
    assert.match(ui.app.innerHTML, /插件安装与运行.*需要登记.*需要管理员登记 Authority/s);
    assert.match(ui.app.innerHTML, /Sylanne Owner.*锁定/s);
    assert.equal(ui.requests.length, 0);
    assert.doesNotMatch(ui.app.innerHTML, /aria-label="服务返回的权限过滤投影"/);
  } finally { ui.restore(); }
});

test("setup names pending Owner, role, and scene work from server reason codes", async () => {
  const ui = await mountWorkbench({ statusResponses: [
    { schema_version: "sylanne.install-status.v1", runtime_stage: "limited", reason_code: "owner_guard" },
    { schema_version: "sylanne.install-status.v1", runtime_stage: "limited", reason_code: "active_role" },
    { schema_version: "sylanne.install-status.v1", runtime_stage: "limited", reason_code: "scene_binding" }
  ] });
  try {
    await new Promise((resolve) => setImmediate(resolve));
    assert.match(ui.app.innerHTML, /Owner 授权尚未核验/);
    await ui.clickCommand("retry-status");
    assert.match(ui.app.innerHTML, /当前活跃角色尚未确认/);
    await ui.clickCommand("retry-status");
    assert.match(ui.app.innerHTML, /场景尚未绑定/);
    assert.equal(ui.requests.length, 0);
    assert.doesNotMatch(ui.app.innerHTML, /aria-label="服务返回的权限过滤投影"/);
  } finally { ui.restore(); }
});

test("a command response from the previous role cannot alter projection or receipt", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("role-a");
    const initial = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { label: "role-a" } });
    await initial;

    const oldCommand = ui.clickCommand("open-workspace");
    ui.setRole("role-b");
    const switched = ui.clickCommand("switch-role");
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "ready", projection: { label: "role-b-current" }, receipt: { operation_id: "receipt-b" } });
    await switched;
    ui.requests[1].resolve({ status: "ready", projection: { label: "role-a-obsolete" }, receipt: { operation_id: "receipt-a" } });
    await oldCommand;

    assert.match(ui.app.innerHTML, /role-b-current|receipt-b/);
    assert.doesNotMatch(ui.app.innerHTML, /role-a-obsolete|receipt-a/);
  } finally { ui.restore(); }
});

test("revoked Owner session clears private projection and relocks the page", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("role-a");
    const initial = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { private: "must-clear" } });
    await initial;
    const view = ui.clickView("overview");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: { private: "must-clear" } });
    await view;
    assert.match(ui.app.innerHTML, /must-clear/);

    const revoked = ui.clickCommand("open-workspace");
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "unauthorized", problem: { code: "owner_session_locked" } });
    await revoked;
    assert.doesNotMatch(ui.app.innerHTML, /must-clear/);
    assert.match(ui.app.innerHTML, /Sylanne Owner.*锁定/s);
    assert.doesNotMatch(ui.app.innerHTML, /aria-label="服务返回的权限过滤投影"/);
  } finally { ui.restore(); }
});

test("refresh retains the current projection while requesting its replacement", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("role-a");
    const initial = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await initial;

    const overview = ui.clickView("overview");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: { label: "current" } });
    await overview;

    const refreshing = ui.clickCommand("refresh");
    assert.match(ui.app.innerHTML, /current/);
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "ready", projection: { label: "refreshed" } });
    await refreshing;
    assert.match(ui.app.innerHTML, /refreshed/);
  } finally { ui.restore(); }
});

test("start page requests only the authenticated capability catalogue and never claims role binding", async () => {
  const ui = await mountWorkbench();
  try {
    assert.match(ui.app.innerHTML, /开始与连接/);
    assert.match(ui.app.innerHTML, /角色初始化.*未核验/s);
    assert.equal(ui.requests.length, 0);
    ui.setRole("role-a");
    const requested = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    assert.equal(ui.requests[0].payload.action, "open_workspace");
    ui.requests[0].resolve({ status: "ready", projection: { views: [{ view_type: "overview", status: "available" }] } });
    await requested;
    assert.match(ui.app.innerHTML, /Sylanne Owner.*已解锁/s);
    assert.match(ui.app.innerHTML, /角色初始化.*未核验/s);
    assert.match(ui.app.innerHTML, /场景绑定.*未核验/s);
  } finally { ui.restore(); }
});

test("Owner can explicitly submit a manually supplied scene binding with acknowledgement", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("role-a");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await opened;
    assert.match(ui.app.innerHTML, /管理员可信渠道提供的当前会话场景引用/);
    assert.match(ui.app.innerHTML, /服务端仍会核验角色、场景和权限，可能暂缓绑定/);

    const sceneRef = `scene:conversation-v1:${"a".repeat(64)}`;
    ui.setPageFields({ scene_ref: sceneRef, visibility: "group", acknowledgement: "on" });
    const submitted = ui.clickCommand("page-action");
    const request = await ui.nextRequest(1);
    assert.equal(request.payload.action, "bind_scene");
    assert.equal(request.payload.scope, "role-a");
    assert.match(request.payload.operation_id, /^[0-9a-f-]{36}$/i);
    assert.deepEqual(request.payload.input, {
      scene_ref: sceneRef, visibility: "group", acknowledgement: true
    });
    request.resolve({ status: "ready", receipt: { operation_id: request.payload.operation_id, phase: "scene_bound", scene_ref: sceneRef, binding_revision: 1 } });
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "ready", projection: { views: [] } });
    await submitted;
    assert.match(ui.app.innerHTML, /scene_bound/);
  } finally { ui.restore(); }
});

test("Owner can submit D01 creation using only explicit trusted references and receive server receipt", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("role-a");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await opened;
    assert.match(ui.app.innerHTML, /模型能力和预算目录不会由工作台推测/);
    assert.match(ui.app.innerHTML, /来自可信安装资料/);
    ui.setCreateFields({ display_name: "Mira", blueprint: "d01.persona.warm-listener.v1", model_capability_ref: "capability:local:verified", budget_ref: "budget:local:verified" });
    const submitted = ui.clickCommand("create-character");
    const request = await ui.nextRequest(1);
    assert.equal(request.payload.action, "create_character");
    assert.equal(request.payload.scope, "role-a");
    assert.match(request.payload.operation_id, /^[0-9a-f-]{36}$/i);
    assert.deepEqual(request.payload.input, {
      display_name: "Mira", blueprint: "d01.persona.warm-listener.v1",
      model_capability_ref: "capability:local:verified", budget_ref: "budget:local:verified"
    });
    request.resolve({ status: "ready", receipt: { operation_id: request.payload.operation_id, phase: "role_initialized", role_ref: "persona:mira", owner_grant_revision: 1 } });
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "ready", projection: { views: [] } });
    await submitted;
    assert.match(ui.app.innerHTML, /角色初始化.*已初始化.*persona:mira/s);
    assert.match(ui.app.innerHTML, new RegExp(request.payload.operation_id));
  } finally { ui.restore(); }
});

test("D01 creation stays HOLD when installed catalogue resolution is unavailable", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("role-a");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await opened;
    ui.setCreateFields({ display_name: "Mira", blueprint: "d01.persona.curious-maker.v1", model_capability_ref: "capability:from:install", budget_ref: "budget:from:install" });
    const submitted = ui.clickCommand("create-character");
    const request = await ui.nextRequest(1);
    request.resolve({ status: "unavailable", problem: { code: "role_initialization_unavailable", retryable: true } });
    await submitted;
    assert.match(ui.app.innerHTML, /角色初始化.*HOLD.*服务端未确认初始化/);
    assert.doesNotMatch(ui.app.innerHTML, /role_initialized/);
  } finally { ui.restore(); }
});
