import test from "node:test";
import assert from "node:assert/strict";

async function mountWorkbench({ sessionResponses = [], statusResponses = [] } = {}) {
  const previousDocument = globalThis.document;
  const previousFetch = globalThis.fetch;
  const requests = [];
  const app = {
    innerHTML: "",
    addEventListener(type, listener) { if (type === "click") this.click = listener; }
  };
  let roleInput = "";
  let sessionRequests = 0;
  let statusRequests = 0;
  globalThis.document = {
    querySelector(selector) {
      if (selector === "#app") return app;
      if (selector === "#role-input") return { value: roleInput };
      return null;
    }
  };
  globalThis.fetch = async (url, init) => {
    if (init.method === "GET") {
      if (url.endsWith("/status")) {
        const body = statusResponses[statusRequests++] ?? { schema_version: "sylanne.install-status.v1", runtime_stage: "limited", reason_code: "runtime_unavailable" };
        return { ok: true, status: 200, json: async () => body };
      }
      const body = sessionResponses[sessionRequests++] ?? { status: "ready", csrf_token: "issued" };
      return { ok: body.status === "ready", status: body.status === "ready" ? 200 : 401, json: async () => body };
    }
    return new Promise((resolve) => {
      requests.push({ payload: JSON.parse(init.body), resolve: (body) => resolve({ ok: true, json: async () => body }) });
    });
  };
  await import(`../../../../webui-src/src/app.js?test=${Date.now()}-${Math.random()}`);
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
    clickCommand(command) { return app.click({ target: { closest(selector) { return selector === "[data-command]" ? { dataset: { command } } : null; } } }); },
    clickView(view) { return app.click({ target: { closest(selector) { return selector === "[data-view]" ? { dataset: { view } } : null; } } }); },
    restore() { globalThis.document = previousDocument; globalThis.fetch = previousFetch; }
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

test("unpaired startup exposes recovery and retry verifies a new session", async () => {
  const ui = await mountWorkbench({ sessionResponses: [
    { status: "unauthorized", problem: { code: "session_unbound", message: "工作台会话未建立。" } },
    { status: "ready", csrf_token: "paired" }
  ] });
  try {
    await new Promise((resolve) => setImmediate(resolve));
    assert.match(ui.app.innerHTML, /工作台会话未建立/);
    assert.match(ui.app.innerHTML, /重新核验工作台会话/);
    await ui.clickCommand("retry-session");
    assert.equal(ui.sessionRequests, 2);
    assert.match(ui.app.innerHTML, /宿主与工作台会话.*已核验/s);
    assert.doesNotMatch(ui.app.innerHTML, /工作台会话未建立/);
  } finally { ui.restore(); }
});

test("unpaired setup shows authenticated installation stage without role content", async () => {
  const ui = await mountWorkbench({
    statusResponses: [{ schema_version: "sylanne.install-status.v1", runtime_stage: "enrollment_required", reason_code: "authority_profile" }],
    sessionResponses: [{ status: "unauthorized", problem: { code: "session_unbound" } }]
  });
  try {
    await new Promise((resolve) => setImmediate(resolve));
    assert.match(ui.app.innerHTML, /插件安装与运行.*需要登记.*需要管理员登记 Authority/s);
    assert.match(ui.app.innerHTML, /工作台会话尚未核验/);
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
    assert.match(ui.app.innerHTML, /宿主与工作台会话.*已核验/s);
    assert.match(ui.app.innerHTML, /角色初始化.*未核验/s);
    assert.match(ui.app.innerHTML, /场景绑定.*未核验/s);
  } finally { ui.restore(); }
});
