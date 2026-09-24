import test from "node:test";
import assert from "node:assert/strict";

async function mountWorkbench({ sessionResponses = [], statusResponses = [], sceneCandidates = [], deferSceneCandidates = false, ownerFields = {}, origin = "https://localhost:6185" } = {}) {
  const previousDocument = globalThis.document;
  const previousFetch = globalThis.fetch;
  const previousFormData = globalThis.FormData;
  const previousLocation = globalThis.location;
  const requests = [];
  const candidateRequests = [];
  const workspace = { focusCount: 0, focus() { this.focusCount++; } };
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
  const pageForm = { id: "page-form", elements: { namedItem(name) { return {
    set value(value) { pageFields[name] = value; },
    set checked(value) { pageFields[name] = value ? "on" : ""; }
  }; } } };
  globalThis.document = {
    querySelector(selector) {
      if (selector === "#app") return app;
      if (selector === "#workspace") return workspace;
      if (selector === "#role-input") return { value: roleInput };
      if (selector === "#owner-login-form") return { id: "owner-login-form" };
      if (selector === "#page-form") return pageForm;
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
      if (url.endsWith("/scene-candidates")) {
        if (deferSceneCandidates) return new Promise((resolve) => {
          candidateRequests.push({ resolve: (candidates) => resolve({ ok: true, status: 200, json: async () => ({
            schema_version: "sylanne.scene-candidates.v1", status: candidates.length ? "ready" : "empty",
            candidates
          }) }) });
        });
        return { ok: true, status: 200, json: async () => ({
          schema_version: "sylanne.scene-candidates.v1", status: sceneCandidates.length ? "ready" : "empty",
          candidates: sceneCandidates
        }) };
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
  await import(`../../../../webui-src/src/app.js?test=${Date.now()}-${Math.random()}`);
  async function nextRequest(index) {
    for (let attempt = 0; attempt < 10 && requests.length <= index; attempt++) await new Promise((resolve) => setImmediate(resolve));
    assert.ok(requests[index], `expected command request ${index}`);
    return requests[index];
  }
  return {
    app, requests, candidateRequests, nextRequest,
    get workspaceFocusCount() { return workspace.focusCount; },
    get sessionRequests() { return sessionRequests; },
    get statusRequests() { return statusRequests; },
    setRole(value) { roleInput = value; },
    setOwnerSignature(value) { ownerSignature = value; },
    setPageFields(value) { pageFields = value; },
    getPageFields() { return pageFields; },
    setCreateFields(value) { createFields = value; },
    clickCommand(command) { return app.click({ target: { closest(selector) { return selector === "[data-command]" ? { dataset: { command } } : null; } } }); },
    clickView(view) { return app.click({ target: { closest(selector) { return selector === "[data-view]" ? { dataset: { view } } : null; } } }); },
    clickCandidate(index) { return app.click({ target: { closest(selector) { return selector === "[data-scene-candidate]" ? { dataset: { sceneCandidate: String(index) } } : null; } } }); },
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
    assert.equal(ui.requests[2].payload.input.view_type, "d06.memory_sources.v1");
    assert.equal(ui.requests[2].payload.input.page_size, 100);
    ui.requests[2].resolve({ status: "ready", projection: { view_type: "d06.memory_sources.v1", data: {
      sources: [{ source_id: "memory-current", source_kind: "reported", assertion_status: "asserted", recorded_at: 42, qualification: "not_recorded" }], coverage: "complete"
    } } });
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

test("Owner selects a recent scene but acknowledgement and submit remain separate", async () => {
  const scene_ref = `scene:conversation-v1:${"a".repeat(64)}`;
  const ui = await mountWorkbench({ sceneCandidates: [{
    platform_ref: "onebot", conversation_ref: "group-7", visibility: "group", scene_ref
  }] });
  try {
    await new Promise((resolve) => setImmediate(resolve));
    await ui.clickCommand("refresh-scene-candidates");
    assert.match(ui.app.innerHTML, /onebot · group-7 · 群聊/);
    await ui.clickCandidate(0);
    assert.deepEqual(ui.getPageFields(), { scene_ref, visibility: "group", acknowledgement: "" });
    assert.equal(ui.requests.length, 0);
  } finally { ui.restore(); }
});

test("switching roles clears candidates and rejects an earlier candidate response", async () => {
  const candidate = {
    platform_ref: "onebot", conversation_ref: "old-group", visibility: "group",
    scene_ref: `scene:conversation-v1:${"a".repeat(64)}`
  };
  const ui = await mountWorkbench({ deferSceneCandidates: true });
  try {
    await new Promise((resolve) => setImmediate(resolve));
    const pending = ui.clickCommand("refresh-scene-candidates");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(ui.candidateRequests.length, 1);
    ui.setRole("role-b");
    const switching = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.candidateRequests[0].resolve([candidate]);
    await pending;
    assert.doesNotMatch(ui.app.innerHTML, /old-group/);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await switching;
    assert.doesNotMatch(ui.app.innerHTML, /old-group/);
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
    ui.requests[1].resolve({ status: "ready", projection: {
      views: [{ view_type: "must-clear", status: "available" }], unavailable_domains: []
    } });
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
    ui.requests[1].resolve({ status: "ready", projection: {
      views: [{ view_type: "current", status: "available" }], unavailable_domains: []
    } });
    await overview;

    const refreshing = ui.clickCommand("refresh");
    assert.match(ui.app.innerHTML, /current/);
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "ready", projection: {
      views: [{ view_type: "refreshed", status: "available" }], unavailable_domains: []
    } });
    await refreshing;
    assert.match(ui.app.innerHTML, /refreshed/);
  } finally { ui.restore(); }
});

test("overview reads the Owner-authorized service catalogue without inventing domain content", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await opened;
    const selected = ui.clickView("overview");
    const request = await ui.nextRequest(1);
    assert.equal(request.payload.action, "open_workspace");
    assert.equal(request.payload.scope, "bot/persona");
    assert.equal(request.payload.purpose, "workbench_view");
    request.resolve({ status: "ready", projection: {
      namespace: { bot: "bot", persona: "persona" }, access_generation: 3,
      views: [{ view_type: "creation", status: "available" },
        { view_type: "d06.memory_sources.v1", status: "unavailable" }],
      unavailable_domains: [{ domain: "d06<script>", reason: "no_public_projection_contract" }]
    } });
    await selected;
    assert.match(ui.app.innerHTML, /服务返回的能力目录/);
    assert.match(ui.app.innerHTML, /data-view="creation" aria-label="打开创作视图"/);
    assert.match(ui.app.innerHTML, /d06\.memory_sources\.v1\)<\/strong><span>暂不可用；没有可读取内容/);
    assert.match(ui.app.innerHTML, /d06&lt;script&gt;/);
    assert.match(ui.app.innerHTML, /no_public_projection_contract/);
    assert.doesNotMatch(ui.app.innerHTML, /<script>/);
    assert.match(ui.app.innerHTML, /不代表领域内容或真实对话已经就绪/);
  } finally { ui.restore(); }
});

test("catalogue opens only a service-available known page and requests its fresh projection", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: {
      views: [
        { view_type: "creation", status: "available" },
        { view_type: "d06.memory_sources.v1", status: "unavailable" },
        { view_type: "future-view", status: "available" }
      ], unavailable_domains: []
    } });
    await opened;
    const overview = ui.clickView("overview");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: {
      views: [
        { view_type: "creation", status: "available" },
        { view_type: "d06.memory_sources.v1", status: "unavailable" },
        { view_type: "future-view", status: "available" }
      ], unavailable_domains: []
    } });
    await overview;
    assert.match(ui.app.innerHTML, /data-view="creation" aria-label="打开创作视图"/);
    assert.doesNotMatch(ui.app.innerHTML, /data-view="memory" aria-label="打开记忆视图"/);
    assert.match(ui.app.innerHTML, /future-view<\/strong><span>服务声明可读取；当前客户端没有对应页面/);

    const selected = ui.clickView("creation");
    const request = await ui.nextRequest(2);
    assert.equal(request.payload.action, "read_character_view");
    assert.equal(request.payload.input.view_type, "creation");
    assert.equal(request.payload.scope, "bot/persona");
    request.resolve({ status: "ready", projection: { view_type: "creation", data: { candidates: [] } } });
    await selected;
    assert.match(ui.app.innerHTML, /尚不能确认整个范围为空/);
  } finally { ui.restore(); }
});

test("D06 catalogue opens a read-only memory summary without source text", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: {
      views: [{ view_type: "d06.memory_sources.v1", status: "available" }], unavailable_domains: []
    } });
    await opened;
    const overview = ui.clickView("overview");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: {
      views: [{ view_type: "d06.memory_sources.v1", status: "available" }], unavailable_domains: []
    } });
    await overview;
    assert.match(ui.app.innerHTML, /data-view="memory" aria-label="打开记忆视图"/);
    const memory = ui.clickView("memory");
    const request = await ui.nextRequest(2);
    assert.equal(request.payload.action, "read_character_view");
    assert.equal(request.payload.input.view_type, "d06.memory_sources.v1");
    assert.equal(request.payload.input.page_size, 100);
    request.resolve({ status: "ready", projection: { view_type: "d06.memory_sources.v1", data: {
      sources: [{ source_id: "source-<unsafe>", source_kind: "reported", assertion_status: "asserted", recorded_at: 12.5, qualification: "not_recorded", text: "secret-original" }],
      coverage: "complete"
    } } });
    await memory;
    assert.match(ui.app.innerHTML, /source-&lt;unsafe&gt;/);
    assert.match(ui.app.innerHTML, /服务已确认完整覆盖，共 1 条来源/);
    assert.doesNotMatch(ui.app.innerHTML, /secret-original|<unsafe>|纠错类型|提交给服务端|<pre class="projection"/);
    const refresh = ui.clickCommand("page-action");
    await ui.nextRequest(3);
    assert.equal(ui.requests[3].payload.action, "read_character_view");
    ui.requests[3].resolve({ status: "ready", projection: { view_type: "d06.memory_sources.v1", data: { sources: [], coverage: "complete" } } });
    await refresh;
    assert.match(ui.app.innerHTML, /当前授权范围内没有可显示的记忆来源/);
  } finally { ui.restore(); }
});

test("D06 memory rejects partial or malformed source coverage and clears prior summary", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [], unavailable_domains: [] } });
    await opened;
    const memory = ui.clickView("memory");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: { view_type: "d06.memory_sources.v1", data: {
      sources: [{ source_id: "prior-source", source_kind: "observed", assertion_status: "asserted", recorded_at: 1, qualification: "not_recorded" }], coverage: "complete"
    } } });
    await memory;
    assert.match(ui.app.innerHTML, /prior-source/);
    for (const data of [
      { sources: [{ source_id: "partial-source", source_kind: "reported", assertion_status: "asserted", recorded_at: 2, qualification: "not_recorded" }], coverage: "partial" },
      { sources: [{ source_id: "malformed-source", source_kind: "reported", assertion_status: "asserted", recorded_at: "2", qualification: "not_recorded" }], coverage: "complete" }
    ]) {
      const nextIndex = ui.requests.length;
      const refresh = ui.clickCommand("page-action");
      const request = await ui.nextRequest(nextIndex);
      request.resolve({ status: "ready", projection: { view_type: "d06.memory_sources.v1", data } });
      await refresh;
      assert.match(ui.app.innerHTML, /state-unavailable/);
      assert.doesNotMatch(ui.app.innerHTML, /prior-source|partial-source|malformed-source|<pre class="projection"/);
    }
  } finally { ui.restore(); }
});

test("D06 correction sends the versioned request and displays server HOLD without adoption", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [], unavailable_domains: [] } });
    await opened;
    const memory = ui.clickView("memory");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: { view_type: "d06.memory_sources.v1", data: {
      sources: [{ source_id: "visible-source", source_kind: "reported", assertion_status: "asserted", recorded_at: 2, qualification: "not_recorded" }],
      coverage: "complete"
    } } });
    await memory;
    assert.match(ui.app.innerHTML, /visible-source/);
    ui.setPageFields({ statement: "更正说明", source_refs: "source-a, source-b", target_refs: "target-a",
      access_epoch: "3", deletion_epoch: "4", impact_preview_ref: "preview-1" });
    const submitted = ui.clickCommand("memory-correction");
    const request = await ui.nextRequest(2);
    assert.equal(request.payload.action, "correct_or_edit");
    assert.equal(request.payload.scope, "bot/persona");
    assert.deepEqual(request.payload.input, {
      schema: "d12.source_correction.v1", correction_kind: "source_claim", statement: "更正说明",
      source_refs: ["source-a", "source-b"], target_refs: ["target-a"],
      access_epoch: 3, deletion_epoch: 4, impact_preview_ref: "preview-1"
    });
    request.resolve({ status: "unavailable", problem: {
      schema: "d12.source_correction_response.v1", code: "source_correction_commit_unavailable",
      message: "来源纠错提交尚未接入权威协调器；未修改来源或解释。", retryable: false
    } });
    await submitted;
    assert.match(ui.app.innerHTML, /更正待接入（HOLD）/);
    assert.match(ui.app.innerHTML, /未修改来源或解释/);
    assert.doesNotMatch(ui.app.innerHTML, /visible-source|<dd>source_claim<\/dd>|<dd>correction_committed<\/dd>/);
    assert.equal(ui.requests.length, 3, "HOLD does not trigger a refresh that could imply a commit");
  } finally { ui.restore(); }
});

test("D06 correction permission denial clears the projection and locks Owner", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [], unavailable_domains: [] } });
    await opened;
    const memory = ui.clickView("memory");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: { view_type: "d06.memory_sources.v1", data: {
      sources: [{ source_id: "private-source", source_kind: "reported", assertion_status: "asserted", recorded_at: 2, qualification: "not_recorded" }],
      coverage: "complete"
    } } });
    await memory;
    ui.setPageFields({ statement: "更正说明", source_refs: "source-a", target_refs: "target-a", access_epoch: "3", deletion_epoch: "4" });
    const submitted = ui.clickCommand("memory-correction");
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "unauthorized", problem: { code: "capability_denied", message: "当前会话无权更正。" } });
    await submitted;
    assert.match(ui.app.innerHTML, /当前会话无权更正/);
    assert.match(ui.app.innerHTML, /Sylanne Owner 锁定/);
    assert.doesNotMatch(ui.app.innerHTML, /private-source/);
  } finally { ui.restore(); }
});

test("overview keeps absent and malformed service catalogues distinct", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await opened;
    const selected = ui.clickView("overview");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: { views: [], unavailable_domains: [] } });
    await selected;
    assert.match(ui.app.innerHTML, /服务当前未公布可读取视图/);
    const refreshed = ui.clickCommand("refresh");
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "ready", projection: { views: [{ view_type: "creation" }] } });
    await refreshed;
    assert.match(ui.app.innerHTML, /能力目录不可用/);
    assert.doesNotMatch(ui.app.innerHTML, /creation<\/strong>/);
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
    assert.match(ui.app.innerHTML, /近期场景候选仅来自宿主已观察到的会话/);
    assert.match(ui.app.innerHTML, /服务端仍会核验场景和权限，可能暂缓绑定/);

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

test("creation page renders only the authorized D01 plan summary returned by read_character_view", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await opened;
    const selected = ui.clickView("creation");
    const request = await ui.nextRequest(1);
    assert.equal(request.payload.action, "read_character_view");
    assert.equal(request.payload.scope, "bot/persona");
    assert.deepEqual(request.payload.input, { view_type: "creation", page_size: 50 });
    request.resolve({ status: "ready", projection: {
      view_type: "creation", namespace: { bot: "bot", persona: "persona" },
      data: { candidates: [{ plan_id: "plan:<script>alert(1)</script>", version: 2,
        authored: true, block_count: 3, value_rule_count: 1 }] },
      snapshot_epoch: 7
    } });
    await selected;
    assert.equal(ui.workspaceFocusCount, 2, "view selection focuses the loading page and the completed page");
    assert.match(ui.app.innerHTML, /已授权角色方案/);
    assert.match(ui.app.innerHTML, /plan:&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(ui.app.innerHTML, /版本 2 · 创作标记：是/);
    assert.match(ui.app.innerHTML, /3 个设定块 · 1 条价值规则/);
    assert.doesNotMatch(ui.app.innerHTML, /<script>alert\(1\)<\/script>/);
    assert.doesNotMatch(ui.app.innerHTML, /已采用方案/);
  } finally { ui.restore(); }
});

test("creation page keeps empty and malformed projections distinct and clears on Owner lock", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await opened;
    const selected = ui.clickView("creation");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: {
      view_type: "creation", data: { candidates: [] }
    } });
    await selected;
    assert.match(ui.app.innerHTML, /尚不能确认整个范围为空/);
    const refreshed = ui.clickCommand("refresh");
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "ready", projection: {
      view_type: "creation", data: { candidates: [{ plan_id: "unverified" }] }
    } });
    await refreshed;
    assert.match(ui.app.innerHTML, /方案投影不可用/);
    assert.doesNotMatch(ui.app.innerHTML, /<strong>unverified<\/strong>/);
    const logout = ui.clickCommand("owner-logout");
    await ui.nextRequest(3);
    assert.doesNotMatch(ui.app.innerHTML, /已授权角色方案/);
    ui.requests[3].resolve({ status: "ok", owner_session: "locked" });
    await logout;
  } finally { ui.restore(); }
});

test("creation list marks truncated coverage and appends only matching cursor pages", async () => {
  const ui = await mountWorkbench();
  const candidate = (id) => ({ plan_id: id, version: 1, authored: true, block_count: 0, value_rule_count: 0 });
  const projection = (candidates, truncated, cursor) => ({
    view_type: "creation", namespace: { bot: "bot", persona: "persona" },
    access_generation: 4, snapshot_epoch: 9, data: { candidates },
    coverage: { returned_atoms: candidates.length, truncated }, next_cursor: cursor
  });
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await opened;
    const selected = ui.clickView("creation");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: projection([candidate("first")], true, "opaque-cursor") });
    await selected;
    assert.match(ui.app.innerHTML, /已读取 1 个方案，服务标记还有后续页面/);
    assert.match(ui.app.innerHTML, /data-command="creation-next"[^>]*>继续读取后续方案/);
    const next = ui.clickCommand("creation-next");
    const request = await ui.nextRequest(2);
    assert.equal(request.payload.input.cursor, "opaque-cursor");
    assert.equal(request.payload.input.view_type, "creation");
    assert.match(ui.app.innerHTML, /正在读取后续方案/);
    request.resolve({ status: "ready", projection: projection([candidate("second")], false, null) });
    await next;
    assert.match(ui.app.innerHTML, /first<\/strong>/);
    assert.match(ui.app.innerHTML, /second<\/strong>/);
    assert.match(ui.app.innerHTML, /当前快照已读完，共 2 个方案/);
    assert.doesNotMatch(ui.app.innerHTML, /data-command="creation-next"/);
  } finally { ui.restore(); }
});

test("creation cursor refuses a page from another snapshot and clears prior plans", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    await ui.nextRequest(0);
    ui.requests[0].resolve({ status: "ready", projection: { views: [] } });
    await opened;
    const selected = ui.clickView("creation");
    await ui.nextRequest(1);
    ui.requests[1].resolve({ status: "ready", projection: {
      view_type: "creation", namespace: { bot: "bot", persona: "persona" },
      access_generation: 4, snapshot_epoch: 9,
      data: { candidates: [{ plan_id: "prior-private-plan", version: 1, authored: true, block_count: 0, value_rule_count: 0 }] },
      coverage: { truncated: true }, next_cursor: "opaque-cursor"
    } });
    await selected;
    const next = ui.clickCommand("creation-next");
    await ui.nextRequest(2);
    ui.requests[2].resolve({ status: "ready", projection: {
      view_type: "creation", namespace: { bot: "bot", persona: "persona" },
      access_generation: 4, snapshot_epoch: 10,
      data: { candidates: [] }, coverage: { truncated: false }, next_cursor: null
    } });
    await next;
    assert.match(ui.app.innerHTML, /后续方案页无法与当前快照核对/);
    assert.doesNotMatch(ui.app.innerHTML, /prior-private-plan/);
  } finally { ui.restore(); }
});

test("setup keeps independent server receipts for role initialization and scene binding", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    (await ui.nextRequest(0)).resolve({ status: "ready", projection: { views: [], unavailable_domains: [] } });
    await opened;
    ui.setCreateFields({ display_name: "Mira", blueprint: "d01.persona.warm-listener.v1",
      model_capability_ref: "capability:verified", budget_ref: "budget:verified" });
    const created = ui.clickCommand("create-character");
    const createRequest = await ui.nextRequest(1);
    createRequest.resolve({ status: "ready", receipt: { operation_id: createRequest.payload.operation_id,
      phase: "role_initialized", role_ref: "persona:persona", owner_grant_revision: 1 } });
    (await ui.nextRequest(2)).resolve({ status: "ready", projection: { views: [], unavailable_domains: [] } });
    await created;
    assert.match(ui.app.innerHTML, /角色初始化<\/strong><span>已初始化/);
    assert.match(ui.app.innerHTML, /场景绑定<\/strong><span>未核验/);

    ui.setPageFields({ scene_ref: `scene:conversation-v1:${"a".repeat(64)}`,
      visibility: "private", acknowledgement: "on" });
    const bound = ui.clickCommand("page-action");
    const bindRequest = await ui.nextRequest(3);
    bindRequest.resolve({ status: "ready", receipt: { operation_id: bindRequest.payload.operation_id,
      phase: "scene_bound", scene_ref: `scene:conversation-v1:${"a".repeat(64)}`, binding_revision: 1 } });
    (await ui.nextRequest(4)).resolve({ status: "ready", projection: { views: [], unavailable_domains: [] } });
    await bound;
    assert.match(ui.app.innerHTML, /角色初始化<\/strong><span>已初始化/);
    assert.match(ui.app.innerHTML, /场景绑定<\/strong><span>已绑定/);
    assert.match(ui.app.innerHTML, /验证对话<\/strong><span>未核验/);
  } finally { ui.restore(); }
});

test("setup receipts are cleared on role switch and Owner logout", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("bot/persona");
    const opened = ui.clickCommand("switch-role");
    (await ui.nextRequest(0)).resolve({ status: "ready", projection: { views: [], unavailable_domains: [] } });
    await opened;
    ui.setCreateFields({ display_name: "Mira", blueprint: "d01.persona.warm-listener.v1",
      model_capability_ref: "capability:verified", budget_ref: "budget:verified" });
    const created = ui.clickCommand("create-character");
    const createRequest = await ui.nextRequest(1);
    createRequest.resolve({ status: "ready", receipt: { operation_id: createRequest.payload.operation_id,
      phase: "role_initialized", role_ref: "persona:persona", owner_grant_revision: 1 } });
    (await ui.nextRequest(2)).resolve({ status: "ready", projection: { views: [], unavailable_domains: [] } });
    await created;
    ui.setRole("bot/other");
    const switched = ui.clickCommand("switch-role");
    (await ui.nextRequest(3)).resolve({ status: "ready", projection: { views: [], unavailable_domains: [] } });
    await switched;
    assert.match(ui.app.innerHTML, /角色初始化<\/strong><span>未核验/);
    const logout = ui.clickCommand("owner-logout");
    (await ui.nextRequest(4)).resolve({ status: "ok", owner_session: "locked" });
    await logout;
    assert.doesNotMatch(ui.app.innerHTML, /角色初始化<\/strong><span>已初始化/);
  } finally { ui.restore(); }
});
