import test from "node:test";
import assert from "node:assert/strict";
import { ACTIONS, D12_SCHEMA_VERSION, makeRequest } from "../../../../webui-src/src/api/contract.js";
import { DEFAULT_WORKBENCH_API_BASE, WorkbenchApi, WorkbenchApiError } from "../../../../webui-src/src/api/client.js";
import { applyProblem, applyResponse, initialState, switchRole, VIEW_STATES } from "../../../../webui-src/src/state.js";
import { needsFreshProjection, workflowForPage } from "../../../../webui-src/src/workflows.js";

test("client posts to the AstrBot plugin extension route with host cookie and CSRF", async () => {
  let requested;
  const api = new WorkbenchApi({ csrfToken: "server-issued", fetchImpl: async (url, init) => {
    requested = { url, init };
    return { ok: true, json: async () => ({ status: "unavailable", problem: { code: "provider_unavailable" } }) };
  } });
  await api.command(ACTIONS.openWorkspace, { scope: "role-1", purpose: "workbench_view", input: { client_protocol: D12_SCHEMA_VERSION } });
  assert.equal(DEFAULT_WORKBENCH_API_BASE, "/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1");
  assert.equal(requested.url, `${DEFAULT_WORKBENCH_API_BASE}/commands`);
  assert.equal(requested.init.credentials, "same-origin");
  assert.equal(requested.init.headers["x-csrf-token"], "server-issued");
});

test("client displays a D12 problem from an HTTP error", async () => {
  const api = new WorkbenchApi({ csrfToken: "server-issued", fetchImpl: async () => ({
    ok: false, status: 403, json: async () => ({ status: "unauthorized", problem: { code: "csrf_denied", message: "防跨站校验未通过。", retryable: false } })
  }) });
  await assert.rejects(api.command(ACTIONS.openWorkspace, { scope: "role-1", purpose: "workbench_view" }),
    (error) => error instanceof WorkbenchApiError && error.status === 403 && error.code === "csrf_denied" && error.message === "防跨站校验未通过。");
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
