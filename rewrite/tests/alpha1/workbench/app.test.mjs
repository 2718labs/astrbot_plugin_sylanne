import test from "node:test";
import assert from "node:assert/strict";

async function mountWorkbench() {
  const previousDocument = globalThis.document;
  const previousFetch = globalThis.fetch;
  const requests = [];
  const app = {
    innerHTML: "",
    addEventListener(type, listener) { if (type === "click") this.click = listener; }
  };
  let roleInput = "";
  globalThis.document = {
    querySelector(selector) {
      if (selector === "#app") return app;
      if (selector === "#role-input") return { value: roleInput };
      return null;
    }
  };
  globalThis.fetch = async (_url, init) => new Promise((resolve) => {
    requests.push({ payload: JSON.parse(init.body), resolve: (body) => resolve({ ok: true, json: async () => body }) });
  });
  await import(`../../../../webui-src/src/app.js?test=${Date.now()}-${Math.random()}`);
  return {
    app, requests,
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
    ui.requests[0].resolve({ status: "ready", projection: { label: "overview" } });
    await initial;

    const older = ui.clickView("creation");
    const newer = ui.clickView("memory");
    ui.requests[2].resolve({ status: "ready", projection: { label: "memory-current" } });
    await newer;
    ui.requests[1].resolve({ status: "ready", projection: { label: "creation-obsolete" } });
    await older;

    assert.match(ui.app.innerHTML, /memory-current/);
    assert.doesNotMatch(ui.app.innerHTML, /creation-obsolete/);
  } finally { ui.restore(); }
});

test("a command response from the previous role cannot alter projection or receipt", async () => {
  const ui = await mountWorkbench();
  try {
    ui.setRole("role-a");
    const initial = ui.clickCommand("switch-role");
    ui.requests[0].resolve({ status: "ready", projection: { label: "role-a" } });
    await initial;

    const oldCommand = ui.clickCommand("open-workspace");
    ui.setRole("role-b");
    const switched = ui.clickCommand("switch-role");
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
    ui.requests[0].resolve({ status: "ready", projection: { label: "current" } });
    await initial;

    const refreshing = ui.clickCommand("refresh");
    assert.match(ui.app.innerHTML, /current/);
    ui.requests[1].resolve({ status: "ready", projection: { label: "refreshed" } });
    await refreshing;
    assert.match(ui.app.innerHTML, /refreshed/);
  } finally { ui.restore(); }
});
