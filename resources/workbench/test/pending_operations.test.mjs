import assert from "node:assert/strict";
import test from "node:test";
import { makeRequest } from "../src/api/contract.js";
import { PendingOperationIds } from "../src/api/pending_operations.js";

test("retries reuse an operation ID only for the same action and payload", () => {
  let next = 0;
  const pending = new PendingOperationIds({ createId: () => `operation-${++next}` });
  const input = { display_name: "Companion", blueprint: "blank" };
  const key = pending.key("create_character", "bot/persona", "workbench_user_action", input);

  const firstAttempt = pending.get(key);
  const retry = pending.get(pending.key(
    "create_character", "bot/persona", "workbench_user_action", { ...input }));
  assert.equal(retry, firstAttempt);
  assert.equal(makeRequest("create_character", {
    scope: "bot/persona", purpose: "workbench_user_action", input, operationId: retry,
  }).operation_id, firstAttempt);

  const changedPayload = pending.key("create_character", "bot/persona",
    "workbench_user_action", { ...input, display_name: "Another" });
  assert.notEqual(pending.get(changedPayload), firstAttempt);
});

test("completed operations and owner-session resets do not reuse old IDs", () => {
  let next = 0;
  const pending = new PendingOperationIds({ createId: () => `operation-${++next}` });
  const key = pending.key("bind_scene", "bot/persona", "workbench_user_action", {
    scene_ref: "scene:conversation-v1:" + "a".repeat(64), visibility: "private",
  });
  const committed = pending.get(key);
  pending.complete(key);
  assert.notEqual(pending.get(key), committed);
  pending.clear();
  assert.notEqual(pending.get(key), committed);
});
