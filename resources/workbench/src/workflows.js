import { ACTIONS } from "./api/contract.js";

function text(value) { return String(value ?? "").trim(); }
function commaList(value) { return text(value).split(",").map((item) => item.trim()).filter(Boolean); }
function objectJson(value) {
  const raw = text(value);
  if (!raw) return null;
  let parsed;
  try { parsed = JSON.parse(raw); } catch { throw new Error("草稿必须是合法 JSON 对象。服务端仍会进行领域校验。"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("草稿必须是 JSON 对象。");
  return parsed;
}

export function workflowForPage(page, values) {
  const mode = text(values.mode);
  switch (page) {
    case "creation": {
      const draft = objectJson(values.draft_json);
      return mode === "activate"
        ? [ACTIONS.activateScheme, { compiled_scheme_ref: text(values.compiled_scheme_ref), adopt_intent: "user_requested_adoption" }]
        : [ACTIONS.compileScheme, { ...(draft ? { draft } : { draft_ref: text(values.draft_ref) }), intent: "user_requested_candidate" }];
    }
    case "relations":
    case "memory":
      return [ACTIONS.correctOrEdit, { correction_kind: text(values.correction_kind), statement: text(values.statement), source_refs: commaList(values.source_refs) }];
    case "cognition":
      return [ACTIONS.configureOrControl, { object_ref: text(values.object_ref), config_diff: { requested_view: page } }];
    case "action":
    case "expression":
      return [ACTIONS.configureOrControl, { object_ref: text(values.object_ref), control: text(values.control) }];
    case "diagnostics":
      return mode === "support"
        ? [ACTIONS.diagnoseAndExportSupport, { question: text(values.question), allowed_data: [] }]
        : [ACTIONS.runExperiment, { experiment: { hypothesis: text(values.hypothesis), simulated: true } }];
    case "lifecycle":
      if (mode === "execute") return [ACTIONS.executeTransfer, { plan_ref: text(values.plan_ref), current_epochs: {} }];
      if (mode === "erase") return [ACTIONS.eraseOrRetire, { mode: "erase", scope_selection: text(values.scope_selection), data_choice: text(values.data_choice) }];
      if (mode === "upgrade") return [ACTIONS.installOrUpgrade, { release_manifest_ref: text(values.release_manifest_ref) }];
      return [ACTIONS.prepareTransfer, { mode: "backup", scope_selection: text(values.scope_selection) }];
    default:
      return [ACTIONS.readCharacterView, null];
  }
}

export function needsFreshProjection(action) {
  return action !== ACTIONS.readCharacterView && action !== ACTIONS.openWorkspace;
}
