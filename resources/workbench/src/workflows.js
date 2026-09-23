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
    case "setup": {
      const sceneRef = text(values.scene_ref);
      const visibility = text(values.visibility);
      if (!/^scene:conversation-v1:[a-f0-9]{64}$/.test(sceneRef)) throw new Error("请输入管理员可信渠道提供的当前会话场景引用（scene:conversation-v1: 后接 64 位小写十六进制值）。");
      if (!["private", "group"].includes(visibility)) throw new Error("请选择场景可见范围。");
      if (values.acknowledgement !== "on" && values.acknowledgement !== true) throw new Error("请确认场景引用和可见范围准确后再提交。");
      return [ACTIONS.bindScene, { scene_ref: sceneRef, visibility, acknowledgement: true }];
    }
    case "role-init": {
      const displayName = text(values.display_name);
      const blueprint = text(values.blueprint);
      const modelCapabilityRef = text(values.model_capability_ref);
      const budgetRef = text(values.budget_ref);
      if (!displayName || displayName.length > 80) throw new Error("名称需为 1 至 80 个字符。");
      if (!["blank", "example"].includes(blueprint)) throw new Error("请选择服务端支持的初始化方案。");
      const validRef = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$/;
      if (!validRef.test(modelCapabilityRef) || !validRef.test(budgetRef)) throw new Error("请填写可信安装资料中的模型能力引用和预算引用。");
      return [ACTIONS.createCharacter, {
        display_name: displayName, blueprint,
        model_capability_ref: modelCapabilityRef, budget_ref: budgetRef
      }];
    }
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
