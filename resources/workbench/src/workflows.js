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
      if (!["d01.persona.warm-listener.v1", "d01.persona.curious-maker.v1"].includes(blueprint)) throw new Error("请选择本地目录中的有效角色预设。");
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
    case "memory": {
      const statement = text(values.statement);
      const sourceRefs = commaList(values.source_refs);
      const targetRefs = commaList(values.target_refs);
      const epoch = (value) => /^(0|[1-9]\d*)$/.test(text(value)) && Number.isSafeInteger(Number(value));
      if (!statement || statement.length > 4096) throw new Error("来源更正说明需为 1 至 4096 个字符。");
      if (!sourceRefs.length || !targetRefs.length || sourceRefs.length > 100 || targetRefs.length > 100
          || [...sourceRefs, ...targetRefs].some((ref) => ref.length > 4096)
          || new Set(sourceRefs).size !== sourceRefs.length || new Set(targetRefs).size !== targetRefs.length) {
        throw new Error("请填写不重复的来源与目标引用，每组 1 至 100 项，以逗号分隔。");
      }
      if (!epoch(values.access_epoch) || !epoch(values.deletion_epoch)) {
        throw new Error("访问与删除纪元必须是已核验的非负整数。");
      }
      const previewRef = text(values.impact_preview_ref);
      if (previewRef.length > 4096) throw new Error("影响预览引用过长。");
      return [ACTIONS.correctOrEdit, {
        schema: "d12.source_correction.v1", correction_kind: "source_claim", statement,
        source_refs: sourceRefs, target_refs: targetRefs,
        access_epoch: Number(values.access_epoch), deletion_epoch: Number(values.deletion_epoch),
        ...(previewRef ? { impact_preview_ref: previewRef } : {})
      }];
    }
    case "relations":
      // D12 currently admits only the source_claim correction contract. Keep
      // relations-page submissions on the same validated path as memory.
      return workflowForPage("memory", values);
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
