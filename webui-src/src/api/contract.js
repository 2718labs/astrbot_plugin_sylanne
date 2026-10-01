export const D12_SCHEMA_VERSION = "d12.contract.v1";

export const ACTIONS = Object.freeze({
  readD04InitializationProfile: "read_d04_initialization_profile",
  d04RootDraft: "d04_root_draft",
  d04RootBudget: "d04_root_budget",
  d04RootCoupling: "d04_root_coupling",
  d04SemanticMapping: "d04_semantic_mapping",
  d11RoleClock: "d11_role_clock",
  openWorkspace: "open_workspace",
  createCharacter: "create_character",
  bindScene: "bind_scene",
  compileScheme: "compile_scheme",
  activateScheme: "activate_scheme",
  readCharacterView: "read_character_view",
  correctOrEdit: "correct_or_edit",
  runExperiment: "run_experiment",
  prepareTransfer: "prepare_transfer",
  executeTransfer: "execute_transfer",
  eraseOrRetire: "erase_or_retire",
  diagnoseAndExportSupport: "diagnose_and_export_support",
  installOrUpgrade: "install_or_upgrade",
  configureOrControl: "configure_or_control"
});

export const VIEW_TYPES = Object.freeze({
  overview: "overview",
  creation: "creation",
  relations: "relations",
  memory: "d06.memory_sources.v1",
  cognition: "cognition",
  action: "action",
  expression: "expression",
  diagnostics: "diagnostics",
  lifecycle: "lifecycle"
});

export function makeRequest(action, { scope, purpose, audience = "owner", input = {}, operationId } = {}) {
  if (!Object.values(ACTIONS).includes(action)) throw new Error(`Unknown D12 action: ${action}`);
  if (!scope) throw new Error("A role scope is required before sending a D12 command.");
  return {
    schema_version: D12_SCHEMA_VERSION,
    action,
    scope,
    purpose,
    audience,
    operation_id: operationId ?? crypto.randomUUID(),
    input
  };
}

export function isSafeAction(action) {
  return Object.values(ACTIONS).includes(action);
}

const OWNER_SESSION_SCHEMA = "sylanne3.authority.owner-session.v1";

export function makeOwnerLoginRequest(values, dashboardOrigin) {
  const fields = [
    "authority_id", "authority_namespace", "installation_id",
    "identity_provider", "account_ref", "account_incarnation", "credential_id"
  ];
  const request = {};
  for (const field of fields) {
    const value = values[field];
    if (typeof value !== "string" || !value.trim()) {
      throw new Error(`请从已配对的本机安装记录填写 ${field}。`);
    }
    request[field] = value.trim();
  }
  const epoch = Number(values.credential_epoch);
  if (!Number.isSafeInteger(epoch) || epoch < 1 || String(epoch) !== String(values.credential_epoch).trim()) {
    throw new Error("请填写已登记的正整数 credential_epoch。");
  }
  if (typeof dashboardOrigin !== "string" || !/^https:\/\/[^/]+$/.test(dashboardOrigin)) {
    throw new Error("Owner 登录需要受信 HTTPS 工作台地址。");
  }
  return {
    kind: "owner_session_login_request_v1",
    schema: OWNER_SESSION_SCHEMA,
    authority_id: request.authority_id,
    authority_namespace: request.authority_namespace,
    installation_id: request.installation_id,
    principal: {
      identity_provider: request.identity_provider,
      account_ref: request.account_ref,
      account_incarnation: request.account_incarnation
    },
    credential_id: request.credential_id,
    credential_epoch: epoch,
    audience: "owner",
    dashboard_origin: dashboardOrigin
  };
}
