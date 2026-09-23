export const D12_SCHEMA_VERSION = "d12.contract.v1";

export const ACTIONS = Object.freeze({
  openWorkspace: "open_workspace",
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
  memory: "memory",
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
