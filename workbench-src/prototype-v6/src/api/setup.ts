import { hasFields } from './contract.ts'

export const SETUP_PREFIX = '/setup/v1/status'
export const SETUP_RESPONSE_MAX_BYTES = 16 * 1024
export type ModelSelectionState = 'unselected' | 'unavailable' | 'unsupported' | 'changed' | 'awaiting_installation' | 'authorized'
export interface HostModelPlan {
  schema: 'sylanne.host-model-selection.v1'
  authority_profile: string
  provider_id: string
  model_id: string
  provider_config_digest: string
}
export interface SetupStatus {
  schema_version: 'sylanne.workbench-setup-status.v1'
  profile_id: string
  host_enabled: boolean
  authority_enabled: boolean | null
  effective_enabled: boolean
  model_selection: { provider_id: string | null; model_id: string | null; state: ModelSelectionState }
  runtime: { stage: 'limited' | 'blocked' | 'enrollment_required' | 'ready' | 'stopped'; reason_codes: string[] }
  installer: { supported: boolean; mode: 'fresh_install_only'; requires_administrator: true }
  model_plan: HostModelPlan | null
}
function invalid(): never { throw new Error('Invalid setup status contract') }
const text = (value: unknown, max: number): value is string => typeof value === 'string' && value.length >= 1 && value.length <= max
const optionalId = (value: unknown) => value === null || text(value, 256)
export function validateSetupStatus(body: unknown): SetupStatus {
  if (!hasFields(body, ['schema_version', 'profile_id', 'host_enabled', 'authority_enabled', 'effective_enabled', 'model_selection', 'runtime', 'installer', 'model_plan']) ||
      body.schema_version !== 'sylanne.workbench-setup-status.v1' || !text(body.profile_id,64) || typeof body.host_enabled !== 'boolean' ||
      body.authority_enabled !== null && typeof body.authority_enabled !== 'boolean' || typeof body.effective_enabled !== 'boolean' ||
      body.effective_enabled !== (body.host_enabled && body.authority_enabled === true)) invalid()
  const selection = body.model_selection, runtime = body.runtime, installer = body.installer, plan = body.model_plan
  if (!hasFields(selection, ['provider_id','model_id','state']) || !optionalId(selection.provider_id) || !optionalId(selection.model_id) ||
      typeof selection.state !== 'string' || !['unselected','unavailable','unsupported','changed','awaiting_installation','authorized'].includes(selection.state)) invalid()
  if (!hasFields(runtime, ['stage','reason_codes']) || typeof runtime.stage !== 'string' || !['limited','blocked','enrollment_required','ready','stopped'].includes(runtime.stage) ||
      !Array.isArray(runtime.reason_codes) || runtime.reason_codes.length > 16 || runtime.reason_codes.some(value => typeof value !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(value))) invalid()
  if (!hasFields(installer, ['supported','mode','requires_administrator']) || typeof installer.supported !== 'boolean' || installer.mode !== 'fresh_install_only' || installer.requires_administrator !== true) invalid()
  const observed = ['changed','awaiting_installation','authorized'].includes(selection.state)
  if (plan === null) {
    if (observed && selection.state !== 'changed' || selection.state === 'unselected' && (selection.provider_id !== null || selection.model_id !== null) || selection.state === 'unavailable' && selection.model_id !== null) invalid()
  } else {
    if (!observed || !hasFields(plan, ['schema','authority_profile','provider_id','model_id','provider_config_digest']) || plan.schema !== 'sylanne.host-model-selection.v1' ||
        !text(plan.authority_profile,64) || !text(plan.provider_id,256) || !text(plan.model_id,256) || typeof plan.provider_config_digest !== 'string' || !/^[0-9a-f]{64}$/.test(plan.provider_config_digest) ||
        plan.authority_profile !== body.profile_id || plan.provider_id !== selection.provider_id || plan.model_id !== selection.model_id) invalid()
  }
  return body as unknown as SetupStatus
}
