import { canonicalJson, hasFields, isInteger, isRecord, isText, UUID4, validateScope } from './contract.ts'
import { projectControlDigest } from './project-control.ts'

export const OWNER_TASK_ACTION = 'domain_submit_owner_source_note_task_v1' as const
export interface OwnerTaskOption {
  body_source_ref: string; recipe_ref: string; target_entity_ref: string; role_binding_ref: string
  body_policy_id: string; body_policy_version: number; effect_policy_ref: string
}
export interface OwnerTaskOptions {
  schema: 'd12.owner-source-note-task-options.v1'; namespace: { bot_id: string; persona_id: string }
  project_ref: string; observed_utc: number; deadline_upper_bound_utc: number | null; items: OwnerTaskOption[]
}
export interface OwnerTaskRequest extends OwnerTaskOption { project_ref: string; requested_deadline_utc: number }
export interface PendingOwnerTask { scope: string; operationId: string; inputDigest: string }
export const OWNER_TASK_STEPS = ['qualify','values','select','prepare_action','prepare_body','register_life_plan','prepare_life','execute_life','observe_life','adopt_outcome','completed'] as const
export interface OwnerTaskStatus {
  schema: 'd12.owner-source-note-task-status.v1'; namespace: { bot_id: string; persona_id: string }
  owner_operation_id: string; input_digest: string
  state: 'not_found' | 'focus_saved_task_not_saved' | 'accepted' | 'pending_start' | 'active' | 'waiting' | 'draining' | 'completed' | 'failed' | 'cancelled' | 'conflict' | 'unknown'
  job_id: string | null; job_phase: 'queued' | 'running' | 'waiting' | 'draining' | 'completed' | 'failed' | 'cancelled' | null
  step: typeof OWNER_TASK_STEPS[number] | null; wait_reason: string | null; pending_effect_refs: string[]
  original_deadline_utc: number | null; observed_utc: number
}
export interface OwnerTaskReceipt {
  schema: 'd12.domain-operation-receipt.v1'; operation_id: string; action: typeof OWNER_TASK_ACTION | typeof OWNER_MATERIAL_ACTION
  input_digest: string; original_digest: string; original: Record<string, unknown>
}
export class OwnerTaskContractError extends Error { constructor() { super('所有者来源便笺任务的正式 metadata 或原件不兼容。') } }
function invalid(): never { throw new OwnerTaskContractError() }
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
const text = (value: unknown): value is string => isText(value) && value.length <= 4096
const utc = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0
const optionFields = ['body_source_ref','recipe_ref','target_entity_ref','role_binding_ref','body_policy_id','body_policy_version','effect_policy_ref']
function reference(value: unknown, kind: string, scope: string): boolean {
  if (!text(value)) return false
  try { const key = JSON.parse(value); return Array.isArray(key) && key.length === 6 && key.every(item => typeof item === 'string')
    && key[1] + '/' + key[2] === scope && key[4] === kind } catch { return false }
}
function option(value: unknown, scope: string): value is OwnerTaskOption {
  return hasFields(value, optionFields) && reference(value.body_source_ref, 'memory.source', scope)
    && reference(value.recipe_ref, 'd10.activity_recipe.v1', scope) && reference(value.target_entity_ref, 'd03.entity_anchor', scope)
    && reference(value.role_binding_ref, 'd03.role_binding', scope) && text(value.body_policy_id)
    && isInteger(value.body_policy_version, 1) && text(value.effect_policy_ref)
}
export function validateOwnerTaskOptions(value: unknown, scope: string, projectRef: string): OwnerTaskOptions {
  validateScope(scope)
  if (!hasFields(value, ['schema','namespace','project_ref','observed_utc','deadline_upper_bound_utc','items'])
    || value.schema !== 'd12.owner-source-note-task-options.v1' || !hasFields(value.namespace, ['bot_id','persona_id'])
    || value.namespace.bot_id + '/' + value.namespace.persona_id !== scope || value.project_ref !== projectRef
    || !reference(value.project_ref, 'd10.life_project.v1', scope) || !utc(value.observed_utc)
    || value.deadline_upper_bound_utc !== null && (!utc(value.deadline_upper_bound_utc) || value.deadline_upper_bound_utc <= value.observed_utc)
    || !Array.isArray(value.items) || value.items.length > 32 || !value.items.every(item => option(item, scope))
    || new Set(value.items.map(item => canonicalJson(item))).size !== value.items.length) invalid()
  return value as unknown as OwnerTaskOptions
}
export function ownerTaskRequest(options: OwnerTaskOptions, item: OwnerTaskOption, deadline: number): OwnerTaskRequest {
  if (!options.items.includes(item) || options.deadline_upper_bound_utc === null || !utc(deadline)
    || deadline <= options.observed_utc || deadline > options.deadline_upper_bound_utc) invalid()
  return { ...item, project_ref: options.project_ref, requested_deadline_utc: deadline }
}
export function validateOwnerTaskRequest(value: unknown, scope: string): asserts value is OwnerTaskRequest {
  validateScope(scope)
  if (!hasFields(value, [...optionFields, 'project_ref','requested_deadline_utc'])
    || !reference(value.project_ref, 'd10.life_project.v1', scope) || !utc(value.requested_deadline_utc)) invalid()
  const { project_ref: _project, requested_deadline_utc: _deadline, ...selectors } = value
  if (!option(selectors, scope)) invalid()
}
export const ownerTaskInputDigest = (request: OwnerTaskRequest) => projectControlDigest({ request })
export function validateOwnerTaskStatus(value: unknown, scope: string, operationId: string, inputDigest: string): OwnerTaskStatus {
  validateScope(scope)
  if (!UUID4.test(operationId) || !digest(inputDigest)
    || !hasFields(value, ['schema','namespace','owner_operation_id','input_digest','state','job_id','job_phase','step','wait_reason','pending_effect_refs','original_deadline_utc','observed_utc'])
    || value.schema !== 'd12.owner-source-note-task-status.v1' || !hasFields(value.namespace, ['bot_id','persona_id'])
    || value.namespace.bot_id + '/' + value.namespace.persona_id !== scope || value.owner_operation_id !== operationId || value.input_digest !== inputDigest
    || typeof value.state !== 'string' || !['not_found','focus_saved_task_not_saved','accepted','pending_start','active','waiting','draining','completed','failed','cancelled','conflict','unknown'].includes(value.state)
    || value.job_id !== null && !text(value.job_id) || value.job_phase !== null && (typeof value.job_phase !== 'string' || !['queued','running','waiting','draining','completed','failed','cancelled'].includes(value.job_phase))
    || value.step !== null && (typeof value.step !== 'string' || !(OWNER_TASK_STEPS as readonly string[]).includes(value.step)) || value.wait_reason !== null && !text(value.wait_reason)
    || !Array.isArray(value.pending_effect_refs) || value.pending_effect_refs.length > 32 || !value.pending_effect_refs.every(text)
    || new Set(value.pending_effect_refs).size !== value.pending_effect_refs.length || !utc(value.observed_utc)
    || value.original_deadline_utc !== null && !utc(value.original_deadline_utc)) invalid()
  if (['not_found','conflict'].includes(value.state) && (value.job_id !== null || value.job_phase !== null || value.step !== null
    || value.pending_effect_refs.length || value.original_deadline_utc !== null)) invalid()
  if (value.state === 'focus_saved_task_not_saved' && (value.job_id !== null || value.job_phase !== null
    || value.step !== null || value.original_deadline_utc !== null || value.pending_effect_refs.length !== 0
    || typeof value.wait_reason !== 'string'
    || !/^owner_focus_saved_task_not_saved:owner-note-focus:[0-9a-f]{40}$/.test(value.wait_reason))) invalid()
  return value as unknown as OwnerTaskStatus
}
export async function validateOwnerTaskReceipt(value: unknown, operationId: string, request: OwnerTaskRequest): Promise<OwnerTaskReceipt> {
  if (!hasFields(value, ['schema','operation_id','action','input_digest','original_digest','original'])
    || value.schema !== 'd12.domain-operation-receipt.v1' || value.operation_id !== operationId || value.action !== OWNER_TASK_ACTION
    || value.input_digest !== await ownerTaskInputDigest(request) || !digest(value.original_digest)
    || !hasFields(value.original, ['schema','domain','operation_kind','operation_id','activity_id','original_ref','original_digest','receipt','receipt_digest','job_states','coverage','missing_inputs','continuation_ref','outbox','produced_originals'])
    || value.original.schema !== 'sylanne.domain-production-receipt.v1' || value.original.domain !== 'd08'
    || value.original.operation_kind !== 'submit_owner_source_note_task_v1' || value.original.operation_id !== operationId
    || !text(value.original.original_ref) || !digest(value.original.original_digest) || !digest(value.original.receipt_digest)
    || !isRecord(value.original.receipt) || value.original.receipt.status !== 'committed'
    || !isInteger(value.original.receipt.commit_seq, 1) || !Array.isArray(value.original.job_states)
    || !Array.isArray(value.original.missing_inputs) || !Array.isArray(value.original.outbox) || !Array.isArray(value.original.produced_originals)) invalid()
  return value as unknown as OwnerTaskReceipt
}

export const OWNER_MATERIAL_ACTION = 'domain_admit_owner_material_source_v1' as const
export interface OwnerMaterialStatus {
  schema: 'd12.owner-material-source-status.v1'; namespace: { bot_id: string; persona_id: string }
  owner_operation_id: string; input_digest: string; state: 'not_found' | 'accepted' | 'conflict' | 'unknown'
  source_ref: string | null; source_id: string | null; source_revision: number | null; observed_utc: number
}
export const ownerMaterialInputDigest = (value: string) => projectControlDigest({ request: { text: value } })
export function validateOwnerMaterialStatus(value: unknown, scope: string, operationId: string, inputDigest: string): OwnerMaterialStatus {
  validateScope(scope)
  if (!hasFields(value, ['schema','namespace','owner_operation_id','input_digest','state','source_ref','source_id','source_revision','observed_utc'])
    || value.schema !== 'd12.owner-material-source-status.v1' || !hasFields(value.namespace, ['bot_id','persona_id'])
    || value.namespace.bot_id + '/' + value.namespace.persona_id !== scope || value.owner_operation_id !== operationId || value.input_digest !== inputDigest
    || !UUID4.test(operationId) || !digest(inputDigest) || typeof value.state !== 'string' || !['not_found','accepted','conflict','unknown'].includes(value.state)
    || !utc(value.observed_utc)) invalid()
  if (value.state === 'accepted') {
    if (!reference(value.source_ref, 'memory.source', scope) || !text(value.source_id) || !isInteger(value.source_revision, 1)
      || JSON.parse(value.source_ref as string)[3] !== value.source_id) invalid()
  } else if (value.source_ref !== null || value.source_id !== null || value.source_revision !== null) invalid()
  return value as unknown as OwnerMaterialStatus
}
export async function validateOwnerMaterialReceipt(value: unknown, operationId: string, content: string): Promise<OwnerTaskReceipt> {
  if (!hasFields(value, ['schema','operation_id','action','input_digest','original_digest','original'])
    || value.schema !== 'd12.domain-operation-receipt.v1' || value.operation_id !== operationId || value.action !== OWNER_MATERIAL_ACTION
    || value.input_digest !== await ownerMaterialInputDigest(content) || !digest(value.original_digest)
    || !hasFields(value.original, ['schema','domain','operation_kind','operation_id','activity_id','original_ref','original_digest','receipt','receipt_digest','job_states','coverage','missing_inputs','continuation_ref','outbox','produced_originals'])
    || value.original.schema !== 'sylanne.domain-production-receipt.v1' || value.original.domain !== 'd06'
    || value.original.operation_kind !== 'admit_owner_material_source_v1' || value.original.operation_id !== operationId
    || !text(value.original.original_ref) || !digest(value.original.original_digest) || !digest(value.original.receipt_digest)
    || !isRecord(value.original.receipt) || value.original.receipt.status !== 'committed' || !isInteger(value.original.receipt.commit_seq, 1)) invalid()
  return value as unknown as OwnerTaskReceipt
}

export const OWNER_MATERIAL_MAX_CHARACTERS = 65536
export function validateOwnerMaterialText(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !value.trim() || Array.from(value).length > OWNER_MATERIAL_MAX_CHARACTERS) invalid()
}
