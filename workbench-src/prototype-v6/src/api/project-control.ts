import {sha256HexV1} from './browser-crypto.ts'
import { canonicalJson, hasFields, isInteger, isRecord, isText, UUID4, validateScope } from './contract.ts'

export type ProjectControlAction = 'pause_project_v1' | 'resume_project_v1'
export type ProjectPlanState = 'active' | 'waiting' | 'paused' | 'satisfied' | 'abandoned' | 'superseded'
export interface ProjectExecutionSummary { inflight: number; unknown: number; settlement_pending: number }
export interface ProjectControlContext {
  schema: 'd12.project-control-context.v1'; namespace: { bot_id: string; persona_id: string }
  project_ref: string; plan_ref: string; plan_revision: number; goal_ref: string; goal_state: string; plan_state: ProjectPlanState
  pause_original_ref: string | null; permitted_controls: ProjectControlAction[]; execution_summary: ProjectExecutionSummary
  resume_preview: { state: 'active' | 'waiting' | null; reasons: string[] }; context_digest: string; graph_revision: number
}
export interface ProjectControlInput { project_ref: string; plan_ref: string; expected_plan_revision: number; pause_original_ref?: string }
export interface PendingProjectControl { scope: string; action: ProjectControlAction; operationId: string; input: ProjectControlInput }
export class ProjectControlContractError extends Error { constructor() { super('项目控制的正式原件不兼容。') } }
function invalid(): never { throw new ProjectControlContractError() }
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
const planState = (value: unknown): value is ProjectPlanState => typeof value === 'string' && ['active', 'waiting', 'paused', 'satisfied', 'abandoned', 'superseded'].includes(value)
function summary(value: unknown): value is ProjectExecutionSummary { return hasFields(value, ['inflight', 'unknown', 'settlement_pending']) && isInteger(value.inflight) && isInteger(value.unknown) && isInteger(value.settlement_pending) }
export async function projectControlDigest(value: unknown): Promise<string> {
  const bytes = canonicalJson(value).replace(/[\u007f-\uffff]/g, character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'))
  return sha256HexV1(new TextEncoder().encode(bytes))
}
const contextFields = ['schema', 'namespace', 'project_ref', 'plan_ref', 'plan_revision', 'goal_ref', 'goal_state', 'plan_state', 'pause_original_ref', 'permitted_controls', 'execution_summary', 'resume_preview', 'context_digest', 'graph_revision']
async function validateContextBase(value: unknown, scope: string, projectRef: string, version: 1 | 2): Promise<Record<string, any>> {
  validateScope(scope)
  if (!hasFields(value, version === 1 ? contextFields : [...contextFields, 'checkpoint', 'next_step', 'pending_effects', 'budget', 'missing'])
    || value.schema !== 'd12.project-control-context.v' + version || !hasFields(value.namespace, ['bot_id', 'persona_id'])
    || `${value.namespace.bot_id}/${value.namespace.persona_id}` !== scope || value.project_ref !== projectRef || !isText(value.project_ref)
    || !isText(value.plan_ref) || !isInteger(value.plan_revision, 1) || !isText(value.goal_ref) || !isText(value.goal_state) || !planState(value.plan_state)
    || value.pause_original_ref !== null && !isText(value.pause_original_ref) || !Array.isArray(value.permitted_controls)
    || value.permitted_controls.length > 2 || new Set(value.permitted_controls).size !== value.permitted_controls.length
    || value.permitted_controls.some(action => action !== 'pause_project_v1' && action !== 'resume_project_v1') || !summary(value.execution_summary)
    || !hasFields(value.resume_preview, ['state', 'reasons']) || value.resume_preview.state !== null && value.resume_preview.state !== 'active' && value.resume_preview.state !== 'waiting'
    || !Array.isArray(value.resume_preview.reasons) || value.resume_preview.reasons.length > 100 || !value.resume_preview.reasons.every(isText)
    || !digest(value.context_digest) || !isInteger(value.graph_revision)) invalid()
  const { context_digest: commitment, ...observed } = value
  if (await projectControlDigest(observed) !== commitment) invalid()
  return value
}
export async function validateProjectControlContext(value: unknown, scope: string, projectRef: string): Promise<ProjectControlContext> {
  return await validateContextBase(value, scope, projectRef, 1) as unknown as ProjectControlContext
}

export interface ProjectBudgetDimension {
  dimension: string; unit: string | null; limit: number; grant_ceiling: number | null; spent: number; reserved: number
  unconfirmed: number; allocated: number | null; remaining: number
}
export interface ProjectControlContextV2 extends Omit<ProjectControlContext, 'schema'> {
  schema: 'd12.project-control-context.v2'
  checkpoint: { checkpoint_ref: string; revision: number; plan_revision: number; state: 'active' | 'waiting' | 'paused' | 'completed' | 'cancelled'; basis_status: 'current' | 'stale'; wait_reason: string | null } | null
  next_step: { node_ref: string; action_kind: string; depends_on: string[]; wait_condition: string | null } | null
  pending_effects: { refs: string[]; total_count: number; truncated: boolean }
  budget: { scope: 'shared_parent_pool'; lease_ref: string; lease_version: number; state: 'active' | 'closed' | 'blocked'; currency: string
    grant_ref: string; grant_version: number; grant_expires_utc: string; qualification_state: 'not_evaluated' | 'hold' | 'unknown'
    allocation_coverage: 'complete' | 'partial'; dimensions: ProjectBudgetDimension[] } | null
  missing: string[]
}
const texts = (value: unknown, limit: number): value is string[] => Array.isArray(value) && value.length <= limit && value.every(isText) && new Set(value).size === value.length
const nullableText = (value: unknown) => value === null || isText(value)
const nullableAmount = (value: unknown) => value === null || isInteger(value)
const units = ['cpu_ms', 'thread_cpu_ms', 'input_tokens', 'output_tokens', 'model_tokens', 'model_microusd']
export async function validateProjectControlContextV2(value: unknown, scope: string, projectRef: string): Promise<ProjectControlContextV2> {
  const v = await validateContextBase(value, scope, projectRef, 2)
  if (!texts(v.missing, 100) || !hasFields(v.pending_effects, ['refs', 'total_count', 'truncated'])
    || !texts(v.pending_effects.refs, 32) || !isInteger(v.pending_effects.total_count) || v.pending_effects.total_count > 256
    || v.pending_effects.refs.length !== Math.min(v.pending_effects.total_count, 32)
    || v.pending_effects.truncated !== (v.pending_effects.total_count > 32)) invalid()
  const cp = v.checkpoint, next = v.next_step, budget = v.budget
  if (cp !== null && (!hasFields(cp, ['checkpoint_ref', 'revision', 'plan_revision', 'state', 'basis_status', 'wait_reason'])
    || !isText(cp.checkpoint_ref) || !isInteger(cp.revision, 1) || !isInteger(cp.plan_revision, 1)
    || !['active', 'waiting', 'paused', 'completed', 'cancelled'].includes(String(cp.state))
    || !['current', 'stale'].includes(String(cp.basis_status)) || !nullableText(cp.wait_reason)
    || cp.basis_status === 'current' && cp.plan_revision !== v.plan_revision)) invalid()
  if (next !== null && (!hasFields(next, ['node_ref', 'action_kind', 'depends_on', 'wait_condition']) || !cp || cp.basis_status !== 'current'
    || !isText(next.node_ref) || !next.node_ref.startsWith('task:') || !isText(next.action_kind)
    || !texts(next.depends_on, 8) || !nullableText(next.wait_condition))) invalid()
  if (budget !== null) {
    if (!hasFields(budget, ['scope', 'lease_ref', 'lease_version', 'state', 'currency', 'grant_ref', 'grant_version', 'grant_expires_utc', 'qualification_state', 'allocation_coverage', 'dimensions'])
      || budget.scope !== 'shared_parent_pool' || !isText(budget.lease_ref) || !isInteger(budget.lease_version, 1)
      || !['active', 'closed', 'blocked'].includes(String(budget.state)) || typeof budget.currency !== 'string' || !/^[A-Z]{3}$/.test(budget.currency)
      || !isText(budget.grant_ref) || !isInteger(budget.grant_version, 1) || typeof budget.grant_expires_utc !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T.*Z$/.test(budget.grant_expires_utc) || !Number.isFinite(Date.parse(budget.grant_expires_utc))
      || !['not_evaluated', 'hold', 'unknown'].includes(String(budget.qualification_state))
      || !['complete', 'partial'].includes(String(budget.allocation_coverage)) || !Array.isArray(budget.dimensions)
      || !budget.dimensions.length || budget.dimensions.length > 32) invalid()
    const seen = new Set<string>()
    for (const row of budget.dimensions) {
      if (!hasFields(row, ['dimension', 'unit', 'limit', 'grant_ceiling', 'spent', 'reserved', 'unconfirmed', 'allocated', 'remaining'])
        || !isText(row.dimension) || seen.has(row.dimension) || row.unit !== null && (!units.includes(String(row.unit)) || row.unit !== row.dimension)
        || row.unit === 'model_microusd' && budget.currency !== 'USD'
        || !['limit', 'spent', 'reserved', 'unconfirmed', 'remaining'].every(key => isInteger(row[key]))
        || !nullableAmount(row.grant_ceiling) || !nullableAmount(row.allocated)
        || (budget.allocation_coverage === 'partial' ? row.allocated !== null : row.allocated === null)
        || row.remaining !== Math.max(0, (row.limit as number) - (row.spent as number) - (row.reserved as number) - (row.unconfirmed as number))) invalid()
      seen.add(row.dimension)
    }
  }
  return v as unknown as ProjectControlContextV2
}

export function projectControlInput(context: ProjectControlContext | ProjectControlContextV2, action: ProjectControlAction): ProjectControlInput {
  if (!context.permitted_controls.includes(action) || action === 'resume_project_v1' && !context.pause_original_ref) invalid()
  return { project_ref: context.project_ref, plan_ref: context.plan_ref, expected_plan_revision: context.plan_revision,
    ...(action === 'resume_project_v1' ? { pause_original_ref: context.pause_original_ref! } : {}) }
}


export interface ProjectControlProvenance {
  schema: 'd08.project-control-original.v1'; project_ref: string; plan_ref: string; control: 'pause' | 'resume'
  before_plan_revision: number; after_plan_revision: number; before_plan_state: ProjectPlanState; after_plan_state: ProjectPlanState
  before_plan: Record<string, unknown>; after_plan: Record<string, unknown>; pause_origin: string | null; noop: boolean
  execution_summary: ProjectExecutionSummary; control_original_ref: string
}
export interface ProjectControlReceipt {
  schema: 'd12.project-control-receipt.v1'; operation_id: string; action: ProjectControlAction; input_digest: string; original_digest: string
  original: Record<string, unknown>; control: ProjectControlProvenance
}
const summaryFields = ['schema', 'domain', 'operation_kind', 'operation_id', 'activity_id', 'original_ref', 'original_digest', 'receipt',
  'receipt_digest', 'job_states', 'coverage', 'missing_inputs', 'continuation_ref', 'outbox', 'produced_originals', 'actual_original']
const payloadFields = ['schema', 'request', 'namespace', 'identity', 'authority', 'parent_budget', 'now_utc', 'owner_guard', 'policy_refs',
  'read_versions', 'query_coverage', 'observed_originals', 'provenance', 'writes', 'coverage', 'missing_inputs', 'continuation_ref']
export async function validateProjectControlReceipt(value: unknown, scope: string, action: ProjectControlAction,
  input: ProjectControlInput, operationId: string): Promise<ProjectControlReceipt> {
  validateScope(scope)
  if (!UUID4.test(operationId) || !hasFields(value, ['schema', 'operation_id', 'action', 'input_digest', 'original_digest', 'original'])
    || value.schema !== 'd12.project-control-receipt.v1' || value.operation_id !== operationId || value.action !== action
    || !digest(value.input_digest) || !digest(value.original_digest) || value.input_digest !== await projectControlDigest(input)) invalid()
  const original = value.original
  if (!hasFields(original, summaryFields) || original.schema !== 'sylanne.domain-production-receipt.v1' || original.domain !== 'd08'
    || original.operation_kind !== action || original.operation_id !== operationId || !digest(original.original_digest) || !digest(original.receipt_digest)
    || !isText(original.original_ref) || !isText(original.activity_id) || !isRecord(original.receipt) || original.receipt.operation_id !== operationId) invalid()
  const adopted = original.actual_original
  if (!hasFields(adopted, ['domain', 'operation_kind', 'request_digest', 'original_digest', 'payload', 'read_versions', 'receipt'])
    || adopted.domain !== 'd08' || adopted.operation_kind !== action || !digest(adopted.request_digest) || !digest(adopted.original_digest)
    || adopted.original_digest !== original.original_digest || !isRecord(adopted.receipt) || adopted.receipt.operation_id !== operationId
    || !hasFields(adopted.payload, payloadFields)) invalid()
  const payload = adopted.payload
  if (payload.schema !== 'd08.current-' + action + '.v1' || !hasFields(payload.namespace, ['bot_id', 'persona_id'])
    || `${payload.namespace.bot_id}/${payload.namespace.persona_id}` !== scope || !isRecord(payload.identity) || payload.identity.operation_id !== operationId
    || canonicalJson(payload.request) !== canonicalJson(input) || !isRecord(payload.provenance)) invalid()
  const control = payload.provenance.project_control
  if (!hasFields(control, ['schema', 'project_ref', 'plan_ref', 'control', 'before_plan_revision', 'after_plan_revision', 'before_plan_state',
      'after_plan_state', 'before_plan', 'after_plan', 'pause_origin', 'noop', 'execution_summary', 'control_original_ref'])
    || control.schema !== 'd08.project-control-original.v1' || control.project_ref !== input.project_ref || control.plan_ref !== input.plan_ref
    || control.control !== (action === 'pause_project_v1' ? 'pause' : 'resume') || control.control_original_ref !== operationId
    || control.before_plan_revision !== input.expected_plan_revision || !isInteger(control.before_plan_revision, 1) || !isInteger(control.after_plan_revision, 1) || !planState(control.before_plan_state)
    || !planState(control.after_plan_state) || typeof control.noop !== 'boolean' || control.pause_origin !== null && !isText(control.pause_origin)
    || !summary(control.execution_summary) || !isRecord(control.before_plan) || !isRecord(control.after_plan)
    || control.before_plan.schema !== 'd08.personal_plan.v1' || control.after_plan.schema !== 'd08.personal_plan.v1'
    || control.before_plan.state !== control.before_plan_state || control.after_plan.state !== control.after_plan_state
    || control.after_plan_revision !== control.before_plan_revision + (control.noop ? 0 : 1)
    || control.noop && control.before_plan_state !== control.after_plan_state
    || !control.noop && action === 'pause_project_v1' && control.after_plan_state !== 'paused'
    || !control.noop && action === 'resume_project_v1' && !['active', 'waiting'].includes(control.after_plan_state)
    || action === 'resume_project_v1' && control.pause_origin !== input.pause_original_ref) invalid()
  // Authority signatures and the original's floating-point canonical bytes are verified by the actual backend, not reconstructed in JavaScript.
  return { ...(value as unknown as Omit<ProjectControlReceipt, 'control'>), control: control as unknown as ProjectControlProvenance }
}
