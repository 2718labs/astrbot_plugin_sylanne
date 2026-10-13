import {operationIdV1} from './browser-crypto.ts'
import { D12_SCHEMA, UUID4, hasFields, isInteger, isText, validateScope } from './contract.ts'

export interface ReplyNamespace { bot_id: string; persona_id: string }
export interface ReplyControlMetadata {
  schema: 'd12.owner-reply-control-metadata.v1' | 'd12.owner-reply-control-metadata.v2'; namespace: ReplyNamespace; installation_id: string
  cycle_job_ref: string; c02_operation_id: string; cancel_generation: number; job_phase: string
  original_ref: string | null; stop_state: string | null; natural_batch?: NaturalBatchMetadata | null
}
export interface NaturalFeeMetadata { settlement_ref: string; status: string; currency: string; actual: Record<string, number> | null; unconfirmed: Record<string, number> }
export interface NaturalBubbleMetadata {
  index: number; operation_id: string; effect_id: string; actual_intent_ref: string | null; admission_ref: string | null
  continuation_state: 'ready' | 'held' | 'cancelled' | 'superseded'; reason_code: string | null
  authority_state: 'absent' | 'unresolved' | 'observed' | 'unavailable'; observation_outcome: string | null; observation_ref: string | null
  read_state: 'unknown'; fees: NaturalFeeMetadata[]
}
export interface NaturalBatchMetadata {
  schema: 'd12.natural-batch-metadata.v1'; parent_original_id: string; roster_revision: number | null
  details_state: 'adopted' | 'manifest_not_adopted' | 'bubble_details_unavailable'; parent_fees: NaturalFeeMetadata[]; children: NaturalBubbleMetadata[]
}
export interface ReplyControlPage { items: ReplyControlMetadata[]; next_cursor: string | null }
export interface StopReplyRequest {
  schema: 'd12.owner-stop-reply-request.v1'; namespace: ReplyNamespace; installation_id: string
  operation_id: string; cycle_job_ref: string; c02_operation_id: string; expected_cancel_generation: number
}
export interface ReplyControlStatus {
  schema: 'd12.owner-stop-reply-status.v1'; namespace: ReplyNamespace; cycle_job_ref: string
  operation_id: string; original_ref: string; original_digest: string; state: string
  cancel_generation: number; cancellation_confirmed: boolean
}
export class ReplyControlContractError extends Error {}
const phases = new Set(['queued', 'running', 'waiting', 'deferred', 'draining', 'completed', 'failed', 'cancelled', 'pending_confirmation'])
const stopStates = new Set(['cancel_requested', 'pending_confirmation', 'cancelled'])
function invalid(): never { throw new ReplyControlContractError('回复控制返回的正式字段不兼容。') }
function namespace(value: unknown, scope: string): value is ReplyNamespace {
  return hasFields(value, ['bot_id', 'persona_id']) && isText(value.bot_id) && isText(value.persona_id)
    && `${value.bot_id}/${value.persona_id}` === validateScope(scope)
}
function amounts(value: unknown): value is Record<string, number> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && Object.keys(value).length <= 32
    && Object.entries(value).every(([key, amount]) => isText(key) && isInteger(amount))
}
function validateNaturalBatch(value: unknown, parent: string): NaturalBatchMetadata {
  if (!hasFields(value, ['schema', 'parent_original_id', 'roster_revision', 'details_state', 'parent_fees', 'children'])
    || value.schema !== 'd12.natural-batch-metadata.v1' || value.parent_original_id !== parent
    || !Array.isArray(value.children) || value.children.length > 4 || !Array.isArray(value.parent_fees) || value.parent_fees.length > 8
    || value.details_state === 'adopted' && (!value.children.length || !isInteger(value.roster_revision, 1))
    || ['manifest_not_adopted', 'bubble_details_unavailable'].includes(value.details_state as string) && (value.children.length !== 0 || value.roster_revision !== null)
    || !['adopted', 'manifest_not_adopted', 'bubble_details_unavailable'].includes(value.details_state as string)) invalid()
  const allFees: unknown[] = [...value.parent_fees]
  value.children.forEach((child, index) => {
    if (!hasFields(child, ['index', 'operation_id', 'effect_id', 'actual_intent_ref', 'admission_ref', 'continuation_state', 'reason_code', 'authority_state', 'observation_outcome', 'observation_ref', 'read_state', 'fees'])
      || child.index !== index || !isText(child.operation_id) || !isText(child.effect_id)
      || child.actual_intent_ref !== null && !isText(child.actual_intent_ref) || child.admission_ref !== null && !isText(child.admission_ref)
      || (child.actual_intent_ref === null) !== (child.admission_ref === null)
      || !['ready', 'held', 'cancelled', 'superseded'].includes(child.continuation_state as string)
      || child.reason_code !== null && !['owner_stop', 'scoped_source_changed', 'deadline_expired', 'predecessor_unknown', 'qualification_unavailable', 'relevant_new_turn'].includes(child.reason_code as string)
      || !['absent', 'unresolved', 'observed', 'unavailable'].includes(child.authority_state as string)
      || child.observation_outcome !== null && !['accepted', 'delivered', 'failed_before_acceptance', 'handed_off', 'read', 'unknown'].includes(child.observation_outcome as string)
      || child.observation_ref !== null && !isText(child.observation_ref) || child.read_state !== 'unknown'
      || child.authority_state !== 'observed' && (child.observation_outcome !== null || child.observation_ref !== null)
      || !Array.isArray(child.fees) || child.fees.length > 4) invalid()
    allFees.push(...child.fees)
  })
  const feeRefs = new Set<string>()
  allFees.forEach(fee => {
    if (!hasFields(fee, ['settlement_ref', 'status', 'currency', 'actual', 'unconfirmed']) || !isText(fee.settlement_ref)
      || feeRefs.has(fee.settlement_ref) || !['settled', 'overrun', 'pending_confirmation', 'pending_overrun'].includes(fee.status as string)
      || typeof fee.currency !== 'string' || !/^[A-Z]{3}$/.test(fee.currency) || fee.actual !== null && !amounts(fee.actual) || !amounts(fee.unconfirmed)) invalid()
    feeRefs.add(fee.settlement_ref)
  })
  return value as unknown as NaturalBatchMetadata
}
export function validateReplyControlMetadata(value: unknown, scope: string): ReplyControlMetadata {
  const v2 = typeof value === 'object' && value !== null && 'schema' in value && value.schema === 'd12.owner-reply-control-metadata.v2'
  if (!hasFields(value, ['schema', 'namespace', 'installation_id', 'cycle_job_ref', 'c02_operation_id', 'cancel_generation', 'job_phase', 'original_ref', 'stop_state', ...(v2 ? ['natural_batch'] : [])])
    || !['d12.owner-reply-control-metadata.v1', 'd12.owner-reply-control-metadata.v2'].includes(value.schema as string) || !namespace(value.namespace, scope)
    || !isText(value.installation_id) || !isText(value.cycle_job_ref) || !isText(value.c02_operation_id)
    || !isInteger(value.cancel_generation) || typeof value.job_phase !== 'string' || !phases.has(value.job_phase)
    || value.original_ref !== null && !isText(value.original_ref)
    || value.stop_state !== null && (typeof value.stop_state !== 'string' || !stopStates.has(value.stop_state))) invalid()
  if (v2 && value.natural_batch !== null) validateNaturalBatch(value.natural_batch, value.c02_operation_id as string)
  return value as unknown as ReplyControlMetadata
}
export function validateReplyControls(value: unknown, scope: string): ReplyControlPage {
  if (!hasFields(value, ['status', 'items', 'next_cursor']) || value.status !== 'ready' || !Array.isArray(value.items) || value.items.length > 32
    || value.next_cursor !== null && (typeof value.next_cursor !== 'string' || !value.next_cursor.length || value.next_cursor.length > 256 || value.items.length !== 32)) invalid()
  return { items: value.items.map(item => validateReplyControlMetadata(item, scope)), next_cursor: value.next_cursor as string | null }
}
export function validateReplyControlStatus(value: unknown, scope: string): ReplyControlStatus {
  if (!hasFields(value, ['status', 'control']) || value.status !== 'ready') invalid()
  const control = value.control
  if (!hasFields(control, ['schema', 'namespace', 'cycle_job_ref', 'operation_id', 'original_ref', 'original_digest', 'state', 'cancel_generation', 'cancellation_confirmed'])
    || control.schema !== 'd12.owner-stop-reply-status.v1' || !namespace(control.namespace, scope)
    || !isText(control.cycle_job_ref) || typeof control.operation_id !== 'string' || !UUID4.test(control.operation_id)
    || !isText(control.original_ref) || typeof control.original_digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(control.original_digest)
    || typeof control.state !== 'string' || !stopStates.has(control.state) || !isInteger(control.cancel_generation)
    || typeof control.cancellation_confirmed !== 'boolean' || control.cancellation_confirmed && control.state !== 'cancelled') invalid()
  return control as unknown as ReplyControlStatus
}
export function makeStopReplyRequest(target: ReplyControlMetadata, operationId: string = operationIdV1()): StopReplyRequest {
  const scope = validateScope(`${target.namespace.bot_id}/${target.namespace.persona_id}`)
  validateReplyControlMetadata(target, scope)
  if (!UUID4.test(operationId)) invalid()
  return { schema: 'd12.owner-stop-reply-request.v1', namespace: { ...target.namespace }, installation_id: target.installation_id,
    operation_id: operationId, cycle_job_ref: target.cycle_job_ref, c02_operation_id: target.c02_operation_id,
    expected_cancel_generation: target.cancel_generation }
}
export function makeReplyControlCommand(action: 'read_reply_controls' | 'stop_reply' | 'read_reply_control_status', scope: string,
  input: StopReplyRequest | { original_ref: string } | { cursor: string } | Record<string, never>, operationId: string = operationIdV1()) {
  validateScope(scope)
  if (!UUID4.test(operationId)) invalid()
  return { schema_version: D12_SCHEMA, action, scope, purpose: 'workbench_user_action', audience: 'owner', operation_id: operationId, input }
}
