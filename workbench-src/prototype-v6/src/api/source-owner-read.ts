import { hasFields, isInteger, isRecord, isText, UUID4, validateScope } from './contract.ts'
export interface OwnerSourceMetadata { source_id: string; source_kind: string; assertion_status: string; recorded_at: number; qualification: 'not_recorded'; revision: number }
export interface OwnerSourcePage { schema: 'd12.source-page.v1'; scope: string; operation_id: string; sources: OwnerSourceMetadata[]; next_cursor: string | null; has_more: boolean }
export interface OwnerSourceDetail { schema: 'd12.source-detail.v1'; scope: string; operation_id: string; source: OwnerSourceMetadata & { text: string } }
const fields = ['source_id', 'source_kind', 'assertion_status', 'recorded_at', 'qualification', 'revision']
function metadata(value: unknown, detail = false): value is OwnerSourceMetadata {
  return hasFields(value, detail ? [...fields, 'text'] : fields) && isText(value.source_id) && value.source_id.length <= 256 && isText(value.source_kind) && isText(value.assertion_status) && typeof value.recorded_at === 'number' && Number.isFinite(value.recorded_at) && value.recorded_at >= 0 && value.qualification === 'not_recorded' && isInteger(value.revision, 1) && (!detail || typeof value.text === 'string')
}
export function validateOwnerSourcePage(value: unknown, scope: string, operationId: string, pageSize: number): OwnerSourcePage {
  if (!hasFields(value, ['schema', 'scope', 'operation_id', 'sources', 'next_cursor', 'has_more']) || value.schema !== 'd12.source-page.v1' || value.scope !== scope || value.operation_id !== operationId || !Array.isArray(value.sources) || value.sources.length > pageSize || !value.sources.every(v => metadata(v)) || new Set(value.sources.map(v => v.source_id)).size !== value.sources.length || typeof value.has_more !== 'boolean' || !(value.next_cursor === null || isText(value.next_cursor)) || value.has_more !== (value.next_cursor !== null) || value.has_more && value.sources.length !== pageSize) throw new Error('来源目录未通过当前分页合同核验。')
  return value as unknown as OwnerSourcePage
}
export function validateOwnerSourceDetail(value: unknown, scope: string, operationId: string, selected: OwnerSourceMetadata): OwnerSourceDetail {
  if (!hasFields(value, ['schema', 'scope', 'operation_id', 'source']) || value.schema !== 'd12.source-detail.v1' || value.scope !== scope || value.operation_id !== operationId || !metadata(value.source, true) || !isRecord(value.source) || value.source.source_id !== selected.source_id || value.source.revision !== selected.revision) throw new Error('来源详情与当前选择版本不一致。')
  return value as unknown as OwnerSourceDetail
}

export interface SourceInspectionWorkflowInput {
  pause_operation_id: string; resume_operation_id: string | null; resume_on_complete: boolean
  scope_kind: 'exact_parent_closed_targets' | 'namespace_source_family'; target_refs: string[]
  deadline_utc: number; interpretation_status_discovery: boolean
}
export interface SourceInspectionWorkflowProgress {
  phase: 'pending' | 'completed'; local_phase: string | null; cursor: string
  batch_index: number; migrated: number; retired: number; producer_operation_id: string | null
}
export type SourceInspectionWorkflowPhase = 'accepted' | 'pausing' | 'paused' | 'migrating' | 'migration_complete' | 'resuming' | 'active' | 'held'
export interface SourceInspectionWorkflowView extends SourceInspectionWorkflowInput {
  schema: 'd12.source-inspection-workflow-view.v1'; scope: string; installation_id: string
  operation_id: string; request_digest: string; effective_deadline_utc: number
  state: 'accepted' | 'running' | 'completed' | 'held'; phase: SourceInspectionWorkflowPhase; hold_code: string | null
  progress: SourceInspectionWorkflowProgress | null
}
const workflowInputFields = ['pause_operation_id', 'resume_operation_id', 'resume_on_complete', 'scope_kind', 'target_refs', 'deadline_utc', 'interpretation_status_discovery']
function inspectionWorkflowInvalid(): never { throw new Error('来源维护受理请求或原操作回执未通过合同核验。') }
export function validateSourceInspectionWorkflowInput(input: unknown, scope: string, operationId: string): SourceInspectionWorkflowInput {
  validateScope(scope)
  if (!UUID4.test(operationId) || !hasFields(input, workflowInputFields) || !isText(input.pause_operation_id)
      || !UUID4.test(input.pause_operation_id) || input.pause_operation_id === operationId || typeof input.resume_on_complete !== 'boolean'
      || !(input.resume_on_complete ? typeof input.resume_operation_id === 'string' && UUID4.test(input.resume_operation_id)
        && input.resume_operation_id !== operationId && input.resume_operation_id !== input.pause_operation_id : input.resume_operation_id === null)
      || !['exact_parent_closed_targets', 'namespace_source_family'].includes(String(input.scope_kind))
      || !Array.isArray(input.target_refs) || input.target_refs.length > 32
      || typeof input.deadline_utc !== 'number' || !Number.isFinite(input.deadline_utc) || input.deadline_utc <= 0
      || typeof input.interpretation_status_discovery !== 'boolean') inspectionWorkflowInvalid()
  const refs = input.target_refs as unknown[]
  if ((input.scope_kind === 'namespace_source_family') !== (refs.length === 0)) inspectionWorkflowInvalid()
  for (let i = 0; i < refs.length; ++i) {
    const ref = refs[i]
    if (!isText(ref) || i > 0 && String(refs[i - 1]) >= ref) inspectionWorkflowInvalid()
    let key: unknown
    try { key = JSON.parse(ref) } catch { inspectionWorkflowInvalid() }
    if (!Array.isArray(key) || key.length !== 6 || key.some(v => typeof v !== 'string')
        || key[1] + '/' + key[2] !== scope || !['memory.source', 'memory.interpretation'].includes(key[4])) inspectionWorkflowInvalid()
  }
  return input as unknown as SourceInspectionWorkflowInput
}
export function sourceInspectionWorkflowInput(view: SourceInspectionWorkflowView): SourceInspectionWorkflowInput {
  return { pause_operation_id: view.pause_operation_id, resume_operation_id: view.resume_operation_id, resume_on_complete: view.resume_on_complete,
    scope_kind: view.scope_kind, target_refs: [...view.target_refs], deadline_utc: view.deadline_utc, interpretation_status_discovery: view.interpretation_status_discovery }
}
export function sameSourceInspectionWorkflowInput(a: SourceInspectionWorkflowInput, b: SourceInspectionWorkflowInput): boolean {
  return workflowInputFields.every(k => JSON.stringify(a[k as keyof SourceInspectionWorkflowInput]) === JSON.stringify(b[k as keyof SourceInspectionWorkflowInput]))
}
export function validateSourceInspectionWorkflowResponse(body: unknown, scope: string, operationId: string,
    kind: 'accept' | 'read', expected?: SourceInspectionWorkflowInput): SourceInspectionWorkflowView | null {
  if (!UUID4.test(operationId) || !isRecord(body)) inspectionWorkflowInvalid()
  if (body.status === 'pending_confirmation') {
    if (!hasFields(body, ['status', 'problem']) || !hasFields(body.problem, ['code', 'operation_id', 'recovery_action'], ['message', 'retryable'])
        || body.problem.code !== 'inspection_migration_unconfirmed' || body.problem.operation_id !== operationId
        || body.problem.recovery_action !== 'read_source_inspection_migration_v1') inspectionWorkflowInvalid()
    return null
  }
  const resultKey = kind === 'accept' ? 'receipt' : 'projection'
  if (!hasFields(body, ['status', resultKey]) || !(kind === 'accept' ? ['accepted', 'ready'].includes(String(body.status)) : body.status === 'ready')) inspectionWorkflowInvalid()
  const value = body[resultKey]
  if (!hasFields(value, ['schema', 'scope', 'installation_id', 'operation_id', 'request_digest', 'state', 'phase', 'hold_code', 'effective_deadline_utc', 'progress', ...workflowInputFields])
      || value.schema !== 'd12.source-inspection-workflow-view.v1' || value.scope !== scope || value.operation_id !== operationId
      || !isText(value.installation_id) || typeof value.request_digest !== 'string' || !/^[0-9a-f]{64}$/.test(value.request_digest)
      || !['accepted', 'running', 'completed', 'held'].includes(String(value.state))
      || !['accepted', 'pausing', 'paused', 'migrating', 'migration_complete', 'resuming', 'active', 'held'].includes(String(value.phase))
      || !(value.hold_code === null || isText(value.hold_code)) || (value.state === 'held') !== (value.phase === 'held')
      || (value.state === 'held') !== (value.hold_code !== null)
      || typeof value.effective_deadline_utc !== 'number' || !Number.isFinite(value.effective_deadline_utc) || value.effective_deadline_utc <= 0) inspectionWorkflowInvalid()
  const input = validateSourceInspectionWorkflowInput(Object.fromEntries(workflowInputFields.map(k => [k, value[k]])), scope, operationId)
  if (value.effective_deadline_utc > input.deadline_utc || expected && !sameSourceInspectionWorkflowInput(input, expected)) inspectionWorkflowInvalid()
  let progress: SourceInspectionWorkflowProgress | null = null
  if (value.progress !== null) {
    const p = value.progress, common = ['schema', 'operation_id', 'request_digest', 'phase', 'batch_index', 'cursor', 'migrated', 'retired']
    if (!isRecord(p) || !(p.schema === 'sylanne.source-inspection-migration-progress.v1'
        ? hasFields(p, [...common, 'local_phase']) : p.schema === 'sylanne.source-inspection-migration-receipt.v1'
        && hasFields(p, [...common, 'producer_operation_id', 'before_stamp', 'after_stamp', 'event_digest']))
        || p.operation_id !== operationId || typeof p.request_digest !== 'string' || !/^[0-9a-f]{64}$/.test(p.request_digest)
        || !['pending', 'completed'].includes(String(p.phase))
        || !isInteger(p.batch_index, p.schema === 'sylanne.source-inspection-migration-receipt.v1' ? 0 : -1)
        || typeof p.cursor !== 'string' || p.cursor.length > 4096 || !isInteger(p.migrated) || !isInteger(p.retired)
        || p.schema === 'sylanne.source-inspection-migration-progress.v1' && (p.phase !== 'pending' || !isText(p.local_phase))
        || p.schema === 'sylanne.source-inspection-migration-receipt.v1' && (!isText(p.producer_operation_id)
          || typeof p.event_digest !== 'string' || !/^[0-9a-f]{64}$/.test(p.event_digest)
          || !Array.isArray(p.before_stamp) || p.before_stamp.length !== 3 || !Array.isArray(p.after_stamp) || p.after_stamp.length !== 3)) inspectionWorkflowInvalid()
    progress = { phase: p.phase as 'pending' | 'completed', local_phase: typeof p.local_phase === 'string' ? p.local_phase : null,
      cursor: p.cursor, batch_index: p.batch_index, migrated: p.migrated, retired: p.retired,
      producer_operation_id: typeof p.producer_operation_id === 'string' ? p.producer_operation_id : null }
  }
  if (value.state === 'completed' && (progress?.phase !== 'completed' || value.phase !== (input.resume_on_complete ? 'active' : 'paused'))) inspectionWorkflowInvalid()
  return { schema: 'd12.source-inspection-workflow-view.v1', scope, installation_id: value.installation_id,
    operation_id: operationId, request_digest: value.request_digest, state: value.state as SourceInspectionWorkflowView['state'],
    phase: value.phase as SourceInspectionWorkflowPhase, hold_code: value.hold_code as string | null,
    effective_deadline_utc: value.effective_deadline_utc, progress, ...input }
}
