import {sha256HexV1} from './browser-crypto.ts'
import { canonicalJson, hasFields, isInteger, isText, UUID4, validateScope } from './contract.ts'

export interface SourceCorrectionContext {
  schema: 'd12.source-correction-context.v1'; namespace: { bot_id: string; persona_id: string }
  source_refs: string[]; source_revision: number; source_digest: string
  targets: { target_ref: string; revision: number; digest: string; claim: string }[]
  access_epoch: number; deletion_epoch: number
}
export interface SourceCorrectionInput {
  schema: 'd12.source_correction.v1'; correction_kind: 'source_claim'; statement: string
  source_refs: string[]; target_refs: string[]; access_epoch: number; deletion_epoch: number
}
export interface SourceCorrectionReceipt {
  schema: 'd12.source_correction_receipt.v1'; phase: 'source_correction_committed'; operation_id: string
  request_digest: string; correction_source_ref: string; source_refs: string[]; invalidated_target_refs: string[]
  reevaluation_outbox_ref: string; audit_event_ref: string; graph_revision: number; access_epoch: number; deletion_epoch: number
}
/** Retain identity and technical input only; the user's statement never survives navigation here. */
export interface PendingSourceCorrection {
  scope: string; sourceId: string; operationId: string; requestDigest: string; input: Omit<SourceCorrectionInput, 'statement'>
}
export class SourceCorrectionContractError extends Error { constructor() { super('来源更正的正式原件不兼容。') } }
function invalid(): never { throw new SourceCorrectionContractError() }
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
function reference(value: unknown, scope: string, type: string, name: string, subject?: string): boolean {
  if (!isText(value)) return false
  try {
    const parts: unknown = JSON.parse(value), [bot, persona] = validateScope(scope).split('/')
    return Array.isArray(parts) && parts.length === 6 && parts[0] === 'event' && parts[1] === bot && parts[2] === persona
      && isText(parts[3]) && (subject === undefined || parts[3] === subject) && parts[4] === type && parts[5] === name
  } catch { return false }
}
export function validateSourceCorrectionContext(value: unknown, scope: string, sourceId: string): SourceCorrectionContext {
  validateScope(scope)
  if (!isText(sourceId) || sourceId.length > 256
    || !hasFields(value, ['schema', 'namespace', 'source_refs', 'source_revision', 'source_digest', 'targets', 'access_epoch', 'deletion_epoch'])
    || value.schema !== 'd12.source-correction-context.v1' || !hasFields(value.namespace, ['bot_id', 'persona_id'])
    || `${value.namespace.bot_id}/${value.namespace.persona_id}` !== scope
    || !Array.isArray(value.source_refs) || value.source_refs.length !== 1
    || !reference(value.source_refs[0], scope, 'memory.source', 'record', sourceId)
    || !isInteger(value.source_revision, 1) || !digest(value.source_digest)
    || !isInteger(value.access_epoch) || !isInteger(value.deletion_epoch) || !Array.isArray(value.targets) || value.targets.length > 100) invalid()
  const seen = new Set<string>()
  for (const item of value.targets) {
    if (!hasFields(item, ['target_ref', 'revision', 'digest', 'claim']) || !reference(item.target_ref, scope, 'memory.interpretation', 'current')
      || seen.has(item.target_ref as string) || !isInteger(item.revision, 1) || !digest(item.digest) || !isText(item.claim)) invalid()
    seen.add(item.target_ref as string)
  }
  return value as unknown as SourceCorrectionContext
}
export function sourceCorrectionInput(context: SourceCorrectionContext, statement: string, targets: string[]): SourceCorrectionInput {
  if (typeof statement !== 'string' || !statement.trim() || statement.length > 4096 || !targets.length || targets.length > 100
    || new Set(targets).size !== targets.length || targets.some(ref => !context.targets.some(item => item.target_ref === ref))) invalid()
  return { schema: 'd12.source_correction.v1', correction_kind: 'source_claim', statement,
    source_refs: [...context.source_refs], target_refs: [...targets], access_epoch: context.access_epoch, deletion_epoch: context.deletion_epoch }
}
export async function sourceCorrectionRequestDigest(scope: string, input: SourceCorrectionInput, operationId: string): Promise<string> {
  validateScope(scope); if (!UUID4.test(operationId)) invalid()
  // Existing W01 hashes Python json.dumps(..., ensure_ascii=True); escape UTF-16 code units identically, including surrogate pairs.
  const original = canonicalJson({ action: 'correct_or_edit', scope, purpose: 'workbench_user_action', audience: 'owner', operation_id: operationId, input })
    .replace(/[\u007f-\uffff]/g, character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'))
  return 'sha256:' + sha256HexV1(new TextEncoder().encode(original))
}
export function validateSourceCorrectionReceipt(value: unknown, input: SourceCorrectionInput, operationId: string, requestDigest: string): SourceCorrectionReceipt {
  if (!hasFields(value, ['schema', 'phase', 'operation_id', 'request_digest', 'correction_source_ref', 'source_refs', 'invalidated_target_refs',
      'reevaluation_outbox_ref', 'audit_event_ref', 'graph_revision', 'access_epoch', 'deletion_epoch'])
    || value.schema !== 'd12.source_correction_receipt.v1' || value.phase !== 'source_correction_committed'
    || value.operation_id !== operationId || value.request_digest !== requestDigest
    || canonicalJson(value.source_refs) !== canonicalJson(input.source_refs) || canonicalJson(value.invalidated_target_refs) !== canonicalJson(input.target_refs)
    || value.access_epoch !== input.access_epoch || value.deletion_epoch !== input.deletion_epoch || !isInteger(value.graph_revision, 1)
    || !isText(value.correction_source_ref) || !isText(value.reevaluation_outbox_ref) || !isText(value.audit_event_ref)) invalid()
  return value as unknown as SourceCorrectionReceipt
}
