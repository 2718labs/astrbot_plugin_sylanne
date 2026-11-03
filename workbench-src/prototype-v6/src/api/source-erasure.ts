import { hasFields, isInteger, isText, UUID4, validateScope } from './contract.ts'

export interface SourceErasureAttempt { scope: string; sourceId: string; operationId: string }
export interface SourceErasurePending {
  schema: 'd12.scoped_erasure_pending.v2'; phase: 'authority_pending'; operation_id: string
  source_id: string; deletion_epoch: number; request_digest: string
}
export interface SourceErasureAccepted {
  schema: 'd12.scoped_erasure_accepted.v1'; phase: 'authority_accepted'; operation_id: string
  source_id: string; deletion_epoch: number; scope_digest: string; graph_barrier_digest: string; cleanup_complete: false
}
export type SourceErasureReceipt = SourceErasurePending | SourceErasureAccepted
export function sourceErasureRequest(attempt: SourceErasureAttempt) {
  validateScope(attempt.scope)
  if (attempt.scope.split('/').length !== 2 || !UUID4.test(attempt.operationId)
      || !isText(attempt.sourceId) || attempt.sourceId.length > 256 || attempt.sourceId !== attempt.sourceId.trim()) {
    throw new Error('来源删除需要当前角色、完整来源ID和原操作ID。')
  }
  return {schema:'d12.scoped_erasure_request.v2' as const, source_id:attempt.sourceId}
}
export function validateSourceErasureResponse(value: unknown, attempt: SourceErasureAttempt): SourceErasureReceipt {
  sourceErasureRequest(attempt)
  if (!hasFields(value, ['status','receipt'])) throw new Error('来源删除响应不兼容。')
  const receipt = value.receipt
  const pending = value.status === 'pending'
  const fields = pending ? ['request_digest'] : ['scope_digest','graph_barrier_digest','cleanup_complete']
  if ((!pending && value.status !== 'accepted')
      || !hasFields(receipt, ['schema','phase','operation_id','source_id','deletion_epoch',...fields])
      || receipt.schema !== (pending ? 'd12.scoped_erasure_pending.v2' : 'd12.scoped_erasure_accepted.v1')
      || receipt.phase !== (pending ? 'authority_pending' : 'authority_accepted')
      || receipt.operation_id !== attempt.operationId || receipt.source_id !== attempt.sourceId
      || !isInteger(receipt.deletion_epoch,1)
      || (pending ? !digest(receipt.request_digest) : (!digest(receipt.scope_digest)
          || !digest(receipt.graph_barrier_digest) || receipt.cleanup_complete !== false))) {
    throw new Error('来源删除原件与当前请求不符。')
  }
  return receipt as unknown as SourceErasureReceipt
}
function digest(value: unknown): value is string { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value) }
