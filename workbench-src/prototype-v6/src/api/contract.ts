import {operationIdV1} from './browser-crypto.ts'
/** Verified against 2718labs/astrbot_plugin_sylanne @ 00049ab3f547bd996113c8ef1c478b1e8f991f5a. */
export const BACKEND_COMMIT = '00049ab3f547bd996113c8ef1c478b1e8f991f5a'
export const DEFAULT_API_BASE = '/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1'
export const D12_SCHEMA = 'd12.contract.v1'
export const OWNER_SCHEMA = 'sylanne3.authority.owner-session.v1'
export const CONTACT_HOLD = true
export const VIEW_TYPES = ['overview', 'creation', 'relations', 'memory', 'd06.memory_sources.v1', 'cognition', 'action', 'expression', 'diagnostics', 'lifecycle'] as const
export type ViewType = typeof VIEW_TYPES[number]
export type ProjectionStatus = 'loading' | 'empty' | 'unauthorized' | 'stale' | 'partial' | 'unavailable' | 'ready'
export interface Problem { code: string; retryable: boolean }
export interface Namespace { bot: string; persona: string }
export interface ViewAvailability { view_type: ViewType; status: 'available' | 'unavailable'; snapshot_epoch?: number }
export interface WorkspaceProjection {
  namespace: Namespace; access_generation: number; views: ViewAvailability[]
  view_diagnostics: { view_type: ViewType; read_status: ProjectionStatus; coverage?: string; problem_code?: string; snapshot_epoch?: number }[]
  unavailable_domains: Record<string, string>
  command_routes: { action: string; status: 'route_installed' | 'partial_route_installed' | 'unavailable' }[]
}
export interface PersonaCandidate { plan_id: string; version: number; authored: boolean; block_count: number; value_rule_count: number }
export interface MemorySource { source_id: string; source_kind: string; assertion_status: string; recorded_at: string; qualification: 'not_recorded' }
export interface CharacterProjection {
  namespace: Namespace; access_generation: number; view_type: ViewType
  data: { candidates?: PersonaCandidate[]; sources?: MemorySource[]; coverage?: 'complete' }
  snapshot_epoch?: number
  coverage?: { requested_types: string[]; returned_atoms: number; truncated: boolean }
  next_cursor?: string | null
}
export interface ProjectionResult<T> { status: ProjectionStatus; projection?: T; problem?: Problem }
export interface OwnerFields {
  authority_id: string; authority_namespace: string; installation_id: string
  identity_provider: string; account_ref: string; account_incarnation: string
  credential_id: string; credential_epoch: string
}
export interface OwnerLoginRequest {
  kind: 'owner_session_login_request_v1'; schema: typeof OWNER_SCHEMA
  authority_id: string; authority_namespace: string; installation_id: string
  principal: { identity_provider: string; account_ref: string; account_incarnation: string }
  credential_id: string; credential_epoch: number; audience: 'owner'; dashboard_origin: string
}
export interface OwnerChallenge {
  kind: 'owner_session_login_challenge_v1'; schema: typeof OWNER_SCHEMA; request: OwnerLoginRequest
  nonce: string; principal_epoch: number; boot_id: string; issued_at_utc: string; expires_at_utc: string
}
export interface ChallengeResult { challenge: OwnerChallenge; signingPayloadBase64: string }
export interface ReadCommand {
  schema_version: typeof D12_SCHEMA; action: 'open_workspace' | 'read_character_view'
  scope: string; purpose: 'workbench_view'; audience: 'owner'; operation_id: string
  input: { client_protocol: typeof D12_SCHEMA } | { view_type: ViewType; cursor?: string; page_size: 100 }
}
const identifier = /^[A-Za-z0-9][A-Za-z0-9._:/@#=+\-]{0,255}$/
export const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
export const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value)
export const hasFields = (value: unknown, required: string[], optional: string[] = []): value is Record<string, unknown> => isRecord(value) && required.every(key => key in value) && Object.keys(value).every(key => required.includes(key) || optional.includes(key))
export const isText = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 4096
export const isInteger = (value: unknown, minimum = 0): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum
export const isViewType = (value: unknown): value is ViewType => VIEW_TYPES.includes(value as ViewType)
export function validateScope(scope: string) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,191}$/.test(scope) || scope.split('/').length !== 2 || !scope.split('/').every(part => identifier.test(part))) throw new Error('请填写当前 Owner 授权的 bot/persona。')
  return scope
}
export function makeReadCommand(action: ReadCommand['action'], scope: string, viewType?: ViewType, cursor: string | null = null, operationId = operationIdV1()): ReadCommand {
  validateScope(scope)
  if (!UUID4.test(operationId)) throw new Error('operation_id 必须是规范 UUID4。')
  if (action !== 'open_workspace' && action !== 'read_character_view') throw new Error('此界面只支持已核验的只读请求。')
  if (action === 'read_character_view' && !isViewType(viewType)) throw new Error('未支持的视图类型。')
  if (cursor !== null && (typeof cursor !== 'string' || !cursor || cursor.length > 4096)) throw new Error('视图游标无效。')
  return { schema_version: D12_SCHEMA, action, scope, purpose: 'workbench_view', audience: 'owner', operation_id: operationId,
    input: action === 'open_workspace' ? { client_protocol: D12_SCHEMA } : { view_type: viewType!, ...(cursor === null ? {} : { cursor }), page_size: 100 } }
}
export function trustedWorkbenchOrigin(value: string) {
  try { const url = new URL(value); if (['http:','https:'].includes(url.protocol) && url.origin === value && !url.username && !url.password) return value } catch { /* invalid origin */ }
  throw new Error('Owner 签名登录需要与后端同源的正式 HTTP/HTTPS 工作台。')
}
export function makeOwnerLoginRequest(fields: OwnerFields, dashboardOrigin: string): OwnerLoginRequest {
  const values: Record<string, string> = {}
  for (const key of ['authority_id', 'authority_namespace', 'installation_id', 'identity_provider', 'account_ref', 'account_incarnation', 'credential_id'] as const) {
    const value = fields[key]?.trim()
    if (!value || !identifier.test(value)) throw new Error(`请填写已配对安装记录中的 ${key}。`)
    values[key] = value
  }
  const epoch = Number(fields.credential_epoch)
  if (!isInteger(epoch, 1) || String(epoch) !== fields.credential_epoch.trim()) throw new Error('credential_epoch 必须是已登记的正整数。')
  return { kind: 'owner_session_login_request_v1', schema: OWNER_SCHEMA, authority_id: values.authority_id!, authority_namespace: values.authority_namespace!, installation_id: values.installation_id!,
    principal: { identity_provider: values.identity_provider!, account_ref: values.account_ref!, account_incarnation: values.account_incarnation! }, credential_id: values.credential_id!, credential_epoch: epoch,
    audience: 'owner', dashboard_origin: trustedWorkbenchOrigin(dashboardOrigin) }
}
/** The Authority signs asdict(challenge), not the wire object's kind fields. */
export function canonicalJson(input: unknown): string {
  function ordered(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(ordered)
    if (isRecord(value)) return Object.fromEntries(Object.keys(value).sort().map(key => [key, ordered(value[key])]))
    return value
  }
  return JSON.stringify(ordered(input))
}
export function signingPayload(challenge: OwnerChallenge): string {
  const { kind: _challengeKind, ...value } = challenge
  const { kind: _requestKind, ...request } = value.request
  return 'Sylanne3 Owner session login v1\n' + canonicalJson({ ...value, request })
}
export function decodeBase64(value: string): Uint8Array {
  if (!value || value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error('Base64 格式无效。')
  const binary = atob(value)
  return Uint8Array.from(binary, character => character.charCodeAt(0))
}
export function validateChallenge(body: unknown, request: OwnerLoginRequest, now = Date.now()): ChallengeResult {
  if (!hasFields(body, ['schema_version', 'challenge', 'signing_payload_base64']) || body.schema_version !== 'sylanne.owner-login.v1' || !isRecord(body.challenge) || !isText(body.signing_payload_base64)) throw new Error('Owner 挑战响应无效。')
  const c = body.challenge
  const expected = ['kind', 'schema', 'request', 'nonce', 'principal_epoch', 'boot_id', 'issued_at_utc', 'expires_at_utc']
  if (Object.keys(c).length !== expected.length || expected.some(key => !(key in c)) || c.kind !== 'owner_session_login_challenge_v1' || c.schema !== OWNER_SCHEMA ||
    !isRecord(c.request) || canonicalJson(c.request) !== canonicalJson(request) || !isInteger(c.principal_epoch) ||
    typeof c.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(c.nonce) || typeof c.boot_id !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(c.boot_id) ||
    typeof c.issued_at_utc !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(c.issued_at_utc) || typeof c.expires_at_utc !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(c.expires_at_utc)) throw new Error('Owner 挑战与当前请求不匹配。')
  const issued = Date.parse(c.issued_at_utc), expires = Date.parse(c.expires_at_utc)
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > 300000 || expires <= now) throw new Error('Owner 挑战已过期或时间无效。')
  const challenge = c as unknown as OwnerChallenge
  if (new TextDecoder('utf-8', { fatal: true }).decode(decodeBase64(body.signing_payload_base64)) !== signingPayload(challenge)) throw new Error('签名载荷与挑战不一致。')
  return { challenge, signingPayloadBase64: body.signing_payload_base64 }
}
