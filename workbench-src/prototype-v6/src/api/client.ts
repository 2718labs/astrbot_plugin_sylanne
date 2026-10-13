import {operationIdV1} from './browser-crypto.ts'
import { OWNER_TASK_ACTION, OWNER_MATERIAL_ACTION, ownerMaterialInputDigest, validateOwnerMaterialText, validateOwnerMaterialStatus, validateOwnerMaterialReceipt, type OwnerMaterialStatus, OwnerTaskContractError, validateOwnerTaskOptions, validateOwnerTaskRequest, validateOwnerTaskStatus, validateOwnerTaskReceipt, type OwnerTaskOptions, type OwnerTaskRequest, type OwnerTaskStatus, type OwnerTaskReceipt } from './owner-source-note-task.ts'
import { MANAGEMENT_PREFIX, LOG_LIMIT, MANAGEMENT_RESPONSE_MAX_BYTES, ManagementContractError, managementRequest, binding, validateCapabilities, validateManagementProblem, validateLogFilter, validateLogPage, validateSettings, validateReceipt, type ManagementCapabilities, type LogFilter, type LogPage, type SettingsSnapshot, type SettingsReceipt } from './management.ts'
import { SETUP_PREFIX, SETUP_RESPONSE_MAX_BYTES, validateSetupStatus, type SetupStatus } from './setup.ts'
import { CreatorContractError, DOMAIN_INPUT_ACTIONS, draftSaveInput, validateCreatorConfiguration, validateDraftSaveReceipt, validateSchemeReceipt, validateLegacyCreatorDraft, validateDomainInputReceipt, type CreatorConfiguration, type SchemeValues, type DomainInputAction, type DomainInputIntent } from './creator.ts'
import { DEFAULT_API_BASE, validateScope, CONTACT_HOLD, UUID4, isRecord, hasFields, isText, isInteger, isViewType, makeReadCommand, makeOwnerLoginRequest, validateChallenge, decodeBase64, trustedWorkbenchOrigin, type OwnerFields, type ChallengeResult, type WorkspaceProjection, type CharacterProjection, type ProjectionResult, type ProjectionStatus, type ViewType, type Problem } from './contract.ts'
import { ReplyControlContractError, makeReplyControlCommand, validateReplyControls, validateReplyControlStatus, type ReplyControlPage, type ReplyControlStatus, type StopReplyRequest } from './reply-controls.ts'
import { projectContextInput, validateProjectContextOptions, validateProjectContextReceipt, type ProjectContextOptions, type ProjectContextItem } from './project-context.ts'
import { SourceCorrectionContractError, validateSourceCorrectionContext, validateSourceCorrectionReceipt, sourceCorrectionRequestDigest, type SourceCorrectionContext, type SourceCorrectionInput, type SourceCorrectionReceipt } from './source-correction.ts'
import { ProjectControlContractError, validateProjectControlContext, validateProjectControlContextV2, type ProjectControlContextV2, validateProjectControlReceipt, type ProjectControlContext, type ProjectControlAction, type ProjectControlInput, type ProjectControlReceipt } from './project-control.ts'
import { OwnerArtifactContractError, validateOwnerArtifactOptions, validateOwnerArtifactBody, ownerArtifactReadInput, type OwnerArtifactOptions, type OwnerArtifactItem, type OwnerArtifactBody } from './owner-artifact.ts'
import { RelationsContractError, validateRelationsProjection, type RelationsProjection } from './relations.ts'
export interface FetchResponse { ok: boolean; status: number; body?: ReadableStream<Uint8Array> | null; json(): Promise<unknown> }
export type FetchLike = (input: string, init: RequestInit) => Promise<FetchResponse>
export type ApiErrorCode = 'offline' | 'unauthorized' | 'timeout' | 'network_unavailable' | 'invalid_response' | 'session_changed' | 'action_pending' | 'contact_hold' | string
export class WorkbenchApiError extends Error {
  readonly code: ApiErrorCode; readonly status: number; readonly retryable: boolean
  constructor(message: string, options: { code?: ApiErrorCode; status?: number; retryable?: boolean } = {}) {
    super(message); this.name = 'WorkbenchApiError'; this.code = options.code ?? 'network_unavailable'; this.status = options.status ?? 0; this.retryable = options.retryable ?? false
  }
}
export const HTTPS_REQUIRED_MESSAGE = '当前后端要求 HTTPS；请核对所安装插件的版本和实际监听协议。'
export const HTTP_TRANSPORT_MESSAGE = '当前连接使用 HTTP，传输未加密；后台登录、配置和 Owner 核验仍使用真实身份与授权。'
export function workbenchTransportAvailable(origin: string): boolean {
  try {
    trustedWorkbenchOrigin(origin)
    return typeof location==='undefined'||trustedWorkbenchOrigin(location.origin)===origin
  } catch { return false }
}
export function requireWorkbenchTransport(origin: string): void {
  if (!workbenchTransportAvailable(origin)) throw new WorkbenchApiError('工作台需要同源的 HTTP/HTTPS 地址。',{code:'origin_denied',status:403})
}
export function httpsResponseError(status: number, body: unknown): WorkbenchApiError | null {
  if (status!==403) return null
  const flat=hasFields(body,['reason_code'])&&body.reason_code==='https_required'
  const nested=isRecord(body)&&isRecord(body.problem)&&body.problem.code==='https_required'
  return flat||nested?new WorkbenchApiError(HTTPS_REQUIRED_MESSAGE,{code:'https_required',status,retryable:false}):null
}
const projectionStates: ProjectionStatus[] = ['loading', 'empty', 'unauthorized', 'stale', 'partial', 'unavailable', 'ready']
function invalid(): never { throw new WorkbenchApiError('后端响应未通过合同校验，没有显示角色内容。', { code: 'invalid_response' }) }
async function boundedJson(response: FetchResponse, maximumBytes: number): Promise<unknown> {
  if (!response.body) {
    const value = await response.json()
    if (new TextEncoder().encode(JSON.stringify(value)).byteLength > maximumBytes) invalid()
    return value
  }
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true })
  let bytes = 0, text = ''
  try {
    while (true) {
      const chunk = await reader.read()
      if (chunk.done) break
      bytes += chunk.value.byteLength
      if (bytes > maximumBytes) { await reader.cancel(); invalid() }
      text += decoder.decode(chunk.value, { stream: true })
    }
    return JSON.parse(text + decoder.decode())
  } finally { reader.releaseLock() }
}
function namespace(value: unknown, scope: string): boolean {
  return isRecord(value) && Object.keys(value).length === 2 && isText(value.bot) && isText(value.persona) && `${value.bot}/${value.persona}` === scope
}
function problem(value: unknown): Problem | undefined {
  if (!isRecord(value)) return undefined
  return { code: typeof value.code === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value.code) ? value.code : 'request_rejected', retryable: value.retryable === true }
}
function responseError(status: number, body: unknown) {
  const transport=httpsResponseError(status,body);if(transport)return transport
  const p = isRecord(body) ? problem(body.problem) : undefined
  const code = p?.code ?? ([401, 403].includes(status) ? 'unauthorized' : 'request_rejected')
  const messages: Record<string, string> = {
    host_session_missing: '请先在同源 AstrBot Dashboard 登录，再核验工作台会话。',
    owner_session_locked: 'Owner 会话未解锁或已经失效。请完成已配对凭据的签名登录。',
    origin_denied: '请求来源未通过核验。请从后端的同源工作台打开。',
    csrf_denied: '防跨站校验未通过。角色内容已清空，请重新核验会话。',
    owner_login_https_required: 'Owner 登录需要受信 HTTPS 工作台。',
    owner_login_rejected: 'Owner 签名或当前授权核验未通过。请重新取得挑战。',
    owner_logout_authority_unavailable: '当前浏览器会话已锁定，Authority 退出尚未确认。',
    revision_conflict: '配置已经被其他操作修改，请重新读取后再决定是否保存。',
    capabilities_changed: '管理权限或安装版本已经变化，请重新核验接口。',
    cursor_expired: '日志翻页游标已过期，请从第一页重新读取。',
    snapshot_changed: '日志快照已经变化，请从第一页重新读取。',
    validation_failed: '配置值未通过后端验证；未确认保存。',
    rate_limited: '请求过于频繁，请稍后手动重试。',
  }
  return new WorkbenchApiError(messages[code] ?? ([401, 403].includes(status) ? '当前会话无权执行此请求。' : status >= 500 ? '后端服务暂不可用。未使用缓存替代真实内容。' : '后端拒绝了此请求。'), { code, status, retryable: p?.retryable ?? status >= 500 })
}
export function validateWorkspace(body: unknown, scope: string): ProjectionResult<WorkspaceProjection> {
  const base = envelope<WorkspaceProjection>(body)
  if (base.status !== 'ready') return base
  const p = base.projection
  if (!hasFields(p, ['namespace', 'access_generation', 'views', 'view_diagnostics', 'unavailable_domains', 'command_routes']) || !namespace(p.namespace, scope) || !isInteger(p.access_generation, 1) || !Array.isArray(p.views) || !Array.isArray(p.view_diagnostics) || !isRecord(p.unavailable_domains) || !Array.isArray(p.command_routes)) invalid()
  if (p.views.some(v => !hasFields(v, ['view_type', 'status'], ['snapshot_epoch']) || !isViewType(v.view_type) || typeof v.status !== 'string' || !['available', 'unavailable'].includes(v.status) || (v.snapshot_epoch !== undefined && !isInteger(v.snapshot_epoch))) ||
      new Set(p.views.map(v => v.view_type)).size !== p.views.length ||
      p.view_diagnostics.some(v => !hasFields(v, ['view_type', 'read_status'], ['coverage', 'problem_code', 'snapshot_epoch']) || !isViewType(v.view_type) || !projectionStates.includes(v.read_status as ProjectionStatus) || (v.coverage !== undefined && (typeof v.coverage !== 'string' || !['partial', 'complete', 'not_disclosed'].includes(v.coverage))) || (v.problem_code !== undefined && !isText(v.problem_code)) || (v.snapshot_epoch !== undefined && !isInteger(v.snapshot_epoch))) ||
      Object.values(p.unavailable_domains).some(v => !isText(v)) || p.command_routes.some(v => !hasFields(v, ['action', 'status']) || !isText(v.action) || typeof v.status !== 'string' || !['route_installed', 'partial_route_installed', 'unavailable'].includes(v.status))) invalid()
  return base
}
export function validateCharacterView(body: unknown, scope: string, viewType: ViewType): ProjectionResult<CharacterProjection> {
  const base = envelope<CharacterProjection>(body)
  if (base.status !== 'ready') return base
  const p = base.projection
  if (!hasFields(p, ['view_type', 'namespace', 'access_generation', 'data'], ['snapshot_epoch', 'coverage', 'next_cursor']) || p.view_type !== viewType || !namespace(p.namespace, scope) || !isInteger(p.access_generation, 1) || !isRecord(p.data)) invalid()
  const data = p.data
  // These are the only field-level projections verified for this frontend slice.
  if (viewType === 'creation') {
    if (Object.keys(data).some(k => k !== 'candidates') || !Array.isArray(data.candidates) || data.candidates.some(v => !isRecord(v) || !isText(v.plan_id) || !isInteger(v.version, 1) || typeof v.authored !== 'boolean' || !isInteger(v.block_count) || !isInteger(v.value_rule_count) || Object.keys(v).length !== 5)) invalid()
  } else if (viewType === 'd06.memory_sources.v1') {
    if (Object.keys(data).some(k => !['sources', 'coverage'].includes(k)) || !Array.isArray(data.sources) || data.coverage !== 'complete' || data.sources.some(v => !isRecord(v) || !isText(v.source_id) || !isText(v.source_kind) || !isText(v.assertion_status) || !isText(v.recorded_at) || v.qualification !== 'not_recorded' || Object.keys(v).length !== 5)) invalid()
  } else {
    throw new WorkbenchApiError('此视图尚未实现字段合同，不能显示未经核验的内容。', { code: 'view_unsupported' })
  }
  if (p.snapshot_epoch !== undefined && !isInteger(p.snapshot_epoch)) invalid()
  if (p.next_cursor !== undefined && p.next_cursor !== null && (!isText(p.next_cursor) || p.next_cursor.length > 4096)) invalid()
  if (p.coverage !== undefined && (!hasFields(p.coverage, ['requested_types', 'returned_atoms', 'truncated']) || !Array.isArray(p.coverage.requested_types) || p.coverage.requested_types.some(v => !isText(v)) || !isInteger(p.coverage.returned_atoms) || typeof p.coverage.truncated !== 'boolean')) invalid()
  return base
}
function envelope<T>(body: unknown): ProjectionResult<T> {
  if (!hasFields(body, ['status'], ['projection', 'problem']) || !projectionStates.includes(body.status as ProjectionStatus)) invalid()
  if (body.problem !== undefined && (!hasFields(body.problem, ['code', 'retryable'], ['message']) || typeof body.problem.code !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(body.problem.code) || typeof body.problem.retryable !== 'boolean' || body.problem.message !== undefined && !isText(body.problem.message))) invalid()
  const status = body.status as ProjectionStatus
  if (status !== 'ready' && body.projection !== undefined) invalid()
  if (status === 'ready' && !isRecord(body.projection)) invalid()
  return { status, ...(status === 'ready' ? { projection: body.projection as T } : {}), ...(problem(body.problem) ? { problem: problem(body.problem) } : {}) }
}
export class WorkbenchApi {
  readonly enabled: boolean; readonly baseUrl: string; readonly origin: string
  #csrf: string | null = null; #generation = 0; #sessionRequest: Promise<void> | null = null
  #replyControlCsrf: string | null = null
  #fetchImpl: FetchLike; #timeoutMs: number; #pending = new Map<string, Promise<unknown>>()
  #challenge: ChallengeResult | null = null; #challengeRequest: Promise<ChallengeResult> | null = null
  #requests = new Set<AbortController>(); #managementRequests = new Set<AbortController>(); #managementGeneration = 0; #managementCaps: ManagementCapabilities | null = null
  #setupRequests = new Set<AbortController>(); #setupGeneration = 0
  #creatorRequests = new Set<AbortController>(); #creatorGeneration = 0
  constructor({ enabled = false, baseUrl = DEFAULT_API_BASE, origin = typeof location === 'undefined' ? 'http://localhost' : location.origin, fetchImpl = globalThis.fetch as FetchLike, timeoutMs = 10000 }: { enabled?: boolean; baseUrl?: string; origin?: string; fetchImpl?: FetchLike; timeoutMs?: number } = {}) {
    if (!baseUrl.startsWith('/') || baseUrl.startsWith('//') || /[?#\\]/.test(baseUrl) || !/^\/[A-Za-z0-9/_-]+$/.test(baseUrl)) throw new Error('API 地址必须是同源路径。')
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw new Error('无效的请求超时。')
    this.enabled = enabled; this.baseUrl = baseUrl.replace(/\/$/, ''); this.origin = origin; this.#fetchImpl = fetchImpl; this.#timeoutMs = timeoutMs
  }
  get hasSession() { return this.#csrf !== null }
  get transportAvailable() { return workbenchTransportAvailable(this.origin) }
  get secureTransport() { return this.transportAvailable && new URL(this.origin).protocol==='https:' }
  clearSession() { ++this.#generation; this.#csrf = null; this.#replyControlCsrf = null; this.#sessionRequest = null; this.#challenge = null; this.#challengeRequest = null; this.#managementCaps = null; ++this.#managementGeneration; ++this.#setupGeneration; ++this.#creatorGeneration; this.#pending.clear(); for (const request of this.#requests) request.abort(); this.#requests.clear(); this.#setupRequests.clear(); this.#creatorRequests.clear() }
  invalidateManagement() { ++this.#managementGeneration; this.#managementCaps = null; for (const [key] of this.#pending) if (key.startsWith('management:')) this.#pending.delete(key); for (const request of this.#managementRequests) request.abort(); this.#managementRequests.clear() }
  invalidateSetup() { ++this.#setupGeneration; this.#pending.delete('setup:status'); for (const request of this.#setupRequests) request.abort(); this.#setupRequests.clear() }
  invalidateCreator() { ++this.#creatorGeneration; for(const[key]of this.#pending)if(key.startsWith('creator:'))this.#pending.delete(key);for(const request of this.#creatorRequests)request.abort();this.#creatorRequests.clear() }
  cancelOwnerChallenge() { this.clearSession() }
  #assertEnabled() { if (!this.enabled) throw new WorkbenchApiError('离线界面预览：未连接本地后端，不能验证登录或读取角色。', { code: 'offline' }); requireWorkbenchTransport(this.origin) }
  #one<T>(key: string, action: () => Promise<T>): Promise<T> {
    const existing = this.#pending.get(key); if (existing) return existing as Promise<T>
    const promise = action().finally(() => { if (this.#pending.get(key) === promise) this.#pending.delete(key) })
    this.#pending.set(key, promise); return promise
  }
  async #json(path: string, method: 'GET' | 'POST', payload?: object, csrf?: string, management = false, setup = false, creator = false): Promise<unknown> {
    this.#assertEnabled()
    const fetcher = this.#fetchImpl
    const requestGeneration = this.#generation, managementGeneration = this.#managementGeneration, setupGeneration = this.#setupGeneration, creatorGeneration = this.#creatorGeneration
    const abort = new AbortController(); this.#requests.add(abort); if (management) this.#managementRequests.add(abort); if (setup) this.#setupRequests.add(abort); if(creator)this.#creatorRequests.add(abort); let timer: ReturnType<typeof setTimeout> | undefined
    let abortListener: (() => void) | undefined
    const init: RequestInit = { method, credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', referrerPolicy: 'same-origin', signal: abort.signal,
      headers: { accept: 'application/json', ...(method === 'POST' ? { 'content-type': 'application/json' } : {}), ...(csrf ? { 'x-csrf-token': csrf } : {}) }, ...(payload ? { body: JSON.stringify(payload) } : {}) }
    try {
      const result = await Promise.race([
        (async () => {
          const response = await fetcher(`${this.baseUrl}${path}`, init)
          let body: unknown
          try { body = management || setup || creator ? await boundedJson(response,setup ? SETUP_RESPONSE_MAX_BYTES : MANAGEMENT_RESPONSE_MAX_BYTES) : await response.json() } catch { if (!response.ok) throw responseError(response.status, null); invalid() }
          if (!response.ok) {
            const transport=httpsResponseError(response.status,body);if(transport)throw transport
            if (management || setup && ![401,403].includes(response.status)) {
              try { validateManagementProblem(body,response.status) }
              catch { throw new WorkbenchApiError('管理接口错误响应未通过协议校验，结果未确认。', {code:'invalid_response',status:response.status,retryable:response.status>=500}) }
            }
            throw responseError(response.status, body)
          }
          return body
        })(),
        new Promise<never>((_, reject) => { timer = setTimeout(() => { reject(new WorkbenchApiError('请求超时，结果未确认。请手动重试核验。', { code: 'timeout', retryable: true })); abort.abort() }, this.#timeoutMs); abortListener = () => { if (requestGeneration !== this.#generation || management && managementGeneration !== this.#managementGeneration || setup && setupGeneration !== this.#setupGeneration || creator&&creatorGeneration!==this.#creatorGeneration) reject(new WorkbenchApiError('会话已切换，旧请求已取消。', { code: 'session_changed' })) }; abort.signal.addEventListener('abort', abortListener, {once:true}) }),
      ])
      if (requestGeneration !== this.#generation || management && managementGeneration !== this.#managementGeneration || setup && setupGeneration !== this.#setupGeneration || creator&&creatorGeneration!==this.#creatorGeneration) throw new WorkbenchApiError('会话已切换，旧响应已丢弃。', { code: 'session_changed' })
      return result
    } catch (error) {
      if (error instanceof WorkbenchApiError) { if (error.code!=='https_required' && [401, 403].includes(error.status) && requestGeneration === this.#generation) this.clearSession(); throw error }
      throw new WorkbenchApiError('无法连接本地后端。没有显示缓存或示例角色。', { code: 'network_unavailable', retryable: true })
    } finally { if (timer) clearTimeout(timer); if (abortListener) abort.signal.removeEventListener('abort', abortListener); this.#requests.delete(abort); this.#managementRequests.delete(abort); this.#setupRequests.delete(abort); this.#creatorRequests.delete(abort) }
  }
  #creatorPayload(action:string,scope:string,input:object,operationId:string,purpose:'workbench_user_action'|'workbench_view'){
    const payload={schema_version:'d12.contract.v1',action,scope,purpose,audience:'owner',operation_id:operationId,input}
    if(new TextEncoder().encode(JSON.stringify(payload)).byteLength>64*1024)throw new WorkbenchApiError('完整请求超过当前64KiB命令上限，未发送；不会截断原文。',{code:'invalid_input'})
    return payload
  }
  async #creatorCommand(action:string,scope:string,input:object,operationId:string,purpose:'workbench_user_action'|'workbench_view'='workbench_user_action'){
    if(!UUID4.test(operationId))invalid()
    makeReadCommand('open_workspace',scope)
    const generation=this.#creatorGeneration
    await this.openSession()
    if(generation!==this.#creatorGeneration||!this.#csrf)throw new WorkbenchApiError('当前 Owner 会话已变化。',{code:'session_changed'})
    const payload=this.#creatorPayload(action,scope,input,operationId,purpose)
    const body=await this.#json('/commands','POST',payload,this.#csrf,false,false,true)
    if(!isRecord(body)||typeof body.status!=='string')invalid()
    if(body.status!=='ready'){
      if(!hasFields(body,['status'],['problem'])||!['stale','unavailable','partial','pending_confirmation','unauthorized'].includes(body.status)||!hasFields(body.problem,['code'],['retryable','message',...(action==='correct_or_edit'?['schema']:[])])||typeof body.problem.code!=='string'||!/^[A-Za-z0-9_.:-]{1,128}$/.test(body.problem.code))invalid()
      if(action==='correct_or_edit'&&body.problem.schema!==undefined&&body.problem.schema!=='d12.source_correction_response.v1')invalid()
      if(body.status==='unauthorized'){this.clearSession();throw responseError(403,body)}
      throw new WorkbenchApiError(body.problem.code==='local_module_disabled'&&typeof body.problem.message==='string'?body.problem.message:'当前领域操作未完成。请按实际状态重新读取；不会自动重放。',{code:body.status==='stale'&&body.problem.code==='draft_current_basis_changed'?'creator_conflict':body.problem.code,status:0,retryable:body.problem.retryable===true})
    }
    return body
  }
  #creatorValidate<T>(validate:()=>T):T{try{return validate()}catch(error){if(error instanceof CreatorContractError)invalid();throw error}}
  readConfigurationDraft(scope:string):Promise<CreatorConfiguration>{
    return this.#one(`creator:discover:${scope}`,async()=>{const body=await this.#creatorCommand('read_configuration_draft',scope,{},operationIdV1());if(!hasFields(body,['status','projection']))invalid();return this.#creatorValidate(()=>validateCreatorConfiguration(body.projection))})
  }
  readRelationsView(scope: string, cursor: string | null = null): Promise<ProjectionResult<RelationsProjection>> {
    return this.#one('relations:' + scope + ':' + (cursor ?? ''), async () => {
      const command = makeReadCommand('read_character_view', scope, 'relations', cursor)
      const generation = this.#creatorGeneration
      await this.openSession()
      if (generation !== this.#creatorGeneration || !this.#csrf) throw new WorkbenchApiError('当前关系页面已变化。', { code: 'session_changed' })
      const result = envelope<RelationsProjection>(await this.#json('/commands', 'POST', command, this.#csrf, false, false, true))
      if (result.status === 'ready') {
        try { result.projection = validateRelationsProjection(result.projection, scope) }
        catch (error) { if (error instanceof RelationsContractError) invalid(); throw error }
      }
      return result
    })
  }
  async #artifactReadCommand(action: 'read_owner_project_artifact_options_v1' | 'read_owner_project_artifact_v1', scope: string, input: object) {
    validateScope(scope)
    const generation = this.#creatorGeneration
    await this.openSession()
    if (generation !== this.#creatorGeneration || !this.#csrf) throw new WorkbenchApiError('当前 Owner 会话已变化。', { code: 'session_changed' })
    const body = await this.#json('/commands', 'POST', { schema_version: 'd12.contract.v1', action, scope, purpose: 'workbench_view', audience: 'owner', operation_id: operationIdV1(), input }, this.#csrf, false, false, true)
    if (!isRecord(body) || typeof body.status !== 'string') invalid()
    if (body.status !== 'ready') {
      if (!hasFields(body, ['status'], ['problem']) || !hasFields(body.problem, ['code'], ['message', 'retryable']) || typeof body.problem.code !== 'string') invalid()
      throw new WorkbenchApiError('作品尚未取得。请核验当前权限、来源、版本和本次读取范围；没有使用缓存正文。', { code: body.problem.code, status: body.status === 'unauthorized' ? 403 : 0 })
    }
    return body
  }
  async readOwnerArtifactOptions(scope: string, projectRef: string): Promise<OwnerArtifactOptions> {
    if (!isText(projectRef)) invalid()
    const body = await this.#artifactReadCommand('read_owner_project_artifact_options_v1', scope, { project_ref: projectRef })
    if (!hasFields(body, ['status', 'projection'])) invalid()
    try { return validateOwnerArtifactOptions(body.projection, scope, projectRef) }
    catch (error) { if (error instanceof OwnerArtifactContractError) invalid(); throw error }
  }
  async readOwnerArtifactBody(scope: string, options: OwnerArtifactOptions, item: OwnerArtifactItem): Promise<OwnerArtifactBody> {
    validateOwnerArtifactOptions(options, scope, options.project_ref)
    const input = ownerArtifactReadInput(options, item)
    const body = await this.#artifactReadCommand('read_owner_project_artifact_v1', scope, input)
    if (!hasFields(body, ['status', 'projection'])) invalid()
    try { return await validateOwnerArtifactBody(body.projection, scope, input, item) }
    catch (error) { if (error instanceof OwnerArtifactContractError) invalid(); throw error }
  }
  async readProjectControlContext(scope: string, projectRef: string): Promise<ProjectControlContext> {
    if (!isText(projectRef)) throw new WorkbenchApiError('请选择当前项目。', { code: 'invalid_input' })
    const body = await this.#creatorCommand('read_project_control_context_v1', scope, { project_ref: projectRef }, operationIdV1())
    if (!hasFields(body, ['status', 'projection'])) invalid()
    try { return await validateProjectControlContext(body.projection, scope, projectRef) }
    catch (error) { if (error instanceof ProjectControlContractError) invalid(); throw error }
  }
  async readProjectControlContextV2(scope: string, projectRef: string): Promise<ProjectControlContextV2> {
    if (!isText(projectRef)) throw new WorkbenchApiError('请选择当前项目。', { code: 'invalid_input' })
    const body = await this.#creatorCommand('read_project_control_context_v2', scope, { project_ref: projectRef }, operationIdV1())
    if (!hasFields(body, ['status', 'projection'])) invalid()
    try { return await validateProjectControlContextV2(body.projection, scope, projectRef) }
    catch (error) { if (error instanceof ProjectControlContractError) invalid(); throw error }
  }
  async submitProjectControl(scope: string, action: ProjectControlAction, input: ProjectControlInput, operationId: string): Promise<ProjectControlReceipt> {
    if (!hasFields(input, action === 'resume_project_v1' ? ['project_ref', 'plan_ref', 'expected_plan_revision', 'pause_original_ref'] : ['project_ref', 'plan_ref', 'expected_plan_revision'])
      || !isText(input.project_ref) || !isText(input.plan_ref) || !isInteger(input.expected_plan_revision, 1)
      || action === 'resume_project_v1' && !isText(input.pause_original_ref)) invalid()
    const body = await this.#creatorCommand(action, scope, input, operationId)
    if (!hasFields(body, ['status', 'receipt'])) invalid()
    try { return await validateProjectControlReceipt(body.receipt, scope, action, input, operationId) }
    catch (error) { if (error instanceof ProjectControlContractError) invalid(); throw error }
  }
  async prepareOwnerMaterialSubmission(scope: string, content: string, operationId: string): Promise<string> {
    validateScope(scope); if (!UUID4.test(operationId)) invalid()
    try { validateOwnerMaterialText(content) } catch (error) { if (error instanceof OwnerTaskContractError) invalid(); throw error }
    this.#creatorPayload(OWNER_MATERIAL_ACTION,scope,{request:{text:content}},operationId,'workbench_user_action')
    return ownerMaterialInputDigest(content)
  }
  async submitOwnerMaterial(scope: string, content: string, operationId: string): Promise<OwnerTaskReceipt> {
    await this.prepareOwnerMaterialSubmission(scope,content,operationId)
    const body = await this.#creatorCommand(OWNER_MATERIAL_ACTION,scope,{request:{text:content}},operationId)
    if (!hasFields(body,['status','receipt'])) invalid()
    try { return await validateOwnerMaterialReceipt(body.receipt,operationId,content) }
    catch (error) { if (error instanceof OwnerTaskContractError) invalid(); throw error }
  }
  async readOwnerMaterialStatus(scope: string, operationId: string, inputDigest: string): Promise<OwnerMaterialStatus> {
    if (!UUID4.test(operationId) || !/^[0-9a-f]{64}$/.test(inputDigest)) invalid()
    const body = await this.#creatorCommand('read_owner_material_source_status_v1',scope,
      {owner_operation_id:operationId,input_digest:inputDigest},operationIdV1(),'workbench_view')
    if (!hasFields(body,['status','projection'])) invalid()
    try { return validateOwnerMaterialStatus(body.projection,scope,operationId,inputDigest) }
    catch (error) { if (error instanceof OwnerTaskContractError) invalid(); throw error }
  }
  async readOwnerTaskOptions(scope: string, projectRef: string): Promise<OwnerTaskOptions> {
    const body = await this.#creatorCommand('read_owner_source_note_task_options_v1', scope, { project_ref: projectRef }, operationIdV1(), 'workbench_view')
    if (!hasFields(body, ['status','projection'])) invalid()
    try { return validateOwnerTaskOptions(body.projection, scope, projectRef) }
    catch (error) { if (error instanceof OwnerTaskContractError) invalid(); throw error }
  }
  async submitOwnerSourceNoteTask(scope: string, request: OwnerTaskRequest, operationId: string): Promise<OwnerTaskReceipt> {
    try { validateOwnerTaskRequest(request, scope) } catch (error) { if (error instanceof OwnerTaskContractError) invalid(); throw error }
    const body = await this.#creatorCommand(OWNER_TASK_ACTION, scope, { request }, operationId)
    if (!hasFields(body, ['status','receipt'])) invalid()
    try { return await validateOwnerTaskReceipt(body.receipt, operationId, request) }
    catch (error) { if (error instanceof OwnerTaskContractError) invalid(); throw error }
  }
  async readOwnerSourceNoteTaskStatus(scope: string, operationId: string, inputDigest: string): Promise<OwnerTaskStatus> {
    if (!UUID4.test(operationId) || !/^[0-9a-f]{64}$/.test(inputDigest)) invalid()
    const body = await this.#creatorCommand('read_owner_source_note_task_status_v1', scope,
      { owner_operation_id: operationId, input_digest: inputDigest }, operationIdV1(), 'workbench_view')
    if (!hasFields(body, ['status','projection'])) invalid()
    try { return validateOwnerTaskStatus(body.projection, scope, operationId, inputDigest) }
    catch (error) { if (error instanceof OwnerTaskContractError) invalid(); throw error }
  }
  async readSourceCorrectionContext(scope: string, sourceId: string): Promise<SourceCorrectionContext> {
    if (!isText(sourceId) || sourceId.length > 256) throw new WorkbenchApiError('请选择当前来源记录。', { code: 'invalid_input' })
    const body = await this.#creatorCommand('read_source_correction_context_v1', scope, { source_id: sourceId }, operationIdV1())
    if (!hasFields(body, ['status', 'projection'])) invalid()
    try { return validateSourceCorrectionContext(body.projection, scope, sourceId) }
    catch (error) { if (error instanceof SourceCorrectionContractError) invalid(); throw error }
  }
  async submitSourceCorrection(scope: string, input: SourceCorrectionInput, operationId: string): Promise<SourceCorrectionReceipt> {
    const expectedDigest = await sourceCorrectionRequestDigest(scope, input, operationId)
    const body = await this.#creatorCommand('correct_or_edit', scope, input, operationId)
    if (!hasFields(body, ['status', 'receipt'])) invalid()
    try { return validateSourceCorrectionReceipt(body.receipt, input, operationId, expectedDigest) }
    catch (error) { if (error instanceof SourceCorrectionContractError) invalid(); throw error }
  }
  async readOwnerProjectContexts(scope:string):Promise<ProjectContextOptions>{
    const body=await this.#creatorCommand('read_owner_artifact_project_context_options',scope,{},operationIdV1())
    if(!hasFields(body,['status','projection']))invalid()
    return validateProjectContextOptions(body.projection,scope)
  }
  async adoptOwnerProjectContext(scope:string,options:ProjectContextOptions,item:ProjectContextItem,
    socialRole:string,normRefs:string[],operationId:string){
    validateProjectContextOptions(options,scope)
    const body=await this.#creatorCommand('domain_adopt_owner_artifact_project_context_v1',scope,
      projectContextInput(options,item,socialRole,normRefs),operationId)
    if(!hasFields(body,['status','receipt']))invalid()
    return validateProjectContextReceipt(body.receipt,operationId)
  }
  readCreatorDraft(scope:string,draftRef:string,expectedGraphRevision:number){
    if(!isText(draftRef)||!isInteger(expectedGraphRevision))throw new WorkbenchApiError('缺少真实的草稿与 Graph 定位。',{code:'invalid_input'})
    return this.#one(`creator:read:${scope}:${draftRef}:${expectedGraphRevision}`,async()=>{const body=await this.#creatorCommand('read_creator_draft',scope,{draft_ref:draftRef,expected_graph_revision:expectedGraphRevision},operationIdV1());if(!hasFields(body,['status','projection']))invalid();return this.#creatorValidate(()=>validateLegacyCreatorDraft(body.projection,scope))})
  }
  async saveCreatorDraft(scope:string,current:CreatorConfiguration,fields:SchemeValues,operationId:string){
    const body=await this.#creatorCommand('save_creator_draft',scope,draftSaveInput(current,fields),operationId)
    if(!hasFields(body,['status','receipt']))invalid()
    return this.#creatorValidate(()=>validateDraftSaveReceipt(body.receipt,current,operationId))
  }
  async schemeCommand(action:'compile_scheme'|'preview_scheme'|'activate_scheme',scope:string,input:Record<string,string>,operationId:string){
    const expected=action==='compile_scheme'?['draft_ref','budget_ref']:action==='preview_scheme'?['compiled_digest','budget_ref']:['compiled_digest','preview_seal']
    if(!hasFields(input,expected)||Object.values(input).some(value=>!isText(value)))throw new WorkbenchApiError('方案操作缺少真实的当前引用。',{code:'invalid_input'})
    const body=await this.#creatorCommand(action,scope,input,operationId);if(!hasFields(body,['status','receipt']))invalid()
    return this.#creatorValidate(()=>validateSchemeReceipt(action,body.receipt,operationId,input))
  }
  async domainInput(action:DomainInputAction,scope:string,input:DomainInputIntent,operationId:string){
    if(!DOMAIN_INPUT_ACTIONS.includes(action)||!hasFields(input,['activity_id','audience_ref','parent_budget_lease_ref','request'])||!isText(input.activity_id)||!isText(input.audience_ref)||!isText(input.parent_budget_lease_ref)||!isRecord(input.request))throw new WorkbenchApiError('领域输入缺少已注册动作和真实定位。',{code:'invalid_input'})
    const body=await this.#creatorCommand(action,scope,input,operationId);if(!hasFields(body,['status','receipt']))invalid()
    return this.#creatorValidate(()=>validateDomainInputReceipt(body.receipt,action,operationId))
  }
  setupStatus(): Promise<SetupStatus> {
    return this.#one('setup:status', async () => {
      const body = await this.#json(SETUP_PREFIX,'GET',undefined,undefined,false,true)
      try { return validateSetupStatus(body) } catch { invalid() }
    })
  }
  openSession(): Promise<void> {
    if (this.#csrf) return Promise.resolve()
    if (this.#sessionRequest) return this.#sessionRequest
    const generation = this.#generation
    const request = (async () => {
      const body = await this.#json('/session', 'GET')
      if (generation !== this.#generation) throw new WorkbenchApiError('会话在核验期间已切换，旧响应已丢弃。', { code: 'session_changed' })
      if (!hasFields(body, ['status', 'dashboard_session', 'owner_session', 'csrf_token']) || body.status !== 'ready' || body.dashboard_session !== 'authenticated' || body.owner_session !== 'unlocked' || !isText(body.csrf_token)) invalid()
      this.#csrf = body.csrf_token
    })().catch(error => { if (generation === this.#generation) this.clearSession(); throw error }).finally(() => { if (this.#sessionRequest === request) this.#sessionRequest = null })
    this.#sessionRequest = request; return request
  }
  installationStatus() {
    return this.#one('status', async () => {
      const body = await this.#json('/status', 'GET')
      if (!hasFields(body, ['schema_version', 'runtime_stage', 'reason_code']) || body.schema_version !== 'sylanne.install-status.v1' || typeof body.runtime_stage !== 'string' || !['limited', 'blocked', 'enrollment_required', 'ready', 'stopped'].includes(body.runtime_stage) || typeof body.reason_code !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(body.reason_code)) invalid()
      return { stage: body.runtime_stage as string, reason: body.reason_code }
    })
  }
  async #read(action: 'open_workspace' | 'read_character_view', scope: string, viewType?: ViewType, cursor: string | null = null) {
    const command = makeReadCommand(action, scope, viewType, cursor)
    await this.openSession(); const generation = this.#generation, csrf = this.#csrf
    if (!csrf) throw new WorkbenchApiError('当前会话未通过核验。', { code: 'unauthorized' })
    const body = await this.#json('/commands', 'POST', command, csrf)
    if (generation !== this.#generation) throw new WorkbenchApiError('会话已切换，旧内容已丢弃。', { code: 'session_changed' })
    if (isRecord(body) && body.status === 'unauthorized') { this.clearSession(); throw responseError(403, body) }
    return body
  }
  openWorkspace(scope: string): Promise<ProjectionResult<WorkspaceProjection>> {
    return this.#one(`workspace:${scope}`, async () => validateWorkspace(await this.#read('open_workspace', scope), scope))
  }
  readView(scope: string, viewType: ViewType, cursor: string | null = null): Promise<ProjectionResult<CharacterProjection>> {
    // Config/control, paid operations and contact sends are deliberately not exposed.
    if (viewType !== 'creation' && viewType !== 'd06.memory_sources.v1') return Promise.reject(new WorkbenchApiError('此界面尚未实现该视图的字段合同。', { code: 'view_unsupported' }))
    return this.#one(`view:${scope}:${viewType}:${cursor ?? ''}`, async () => validateCharacterView(await this.#read('read_character_view', scope, viewType, cursor), scope, viewType))
  }
  async #replyControlSession() {
    if (this.#replyControlCsrf) return
    await this.#one('reply-control:session', async () => {
      const body = await this.#json('/reply-control-session', 'GET')
      if (!hasFields(body, ['status', 'dashboard_session', 'owner_session', 'csrf_token'])
        || body.status !== 'ready' || body.dashboard_session !== 'authenticated'
        || body.owner_session !== 'unlocked' || !isText(body.csrf_token)) invalid()
      this.#replyControlCsrf = body.csrf_token
    })
  }
  async #replyControlCommand(command: ReturnType<typeof makeReplyControlCommand>) {
    await this.#replyControlSession()
    const csrf = this.#replyControlCsrf
    if (!csrf) throw new WorkbenchApiError('Owner 回复控制会话尚未核验。', { code: 'unauthorized' })
    return this.#json('/commands', 'POST', command, csrf)
  }
  #replyControlValidate<T>(read: () => T): T {
    try { return read() } catch (error) { if (error instanceof ReplyControlContractError) invalid(); throw error }
  }
  readReplyControls(scope: string, cursor: string | null = null): Promise<ReplyControlPage> {
    return this.#one('reply-control:list:' + scope + ':' + (cursor ?? ''), async () => {
      const body = await this.#replyControlCommand(makeReplyControlCommand('read_reply_controls', scope, cursor === null ? {} : { cursor }))
      return this.#replyControlValidate(() => validateReplyControls(body, scope))
    })
  }
  stopReply(request: StopReplyRequest): Promise<ReplyControlStatus> {
    const scope = request.namespace.bot_id + '/' + request.namespace.persona_id
    return this.#one('reply-control:stop:' + request.operation_id, async () => {
      const body = await this.#replyControlCommand(makeReplyControlCommand('stop_reply', scope, request, request.operation_id))
      const result = this.#replyControlValidate(() => validateReplyControlStatus(body, scope))
      if (result.cycle_job_ref !== request.cycle_job_ref) invalid()
      return result
    })
  }
  readReplyControlStatus(scope: string, originalRef: string): Promise<ReplyControlStatus> {
    return this.#one('reply-control:status:' + scope + ':' + originalRef, async () => {
      const body = await this.#replyControlCommand(makeReplyControlCommand('read_reply_control_status', scope, { original_ref: originalRef }))
      return this.#replyControlValidate(() => validateReplyControlStatus(body, scope))
    })
  }
  ownerChallenge(fields: OwnerFields): Promise<ChallengeResult> {
    if (this.#challengeRequest) return this.#challengeRequest
    this.#assertEnabled(); const request = makeOwnerLoginRequest(fields, this.origin)
    this.cancelOwnerChallenge(); const generation = this.#generation
    const pending = (async () => {
      const result = validateChallenge(await this.#json('/owner/challenge', 'POST', { request }), request)
      if (generation !== this.#generation) throw new WorkbenchApiError('登录已关闭或切换，旧挑战已丢弃。', { code: 'session_changed' })
      this.#challenge = result; return result
    })().finally(() => { if (this.#challengeRequest === pending) this.#challengeRequest = null })
    this.#challengeRequest = pending; return pending
  }
  ownerComplete(signatureBase64: string): Promise<void> {
    return this.#one('owner-complete', async () => {
      this.#assertEnabled(); trustedWorkbenchOrigin(this.origin)
      const current = this.#challenge
      if (!current || Date.parse(current.challenge.expires_at_utc) <= Date.now()) { this.#challenge = null; throw new WorkbenchApiError('请重新取得尚未过期的 Owner 挑战。', { code: 'challenge_expired' }) }
      if (signatureBase64.length > 128 || decodeBase64(signatureBase64).length !== 64) throw new WorkbenchApiError('请提供本机 Owner 凭据签出的 64 字节 Ed25519 签名。', { code: 'invalid_signature' })
      const generation = this.#generation
      // Never automatically replay a one-use challenge after an uncertain outcome.
      this.#challenge = null
      const body = await this.#json('/owner/complete', 'POST', { challenge: current.challenge, signature_base64: signatureBase64 })
      if (generation !== this.#generation) throw new WorkbenchApiError('登录期间会话已切换，请重新核验。', { code: 'session_changed' })
      if (!hasFields(body, ['status', 'owner_session']) || body.status !== 'authenticated' || body.owner_session !== 'unlocked') invalid()
      this.clearSession(); await this.openSession()
    })
  }
  ownerLogout(): Promise<void> {
    return this.#one('owner-logout', async () => {
      this.clearSession(); this.#assertEnabled(); trustedWorkbenchOrigin(this.origin)
      const body = await this.#json('/owner/logout', 'POST', {})
      if (!hasFields(body, ['status', 'owner_session']) || body.status !== 'ok' || body.owner_session !== 'locked') invalid()
    })
  }
  #managementValidate<T>(validate: () => T): T {
    try { return validate() } catch (error) { if (error instanceof ManagementContractError) throw new WorkbenchApiError('管理接口响应未通过版本或字段校验。', {code:'invalid_response'}); throw error }
  }
  async #managementPost(path: string, payload: object): Promise<unknown> {
    const generation = this.#managementGeneration
    await this.openSession()
    if (generation !== this.#managementGeneration) throw new WorkbenchApiError('管理页面已切换。', {code:'session_changed'})
    const csrf = this.#csrf
    if (!csrf) throw new WorkbenchApiError('当前会话未通过核验。', {code:'unauthorized'})
    return this.#json(`${MANAGEMENT_PREFIX}${path}`, 'POST', payload, csrf, true)
  }
  #requireCapability(caps: ManagementCapabilities, kind: 'logs' | 'settings', write = false) {
    if (!this.#managementCaps || JSON.stringify(this.#managementCaps) !== JSON.stringify(caps) || !caps.capabilities[kind].available || write && !caps.capabilities.settings.writable_fields.includes('enabled'))
      throw new WorkbenchApiError('当前服务未授权此管理能力。请重新核验接口。', {code:'capability_unavailable'})
  }
  managementCapabilities(): Promise<ManagementCapabilities> {
    return this.#one('management:capabilities', async () => {
      this.#managementCaps = null
      try {
        const body = await this.#managementPost('/capabilities', managementRequest())
        const caps = this.#managementValidate(() => validateCapabilities(body)); this.#managementCaps = structuredClone(caps); return caps
      } catch (error) {
        if (error instanceof WorkbenchApiError && [404,501].includes(error.status)) throw new WorkbenchApiError('当前后端尚未实现此版本的日志与设置接口。', {code:'capability_unsupported',status:error.status})
        throw error
      }
    })
  }
  queryLogs(caps: ManagementCapabilities, filter: LogFilter, cursor: string | null = null): Promise<LogPage> {
    this.#requireCapability(caps,'logs'); this.#managementValidate(() => validateLogFilter(filter,cursor))
    return this.#one(`management:logs:${caps.access_generation}:${JSON.stringify(filter)}:${cursor ?? ''}`, async () => {
      const body = await this.#managementPost('/logs/query', managementRequest({...binding(caps),filter:{...filter},cursor,limit:LOG_LIMIT}))
      this.#requireCapability(caps,'logs'); return this.#managementValidate(() => validateLogPage(body,caps))
    })
  }
  readSettings(caps: ManagementCapabilities): Promise<SettingsSnapshot> {
    this.#requireCapability(caps,'settings')
    return this.#one(`management:settings:${caps.access_generation}`, async () => {
      const body = await this.#managementPost('/settings/read', managementRequest(binding(caps)))
      this.#requireCapability(caps,'settings'); return this.#managementValidate(() => validateSettings(body,caps))
    })
  }
  updateSettings(caps: ManagementCapabilities, current: SettingsSnapshot, enabled: boolean): Promise<SettingsReceipt> {
    this.#requireCapability(caps,'settings',true)
    this.#managementValidate(() => validateSettings(current,caps))
    if (typeof enabled !== 'boolean' || !current.writable_fields.includes('enabled')) throw new WorkbenchApiError('配置值或写入权限无效。', {code:'invalid_input'})
    // Never coalesce different writes or replay an uncertain mutation.
    if (this.#pending.has('management:save')) return Promise.reject(new WorkbenchApiError('已有设置保存请求，等待结果后再操作。', {code:'action_pending'}))
    return this.#one('management:save', async () => {
      const payload = managementRequest({...binding(caps),expected_revision:current.revision,patch:{enabled}})
      const body = await this.#managementPost('/settings/update', payload)
      this.#requireCapability(caps,'settings',true); return this.#managementValidate(() => validateReceipt(body,caps,current,payload.operation_id))
    })
  }
  sendContact(): Promise<never> {
    return Promise.reject(new WorkbenchApiError(CONTACT_HOLD ? 'HOLD：发送归属与在途状态尚未确认，此界面没有发送能力。' : '发送能力未开放。', { code: 'contact_hold' }))
  }
}
