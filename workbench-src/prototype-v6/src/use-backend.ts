import { computed, onBeforeUnmount, onMounted, reactive, ref, toRaw, watch } from 'vue'
import { createManagement } from './use-management.ts'
import { operationIdV1 } from './api/browser-crypto.ts'
import { UUID4 } from './api/contract.ts'
import { validateSourceInspectionWorkflowInput, sourceInspectionWorkflowInput, sameSourceInspectionWorkflowInput, type SourceInspectionWorkflowInput, type SourceInspectionWorkflowView } from './api/source-owner-read.ts'
import {pendingBeta1Attempts} from './api/beta1-owner.ts'
import { createSetup } from './use-setup.ts'
import { createConfiguration } from './use-configuration.ts'
import { ConfigurationApi } from './api/configuration.ts'
import { createCreatorConfiguration } from './use-creator-configuration.ts'
import { WorkbenchApi, WorkbenchApiError, HTTPS_REQUIRED_MESSAGE, type FetchLike } from './api/client.ts'
import { validateScope, type CharacterProjection, type WorkspaceProjection, type ViewType, type OwnerFields, type ChallengeResult, type ProjectionStatus } from './api/contract.ts'
export type ContentState = 'idle' | 'loading' | 'empty' | 'ready' | 'unauthorized' | 'disabled' | 'error' | 'unavailable' | 'stale' | 'partial'
export type AuthOperation = 'none' | 'session' | 'challenge' | 'complete' | 'logout'
export interface LoadState<T> { status: ContentState; data: T | null; message: string; pending?: boolean }
export interface BackendState {
  mode: 'offline' | 'same-origin'; auth: 'offline' | 'checking' | 'locked' | 'authenticated' | 'error' | 'https_required'
  dashboard: 'unknown' | 'authenticated' | 'missing'; owner: 'unknown' | 'unlocked' | 'locked'
  busy: boolean; authOperation: AuthOperation; logoutStatus: 'idle' | 'loading' | 'confirmed' | 'unconfirmed'
  error: string; errorCode: string; scope: string; challenge: ChallengeResult | null
  workspace: LoadState<WorkspaceProjection>; view: LoadState<CharacterProjection>; viewType: ViewType | null
}
export const VIEW_LABELS: Record<ViewType, string> = { overview: '角色概览', creation: '人格方案', relations: '关系', memory: '记忆', 'd06.memory_sources.v1': '记忆来源', cognition: '认知', action: '行动', expression: '表达', diagnostics: '诊断', lifecycle: '生命周期' }
const stateMessages: Partial<Record<ProjectionStatus, string>> = { loading: '后端仍在读取，请手动重试。', empty: '本次读取没有返回记录。', unauthorized: '当前会话没有读取权限。', unavailable: '当前功能尚未接入。', stale: '视图已过期，请重新读取。', partial: '读取不完整，请手动重试。' }
/** Defaults to an offline frontend preview. Only /session can establish authorization. */
export function useBackend(options: { enabled?: boolean; fetchImpl?: FetchLike; origin?: string; timeoutMs?: number } = {}) {
  const enabled = options.enabled ?? import.meta.env.VITE_SYLANNE_BACKEND === 'same-origin'
  const api = new WorkbenchApi({ ...options, enabled })
  const state = reactive<BackendState>({ mode: enabled ? 'same-origin' : 'offline', auth: enabled ? 'locked' : 'offline', dashboard: 'unknown', owner: 'unknown', busy: false, authOperation: 'none', logoutStatus: 'idle', error: '', errorCode: '', scope: '', challenge: null, viewType: null,
    workspace: { status: enabled ? 'idle' : 'disabled', data: null, message: enabled ? '等待核验会话和角色范围。' : '离线预览，未读取工作台目录。' },
    view: { status: enabled ? 'idle' : 'disabled', data: null, message: enabled ? '还没有读取角色内容。' : '离线预览，未读取真实角色内容。' } })
  const networkAvailable = ref(typeof navigator === 'undefined' || navigator.onLine !== false)
  const viewPaging = reactive({ page: 0 })
  const sourceReadGeneration = ref(0)
  const pendingOnboardingRecovery=ref<import('./api/client.ts').PendingOnboardingAttempt|null>(null)
  const onboardingRecovery={pending:pendingOnboardingRecovery}
  const laborRebuild={pending:ref<import('./api/character-labor-rebuild.ts').LaborRebuildAttempt|null>(null)}
  const pendingProjectControl = ref<import('./api/project-control.ts').PendingProjectControl | null>(null)
  const pendingSourceCorrection = ref<import('./api/source-correction.ts').PendingSourceCorrection | null>(null)
  const commitmentAttempts=reactive(new Map<string,import('./api/commitment-communication.ts').CommitmentCommandAttempt>())
  const commitmentApprovals=reactive(new Map<string,import('./api/commitment-communication.ts').ApprovedCommitmentScope>())
  const preparedCommitmentActions=reactive(new Map<string,import('./api/commitment-communication.ts').CommitmentPreparedAction>())
  const fulfillmentAttempts=reactive(new Map<string,import('./api/commitment-fulfillment.ts').FulfillmentAttempt>())
  const fulfillmentViews=reactive(new Map<string,import('./api/commitment-fulfillment.ts').CommitmentTransitionView>())
  const fulfillmentApprovals=reactive(new Map<string,import('./api/commitment-fulfillment.ts').ApprovedTermsScope>())
  const pendingFulfillment=computed({get:()=>fulfillmentAttempts.get(state.scope)??null,set:(value:import('./api/commitment-fulfillment.ts').FulfillmentAttempt|null)=>{if(value)fulfillmentAttempts.set(value.scope,value);else fulfillmentAttempts.delete(state.scope)}})
  const currentFulfillment=computed({get:()=>fulfillmentViews.get(state.scope)??null,set:(value:import('./api/commitment-fulfillment.ts').CommitmentTransitionView|null)=>{if(value)fulfillmentViews.set(state.scope,value);else fulfillmentViews.delete(state.scope)}})
  const approvedTerms=computed({get:()=>fulfillmentApprovals.get(state.scope)??null,set:(value:import('./api/commitment-fulfillment.ts').ApprovedTermsScope|null)=>{if(value)fulfillmentApprovals.set(state.scope,value);else fulfillmentApprovals.delete(state.scope)}})
  const preparedCommitmentAction=computed(()=>preparedCommitmentActions.get(state.scope)??null)
  const pendingCommitment=computed({get:()=>commitmentAttempts.get(state.scope)??null,set:(value:import('./api/commitment-communication.ts').CommitmentCommandAttempt|null)=>{if(value)commitmentAttempts.set(value.scope,value);else commitmentAttempts.delete(state.scope)}})
  const approvedCommitment=computed({get:()=>commitmentApprovals.get(state.scope)??null,set:(value:import('./api/commitment-communication.ts').ApprovedCommitmentScope|null)=>{if(value)commitmentApprovals.set(state.scope,value);else commitmentApprovals.delete(state.scope)}})
  const singleEventAttempts=reactive(new Map<string,import('./api/single-event-growth.ts').SingleEventGrowthAttempt>())
  const singleEventViews=reactive(new Map<string,import('./api/single-event-growth.ts').SingleEventGrowthView>())
  const pendingSingleEvent=computed(()=>singleEventAttempts.get(state.scope)??null)
  const currentSingleEvent=computed(()=>singleEventViews.get(state.scope)??null)
  let singleEventGeneration=0
  watch(()=>[state.scope,state.auth,state.owner],()=>{++singleEventGeneration;singleEventAttempts.clear();singleEventViews.clear()},{flush:'sync'})
  const growthReviewAttempts = reactive(new Map<string, import('./api/growth-review.ts').GrowthReviewAttempt>())
  const pendingGrowthReview = computed({
    get: () => growthReviewAttempts.get(state.scope) ?? null,
    set: (value: import('./api/growth-review.ts').GrowthReviewAttempt | null) => {
      if (value) growthReviewAttempts.set(value.scope,value)
      else growthReviewAttempts.delete(state.scope)
    },
  })
  watch(()=>[state.scope,state.auth,state.owner],()=>{commitmentAttempts.clear();commitmentApprovals.clear();preparedCommitmentActions.clear();fulfillmentAttempts.clear();fulfillmentViews.clear();fulfillmentApprovals.clear()},{flush:'sync'})
  const sourceErasureAttempts = reactive(new Map<string, import('./api/source-erasure.ts').SourceErasureAttempt>())
  const pendingSourceErasure = computed({
    get: () => sourceErasureAttempts.get(state.scope) ?? null,
    set: (value: import('./api/source-erasure.ts').SourceErasureAttempt | null) => {
      if (value) sourceErasureAttempts.set(value.scope,value)
      else sourceErasureAttempts.delete(state.scope)
    },
  })
  const ownerTaskAttempts = reactive(new Map<string, import('./api/owner-source-note-task.ts').PendingOwnerTask>())
  const ownerMaterialAttempts = reactive(new Map<string, import('./api/owner-source-note-task.ts').PendingOwnerTask>())
  const requiresHttps = computed(() => enabled && state.errorCode==='https_required')
  const transportReady = () => enabled && api.transportAvailable && networkAvailable.value && !requiresHttps.value
  const setup = createSetup(api, () => transportReady() && !state.busy, fail)
  const configuration = createConfiguration(new ConfigurationApi({...options,enabled}), () => transportReady() && !state.busy, fail)
  const creator = createCreatorConfiguration(api, () => transportReady() && state.auth==='authenticated'&&state.dashboard==='authenticated'&&state.owner==='unlocked'&&!state.busy&&scopeValid.value, () => state.scope, fail)
  const management = createManagement(api, () => transportReady() && state.auth === 'authenticated' && state.dashboard === 'authenticated' && state.owner === 'unlocked' && !state.busy && api.hasSession, fail)
  watch(() => [state.auth, state.dashboard, state.owner, state.busy] as const, () => {
    if(state.auth!=='authenticated'||state.owner!=='unlocked'||state.dashboard!=='authenticated')pendingBeta1Attempts.clear()
    if (state.auth !== 'authenticated' || state.dashboard !== 'authenticated' || state.owner !== 'unlocked' || state.busy) management.invalidate()
  }, { flush: 'sync' })
  let revision = 0, viewRevision = 0, workspaceRevision = 0, authRevision = 0, activeView: ViewType | null = null, selectedEntry = ''
  // Retain invalidated jobs until settlement so a reopened page cannot reuse the API's old coalesced promise.
  const workspaceJobs = new Map<string, { revision: number; workspaceRevision: number; promise: Promise<void> }>()
  const viewJobs = new Set<string>()
  function invalidateView(preserveRuntime = false) {
    ++sourceReadGeneration.value
    if (!preserveRuntime) { setup.invalidate(); configuration.invalidate(); creator.invalidate() }
    management.invalidate(preserveRuntime)
    ++viewRevision; ++workspaceRevision; activeView = null; state.viewType = null; viewPaging.page = 0
    state.view = { status: enabled ? 'idle' : 'disabled', data: null, message: enabled ? '还没有读取当前档案。' : '离线预览，未读取真实角色内容。' }
    if (state.workspace.status === 'loading') state.workspace = { status: 'idle', data: null, message: '页面已切换，旧目录响应已作废。请重新读取。' }
  }
  function invalidateNavigation() { clearContent() }
  function selectArchive(entryId: string) { if (entryId === selectedEntry) return; selectedEntry = entryId; invalidateView() }
  function clearContent() { invalidateView(); state.workspace = { status: enabled ? 'idle' : 'disabled', data: null, message: enabled ? '等待核验会话和角色范围。' : '离线预览，未读取工作台目录。' } }
  function errorText(error: unknown) { return error instanceof WorkbenchApiError ? error.code === 'invalid_response' ? '返回信息未通过校验，未显示角色信息。' : error.message : '输入或返回数据未通过核验。请检查安装记录并重试。' }
  function finishAuth(token: number) { if (token === authRevision) { state.busy = false; state.authOperation = 'none' } }
  function startAuth(operation: AuthOperation) {
    const token = ++authRevision; state.busy = true; state.authOperation = operation; state.error = ''; state.errorCode = ''; return token
  }
  function revokeLocal(owner: BackendState['owner'] = 'locked') {
    ++revision; ++authRevision; api.clearSession(); clearContent(); state.challenge = null; pendingSourceCorrection.value = null; sourceErasureAttempts.clear(); growthReviewAttempts.clear(); commitmentAttempts.clear(); commitmentApprovals.clear(); preparedCommitmentActions.clear(); fulfillmentAttempts.clear(); fulfillmentViews.clear(); fulfillmentApprovals.clear(); pendingProjectControl.value = null
    state.auth = enabled ? requiresHttps.value?'https_required':'locked' : 'offline'; state.owner = owner; state.busy = false; state.authOperation = 'none'
  }
  function fail(error: unknown) {
    state.error = errorText(error); state.errorCode = error instanceof WorkbenchApiError ? error.code : 'invalid_input'
    if (error instanceof WorkbenchApiError && error.code==='https_required') { clearContent(); return }
    if (error instanceof WorkbenchApiError && [401, 403].includes(error.status)) {
      revokeLocal(); state.dashboard = error.code === 'host_session_missing' ? 'missing' : error.code === 'owner_session_locked' ? 'authenticated' : 'unknown'
      state.workspace = { status: 'unauthorized', data: null, message: state.error }
      state.view = { status: 'unauthorized', data: null, message: state.error }
    }
  }
  async function checkSession(): Promise<boolean> {
    if (state.busy || !networkAvailable.value) return false
    if (requiresHttps.value) { fail(new WorkbenchApiError(HTTPS_REQUIRED_MESSAGE,{code:'https_required'})); state.auth='https_required'; return false }
    if (!enabled) { fail(new WorkbenchApiError('离线界面预览：后端未连接，身份尚未核验。', { code: 'offline' })); return false }
    clearContent(); state.challenge = null; state.auth = 'checking'; state.dashboard = 'unknown'; state.owner = 'unknown'; state.logoutStatus = 'idle'; api.clearSession()
    const current = ++revision, token = startAuth('session')
    try { await api.openSession(); if (current !== revision || token !== authRevision) return false; state.auth = 'authenticated'; state.dashboard = 'authenticated'; state.owner = 'unlocked'; return true }
    catch (error) { if (current === revision && token === authRevision) { state.auth = error instanceof WorkbenchApiError&&error.code==='https_required'?'https_required':error instanceof WorkbenchApiError && [401, 403].includes(error.status) ? 'locked' : 'error'; fail(error) } return false }
    finally { finishAuth(token) }
  }
  function setScope(scope: string) {
    const value = scope.trim(); if (value === state.scope) return
    ++revision; clearContent(); state.scope = value; state.error = ''; state.errorCode = ''
    if (state.busy && state.authOperation !== 'logout') { revokeLocal('unknown') }
  }
  async function beginOwnerLogin(fields: OwnerFields): Promise<boolean> {
    if (state.busy || !networkAvailable.value) return false
    if (requiresHttps.value) { fail(new WorkbenchApiError(HTTPS_REQUIRED_MESSAGE,{code:'https_required'})); return false }
    clearContent(); state.challenge = null; state.auth = enabled ? 'locked' : 'offline'; state.owner = 'locked'; state.logoutStatus = 'idle'
    const current = ++revision, token = startAuth('challenge')
    try { const challenge = await api.ownerChallenge(fields); if (current !== revision || token !== authRevision) return false; state.challenge = challenge; state.dashboard = 'authenticated'; return true }
    catch (error) { if (current === revision && token === authRevision) fail(error); return false }
    finally { finishAuth(token) }
  }
  async function completeOwnerLogin(signature: string): Promise<boolean> {
    if (state.busy || !networkAvailable.value) return false
    if (requiresHttps.value) { fail(new WorkbenchApiError(HTTPS_REQUIRED_MESSAGE,{code:'https_required'})); return false }
    clearContent(); state.challenge = null; state.auth = enabled ? 'checking' : 'offline'
    const current = ++revision, token = startAuth('complete')
    try {
      await api.ownerComplete(signature) // Includes a fresh, independently validated GET /session.
      if (current !== revision || token !== authRevision) return false
      state.auth = 'authenticated'; state.dashboard = 'authenticated'; state.owner = 'unlocked'; return true
    } catch (error) { if (current === revision && token === authRevision) { state.auth = enabled ? 'locked' : 'offline'; state.owner = 'locked'; fail(error) } return false }
    finally { finishAuth(token) }
  }
  function dismissLogin() {
    if (state.auth === 'authenticated' && !state.busy) { state.challenge = null; state.error = ''; state.errorCode = ''; return }
    if (state.authOperation === 'logout') return
    revokeLocal('unknown'); state.error = ''; state.errorCode = ''
  }
  function cancelChallenge() { if (state.auth === 'authenticated' && !state.challenge && !state.busy) return; revokeLocal(); state.error = ''; state.errorCode = '' }
  async function logout(): Promise<boolean> {
    if (state.authOperation === 'logout') return false
    // Lock immediately, including during pending verification or signature completion.
    revokeLocal(); state.logoutStatus = enabled ? 'loading' : 'idle'
    if (!enabled) { state.error = ''; state.errorCode = ''; return false }
    if (requiresHttps.value) { state.logoutStatus='idle'; fail(new WorkbenchApiError(HTTPS_REQUIRED_MESSAGE,{code:'https_required'})); return false }
    const token = startAuth('logout')
    try { await api.ownerLogout(); if (token !== authRevision) return false; state.logoutStatus = 'confirmed'; return true }
    catch (error) { if (token === authRevision) { fail(error); state.logoutStatus = 'unconfirmed' } return false }
    finally { finishAuth(token) }
  }
  const scopeValid = computed(() => { try { validateScope(state.scope); return true } catch { return false } })
  // Runtime readiness permits an attempt only; D12 still checks actual Graph authorization on every command.
  const runtimeReadable = computed(() => {
    const runtime = management.state.runtime
    return runtime.status === 'ready' && !!runtime.data && (runtime.data.stage === 'ready' || runtime.data.stage === 'limited' && !['disabled', 'not_started'].includes(runtime.data.reason))
  })
  const canRead = computed(() => transportReady() && state.auth === 'authenticated' && scopeValid.value && runtimeReadable.value && !state.busy)
  watch(runtimeReadable, readable => {
    if (readable) return
    ++viewRevision; ++workspaceRevision; activeView = null; state.viewType = null; viewPaging.page = 0
    state.workspace = { status: enabled ? 'idle' : 'disabled', data: null, message: '实际运行状态尚未允许角色读取。' }
    state.view = { status: enabled ? 'idle' : 'disabled', data: null, message: '请先核验实际运行状态，再发起角色读取。' }
  }, { flush: 'sync' })
  const canSignedLogin = computed(() => transportReady() && !state.busy)
  async function loadWorkspace() {
    if (!canRead.value) return
    const current = revision, scope = state.scope, workspaceCurrent = workspaceRevision
    const existing = workspaceJobs.get(scope)
    if (existing) {
      if (existing.revision === current && existing.workspaceRevision === workspaceCurrent) await existing.promise
      else state.workspace = { status: 'stale', data: null, message: '上一页的目录请求尚未结束，旧响应不会回填。结束后请手动重试。' }
      return
    }
    state.error = ''; state.workspace = { status: 'loading', data: null, message: '正在读取可用功能。', pending: true }
    const job = { revision: current, workspaceRevision: workspaceCurrent, promise: Promise.resolve() }
    job.promise = (async () => {
      try { const result = await api.openWorkspace(scope); if (current !== revision || workspaceCurrent !== workspaceRevision) return; state.workspace = { status: result.status as ContentState, data: result.projection ?? null, message: stateMessages[result.status] ?? '' } }
      catch (error) { if (current === revision && workspaceCurrent === workspaceRevision) { fail(error); state.workspace = { status: error instanceof WorkbenchApiError && [401, 403].includes(error.status) ? 'unauthorized' : 'error', data: null, message: errorText(error) } } }
      finally { if (workspaceJobs.get(scope) === job) workspaceJobs.delete(scope) }
    })()
    workspaceJobs.set(scope, job); await job.promise
  }
  async function openWorkspace() { if (!canRead.value || state.workspace.pending) return; invalidateView(true); await loadWorkspace() }
  const canNextView = computed(() => canRead.value && !state.view.pending && ['ready', 'empty'].includes(state.view.status) && !!state.view.data?.next_cursor)
  async function readView(viewType: ViewType, next = false) {
    if (!canRead.value || state.view.pending && activeView === viewType || next && (!canNextView.value || state.viewType !== viewType)) return
    const previous = next ? state.view.data : null, cursor = previous?.next_cursor ?? null
    const page = next ? viewPaging.page + 1 : 1
    if (!next) viewPaging.page = 0
    activeView = viewType; state.viewType = viewType; const viewCurrent = ++viewRevision
    if (!state.workspace.data) {
      state.view = { status: 'loading', data: null, message: '正在核验可用功能。', pending: true }
      await loadWorkspace()
      if (viewCurrent !== viewRevision) return
      if (!state.workspace.data || !canRead.value) { state.view = { status: state.workspace.status === 'ready' ? 'disabled' : state.workspace.status, data: null, message: state.workspace.message }; return }
    }
    if (!state.workspace.data.views.some(v => v.view_type === viewType && v.status === 'readable_not_loaded')) { state.view = { status: 'unavailable', data: null, message: '当前账户暂时无法查看此项信息。' }; return }
    const current = revision, scope = state.scope, key = `${scope}:${viewType}`
    if (viewJobs.has(key)) { state.view = { status: 'stale', data: null, message: '上一页的相同字段请求尚未结束，旧响应不会回填。结束后请手动重试。' }; return }
    state.error = ''; state.view = { status: 'loading', data: null, message: '正在读取角色信息。', pending: true }; viewJobs.add(key)
    try {
      const result = await api.readView(scope, viewType, cursor); if (current !== revision || viewCurrent !== viewRevision) return
      if (previous && result.projection && (result.projection.access_generation !== previous.access_generation || result.projection.snapshot_epoch !== previous.snapshot_epoch)) {
        viewPaging.page = 0; state.view = { status: 'stale', data: null, message: '分页的访问版本或快照已变化，请从第一页重新读取。' }; return
      }
      viewPaging.page = result.projection ? page : 0
      const rows = result.projection?.data.candidates ?? result.projection?.data.sources
      state.view = { status: result.status === 'ready' && rows?.length === 0 ? 'empty' : result.status as ContentState, data: result.projection ?? null, message: result.status === 'ready' && rows?.length === 0 ? '本次读取没有返回记录。' : stateMessages[result.status] ?? '' }
    } catch (error) { if (current === revision && viewCurrent === viewRevision) { viewPaging.page = 0; fail(error); state.view = { status: error instanceof WorkbenchApiError && [401, 403].includes(error.status) ? 'unauthorized' : 'error', data: null, message: errorText(error) } } }
    finally { viewJobs.delete(key) }
  }
  function leavePage() { revokeLocal('unknown'); state.dashboard = 'unknown'; state.error = ''; state.errorCode = '' }
  function visibility() { if (document.hidden) leavePage() }
  function networkLost() {
    networkAvailable.value = false
    if (!enabled) return
    leavePage(); state.errorCode = 'network_offline'; state.error = '网络已断开，保护内容和本页会话已锁定。连接恢复后请重新核验会话。'
  }
  function networkRestored() {
    networkAvailable.value = true
    if (enabled && state.errorCode === 'network_offline') state.error = '网络连接已恢复，请重新核验会话。'
  }
  onMounted(() => {
    document.addEventListener('visibilitychange', visibility); window.addEventListener('pagehide', leavePage); window.addEventListener('popstate', leavePage)
    window.addEventListener('offline', networkLost); window.addEventListener('online', networkRestored)
    if (!networkAvailable.value) networkLost()
  })
  onBeforeUnmount(() => {
    leavePage(); document.removeEventListener('visibilitychange', visibility); window.removeEventListener('pagehide', leavePage); window.removeEventListener('popstate', leavePage)
    window.removeEventListener('offline', networkLost); window.removeEventListener('online', networkRestored)
  })
  type InspectionAttempt = { scope: string; operation_id: string; input: SourceInspectionWorkflowInput | null;
    request_digest: string | null; view: SourceInspectionWorkflowView | null; status: 'unknown' | SourceInspectionWorkflowView['state'] }
  const inspectionAttempts = reactive(new Map<string, InspectionAttempt>())
  const inspectionActive = ref(false), inspectionMessage = ref('')
  let inspectionGeneration = 0
  const inspectionAttempt = computed(() => inspectionAttempts.get(state.scope) ?? null)
  const inspectionCanRequest = computed(() => transportReady() && scopeValid.value && !state.busy && !inspectionActive.value)
  watch(() => [state.scope, state.auth, state.owner], () => {
    ++inspectionGeneration; inspectionMessage.value = ''
    for (const attempt of inspectionAttempts.values()) attempt.view = null
  }, { flush: 'sync' })
  async function inspectionRequest(kind: 'accept' | 'read', originalId: string) {
    if (!inspectionCanRequest.value) return
    if (!UUID4.test(originalId)) { inspectionMessage.value = '请填写原维护操作的规范 UUID4。'; return }
    const scope = state.scope, token = inspectionGeneration
    let attempt = inspectionAttempts.get(scope)
    if (attempt && attempt.operation_id !== originalId && attempt.status !== 'completed') {
      inspectionMessage.value = '当前原维护尚未确认完成，须先查询此原操作。'; return
    }
    if (!attempt || attempt.operation_id !== originalId) {
      inspectionAttempts.set(scope, { scope, operation_id: originalId, input: null, request_digest: null, view: null, status: 'unknown' })
      attempt = inspectionAttempts.get(scope)!
    }
    if (kind === 'accept' && !attempt.input) return
    inspectionActive.value = true; inspectionMessage.value = kind === 'read' ? '正在只读查询原维护；不会重发受理或推进操作。'
      : '正在一次受理所选范围、暂停与恢复选择。受理后 Host 暂停可能使本页断开。'
    try {
      const view = kind === 'read' ? await api.readSourceInspectionMigration(scope, originalId)
        : await api.acceptSourceInspectionMigration(scope, originalId, attempt.input!)
      if (token !== inspectionGeneration || scope !== state.scope) { attempt.status = 'unknown'; return }
      if (!view) { attempt.status = 'unknown'; attempt.view = null; inspectionMessage.value = '受理结果待确认。保留三个原 ID 与完整输入；恢复连接后只查询原操作，不重发受理。'; return }
      if (attempt.request_digest && attempt.request_digest !== view.request_digest
          || attempt.input && !sameSourceInspectionWorkflowInput(attempt.input, sourceInspectionWorkflowInput(view))) {
        throw new WorkbenchApiError('原维护输入或摘要变化。', { code: 'invalid_response' })
      }
      attempt.input = sourceInspectionWorkflowInput(view); attempt.request_digest = view.request_digest; attempt.view = view; attempt.status = view.state
      inspectionMessage.value = view.state === 'completed' ? view.resume_on_complete ? '迁移 EOF 与 Host active 均已由后端确认；可另行独立重读来源。'
        : '迁移 EOF 已确认，按原选择保持暂停。本页不代替正式恢复控制面。'
        : view.state === 'held' ? '原维护已 HOLD。后台不会自动重试；暂停期间本页可能离线，需要正式运维恢复入口。'
        : '后台按已受理的原范围与期限有界执行。预计暂停期间断开；网络恢复后请手动查询此原操作。'
    } catch (error) {
      attempt.status = 'unknown'; attempt.view = null
      if (token !== inspectionGeneration || scope !== state.scope) return
      if (error instanceof WorkbenchApiError && [401, 403].includes(error.status)) fail(error)
      inspectionMessage.value = error instanceof WorkbenchApiError && error.code === 'inspection_migration_not_found'
        ? '尚未找到此原维护。保留原 UUID 与三个 ID，只查询原操作；不会换号或重新受理。'
        : '连接或受理结果尚未确认。Host 可能正在暂停；保留原 UUID 与完整输入，恢复连接后只查询原操作。'
    } finally { inspectionActive.value = false }
  }
  const inspectionMaintenance = {
    attempt: inspectionAttempt, active: inspectionActive, message: inspectionMessage, canRequest: inspectionCanRequest,
    async accept(selection: Omit<SourceInspectionWorkflowInput, 'pause_operation_id' | 'resume_operation_id'>) {
      if (!inspectionCanRequest.value || inspectionAttempt.value) return
      const originalId = operationIdV1(), input: SourceInspectionWorkflowInput = { ...selection, target_refs: [...selection.target_refs],
        pause_operation_id: operationIdV1(), resume_operation_id: selection.resume_on_complete ? operationIdV1() : null }
      try {
        validateSourceInspectionWorkflowInput(input, state.scope, originalId)
        const now = Date.now() / 1000
        if (input.deadline_utc <= now || input.deadline_utc > now + 3600) throw new Error('维护期限应在未来一小时内。')
      } catch (error) { inspectionMessage.value = error instanceof Error ? error.message : '请核对维护受理输入。'; return }
      inspectionAttempts.set(state.scope, { scope: state.scope, operation_id: originalId, input, request_digest: null, view: null, status: 'unknown' })
      await inspectionRequest('accept', originalId)
    },
    read: (originalId: string) => inspectionRequest('read', originalId.trim()),
    newOperation() { if (inspectionCanRequest.value && inspectionAttempt.value?.status === 'completed') { inspectionAttempts.delete(state.scope); inspectionMessage.value = '' } },
  }
  const sources = {
    generation: sourceReadGeneration,
    async page(scope: string, cursor: string | null = null, pageSize = 32) { try { return await api.readOwnerSourcePage(scope, cursor, pageSize) } catch (error) { fail(error); throw error } },
    async detail(scope: string, selected: import('./api/source-owner-read.ts').OwnerSourceMetadata) { try { return await api.readOwnerSourceDetail(scope, selected) } catch (error) { fail(error); throw error } },
  }
  const relations = {
    async read(scope: string, cursor: string | null = null) { try { return await api.readRelationsView(scope, cursor) } catch (error) { fail(error); throw error } },
  }
  const artifacts = {
    async options(scope: string, projectRef: string) { try { return await api.readOwnerArtifactOptions(scope, projectRef) } catch (error) { fail(error); throw error } },
    async read(scope: string, options: import('./api/owner-artifact.ts').OwnerArtifactOptions, item: import('./api/owner-artifact.ts').OwnerArtifactItem) {
      try { return await api.readOwnerArtifactBody(scope, options, item) } catch (error) { fail(error); throw error }
    },
  }
  const projectControls = {
    pending: pendingProjectControl,
    async readV2(scope: string, projectRef: string) { try { return await api.readProjectControlContextV2(scope, projectRef) } catch (error) { fail(error); throw error } },
    async read(scope: string, projectRef: string) { try { return await api.readProjectControlContext(scope, projectRef) } catch (error) { fail(error); throw error } },
    async submit(scope: string, action: import('./api/project-control.ts').ProjectControlAction, input: import('./api/project-control.ts').ProjectControlInput, operationId: string) {
      try { return await api.submitProjectControl(scope, action, input, operationId) } catch (error) { fail(error); throw error }
    },
  }
  const sourceErasures = {
    pending: pendingSourceErasure,
    async submit(attempt: import('./api/source-erasure.ts').SourceErasureAttempt) {
      invalidateView(true)
      try { return await api.eraseSource(attempt) } catch (error) { fail(error); throw error } finally { ++sourceReadGeneration.value }
    },
  }
  const sourceCorrections = {
    pending: pendingSourceCorrection,
    async read(scope: string, sourceId: string) { try { return await api.readSourceCorrectionContext(scope, sourceId) } catch (error) { fail(error); throw error } },
    async submit(scope: string, input: import('./api/source-correction.ts').SourceCorrectionInput, operationId: string) {
      ++sourceReadGeneration.value
      try { return await api.submitSourceCorrection(scope, input, operationId) } catch (error) { fail(error); throw error } finally { ++sourceReadGeneration.value }
    },
  }
  const ownerMaterials = {
    attempts: ownerMaterialAttempts,
    prepare: (scope:string,content:string,operationId:string) => api.prepareOwnerMaterialSubmission(scope,content,operationId),
    async submit(scope:string,content:string,operationId:string) {
      try { return await api.submitOwnerMaterial(scope,content,operationId) } catch(error) { fail(error); throw error }
    },
    async status(scope:string,operationId:string,inputDigest:string) {
      try { return await api.readOwnerMaterialStatus(scope,operationId,inputDigest) } catch(error) { fail(error); throw error }
    },
  }
  const ownerTasks = {
    attempts: ownerTaskAttempts,
    async options(scope: string, projectRef: string) { try { return await api.readOwnerTaskOptions(scope, projectRef) } catch (error) { fail(error); throw error } },
    async submit(scope: string, request: import('./api/owner-source-note-task.ts').OwnerTaskRequest, operationId: string) {
      try { return await api.submitOwnerSourceNoteTask(scope, request, operationId) } catch (error) { fail(error); throw error }
    },
    async status(scope: string, operationId: string, inputDigest: string) {
      try { return await api.readOwnerSourceNoteTaskStatus(scope, operationId, inputDigest) } catch (error) { fail(error); throw error }
    },
  }
  const replyControls = { read: (scope: string, cursor: string | null = null) => api.readReplyControls(scope, cursor), stop: (request: import('./api/reply-controls.ts').StopReplyRequest) => api.stopReply(request), status: (scope: string, originalRef: string) => api.readReplyControlStatus(scope, originalRef) }
  async function ownerRequest<T>(request:()=>Promise<T>):Promise<T>{try{return await request()}catch(error){fail(error);throw error}}
  const commitments={pending:pendingCommitment,approval:approvedCommitment,lastAction:preparedCommitmentAction,async run(attempt:import('./api/commitment-communication.ts').CommitmentCommandAttempt){const result=await ownerRequest(()=>api.runCommitmentCommand(attempt));if(result.kind==='submit'&&attempt.scope===state.scope&&canRead.value)preparedCommitmentActions.set(attempt.scope,result.action);return result}}
  const fulfillment={pending:pendingFulfillment,current:currentFulfillment,approval:approvedTerms,readAction:(scope:string,refs:string[])=>ownerRequest(()=>api.readCurrentCommitmentAction(scope,refs)),async run(attempt:import('./api/commitment-fulfillment.ts').FulfillmentAttempt){const result=await ownerRequest(()=>api.runCommitmentFulfillment(attempt));if(attempt.scope===state.scope&&canRead.value){if(result.kind==='transition'){fulfillmentViews.set(attempt.scope,result.view);fulfillmentApprovals.delete(attempt.scope)}else if(result.kind==='approval'){if(result.approval)fulfillmentApprovals.set(attempt.scope,result.approval);else fulfillmentApprovals.delete(attempt.scope)}}return result}}
  const beta1 = { prepareCommand:(scope:string,input:import('./api/beta1-owner.ts').JointCommandSelectionInput,operationId:string)=>ownerRequest(()=>api.prepareJointCommand(scope,input,operationId)), freezeCommand:(scope:string,input:import('./api/beta1-owner.ts').PreparedJointCommand,operationId:string)=>ownerRequest(()=>api.freezeNamedJointCommand(scope,input,operationId)), prepareNode:(scope:string,windowRef:string,nodeId:string,operationId:string)=>ownerRequest(()=>api.prepareNamedJointNode(scope,windowRef,nodeId,operationId)), submit:(scope:string,kind:import('./api/beta1-owner.ts').Beta1Kind,input:import('./api/beta1-owner.ts').Beta1Input,operationId:string)=>ownerRequest(()=>api.submitBeta1Owner(scope,kind,input,operationId)), read:(scope:string,domain:Exclude<import('./api/beta1-owner.ts').Beta1Domain,'self'>,refs:string[])=>ownerRequest(()=>api.readBeta1OwnerState(scope,domain,refs)) }
  const growthReviews = { pending:pendingGrowthReview,
    read:(scope:string,refs:string[])=>ownerRequest(()=>api.readGrowthReviewState(scope,refs)),
    submit:(scope:string,kind:import('./api/growth-review.ts').GrowthReviewKind,input:import('./api/growth-review.ts').GrowthReviewInput,operationId:string)=>ownerRequest(()=>api.submitGrowthReview(scope,kind,input,operationId)) }
  const selfView = { read: (scope:string,blockIds:string[]=[]) => ownerRequest(()=>api.readCurrentSelfView(scope,blockIds)) }
  const singleEventGrowth={pending:pendingSingleEvent,view:currentSingleEvent,
    submit:async(attempt:import('./api/single-event-growth.ts').SingleEventGrowthAttempt)=>{
      if(attempt.scope!==state.scope||!canRead.value)throw new Error('当前 Owner 或角色范围已变化。')
      const generation=singleEventGeneration
      const prior=singleEventAttempts.get(attempt.scope)
      if(prior&&(prior.operationId!==attempt.operationId||JSON.stringify(prior.input)!==JSON.stringify(attempt.input)))
        throw new Error('请先核验原 UUID 的结果，不能替换待确认输入。')
      singleEventAttempts.set(attempt.scope,structuredClone(toRaw(attempt)))
      const receipt=await api.submitSingleEventGrowth(attempt.scope,attempt.kind,attempt.input,attempt.operationId)
      if(generation!==singleEventGeneration||attempt.scope!==state.scope)throw new Error('Owner 会话已变化，旧回执未合入当前页面。')
      singleEventAttempts.delete(attempt.scope)
      if(receipt.view)singleEventViews.set(attempt.scope,receipt.view)
      return receipt
    }}
  const generalGrowth = { submit: (scope:string,kind:import('./api/general-growth.ts').GeneralGrowthKind,
    input:import('./api/general-growth.ts').GeneralGrowthInput,operationId:string) => api.submitGeneralGrowth(scope,kind,input,operationId) }
  const projectContext = { read: (scope:string) => api.readOwnerProjectContexts(scope),
    adopt: (scope:string,options:import('./api/project-context.ts').ProjectContextOptions,item:import('./api/project-context.ts').ProjectContextItem,
      role:string,norms:string[],operationId:string) => api.adoptOwnerProjectContext(scope,options,item,role,norms,operationId) }
  return { state, setup, configuration, creator, onboardingRecovery, laborRebuild, management, inspectionMaintenance, sources, relations, artifacts, projectControls, sourceCorrections, sourceErasures, ownerTasks, ownerMaterials, replyControls, projectContext, singleEventGrowth, generalGrowth, selfView, beta1, growthReviews, commitments, fulfillment, requiresHttps, canRead, canNextView, viewPaging, nextView: () => state.viewType ? readView(state.viewType, true) : Promise.resolve(), runtimeReadable, scopeValid, canSignedLogin, checkSession, connect: checkSession, setScope, beginOwnerLogin, completeOwnerLogin, cancelChallenge, dismissLogin, logout, openWorkspace, readView, selectArchive, invalidateView, invalidateNavigation }
}
export type BackendController = ReturnType<typeof useBackend>
