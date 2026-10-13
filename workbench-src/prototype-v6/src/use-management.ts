import { computed, reactive } from 'vue'
import { WorkbenchApiError, type WorkbenchApi } from './api/client.ts'
import type { ManagementCapabilities, LogFilter, LogPage, SettingsSnapshot } from './api/management.ts'

type ManagementApi = Pick<WorkbenchApi, 'managementCapabilities' | 'queryLogs' | 'readSettings' | 'updateSettings' | 'installationStatus' | 'invalidateManagement'>
type ReadStatus = 'idle' | 'loading' | 'ready' | 'empty' | 'error' | 'refresh_required'
type SettingsStatus = 'idle' | 'loading' | 'ready' | 'saving' | 'verifying' | 'confirmed' | 'conflict' | 'unknown' | 'error'
export interface ManagementState {
  capabilities: { status: 'idle' | 'loading' | 'ready' | 'unsupported' | 'error'; data: ManagementCapabilities | null; message: string }
  logs: { status: ReadStatus; page: LogPage | null; filter: LogFilter; selectedEventId: string | null; pageNumber: number; message: string }
  settings: { status: SettingsStatus; data: SettingsSnapshot | null; draftEnabled: boolean | null; needsRead: boolean; message: string }
  runtime: { status: 'idle' | 'loading' | 'ready' | 'error'; data: { stage: string; reason: string } | null; message: string }
}
const MAX_CHAIN_PAGES = 100 // Retain one visible page and at most 5,000 deduplication identifiers.
const initialLogs = (): ManagementState['logs'] => ({ status: 'idle', page: null, filter: { level: 'ALL', query: '' }, selectedEventId: null, pageNumber: 0, message: '' })
const initialSettings = (): ManagementState['settings'] => ({ status: 'idle', data: null, draftEnabled: null, needsRead: true, message: '' })
const unknownWrite = '保存结果未知，可能已生效。请重新读取实际配置后再决定是否保存；不会自动重试。'

/** Current session eligibility gates requests; only explicit, validated discovery grants utility availability. */
export function createManagement(api: ManagementApi, eligible: () => boolean, onAuthError: (error: unknown) => void = () => {}) {
  const state = reactive<ManagementState>({
    capabilities: { status: 'idle', data: null, message: '' }, logs: initialLogs(), settings: initialSettings(),
    runtime: { status: 'idle', data: null, message: '' },
  })
  // Keep transport gates until settlement even after navigation. This prevents reusing an old coalesced promise.
  const active = reactive({ capabilities: false, logs: false, settings: false, update: false, runtime: false })
  let generation = 0, logsGeneration = 0, settingsGeneration = 0, uncertainWrite = false
  let cursors = new Set<string>(), eventIds = new Set<string>()
  const current = (token: number) => token === generation && eligible()
  const canDiscover = computed(() => eligible() && !active.capabilities && !active.update)
  const canLogs = computed(() => eligible() && state.capabilities.status === 'ready' && state.capabilities.data?.capabilities.logs.available === true)
  const canSettings = computed(() => eligible() && state.capabilities.status === 'ready' && state.capabilities.data?.capabilities.settings.available === true)
  const canReadSettings = computed(() => canSettings.value && !active.settings && !active.update)
  const canEdit = computed(() => canSettings.value && !active.settings && !active.update && !state.settings.needsRead && !!state.settings.data && state.settings.data.writable_fields.includes('enabled') && state.capabilities.data!.capabilities.settings.writable_fields.includes('enabled'))
  const canSave = computed(() => canEdit.value && typeof state.settings.draftEnabled === 'boolean' && state.settings.draftEnabled !== state.settings.data!.values.enabled)
  const canRefreshLogs = computed(() => canLogs.value && !active.logs && state.logs.filter.query.length <= 128)
  const canNext = computed(() => canRefreshLogs.value && !!state.logs.page?.next_cursor && state.logs.pageNumber < MAX_CHAIN_PAGES && state.logs.status === 'ready')
  const selectedEvent = computed(() => state.logs.page?.entries.find(entry => entry.event_id === state.logs.selectedEventId) ?? null)
  const canRuntime = computed(() => eligible() && !active.runtime)

  function invalidate(preserveRuntime = false) {
    const runtime = preserveRuntime && !active.runtime && state.runtime.status === 'ready' ? state.runtime : null
    api.invalidateManagement()
    ++generation; ++logsGeneration; ++settingsGeneration; cursors.clear(); eventIds.clear()
    uncertainWrite = uncertainWrite || active.update
    state.capabilities = { status: 'idle', data: null, message: '' }; state.logs = initialLogs(); state.settings = initialSettings()
    if (uncertainWrite) { state.settings.status = 'unknown'; state.settings.message = unknownWrite }
    state.runtime = runtime ?? { status: 'idle', data: null, message: '' }
  }
  function sharedFailure(error: unknown): boolean {
    if (error instanceof WorkbenchApiError && [401, 403].includes(error.status)) { invalidate(); onAuthError(error); return true }
    if (error instanceof WorkbenchApiError && error.code === 'capabilities_changed') {
      invalidate(); state.capabilities.message = '安装或权限范围已变化。请重新核验管理接口。'; return true
    }
    return false
  }
  async function discover() {
    if (!canDiscover.value) return
    invalidate(); const token = generation; active.capabilities = true
    state.capabilities = { status: 'loading', data: null, message: '正在核验当前安装的日志与配置权限。' }
    try {
      const data = await api.managementCapabilities(); if (!current(token)) return
      state.capabilities = { status: 'ready', data, message: '仅按后端本次返回的安装级权限开放操作。' }
    } catch (error) {
      if (token !== generation || sharedFailure(error) || !current(token)) return
      state.capabilities = error instanceof WorkbenchApiError && error.code === 'capability_unsupported'
        ? { status: 'unsupported', data: null, message: '后端未提供管理扩展，日志与实际配置操作保持关闭。' }
        : { status: 'error', data: null, message: '管理接口核验失败或返回不兼容。未保留之前的数据，请手动重试。' }
    } finally { active.capabilities = false }
  }
  function setLogFilter(patch: Partial<LogFilter>) {
    if (!canLogs.value) return
    const filter = { ...state.logs.filter, ...patch }
    if (!['ALL', 'INFO', 'WARNING', 'ERROR'].includes(filter.level) || typeof filter.query !== 'string') return
    if (filter.level === state.logs.filter.level && filter.query === state.logs.filter.query) return
    ++logsGeneration; cursors.clear(); eventIds.clear(); state.logs = { ...initialLogs(), filter }
  }
  function selectEvent(eventId: string | null) { state.logs.selectedEventId = state.logs.page?.entries.some(entry => entry.event_id === eventId) ? eventId : null }
  async function readLogs(next = false) {
    if (!(next ? canNext.value : canRefreshLogs.value)) return
    const caps = state.capabilities.data!, previous = next ? state.logs.page : null, cursor = previous?.next_cursor ?? null
    const filter = { level: state.logs.filter.level, query: state.logs.filter.query.trim() }
    if (!next) { cursors.clear(); eventIds.clear() }
    const pageNumber = next ? state.logs.pageNumber + 1 : 1
    const token = generation, logToken = ++logsGeneration
    active.logs = true; state.logs.page = null; state.logs.selectedEventId = null; state.logs.status = 'loading'; state.logs.message = '正在读取经过服务端脱敏的事件。'
    try {
      const page = await api.queryLogs(caps, filter, cursor); if (!current(token) || logToken !== logsGeneration) return
      const first = page.entries[0], last = previous?.entries.at(-1)
      const orderChanged = first && last && (Date.parse(first.occurred_at) > Date.parse(last.occurred_at) || (Date.parse(first.occurred_at) === Date.parse(last.occurred_at) && first.event_id >= last.event_id))
      if (previous && page.snapshot_id !== previous.snapshot_id || page.entries.some(entry => eventIds.has(entry.event_id)) || page.next_cursor && (page.next_cursor === cursor || cursors.has(page.next_cursor)) || orderChanged) {
        throw new WorkbenchApiError('日志分页需要刷新。', { code: 'snapshot_changed' })
      }
      if (cursor) cursors.add(cursor)
      for (const entry of page.entries) eventIds.add(entry.event_id)
      state.logs.page = page; state.logs.pageNumber = pageNumber; state.logs.status = page.entries.length ? 'ready' : 'empty'
      state.logs.message = page.entries.length ? pageNumber >= MAX_CHAIN_PAGES && page.next_cursor ? '已达本次浏览上限，请从第一页刷新。' : '仅显示本次响应中经过服务端脱敏的事件。' : '本次有效读取没有返回事件。'
    } catch (error) {
      if (token !== generation || sharedFailure(error) || logToken !== logsGeneration || !current(token)) return
      state.logs.page = null; state.logs.selectedEventId = null; cursors.clear(); eventIds.clear()
      const restart = error instanceof WorkbenchApiError && ['cursor_expired', 'snapshot_changed', 'invalid_response'].includes(error.code)
      state.logs.status = restart ? 'refresh_required' : 'error'
      state.logs.message = restart ? '日志游标已过期或分页不一致。请从第一页刷新，不会拼接旧记录。' : '日志读取未完成。未显示缓存或示例记录，请手动重试。'
    } finally { active.logs = false }
  }
  async function readSettings() {
    if (!canReadSettings.value) return
    const caps = state.capabilities.data!, token = generation, settingsToken = ++settingsGeneration
    state.settings = { ...initialSettings(), status: 'loading', message: '正在读取当前安装的实际配置。' }; active.settings = true
    try {
      const data = await api.readSettings(caps); if (!current(token) || settingsToken !== settingsGeneration) return
      uncertainWrite = false
      state.settings = { status: 'ready', data, draftEnabled: data.values.enabled, needsRead: false, message: '已读取实际配置。修改后需要明确点击保存。' }
    } catch (error) {
      if (token !== generation || sharedFailure(error) || settingsToken !== settingsGeneration || !current(token)) return
      state.settings = { ...initialSettings(), status: uncertainWrite ? 'unknown' : 'error', message: uncertainWrite ? unknownWrite + ' 本次重新读取仍未完成。' : '实际配置读取失败或返回未通过校验。请重新读取。' }
    } finally { active.settings = false }
  }
  function setEnabled(enabled: boolean) {
    if (!canEdit.value || typeof enabled !== 'boolean') return
    state.settings.draftEnabled = enabled; state.settings.status = 'ready'; state.settings.message = enabled === state.settings.data!.values.enabled ? '当前草稿与实际配置一致。' : '存在未保存修改。'
  }
  async function saveSettings() {
    if (!canSave.value) return
    const caps = state.capabilities.data!, snapshot = state.settings.data!, desired = state.settings.draftEnabled!, token = generation, settingsToken = ++settingsGeneration
    active.update = true; state.settings.status = 'saving'; state.settings.message = '正在提交配置变更。不会自动重试保存。'
    let receivedReceipt = false
    try {
      const receipt = await api.updateSettings(caps, snapshot, desired); if (!current(token) || settingsToken !== settingsGeneration) return
      receivedReceipt = true; state.settings.status = 'verifying'; state.settings.message = '已收到回执，正在重新读取并核对版本与值。'
      const data = await api.readSettings(caps); if (!current(token) || settingsToken !== settingsGeneration) return
      if (data.revision !== receipt.revision || data.values.enabled !== desired) throw new WorkbenchApiError('回读结果未匹配。', { code: 'write_unconfirmed' })
      uncertainWrite = false
      state.settings = { status: 'confirmed', data, draftEnabled: data.values.enabled, needsRead: false, message: receipt.applied === 'next_restart' ? '保存已确认。实际配置已回读一致，下次重启生效。' : '保存已确认。实际配置已回读一致，立即生效。' }
    } catch (error) {
      if (token !== generation || sharedFailure(error) || settingsToken !== settingsGeneration || !current(token)) return
      const conflict = !receivedReceipt && error instanceof WorkbenchApiError && error.code === 'revision_conflict' && error.status === 409
      const rejected = !receivedReceipt && error instanceof WorkbenchApiError && error.code === 'validation_failed' && error.status === 422
      uncertainWrite = !conflict && !rejected
      state.settings = { ...initialSettings(), status: conflict ? 'conflict' : rejected ? 'error' : 'unknown', message: conflict ? '配置已被其他操作修改。请重新读取，再明确修改并保存；不会覆盖新版本。' : rejected ? '变更未通过后端校验。请重新读取配置并核对启用条件。' : unknownWrite }
    } finally { active.update = false }
  }
  async function checkRuntime() {
    if (!canRuntime.value) return
    const token = generation; active.runtime = true; state.runtime = { status: 'loading', data: null, message: '正在读取安装运行状态。' }
    try { const data = await api.installationStatus(); if (!current(token)) return; state.runtime = { status: 'ready', data, message: '这是 /status 返回的运行阶段，不代表管理功能或其他模块已就绪。' } }
    catch (error) { if (token !== generation || sharedFailure(error) || !current(token)) return; state.runtime = { status: 'error', data: null, message: '安装运行状态尚未核验，请手动重试。' } }
    finally { active.runtime = false }
  }
  return { state, active, canDiscover, canLogs, canSettings, canReadSettings, canEdit, canSave, canRefreshLogs, canNext, canRuntime, selectedEvent, invalidate, discover, setLogFilter, selectEvent, refreshLogs: () => readLogs(), nextLogs: () => readLogs(true), readSettings, setEnabled, saveSettings, checkRuntime }
}
export type ManagementController = ReturnType<typeof createManagement>
