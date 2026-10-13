import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRenderer, createSSRApp, h, ref } from 'vue'
import { renderToString } from '@vue/server-renderer'
import { createManagement } from './use-management.ts'
import { useBackend, type BackendController } from './use-backend.ts'
import { WorkbenchApiError, type FetchLike, type FetchResponse } from './api/client.ts'
import type { ManagementCapabilities, LogPage, SettingsSnapshot, SettingsReceipt } from './api/management.ts'

const caps = (): ManagementCapabilities => ({ schema_version: 'sylanne.workbench-capabilities.v1', installation_id: 'test-installation', access_generation: 1, capabilities: { logs: { available: true, reason_code: 'available', max_page_size: 50, redaction: 'server_allowlist.v1' }, settings: { available: true, reason_code: 'available', writable_fields: ['enabled'], apply_semantics: 'next_restart' } } })
const page = (id = 'event-2', next: string | null = 'cursor-1', time = '2026-10-04T02:00:00Z'): LogPage => ({ schema_version: 'sylanne.workbench-logs.v1', installation_id: 'test-installation', access_generation: 1, entries: [{ event_id: id, occurred_at: time, level: 'INFO', event_code: 'runtime.changed', summary: 'Safe event summary', redacted: true }], next_cursor: next, snapshot_id: 'snapshot-1', redaction: 'server_allowlist.v1' })
const settings = (enabled = false, revision = 'r1'): SettingsSnapshot => ({ schema_version: 'sylanne.workbench-settings.v1', installation_id: 'test-installation', access_generation: 1, revision, values: { enabled, authority_profile: 'actual-profile' }, writable_fields: ['enabled'], apply_semantics: 'next_restart' })
const receipt = (): SettingsReceipt => ({ schema_version: 'sylanne.workbench-settings-receipt.v1', installation_id: 'test-installation', access_generation: 1, operation_id: 'afea6544-84cc-40b4-97cd-7c345c329777', revision: 'r2', applied: 'next_restart' })
function deferred<T>() { let resolve!: (value: T) => void, reject!: (reason: unknown) => void; const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail }); return { promise, resolve, reject } }
const tick = () => new Promise(done => setTimeout(done, 0))
function fixture() {
  const eligible = ref(true), calls: string[] = [], errors: unknown[] = []
  const api = {
    invalidateManagement() { calls.push('invalidate') },
    async managementCapabilities() { calls.push('capabilities'); return caps() },
    async queryLogs(_caps: ManagementCapabilities, _filter: unknown, _cursor: string | null) { calls.push('logs'); return page() },
    async readSettings(_caps: ManagementCapabilities) { calls.push('read'); return settings() },
    async updateSettings(_caps: ManagementCapabilities, _current: SettingsSnapshot, _enabled: boolean) { calls.push('update'); return receipt() },
    async installationStatus() { calls.push('status'); return { stage: 'blocked', reason: 'prerequisite_missing' } },
  }
  const controller = createManagement(api, () => eligible.value, error => { errors.push(error); eligible.value = false })
  return { api, controller, calls, errors, eligible }
}
async function readySettings(f: ReturnType<typeof fixture>) { await f.controller.discover(); await f.controller.readSettings(); f.controller.setEnabled(true) }

test('session eligibility alone does not fetch, grant access, or permit reads/writes', async () => {
  const f = fixture(); assert.deepEqual(f.calls, [])
  assert.equal(f.controller.canLogs.value, false); assert.equal(f.controller.canSettings.value, false)
  await f.controller.refreshLogs(); await f.controller.readSettings(); await f.controller.saveSettings(); assert.deepEqual(f.calls, [])
  f.eligible.value = false; await f.controller.discover(); await f.controller.checkRuntime(); assert.deepEqual(f.calls, [])
})

test('discovery independently gates unavailable logs and read-only settings', async () => {
  const f = fixture(); const c = caps(); c.capabilities.logs = { ...c.capabilities.logs, available: false, reason_code: 'service_unavailable' }; c.capabilities.settings.writable_fields = []; c.capabilities.settings.apply_semantics = 'read_only'
  f.api.managementCapabilities = async () => c; f.api.readSettings = async () => ({ ...settings(), writable_fields: [], apply_semantics: 'read_only' })
  await f.controller.discover(); await f.controller.refreshLogs(); await f.controller.readSettings(); f.controller.setEnabled(true); await f.controller.saveSettings()
  assert.equal(f.controller.canLogs.value, false); assert.equal(f.controller.canSettings.value, true); assert.equal(f.controller.canSave.value, false)
  assert.equal(f.controller.state.settings.draftEnabled, false); assert.equal(f.calls.includes('update'), false)
})

for (const code of ['capability_unsupported', 'invalid_response']) test(`discovery ${code} fails closed without fallback`, async () => {
  const f = fixture(); f.api.managementCapabilities = async () => { throw new WorkbenchApiError('private server text', { code }) }
  await f.controller.discover(); assert.equal(f.controller.state.capabilities.status, code === 'capability_unsupported' ? 'unsupported' : 'error')
  assert.equal(f.controller.state.capabilities.data, null); assert.equal(f.controller.canLogs.value, false); assert.doesNotMatch(JSON.stringify(f.controller.state), /private server text/)
})

test('refreshing capability clears all old data/drafts before the response, and late discovery stays discarded', async () => {
  const f = fixture(); await readySettings(f); await f.controller.refreshLogs(); await f.controller.checkRuntime()
  const late = deferred<ManagementCapabilities>(); f.api.managementCapabilities = () => late.promise
  const work = f.controller.discover(); assert.equal(f.controller.state.logs.page, null); assert.equal(f.controller.state.settings.data, null); assert.equal(f.controller.state.settings.draftEnabled, null); assert.equal(f.controller.state.runtime.data, null)
  f.controller.invalidate(); late.resolve(caps()); await work; assert.equal(f.controller.state.capabilities.data, null)
})

test('log next page replaces the prior page and selected details; filter edit clears cursor and stale response', async () => {
  const f = fixture(); await f.controller.discover(); await f.controller.refreshLogs(); f.controller.selectEvent('event-2'); assert.equal(f.controller.selectedEvent.value?.event_id, 'event-2')
  const late = deferred<LogPage>(); let usedCursor: string | null = null
  f.api.queryLogs = async (_caps, _filter, cursor) => { usedCursor = cursor; return late.promise }
  const work = f.controller.nextLogs(); assert.equal(usedCursor, 'cursor-1'); assert.equal(f.controller.selectedEvent.value, null); assert.equal(f.controller.state.logs.page, null)
  f.controller.setLogFilter({ level: 'ERROR', query: ' search ' }); late.resolve(page('event-1', null, '2026-10-04T01:00:00Z')); await work
  assert.equal(f.controller.state.logs.page, null); assert.equal(f.controller.state.logs.pageNumber, 0)
  f.api.queryLogs = async (_caps, filter, cursor) => { assert.deepEqual(filter, { level: 'ERROR', query: 'search' }); assert.equal(cursor, null); return { ...page(), entries: [], next_cursor: null } }
  await f.controller.refreshLogs(); assert.equal(f.controller.state.logs.status, 'empty'); assert.equal(f.controller.state.logs.page?.entries.length, 0)
})

for (const [name, next] of [
  ['snapshot drift', { ...page('event-1', null, '2026-10-04T01:00:00Z'), snapshot_id: 'snapshot-2' }],
  ['repeated event id', page('event-2', null, '2026-10-04T01:00:00Z')],
  ['repeated cursor', page('event-1', 'cursor-1', '2026-10-04T01:00:00Z')],
  ['cross-page ordering', page('event-3', null, '2026-10-04T03:00:00Z')],
] as const) test(`log pagination ${name} requires explicit restart and never splices data`, async () => {
  const f = fixture(); await f.controller.discover(); await f.controller.refreshLogs(); f.api.queryLogs = async () => next
  await f.controller.nextLogs(); assert.equal(f.controller.state.logs.status, 'refresh_required'); assert.equal(f.controller.state.logs.page, null); assert.equal(f.controller.canNext.value, false)
})

test('expired cursor stops at one failed call and explicit refresh starts page one', async () => {
  const f = fixture(); await f.controller.discover(); await f.controller.refreshLogs(); let calls = 0
  f.api.queryLogs = async () => { ++calls; throw new WorkbenchApiError('private', { code: 'cursor_expired', status: 410 }) }
  await f.controller.nextLogs(); assert.equal(calls, 1); assert.equal(f.controller.state.logs.status, 'refresh_required')
  f.api.queryLogs = async (_caps, _filter, cursor) => { ++calls; assert.equal(cursor, null); return page() }; await f.controller.refreshLogs(); assert.equal(calls, 2)
})

test('log page chain has bounded identifier memory and requires restart at 100 pages', async () => {
  const f = fixture(); let count = 0
  f.api.queryLogs = async () => { ++count; return page(`event-${count}`, `cursor-${count}`, new Date(Date.UTC(2026, 9, 4) - count * 1000).toISOString()) }
  await f.controller.discover(); await f.controller.refreshLogs(); for (let i = 1; i < 100; ++i) await f.controller.nextLogs()
  assert.equal(f.controller.state.logs.pageNumber, 100); assert.equal(f.controller.state.logs.page?.entries.length, 1); assert.equal(f.controller.canNext.value, false)
  await f.controller.nextLogs(); assert.equal(count, 100); await f.controller.refreshLogs(); assert.equal(f.controller.state.logs.pageNumber, 1)
})

test('save reports success only after exact receipt revision and desired value readback', async () => {
  const f = fixture(); await readySettings(f)
  const late = deferred<SettingsSnapshot>(); f.api.readSettings = () => late.promise; let writes = 0
  f.api.updateSettings = async (_caps, current, enabled) => { ++writes; assert.equal(current.revision, 'r1'); assert.equal(enabled, true); return receipt() }
  const work = f.controller.saveSettings(); await tick(); assert.equal(f.controller.state.settings.status, 'verifying'); assert.equal(f.controller.canSave.value, false); assert.doesNotMatch(f.controller.state.settings.message, /保存已确认/)
  await f.controller.saveSettings(); assert.equal(writes, 1); late.resolve(settings(true, 'r2')); await work
  assert.equal(f.controller.state.settings.status, 'confirmed'); assert.match(f.controller.state.settings.message, /下次重启生效/); assert.equal(f.controller.canSave.value, false)
})

for (const [name, readback] of [['wrong revision', settings(true, 'r3')], ['wrong enabled', settings(false, 'r2')]] as const) test(`save ${name} is unknown and cannot be replayed until fresh read`, async () => {
  const f = fixture(); await readySettings(f); f.api.readSettings = async () => readback
  await f.controller.saveSettings(); assert.equal(f.controller.state.settings.status, 'unknown'); assert.equal(f.controller.state.settings.data, null); assert.equal(f.controller.state.settings.draftEnabled, null); assert.equal(f.controller.canSave.value, false)
  await f.controller.saveSettings(); assert.equal(f.calls.filter(call => call === 'update').length, 1)
  f.api.readSettings = async () => settings(true, 'r3'); await f.controller.readSettings(); assert.equal(f.controller.state.settings.status, 'ready'); assert.equal(f.controller.canSave.value, false)
})

test('revision conflict clears draft and requires a new read plus explicit edit/save', async () => {
  const f = fixture(); await readySettings(f); let writes = 0
  f.api.updateSettings = async () => { ++writes; throw new WorkbenchApiError('private', { code: 'revision_conflict', status: 409 }) }
  await f.controller.saveSettings(); assert.equal(f.controller.state.settings.status, 'conflict'); assert.equal(f.controller.state.settings.data, null); assert.equal(f.controller.canSave.value, false)
  await f.controller.saveSettings(); assert.equal(writes, 1)
  f.api.readSettings = async () => settings(false, 'r7'); await f.controller.readSettings(); assert.equal(f.controller.canSave.value, false); f.controller.setEnabled(true)
  f.api.updateSettings = async (_caps, current) => { ++writes; assert.equal(current.revision, 'r7'); return { ...receipt(), revision: 'r8' } }; f.api.readSettings = async () => settings(true, 'r8'); await f.controller.saveSettings()
  assert.equal(writes, 2); assert.equal(f.controller.state.settings.status, 'confirmed')
})

for (const code of ['timeout', 'network_unavailable', 'invalid_response']) test(`write ${code} means unknown, never success or automatic retry`, async () => {
  const f = fixture(); await readySettings(f); let writes = 0
  f.api.updateSettings = async () => { ++writes; throw new WorkbenchApiError('private details', { code }) }
  await f.controller.saveSettings(); assert.equal(f.controller.state.settings.status, 'unknown'); assert.equal(f.controller.canSave.value, false); assert.equal(writes, 1); assert.doesNotMatch(f.controller.state.settings.message, /private details|保存已确认/)
})

test('navigation during pending mutation clears data and keeps unknown outcome; late receipt cannot restore it', async () => {
  const f = fixture(); await readySettings(f); const late = deferred<SettingsReceipt>(); f.api.updateSettings = () => late.promise
  const work = f.controller.saveSettings(); f.controller.invalidate(); assert.equal(f.controller.state.settings.status, 'unknown'); assert.equal(f.controller.state.settings.data, null); assert.equal(f.controller.state.settings.draftEnabled, null)
  late.resolve(receipt()); await work; assert.equal(f.controller.state.settings.status, 'unknown'); assert.equal(f.controller.state.capabilities.data, null); assert.equal(f.calls.filter(call => call === 'read').length, 1)
})

test('navigation during settings read discards result and holds request gate until settlement', async () => {
  const f = fixture(); await f.controller.discover(); const late = deferred<SettingsSnapshot>(); f.api.readSettings = () => late.promise
  const work = f.controller.readSettings(); f.controller.invalidate(); await f.controller.discover(); assert.equal(f.controller.canReadSettings.value, false)
  late.resolve(settings()); await work; assert.equal(f.controller.state.settings.data, null); assert.equal(f.controller.canReadSettings.value, true)
})

test('capability generation conflict clears all caches and requires explicit discovery', async () => {
  const f = fixture(); await readySettings(f); f.api.queryLogs = async () => { throw new WorkbenchApiError('private', { code: 'capabilities_changed', status: 409 }) }
  await f.controller.refreshLogs(); assert.equal(f.controller.state.settings.data, null); assert.equal(f.controller.state.capabilities.data, null); assert.equal(f.controller.canSave.value, false); assert.match(f.controller.state.capabilities.message, /重新核验/)
})

test('401/403 invokes session revocation even when the API already cleared eligibility', async () => {
  for (const status of [401, 403]) {
    const f = fixture(); await readySettings(f); f.api.queryLogs = async () => { f.eligible.value = false; throw new WorkbenchApiError('private', { code: 'unauthorized', status }) }
    await f.controller.refreshLogs(); assert.equal(f.errors.length, 1); assert.equal(f.controller.state.capabilities.data, null); assert.equal(f.controller.state.settings.data, null)
  }
})

test('runtime status is explicit and independent of management availability', async () => {
  const f = fixture(); await f.controller.checkRuntime(); assert.deepEqual(f.controller.state.runtime.data, { stage: 'blocked', reason: 'prerequisite_missing' }); assert.equal(f.controller.state.capabilities.data, null); assert.equal(f.controller.canLogs.value, false); assert.deepEqual(f.calls, ['status'])
})
test('D12 controls require a current running status while installation management remains independently available', async () => {
  for (const [stage, reason, allowed] of [['limited', 'disabled', false], ['limited', 'not_started', false], ['limited', 'active_role', true], ['limited', 'scene_binding', true], ['limited', 'dispatch', true], ['blocked', 'configuration', false], ['enrollment_required', 'authority_profile', false], ['stopped', 'none', false], ['ready', 'none', true]] as const) {
    let commands = 0
    const backend = await backendFixture(async url => {
      if (url.endsWith('/session')) return response(session)
      if (url.endsWith('/status')) return response({ schema_version: 'sylanne.install-status.v1', runtime_stage: stage, reason_code: reason })
      if (url.endsWith('/capabilities')) return response(caps())
      ++commands; return response({ status: 'unavailable', problem: { code: 'authority_unavailable', retryable: true } }, 503)
    })
    backend.setScope('test-bot/test-persona'); assert.equal(backend.canRead.value, false)
    await backend.management.checkRuntime(); assert.equal(backend.canRead.value, allowed)
    await backend.openWorkspace(); assert.equal(commands, allowed ? 1 : 0)
    assert.equal(backend.state.auth, 'authenticated'); assert.equal(backend.management.canDiscover.value, true)
    await backend.management.discover(); assert.equal(backend.management.canLogs.value, true); assert.equal(backend.management.canSettings.value, true)
  }
})
test('status refresh failure or nonrunning result purges earlier D12 projection and cannot replay a read', async () => {
  const namespace = {bot:'test-bot',persona:'test-persona'}
  const workspace = {status:'ready',projection:{namespace,access_generation:1,views:[],view_diagnostics:[],unavailable_domains:{},command_routes:[]}}
  const late = deferred<FetchResponse>(); let statusCalls = 0, commands = 0
  const mounted = await mountedBackendFixture(async url => {
    if (url.endsWith('/session')) return response(session)
    if (url.endsWith('/status')) return ++statusCalls === 1 ? response({schema_version:'sylanne.install-status.v1',runtime_stage:'ready',reason_code:'none'}) : late.promise
    ++commands; return response(workspace)
  })
  const backend = mounted.backend
  try {
    backend.setScope('test-bot/test-persona'); await backend.management.checkRuntime(); await backend.openWorkspace(); assert.ok(backend.state.workspace.data)
    const pending = backend.management.checkRuntime(); assert.equal(backend.canRead.value,false); assert.equal(backend.state.workspace.data,null)
    await backend.openWorkspace(); assert.equal(commands,1)
    late.resolve(response({schema_version:'sylanne.install-status.v1',runtime_stage:'blocked',reason_code:'configuration'})); await pending
    assert.equal(backend.canRead.value,false); assert.equal(backend.state.workspace.data,null); assert.equal(backend.state.auth,'authenticated')
  } finally { late.resolve(response({schema_version:'sylanne.install-status.v1',runtime_stage:'blocked',reason_code:'configuration'})); mounted.stop() }
  const broken = await backendFixture(async url => url.endsWith('/session') ? response(session) : response({schema_version:'future',runtime_stage:'ready',reason_code:'none'}))
  broken.setScope('test-bot/test-persona'); await broken.management.checkRuntime(); assert.equal(broken.canRead.value,false); assert.equal(broken.management.state.runtime.status,'error'); assert.equal(broken.management.canDiscover.value,true)
})
test('a late ready status cannot restore D12 controls after navigation or identity loss', async () => {
  for (const action of ['navigation', 'scope', 'logout'] as const) {
    const late = deferred<FetchResponse>()
    const backend = await backendFixture(async url => url.endsWith('/session') ? response(session) : url.endsWith('/owner/logout') ? response({status:'ok',owner_session:'locked'}) : late.promise)
    backend.setScope('test-bot/test-persona'); const pending = backend.management.checkRuntime(); await tick()
    if (action === 'navigation') backend.invalidateView()
    else if (action === 'scope') backend.setScope('other/persona')
    else await backend.logout()
    late.resolve(response({schema_version:'sylanne.install-status.v1',runtime_stage:'ready',reason_code:'none'})); await pending
    assert.equal(backend.management.state.runtime.data, null); assert.equal(backend.canRead.value, false)
    assert.equal(backend.management.canDiscover.value, action !== 'logout')
  }
})

function response(body: unknown, status = 200): FetchResponse { return { ok: status >= 200 && status < 300, status, json: async () => body } }
const session = { status: 'ready', dashboard_session: 'authenticated', owner_session: 'unlocked', csrf_token: 'test-token' }
async function backendFixture(fetchImpl: FetchLike) {
  let backend!: BackendController
  await renderToString(createSSRApp({ setup() { backend = useBackend({ enabled: true, origin: 'https://test.invalid', fetchImpl }); return () => h('div') } }))
  assert.equal(backend.management.canDiscover.value, false); assert.equal(backend.management.canRuntime.value, false)
  await backend.checkSession(); assert.equal(backend.management.canDiscover.value, true); assert.equal(backend.management.canRuntime.value, true); return backend
}
async function mountedBackendFixture(fetchImpl: FetchLike) {
  const descriptors = ['document', 'window'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)] as const)
  const events = {hidden:false,addEventListener(){},removeEventListener(){}}
  for (const [key] of descriptors) Object.defineProperty(globalThis,key,{configurable:true,value:events})
  let backend!: BackendController
  const renderer = createRenderer<any,any>({createElement:type=>({type,children:[]}),createText:text=>({text}),createComment:text=>({text}),setText(){},setElementText(){},parentNode:node=>node.parent,nextSibling:()=>null,insert(node,parent){node.parent=parent;parent.children.push(node)},remove(){},patchProp(){}})
  const app=renderer.createApp({setup(){backend=useBackend({enabled:true,origin:'https://test.invalid',fetchImpl});return()=>h('div')}})
  app.mount({children:[]}); await backend.checkSession()
  return {backend,stop(){app.unmount();for(const [key,descriptor] of descriptors){if(descriptor)Object.defineProperty(globalThis,key,descriptor);else Reflect.deleteProperty(globalThis,key)}}}
}
for (const [name, clear] of [
  ['navigation', (b: BackendController) => b.invalidateView()],
  ['scope change', (b: BackendController) => b.setScope('new/persona')],
  ['archive change', (b: BackendController) => b.selectArchive('other')],
  ['logout', (b: BackendController) => b.logout()],
] as const) test(`real controller ${name} aborts old management transport and cannot refill`, async () => {
  const late = deferred<FetchResponse>(); let signal: AbortSignal | null | undefined
  const backend = await backendFixture(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    if (url.endsWith('/capabilities')) return response(caps())
    if (url.endsWith('/owner/logout')) return response({ status: 'ok', owner_session: 'locked' })
    signal = init.signal; return late.promise
  })
  await backend.management.discover(); const work = backend.management.readSettings(); await tick(); await clear(backend)
  assert.equal(signal?.aborted, true); late.resolve(response(settings())); await work; assert.equal(backend.management.state.settings.data, null); assert.equal(backend.management.state.capabilities.data, null)
})

test('real API 403 revokes dashboard/owner content and management capabilities', async () => {
  const backend = await backendFixture(async url => url.endsWith('/session') ? response(session) : url.endsWith('/capabilities') ? response(caps()) : response({ schema_version: 'sylanne.workbench-error.v1', problem: { code: 'owner_session_locked', retryable: false } }, 403))
  await backend.management.discover(); await backend.management.readSettings(); assert.equal(backend.state.auth, 'locked'); assert.equal(backend.management.state.capabilities.data, null); assert.equal(backend.management.canSave.value, false)
})

 test('failed fresh read preserves unknown mutation outcome until a successful authoritative read', async () => {
  const f = fixture(); await readySettings(f)
  f.api.updateSettings = async () => { throw new WorkbenchApiError('timeout', { code: 'timeout' }) }; await f.controller.saveSettings()
  f.api.readSettings = async () => { throw new WorkbenchApiError('unavailable', { code: 'network_unavailable' }) }; await f.controller.readSettings()
  assert.equal(f.controller.state.settings.status, 'unknown'); assert.equal(f.controller.canSave.value, false)
  f.controller.invalidate(); await f.controller.discover(); assert.equal(f.controller.state.settings.status, 'unknown')
  f.api.readSettings = async () => settings(true, 'r9'); await f.controller.readSettings(); assert.equal(f.controller.state.settings.status, 'ready')
})

for (const status of [401, 403]) test(`obsolete log filter still purges current session on HTTP ${status}`, async () => {
  const late = deferred<FetchResponse>()
  const backend = await backendFixture(async url => url.endsWith('/session') ? response(session) : url.endsWith('/capabilities') ? response(caps()) : url.endsWith('/settings/read') ? response(settings()) : late.promise)
  await backend.management.discover(); await backend.management.readSettings()
  const work = backend.management.refreshLogs(); await tick(); backend.management.setLogFilter({ query: 'new-filter' })
  late.resolve(response({ schema_version: 'sylanne.workbench-error.v1', problem: { code: 'owner_session_locked', retryable: false } }, status)); await work
  assert.equal(backend.state.auth, 'locked'); assert.equal(backend.management.state.capabilities.data, null); assert.equal(backend.management.state.settings.data, null)
})

for (const code of ['revision_conflict', 'validation_failed']) test(`HTTP 500 with ${code} never claims a known rejected write`, async () => {
  const f = fixture(); await readySettings(f); f.api.updateSettings = async () => { throw new WorkbenchApiError('private', { code, status: 500 }) }
  await f.controller.saveSettings(); assert.equal(f.controller.state.settings.status, 'unknown'); assert.equal(f.controller.canSave.value, false)
})

test('HTTP 422 validation rejection is fixed local copy and requires a fresh read', async () => {
  const f = fixture(); await readySettings(f); f.api.updateSettings = async () => { throw new WorkbenchApiError('private', { code: 'validation_failed', status: 422 }) }
  await f.controller.saveSettings(); assert.equal(f.controller.state.settings.status, 'error'); assert.equal(f.controller.state.settings.data, null); assert.equal(f.controller.canSave.value, false); assert.match(f.controller.state.settings.message, /未通过后端校验/)
})

for (const action of ['hidden', 'unmount', 'pagehide', 'popstate']) test(`mounted backend ${action} clears utility data/drafts and aborts pending response`, async () => {
  const oldDocument = Object.getOwnPropertyDescriptor(globalThis, 'document'), oldWindow = Object.getOwnPropertyDescriptor(globalThis, 'window'), listeners = new Map<string, Function>()
  const document = { hidden: false, addEventListener(name: string, fn: Function) { listeners.set(name, fn) }, removeEventListener(name: string) { listeners.delete(name) } }
  Object.defineProperty(globalThis, 'document', { configurable: true, value: document })
  Object.defineProperty(globalThis, 'window', { configurable: true, value: document })
  const renderer = createRenderer<any, any>({ createElement: type => ({ type, children: [] }), createText: text => ({ text }), createComment: text => ({ text }), setText() {}, setElementText() {}, parentNode: node => node.parent, nextSibling: () => null, insert(node, parent) { node.parent = parent; parent.children.push(node) }, remove() {}, patchProp() {} })
  const late = deferred<FetchResponse>(); let backend!: BackendController, signal: AbortSignal | null | undefined
  const app = renderer.createApp({ setup() { backend = useBackend({ enabled: true, origin: 'https://test.invalid', fetchImpl: async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    if (url.endsWith('/capabilities')) return response(caps())
    if (url.endsWith('/settings/read')) return response(settings())
    signal = init.signal; return late.promise
  } }); return () => h('div') } })
  let stopped = false
  try {
    app.mount({ children: [] }); assert.equal(backend.management.canDiscover.value, false); await backend.checkSession(); assert.equal(backend.management.canDiscover.value, true)
    await backend.management.discover(); await backend.management.readSettings(); backend.management.setEnabled(true)
    const work = backend.management.refreshLogs(); await tick()
    if (action === 'hidden') { document.hidden = true; listeners.get('visibilitychange')!() } else if (action === 'unmount') { app.unmount(); stopped = true } else { assert.equal(typeof listeners.get(action), 'function'); listeners.get(action)!() }
    assert.equal(signal?.aborted, true); assert.equal(backend.state.auth, 'locked'); assert.equal(backend.management.state.settings.data, null); assert.equal(backend.management.state.settings.draftEnabled, null)
    late.resolve(response(page())); await work; assert.equal(backend.management.state.logs.page, null)
  } finally { if (!stopped) app.unmount(); if (oldDocument) Object.defineProperty(globalThis, 'document', oldDocument); else Reflect.deleteProperty(globalThis, 'document'); if (oldWindow) Object.defineProperty(globalThis, 'window', oldWindow); else Reflect.deleteProperty(globalThis, 'window') }
})
