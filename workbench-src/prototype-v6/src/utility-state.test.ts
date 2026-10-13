import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parse, compileScript } from '@vue/compiler-sfc'
import { createSSRApp, h } from 'vue'
import { renderToString } from '@vue/server-renderer'
import ts from 'typescript'
import { PLUGIN_SETTING_SCHEMA, utilityAccessState, type UtilitySessionState, type UtilityKind } from './utility-state.ts'
import { useBackend, type BackendController } from './use-backend.ts'

const verified: UtilitySessionState = { mode: 'same-origin', auth: 'authenticated', dashboard: 'authenticated', owner: 'unlocked', busy: false }

test('utility access never turns a verified session into an unimplemented API', () => {
  assert.equal(utilityAccessState(verified), 'undiscovered')
  assert.equal(utilityAccessState({ ...verified, mode: 'offline' }), 'offline')
  assert.equal(utilityAccessState({ ...verified, auth: 'offline' }), 'offline')
  assert.equal(utilityAccessState({ ...verified, auth: 'checking' }), 'checking')
  assert.equal(utilityAccessState({ ...verified, busy: true }), 'checking')
  assert.equal(utilityAccessState({ ...verified, auth: 'error' }), 'error')
  assert.equal(utilityAccessState({ ...verified, auth: 'locked' }), 'locked')
  assert.equal(utilityAccessState({ ...verified, owner: 'locked' }), 'locked')
  assert.equal(utilityAccessState({ ...verified, owner: 'unknown' }), 'locked')
  assert.equal(utilityAccessState({ ...verified, dashboard: 'missing' }), 'locked')
  assert.equal(utilityAccessState({ ...verified, dashboard: 'unknown' }), 'locked')
})

test('plugin schema exposes only the two verified fields and their schema defaults', () => {
  assert.deepEqual(Object.keys(PLUGIN_SETTING_SCHEMA), ['enabled', 'authority_profile'])
  assert.deepEqual(PLUGIN_SETTING_SCHEMA.enabled, { type: 'boolean', defaultValue: false })
  assert.deepEqual(PLUGIN_SETTING_SCHEMA.authority_profile, { type: 'string', defaultValue: 'default', minimumLength: 1, maximumLength: 64 })
})

const temporary = await mkdtemp(resolve('.utility-panel-tests-'))
after(async () => { await rm(temporary, { recursive: true, force: true }) })
async function component(name: string) {
  const filename = resolve('src',name+'.vue')
  const { descriptor } = parse(await readFile(filename, 'utf8'), { filename })
  const output = compileScript(descriptor, { id: name, inlineTemplate: true, templateOptions: { compilerOptions: { hoistStatic: false } } })
  const javascript = ts.transpileModule(output.content, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText
    .replace(/from (["'])\.\/([^"']+)\1/g, (_match, quote, file) => `from ${quote}${pathToFileURL(file.endsWith('.vue') ? join(temporary,file.replace('.vue','.mjs')) : resolve('src', file)).href}${quote}`)
  const target=join(temporary,name+'.mjs');await writeFile(target,javascript)
  return (await import(pathToFileURL(target).href)).default
}
await component('SetupPanel')
await component('CreatorConfigurationPanel')
await component('ConfigurationPanel')
const UtilityPanel = await component('UtilityPanel')

async function controller(enabled: boolean) {
  let backend!: BackendController, calls = 0
  await renderToString(createSSRApp({ setup() { backend = useBackend({ enabled, origin: 'https://test.invalid', fetchImpl: async () => { ++calls; throw new Error('Utility views must not issue an API request') } }); return () => h('div') } }))
  return { backend, calls: () => calls }
}
const renderPanel = (backend: BackendController, kind: UtilityKind) => renderToString(createSSRApp({ render: () => h(UtilityPanel, { backend, kind }) }))

test('actual logs panel renders disabled search, level and refresh without invented entries or calls', async () => {
  const { backend, calls } = await controller(false)
  const html = await renderPanel(backend, 'logs')
  assert.match(html, /data-access-state="offline"/)
  assert.match(html, /日志接口尚未接入/)
  assert.match(html, /未读取记录，不代表运行期间没有事件/)
  assert.match(html, /UNCONNECTED \/ 未接入/)
  assert.match(html, /<button[^>]+disabled[^>]*>查看详情/)
  assert.match(html, /<select[^>]+id="utility-logs-level"[^>]+disabled/)
  assert.match(html, /<input[^>]+id="utility-logs-query"[^>]+disabled/)
  assert.match(html, /<button[^>]+disabled[^>]+aria-describedby="utility-logs-reason"[^>]*>刷新日志/)
  assert.doesNotMatch(html, /<tbody|<time|0 条|保存成功|读取成功|日志为空/)
  assert.equal(calls(), 0)
})

test('actual settings panel separates unread actual values from false/default schema metadata', async () => {
  const { backend, calls } = await controller(false)
  const html = await renderPanel(backend, 'settings')
  assert.match(html, /结构默认值不代表当前安装的实际配置/)
  assert.match(html, /<select[^>]+id="utility-settings-enabled"[^>]+disabled[^>]*><option>当前值未读取/)
  assert.match(html, /<input[^>]+id="utility-settings-authority"[^>]+value="当前值未读取"[^>]+disabled[^>]+readonly/)
  assert.match(html, /关闭（false）/)
  assert.match(html, /<dd[^>]*>default<\/dd>/)
  assert.match(html, /1–64 个字符/)
  assert.match(html, /<button[^>]+disabled[^>]*>保存设置/)
  assert.doesNotMatch(html, /value="default"|type="checkbox"|role="switch"|保存成功/)
  assert.equal(calls(), 0)
})

test('utility state follows lock, pending, error and verified state without revealing backend errors', async () => {
  const { backend, calls } = await controller(true)
  backend.state.error = 'private-backend-diagnostic-do-not-display'
  for (const [state, expected, text] of [
    [{ ...verified, auth: 'locked', owner: 'locked' }, 'locked', '访问尚未核验'],
    [{ ...verified, auth: 'checking' }, 'checking', '会话处理中'],
    [{ ...verified, auth: 'error' }, 'error', '会话核验未完成'],
    [verified, 'undiscovered', '会话已核验 · 管理接口待核验'],
  ] as const) {
    Object.assign(backend.state, state)
    for (const kind of ['logs', 'settings'] as const) {
      const html = await renderPanel(backend, kind)
      assert.match(html, new RegExp(`data-access-state="${expected}"`))
      assert.ok(html.includes(text))
      assert.doesNotMatch(html, /private-backend-diagnostic-do-not-display|保存成功|读取成功/)
    }
  }
  assert.equal(calls(), 0)
})

test('utility panel uses the shared dashboard controls and keeps accessible status, narrow layout and reduced motion', async () => {
  const source = await readFile(filename, 'utf8')
  assert.doesNotMatch(source, /utility-header|utility-close|utility-footer|@keydown\.esc|overflow-y:auto/)
  assert.match(source, /:focus-visible/)
  assert.match(source, /@media\(max-width:430px\)/)
  assert.match(source, /prefers-reduced-motion:reduce/)
  const { backend } = await controller(false)
  const html = await renderPanel(backend, 'logs')
  assert.match(html, /aria-label="运行日志"/)
  assert.match(html, /aria-describedby="utility-logs-intro"/)
  assert.doesNotMatch(html, /<h2|返回档案|关闭运行日志/)
  assert.match(html, /role="status" aria-live="polite"/)
})

const managementCaps = () => ({ schema_version: 'sylanne.workbench-capabilities.v1', installation_id: 'ui-install', access_generation: 1, capabilities: { logs: { available: true, reason_code: 'available', max_page_size: 50, redaction: 'server_allowlist.v1' }, settings: { available: true, reason_code: 'available', writable_fields: ['enabled'], apply_semantics: 'next_restart' } } })
const liveSnapshot = (enabled = true, revision = 'ui-r1') => ({ schema_version: 'sylanne.workbench-settings.v1', installation_id: 'ui-install', access_generation: 1, revision, values: { enabled, authority_profile: 'live-authority-profile' }, writable_fields: ['enabled'], apply_semantics: 'next_restart' })
const liveLogPage = () => ({ schema_version: 'sylanne.workbench-logs.v1', installation_id: 'ui-install', access_generation: 1, entries: [{ event_id: 'ui-event-1', occurred_at: '2026-10-04T00:00:00Z', level: 'WARNING', event_code: 'safe.event', summary: '<img src=x onerror=alert(1)> is literal safe text', redacted: true }], next_cursor: 'ui-next-cursor', snapshot_id: 'ui-snapshot', redaction: 'server_allowlist.v1' })
async function liveController(handler: (url: string, init: RequestInit) => unknown | Promise<unknown>) {
  const calls: string[] = []; let backend!: BackendController
  await renderToString(createSSRApp({ setup() {
    backend = useBackend({ enabled: true, origin: 'https://test.invalid', fetchImpl: async (url, init) => {
      calls.push(url)
      const body = url.endsWith('/session') ? { status: 'ready', dashboard_session: 'authenticated', owner_session: 'unlocked', csrf_token: 'test-ui-csrf' } : await handler(url, init)
      return { ok: true, status: 200, json: async () => body }
    } }); return () => h('div')
  } }))
  return { backend, calls }
}

test('rendered buttons react from initial locked state to verified session without fetching on utility mount', async () => {
  const { backend, calls } = await liveController(() => managementCaps())
  const before = await renderPanel(backend, 'logs'); assert.match(before, /capability-check" disabled/); assert.deepEqual(calls, [])
  await backend.checkSession(); const verified = await renderPanel(backend, 'logs')
  assert.doesNotMatch(verified, /capability-check" disabled/); assert.match(verified, /管理接口待核验/); assert.match(verified, /<button[^>]+disabled[^>]*>刷新日志/); assert.equal(calls.length, 1)
  await backend.management.discover(); const discovered = await renderPanel(backend, 'logs')
  assert.match(discovered, /data-access-state="ready"/); assert.match(discovered, /尚未读取日志/); assert.doesNotMatch(discovered, /<select[^>]+id="utility-logs-level"[^>]+disabled/); assert.equal(calls.length, 2)
})

test('rendered actual logs/details use text escaping, bounded page navigation and no raw-log endpoint', async () => {
  const { backend } = await liveController(url => url.endsWith('/capabilities') ? managementCaps() : liveLogPage())
  await backend.checkSession(); await backend.management.discover(); await backend.management.refreshLogs(); backend.management.selectEvent('ui-event-1')
  const html = await renderPanel(backend, 'logs')
  assert.match(html, /<time datetime="2026-10-04T00:00:00Z"/); assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/); assert.doesNotMatch(html, /<img|v-html/)
  assert.match(html, /aria-label="脱敏事件详情"/); assert.match(html, /第 1 页 · 本页 1 条/); assert.match(html, /服务端脱敏字段，不提供原始日志/)
  assert.doesNotMatch(html, /<button[^>]+disabled[^>]*>下一页/)
  backend.management.setLogFilter({ query: 'changed' }); const filtered = await renderPanel(backend, 'logs'); assert.doesNotMatch(filtered, /<time|ui-event-1|onerror/)
})

test('rendered actual settings show real values, authority read-only, dirty save, and restart confirmation', async () => {
  let enabled = true, revision = 'ui-r1'
  const { backend } = await liveController((url, init) => {
    if (url.endsWith('/capabilities')) return managementCaps()
    if (url.endsWith('/settings/update')) { const request = JSON.parse(init.body as string); enabled = request.patch.enabled; revision = 'ui-r2'; return { schema_version: 'sylanne.workbench-settings-receipt.v1', installation_id: 'ui-install', access_generation: 1, operation_id: request.operation_id, revision, applied: 'next_restart' } }
    return liveSnapshot(enabled, revision)
  })
  await backend.checkSession(); await backend.management.discover(); await backend.management.readSettings()
  let html = await renderPanel(backend, 'settings')
  assert.match(html, /<select[^>]+id="utility-settings-enabled"[^>]+value="true"/); assert.doesNotMatch(html, /<select[^>]+id="utility-settings-enabled"[^>]+disabled/)
  assert.match(html, /value="live-authority-profile" disabled readonly/); assert.match(html, /关闭（false）/); assert.match(html, /更改保存后，下次重启生效/); assert.match(html, /保存使用版本核对/)
  assert.match(html, /<button[^>]+disabled[^>]*>保存设置/)
  backend.management.setEnabled(false); html = await renderPanel(backend, 'settings'); assert.match(html, /存在未保存修改/); assert.doesNotMatch(html, /<button[^>]+disabled[^>]*>保存设置/)
  await backend.management.saveSettings(); html = await renderPanel(backend, 'settings'); assert.match(html, /保存已确认。实际配置已回读一致，下次重启生效/); assert.match(html, /ui-r2/)
})

test('rendered read-only settings never enable an edit or save even after a valid read', async () => {
  const cap = managementCaps(); cap.capabilities.settings.writable_fields = []; cap.capabilities.settings.apply_semantics = 'read_only'
  const data = liveSnapshot(); data.writable_fields = []; data.apply_semantics = 'read_only'
  const { backend } = await liveController(url => url.endsWith('/capabilities') ? cap : data)
  await backend.checkSession(); await backend.management.discover(); await backend.management.readSettings()
  const html = await renderPanel(backend, 'settings'); assert.match(html, /<select[^>]+id="utility-settings-enabled"[^>]+disabled/); assert.match(html, /<button[^>]+disabled[^>]*>保存设置/); assert.match(html, /仅可读取，当前授权不允许保存/)
})

test('rendered runtime state stays independent of undiscovered management capability', async () => {
  const { backend } = await liveController(() => ({ schema_version: 'sylanne.install-status.v1', runtime_stage: 'stopped', reason_code: 'operator_stopped' }))
  await backend.checkSession(); await backend.management.checkRuntime(); const html = await renderPanel(backend, 'settings')
  assert.match(html, /runtime_stage：stopped · reason_code：operator_stopped/); assert.match(html, /管理接口待核验/); assert.match(html, /不代表管理功能或其他模块已就绪/); assert.match(html, /<button[^>]+disabled[^>]*>保存设置/)
})

test('new management controls and log details inherit both theme palettes and readable metadata sizes', async () => {
  const source = await readFile(filename, 'utf8'), additions = source.slice(source.indexOf('.capability-check{'))
  assert.match(additions, /\.utility-action:not\(:disabled\)\{[^}]*background:var\(--button\)[^}]*border-color:var\(--line\)/)
  assert.match(additions, /\.utility-panel input:not\(:disabled\)[^{]*\{[^}]*background:var\(--surface\)/)
  assert.match(additions, /\.log-event-detail\{[^}]*border:1px solid var\(--line\)[^}]*background:var\(--surface\)/)
  assert.match(additions, /\.runtime-check p\{font-size:12px/); assert.match(additions, /\.log-event-code\{font-size:12px/)
  assert.doesNotMatch(additions, /background:#[a-fA-F0-9]+|border(?:-color)?:[^;}]*#[a-fA-F0-9]+|font-size:(?:8|9|10|11)px/)
  assert.doesNotMatch(source, /v-html|localStorage|sessionStorage/)
})
