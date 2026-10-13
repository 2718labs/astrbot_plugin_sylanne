import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { resolve, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parse, compileScript } from '@vue/compiler-sfc'
import ts from 'typescript'
import { createRenderer, createSSRApp, h, nextTick } from 'vue'
import { renderToString } from '@vue/server-renderer'
import { useBackend, type BackendState, type BackendController } from './use-backend.ts'
import { ARCHIVE_META, visibleProjection, challengeExpired } from './access-content-state.ts'
import type { FetchResponse, FetchLike } from './api/client.ts'
const temporary = await mkdtemp(resolve('.access-panel-tests-'))
after(async () => { await rm(temporary, { recursive: true, force: true }) })
async function component(name: string) {
  const filename = resolve('src', name + '.vue')
  const { descriptor } = parse(await readFile(filename, 'utf8'), { filename })
  const output = compileScript(descriptor, { id: name, inlineTemplate: true, templateOptions: { compilerOptions: { hoistStatic: false } } })
  const javascript = ts.transpileModule(output.content, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText
    .replace(/from (["'])\.\/([^"']+)\1/g, (_match, quote, file) => `from ${quote}${pathToFileURL(file.endsWith('.vue') ? join(temporary,file.replace('.vue','.mjs')) : resolve('src', file)).href}${quote}`)
  const target = join(temporary, name + '.mjs'); await writeFile(target, javascript)
  return (await import(pathToFileURL(target).href)).default
}
await component('RelationsPanel')
await component('OwnerArtifactPanel')
await component('SourceCorrectionPanel')
await component('ProjectControlsPanel')
await component('SetupPanel')
await component('CreatorConfigurationPanel')
await component('ConfigurationPanel')
const LoginPanel = await component('LoginPanel'), ContentPanel = await component('ContentPanel')
const namespace = { bot: 'test-bot', persona: 'test-persona' }, scope = 'test-bot/test-persona'
const session = { status: 'ready', dashboard_session: 'authenticated', owner_session: 'unlocked', csrf_token: 'mock-panel-csrf' }
const workspace = { status: 'ready', projection: { namespace, access_generation: 3, views: [{ view_type: 'creation', status: 'available' }, { view_type: 'd06.memory_sources.v1', status: 'available' }], view_diagnostics: [], unavailable_domains: {}, command_routes: [] } }
const persona = { status: 'ready', projection: { namespace, access_generation: 3, view_type: 'creation', data: { candidates: [{ plan_id: 'authorized-plan', version: 2, authored: true, block_count: 8, value_rule_count: 4 }] }, coverage: { requested_types: ['d01.persona_plan.v1'], returned_atoms: 1, truncated: true }, next_cursor: 'opaque-next-page' } }
const memory = { status: 'ready', projection: { namespace, access_generation: 3, view_type: 'd06.memory_sources.v1', data: { sources: [{ source_id: 'authorized-source', source_kind: 'statement', assertion_status: 'asserted', recorded_at: '2026-10-03T00:00:00Z', qualification: 'not_recorded' }], coverage: 'complete' } } }
function response(body: unknown, status = 200): FetchResponse { return { ok: status >= 200 && status < 300, status, json: async () => body } }
async function controller(fetchImpl: FetchLike, enabled = true) {
  let backend!: BackendController
  await renderToString(createSSRApp({ setup() { backend = useBackend({ enabled, origin: 'https://test.invalid', fetchImpl: async (url, init) => url.endsWith('/status') ? response({schema_version:'sylanne.install-status.v1',runtime_stage:'ready',reason_code:'none'}) : fetchImpl(url, init) }); return () => h('div') } }))
  return { ...backend, readView: async (view: Parameters<typeof backend.readView>[0]) => { if (!backend.runtimeReadable.value) await backend.management.checkRuntime(); await backend.readView(view) } }
}
async function content(backend: BackendController, entryId: string) { return renderToString(createSSRApp({ render: () => h(ContentPanel, { backend, entryId }) })) }
test('archive definitions expose exactly the contract five fields, with no life/contact projector', () => {
  assert.deepEqual(ARCHIVE_META['demo-persona']!.fields.map(field => field.key), ['plan_id', 'version', 'authored', 'block_count', 'value_rule_count'])
  assert.deepEqual(ARCHIVE_META['demo-memory']!.fields.map(field => field.key), ['source_id', 'source_kind', 'assertion_status', 'recorded_at', 'qualification'])
  assert.equal(ARCHIVE_META['demo-life']!.view, null); assert.equal(ARCHIVE_META['demo-contact']!.view, null)
})
test('challenge expiry uses the actual supplied timestamp and cannot invent validity', () => {
  assert.equal(challengeExpired(undefined, 1000), false); assert.equal(challengeExpired('invalid', 1000), true)
  assert.equal(challengeExpired('1970-01-01T00:00:01Z', 1000), true); assert.equal(challengeExpired('1970-01-01T00:00:02Z', 1000), false)
})
test('actual ContentPanel offline render makes zero requests and contains no fabricated rows or metrics', async () => {
  let calls = 0; const backend = await controller(async () => { ++calls; return response(session) }, false)
  for (const entryId of Object.keys(ARCHIVE_META)) {
    const html = await content(backend, entryId)
    assert.match(html, /01 \/ OVERVIEW/); assert.match(html, /02 \/ INFORMATION/); assert.match(html, /03 \/ OPERATIONS/)
    assert.match(html, /后端未连接|HOLD/); assert.doesNotMatch(html, /authorized-plan|authorized-source|本次返回记录|访问版本/)
  }
  assert.equal(calls, 0); assert.equal(backend.state.auth, 'offline')
})
test('actual ContentPanel shows every authorized persona field and discloses truncation', async () => {
  const backend = await controller(async (url, init) => response(url.endsWith('/session') ? session : JSON.parse(init.body as string).action === 'open_workspace' ? workspace : persona))
  await backend.checkSession(); backend.setScope(scope); backend.selectArchive('demo-persona'); await backend.readView('creation')
  const html = await content(backend, 'demo-persona')
  assert.match(html, /authorized-plan/); for (const field of ARCHIVE_META['demo-persona']!.fields) assert.match(html, new RegExp(field.key))
  assert.match(html, /是（true）/); assert.match(html, /本次返回的信息已截断/); assert.match(html, /返回条数不能视为全部记录/)
})
test('actual ContentPanel memory render only exposes source metadata and not verified evidence claims', async () => {
  const backend = await controller(async (url, init) => response(url.endsWith('/session') ? session : JSON.parse(init.body as string).action === 'open_workspace' ? workspace : memory))
  await backend.checkSession(); backend.setScope(scope); backend.selectArchive('demo-memory'); await backend.readView('d06.memory_sources.v1')
  const html = await content(backend, 'demo-memory')
  assert.match(html, /authorized-source/); for (const field of ARCHIVE_META['demo-memory']!.fields) assert.match(html, new RegExp(field.key))
  assert.match(html, /未记录 · not_recorded/); assert.match(html, /仅呈现来源元数据/); assert.doesNotMatch(html, /已验证来源|记忆正文<\/dt>/)
})
test('projection display guard rejects stale, partial, unauthorized, wrong scope, wrong view and offline data', async () => {
  const backend = await controller(async (url, init) => response(url.endsWith('/session') ? session : JSON.parse(init.body as string).action === 'open_workspace' ? workspace : persona))
  await backend.checkSession(); backend.setScope(scope); backend.selectArchive('demo-persona'); await backend.readView('creation')
  assert.ok(visibleProjection(backend.state, 'demo-persona'))
  for (const patch of [{ auth: 'locked' }, { mode: 'offline' }, { scope: 'other/role' }, { viewType: 'd06.memory_sources.v1' }, ...['stale', 'partial', 'unauthorized', 'error', 'loading'].map(status => ({ view: { ...backend.state.view, status } }))]) {
    assert.equal(visibleProjection({ ...backend.state, ...patch } as BackendState, 'demo-persona'), null)
  }
  assert.equal(visibleProjection(backend.state, 'demo-memory'), null)
})
test('actual access panel distinguishes missing Dashboard and Owner lock and reports catalogue states', async () => {
  const backend = await controller(async () => response({ problem: { code: 'host_session_missing' } }, 401))
  await backend.checkSession(); const html = await content(backend, 'demo-access')
  assert.match(html, /AstrBot 后台<\/dt><dd>未登录/); assert.match(html, /所有者会话<\/dt><dd>本页已锁定/); assert.match(html, /当前会话|同源 AstrBot Dashboard/)
  assert.doesNotMatch(html, /class="capability-list"/)
})
test('actual life/contact render cannot turn installed contact routes into sender permission', async () => {
  let calls = 0; const backend = await controller(async () => { ++calls; return response(session) }, false)
  const life = await content(backend, 'demo-life'), contact = await content(backend, 'demo-contact')
  assert.match(life, /生活内容尚未接入/); assert.match(contact, /disabled[^>]*aria-describedby="contact-hold-reason"[^>]*>发送联系 · HOLD/)
  assert.match(contact, /不会调用发送接口/); assert.doesNotMatch(contact, /scope-form|读取档案信息/); assert.equal(calls, 0)
})
// Actual compiled Vue event handlers run against a DOM-free renderer. This is not browser or GPU QA.
type HostNode = { type: string; text: string; children: HostNode[]; parent: HostNode | null; props: Record<string, any>; tagName: string; value?: string; listeners: Record<string, any>; addEventListener: (name: string, callback: any) => void; removeEventListener: (name: string) => void; setAttribute: (name: string, value: unknown) => void; removeAttribute: (name: string) => void }
function node(type: string, text = ''): HostNode {
  return { type, text, children: [], parent: null, props: {}, tagName: type.toUpperCase(), listeners: {}, addEventListener(name, callback) { this.listeners[name] = callback }, removeEventListener(name) { delete this.listeners[name] }, setAttribute(name, value) { this.props[name] = value }, removeAttribute(name) { delete this.props[name] } }
}
const renderer = createRenderer<HostNode, HostNode>({
  createElement: type => node(type), createText: text => node('text', text), createComment: text => node('comment', text),
  setText: (target, text) => { target.text = text }, setElementText: (target, text) => { target.text = text; target.children = [] },
  parentNode: target => target.parent, nextSibling: target => target.parent?.children[target.parent.children.indexOf(target) + 1] ?? null,
  insert(target, parent, anchor = null) { if (target.parent) this.remove(target); target.parent = parent; const index = anchor ? parent.children.indexOf(anchor) : -1; if (index < 0) parent.children.push(target); else parent.children.splice(index, 0, target) },
  remove(target) { if (target.parent) { const index = target.parent.children.indexOf(target); if (index >= 0) target.parent.children.splice(index, 1); target.parent = null } },
  patchProp: (target, key, _previous, value) => { target.props[key] = value },
})
function treeText(target: HostNode): string { return target.text + target.children.map(treeText).join('') }
function button(target: HostNode, text: string): HostNode | undefined { if (target.type === 'button' && treeText(target).includes(text)) return target; for (const child of target.children) { const match = button(child, text); if (match) return match } }
async function mountLogin(backend: BackendController) {
  const events: string[] = [], root = node('root')
  const app = renderer.createApp({ render: () => h(LoginPanel, { backend, onVerified: () => events.push('verified'), onClose: () => events.push('close') }) })
  const originalDocument = globalThis.document
  // Vue's text input directive only uses activeElement in these component tests.
  if (!globalThis.document) Object.defineProperty(globalThis, 'document', { configurable: true, value: { activeElement: null } })
  app.mount(root)
  return { root, events, stop() { app.unmount(); if (!originalDocument) Reflect.deleteProperty(globalThis, 'document') } }
}
test('actual LoginPanel verified event is absent for rejected /session and emitted for a later valid session', async () => {
  let verified = false; const backend = await controller(async () => verified ? response(session) : response({ problem: { code: 'owner_session_locked' } }, 401))
  const mounted = await mountLogin(backend)
  try {
    await button(mounted.root, '核验已有会话')!.props.onClick(); await nextTick(); assert.deepEqual(mounted.events, []); assert.equal(backend.state.auth, 'locked')
    verified = true; await button(mounted.root, '核验已有会话')!.props.onClick(); await nextTick(); assert.deepEqual(mounted.events, ['verified']); assert.equal(backend.state.auth, 'authenticated')
    await button(mounted.root, '返回')!.props.onClick(); await nextTick(); assert.deepEqual(mounted.events, ['verified', 'close']); assert.equal(backend.state.auth, 'authenticated')
  } finally { mounted.stop() }
})
test('actual LoginPanel close during checking cancels late entry and never emits verified', async () => {
  let resolveSession!: (value: FetchResponse) => void
  const pendingSession = new Promise<FetchResponse>(done => { resolveSession = done })
  const backend = await controller(async () => pendingSession), mounted = await mountLogin(backend)
  try {
    const check = button(mounted.root, '核验已有会话')!.props.onClick(); await nextTick()
    await button(mounted.root, '返回')!.props.onClick(); resolveSession(response(session)); await check; await nextTick()
    assert.deepEqual(mounted.events, ['close']); assert.equal(backend.state.auth, 'locked'); assert.equal(backend.state.busy, false)
  } finally { mounted.stop() }
})
