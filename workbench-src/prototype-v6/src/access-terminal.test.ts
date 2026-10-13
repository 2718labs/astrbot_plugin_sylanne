import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { resolve, join, extname } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parse, compileScript } from '@vue/compiler-sfc'
import ts from 'typescript'
import { createRenderer, h, nextTick, markRaw } from 'vue'
import { ENTRY_TIMING } from './dashboard-flow.ts'
import { demoEntries, type ArcSnapshot } from './arc-engine.ts'
import type { BackendController } from './use-backend.ts'
import type { FetchLike, FetchResponse } from './api/client.ts'

// These tests execute the compiled App and LoginPanel, their watchers, and the real
// auth controller. Only the GPU/audio surfaces and browser primitives are doubles.
// No browser, network service, canvas, or alternate localhost route is used.
const temporary = await mkdtemp(resolve('.access-terminal-tests-'))
after(async () => { await rm(temporary, { recursive: true, force: true }) })
const hookName = '__sylanneTerminalTestRuntime'
await writeFile(join(temporary, 'backend.mjs'), `import {useBackend as realUseBackend} from ${JSON.stringify(pathToFileURL(resolve('src/use-backend.ts')).href)}; export function useBackend(){const hook=globalThis.${hookName};return hook.backend=realUseBackend(hook.options)}`)
await writeFile(join(temporary, 'arc.mjs'), `import {h} from 'vue'; export default {props:['disabled','reduced','frame','entries'],emits:['select','drag-start','drag','drag-end','wheel'],setup(props,{emit}){const hook=globalThis.${hookName};hook.arcMounts++;hook.arcSelect=logical=>emit('select',logical);hook.arcEmit=(event,...args)=>emit(event,...args);return()=>{hook.arcFrame=props.frame;return h('div',{'data-arc-stub':true,'data-disabled':props.disabled})}}}`)
await writeFile(join(temporary, 'audio.mjs'), `export class SoftAudio { muted=true;volume=.35;unlock(){};cue(){};silence(){};dispose(){};setMuted(v){this.muted=v};setVolume(v){this.volume=v}}`)
async function compileComponent(name: string) {
  const filename = resolve('src', name + '.vue')
  const { descriptor } = parse(await readFile(filename, 'utf8'), { filename })
  const output = compileScript(descriptor, { id: name, inlineTemplate: true, templateOptions: { compilerOptions: { hoistStatic: false } } })
  const javascript = ts.transpileModule(output.content, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText
    .replace(/from (["'])\.\/([^"']+)\1/g, (_match, quote, file) => {
      const substitute = file === 'ArchiveArc.vue' ? 'arc.mjs' : file === 'use-backend' ? 'backend.mjs' : file === 'soft-audio' ? 'audio.mjs' : file.endsWith('.vue') ? file.replace('.vue', '.mjs') : null
      const target = substitute ? join(temporary, substitute) : resolve('src', extname(file) ? file : file + '.ts')
      return `from ${quote}${pathToFileURL(target).href}${quote}`
    })
  await writeFile(join(temporary, name + '.mjs'), javascript)
}
for (const name of ['SetupPanel', 'CreatorConfigurationPanel', 'ConfigurationPanel', 'LoginPanel', 'ContentPanel', 'UtilityPanel', 'App']) await compileComponent(name)
const App = (await import(pathToFileURL(join(temporary, 'App.mjs')).href)).default

// Vue must keep host-element identity stable, just as it does for native DOM nodes.
class HostNode {
  type: string; text: string; children: HostNode[] = []; parent: HostNode | null = null
  props: Record<string, any> = {}; style: Record<string, any> = {}; listeners: Record<string, Function> = {}
  tagName: string; value = ''; focusCalls = 0
  constructor(type: string, text = '') { this.type = type; this.text = text; this.tagName = type.toUpperCase(); markRaw(this) }
  addEventListener(name: string, callback: Function) { this.listeners[name] = callback }
  removeEventListener(name: string) { delete this.listeners[name] }
  setAttribute(name: string, value: unknown) { this.props[name] = value }
  removeAttribute(name: string) { delete this.props[name] }
  getAttribute(name: string) { return this.props[name] ?? null }
  contains(target: HostNode | null): boolean { return !!target && (target === this || this.children.some(child => child.contains(target))) }
  getClientRects() { return this.parent && this.style.display !== 'none' ? [{}] : [] }
  blur() { if ((globalThis.document as any).activeElement === this) (globalThis.document as any).activeElement = null }
  focus() { ++this.focusCalls; (globalThis.document as any).activeElement = this }
}
const renderer = createRenderer<HostNode, HostNode>({
  createElement: type => new HostNode(type), createText: text => new HostNode('text', text), createComment: text => new HostNode('comment', text),
  setText: (target, text) => { target.text = text }, setElementText: (target, text) => { target.text = text; target.children = [] },
  parentNode: target => target.parent, nextSibling: target => target.parent?.children[target.parent.children.indexOf(target) + 1] ?? null,
  insert(target, parent, anchor = null) { if (target.parent) this.remove(target); target.parent = parent; const index = anchor ? parent.children.indexOf(anchor) : -1; if (index < 0) parent.children.push(target); else parent.children.splice(index, 0, target) },
  remove(target) { if (target.parent) { const index = target.parent.children.indexOf(target); if (index >= 0) target.parent.children.splice(index, 1); target.parent = null } },
  patchProp(target, key, _previous, value) { target.props[key] = value },
})
function text(target: HostNode): string { return target.text + target.children.filter(child => child.type !== 'comment').map(text).join('') }
function find(root: HostNode, predicate: (item: HostNode) => boolean): HostNode | undefined { if (predicate(root)) return root; for (const child of root.children) { const result = find(child, predicate); if (result) return result } }
function byClass(root: HostNode, name: string) { return find(root, item => String(item.props.class ?? '').split(/\s+/).includes(name)) }
function requiredClass(root: HostNode, name: string) { const result = byClass(root, name); assert.ok(result, `Expected rendered .${name}`); return result }
function button(root: HostNode, label: string) { const result = find(root, item => item.type === 'button' && text(item).trim() === label); assert.ok(result, `Expected button ${label}`); return result }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done }); return { promise, resolve } }
function response(body: unknown, status = 200): FetchResponse { return { ok: status >= 200 && status < 300, status, json: async () => body } }
const session = { status: 'ready', dashboard_session: 'authenticated', owner_session: 'unlocked', csrf_token: 'mock-terminal-csrf' }
async function flush() { await nextTick(); await nextTick() }
async function mount(fetchImpl: FetchLike, options: { enabled?: boolean; reduced?: boolean; timeoutMs?: number } = {}) {
  const descriptors = new Map<string, PropertyDescriptor | undefined>()
  function install(key: string, value: unknown) { descriptors.set(key, Object.getOwnPropertyDescriptor(globalThis, key)); Object.defineProperty(globalThis, key, { configurable: true, writable: true, value }) }
  let now = 0, nextFrame = 0
  const frames = new Map<number, FrameRequestCallback>(), listeners = new Map<string, Set<Function>>(), mediaListeners = new Set<Function>()
  const root = new HostNode('root'), document = { hidden: false, activeElement: null as HostNode | null, contains: (target: HostNode) => root.contains(target), addEventListener(name: string, callback: Function) { if (!listeners.has(name)) listeners.set(name, new Set()); listeners.get(name)!.add(callback) }, removeEventListener(name: string, callback: Function) { listeners.get(name)?.delete(callback) } }
  const media = { matches: options.reduced ?? false, addEventListener(_name: string, callback: Function) { mediaListeners.add(callback) }, removeEventListener(_name: string, callback: Function) { mediaListeners.delete(callback) } }
  const hook: { options: any; backend?: BackendController; arcMounts: number; arcSelect?: (logical: number) => void; arcEmit?: (event: string, ...args: unknown[]) => void; arcFrame?: ArcSnapshot } = { options: { enabled: options.enabled ?? true, origin: 'https://test.invalid', fetchImpl, timeoutMs: options.timeoutMs ?? 5000 }, arcMounts: 0 }
  install(hookName, hook); install('document', document); install('window', { matchMedia: () => media, addEventListener: document.addEventListener, removeEventListener: document.removeEventListener }); install('HTMLElement', HostNode)
  install('performance', { now: () => now }); install('requestAnimationFrame', (callback: FrameRequestCallback) => { const id = ++nextFrame; frames.set(id, callback); return id }); install('cancelAnimationFrame', (id: number) => frames.delete(id))
  const app = renderer.createApp({ render: () => h(App) }); app.mount(root); await flush()
  return {
    root, document, get backend() { return hook.backend! }, get arcMounts() { return hook.arcMounts }, get arcFrame() { return hook.arcFrame! },
    async selectDisk(logical: number) { hook.arcSelect!(logical); await flush() },
    async arcEvent(event: string, ...args: unknown[]) { hook.arcEmit!(event, ...args); await flush() },
    stage: () => requiredClass(root, 'archive-app').props['data-stage'],
    async advance(time: number) { now = time; const pending = [...frames.values()]; frames.clear(); for (const callback of pending) callback(now); await flush() },
    async motion(reduce: boolean) { media.matches = reduce; for (const callback of mediaListeners) callback(); await flush() },
    async hide() { document.hidden = true; for (const callback of listeners.get('visibilitychange') ?? []) callback(); await flush() },
    async escape() { const event = { key: 'Escape', defaultPrevented: false, target: document.activeElement, preventDefault() { this.defaultPrevented = true } }; for (const callback of listeners.get('keydown') ?? []) callback(event); await flush(); return event },
    async stop() {
      try { app.unmount(); await flush(); assert.equal(frames.size, 0); assert.ok([...listeners.values()].every(items => items.size === 0)); assert.equal(mediaListeners.size, 0) }
      finally { for (const [key, descriptor] of descriptors) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else Reflect.deleteProperty(globalThis, key) } }
    },
  }
}
type Fixture = Awaited<ReturnType<typeof mount>>
async function enterLive(fixture: Fixture) { await requiredClass(fixture.root, 'terminal-enter').props.onClick(); await flush() }
async function finishEntry(fixture: Fixture) { await fixture.advance(ENTRY_TIMING.minimumVerification); await fixture.advance(ENTRY_TIMING.minimumVerification + ENTRY_TIMING.confirmed); await fixture.advance(ENTRY_TIMING.minimumVerification + ENTRY_TIMING.confirmed + ENTRY_TIMING.entering) }

test('mounted terminal starts without credential form or auth request; explicit disclosure mounts real LoginPanel', async () => {
  let calls = 0; const f = await mount(async () => { ++calls; return response(session) })
  try {
    assert.equal(calls, 0); assert.equal(byClass(f.root, 'login-panel'), undefined)
    await f.advance(ENTRY_TIMING.arrival); assert.equal(f.stage(), 'access')
    await requiredClass(f.root, 'terminal-credentials').props.onClick(); await flush()
    assert.ok(byClass(f.root, 'login-panel')); assert.equal(calls, 0)
    await requiredClass(f.root, 'close-button').props.onClick(); await flush()
    assert.equal(byClass(f.root, 'login-panel'), undefined); assert.equal(f.stage(), 'access')
    assert.equal(f.document.activeElement, byClass(f.root, 'access-screen')); assert.equal(f.arcMounts, 1)
  } finally { await f.stop() }
})

for (const [name, failure] of [
  ['owner rejection', response({ problem: { code: 'owner_session_locked' } }, 401)],
  ['server error', response({ problem: { code: 'private_server_detail', message: 'SECRET DIAGNOSTIC' } }, 500)],
  ['malformed session', response({ status: 'ready', dashboard_session: 'authenticated', owner_session: 'locked' })],
] as const) test(`mounted terminal ${name} stays locked and explicit retry runs the actual auth watcher`, async () => {
  let calls = 0; const f = await mount(async () => ++calls === 1 ? failure : response(session))
  try {
    await enterLive(f); assert.equal(f.stage(), 'access'); assert.notEqual(f.backend.state.auth, 'authenticated')
    assert.ok(find(f.root, item => item.props.role === 'alert')); assert.match(text(requiredClass(f.root, 'terminal-enter')), /重试访问/)
    assert.doesNotMatch(text(f.root), /SECRET DIAGNOSTIC/); assert.equal(calls, 1)
    await enterLive(f); assert.equal(f.stage(), 'confirmed'); assert.equal(f.backend.state.auth, 'authenticated')
    await f.advance(ENTRY_TIMING.minimumVerification); assert.equal(f.stage(), 'confirmed'); assert.equal(byClass(f.root, 'workspace-shell'), undefined)
    await f.advance(ENTRY_TIMING.minimumVerification + ENTRY_TIMING.confirmed); assert.equal(f.stage(), 'entering'); assert.equal(requiredClass(f.root, 'workspace-shell').props.inert, true)
    await f.advance(ENTRY_TIMING.minimumVerification + ENTRY_TIMING.confirmed + ENTRY_TIMING.entering); assert.equal(f.stage(), 'workspace'); assert.equal(requiredClass(f.root, 'workspace-shell').props.inert, false)
    assert.equal(f.document.activeElement, byClass(f.root, 'archive-copy')); assert.equal(calls, 2); assert.equal(f.arcMounts, 1)
  } finally { await f.stop() }
})

test('mounted terminal repeated requests coalesce, time cannot invent proof, and cancellation discards late success', async () => {
  const pending = deferred<FetchResponse>(); let calls = 0
  const f = await mount(async () => { ++calls; return pending.promise })
  try {
    const request = requiredClass(f.root, 'terminal-enter').props.onClick
    const first = request(), second = request(); await flush(); assert.equal(calls, 1); assert.equal(f.stage(), 'verifying')
    assert.equal(f.document.activeElement, byClass(f.root, 'terminal-cancel'))
    await f.advance(60000); assert.equal(f.stage(), 'verifying'); assert.match(text(requiredClass(f.root, 'terminal-proof')), /待核验/)
    await requiredClass(f.root, 'terminal-cancel').props.onClick(); await flush(); assert.equal(f.stage(), 'access')
    pending.resolve(response(session)); await Promise.all([first, second]); await flush(); await f.advance(70000)
    assert.equal(f.stage(), 'access'); assert.equal(f.backend.state.auth, 'locked'); assert.equal(f.backend.state.busy, false)
    assert.equal(f.document.activeElement, byClass(f.root, 'access-screen')); assert.equal(f.arcMounts, 1)
  } finally { pending.resolve(response(session)); await f.stop() }
})

test('mounted terminal cancel then retry ignores an older unauthorized result and keeps the newer session', async () => {
  const old = deferred<FetchResponse>(); let calls = 0; const f = await mount(async () => ++calls === 1 ? old.promise : response(session))
  try {
    const first = requiredClass(f.root, 'terminal-enter').props.onClick(); await flush()
    await requiredClass(f.root, 'terminal-cancel').props.onClick(); await flush(); await enterLive(f)
    old.resolve(response({ problem: { code: 'host_session_missing' } }, 401)); await first; await flush(); await finishEntry(f)
    assert.equal(calls, 2); assert.equal(f.stage(), 'workspace'); assert.equal(f.backend.state.auth, 'authenticated'); assert.equal(f.backend.state.error, '')
  } finally { old.resolve(response(session)); await f.stop() }
})

for (const stage of ['confirmed', 'entering']) test(`mounted terminal cancel during ${stage} preserves verified session and prevents ghost workspace`, async () => {
  let calls = 0; const f = await mount(async () => { ++calls; return response(session) })
  try {
    await enterLive(f); await f.advance(ENTRY_TIMING.minimumVerification)
    if (stage === 'entering') await f.advance(ENTRY_TIMING.minimumVerification + ENTRY_TIMING.confirmed)
    assert.equal(f.stage(), stage); await requiredClass(f.root, 'terminal-cancel').props.onClick(); await flush()
    assert.equal(f.stage(), 'access'); assert.equal(f.backend.state.auth, 'authenticated'); await f.advance(10000); assert.equal(f.stage(), 'access')
    await f.motion(true); await enterLive(f); assert.equal(f.stage(), 'workspace'); assert.equal(calls, 1); assert.equal(f.arcMounts, 1)
  } finally { await f.stop() }
})

test('mounted terminal manual reduced motion cannot skip pending proof and finishes immediately once verified', async () => {
  const pending = deferred<FetchResponse>(); const f = await mount(async () => pending.promise)
  try {
    const request = requiredClass(f.root, 'terminal-enter').props.onClick(); await flush()
    await button(f.root, '减少动态效果').props.onClick(); await flush(); await f.advance(60000)
    assert.equal(f.stage(), 'verifying'); assert.equal(f.backend.state.auth, 'checking'); assert.equal(byClass(f.root, 'workspace-shell'), undefined)
    pending.resolve(response(session)); await request; await flush(); assert.equal(f.stage(), 'workspace')
    assert.equal(f.document.activeElement, byClass(f.root, 'archive-copy')); await f.advance(70000); assert.equal(f.stage(), 'workspace')
  } finally { pending.resolve(response(session)); await f.stop() }
})

for (const stage of ['confirmed', 'entering']) test(`mounted terminal media reduced-motion change finishes ${stage} without restarting the scene`, async () => {
  const f = await mount(async () => response(session))
  try {
    await enterLive(f); await f.advance(ENTRY_TIMING.minimumVerification)
    if (stage === 'entering') await f.advance(ENTRY_TIMING.minimumVerification + ENTRY_TIMING.confirmed)
    assert.equal(f.stage(), stage); await f.motion(true); assert.equal(f.stage(), 'workspace')
    await f.motion(false); await f.advance(10000); assert.equal(f.stage(), 'workspace'); assert.equal(f.arcMounts, 1)
  } finally { await f.stop() }
})

test('mounted offline terminal demo uses no backend calls and can be cancelled and replayed', async () => {
  let calls = 0; const f = await mount(async () => { ++calls; return response(session) }, { enabled: false })
  try {
    assert.equal(byClass(f.root, 'terminal-credentials'), undefined)
    await enterLive(f); assert.equal(f.stage(), 'verifying'); assert.match(text(requiredClass(f.root, 'terminal-proof')), /没有授予真实权限/)
    assert.equal((await f.escape()).defaultPrevented, true); assert.equal(f.stage(), 'access')
    await f.motion(true); await enterLive(f); assert.equal(f.stage(), 'workspace'); assert.equal(f.backend.state.auth, 'offline'); assert.equal(f.backend.canRead.value, false)
    await button(f.root, '登出').props.onClick(); await flush(); assert.equal(f.stage(), 'access'); assert.equal(calls, 0)
  } finally { await f.stop() }
})

test('mounted LoginPanel close during checking removes the form and late completion cannot reenter', async () => {
  const pending = deferred<FetchResponse>(); const f = await mount(async () => pending.promise)
  try {
    await requiredClass(f.root, 'terminal-credentials').props.onClick(); await flush()
    const check = requiredClass(f.root, 'full-button').props.onClick(); await flush(); assert.equal(f.stage(), 'verifying')
    await requiredClass(f.root, 'close-button').props.onClick(); await flush(); assert.equal(byClass(f.root, 'login-panel'), undefined)
    pending.resolve(response(session)); await check; await flush(); await f.advance(10000)
    assert.equal(f.stage(), 'access'); assert.equal(f.backend.state.auth, 'locked'); assert.equal(f.document.activeElement, byClass(f.root, 'access-screen'))
  } finally { pending.resolve(response(session)); await f.stop() }
})

test('mounted hidden-page lifecycle revokes a pending session and ignores late proof', async () => {
  const pending = deferred<FetchResponse>(); const f = await mount(async () => pending.promise)
  try {
    const request = requiredClass(f.root, 'terminal-enter').props.onClick(); await flush(); await f.hide()
    assert.equal(f.stage(), 'access'); assert.equal(f.backend.state.auth, 'locked')
    pending.resolve(response(session)); await request; await flush(); assert.equal(f.stage(), 'access'); assert.equal(f.backend.state.auth, 'locked')
  } finally { pending.resolve(response(session)); await f.stop() }
})

test('mounted terminal session timeout clears waiting and allows a fresh explicit retry', async () => {
  const pending = deferred<FetchResponse>(); let calls = 0
  const f = await mount(async () => ++calls === 1 ? pending.promise : response(session), { timeoutMs: 10 })
  try {
    await enterLive(f); assert.equal(f.stage(), 'access'); assert.equal(f.backend.state.errorCode, 'timeout'); assert.equal(f.backend.state.busy, false)
    await f.motion(true); await enterLive(f); assert.equal(f.stage(), 'workspace'); assert.equal(calls, 2)
    pending.resolve(response(session)); await flush(); assert.equal(f.stage(), 'workspace')
  } finally { pending.resolve(response(session)); await f.stop() }
})

test('mounted workspace logout failure immediately locks the terminal and never claims server confirmation', async () => {
  const pending = deferred<FetchResponse>(); const f = await mount(async url => url.endsWith('/session') ? response(session) : pending.promise, { reduced: true })
  try {
    await enterLive(f); assert.equal(f.stage(), 'workspace')
    const logout = button(f.root, '登出').props.onClick(); await flush(); assert.equal(f.stage(), 'access'); assert.equal(f.backend.state.auth, 'locked'); assert.equal(f.backend.canRead.value, false)
    pending.resolve(response({ problem: { code: 'server_error' } }, 500)); await logout; await flush()
    assert.equal(f.backend.state.logoutStatus, 'unconfirmed'); assert.equal(f.stage(), 'access'); assert.ok(byClass(f.root, 'terminal-error'))
  } finally { pending.resolve(response({ status: 'ok', owner_session: 'locked' })); await f.stop() }
})

test('mounted credential verification rejoins the terminal confirmation without duplicate entry or requests', async () => {
  let calls = 0; const f = await mount(async () => { ++calls; return response(session) })
  try {
    await requiredClass(f.root, 'terminal-credentials').props.onClick(); await flush()
    await requiredClass(f.root, 'full-button').props.onClick(); await flush()
    assert.equal(f.backend.state.auth, 'authenticated'); assert.equal(f.stage(), 'confirmed'); assert.equal(calls, 1)
    assert.ok(byClass(f.root, 'terminal-proof'), 'Verified credential flow should show the terminal confirmation')
    assert.equal(byClass(f.root, 'login-panel'), undefined)
    assert.equal(f.document.activeElement, byClass(f.root, 'terminal-cancel'))
    await finishEntry(f); assert.equal(f.stage(), 'workspace'); assert.equal(calls, 1); assert.equal(f.arcMounts, 1)
  } finally { await f.stop() }
})

test('mounted credential verification with reduced motion focuses the workspace instead of removed terminal controls', async () => {
  let calls = 0; const f = await mount(async () => { ++calls; return response(session) }, { reduced: true })
  try {
    await requiredClass(f.root, 'terminal-credentials').props.onClick(); await flush()
    await requiredClass(f.root, 'full-button').props.onClick(); await flush()
    assert.equal(f.stage(), 'workspace'); assert.equal(f.backend.state.auth, 'authenticated'); assert.equal(calls, 1)
    assert.equal(byClass(f.root, 'terminal-cancel'), undefined); assert.equal(byClass(f.root, 'login-panel'), undefined)
    assert.equal(f.document.activeElement, byClass(f.root, 'archive-copy')); assert.equal(f.arcMounts, 1)
    await f.advance(10000); assert.equal(f.stage(), 'workspace')
  } finally { await f.stop() }
})


test('official logo stays the same mounted subject through entry, real wait, confirmation and archive reveal', async () => {
  const pending = deferred<FetchResponse>(); const f = await mount(async () => pending.promise)
  try {
    const subject = requiredClass(f.root, 'logo-subject')
    const logo = find(subject, node => node.type === 'image')!
    assert.equal(find(subject,node=>node.type==='svg')!.props['aria-label'],'2718lab 官方标志'); assert.match(logo.props.href, /^data:image\/png;base64,/)
    const request = requiredClass(f.root, 'terminal-enter').props.onClick(); await flush()
    assert.equal(f.stage(), 'verifying'); assert.equal(requiredClass(f.root, 'logo-subject'), subject)
    await f.advance(15000); assert.equal(f.stage(), 'verifying'); assert.equal(byClass(f.root, 'workspace-shell'), undefined)
    pending.resolve(response(session)); await request; await flush()
    assert.equal(f.stage(), 'confirmed'); assert.equal(requiredClass(f.root, 'logo-subject'), subject)
    await f.advance(15000 + ENTRY_TIMING.confirmed); assert.equal(f.stage(), 'entering'); assert.equal(requiredClass(f.root, 'logo-subject'), subject)
    await f.advance(15000 + ENTRY_TIMING.confirmed + ENTRY_TIMING.entering); assert.equal(f.stage(), 'workspace')
    assert.equal(byClass(f.root, 'logo-subject'), undefined)
    assert.equal(byClass(f.root, 'brand-official-logo'), undefined)
  } finally { pending.resolve(response(session)); await f.stop() }
})


test('mounted browse block slides out before detail, reverses without remount and restores original focus', async () => {
  let calls = 0; const f = await mount(async () => { ++calls; return response(session) }, { enabled: false, reduced: true })
  try {
    await enterLive(f); assert.equal(f.stage(), 'workspace'); await f.motion(false)
    const browse = requiredClass(f.root, 'archive-copy'), trigger = requiredClass(f.root, 'open-action')
    trigger.focus(); await trigger.props.onClick(); await flush()
    const detail = requiredClass(f.root, 'inline-dashboard')
    assert.equal(requiredClass(f.root, 'archive-copy'), browse); assert.equal(browse.props.inert, true); assert.equal(detail.props.inert, true)
    assert.equal(f.document.activeElement, null)
    for(let t=16;t<=320;t+=16) await f.advance(t)
    assert.equal(browse.props.style['--browse-exit'],1); assert.equal(browse.props.style.opacity,0)
    assert.equal(detail.props.inert,false); assert.equal(f.document.activeElement,requiredClass(f.root,'dialog-close'))
    await f.escape(); assert.equal(detail.props.inert,true)
    for(let t=336;t<=2000;t+=16) await f.advance(t)
    assert.equal(requiredClass(f.root,'archive-copy'),browse);assert.equal(browse.props.inert,false)
    assert.equal(browse.props.style['--browse-exit'],0);assert.equal(f.document.activeElement,trigger);assert.equal(calls,0)
  } finally { await f.stop() }
})


test('v15 credential route preserves official subject node while hiding it behind the form',async()=>{
 const f=await mount(async()=>response(session));try{const subject=requiredClass(f.root,'logo-subject');await requiredClass(f.root,'terminal-credentials').props.onClick();await flush();assert.equal(requiredClass(f.root,'logo-subject'),subject);assert.ok(String(subject.props.class).includes('logo-behind-form'));await requiredClass(f.root,'full-button').props.onClick();await flush();assert.equal(requiredClass(f.root,'logo-subject'),subject);assert.equal(f.stage(),'confirmed')}finally{await f.stop()}
})
test('v15 skip presentation enters only after confirmed proof and cancels queued visual motion',async()=>{
 const f=await mount(async()=>response(session));try{assert.equal(byClass(f.root,'skip-entry'),undefined);await enterLive(f);assert.equal(f.stage(),'confirmed');await requiredClass(f.root,'skip-entry').props.onClick();await flush();assert.equal(f.stage(),'workspace');await f.advance(20000);assert.equal(f.stage(),'workspace');assert.equal(f.document.activeElement,requiredClass(f.root,'archive-copy'));assert.equal(f.arcMounts,1)}finally{await f.stop()}
})


test('mounted utility disks share the inline dashboard, stable tabs and the original return focus',async()=>{
 let calls=0;const f=await mount(async()=>{calls++;return response(session)},{enabled:false,reduced:true});try{
 await enterLive(f);const browse=requiredClass(f.root,'archive-copy'), modules=requiredClass(f.root,'module-list'),tabs=requiredClass(f.root,'detail-modules'),header=requiredClass(f.root,'workspace-nav');
 assert.equal(modules.children.filter(item=>item.type==='button').length,7);assert.equal(tabs.children.filter(item=>item.type==='button').length,7);assert.doesNotMatch(text(header),/运行日志|插件设置/);
 const logs=find(modules,item=>item.type==='button'&&text(item).includes('运行日志'))!;assert.ok(logs);logs.focus();await logs.props.onClick();await flush();
 const detail=requiredClass(f.root,'inline-dashboard');assert.equal(f.arcFrame.selected,5);assert.equal(f.arcFrame.mode,'detail');assert.equal(f.document.activeElement,requiredClass(f.root,'dialog-close'));assert.equal(requiredClass(f.root,'arc-stage').props.inert,false);assert.equal(browse.props.inert,true);
 assert.ok(requiredClass(f.root,'dashboard-scroll').contains(requiredClass(f.root,'utility-panel')));assert.equal(requiredClass(f.root,'utility-panel').props['data-utility-kind'],'logs');assert.match(text(detail),/UNCONNECTED/);assert.equal(byClass(f.root,'utility-workspace'),undefined);assert.equal(byClass(f.root,'utility-header'),undefined);
 const settings=button(tabs,'插件设置');settings.focus();await settings.props.onClick();await flush();const pose=f.arcFrame.position;await settings.props.onClick();await flush();assert.equal(f.arcFrame.selected,6);assert.equal(f.arcFrame.mode,'detail');assert.equal(f.arcFrame.position,pose);assert.equal(f.document.activeElement,settings);assert.match(text(detail),/authority_profile/);assert.equal(requiredClass(f.root,'inline-dashboard'),detail);assert.equal(calls,0);
 await f.escape();await f.advance(16);assert.equal(f.arcFrame.mode,'browse');assert.equal(detail.props.inert,true);assert.equal(f.document.activeElement,logs);assert.equal(requiredClass(f.root,'arc-stage').props.inert,false);assert.equal(f.arcMounts,1);
 }finally{await f.stop()}
})
test('mounted utility panel unmounts at real authorization loss without issuing new requests',async()=>{
 let calls=0;const f=await mount(async()=>{calls++;return response(session)},{reduced:true});try{
 await enterLive(f);await f.selectDisk(5);assert.ok(byClass(f.root,'utility-panel'));assert.equal(calls,1);
 f.backend.state.auth='locked';await flush();assert.equal(byClass(f.root,'utility-panel'),undefined);assert.notEqual(f.stage(),'workspace');assert.equal(requiredClass(f.root,'inline-dashboard').props.inert,true);assert.equal(calls,1);
 }finally{await f.stop()}
})
for(const reduced of [false,true])test(`mounted physical disk events toggle all seven modules with reduced motion ${reduced}`,async()=>{
 let calls=0;const f=await mount(async()=>{calls++;return response(session)},{enabled:false,reduced:true});try{
 await enterLive(f);await f.motion(reduced);let time=0;const detail=requiredClass(f.root,'inline-dashboard'),browse=requiredClass(f.root,'archive-copy');
 for(let index=0;index<demoEntries.length;index++){
  const before=f.arcFrame;await f.selectDisk(index);assert.equal(f.arcFrame.selected,index);assert.equal(f.arcFrame.mode,reduced?'detail':'opening');if(!reduced){assert.equal(f.arcFrame.phase,before.phase);assert.equal(f.arcFrame.position,before.position)}
  if(index>=5)assert.equal(requiredClass(f.root,'utility-panel').props['data-utility-kind'],index===5?'logs':'settings');else assert.equal(byClass(f.root,'utility-panel'),undefined);
  for(let frame=0;frame<24;frame++)await f.advance(time+=16);
  assert.equal(detail.props.inert,false);const selected=f.arcFrame;await f.selectDisk(index+demoEntries.length);assert.equal(f.arcFrame.mode,'closing');assert.equal(f.arcFrame.phase,selected.phase);assert.equal(f.arcFrame.position,selected.position);assert.equal(detail.props.inert,true);
  await f.selectDisk(index);assert.equal(f.arcFrame.mode,reduced?'detail':'opening');assert.equal(f.arcFrame.selected,index);
  await f.selectDisk(index);for(let frame=0;frame<160;frame++)await f.advance(time+=16);assert.equal(f.arcFrame.mode,'browse');assert.equal(f.arcFrame.phase,0);assert.equal(browse.props.inert,false);
 }
 assert.equal(calls,0);assert.equal(f.arcMounts,1);assert.equal(requiredClass(f.root,'inline-dashboard'),detail);
 }finally{await f.stop()}
})
test('mounted physical collapse invalidates a pending projection and utility switching never refetches',async()=>{
 let calls=0;const f=await mount(async()=>{calls++;return response(session)},{reduced:true});try{
 await enterLive(f);await f.selectDisk(0);f.backend.state.view={status:'loading',data:null,message:'pending',pending:true};
 await f.selectDisk(0);assert.notEqual(f.backend.state.view.pending,true);assert.equal(f.backend.state.view.status,'idle');assert.equal(f.backend.state.view.data,null);
 await f.selectDisk(5);await f.selectDisk(6);assert.equal(f.arcFrame.selected,6);assert.equal(requiredClass(f.root,'utility-panel').props['data-utility-kind'],'settings');assert.equal(calls,1);
 await button(requiredClass(f.root,'workspace-nav'),'登出').props.onClick();await flush();assert.equal(byClass(f.root,'utility-panel'),undefined);assert.equal(f.stage(),'access');assert.equal(calls,2);
 }finally{await f.stop()}
})

test('mounted expanded drag and wheel events cannot collapse or retarget the selected disk',async()=>{
 let calls=0;const f=await mount(async()=>{calls++;return response(session)},{enabled:false,reduced:true});try{
 await enterLive(f);const browse=requiredClass(f.root,'archive-copy');await f.selectDisk(5);const before=f.arcFrame;
 await f.arcEvent('drag-start',100);await f.arcEvent('drag',20);await f.arcEvent('drag-end',false);await f.arcEvent('wheel',120,0,800);
 assert.deepEqual(f.arcFrame,before);assert.equal(f.arcFrame.mode,'detail');assert.equal(requiredClass(f.root,'inline-dashboard').props.inert,false);
 await f.selectDisk(5);assert.equal(f.arcFrame.mode,'closing');await f.advance(16);assert.equal(f.arcFrame.mode,'browse');assert.equal(f.document.activeElement,browse);assert.equal(calls,0);assert.equal(f.arcMounts,1);
 }finally{await f.stop()}
})

test('v19 mounted header exposes one logout action and honest offline exit, focus and replay',async()=>{
 let calls=0;const f=await mount(async()=>{calls++;return response(session)},{enabled:false,reduced:true});try{
 await enterLive(f);const nav=requiredClass(f.root,'workspace-nav'),actions=nav.children.filter(n=>n.type==='button');
 assert.equal(actions.length,1);assert.equal(text(actions[0]!).trim(),'登出');assert.match(actions[0]!.props.title,/离线预览没有真实登录会话/);assert.doesNotMatch(text(nav),/访问验证|退出界面演示/);assert.match(text(nav),/离线预览/);
 actions[0]!.focus();await actions[0]!.props.onClick();await flush();assert.equal(f.stage(),'access');assert.equal(f.document.activeElement,requiredClass(f.root,'access-screen'));assert.equal(f.backend.state.auth,'offline');assert.equal(f.backend.state.logoutStatus,'idle');assert.equal(calls,0);
 await enterLive(f);assert.equal(f.stage(),'workspace');assert.equal(requiredClass(f.root,'workspace-nav').children.filter(n=>n.type==='button').length,1);assert.equal(calls,0);
 }finally{await f.stop()}
})
test('v19 mounted live logout is one Owner request, locks pending state, moves focus and permits verified reentry',async()=>{
 const pending=deferred<FetchResponse>();const requests:string[]=[];const f=await mount(async url=>{requests.push(url);return url.endsWith('/session')?response(session):pending.promise},{reduced:true});try{
 await enterLive(f);const nav=requiredClass(f.root,'workspace-nav'),action=button(nav,'登出');assert.equal(nav.children.filter(n=>n.type==='button').length,1);assert.match(action.props.title,/本页所有者会话/);
 action.focus();const work=action.props.onClick();await flush();assert.equal(f.stage(),'access');assert.equal(f.backend.state.busy,true);assert.equal(f.backend.state.logoutStatus,'loading');assert.equal(f.document.activeElement,requiredClass(f.root,'access-screen'));assert.equal(f.backend.canRead.value,false);
 await action.props.onClick();assert.equal(requests.filter(url=>url.endsWith('/logout')).length,1);
 pending.resolve(response({status:'ok',owner_session:'locked'}));await work;await flush();assert.equal(f.backend.state.busy,false);assert.equal(f.backend.state.logoutStatus,'confirmed');assert.equal(f.stage(),'access');
 await enterLive(f);assert.equal(f.stage(),'workspace');assert.equal(f.backend.state.auth,'authenticated');
 }finally{pending.resolve(response({status:'ok',owner_session:'locked'}));await f.stop()}
})
test('v19 header CSS remains unboxed and accommodates narrow widths without hiding session context',async()=>{
 const css=await readFile(resolve('src/style.css'),'utf8'),v19=css.slice(css.indexOf('/* v19:'));
 assert.match(v19,/top:5svh;right:3%;left:auto/);assert.match(v19,/background:none;border:0;backdrop-filter:none/);assert.match(v19,/min-height:44px/);assert.match(v19,/@media\(max-width:700px\)/);assert.match(v19,/@media\(max-width:380px\)/);assert.match(v19,/flex-direction:column;align-items:flex-end/);assert.doesNotMatch(v19,/connection-state\{display:none/);
})

test('v20 mounted animated logout keeps scene mounted, locks immediately, waits for proof, and blocks new login',async()=>{
 const pending=deferred<FetchResponse>();let calls=0;const f=await mount(async url=>{calls++;return url.endsWith('/session')?response(session):pending.promise});try{
 await enterLive(f);await finishEntry(f);assert.equal(f.stage(),'workspace');await f.selectDisk(2);await f.advance(6000);
 const action=button(requiredClass(f.root,'workspace-nav'),'登出');const work=action.props.onClick();await flush();
 assert.equal(f.backend.state.auth,'locked');assert.equal(f.backend.canRead.value,false);assert.equal(f.stage(),'workspace');assert.equal(requiredClass(f.root,'workspace-shell').props.inert,true);assert.equal(f.arcMounts,1);
 await action.props.onClick();assert.equal(calls,2);await f.advance(6450);assert.ok(byClass(f.root,'exit-status'));assert.equal(f.stage(),'workspace');
 await f.advance(6960);assert.equal(f.stage(),'access');assert.match(text(requiredClass(f.root,'logout-result')),/等待后端/);assert.equal(requiredClass(f.root,'terminal-enter').props.disabled,true);
 await requiredClass(f.root,'terminal-enter').props.onClick();await f.escape();assert.equal(calls,2);assert.equal(f.backend.state.logoutStatus,'loading');
 pending.resolve(response({status:'ok',owner_session:'locked'}));await work;await flush();assert.match(text(requiredClass(f.root,'logout-result')),/已退出/);assert.equal(requiredClass(f.root,'terminal-enter').props.disabled,false);assert.equal(f.arcMounts,1);
 }finally{pending.resolve(response({status:'ok',owner_session:'locked'}));await f.stop()}
})
test('v20 mounted failed logout exposes explicit retry and offline choreography does not call auth',async()=>{
 let calls=0;const f=await mount(async url=>{calls++;return url.endsWith('/session')?response(session):calls===2?response({problem:{code:'server_error'}},500):response({status:'ok',owner_session:'locked'})},{reduced:true});try{
 await enterLive(f);await button(f.root,'登出').props.onClick();await flush();assert.ok(byClass(f.root,'retry-logout'));assert.match(text(requiredClass(f.root,'logout-result')),/未确认/);
 await requiredClass(f.root,'retry-logout').props.onClick();await flush();assert.equal(calls,3);assert.match(text(requiredClass(f.root,'logout-result')),/已退出/);assert.equal(byClass(f.root,'retry-logout'),undefined);
 }finally{await f.stop()}
 const offline=await mount(async()=>{throw Error('offline must not fetch')},{enabled:false});try{await enterLive(offline);await offline.advance(900);await offline.advance(3000);await offline.advance(5700);assert.equal(offline.stage(),'workspace');await button(offline.root,'登出').props.onClick();await flush();assert.equal(offline.stage(),'workspace');await offline.advance(6660);assert.equal(offline.stage(),'access');assert.match(text(requiredClass(offline.root,'logout-result')),/没有真实登录/);assert.equal(offline.arcMounts,1)}finally{await offline.stop()}
})

test('v20 mounted theme selector preserves selected detail, focus, and single scene identity',async()=>{
 const f=await mount(async()=>{throw Error('offline must not fetch')},{enabled:false,reduced:true});try{
 await enterLive(f);await f.selectDisk(5);assert.equal(f.arcFrame.selected,5);const frame={...f.arcFrame},detail=requiredClass(f.root,'inline-dashboard'),close=requiredClass(f.root,'dialog-close');close.focus();
 const select=find(requiredClass(f.root,'theme-control'),n=>n.type==='select')!;assert.ok(select);select.props.onChange({target:{value:'dark'}});await flush();assert.equal(select.props.value,'dark');assert.equal(requiredClass(f.root,'inline-dashboard'),detail);assert.equal(f.document.activeElement,close);assert.deepEqual(f.arcFrame,frame);assert.equal(f.arcMounts,1);
 select.props.onChange({target:{value:'light'}});await flush();assert.equal(select.props.value,'light');assert.equal(f.arcFrame.selected,5);assert.equal(f.arcMounts,1);
 }finally{await f.stop()}
})
