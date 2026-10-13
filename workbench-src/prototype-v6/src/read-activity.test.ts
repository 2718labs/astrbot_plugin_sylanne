import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import * as THREE from 'three'
import { createSSRApp, h } from 'vue'
import { renderToString } from '@vue/server-renderer'
import { readActivityMode, OPTICAL_ACTIVITY_CYCLE, OPTICAL_ACTIVITY_MAX, OPTICAL_ACTIVITY_PULSES, sampleOpticalActivity, makeOpticalActivity, bindOpticalActivity, updateOpticalActivity } from './read-activity.ts'
import { readingMaterial } from './read-material.ts'
import { makeReadingMotion, updateReadingMotion } from './read-motion.ts'
import { useBackend, type BackendController } from './use-backend.ts'
import type { FetchLike, FetchResponse } from './api/client.ts'

const namespace = { bot: 'activity-bot', persona: 'activity-persona' }, scope = 'activity-bot/activity-persona'
const session = { status: 'ready', dashboard_session: 'authenticated', owner_session: 'unlocked', csrf_token: 'mock-activity-csrf' }
const workspace = { status: 'ready', projection: { namespace, access_generation: 1, views: [{ view_type: 'creation', status: 'available' }, { view_type: 'd06.memory_sources.v1', status: 'available' }], view_diagnostics: [], unavailable_domains: {}, command_routes: [] } }
const creation = { status: 'ready', projection: { namespace, access_generation: 1, view_type: 'creation', data: { candidates: [] }, coverage: { requested_types: ['d01.persona_plan.v1'], returned_atoms: 0, truncated: false }, next_cursor: null } }
const memory = { status: 'ready', projection: { namespace, access_generation: 1, view_type: 'd06.memory_sources.v1', data: { sources: [], coverage: 'complete' } } }
const response = (body: unknown, status = 200): FetchResponse => ({ ok: status >= 200 && status < 300, status, json: async () => body })
const flush = () => new Promise<void>(done => setTimeout(done, 0))
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done }); return { promise, resolve } }
async function controller(fetchImpl: FetchLike, enabled = true, timeoutMs = 1000) {
 let backend!: BackendController
 await renderToString(createSSRApp({ setup() { backend = useBackend({ enabled, fetchImpl, origin: 'https://activity.invalid', timeoutMs }); return () => h('div') } }))
 return backend
}
function material(name: string, opacity = 1) { const result = new THREE.MeshStandardMaterial({ name, opacity }); result.userData.originalOpacity = opacity; return result }

test('power is steady before selection and during selected idle; reduced motion has no activity gain', () => {
 for (const selected of [false, true]) for (const reduced of [false, true]) {
  const activity = makeOpticalActivity(), optic = material('MAT_archive_small_amber')
  for (let n = 0; n < 600; n++) {
   updateOpticalActivity(activity, 0, selected, selected && !reduced ? 'idle' : 'reading', 1 / 60, reduced)
   readingMaterial(optic, 'OPTIC_small', 1, 1, 'available', activity.level)
   assert.equal(activity.level, 0); assert.equal(optic.emissiveIntensity, .68)
  }
 }
 const activity = makeOpticalActivity(); for (let n = 0; n < 25; n++) updateOpticalActivity(activity, 0, true, 'demo', 1 / 60, false)
 assert.ok(activity.level > 0); updateOpticalActivity(activity, 0, true, 'demo', 1 / 60, true); assert.equal(activity.level, 0)
})

test('selected activity uses reproducible unequal gentle pulses, bounded amplitude and fewer than one peak per second', () => {
 const peakTimes = OPTICAL_ACTIVITY_PULSES.map(pulse => pulse.start + pulse.duration / 2)
 const gaps = peakTimes.map((time, i) => (i === 0 ? peakTimes.at(-1)! - OPTICAL_ACTIVITY_CYCLE : peakTimes[i - 1]!) * -1 + time)
 assert.ok(Math.min(...gaps) > 1); assert.ok(new Set(gaps.map(x => x.toFixed(2))).size > 3)
 assert.ok(OPTICAL_ACTIVITY_PULSES.every(pulse => pulse.duration >= .56 && pulse.gain <= OPTICAL_ACTIVITY_MAX))
 let previous = 0, maximumDelta = 0
 for (let n = 0; n <= 4440; n++) {
  const time = n / 600, value = sampleOpticalActivity(time)
  assert.ok(value >= 0 && value <= OPTICAL_ACTIVITY_MAX)
  assert.ok(Math.abs(value - sampleOpticalActivity(time + 2 * OPTICAL_ACTIVITY_CYCLE)) < 1e-12)
  maximumDelta = Math.max(maximumDelta, Math.abs(value - previous)); previous = value
 }
 assert.ok(maximumDelta < .0013)
 const a = makeOpticalActivity(), b = makeOpticalActivity()
 for (let n = 0; n < 1200; n++) { updateOpticalActivity(a, 4, true, 'reading', 1 / 60, false); updateOpticalActivity(b, 4, true, 'demo', 1 / 60, false); assert.deepEqual(a, b) }
})

test('activity changes only small-ring emission, keeping large-ring angle, material opacity and glass levels exact', () => {
 const still = makeReadingMotion(), active = makeReadingMotion(), activity = makeOpticalActivity()
 const pairs = [ ['ARCHIVE_body_1', 'MAT_archive_shell', .24], ['LID_panel_1', 'MAT_archive_lid', .10], ['OPTIC_main', 'MAT_archive_optics', 1], ['OPTIC_small', 'MAT_archive_small_amber', 1] ] as const
 for (let n = 0; n < 480; n++) {
  updateReadingMotion(still, 0, true, 1 / 60, false, 1); updateReadingMotion(active, 0, true, 1 / 60, false, 1)
  updateOpticalActivity(activity, 0, true, 'reading', 1 / 60, false); assert.deepEqual(still, active)
  for (const [node, name, opacity] of pairs) {
   const a = material(name, opacity), b = material(name, opacity)
   readingMaterial(a, node, .83, active.glow, 'available'); readingMaterial(b, node, .83, active.glow, 'available', activity.level)
   for (const key of ['opacity', 'roughness', 'transparent', 'depthWrite'] as const) assert.equal(a[key], b[key])
   assert.ok(a.color.equals(b.color)); assert.ok(a.emissive.equals(b.emissive))
   if (node === 'OPTIC_small') { assert.ok(b.emissiveIntensity >= a.emissiveIntensity); assert.ok(b.emissiveIntensity <= a.emissiveIntensity * 1.16) }
   else assert.equal(b.emissiveIntensity, a.emissiveIntensity)
   a.dispose(); b.dispose()
  }
 }
 for (const bad of [NaN, Infinity, -Infinity, -5, 9]) { const optic = material('MAT_archive_small_amber'); readingMaterial(optic, 'OPTIC_small', 1, 1, 'available', bad); assert.ok(optic.emissiveIntensity >= .68 && optic.emissiveIntensity <= .68 * 1.16) }
})

test('cancel/reselect and rapid pending changes never jump more than the slew bound; idle settles monotonically', () => {
 const activity = makeOpticalActivity(); let previous = 0
 for (let n = 0; n < 1000; n++) {
  updateOpticalActivity(activity, 0, true, n % 37 < 30 ? 'reading' : 'idle', 1 / 60, false)
  assert.ok(Math.abs(activity.level - previous) <= .8 / 60 + 1e-12); previous = activity.level
 }
 for (let n = 0; n < 60; n++) { updateOpticalActivity(activity, 0, true, 'idle', 1 / 60, false); assert.ok(activity.level <= previous); previous = activity.level }
 assert.equal(activity.level, 0); assert.equal(activity.elapsed, 0)
 updateOpticalActivity(activity, 0, true, 'reading', Infinity, false); assert.equal(activity.level, 0)
 for (let n = 0; n < 25; n++) updateOpticalActivity(activity, 0, true, 'reading', 1 / 60, false)
 assert.ok(activity.level > 0); updateOpticalActivity(activity, 0, false, 'reading', 1 / 60, false); assert.equal(activity.level, 0)
 for (let n = 0; n < 25; n++) updateOpticalActivity(activity, 0, true, 'reading', 1 / 60, false)
 bindOpticalActivity(activity, 9); assert.deepEqual(activity, { logical: 9, elapsed: 0, level: 0 })
})

test('live activity requires actual current pending state, never selection, server loading, auth, or offline state', () => {
 const base = { mode: 'same-origin', auth: 'authenticated', workspace: {}, view: {} }
 assert.equal(readActivityMode(base, false), 'idle')
 for (const key of ['workspace', 'view']) {
  const active = { ...base, [key]: { pending: true } }
  assert.equal(readActivityMode(active, false), 'reading'); assert.equal(readActivityMode(active, true), 'reading')
  assert.equal(readActivityMode(active, false, false), 'idle')
  for (const auth of ['checking', 'locked', 'error', 'offline']) assert.equal(readActivityMode({ ...active, auth }, false), 'idle')
  assert.equal(readActivityMode({ ...active, mode: 'offline' }, false), 'idle')
 }
 for (const status of ['loading', 'stale', 'error', 'unavailable', 'partial', 'empty', 'ready']) assert.equal(readActivityMode({ ...base, view: { status } } as typeof base, false), 'idle')
 assert.equal(readActivityMode({ ...base, mode: 'offline' }, true), 'demo')
 assert.equal(readActivityMode({ ...base, mode: 'offline' }, true, false), 'idle')
})

test('actual backend read lifecycle drives activity only during pending and stops on complete/loading/error', async () => {
 for (const result of [response(creation), response({ status: 'loading' }), response({ status: 'unavailable' }), response({ problem: { code: 'server_error' } }, 500)]) {
  const pending = deferred<FetchResponse>()
  const backend = await controller(async (url, init) => url.endsWith('/session') ? response(session) : JSON.parse(init.body as string).action === 'open_workspace' ? response(workspace) : pending.promise)
  await backend.checkSession(); backend.setScope(scope); backend.selectArchive('demo-persona')
  assert.equal(readActivityMode(backend.state, false), 'idle'); const request = backend.readView('creation')
  assert.equal(readActivityMode(backend.state, false), 'reading'); await flush(); assert.equal(readActivityMode(backend.state, false), 'reading')
  pending.resolve(result); await request; assert.equal(readActivityMode(backend.state, false), 'idle')
 }
})

test('actual pending workspace clears on navigation, scope change and revocation; stale completion cannot relight', async () => {
 for (const invalidate of [(b: BackendController) => b.invalidateView(), (b: BackendController) => b.setScope('other/persona'), (b: BackendController) => b.logout(), (b: BackendController) => b.selectArchive('demo-memory')]) {
  const pending = deferred<FetchResponse>(), backend = await controller(async url => url.endsWith('/session') ? response(session) : pending.promise)
  await backend.checkSession(); backend.setScope(scope); backend.selectArchive('demo-persona'); const read = backend.openWorkspace()
  assert.equal(readActivityMode(backend.state, false), 'reading'); const invalidation = invalidate(backend); assert.equal(readActivityMode(backend.state, false), 'idle')
  pending.resolve(response(workspace)); await read; await invalidation; assert.equal(readActivityMode(backend.state, false), 'idle')
 }
})

test('old view settlement cannot clear a newer selection activity; close/reopen duplicate stays idle until retry', async () => {
 const old = deferred<FetchResponse>(), latest = deferred<FetchResponse>(); let creationCalls = 0
 const backend = await controller(async (url, init) => {
  if (url.endsWith('/session')) return response(session)
  const command = JSON.parse(init.body as string)
  if (command.action === 'open_workspace') return response(workspace)
  if (command.input.view_type === 'creation') { ++creationCalls; return old.promise }
  return latest.promise
 })
 await backend.checkSession(); backend.setScope(scope); backend.selectArchive('demo-persona'); const first = backend.readView('creation'); await flush()
 backend.invalidateView(); backend.selectArchive('demo-persona'); await backend.readView('creation')
 assert.equal(backend.state.view.status, 'stale'); assert.equal(readActivityMode(backend.state, false), 'idle'); assert.equal(creationCalls, 1)
 backend.selectArchive('demo-memory'); const second = backend.readView('d06.memory_sources.v1'); await flush()
 assert.equal(readActivityMode(backend.state, false), 'reading'); old.resolve(response(creation)); await first
 assert.equal(readActivityMode(backend.state, false), 'reading'); latest.resolve(response(memory)); await second
 assert.equal(readActivityMode(backend.state, false), 'idle')
})

test('timeout and 401 revoke activity, while offline demo simulation makes no backend requests', async () => {
 const pending = deferred<FetchResponse>(), backend = await controller(async url => url.endsWith('/session') ? response(session) : pending.promise, true, 10)
 await backend.checkSession(); backend.setScope(scope); const request = backend.openWorkspace(); assert.equal(readActivityMode(backend.state, false), 'reading')
 await request; assert.equal(readActivityMode(backend.state, false), 'idle'); pending.resolve(response(workspace)); await flush(); assert.equal(readActivityMode(backend.state, false), 'idle')
 const forbidden = await controller(async url => url.endsWith('/session') ? response(session) : response({ problem: { code: 'owner_scope_denied' } }, 401))
 await forbidden.checkSession(); forbidden.setScope(scope); await forbidden.openWorkspace(); assert.equal(forbidden.state.auth, 'locked'); assert.equal(readActivityMode(forbidden.state, false), 'idle')
 let calls = 0; const offline = await controller(async () => { ++calls; return response(session) }, false)
 await offline.readView('creation'); await offline.openWorkspace(); assert.equal(readActivityMode(offline.state, true), 'demo'); assert.equal(calls, 0)
})

test('renderer gates activity to selected enabled slots and watches pending mode/reduced-motion changes', () => {
 const source = fs.readFileSync(new URL('./ArchiveArc.vue', import.meta.url), 'utf8')
 assert.match(source, /activity\?:ReadActivityMode/)
 assert.match(source, /props\.reduced\|\|props\.disabled\|\|!isReadingSelected\(slot\.logical,props\.frame\)\?0:item\.activity\.level/)
 assert.match(source, /props\.disabled\|\|\(props\.exitProgress\?\?0\)>0\?'idle':props\.activity\?\?'idle'/)
 assert.match(source, /props\.entryProgress,props\.activity,props\.disabled/)
 assert.match(source, /bindOpticalActivity\(item\.activity,slot\.logical\)/)
 assert.doesNotMatch(source, /Math\.random|setInterval/)
})
