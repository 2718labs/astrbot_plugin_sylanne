import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import * as THREE from 'three'
import { ThemeTransition, THEME_TRANSITION_MS } from './theme.ts'
import { sceneLighting, themeSceneMaterial, labelInkColor, themeWeight } from './scene-presentation.ts'
import { readingMaterial } from './read-material.ts'

const close = (actual: number, expected: number) => assert.ok(Math.abs(actual - expected) < 1e-12, `${actual} ≈ ${expected}`)

test('theme clock starts settled in either palette and has exact monotonic endpoints', () => {
  for (const initial of [0, 1]) {
    const transition = new ThemeTransition(initial)
    assert.equal(transition.sample(4000), initial)
    assert.equal(transition.moving, false)
    transition.retarget(1 - initial, 4000)
    assert.equal(transition.sample(4000), initial)
    let prior = initial
    for (let i = 1; i <= 100; i++) {
      const value = transition.sample(4000 + THEME_TRANSITION_MS * i / 100)
      assert.ok(value >= 0 && value <= 1)
      assert.ok(initial === 0 ? value >= prior : value <= prior)
      prior = value
    }
    assert.equal(prior, 1 - initial)
    assert.equal(transition.moving, false)
  }
})

test('rapid theme reversal starts at the current sampled value with no palette reset', () => {
  const transition = new ThemeTransition(0)
  transition.retarget(1, 1000)
  const forward = transition.sample(1000 + THEME_TRANSITION_MS / 3)
  transition.retarget(0, 1000 + THEME_TRANSITION_MS / 3)
  assert.equal(transition.value, forward)
  assert.equal(transition.sample(1000 + THEME_TRANSITION_MS / 3), forward)
  const nextTime = 1000 + THEME_TRANSITION_MS / 2
  const reverse = transition.sample(nextTime)
  assert.ok(reverse < forward && reverse > 0)
  transition.retarget(1, nextTime)
  assert.equal(transition.value, reverse)
  assert.equal(transition.sample(nextTime), reverse)
  assert.equal(transition.sample(nextTime + THEME_TRANSITION_MS), 1)
  assert.equal(transition.moving, false)
})

test('setting the existing target does not restart its duration', () => {
  const transition = new ThemeTransition(0)
  transition.retarget(1, 1000)
  transition.retarget(1, 1000 + THEME_TRANSITION_MS / 2)
  close(transition.value, .5)
  assert.equal(transition.sample(1000 + THEME_TRANSITION_MS), 1)
  assert.equal(transition.moving, false)
})

test('reduced motion settles even the existing target immediately and stays settled', () => {
  const transition = new ThemeTransition(0)
  transition.retarget(1, 1000)
  transition.retarget(1, 1100, true)
  assert.equal(transition.value, 1)
  assert.equal(transition.moving, false)
  assert.equal(transition.sample(1150), 1)
  transition.retarget(0, 1200, true)
  assert.equal(transition.sample(1200), 0)
  assert.equal(transition.sample(4000), 0)
  assert.equal(transition.moving, false)
})

let hostSequence = 0
async function themeHost(t: {after: (callback: () => void) => void}, saved = 'light', systemDark = false, reduced = false) {
  const descriptors = new Map<string, PropertyDescriptor | undefined>()
  const patch = (key: string, value: unknown) => {
    descriptors.set(key, Object.getOwnPropertyDescriptor(globalThis, key))
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value })
  }
  t.after(() => {
    for (const [key, descriptor] of descriptors) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor)
      else Reflect.deleteProperty(globalThis, key)
    }
  })
  const query = (initial: boolean) => {
    const listeners = new Set<() => void>()
    return {
      matches: initial,
      addEventListener(_event: string, listener: () => void) { listeners.add(listener) },
      removeEventListener(_event: string, listener: () => void) { listeners.delete(listener) },
      change(matches: boolean) { this.matches = matches; for (const listener of listeners) listener() },
    }
  }
  const darkMedia = query(systemDark), reducedMedia = query(reduced)
  const properties = new Map<string, string>()
  const root = { dataset: {} as Record<string, string>, style: {
    colorScheme: '', backgroundColor: '',
    setProperty(key: string, value: string) { properties.set(key, value) },
  } }
  const callbacks = new Map<number, FrameRequestCallback>()
  const writes: string[] = []
  let now = 2000, nextRaf = 0
  patch('document', { documentElement: root })
  patch('window', { localStorage: { getItem: () => saved, setItem: (_key: string, value: string) => writes.push(value) }, matchMedia: (query: string) => query.includes('reduced-motion') ? reducedMedia : darkMedia })
  patch('performance', { now: () => now })
  patch('requestAnimationFrame', (callback: FrameRequestCallback) => { const id = ++nextRaf; callbacks.set(id, callback); return id })
  patch('cancelAnimationFrame', (id: number) => { callbacks.delete(id) })
  const module = await import(`./theme.ts?theme-transition-test=${++hostSequence}`)
  const state = module.initializeTheme()
  return {
    state, root, properties, writes, darkMedia, reducedMedia, callbacks,
    advance(milliseconds: number) { now += milliseconds; const pending = [...callbacks.values()]; callbacks.clear(); pending.forEach(callback => callback(now)) },
  }
}

test('saved or OS dark initialization paints 100% before any animation frame', async t => {
  const h = await themeHost(t, 'system', true)
  assert.equal(h.state.resolved.value, 'dark')
  assert.equal(h.state.darkMix.value, 1)
  assert.equal(h.root.dataset.theme, 'dark')
  assert.equal(h.root.style.backgroundColor, 'var(--page)')
  assert.equal(h.properties.get('--theme-dark-percent'), '100%')
  assert.equal(h.callbacks.size, 0)
})

test('runtime publishes the exact same sampled fraction to CSS and the scene ref, with one pending RAF', async t => {
  const h = await themeHost(t)
  h.state.setPreference('dark')
  assert.equal(h.state.darkMix.value, 0)
  assert.equal(h.callbacks.size, 1)
  h.advance(THEME_TRANSITION_MS / 2)
  close(h.state.darkMix.value, .5)
  close(parseFloat(h.properties.get('--theme-dark-percent')!) / 100, h.state.darkMix.value)
  h.state.setPreference('light')
  close(h.state.darkMix.value, .5)
  assert.equal(h.callbacks.size, 1)
  h.advance(THEME_TRANSITION_MS / 2)
  close(h.state.darkMix.value, .25)
  h.state.setPreference('dark')
  close(h.state.darkMix.value, .25)
  assert.equal(h.callbacks.size, 1)
  h.advance(THEME_TRANSITION_MS)
  assert.equal(h.state.darkMix.value, 1)
  assert.equal(h.properties.get('--theme-dark-percent'), '100%')
  assert.equal(h.callbacks.size, 0)
  assert.deepEqual(h.writes, ['dark', 'light', 'dark'])
})

test('application reduced motion cancels a running theme RAF and future palette changes snap', async t => {
  const h = await themeHost(t)
  h.state.setPreference('dark')
  h.advance(200)
  assert.ok(h.state.darkMix.value > 0 && h.state.darkMix.value < 1)
  h.state.setReducedMotion(true)
  assert.equal(h.state.darkMix.value, 1)
  assert.equal(h.properties.get('--theme-dark-percent'), '100%')
  assert.equal(h.callbacks.size, 0)
  h.state.setPreference('light')
  assert.equal(h.state.darkMix.value, 0)
  assert.equal(h.callbacks.size, 0)
  h.state.setReducedMotion(false)
  h.state.setPreference('dark')
  assert.equal(h.callbacks.size, 1)
})

test('OS reduced-motion changes cancel in-flight themes and remain authoritative over the app toggle', async t => {
  const h = await themeHost(t)
  h.state.setPreference('dark')
  h.advance(200)
  h.reducedMedia.change(true)
  assert.equal(h.state.darkMix.value, 1)
  assert.equal(h.callbacks.size, 0)
  h.state.setReducedMotion(false)
  h.state.setPreference('light')
  assert.equal(h.state.darkMix.value, 0)
  assert.equal(h.callbacks.size, 0)
  h.reducedMedia.change(false)
  h.state.setPreference('dark')
  assert.equal(h.callbacks.size, 1)
})

test('system appearance changes retarget the shared clock without overwriting explicit preferences', async t => {
  const h = await themeHost(t, 'system')
  h.darkMedia.change(true)
  h.advance(THEME_TRANSITION_MS / 2)
  close(h.state.darkMix.value, .5)
  h.darkMedia.change(false)
  close(h.state.darkMix.value, .5)
  h.advance(THEME_TRANSITION_MS)
  assert.equal(h.state.darkMix.value, 0)
  h.state.setPreference('light')
  h.darkMedia.change(true)
  assert.equal(h.state.resolved.value, 'light')
  assert.equal(h.state.darkMix.value, 0)
  assert.equal(h.callbacks.size, 0)
})

test('pre-module bootstrap supplies an actual dark background before CSS custom properties exist', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8')
  const script = html.match(/<script>([\s\S]*?)<\/script>/)![1]
  for (const [saved, systemDark] of [['dark', false], ['system', true]] as const) {
    const document = {documentElement: {dataset: {} as Record<string, string>, style: {} as Record<string, string>}}
    vm.runInNewContext(script, {document, localStorage: {getItem: () => saved}, matchMedia: () => ({matches: systemDark})})
    assert.equal(document.documentElement.dataset.theme, 'dark')
    assert.equal(document.documentElement.style.backgroundColor, '#151c20')
    assert.equal(document.documentElement.style.colorScheme, 'dark')
  }
})

test('fractional scene lighting and label ink use numeric theme endpoints without recompilation', () => {
  const light = sceneLighting(0), dark = sceneLighting(1), middle = sceneLighting(.5)
  for (const key of ['hemisphere', 'keyIntensity', 'rimIntensity', 'exposure'] as const) close(middle[key], (light[key] + dark[key]) / 2)
  for (const key of ['sky', 'ground', 'key', 'rim'] as const) for (const channel of ['r', 'g', 'b'] as const) close(middle[key][channel], (light[key][channel] + dark[key][channel]) / 2)
  assert.deepEqual(sceneLighting('light'), light)
  assert.deepEqual(sceneLighting('dark'), dark)
  const ink = new THREE.Color('#34434a')
  const middleInk = labelInkColor(ink, .5)
  assert.deepEqual(middleInk, ink, 'midpoint glass retains original dark printed ink, never flat gray')
  const material = new THREE.MeshStandardMaterial({ map: new THREE.Texture(), alphaTest: .32 })
  const map = material.map
  themeSceneMaterial(material, 'ARCHIVE_label', 0)
  const version = material.version, uniform = material.userData.archiveDarkInk
  for (const fraction of [0, .1, .5, .9, 1, .3, 0]) {
    themeSceneMaterial(material, 'ARCHIVE_label', fraction)
    assert.equal(material.userData.archiveDarkInk, uniform)
    assert.equal(uniform.value, fraction)
    assert.equal(material.map, map)
    assert.equal(material.alphaTest, .32)
    assert.equal(material.version, version)
  }
})

test('repeated fractional material application through the render path never compounds tint or resets optical properties', () => {
  for (const glow of [0, .37, 1]) {
    for (const [name, nodeName] of [['MAT_archive_shell', 'ARCHIVE_body'], ['MAT_archive_lid', 'LID_panel']] as const) {
      const material = new THREE.MeshStandardMaterial({name, color: '#D4DEE1', opacity: .7})
      material.userData.originalOpacity = .7
      const sample = (fraction: number) => {
        readingMaterial(material, nodeName, .8, glow, 'available')
        const opacity = material.opacity, roughness = material.roughness
        themeSceneMaterial(material, nodeName, fraction, glow)
        assert.equal(material.opacity, opacity)
        assert.equal(material.roughness, roughness)
        return material.color.clone()
      }
      const light = sample(0), dark = sample(1), expected = light.clone().lerp(dark, .5)
      for (let repeat = 0; repeat < 20; repeat++) {
        const actual = sample(.5)
        for (const channel of ['r', 'g', 'b'] as const) close(actual[channel], expected[channel])
      }
      assert.deepEqual(sample(0), light)
    }
  }
  assert.equal(themeWeight(Number.NaN), 0)
  assert.equal(themeWeight(-1), 0)
  assert.equal(themeWeight(2), 1)
})

test('theme source stays presentation-only and shares its numeric value with the existing scene instance', () => {
  const app = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  const theme = readFileSync(new URL('./theme.ts', import.meta.url), 'utf8')
  const scene = readFileSync(new URL('./ArchiveArc.vue', import.meta.url), 'utf8')
  assert.match(app, /<ArchiveArc :key="modelRevision"[^>]*:theme="theme\.darkMix\.value"/)
  assert.doesNotMatch(theme, /ArcEngine|DashboardFlow|backend|selectArchive|fetch\(/)
  assert.match(scene, /watch\(\(\)=>props\.theme,\(\)=>\{updateTheme\(\);render\(\)\}/)
  assert.doesNotMatch(scene, /watch\(\(\)=>props\.theme[^\n]*(?:init\(|dispose\(|GLTFLoader)/)
})
