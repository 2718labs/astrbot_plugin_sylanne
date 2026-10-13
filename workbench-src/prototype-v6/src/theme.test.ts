import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { createThemeController, normalizeTheme, resolveTheme, THEME_STORAGE_KEY } from './theme.ts'

function host(saved: string | null = null, dark = false, denied = false) {
  let listener: (() => void) | undefined
  const writes: string[] = [], applied: string[] = []
  const media = {
    matches: dark,
    addEventListener(_event: string, callback: unknown) { listener = callback as () => void },
    removeEventListener() { listener = undefined },
  }
  const storage = {
    getItem(key: string) { assert.equal(key, THEME_STORAGE_KEY); if (denied) throw Error('denied'); return saved },
    setItem(key: string, value: string) { assert.equal(key, THEME_STORAGE_KEY); if (denied) throw Error('denied'); writes.push(value) },
  }
  const state = createThemeController({ storage, media: media as never, apply: (value, preference) => applied.push(`${preference}:${value}`) })
  return { state, writes, applied, change(dark: boolean) { media.matches = dark; listener?.() }, listening: () => !!listener }
}
test('theme preferences normalize invalid/missing values to system', () => {
  for (const value of [null, undefined, '', 'sepia', false, {}]) assert.equal(normalizeTheme(value), 'system')
  assert.equal(resolveTheme('system', true), 'dark')
  assert.equal(resolveTheme('light', true), 'light')
  assert.equal(resolveTheme('dark', false), 'dark')
})
test('initial system mode follows OS and cleans up listener', () => {
  const h = host(null, true)
  assert.equal(h.state.preference.value, 'system'); assert.equal(h.state.resolved.value, 'dark')
  h.change(false); assert.equal(h.state.resolved.value, 'light')
  h.state.dispose(); assert.equal(h.listening(), false)
})
test('explicit setting persists and ignores OS until system is restored', () => {
  const h = host('dark')
  h.change(false); assert.equal(h.state.resolved.value, 'dark')
  h.state.setPreference('light'); h.change(true); assert.equal(h.state.resolved.value, 'light')
  h.state.setPreference('system'); assert.equal(h.state.resolved.value, 'dark')
  assert.deepEqual(h.writes, ['light', 'system'])
})
test('denied storage leaves changes usable in the current tab', () => {
  const h = host('dark', true, true)
  assert.equal(h.state.preference.value, 'system')
  assert.doesNotThrow(() => h.state.setPreference('light'))
  assert.equal(h.state.resolved.value, 'light')
})
test('head bootstrap resolves theme before app module and tolerates denied storage', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8')
  const script = html.match(/<script>([\s\S]*?)<\/script>/)![1]
  assert.ok(html.indexOf(script) < html.indexOf('/src/main.ts'))
  for (const [saved, os, expected] of [['dark', false, 'dark'], ['light', true, 'light'], ['system', true, 'dark'], ['invalid', false, 'light']] as const) {
    const document = { documentElement: { dataset: {}, style: {} } }
    vm.runInNewContext(script, { document, localStorage: { getItem: () => saved }, matchMedia: () => ({ matches: os }) })
    assert.equal((document.documentElement.dataset as {theme: string}).theme, expected)
  }
  const document = { documentElement: { dataset: {}, style: {} } }
  vm.runInNewContext(script, { document, localStorage: { getItem() { throw Error('blocked') } }, matchMedia: () => ({ matches: true }) })
  assert.equal((document.documentElement.dataset as {theme: string}).theme, 'dark')
})
test('responsive source reserves scene and footer, and scopes content to actual panel width', () => {
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8')
  assert.match(css, /--workspace-height:max\(900px,100svh\)/)
  assert.match(css, /@container reading-panel \(max-width:760px\)/)
  assert.match(css, /--stack-arc-top:930px/)
  assert.match(css, /\.theme-control select\{min-height:44px/)
  assert.match(css, /data-theme=dark\] \.official-logo-construction[^}]+background:#fff/)
})

test('detail body keeps a reachable scrollport instead of clipping fields',()=>{
 const css=readFileSync(new URL('./style.css',import.meta.url),'utf8')
 assert.match(css,/\.dashboard-scroll\{overflow:auto;overscroll-behavior:contain;scrollbar-width:thin;flex:1;min-height:0/)
 assert.match(css,/\.inline-dashboard\{[^}]*display:flex;flex-direction:column/)
 assert.match(css,/\.dashboard-scroll\{scroll-padding-block:20px;overflow-wrap:anywhere/)
 assert.match(css,/\.archive-copy\{[^}]*max-height:none;overflow:visible/)
 assert.match(css,/max-width:none;height:var\(--workspace-height\)/)
})
