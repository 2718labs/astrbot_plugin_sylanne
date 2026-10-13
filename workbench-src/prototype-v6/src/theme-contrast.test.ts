import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as THREE from 'three'
import { THEME_COLORS, THEME_POLARITY_CROSSOVER, THEME_TRANSITION_MS, ThemeTransition, applyThemePalette, sampleThemePalette, type ThemeColorToken, type ThemePalette } from './theme.ts'
import { labelInkColor, labelInkPolarity, LABEL_INK_POLARITY_CROSSOVER, LABEL_INK_SHADER, themeSceneMaterial } from './scene-presentation.ts'

// Enumerate actual foreground/surface uses in style.css and component styles.
// Disabled controls are included voluntarily; decorative lines/rings are not text.
const textPairs: [ThemeColorToken, ThemeColorToken][] = [
  ...['page', 'gate', 'surface', 'surface-soft', 'button', 'button-hover', 'disabled-bg'].map(background => ['ink', background]),
  ...['page', 'gate', 'surface', 'surface-soft', 'disabled-bg', 'error-bg'].map(background => ['muted', background]),
  ...['page', 'gate', 'surface', 'surface-soft'].map(background => ['accent', background]),
  ...['page', 'gate', 'surface', 'disabled-bg'].map(background => ['disabled-ink', background]),
  ...['page', 'gate', 'surface', 'error-bg'].map(background => ['error', background]),
] as [ThemeColorToken, ThemeColorToken][]
const focusSurfaces: ThemeColorToken[] = ['page', 'gate', 'surface', 'surface-soft', 'button', 'button-hover', 'disabled-bg', 'error-bg']
function channels(color: string) {
  return color.startsWith('#') ? [1, 3, 5].map(index => parseInt(color.slice(index, index + 2), 16)) : color.match(/[\d.]+/g)!.slice(0, 3).map(Number)
}
function luminance(color: string) {
  const rgb = channels(color).map(channel => channel / 255).map(channel => channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4)
  return rgb[0]! * .2126 + rgb[1]! * .7152 + rgb[2]! * .0722
}
function contrast(a: string, b: string) {
  const first = luminance(a), second = luminance(b)
  return (Math.max(first, second) + .05) / (Math.min(first, second) + .05)
}
function checkPalette(palette: ThemePalette, at: string) {
  for (const [foreground, background] of textPairs) {
    const ratio = contrast(palette[foreground], palette[background])
    assert.ok(ratio >= 4.5, `${at} ${foreground}/${background}: ${ratio}:1`)
  }
  for (const background of focusSurfaces) assert.ok(contrast(palette.focus, palette[background]) >= 3, `${at} focus/${background}`)
  // The entry welcome uses these tokens in reverse.
  assert.ok(contrast(palette.gate, palette.ink) >= 4.5, `${at} reversed welcome lockup`)
}

test('all source text/surface pairs stay above 4.5:1 at 10,001 palette samples, including the old washout', t => {
  let minimum = { ratio: Infinity, weight: 0, pair: '' }
  for (let index = 0; index <= 10000; index++) {
    const weight = index / 10000, palette = sampleThemePalette(weight)
    checkPalette(palette, `weight ${weight}`)
    for (const [foreground, background] of textPairs) {
      const ratio = contrast(palette[foreground], palette[background])
      if (ratio < minimum.ratio) minimum = { ratio, weight, pair: `${foreground}/${background}` }
    }
  }
  for (const weight of [.4694, .4718, .5 - 1e-9, .5, .5 + 1e-9]) checkPalette(sampleThemePalette(weight), `crossover ${weight}`)
  t.diagnostic(`Minimum across ${textPairs.length} text/surface pairs: ${minimum.ratio.toFixed(6)}:1 at ${minimum.weight}, ${minimum.pair}; focus >= 3:1`)
})

test('every millisecond of both 720 ms directions and rapid reversal retains readable sampled colors', () => {
  for (const initial of [0, 1]) {
    const transition = new ThemeTransition(initial)
    transition.retarget(1 - initial, 0)
    for (let ms = 0; ms <= THEME_TRANSITION_MS; ms++) checkPalette(sampleThemePalette(transition.sample(ms)), `${initial}→${1 - initial}, ${ms}ms`)
    assert.equal(transition.value, 1 - initial)
  }
  const transition = new ThemeTransition(0)
  const events = new Map([[0, 1], [180, 0], [240, 1], [601, 0], [720, 1], [1101, 0]])
  for (let ms = 0; ms <= 1900; ms++) {
    const value = transition.sample(ms), palette = sampleThemePalette(value)
    if (events.has(ms)) {
      transition.retarget(events.get(ms)!, ms)
      assert.equal(transition.sample(ms), value)
      assert.deepEqual(sampleThemePalette(transition.value), palette, 'retarget must not reset a visible palette')
    }
    checkPalette(palette, `reversal ${ms}ms`)
  }
  assert.equal(transition.value, 0)
  transition.retarget(1, 2000, true)
  assert.deepEqual(sampleThemePalette(transition.sample(2000)), sampleThemePalette(1))
  assert.equal(transition.moving, false)
})

test('only foreground polarity changes abruptly; all surfaces remain continuous at the safe crossover', () => {
  const before = sampleThemePalette(THEME_POLARITY_CROSSOVER - 1e-9), at = sampleThemePalette(THEME_POLARITY_CROSSOVER)
  for (const token of focusSurfaces) for (let channel = 0; channel < 3; channel++) assert.ok(Math.abs(channels(before[token])[channel]! - channels(at[token])[channel]!) < 1e-5)
  assert.ok(luminance(before.ink) < .001)
  assert.ok(luminance(at.ink) > .999)
  for (const palette of [before, at]) checkPalette(palette, 'polarity switch')
  const page = sampleThemePalette(.5).page
  assert.ok(contrast('#000000', page) >= 4.5 && contrast('#ffffff', page) >= 4.5)
})

test('runtime and preview helper publish the exact same complete CSS palette and keep endpoint bootstrap in sync', () => {
  for (const weight of [0, .1, .4694, .5 - 1e-9, .5, .75, 1, NaN, -2, 4]) {
    const properties = new Map<string, string>()
    const palette = applyThemePalette({ setProperty(name: string, value: string) { properties.set(name, value) } }, weight)
    assert.deepEqual(palette, sampleThemePalette(weight))
    assert.equal(properties.size, Object.keys(palette).length + 1)
    for (const [token, color] of Object.entries(palette)) assert.equal(properties.get(`--${token}`), color)
  }
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8')
  const section = css.slice(css.indexOf('/* v23 theme endpoint fallbacks.'), css.indexOf('body{background:var(--page);color:var(--ink)}'))
  const root = section.match(/:root\{([^}]+)\}/)![1]!, dark = section.match(/:root\[data-theme=dark\]\{([^}]+)\}/)![1]!
  for (const [token, endpoints] of Object.entries(THEME_COLORS)) {
    assert.ok(root.includes(`--${token}:${endpoints[0]};`), `light ${token}`)
    assert.ok(dark.includes(`--${token}:${endpoints[1]};`), `dark ${token}`)
    assert.equal(sampleThemePalette(0)[token as ThemeColorToken], endpoints[0])
    assert.equal(sampleThemePalette(1)[token as ThemeColorToken], endpoints[1])
  }
  assert.doesNotMatch(section, /color-mix/)
  const source = readFileSync(new URL('./theme.ts', import.meta.url), 'utf8')
  assert.match(source, /applyThemePalette\(document.documentElement.style, darkMix.value\)/)
})

test('GLB label ink never collapses distinct printed colors into one gray during transition or reversal', () => {
  const inks = ['#10252c', '#34434a', '#61716a'].map(color => new THREE.Color(color))
  for (let index = 0; index <= 1000; index++) {
    const weight = index / 1000, adapted = inks.map(color => labelInkColor(color, weight))
    for (let inkIndex = 0; inkIndex < inks.length; inkIndex++) {
      const source = inks[inkIndex]!, target = adapted[inkIndex]!
      for (const channel of ['r', 'g', 'b'] as const) assert.equal(target[channel], labelInkPolarity(weight) ? 1 - source[channel] : source[channel])
    }
    assert.notDeepEqual(adapted[0], adapted[1])
    assert.notDeepEqual(adapted[1], adapted[2])
  }
  assert.equal(labelInkPolarity(LABEL_INK_POLARITY_CROSSOVER - 1e-9), 0)
  assert.equal(labelInkPolarity(LABEL_INK_POLARITY_CROSSOVER), 1)
  assert.match(LABEL_INK_SHADER, /step\(0\.8, archiveDarkInk\)/)
  assert.doesNotMatch(LABEL_INK_SHADER, /\.a\s*=/)
  const material = new THREE.MeshStandardMaterial({ map: new THREE.Texture(), alphaTest: .32 }), map = material.map
  themeSceneMaterial(material, 'ARCHIVE_label', 0)
  const version = material.version, uniform = material.userData.archiveDarkInk
  for (const weight of [.5, .7999, .8, .9, 1, .8, .7999, .5, 0]) {
    themeSceneMaterial(material, 'ARCHIVE_label', weight)
    assert.equal(material.version, version)
    assert.equal(material.map, map)
    assert.equal(material.userData.archiveDarkInk, uniform)
    assert.equal(material.alphaTest, .32)
  }
})
