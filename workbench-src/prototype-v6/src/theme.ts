import { readonly, ref } from 'vue'

export type ThemePreference = 'system' | 'light' | 'dark'
export type ResolvedTheme = 'light' | 'dark'
export const THEME_STORAGE_KEY = '2718lab.theme'
export function normalizeTheme(value: unknown): ThemePreference {
  return value === 'light' || value === 'dark' ? value : 'system'
}
export function resolveTheme(preference: ThemePreference, darkSystem: boolean): ResolvedTheme {
  return preference === 'system' ? (darkSystem ? 'dark' : 'light') : preference
}
export const THEME_TRANSITION_MS = 720
/** One source for live CSS and source-driven previews. Endpoint declarations in
 * style.css are verified against these values so pre-module paint also agrees. */
export const THEME_COLORS = {
  page: ['#f2f5f5', '#151c20'], gate: ['#f1f2ec', '#18201f'],
  surface: ['#fafcf9', '#202a2c'], 'surface-soft': ['#edf2e9', '#25322e'],
  button: ['#dfe8d1', '#3a4d35'], 'button-hover': ['#d2dfbf', '#465d3e'],
  'disabled-bg': ['#e9eeea', '#26322f'], 'error-bg': ['#f5e7de', '#3c2c26'],
  ink: ['#354348', '#e0e8e5'], muted: ['#586a70', '#acbdb8'],
  accent: ['#49622e', '#bed69e'], 'disabled-ink': ['#5e6e65', '#a0b2a9'],
  focus: ['#587020', '#c6e39d'], error: ['#874933', '#f3b89c'],
  line: ['#bdcacc', '#4a605a'], 'gate-line': ['#77816e', '#a7bba0'],
  'gate-bright': ['#ffffff', '#dde9de'],
} as const
export type ThemeColorToken = keyof typeof THEME_COLORS
export type ThemePalette = Record<ThemeColorToken | 'shadow', string>
export const THEME_POLARITY_CROSSOVER = .5
const themeSurfaces = new Set<ThemeColorToken>(['page', 'gate', 'surface', 'surface-soft', 'button', 'button-hover', 'disabled-bg', 'error-bg'])
const themeForegrounds = new Set<ThemeColorToken>(['ink', 'muted', 'accent', 'disabled-ink', 'focus', 'error'])
const rgbChannels = (hex: string) => [1, 3, 5].map(offset => parseInt(hex.slice(offset, offset + 2), 16))
const mixChannels = (from: number[], to: number[], fraction: number) => from.map((value, index) => value + (to[index]! - value) * fraction)
const rgbCss = (channels: number[]) => `rgb(${channels.map(value => Number(value.toFixed(6))).join(' ')})`
const unitTheme = (value: number) => Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0))
/** Both polarities exceed 4.5:1 against #757575. A continuous foreground that
 * changes from darker to lighter than a continuous background MUST cross 1:1.
 * Switch polarity once instead; never fade readable text through that hole.
 * Surfaces meet at the same neutral luminance, avoiding conflicting foreground
 * requirements across buttons, fields and the page. This is a pure sample of
 * the shared theme clock, including interruptions and direction reversals. */
export function sampleThemePalette(darkWeight: number): ThemePalette {
  const weight = unitTheme(darkWeight), dark = weight >= THEME_POLARITY_CROSSOVER
  const fraction = dark ? (weight - THEME_POLARITY_CROSSOVER) / (1 - THEME_POLARITY_CROSSOVER) : weight / THEME_POLARITY_CROSSOVER
  const palette = {} as ThemePalette
  for (const token of Object.keys(THEME_COLORS) as ThemeColorToken[]) {
    const [lightColor, darkColor] = THEME_COLORS[token]
    if (weight === 0 || weight === 1) { palette[token] = weight === 0 ? lightColor : darkColor; continue }
    const light = rgbChannels(lightColor), night = rgbChannels(darkColor)
    if (themeSurfaces.has(token)) {
      const crossover = [117, 117, 117]
      palette[token] = rgbCss(dark ? mixChannels(crossover, night, fraction) : mixChannels(light, crossover, fraction))
    } else if (themeForegrounds.has(token)) {
      palette[token] = rgbCss(dark ? mixChannels([255, 255, 255], night, fraction) : mixChannels(light, [0, 0, 0], fraction))
    } else {
      // Decorative lines/rings need no text-polarity switch.
      palette[token] = rgbCss(mixChannels(light, night, weight))
    }
  }
  // Interpolate shadows in premultiplied sRGB, matching CSS color-mix.
  const alpha = .08 + .12 * weight, lightShare = .08 * (1 - weight) / alpha
  palette.shadow = `rgba(${[28, 42, 37].map(channel => Number((channel * lightShare).toFixed(6))).join(', ')}, ${Number(alpha.toFixed(6))})`
  return palette
}
/** Runtime and exported previews can apply exactly the same sampled palette. */
export function applyThemePalette(style: Pick<CSSStyleDeclaration, 'setProperty'>, darkWeight: number) {
  const weight = unitTheme(darkWeight), palette = sampleThemePalette(weight)
  style.setProperty('--theme-dark-percent', `${weight * 100}%`)
  for (const [token, color] of Object.entries(palette)) style.setProperty(`--${token}`, color)
  return palette
}
/** Retarget from the visible weight; reversal never resets the palette branch. */
export class ThemeTransition {
  value: number; private from: number; private target: number; private started = 0
  constructor(dark = 0) { this.value = this.from = this.target = dark }
  sample(now: number) {
    const t = Math.max(0, Math.min(1, (now - this.started) / THEME_TRANSITION_MS))
    this.value = this.from + (this.target - this.from) * t * t * (3 - 2 * t)
    return this.value
  }
  retarget(dark: number, now: number, reduced = false) {
    this.sample(now)
    if (dark === this.target && !reduced) return
    this.from = this.value; this.target = dark; this.started = now
    if (reduced) this.value = this.from = dark
  }
  get moving() { return this.value !== this.target }
}
export interface ThemeEnvironment {
  storage?: Pick<Storage, 'getItem' | 'setItem'>
  media?: Pick<MediaQueryList, 'matches' | 'addEventListener' | 'removeEventListener'>
  apply: (resolved: ResolvedTheme, preference: ThemePreference) => void
}
/** Injectable environment keeps storage-denial and OS changes testable without a browser. */
export function createThemeController(environment: ThemeEnvironment) {
  let saved: unknown
  try { saved = environment.storage?.getItem(THEME_STORAGE_KEY) } catch { /* Private mode: use OS. */ }
  const preference = ref<ThemePreference>(normalizeTheme(saved))
  const resolved = ref<ResolvedTheme>(resolveTheme(preference.value, environment.media?.matches ?? false))
  function apply() {
    resolved.value = resolveTheme(preference.value, environment.media?.matches ?? false)
    environment.apply(resolved.value, preference.value)
  }
  function setPreference(value: unknown) {
    preference.value = normalizeTheme(value)
    try { environment.storage?.setItem(THEME_STORAGE_KEY, preference.value) } catch { /* Keep this tab usable. */ }
    apply()
  }
  const onSystemChange = () => { if (preference.value === 'system') apply() }
  environment.media?.addEventListener('change', onSystemChange)
  apply()
  return {
    preference: readonly(preference), resolved: readonly(resolved), setPreference,
    dispose: () => environment.media?.removeEventListener('change', onSystemChange),
  }
}
const darkMix = ref(0)
let manualReduced = false, themeRaf = 0
let transition: ThemeTransition | undefined
let reducedMedia: MediaQueryList | undefined
function paintTheme(now: number) {
  themeRaf = 0
  if (!transition) return
  darkMix.value = transition.sample(now)
  applyThemePalette(document.documentElement.style, darkMix.value)
  if (transition.moving) themeRaf = requestAnimationFrame(paintTheme)
}
function setReducedMotion(value: boolean) {
  manualReduced = value
  if (transition && (manualReduced || reducedMedia?.matches)) {
    transition.retarget(controller?.resolved.value === 'dark' ? 1 : 0, performance.now(), true)
    cancelAnimationFrame(themeRaf); paintTheme(performance.now())
  }
}
let controller: (ReturnType<typeof createThemeController> & {darkMix: typeof darkMix; setReducedMotion: typeof setReducedMotion}) | undefined
export function initializeTheme() {
  // Server render and small mounted-test hosts have no real document surface.
  if (typeof document === 'undefined' || !document.documentElement || typeof window === 'undefined') {
    return {...createThemeController({ apply() {} }), darkMix, setReducedMotion}
  }
  if (controller) return controller
  let storage: Storage | undefined
  try { storage = window.localStorage } catch { /* Sandboxed preview or private mode. */ }
  reducedMedia = window.matchMedia?.('(prefers-reduced-motion: reduce)')
  reducedMedia?.addEventListener('change', () => setReducedMotion(manualReduced))
  controller = {...createThemeController({
    storage,
    media: typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-color-scheme: dark)') : undefined,
    apply(resolved, preference) {
      document.documentElement.dataset.theme = resolved
      document.documentElement.dataset.themePreference = preference
      document.documentElement.style.colorScheme = resolved
      document.documentElement.style.backgroundColor = 'var(--page)'
      const target = resolved === 'dark' ? 1 : 0
      if (!transition) transition = new ThemeTransition(target)
      else transition.retarget(target, performance.now(), manualReduced || !!reducedMedia?.matches)
      cancelAnimationFrame(themeRaf); paintTheme(performance.now())
    },
  }), darkMix, setReducedMotion}
  return controller
}
export function useTheme() { return initializeTheme() }
