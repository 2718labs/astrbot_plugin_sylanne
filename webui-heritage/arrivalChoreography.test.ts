import { existsSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const source = (path: string): string =>
  readFileSync(new URL(`./src/${path}`, import.meta.url), 'utf8')

describe('spine-first dashboard arrival choreography', () => {
  const appSource = source('App.vue')
  const loginSource = source('views/LoginView.vue')
  const layoutSource = source('components/shell/DashboardLayout.vue')
  const spineSource = source('components/shell/SpineNav.vue')

  it('removes the circular handoff while preserving the login confirmation', () => {
    expect(appSource).not.toContain('VoidVeil')
    expect(
      existsSync(new URL('./src/components/VoidVeil.vue', import.meta.url)),
    ).toBe(false)
    expect(loginSource).toContain('<SpecimenCanvas />')
    expect(loginSource).toContain('await delay(2200)')
    expect(loginSource).toContain('boot.requestArrival()')
    expect(loginSource).toContain('await router.replace(redirect)')
    expect(loginSource).toContain('boot.cancelArrival()')
    expect(loginSource).not.toMatch(
      /nextTick|useVoidTransition|voidTransition|expanding|revealing|veilSolid|Promise\.race/,
    )
  })

  it('enters the spine phase synchronously and clears it on schedule', () => {
    expect(layoutSource).toContain(
      "type ArrivalPhase = 'idle' | 'spine' | 'content'",
    )
    expect(layoutSource).toContain(
      "const arrivalPhase = ref<ArrivalPhase>('idle')",
    )
    expect(layoutSource).toMatch(
      /\{\s*immediate:\s*true,\s*flush:\s*'sync',?\s*\}/,
    )
    expect(layoutSource).toContain('ARRIVAL_CONTENT_MS')
    expect(layoutSource).toContain('ARRIVAL_CLEANUP_MS')
    expect(layoutSource).toContain('prefersReducedMotion()')
    expect(layoutSource).toContain("'arrival-spine': arrivalPhase === 'spine'")
    expect(layoutSource).toContain(
      "'arrival-content': arrivalPhase === 'content'",
    )
  })

  it('draws the spine first, then reveals all shell surfaces together', () => {
    const hiddenSurfaceRule =
      /\.arrival-spine \.area-top,\s*\.arrival-spine \.area-foot,\s*\.arrival-spine \.area-content > :deep\(\*\)\s*\{([^}]*)\}/

    expect(layoutSource).toMatch(
      /\.arrival-spine \.area-nav :deep\(\.spine-line\)\s*\{[^}]*animation:\s*spineDrawIn 1200ms linear both;/,
    )
    expect(layoutSource).toMatch(
      /\.arrival-spine \.area-nav :deep\(\.spine-node\),\s*\.arrival-spine \.area-nav :deep\(\.spine-handle\)\s*\{[^}]*animation:\s*spineNodeIn 250ms [^;]*var\(--arrival-delay\) backwards;/,
    )
    expect(layoutSource).toMatch(hiddenSurfaceRule)
    expect(layoutSource.match(hiddenSurfaceRule)?.[1]).toContain('opacity: 0;')
    expect(layoutSource.match(hiddenSurfaceRule)?.[1]).toContain(
      'visibility: hidden;',
    )
    expect(layoutSource.match(hiddenSurfaceRule)?.[1]).toContain(
      'pointer-events: none;',
    )
    expect(layoutSource).not.toContain(
      '.arrival-spine .area-content :deep(.card)',
    )
    expect(layoutSource).not.toMatch(
      /\.arrival-spine \.area-content\s*\{[^}]*opacity:\s*0;/,
    )
    expect(layoutSource).toContain(
      'animation: shellDropIn 600ms var(--ease-snap) both;',
    )
    expect(layoutSource).toContain(
      'animation: shellRiseIn 600ms var(--ease-snap) both;',
    )
    expect(layoutSource).toMatch(
      /\.arrival-content \.area-content :deep\(\.pane-left \.card\),[\s\S]*?animation-duration:\s*600ms;/,
    )
    expect(layoutSource).not.toMatch(/\.arrive(?:\s|\.)/)
    expect(layoutSource).not.toContain('nth-child')
  })

  it('assigns line-derived delays to every node and the active handle', () => {
    expect(spineSource).toContain(
      "import { arrivalNodeDelay } from '../../motion/arrival'",
    )
    expect(spineSource).toContain(
      "'--arrival-delay': arrivalNodeDelay(n.top) + 'ms'",
    )
    expect(spineSource).toContain(
      "'--arrival-delay': arrivalNodeDelay(NODES[activeIndex]?.top ?? MIN_TOP) + 'ms'",
    )
  })
})
