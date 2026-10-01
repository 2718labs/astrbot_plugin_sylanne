import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  ARRIVAL_CLEANUP_MS,
  ARRIVAL_CONTENT_DURATION_MS,
  ARRIVAL_CONTENT_MS,
  ARRIVAL_LINE_MS,
  ARRIVAL_NODE_FADE_MS,
  arrivalNodeDelay,
  prefersReducedMotion,
} from './arrival'

describe('dashboard arrival timing', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('exposes the approved phase durations', () => {
    expect(ARRIVAL_LINE_MS).toBe(1200)
    expect(ARRIVAL_NODE_FADE_MS).toBe(250)
    expect(ARRIVAL_CONTENT_MS).toBe(1200)
    expect(ARRIVAL_CONTENT_DURATION_MS).toBe(600)
    expect(ARRIVAL_CLEANUP_MS).toBe(1900)
  })

  it.each([
    [16, 192],
    [25, 300],
    [34, 408],
    [43, 516],
    [52, 624],
    [61, 732],
    [70, 840],
    [79, 948],
  ])('delays the %i%% node until the line reaches it', (top, delay) => {
    expect(arrivalNodeDelay(top)).toBe(delay)
  })

  it('detects reduced motion safely with and without a DOM', () => {
    vi.stubGlobal('window', undefined)
    expect(prefersReducedMotion()).toBe(false)

    const matchMedia = vi.fn(() => ({ matches: true }))
    vi.stubGlobal('window', { matchMedia })
    expect(prefersReducedMotion()).toBe(true)
    expect(matchMedia).toHaveBeenCalledWith('(prefers-reduced-motion: reduce)')
  })
})
