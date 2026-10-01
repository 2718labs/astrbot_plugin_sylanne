import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  morphFromRect,
  prefersReducedObservationMotion,
} from './observationChamberMotion'

describe('observation chamber motion', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('falls back safely for zero-sized or non-finite rectangles', () => {
    expect(morphFromRect({ left: 0, top: 0, width: 0, height: 1 }, { left: 1, top: 1, width: 1, height: 1 })).toBeNull()
    expect(morphFromRect({ left: Number.NaN, top: 0, width: 1, height: 1 }, { left: 1, top: 1, width: 1, height: 1 })).toBeNull()
  })

  it('maps the source card rectangle into the centered chamber rectangle', () => {
    const trigger = { left: 100, top: 200, width: 328, height: 168 }
    const dialog = { left: 512, top: 32, width: 800, height: 600 }

    expect(morphFromRect(trigger, dialog)).toEqual({
      translateX: -412,
      translateY: 168,
      scaleX: 0.41,
      scaleY: 0.28,
    })
  })

  it('skips geometry motion when reduced motion is requested', () => {
    vi.stubGlobal('window', undefined)
    expect(prefersReducedObservationMotion()).toBe(false)

    const matchMedia = vi.fn(() => ({ matches: true }))
    vi.stubGlobal('window', { matchMedia })
    expect(prefersReducedObservationMotion()).toBe(true)
    expect(matchMedia).toHaveBeenCalledWith('(prefers-reduced-motion: reduce)')
  })
})
