import { describe, expect, it } from 'vitest'
import { isNestedInteractiveTarget } from './cardInteraction'

describe('card interaction guard', () => {
  it('allows the interactive card itself while blocking a nested role button', () => {
    const card = {} as EventTarget
    const cardTarget = { closest: () => card } as unknown as EventTarget
    const nestedButton = {} as EventTarget
    const nestedTarget = { closest: () => nestedButton } as unknown as EventTarget

    expect(isNestedInteractiveTarget(cardTarget, card)).toBe(false)
    expect(isNestedInteractiveTarget(nestedTarget, card)).toBe(true)
  })
})
