import { describe, expect, it } from 'vitest'
import * as session from './session'

describe('legacy single-session selection removal', () => {
  it('does not expose a selected-session store or session-id fallback helpers', () => {
    expect(session).not.toHaveProperty('useSessionStore')
    expect(session).not.toHaveProperty('sessionId')
    expect(session).not.toHaveProperty('sessionLabel')
  })
})
