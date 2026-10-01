import { describe, expect, it } from 'vitest'
import source from './TopBar.vue?raw'

describe('TopBar small-screen header contract', () => {
  it('keeps controls in one scrollable row below 420px', () => {
    const mobileStyles = source.slice(source.indexOf('@media (max-width: 420px)'))

    expect(mobileStyles).toContain('flex-wrap: nowrap')
    expect(mobileStyles).toContain('overflow-x: auto')
    expect(mobileStyles).toContain('overflow-y: hidden')
    expect(mobileStyles).not.toContain('flex-wrap: wrap')
  })
})
