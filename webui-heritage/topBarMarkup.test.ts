import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

describe('standalone top bar logout control', () => {
  it('uses a localized, responsive text label without icon glyphs', () => {
    const source = readFileSync(
      new URL('./src/components/shell/TopBar.vue', import.meta.url),
      'utf8',
    )
    const logoutButton = source.match(
      /<button\s+v-if="canLogout"[\s\S]*?<\/button>/,
    )?.[0]
    const desktopStyles = source.match(/\.logout-chip\s*\{[^}]*\}/)?.[0]
    const mobileStyles = source
      .match(/@media \(max-width: 620px\) \{([\s\S]*)<\/style>/)?.[1]
      ?.match(/\.logout-chip\s*\{[^}]*\}/)?.[0]

    expect(logoutButton).toContain('class="chip logout-chip"')
    expect(logoutButton).toContain("{{ t('chrome.logout') }}")
    expect(logoutButton).not.toContain('<svg')
    expect(logoutButton).not.toContain('⏻')
    expect(desktopStyles).toContain('width: auto;')
    expect(desktopStyles).toContain('min-width: fit-content;')
    expect(desktopStyles).toContain('padding: 0 var(--space-3);')
    expect(desktopStyles).toContain('font-size: var(--font-xs);')
    expect(desktopStyles).toContain('white-space: nowrap;')
    expect(mobileStyles).toContain('width: auto;')
    expect(mobileStyles).toContain('padding: 0 var(--space-2);')
  })
})
