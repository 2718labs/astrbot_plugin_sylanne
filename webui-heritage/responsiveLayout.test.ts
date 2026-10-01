import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8')
}

describe('responsive dashboard shell contract', () => {
  it('allows the mobile content column and shell children to shrink', () => {
    const layout = source('./src/components/shell/DashboardLayout.vue')

    expect(layout).toContain('grid-template-columns: 56px minmax(0, 1fr)')
    expect(layout).toContain('min-width: 0')
  })

  it('has a compact mobile header and footer-safe runtime labels', () => {
    const topBar = source('./src/components/shell/TopBar.vue')
    const footer = source('./src/components/shell/AppFooter.vue')

    expect(topBar).toContain('@media (max-width: 620px)')
    expect(footer).toContain('runtime_id')
    expect(footer).not.toContain('runtime as string')
  })

  it('declares an inline favicon so standalone mode makes no missing-icon request', () => {
    expect(source('./index.html')).toContain('rel="icon"')
  })

  it('does not present unconditional v2 cognition as a disabled feature', () => {
    const i18n = source('./src/composables/useI18n.ts')

    expect(i18n).not.toContain('v2core 未启用')
    expect(i18n).not.toContain('v2core disabled')
  })
})
