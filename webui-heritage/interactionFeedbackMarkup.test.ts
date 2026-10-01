import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const source = (path: string): string =>
  readFileSync(new URL(`./src/${path}`, import.meta.url), 'utf8').replace(
    /\r\n?/g,
    '\n',
  )

function section(
  text: string,
  start: string,
  end: string,
): string {
  const from = text.indexOf(start)
  const to = text.indexOf(end, from + start.length)
  expect(from, `missing section start: ${start}`).toBeGreaterThanOrEqual(0)
  expect(to, `missing section end: ${end}`).toBeGreaterThan(from)
  return text.slice(from, to)
}

describe('visual-novel interaction feedback', () => {
  const footer = source('components/shell/AppFooter.vue')
  const layout = source('components/shell/DashboardLayout.vue')
  const topBar = source('components/shell/TopBar.vue')
  const config = source('views/ConfigView.vue')
  const life = source('views/LifeView.vue')
  const memory = source('views/MemoryView.vue')
  const i18n = source('composables/useI18n.ts')
  const feedbackSource = source('composables/useInteractionFeedback.ts')

  it('exposes readonly singleton state with owner-aware cleanup', () => {
    expect(feedbackSource).toMatch(
      /import\s*\{[^}]*readonly[^}]*\}\s*from 'vue'/,
    )
    expect(feedbackSource).toContain('const readonlyState = readonly(state)')
    expect(feedbackSource).toContain(
      'const feedback = { state: readonlyState, show, clear }',
    )
    expect(feedbackSource).toContain('function clear(expectedId?: number): boolean')
    expect(feedbackSource).toContain('if (expectedId !== undefined && state.value.id !== expectedId)')
    expect(feedbackSource).toContain('return false')
  })

  it('uses AppFooter as the single stable live-region renderer', () => {
    expect(footer).toContain("import { useInteractionFeedback }")
    expect(footer).toContain('aria-live="polite"')
    expect(footer).toContain('aria-atomic="true"')
    expect(footer).toContain('class="runtime"')
    expect(footer).toContain('class="narration"')
    expect(footer).toContain('class="sessions"')
    expect(footer).toContain("t('feedback.connection_interrupted')")
    expect(footer).toContain('schema')
    expect(footer).toContain('grid-template-columns:')
    expect(footer).toMatch(
      /@media\s*\(max-width:\s*620px\)[\s\S]*?\.narration\s*\{[^}]*white-space:\s*normal;/,
    )

    for (const producer of [layout, topBar, config, life, memory]) {
      expect(producer).not.toContain('aria-live=')
      expect(producer.toLowerCase()).not.toContain('toast')
    }
  })

  it('guards scoped switching and narrates only the current request', () => {
    const handler = section(
      topBar,
      'async function onScopeChange',
      'function onThemeToggle',
    )

    expect(handler).toContain('scope.selectBot(ref)')
    expect(handler).toContain('scope.selectPersona(ref)')
    expect(handler).toContain('scope.selectSession(ref)')
    expect(handler).toContain("t('feedback.session_switching')")
    expect(handler).toContain('sticky: true')
    expect(handler).toContain('const applied = await live.fetchOnce()')
    expect(handler).not.toContain('session.current')
    expect(handler).toContain("t('feedback.session_switched')")
    expect(handler).toContain('feedback.clear()')
    expect(topBar).toContain('function onThemeToggle')
    expect(topBar).toContain("t('feedback.theme_switched')")
    expect(topBar).toContain('function onLanguageToggle')
    expect(topBar).toContain("t('feedback.language_switched')")
  })

  it('reports connection restoration only after an error transition', () => {
    expect(layout).toMatch(
      /watch\(\s*\(\)\s*=>\s*live\.error,\s*\(current,\s*previous\)\s*=>/,
    )
    expect(layout).toContain('if (previous && !current)')
    expect(layout).toContain("t('feedback.connection_restored')")
    expect(layout).not.toContain('feedback.synced')
  })

  it('narrates settings saves without replacing the existing local state', () => {
    const save = section(config, 'async function save()', '\n</script>')

    expect(config).toContain('useInteractionFeedback')
    expect(config).toContain('conciseFeedbackError')
    expect(save).toContain("t('feedback.settings_saved')")
    expect(save).toContain("t('feedback.settings_failed')")
    expect(save).toContain('justSaved.value = true')
    expect(save).toContain('saveError.value')
    expect(save).toContain('savedTimer')
  })

  it('keeps life polling silent and narrates only controls and exports', () => {
    const poll = section(life, 'async function fetchAll()', '\nfunction start')
    const control = section(
      life,
      'async function postControl',
      '\nfunction onToggleEnabled',
    )
    const diagnostics = section(
      life,
      'async function exportDiagnostics',
      '\n</script>',
    )

    expect(poll).not.toContain('feedback.show')
    expect(control).toContain("t('feedback.operation_applied')")
    expect(control).toContain("t('feedback.operation_failed')")
    expect(diagnostics).toContain("t('feedback.diagnostics_exported')")
    expect(diagnostics).toContain("t('feedback.diagnostics_failed')")
    expect(life).toContain('controlsMsg.value')
  })

  it('keeps memory reads scoped and fails closed for unavailable workflows', () => {
    const poll = section(
      memory,
      'async function fetchPools()',
      '\nonMounted(() =>',
    )
    const meltdown = section(
      memory,
      'async function openMeltdown()',
      '\nonUnmounted(() => {\n  meltdownCancelled',
    )

    expect(poll).not.toContain('feedback.show')
    expect(poll).toContain('scopedApiFetch<ScopedMemoryPoolsResponse>')
    expect(memory).not.toContain('apiFetch(')
    expect(memory).not.toContain('async function startConsolidate()')
    expect(meltdown).toContain("t('feedback.meltdown_prepare_failed')")
    expect(meltdown).toContain("t('feedback.meltdown_execute_failed')")
    expect(meltdown).toContain('const snapshot = scope.snapshot()')
    expect(meltdown).toContain('scopedApiFetch')
    expect(meltdown).toMatch(/if\s*\(\s*!resp\.ok/)
    expect(memory).toContain('meltdownError.value')
  })

  it('defines every narration in both languages', () => {
    const keys = [
      'session_switching',
      'session_switched',
      'connection_interrupted',
      'connection_restored',
      'settings_saved',
      'settings_failed',
      'operation_applied',
      'operation_failed',
      'diagnostics_exported',
      'diagnostics_failed',
      'memory_organizing',
      'memory_completed',
      'memory_failed',
      'meltdown_prepare_failed',
      'meltdown_execute_failed',
      'theme_switched',
      'language_switched',
    ]

    for (const key of keys) {
      expect(i18n.match(new RegExp(`'feedback\\.${key}'`, 'g')) ?? []).toHaveLength(2)
    }
  })
})
