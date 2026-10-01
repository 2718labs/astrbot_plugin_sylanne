/// <reference types="node" />

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function source(...parts: string[]): string {
  return readFileSync(resolve(sourceRoot, ...parts), 'utf8')
}

describe('Persona dossier UI contract', () => {
  it('wires every Personality card to the same accessible dossier entry point', () => {
    const view = source('views', 'PersonalityView.vue')
    const card = source('components', 'ui', 'Card.vue')

    expect(view.match(/@activate="openDossier"/g)).toHaveLength(3)
    expect(view.match(/\binteractive\b/g)).toHaveLength(3)
    expect(view).toContain('scope.personaSnapshot')
    expect(view).toContain('scope.isPersonaCurrent')
    expect(view).toContain('AbortController')
    expect(card).toContain('@click="activate"')
    expect(card).toContain("event.key === 'Enter' || event.key === ' '")
    expect(card).toContain("emit('activate', event)")
  })

  it('keeps the dossier read-only, safe, and clearable on Persona changes', () => {
    const view = source('views', 'PersonalityView.vue')
    const dossier = source('components', 'persona', 'PersonaDossier.vue')
    const i18n = source('composables', 'useI18n.ts')

    expect(view).toContain('clearDossier')
    expect(view).toContain('activeDossierRequest?.abort()')
    expect(view).not.toMatch(/\?session=/)
    expect(dossier).toContain('<Modal')
    expect(dossier).toContain("t('pers.dossier_base')")
    expect(dossier).toContain("t('pers.dossier_birth')")
    expect(dossier).toContain("t('pers.dossier_growth')")
    expect(dossier).toContain("t('pers.dossier_updated')")
    expect(dossier).not.toMatch(/<\/?(?:input|textarea)\b/i)
    expect(dossier).not.toMatch(/observation/i)
    expect(dossier).not.toMatch(/(?:fetch|personaApiFetch)\b/)
    expect(i18n.match(/'pers\.dossier_base'/g)).toHaveLength(2)
  })
})
