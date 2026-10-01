import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import type { PersonaDossierResponse, ScopeCatalogResponse } from '../api/types'
import { useScopeStore } from './scope'

const { fetchScopeCatalogMock } = vi.hoisted(() => ({
  fetchScopeCatalogMock: vi.fn(),
}))

vi.mock('../api/client', () => ({
  fetchScopeCatalog: fetchScopeCatalogMock,
}))

function catalog(
  entries: Array<{
    bot: string
    persona: string
    session: string
    botGeneration?: number
    personaGeneration?: number
    sessionGeneration?: number
    scopeGeneration?: number
  }>,
): ScopeCatalogResponse {
  return {
    ok: true,
    scopes: entries.map((entry) => ({
      scope: {
        bot_ref: entry.bot,
        persona_ref: entry.persona,
        session_ref: entry.session,
      },
      generations: {
        bot: entry.botGeneration ?? 0,
        persona_lifecycle: entry.personaGeneration ?? 0,
        session: entry.sessionGeneration ?? 0,
        scope: entry.scopeGeneration ?? 0,
      },
    })),
  }
}

function dossierResponse(
  bot = 'bot_v1_A',
  persona = 'persona_v1_P',
  botGeneration = 0,
  personaGeneration = 0,
): PersonaDossierResponse {
  return {
    ok: true,
    persona_scope: {
      bot_ref: bot,
      persona_ref: persona,
    },
    generations: {
      bot: botGeneration,
      persona_lifecycle: personaGeneration,
    },
    persona: {
      display: 'Persona v1_P',
      ref_short: 'v1_P',
      fingerprint_short: 'fingerprint12',
      resolution: 'active',
      genesis: { state: 'awaiting' },
      updated_at_ms: 1,
    },
  }
}

describe('exact scope selection', () => {
  const values = new Map<string, string>()

  beforeEach(() => {
    values.clear()
    fetchScopeCatalogMock.mockReset()
    vi.stubGlobal('localStorage', {
      getItem: vi.fn((key: string) => values.get(key) ?? null),
      setItem: vi.fn((key: string, value: string) => values.set(key, value)),
      removeItem: vi.fn((key: string) => values.delete(key)),
    })
    setActivePinia(createPinia())
  })

  afterEach(() => vi.unstubAllGlobals())

  it('auto-selects only a unique item at each tier', () => {
    const store = useScopeStore()
    store.setCatalog(
      catalog([
        { bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S1' },
        { bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S2' },
      ]),
    )

    expect(store.selection).toEqual({
      botRef: 'bot_v1_A',
      personaRef: 'persona_v1_P',
      sessionRef: '',
    })
    expect(store.selectedScopeGeneration).toBeNull()
  })

  it('restores a complete selection only while every parent link remains valid', () => {
    values.set(
      'sylanne_scope_selection_v1',
      JSON.stringify({
        schema: 1,
        selection: {
          botRef: 'bot_v1_A',
          personaRef: 'persona_v1_P',
          sessionRef: 'session_v1_S2',
        },
      }),
    )
    const store = useScopeStore()
    store.setCatalog(
      catalog([
        { bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S1' },
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S2',
          scopeGeneration: 4,
        },
      ]),
    )

    expect(store.selection.sessionRef).toBe('session_v1_S2')
    expect(store.selectedScopeGeneration).toBe(4)
  })

  it('ignores the legacy single-session key and never falls back to the first session', () => {
    values.set('sylanne_session', 'session_v1_S1')
    const store = useScopeStore()
    store.setCatalog(
      catalog([
        { bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S1' },
        { bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S2' },
      ]),
    )

    expect(store.selection.sessionRef).toBe('')
    expect(localStorage.getItem).not.toHaveBeenCalledWith('sylanne_session')
  })

  it('clears descendants and increments the epoch when a parent changes', () => {
    const store = useScopeStore()
    store.setCatalog(
      catalog([
        { bot: 'bot_v1_A', persona: 'persona_v1_PA', session: 'session_v1_SA' },
        { bot: 'bot_v1_B', persona: 'persona_v1_PB', session: 'session_v1_SB' },
      ]),
    )
    store.selectBot('bot_v1_A')
    store.selectPersona('persona_v1_PA')
    store.selectSession('session_v1_SA')
    const before = store.selectionEpoch

    store.selectBot('bot_v1_B')

    expect(store.selection).toEqual({
      botRef: 'bot_v1_B',
      personaRef: '',
      sessionRef: '',
    })
    expect(store.selectionEpoch).toBe(before + 1)
  })

  it('invalidates the selection epoch when a selected generation changes', () => {
    const store = useScopeStore()
    store.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          scopeGeneration: 1,
        },
      ]),
    )
    const before = store.selectionEpoch

    store.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          scopeGeneration: 2,
        },
      ]),
    )

    expect(store.selection.sessionRef).toBe('session_v1_S')
    expect(store.selectedScopeGeneration).toBe(2)
    expect(store.selectionEpoch).toBe(before + 1)
  })

  it('rejects a response whose selection epoch, scope echo, or generation is stale', () => {
    const store = useScopeStore()
    store.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          scopeGeneration: 1,
        },
      ]),
    )
    const snapshot = store.snapshot()
    expect(snapshot).not.toBeNull()
    if (!snapshot) return

    expect(
      store.isCurrent(snapshot, {
        scope: {
          bot_ref: 'bot_v1_A',
          persona_ref: 'persona_v1_P',
          session_ref: 'session_v1_S',
        },
        scope_generation: 1,
      }),
    ).toBe(true)
    expect(
      store.isCurrent(snapshot, {
        scope: {
          bot_ref: 'bot_v1_A',
          persona_ref: 'persona_v1_P',
          session_ref: 'session_v1_other',
        },
        scope_generation: 1,
      }),
    ).toBe(false)
    expect(
      store.isCurrent(snapshot, {
        scope: {
          bot_ref: 'bot_v1_A',
          persona_ref: 'persona_v1_P',
          session_ref: 'session_v1_S',
        },
        scope_generation: 2,
      }),
    ).toBe(false)

    store.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          scopeGeneration: 2,
        },
      ]),
    )
    expect(store.isCurrent(snapshot)).toBe(false)
  })

  it('keeps a Persona snapshot current when only the Session changes', () => {
    const store = useScopeStore()
    store.setCatalog(
      catalog([
        { bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S1' },
        { bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S2' },
      ]),
    )
    store.selectSession('session_v1_S1')
    const snapshot = store.personaSnapshot()
    expect(snapshot).not.toBeNull()
    if (!snapshot) return
    const beforePersonaEpoch = store.personaEpoch

    store.selectSession('session_v1_S2')

    expect(store.personaEpoch).toBe(beforePersonaEpoch)
    expect(store.isPersonaCurrent(snapshot, dossierResponse())).toBe(true)
  })

  it('rejects a dossier response when the Persona lifecycle generation changes', () => {
    const store = useScopeStore()
    store.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          personaGeneration: 0,
        },
      ]),
    )
    const snapshot = store.personaSnapshot()
    expect(snapshot).not.toBeNull()
    if (!snapshot) return

    store.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          personaGeneration: 1,
        },
      ]),
    )

    expect(store.isPersonaCurrent(snapshot, dossierResponse())).toBe(false)
  })

  it('rejects a dossier response with a mismatched two-level echo', () => {
    const store = useScopeStore()
    store.setCatalog(
      catalog([{ bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S' }]),
    )
    const snapshot = store.personaSnapshot()
    expect(snapshot).not.toBeNull()
    if (!snapshot) return

    expect(store.isPersonaCurrent(snapshot, dossierResponse('bot_v1_A', 'persona_v1_other'))).toBe(
      false,
    )
  })

  it('reloads the authoritative catalog before issuing scoped requests', async () => {
    fetchScopeCatalogMock.mockResolvedValue(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          scopeGeneration: 3,
        },
      ]),
    )
    const store = useScopeStore()

    await store.refreshCatalog()

    expect(fetchScopeCatalogMock).toHaveBeenCalledOnce()
    expect(store.selection).toEqual({
      botRef: 'bot_v1_A',
      personaRef: 'persona_v1_P',
      sessionRef: 'session_v1_S',
    })
    expect(store.selectedScopeGeneration).toBe(3)
  })
})
