import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import type { ScopeCatalogResponse, ScopedApiResponse } from '../api/types'
import { useLiveStore } from './live'
import { useScopeStore } from './scope'

const { fetchScopeCatalogMock, scopedApiFetchMock, isAstrBotPageMock } = vi.hoisted(() => ({
  fetchScopeCatalogMock: vi.fn(),
  scopedApiFetchMock: vi.fn(),
  isAstrBotPageMock: vi.fn(),
}))

vi.mock('../api/client', () => ({
  fetchScopeCatalog: fetchScopeCatalogMock,
  scopedApiFetch: scopedApiFetchMock,
}))

vi.mock('../api/astrBotBridge', () => ({
  isAstrBotPage: isAstrBotPageMock,
}))

interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason: unknown) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

function catalog(
  entries: Array<{ bot: string; persona: string; session: string; generation: number }>,
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
        bot: 1,
        persona_lifecycle: 1,
        session: 1,
        scope: entry.generation,
      },
    })),
  }
}

function scopedState(
  bot: string,
  persona: string,
  session: string,
  generation: number,
  tickCount: number,
): ScopedApiResponse {
  return {
    ok: true,
    scope: {
      bot_ref: bot,
      persona_ref: persona,
      session_ref: session,
    },
    scope_generation: generation,
    state: {
      tick_count: tickCount,
      gate: {},
      boundary: {},
    },
  }
}

function selectScope(bot: string, persona: string, session: string): void {
  const scope = useScopeStore()
  scope.selectBot(bot)
  scope.selectPersona(persona)
  scope.selectSession(session)
}

describe('live scoped polling', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    fetchScopeCatalogMock.mockReset()
    scopedApiFetchMock.mockReset()
    isAstrBotPageMock.mockReturnValue(false)
  })

  afterEach(() => {
    useLiveStore().stop()
  })

  it('loads the catalog before its first exact scoped state request', async () => {
    fetchScopeCatalogMock.mockResolvedValue(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          generation: 1,
        },
      ]),
    )
    scopedApiFetchMock.mockResolvedValue(
      scopedState('bot_v1_A', 'persona_v1_P', 'session_v1_S', 1, 8),
    )

    const live = useLiveStore()

    expect(await live.fetchOnce()).toBe(true)
    expect(fetchScopeCatalogMock).toHaveBeenCalledOnce()
    expect(scopedApiFetchMock).toHaveBeenCalledWith(
      expect.objectContaining({
        selection: {
          botRef: 'bot_v1_A',
          personaRef: 'persona_v1_P',
          sessionRef: 'session_v1_S',
        },
      }),
      'state',
      expect.anything(),
    )
    expect(live.state).toMatchObject({ tick_count: 8 })
  })

  it('projects safe delivery diagnostics from the scoped envelope into live state', async () => {
    const scope = useScopeStore()
    scope.setCatalog(catalog([{ bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S', generation: 1 }]))
    scopedApiFetchMock.mockResolvedValue({
      ...scopedState('bot_v1_A', 'persona_v1_P', 'session_v1_S', 1, 8),
      delivery: {
        pending: 2,
        failed_retryable: 1,
        outcome_unknown: 3,
        suppressed: 4,
        last_reason: 'delivery_outcome_unknown',
      },
    })

    const live = useLiveStore()
    expect(await live.fetchOnce()).toBe(true)
    expect(live.state?.delivery).toEqual({
      pending: 2,
      failed_retryable: 1,
      outcome_unknown: 3,
      suppressed: 4,
      last_reason: 'delivery_outcome_unknown',
    })
  })

  it('clears stale state and errors when the selected scope is incomplete', async () => {
    const scope = useScopeStore()
    scope.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_PA',
          session: 'session_v1_SA',
          generation: 1,
        },
        {
          bot: 'bot_v1_B',
          persona: 'persona_v1_PB',
          session: 'session_v1_SB',
          generation: 1,
        },
      ]),
    )
    scope.selectBot('bot_v1_A')
    const live = useLiveStore()
    live.state = { tick_count: 99 }
    live.error = 'previous scope failed'

    expect(await live.fetchOnce()).toBe(false)
    expect(live.state).toBeNull()
    expect(live.error).toBe('')
    expect(scopedApiFetchMock).not.toHaveBeenCalled()
  })

  it('discards a late response after the selected exact scope changes', async () => {
    const scope = useScopeStore()
    scope.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_PA',
          session: 'session_v1_SA',
          generation: 1,
        },
        {
          bot: 'bot_v1_B',
          persona: 'persona_v1_PB',
          session: 'session_v1_SB',
          generation: 1,
        },
      ]),
    )
    selectScope('bot_v1_A', 'persona_v1_PA', 'session_v1_SA')
    const late = deferred<ScopedApiResponse>()
    scopedApiFetchMock.mockReturnValueOnce(late.promise)
    const live = useLiveStore()

    const request = live.fetchOnce()
    selectScope('bot_v1_B', 'persona_v1_PB', 'session_v1_SB')
    late.resolve(scopedState('bot_v1_A', 'persona_v1_PA', 'session_v1_SA', 1, 1))

    expect(await request).toBe(false)
    expect(live.state).toBeNull()
    expect(live.error).toBe('')
  })

  it('reloads the catalog and retries one time when the response generation changes', async () => {
    const scope = useScopeStore()
    scope.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          generation: 1,
        },
      ]),
    )
    fetchScopeCatalogMock.mockResolvedValue(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          generation: 2,
        },
      ]),
    )
    scopedApiFetchMock
      .mockResolvedValueOnce(scopedState('bot_v1_A', 'persona_v1_P', 'session_v1_S', 2, 1))
      .mockResolvedValueOnce(scopedState('bot_v1_A', 'persona_v1_P', 'session_v1_S', 2, 2))
    const live = useLiveStore()

    expect(await live.fetchOnce()).toBe(true)
    expect(fetchScopeCatalogMock).toHaveBeenCalledOnce()
    expect(scopedApiFetchMock).toHaveBeenCalledTimes(2)
    expect(scope.selectedScopeGeneration).toBe(2)
    expect(live.state).toMatchObject({ tick_count: 2 })
  })

  it('clears stale state when a generation refresh removes the complete scope', async () => {
    const scope = useScopeStore()
    scope.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          generation: 1,
        },
      ]),
    )
    fetchScopeCatalogMock.mockResolvedValue(catalog([]))
    scopedApiFetchMock.mockResolvedValue(
      scopedState('bot_v1_A', 'persona_v1_P', 'session_v1_S', 2, 2),
    )
    const live = useLiveStore()
    live.state = { tick_count: 1 }
    live.error = 'old scope error'

    expect(await live.fetchOnce()).toBe(false)
    expect(live.state).toBeNull()
    expect(live.error).toBe('')
  })

  it('clears stale state when a scope-stale refresh removes the complete scope', async () => {
    const scope = useScopeStore()
    scope.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          generation: 1,
        },
      ]),
    )
    fetchScopeCatalogMock.mockResolvedValue(catalog([]))
    scopedApiFetchMock.mockRejectedValue({
      status: 409,
      data: { error: 'scope_stale' },
    })
    const live = useLiveStore()
    live.state = { tick_count: 1 }
    live.error = 'old scope error'

    expect(await live.fetchOnce()).toBe(false)
    expect(live.state).toBeNull()
    expect(live.error).toBe('')
  })

  it('serializes Pages polling and queues one fresh poll after the active request settles', async () => {
    const scope = useScopeStore()
    scope.setCatalog(
      catalog([
        {
          bot: 'bot_v1_A',
          persona: 'persona_v1_P',
          session: 'session_v1_S',
          generation: 1,
        },
      ]),
    )
    isAstrBotPageMock.mockReturnValue(true)
    const first = deferred<ScopedApiResponse>()
    scopedApiFetchMock
      .mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce(scopedState('bot_v1_A', 'persona_v1_P', 'session_v1_S', 1, 2))
    const live = useLiveStore()

    const running = live.fetchOnce()
    await vi.waitFor(() => expect(scopedApiFetchMock).toHaveBeenCalledTimes(1))
    expect(isAstrBotPageMock).toHaveReturnedWith(true)
    expect(await live.fetchOnce()).toBe(false)
    expect(scopedApiFetchMock).toHaveBeenCalledTimes(1)

    first.resolve(scopedState('bot_v1_A', 'persona_v1_P', 'session_v1_S', 1, 1))
    expect(await running).toBe(true)
    await vi.waitFor(() => expect(scopedApiFetchMock).toHaveBeenCalledTimes(2))
    expect(live.state).toMatchObject({ tick_count: 2 })
  })

  it('refreshes the catalog once and retries one fenced Pages scope-stale request', async () => {
    const scope = useScopeStore()
    scope.setCatalog(catalog([{ bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S', generation: 1 }]))
    isAstrBotPageMock.mockReturnValue(true)
    fetchScopeCatalogMock.mockResolvedValue(
      catalog([{ bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S', generation: 2 }]),
    )
    scopedApiFetchMock
      .mockRejectedValueOnce({ status: 409, data: { error: 'scope_stale' } })
      .mockResolvedValueOnce(scopedState('bot_v1_A', 'persona_v1_P', 'session_v1_S', 2, 22))

    const live = useLiveStore()
    expect(await live.fetchOnce()).toBe(true)
    expect(fetchScopeCatalogMock).toHaveBeenCalledOnce()
    expect(scopedApiFetchMock).toHaveBeenCalledTimes(2)
    expect(scopedApiFetchMock.mock.calls[0][0].scopeGeneration).toBe(1)
    expect(scopedApiFetchMock.mock.calls[1][0].scopeGeneration).toBe(2)
    expect(live.state).toMatchObject({ tick_count: 22, scope_generation: 2 })
  })

  it('discards a late Pages retry after the selected generation advances again', async () => {
    const scope = useScopeStore()
    scope.setCatalog(catalog([{ bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S', generation: 1 }]))
    isAstrBotPageMock.mockReturnValue(true)
    fetchScopeCatalogMock.mockResolvedValue(
      catalog([{ bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S', generation: 2 }]),
    )
    const lateRetry = deferred<ScopedApiResponse>()
    scopedApiFetchMock
      .mockRejectedValueOnce({ status: 409, data: { error: 'scope_stale' } })
      .mockReturnValueOnce(lateRetry.promise)

    const live = useLiveStore()
    const request = live.fetchOnce()
    await vi.waitFor(() => expect(scopedApiFetchMock).toHaveBeenCalledTimes(2))
    scope.setCatalog(catalog([{ bot: 'bot_v1_A', persona: 'persona_v1_P', session: 'session_v1_S', generation: 3 }]))
    lateRetry.resolve(scopedState('bot_v1_A', 'persona_v1_P', 'session_v1_S', 2, 22))

    expect(await request).toBe(false)
    expect(fetchScopeCatalogMock).toHaveBeenCalledOnce()
    expect(live.state).toBeNull()
  })
})
