import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  ApiError,
  apiBase,
  apiFetch,
  fetchScopeCatalog,
  personaApiFetch,
  personaApiPath,
  scopedApiFetch,
  usesHostAuthentication,
} from './client'
import type {
  PersonaDossierResponse,
  PersonaRequestSnapshot,
  ScopeRequestSnapshot,
  ScopedApiResponse,
} from './types'

function stubToken(token = 'standalone-secret'): void {
  vi.stubGlobal('localStorage', {
    getItem: vi.fn((key: string) => (key === 'sylanne_token' ? token : null)),
    setItem: vi.fn(),
    removeItem: vi.fn(),
  })
}

function jsonResponse(data: unknown): Response {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    text: vi.fn().mockResolvedValue(JSON.stringify(data)),
  } as unknown as Response
}

function errorResponse(status: number, data: unknown): Response {
  return {
    ok: false,
    status,
    statusText: 'Forbidden',
    text: vi.fn().mockResolvedValue(JSON.stringify(data)),
  } as unknown as Response
}

function scopeSnapshot(): ScopeRequestSnapshot {
  return {
    selection: {
      botRef: 'bot_v1_A',
      personaRef: 'persona_v1_P',
      sessionRef: 'session_v1_S',
    },
    selectionEpoch: 3,
    scopeGeneration: 7,
  }
}

function personaSnapshot(): PersonaRequestSnapshot {
  return {
    selection: {
      botRef: 'bot_v1_A',
      personaRef: 'persona_v1_P',
    },
    personaEpoch: 5,
    botGeneration: 2,
    personaLifecycleGeneration: 3,
  }
}

function dossierResponse(): PersonaDossierResponse {
  return {
    ok: true,
    persona_scope: {
      bot_ref: 'bot_v1_A',
      persona_ref: 'persona_v1_P',
    },
    generations: { bot: 2, persona_lifecycle: 3 },
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

describe('apiBase', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it.each([
    [
      '/api/plug/astrbot_plugin_sylanne/dashboard',
      '/api/plug/astrbot_plugin_sylanne',
    ],
    [
      '/api/v1/plugins/extensions/astrbot_plugin_sylanne/dashboard',
      '/api/v1/plugins/extensions/astrbot_plugin_sylanne',
    ],
    ['/dashboard', ''],
  ])('preserves the host route prefix for %s', (pathname, expected) => {
    vi.stubGlobal('location', { pathname })

    expect(apiBase()).toBe(expected)
  })

  it('does not treat a plugin-name substring in a standalone path as host routing', () => {
    vi.stubGlobal('window', {})
    vi.stubGlobal('location', {
      pathname: '/dashboard/astrbot_plugin_sylanne-preview',
    })

    expect(apiBase()).toBe('')
    expect(usesHostAuthentication()).toBe(false)
  })

  it('uses the AstrBot bridge and converts query strings into GET params', async () => {
    const apiGet = vi.fn().mockResolvedValue({ tick_count: 7 })
    const apiPost = vi.fn()
    const fetchMock = vi.fn()
    vi.stubGlobal('window', { AstrBotPluginPage: { apiGet, apiPost } })
    vi.stubGlobal('location', {
      pathname: '/api/plugin/page/content/astrbot_plugin_sylanne/dashboard/index.html',
    })
    vi.stubGlobal('fetch', fetchMock)
    stubToken()

    await expect(apiFetch('/api/scopes?refresh=1')).resolves.toEqual({ tick_count: 7 })
    expect(apiGet).toHaveBeenCalledWith('api/scopes', { refresh: '1' })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(usesHostAuthentication()).toBe(true)
  })

  it('uses the AstrBot bridge for POST without leaking standalone auth', async () => {
    const apiGet = vi.fn()
    const apiPost = vi.fn().mockResolvedValue({ ok: true })
    vi.stubGlobal('window', { AstrBotPluginPage: { apiGet, apiPost } })
    vi.stubGlobal('location', {
      pathname: '/api/plugin/page/content/astrbot_plugin_sylanne/dashboard/index.html',
    })
    vi.stubGlobal('fetch', vi.fn())
    stubToken()

    await expect(
      apiFetch('/api/settings', { method: 'POST', body: { enabled: true } }),
    ).resolves.toEqual({ ok: true })
    expect(apiPost).toHaveBeenCalledWith('api/settings', { enabled: true })
  })

  it('routes a scoped GET through the AstrBot Pages broker without bootstrapping or leaking a nonce', async () => {
    const apiPost = vi.fn()
    const payload: ScopedApiResponse = {
      ok: true,
      scope: {
        bot_ref: 'bot_v1_A',
        persona_ref: 'persona_v1_P',
        session_ref: 'session_v1_S',
      },
      scope_generation: 7,
    }
    const apiGet = vi.fn().mockResolvedValue(payload)
    const fetchMock = vi.fn()
    vi.stubGlobal('window', { AstrBotPluginPage: { apiGet, apiPost } })
    vi.stubGlobal('location', {
      pathname: '/api/plugin/page/content/astrbot_plugin_sylanne/dashboard/index.html',
    })
    vi.stubGlobal('fetch', fetchMock)
    stubToken()

    await expect(scopedApiFetch<ScopedApiResponse>(scopeSnapshot(), 'state')).resolves.toEqual(
      payload,
    )

    expect(apiPost).not.toHaveBeenCalled()
    expect(apiGet).toHaveBeenCalledWith(
      'pages/api/v1/bots/bot_v1_A/personas/persona_v1_P/sessions/session_v1_S/state',
      {},
    )
    expect(JSON.stringify(apiGet.mock.calls)).not.toContain('scope_nonce')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('routes a Persona dossier GET through AstrBot Pages without a session nonce', async () => {
    const apiGet = vi.fn().mockResolvedValue(dossierResponse())
    const apiPost = vi.fn()
    const fetchMock = vi.fn()
    vi.stubGlobal('window', { AstrBotPluginPage: { apiGet, apiPost } })
    vi.stubGlobal('location', {
      pathname: '/api/plugin/page/content/astrbot_plugin_sylanne/dashboard/index.html',
    })
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()

    expect(personaApiPath(personaSnapshot())).toBe(
      '/api/v1/bots/bot_v1_A/personas/persona_v1_P/dossier',
    )
    await expect(personaApiFetch(personaSnapshot(), { signal: controller.signal })).resolves.toEqual(
      dossierResponse(),
    )

    expect(apiGet).toHaveBeenCalledWith(
      'api/v1/bots/bot_v1_A/personas/persona_v1_P/dossier',
      {},
    )
    expect(apiPost).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('rejects an already-aborted Persona dossier request before calling AstrBot Pages', async () => {
    const apiGet = vi.fn()
    vi.stubGlobal('window', { AstrBotPluginPage: { apiGet, apiPost: vi.fn() } })
    vi.stubGlobal('location', {
      pathname: '/api/plugin/page/content/astrbot_plugin_sylanne/dashboard/index.html',
    })
    const controller = new AbortController()
    controller.abort()

    await expect(personaApiFetch(personaSnapshot(), { signal: controller.signal })).rejects.toMatchObject({
      status: 0,
    })
    expect(apiGet).not.toHaveBeenCalled()
  })

  it('routes a scoped POST through the AstrBot Pages broker once with the exact body', async () => {
    const payload: ScopedApiResponse = {
      ok: true,
      scope: {
        bot_ref: 'bot_v1_A',
        persona_ref: 'persona_v1_P',
        session_ref: 'session_v1_S',
      },
      scope_generation: 7,
    }
    const apiGet = vi.fn()
    const apiPost = vi.fn().mockResolvedValue(payload)
    const fetchMock = vi.fn()
    vi.stubGlobal('window', { AstrBotPluginPage: { apiGet, apiPost } })
    vi.stubGlobal('location', {
      pathname: '/api/plugin/page/content/astrbot_plugin_sylanne/dashboard/index.html',
    })
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      scopedApiFetch<ScopedApiResponse>(scopeSnapshot(), 'memory/meltdown', {
        method: 'POST',
        body: { meltdown_nonce: 'arm_v1' },
      }),
    ).resolves.toEqual(payload)

    expect(apiPost).toHaveBeenCalledOnce()
    expect(apiPost).toHaveBeenCalledWith(
      'pages/api/v1/bots/bot_v1_A/personas/persona_v1_P/sessions/session_v1_S/memory/meltdown',
      { meltdown_nonce: 'arm_v1' },
    )
    expect(JSON.stringify(apiPost.mock.calls)).not.toContain('scope_nonce')
    expect(apiGet).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it.each([
    ['query', 'state?scope_nonce=forged', {}],
    ['case-variant query', 'state?Scope_Nonce=forged', {}],
    ['own body property', 'legacy-claim', { method: 'POST', body: { record_id: 'r', scope_nonce: 'forged' } }],
    ['case-variant header', 'state', { headers: { 'x-sylanne-scope-nonce': 'forged' } }],
  ])('rejects a Pages scope nonce carrier in %s before invoking the bridge', async (_carrier, endpoint, options) => {
    const apiGet = vi.fn()
    const apiPost = vi.fn()
    vi.stubGlobal('window', { AstrBotPluginPage: { apiGet, apiPost } })
    vi.stubGlobal('location', {
      pathname: '/api/plugin/page/content/astrbot_plugin_sylanne/dashboard/index.html',
    })

    const error = await scopedApiFetch(scopeSnapshot(), endpoint, options).catch(
      (caught: unknown) => caught,
    )

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 400 })
    expect(apiGet).not.toHaveBeenCalled()
    expect(apiPost).not.toHaveBeenCalled()
  })

  it('maps only the exact Pages scope-stale bridge error into the fixed 409 contract', async () => {
    const apiGet = vi.fn().mockRejectedValue(new Error('scope_stale'))
    vi.stubGlobal('window', { AstrBotPluginPage: { apiGet, apiPost: vi.fn() } })
    vi.stubGlobal('location', {
      pathname: '/api/plugin/page/content/astrbot_plugin_sylanne/dashboard/index.html',
    })

    const error = await scopedApiFetch(scopeSnapshot(), 'state').catch(
      (caught: unknown) => caught,
    )

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 409, data: { error: 'scope_stale' } })
  })

  it.each([
    '{"error":"scope_stale"}',
    'scope_stale ',
    'private backend detail',
  ])('does not trust or disclose another Pages bridge error: %s', async (message) => {
    const apiGet = vi.fn().mockRejectedValue(new Error(message))
    vi.stubGlobal('window', { AstrBotPluginPage: { apiGet, apiPost: vi.fn() } })
    vi.stubGlobal('location', {
      pathname: '/api/plugin/page/content/astrbot_plugin_sylanne/dashboard/index.html',
    })

    const error = await scopedApiFetch(scopeSnapshot(), 'state').catch(
      (caught: unknown) => caught,
    )

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 0, message: 'scoped Pages request failed' })
    expect((error as ApiError).data).toBeUndefined()
  })

  it('does not recover a scoped nonce bootstrap through legacy state when CSRF is absent', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      errorResponse(403, { error: 'csrf required' }),
    )
    vi.stubGlobal('window', {})
    vi.stubGlobal('location', { pathname: '/dashboard' })
    vi.stubGlobal('fetch', fetchMock)
    stubToken()

    const error = await scopedApiFetch<ScopedApiResponse>(scopeSnapshot(), 'state').catch(
      (caught: unknown) => caught,
    )

    expect(error).toMatchObject({ status: 403 })
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/scopes/bot_v1_A/personas/persona_v1_P/sessions/session_v1_S/nonce',
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('uses the catalog CSRF token for a standalone scoped bootstrap', async () => {
    const bootstrap = {
      ok: true,
      scope: {
        bot_ref: 'bot_v1_A',
        persona_ref: 'persona_v1_P',
        session_ref: 'session_v1_S',
      },
      scope_nonce: 'scope_nonce_v1_test',
    }
    const payload: ScopedApiResponse = {
      ok: true,
      scope: bootstrap.scope,
      scope_generation: 7,
    }
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ ok: true, scopes: [], csrf_token: 'catalog-csrf' }))
      .mockResolvedValueOnce(jsonResponse(bootstrap))
      .mockResolvedValueOnce(jsonResponse(payload))
    vi.stubGlobal('window', {})
    vi.stubGlobal('location', { pathname: '/dashboard' })
    vi.stubGlobal('fetch', fetchMock)
    stubToken()

    await expect(fetchScopeCatalog()).resolves.toMatchObject({ csrf_token: 'catalog-csrf' })
    await expect(scopedApiFetch<ScopedApiResponse>(scopeSnapshot(), 'state')).resolves.toEqual(
      payload,
    )

    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      '/api/scopes/bot_v1_A/personas/persona_v1_P/sessions/session_v1_S/nonce',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'X-CSRF-Token': 'catalog-csrf' }),
      }),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      '/api/v1/bots/bot_v1_A/personas/persona_v1_P/sessions/session_v1_S/state',
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          'X-Sylanne-Scope-Nonce': 'scope_nonce_v1_test',
        }),
      }),
    )
  })

  it('loads the authoritative scope catalog without a legacy session selector', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ ok: true, scopes: [] }),
    )
    vi.stubGlobal('window', {})
    vi.stubGlobal('location', { pathname: '/dashboard' })
    vi.stubGlobal('fetch', fetchMock)
    stubToken()

    await expect(fetchScopeCatalog()).resolves.toEqual({ ok: true, scopes: [] })
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/scopes',
      expect.objectContaining({ method: 'GET' }),
    )
  })

  it.each([
    ['/api/settings?mode=a', { method: 'POST', body: {} }, 'POST does not support query'],
    ['/api/state', { method: 'DELETE' }, 'does not support DELETE'],
    [
      '/api/state',
      { signal: new AbortController().signal },
      'does not support request cancellation',
    ],
  ])('rejects bridge requests whose semantics cannot be preserved', async (path, opts, message) => {
    const apiGet = vi.fn()
    const apiPost = vi.fn()
    vi.stubGlobal('window', { AstrBotPluginPage: { apiGet, apiPost } })
    vi.stubGlobal('location', {
      pathname: '/api/plugin/page/content/astrbot_plugin_sylanne/dashboard/index.html',
    })
    vi.stubGlobal('fetch', vi.fn())

    const error = await apiFetch(path, opts).catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 0 })
    expect((error as Error).message).toContain(message)
    expect(apiGet).not.toHaveBeenCalled()
    expect(apiPost).not.toHaveBeenCalled()
  })

  it('uses AstrBot host auth on the legacy wrapper without a Sylanne bearer', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ tick_count: 9 }))
    vi.stubGlobal('window', {})
    vi.stubGlobal('location', {
      pathname: '/api/plug/astrbot_plugin_sylanne/dashboard',
    })
    vi.stubGlobal('fetch', fetchMock)
    stubToken()

    await expect(apiFetch('/api/state')).resolves.toEqual({ tick_count: 9 })
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock.mock.calls[0][0]).toBe(
      '/api/plug/astrbot_plugin_sylanne/api/state',
    )
    expect(fetchMock.mock.calls[0][1].headers).not.toHaveProperty('Authorization')
    expect(usesHostAuthentication()).toBe(true)
  })

  it('keeps bearer authentication for the standalone 2718 server', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ tick_count: 11 }))
    vi.stubGlobal('window', {})
    vi.stubGlobal('location', { pathname: '/dashboard' })
    vi.stubGlobal('fetch', fetchMock)
    stubToken()

    await expect(apiFetch('/api/state')).resolves.toEqual({ tick_count: 11 })
    expect(fetchMock.mock.calls[0][1].headers).toMatchObject({
      Authorization: 'Bearer standalone-secret',
    })
    expect(usesHostAuthentication()).toBe(false)
  })

})
