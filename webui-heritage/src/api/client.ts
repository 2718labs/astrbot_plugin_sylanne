// Single API client for the frozen backend contract.
// - Bearer token (localStorage 'sylanne_token')
// - CSRF double-submit: capture csrf_token from JSON responses (including the
//   scope catalog), then echo it as X-CSRF-Token on standalone non-GET calls.
// - 401 anywhere -> clear token + notify (hard logout), matching the old UI.
// - Resolves /api/* under BOTH serving contexts: standalone (port 2718, '/')
//   and AstrBot-native (served under '/astrbot_plugin_sylanne/...').

import { devMock } from './devMock'
import { bridgeFetch, getAstrBotBridge } from './astrBotBridge'
import type {
  PersonaDossierResponse,
  PersonaPath,
  PersonaRequestSnapshot,
  ScopeBootstrapResponse,
  ScopeCatalogResponse,
  ScopePath,
  ScopeRequestSnapshot,
  ScopedApiResponse,
} from './types'

const TOKEN_KEY = 'sylanne_token'
let csrfToken = ''

export function apiBase(): string {
  const p = typeof location !== 'undefined' ? location.pathname : ''
  const pluginName = 'astrbot_plugin_sylanne'
  const segments = p.split('/')
  const pluginIndex = segments.indexOf(pluginName)
  return pluginIndex >= 0 ? segments.slice(0, pluginIndex + 1).join('/') : ''
}

export function usesHostAuthentication(): boolean {
  return getAstrBotBridge() !== null || apiBase() !== ''
}

export function getToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) || ''
  } catch {
    return ''
  }
}
export function setToken(t: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, t)
  } catch {
    /* ignore */
  }
}
export function clearToken(): void {
  try {
    localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* ignore */
  }
}

type Handler = () => void
let onUnauthorized: Handler | null = null
export function setUnauthorizedHandler(h: Handler): void {
  onUnauthorized = h
}

export class ApiError extends Error {
  status: number
  data?: unknown
  constructor(status: number, message: string, data?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.data = data
  }
}

export interface ApiOptions {
  method?: string
  body?: unknown
  signal?: AbortSignal
  auth?: boolean
  headers?: Record<string, string>
}

export function fetchScopeCatalog(): Promise<ScopeCatalogResponse> {
  return apiFetch<ScopeCatalogResponse>('/api/scopes')
}

export async function apiFetch<T = unknown>(path: string, opts: ApiOptions = {}): Promise<T> {
  const bridge = getAstrBotBridge()
  if (bridge) {
    try {
      return await bridgeFetch<T>(bridge, path, opts)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error || 'bridge failed')
      throw new ApiError(0, message)
    }
  }

  const method = (opts.method || 'GET').toUpperCase()
  const standaloneAuth = !usesHostAuthentication()
  const headers: Record<string, string> = { ...opts.headers }
  const token = getToken()
  if (standaloneAuth && opts.auth !== false && token) {
    headers['Authorization'] = 'Bearer ' + token
  }

  let body: BodyInit | undefined
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.body)
  }
  if (standaloneAuth && method !== 'GET' && csrfToken) {
    headers['X-CSRF-Token'] = csrfToken
  }

  // DEV-only mock (dead-code-stripped from production: import.meta.env.DEV is a
  // build-time constant). Used ONLY as a fallback when a mockable path yields no
  // usable response — a real backend (via the dev proxy) always wins.
  const mockable = import.meta.env.DEV ? devMock(path, method) : undefined
  const returnMock = (m: unknown): T => {
    if (m && typeof m === 'object') {
      const c = (m as Record<string, unknown>).csrf_token
      if (typeof c === 'string' && c) csrfToken = c
    }
    return m as T
  }

  let res: Response
  try {
    res = await fetch(apiBase() + path, { method, headers, body, signal: opts.signal })
  } catch (err) {
    if (mockable !== undefined) return returnMock(mockable)
    throw err
  }

  if (res.status === 401) {
    if (standaloneAuth) {
      clearToken()
      if (onUnauthorized) onUnauthorized()
    }
    throw new ApiError(401, 'unauthorized')
  }

  const text = await res.text()
  let data: unknown = undefined
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
  }
  // DEV: no usable JSON object (proxy error / SPA index.html fallback / non-ok)
  // for a mockable path -> use the mock.
  if (mockable !== undefined && (!res.ok || data === null || typeof data !== 'object')) {
    return returnMock(mockable)
  }

  if (data && typeof data === 'object') {
    const c = (data as Record<string, unknown>).csrf_token
    if (typeof c === 'string' && c) csrfToken = c
  }
  if (!res.ok) {
    const msg =
      (data && typeof data === 'object' && typeof (data as Record<string, unknown>).error === 'string'
        ? ((data as Record<string, unknown>).error as string)
        : '') || res.statusText
    throw new ApiError(res.status, msg, data)
  }
  return data as T
}

const SCOPE_NONCE_HEADER = 'X-Sylanne-Scope-Nonce'

function encodedScopePath(scope: ScopePath): string {
  return [scope.bot_ref, scope.persona_ref, scope.session_ref]
    .map((part) => encodeURIComponent(part))
    .join('/')
}

function snapshotScope(snapshot: ScopeRequestSnapshot): ScopePath {
  const scope = {
    bot_ref: snapshot.selection.botRef,
    persona_ref: snapshot.selection.personaRef,
    session_ref: snapshot.selection.sessionRef,
  }
  if (!scope.bot_ref || !scope.persona_ref || !scope.session_ref) {
    throw new ApiError(400, 'complete scope required')
  }
  return scope
}

function snapshotPersona(snapshot: PersonaRequestSnapshot): PersonaPath {
  const persona = {
    bot_ref: snapshot.selection.botRef,
    persona_ref: snapshot.selection.personaRef,
  }
  if (!persona.bot_ref || !persona.persona_ref) {
    throw new ApiError(400, 'complete Persona scope required')
  }
  return persona
}

function sameScope(left: ScopePath, right: ScopePath): boolean {
  return (
    left.bot_ref === right.bot_ref &&
    left.persona_ref === right.persona_ref &&
    left.session_ref === right.session_ref
  )
}

export function scopedApiPath(snapshot: ScopeRequestSnapshot, endpoint = ''): string {
  const scope = snapshotScope(snapshot)
  const root = `/api/v1/bots/${encodeURIComponent(scope.bot_ref)}/personas/${encodeURIComponent(
    scope.persona_ref,
  )}/sessions/${encodeURIComponent(scope.session_ref)}`
  return endpoint ? `${root}/${endpoint.replace(/^\/+|\/+$/g, '')}` : root
}

function pagesScopedApiPath(snapshot: ScopeRequestSnapshot, endpoint = ''): string {
  return `/pages${scopedApiPath(snapshot, endpoint)}`
}

function hasOwnScopeNonce(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false
  return Object.keys(value).some((key) => key.toLowerCase() === 'scope_nonce')
}

function endpointHasScopeNonce(endpoint: string): boolean {
  const parsed = new URL(endpoint, 'https://sylanne.invalid/')
  return [...parsed.searchParams.keys()].some((key) => key.toLowerCase() === 'scope_nonce')
}

function rejectPagesScopeNonceCarrier(endpoint: string, options: ApiOptions): void {
  const headerCarrier = Object.keys(options.headers || {}).some(
    (key) => key.toLowerCase() === SCOPE_NONCE_HEADER.toLowerCase(),
  )
  if (endpointHasScopeNonce(endpoint) || hasOwnScopeNonce(options.body) || headerCarrier) {
    throw new ApiError(400, 'scope nonce carrier forbidden')
  }
}

function pagesScopedBridgeError(cause: unknown): ApiError {
  if (cause instanceof ApiError && cause.status === 0 && cause.message === 'scope_stale') {
    return new ApiError(409, 'scope stale', { error: 'scope_stale' })
  }
  return new ApiError(0, 'scoped Pages request failed')
}

export function personaApiPath(snapshot: PersonaRequestSnapshot): string {
  const persona = snapshotPersona(snapshot)
  return `/api/v1/bots/${encodeURIComponent(persona.bot_ref)}/personas/${encodeURIComponent(
    persona.persona_ref,
  )}/dossier`
}

export function scopeBootstrapPath(snapshot: ScopeRequestSnapshot): string {
  return `/api/scopes/${encodedScopePath(snapshotScope(snapshot)).replace(
    /^([^/]+)\/([^/]+)\/([^/]+)$/,
    '$1/personas/$2/sessions/$3',
  )}/nonce`
}

export async function scopedApiFetch<T extends ScopedApiResponse>(
  snapshot: ScopeRequestSnapshot,
  endpoint = '',
  options: ApiOptions = {},
): Promise<T> {
  const scope = snapshotScope(snapshot)
  const bridge = getAstrBotBridge()
  if (bridge) {
    rejectPagesScopeNonceCarrier(endpoint, options)
    if (options.signal?.aborted) {
      throw new ApiError(0, 'scoped Pages request aborted')
    }
    const { headers: _headers, signal: _signal, ...bridgeOptions } = options
    try {
      return await apiFetch<T>(pagesScopedApiPath(snapshot, endpoint), bridgeOptions)
    } catch (cause) {
      throw pagesScopedBridgeError(cause)
    }
  }
  const bootstrap = await apiFetch<ScopeBootstrapResponse>(scopeBootstrapPath(snapshot), {
    method: 'POST',
  })
  if (!bootstrap || !sameScope(bootstrap.scope, scope) || !bootstrap.scope_nonce) {
    throw new ApiError(409, 'scoped bootstrap mismatch', bootstrap)
  }
  const path = scopedApiPath(snapshot, endpoint)
  return apiFetch<T>(path, {
    ...options,
    headers: {
      ...options.headers,
      [SCOPE_NONCE_HEADER]: bootstrap.scope_nonce,
    },
  })
}

export async function personaApiFetch<T extends PersonaDossierResponse = PersonaDossierResponse>(
  snapshot: PersonaRequestSnapshot,
  options: ApiOptions = {},
): Promise<T> {
  if ((options.method || 'GET').toUpperCase() !== 'GET' || options.body !== undefined) {
    throw new ApiError(400, 'Persona dossier is read-only')
  }
  const bridge = getAstrBotBridge()
  if (bridge) {
    if (options.signal?.aborted) {
      throw new ApiError(0, 'Persona dossier request aborted')
    }
    const { signal: _signal, ...bridgeOptions } = options
    return apiFetch<T>(personaApiPath(snapshot), bridgeOptions)
  }
  return apiFetch<T>(personaApiPath(snapshot), options)
}
