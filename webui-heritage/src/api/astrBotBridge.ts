export interface AstrBotPluginPageBridge {
  apiGet<T = unknown>(
    endpoint: string,
    params?: Record<string, unknown>,
  ): Promise<T>
  apiPost<T = unknown>(endpoint: string, body?: unknown): Promise<T>
}

declare global {
  interface Window {
    AstrBotPluginPage?: AstrBotPluginPageBridge
  }
}

export interface BridgeRequestOptions {
  method?: string
  body?: unknown
  signal?: AbortSignal
}

export function getAstrBotBridge(): AstrBotPluginPageBridge | null {
  if (typeof window === 'undefined') return null
  const bridge = window.AstrBotPluginPage
  if (
    !bridge ||
    typeof bridge.apiGet !== 'function' ||
    typeof bridge.apiPost !== 'function'
  ) {
    return null
  }
  return bridge
}

export function isAstrBotPage(): boolean {
  return getAstrBotBridge() !== null
}

export function splitBridgePath(path: string): {
  endpoint: string
  params: Record<string, unknown>
} {
  const url = new URL(path, 'https://sylanne.invalid')
  const endpoint = url.pathname.replace(/^\/+/, '')
  if (!endpoint) throw new Error('AstrBot bridge endpoint is empty')

  const params: Record<string, unknown> = {}
  for (const key of new Set(url.searchParams.keys())) {
    const values = url.searchParams.getAll(key)
    params[key] = values.length > 1 ? values : values[0]
  }
  return { endpoint, params }
}

export async function bridgeFetch<T>(
  bridge: AstrBotPluginPageBridge,
  path: string,
  opts: BridgeRequestOptions = {},
): Promise<T> {
  const method = (opts.method || 'GET').toUpperCase()
  if (opts.signal) {
    throw new Error('AstrBot bridge does not support request cancellation')
  }
  const { endpoint, params } = splitBridgePath(path)

  if (method === 'GET') {
    return bridge.apiGet<T>(endpoint, params)
  }
  if (method === 'POST') {
    if (Object.keys(params).length) {
      throw new Error('AstrBot bridge POST does not support query parameters')
    }
    return bridge.apiPost<T>(endpoint, opts.body)
  }
  throw new Error(`AstrBot bridge does not support ${method}`)
}
