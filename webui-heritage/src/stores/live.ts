import { defineStore } from 'pinia'
import { ref } from 'vue'
import { scopedApiFetch } from '../api/client'
import { isAstrBotPage } from '../api/astrBotBridge'
import type { DeliveryDiagnostics, ScopeRequestSnapshot, ScopedApiResponse, ScopedStateResponse, StateResponse } from '../api/types'
import { useScopeStore } from './scope'

function isAbortError(cause: unknown): boolean {
  return cause instanceof Error && cause.name === 'AbortError'
}

function isScopeStaleError(cause: unknown): boolean {
  if (!cause || typeof cause !== 'object') return false
  const error = cause as { status?: unknown; data?: unknown }
  if (error.status !== 409) return false
  const data = error.data
  return !!data && typeof data === 'object' && (data as { error?: unknown }).error === 'scope_stale'
}

function sameScope(
  snapshot: ScopeRequestSnapshot,
  response: ScopedApiResponse,
): boolean {
  return (
    response.scope?.bot_ref === snapshot.selection.botRef &&
    response.scope.persona_ref === snapshot.selection.personaRef &&
    response.scope.session_ref === snapshot.selection.sessionRef
  )
}

function safeDeliveryCount(value: unknown): number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0
}

export function adaptDeliveryDiagnostics(value: unknown): DeliveryDiagnostics | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
  const source = value as Record<string, unknown>
  const result: DeliveryDiagnostics = {
    pending: safeDeliveryCount(source.pending),
    failed_retryable: safeDeliveryCount(source.failed_retryable),
    outcome_unknown: safeDeliveryCount(source.outcome_unknown),
    suppressed: safeDeliveryCount(source.suppressed),
  }
  if (
    source.last_reason === 'account_route_unavailable' ||
    source.last_reason === 'delivery_outcome_unknown'
  ) {
    result.last_reason = source.last_reason
  }
  return result
}

function projectState(response: ScopedStateResponse): StateResponse {
  return {
    ...(response.state || {}),
    delivery: adaptDeliveryDiagnostics(response.delivery),
    scope: response.scope,
    scope_generation: response.scope_generation,
    generations: response.generations,
  }
}

// Pages requests cannot be aborted, so polling remains serialized while one is
// in flight. scopedApiFetch uses the host-authenticated Pages broker.
export const useLiveStore = defineStore('live', () => {
  const state = ref<StateResponse | null>(null)
  const loading = ref(false)
  const error = ref('')
  let timer: number | null = null
  let generation = 0
  let controller: AbortController | null = null
  let pagesInFlight = false
  let pagesRefreshQueued = false

  function clearScopeState(): void {
    state.value = null
    error.value = ''
  }

  async function retryForGeneration(
    requestGeneration: number,
    snapshot: ScopeRequestSnapshot,
    pages: boolean,
    requestController: AbortController | null,
    retried: boolean,
  ): Promise<boolean> {
    const scope = useScopeStore()
    try {
      const response = await scopedApiFetch<ScopedStateResponse>(snapshot, 'state',
        requestController ? { signal: requestController.signal } : {},
      )
      if (
        requestGeneration !== generation ||
        requestController?.signal.aborted ||
        !scope.isCurrent(snapshot)
      ) {
        return false
      }
      if (scope.isCurrent(snapshot, response)) {
        state.value = projectState(response)
        error.value = ''
        return true
      }
      const responseGeneration = response.scope_generation ?? response.generations?.scope
      if (!retried && sameScope(snapshot, response) && responseGeneration !== snapshot.scopeGeneration) {
        await scope.refreshCatalog()
        if (requestGeneration !== generation || requestController?.signal.aborted) return false
        const refreshed = scope.snapshot()
        if (!refreshed) {
          clearScopeState()
          return false
        }
        if (!sameScope(refreshed, response)) return false
        return retryForGeneration(requestGeneration, refreshed, pages, requestController, true)
      }
      return false
    } catch (cause) {
      if (
        requestGeneration !== generation ||
        requestController?.signal.aborted ||
        !scope.isCurrent(snapshot) ||
        isAbortError(cause)
      ) {
        return false
      }
      if (!retried && isScopeStaleError(cause)) {
        await scope.refreshCatalog()
        if (requestGeneration !== generation || requestController?.signal.aborted) return false
        const refreshed = scope.snapshot()
        if (!refreshed) {
          clearScopeState()
          return false
        }
        if (!sameScope(refreshed, {
          scope: {
            bot_ref: snapshot.selection.botRef,
            persona_ref: snapshot.selection.personaRef,
            session_ref: snapshot.selection.sessionRef,
          },
        })) {
          return false
        }
        return retryForGeneration(requestGeneration, refreshed, pages, requestController, true)
      }
      error.value = cause instanceof Error ? cause.message : 'fetch failed'
      return false
    }
  }

  async function fetchOnce(): Promise<boolean> {
    const pages = isAstrBotPage()
    if (pages && pagesInFlight) {
      pagesRefreshQueued = true
      return false
    }

    const requestGeneration = ++generation
    const requestController = pages ? null : new AbortController()
    if (pages) {
      pagesInFlight = true
    } else {
      controller?.abort()
      controller = requestController
    }
    loading.value = true

    try {
      const scope = useScopeStore()
      if (!scope.catalog.length) await scope.refreshCatalog()
      if (requestGeneration !== generation || requestController?.signal.aborted) return false
      const snapshot = scope.snapshot()
      if (!snapshot) {
        clearScopeState()
        return false
      }
      return await retryForGeneration(requestGeneration, snapshot, pages, requestController, false)
    } catch (cause) {
      if (requestGeneration !== generation || requestController?.signal.aborted || isAbortError(cause)) {
        return false
      }
      error.value = cause instanceof Error ? cause.message : 'fetch failed'
      return false
    } finally {
      if (requestGeneration === generation) {
        loading.value = false
        if (controller === requestController) controller = null
      }
      if (pages) {
        pagesInFlight = false
        if (pagesRefreshQueued) {
          pagesRefreshQueued = false
          void fetchOnce()
        }
      }
    }
  }

  function start(intervalMs = 5000): void {
    stop()
    void fetchOnce()
    timer = window.setInterval(() => void fetchOnce(), intervalMs)
  }

  function stop(): void {
    generation += 1
    controller?.abort()
    controller = null
    pagesRefreshQueued = false
    if (timer !== null) {
      clearInterval(timer)
      timer = null
    }
    loading.value = false
  }

  return { state, loading, error, fetchOnce, start, stop }
})
