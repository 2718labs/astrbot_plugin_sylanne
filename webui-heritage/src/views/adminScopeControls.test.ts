import { describe, expect, it, vi } from 'vitest'
import type { ScopeRequestSnapshot, ScopedApiResponse } from '../api/types'

interface LegacyAdminState {
  records: unknown[]
  inventoryError: string
  copyingId: string
  claimMessage: string
}

interface LegacyAdminControlsModule {
  canCopyLegacyClaim?: (snapshot: ScopeRequestSnapshot | null, busy: boolean) => boolean
  legacyClaimBody?: (recordId: string) => Record<string, unknown>
  createLegacyAdminState?: () => LegacyAdminState
  createLegacyAdminRequestGuard?: () => {
    begin: (
      selectionEpoch: number,
      snapshot: ScopeRequestSnapshot | null,
      abortable: boolean,
    ) => { signal?: AbortSignal } & Record<string, unknown>
    acceptsSelection: (fence: unknown, currentSelectionEpoch: number) => boolean
    acceptsScope: (
      fence: unknown,
      currentSelectionEpoch: number,
      currentSnapshot: ScopeRequestSnapshot | null,
      response: ScopedApiResponse,
    ) => boolean
    invalidate: () => void
  }
  clearLegacyAdminState?: (
    state: LegacyAdminState,
    ...guards: Array<{ invalidate: () => void }>
  ) => void
}

async function adminControls(): Promise<Required<LegacyAdminControlsModule>> {
  vi.stubGlobal('document', {
    createElement: vi.fn(() => ({})),
    documentElement: {
      getAttribute: vi.fn(() => null),
      setAttribute: vi.fn(),
    },
  })
  const module = await import('./AdminView.vue') as unknown as LegacyAdminControlsModule
  expect(module.canCopyLegacyClaim).toBeTypeOf('function')
  expect(module.legacyClaimBody).toBeTypeOf('function')
  expect(module.createLegacyAdminState).toBeTypeOf('function')
  expect(module.createLegacyAdminRequestGuard).toBeTypeOf('function')
  expect(module.clearLegacyAdminState).toBeTypeOf('function')
  return module as Required<LegacyAdminControlsModule>
}

function snapshot(generation = 7): ScopeRequestSnapshot {
  return {
    selection: { botRef: 'bot_v1_A', personaRef: 'persona_v1_P', sessionRef: 'session_v1_S' },
    selectionEpoch: 3,
    scopeGeneration: generation,
  }
}

function response(generation = 7): ScopedApiResponse {
  return {
    scope: { bot_ref: 'bot_v1_A', persona_ref: 'persona_v1_P', session_ref: 'session_v1_S' },
    scope_generation: generation,
  }
}

describe('Task 14 executable scoped admin controls', () => {
  it('disables claim without a complete scope and builds only the exact record body', async () => {
    const controls = await adminControls()

    expect(controls.canCopyLegacyClaim(null, false)).toBe(false)
    expect(controls.canCopyLegacyClaim(snapshot(), false)).toBe(true)
    expect(controls.canCopyLegacyClaim(snapshot(), true)).toBe(false)
    expect(controls.legacyClaimBody('record-v1')).toEqual({ record_id: 'record-v1' })
    expect(Object.keys(controls.legacyClaimBody('record-v1'))).toEqual(['record_id'])
  })

  it('rejects stale epoch, generation, and scope echoes and aborts while clearing on change', async () => {
    const controls = await adminControls()
    const guard = controls.createLegacyAdminRequestGuard()
    const current = snapshot()
    const fence = guard.begin(current.selectionEpoch, current, true)
    const state = controls.createLegacyAdminState()
    state.records = [{ record_id: 'legacy' }]
    state.inventoryError = 'old error'
    state.copyingId = 'legacy'
    state.claimMessage = 'old result'

    expect(guard.acceptsSelection(fence, current.selectionEpoch)).toBe(true)
    expect(guard.acceptsScope(fence, current.selectionEpoch, current, response())).toBe(true)
    expect(guard.acceptsScope(fence, current.selectionEpoch + 1, current, response())).toBe(false)
    expect(guard.acceptsScope(fence, current.selectionEpoch, snapshot(8), response())).toBe(false)
    expect(guard.acceptsScope(fence, current.selectionEpoch, current, response(8))).toBe(false)
    expect(guard.acceptsScope(fence, current.selectionEpoch, current, {
      ...response(),
      scope: { bot_ref: 'bot_v1_B', persona_ref: 'persona_v1_P', session_ref: 'session_v1_S' },
    })).toBe(false)

    controls.clearLegacyAdminState(state, guard)
    expect(fence.signal?.aborted).toBe(true)
    expect(state).toEqual({ records: [], inventoryError: '', copyingId: '', claimMessage: '' })
    expect(guard.acceptsScope(fence, current.selectionEpoch, current, response())).toBe(false)
  })

  it('executes capacity and delivery adapters without trusting unsafe fields', async () => {
    const observation = await import('./monitorObservation') as Record<string, unknown>
    const live = await import('../stores/live') as Record<string, unknown>
    expect(observation.observationCapacityModel).toBeTypeOf('function')
    expect(live.adaptDeliveryDiagnostics).toBeTypeOf('function')
    const capacity = observation.observationCapacityModel as (
      storage: Record<string, unknown>,
      labels: Record<string, string>,
    ) => Record<string, unknown>
    const delivery = live.adaptDeliveryDiagnostics as (value: unknown) => unknown

    expect(capacity({
      used_bytes: 4096,
      limit_bytes: null,
      cleanup_active: true,
      budget_unsatisfiable: true,
    }, {
      unlimited: 'Unlimited',
      cleanupActive: 'Active',
      cleanupIdle: 'Idle',
      protectedWarning: 'Protected data warning',
    })).toEqual({
      used: '4.0 KiB',
      limit: 'Unlimited',
      cleanup: 'Active',
      warning: 'Protected data warning',
    })

    expect(delivery({
      pending: 2,
      failed_retryable: -1,
      outcome_unknown: 3.5,
      suppressed: 4,
      last_reason: 'private_backend_reason',
      platform: 'must-not-project',
    })).toEqual({ pending: 2, failed_retryable: 0, outcome_unknown: 0, suppressed: 4 })
    expect(delivery({
      pending: 1,
      failed_retryable: 2,
      outcome_unknown: 3,
      suppressed: 4,
      last_reason: 'delivery_outcome_unknown',
    })).toEqual({
      pending: 1,
      failed_retryable: 2,
      outcome_unknown: 3,
      suppressed: 4,
      last_reason: 'delivery_outcome_unknown',
    })
  })
})
