import { ref } from 'vue'

// Models the login<->dashboard "void" transition as a small FSM, ported from
// the old UI's voidTransitionState/Start/Duration/Callback globals
// (UI/index.html ~773-994). SpecimenCanvas reads state/progress every frame;
// LoginView (and later a logout flow) drive it via start().
//
// 'revealing' is a second phase added for the cross-route handoff (VoidVeil):
// it does NOT drive the specimen canvas (that's gone by then — new route,
// new page), it drives the veil's iris-open. Kept in the same FSM so both
// phases share the same guarded start()/progress contract.

export type VoidDirection = 'expanding' | 'shrinking' | 'revealing'
export type VoidState = 'idle' | VoidDirection

// Module-level singleton — shared across every caller (mirrors useTheme.ts).
const state = ref<VoidState>('idle')
const progress = ref(0)

// Cross-route veil solidity: a plain on/off flag, orthogonal to the
// progress-driven phases above. The specimen canvas ends 'expanding' fully
// solid but is about to be unmounted (route change) — the veil must snap
// opaque in that exact instant so the swallow never "un-solidifies" for a
// frame, then stay opaque across the route swap until 'revealing' starts.
const veilSolid = ref(false)

// Guards overlapping start() calls: while a transition is in flight, further
// calls get the same promise back instead of racing a second rAF ticker.
let activePromise: Promise<void> | null = null

export function useVoidTransition() {
  function start(direction: VoidDirection, durationMs = 1600): Promise<void> {
    if (activePromise) return activePromise

    state.value = direction
    progress.value = 0

    activePromise = new Promise<void>((resolve) => {
      const startedAt = performance.now()

      function tick(now: number): void {
        const elapsed = now - startedAt
        progress.value = Math.min(elapsed / durationMs, 1)

        if (progress.value >= 1) {
          state.value = 'idle'
          activePromise = null
          resolve()
          return
        }
        requestAnimationFrame(tick)
      }

      requestAnimationFrame(tick)
    })

    return activePromise
  }

  function setVeilSolid(solid: boolean): void {
    veilSolid.value = solid
  }

  // Failsafe: if a caller starts a transition but navigation/mount never
  // completes it (route guard bounce, thrown error), the veil must not trap
  // the UI forever. Call this from a timeout race.
  function reset(): void {
    state.value = 'idle'
    progress.value = 0
    veilSolid.value = false
    activePromise = null
  }

  return { state, progress, veilSolid, start, setVeilSolid, reset }
}
