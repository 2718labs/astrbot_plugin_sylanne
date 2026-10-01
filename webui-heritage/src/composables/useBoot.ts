import { ref } from 'vue'

// Boot ritual state — module-level singleton (mirrors useTheme.ts / the void
// transition FSM). BootScreen.vue drives `done`; LoginView delays its deco
// `.entered` on it (old behavior: decos only entered once the loading cover
// had fully faded — UI/index.html ~4134-4137); DashboardLayout consumes
// `arrivalPending` exactly once to gate its entrance choreography (old
// behavior: the header/footer/card stagger fired only on the
// transitionToDashboard() arrival, never on ordinary nav).

const done = ref(false)
const arrivalPending = ref(false)

export function waitForBootVerification(
  verification: Promise<boolean>,
  timeoutMs = 3000,
): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false
    const settle = (result: boolean): void => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      resolve(result)
    }
    const timeout = setTimeout(() => settle(false), timeoutMs)
    verification.then(settle, () => settle(false))
  })
}

export function useBoot() {
  function markDone(): void {
    done.value = true
  }

  // Called by LoginView right before router.replace() on a successful login,
  // and by BootScreen when a verified existing token lands directly on a
  // dashboard route ("welcome back") — both are real arrivals at the shell.
  function requestArrival(): void {
    arrivalPending.value = true
  }

  function cancelArrival(): void {
    arrivalPending.value = false
  }

  // DashboardLayout calls this once it has consumed the flag on mount.
  function consumeArrival(): boolean {
    const pending = arrivalPending.value
    arrivalPending.value = false
    return pending
  }

  return {
    done,
    arrivalPending,
    markDone,
    requestArrival,
    cancelArrival,
    consumeArrival,
  }
}
