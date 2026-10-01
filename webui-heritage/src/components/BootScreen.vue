<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useAuthStore } from '../stores/auth'
import { useBoot, waitForBootVerification } from '../composables/useBoot'

// Faithful port of the old #loadingScreen (UI/index.html ~599-605, 4144-4153):
// full-screen cover shown at least 1000ms AND until window load or a 3000ms
// timeout (Promise.all of both), then a .6s opacity fade before removal.
// Extended per the restoration spec: while the cover is up we ALSO verify an
// existing token (real network check absorbed by the cover, not a fake delay)
// so a reload with a valid session lands straight on the dashboard with its
// arrival choreography, and an invalid one lands cleanly on /login.

const auth = useAuthStore()
const boot = useBoot()

const fadeOut = ref(false)
const removed = ref(false)

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

onMounted(() => {
  const minDelay = delay(1000)
  const resourcesReady = new Promise<void>((resolve) => {
    if (document.readyState === 'complete') {
      resolve()
      return
    }
    window.addEventListener('load', () => resolve(), { once: true })
    setTimeout(resolve, 3000)
  })
  // Absorbed under the cover: welcome-back verification. Runs in parallel
  // with the min-delay/load race above, not stacked after it.
  let welcomeBack = false
  const verify = waitForBootVerification(auth.verifyExisting()).then((ok) => {
    welcomeBack = ok
  })

  Promise.all([minDelay, resourcesReady, verify]).then(() => {
    fadeOut.value = true
    setTimeout(() => {
      removed.value = true
      boot.markDone()
      // Request the arrival choreography only now, once the cover has fully
      // faded — DashboardLayout consumes it reactively, so a welcome-back
      // entrance plays on a visible screen instead of burning under the cover
      // (and instead of racing the layout's mount, which happens well before
      // this async verify resolves).
      if (welcomeBack) boot.requestArrival()
    }, 600)
  })
})
</script>

<template>
  <div v-if="!removed" class="boot-screen" :class="{ 'fade-out': fadeOut }" role="alert" aria-live="polite">
    <div class="boot-label">SYSTEM INIT</div>
    <div class="boot-title">SYLANNE EMBODIMENT</div>
    <div class="boot-spinner" aria-hidden="true" />
    <div class="boot-status">CONNECTING</div>
  </div>
</template>

<style scoped>
.boot-screen {
  position: fixed;
  inset: 0;
  z-index: 50000;
  background: var(--bg);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  transition: opacity 0.6s ease;
}
.boot-screen.fade-out {
  opacity: 0;
  pointer-events: none;
}
.boot-label {
  background: var(--text);
  color: var(--bg);
  padding: 5px 12px;
  font-family: var(--font-head);
  font-size: var(--font-xs);
  font-weight: 700;
  letter-spacing: 2px;
  border-radius: var(--r-xs);
  margin-bottom: var(--space-4);
}
.boot-title {
  font-family: var(--font-head);
  font-size: var(--font-xl);
  font-weight: 700;
  letter-spacing: 4px;
  margin-bottom: var(--space-9);
}
.boot-spinner {
  width: 24px;
  height: 24px;
  border: 2px solid transparent;
  border-top-color: var(--accent);
  border-right-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  margin-bottom: var(--space-5);
}
.boot-status {
  font-family: var(--font-head);
  font-size: var(--font-sm);
  letter-spacing: 2px;
  color: var(--text-muted);
}
</style>
