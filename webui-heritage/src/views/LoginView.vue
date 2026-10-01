<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { useI18n } from '../composables/useI18n'
import { useBoot } from '../composables/useBoot'
import SpecimenCanvas from '../components/SpecimenCanvas.vue'

// Login screen — faithful port of the old #loginSection p3 (form) / p4
// (verify) phases (UI/index.html ~622-673) + doLogin/transitionToDashboard
// (~1975-2060). See docs/architecture/webui-design-system.md §3.

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const { t } = useI18n()
const boot = useBoot()

type Phase = 'form' | 'verify'
type VerifyState = 'verifying' | 'success' | 'error'

const token = ref('')
const phase = ref<Phase>('form')
const verifyState = ref<VerifyState>('verifying')
const shakeActive = ref(false)
const decoEntered = ref(false)
const tokenInputEl = ref<HTMLInputElement | null>(null)
const loginError = ref('')

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function triggerShake(): void {
  shakeActive.value = false
  requestAnimationFrame(() => {
    shakeActive.value = true
    setTimeout(() => {
      shakeActive.value = false
    }, 350)
  })
}

function recoverFromNavigationFailure(): void {
  boot.cancelArrival()
  phase.value = 'form'
  tokenInputEl.value?.focus()
}

function clearLoginError(): void {
  loginError.value = ''
}

async function submit(): Promise<void> {
  if (phase.value !== 'form') return
  clearLoginError()
  const val = token.value.trim()
  if (!val) {
    triggerShake()
    return
  }

  phase.value = 'verify'
  verifyState.value = 'verifying'

  const ok = await auth.login(val)
  if (ok) {
    verifyState.value = 'success'
    await delay(2200)
    boot.requestArrival()
    const redirect = (route.query.redirect as string) || '/monitor'
    try {
      const failure = await router.replace(redirect)
      if (failure) recoverFromNavigationFailure()
    } catch {
      recoverFromNavigationFailure()
    }
  } else {
    verifyState.value = 'error'
    await delay(1600)
    phase.value = 'form'
    loginError.value = t('login.error')
    triggerShake()
    tokenInputEl.value?.focus()
    tokenInputEl.value?.select()
  }
}

onMounted(() => {
  // Old behavior: decos only .entered once the loading cover finished
  // fading (UI/index.html ~4134-4137). If boot already finished (e.g. a
  // hot route change back to /login), enter immediately instead of waiting
  // on a boot that will never complete again.
  if (boot.done.value) {
    setTimeout(() => {
      decoEntered.value = true
    }, 300)
  } else {
    const stop = watch(boot.done, (isDone) => {
      if (isDone) {
        stop()
        setTimeout(() => {
          decoEntered.value = true
        }, 300)
      }
    })
  }
  tokenInputEl.value?.focus()
})
</script>

<template>
  <div class="login-view">
    <SpecimenCanvas />

    <div class="deco-tl" :class="{ entered: decoEntered }">
      <div class="sm">ANALYSIS OS</div>
      <div class="lg">SYLANNE EMBODIMENT</div>
    </div>
    <div class="deco-bl" :class="{ entered: decoEntered }">SYLANNE LAB</div>

    <!-- Phase: login form -->
    <div class="phase" :class="{ active: phase === 'form' }">
      <div class="login-box">
        <div class="logo-row">
          <svg class="logo-svg" viewBox="0 0 100 100" fill="none" aria-hidden="true">
            <path
              d="M 45 12 L 45 38 L 37 44 L 53 56 L 45 62 L 45 88"
              stroke="currentColor"
              stroke-width="7"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
            <path
              d="M 33 20 C 14 28, 14 72, 33 80"
              stroke="currentColor"
              stroke-width="4.5"
              stroke-linecap="round"
              opacity="0.45"
            />
            <circle cx="53" cy="56" r="5" fill="var(--accent)" />
          </svg>
          <div class="logo-titles">
            <h1>{{ t('login.title') }}</h1>
            <p>{{ t('login.subtitle') }}</p>
          </div>
        </div>

        <label class="input-label" for="tokenInput">{{ t('login.token') }}</label>
        <input
          id="tokenInput"
          ref="tokenInputEl"
          v-model="token"
          class="token-input"
          :class="{ shake: shakeActive }"
          :aria-invalid="Boolean(loginError)"
          aria-describedby="tokenError"
          aria-errormessage="tokenError"
          type="password"
          autocomplete="off"
          spellcheck="false"
          @input="clearLoginError"
          @keydown.enter.prevent="submit"
        />
        <p id="tokenError" class="token-error" role="alert">{{ loginError }}</p>
        <button type="button" class="submit-btn" :disabled="phase !== 'form'" @click="submit">
          {{ t('login.authenticate') }}
        </button>
      </div>
    </div>

    <!-- Phase: verification -->
    <div class="phase" :class="{ active: phase === 'verify' }">
      <div class="confirm-row" :class="'state-' + verifyState">
        <svg class="status-svg" viewBox="0 0 100 100">
          <g class="ring" :class="{ spinning: verifyState === 'verifying' }">
            <circle class="stroke circle" cx="50" cy="50" r="40" />
          </g>
          <path class="stroke check" d="M 35 52 L 45 62 L 68 38" />
          <path class="stroke cross1" d="M 35 35 L 65 65" />
          <path class="stroke cross2" d="M 65 35 L 35 65" />
        </svg>
        <div class="text-stack">
          <div class="text-item t-verify"><h2>{{ t('login.verifying') }}</h2></div>
          <div class="text-item t-success"><h2>{{ t('login.success') }}</h2></div>
          <div class="text-item t-error"><h2>{{ t('login.error') }}</h2></div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.login-view {
  position: fixed;
  inset: 0;
  z-index: 200;
  display: flex;
  align-items: center;
  justify-content: center;
}

.deco-tl {
  position: fixed;
  top: 36px;
  left: 36px;
  z-index: 50;
  transform: translateX(-80px);
  opacity: 0;
  transition: transform var(--dur-slow) var(--ease-organic), opacity var(--dur-slow) ease;
}
.deco-tl.entered {
  transform: translateX(0);
  opacity: 1;
}
.deco-tl .sm {
  font-family: var(--font-head);
  font-size: var(--font-xs);
  font-weight: 700;
  letter-spacing: 2px;
  opacity: 0.6;
}
.deco-tl .lg {
  font-family: var(--font-head);
  font-size: var(--font-md);
  font-weight: 700;
  letter-spacing: 2.5px;
  margin-top: 2px;
}
.deco-bl {
  position: fixed;
  bottom: 36px;
  left: 36px;
  z-index: 50;
  font-family: var(--font-head);
  font-size: var(--font-md);
  font-weight: 700;
  letter-spacing: 2.5px;
  transform: translateX(-80px);
  opacity: 0;
  transition: transform var(--dur-slow) var(--ease-organic) 0.1s, opacity var(--dur-slow) ease 0.1s;
}
.deco-bl.entered {
  transform: translateX(0);
  opacity: 1;
}
.deco-bl::before {
  content: '';
  position: absolute;
  top: -10px;
  left: 0;
  width: 22px;
  height: 3px;
  background: var(--accent);
  border-radius: 2px;
}

.phase {
  position: fixed;
  inset: 0;
  z-index: 10;
  display: flex;
  justify-content: center;
  align-items: center;
  opacity: 0;
  pointer-events: none;
  transform: scale(0.97);
  transition: opacity var(--dur-slow) var(--ease-organic), transform var(--dur-slow) var(--ease-organic);
}
.phase.active {
  opacity: 1;
  pointer-events: auto;
  transform: scale(1);
}

.login-box {
  max-width: 380px;
  width: 90%;
}
.logo-row {
  display: flex;
  align-items: center;
  gap: var(--space-6);
  margin-bottom: var(--space-10);
}
.logo-svg {
  width: 48px;
  height: 48px;
  flex-shrink: 0;
  color: var(--text);
}
.logo-titles h1 {
  font-family: var(--font-head);
  font-size: 21px;
  font-weight: 700;
  letter-spacing: 2.5px;
  line-height: 1.1;
}
.logo-titles p {
  font-size: var(--font-xs);
  opacity: 0.4;
  font-weight: 600;
  letter-spacing: 1.5px;
  margin-top: 3px;
}
.input-label {
  display: block;
  font-family: var(--font-head);
  font-size: var(--font-sm);
  font-weight: 700;
  letter-spacing: 1.5px;
  opacity: 0.65;
  margin-bottom: var(--space-4);
}
.token-input {
  width: 100%;
  padding: var(--space-5) 0;
  font-size: 18px;
  font-family: var(--font-mono);
  letter-spacing: 3px;
  border: none;
  border-bottom: 2px solid rgba(240, 236, 228, 0.15);
  background: transparent;
  color: var(--text);
  outline: none;
  transition: border-color 0.3s, box-shadow 0.3s;
}
[data-theme='light'] .token-input {
  border-bottom-color: rgba(26, 26, 26, 0.15);
}
.token-input:focus {
  border-bottom-color: var(--accent);
  box-shadow: 0 3px 12px rgba(184, 138, 158, 0.18);
}
.token-input.shake {
  animation: shake 0.3s ease;
}
.token-error {
  min-height: 1.6em;
  margin: var(--space-2) 0 0;
  color: var(--red);
  font-size: var(--font-sm);
}

.submit-btn {
  margin-top: var(--space-10);
  width: 100%;
  padding: var(--space-7);
  font-family: var(--font-head);
  font-size: var(--font-base);
  font-weight: 700;
  letter-spacing: 3px;
  border: none;
  border-radius: var(--r-pill);
  cursor: pointer;
  background: var(--btn-primary-bg);
  color: var(--btn-primary-fg);
  transition: transform 0.2s var(--ease-organic), box-shadow 0.3s;
}
.submit-btn:hover {
  transform: translateY(-3px);
  box-shadow: 0 10px 28px rgba(184, 138, 158, 0.22);
}
.submit-btn:active {
  transform: translateY(-1px);
}
.submit-btn:disabled {
  cursor: default;
}

.confirm-row {
  display: flex;
  align-items: center;
  gap: var(--space-9);
}
.status-svg {
  width: 48px;
  height: 48px;
}
.ring {
  transform-origin: 50px 50px;
}
.ring.spinning {
  animation: spin 1.1s linear infinite;
}
.stroke {
  fill: none;
  stroke: var(--text);
  stroke-width: 7;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-dasharray: 252;
  stroke-dashoffset: 252;
  transition: stroke-dashoffset 0.5s cubic-bezier(0.7, 0, 1, 0.5), stroke 0.4s;
}
.state-verifying .stroke.circle {
  stroke-dashoffset: 70;
}
.state-success .stroke.circle {
  stroke-dashoffset: 0;
  stroke: var(--accent);
  transition: stroke-dashoffset 0.45s cubic-bezier(0.5, 0, 0.8, 0.4), stroke 0.3s ease 0.3s;
}
.state-success .stroke.check {
  stroke-dashoffset: 0;
  stroke: var(--accent);
  transition: stroke-dashoffset 0.4s var(--ease-snap) 0.5s, stroke 0.3s ease 0.5s;
}
.state-error .stroke.circle {
  stroke-dashoffset: 0;
  stroke: var(--red);
}
.state-error .stroke.cross1,
.state-error .stroke.cross2 {
  stroke-dashoffset: 0;
  stroke: var(--red);
}

.text-stack {
  position: relative;
  height: 48px;
  width: 220px;
}
.text-item {
  position: absolute;
  inset: 0;
  opacity: 0;
  transform: translateY(8px);
  transition: opacity 0.4s, transform 0.4s var(--ease-organic);
}
.text-item h2 {
  font-family: var(--font-head);
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 2px;
}
.state-verifying .text-item.t-verify {
  opacity: 1;
  transform: translateY(0);
}
.state-success .text-item.t-success {
  opacity: 1;
  transform: translateY(0);
}
.state-error .text-item.t-error {
  opacity: 1;
  transform: translateY(0);
}

@media (max-width: 480px) {
  .deco-tl,
  .deco-bl {
    display: none;
  }
}
</style>
