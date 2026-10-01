<script setup lang="ts">
// Memory pools page. Owns its own 10s poll of /api/memory_pools (mirrors the
// old dashboard's adaptMemoryPools()) plus the supported meltdown action.
// Both are destructive-adjacent (meltdown genuinely irreversible), so the
// meltdown flow is deliberately defensive: a `cancelled` flag is checked
// right before the POST fires, so dismissing the Modal mid-countdown (Esc /
// backdrop) can never let the network call slip through afterward.
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { scopedApiFetch } from '../api/client'
import { num } from '../composables/useAdapt'
import { useI18n } from '../composables/useI18n'
import {
  conciseFeedbackError,
  useInteractionFeedback,
} from '../composables/useInteractionFeedback'
import { useScopeStore } from '../stores/scope'
import { useAuthStore } from '../stores/auth'
import type {
  MemoryPoolItem,
  MemoryPoolsResponse,
  ScopedApiResponse,
  ScopedMemoryPoolsResponse,
  ScopeRequestSnapshot,
} from '../api/types'
import Card from '../components/ui/Card.vue'
import StatGrid from '../components/ui/StatGrid.vue'
import EmptyState from '../components/ui/EmptyState.vue'
import ErrorState from '../components/ui/ErrorState.vue'
import Button from '../components/ui/Button.vue'
import Modal from '../components/ui/Modal.vue'
import TextInput from '../components/ui/TextInput.vue'

const { t } = useI18n()
const scope = useScopeStore()
const auth = useAuthStore()
const feedback = useInteractionFeedback()

// ---- data: own poll of /api/memory_pools ----

const pools = ref<MemoryPoolsResponse | null>(null)
const poolsError = ref('')
let timer: number | null = null
let poolsGeneration = 0

function toMemoryPools(data: ScopedMemoryPoolsResponse): MemoryPoolsResponse {
  const pools = data.memory_pools || {}
  const l1 = pools.l1_count || 0
  const l2 = pools.l2_count || 0
  const l3Nodes = pools.l3_node_count || 0
  const l3Edges = pools.l3_edge_count || 0
  return {
    summary: {
      total: l1 + l2 + l3Nodes + l3Edges,
      l1_count: l1,
      l2_count: l2,
      l3_node_count: l3Nodes,
      l3_edge_count: l3Edges,
    },
  }
}

async function fetchPools(): Promise<void> {
  const requestGeneration = ++poolsGeneration
  const snapshot = scope.snapshot()
  if (!snapshot) {
    pools.value = null
    poolsError.value = ''
    return
  }
  try {
    const data = await scopedApiFetch<ScopedMemoryPoolsResponse>(snapshot, 'memory-pools')
    if (requestGeneration !== poolsGeneration || !scope.isCurrent(snapshot, data)) return
    pools.value = toMemoryPools(data)
    poolsError.value = ''
  } catch (e) {
    if (requestGeneration !== poolsGeneration || !scope.isCurrent(snapshot)) return
    poolsError.value = e instanceof Error ? e.message : 'fetch failed'
  }
}

onMounted(() => {
  void fetchPools()
  timer = window.setInterval(() => void fetchPools(), 10000)
})
onUnmounted(() => {
  if (timer !== null) {
    clearInterval(timer)
    timer = null
  }
})
watch(
  () => scope.selectionEpoch,
  () => {
    resetConsolidation()
    abortMeltdown()
    void fetchPools()
  },
)

// ---- adapt: mirrors old adaptMemoryPools() — prefer layers.*, fallback flat ----

function itemText(it: MemoryPoolItem): string {
  return String(it.content ?? it.text ?? it.summary ?? '')
}
function itemMeta(it: MemoryPoolItem): string {
  const parts: string[] = []
  const w = num(it, ['weight'], NaN)
  if (!Number.isNaN(w)) parts.push(t('mem.weight') + ' ' + w.toFixed(2))
  const age = num(it, ['age'], NaN)
  if (!Number.isNaN(age)) parts.push(t('mem.age') + ' ' + age)
  else if (it.created_at) parts.push(String(it.created_at))
  return parts.join(' · ')
}

const l1Items = computed<MemoryPoolItem[]>(() => {
  const p = pools.value
  return p?.layers?.l1_hot?.items ?? p?.hot ?? []
})
const l2Items = computed<MemoryPoolItem[]>(() => {
  const p = pools.value
  return p?.layers?.l2_warm?.items ?? p?.warm ?? []
})
const l3Items = computed<MemoryPoolItem[]>(() => {
  const p = pools.value
  return p?.layers?.l3_cold?.nodes ?? p?.cold ?? []
})

const summaryItems = computed(() => {
  const s = pools.value?.summary
  return [
    { label: 'total', value: num(s, ['total'], 0) },
    { label: 'l1_count', value: num(s, ['l1_count'], 0) },
    { label: 'l2_count', value: num(s, ['l2_count'], 0) },
    { label: 'l3_node_count', value: num(s, ['l3_node_count'], 0) },
    { label: 'avg_weight', value: num(s, ['avg_weight'], 0).toFixed(2) },
    { label: 'avg_temperature', value: num(s, ['avg_temperature'], 0).toFixed(2) },
  ]
})

// ---- consolidation ----
// The scoped backend currently exposes no consolidation/sink contract. Keep
// this reset path so a scope change cannot retain an old timer, feedback, or
// result if the capability is added later.

const consolidating = ref(false)
const consolidateCountdown = ref(0)
const sinkResult = ref<number | null>(null)
let consolidateTimer: number | null = null
let organizingFeedbackId: number | null = null
let consolidationScope: ScopeRequestSnapshot | null = null

function clearConsolidateTimer(): void {
  if (consolidateTimer !== null) {
    clearInterval(consolidateTimer)
    consolidateTimer = null
  }
}

function resetConsolidation(): void {
  clearConsolidateTimer()
  consolidating.value = false
  consolidateCountdown.value = 0
  sinkResult.value = null
  if (consolidationScope !== null) consolidationScope = null
  if (organizingFeedbackId !== null) {
    feedback.clear(organizingFeedbackId)
    organizingFeedbackId = null
  }
}

onUnmounted(() => {
  resetConsolidation()
})

// ---- meltdown ----

type MeltdownStage = 'idle' | 'confirm' | 'counting'

const meltdownOpen = ref(false)
const meltdownStage = ref<MeltdownStage>('idle')
const meltdownNonce = ref('')
const meltdownInput = ref('')
const meltdownCountdown = ref(0)
const meltdownError = ref('')
let meltdownTimer: number | null = null
let meltdownScope: ScopeRequestSnapshot | null = null
// Guards the one truly dangerous race: Modal dismissed (Esc/backdrop) while
// the countdown is running must NEVER let the queued POST fire afterward.
let meltdownCancelled = false

function clearMeltdownTimer(): void {
  if (meltdownTimer !== null) {
    clearInterval(meltdownTimer)
    meltdownTimer = null
  }
}

function resetMeltdownState(): void {
  clearMeltdownTimer()
  meltdownStage.value = 'idle'
  meltdownNonce.value = ''
  meltdownInput.value = ''
  meltdownCountdown.value = 0
  meltdownError.value = ''
  meltdownScope = null
}

async function openMeltdown(): Promise<void> {
  const snapshot = scope.snapshot()
  if (!snapshot) return
  meltdownCancelled = false
  meltdownOpen.value = true
  meltdownStage.value = 'confirm'
  meltdownInput.value = ''
  meltdownError.value = ''
  try {
    const resp = await scopedApiFetch<ScopedApiResponse & { meltdown_nonce?: string }>(
      snapshot,
      'memory/meltdown-nonce',
    )
    if (!scope.isCurrent(snapshot, resp)) return
    meltdownScope = snapshot
    meltdownNonce.value = String(resp.meltdown_nonce ?? '')
    if (!meltdownNonce.value) {
      meltdownError.value = 'nonce fetch failed'
      feedback.show(t('feedback.meltdown_prepare_failed'), 'error')
    }
  } catch (e) {
    meltdownNonce.value = ''
    meltdownError.value = 'nonce fetch failed'
    const detail = conciseFeedbackError(e, '')
    feedback.show(
      detail
        ? `${t('feedback.meltdown_prepare_failed')} · ${detail}`
        : t('feedback.meltdown_prepare_failed'),
      'error',
    )
  }
}

const meltdownMatch = computed(
  () => meltdownNonce.value !== '' && meltdownInput.value === meltdownNonce.value,
)

function armMeltdown(): void {
  if (!meltdownMatch.value) return
  meltdownStage.value = 'counting'
  meltdownCountdown.value = 10
  clearMeltdownTimer()
  meltdownTimer = window.setInterval(() => {
    meltdownCountdown.value -= 1
    if (meltdownCountdown.value <= 0) {
      clearMeltdownTimer()
      void fireMeltdown()
    }
  }, 1000)
}

function abortMeltdown(): void {
  meltdownCancelled = true
  clearMeltdownTimer()
  meltdownOpen.value = false
  resetMeltdownState()
}

// Watches the Modal's own open state — covers Esc/backdrop dismissal, which
// bypasses abortMeltdown() and only ever fires 'update:open'.
watch(meltdownOpen, (isOpen) => {
  if (!isOpen) {
    meltdownCancelled = true
    clearMeltdownTimer()
    resetMeltdownState()
  }
})

async function fireMeltdown(): Promise<void> {
  if (meltdownCancelled) return
  const snapshot = meltdownScope
  if (!snapshot || !scope.isCurrent(snapshot)) return
  try {
    const resp = await scopedApiFetch<ScopedApiResponse & { cleared?: boolean }>(snapshot, 'memory/meltdown', {
      method: 'POST',
      body: { meltdown_nonce: meltdownNonce.value },
    })
    if (meltdownCancelled || !scope.isCurrent(snapshot, resp)) return
    if (!resp.ok && !resp.cleared) {
      meltdownError.value = 'meltdown failed'
      feedback.show(t('feedback.meltdown_execute_failed'), 'error')
      return
    }
    // Reuse the auth store's logout path exactly (clears token + status),
    // then hard-redirect so no stale in-memory state (pools, session)
    // survives the meltdown.
    auth.logout()
    window.location.hash = '#/login'
    window.location.reload()
  } catch (e) {
    if (!meltdownCancelled) {
      meltdownError.value = 'meltdown failed'
      const detail = conciseFeedbackError(e, '')
      feedback.show(
        detail
          ? `${t('feedback.meltdown_execute_failed')} · ${detail}`
          : t('feedback.meltdown_execute_failed'),
        'error',
      )
    }
  }
}

onUnmounted(() => {
  meltdownCancelled = true
  clearMeltdownTimer()
})
</script>

<template>
  <div class="page-split">
    <div class="pane-left">
      <ErrorState v-if="!pools && poolsError" :message="poolsError" class="page-error" />

      <div v-else-if="!pools" class="loading-state">
        <span class="mono">{{ t('common.loading') }}</span>
      </div>

      <template v-else>
        <Card :title="t('mem.l1')" class="pool-card">
          <div v-if="l1Items.length" class="pool-list">
            <div v-for="(it, i) in l1Items" :key="i" class="pool-item">
              <div class="pool-text mono">{{ itemText(it) }}</div>
              <div class="pool-meta mono">{{ itemMeta(it) }}</div>
            </div>
          </div>
          <EmptyState v-else />
        </Card>

        <Card :title="t('mem.l2')" class="pool-card">
          <div v-if="l2Items.length" class="pool-list">
            <div v-for="(it, i) in l2Items" :key="i" class="pool-item">
              <div class="pool-text mono">{{ itemText(it) }}</div>
              <div class="pool-meta mono">{{ itemMeta(it) }}</div>
            </div>
          </div>
          <EmptyState v-else />
        </Card>

        <Card class="stat-card">
          <StatGrid :items="summaryItems" :cols="3" />
        </Card>
      </template>
    </div>

    <div v-if="pools" class="pane-right">
      <Card :title="t('mem.l3')" class="pool-card">
        <div v-if="l3Items.length" class="pool-list">
          <div v-for="(it, i) in l3Items" :key="i" class="pool-item">
            <div class="pool-text mono">{{ itemText(it) }}</div>
            <div class="pool-meta mono">{{ itemMeta(it) }}</div>
          </div>
        </div>
        <EmptyState v-else />
      </Card>

      <Card :title="t('mem.consolidate')" class="consolidate-card">
        <EmptyState />
      </Card>

      <Card :title="t('mem.meltdown')" class="meltdown-card">
        <p class="meltdown-desc">{{ t('mem.meltdown_desc') }}</p>
        <Button variant="danger" @click="openMeltdown">{{ t('mem.meltdown_btn') }}</Button>
      </Card>
    </div>

    <Modal v-model:open="meltdownOpen" :title="t('mem.meltdown_btn')" size="sm">
      <div v-if="meltdownStage === 'confirm'" class="meltdown-confirm">
        <p class="meltdown-confirm-desc">{{ t('mem.meltdown_confirm') }}</p>
        <p v-if="meltdownNonce" class="meltdown-nonce mono">{{ meltdownNonce }}</p>
        <p v-else-if="meltdownError" class="meltdown-error mono">{{ meltdownError }}</p>
        <TextInput
          v-model="meltdownInput"
          placeholder="..."
          :invalid="meltdownInput.length > 0 && !meltdownMatch"
        />
      </div>
      <div v-else-if="meltdownStage === 'counting'" class="meltdown-counting">
        <p class="countdown-big mono">{{ meltdownCountdown }}</p>
        <p v-if="meltdownError" class="meltdown-error mono">{{ meltdownError }}</p>
      </div>

      <template #footer>
        <Button variant="secondary" @click="abortMeltdown">{{ t('mem.meltdown_abort') }}</Button>
        <Button
          v-if="meltdownStage === 'confirm'"
          variant="danger"
          :disabled="!meltdownMatch"
          @click="armMeltdown"
        >
          {{ t('mem.meltdown_btn') }}
        </Button>
      </template>
    </Modal>
  </div>
</template>

<style scoped>
.pane-left > .card + .card,
.pane-right > .card + .card {
  margin-top: var(--space-8);
}

.pool-list {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  max-height: 280px;
  overflow-y: auto;
}

.pool-item {
  padding: var(--space-4) var(--space-5);
  background: var(--stat-bg);
  border: 1px solid var(--stat-border);
  border-radius: var(--r-md);
}

.pool-text {
  font-size: var(--font-sm);
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-word;
}

.pool-meta {
  margin-top: var(--space-2);
  font-size: var(--font-xs);
  color: var(--text-muted);
}

.consolidate-row {
  display: flex;
  align-items: center;
  gap: var(--space-6);
}

.countdown {
  font-size: var(--font-sm);
  color: var(--accent);
}

.sink-result {
  font-size: var(--font-sm);
  color: var(--text-muted);
}

.meltdown-card {
  border-color: rgba(255, 68, 68, 0.25);
  background: rgba(255, 68, 68, 0.04);
}

.meltdown-desc {
  margin: 0 0 var(--space-6);
  font-size: var(--font-sm);
  color: var(--text-muted);
}

.meltdown-confirm,
.meltdown-counting {
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
  align-items: center;
  text-align: center;
}

.meltdown-confirm-desc {
  margin: 0;
  font-size: var(--font-sm);
  color: var(--text-muted);
}

.meltdown-nonce {
  font-size: var(--font-lg);
  font-weight: 700;
  letter-spacing: 4px;
  color: var(--red);
}

.meltdown-error {
  font-size: var(--font-xs);
  color: var(--red);
}

.countdown-big {
  font-size: var(--font-xl);
  font-weight: 700;
  color: var(--red);
  text-shadow: 0 0 12px rgba(255, 68, 68, 0.45);
}

.loading-state {
  height: 100%;
  min-height: 200px;
  display: grid;
  place-items: center;
  color: var(--text-muted);
  font-size: var(--font-sm);
  letter-spacing: 1px;
  opacity: 0.7;
}
</style>
