<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { onBeforeRouteLeave } from 'vue-router'
import { useLiveStore } from '../stores/live'
import { useI18n } from '../composables/useI18n'
import Card from '../components/ui/Card.vue'
import BarRow from '../components/ui/BarRow.vue'
import StatGrid from '../components/ui/StatGrid.vue'
import Badge from '../components/ui/Badge.vue'
import RouteBar from '../components/ui/RouteBar.vue'
import type { RouteDistribution } from '../api/types'
import { buildTimingRows, type TimingRow } from './monitorTiming'
import ObservationChamber from '../components/monitor/ObservationChamber.vue'
import { useScopeStore } from '../stores/scope'
import type { ObservationGroup } from './monitorObservation'

// Mirrors the old dashboard's adaptState()/num() helper (UI/index.html,
// pre-rebuild — see git history at 1f8a21f). Explicit null/undefined/''
// check so a real 0 (e.g. boundary.integrity=0, a fully-breached boundary)
// never gets silently swapped for the fallback by a `Number(x) || default`
// falsy check — that was a real shipped bug the old dashboard had to fix.
function num(obj: Record<string, unknown> | undefined, keys: string[], dflt: number): number {
  if (!obj) return dflt
  for (const k of keys) {
    const v = obj[k]
    if (v !== null && v !== undefined && v !== '') {
      const n = Number(v)
      if (!Number.isNaN(n)) return n
    }
  }
  return dflt
}

const live = useLiveStore()
const scope = useScopeStore()
const { t } = useI18n()
const activeObservation = ref<ObservationGroup | null>(null)
const observationOpen = ref(false)
const originRect = ref<DOMRect | null>(null)
function openObservation(group: ObservationGroup, event: MouseEvent | KeyboardEvent): void {
  if (observationOpen.value) return
  const card = event.currentTarget as HTMLElement
  card.focus()
  originRect.value = card.getBoundingClientRect()
  activeObservation.value = group
  observationOpen.value = true
}
function closeObservation(): void { observationOpen.value = false; activeObservation.value = null; originRect.value = null }
watch(() => scope.selectionEpoch, closeObservation, { flush: 'sync' })
onBeforeRouteLeave(() => closeObservation())

const EMOTION_KEYS = [
  'warmth',
  'arousal',
  'valence',
  'tension',
  'curiosity',
  'repair_pressure',
  'expression_drive',
  'boundary_firmness',
] as const

// Old UI: pct = min(abs(v)*100, 100); bar turns cyan when v < 0 (valence can
// go negative). BarRow's :value/:max drive width off a plain ratio, so we
// feed it the magnitude and let :display show the true signed value.
const emotionRows = computed(() =>
  EMOTION_KEYS.map((k) => {
    const raw = num(live.state?.emotion, [k], 0)
    return {
      key: k,
      label: t('emo.' + k),
      value: Math.abs(raw),
      display: raw.toFixed(2),
      color: raw < 0 ? 'var(--cyan)' : undefined,
    }
  }),
)

const boundaryItems = computed(() => {
  const bd = live.state?.boundary
  return [
    { label: t('bound.integrity'), value: num(bd, ['integrity'], 1).toFixed(2) },
    { label: t('bound.entropy'), value: num(bd, ['entropy'], 0).toFixed(2) },
    { label: t('bound.rotation'), value: num(bd, ['rotation', 'stability'], 0).toFixed(2) },
    { label: t('bound.repair_rate'), value: num(bd, ['repair_rate', 'stability'], 1).toFixed(2) },
  ]
})

const routeDist = computed<RouteDistribution>(() => {
  const s = live.state
  if (s?.route_distribution) return s.route_distribution
  if (s?.route_stats) {
    const distribution: RouteDistribution = {}
    for (const [route, count] of Object.entries(s.route_stats)) {
      distribution[route.toUpperCase()] = Number(count) || 0
    }
    return distribution
  }
  return { RESONANCE: 0, SKIP: 0 }
})

const gateItems = computed(() => {
  const g = live.state?.gate
  return [
    { label: t('gate.surprise'), value: num(g, ['surprise', 'mean_surprise'], 0).toFixed(2) },
    { label: t('gate.threshold'), value: num(g, ['threshold'], 0.5).toFixed(2) },
    { label: t('gate.route'), value: g?.route || 'N/A' },
  ]
})

// Old adaptState(): `expression.drive = num(expression, ['pressure', 'drive'], 0)`
// — 'pressure' is checked FIRST, 'drive' is the legacy alias. Preserved here.
const exprMode = computed(() => (live.state?.expression?.mode || 'SILENT').toUpperCase())
const exprDrive = computed(() => num(live.state?.expression, ['pressure', 'drive'], 0))
const exprThreshold = computed(() => num(live.state?.expression, ['threshold'], 0.5))

const feedbackItems = computed(() => {
  const fb = live.state?.feedback
  return [
    { label: t('fb.positive'), value: num(fb, ['positive', 'accepted'], 0) },
    { label: t('fb.negative'), value: num(fb, ['negative', 'rejected'], 0) },
    { label: t('fb.neutral'), value: num(fb, ['neutral', 'ignored'], 0) },
  ]
})

const timingRows = computed<TimingRow[]>(() => buildTimingRows(live.state))
</script>

<template>
  <div v-if="live.state" class="page-split">
    <div class="pane-left">
      <Card :title="t('monitor.emotion')" interactive :aria-label="t('monitor.emotion')" :expanded="activeObservation === 'emotion' && observationOpen" controls="observation-chamber" @activate="openObservation('emotion', $event)">
        <BarRow
          v-for="row in emotionRows"
          :key="row.key"
          :label="row.label"
          :value="row.value"
          :color="row.color"
          :display="row.display"
        />
      </Card>

      <Card :title="t('monitor.boundary')" interactive :aria-label="t('monitor.boundary')" :expanded="activeObservation === 'boundary' && observationOpen" controls="observation-chamber" @activate="openObservation('boundary', $event)">
        <StatGrid :items="boundaryItems" :cols="2" />
      </Card>

      <Card :title="t('monitor.timing')" interactive :aria-label="t('monitor.timing')" :expanded="activeObservation === 'timing' && observationOpen" controls="observation-chamber" @activate="openObservation('timing', $event)">
        <table v-if="timingRows.length" class="timing-table mono">
          <thead>
            <tr>
              <th>{{ t('timing.layer') }}</th>
              <th>{{ t('timing.avg') }}</th>
              <th>{{ t('timing.p95') }}</th>
              <th>{{ t('timing.count') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in timingRows" :key="row.layer">
              <td>{{ row.layer }}</td>
              <td>{{ row.avg }}</td>
              <td>{{ row.p95 }}</td>
              <td>{{ row.count }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty-note">{{ t('common.empty') }}</div>
      </Card>
    </div>

    <div class="pane-right">
      <Card :title="t('monitor.routing')" interactive :aria-label="t('monitor.routing')" :expanded="activeObservation === 'routing' && observationOpen" controls="observation-chamber" @activate="openObservation('routing', $event)">
        <RouteBar :dist="routeDist" />
      </Card>

      <Card :title="t('monitor.gate')" interactive :aria-label="t('monitor.gate')" :expanded="activeObservation === 'gate' && observationOpen" controls="observation-chamber" @activate="openObservation('gate', $event)">
        <StatGrid :items="gateItems" :cols="3" />
      </Card>

      <Card :title="t('monitor.expression')" interactive :aria-label="t('monitor.expression')" :expanded="activeObservation === 'expression' && observationOpen" controls="observation-chamber" @activate="openObservation('expression', $event)">
        <div class="expr-mode">
          <Badge variant="accent">{{ exprMode }}</Badge>
        </div>
        <BarRow :label="t('expr.drive')" :value="exprDrive" :display="exprDrive.toFixed(2)" />
        <BarRow
          :label="t('expr.threshold')"
          :value="exprThreshold"
          color="var(--cyan)"
          :display="exprThreshold.toFixed(2)"
        />
      </Card>

      <Card :title="t('monitor.feedback')" interactive :aria-label="t('monitor.feedback')" :expanded="activeObservation === 'feedback' && observationOpen" controls="observation-chamber" @activate="openObservation('feedback', $event)">
        <StatGrid :items="feedbackItems" :cols="3" />
      </Card>
    </div>
  </div>
  <div v-else class="loading-state">
    <span class="mono">{{ t('common.loading') }}</span>
  </div>
  <ObservationChamber :open="observationOpen" :group="activeObservation" :state="live.state" :origin-rect="originRect" @update:open="closeObservation" />
</template>

<style scoped>
.pane-left > .card + .card,
.pane-right > .card + .card {
  margin-top: var(--space-8);
}

.expr-mode {
  margin-bottom: var(--space-6);
}

.timing-table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--font-sm);
}
.timing-table th {
  text-align: left;
  padding: var(--space-3) var(--space-4);
  color: var(--text-muted);
  border-bottom: 1px solid var(--card-border);
  font-weight: 700;
  letter-spacing: 0.5px;
}
.timing-table td {
  padding: var(--space-3) var(--space-4);
  border-bottom: 1px solid var(--card-border);
}
.timing-table tbody tr:last-child td {
  border-bottom: none;
}

.empty-note {
  text-align: center;
  padding: var(--space-8) 0;
  color: var(--text-muted);
  font-size: var(--font-sm);
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
