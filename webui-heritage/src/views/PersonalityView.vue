<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { personaApiFetch } from '../api/client'
import type { PersonaDossierResponse } from '../api/types'
import PersonaDossier from '../components/persona/PersonaDossier.vue'
import { useLiveStore } from '../stores/live'
import { useScopeStore } from '../stores/scope'
import { useI18n } from '../composables/useI18n'
import Card from '../components/ui/Card.vue'
import BarRow from '../components/ui/BarRow.vue'
import RadarChart, { type RadarAxis } from '../components/ui/RadarChart.vue'
import Timeline, { type TimelineItem } from '../components/ui/Timeline.vue'
import EmptyState from '../components/ui/EmptyState.vue'

// Mirrors the old dashboard's adaptState() for the personality block: the
// "five" axes default to a flat 0.5 each when absent (a personality with no
// signal yet reads as neutral, not zeroed-out), while "six" and "drift"
// default to empty lists — there's nothing sensible to synthesize for those.
const FIVE_DEFAULTS: Record<string, number> = {
  openness: 0.5,
  warmth: 0.5,
  intensity: 0.5,
  autonomy: 0.5,
  resilience: 0.5,
}

const live = useLiveStore()
const scope = useScopeStore()
const { t } = useI18n()
const dossierOpen = ref(false)
const dossier = ref<PersonaDossierResponse['persona'] | null>(null)
const dossierLoading = ref(false)
let activeDossierRequest: AbortController | null = null

const fiveEntries = computed(() => {
  const five = live.state?.personality?.five
  const src = five && Object.keys(five).length ? five : FIVE_DEFAULTS
  return Object.entries(src)
})

const radarAxes = computed<RadarAxis[]>(() =>
  fiveEntries.value.map(([key, value]) => ({ label: key, value: Number(value) })),
)

interface SixRow {
  label: string
  value: number
  color?: string
}

const sixRows = computed<SixRow[]>(() => {
  const six = live.state?.personality?.six
  if (!six || !six.length) return []
  return six.map((item) => ({
    label: item.name ?? '',
    value: item.value ?? 0,
    color: item.color,
  }))
})

const driftItems = computed<TimelineItem[]>(() => {
  const drift = live.state?.personality?.drift
  if (!drift || !drift.length) return []
  return drift.map((d) => ({ time: d.time ?? '', text: d.text ?? '' }))
})

function clearDossier(): void {
  activeDossierRequest?.abort()
  activeDossierRequest = null
  dossier.value = null
  dossierLoading.value = false
  dossierOpen.value = false
}

function updateDossierOpen(value: boolean): void {
  if (!value) {
    clearDossier()
    return
  }
  dossierOpen.value = true
}

async function openDossier(): Promise<void> {
  const snapshot = scope.personaSnapshot()
  if (!snapshot) return

  activeDossierRequest?.abort()
  const controller = new AbortController()
  activeDossierRequest = controller
  dossier.value = null
  dossierLoading.value = true
  dossierOpen.value = true
  try {
    const response = await personaApiFetch(snapshot, { signal: controller.signal })
    if (!controller.signal.aborted && scope.isPersonaCurrent(snapshot, response)) {
      dossier.value = response.persona
    }
  } catch {
    // A closed, changed, or unavailable Persona leaves no stale dossier behind.
  } finally {
    if (activeDossierRequest === controller) {
      activeDossierRequest = null
      dossierLoading.value = false
    }
  }
}

watch(
  () => [
    scope.selection.botRef,
    scope.selection.personaRef,
    scope.selectedPersonaGeneration,
    scope.personaEpoch,
  ],
  clearDossier,
)

onBeforeUnmount(clearDossier)
</script>

<template>
  <div v-if="live.state" class="page-split">
    <div class="pane-left">
      <Card
        :title="t('pers.radar')"
        interactive
        :aria-label="t('pers.dossier_open')"
        @activate="openDossier"
      >
        <RadarChart :axes="radarAxes" :max="1" />
      </Card>
    </div>

    <div class="pane-right">
      <Card
        :title="t('pers.six')"
        interactive
        :aria-label="t('pers.dossier_open')"
        @activate="openDossier"
      >
        <BarRow
          v-for="row in sixRows"
          :key="row.label"
          :label="row.label"
          :value="row.value"
          :color="row.color"
          :display="row.value.toFixed(2)"
        />
        <EmptyState v-if="!sixRows.length" />
      </Card>

      <Card
        :title="t('pers.drift')"
        interactive
        :aria-label="t('pers.dossier_open')"
        @activate="openDossier"
      >
        <Timeline v-if="driftItems.length" :items="driftItems" />
        <EmptyState v-else />
      </Card>
    </div>
  </div>

  <div v-else class="loading-state">
    <span class="mono">{{ t('common.loading') }}</span>
  </div>

  <PersonaDossier
    :open="dossierOpen"
    :dossier="dossier"
    :loading="dossierLoading"
    @update:open="updateDossierOpen"
  />
</template>

<style scoped>
.pane-right > .card + .card {
  margin-top: var(--space-8);
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
