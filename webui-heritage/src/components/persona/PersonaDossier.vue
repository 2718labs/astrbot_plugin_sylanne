<script setup lang="ts">
import { computed } from 'vue'
import type { PersonaDossierResponse } from '../../api/types'
import { useI18n } from '../../composables/useI18n'
import Modal from '../ui/Modal.vue'

type PersonaDossier = PersonaDossierResponse['persona']

const props = defineProps<{
  open: boolean
  dossier: PersonaDossier | null
  loading: boolean
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
}>()

const { t } = useI18n()

const priorRows = computed(() => {
  const dossier = props.dossier
  if (!dossier || dossier.genesis.state !== 'active' || !dossier.genesis.priors) return []
  return Object.entries(dossier.genesis.priors).map(([name, value]) => ({
    name,
    value: formatPrior(value),
  }))
})

function formatPrior(value: unknown): string {
  if (typeof value === 'string') return value
  const rendered = JSON.stringify(value)
  return typeof rendered === 'string' ? rendered : ''
}

function formatTimestamp(value: number): string {
  return new Date(value).toLocaleString()
}
</script>

<template>
  <Modal
    :open="open"
    :title="t('pers.dossier')"
    size="lg"
    @update:open="emit('update:open', $event)"
  >
    <p v-if="loading && !dossier" class="dossier-muted">{{ t('common.loading') }}</p>

    <div v-else-if="dossier" class="dossier-grid">
      <section class="dossier-section">
        <h3>{{ t('pers.dossier_base') }}</h3>
        <dl>
          <div><dt>{{ t('pers.dossier_display') }}</dt><dd>{{ dossier.display }}</dd></div>
          <div><dt>{{ t('pers.dossier_ref') }}</dt><dd class="mono">{{ dossier.ref_short }}</dd></div>
          <div><dt>{{ t('pers.dossier_fingerprint') }}</dt><dd class="mono">{{ dossier.fingerprint_short }}</dd></div>
          <div><dt>{{ t('pers.dossier_resolution') }}</dt><dd>{{ t('pers.dossier_active') }}</dd></div>
        </dl>
      </section>

      <section class="dossier-section">
        <h3>{{ t('pers.dossier_birth') }}</h3>
        <dl v-if="dossier.genesis.state === 'active' && priorRows.length">
          <div v-for="row in priorRows" :key="row.name">
            <dt>{{ row.name }}</dt><dd class="mono">{{ row.value }}</dd>
          </div>
        </dl>
        <p v-else class="dossier-muted">{{ t('pers.dossier_awaiting') }}</p>
      </section>

      <section class="dossier-section">
        <h3>{{ t('pers.dossier_growth') }}</h3>
        <p>
          {{ dossier.genesis.state === 'active' ? t('pers.dossier_growth_enabled') : t('pers.dossier_growth_waiting') }}
        </p>
      </section>

      <section class="dossier-section">
        <h3>{{ t('pers.dossier_updated') }}</h3>
        <p class="mono">{{ formatTimestamp(dossier.updated_at_ms) }}</p>
      </section>
    </div>

    <p v-else class="dossier-muted">{{ t('pers.dossier_empty') }}</p>
  </Modal>
</template>

<style scoped>
.dossier-grid {
  display: grid;
  gap: var(--space-7);
}

.dossier-section {
  border-top: 1px solid var(--card-border);
  padding-top: var(--space-5);
}

.dossier-section:first-child {
  border-top: 0;
  padding-top: 0;
}

h3 {
  margin: 0 0 var(--space-4);
  color: var(--text);
  font-size: var(--font-xs);
  letter-spacing: 1px;
  text-transform: uppercase;
}

dl {
  display: grid;
  gap: var(--space-3);
  margin: 0;
}

dl > div {
  display: grid;
  grid-template-columns: minmax(120px, 0.42fr) 1fr;
  gap: var(--space-4);
}

dt {
  color: var(--text-muted);
}

dd,
p {
  margin: 0;
  overflow-wrap: anywhere;
}

.dossier-muted {
  color: var(--text-muted);
}
</style>
