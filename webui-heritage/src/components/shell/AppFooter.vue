<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from '../../composables/useI18n'
import { useInteractionFeedback } from '../../composables/useInteractionFeedback'
import { useLiveStore } from '../../stores/live'

const live = useLiveStore()
const { t } = useI18n()
const feedback = useInteractionFeedback()

const runtime = computed(() => {
  const value = live.state?.runtime
  if (typeof value === 'string') return value || '—'
  if (value && typeof value === 'object') {
    const info = value as Record<string, unknown>
    return String(info.runtime_id || info.instance_id || info.plugin_name || '—')
  }
  return '—'
})
const schema = computed(() => {
  const value = live.state?.schema_version
  return value === undefined ? '' : String(value).replace(/^sylanne\.webui\./, '')
})
const sessionCount = computed(() => live.state?.sessions?.length ?? 0)
const narration = computed(() => {
  const current = feedback.state.value
  if (current.text) return current
  if (live.error) {
    return {
      ...current,
      text: t('feedback.connection_interrupted'),
      tone: 'warning' as const,
    }
  }
  return {
    ...current,
    text: schema.value ? `schema ${schema.value}` : '',
    tone: 'neutral' as const,
  }
})
</script>

<template>
  <footer class="foot mono">
    <span class="runtime">runtime: {{ runtime }}</span>
    <span
      class="narration"
      :class="'tone-' + narration.tone"
      aria-live="polite"
      aria-atomic="true"
    >
      {{ narration.text }}
    </span>
    <span class="sessions">sessions: {{ sessionCount }}</span>
  </footer>
</template>

<style scoped>
.foot {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 2fr) minmax(0, 1fr);
  align-items: center;
  gap: var(--space-7);
  padding: 0 var(--space-8);
  border-top: 1px solid var(--card-border);
  font-size: var(--font-xs);
  color: var(--text-muted);
  letter-spacing: 0.5px;
  min-width: 0;
}
.runtime {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.narration {
  min-width: 0;
  text-align: center;
  white-space: nowrap;
}
.sessions {
  text-align: right;
  white-space: nowrap;
}
.tone-neutral {
  color: var(--text-muted);
}
.tone-success {
  color: var(--green);
}
.tone-warning {
  color: var(--accent);
}
.tone-error {
  color: var(--red);
}

@media (max-width: 620px) {
  .foot {
    grid-template-columns: minmax(0, 0.7fr) minmax(0, 1.6fr) auto;
    gap: var(--space-4);
    padding: 0 var(--space-3);
  }
  .narration {
    white-space: normal;
    overflow-wrap: anywhere;
    line-height: 1.15;
  }
}
</style>
