<script setup lang="ts">
// Centered muted icon + message. Extracted from the ad-hoc .empty-note block
// duplicated inline in MonitorView (see card-timing's v-else branch).
import { useSlots } from 'vue'
import { useI18n } from '../../composables/useI18n'

withDefaults(
  defineProps<{
    messageKey?: string
  }>(),
  { messageKey: 'common.empty' },
)

const slots = useSlots()
const { t } = useI18n()
</script>

<template>
  <div class="empty-state">
    <div v-if="slots.icon" class="empty-icon">
      <slot name="icon" />
    </div>
    <div class="empty-message mono">
      <slot>{{ t(messageKey) }}</slot>
    </div>
  </div>
</template>

<style scoped>
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--space-4);
  padding: var(--space-9) var(--space-8);
  color: var(--text-muted);
  text-align: center;
}
.empty-icon {
  opacity: 0.5;
  display: grid;
  place-items: center;
  font-size: var(--font-xl);
}
.empty-message {
  font-size: var(--font-sm);
  letter-spacing: 0.5px;
}
</style>
