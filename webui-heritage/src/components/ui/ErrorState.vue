<script setup lang="ts">
// Error card — for "CONFIG FETCH FAILED" style states the old dashboard
// showed. Uses --red tint; optional #action slot (e.g. a Retry button).
import { useSlots } from 'vue'
import { useI18n } from '../../composables/useI18n'

withDefaults(
  defineProps<{
    messageKey?: string
    message?: string
  }>(),
  { messageKey: undefined, message: undefined },
)

const slots = useSlots()
const { t } = useI18n()
</script>

<template>
  <div class="error-state" role="alert">
    <div class="error-icon" aria-hidden="true">!</div>
    <div class="error-message">
      <slot>{{ message ?? (messageKey ? t(messageKey) : t('common.empty')) }}</slot>
    </div>
    <div v-if="slots.action" class="error-action">
      <slot name="action" />
    </div>
  </div>
</template>

<style scoped>
.error-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--space-5);
  padding: var(--space-9) var(--space-8);
  text-align: center;
  background: rgba(255, 68, 68, 0.06);
  border: 1px solid rgba(255, 68, 68, 0.2);
  border-radius: var(--r-md);
}
.error-icon {
  width: 28px;
  height: 28px;
  flex: none;
  display: grid;
  place-items: center;
  border-radius: 50%;
  background: rgba(255, 68, 68, 0.16);
  color: var(--red);
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: var(--font-md);
}
.error-message {
  font-size: var(--font-sm);
  color: var(--text);
  letter-spacing: 0.3px;
}
.error-action {
  display: flex;
  gap: var(--space-4);
}
</style>
