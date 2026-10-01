<script setup lang="ts">
import { useI18n } from '../../composables/useI18n'
defineProps<{ titleKey: string }>()
const { t } = useI18n()
</script>

<template>
  <section class="placeholder">
    <div class="ph-inner">
      <div class="ph-title">{{ t(titleKey) }}</div>
      <div class="ph-soon mono">{{ t('common.soon') }}</div>
    </div>
  </section>
</template>

<style scoped>
.placeholder {
  height: 100%;
  display: grid;
  place-items: center;
}
.ph-inner {
  text-align: center;
  opacity: 0.6;
}
.ph-title {
  font-size: var(--font-xl);
  font-weight: 700;
  letter-spacing: 2px;
  margin-bottom: var(--space-3);
}
.ph-soon {
  font-size: var(--font-xs);
  letter-spacing: 3px;
  color: var(--text-muted);
}
</style>
