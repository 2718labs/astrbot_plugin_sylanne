<script setup lang="ts">
export interface StatItem {
  label: string
  value: string | number
}
withDefaults(defineProps<{ items: StatItem[]; cols?: number }>(), { cols: 2 })
</script>

<template>
  <div class="stat-grid" :style="{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }">
    <div v-for="(it, i) in items" :key="i" class="stat-box">
      <div class="stat-val mono">{{ it.value }}</div>
      <div class="stat-lbl">{{ it.label }}</div>
    </div>
  </div>
</template>

<style scoped>
.stat-grid {
  display: grid;
  gap: var(--space-3);
}
.stat-box {
  min-width: 0;
  text-align: center;
  padding: var(--space-5);
  background: var(--stat-bg);
  border: 1px solid var(--stat-border);
  border-radius: var(--r-md);
}
.stat-val {
  font-size: var(--font-lg);
  font-weight: 700;
  color: var(--accent);
  text-shadow: var(--glow-text);
}
.stat-lbl {
  font-size: var(--font-xs);
  color: var(--text-muted);
  margin-top: var(--space-1);
  letter-spacing: 0.5px;
  overflow-wrap: anywhere;
}
</style>
