<script setup lang="ts">
import { computed } from 'vue'
import type { RouteDistribution } from '../../api/types'

const props = defineProps<{ dist: RouteDistribution }>()

const ORDER = ['RESONANCE', 'SKIP'] as const
const COLORS: Record<string, string> = {
  RESONANCE: 'var(--accent)',
  SKIP: 'rgba(255,255,255,0.2)',
}

const keys = computed(() => {
  const extras = Object.keys(props.dist)
    .map((key) => key.toUpperCase())
    .filter((key) => !ORDER.includes(key as (typeof ORDER)[number]))
  return [...ORDER, ...extras]
})
const total = computed(() => keys.value.reduce((sum, key) => sum + (props.dist[key] || 0), 0))
const segs = computed(() =>
  keys.value.map((k, index) => {
    const count = props.dist[k] || 0
    return {
      key: k,
      count,
      pct: total.value ? (count / total.value) * 100 : 0,
      color: COLORS[k] || ['var(--cyan)', 'var(--amber)', 'var(--green)'][index % 3],
    }
  }),
)
</script>

<template>
  <div>
    <div class="route-bar">
      <div
        v-for="s in segs"
        :key="s.key"
        class="route-seg"
        :style="{ width: s.pct + '%', background: s.color }"
      />
    </div>
    <div class="route-legend">
      <span v-for="s in segs" :key="s.key" class="leg mono">
        <i class="dot" :style="{ background: s.color }" />{{ s.key }}
        <b>{{ s.count }}</b>
      </span>
    </div>
  </div>
</template>

<style scoped>
.route-bar {
  display: flex;
  height: 16px;
  border-radius: var(--r-xs);
  overflow: hidden;
  background: var(--track);
}
.route-seg {
  height: 100%;
  transition: width var(--dur-slow) ease;
}
.route-legend {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-5);
  margin-top: var(--space-5);
  font-size: var(--font-xs);
  color: var(--text-muted);
}
.leg {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
}
.leg b {
  color: var(--text);
  font-weight: 700;
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
}
</style>
