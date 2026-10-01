<script setup lang="ts">
// The single badge/pill component. Also closes the old Life-page bug where
// `.badge` was referenced but never defined (rendered as bare text).
export type BadgeVariant =
  | 'accent'
  | 'fast'
  | 'normal'
  | 'full'
  | 'skip'
  | 'neutral'
  | 'green'
  | 'red'
withDefaults(defineProps<{ variant?: BadgeVariant }>(), { variant: 'accent' })
</script>

<template>
  <span class="badge" :class="'v-' + variant"><slot /></span>
</template>

<style scoped>
.badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: var(--r-xs);
  font-size: var(--font-xs);
  font-family: var(--font-mono);
  letter-spacing: 0.5px;
  white-space: nowrap;
}
.v-accent {
  border-radius: var(--r-pill);
  padding: 4px 14px;
  background: var(--glow);
  color: var(--accent);
}
.v-fast {
  background: rgba(184, 138, 158, 0.25);
  color: #d4a0b8;
}
.v-normal {
  background: rgba(0, 180, 216, 0.2);
  color: #33ccee;
}
.v-full {
  background: rgba(255, 170, 0, 0.2);
  color: #ffcc44;
}
.v-skip,
.v-neutral {
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-muted);
}
.v-green {
  background: rgba(76, 175, 80, 0.18);
  color: #7bd07f;
}
.v-red {
  background: rgba(255, 68, 68, 0.16);
  color: #ff7a7a;
}
</style>
