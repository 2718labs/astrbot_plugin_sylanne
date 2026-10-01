<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'

export type LogLevel = 'info' | 'warn' | 'error'

export interface LogLine {
  time?: string
  route?: string
  text: string
  level?: LogLevel
}

const props = withDefaults(
  defineProps<{
    lines: LogLine[]
    autoScroll?: boolean
  }>(),
  { autoScroll: true },
)

const scrollRef = ref<HTMLDivElement | null>(null)

function routeColor(route: string | undefined): string {
  if (!route) return 'var(--accent)'
  const key = route.toUpperCase()
  if (key === 'FULL') return 'var(--amber)'
  if (key === 'NORMAL') return 'var(--cyan)'
  if (key === 'SKIP' || key === 'FAST') return 'var(--accent)'
  return 'var(--accent)'
}

function levelColor(level: LogLevel | undefined): string | undefined {
  if (level === 'error') return 'var(--red)'
  if (level === 'warn') return 'var(--amber)'
  return undefined
}

watch(
  () => props.lines.length,
  async () => {
    if (!props.autoScroll) return
    await nextTick()
    const el = scrollRef.value
    if (el) el.scrollTop = el.scrollHeight
  },
)
</script>

<template>
  <div ref="scrollRef" class="log-terminal mono" role="log" aria-live="polite">
    <div class="log-scanlines" aria-hidden="true" />
    <div v-if="lines.length" class="log-lines">
      <div
        v-for="(line, i) in lines"
        :key="i"
        class="log-line"
        :class="'level-' + (line.level || 'info')"
      >
        <span v-if="line.time" class="log-time">{{ line.time }}</span>
        <span
          v-if="line.route"
          class="log-route"
          :style="{ color: routeColor(line.route) }"
        >
          {{ line.route }}
        </span>
        <span
          class="log-text"
          :style="levelColor(line.level) ? { color: levelColor(line.level) } : undefined"
        >
          {{ line.text }}
        </span>
      </div>
    </div>
    <div v-else class="log-empty">— no log output —</div>
  </div>
</template>

<style scoped>
.log-terminal {
  position: relative;
  height: 320px;
  overflow-y: auto;
  background: rgba(0, 0, 0, 0.25);
  border: 1px solid var(--card-border);
  border-radius: var(--r-md);
  padding: var(--space-5) var(--space-6);
  font-size: var(--font-sm);
  line-height: 1.7;
}
/* subtle scanline vibe consistent with the "living tissue" identity —
   a faint repeating gradient overlay, purely decorative */
.log-scanlines {
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: repeating-linear-gradient(
    180deg,
    rgba(255, 255, 255, 0.015) 0px,
    rgba(255, 255, 255, 0.015) 1px,
    transparent 1px,
    transparent 3px
  );
}
.log-lines {
  position: relative;
}
.log-line {
  display: flex;
  align-items: baseline;
  gap: var(--space-4);
  padding: 2px 0;
  white-space: pre-wrap;
  word-break: break-word;
}
.log-time {
  flex: none;
  color: var(--text-muted);
  opacity: 0.8;
}
.log-route {
  flex: none;
  font-weight: 700;
  letter-spacing: 0.5px;
}
.log-text {
  flex: 1;
  min-width: 0;
  color: var(--text);
}
.level-error .log-text {
  text-shadow: 0 0 8px rgba(255, 68, 68, 0.35);
}
.level-warn .log-text {
  text-shadow: 0 0 8px rgba(255, 170, 0, 0.3);
}
.log-empty {
  position: relative;
  color: var(--text-muted);
  opacity: 0.7;
  padding: var(--space-4) 0;
}

/* custom scrollbar to keep the console feeling like an instrument, not a
   generic browser widget */
.log-terminal::-webkit-scrollbar {
  width: 8px;
}
.log-terminal::-webkit-scrollbar-track {
  background: transparent;
}
.log-terminal::-webkit-scrollbar-thumb {
  background: rgba(var(--accent-rgb), 0.25);
  border-radius: var(--r-pill);
}
.log-terminal::-webkit-scrollbar-thumb:hover {
  background: rgba(var(--accent-rgb), 0.4);
}
</style>
