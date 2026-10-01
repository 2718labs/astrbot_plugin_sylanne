<script setup lang="ts">
export interface TimelineItem {
  time: string
  text: string
  tag?: string
}

withDefaults(defineProps<{ items: TimelineItem[] }>(), { items: () => [] })
</script>

<template>
  <div class="timeline">
    <ol v-if="items.length" class="timeline-list">
      <li v-for="(item, i) in items" :key="i" class="timeline-item">
        <span class="timeline-dot" />
        <div class="timeline-body">
          <div class="timeline-head">
            <span class="timeline-time mono">{{ item.time }}</span>
            <span v-if="item.tag" class="timeline-tag mono">{{ item.tag }}</span>
          </div>
          <div class="timeline-text">{{ item.text }}</div>
        </div>
      </li>
    </ol>
    <div v-else class="timeline-empty">
      <slot name="empty">
        <span class="mono">— no events —</span>
      </slot>
    </div>
  </div>
</template>

<style scoped>
.timeline {
  width: 100%;
}
.timeline-list {
  position: relative;
  list-style: none;
  margin: 0;
  padding: 0;
}
/* the glowing rose spine */
.timeline-list::before {
  content: '';
  position: absolute;
  top: 4px;
  bottom: 4px;
  left: 5px;
  width: 2px;
  background: linear-gradient(
    180deg,
    rgba(var(--accent-rgb), 0.7),
    rgba(var(--accent-rgb), 0.15)
  );
  box-shadow: var(--glow-accent);
}
.timeline-item {
  position: relative;
  display: flex;
  gap: var(--space-6);
  padding-left: var(--space-9);
  padding-bottom: var(--space-8);
}
.timeline-item:last-child {
  padding-bottom: 0;
}
.timeline-dot {
  position: absolute;
  left: 0;
  top: 3px;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--accent);
  box-shadow: var(--glow-accent);
  border: 2px solid var(--bg);
}
.timeline-body {
  flex: 1;
  min-width: 0;
}
.timeline-head {
  display: flex;
  align-items: baseline;
  gap: var(--space-5);
  flex-wrap: wrap;
  margin-bottom: var(--space-1);
}
.timeline-time {
  font-size: var(--font-xs);
  color: var(--text-muted);
  letter-spacing: 0.5px;
}
.timeline-tag {
  font-size: var(--font-xs);
  color: var(--accent);
  background: var(--glow);
  border-radius: var(--r-xs);
  padding: 1px var(--space-3);
  letter-spacing: 0.5px;
}
.timeline-text {
  font-size: var(--font-sm);
  color: var(--text);
  line-height: 1.5;
  word-break: break-word;
}
.timeline-empty {
  text-align: center;
  padding: var(--space-8) 0;
  color: var(--text-muted);
  font-size: var(--font-sm);
  opacity: 0.7;
}
</style>
