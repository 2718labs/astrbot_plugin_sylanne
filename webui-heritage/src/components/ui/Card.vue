<script setup lang="ts">
import { useSlots } from 'vue'
import { isNestedInteractiveTarget } from './cardInteraction'
const props = defineProps<{
  title?: string
  interactive?: boolean
  expanded?: boolean
  controls?: string
  ariaLabel?: string
}>()
const emit = defineEmits<{ activate: [event: MouseEvent | KeyboardEvent] }>()
const slots = useSlots()

function hasSelectionWithinCard(card: HTMLElement): boolean {
  const selection = window.getSelection()
  return !!(selection?.toString() && (card.contains(selection.anchorNode) || card.contains(selection.focusNode)))
}

function activate(event: MouseEvent | KeyboardEvent): void {
  if (!props.interactive || isNestedInteractiveTarget(event.target, event.currentTarget)) return
  if (event.type === 'click' && hasSelectionWithinCard(event.currentTarget as HTMLElement)) return
  emit('activate', event)
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault()
    activate(event)
  }
}
</script>

<template>
  <div
    class="card"
    :class="{ interactive }"
    :role="interactive ? 'button' : undefined"
    :tabindex="interactive ? 0 : undefined"
    :aria-label="interactive ? (ariaLabel || title) : undefined"
    :aria-expanded="interactive ? expanded : undefined"
    :aria-controls="interactive ? controls : undefined"
    @click="activate"
    @keydown="onKeydown"
  >
    <div v-if="title || slots.header" class="card-head">
      <slot name="header"><span class="card-title">{{ title }}</span></slot>
      <slot name="action" />
    </div>
    <slot />
  </div>
</template>

<style scoped>
.card {
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: var(--r-lg);
  padding: var(--space-8);
  position: relative;
  overflow: hidden;
  box-shadow: 0 2px 20px rgba(0, 0, 0, 0.22);
  transition: border-color var(--dur-mid) ease, box-shadow var(--dur-mid) ease, transform var(--dur-mid) ease;
  animation: fadeUp 0.5s var(--ease-snap) backwards;
  min-width: 0;
}
/* glowing "tissue slice" top edge — a constant faint version of the hover tint */
.card::before {
  content: '';
  position: absolute;
  top: 0;
  left: var(--space-7);
  right: var(--space-7);
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--card-tick), transparent);
  opacity: 0.4;
}
.card.interactive {
  cursor: pointer;
}
.card.interactive:hover,
.card.interactive:focus-visible {
  border-color: rgba(184, 138, 158, 0.28);
  box-shadow: 0 2px 24px rgba(0, 0, 0, 0.28), 0 0 20px rgba(184, 138, 158, 0.06);
  transform: translateY(-1px);
  outline: none;
}
.card.interactive:focus-visible {
  box-shadow: var(--ring-focus), 0 2px 24px rgba(0, 0, 0, 0.28), 0 0 20px rgba(184, 138, 158, 0.06);
}
.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--space-6);
}
.card-title {
  display: inline-flex;
  align-items: center;
  gap: var(--space-3);
  font-size: var(--font-xs);
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text);
  opacity: 0.85;
}
/* glowing rose anchor tick — gives each card title an identity, not just a label */
.card-title::before {
  content: '';
  width: 3px;
  height: 12px;
  border-radius: 1px;
  background: var(--accent);
  box-shadow: var(--glow-accent);
}

@media (max-width: 620px) {
  .card {
    padding: var(--space-7);
  }
}
</style>
