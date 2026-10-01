<script setup lang="ts">
// Real <button> primitive for all call-to-action chrome. `danger` is reserved
// for destructive ops (meltdown / purge) — tinted with --red, not the accent.
export type ButtonVariant = 'primary' | 'secondary' | 'danger'
export type ButtonSize = 'sm' | 'md'

withDefaults(
  defineProps<{
    variant?: ButtonVariant
    size?: ButtonSize
    loading?: boolean
    disabled?: boolean
    type?: 'button' | 'submit' | 'reset'
  }>(),
  {
    variant: 'secondary',
    size: 'md',
    loading: false,
    disabled: false,
    type: 'button',
  },
)

const emit = defineEmits<{
  click: [event: MouseEvent]
}>()

function onClick(e: MouseEvent): void {
  emit('click', e)
}
</script>

<template>
  <button
    class="btn"
    :class="['v-' + variant, 's-' + size, { 'is-loading': loading }]"
    :type="type"
    :disabled="disabled || loading"
    @click="onClick"
  >
    <span v-if="loading" class="btn-spinner" aria-hidden="true" />
    <span class="btn-content"><slot /></span>
  </button>
</template>

<style scoped>
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-3);
  font-family: var(--font-head);
  font-weight: 700;
  letter-spacing: 1px;
  border: 1px solid transparent;
  border-radius: var(--r-md);
  cursor: pointer;
  transition: transform var(--dur-fast) var(--ease-organic), box-shadow var(--dur-mid) ease,
    background var(--dur-mid) ease, border-color var(--dur-mid) ease;
}
.btn:disabled {
  cursor: default;
  opacity: 0.5;
}
.btn:focus-visible {
  outline: none;
  box-shadow: var(--ring-focus);
}
.btn:not(:disabled):hover {
  transform: translateY(-1px);
}
.btn:not(:disabled):active {
  transform: translateY(0);
}

.s-sm {
  padding: var(--space-2) var(--space-6);
  font-size: var(--font-xs);
}
.s-md {
  padding: var(--space-4) var(--space-8);
  font-size: var(--font-base);
}

.v-primary {
  background: var(--btn-primary-bg);
  color: var(--btn-primary-fg);
}
.v-primary:not(:disabled):hover {
  box-shadow: var(--glow-strong);
}

.v-secondary {
  background: var(--input-bg);
  color: var(--text);
  border-color: var(--card-border);
}
.v-secondary:not(:disabled):hover {
  border-color: var(--accent);
  box-shadow: var(--glow-accent);
}

.v-danger {
  background: rgba(255, 68, 68, 0.12);
  color: var(--red);
  border-color: rgba(255, 68, 68, 0.35);
}
.v-danger:not(:disabled):hover {
  background: rgba(255, 68, 68, 0.2);
  box-shadow: 0 0 12px rgba(255, 68, 68, 0.35);
}

.btn-spinner {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  border: 2px solid currentColor;
  border-top-color: transparent;
  opacity: 0.8;
  animation: btn-spin 0.7s linear infinite;
}
.btn-content {
  display: inline-flex;
  align-items: center;
}
.is-loading .btn-content {
  opacity: 0.7;
}

@keyframes btn-spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
