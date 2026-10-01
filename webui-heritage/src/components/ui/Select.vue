<script setup lang="ts">
// Styled dropdown primitive. Wraps a real <select> (kept for native a11y/
// keyboard behavior) and layers custom chrome + a chevron on top so it never
// falls back to raw browser select rendering.
export interface SelectOption {
  label: string
  value: string
}

withDefaults(
  defineProps<{
    modelValue: string
    options: SelectOption[]
    disabled?: boolean
  }>(),
  { disabled: false },
)

const emit = defineEmits<{
  'update:modelValue': [value: string]
}>()

function onChange(e: Event): void {
  emit('update:modelValue', (e.target as HTMLSelectElement).value)
}
</script>

<template>
  <div class="select-wrap" :class="{ 'is-disabled': disabled }">
    <select
      class="select mono"
      :value="modelValue"
      :disabled="disabled"
      @change="onChange"
    >
      <option v-for="opt in options" :key="opt.value" :value="opt.value">
        {{ opt.label }}
      </option>
    </select>
    <svg class="chevron" viewBox="0 0 20 20" aria-hidden="true">
      <path d="M5 7.5L10 12.5L15 7.5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
  </div>
</template>

<style scoped>
.select-wrap {
  position: relative;
  display: inline-block;
  width: 100%;
}
.select-wrap.is-disabled {
  opacity: 0.5;
}

.select {
  width: 100%;
  padding: var(--space-4) var(--space-9) var(--space-4) var(--space-5);
  font-size: var(--font-base);
  color: var(--text);
  background: var(--input-bg);
  border: 1px solid var(--card-border);
  border-radius: var(--r-sm);
  outline: none;
  cursor: pointer;
  appearance: none;
  -webkit-appearance: none;
  transition: border-color var(--dur-mid) ease, box-shadow var(--dur-mid) ease;
}
.select:disabled {
  cursor: default;
}
.select:focus {
  border-color: var(--accent);
  box-shadow: var(--ring-focus);
}
.select option {
  background: var(--bg);
  color: var(--text);
}

.chevron {
  position: absolute;
  top: 50%;
  right: var(--space-5);
  transform: translateY(-50%);
  width: 14px;
  height: 14px;
  color: var(--text-muted);
  pointer-events: none;
}
</style>
