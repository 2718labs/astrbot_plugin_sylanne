<script setup lang="ts">
// Single-line text input primitive — styled chrome so it matches the rest of
// the "living tissue" surfaces instead of raw browser input styling.
withDefaults(
  defineProps<{
    modelValue: string
    placeholder?: string
    disabled?: boolean
    invalid?: boolean
    type?: 'text' | 'password' | 'email' | 'search'
  }>(),
  {
    placeholder: '',
    disabled: false,
    invalid: false,
    type: 'text',
  },
)

const emit = defineEmits<{
  'update:modelValue': [value: string]
}>()

function onInput(e: Event): void {
  emit('update:modelValue', (e.target as HTMLInputElement).value)
}
</script>

<template>
  <input
    class="text-input mono"
    :class="{ 'is-invalid': invalid }"
    :type="type"
    :value="modelValue"
    :placeholder="placeholder"
    :disabled="disabled"
    @input="onInput"
  />
</template>

<style scoped>
.text-input {
  width: 100%;
  padding: var(--space-4) var(--space-5);
  font-size: var(--font-base);
  color: var(--text);
  background: var(--input-bg);
  border: 1px solid var(--card-border);
  border-radius: var(--r-sm);
  outline: none;
  transition: border-color var(--dur-mid) ease, box-shadow var(--dur-mid) ease;
}
.text-input::placeholder {
  color: var(--text-muted);
}
.text-input:disabled {
  cursor: default;
  opacity: 0.5;
}
.text-input:focus {
  border-color: var(--accent);
  box-shadow: var(--ring-focus);
}
.text-input.is-invalid {
  border-color: var(--red);
}
.text-input.is-invalid:focus {
  box-shadow: 0 0 0 2px rgba(255, 68, 68, 0.18);
}
</style>
