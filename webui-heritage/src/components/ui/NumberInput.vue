<script setup lang="ts">
// Numeric input primitive — same chrome as TextInput, mono digits, emits a
// real number (not a string) on v-model:number.
const props = withDefaults(
  defineProps<{
    modelValue: number
    min?: number
    max?: number
    step?: number
    disabled?: boolean
  }>(),
  {
    step: 1,
    disabled: false,
  },
)

const emit = defineEmits<{
  'update:modelValue': [value: number]
}>()

function onInput(e: Event): void {
  const raw = (e.target as HTMLInputElement).value
  const n = Number(raw)
  if (raw !== '' && !Number.isNaN(n)) {
    emit('update:modelValue', n)
  }
}

// 清空/非法输入时不改模型（onInput 已跳过），失焦时把视图回填成当前模型值——
// 否则 `:value="modelValue"` 在 modelValue 未变时不会把 DOM 拨回去，会留下
// "输入框显示空、底层模型仍是旧值"的 UI/数据不一致（gemini review）。
function onBlur(e: Event): void {
  const el = e.target as HTMLInputElement
  const n = Number(el.value)
  if (el.value === '' || Number.isNaN(n)) {
    el.value = String(props.modelValue)
  }
}
</script>

<template>
  <input
    class="number-input mono"
    type="number"
    :value="modelValue"
    :min="min"
    :max="max"
    :step="step"
    :disabled="disabled"
    @input="onInput"
    @blur="onBlur"
  />
</template>

<style scoped>
.number-input {
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
.number-input:disabled {
  cursor: default;
  opacity: 0.5;
}
.number-input:focus {
  border-color: var(--accent);
  box-shadow: var(--ring-focus);
}

/* browser spinner chrome is dropped — value still steppable via keyboard
   up/down arrows, min/max/step remain enforced by the native input */
.number-input::-webkit-outer-spin-button,
.number-input::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}
.number-input {
  -moz-appearance: textfield;
}
</style>
