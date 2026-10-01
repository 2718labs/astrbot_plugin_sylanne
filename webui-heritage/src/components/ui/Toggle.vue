<script setup lang="ts">
// On/off switch primitive — used for Config booleans and the Life-sim enable
// flag. Track glows with the signature accent when on; knob slides with the
// same snap easing the rest of the chrome uses.
withDefaults(
  defineProps<{
    modelValue: boolean
    disabled?: boolean
  }>(),
  { disabled: false },
)

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
}>()
</script>

<template>
  <label class="toggle-row" :class="{ 'is-disabled': disabled }">
    <button
      type="button"
      role="switch"
      class="toggle-track"
      :class="{ 'is-on': modelValue }"
      :aria-checked="modelValue"
      :disabled="disabled"
      @click="!disabled && emit('update:modelValue', !modelValue)"
    >
      <span class="toggle-knob" />
    </button>
    <span v-if="$slots.default" class="toggle-label"><slot /></span>
  </label>
</template>

<style scoped>
.toggle-row {
  display: inline-flex;
  align-items: center;
  gap: var(--space-5);
  cursor: pointer;
  user-select: none;
}
.toggle-row.is-disabled {
  cursor: default;
  opacity: 0.5;
}

.toggle-track {
  position: relative;
  flex: none;
  width: 40px;
  height: 22px;
  padding: 0;
  border: none;
  border-radius: var(--r-pill);
  background: var(--track);
  cursor: pointer;
  transition: background var(--dur-mid) var(--ease-snap), box-shadow var(--dur-mid) var(--ease-snap);
}
.toggle-track:disabled {
  cursor: default;
}
.toggle-track:focus-visible {
  outline: none;
  box-shadow: var(--ring-focus);
}
.toggle-track.is-on {
  background: var(--accent);
  box-shadow: var(--glow-strong);
}

.toggle-knob {
  position: absolute;
  top: 2px;
  left: 2px;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: var(--text);
  transition: transform var(--dur-mid) var(--ease-snap);
}
.toggle-track.is-on .toggle-knob {
  transform: translateX(18px);
}

.toggle-label {
  font-size: var(--font-sm);
  color: var(--text);
}
</style>
