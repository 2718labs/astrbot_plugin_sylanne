<script setup lang="ts">
// Accessible dialog shell — teleported to body, focus-trapped, Esc + backdrop
// dismiss. Backs the Memory meltdown confirmation flow (nonce type-to-confirm
// + countdown), which is built INTO the memory page using this shell.
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { morphFromRect, prefersReducedObservationMotion } from '../monitor/observationChamberMotion'

export type ModalSize = 'sm' | 'md' | 'lg'

const props = withDefaults(
  defineProps<{
    open: boolean
    title?: string
    size?: ModalSize
    variant?: 'standard' | 'observation'
    originRect?: DOMRect | null
  }>(),
  { size: 'md', variant: 'standard' },
)

const emit = defineEmits<{
  'update:open': [value: boolean]
}>()

const dialogRef = ref<HTMLElement | null>(null)
const lastFocused = ref<HTMLElement | null>(null)
let motion: Animation | null = null
let settling = false
let opening = false

function close(): void {
  if (settling) return
  if (opening) {
    motion?.finished.then(() => { opening = false; close() }).catch(() => {})
    return
  }
  if (props.variant === 'observation' && props.originRect && dialogRef.value && !prefersReducedObservationMotion()) {
    const transform = morphFromRect(props.originRect, dialogRef.value.getBoundingClientRect())
    if (transform) {
      settling = true
      motion?.cancel()
      motion = dialogRef.value.animate([{ transform: 'none', opacity: 1 }, { transform: `translate(${transform.translateX}px, ${transform.translateY}px) scale(${transform.scaleX}, ${transform.scaleY})`, opacity: 0.75 }], { duration: 180, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'forwards' })
      motion.onfinish = () => { settling = false; if (dialogRef.value) dialogRef.value.style.visibility = 'hidden'; emit('update:open', false) }
      return
    }
  }
  emit('update:open', false)
}

function onBackdropClick(): void {
  close()
}

function onKeydown(e: KeyboardEvent): void {
  if (e.key === 'Escape') {
    e.stopPropagation()
    close()
    return
  }
  if (e.key === 'Tab') trapFocus(e)
}

function focusableEls(): HTMLElement[] {
  const root = dialogRef.value
  if (!root) return []
  const selector =
    'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
  return Array.from(root.querySelectorAll<HTMLElement>(selector)).filter(
    (el) => el.offsetParent !== null,
  )
}

function trapFocus(e: KeyboardEvent): void {
  const els = focusableEls()
  if (els.length === 0) return
  const first = els[0]
  const last = els[els.length - 1]
  const active = document.activeElement as HTMLElement | null

  if (e.shiftKey) {
    if (active === first || !root_contains(active)) {
      e.preventDefault()
      last.focus()
    }
  } else {
    if (active === last || !root_contains(active)) {
      e.preventDefault()
      first.focus()
    }
  }
}

function root_contains(el: HTMLElement | null): boolean {
  return !!(el && dialogRef.value && dialogRef.value.contains(el))
}

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      settling = false
      if (dialogRef.value) dialogRef.value.style.visibility = ''
      lastFocused.value = document.activeElement as HTMLElement | null
      nextTick(() => {
        const els = focusableEls()
        if (els.length > 0) els[0].focus()
        else dialogRef.value?.focus()
        if (props.variant === 'observation' && props.originRect && dialogRef.value && !prefersReducedObservationMotion()) {
          const transform = morphFromRect(props.originRect, dialogRef.value.getBoundingClientRect())
          if (transform) {
            motion?.cancel()
            opening = true
            motion = dialogRef.value.animate([{ transform: `translate(${transform.translateX}px, ${transform.translateY}px) scale(${transform.scaleX}, ${transform.scaleY})`, opacity: 0.75 }, { transform: 'none', opacity: 1 }], { duration: 220, easing: 'cubic-bezier(.2,.8,.2,1)' })
            motion.onfinish = () => { opening = false }
          }
        }
      })
    } else {
      motion?.cancel()
      settling = false
      opening = false
      if (lastFocused.value?.isConnected) lastFocused.value?.focus()
      lastFocused.value = null
    }
  },
)

onBeforeUnmount(() => {
  motion?.cancel()
  lastFocused.value = null
})

const sizeClass = computed(() => ['size-' + props.size, 'variant-' + props.variant])
</script>

<template>
  <Teleport to="body">
    <Transition name="modal-fade">
      <div v-if="open" class="modal-backdrop" :class="{ 'backdrop-observation': variant === 'observation' }" @mousedown.self="onBackdropClick">
        <div
          ref="dialogRef"
          class="modal-panel"
          :class="sizeClass"
          role="dialog"
          aria-modal="true"
          :aria-label="title"
          tabindex="-1"
          @keydown="onKeydown"
        >
          <div v-if="title || $slots.header" class="modal-head">
            <slot name="header">
              <span class="modal-title">{{ title }}</span>
            </slot>
            <button
              type="button"
              class="modal-close"
              aria-label="Close"
              @click="close"
            >
              &times;
            </button>
          </div>
          <div class="modal-body">
            <slot />
          </div>
          <div v-if="$slots.footer" class="modal-footer">
            <slot name="footer" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: grid;
  place-items: center;
  background: rgba(0, 0, 0, 0.55);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  padding: var(--space-8);
}

.modal-panel {
  width: 100%;
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: var(--r-lg);
  box-shadow: var(--shadow-toast), 0 0 32px rgba(var(--accent-rgb), 0.12);
  position: relative;
  overflow: hidden;
  max-height: calc(100vh - var(--space-10) * 2);
  display: flex;
  flex-direction: column;
}
.modal-panel::before {
  content: '';
  position: absolute;
  top: 0;
  left: var(--space-7);
  right: var(--space-7);
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--card-tick), transparent);
  opacity: 0.4;
}
.modal-panel:focus {
  outline: none;
}
.modal-panel.size-sm {
  max-width: 360px;
}
.modal-panel.size-md {
  max-width: 520px;
}
.modal-panel.size-lg {
  max-width: 760px;
}
.modal-panel.variant-observation { width: min(72vw, 1200px); min-width: min(1100px, calc(100vw - var(--space-10) * 2)); max-width: none; max-height: 76dvh; background: color-mix(in srgb, var(--bg) 96%, var(--accent)); }
.backdrop-observation { background: color-mix(in srgb, var(--bg) 28%, transparent); backdrop-filter: blur(2px); -webkit-backdrop-filter: blur(2px); }
@media (max-width: 620px) { .modal-panel.variant-observation { width: calc(100vw - var(--space-6) * 2); max-height: calc(100dvh - var(--space-6) * 2); } }

.modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  padding: var(--space-8) var(--space-8) var(--space-6);
  flex: none;
}
.modal-title {
  font-size: var(--font-lg);
  font-weight: 700;
  letter-spacing: 0.5px;
  color: var(--text);
}
.modal-close {
  background: transparent;
  border: none;
  color: var(--text-muted);
  font-size: var(--font-xl);
  line-height: 1;
  padding: var(--space-1) var(--space-3);
  border-radius: var(--r-sm);
  transition: color var(--dur-fast) var(--ease-snap), background var(--dur-fast) var(--ease-snap);
}
.modal-close:hover {
  color: var(--text);
  background: rgba(255, 255, 255, 0.06);
}
.modal-close:focus-visible {
  outline: none;
  box-shadow: var(--ring-focus);
}

.modal-body {
  padding: 0 var(--space-8) var(--space-8);
  overflow-y: auto;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-4);
  padding: var(--space-6) var(--space-8) var(--space-8);
  flex: none;
}

/* entrance/exit — fade + scale; collapses to opacity-only under reduced-motion
 * via the global @media rule in base.css, which forces transition-duration
 * to ~0 so no scale jump is perceptible. */
.modal-fade-enter-active,
.modal-fade-leave-active {
  transition: opacity var(--dur-mid) var(--ease-organic);
}
.modal-fade-enter-active .modal-panel,
.modal-fade-leave-active .modal-panel {
  transition: transform var(--dur-mid) var(--ease-organic), opacity var(--dur-mid) var(--ease-organic);
}
.modal-fade-enter-from,
.modal-fade-leave-to {
  opacity: 0;
}
.modal-fade-enter-from .modal-panel,
.modal-fade-leave-to .modal-panel {
  opacity: 0;
  transform: scale(0.96) translateY(8px);
}
</style>
