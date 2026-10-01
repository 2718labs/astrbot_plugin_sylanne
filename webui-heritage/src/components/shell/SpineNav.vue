<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from '../../composables/useI18n'
import { arrivalNodeDelay } from '../../motion/arrival'

// ── Center-seam spine rail — restored from the old fixed-spine paradigm
// (8655acd:UI/index.html ~164-242, ~3846-4013): a permanent floating rail on
// the viewport's vertical center seam with a draw-in line, evenly-spaced
// nodes, and a draggable handle with springy snap-to-node physics. Below
// 900px the rail docks as a compact left strip instead (floating center
// would sit on top of single-column content).
//
// This keeps real <router-link>-equivalent nav semantics (programmatic
// router.push + role="link"/aria-current) so it stays keyboard/a11y
// reachable, unlike the old version's plain divs.

const { t } = useI18n()
const route = useRoute()
const router = useRouter()

interface SpineNode {
  page: string
  key: string
  top: number
}

// 8 nodes evenly spaced on the 16%..79% band (9% step) — the arrival spec's
// node stop list, also used as the drag/keyboard step order.
const NODES: SpineNode[] = [
  { page: 'monitor', key: 'nav.monitor', top: 16 },
  { page: 'cognition', key: 'nav.cognition', top: 25 },
  { page: 'config', key: 'nav.config', top: 34 },
  { page: 'logs', key: 'nav.logs', top: 43 },
  { page: 'memory', key: 'nav.memory', top: 52 },
  { page: 'personality', key: 'nav.personality', top: 61 },
  { page: 'life', key: 'nav.life', top: 70 },
  { page: 'admin', key: 'nav.admin', top: 79 },
]
const TOPS = NODES.map((n) => n.top)
const MIN_TOP = TOPS[0]
const MAX_TOP = TOPS[TOPS.length - 1]
const PAGE_ORDER = NODES.map((n) => n.page)

const activeIndex = computed(() => {
  const name = typeof route.name === 'string' ? route.name : ''
  const idx = PAGE_ORDER.indexOf(name)
  return idx === -1 ? 0 : idx
})

// ── Handle position — starts synced to the active route, then tracks drag
// or animates (CSS transition on `top`) to whichever node navigation lands
// on. `handleTransition` is toggled off during 1:1 drag tracking so the
// handle follows the pointer with zero lag, then restored for the springy
// snap/settle legs.
const handleTop = ref(NODES[activeIndex.value]?.top ?? MIN_TOP)
const handleTransition = ref('top 0.3s cubic-bezier(0.4,0,0.2,1)')
const handleScale = ref(1)
const dragging = ref(false)
// Live-highlighted node index while dragging near a stop (nearestDist < 4%).
const dragHighlightIndex = ref(-1)

const railRef = ref<HTMLElement | null>(null)

// On any navigation (click, keyboard, router, or a settled drag) sync the
// handle to the active node's top% — unless a drag is actively in flight,
// which drives handleTop itself.
watch(activeIndex, (idx) => {
  if (dragging.value) return
  handleTransition.value = 'top 0.3s cubic-bezier(0.4,0,0.2,1)'
  handleTop.value = NODES[idx]?.top ?? MIN_TOP
})

function navigate(page: string): void {
  if (page === route.name) return
  void router.push({ name: page })
}

function onNodeClick(page: string): void {
  navigate(page)
}

// ── Drag physics (ported verbatim from initSpineHandle in UI/index.html) ──
let lastSnappedIdx = -1

function nearestStop(pct: number): { idx: number; dist: number } {
  let nearestDist = Infinity
  let nearestIdx = 0
  for (let i = 0; i < TOPS.length; i++) {
    const d = Math.abs(pct - TOPS[i])
    if (d < nearestDist) {
      nearestDist = d
      nearestIdx = i
    }
  }
  return { idx: nearestIdx, dist: nearestDist }
}

function startDrag(e: MouseEvent | TouchEvent): void {
  dragging.value = true
  lastSnappedIdx = activeIndex.value
  handleTransition.value = 'none'
  e.preventDefault()
}

function pointerY(e: MouseEvent | TouchEvent): number {
  return 'touches' in e ? e.touches[0]!.clientY : e.clientY
}

function moveDrag(e: MouseEvent | TouchEvent): void {
  if (!dragging.value || !railRef.value) return
  const rect = railRef.value.getBoundingClientRect()
  let pct = ((pointerY(e) - rect.top) / rect.height) * 100
  pct = Math.max(MIN_TOP, Math.min(MAX_TOP, pct))
  handleTop.value = pct

  const { idx: nearestIdx, dist: nearestDist } = nearestStop(pct)

  // 6% hysteresis: only release the lock once far enough from the last
  // snapped node, so borderline pointer jitter doesn't flicker between two
  // neighbors.
  if (lastSnappedIdx !== -1) {
    const distFromSnapped = Math.abs(pct - TOPS[lastSnappedIdx])
    if (distFromSnapped > 6) lastSnappedIdx = -1
  }

  dragHighlightIndex.value = nearestDist < 4 ? nearestIdx : -1

  if (nearestDist < 4) {
    handleScale.value = 1.15
    if (nearestIdx !== lastSnappedIdx) {
      handleTransition.value = 'top 0.25s cubic-bezier(0.2,0.8,0.3,1.0)'
      handleTop.value = TOPS[nearestIdx]!
      navigate(PAGE_ORDER[nearestIdx]!)
      lastSnappedIdx = nearestIdx
      window.setTimeout(() => {
        if (dragging.value) handleTransition.value = 'none'
      }, 260)
    }
  } else {
    handleScale.value = 1
    handleTransition.value = 'none'
  }
}

function endDrag(): void {
  if (!dragging.value) return
  dragging.value = false
  handleScale.value = 1
  dragHighlightIndex.value = -1

  const { idx: closestIdx } = nearestStop(handleTop.value)
  // Damped release: a touch slower/springier than the in-drag snap.
  handleTransition.value =
    'top 0.4s cubic-bezier(0.2,0.8,0.3,1.0), transform 0.2s ease'
  handleTop.value = TOPS[closestIdx]!

  if (closestIdx !== lastSnappedIdx) {
    navigate(PAGE_ORDER[closestIdx]!)
    lastSnappedIdx = closestIdx
  }
}

// ── Keyboard: ArrowUp/ArrowDown + W/S step through PAGE_ORDER, skipped
// while focus is in a form control or a modal is open.
function isModalOpen(): boolean {
  return !!document.querySelector('[role="dialog"][aria-modal="true"]')
}

function onKeydown(e: KeyboardEvent): void {
  const up = e.key === 'ArrowUp' || e.key === 'w' || e.key === 'W'
  const down = e.key === 'ArrowDown' || e.key === 's' || e.key === 'S'
  if (!up && !down) return
  const tag = (document.activeElement?.tagName || '').toUpperCase()
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
  if (isModalOpen()) return
  const idx = activeIndex.value
  if (up && idx > 0) navigate(PAGE_ORDER[idx - 1]!)
  if (down && idx < PAGE_ORDER.length - 1) navigate(PAGE_ORDER[idx + 1]!)
  e.preventDefault()
}

onMounted(async () => {
  await nextTick()
  handleTop.value = NODES[activeIndex.value]?.top ?? MIN_TOP
  window.addEventListener('mousemove', moveDrag)
  window.addEventListener('mouseup', endDrag)
  window.addEventListener('touchmove', moveDrag, { passive: false })
  window.addEventListener('touchend', endDrag)
  window.addEventListener('keydown', onKeydown)
})
onBeforeUnmount(() => {
  window.removeEventListener('mousemove', moveDrag)
  window.removeEventListener('mouseup', endDrag)
  window.removeEventListener('touchmove', moveDrag)
  window.removeEventListener('touchend', endDrag)
  window.removeEventListener('keydown', onKeydown)
})
</script>

<template>
  <nav ref="railRef" class="fixed-spine" aria-label="primary">
    <div class="spine-line" aria-hidden="true" />

    <button
      v-for="(n, i) in NODES"
      :key="n.page"
      type="button"
      class="spine-node"
      :class="{ active: i === activeIndex, 'drag-near': i === dragHighlightIndex }"
      :style="{
        top: n.top + '%',
        '--arrival-delay': arrivalNodeDelay(n.top) + 'ms',
      }"
      role="link"
      :aria-current="i === activeIndex ? 'page' : undefined"
      :aria-label="t(n.key)"
      :data-label="t(n.key)"
      @click="onNodeClick(n.page)"
    />

    <div
      class="spine-handle"
      :class="{ dragging }"
      :style="{
        top: handleTop + '%',
        transition: handleTransition,
        transform: `translate(-50%, -50%) scale(${handleScale})`,
        '--arrival-delay': arrivalNodeDelay(NODES[activeIndex]?.top ?? MIN_TOP) + 'ms',
      }"
      role="presentation"
      aria-hidden="true"
      @mousedown="startDrag"
      @touchstart="startDrag"
    />
  </nav>
</template>

<style scoped>
/* ═══ FIXED SPINE — floats on the viewport's vertical center seam at
 * ≥900px (ported 1:1 from .fixed-spine, UI/index.html ~164-183). Children
 * opt back into pointer events individually so the 40px-wide strip doesn't
 * eat clicks over the content it straddles. */
.fixed-spine {
  position: fixed;
  top: 0;
  bottom: 0;
  left: 50%;
  transform: translateX(-50%);
  width: 40px;
  z-index: 300;
  pointer-events: none;
}
.spine-line {
  position: absolute;
  top: 0;
  bottom: 0;
  left: 50%;
  width: 3px;
  transform: translateX(-50%);
  /* Pixel-anchored fades (not percentage stops) so the line reads as passing
   * UNDER the header/footer chrome rather than stabbing through it — it's
   * fully transparent for exactly --header-h / --footer-h, then fades in
   * over 48px into the visible band that spans the node area (16%..79%,
   * see NODES below). Percentage stops would drift relative to header/footer
   * height on differently-sized viewports; anchoring to the same --header-h/
   * --footer-h vars TopBar/AppFooter use keeps the seam exact. */
  background: linear-gradient(
    180deg,
    transparent 0,
    transparent var(--header-h),
    var(--accent) calc(var(--header-h) + 48px),
    var(--accent) calc(100% - var(--footer-h) - 48px),
    transparent calc(100% - var(--footer-h)),
    transparent 100%
  );
  /* Resting state is fully drawn-in; DashboardLayout's `.arrival-spine`
   * choreography overrides this via the spineDrawIn keyframe animating
   * clip-path from fully-clipped. */
  clip-path: inset(0 0 0% 0);
}
.spine-node {
  position: absolute;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 12px;
  height: 12px;
  padding: 0;
  border-radius: 50%;
  border: 2px solid var(--accent);
  background: var(--accent);
  opacity: 0.4;
  cursor: pointer;
  pointer-events: auto;
  transition: transform 0.3s ease, opacity 0.3s ease, box-shadow 0.3s ease;
}
.spine-node.active {
  opacity: 1;
  box-shadow: 0 0 10px rgba(var(--accent-rgb), 0.5);
}
.spine-node:hover,
.spine-node:focus-visible {
  opacity: 0.8;
  transform: translate(-50%, -50%) scale(1.5);
}
.spine-node.drag-near {
  opacity: 1;
  transform: translate(-50%, -50%) scale(1.8);
  box-shadow: 0 0 14px rgba(var(--accent-rgb), 0.7);
}
.spine-node:focus-visible {
  outline: none;
  box-shadow: var(--ring-focus);
}

/* Hover flyout label (CSS-only) — old data-label tooltip, same design
 * language as the rail itself. Also shows on :focus-visible for keyboard
 * users per the spec. */
.spine-node::after {
  content: attr(data-label);
  position: absolute;
  left: 22px;
  top: 50%;
  transform: translateY(-50%) translateX(-6px);
  font-family: var(--font-head);
  font-size: var(--font-xs);
  font-weight: 700;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--accent);
  white-space: nowrap;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.2s ease, transform 0.25s cubic-bezier(0.25, 1, 0.2, 1);
}
.spine-node:hover::after,
.spine-node:focus-visible::after {
  opacity: 1;
  transform: translateY(-50%) translateX(0);
}

/* ═══ DRAGGABLE HANDLE ═══ */
.spine-handle {
  position: absolute;
  left: 50%;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: var(--accent);
  cursor: grab;
  z-index: 2;
  pointer-events: auto;
  opacity: 0.45;
  box-shadow: 0 0 8px rgba(var(--accent-rgb), 0.3);
}
.spine-handle:hover {
  opacity: 0.9;
}
.spine-handle:hover,
.spine-handle.dragging {
  width: 26px;
  height: 26px;
  box-shadow: 0 0 14px rgba(var(--accent-rgb), 0.6), 0 0 28px rgba(var(--accent-rgb), 0.25);
  cursor: grabbing;
}

/* ═══ <900px: dock as a compact LEFT fixed strip ═══
 * The floating center seam would sit on top of the single-column content
 * below 900px, so the rail relocates to the left edge instead — same line/
 * node/handle chrome, just repositioned; no flyout-blocking since labels
 * still open rightward into free space. */
@media (max-width: 899px) {
  .fixed-spine {
    left: 24px;
    transform: none;
    width: 32px;
  }
}
</style>
