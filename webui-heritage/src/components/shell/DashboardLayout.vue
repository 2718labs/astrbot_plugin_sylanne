<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { RouterView, useRoute } from 'vue-router'
import SpineNav from './SpineNav.vue'
import TopBar from './TopBar.vue'
import AppFooter from './AppFooter.vue'
import { useLiveStore } from '../../stores/live'
import { useBoot } from '../../composables/useBoot'
import { useI18n } from '../../composables/useI18n'
import { useInteractionFeedback } from '../../composables/useInteractionFeedback'
import {
  ARRIVAL_CLEANUP_MS,
  ARRIVAL_CONTENT_MS,
  prefersReducedMotion,
} from '../../motion/arrival'

// The shell owns the shared /api/state poll for its whole lifetime, so every
// dashboard page just reads useLiveStore().state.
const live = useLiveStore()
const { t } = useI18n()
const feedback = useInteractionFeedback()
onMounted(() => live.start(5000))
onUnmounted(() => live.stop())
watch(
  () => live.error,
  (current, previous) => {
    if (previous && !current) {
      feedback.show(t('feedback.connection_restored'), 'success')
    }
  },
)

// ── Spine-first arrival choreography. A synchronous watcher applies the
// hidden spine phase before the shell's first render, then advances all
// content surfaces together only after the line has completed.
const boot = useBoot()
type ArrivalPhase = 'idle' | 'spine' | 'content'
const arrivalPhase = ref<ArrivalPhase>('idle')
let contentTimer: ReturnType<typeof setTimeout> | null = null
let cleanupTimer: ReturnType<typeof setTimeout> | null = null

function clearArrivalTimers(): void {
  if (contentTimer !== null) clearTimeout(contentTimer)
  if (cleanupTimer !== null) clearTimeout(cleanupTimer)
  contentTimer = null
  cleanupTimer = null
}

// Reactive consume instead of a one-shot mount check: on a welcome-back boot
// this layout mounts (under the boot cover) BEFORE the async verifyExisting()
// resolves and requests the arrival — a mount-time consume would race it and
// the entrance would never play. The watcher covers both orders: flag already
// set at mount (fresh login set it before router.replace) fires via
// immediate; flag set later (boot verify) fires when it flips.
watch(
  () => boot.arrivalPending.value,
  (pending) => {
    if (!pending || !boot.consumeArrival()) return
    clearArrivalTimers()
    if (prefersReducedMotion()) {
      arrivalPhase.value = 'idle'
      return
    }

    arrivalPhase.value = 'spine'
    contentTimer = setTimeout(() => {
      arrivalPhase.value = 'content'
      contentTimer = null
    }, ARRIVAL_CONTENT_MS)
    cleanupTimer = setTimeout(() => {
      arrivalPhase.value = 'idle'
      cleanupTimer = null
    }, ARRIVAL_CLEANUP_MS)
  },
  { immediate: true, flush: 'sync' },
)
onUnmounted(clearArrivalTimers)

// ── Directional page-switch (old .content-slider filmstrip, UI/index.html
// ~285-289): navigating down the nav list slides the outgoing page up and
// brings the new one in from below; navigating up does the inverse.
const NAV_ORDER = ['monitor', 'cognition', 'config', 'logs', 'memory', 'personality', 'life', 'admin']
const route = useRoute()
const routeKey = computed(() => (typeof route.name === 'string' ? route.name : String(route.name ?? '')))

const transitionName = ref('page-down')
// `flush: 'pre'` (the default) runs this before the component re-renders, so
// transitionName is already correct by the time <Transition> reads it for
// the upcoming leave/enter pair.
watch(
  () => routeKey.value,
  (next, prev) => {
    const nextIndex = NAV_ORDER.indexOf(next)
    const prevIndex = NAV_ORDER.indexOf(prev ?? '')
    transitionName.value = nextIndex < prevIndex ? 'page-up' : 'page-down'
  },
)
</script>

<template>
  <div
    class="layout"
    :class="{
      'arrival-spine': arrivalPhase === 'spine',
      'arrival-content': arrivalPhase === 'content',
    }"
  >
    <SpineNav class="area-nav" />
    <TopBar class="area-top" />
    <main class="area-content">
      <RouterView v-slot="{ Component }">
        <!-- Explicit :duration: completion runs on a JS timer instead of
             waiting for transitionend — in a compositor-less environment
             (headless embed, hidden webview) that event may never fire and
             mode="out-in" would strand the leave phase, leaving navigation
             permanently stuck on the outgoing page. -->
        <Transition :name="transitionName" mode="out-in" :duration="350">
          <component :is="Component" :key="routeKey" />
        </Transition>
      </RouterView>
    </main>
    <AppFooter class="area-foot" />
  </div>
</template>

<style scoped>
/* ≥900px: SpineNav is a fixed-position floating rail on the viewport's
 * center seam (see SpineNav.vue) — it does not occupy a grid track, so the
 * content spans full width and floats over it. The content area itself is a
 * fixed-height stage (no page-level scroll) — each routed view renders a
 * .page-split (styles/base.css) whose two .pane-left/.pane-right panes each
 * scroll independently and dissolve at top/bottom via mask-image, exactly
 * like the old .page-section/.page-left/.page-right anatomy table. Below
 * 900px SpineNav docks as a left strip instead, so the grid gets a matching
 * dedicated nav column there, and .page-split collapses to a normal-flow
 * single column (see base.css). */
.layout {
  display: grid;
  grid-template-columns: 1fr;
  grid-template-rows: var(--header-h) minmax(0, 1fr) var(--footer-h);
  height: 100vh;
}
/* SpineNav itself is position:fixed (see SpineNav.vue) so it never actually
 * occupies a grid track — .area-nav is just a class hook for the :deep()
 * arrival-choreography selectors below. */
.area-top {
  grid-column: 1;
  grid-row: 1;
}
.area-top,
.area-content,
.area-foot {
  min-width: 0;
}
.area-content {
  grid-column: 1;
  grid-row: 2;
  overflow: hidden;
  /* faint instrument ambiance so the field isn't a dead-flat --bg */
  background:
    radial-gradient(ellipse 120% 70% at 50% -10%, rgba(184, 138, 158, 0.04), transparent 55%),
    radial-gradient(ellipse 90% 60% at 50% 120%, rgba(0, 0, 0, 0.25), transparent 60%);
}
.area-foot {
  grid-column: 1;
  grid-row: 3;
}

@media (max-width: 899px) {
  .layout {
    grid-template-columns: 56px minmax(0, 1fr);
  }
  .area-top,
  .area-content,
  .area-foot {
    grid-column: 2;
  }
  /* Below 900px .page-split is normal-flow (base.css), so the stage itself
   * must scroll again instead of clipping it. */
  .area-content {
    overflow-y: auto;
    padding: var(--space-8);
  }
}

@media (max-width: 620px) {
  .area-content {
    padding: var(--space-3);
  }
}

/* ── Directional page-switch: a lighter-weight echo of the old vertical
 * filmstrip (.content-slider, 0.6s) — GPU-friendly transform/opacity only,
 * two ~.35s legs instead of one .6s slide since out-in runs them in series. */
.page-down-enter-active,
.page-down-leave-active,
.page-up-enter-active,
.page-up-leave-active {
  transition: transform 0.35s var(--ease-organic), opacity 0.35s var(--ease-organic);
}
.page-down-leave-to {
  transform: translateY(-20px);
  opacity: 0;
}
.page-down-enter-from {
  transform: translateY(20px);
  opacity: 0;
}
.page-up-leave-to {
  transform: translateY(20px);
  opacity: 0;
}
.page-up-enter-from {
  transform: translateY(-20px);
  opacity: 0;
}

/* ── Arrival choreography: the first 1200ms show only the growing spine and
 * its line-synchronised nodes. Shell chrome and the routed content subtree
 * are hidden before the first paint, then all surfaces enter together. */
.arrival-spine .area-top,
.arrival-spine .area-foot,
.arrival-spine .area-content > :deep(*) {
  opacity: 0;
  visibility: hidden;
  pointer-events: none;
}
.arrival-spine .area-nav :deep(.spine-line) {
  animation: spineDrawIn 1200ms linear both;
}
.arrival-spine .area-nav :deep(.spine-node),
.arrival-spine .area-nav :deep(.spine-handle) {
  animation: spineNodeIn 250ms var(--ease-organic) var(--arrival-delay) backwards;
}
.arrival-content .area-top {
  animation: shellDropIn 600ms var(--ease-snap) both;
}
.arrival-content .area-foot {
  animation: shellRiseIn 600ms var(--ease-snap) both;
}
.arrival-content .area-content :deep(.pane-left .card),
.arrival-content .area-content :deep(.pane-right .card) {
  animation-duration: 600ms;
  animation-timing-function: var(--ease-snap);
  animation-fill-mode: both;
}
.arrival-content .area-content :deep(.pane-left .card) {
  animation-name: cardFromLeft;
}
.arrival-content .area-content :deep(.pane-right .card) {
  animation-name: cardFromRight;
}

@keyframes shellDropIn {
  from {
    transform: translateY(-100%);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}
@keyframes shellRiseIn {
  from {
    transform: translateY(100%);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}
@keyframes spineDrawIn {
  from {
    clip-path: inset(0 0 100% 0);
  }
  to {
    clip-path: inset(0 0 0 0);
  }
}
@keyframes spineNodeIn {
  from {
    opacity: 0;
  }
}
@keyframes cardFromLeft {
  from {
    opacity: 0;
    transform: translateX(40px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}
@keyframes cardFromRight {
  from {
    opacity: 0;
    transform: translateX(-40px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}
</style>
