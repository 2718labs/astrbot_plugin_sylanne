<script setup lang="ts">
import { computed } from 'vue'

export interface RadarAxis {
  label: string
  value: number
}

const props = withDefaults(
  defineProps<{
    axes: RadarAxis[]
    max?: number
  }>(),
  { max: 1 },
)

// Viewbox is a fixed square; everything below is derived from this so the
// component is trivially re-scalable via CSS width/height on the host.
const SIZE = 320
const CENTER = SIZE / 2
const RADIUS = SIZE * 0.36
const RINGS = 4

const axisCount = computed(() => Math.max(3, Math.min(8, props.axes.length)))

// angle 0 is straight up, then clockwise — matches how a radar/spider chart
// reads visually (first axis at 12 o'clock).
function angleFor(i: number): number {
  return (Math.PI * 2 * i) / axisCount.value - Math.PI / 2
}

function pointFor(i: number, r: number): { x: number; y: number } {
  const a = angleFor(i)
  return { x: CENTER + r * Math.cos(a), y: CENTER + r * Math.sin(a) }
}

// concentric grid rings (faint webbing)
const rings = computed(() =>
  Array.from({ length: RINGS }, (_, ringIdx) => {
    const r = (RADIUS * (ringIdx + 1)) / RINGS
    const pts = Array.from({ length: axisCount.value }, (_, i) => pointFor(i, r))
    return pts.map((p) => `${p.x},${p.y}`).join(' ')
  }),
)

// spokes from center to each axis tip
const spokes = computed(() =>
  Array.from({ length: axisCount.value }, (_, i) => pointFor(i, RADIUS)),
)

// axis label anchors, pushed slightly beyond the outer ring
const labelPoints = computed(() =>
  props.axes.slice(0, axisCount.value).map((axis, i) => {
    const p = pointFor(i, RADIUS * 1.22)
    const a = angleFor(i)
    // simple anchor heuristic: near-vertical spokes center the label,
    // left-leaning spokes end-anchor, right-leaning ones start-anchor
    const cos = Math.cos(a)
    let anchor: 'start' | 'middle' | 'end' = 'middle'
    if (cos > 0.3) anchor = 'start'
    else if (cos < -0.3) anchor = 'end'
    return { ...p, label: axis.label, anchor }
  }),
)

// the data polygon itself, clamped to [0, max]
const dataPolygon = computed(() => {
  const m = props.max || 1
  const pts = props.axes.slice(0, axisCount.value).map((axis, i) => {
    const ratio = Math.max(0, Math.min(1, axis.value / m))
    return pointFor(i, RADIUS * ratio)
  })
  return pts.map((p) => `${p.x},${p.y}`).join(' ')
})

const dataDots = computed(() => {
  const m = props.max || 1
  return props.axes.slice(0, axisCount.value).map((axis, i) => {
    const ratio = Math.max(0, Math.min(1, axis.value / m))
    return pointFor(i, RADIUS * ratio)
  })
})
</script>

<template>
  <div class="radar-chart">
    <svg :viewBox="`0 0 ${SIZE} ${SIZE}`" class="radar-svg" role="img" aria-label="radar chart">
      <!-- grid rings -->
      <polygon
        v-for="(ring, i) in rings"
        :key="'ring-' + i"
        :points="ring"
        class="radar-ring"
      />
      <!-- spokes -->
      <line
        v-for="(p, i) in spokes"
        :key="'spoke-' + i"
        :x1="CENTER"
        :y1="CENTER"
        :x2="p.x"
        :y2="p.y"
        class="radar-spoke"
      />
      <!-- data polygon -->
      <polygon :points="dataPolygon" class="radar-fill" />
      <polygon :points="dataPolygon" class="radar-stroke" />
      <!-- data node dots -->
      <circle
        v-for="(p, i) in dataDots"
        :key="'dot-' + i"
        :cx="p.x"
        :cy="p.y"
        r="3.2"
        class="radar-dot"
      />
      <!-- axis labels -->
      <text
        v-for="(lp, i) in labelPoints"
        :key="'label-' + i"
        :x="lp.x"
        :y="lp.y"
        :text-anchor="lp.anchor"
        class="radar-label mono"
        dominant-baseline="middle"
      >
        {{ lp.label }}
      </text>
    </svg>
  </div>
</template>

<style scoped>
.radar-chart {
  width: 100%;
  display: flex;
  justify-content: center;
}
.radar-svg {
  width: 100%;
  max-width: 380px;
  height: auto;
  overflow: visible;
}
.radar-ring {
  fill: none;
  stroke: var(--card-border);
  stroke-width: 1;
}
.radar-spoke {
  stroke: var(--card-border);
  stroke-width: 1;
}
.radar-fill {
  fill: rgba(var(--accent-rgb), 0.18);
  stroke: none;
}
.radar-stroke {
  fill: none;
  stroke: var(--accent);
  stroke-width: 2;
  stroke-linejoin: round;
  filter: drop-shadow(0 0 6px rgba(var(--accent-rgb), 0.65));
}
.radar-dot {
  fill: var(--accent);
  filter: drop-shadow(0 0 4px rgba(var(--accent-rgb), 0.8));
}
.radar-label {
  font-size: var(--font-xs);
  fill: var(--text-muted);
  letter-spacing: 0.5px;
  text-transform: uppercase;
}
</style>
