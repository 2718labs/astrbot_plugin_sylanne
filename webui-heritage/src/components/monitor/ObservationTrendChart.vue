<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { buildTrendSeries, type NormalizedBucket } from '../../views/monitorObservation'

const props = defineProps<{ buckets: NormalizedBucket[]; label: string }>()
const canvas = ref<HTMLCanvasElement | null>(null)
const host = ref<HTMLElement | null>(null)
const plot = ref<HTMLElement | null>(null)
let observer: ResizeObserver | null = null
let frame = 0
const series = computed(() => buildTrendSeries(props.buckets))
const summary = computed(() => series.value.map(s => { const point = s.points.at(-1); return `${s.key}: ${point?.last ?? point?.first ?? '—'} at ${point?.toTimestamp ?? '—'}` }).join(', '))

function draw(): void {
  frame = 0
  const element = canvas.value; const container = plot.value
  if (!element || !container || !series.value.length) return
  const rect = container.getBoundingClientRect(); if (!rect.width || !rect.height) return
  const ratio = window.devicePixelRatio || 1; element.width = Math.round(rect.width * ratio); element.height = Math.round(rect.height * ratio)
  element.style.width = `${rect.width}px`; element.style.height = `${rect.height}px`
  const ctx = element.getContext('2d'); if (!ctx) return
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0); ctx.clearRect(0, 0, rect.width, rect.height)
  const points = series.value.flatMap(item => item.points); const values = points.flatMap(point => [point.first, point.last, point.min, point.max]).filter((value): value is number => Number.isFinite(value))
  if (!values.length) return
  const times = points.flatMap(point => [point.fromTimestamp, point.toTimestamp]); const lo = Math.min(...values); const hi = Math.max(...values); const start = Math.min(...times); const end = Math.max(...times)
  const pad = 12; const width = Math.max(1, rect.width - pad * 2); const height = Math.max(1, rect.height - pad * 2)
  const x = (value: number) => pad + (end === start ? width / 2 : ((value - start) / (end - start)) * width)
  const y = (value: number) => pad + (hi === lo ? height / 2 : (1 - (value - lo) / (hi - lo)) * height)
  ctx.strokeStyle = 'rgba(184, 138, 158, .18)'; ctx.lineWidth = 1
  for (let i = 1; i < 4; i += 1) { const gy = pad + (height * i) / 4; ctx.beginPath(); ctx.moveTo(pad, gy); ctx.lineTo(pad + width, gy); ctx.stroke() }
  const colors = ['rgba(184, 138, 158, .85)', 'rgba(121, 165, 160, .85)', 'rgba(183, 153, 104, .85)', 'rgba(142, 132, 184, .85)']
  const drawWhiskers = (item: typeof series.value[number], color: string): void => { ctx.strokeStyle = color; ctx.lineWidth = 1; ctx.beginPath(); item.points.forEach(point => { if (point.min !== undefined && point.max !== undefined) { const px = x(point.toTimestamp); ctx.moveTo(px, y(point.min)); ctx.lineTo(px, y(point.max)) } }); ctx.stroke() }
  series.value.forEach((item, seriesIndex) => { const color = colors[seriesIndex % colors.length]; ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.beginPath(); let drawn = false; item.points.forEach(point => { if (point.first !== undefined) { const px = x(point.fromTimestamp); const py = y(point.first); if (drawn) ctx.lineTo(px, py); else { ctx.moveTo(px, py); drawn = true } }; if (point.last !== undefined) { const px = x(point.toTimestamp); const py = y(point.last); if (drawn) ctx.lineTo(px, py); else { ctx.moveTo(px, py); drawn = true } } }); ctx.stroke(); drawWhiskers(item, color) })
}
function schedule(): void { if (!frame) frame = requestAnimationFrame(draw) }
onMounted(() => { observer = new ResizeObserver(schedule); if (host.value) observer.observe(host.value); nextTick(schedule) })
watch(series, () => nextTick(schedule), { deep: true })
onBeforeUnmount(() => { observer?.disconnect(); if (frame) cancelAnimationFrame(frame) })
</script>

<template>
  <div ref="host" class="trend-chart">
    <div ref="plot" class="plot"><canvas v-if="series.length" ref="canvas" role="img" :aria-label="`${label}: ${summary}`" /></div>
    <span class="sr-only">{{ summary }}</span>
    <div class="legend" aria-hidden="true">{{ series.map(item => item.key).join(' · ') }}</div>
  </div>
</template>

<style scoped>
.trend-chart { height: 180px; width: 100%; display: grid; grid-template-rows: minmax(0, 1fr) auto; background: color-mix(in srgb, var(--card) 86%, var(--accent)); border-radius: var(--r-md); overflow: hidden; }
.plot { min-height: 0; }
.trend-chart canvas { display: block; }
.legend { padding: 0 var(--space-4) var(--space-3); color: var(--text-muted); font-size: var(--font-xs); }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; }
</style>
