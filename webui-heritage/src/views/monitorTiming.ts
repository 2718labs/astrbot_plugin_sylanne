import type {
  SpineLayer,
  StateResponse,
  TimingEntry,
  TimingLayer,
} from '../api/types'

export interface TimingRow {
  layer: string
  avg: string
  p95: string
  count: string
}

const LAYER_ORDER = ['L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7'] as const
const INTERNAL_LAYER_IDS: Record<string, (typeof LAYER_ORDER)[number]> = {
  perception: 'L1',
  gate: 'L2',
  void_scar: 'L3',
  sheaf: 'L4',
  hgt: 'L5',
  boundary: 'L6',
  expression: 'L7',
}

function layerId(raw: unknown): (typeof LAYER_ORDER)[number] | undefined {
  const value = String(raw ?? '').trim()
  const internal = INTERNAL_LAYER_IDS[value.toLowerCase()]
  if (internal) return internal
  const match = value.toUpperCase().match(/^L([1-7])(?:_|$)/)
  return match ? (`L${match[1]}` as (typeof LAYER_ORDER)[number]) : undefined
}

function numberValue(raw: unknown): number | undefined {
  if (raw === null || raw === undefined || raw === '') return undefined
  const value = typeof raw === 'string' ? Number.parseFloat(raw) : Number(raw)
  return Number.isFinite(value) ? value : undefined
}

function fmtMs(raw: unknown): string {
  const value = numberValue(raw)
  if (value === undefined) return '—'
  if (value !== 0 && Math.abs(value) < 0.1) {
    return `${(value * 1000).toFixed(1)}µs`
  }
  return `${value.toFixed(1)}ms`
}

function fmtCount(raw: unknown): string {
  const value = numberValue(raw)
  return value === undefined ? '—' : String(value)
}

function rowFromSpineLayer(id: string, layer: SpineLayer): TimingRow {
  return {
    layer: id,
    avg: fmtMs(layer.avg),
    p95: fmtMs(layer.p95 ?? layer.p99),
    count: fmtCount(layer.count),
  }
}

function canonicalRows(state: StateResponse): TimingRow[] {
  if (!Array.isArray(state.spine_layers) || state.spine_layers.length === 0) return []
  const byId = new Map<string, SpineLayer>()
  for (const layer of state.spine_layers) {
    const id = layerId(layer.id)
    if (id) byId.set(id, layer)
  }
  return LAYER_ORDER.flatMap((id) => {
    const layer = byId.get(id)
    return layer ? [rowFromSpineLayer(id, layer)] : []
  })
}

function layerRows(layers: Record<string, TimingLayer> | undefined): TimingRow[] {
  if (!layers) return []
  const byId = new Map<string, TimingLayer>()
  for (const [key, layer] of Object.entries(layers)) {
    const id = layerId(key)
    if (!id) continue
    const hasTiming = (
      layer.avg !== undefined
      || layer.avg_ms !== undefined
      || layer.p95 !== undefined
      || layer.p95_ms !== undefined
      || layer.count !== undefined
    )
    if (!hasTiming) continue
    if (!byId.has(id) || key.toUpperCase() === id) byId.set(id, layer)
  }
  return LAYER_ORDER.flatMap((id) => {
    const layer = byId.get(id)
    if (!layer) return []
    return [{
      layer: id,
      avg: fmtMs(layer.avg ?? layer.avg_ms),
      p95: fmtMs(layer.p95 ?? layer.p95_ms),
      count: fmtCount(layer.count),
    }]
  })
}

function timingArrayRows(timing: TimingEntry[]): TimingRow[] {
  const byId = new Map<string, TimingEntry>()
  for (const entry of timing) {
    const id = layerId(entry.layer)
    if (id) byId.set(id, entry)
  }
  return LAYER_ORDER.flatMap((id) => {
    const entry = byId.get(id)
    if (!entry) return []
    return [{
      layer: id,
      avg: fmtMs(entry.avg),
      p95: fmtMs(entry.p95 ?? entry.p99),
      count: fmtCount(entry.count),
    }]
  })
}

function timingObjectRows(timing: Record<string, number>): TimingRow[] {
  return LAYER_ORDER.flatMap((id) => {
    const internal = Object.entries(INTERNAL_LAYER_IDS)
      .find(([, layer]) => layer === id)?.[0]
    const value = timing[`${id}_ms`] ?? (internal ? timing[`${internal}_ms`] : undefined)
    return numberValue(value) === undefined
      ? []
      : [{ layer: id, avg: fmtMs(value), p95: '—', count: '—' }]
  })
}

export function buildTimingRows(state: StateResponse | null | undefined): TimingRow[] {
  if (!state) return []
  const canonical = canonicalRows(state)
  if (canonical.length) return canonical

  const layers = layerRows(state.layers)
  if (layers.length) return layers

  if (Array.isArray(state.timing)) return timingArrayRows(state.timing)
  return state.timing ? timingObjectRows(state.timing) : []
}
