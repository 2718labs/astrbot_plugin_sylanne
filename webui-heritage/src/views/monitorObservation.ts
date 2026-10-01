import type { ObservationHistoryPoint, ObservationHistoryStorage, StateResponse } from '../api/types'
import { buildTimingRows } from './monitorTiming'

export const OBSERVATION_GROUPS = ['emotion', 'boundary', 'timing', 'routing', 'gate', 'expression', 'feedback'] as const
export type ObservationGroup = (typeof OBSERVATION_GROUPS)[number]

export interface Reading { key: string; value: number | string; discrete?: boolean }
export interface NormalizedBucket { fromMs: number; toMs: number; metrics: Record<string, { first?: number; last?: number; min?: number; max?: number }> }

export function adaptObservationStorage(
  storage: Partial<ObservationHistoryStorage> | null | undefined,
): ObservationHistoryStorage {
  return {
    used_bytes: storage?.used_bytes ?? 0,
    limit_bytes: storage?.limit_bytes ?? null,
    oldest_ms: storage?.oldest_ms ?? null,
    segment_count: storage?.segment_count ?? 0,
    cleanup_active: storage?.cleanup_active === true,
    budget_unsatisfiable: storage?.budget_unsatisfiable === true,
  }
}

export interface ObservationCapacityLabels {
  unlimited: string
  cleanupActive: string
  cleanupIdle: string
  protectedWarning: string
}

export interface ObservationCapacityModel {
  used: string
  limit: string
  cleanup: string
  warning: string
}

export function observationCapacityModel(
  input: Partial<ObservationHistoryStorage> | null | undefined,
  labels: ObservationCapacityLabels,
): ObservationCapacityModel {
  const storage = adaptObservationStorage(input)
  return {
    used: formatObservationBytes(storage.used_bytes),
    limit:
      storage.limit_bytes === null || storage.limit_bytes === 0
        ? labels.unlimited
        : formatObservationBytes(storage.limit_bytes),
    cleanup: storage.cleanup_active ? labels.cleanupActive : labels.cleanupIdle,
    warning: storage.budget_unsatisfiable ? labels.protectedWarning : '',
  }
}

export function normalizedMeterPercent(reading: Reading): number | undefined {
  if (reading.discrete || typeof reading.value !== 'number' || reading.value < 0 || reading.value > 1) return undefined
  return reading.value * 100
}

const number = (value: unknown): number | undefined => typeof value === 'number' && Number.isFinite(value) ? value : undefined
const pick = (source: Record<string, unknown> | undefined, keys: string[]): number | undefined => {
  for (const key of keys) { const value = number(source?.[key]); if (value !== undefined) return value }
  return undefined
}
const readings = (source: Record<string, unknown> | undefined, entries: Array<[string, string[]]>): Reading[] => entries.flatMap(([key, aliases]) => {
  const value = pick(source, aliases)
  return value === undefined ? [] : [{ key, value }]
})

export function buildCurrentReadings(state: StateResponse, group: ObservationGroup): Reading[] {
  if (group === 'emotion') return readings(state.emotion, [['warmth', ['warmth']], ['arousal', ['arousal']], ['valence', ['valence']], ['tension', ['tension']], ['curiosity', ['curiosity']], ['repair_pressure', ['repair_pressure']], ['expression_drive', ['expression_drive']], ['boundary_firmness', ['boundary_firmness']]])
  if (group === 'boundary') return readings(state.boundary, [['integrity', ['integrity']], ['entropy', ['entropy']], ['rotation', ['rotation', 'stability']], ['repair_rate', ['repair_rate', 'stability']]])
  if (group === 'timing') return buildTimingRows(state).map(row => ({ key: row.layer, value: row.avg }))
  if (group === 'routing') return readings(state.route_distribution || state.route_stats, Object.keys(state.route_distribution || state.route_stats || {}).map(key => [key.toUpperCase(), [key]]))
  if (group === 'gate') return readings(state.gate, [['surprise', ['surprise', 'mean_surprise']], ['threshold', ['threshold']]]).concat(state.gate?.route ? [{ key: 'route', value: state.gate.route, discrete: true }] : [])
  if (group === 'expression') return readings(state.expression, [['drive', ['pressure', 'drive']], ['threshold', ['threshold']]]).concat(state.expression?.mode ? [{ key: 'mode', value: state.expression.mode.toUpperCase(), discrete: true }] : [])
  return readings(state.feedback, [['positive', ['positive', 'accepted']], ['negative', ['negative', 'rejected']], ['neutral', ['neutral', 'ignored']]])
}

export function normalizeHistoryBuckets(points: ObservationHistoryPoint[]): NormalizedBucket[] {
  return points.map((point, index) => {
    const metrics: NormalizedBucket['metrics'] = {}
    for (const key of new Set([...Object.keys(point.first || {}), ...Object.keys(point.last || {}), ...Object.keys(point.min || {}), ...Object.keys(point.max || {})])) {
      const metric = { first: number(point.first?.[key]), last: number(point.last?.[key]), min: number(point.min?.[key]), max: number(point.max?.[key]) }
      if (Object.values(metric).some(v => v !== undefined)) metrics[key] = metric
    }
    return { fromMs: Number.isFinite(point.from_ms) ? point.from_ms : 0, toMs: Number.isFinite(point.to_ms) ? point.to_ms : 0, metrics, index }
  }).sort((a, b) => a.toMs - b.toMs || a.fromMs - b.fromMs || a.index - b.index).map(({ index: _index, ...bucket }) => bucket)
}

export function buildTrendSeries(buckets: NormalizedBucket[]): Array<{ key: string; points: Array<{ fromTimestamp: number; toTimestamp: number; first?: number; last?: number; min?: number; max?: number }> }> {
  const series = new Map<string, Array<{ fromTimestamp: number; toTimestamp: number; first?: number; last?: number; min?: number; max?: number }>>()
  for (const bucket of buckets) for (const [key, metric] of Object.entries(bucket.metrics)) if (metric.first !== undefined || metric.last !== undefined || metric.min !== undefined || metric.max !== undefined) {
    const points = series.get(key) || []
    const next = { fromTimestamp: bucket.fromMs, toTimestamp: bucket.toMs, first: metric.first, last: metric.last, min: metric.min, max: metric.max }
    const existing = points.findIndex(point => point.fromTimestamp === next.fromTimestamp && point.toTimestamp === next.toTimestamp)
    if (existing >= 0) points[existing] = next
    else points.push(next)
    series.set(key, points)
  }
  return [...series].map(([key, points]) => ({ key, points }))
}

export function resolveHistoryState(input: { loading: boolean; history: { points: unknown[]; partial: boolean } | null; error: string }): 'loading' | 'empty' | 'partial' | 'error' | 'ready' {
  if (input.history?.partial) return 'partial'
  if (input.loading) return 'loading'
  if (input.error && !input.history) return 'error'
  if (!input.history || input.history.points.length === 0) return 'empty'
  return 'ready'
}

export function createObservationRequestGuard() { let generation = 0; let key = ''
  return { begin(session: string, group: ObservationGroup) { generation += 1; key = `${session}:${group}`; return generation }, isCurrent(token: number, session: string, group: ObservationGroup) { return token === generation && key === `${session}:${group}` }, invalidate() { generation += 1; key = '' } }
}

export function formatObservationBytes(value: number | null | undefined): string {
  const bytes = Number.isFinite(value) ? Number(value) : 0
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MiB` : bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KiB` : `${bytes} B`
}
export function formatObservationOldest(value: number | null | undefined, empty: string): string {
  return value == null ? empty : new Date(value).toLocaleString()
}
