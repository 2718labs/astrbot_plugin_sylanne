import { describe, expect, it } from 'vitest'
import type {
  ObservationHistoryPoint,
  StateResponse,
} from '../api/types'
import {
  adaptObservationStorage,
  OBSERVATION_GROUPS,
  buildCurrentReadings,
  buildTrendSeries,
  createObservationRequestGuard,
  formatObservationBytes,
  formatObservationOldest,
  normalizeHistoryBuckets,
  normalizedMeterPercent,
  resolveHistoryState,
} from './monitorObservation'

describe('monitor observation adapters', () => {
  it('only gives normalized continuous readings a meter fill', () => {
    expect(normalizedMeterPercent({ key: 'warmth', value: 0.42 })).toBe(42)
    expect(normalizedMeterPercent({ key: 'warmth', value: 0 })).toBe(0)
    expect(normalizedMeterPercent({ key: 'count', value: 12 })).toBeUndefined()
    expect(normalizedMeterPercent({ key: 'route', value: 'dialogue', discrete: true })).toBeUndefined()
  })

  it('maps all seven cards and preserves legacy aliases', () => {
    expect(OBSERVATION_GROUPS).toEqual([
      'emotion',
      'boundary',
      'timing',
      'routing',
      'gate',
      'expression',
      'feedback',
    ])

    const state: StateResponse = {
      emotion: { warmth: 0.25, arousal: .1, valence: -.2, tension: .3, curiosity: .4, repair_pressure: .5, expression_drive: .6, boundary_firmness: .7 },
      boundary: { stability: 0.75 },
      timing: { L1_ms: 4.5 },
      route_stats: { resonance: 3, skip: 1 },
      gate: { mean_surprise: 0.42, threshold: 0.5, route: 'RESONANCE' },
      expression: { drive: 0.33, threshold: 0.6, mode: 'silent' },
      feedback: { accepted: 4, rejected: 2, ignored: 1 },
    }

    expect(buildCurrentReadings(state, 'emotion').map(reading => reading.key)).toEqual(['warmth', 'arousal', 'valence', 'tension', 'curiosity', 'repair_pressure', 'expression_drive', 'boundary_firmness'])
    expect(buildCurrentReadings(state, 'boundary')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: 'rotation', value: 0.75 }),
        expect.objectContaining({ key: 'repair_rate', value: 0.75 }),
      ]),
    )
    expect(buildCurrentReadings(state, 'timing')).toEqual([{ key: 'L1', value: '4.5ms' }])
    expect(buildCurrentReadings(state, 'routing')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: 'RESONANCE', value: 3 }),
        expect.objectContaining({ key: 'SKIP', value: 1 }),
      ]),
    )
    expect(buildCurrentReadings(state, 'gate')[0]).toMatchObject({
      key: 'surprise',
      value: 0.42,
    })
    expect(buildCurrentReadings(state, 'expression')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: 'drive', value: 0.33 }),
        expect.objectContaining({ key: 'mode', value: 'SILENT', discrete: true }),
      ]),
    )
    expect(buildCurrentReadings(state, 'feedback')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: 'positive', value: 4 }),
        expect.objectContaining({ key: 'negative', value: 2 }),
        expect.objectContaining({ key: 'neutral', value: 1 }),
      ]),
    )
  })

  it('sorts unordered buckets and never turns missing metrics into zeroes', () => {
    const points: ObservationHistoryPoint[] = [
      {
        from_ms: 200,
        to_ms: 250,
        first: { warmth: 0.3 },
        last: { warmth: 0.4 },
        min: { warmth: 0.2 },
        max: { warmth: 0.5 },
      },
      {
        from_ms: 100,
        to_ms: 150,
        first: { warmth: 0.1, tension: -0.2 },
        last: { warmth: 0.2, tension: -0.1 },
        min: { warmth: 0.1, tension: -0.2 },
        max: { warmth: 0.2, tension: -0.1 },
      },
    ]

    const buckets = normalizeHistoryBuckets(points)
    expect(buckets.map((bucket) => bucket.toMs)).toEqual([150, 250])
    expect(buckets[0].metrics.tension?.last).toBe(-0.1)
    expect(buckets[1].metrics).not.toHaveProperty('tension')
  })

  it('builds trend lines from persisted buckets only, without a synthetic live tail', () => {
    const buckets = normalizeHistoryBuckets([
      {
        from_ms: 100,
        to_ms: 150,
        first: { warmth: 0.1 },
        last: { warmth: 0.2 },
        min: { warmth: 0.1 },
        max: { warmth: 0.2 },
      },
    ])

    expect(buildTrendSeries(buckets)).toEqual([
      {
        key: 'warmth',
        points: [{ fromTimestamp: 100, toTimestamp: 150, first: 0.1, last: 0.2, min: 0.1, max: 0.2 }],
      },
    ])
  })

  it('keeps bucket first and last at distinct persisted timestamps', () => {
    const series = buildTrendSeries(normalizeHistoryBuckets([{ from_ms: 10, to_ms: 20, first: { warmth: .1 }, last: { warmth: .2 }, min: { warmth: 0 }, max: { warmth: .3 } }]))
    expect(series[0].points[0]).toMatchObject({ fromTimestamp: 10, toTimestamp: 20, first: .1, last: .2 })
  })

  it('uses canonical timing adapters for spine, layer and array payloads', () => {
    expect(buildCurrentReadings({ spine_layers: [{ id: 'perception', avg: 2, p95: 3, count: 4 }] }, 'timing')).toEqual([{ key: 'L1', value: '2.0ms' }])
    expect(buildCurrentReadings({ layers: { L2: { avg_ms: 5 } } }, 'timing')).toEqual([{ key: 'L2', value: '5.0ms' }])
    expect(buildCurrentReadings({ timing: [{ layer: 'L3', avg: 6 }] }, 'timing')).toEqual([{ key: 'L3', value: '6.0ms' }])
  })

  it('distinguishes loading, empty, partial, error, and ready history', () => {
    expect(resolveHistoryState({ loading: true, history: null, error: '' })).toBe('loading')
    expect(resolveHistoryState({
      loading: false,
      history: { points: [], partial: false },
      error: '',
    })).toBe('empty')
    expect(resolveHistoryState({
      loading: false,
      history: { points: [], partial: true },
      error: '',
    })).toBe('partial')
    expect(resolveHistoryState({ loading: false, history: null, error: 'offline' })).toBe('error')
    expect(resolveHistoryState({
      loading: false,
      history: { points: [{}], partial: false },
      error: '',
    })).toBe('ready')
  })

  it('rejects responses from an older session, group, or generation', () => {
    const guard = createObservationRequestGuard()
    const emotion = guard.begin('session-a', 'emotion')
    expect(guard.isCurrent(emotion, 'session-a', 'emotion')).toBe(true)

    const gate = guard.begin('session-a', 'gate')
    expect(guard.isCurrent(emotion, 'session-a', 'emotion')).toBe(false)
    expect(guard.isCurrent(gate, 'session-a', 'emotion')).toBe(false)
    expect(guard.isCurrent(gate, 'session-a', 'gate')).toBe(true)

    guard.invalidate()
    expect(guard.isCurrent(gate, 'session-a', 'gate')).toBe(false)
  })

  it('formats storage without inventing a 1970 oldest record', () => {
    expect(formatObservationBytes(1536)).toBe('1.5 KiB')
    expect(formatObservationBytes(2 * 1024 * 1024)).toBe('2.0 MiB')
    expect(formatObservationOldest(null, 'No record')).toBe('No record')
    expect(formatObservationOldest(0, 'No record')).not.toBe('No record')
  })

  it('preserves cleanup and protected-budget status from scoped history storage', () => {
    expect(adaptObservationStorage({
      used_bytes: 4096,
      limit_bytes: 2048,
      oldest_ms: 123,
      segment_count: 2,
      cleanup_active: true,
      budget_unsatisfiable: true,
    })).toEqual({
      used_bytes: 4096,
      limit_bytes: 2048,
      oldest_ms: 123,
      segment_count: 2,
      cleanup_active: true,
      budget_unsatisfiable: true,
    })
  })
})
