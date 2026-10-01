import { describe, expect, it } from 'vitest'
import type { StateResponse } from '../api/types'
import { buildTimingRows } from './monitorTiming'

describe('buildTimingRows', () => {
  it('prefers canonical spine layers, preserves real zeroes, and orders L1 through L7', () => {
    const state = {
      spine_layers: [
        { id: 'L7', avg: 12.34, p95: 34.56, count: 9 },
        { id: 'L2', avg: 0.004, p95: 0.009, count: 1 },
        { id: 'L1', avg: 0, p99: 0, count: 0 },
      ],
      layers: {
        L1: { avg: 99, p95: 99, count: 99 },
      },
      timing: {
        L1_ms: 99,
      },
    } as unknown as StateResponse

    expect(buildTimingRows(state)).toEqual([
      { layer: 'L1', avg: '0.0ms', p95: '0.0ms', count: '0' },
      { layer: 'L2', avg: '4.0µs', p95: '9.0µs', count: '1' },
      { layer: 'L7', avg: '12.3ms', p95: '34.6ms', count: '9' },
    ])
  })

  it('keeps legacy object and array timing payloads readable', () => {
    const legacyLayers = {
      layers: {
        L1_HDC: { avg_ms: 1.25, p95_ms: 2.75, count: 4 },
      },
    } as unknown as StateResponse
    const legacyArray = {
      timing: [
        { layer: 'perception', avg: '3.2ms', p95: '4.8ms', count: 6 },
        { layer: 'expression', avg: 0, p95: 0, count: 0 },
      ],
    } as unknown as StateResponse

    expect(buildTimingRows(legacyLayers)).toEqual([
      { layer: 'L1', avg: '1.3ms', p95: '2.8ms', count: '4' },
    ])
    expect(buildTimingRows(legacyArray)).toEqual([
      { layer: 'L1', avg: '3.2ms', p95: '4.8ms', count: '6' },
      { layer: 'L7', avg: '0.0ms', p95: '0.0ms', count: '0' },
    ])
  })

  it('does not let non-timing layer diagnostics hide a usable timing payload', () => {
    const state = {
      layers: {
        L1_HDC: { sample_bits: [1, 0], vector_dim: 2048, density: 0.5 },
        L5_HGT: { source: 'moe_hgt' },
      },
      timing: [
        { layer: 'perception', avg: '3.2ms', p95: '4.8ms', count: 6 },
      ],
    } as unknown as StateResponse

    expect(buildTimingRows(state)).toEqual([
      { layer: 'L1', avg: '3.2ms', p95: '4.8ms', count: '6' },
    ])
  })
})
