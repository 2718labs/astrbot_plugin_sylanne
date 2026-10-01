import { isReadonly } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  conciseFeedbackError,
  useInteractionFeedback,
} from './useInteractionFeedback'

describe('useInteractionFeedback', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.stubGlobal('window', {
      setTimeout: globalThis.setTimeout,
      clearTimeout: globalThis.clearTimeout,
    })
    useInteractionFeedback().clear()
  })

  afterEach(() => {
    useInteractionFeedback().clear()
    vi.clearAllTimers()
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('expires a non-sticky message after the default ttl', () => {
    const feedback = useInteractionFeedback()

    const id = feedback.show('saved', 'success')
    expect(id).toBe(feedback.state.value.id)
    expect(feedback.state.value.text).toBe('saved')

    vi.advanceTimersByTime(2199)
    expect(feedback.state.value.text).toBe('saved')

    vi.advanceTimersByTime(1)
    expect(feedback.state.value.text).toBe('')
  })

  it('uses last-write-wins and an older timer cannot clear a newer message', () => {
    const feedback = useInteractionFeedback()

    feedback.show('first', 'neutral', { ttlMs: 1000 })
    vi.advanceTimersByTime(500)
    feedback.show('second', 'warning', { ttlMs: 1500 })

    vi.advanceTimersByTime(500)
    expect(feedback.state.value.text).toBe('second')
    expect(feedback.state.value.tone).toBe('warning')

    vi.advanceTimersByTime(1000)
    expect(feedback.state.value.text).toBe('')
  })

  it('keeps sticky feedback until explicitly replaced or cleared', () => {
    const feedback = useInteractionFeedback()

    feedback.show('working', 'neutral', { sticky: true })
    vi.advanceTimersByTime(60_000)

    expect(feedback.state.value.text).toBe('working')
    expect(feedback.state.value.sticky).toBe(true)
  })

  it('clear cancels pending expiry and invalidates the old message', () => {
    const feedback = useInteractionFeedback()

    feedback.show('temporary', 'error', { ttlMs: 500 })
    const shownId = feedback.state.value.id
    expect(feedback.clear()).toBe(true)

    expect(feedback.state.value.text).toBe('')
    expect(feedback.state.value.id).toBeGreaterThan(shownId)
    expect(vi.getTimerCount()).toBe(0)

    vi.advanceTimersByTime(500)
    expect(feedback.state.value.text).toBe('')
  })

  it('conditionally clears only the message with the expected id', () => {
    const feedback = useInteractionFeedback()

    const firstId = feedback.show('first', 'neutral', { ttlMs: 1000 })
    const secondId = feedback.show('second', 'success', { ttlMs: 2000 })

    expect(feedback.clear(firstId)).toBe(false)
    expect(feedback.state.value.id).toBe(secondId)
    expect(feedback.state.value.text).toBe('second')
    expect(vi.getTimerCount()).toBe(1)

    vi.advanceTimersByTime(1999)
    expect(feedback.state.value.text).toBe('second')
    vi.advanceTimersByTime(1)
    expect(feedback.state.value.text).toBe('')
  })

  it('clears a matching owner id and exposes state as readonly', () => {
    const feedback = useInteractionFeedback()
    const id = feedback.show('owned', 'neutral', { sticky: true })

    expect(isReadonly(feedback.state)).toBe(true)
    expect(feedback.clear(id)).toBe(true)
    expect(feedback.state.value.text).toBe('')
  })

  it('does not schedule an expiry timer without a browser window', () => {
    const feedback = useInteractionFeedback()
    vi.stubGlobal('window', undefined)

    feedback.show('server render', 'neutral', { ttlMs: 10 })

    expect(feedback.state.value.text).toBe('server render')
    expect(vi.getTimerCount()).toBe(0)
  })
})

describe('conciseFeedbackError', () => {
  it('normalizes Error and string causes and falls back for empty text', () => {
    expect(conciseFeedbackError(new Error('  broken request  '), 'failed')).toBe(
      'broken request',
    )
    expect(conciseFeedbackError('  unavailable  ', 'failed')).toBe('unavailable')
    expect(conciseFeedbackError(' \n\t ', 'failed')).toBe('failed')
    expect(conciseFeedbackError(null, '  failed  ')).toBe('failed')
  })

  it('truncates to the requested maximum and ends with an ellipsis', () => {
    const result = conciseFeedbackError('abcdefghij', 'failed', 6)

    expect(result).toBe('abcde…')
    expect(result).toHaveLength(6)
  })
})
