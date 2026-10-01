import { readonly, ref } from 'vue'

export type InteractionFeedbackTone =
  | 'neutral'
  | 'success'
  | 'warning'
  | 'error'

export interface InteractionFeedbackState {
  id: number
  text: string
  tone: InteractionFeedbackTone
  sticky: boolean
}

interface ShowFeedbackOptions {
  ttlMs?: number
  sticky?: boolean
}

const DEFAULT_TTL_MS = 2200
let nextId = 0
let expiryTimer: ReturnType<typeof setTimeout> | null = null

function emptyState(id: number): InteractionFeedbackState {
  return { id, text: '', tone: 'neutral', sticky: false }
}

const state = ref<InteractionFeedbackState>(emptyState(nextId))
const readonlyState = readonly(state)

function cancelExpiry(): void {
  if (expiryTimer !== null) {
    globalThis.clearTimeout(expiryTimer)
    expiryTimer = null
  }
}

function clear(expectedId?: number): boolean {
  if (expectedId !== undefined && state.value.id !== expectedId) return false
  cancelExpiry()
  state.value = emptyState(++nextId)
  return true
}

function show(
  text: string,
  tone: InteractionFeedbackTone = 'neutral',
  options: ShowFeedbackOptions = {},
): number {
  cancelExpiry()
  const id = ++nextId
  const sticky = options.sticky === true
  state.value = { id, text, tone, sticky }

  if (!sticky && typeof window !== 'undefined') {
    const ttlMs = Math.max(0, options.ttlMs ?? DEFAULT_TTL_MS)
    const timer = globalThis.setTimeout(() => {
      if (state.value.id === id) {
        state.value = emptyState(++nextId)
      }
      if (expiryTimer === timer) expiryTimer = null
    }, ttlMs)
    expiryTimer = timer
  }
  return id
}

const feedback = { state: readonlyState, show, clear }

export function useInteractionFeedback(): typeof feedback {
  return feedback
}

export function conciseFeedbackError(
  cause: unknown,
  fallback: string,
  max = 96,
): string {
  const raw =
    cause instanceof Error
      ? cause.message
      : typeof cause === 'string'
        ? cause
        : ''
  const text = raw.trim() || fallback.trim()
  const limit = Math.max(0, Math.floor(max))

  if (text.length <= limit) return text
  if (limit === 0) return ''
  if (limit === 1) return '…'
  return text.slice(0, limit - 1) + '…'
}
