export const ARRIVAL_LINE_MS = 1200
export const ARRIVAL_NODE_FADE_MS = 250
export const ARRIVAL_CONTENT_MS = 1200
export const ARRIVAL_CONTENT_DURATION_MS = 600
export const ARRIVAL_CLEANUP_MS = 1900

export function arrivalNodeDelay(top: number): number {
  return Math.round((top / 100) * ARRIVAL_LINE_MS)
}

export function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false
  }
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}
