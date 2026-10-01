export function morphFromRect(trigger: DOMRect | { left: number; top: number; width: number; height: number }, dialog: DOMRect | { left: number; top: number; width: number; height: number }) {
  const values = [trigger.left, trigger.top, trigger.width, trigger.height, dialog.left, dialog.top, dialog.width, dialog.height]
  if (!values.every(Number.isFinite) || trigger.width <= 0 || trigger.height <= 0 || dialog.width <= 0 || dialog.height <= 0) return null
  return { translateX: trigger.left - dialog.left, translateY: trigger.top - dialog.top, scaleX: trigger.width / dialog.width, scaleY: trigger.height / dialog.height }
}
export function prefersReducedObservationMotion(): boolean { return typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches }
