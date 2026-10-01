const INTERACTIVE_SELECTOR = 'a, button, input, select, textarea, [contenteditable="true"], [role="button"], [role="link"]'

export function isNestedInteractiveTarget(target: EventTarget | null, currentTarget: EventTarget | null): boolean {
  if (!target || typeof (target as { closest?: unknown }).closest !== 'function') return false
  const interactive = (target as unknown as { closest(selector: string): EventTarget | null }).closest(INTERACTIVE_SELECTOR)
  return interactive !== null && interactive !== currentTarget
}
