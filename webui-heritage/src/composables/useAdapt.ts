// Shared "adaptState" style helpers — extracted from MonitorView's local
// num()/fmtMs() so every view can normalize loosely-shaped backend payloads
// the same way. Semantics preserved exactly (see MonitorView.vue history).

/**
 * Walk candidate key names on a possibly-undefined object and return the
 * first value that is not null/undefined/'' coerced to a finite Number,
 * else dflt.
 *
 * CRITICAL: a legit 0 must survive — this is why we do an explicit
 * null/undefined/'' check per-key rather than `Number(x) || dflt`, which
 * would silently swap a real 0 (e.g. boundary.integrity=0, a fully-breached
 * boundary) for the fallback. That was a real shipped bug the old dashboard
 * had to fix.
 */
export function num(
  obj: Record<string, unknown> | undefined,
  keys: string[],
  dflt: number,
): number {
  if (!obj) return dflt
  for (const k of keys) {
    const v = obj[k]
    if (v !== null && v !== undefined && v !== '') {
      const n = Number(v)
      if (!Number.isNaN(n)) return n
    }
  }
  return dflt
}

/** Format a millisecond duration for display, e.g. 12.3 -> "12.3ms". */
export function fmtMs(v: number | undefined): string {
  if (v === undefined || Number.isNaN(v)) return '—'
  return v.toFixed(1) + 'ms'
}

/** Clamp v/max (default max=1) into a 0..100 percentage. */
export function pct(v: number, max = 1): number {
  const m = max || 1
  return Math.max(0, Math.min(100, (v / m) * 100))
}
