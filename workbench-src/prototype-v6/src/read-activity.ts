/** Optical status is presentation only. No request, permission or progress is inferred. */
export type ReadActivityMode = 'idle' | 'reading' | 'demo'
interface ReadActivitySource {
 mode: string; auth: string
 workspace: { pending?: boolean }; view: { pending?: boolean }
}
export function readActivityMode(state: ReadActivitySource, demo: boolean, workspaceVisible = true): ReadActivityMode {
 if (!workspaceVisible) return 'idle'
 if (state.mode === 'offline') return demo ? 'demo' : 'idle'
 // A backend 'loading' response is not a pending request. Only the current,
 // locally validated request lifecycle is allowed to animate real activity.
 return state.mode === 'same-origin' && state.auth === 'authenticated' &&
  (state.workspace.pending === true || state.view.pending === true) ? 'reading' : 'idle'
}
export const OPTICAL_ACTIVITY_CYCLE = 7.4
export const OPTICAL_ACTIVITY_MAX = .16
// Fixed, unequal spacing/amplitudes are reproducible. Every raised-cosine pulse
// lasts at least .56 s; neighboring peaks are at least 1.05 s apart. The light
// never turns off: this is a small additive gain on its steady powered level.
export const OPTICAL_ACTIVITY_PULSES = [
 { start: .08, duration: .60, gain: .12 },
 { start: 1.22, duration: .68, gain: .16 },
 { start: 2.93, duration: .56, gain: .10 },
 { start: 4.06, duration: .72, gain: .14 },
 { start: 6.03, duration: .62, gain: .11 },
] as const
export function sampleOpticalActivity(seconds: number) {
 if (!Number.isFinite(seconds) || seconds < 0) return 0
 const time = seconds % OPTICAL_ACTIVITY_CYCLE
 for (const pulse of OPTICAL_ACTIVITY_PULSES) {
  const t = (time - pulse.start) / pulse.duration
  if (t >= 0 && t <= 1) return pulse.gain * (1 - Math.cos(2 * Math.PI * t)) / 2
 }
 return 0
}
export interface OpticalActivity { logical: number | null; elapsed: number; level: number }
export const makeOpticalActivity = (): OpticalActivity => ({ logical: null, elapsed: 0, level: 0 })
export function bindOpticalActivity(activity: OpticalActivity, logical: number) {
 if (activity.logical !== logical) { activity.logical = logical; activity.elapsed = 0; activity.level = 0 }
 return activity
}
export function updateOpticalActivity(activity: OpticalActivity, logical: number, selected: boolean, mode: ReadActivityMode, dt: number, reduced: boolean) {
 bindOpticalActivity(activity, logical)
 const elapsed = Number.isFinite(dt) ? Math.max(0, Math.min(.1, dt)) : 0
 if (reduced || !selected) { activity.elapsed = 0; activity.level = 0; return activity }
 if (mode === 'idle') {
  activity.elapsed = 0
  // No new pulse after settlement/cancellation. Finish the current small gain
  // monotonically, within .32 s, then stay at the exact steady powered value.
  activity.level = Math.max(0, activity.level - elapsed * .5)
 } else {
  activity.elapsed = (activity.elapsed + elapsed) % OPTICAL_ACTIVITY_CYCLE
  const target = sampleOpticalActivity(activity.elapsed), step = elapsed * .8
  activity.level += Math.max(-step, Math.min(step, target - activity.level))
 }
 return activity
}
