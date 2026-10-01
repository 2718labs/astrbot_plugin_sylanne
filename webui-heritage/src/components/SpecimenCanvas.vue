<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { useVoidTransition } from '../composables/useVoidTransition'

// Faithful port of the old "specimen" canvas engine (UI/index.html
// initNetworkCanvas/stopNetworkCanvas, ~770-1315) — see
// docs/architecture/webui-design-system.md §5. Full-viewport background: an
// organic breathing blob, permanent scars, and a gravity particle field,
// with the void-transition contract (radius/fill ramp) layered on top.

const canvasEl = ref<HTMLCanvasElement | null>(null)
const visible = ref(false)
const { state: voidState, progress: voidProgress } = useVoidTransition()

let raf = 0
let resizeListener: (() => void) | null = null
let mql: MediaQueryList | null = null
let mqlListener: (() => void) | null = null
let themeObserver: MutationObserver | null = null
let stopVoidWatch: (() => void) | null = null

interface CtrlPoint {
  baseAngle: number
  freq1: number
  amp1: number
  phase1: number
  freq2: number
  amp2: number
  phase2: number
  freq3: number
  amp3: number
  phase3: number
}
interface OutlinePoint {
  x: number
  y: number
  r: number
}
interface Pseudopod {
  active: boolean
  pointIdx: number
  startTime: number
  duration: number
  extension: number
}
interface Scar {
  angle: number
  startTime: number
  scarLen: number
  cutDir: number
}
interface Particle {
  x: number
  y: number
  vx: number
  vy: number
  size: number
  opacity: number
  fadeOut: number
  scatterVx: number
  scatterVy: number
}

onMounted(() => {
  const maybeCanvas = canvasEl.value
  if (!maybeCanvas) return
  const maybeCx = maybeCanvas.getContext('2d')
  if (!maybeCx) return
  // Re-bind with explicit non-null types: nested function *declarations*
  // below (resize/render/loop) are hoisted, so plain narrowing on a
  // `T | null` const doesn't reach them — the declared type has to be
  // non-null at the binding itself.
  const canvas: HTMLCanvasElement = maybeCanvas
  const cx: CanvasRenderingContext2D = maybeCx

  let W = 0
  let H = 0

  // ── colors, read from CSS tokens (never hardcode rgba literals here) ──
  let accentRGB = '184, 138, 158'
  let voidFillCss = 'rgba(0, 0, 0, 0.45)'
  let voidSolidRGB = '26, 26, 27'
  function readColors(): void {
    const cs = getComputedStyle(document.documentElement)
    accentRGB = cs.getPropertyValue('--accent-rgb').trim() || accentRGB
    voidFillCss = cs.getPropertyValue('--void-fill').trim() || voidFillCss
    voidSolidRGB = cs.getPropertyValue('--void-solid').trim() || voidSolidRGB
  }
  readColors()
  themeObserver = new MutationObserver(readColors)
  themeObserver.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-theme'],
  })

  // ── static overlay (offscreen canvas — crosshair + edge ticks) ──
  const overlayCanvas = document.createElement('canvas')
  const overlayCx = overlayCanvas.getContext('2d')
  let overlayDirty = true
  function drawOverlay(): void {
    if (!overlayCx) return
    overlayCanvas.width = W
    overlayCanvas.height = H
    overlayCx.clearRect(0, 0, W, H)

    const cX = W / 2
    const cY = H / 2
    overlayCx.strokeStyle = 'rgba(255,255,255,0.04)'
    overlayCx.lineWidth = 1
    overlayCx.beginPath()
    overlayCx.moveTo(cX - 40, cY)
    overlayCx.lineTo(cX + 40, cY)
    overlayCx.moveTo(cX, cY - 40)
    overlayCx.lineTo(cX, cY + 40)
    overlayCx.stroke()

    overlayCx.strokeStyle = 'rgba(255,255,255,0.03)'
    for (let i = 0; i < W; i += 60) {
      const len = i % 180 === 0 ? 10 : 5
      overlayCx.beginPath()
      overlayCx.moveTo(i, 0)
      overlayCx.lineTo(i, len)
      overlayCx.moveTo(i, H)
      overlayCx.lineTo(i, H - len)
      overlayCx.stroke()
    }
    for (let j = 0; j < H; j += 60) {
      const len2 = j % 180 === 0 ? 10 : 5
      overlayCx.beginPath()
      overlayCx.moveTo(0, j)
      overlayCx.lineTo(len2, j)
      overlayCx.moveTo(W, j)
      overlayCx.lineTo(W - len2, j)
      overlayCx.stroke()
    }
    overlayDirty = false
  }

  function resize(): void {
    W = canvas.width = window.innerWidth
    H = canvas.height = window.innerHeight
    overlayDirty = true
  }
  resize()
  resizeListener = resize
  window.addEventListener('resize', resizeListener)

  // ── reduced motion: freeze breathing/particles, keep transitions working ──
  const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
  mql = mediaQuery
  let reduced = mediaQuery.matches
  mqlListener = () => {
    reduced = mediaQuery.matches
    if (!reduced && raf === 0) loop(performance.now())
  }
  mediaQuery.addEventListener('change', mqlListener)

  const startTime = performance.now()

  // ═══ 1. specimen control points (14, each 3 stacked sines) ═══
  const NUM_CTRL = 14
  const ctrlPoints: CtrlPoint[] = []
  for (let i = 0; i < NUM_CTRL; i++) {
    ctrlPoints.push({
      baseAngle: (Math.PI * 2 * i) / NUM_CTRL,
      freq1: 0.8 + Math.random() * 0.4,
      amp1: 0.06 + Math.random() * 0.04,
      phase1: Math.random() * Math.PI * 2,
      freq2: 1.5 + Math.random() * 1.0,
      amp2: 0.02 + Math.random() * 0.02,
      phase2: Math.random() * Math.PI * 2,
      freq3: 3.0 + Math.random() * 2.0,
      amp3: 0.008 + Math.random() * 0.008,
      phase3: Math.random() * Math.PI * 2,
    })
  }

  const pseudopod: Pseudopod = { active: false, pointIdx: 0, startTime: 0, duration: 2000, extension: 0 }
  let nextPseudopodTime = startTime + 8000 + Math.random() * 4000

  // ═══ 2. scars (permanent, max 12) ═══
  const scars: Scar[] = []
  let nextScarTime = startTime + 5000 + Math.random() * 10000
  const MAX_SCARS = 12

  // ═══ 3. scanline ═══
  const scanLine = { startTime, period: 7000 }

  // ═══ 4. gravity particle field ═══
  const NUM_PARTICLES = 70
  const particles: Particle[] = []
  function spawnParticleAtEdge(): Particle {
    const edge = Math.floor(Math.random() * 4)
    let px: number
    let py: number
    if (edge === 0) {
      px = Math.random() * W
      py = -10
    } else if (edge === 1) {
      px = Math.random() * W
      py = H + 10
    } else if (edge === 2) {
      px = -10
      py = Math.random() * H
    } else {
      px = W + 10
      py = Math.random() * H
    }
    const dx = W / 2 - px
    const dy = H / 2 - py
    const angle = Math.atan2(dy, dx)
    const tangentialSpeed = 0.2 + Math.random() * 0.3
    const radialSpeed = 0.05 + Math.random() * 0.1
    return {
      x: px,
      y: py,
      vx:
        Math.cos(angle + Math.PI / 2) * tangentialSpeed +
        Math.cos(angle) * radialSpeed +
        (Math.random() - 0.5) * 0.15,
      vy:
        Math.sin(angle + Math.PI / 2) * tangentialSpeed +
        Math.sin(angle) * radialSpeed +
        (Math.random() - 0.5) * 0.15,
      size: 1.5 + Math.random() * 1.5,
      opacity: 0.15 + Math.random() * 0.2,
      fadeOut: 0,
      scatterVx: 0,
      scatterVy: 0,
    }
  }
  for (let i = 0; i < NUM_PARTICLES; i++) {
    const p = spawnParticleAtEdge()
    p.x = Math.random() * W
    p.y = Math.random() * H
    const initDx = p.x - W / 2
    const initDy = p.y - H / 2
    const initDist = Math.sqrt(initDx * initDx + initDy * initDy)
    if (initDist < Math.min(W, H) * 0.15) {
      const pushAngle = Math.atan2(initDy, initDx)
      p.x = W / 2 + Math.cos(pushAngle) * (Math.min(W, H) * 0.2 + Math.random() * 100)
      p.y = H / 2 + Math.sin(pushAngle) * (Math.min(W, H) * 0.2 + Math.random() * 100)
    }
    const toDx = W / 2 - p.x
    const toDy = H / 2 - p.y
    const toAngle = Math.atan2(toDy, toDx)
    p.vx = Math.cos(toAngle + Math.PI / 2) * (0.1 + Math.random() * 0.2)
    p.vy = Math.sin(toAngle + Math.PI / 2) * (0.1 + Math.random() * 0.2)
    particles.push(p)
  }

  function sampleSurfaceR(a: number, outline: OutlinePoint[]): number {
    const an = ((a % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2)
    const sf = (an / (Math.PI * 2)) * NUM_CTRL
    const si = Math.floor(sf) % NUM_CTRL
    const st = sf - Math.floor(sf)
    return outline[si].r + (outline[(si + 1) % NUM_CTRL].r - outline[si].r) * st
  }

  // frozen === true: reduced-motion idle frame — breathing/particles/scars/
  // pseudopod/scanline/REC all suppressed. The void-transition radius/fill
  // ramp still runs (it's a functional state change, not ambient motion).
  function render(now: number, frozen: boolean): void {
    // Zero-sized viewport (hidden/pre-layout webview, background prerender):
    // drawImage from a 0×0 canvas throws InvalidStateError — and an exception
    // escaping the first mounted-hook frame aborts Vue's remaining post-flush
    // queue in dev, taking sibling components (the boot cover) down with it.
    // Skip the frame and re-poll the size; the loop self-heals once laid out.
    if (W === 0 || H === 0) {
      resize()
      return
    }
    const t = frozen ? 0 : (now - startTime) / 1000
    cx.clearRect(0, 0, W, H)

    if (overlayDirty) drawOverlay()
    cx.drawImage(overlayCanvas, 0, 0)

    if (!frozen) {
      const recAlpha = 0.15 + 0.15 * Math.sin(t * 1.2)
      cx.fillStyle = `rgba(255,68,68,${recAlpha.toFixed(3)})`
      cx.beginPath()
      cx.arc(W - 30, 30, 4, 0, Math.PI * 2)
      cx.fill()
      cx.font = '9px monospace'
      cx.fillStyle = `rgba(255,68,68,${(recAlpha * 0.8).toFixed(3)})`
      cx.fillText('REC', W - 55, 34)
    }

    const specCX = W / 2
    const specCY = H / 2
    const normalBaseRadius = Math.min(W, H) * 0.12
    let baseRadius = normalBaseRadius

    const direction = voidState.value
    const rawProgress = direction === 'idle' ? 0 : voidProgress.value
    let eased = rawProgress
    if (direction === 'shrinking') {
      eased = 1 - Math.pow(1 - rawProgress, 3)
    } else if (direction === 'expanding') {
      eased = rawProgress < 0.5 ? 2 * rawProgress * rawProgress : 1 - Math.pow(-2 * rawProgress + 2, 2) / 2
    }
    const maxRadius = Math.hypot(W, H)
    if (direction === 'expanding') {
      baseRadius = normalBaseRadius + (maxRadius - normalBaseRadius) * eased
    } else if (direction === 'shrinking') {
      baseRadius = maxRadius - (maxRadius - normalBaseRadius) * eased
    }

    const agitation = scars.length / MAX_SCARS
    const pseudopodInterval = 8000 - agitation * 6000
    const pseudopodStrength = 0.25 + agitation * 0.35
    if (!frozen) {
      if (!pseudopod.active && now > nextPseudopodTime) {
        pseudopod.active = true
        pseudopod.pointIdx = Math.floor(Math.random() * NUM_CTRL)
        pseudopod.startTime = now
        pseudopod.duration = 1800 + Math.random() * 400
        nextPseudopodTime = now + pseudopodInterval + Math.random() * (pseudopodInterval * 0.5)
      }
      if (pseudopod.active) {
        const elapsed = now - pseudopod.startTime
        if (elapsed > pseudopod.duration) {
          pseudopod.active = false
          pseudopod.extension = 0
        } else {
          pseudopod.extension = Math.sin((elapsed / pseudopod.duration) * Math.PI) * pseudopodStrength
        }
      }
    }

    const outlinePoints: OutlinePoint[] = []
    for (let i = 0; i < NUM_CTRL; i++) {
      const cp = ctrlPoints[i]
      const osc = frozen
        ? 0
        : Math.sin(t * cp.freq1 + cp.phase1) * cp.amp1 +
          Math.sin(t * cp.freq2 + cp.phase2) * cp.amp2 +
          Math.sin(t * cp.freq3 + cp.phase3) * cp.amp3
      let r = baseRadius * (1.0 + osc)
      if (!frozen && pseudopod.active && i === pseudopod.pointIdx) {
        r += baseRadius * pseudopod.extension
      }
      const angle = cp.baseAngle
      outlinePoints.push({ x: specCX + Math.cos(angle) * r, y: specCY + Math.sin(angle) * r, r })
    }

    const scarGravityFactor = Math.max(0, 1 - scars.length / MAX_SCARS)

    if (!frozen) {
      const scanElapsed = (now - scanLine.startTime) % scanLine.period
      const scanY = (scanElapsed / scanLine.period) * (H + 20) - 10
      const distToSpec = Math.abs(scanY - specCY)
      const scanAlpha = distToSpec < baseRadius * 1.2 ? 0.12 : 0.06
      cx.strokeStyle = `rgba(${accentRGB},${scanAlpha.toFixed(3)})`
      cx.lineWidth = 1
      cx.beginPath()
      cx.moveTo(0, scanY)
      cx.lineTo(W, scanY)
      cx.stroke()
    }

    cx.beginPath()
    for (let i = 0; i < NUM_CTRL; i++) {
      const p0 = outlinePoints[(i - 1 + NUM_CTRL) % NUM_CTRL]
      const p1 = outlinePoints[i]
      const p2 = outlinePoints[(i + 1) % NUM_CTRL]
      const p3 = outlinePoints[(i + 2) % NUM_CTRL]
      if (i === 0) cx.moveTo(p1.x, p1.y)
      const cp1x = p1.x + (p2.x - p0.x) / 6
      const cp1y = p1.y + (p2.y - p0.y) / 6
      const cp2x = p2.x - (p3.x - p1.x) / 6
      const cp2y = p2.y - (p3.y - p1.y) / 6
      cx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2.x, p2.y)
    }
    cx.closePath()

    if (direction !== 'idle') {
      const fillAlpha = 0.15 + 0.85 * rawProgress
      cx.fillStyle = `rgba(${voidSolidRGB},${fillAlpha})`
    } else {
      cx.fillStyle = voidFillCss
    }
    cx.fill()

    const strokeAlpha = direction !== 'idle' ? 0.5 * (1 - rawProgress) : 0.5
    cx.strokeStyle = `rgba(${accentRGB},${strokeAlpha.toFixed(3)})`
    cx.lineWidth = 1.5
    if (!frozen && direction === 'idle') {
      cx.shadowColor = `rgba(${accentRGB},0.5)`
      cx.shadowBlur = 14
    }
    cx.stroke()
    cx.shadowBlur = 0

    // ── scars ──
    if (!frozen) {
      if (now > nextScarTime && scars.length < MAX_SCARS && scarGravityFactor > 0) {
        const scarAngle = Math.random() * Math.PI * 2
        scars.push({
          angle: scarAngle,
          startTime: now,
          scarLen: 60 + Math.random() * 30,
          cutDir: Math.random() < 0.5 ? 1 : -1,
        })
        nextScarTime = now + 7500 + Math.random() * 7500

        const scarX = specCX + Math.cos(scarAngle) * baseRadius
        const scarY = specCY + Math.sin(scarAngle) * baseRadius
        for (const pp of particles) {
          const dx = pp.x - scarX
          const dy = pp.y - scarY
          const dist = Math.hypot(dx, dy)
          if (dist < 120 && dist > 0) {
            const force = (1 - dist / 120) * 2.5
            pp.scatterVx = (dx / dist) * force
            pp.scatterVy = (dy / dist) * force
          }
        }
      }

      for (const scar of scars) {
        const scarElapsed = now - scar.startTime
        const scarProgress = Math.min(scarElapsed / 8000, 1.0)
        const cutProgress = Math.min(scarElapsed / 600, 1.0)
        const cutEased = 1 - Math.pow(1 - cutProgress, 2)

        let scarAlpha: number
        let scarR: number
        let scarG: number
        let scarB: number
        if (scarProgress < 0.15) {
          scarAlpha = cutEased * 1.0
          scarR = 200
          scarG = 140
          scarB = 165
        } else if (scarProgress < 0.8) {
          let blend = (scarProgress - 0.15) / 0.65
          blend = 1 - Math.pow(1 - blend, 2)
          scarR = 200 + (100 - 200) * blend
          scarG = 140 + (50 - 140) * blend
          scarB = 165 + (70 - 165) * blend
          scarAlpha = 1.0 - blend * 0.6
        } else {
          scarR = 100
          scarG = 50
          scarB = 70
          scarAlpha = 0.4
        }

        const scarDepth = 0.55 + Math.abs(Math.sin(scar.angle * 3.7)) * 0.35
        const lenFactor = 1.0 - scarProgress * 0.15
        const scarLen = scar.scarLen * lenFactor
        const angularSpan = scarLen / (baseRadius * 2)
        const angleL = scar.angle - angularSpan * 0.5
        const angleR = scar.angle + angularSpan * 0.5
        const angleC = scar.angle

        const rL = sampleSurfaceR(angleL, outlinePoints) * scarDepth
        const rC = sampleSurfaceR(angleC, outlinePoints) * scarDepth
        const rR = sampleSurfaceR(angleR, outlinePoints) * scarDepth

        const fX1 = specCX + Math.cos(angleL) * rL
        const fY1 = specCY + Math.sin(angleL) * rL
        const fX2 = specCX + Math.cos(angleR) * rR
        const fY2 = specCY + Math.sin(angleR) * rR
        const fSx = specCX + Math.cos(angleC) * rC
        const fSy = specCY + Math.sin(angleC) * rC

        let startX: number
        let startY: number
        let fullEndX: number
        let fullEndY: number
        if (scar.cutDir > 0) {
          startX = fX1
          startY = fY1
          fullEndX = fX2
          fullEndY = fY2
        } else {
          startX = fX2
          startY = fY2
          fullEndX = fX1
          fullEndY = fY1
        }
        const x1 = startX
        const y1 = startY
        const x2 = startX + (fullEndX - startX) * cutEased
        const y2 = startY + (fullEndY - startY) * cutEased
        const sx = startX + (fSx - startX) * cutEased
        const sy = startY + (fSy - startY) * cutEased

        const bulge = 2.5 + scarAlpha * 2.0
        const bulgeDx = Math.cos(angleC) * bulge
        const bulgeDy = Math.sin(angleC) * bulge

        cx.fillStyle = `rgba(${Math.round(scarR)},${Math.round(scarG)},${Math.round(scarB)},${scarAlpha.toFixed(3)})`
        cx.beginPath()
        cx.moveTo(x1, y1)
        cx.quadraticCurveTo(sx + bulgeDx, sy + bulgeDy, x2, y2)
        cx.quadraticCurveTo(sx - bulgeDx, sy - bulgeDy, x1, y1)
        cx.closePath()
        cx.fill()

        if (scarProgress < 0.15) {
          cx.shadowColor = 'rgba(200,140,165,0.6)'
          cx.shadowBlur = 12
          cx.fill()
          cx.shadowBlur = 0
        }
      }
    }

    // ── gravity particle field ──
    if (!frozen) {
      const baseGravity = direction === 'expanding' ? 4000 : 500
      const gravityG = baseGravity * scarGravityFactor
      const absorptionRadius = baseRadius * 0.6

      for (const pp of particles) {
        const dxToCenter = specCX - pp.x
        const dyToCenter = specCY - pp.y
        const distToCenter = Math.sqrt(dxToCenter * dxToCenter + dyToCenter * dyToCenter)
        const force = gravityG / (distToCenter * distToCenter + 100)
        if (distToCenter > 0) {
          pp.vx += (dxToCenter / distToCenter) * force
          pp.vy += (dyToCenter / distToCenter) * force
        }
        pp.vx *= 0.998
        pp.vy *= 0.998
        pp.scatterVx *= 0.95
        pp.scatterVy *= 0.95
        pp.x += pp.vx + pp.scatterVx
        pp.y += pp.vy + pp.scatterVy

        if (pp.fadeOut === 0) {
          if (distToCenter < baseRadius) {
            pp.fadeOut = Math.random() < 0.8 ? 0.8 : 0.01
          }
        } else if (pp.fadeOut < 0.1) {
          if (distToCenter < absorptionRadius) {
            pp.fadeOut = 0.5
          }
        }

        if (pp.fadeOut > 0) {
          pp.fadeOut += 0.04
          if (pp.fadeOut >= 1.5) {
            const np = spawnParticleAtEdge()
            pp.x = np.x
            pp.y = np.y
            pp.vx = np.vx
            pp.vy = np.vy
            pp.size = np.size
            pp.opacity = np.opacity
            pp.fadeOut = 0
            pp.scatterVx = 0
            pp.scatterVy = 0
            continue
          }
        }

        const speed = Math.sqrt(pp.vx * pp.vx + pp.vy * pp.vy)
        const proximityBrightness = Math.min(1.0, 200 / (distToCenter + 50))
        let pAlpha = Math.min(0.6, pp.opacity + speed * 0.15 + proximityBrightness * 0.2)
        if (pp.fadeOut > 0) {
          pAlpha *= Math.max(0, 1 - pp.fadeOut)
        }
        if (pAlpha > 0.01) {
          cx.fillStyle = `rgba(${accentRGB},${pAlpha.toFixed(3)})`
          cx.beginPath()
          cx.arc(pp.x, pp.y, pp.size, 0, Math.PI * 2)
          cx.fill()
        }
      }
    }
  }

  function loop(now: number): void {
    render(now, reduced)
    const activeTransition = voidState.value !== 'idle'
    // W===0: keep the loop alive through a zero-sized (pre-layout) viewport
    // even under reduced motion, so the static frame appears once laid out.
    if (!reduced || activeTransition || W === 0) {
      raf = requestAnimationFrame(loop)
    } else {
      raf = 0
    }
  }
  loop(performance.now())

  // If motion is reduced, the loop above self-stops once idle; a later void
  // transition needs to wake it back up.
  stopVoidWatch = watch(voidState, (v) => {
    if (reduced && v !== 'idle' && raf === 0) loop(performance.now())
  })

  requestAnimationFrame(() => {
    visible.value = true
  })
})

onUnmounted(() => {
  if (raf) cancelAnimationFrame(raf)
  if (resizeListener) window.removeEventListener('resize', resizeListener)
  if (mql && mqlListener) mql.removeEventListener('change', mqlListener)
  if (themeObserver) themeObserver.disconnect()
  if (stopVoidWatch) stopVoidWatch()
})
</script>

<template>
  <canvas ref="canvasEl" class="specimen-canvas" :class="{ visible }" aria-hidden="true" />
</template>

<style scoped>
.specimen-canvas {
  position: fixed;
  inset: 0;
  z-index: 1;
  width: 100vw;
  height: 100vh;
  opacity: 0;
  transition: opacity 1.2s ease;
}
.specimen-canvas.visible {
  opacity: 1;
}
</style>
