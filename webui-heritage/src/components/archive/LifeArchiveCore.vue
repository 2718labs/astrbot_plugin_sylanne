<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as THREE from 'three'

export type ArchiveEntry = {
  id: string
  label: string
  status: 'available' | 'unavailable'
  detail?: string
}

const props = withDefaults(defineProps<{
  entries: ArchiveEntry[]
  selectedId?: string
  loading?: boolean
  readStatus?: 'loading' | 'empty' | 'unauthorized' | 'stale' | 'partial' | 'unavailable' | 'ready'
}>(), {
  selectedId: '',
  loading: false,
})

const emit = defineEmits<{
  select: [id: string]
  open: [id: string]
}>()

const stage = ref<HTMLElement | null>(null)
const fallback = ref(false)
const reducedMotion = ref(false)
const active = ref(false)
const exploded = ref(false)
const clearShell = ref(false)
const selected = computed(() => props.entries.find(entry => entry.id === props.selectedId))
const visibleEntries = computed(() => props.entries.slice(0, 24))

let renderer: THREE.WebGLRenderer | undefined
let scene: THREE.Scene | undefined
let camera: THREE.PerspectiveCamera | undefined
let assembly: THREE.Group | undefined
let core: THREE.Group | undefined
let rings: THREE.Group | undefined
let cards: THREE.Group | undefined
let raycaster: THREE.Raycaster | undefined
let pointer = new THREE.Vector2()
let resizeObserver: ResizeObserver | undefined
let intersectionObserver: IntersectionObserver | undefined
let motionQuery: MediaQueryList | undefined
let frame = 0
let previousFrame = 0
let dragStart: { x: number; y: number; angle: number; pitch: number } | undefined
let dragged = false
let currentAngle = -0.25
let currentPitch = -0.31
let targetAngle = -0.25
let targetPitch = -0.31
let shellGlass: THREE.MeshPhongMaterial | undefined
let shellFrost: THREE.MeshPhongMaterial | undefined
type ExplodeRig = { group: THREE.Group; base: THREE.Vector3; offset: THREE.Vector3 }
const explodeRigs: ExplodeRig[] = []
type CardRig = {
  group: THREE.Group
  bodyMaterial: THREE.MeshPhongMaterial
  rimMaterial: THREE.LineBasicMaterial
  lid: THREE.Group
  baseY: number
  targetX: number
  targetY: number
  targetZ: number
  targetTilt: number
  targetPitch: number
  targetOpen: number
}
const cardRigs = new Map<string, CardRig>()

const geometries: THREE.BufferGeometry[] = []
const materials: THREE.Material[] = []
const makeGeometry = <T extends THREE.BufferGeometry>(geometry: T): T => {
  geometries.push(geometry)
  return geometry
}
const makeMaterial = <T extends THREE.Material>(material: T): T => {
  materials.push(material)
  return material
}

function addMesh(parent: THREE.Object3D, geometry: THREE.BufferGeometry, material: THREE.Material, x = 0, y = 0, z = 0) {
  const mesh = new THREE.Mesh(geometry, material)
  mesh.position.set(x, y, z)
  parent.add(mesh)
  return mesh
}

function addRing(parent: THREE.Object3D, radius: number, tube: number, color: number, y: number, opacity = 1) {
  const ring = addMesh(parent,
    makeGeometry(new THREE.TorusGeometry(radius, tube, 7, 48)),
    makeMaterial(new THREE.MeshBasicMaterial({ color, transparent: opacity < 1, opacity, depthWrite: opacity === 1 })),
    0, y, 0)
  ring.rotation.x = Math.PI / 2
  return ring
}

function addExplodeGroup(parent: THREE.Object3D, offset: [number, number, number]) {
  const group = new THREE.Group()
  parent.add(group)
  explodeRigs.push({ group, base: group.position.clone(), offset: new THREE.Vector3(...offset) })
  return group
}

function buildHousing() {
  if (!assembly) return
  const housing = new THREE.Group()
  assembly.add(housing)
  const skin = addExplodeGroup(housing, [-0.5, 0, -0.22])
  const frame = addExplodeGroup(housing, [0.42, 0, -0.19])
  const supports = addExplodeGroup(housing, [0, 0, 0.42])

  // The specimen is a vertical memory vessel: layered tissue around a central seed.
  shellGlass = makeMaterial(new THREE.MeshPhongMaterial({
    color: 0xa999a2, emissive: 0x1d171b, shininess: 108,
    transparent: true, opacity: 0.15, side: THREE.DoubleSide, depthWrite: false,
  }))
  addMesh(skin, makeGeometry(new THREE.CylinderGeometry(1.07, 1.07, 3.2, 32, 1, true)), shellGlass)
  shellFrost = makeMaterial(new THREE.MeshPhongMaterial({
    color: 0xcfc8bc, emissive: 0x201b17, shininess: 22,
    transparent: true, opacity: 0.27, side: THREE.DoubleSide, depthWrite: false,
  }))
  // Five uneven curved leaves leave a viewing aperture through the vessel.
  for (let index = 0; index < 5; index++) {
    const height = [2.87, 2.62, 2.76, 2.92, 2.58][index] ?? 2.7
    const panel = addMesh(skin,
      makeGeometry(new THREE.CylinderGeometry(1.084, 1.084, height, 12, 1, true,
        index * (Math.PI * 2 / 6) + 0.11, Math.PI * 2 / 6 - 0.23)), shellFrost)
    panel.position.y = index % 2 ? 0.05 : -0.04
  }
  const cap = makeMaterial(new THREE.MeshPhongMaterial({
    color: 0x887f7b, emissive: 0x1a1214, shininess: 120,
    transparent: true, opacity: 0.91, depthWrite: false,
  }))
  for (const y of [-1.67, 1.67]) {
    const collar = addExplodeGroup(housing, [0, y > 0 ? 0.39 : -0.39, 0])
    addMesh(collar, makeGeometry(new THREE.CylinderGeometry(1.1, 1.1, 0.11, 32)), cap, 0, y, 0)
    addRing(collar, 1.08, 0.038, 0xc9a48d, y, 0.94)
    addRing(collar, 0.88, 0.012, 0xd8bfaa, y + (y > 0 ? 0.063 : -0.063), 0.76)
    addRing(collar, 1.01, 0.009, 0x514a4c, y + (y > 0 ? 0.07 : -0.07), 0.82)
  }
  const strutGeometry = makeGeometry(new THREE.CylinderGeometry(0.032, 0.032, 3.12, 6))
  const strutMaterial = makeMaterial(new THREE.MeshPhongMaterial({ color: 0xa69694, emissive: 0x1c1215,
    shininess: 94, transparent: true, opacity: 0.86 }))
  for (let index = 0; index < 8; index++) {
    const angle = index * Math.PI / 4
    addMesh(frame, strutGeometry, strutMaterial, Math.sin(angle) * 1.075, 0, Math.cos(angle) * 1.075)
  }
  for (const y of [-1.17, -0.59, 0, 0.59, 1.17]) addRing(frame, 1.079, 0.008, 0xa77d77, y, 0.43)
  const guideMaterial = makeMaterial(new THREE.MeshBasicMaterial({ color: 0xc5975b, transparent: true, opacity: 0.71 }))
  const guideGeometry = makeGeometry(new THREE.BoxGeometry(0.016, 2.6, 0.019))
  for (const [x, z] of [[-0.58, 0.61], [0.58, 0.61], [-0.58, -0.61], [0.58, -0.61]]) {
    addMesh(frame, guideGeometry, guideMaterial, x, 0, z)
  }
  // Empty supports describe the mechanism; they never imply a server archive exists.
  const supportMaterial = makeMaterial(new THREE.MeshPhongMaterial({ color: 0xa59491, emissive: 0x261d1a,
    transparent: true, opacity: 0.59, shininess: 66, depthWrite: false }))
  for (const [y, x, z] of [[-1.02, -0.10, -0.13], [0, 0.11, -0.23], [1.02, -0.06, -0.16]]) {
    const support = addMesh(supports,
      makeGeometry(new THREE.BoxGeometry(1.63, 0.072, 0.81)), supportMaterial, x, y, z)
    support.rotation.y = y * 0.12
    addMesh(supports, makeGeometry(new THREE.BoxGeometry(1.53, 0.018, 0.022)),
      guideMaterial, x, y + 0.051, z + 0.39)
    for (const end of [-1, 1]) {
      addMesh(supports, makeGeometry(new THREE.BoxGeometry(0.12, 0.12, 0.13)),
        cap, x + end * 0.81, y, z)
    }
  }

  core = addExplodeGroup(assembly, [0.22, 0, 0.4])
  const spindle = makeMaterial(new THREE.MeshBasicMaterial({ color: 0x8b727f, transparent: true, opacity: 0.54 }))
  addMesh(core, makeGeometry(new THREE.CylinderGeometry(0.025, 0.025, 2.38, 8)), spindle)
  const seed = addMesh(core,
    makeGeometry(new THREE.IcosahedronGeometry(0.4, 1)),
    makeMaterial(new THREE.MeshPhongMaterial({ color: 0xc69aa7, emissive: 0x58323b, shininess: 140,
      transparent: true, opacity: 0.96, flatShading: true, depthWrite: false })))
  seed.scale.set(0.9, 1.35, 0.9)
  const seedWire = new THREE.LineSegments(
    makeGeometry(new THREE.EdgesGeometry(seed.geometry, 18)),
    makeMaterial(new THREE.LineBasicMaterial({ color: 0xf2bdcd, transparent: true, opacity: 0.46 })))
  seedWire.scale.copy(seed.scale)
  core.add(seedWire)
  const seedHalo = addMesh(core,
    makeGeometry(new THREE.IcosahedronGeometry(0.49, 1)),
    makeMaterial(new THREE.MeshPhongMaterial({ color: 0xceaa9c, emissive: 0x3a231e,
      transparent: true, opacity: 0.09, side: THREE.DoubleSide, depthWrite: false })))
  seedHalo.scale.set(0.9, 1.35, 0.9)
  for (let strand = 0; strand < 2; strand++) {
    const points: THREE.Vector3[] = []
    for (let index = 0; index <= 72; index++) {
      const fraction = index / 72
      const angle = fraction * Math.PI * 4 + strand * Math.PI
      points.push(new THREE.Vector3(Math.cos(angle) * 0.38, -1.04 + fraction * 2.08,
        Math.sin(angle) * 0.38))
    }
    const filament = new THREE.Line(
      makeGeometry(new THREE.BufferGeometry().setFromPoints(points)),
      makeMaterial(new THREE.LineBasicMaterial({ color: strand ? 0x9bb2ae : 0xcfa477,
        transparent: true, opacity: 0.45 })))
    core.add(filament)
  }

  rings = new THREE.Group()
  core.add(rings)
  for (const [radius, slope, color] of [
    [0.64, 0.33, 0xcc9baf], [0.85, -0.29, 0x9cb7bc], [0.99, 0.12, 0x826f93],
  ] as const) {
    const ring = addMesh(rings,
      makeGeometry(new THREE.TorusGeometry(radius, 0.013, 6, 48)),
      makeMaterial(new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.65, depthWrite: false })))
    ring.rotation.set(Math.PI / 2 + slope, 0.13, slope)
  }
}

function removeCards() {
  if (!cards) return
  cards.traverse(object => {
    if (object instanceof THREE.Mesh || object instanceof THREE.LineSegments) {
      object.geometry.dispose()
      if (Array.isArray(object.material)) object.material.forEach(material => material.dispose())
      else object.material.dispose()
    }
  })
  cards.clear()
  cardRigs.clear()
}

function buildCards() {
  if (!assembly || !cards) return
  removeCards()
  visibleEntries.value.forEach((entry, index) => {
    const layer = new THREE.Group()
    layer.userData.id = entry.id
    const count = visibleEntries.value.length
    const baseY = (index - (count - 1) / 2) * Math.min(0.17, 2.4 / Math.max(1, count))
    layer.position.set(0, baseY, 0)
    cards?.add(layer)

    const bodyMaterial = new THREE.MeshPhongMaterial({ color: entry.status === 'available' ? 0x77546a : 0x4b434e,
      emissive: 0x140e15, shininess: 80, transparent: true,
      opacity: entry.status === 'available' ? 0.78 : 0.55 })
    const surface = new THREE.Mesh(
      new THREE.BoxGeometry(1.41, 0.105, 0.76),
      bodyMaterial)
    surface.userData.id = entry.id
    layer.add(surface)
    const rimMaterial = new THREE.LineBasicMaterial({ color: 0xa391a0, transparent: true, opacity: 0.7 })
    const rim = new THREE.LineSegments(
      new THREE.EdgesGeometry(surface.geometry),
      rimMaterial)
    rim.userData.id = entry.id
    layer.add(rim)
    const marker = new THREE.Mesh(
      new THREE.BoxGeometry(0.12, 0.081, 0.77),
      new THREE.MeshBasicMaterial({ color: entry.status === 'available' ? 0xd7abbc : 0x716672 }))
    marker.position.x = -0.7
    marker.userData.id = entry.id
    layer.add(marker)
    const inlay = new THREE.Mesh(
      new THREE.BoxGeometry(1.12, 0.006, 0.59),
      new THREE.MeshPhongMaterial({ color: 0xd4c3b2, transparent: true, opacity: 0.34,
        shininess: 96, depthWrite: false }))
    inlay.position.y = 0.057
    inlay.userData.id = entry.id
    layer.add(inlay)
    const traceMaterial = new THREE.MeshBasicMaterial({ color: entry.status === 'available' ? 0xd7ac71 : 0x918a83,
      transparent: true, opacity: 0.75 })
    for (let line = 0; line < 3; line++) {
      const trace = new THREE.Mesh(new THREE.BoxGeometry(0.55 - line * 0.1, 0.008, 0.012), traceMaterial)
      trace.position.set(0.12, 0.062, -0.15 + line * 0.11)
      trace.userData.id = entry.id
      layer.add(trace)
    }

    // A hinged translucent leaf gives "open" a physical motion distinct from extract.
    const lid = new THREE.Group()
    lid.position.set(0, 0.056, -0.38)
    layer.add(lid)
    const leaf = new THREE.Mesh(
      new THREE.BoxGeometry(1.24, 0.018, 0.73),
      new THREE.MeshPhongMaterial({ color: 0xbfa0af, emissive: 0x2f1a28,
        transparent: true, opacity: 0.42, shininess: 110, depthWrite: false }))
    leaf.position.z = 0.365
    leaf.userData.id = entry.id
    lid.add(leaf)
    const leafRim = new THREE.LineSegments(
      new THREE.EdgesGeometry(leaf.geometry),
      new THREE.LineBasicMaterial({ color: 0xe2bacb, transparent: true, opacity: 0.45 }))
    leafRim.position.copy(leaf.position)
    leafRim.userData.id = entry.id
    lid.add(leafRim)

    cardRigs.set(entry.id, { group: layer, bodyMaterial, rimMaterial, lid, baseY,
      targetX: 0, targetY: baseY, targetZ: 0, targetTilt: 0, targetPitch: 0, targetOpen: 0 })
  })
  updateSelection(true)
  requestRender()
}

function updateSelection(immediate: boolean) {
  let index = 0
  for (const [id, rig] of cardRigs) {
    const selectedLayer = props.selectedId === id
    rig.targetX = selectedLayer ? (exploded.value ? 1.84 : 1.47) : (exploded.value ? (index % 2 ? -0.22 : 0.22) : 0)
    rig.targetY = rig.baseY * (exploded.value ? 1.34 : 1)
    rig.targetZ = selectedLayer ? (exploded.value ? 0.9 : 0.55) : (exploded.value ? 0.2 + index * 0.055 : 0)
    rig.targetTilt = selectedLayer ? -0.1 : 0
    rig.targetPitch = selectedLayer ? -0.49 : 0
    rig.targetOpen = selectedLayer && (props.loading || props.readStatus === 'ready') ? -1.08 : 0
    rig.bodyMaterial.emissive.setHex(selectedLayer ? 0x442432 : 0x140e15)
    rig.rimMaterial.color.setHex(selectedLayer ? 0xf0bccc : 0xa391a0)
    if (immediate || reducedMotion.value) {
      rig.group.position.x = rig.targetX
      rig.group.position.y = rig.targetY
      rig.group.position.z = rig.targetZ
      rig.group.rotation.z = rig.targetTilt
      rig.group.rotation.x = rig.targetPitch
      rig.lid.rotation.x = rig.targetOpen
    }
    index++
  }
  requestRender()
}

function setExploded() {
  exploded.value = !exploded.value
  updateSelection(reducedMotion.value)
  requestRender()
}

function setClearShell() {
  clearShell.value = !clearShell.value
  if (shellGlass) shellGlass.opacity = clearShell.value ? 0.055 : 0.15
  if (shellFrost) shellFrost.opacity = clearShell.value ? 0.065 : 0.27
  requestRender()
}

function render(time: number) {
  frame = 0
  if (!renderer || !scene || !camera || !assembly || !active.value) return
  // Keep the idle specimen at about 30 fps; selection and drag stay responsive.
  if (!reducedMotion.value && time - previousFrame < 31) {
    frame = requestAnimationFrame(render)
    return
  }
  const timeStep = Math.min(50, Math.max(0, time - previousFrame))
  previousFrame = time
  const settle = reducedMotion.value ? 1 : 1 - Math.exp(-timeStep / 135)
  for (const rig of cardRigs.values()) {
    rig.group.position.x += (rig.targetX - rig.group.position.x) * settle
    rig.group.position.y += (rig.targetY - rig.group.position.y) * settle
    rig.group.position.z += (rig.targetZ - rig.group.position.z) * settle
    rig.group.rotation.z += (rig.targetTilt - rig.group.rotation.z) * settle
    rig.group.rotation.x += (rig.targetPitch - rig.group.rotation.x) * settle
    rig.lid.rotation.x += (rig.targetOpen - rig.lid.rotation.x) * settle
  }
  const explodeScale = (stage.value?.clientWidth ?? 600) < 420 ? 0.65 : 1
  for (const rig of explodeRigs) {
    const distance = exploded.value ? explodeScale : 0
    rig.group.position.x += (rig.base.x + rig.offset.x * distance - rig.group.position.x) * settle
    rig.group.position.y += (rig.base.y + rig.offset.y * distance - rig.group.position.y) * settle
    rig.group.position.z += (rig.base.z + rig.offset.z * distance - rig.group.position.z) * settle
  }
  if (!reducedMotion.value) {
    currentAngle += (targetAngle - currentAngle) * Math.min(1, timeStep * 0.013)
    currentPitch += (targetPitch - currentPitch) * Math.min(1, timeStep * 0.013)
    if (rings) rings.rotation.y += timeStep * 0.00022
    if (core) core.rotation.y -= timeStep * 0.00008
  } else {
    currentAngle = targetAngle
    currentPitch = targetPitch
  }
  assembly.rotation.set(currentPitch, currentAngle, 0)
  renderer.render(scene, camera)
  if (!reducedMotion.value) frame = requestAnimationFrame(render)
}

function requestRender() {
  if (!frame && active.value && renderer) frame = requestAnimationFrame(render)
}

function resize() {
  if (!renderer || !camera || !stage.value) return
  const width = Math.max(1, stage.value.clientWidth)
  const height = Math.max(1, stage.value.clientHeight)
  renderer.setSize(width, height, false)
  camera.aspect = width / height
  camera.position.z = width < 420 ? 8.05 : 7.2
  camera.updateProjectionMatrix()
  requestRender()
}

function scenePointer(event: PointerEvent) {
  if (!stage.value || !renderer || !raycaster || !camera || !cards) return
  const rect = renderer.domElement.getBoundingClientRect()
  pointer.set((event.clientX - rect.left) / rect.width * 2 - 1, -(event.clientY - rect.top) / rect.height * 2 + 1)
  raycaster.setFromCamera(pointer, camera)
  const hit = raycaster.intersectObjects(cards.children, true).find(item => typeof item.object.userData.id === 'string')
  if (hit) emit('select', hit.object.userData.id as string)
}

function pointerDown(event: PointerEvent) {
  if (fallback.value || !stage.value) return
  dragStart = { x: event.clientX, y: event.clientY, angle: targetAngle, pitch: targetPitch }
  dragged = false
  stage.value.setPointerCapture(event.pointerId)
}

function pointerMove(event: PointerEvent) {
  if (!dragStart || !stage.value) return
  const dx = event.clientX - dragStart.x
  const dy = event.clientY - dragStart.y
  if (Math.abs(dx) + Math.abs(dy) > 6) dragged = true
  if (!dragged) return
  targetAngle = dragStart.angle + dx * 0.008
  targetPitch = THREE.MathUtils.clamp(dragStart.pitch + dy * 0.005, -0.45, 0.45)
  requestRender()
}

function pointerUp(event: PointerEvent) {
  if (!dragStart) return
  if (!dragged) scenePointer(event)
  dragStart = undefined
}

function turn(direction: number) {
  targetAngle += direction * Math.PI / 5
  requestRender()
}

function choose(entry: ArchiveEntry) {
  emit('select', entry.id)
}

function openSelected() {
  if (selected.value?.status === 'available' && !props.loading) emit('open', selected.value.id)
}

function motionChanged() {
  reducedMotion.value = motionQuery?.matches ?? false
  if (reducedMotion.value) {
    cancelAnimationFrame(frame)
    frame = 0
    updateSelection(true)
  }
  requestRender()
}

function initScene() {
  if (!stage.value) return
  try {
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'low-power' })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5))
    renderer.outputColorSpace = THREE.SRGBColorSpace
    renderer.domElement.setAttribute('aria-hidden', 'true')
    stage.value.appendChild(renderer.domElement)
    scene = new THREE.Scene()
    camera = new THREE.PerspectiveCamera(37, 1, 0.1, 30)
    camera.position.set(0, 0, 7.6)
    scene.add(new THREE.AmbientLight(0xd9c4d0, 1.15))
    const light = new THREE.DirectionalLight(0xffd6e5, 2.2)
    light.position.set(-3, 4, 5)
    scene.add(light)
    const rimLight = new THREE.DirectionalLight(0x8ec4d0, 1.5)
    rimLight.position.set(3, -2, -4)
    scene.add(rimLight)
    assembly = new THREE.Group()
    assembly.position.x = -0.18
    assembly.scale.set(1.2, 1.08, 1.2)
    scene.add(assembly)
    cards = new THREE.Group()
    assembly.add(cards)
    raycaster = new THREE.Raycaster()
    buildHousing()
    buildCards()
    resizeObserver = new ResizeObserver(resize)
    resizeObserver.observe(stage.value)
    intersectionObserver = new IntersectionObserver(([entry]) => {
      active.value = Boolean(entry?.isIntersecting) && !document.hidden
      if (active.value) requestRender()
      else { cancelAnimationFrame(frame); frame = 0 }
    }, { threshold: 0.01 })
    intersectionObserver.observe(stage.value)
    document.addEventListener('visibilitychange', visibilityChanged)
    renderer.domElement.addEventListener('webglcontextlost', contextLost, { passive: false })
    resize()
  } catch {
    fallback.value = true
    disposeScene()
  }
}

function visibilityChanged() {
  active.value = !document.hidden && Boolean(stage.value?.getBoundingClientRect().height)
  if (active.value) requestRender()
  else { cancelAnimationFrame(frame); frame = 0 }
}

function contextLost(event: Event) {
  event.preventDefault()
  fallback.value = true
  disposeScene()
}

function disposeScene() {
  cancelAnimationFrame(frame)
  frame = 0
  resizeObserver?.disconnect()
  intersectionObserver?.disconnect()
  document.removeEventListener('visibilitychange', visibilityChanged)
  renderer?.domElement.removeEventListener('webglcontextlost', contextLost)
  removeCards()
  geometries.forEach(geometry => geometry.dispose())
  materials.forEach(material => material.dispose())
  geometries.length = 0
  materials.length = 0
  renderer?.dispose()
  renderer?.domElement.remove()
  renderer = undefined
  scene = undefined
  camera = undefined
  assembly = undefined
  core = undefined
  rings = undefined
  cards = undefined
  raycaster = undefined
  shellGlass = undefined
  shellFrost = undefined
  explodeRigs.length = 0
}

onMounted(() => {
  motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
  reducedMotion.value = motionQuery.matches
  motionQuery.addEventListener('change', motionChanged)
  initScene()
})

onBeforeUnmount(() => {
  motionQuery?.removeEventListener('change', motionChanged)
  disposeScene()
})

watch(visibleEntries, () => {
  if (renderer) buildCards()
}, { deep: true })

watch([() => props.selectedId, () => props.loading, () => props.readStatus], () => {
  updateSelection(false)
})
</script>

<template>
  <section class="life-archive" aria-label="生命档案核心">
    <div class="archive-stage" ref="stage" @pointerdown="pointerDown" @pointermove="pointerMove"
      @pointerup="pointerUp" @pointercancel="dragStart = undefined">
      <div v-if="fallback" class="archive-fallback" aria-hidden="true">
        <div class="fallback-vessel"><div class="fallback-seed"></div><i v-for="n in 7" :key="n"></i></div>
      </div>
      <div class="stage-id">SYLANNE / LIFE ARCHIVE</div>
      <div class="stage-caption">{{ entries.length ? `${entries.length} 条服务端目录项` : '等待真实档案目录' }}</div>
      <div v-if="!fallback" class="stage-hint">拖动旋转 · 点选档案片抽取</div>
      <div v-if="!fallback" class="stage-controls" aria-label="模型旋转" @pointerdown.stop>
        <button type="button" @click.stop="turn(-1)" aria-label="向左旋转模型">↶</button>
        <button type="button" @click.stop="turn(1)" aria-label="向右旋转模型">↷</button>
        <button type="button" class="stage-action" :aria-pressed="clearShell" :aria-label="clearShell ? '切换磨砂外壳' : '切换清晰外壳'" @click.stop="setClearShell">{{ clearShell ? '磨砂' : '清晰' }}</button>
        <button type="button" class="stage-action" :aria-pressed="exploded" :aria-label="exploded ? '重组档案核心' : '拆解档案核心'" @click.stop="setExploded">{{ exploded ? '重组' : '拆解' }}</button>
      </div>
    </div>
    <div class="archive-ledger">
      <div class="ledger-top"><span>ARCHIVE LAYERS</span><span>{{ entries.length ? `${entries.length} / SERVER INDEX` : 'NO CATALOGUE' }}</span></div>
      <div v-if="entries.length" class="layer-list" role="list" aria-label="档案层">
        <div v-for="entry in entries" :key="entry.id" role="listitem">
          <button type="button" class="layer-row" :class="{ selected: selectedId === entry.id }"
            :aria-pressed="selectedId === entry.id" @click="choose(entry)">
            <span class="layer-id">{{ entry.id }}</span><span class="layer-name">{{ entry.label }}</span>
            <span class="layer-status">{{ entry.status === 'available' ? '可读取' : '暂不可用' }}</span>
          </button>
        </div>
      </div>
      <p v-else class="ledger-empty">解锁 Owner 会话并读取范围后，服务端返回的目录会进入档案核心。</p>
      <div v-if="selected" class="selected-layer">
        <div><small>EXTRACTED LAYER</small><strong>{{ selected.label }}</strong><span>{{ selected.detail || (selected.status === 'available' ? '可读取服务端投影' : '服务端标记为不可用') }}</span></div>
        <button type="button" :disabled="selected.status !== 'available' || loading" @click="openSelected">
          {{ loading ? '读取中…' : '展开档案' }}
        </button>
      </div>
      <p v-if="readStatus && selected" class="read-state">视图读取状态：{{ readStatus }}</p>
    </div>
  </section>
</template>

<style scoped>
.life-archive{border:1px solid #c8c5bd;background:#eceae4;color:#242525;min-width:0;box-shadow:0 18px 44px #0b0e1022}
.archive-stage{height:340px;position:relative;overflow:hidden;touch-action:none;background:linear-gradient(90deg,transparent calc(50% - .5px),#ffffff0a 50%,transparent calc(50% + .5px)),radial-gradient(ellipse at 48% 47%,#b88a9e20,transparent 42%),radial-gradient(ellipse at 54% 79%,#8bb5bc0e,transparent 52%),#181a1d;cursor:grab;user-select:none}
.archive-stage:active{cursor:grabbing}.archive-stage :deep(canvas){display:block;width:100%;height:100%}
.stage-id,.stage-caption{position:absolute;left:18px;font:10px var(--font-mono,monospace);letter-spacing:.15em;pointer-events:none}
.stage-id{top:18px;color:#ead4bd}.stage-caption{bottom:18px;color:#b7aa9c;letter-spacing:.04em}
.stage-hint{position:absolute;top:19px;right:18px;color:#a89b90;font:10px var(--font-mono,monospace);pointer-events:none}
.stage-controls{position:absolute;right:16px;bottom:14px;display:flex;gap:7px}.stage-controls button{background:#222528e8;border:1px solid #d6b89088;color:#e9d7ba;min-width:34px;height:30px;font-size:20px;line-height:1;cursor:pointer}.stage-controls button[aria-pressed="true"]{background:#c19865;color:#1c1c1a}.stage-controls .stage-action{font:10px var(--font-mono,monospace);padding:0 9px}
.archive-ledger{border-top:3px solid #c99d66;padding:18px;background:#eceae4}.ledger-top{display:flex;justify-content:space-between;color:#716c63;font:10px var(--font-mono,monospace);letter-spacing:.13em}
.layer-list{max-height:202px;overflow:auto;margin-top:12px;scrollbar-color:#b8b3a8 #e5e2da}.layer-row{width:100%;border:0;border-bottom:1px solid #c8c4bb;background:transparent;color:#252626;display:grid;grid-template-columns:minmax(60px,.8fr) minmax(0,1.4fr) auto;gap:12px;text-align:left;align-items:center;padding:9px 10px;cursor:pointer;font:11px var(--font-mono,monospace)}
.layer-row:hover,.layer-row.selected{background:#d9d2c6}.layer-row.selected{box-shadow:inset 3px 0 #ba7e39}.layer-id{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#5e5b57}.layer-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.layer-status{color:#6c6760;font-size:10px;white-space:nowrap}.ledger-empty{padding:18px 4px;color:#6c6862;font-size:12px;line-height:1.6}
.selected-layer{margin-top:14px;border:1px solid #bcad98;background:#e2dcd1;padding:13px;display:flex;gap:12px;align-items:center;justify-content:space-between}.selected-layer div{display:flex;flex-direction:column;gap:5px;min-width:0}.selected-layer small{color:#946e43;font:9px var(--font-mono,monospace);letter-spacing:.1em}.selected-layer strong{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.selected-layer span{color:#615b54;font-size:11px}.selected-layer button{flex:none;background:#bc8747;color:#201c17;border:0;padding:9px 12px;font:11px var(--font-mono,monospace);cursor:pointer}.selected-layer button:disabled{opacity:.45;cursor:not-allowed}.read-state{font:10px var(--font-mono,monospace);color:#706b64;margin:10px 0 0}
button:focus-visible{outline:2px solid #a0682f;outline-offset:2px}
.archive-fallback{position:absolute;inset:0;display:grid;place-items:center}.fallback-vessel{width:150px;height:270px;border:2px solid #c49eaf88;border-radius:56px 56px 24px 24px;background:linear-gradient(110deg,#b88a9e08,#b88a9e1c,#8bb5bc0a);box-shadow:inset 12px 0 26px #ddb2c010,0 0 42px #b88a9e16;position:relative;display:flex;flex-direction:column;justify-content:space-evenly;padding:35px 22px}.fallback-vessel i{height:3px;border:1px solid #b88a9e88;background:#b88a9e2b;transform:skewY(-8deg)}.fallback-seed{position:absolute;left:50%;top:50%;width:37px;height:49px;transform:translate(-50%,-50%) rotate(45deg);border:1px solid #e9b8cc;background:#b88a9e55;box-shadow:0 0 24px #b88a9e77}
@media(max-width:700px){.archive-stage{height:300px}.archive-ledger{padding:13px}.layer-row{grid-template-columns:minmax(55px,.7fr) minmax(0,1fr) auto;gap:7px;font-size:10px}.selected-layer{align-items:stretch;flex-direction:column}.selected-layer button{align-self:flex-start}.stage-hint{top:39px;left:18px;right:auto;font-size:9px}.stage-caption{bottom:53px}.stage-controls{left:12px;right:auto;bottom:10px;gap:6px}}
@media(prefers-reduced-motion:reduce){.archive-stage{scroll-behavior:auto}}
</style>
