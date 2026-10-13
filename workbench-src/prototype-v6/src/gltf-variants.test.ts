import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import * as THREE from 'three'
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js'
import { demoEntries } from './arc-engine.ts'
import { inspectModel, requiredNodes } from './arc-model.ts'

const expectedIdentities = [
  { id: 'demo-persona', number: '01', title: '人格方案', icon: 'persona' },
  { id: 'demo-memory', number: '02', title: '记忆来源', icon: 'memory' },
  { id: 'demo-life', number: '03', title: '生活档案', icon: 'life' },
  { id: 'demo-contact', number: '04', title: '主动联系', icon: 'contact' },
  { id: 'demo-access', number: '05', title: '访问状态', icon: 'access' },
  { id: 'demo-logs', number: '06', title: '运行日志', icon: 'logs' },
  { id: 'demo-settings', number: '07', title: '插件设置', icon: 'settings' },
]

function parseGlbFile(filename: string) {
  const bytes = fs.readFileSync(new URL(`../public/models/${filename}`, import.meta.url))
  assert.equal(bytes.readUInt32LE(0), 0x46546c67)
  assert.equal(bytes.readUInt32LE(4), 2)
  assert.equal(bytes.readUInt32LE(8), bytes.length)
  const jsonLength = bytes.readUInt32LE(12)
  assert.equal(bytes.readUInt32LE(16), 0x4e4f534a)
  const json = JSON.parse(bytes.subarray(20, 20 + jsonLength).toString('utf8'))
  const binaryOffset = 20 + jsonLength
  const binaryLength = bytes.readUInt32LE(binaryOffset)
  assert.equal(bytes.readUInt32LE(binaryOffset + 4), 0x004e4942)
  assert.equal(binaryOffset + 8 + binaryLength, bytes.length)
  return { json, binary: bytes.subarray(binaryOffset + 8), bytes }
}

test('v18 GLB adds two actual embedded label variants without changing original geometry or materials', () => {
  const original = parseGlbFile('sylanne-archive-v12.glb')
  const current = parseGlbFile('sylanne-archive-v18.glb')
  const gltf = current.json
  assert.deepEqual(demoEntries.map(({ id, title }) => ({ id, title })), expectedIdentities.map(({ id, title }) => ({ id, title })))
  assert.equal(gltf.scenes.length, 7)
  assert.equal(gltf.images.length, 7)
  assert.equal(gltf.textures.length, 7)
  assert.equal(gltf.scene, original.json.scene)
  for (const key of ['accessors', 'samplers', 'animations']) {
    assert.deepEqual(gltf[key], original.json[key], `${key} is unchanged`)
  }
  for (const key of ['nodes', 'scenes', 'meshes', 'materials', 'images', 'textures', 'bufferViews']) {
    assert.deepEqual(gltf[key].slice(0, original.json[key].length), original.json[key], `${key} original items are unchanged`)
  }
  assert.deepEqual(current.binary.subarray(0, original.binary.length), original.binary, 'Original geometry and embedded pixel bytes are exact-preserved')
  const meshIndices = new Set<number>()
  const materialIndices = new Set<number>()
  const imageViews = new Set<number>()
  const firstLabel = gltf.nodes.find((node: any) => node.extras?.entryId === 'demo-persona')
  const firstPrimitive = gltf.meshes[firstLabel.mesh].primitives[0]
  for (const [index, identity] of expectedIdentities.entries()) {
    const scene = gltf.scenes[index]
    assert.equal(scene.name, identity.id)
    assert.deepEqual(scene.extras, { entryId: identity.id, label: identity.title })
    const nodes: any[] = []
    const collect = (nodeIndex: number) => {
      const node = gltf.nodes[nodeIndex]
      nodes.push(node)
      node.children?.forEach(collect)
    }
    scene.nodes.forEach(collect)
    const labels = nodes.filter(node => node.name === 'ARCHIVE_label')
    assert.equal(labels.length, 1, identity.id)
    const label = labels[0]
    assert.deepEqual(label.extras, { entryId: identity.id, number: identity.number, title: identity.title, icon: identity.icon })
    const mesh = gltf.meshes[label.mesh]
    const primitive = mesh.primitives[0]
    assert.equal(mesh.name, `MESH_label_${identity.id}`)
    assert.deepEqual(primitive.attributes, firstPrimitive.attributes, 'All labels share the original subtle frame-print geometry')
    assert.equal(primitive.indices, firstPrimitive.indices)
    const material = gltf.materials[primitive.material]
    assert.equal(material.name, `MAT_label_${identity.id}`)
    assert.equal(material.alphaMode, 'MASK')
    assert.equal(material.alphaCutoff, .32)
    assert.equal(material.doubleSided, false)
    assert.deepEqual(material.pbrMetallicRoughness.baseColorFactor, [1, 1, 1, 1])
    assert.equal(material.pbrMetallicRoughness.metallicFactor, 0)
    assert.equal(material.pbrMetallicRoughness.roughnessFactor, .7)
    assert.equal(material.pbrMetallicRoughness.baseColorTexture.index, index)
    const texture = gltf.textures[index]
    assert.equal(texture.source, index)
    const image = gltf.images[texture.source]
    assert.equal(image.name, `${identity.id}-embedded-nameplate`)
    assert.equal(image.mimeType, 'image/png')
    assert.equal(image.uri, undefined, 'Labels must not depend on external texture files')
    const view = gltf.bufferViews[image.bufferView]
    assert.equal(view.buffer, 0)
    const png = current.binary.subarray(view.byteOffset, view.byteOffset + view.byteLength)
    assert.deepEqual([...png.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10])
    assert.equal(png.subarray(12, 16).toString(), 'IHDR')
    assert.equal(png.readUInt32BE(16), 1240)
    assert.equal(png.readUInt32BE(20), 192)
    assert.equal(png[25], 6, 'Embedded label keeps RGBA for transparent frame printing')
    meshIndices.add(label.mesh)
    materialIndices.add(primitive.material)
    imageViews.add(image.bufferView)
    for (const name of requiredNodes) assert.equal(nodes.filter(node => node.name === name).length, 1, `${identity.id} / ${name}`)
  }
  assert.equal(meshIndices.size, 7)
  assert.equal(materialIndices.size, 7)
  assert.equal(imageViews.size, 7)
})

test('actual GLTFLoader preserves seven entry identities despite global node-name deduplication', async () => {
  // CPU-only parse: replace image decoding, but exercise the installed loader's
  // real scene/node naming, extras, mesh, material and texture binding behavior.
  // This does not create a browser, a WebGL context, or a network request.
  const loader = new GLTFLoader()
  loader.register(() => ({
    name: 'TEST_LOCAL_TEXTURE_STUB',
    loadTexture(index: number) {
      const texture = new THREE.Texture()
      texture.userData.textureIndex = index
      return Promise.resolve(texture)
    },
  }))
  const { bytes } = parseGlbFile('sylanne-archive-v18.glb')
  const gltf = await loader.parseAsync(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength), '')
  assert.equal(gltf.scenes.length, demoEntries.length)
  const labels: THREE.Mesh[] = []
  const textures = new Set<THREE.Texture>()
  for (const [index, entry] of demoEntries.entries()) {
    const scenes = gltf.scenes.filter(scene => scene.userData.entryId === entry.id)
    assert.equal(scenes.length, 1, `Expected exactly one scene for ${entry.id}`)
    const matches: THREE.Mesh[] = []
    scenes[0]!.traverse(node => {
      if (node instanceof THREE.Mesh && node.userData.entryId === entry.id) matches.push(node)
    })
    assert.equal(matches.length, 1, `Expected exactly one entry-tagged nameplate for ${entry.id}`)
    const label = matches[0]!
    labels.push(label)
    assert.equal(label.userData.title, entry.title)
    assert.equal(label.userData.number, String(index + 1).padStart(2, '0'))
    assert.equal(label.userData.icon, expectedIdentities[index]!.icon)
    assert.ok(label.material instanceof THREE.MeshStandardMaterial)
    assert.equal(label.material.name, `MAT_label_${entry.id}`)
    assert.equal(label.material.alphaTest, .32)
    assert.equal(label.material.transparent, false)
    label.geometry.computeBoundingBox()
    const bounds=label.geometry.boundingBox!
    assert.ok(bounds.max.y-bounds.min.y<.3)
    assert.ok(bounds.min.y>1.3)
    assert.ok(bounds.max.z<.41)
    assert.ok(label.material.map instanceof THREE.Texture)
    assert.equal(label.material.map.userData.textureIndex, index)
    textures.add(label.material.map)
  }
  assert.equal(textures.size, demoEntries.length)
  assert.equal(new Set(labels.map(label => label.name)).size, demoEntries.length)
  assert.equal(labels[0]!.name, 'ARCHIVE_label')
  assert.notEqual(labels[1]!.name, 'ARCHIVE_label', 'Loader renames duplicate node names across scenes')

  const nodes = inspectModel(gltf.scene)
  for (const name of requiredNodes) assert.ok(nodes.get(name), name)
  assert.equal(nodes.get('ARCHIVE_label'), labels[0])
  assert.ok(inspectModel(gltf.scene.clone(true)).get('ARCHIVE_label'))

  // Ensure the runtime uses the stable identity this parse regression validates.
  const runtime = fs.readFileSync(new URL('./ArchiveArc.vue', import.meta.url), 'utf8')
  assert.match(runtime, /n\.userData\.entryId===entry\.id/)
  assert.doesNotMatch(runtime, /variant\?\.getObjectByName\(['"]ARCHIVE_label['"]\)/)
  textures.forEach(texture => texture.dispose())
})

test('actual label fade code invalidates its shader only at transparency boundaries', () => {
  const runtime = fs.readFileSync(new URL('./ArchiveArc.vue', import.meta.url), 'utf8')
  const start = runtime.indexOf('labelMaterial.map=')
  const end = runtime.indexOf(";item.nodes.get('LID_panel')", start)
  assert.ok(start > 0 && end > start)
  const applyLabel = Function('labelMaterial', 'labelVariants', 'slot', 'props={}', 'exit={opacity:1}', 'themeSceneMaterial=()=>{}', stripTypeScriptTypes(runtime.slice(start, end)))
  const material = new THREE.MeshStandardMaterial()
  const variants = [{ map: new THREE.Texture() }, { map: new THREE.Texture() }]
  const version = material.version
  applyLabel(material, variants, { index: 0, opacity: 1 })
  assert.equal(material.version, version)
  applyLabel(material, variants, { index: 1, opacity: 0.6 })
  assert.equal(material.map, variants[1]!.map)
  assert.equal(material.opacity, 0.6)
  assert.equal(material.transparent, true)
  assert.equal(material.depthWrite, false)
  assert.equal(material.version, version + 1)
  applyLabel(material, variants, { index: 1, opacity: 0.2 })
  assert.equal(material.version, version + 1, 'Continuous fading must not recompile every frame')
  applyLabel(material, variants, { index: 0, opacity: 1 })
  assert.equal(material.transparent, false)
  assert.equal(material.depthWrite, true)
  assert.equal(material.version, version + 2)
  material.dispose()
  variants.forEach(variant => variant.map.dispose())
})

test('parsed-scene texture ownership is registered before cancelled-load disposal', () => {
  const runtime = fs.readFileSync(new URL('./ArchiveArc.vue', import.meta.url), 'utf8')
  const parsed = runtime.indexOf('const gltf=await new GLTFLoader().parseAsync')
  const registration = runtime.indexOf('for(const variant of gltf.scenes)', parsed)
  const cancelled = runtime.indexOf('if(!alive)', parsed)
  assert.ok(parsed >= 0 && registration > parsed && cancelled > registration)
  const registrationCode = runtime.slice(registration, cancelled)
  assert.match(registrationCode, /variant\.traverse/)
  assert.match(registrationCode, /ownedMaterials\.add\(m\)/)
  assert.match(registrationCode, /ownedTextures\.add\(m\.map\)/)
  assert.match(runtime.slice(cancelled), /^if\(!alive\)\{template=gltf\.scene;dispose\(\);return\}/)
})

test('actual disposal closes shared bitmap data once after disposing all textures', () => {
  const runtime = fs.readFileSync(new URL('./ArchiveArc.vue', import.meta.url), 'utf8')
  const start = runtime.indexOf('function dispose(){')
  const end = runtime.indexOf('async function init()', start)
  assert.ok(start > 0 && end > start)
  const calls: string[] = []
  const sharedBitmap = { close() { calls.push('shared-close') } }
  const otherBitmap = { close() { calls.push('other-close') } }
  const first = new THREE.Texture(sharedBitmap)
  const second = new THREE.Texture(sharedBitmap)
  const third = new THREE.Texture(otherBitmap)
  for (const [index, texture] of [first, second, third].entries()) {
    texture.addEventListener('dispose', () => calls.push(`texture-${index}`))
  }
  const textures = new Set([first, second, third])
  const dispose = Function('THREE', 'template', 'pool', 'ownedMaterials', 'ownedTextures', 'renderer',
    stripTypeScriptTypes(runtime.slice(start, end)) + ';return dispose')(
    THREE, new THREE.Group(), [], new Set<THREE.Material>(), textures, null)
  dispose()
  assert.deepEqual(calls, ['texture-0', 'texture-1', 'texture-2', 'shared-close', 'other-close'])
  assert.equal(textures.size, 0)
  dispose()
  assert.equal(calls.length, 5, 'A later teardown must not close disposed images again')
})
