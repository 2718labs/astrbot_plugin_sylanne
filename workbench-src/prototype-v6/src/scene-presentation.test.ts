import {test} from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import * as THREE from 'three'
import {GLTFLoader} from 'three/addons/loaders/GLTFLoader.js'
import {ArcEngine,visibleSlots} from './arc-engine.ts'
import {slotTransform,inspectModel} from './arc-model.ts'
import {sceneViewport,pointerNdc,exitScenePose,sceneExitFrame,sceneLighting,themeSceneMaterial,labelInkColor,LABEL_INK_SHADER} from './scene-presentation.ts'
import {readingMaterial} from './read-material.ts'
const sizes=[[320,700],[375,812],[768,1024],[1024,768],[1280,800],[1920,1080],[2560,1440],[320,240],[375,180],[768,300],[2560,500],[1024,1600]]
function cameraFor(width:number,height:number,dpr=1){const v=sceneViewport(width,height,dpr),camera=new THREE.OrthographicCamera(-v.halfWidth,v.halfWidth,v.halfHeight,-v.halfHeight,.1,80);camera.position.set(0,0,20);camera.lookAt(0,0,0);camera.updateProjectionMatrix();camera.updateMatrixWorld();return {v,camera}}
test('all viewport classes preserve aspect without nonuniform distortion or DPR-dependent projection',()=>{
 for(const [width,height] of sizes){const {v,camera}=cameraFor(width!,height!);assert.ok(Math.abs((camera.right-camera.left)/(camera.top-camera.bottom)-width!/height!)<1e-12);for(const dpr of[1,1.25,1.5,2,3]){const next=cameraFor(width!,height!,dpr);assert.deepEqual(next.camera.projectionMatrix.elements,camera.projectionMatrix.elements);assert.ok(next.v.dpr<=1.5)}assert.equal(v.rootY-v.halfHeight+2*v.halfHeight,5)}
})
test('CPU-loaded official GLB remains visible and raycastable across dynamic resize and portrait/short classes',async()=>{
 const bytes=fs.readFileSync(new URL('../public/models/sylanne-archive-v18.glb',import.meta.url)),loader=new GLTFLoader()
 loader.register(()=>({name:'CPU_TEXTURE_STUB',loadTexture:()=>Promise.resolve(new THREE.Texture())}))
 const gltf=await loader.parseAsync(bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength),'')
 const root=gltf.scene,nodes=inspectModel(root),hit=nodes.get('HIT_archive')!,engine=new ArcEngine(),state=engine.snapshot(),initial=JSON.stringify(state)
 const scene=new THREE.Scene(),shared=new THREE.Group();scene.add(shared);shared.add(root)
 for(const [width,height]of[...sizes,...sizes.slice().reverse()]){
  const {v,camera}=cameraFor(width!,height!),slot=visibleSlots(state.position,state.count).find(s=>s.logical===state.logical)!,t=slotTransform(slot,state,v.layoutAspect)
  shared.position.y=v.rootY;root.position.set(t.x,t.y,t.z);root.rotation.set(t.rotationX,t.rotationY,t.rotationZ,t.rotationOrder);root.scale.setScalar(t.scale);scene.updateMatrixWorld(true)
  const label=nodes.get('ARCHIVE_label')!,labelCenter=new THREE.Box3().setFromObject(label).getCenter(new THREE.Vector3()).project(camera)
  assert.ok(Math.abs(labelCenter.x)<1&&Math.abs(labelCenter.y)<1,`embedded label in ${width}x${height}: ${labelCenter.toArray()}`)
  const center=new THREE.Box3().setFromObject(hit).getCenter(new THREE.Vector3()),projected=center.clone().project(camera)
  assert.ok(Math.abs(projected.x)<1&&Math.abs(projected.y)<1,`focused hit center in ${width}x${height}: ${projected.toArray()}`)
  const box={left:31,top:47,width:width!,height:height!},ndc=pointerNdc(box.left+(projected.x+1)*box.width/2,box.top+(1-projected.y)*box.height/2,box)!
  const ray=new THREE.Raycaster();ray.setFromCamera(new THREE.Vector2(ndc.x,ndc.y),camera);assert.ok(ray.intersectObject(hit,false).length>0,`actual model hit in ${width}x${height}`)
  const plusX=center.clone().add(new THREE.Vector3(1,0,0)).project(camera),plusY=center.clone().add(new THREE.Vector3(0,1,0)).project(camera)
  assert.ok(Math.abs((plusX.x-projected.x)*width!-(plusY.y-projected.y)*height!)<1e-8,'equal pixel units on both axes')
  assert.equal(JSON.stringify(engine.snapshot()),initial,'resize never resets engine state');assert.equal(t.z,slot.offset*1.7)
 }
})
test('pointer coordinates account for viewport offset and reject empty hosts',()=>{assert.deepEqual(pointerNdc(150,250,{left:50,top:50,width:200,height:400}),{x:0,y:0});assert.equal(pointerNdc(0,0,{left:0,top:0,width:0,height:10}),null)})
test('dark and light theme switches preserve embedded label identity and update ink without repeat compilation',()=>{
 const label=new THREE.MeshStandardMaterial({map:new THREE.Texture(),alphaTest:.32}),map=label.map!,version=label.version
 themeSceneMaterial(label,'ARCHIVE_label','dark');assert.equal(label.map,map);assert.equal(label.userData.archiveDarkInk.value,1);assert.equal(label.alphaTest,.32);assert.equal(label.version,version+1)
 themeSceneMaterial(label,'ARCHIVE_label','dark');assert.equal(label.version,version+1)
 themeSceneMaterial(label,'ARCHIVE_label','light');assert.equal(label.map,map);assert.equal(label.emissiveMap,null);assert.equal(label.version,version+1);assert.equal(label.userData.archiveDarkInk.value,0)
 const shell=new THREE.MeshStandardMaterial({name:'MAT_archive_shell',opacity:.7});shell.userData.originalOpacity=.7
 readingMaterial(shell,'ARCHIVE_body',1,0,'available');const original=shell.color.clone();themeSceneMaterial(shell,'ARCHIVE_body','dark');assert.notDeepEqual(shell.color,original);assert.equal(shell.opacity,.7)
 readingMaterial(shell,'ARCHIVE_body',1,0,'available');themeSceneMaterial(shell,'ARCHIVE_body','light');assert.deepEqual(shell.color,original)
 assert.notDeepEqual(sceneLighting('dark'),sceneLighting('light'))
})
test('logout transforms and relaxation are continuous, bounded and snapshot-only',()=>{
 const engine=new ArcEngine(),frame={...engine.snapshot(),repulsion:[{logical:1,angle:.04,velocity:.01}]},copy=JSON.stringify(frame)
 assert.equal(sceneExitFrame(frame,0),frame)
 let previous=1
 for(let i=0;i<=100;i++){const progress=i/100,pose=exitScenePose(progress),exit=sceneExitFrame(frame,progress);assert.ok(pose.opacity<=previous&&pose.opacity>=0);assert.equal(exit.position,frame.position);assert.equal(exit.phase,frame.phase);assert.equal(exit.logical,frame.logical);assert.ok(Math.abs(exit.repulsion![0]!.angle)<=.04);previous=pose.opacity}
 assert.equal(exitScenePose(1).opacity,0);assert.equal(sceneExitFrame(frame,1).repulsion![0]!.angle,0);assert.equal(JSON.stringify(frame),copy)
})
test('runtime observes element resize and DPR changes with explicit teardown and no engine replacement',()=>{const source=fs.readFileSync(new URL('./ArchiveArc.vue',import.meta.url),'utf8');assert.match(source,/new ResizeObserver\(resize\)/);assert.match(source,/window\.visualViewport\?\.addEventListener\('resize',resize/);assert.match(source,/dprQuery\?\.removeEventListener\('change',onDprChange\)/);assert.match(source,/camera\.updateMatrixWorld\(\)/);assert.doesNotMatch(source,/new ArcEngine|filter:\s*invert|models\/.*v20/);assert.match(source,/sylanne-archive-v18\.glb/)})

test('embedded ink shader changes RGB only, retains alpha and restores original light color exactly',()=>{
 const ink=new THREE.Color('#34434a'),dark=labelInkColor(ink,'dark'),light=labelInkColor(ink,'light')
 assert.deepEqual(light,ink);assert.equal(dark.r,1-ink.r);assert.equal(dark.g,1-ink.g);assert.equal(dark.b,1-ink.b)
 const luminance=(color:THREE.Color)=>.2126*color.r+.7152*color.g+.0722*color.b
 for(const background of['#334752','#647984']){const shell=new THREE.Color(background);assert.ok((luminance(dark)+.05)/(luminance(shell)+.05)>4.3,`ink contrast on ${background}`)}
 const material=new THREE.MeshStandardMaterial({map:new THREE.Texture(),alphaTest:.32});themeSceneMaterial(material,'ARCHIVE_label','dark')
 const shader={uniforms:{},fragmentShader:'#include <map_fragment>\n#include <emissivemap_fragment>\n#include <alphatest_fragment>'}
 material.onBeforeCompile(shader as any,{} as any)
 assert.ok(shader.fragmentShader.includes(LABEL_INK_SHADER));assert.ok(shader.fragmentShader.includes('#include <alphatest_fragment>'));assert.doesNotMatch(LABEL_INK_SHADER,/\.a\s*=/)
 const uniforms=shader.uniforms as {archiveDarkInk:{value:number}};assert.equal(uniforms.archiveDarkInk.value,1);themeSceneMaterial(material,'ARCHIVE_label','light');assert.equal(uniforms.archiveDarkInk.value,0)
})
