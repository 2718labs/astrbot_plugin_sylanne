import {test} from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import * as THREE from 'three'
import {GLTFLoader} from 'three/addons/loaders/GLTFLoader.js'
import {ArcEngine,ARC_STEP_ANGLE,visibleSlots,type ArcSnapshot} from './arc-engine.ts'
import {slotTransform} from './arc-model.ts'
import {entryScenePose} from './entry-choreography.ts'
import {LogoutFlow,LOGOUT_DURATION,logoutVisuals} from './logout-flow.ts'
import {captureExitScene,sampleExitScene,sceneRootMatrix,sceneViewport,exitScenePose,EXIT_ARC_TURN} from './scene-presentation.ts'
import type {FetchLike,FetchResponse} from './api/client.ts'

const close=(actual:number,expected:number,tolerance=1e-10)=>assert.ok(Math.abs(actual-expected)<=tolerance,`${actual} ≈ ${expected}`)
const viewportSizes=[[320,700],[375,812],[768,1024],[1024,768],[1280,800],[1920,1080],[2560,1440],[320,240],[375,180],[768,300],[2560,500],[1024,1600]] as const
function cameraFor(width:number,height:number){
 const viewport=sceneViewport(width,height),camera=new THREE.OrthographicCamera(-viewport.halfWidth,viewport.halfWidth,viewport.halfHeight,-viewport.halfHeight,.1,80)
 camera.position.set(0,0,20);camera.lookAt(0,0,0);camera.updateProjectionMatrix();camera.updateMatrixWorld()
 return {viewport,camera}
}
function rapidWheel(direction:number){
 const engine=new ArcEngine();engine.update(0)
 for(let i=1;i<=20;i++){engine.wheel(direction*156.25,0,700,i*16);engine.update(i*16)}
 return engine
}

test('logout continues the entrance root Z direction, with no backwards segment or early opacity escape',()=>{
 assert.equal(entryScenePose(0).rootRotationZ,.12)
 assert.equal(Math.abs(entryScenePose(1).rootRotationZ),0)
 assert.equal(Math.abs(exitScenePose(0).rotationZ),0)
 assert.equal(EXIT_ARC_TURN,-2.25)
 assert.equal(exitScenePose(1).rotationZ,EXIT_ARC_TURN)
 let lastEntry=Infinity,lastExit=Infinity
 for(let i=0;i<=1000;i++){
  const p=i/1000,entry=entryScenePose(p),exit=exitScenePose(p)
  assert.ok(entry.rootRotationZ<=lastEntry);assert.ok(exit.rotationZ<=lastExit)
  if(p<=.94){assert.equal(exit.opacity,1);assert.equal(logoutVisuals(p).arc,1)}
  lastEntry=entry.rootRotationZ;lastExit=exit.rotationZ
 }
 assert.equal(exitScenePose(1).opacity,0)
})

test('exit pivot is exactly inert at progress zero across entry poses and every viewport class',()=>{
 const frame={...new ArcEngine().snapshot(),position:.43,phase:.61}
 for(const [width,height] of viewportSizes)for(const entryProgress of [0,.25,.8,1]){
  const {viewport}=cameraFor(width,height),pose=entryScenePose(entryProgress)
  const expected=new THREE.Matrix4().compose(new THREE.Vector3(pose.rootX,pose.rootY+viewport.rootY,pose.rootZ),new THREE.Quaternion().setFromEuler(new THREE.Euler(pose.rootRotationX,pose.rootRotationY,pose.rootRotationZ)),new THREE.Vector3(1,1,1))
  const actual=sceneRootMatrix(entryProgress,0,viewport.layoutAspect,viewport.rootY,frame)
  actual.elements.forEach((value,index)=>close(value,expected.elements[index]!))
 }
})

test('capture owns the displayed pose and repulsion before closing or cancelled dragging can mutate the engine',()=>{
 const selected=new ArcEngine();selected.update(0);selected.select(3);selected.update(16);selected.update(64)
 const dragged=new ArcEngine();dragged.beginDrag(400,0);dragged.drag(335,20)
 for(const engine of [selected,dragged]){
  const displayed=engine.snapshot(),before=JSON.stringify(displayed),velocity=engine.velocity,phaseVelocity=engine.phaseVelocity
  const captured=captureExitScene(displayed,velocity,phaseVelocity),sample=sampleExitScene(captured,0)
  assert.deepEqual(sample.frame,displayed);assert.deepEqual(sample.slots,visibleSlots(displayed.position,displayed.count))
  assert.notEqual(captured.frame,displayed);assert.notEqual(captured.frame.repulsion,displayed.repulsion);assert.notEqual(captured.frame.radial,displayed.radial)
  for(const [index,value] of (displayed.repulsion??[]).entries())assert.notEqual(captured.frame.repulsion![index],value)
  for(const [index,value] of (displayed.radial??[]).entries())assert.notEqual(captured.frame.radial![index],value)
  engine.back();engine.endDrag(true)
  if(engine===dragged)assert.equal(engine.velocity,0,'pointer cancellation clears live velocity only after capture')
  engine.update(120)
  assert.equal(JSON.stringify(captured.frame),before)
  assert.equal(captured.velocity,velocity);assert.equal(captured.phaseVelocity,phaseVelocity)
  for(const aspect of [.95,1.6,5.12])for(const slot of captured.slots){
   assert.deepEqual(slotTransform(slot,sample.frame,aspect),slotTransform(slot,displayed,aspect),'selected and drag exit starts from the displayed angle, depth and scale')
  }
 }
})

test('exit preserves every captured physical slot, label, edge opacity and depth while coasting across integer positions',()=>{
 for(const velocity of [-76,-12,-5,5,12,76]){
  const frame={...new ArcEngine().snapshot(),position:.999,phase:.42},captured=captureExitScene(frame,velocity,.8),before=JSON.stringify(captured)
  for(const progress of [0,.001,.1,.5,.94,1]){
   const {frame:next,slots}=sampleExitScene(captured,progress),delta=next.position-frame.position
   assert.equal(next.logical,frame.logical);assert.equal(next.selected,frame.selected);assert.equal(next.mode,frame.mode)
   for(const [index,slot] of slots.entries()){
    const original=captured.slots[index]!
    assert.deepEqual({...slot,angle:original.angle},original)
    close(slot.angle-original.angle,delta*ARC_STEP_ANGLE)
    close(slotTransform(slot,next,1.6).z,slotTransform(original,frame,1.6).z)
   }
  }
  assert.equal(JSON.stringify(captured),before)
 }
 const crossing=captureExitScene({...new ArcEngine().snapshot(),position:.999},5)
 assert.notDeepEqual(visibleSlots(sampleExitScene(crossing,1).frame.position,7).map(s=>s.logical),crossing.slots.map(s=>s.logical),'fixture actually crosses a recycling boundary')
})

test('inertial exit has matching initial position, phase and repulsion velocities and settles without a snap',()=>{
 const dt=1e-7,progress=dt/(LOGOUT_DURATION/1000)
 for(const velocity of [-76,-5,0,5,76])for(const phaseVelocity of [-3,0,3]){
  const frame={...new ArcEngine().snapshot(),position:.43,phase:.5,repulsion:[{logical:0,angle:.025,velocity:-.08},{logical:1,angle:-.025,velocity:.06}],radial:[{logical:0,offset:.04,velocity:.3},{logical:1,offset:.05,velocity:-.2}]}
  const captured=captureExitScene(frame,velocity,phaseVelocity),start=sampleExitScene(captured,0),next=sampleExitScene(captured,progress)
  assert.deepEqual(start.frame,frame)
  close((next.frame.position-frame.position)/dt,velocity,1e-3)
  close((next.frame.phase-frame.phase)/dt,phaseVelocity,1e-4)
  for(const [i,original] of frame.repulsion.entries()){
   close((next.frame.repulsion![i]!.angle-original.angle)/dt,original.velocity,1e-5)
   assert.equal(start.frame.repulsion![i]!.velocity,original.velocity)
  }
  for(const [i,original] of frame.radial.entries()){
   close((next.frame.radial![i]!.offset-original.offset)/dt,original.velocity,1e-4)
   assert.equal(start.frame.radial![i]!.velocity,original.velocity)
  }
  const beforeEnd=sampleExitScene(captured,1-1e-5),end=sampleExitScene(captured,1)
  assert.ok(Math.abs(end.frame.position-beforeEnd.frame.position)<1e-7)
  for(const repulsion of end.frame.repulsion!){assert.ok(Math.abs(repulsion.angle)<1e-6);assert.ok(Math.abs(repulsion.velocity)<1e-5)}
 }
 const invalid=captureExitScene(new ArcEngine().snapshot(),NaN,Infinity)
 assert.equal(invalid.velocity,0);assert.equal(invalid.phaseVelocity,0)
})

test('adaptive damping bounds angular coast below one slot even at extreme scroll velocities',()=>{
 for(const velocity of [-1e6,-1e3,-76,-12,-5,0,5,12,76,1e3,1e6]){
  const captured=captureExitScene({...new ArcEngine().snapshot(),position:.5},velocity)
  let previous=0
  for(let i=1;i<=100;i++){
   const delta=sampleExitScene(captured,i/100).frame.position-captured.frame.position
   assert.ok(Math.abs(delta)<.75)
   assert.ok(Math.abs(delta)>=previous)
   if(velocity!==0)assert.equal(Math.sign(delta),Math.sign(velocity))
   previous=Math.abs(delta)
  }
 }
})

test('App captures before back, privacy invalidation and disabled-pointer cancellation, and renders from frozen slots',()=>{
 const app=fs.readFileSync(new URL('./App.vue',import.meta.url),'utf8'),arc=fs.readFileSync(new URL('./ArchiveArc.vue',import.meta.url),'utf8')
 const logout=app.slice(app.indexOf('async function logout(){'),app.indexOf('function keydown('))
 const capture=logout.indexOf('captureExitScene(frame.value,engine.velocity,engine.phaseVelocity)')
 assert.ok(capture>=0)
 for(const mutation of ['refreshExit()','engine.back()','backend.invalidateNavigation()','backend.logout()'])assert.ok(logout.indexOf(mutation)>capture,`${mutation} must follow pose capture`)
 assert.doesNotMatch(logout.slice(0,capture),/endDrag|stopPointer|engine\.update/)
 assert.match(arc,/watch\(\(\)=>props\.disabled,disabled=>\{if\(disabled\)\{hover.value=false;stopPointer\(\)/)
 assert.match(arc,/exitSample\?\.slots\?\?visibleSlots/)
 assert.match(arc,/exitSample\?\.frame\?\?props\.frame/)
 assert.match(arc,/sceneRootMatrix\([^;]+props\.exitSnapshot\?\.frame\?\?props\.frame\)/)
 assert.match(arc,/entryRoot\.matrixWorldNeedsUpdate=true/)
 assert.match(arc,/scene\.updateMatrixWorld\(true\)/)
 assert.match(app,/:exit-snapshot="exitSnapshot"/)
 assert.match(app,/:disabled="loginVisible\|\|exitState.blocked"/)
 assert.match(app,/:inert="loginVisible\|\|exitState.blocked"/)
 assert.match(app,/exitSnapshot.value=null/)
})

test('actual GLB geometry clears the viewport before fading, including attainable rapid-wheel inertia',async context=>{
 const bytes=fs.readFileSync(new URL('../public/models/sylanne-archive-v18.glb',import.meta.url)),loader=new GLTFLoader()
 loader.register(()=>({name:'CPU_TEXTURE_STUB',loadTexture:()=>Promise.resolve(new THREE.Texture())}))
 const {scene:root}=await loader.parseAsync(bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength),'')
 const shared=new THREE.Group();shared.matrixAutoUpdate=false;shared.add(root)
 const meshes:THREE.Mesh[]=[]
 root.traverse(node=>{if(node instanceof THREE.Mesh&&node.name!=='HIT_archive'){node.geometry.computeBoundingBox();meshes.push(node)}})
 assert.ok(meshes.some(mesh=>mesh.name==='ARCHIVE_label'),'official embedded-label geometry is included')
 const fixtures:Array<{name:string;frame:ArcSnapshot;velocity:number;phaseVelocity:number}>=[]
 for(const position of [-12.999,-.51,-.001,0,.001,.49,.999,15.75])for(const phase of [0,.4,1])for(const velocity of [-12,-5,0,5,12])for(const phaseVelocity of [-3,0,3]){
  const frame={...new ArcEngine().snapshot(),position,phase}
  frame.repulsion=visibleSlots(position,frame.count).map(slot=>({logical:slot.logical,angle:Math.sign(slot.logical-frame.logical)*.045,velocity:.12}))
  frame.radial=[{logical:Math.round(position),offset:.1*phase,velocity:phase===1?0:.4}]
  fixtures.push({name:'pose sweep',frame,velocity,phaseVelocity})
 }
 for(const direction of [-1,1]){const engine=rapidWheel(direction);assert.ok(Math.abs(engine.velocity)>70);fixtures.push({name:`rapid wheel ${direction}`,frame:engine.snapshot(),velocity:engine.velocity,phaseVelocity:engine.phaseVelocity})}
 for(const position of [-.001,.49,.999])for(const velocity of [-1e6,1e6])fixtures.push({name:'extreme inertia bound',frame:{...new ArcEngine().snapshot(),position},velocity,phaseVelocity:0})
 let checks=0,smallest=Infinity,smallestCase='',failures=0
 const examples:string[]=[]
 for(const [width,height] of viewportSizes){
  const {viewport,camera}=cameraFor(width,height)
  for(const fixture of fixtures){
   const captured=captureExitScene(fixture.frame,fixture.velocity,fixture.phaseVelocity)
   for(const progress of [.94,1]){
    shared.matrix.copy(sceneRootMatrix(1,progress,viewport.layoutAspect,viewport.rootY,captured.frame))
    const sample=sampleExitScene(captured,progress)
    for(const slot of sample.slots.filter(slot=>slot.visible&&slot.opacity>0)){
     const transform=slotTransform(slot,sample.frame,viewport.layoutAspect)
     root.position.set(transform.x,transform.y,transform.z);root.rotation.set(transform.rotationX,transform.rotationY,transform.rotationZ,transform.rotationOrder);root.scale.setScalar(transform.scale);shared.updateMatrixWorld(true)
     const projected=new THREE.Box3()
     // Project all mesh bounding-box corners, ignoring exit opacity even at p=1.
     // These conservative bounds include embedded labels and transparent shells;
     // HIT_archive is the only excluded, deliberately non-rendered interaction mesh.
     for(const mesh of meshes){
      const box=mesh.geometry.boundingBox!
      for(const x of [box.min.x,box.max.x])for(const y of [box.min.y,box.max.y])for(const z of [box.min.z,box.max.z])projected.expandByPoint(new THREE.Vector3(x,y,z).applyMatrix4(mesh.matrixWorld).project(camera))
     }
     const clearance=Math.max((projected.min.x-1)*width/2,(-1-projected.max.x)*width/2,(projected.min.y-1)*height/2,(-1-projected.max.y)*height/2)
     const label=JSON.stringify({fixture:fixture.name,width,height,position:fixture.frame.position,phase:fixture.frame.phase,velocity:fixture.velocity,phaseVelocity:fixture.phaseVelocity,progress,logical:slot.logical,clearancePx:clearance,ndcMin:projected.min.toArray(),ndcMax:projected.max.toArray()})
     if(clearance<smallest){smallest=clearance;smallestCase=label}
     if(clearance<=0){failures++;if(examples.length<8)examples.push(label)}
     checks++
    }
   }
  }
 }
 context.diagnostic(`${checks} visible-card bounds; smallest conservative clearance: ${smallest.toFixed(6)} px; ${smallestCase}`)
 assert.equal(failures,0,`${failures} projected card bounds intersect the viewport. First cases:\n${examples.join('\n')}`)
})

function deferred<T>(){let resolve!:(value:T)=>void;const promise=new Promise<T>(done=>{resolve=done});return {promise,resolve}}
const response=(body:unknown,status=200):FetchResponse=>({ok:status>=200&&status<300,status,json:async()=>body})
async function controller(fetchImpl:FetchLike){
 const {createSSRApp,h}=await import('vue'),{renderToString}=await import('@vue/server-renderer'),{useBackend}=await import('./use-backend.ts')
 let backend!:ReturnType<typeof useBackend>
 await renderToString(createSSRApp({setup(){backend=useBackend({enabled:true,origin:'https://logout-test.sylanne.invalid',fetchImpl});return ()=>h('div')}}))
 return backend
}
test('rotating exit locks and erases content immediately, while pending/failure/retry remain independent of animation',async()=>{
 const session={status:'ready',dashboard_session:'authenticated',owner_session:'unlocked',csrf_token:'mock-test-token'},namespace={bot:'test-bot',persona:'test-persona'}
 const workspace={status:'ready',projection:{namespace,access_generation:1,views:[{view_type:'creation',status:'available'}],view_diagnostics:[],unavailable_domains:{d10:'no_public_projection_contract'},command_routes:[]}}
 const creation={status:'ready',projection:{view_type:'creation',namespace,access_generation:1,data:{candidates:[{plan_id:'test-private-plan',version:1,authored:true,block_count:2,value_rule_count:0}]},coverage:{requested_types:['d01.persona_plan.v1'],returned_atoms:1,truncated:false},snapshot_epoch:1,next_cursor:null}}
 const lateView=deferred<FetchResponse>(),firstLogout=deferred<FetchResponse>();let reads=0,logouts=0
 const backend=await controller(async(url,init)=>{
  if(url.endsWith('/session'))return response(session)
  if(url.endsWith('/owner/logout'))return ++logouts===1?firstLogout.promise:response({status:'ok',owner_session:'locked'})
  if(JSON.parse(init.body as string).action==='open_workspace')return response(workspace)
  return ++reads===1?response(creation):lateView.promise
 })
 await backend.checkSession();backend.setScope('test-bot/test-persona');await backend.openWorkspace();await backend.readView('creation')
 assert.ok(backend.state.workspace.data);assert.ok(backend.state.view.data)
 const inFlight=backend.readView('creation'),flow=new LogoutFlow(),generation=flow.begin(100,false,false)!,pending=backend.logout()
 assert.equal(backend.state.auth,'locked');assert.equal(backend.canRead.value,false)
 assert.equal(backend.state.workspace.data,null);assert.equal(backend.state.view.data,null)
 assert.equal(backend.state.logoutStatus,'loading');assert.equal(flow.result,'pending')
 flow.update(100+LOGOUT_DURATION);assert.equal(flow.active,false);assert.equal(flow.blocked,true);assert.equal(flow.clear(),false);assert.equal(flow.begin(2000,false,false),null)
 lateView.resolve(response(creation));await inFlight;assert.equal(backend.state.view.data,null)
 firstLogout.resolve(response({problem:{code:'owner_logout_authority_unavailable'}},503))
 assert.equal(flow.settle(generation,await pending),true);assert.equal(flow.result,'failed');assert.equal(backend.state.logoutStatus,'unconfirmed');assert.match(flow.message,/未确认/)
 const retry=flow.begin(2000,false,true)!
 assert.equal(flow.settle(generation,true),false);assert.equal(flow.result,'pending');assert.equal(flow.blocked,true)
 assert.equal(flow.settle(retry,await backend.logout()),true);assert.equal(flow.result,'confirmed');assert.equal(flow.blocked,false);assert.equal(logouts,2)
 assert.equal(backend.state.auth,'locked');assert.equal(backend.state.view.data,null);assert.equal(flow.clear(),true);assert.equal(flow.settle(retry,false),false)
})

test('reduced motion and offline exit keep their immediate semantic endpoint without claiming server success',()=>{
 const online=new LogoutFlow(),generation=online.begin(0,false,true)!
 assert.equal(online.progress,1);assert.equal(online.active,false);assert.equal(online.result,'pending');assert.equal(online.blocked,true)
 assert.equal(online.settle(generation,true),true);assert.equal(online.result,'confirmed');assert.equal(online.blocked,false)
 const offline=new LogoutFlow();offline.begin(0,true,true)
 assert.equal(offline.progress,1);assert.equal(offline.active,false);assert.equal(offline.result,'offline');assert.match(offline.message,/没有真实/);assert.equal(offline.settle(offline.generation,true),false)
 const switched=new LogoutFlow();switched.begin(0,false,false);switched.update(20,true)
 assert.equal(switched.progress,1);assert.equal(switched.active,false);assert.equal(switched.result,'pending');assert.equal(switched.blocked,true)
})
