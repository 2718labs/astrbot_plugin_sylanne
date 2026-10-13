import {test} from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import {ArcEngine,visibleSlots} from './arc-engine.ts'
import {arcLayout,slotTransform} from './arc-model.ts'
import {makeReadingMotion,updateReadingMotion} from './read-motion.ts'

const close=(actual:number,expected:number)=>assert.ok(Math.abs(actual-expected)<1e-12,`${actual} != ${expected}`)
function poses(engine:ArcEngine){const frame=engine.snapshot();return visibleSlots(frame.position,frame.count).map(slot=>{const {selected,...transform}=slotTransform(slot,frame,1.056);void selected;return {logical:slot.logical,...transform}})}
function settle(engine:ArcEngine,start=0){let now=start;for(let count=0;count<1000&&engine.moving;count++)engine.update(now+=16);assert.equal(engine.moving,false);return now}

test('idle physical selection advances only the new frame interval, never the preceding idle time',()=>{
 for(const idle of[1000,30_000,3_600_000]){
  const reference=new ArcEngine(),resumed=new ArcEngine()
  reference.update(0);resumed.update(0)
  reference.toggleSelect(1);resumed.toggleSelect(1)
  const before=resumed.snapshot(),beforePoses=poses(resumed)
  reference.wake(0);resumed.wake(idle)
  assert.deepEqual(resumed.snapshot(),before);assert.deepEqual(poses(resumed),beforePoses)
  reference.update(16);resumed.update(idle+16)
  assert.deepEqual(resumed.snapshot(),reference.snapshot());assert.deepEqual(poses(resumed),poses(reference))
  close(resumed.snapshot().radial!.find(sample=>sample.logical===1)!.offset,.001623421275791459)
  close(resumed.phase,.011513204799194932)
 }
})

test('clock wake never changes a live selection pose, spring velocity or destination',()=>{
 const engine=new ArcEngine();engine.update(0);engine.step(1);engine.update(40);engine.toggleSelect(-1);engine.update(64)
 const before=engine.snapshot(),beforePoses=poses(engine),target=engine.target,velocity=engine.velocity,phaseVelocity=engine.phaseVelocity
 engine.wake(50_000)
 assert.deepEqual(engine.snapshot(),before);assert.deepEqual(poses(engine),beforePoses)
 assert.equal(engine.target,target);assert.equal(engine.velocity,velocity);assert.equal(engine.phaseVelocity,phaseVelocity)
})

test('resuming a hidden in-flight scene retains all motion and advances like the next ordinary frame',()=>{
 const reference=new ArcEngine(),resumed=new ArcEngine()
 for(const engine of[reference,resumed]){engine.update(0);engine.step(1);engine.update(16);engine.toggleSelect(-1);engine.update(32)}
 resumed.wake(120_000)
 reference.update(48);resumed.update(120_016)
 assert.deepEqual(resumed.snapshot(),reference.snapshot());assert.deepEqual(poses(resumed),poses(reference))
})

test('new input in an already-queued frame does not discard the active integration interval',()=>{
 const reference=new ArcEngine(),engine=new ArcEngine();let now=1000,queued=false,wakes=0
 const request=()=>{if(!queued){engine.wake(now);queued=true;wakes++}}
 const tick=()=>{assert.equal(queued,true);queued=false;engine.update(now);if(engine.moving)queued=true}
 reference.update(now);engine.update(now)
 engine.step(1);request();reference.step(1)
 now+=8;engine.step(1);request();reference.step(1)
 now+=8;tick();reference.update(now)
 assert.equal(wakes,1);assert.deepEqual(engine.snapshot(),reference.snapshot())
 now+=8;engine.toggleSelect(-1);request();reference.toggleSelect(-1)
 now+=8;tick();reference.update(now)
 assert.equal(wakes,1);assert.deepEqual(engine.snapshot(),reference.snapshot());assert.deepEqual(poses(engine),poses(reference))
})

test('actual App request handler rebases only a visible dormant frame loop',()=>{
 const source=fs.readFileSync(new URL('./App.vue',import.meta.url),'utf8'),start=source.indexOf('function request(){'),end=source.indexOf('function unlock()',start)
 assert.ok(start>=0&&end>start)
 const engine=new ArcEngine(),document={hidden:false},clock={now:1000},callbacks:Array<()=>void>=[],wakes:number[]=[]
 const originalWake=engine.wake.bind(engine);engine.wake=(now:number)=>{wakes.push(now);originalWake(now)}
 const host=Function('engine','refresh','alive','document','performance','requestAnimationFrame','sync',`let raf=0;${source.slice(start,end)};return {request,clearQueuedFrame(){raf=0}}`)(engine,()=>{},true,document,{now:()=>clock.now},(callback:()=>void)=>{callbacks.push(callback);return callbacks.length},()=>{})
 host.request();assert.deepEqual(wakes,[1000]);assert.equal(callbacks.length,1)
 clock.now=1008;host.request();assert.deepEqual(wakes,[1000]);assert.equal(callbacks.length,1)
 host.clearQueuedFrame();document.hidden=true;clock.now=60_000;host.request();assert.deepEqual(wakes,[1000]);assert.equal(callbacks.length,1)
 document.hidden=false;host.request();assert.deepEqual(wakes,[1000,60_000]);assert.equal(callbacks.length,2)
})

test('deselecting after an idle detail preserves the initial pose and closes by one frame',()=>{
 const reference=new ArcEngine(),resumed=new ArcEngine()
 for(const engine of[reference,resumed]){engine.update(0);engine.toggleSelect(0)}
 const stopped=settle(reference);assert.equal(settle(resumed),stopped)
 reference.back();resumed.back();const before=resumed.snapshot()
 reference.wake(stopped);resumed.wake(stopped+30_000)
 assert.deepEqual(resumed.snapshot(),before)
 reference.update(stopped+16);resumed.update(stopped+30_016)
 assert.deepEqual(resumed.snapshot(),reference.snapshot());assert.deepEqual(poses(resumed),poses(reference))
 assert.ok(resumed.phase>.98);assert.ok(resumed.snapshot().radial!.find(sample=>sample.logical===0)!.offset>.099)
})

test('idle keyboard and wheel navigation keep absolute wheel deadlines but use a fresh motion clock',()=>{
 for(const kind of['step','wheel'] as const){
  const reference=new ArcEngine(),resumed=new ArcEngine();reference.update(0);resumed.update(0)
  if(kind==='step'){reference.step(1);resumed.step(1)}else{reference.wheel(90,0,800,0);resumed.wheel(90,0,800,10_000)}
  reference.wake(0);resumed.wake(10_000)
  for(const elapsed of[16,32,64,128,130,160,192,240]){reference.update(elapsed);resumed.update(10_000+elapsed);assert.deepEqual(resumed.snapshot(),reference.snapshot())}
 }
})

test('dormant drag updates and release preserve pointer motion and cancellation semantics',()=>{
 for(const cancelled of[false,true]){
  const reference=new ArcEngine(),resumed=new ArcEngine()
  for(const engine of[reference,resumed])engine.update(0)
  reference.beginDrag(400,0);resumed.beginDrag(400,10_000)
  reference.drag(340,16);resumed.drag(340,10_016)
  reference.wake(16);resumed.wake(10_016)
  reference.update(32);resumed.update(10_032)
  assert.deepEqual(resumed.snapshot(),reference.snapshot());assert.equal(resumed.position,.5)
  reference.endDrag(cancelled);resumed.endDrag(cancelled)
  reference.wake(32);resumed.wake(10_032)
  reference.update(48);resumed.update(10_048)
  assert.deepEqual(resumed.snapshot(),reference.snapshot());assert.deepEqual(poses(resumed),poses(reference))
 }
})

test('wake keeps reduced-motion endpoints immediate and ignores non-finite timestamps',()=>{
 const reduced=new ArcEngine();reduced.setReduced(true);reduced.position=.37;reduced.target=.37;reduced.toggleSelect(1)
 const selected=reduced.snapshot();reduced.wake(10_000)
 assert.deepEqual(reduced.snapshot(),selected);assert.equal(reduced.mode,'detail');assert.equal(reduced.moving,false)
 reduced.toggleSelect(1);reduced.update(10_016);assert.equal(reduced.mode,'browse');assert.equal(reduced.moving,false)
 const reference=new ArcEngine(),engine=new ArcEngine()
 for(const item of[reference,engine]){item.update(0);item.toggleSelect(0);item.wake(1000)}
 for(const invalid of[NaN,Infinity,-Infinity])engine.wake(invalid)
 reference.update(1016);engine.update(1016);assert.deepEqual(engine.snapshot(),reference.snapshot())
})

test('clicking an angularly moving neighbor preserves its live spring before decaying toward the centered pose',()=>{
 for(const clickTime of[16,40,100,200]){
  const engine=new ArcEngine();engine.update(0);engine.toggleSelect(0)
  for(let now=8;now<=clickTime;now+=8)engine.update(now)
  const before=engine.snapshot(),beforePoses=poses(engine),neighbor=before.repulsion!.find(sample=>sample.logical===1)!
  const velocity=engine.velocity,phaseVelocity=engine.phaseVelocity
  assert.ok(Math.abs(neighbor.velocity)>0)
  engine.toggleSelect(1)
  assert.deepEqual(poses(engine),beforePoses)
  assert.deepEqual(engine.snapshot().radial,before.radial)
  assert.deepEqual(engine.snapshot().repulsion,before.repulsion)
  assert.equal(engine.velocity,velocity);assert.equal(engine.phaseVelocity,phaseVelocity);assert.equal(engine.target,1)
  for(let now=clickTime+8;now<=clickTime+3000;now+=8)engine.update(now)
  const selected=engine.snapshot().repulsion!.find(sample=>sample.logical===1)!
  assert.equal(selected.angle,0);assert.equal(selected.velocity,0)
  assert.equal(engine.position,1);assert.equal(engine.mode,'detail');assert.equal(engine.moving,false)
 }
})

test('selected body docks then holds still for ten seconds at 30/60/120 fps and jitter while read ring rotates',()=>{
 const cadences=[[1000/30],[1000/60],[1000/120],[7,31,12,24,17,5,39]]
 for(const cadence of cadences)for(const direction of[-1,1]){
  const engine=new ArcEngine();engine.update(0);engine.toggleSelect(0);engine.update(40)
  const clicked=poses(engine).find(pose=>pose.logical===direction)!,layout=arcLayout(1.056)
  engine.toggleSelect(direction);const reading=makeReadingMotion()
  let now=40,frame=0,settledPose:ReturnType<typeof poses>[number]|undefined,settledRing:ReturnType<typeof poses>|undefined,settledAt:number|undefined,ringAngleAtRest=0
  while(now<12_040){
   const dt=cadence[frame++%cadence.length]!
   now+=dt;engine.update(now);updateReadingMotion(reading,direction,true,dt/1000,false)
   const selected=poses(engine).find(pose=>pose.logical===direction)!
   for(const key of['rotationX','rotationY','scale','lidRotationY'] as const)close(selected[key],clicked[key])
   if(!engine.moving&&!settledPose){settledPose=selected;settledRing=poses(engine);settledAt=now;ringAngleAtRest=reading.angle}
   if(settledPose){assert.deepEqual(selected,settledPose,'a settled body must never resume drifting');assert.deepEqual(poses(engine),settledRing,'all body poses remain still after docking')}
  }
  assert.ok(settledPose&&settledAt!==undefined&&settledAt<2040,'body springs must settle within two seconds')
  close(settledPose.z,0);close(settledPose.rotationZ,-layout.focusAngle)
  close(Math.hypot(settledPose.x-layout.cx,settledPose.y-layout.cy),layout.radius+.10)
  assert.ok(reading.angle-ringAngleAtRest>.9,'the large read ring continues rotating independently')
  assert.equal(engine.position,direction);assert.equal(engine.mode,'detail');assert.equal(engine.moving,false)
 }
})

test('physical click during attainable fast navigation preserves velocity then docks smoothly at every cadence',()=>{
 for(const direction of[-1,1])for(const cadence of[[1000/30],[1000/60],[1000/120],[7,31,12,24,17,5,39]]){
  const engine=new ArcEngine();engine.update(0)
  for(let now=8;now<=400;now+=8){engine.wheel(direction*156.25,0,800,now);engine.update(now)}
  assert.ok(Math.abs(engine.velocity)>70,'fixture reaches real fast wheel velocity')
  const position=engine.position,logical=Math.floor(position)+1,before=engine.snapshot(),beforePoses=poses(engine),velocity=engine.velocity,phaseVelocity=engine.phaseVelocity
  engine.toggleSelect(logical)
  assert.deepEqual(poses(engine),beforePoses);assert.deepEqual(engine.snapshot().radial,before.radial);assert.deepEqual(engine.snapshot().repulsion,before.repulsion)
  assert.equal(engine.position,position);assert.equal(engine.target,logical);assert.equal(engine.velocity,velocity);assert.equal(engine.phaseVelocity,phaseVelocity)
  let now=400,index=0,settledRing:ReturnType<typeof poses>|undefined
  while(now<10_400){
   now+=cadence[index++%cadence.length]!;engine.update(now)
   assert.ok(Number.isFinite(engine.position)&&Number.isFinite(engine.velocity))
   assert.equal(engine.target,logical)
   if(!engine.moving&&!settledRing)settledRing=poses(engine)
   if(settledRing)assert.deepEqual(poses(engine),settledRing)
  }
  assert.equal(engine.position,logical);assert.equal(engine.velocity,0);assert.equal(engine.mode,'detail');assert.equal(engine.moving,false)
  const selected=poses(engine).find(pose=>pose.logical===logical)!,layout=arcLayout(1.056)
  close(selected.z,0);close(selected.rotationZ,-layout.focusAngle)
  close(Math.hypot(selected.x-layout.cx,selected.y-layout.cy),layout.radius+.10)
 }
})
