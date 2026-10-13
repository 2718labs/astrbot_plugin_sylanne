import {test} from 'node:test'
import assert from 'node:assert/strict'
import {ArcEngine,ARC_STEP_ANGLE,modulo,visibleSlots,type ArcSnapshot} from './arc-engine.ts'
import {arcLayout,slotTransform} from './arc-model.ts'
import {repulsionAngle,REPULSION_MAX_ANGLE} from './arc-repulsion.ts'
import {radialOffset,SELECTION_RADIAL_DISTANCE} from './arc-selection.ts'

const cadences=[[1000/30],[1000/60],[1000/120],[7,31,12,24,17,5,39]]
const near=(actual:number,expected:number,epsilon=1e-10)=>assert.ok(Math.abs(actual-expected)<=epsilon,`${actual} != ${expected}`)
const transformKeys=['x','y','z','rotationX','rotationY','rotationZ','scale','lidRotationY'] as const
function pose(state:ArcSnapshot,logical:number,aspect=1.056){
 const slot=visibleSlots(state.position,state.count).find(slot=>slot.logical===logical)
 assert.ok(slot,`logical ${logical} must remain in the physical pool`)
 return slotTransform(slot,state,aspect)
}
function unchanged(before:ArcSnapshot,after:ArcSnapshot){
 assert.equal(after.position,before.position);assert.equal(after.phase,before.phase)
 assert.deepEqual(after.repulsion,before.repulsion);assert.deepEqual(after.radial,before.radial)
 for(const slot of visibleSlots(before.position,before.count)){
  const a=pose(before,slot.logical),b=pose(after,slot.logical)
  for(const key of transformKeys)assert.equal(b[key],a[key],`${slot.logical}.${key} changed at input time`)
 }
}
function tickFor(engine:ArcEngine,duration:number,cadence:readonly number[],start=0){
 let now=start,frame=0
 while(now<start+duration){now=Math.min(start+duration,now+cadence[frame++%cadence.length]!);engine.update(now)}
 return now
}
function assertCentered(engine:ArcEngine,logical:number){
 const state=engine.snapshot(),selected=pose(state,logical),layout=arcLayout(1.056)
 assert.equal(state.position,logical);assert.equal(state.logical,logical);assert.equal(state.selected,modulo(logical,state.count))
 assert.equal(state.mode,'detail');assert.equal(state.phase,1);assert.equal(state.settled,true);assert.equal(engine.moving,false)
 assert.equal(engine.velocity,0);assert.equal(engine.phaseVelocity,0);assert.equal(selected.z,0)
 near(selected.rotationZ,-layout.focusAngle);near(Math.hypot(selected.x-layout.cx,selected.y-layout.cy),layout.radius+.10)
 assert.equal(repulsionAngle(state.repulsion,logical),0)
 assert.ok(state.radial!.every(sample=>sample.offset===(sample.logical===logical?SELECTION_RADIAL_DISTANCE:0)&&sample.velocity===0))
}

// The nearest target oracle deliberately enumerates candidate turns instead of
// repeating the engine's modulo/round target-selection expression.
function nearestDistance(position:number,index:number,count:number){
 const cycle=Math.floor(position/count)
 return Math.min(...[-2,-1,0,1,2].map(offset=>Math.abs(index+(cycle+offset)*count-position)))
}

test('every direct-click record chooses the shortest cyclic center from the current fractional pose',()=>{
 for(const position of[-100.25,-7.5,-.2,0,.37,6.75,100.2])for(let index=0;index<7;index++)for(const cadence of cadences){
  const engine=new ArcEngine();engine.position=position;engine.target=position;engine.update(0)
  const before=engine.snapshot(),clicked=index+7*Math.floor(position/7)
  assert.equal(engine.toggleSelect(clicked),true);unchanged(before,engine.snapshot())
  assert.equal(modulo(engine.target,7),index);near(Math.abs(engine.target-position),nearestDistance(position,index,7))
  assert.ok(Math.abs(engine.target-position)<=3.5);assert.equal(engine.logical,engine.target);assert.equal(engine.selected,index)
  const target=engine.target;tickFor(engine,3000,cadence);assertCentered(engine,target)
 }
})

test('direct clicks rotate the whole arc in both directions and across either cyclic boundary',()=>{
 for(const [start,clicked,target] of[[0,2,2],[0,-2,-2],[6,0,7],[0,6,-1],[-7,6,-8],[7,0,7]] as const)for(const cadence of cadences){
  const engine=new ArcEngine();engine.position=start;engine.target=start;engine.update(0)
  const before=engine.snapshot();engine.toggleSelect(clicked);assert.equal(engine.target,target)
  let now=0,frame=0,previous=start
  while(now<3000){
   now=Math.min(3000,now+cadence[frame++%cadence.length]!);const state=engine.update(now)
   assert.ok(state.position>=Math.min(start,target)-1e-12&&state.position<=Math.max(start,target)+1e-12)
   assert.ok((state.position-previous)*Math.sign(target-start)>=-1e-12);previous=state.position
   for(const slot of visibleSlots(before.position,before.count)){
    const current=visibleSlots(state.position,state.count).find(candidate=>candidate.logical===slot.logical)
    if(!current)continue
    const oldPose=pose(before,slot.logical),newPose=pose(state,slot.logical)
    near(newPose.z-oldPose.z,-1.7*(state.position-start))
    near(newPose.rotationZ-oldPose.rotationZ,-ARC_STEP_ANGLE*(state.position-start)-repulsionAngle(state.repulsion,slot.logical))
    near(newPose.scale,oldPose.scale);near(newPose.rotationX,oldPose.rotationX);near(newPose.rotationY,oldPose.rotationY);near(newPose.lidRotationY,0)
   }
  }
  assertCentered(engine,target)
 }
})

test('a click retargets from displayed position rather than a distant queued navigation target',()=>{
 for(const direction of[-1,1]){
  const engine=new ArcEngine();engine.update(0)
  for(let i=0;i<20;i++)engine.step(direction)
  engine.update(16);const before=engine.snapshot(),velocity=engine.velocity,logical=Math.floor(engine.position)-direction
  assert.ok(Math.abs(engine.target-engine.position)>10)
  engine.toggleSelect(logical);unchanged(before,engine.snapshot());assert.equal(engine.velocity,velocity)
  assert.equal(engine.target,logical);assert.ok(Math.abs(engine.target-engine.position)<=3.5)
  tickFor(engine,3000,[1000/60],16);assertCentered(engine,logical)
 }
})

test('rapid direct-click reversals preserve live navigation, panel, repulsion and radial velocities at every cadence',()=>{
 for(const cadence of cadences){
  const engine=new ArcEngine();engine.update(0);let now=0,angularRetargets=0,navigationRetargets=0,radialRetargets=0
  for(const logical of[0,1,-1,2,2,2,0,-2,-2,-2,1]){
   const before=engine.snapshot(),velocity=engine.velocity,phaseVelocity=engine.phaseVelocity
   angularRetargets+=Number(before.repulsion!.some(sample=>Math.abs(sample.velocity)>0))
   navigationRetargets+=Number(Math.abs(velocity)>0);radialRetargets+=Number(before.radial!.some(sample=>Math.abs(sample.velocity)>0))
   assert.equal(engine.toggleSelect(logical),true);unchanged(before,engine.snapshot())
   assert.equal(engine.velocity,velocity);assert.equal(engine.phaseVelocity,phaseVelocity)
   now=tickFor(engine,48,cadence,now)
   const state=engine.snapshot()
   for(const sample of state.radial!)assert.ok(Number.isFinite(sample.offset)&&Number.isFinite(sample.velocity)&&sample.offset>=-1e-12&&sample.offset<=.10+1e-12)
   for(const sample of state.repulsion!)assert.ok(Number.isFinite(sample.angle)&&Number.isFinite(sample.velocity)&&Math.abs(sample.angle)<=REPULSION_MAX_ANGLE)
  }
  assert.ok(angularRetargets>5&&navigationRetargets>5&&radialRetargets>5,'fixture must interrupt all live spring families')
  const target=engine.target;tickFor(engine,3000,cadence,now);assertCentered(engine,target);assert.equal(engine.selected,1)
 }
})

test('repeat active-disk click cancels during navigation or after docking without changing the current pose',()=>{
 for(const cadence of cadences)for(const direction of[-1,1])for(const elapsed of[0,40,180,3000]){
  const engine=new ArcEngine();engine.update(0);engine.toggleSelect(2*direction);tickFor(engine,elapsed,cadence)
  const before=engine.snapshot(),target=engine.target,velocity=engine.velocity,phaseVelocity=engine.phaseVelocity
  assert.equal(engine.toggleSelect(engine.logical),true);unchanged(before,engine.snapshot())
  assert.equal(engine.mode,'closing');assert.equal(engine.target,target);assert.equal(engine.velocity,velocity);assert.equal(engine.phaseVelocity,phaseVelocity)
  tickFor(engine,3000,cadence,elapsed)
  assert.equal(engine.mode,'browse');assert.equal(engine.position,target);assert.equal(engine.phase,0);assert.equal(engine.moving,false)
  assert.equal(engine.selected,modulo(target,engine.count));assert.ok(engine.snapshot().radial!.every(sample=>sample.offset===0&&sample.velocity===0))
  assert.ok(engine.snapshot().repulsion!.every(sample=>sample.angle===0&&sample.velocity===0))
 }
})

test('clicking again during cancellation reopens the same nearest center continuously',()=>{
 for(const cadence of cadences){
  const engine=new ArcEngine();engine.update(0);engine.toggleSelect(-2);let now=tickFor(engine,80,cadence)
  engine.toggleSelect(-2);now=tickFor(engine,40,cadence,now)
  const before=engine.snapshot(),velocity=engine.velocity,phaseVelocity=engine.phaseVelocity
  assert.equal(engine.mode,'closing');assert.equal(engine.toggleSelect(-2),true);unchanged(before,engine.snapshot())
  assert.equal(engine.mode,'opening');assert.equal(engine.velocity,velocity);assert.equal(engine.phaseVelocity,phaseVelocity)
  tickFor(engine,3000,cadence,now);assertCentered(engine,-2)
 }
})

test('tab and direct selection produce identical state, destination and body trajectories',()=>{
 for(const position of[-7.2,-.4,0,.37,6.8])for(const logical of[-2,0,1,6,7])for(const cadence of cadences){
  const direct=new ArcEngine(),tab=new ArcEngine()
  for(const engine of[direct,tab]){engine.position=position;engine.target=position;engine.update(0)}
  assert.equal(direct.toggleSelect(logical),tab.select(logical));assert.equal(direct.target,tab.target)
  let now=0,index=0
  while(now<3000){
   now=Math.min(3000,now+cadence[index++%cadence.length]!)
   assert.deepEqual(direct.update(now),tab.update(now));assert.equal(direct.velocity,tab.velocity);assert.equal(direct.phaseVelocity,tab.phaseVelocity)
  }
  assertCentered(direct,direct.target)
  const before=tab.snapshot();assert.equal(tab.select(logical),false);assert.deepEqual(tab.snapshot(),before)
  assert.equal(direct.toggleSelect(logical),true);assert.equal(direct.mode,'closing')
 }
})

test('after direct-click docking, keyboard navigation closes details and returns to ordinary browse',()=>{
 const engine=new ArcEngine();engine.update(0);engine.toggleSelect(1);tickFor(engine,3000,[16]);assertCentered(engine,1)
 const before=engine.snapshot();engine.step(-1);unchanged(before,engine.snapshot());assert.equal(engine.target,0)
 tickFor(engine,3000,[16],3000);assert.equal(engine.position,0);assert.equal(engine.selected,0);assert.equal(engine.mode,'browse');assert.equal(engine.moving,false)
 assert.equal(radialOffset(engine.snapshot().radial,0),0)
})
