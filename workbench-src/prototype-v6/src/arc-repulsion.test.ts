import {test} from 'node:test'
import assert from 'node:assert/strict'
import {ArcEngine,visibleSlots,ARC_STEP_ANGLE} from './arc-engine.ts'
import {slotTransform,arcLayout} from './arc-model.ts'
import {radialOffset,SELECTION_RADIAL_DISTANCE} from './arc-selection.ts'
import {advanceRepulsion,repulsionTarget,REPULSION_MAX_ANGLE} from './arc-repulsion.ts'
const near=(a:number,b:number,eps=1e-10)=>assert.ok(Math.abs(a-b)<eps,`${a} != ${b}`)
function run(e:ArcEngine,start=0,end=3000){for(let t=start;t<=end;t+=1000/120)e.update(t)}
test('only actual select activates a local, nonuniform, outward magnetic field',()=>{
 const e=new ArcEngine();e.choose(1);run(e);assert.ok(e.snapshot().repulsion!.every(s=>s.angle===0));e.select(1);run(e,3010,6010)
 for(const sample of e.snapshot().repulsion!){near(sample.angle,repulsionTarget(sample.logical,1));if(sample.logical!==1)assert.equal(Math.sign(sample.angle),-Math.sign(sample.logical-1))}
 near(repulsionTarget(1,1),0);assert.ok(Math.abs(repulsionTarget(2,1))>3*Math.abs(repulsionTarget(3,1)));assert.ok(Math.abs(repulsionTarget(3,1))>Math.abs(repulsionTarget(4,1)))
})
test('initial selected pose lifts only radially; neighbors retain radius, scale, tilt, lid and sequential depth',()=>{
 for(const aspect of[.75,1.056,1.6]){const e=new ArcEngine(),base=e.snapshot();e.select(0)
 for(let t=0;t<2600;t+=16){const state=e.update(t),layout=arcLayout(aspect)
 for(const slot of visibleSlots(state.position,state.count)){const a=slotTransform(slot,base,aspect),b=slotTransform(slot,state,aspect);near(a.z,b.z);near(a.scale,b.scale);near(a.rotationX,b.rotationX);near(a.rotationY,b.rotationY);near(b.lidRotationY,0);const radial=radialOffset(state.radial,slot.logical);near(Math.hypot(b.x-layout.cx,b.y-layout.cy),layout.radius+radial)
 if(slot.logical===0){assert.ok(radial>=0&&radial<=SELECTION_RADIAL_DISTANCE);near((b.x-a.x)*Math.sin(-a.rotationZ)+(b.y-a.y)*Math.cos(-a.rotationZ),0);near(b.rotationZ,a.rotationZ)}else{near(radial,0);assert.ok(Math.abs(b.rotationZ-a.rotationZ)<=REPULSION_MAX_ANGLE+1e-12)}
 }}}
})
test('repeat select is idempotent; rapid retarget preserves every live displacement and velocity',()=>{
 const e=new ArcEngine();e.select(0);run(e,0,150);const before=e.snapshot();assert.equal(e.select(0),false);assert.deepEqual(e.snapshot(),before)
 e.select(1);assert.deepEqual(e.snapshot().repulsion,before.repulsion)
 const selectedResidual=before.repulsion!.find(s=>s.logical===1)!;assert.notEqual(selectedResidual.angle,0)
 // A newly selected previously displaced neighbor smoothly returns to zero;
 // zeroing instantly would violate continuity. Its endpoint is never displaced.
 run(e,160,3160);near(e.snapshot().repulsion!.find(s=>s.logical===1)!.angle,0)
})
test('rapid changes and cyclic boundaries preserve identity, angle order, finite bounds and state serialization',()=>{
 const e=new ArcEngine();let previous=e.snapshot();for(let frame=0;frame<1000;frame++){
 if(frame%13===0){previous=e.snapshot();e.select((frame/13)%7);assert.deepEqual(e.snapshot().repulsion,previous.repulsion)}
 const state=e.update(frame*8),samples=state.repulsion!;JSON.parse(JSON.stringify(state));assert.ok(samples.every(s=>Number.isFinite(s.angle)&&Number.isFinite(s.velocity)&&Math.abs(s.angle)<=REPULSION_MAX_ANGLE))
 const slots=visibleSlots(state.position,state.count);for(let i=1;i<slots.length;i++){const a=slotTransform(slots[i-1]!,state,1.056),b=slotTransform(slots[i]!,state,1.056);assert.ok(b.rotationZ-a.rotationZ>ARC_STEP_ANGLE-2*REPULSION_MAX_ANGLE-1e-12);near(b.z-a.z,1.7)}
 }
 const a=advanceRepulsion([],[-1,0,1,2],0,0,true),b=advanceRepulsion([],[4,5,6,7],5,0,true);assert.deepEqual(a.map(s=>s.angle),b.map(s=>s.angle))
})
test('closing is gentler than opening and returns without a snap; reduced motion reaches same semantic endpoint',()=>{
 const initial=advanceRepulsion([],[1],0,0,true),closing=advanceRepulsion(initial,[1],null,.1),opening=advanceRepulsion([],[1],0,.1);assert.ok(Math.abs(closing[0]!.angle)>Math.abs(initial[0]!.angle)-Math.abs(opening[0]!.angle))
 const e=new ArcEngine();e.setReduced(true);e.select(0);near(e.snapshot().repulsion!.find(s=>s.logical===1)!.angle,repulsionTarget(1,0));e.back();e.update(10);assert.ok(e.snapshot().repulsion!.every(s=>s.angle===0&&s.velocity===0));assert.equal(e.moving,false)
})
test('large-coordinate rebasing shifts magnetic identity without changing physical deformation',()=>{
 const e=new ArcEngine();e.position=10005;e.target=10005;e.select(0);run(e);e.back();const prior=e.snapshot().repulsion!;for(let t=3010;e.mode!=='browse'&&t<6000;t+=16)e.update(t);const after=e.snapshot().repulsion!;assert.ok(after.every(s=>Math.abs(s.logical)<10));assert.ok(prior.some(s=>s.angle!==0));assert.ok(after.some(s=>s.angle!==0))
})
