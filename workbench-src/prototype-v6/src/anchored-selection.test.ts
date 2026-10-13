import {test} from 'node:test'
import fs from 'node:fs'
import assert from 'node:assert/strict'
import {ArcEngine,visibleSlots,modulo,type ArcSnapshot} from './arc-engine.ts'
import {arcLayout,slotTransform,readingStageShift} from './arc-model.ts'
import {repulsionTarget} from './arc-repulsion.ts'
import {SELECTION_RADIAL_DISTANCE,advanceRadial,radialMoving,radialOffset} from './arc-selection.ts'

// Preserve the stationary geometry regressions from the original selection suite.
// A direct click now docks its disk; only an already-centered disk stays in place.
const near=(a:number,b:number,epsilon=1e-10)=>assert.ok(Math.abs(a-b)<=epsilon,`${a} != ${b}`)
const poseKeys=['x','y','z','rotationX','rotationY','rotationZ','scale','lidRotationY'] as const
function pose(state:ArcSnapshot,logical:number,aspect=1.056){
 const slot=visibleSlots(state.position,state.count).find(s=>s.logical===logical)
 assert.ok(slot,`physical logical ${logical} remains in the pool`)
 return slotTransform(slot,state,aspect)
}
function samePose(before:ArcSnapshot,after:ArcSnapshot){
 for(const slot of visibleSlots(before.position,before.count)){
  const a=pose(before,slot.logical),b=pose(after,slot.logical)
  for(const key of poseKeys)near(a[key],b[key])
 }
 assert.deepEqual(after.repulsion,before.repulsion)
 assert.deepEqual(after.radial,before.radial)
}
function run(engine:ArcEngine,start=0,duration=3000){for(let t=start;t<=start+duration;t+=8)engine.update(t);return engine.snapshot()}

test('clicking the already-centered preselected browse disk adds only .10 monotonic radial extraction',()=>{
 assert.equal(SELECTION_RADIAL_DISTANCE,.10)
 for(const aspect of[.39,.75,1.056,1.6])for(const logical of[-7,0,7]){
  const engine=new ArcEngine();engine.position=logical;engine.target=logical;engine.update(0)
  const before=engine.snapshot(),base=pose(before,logical,aspect),layout=arcLayout(aspect)
  assert.equal(before.mode,'browse');assert.equal(before.selected,modulo(logical,engine.count));assert.equal(before.phase,0)
  const ux=(base.x-layout.cx)/layout.radius,uy=(base.y-layout.cy)/layout.radius
  assert.equal(engine.toggleSelect(logical),true);samePose(before,engine.snapshot());let previous=0
  for(let t=8;t<=3000;t+=8){
   const state=engine.update(t),selected=pose(state,logical,aspect),dx=selected.x-base.x,dy=selected.y-base.y
   const outward=dx*ux+dy*uy,tangential=-dx*uy+dy*ux
   near(tangential,0);assert.ok(outward>=previous-1e-12&&outward<=.10+1e-12)
   near(outward,radialOffset(state.radial,logical));previous=outward
   assert.equal(state.position,logical);assert.equal(engine.velocity,0)
   for(const key of ['z','rotationX','rotationY','rotationZ','scale','lidRotationY'] as const)near(selected[key],base[key])
   for(const other of state.radial!.filter(s=>s.logical!==logical))assert.equal(other.offset,0)
  }
  near(previous,SELECTION_RADIAL_DISTANCE);assert.equal(engine.mode,'detail');assert.equal(engine.moving,false)
 }
})

test('panel phase cannot translate the complete ring at any viewport aspect',()=>{
 const engine=new ArcEngine(),base=engine.snapshot()
 for(const aspect of[.39,.75,1.056,1.6])for(const phase of[0,.1,.5,.9,1]){
  assert.deepEqual(readingStageShift(phase,aspect),{x:0,y:0})
  for(const slot of visibleSlots(base.position,base.count)){
   const a=slotTransform(slot,base,aspect),b=slotTransform(slot,{...base,phase,mode:'opening'},aspect)
   for(const key of poseKeys)assert.equal(a[key],b[key])
  }
 }
})

test('centered selection repels immediate neighbors most while preserving radius and shingle depth',()=>{
 const engine=new ArcEngine();engine.update(0);const base=engine.snapshot(),layout=arcLayout(1.056)
 engine.toggleSelect(0);const end=run(engine,8)
 for(const sample of end.repulsion!.filter(s=>s.logical!==0)){
  near(sample.angle,repulsionTarget(sample.logical,0))
  assert.equal(Math.sign(sample.angle),-Math.sign(sample.logical))
  const a=pose(base,sample.logical),b=pose(end,sample.logical)
  near(Math.hypot(b.x-layout.cx,b.y-layout.cy),layout.radius)
  for(const key of ['z','scale','rotationX','rotationY','lidRotationY'] as const)near(a[key],b[key])
 }
 assert.ok(Math.abs(end.repulsion!.find(s=>s.logical===1)!.angle)>3*Math.abs(end.repulsion!.find(s=>s.logical===2)!.angle))
 assert.equal(end.position,base.position)
})

test('cancel after docking retracts radial lift and neighbor field smoothly while the center stays put',()=>{
 const engine=new ArcEngine();engine.position=.37;engine.target=.37;engine.toggleSelect(1);run(engine)
 const before=engine.snapshot();assert.equal(before.position,1);engine.toggleSelect(1);samePose(before,engine.snapshot())
 const first=engine.update(3008)
 assert.ok(radialOffset(first.radial,1)>0&&radialOffset(first.radial,1)<SELECTION_RADIAL_DISTANCE)
 assert.ok(first.repulsion!.some(s=>s.angle!==0));assert.equal(engine.moving,true)
 const end=run(engine,3016)
 assert.equal(end.mode,'browse');assert.equal(end.position,1);assert.equal(end.selected,1);assert.equal(engine.moving,false)
 assert.ok(end.radial!.every(s=>s.offset===0&&s.velocity===0));assert.ok(end.repulsion!.every(s=>s.angle===0&&s.velocity===0))
})

test('reduced motion docks the selected disk and resolves both fields immediately',()=>{
 for(const reduceBefore of[false,true]){
  const engine=new ArcEngine();if(reduceBefore)engine.setReduced(true)
  engine.position=.37;engine.target=.37;engine.toggleSelect(1)
  if(!reduceBefore){engine.update(0);engine.update(32);engine.setReduced(true)}
  const selected=engine.snapshot();assert.equal(selected.position,1);assert.equal(selected.mode,'detail');assert.equal(engine.moving,false)
  near(radialOffset(selected.radial,1),SELECTION_RADIAL_DISTANCE)
  assert.ok(selected.radial!.every(s=>s.velocity===0));assert.ok(selected.repulsion!.every(s=>s.velocity===0))
  assert.equal(selected.repulsion!.find(s=>s.logical===1)!.angle,0)
  engine.toggleSelect(1);engine.update(40)
  assert.equal(engine.position,1);assert.equal(engine.mode,'browse');assert.equal(engine.moving,false)
  assert.ok(engine.snapshot().radial!.every(s=>s.offset===0&&s.velocity===0))
 }
})

test('radial spring is identity-keyed, independent of frame subdivision and coasts through interruptions',()=>{
 const logicals=[-1,0,1],single=advanceRadial([],logicals,0,.1)
 let split=advanceRadial([],logicals,0,0)
 for(let n=0;n<10;n++)split=advanceRadial(split,logicals,0,.01)
 for(let i=0;i<single.length;i++){near(single[i]!.offset,split[i]!.offset);near(single[i]!.velocity,split[i]!.velocity)}
 assert.deepEqual(advanceRadial(single,logicals,1,0),single)
 const closing=advanceRadial(single,logicals,null,.016)
 assert.ok(closing[1]!.offset>single[1]!.offset,'release preserves outward momentum before damping it')
 assert.equal(radialMoving(closing,null),true)
 const recycled=advanceRadial(single,[1,2,3],2,0)
 assert.equal(recycled.find(s=>s.logical===1)!.offset,0);assert.equal(recycled.find(s=>s.logical===2)!.offset,0)
 assert.deepEqual(advanceRadial(single,logicals,null,0,true),logicals.map(logical=>({logical,offset:0,velocity:0})))
})

test('large-coordinate rebasing preserves docked radial identity and returns to rest',()=>{
 const engine=new ArcEngine();engine.position=10005.37;engine.target=engine.position;engine.toggleSelect(10006);run(engine)
 const before=engine.snapshot(),logical=engine.logical;assert.equal(logical,10006);assert.equal(before.position,logical)
 engine.back();let time=3008,rebased:ArcSnapshot|undefined
 for(;time<5000;time+=8){const state=engine.update(time);if(Math.abs(state.position)<10000){rebased=state;break}}
 assert.ok(rebased);const shift=before.position-rebased.position;near(shift/7,Math.round(shift/7))
 const sample=rebased.radial!.find(s=>s.logical===logical-shift);assert.ok(sample&&sample.offset>0)
 assert.equal(modulo(logical-shift,7),modulo(logical,7));run(engine,time+8)
 assert.equal(engine.moving,false);assert.ok(engine.snapshot().radial!.every(s=>s.offset===0&&s.velocity===0))
})

test('active stacked responsive layout reserves the same arc origin through selection and logout',()=>{
 const css=fs.readFileSync(new URL('./style.css',import.meta.url),'utf8')
 const start=css.lastIndexOf('@media(max-width:1100px),(max-aspect-ratio:4/3){'),end=css.indexOf('@media(max-width:700px)',start),stacked=css.slice(start,end)
 assert.ok(start>=0)
 assert.doesNotMatch(stacked,/var\(--scene-progress,0\)/)
 assert.match(stacked,/top:calc\(var\(--stack-arc-top\) \+ var\(--stack-detail-extra\)\)/)
 assert.match(stacked,/--workspace-height:calc\(var\(--stack-arc-top\) \+ var\(--stack-detail-extra\) \+ var\(--stack-arc-height\) \+ 220px\)/)
 assert.match(stacked,/var\(--entry-scene\)/,'entry traversal remains choreographed')
})
