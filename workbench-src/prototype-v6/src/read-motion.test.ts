import {test} from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import {ArcEngine,visibleSlots,ARC_POOL_SIZE} from './arc-engine.ts'
import {bindReadingIdentity,isReadingSelected,readingFocusWeight,makeReadingMotion,updateReadingMotion} from './read-motion.ts'
test('focus has compact support and continuous complementary neighbor weights',()=>{
 for(let n=0;n<=1000;n++){const p=n/1000,a=readingFocusWeight(0,p),b=readingFocusWeight(1,p);assert.ok(Math.abs(a+b-1)<1e-12);assert.equal(readingFocusWeight(-1,p),0);assert.equal(readingFocusWeight(2,p),0)}
 assert.equal(readingFocusWeight(0,0),1);assert.equal(readingFocusWeight(0,.5),.5)
 assert.ok(Math.abs(readingFocusWeight(0,.499999)-readingFocusWeight(0,.500001))<.00001)
})
test('initial center and newly docked center glow without rotation or selection',()=>{
 const e=new ArcEngine(),pool=Array.from({length:ARC_POOL_SIZE},makeReadingMotion)
 const tick=(n:number)=>{const s=e.update(n*1000/60);for(const slot of visibleSlots(s.position,s.count)){const m=pool[slot.slot];updateReadingMotion(m,slot.logical,isReadingSelected(slot.logical,s),1/60,false,readingFocusWeight(slot.logical,s.position));assert.equal(m.speed,0);assert.equal(m.angle,0)}}
 for(let n=0;n<120;n++)tick(n);assert.equal(pool[0].glow,1);assert.equal(e.mode,'browse');assert.equal(e.phase,0)
 e.step(1);let maxSum=0;for(let n=120;n<300;n++){tick(n);maxSum=Math.max(maxSum,pool.reduce((s,m)=>s+m.glow,0))}
 assert.ok(maxSum<=1.001);assert.equal(pool[0].glow,0);assert.equal(pool[1].glow,1);assert.equal(e.mode,'browse');assert.equal(e.phase,0)
})
test('selected large ring gently spins; unselect coasts with no angle jump and eventually stops',()=>{
 const m=makeReadingMotion();for(let n=0;n<240;n++)updateReadingMotion(m,1,true,1/60,false,1)
 assert.equal(m.glow,1);assert.ok(m.speed>.129&&m.speed<=.13);assert.ok(m.angle>.45&&m.angle<.55)
 const angle=m.angle,speed=m.speed;updateReadingMotion(m,1,false,0,false,1);assert.equal(m.angle,angle);assert.equal(m.speed,speed)
 updateReadingMotion(m,1,false,1/60,false,1);assert.ok(m.angle>angle);assert.ok(m.speed>0&&m.speed<speed)
 for(let n=0;n<240;n++)updateReadingMotion(m,1,false,1/60,false,1)
 assert.equal(m.speed,0);assert.equal(m.glow,1);const stopped=m.angle;updateReadingMotion(m,1,false,1/60,false,1);assert.equal(m.angle,stopped)
})
test('rapid selection changes activate latest ring; prior selected ring only decelerates',()=>{
 const e=new ArcEngine(),pool=Array.from({length:ARC_POOL_SIZE},makeReadingMotion)
 for(let n=0;n<360;n++){if(n===0)e.select(0);if(n===30)e.select(1);if(n===32)e.select(2);if(n===34)e.select(0);const s=e.update(n*1000/60);for(const slot of visibleSlots(s.position,s.count))updateReadingMotion(pool[slot.slot],slot.logical,isReadingSelected(slot.logical,s),1/60,false,readingFocusWeight(slot.logical,s.position))}
 assert.equal(e.selected,0);assert.equal(e.mode,'detail');assert.ok(pool[0].speed>.129);assert.equal(pool[1].speed,0);assert.equal(pool[2].speed,0)
})
test('reduced motion resolves optical status immediately without moving the ring',()=>{
 const m=makeReadingMotion();updateReadingMotion(m,0,false,1/60,true,1);assert.equal(m.glow,1);assert.equal(m.speed,0);assert.equal(m.angle,0)
 updateReadingMotion(m,0,true,1/60,true,1);assert.equal(m.angle,0);updateReadingMotion(m,0,false,1/60,true,0);assert.equal(m.glow,0)
})
test('recycling resets only a changed physical identity; reversals preserve pose',()=>{
 const m=makeReadingMotion();for(let n=0;n<60;n++)updateReadingMotion(m,1,true,1/60,false,1)
 const before={...m};updateReadingMotion(m,1,false,0,false,0);assert.deepEqual(m,before);updateReadingMotion(m,1,true,0,false,1);assert.deepEqual(m,before)
 bindReadingIdentity(m,10);assert.deepEqual(m,{logical:10,glow:0,speed:0,angle:0})
})
test('renderer derives focus from physical arc position, while only OPTIC_main spins',()=>{
 const src=fs.readFileSync(new URL('./ArchiveArc.vue',import.meta.url),'utf8')
 assert.match(src,/readingFocusWeight\(slot.logical,props.frame.position\)/)
 assert.match(src,/isReadingSelected\(slot.logical,props.frame\)/)
 assert.match(src,/get\('OPTIC_main'\)!\.rotation.z=item.reading.angle/)
 assert.doesNotMatch(src,/get\('OPTIC_small'\)!\.rotation/)
})

test('v18 cancel keeps centrally docked frost powered and smoothly decelerates the main ring',()=>{const motion=makeReadingMotion();for(let i=0;i<120;i++)updateReadingMotion(motion,5,true,1/60,false,1);const before={...motion};updateReadingMotion(motion,5,false,1/60,false,1);assert.equal(motion.glow,1);assert.ok(motion.speed>0&&motion.speed<before.speed);assert.ok(motion.angle>before.angle);for(let i=0;i<240;i++)updateReadingMotion(motion,5,false,1/60,false,1);assert.equal(motion.glow,1);assert.equal(motion.speed,0)});
