import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as THREE from 'three'
import {readingMaterial} from './read-material.ts'
import {ArcEngine} from './arc-engine.ts'
import {isReadingSelected,readingFocusWeight,makeReadingMotion,updateReadingMotion} from './read-motion.ts'
function material(name:string,opacity:number){const m=new THREE.MeshStandardMaterial({name,opacity});m.userData.originalOpacity=opacity;return m}
test('rear privacy glass frosts smoothly while own optic stays opaque',()=>{
 const shell=material('MAT_archive_shell',.24),ring=material('MAT_archive_optics',1),lid=material('MAT_archive_lid',.10)
 for(let i=0;i<=100;i++){const glow=i/100;readingMaterial(shell,'ARCHIVE_body_1',1,glow,'available');readingMaterial(ring,'OPTIC_main',1,glow,'available');readingMaterial(lid,'LID_panel_1',1,glow,'available');assert.ok(Math.abs(shell.opacity-(.24+.72*glow))<1e-12);assert.equal(ring.opacity,1);assert.equal(ring.depthWrite,true);assert.equal(ring.transparent,false);assert.ok(lid.opacity<=.17)}
 readingMaterial(shell,'ARCHIVE_body',1,0,'available');assert.equal(shell.opacity,.24)
})
test('only small optic receives green reading emission, copies stay independent',()=>{
 const a=material('MAT_archive_small_amber',1),b=material('MAT_archive_optics',1)
 readingMaterial(a,'OPTIC_small',1,.5,'available');readingMaterial(b,'OPTIC_main',1,1,'available');assert.equal(a.emissiveIntensity,.34);assert.equal(b.emissiveIntensity,0)
 const copy=a.clone();copy.userData.originalOpacity=1;readingMaterial(copy,'OPTIC_small',1,0,'available');assert.equal(a.emissiveIntensity,.34);assert.equal(copy.emissiveIntensity,0)
})
test('visibility fade has no selected-card opacity or render-order promotion',()=>{
 const m=material('MAT_archive_optics',1);readingMaterial(m,'OPTIC_main',.4,1,'available');assert.equal(m.opacity,.4);readingMaterial(m,'OPTIC_main',.4,0,'available');assert.equal(m.opacity,.4)
})
test('center preselection progressively frosts and glows without opening details or spinning',()=>{
 const engine=new ArcEngine(),motion=makeReadingMotion(),shell=material('MAT_archive_shell',.24),small=material('MAT_archive_small_amber',1)
 const frame=(n:number)=>{const state=engine.update(n*1000/60);updateReadingMotion(motion,0,isReadingSelected(0,state),1/60,false,readingFocusWeight(0,state.position));readingMaterial(shell,'ARCHIVE_body_1',1,motion.glow,'available');readingMaterial(small,'OPTIC_small',1,motion.glow,'available')}
 frame(0);assert.ok(shell.opacity>.24&&shell.opacity<.31);assert.ok(small.emissiveIntensity>0);assert.equal(motion.angle,0)
 for(let n=1;n<120;n++)frame(n)
 assert.equal(shell.opacity,.96);assert.equal(shell.roughness,.9);assert.equal(small.emissiveIntensity,.68);assert.equal(engine.mode,'browse');assert.equal(engine.phase,0);assert.equal(motion.angle,0)
 engine.select(0);for(let n=120;n<240;n++)frame(n)
 assert.equal(shell.opacity,.96);assert.ok(motion.angle>0);assert.equal(shell.transparent,true);assert.equal(shell.depthWrite,false)
 engine.back();for(let n=240;n<480;n++)frame(n)
 assert.equal(motion.speed,0);assert.equal(shell.opacity,.96)
 engine.step(1);for(let n=480;n<720;n++)frame(n)
 assert.equal(shell.opacity,.24);assert.equal(shell.roughness,.55);assert.equal(small.emissiveIntensity,0)
})
