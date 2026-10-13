import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as THREE from 'three'
import {ArcEngine} from './arc-engine.ts'
import {panelExchange} from './panel-exchange.ts'
import {logoutVisuals} from './logout-flow.ts'
import {readingMaterial} from './read-material.ts'

test('departing detail never reverses into browse while the engine closes',()=>{
 const e=new ArcEngine();e.setReduced(true);e.select(0);e.setReduced(false);const departure=e.snapshot().phase;e.wake(0);e.back()
 for(let now=0;now<=960;now+=4){const f=e.update(now),panel=panelExchange(f.phase,departure);assert.equal(panel.browseOpacity*logoutVisuals(now/960).workspace,0);assert.equal(panel.detailReveal,1)}
})
test('logout from browse preserves its existing pose without replaying a panel transition',()=>{
 for(let phase=0;phase<=1;phase+=.05){const capture=panelExchange(phase);for(let now=0;now<=960;now+=8){assert.deepEqual(panelExchange(Math.max(0,phase-now/960),phase),capture)}}
})
test('opacity classification invalidates the actual Three shader only when it changes',()=>{
 const m=new THREE.MeshStandardMaterial({opacity:1});m.userData.originalOpacity=1;const version=m.version
 readingMaterial(m,'OPTIC_main',1,0,'available');assert.equal(m.version,version)
 readingMaterial(m,'OPTIC_main',.99,0,'available');assert.equal(m.transparent,true);assert.equal(m.depthWrite,false);assert.equal(m.version,version+1)
 readingMaterial(m,'OPTIC_main',.25,0,'available');assert.equal(m.version,version+1)
 readingMaterial(m,'OPTIC_main',1,0,'available');assert.equal(m.transparent,false);assert.equal(m.depthWrite,true);assert.equal(m.version,version+2)
})
