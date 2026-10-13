import {test} from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import {ArcEngine} from './arc-engine.ts'
import {panelExchange} from './panel-exchange.ts'
test('browse clears left before any detail text appears; both endpoints exact',()=>{
 assert.deepEqual(panelExchange(0),{browseExit:0,browseOpacity:1,detailReveal:0,detailX:-28,detailVisible:false})
 assert.equal(panelExchange(1).browseExit,1);assert.equal(panelExchange(1).detailReveal,1)
 let last=panelExchange(0)
 for(let i=0;i<=1000;i++){const p=panelExchange(i/1000);assert.ok(p.browseExit>=last.browseExit);assert.ok(p.detailReveal>=last.detailReveal);if(p.detailVisible){assert.equal(p.browseExit,1);assert.equal(p.browseOpacity,0)}last=p}
})
test('rapid select-close-reselect keeps every panel property continuous and latest module wins',()=>{
 const e=new ArcEngine();e.update(0)
 for(let t=16;t<900;t+=16){const prior=panelExchange(e.phase);if(t%64===0)e.back();else if(t%48===0)e.select(t%5);assert.deepEqual(panelExchange(e.phase),prior);e.update(t)}
 e.select(3);for(let t=900;t<3000;t+=16)e.update(t);assert.equal(e.selected,3);assert.equal(e.phase,1)
 e.back();for(let t=3000;t<5000;t+=16)e.update(t);assert.equal(e.mode,'browse');assert.equal(panelExchange(e.phase).browseExit,0)
})
test('reverse path uses identical geometry and reduced motion resolves immediately',()=>{
 for(let i=0;i<=100;i++){const phase=i/100;assert.ok(Math.abs(panelExchange(phase).browseExit-panelExchange(1-(1-phase)).browseExit)<1e-12)}
 const e=new ArcEngine();e.setReduced(true);e.select(1);assert.equal(panelExchange(e.phase).detailReveal,1);e.back();e.update(0);assert.equal(panelExchange(e.phase).browseOpacity,1)
})
test('browse remains mounted, hidden controls are inert, focus returns and layout uses continuous phase',()=>{
 const app=fs.readFileSync(new URL('./App.vue',import.meta.url),'utf8'),css=fs.readFileSync(new URL('./style.css',import.meta.url),'utf8')
 assert.match(app,/<section ref="browseControls" class="archive-copy" :style="browseStyle" :inert="expanded" :aria-hidden="expanded"/)
 assert.match(app,/:inert="!detailInteractive" :aria-hidden="!detailInteractive"/)
 assert.match(app,/watch\(detailInteractive/);assert.match(app,/mode==='browse'/);assert.match(app,/getClientRects\(\).length/)
 assert.doesNotMatch(app,/v-show="!expanded"/)
 assert.match(css,/-100% - 8vw/);assert.match(css,/695px \+ 195px \* var\(--scene-progress,0\)/)
})
