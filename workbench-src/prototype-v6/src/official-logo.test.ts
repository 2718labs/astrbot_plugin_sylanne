import {test} from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import crypto from 'node:crypto'
import {officialLogo} from './assets/2718labs-logo.ts'
import {entryVisuals,ENTRY_TIMING} from './dashboard-flow.ts'
test('official 2718labs pixels match provenance and are embedded without an external request',()=>{
 const bytes=Buffer.from(officialLogo.split(',')[1]!,'base64')
 assert.deepEqual(bytes,fs.readFileSync('../official-assets/2718labs-github-avatar.png'))
 assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),'84c1b7ef1928ea8851d34e12339328490b1a89c78356816b6c222fd8baf94618')
 assert.equal(bytes.readUInt32BE(16),200);assert.equal(bytes.readUInt32BE(20),200)
})
test('logo reveal and travel are bounded and continuous through confirmation into archive',()=>{
 const start=entryVisuals({stage:'arriving',progress:0,demo:true}),ready=entryVisuals({stage:'access',progress:0,demo:true})
 assert.equal(start.logoReveal,0);assert.equal(ready.logoReveal,1);assert.equal(ready.logoOpacity,1)
 const confirm=entryVisuals({stage:'confirmed',progress:1,demo:true}),enter=entryVisuals({stage:'entering',progress:0,demo:true})
 for(const key of ['logoX','logoY','logoScale','logoOpacity'] as const)assert.equal(confirm[key],enter[key])
 let x=0,opacity=1
 for(let i=0;i<=50;i++){const v=entryVisuals({stage:'entering',progress:i/50,demo:true});assert.ok(v.logoX>=x);assert.ok(v.logoOpacity<=opacity);assert.ok(v.logoScale>0&&v.logoScale<=1);x=v.logoX;opacity=v.logoOpacity}
 assert.equal(opacity,0);assert.ok(ENTRY_TIMING.entering>=1200);assert.equal(ENTRY_TIMING.minimumVerification,0)
})
test('logo motion retains cancel, accessible branding and reduced-motion paths',()=>{
 const app=fs.readFileSync('src/App.vue','utf8'),css=fs.readFileSync('src/style.css','utf8')
 assert.doesNotMatch(app,/class="terminal-mark"/);assert.match(app,/class="logo-subject"/)
 assert.match(app,/@click="cancelEntry"/);assert.match(css,/\.reduce-motion \.logo-subject/)
 assert.match(css,/@media\(prefers-reduced-motion:reduce\)/);assert.match(css,/object-fit:contain/)
})
