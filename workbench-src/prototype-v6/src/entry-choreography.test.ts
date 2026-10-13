import {test} from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import * as THREE from 'three'
import {entryScenePose,RING_CONTRACTION,interpolate,LOGO_BRUSHES,logoBrushProgress} from './entry-choreography.ts'
import {entryVisuals,DashboardFlow,ENTRY_TIMING} from './dashboard-flow.ts'
test('measured logo translates left at constant size and y, with exact source normalized distance',()=>{
 let previous=50
 for(let n=0;n<=100;n++){const v=entryVisuals({stage:'arriving',progress:n/100,demo:false});assert.equal(v.logoScale,1);assert.equal(v.logoY,49.3);assert.ok(v.logoX<=previous);previous=v.logoX}
 assert.ok(Math.abs(50-previous-131/852*100)<1e-10)
})
test('independent inward ring tracks retain measured radii and omit alternating flash substitutions',()=>{
 for(const [p,r] of RING_CONTRACTION)assert.equal(interpolate(RING_CONTRACTION,p),r)
 let radius=Infinity
 for(let n=0;n<=100;n++){const v=entryVisuals({stage:'confirmed',progress:n/100,demo:false});assert.ok(v.ringRadius<=radius);radius=v.ringRadius;assert.ok(v.whiteRadius<v.ringRadius);assert.notEqual(v.whiteAngle,v.outerAngle)}
 assert.equal(radius,110)
})
test('original-pixel brush paths reveal in separate schedules and restore full official PNG',()=>{
 assert.equal(LOGO_BRUSHES.length,6)
 for(const b of LOGO_BRUSHES){assert.equal(logoBrushProgress(0,b.start,b.end),0);assert.equal(logoBrushProgress(1,b.start,b.end),1)}
 const end=entryVisuals({stage:'access',progress:0,demo:false});assert.equal(end.logoFull,1);assert.equal(end.logoCenter,1)
 const app=fs.readFileSync(new URL('./App.vue',import.meta.url),'utf8');assert.match(app,/<image :href="officialLogo"/);assert.match(app,/mask="url\(#official-logo-mask\)"/);assert.doesNotMatch(app,/v-if="!credentialRequested" class="logo-subject"/)
})
test('collective root and real oblique camera move GLB-space landmarks and settle at exact old pose',()=>{
 const positions=[]
 for(const p of[0,.25,.5,.75,1]){const pose=entryScenePose(p),root=new THREE.Group(),camera=new THREE.OrthographicCamera(-5,5,5,-5,.1,80);root.position.set(pose.rootX,pose.rootY,pose.rootZ);root.rotation.set(pose.rootRotationX,pose.rootRotationY,pose.rootRotationZ);root.updateMatrixWorld();camera.position.set(pose.cameraX,pose.cameraY,pose.cameraZ);camera.lookAt(0,0,0);camera.zoom=pose.cameraZoom;camera.updateProjectionMatrix();camera.updateMatrixWorld();positions.push(new THREE.Vector3(1,2,3).applyMatrix4(root.matrixWorld).project(camera).toArray())}
 assert.equal(new Set(positions.map(p=>p.join(','))).size,5)
 const final=entryScenePose(1);for(const key of ['rootX','rootY','rootZ','rootRotationX','rootRotationY','rootRotationZ','cameraX','cameraY'] as const)assert.equal(Math.abs(final[key]),0);assert.equal(final.cameraZoom,1);assert.equal(final.cameraZ,20)
 const source=fs.readFileSync(new URL('./ArchiveArc.vue',import.meta.url),'utf8');assert.match(source,/entryRoot!\.add\(root\)/);assert.match(source,/camera\.position\.set\(pose.cameraX/);assert.match(source,/props.entryProgress/)
})
test('welcome holds before geometry traversal, and browse hierarchy enters after geometry starts',()=>{
 const a=entryVisuals({stage:'entering',progress:.15,demo:true}),b=entryVisuals({stage:'entering',progress:.5,demo:true});assert.equal(a.scene,0);assert.equal(a.welcomeOpacity,1);assert.ok(b.scene>0);assert.equal(b.workspaceOpacity,0)
})
test('skip cannot manufacture proof, and cancellation/reset blocks stale reentry at every motion point',()=>{
 const f=new DashboardFlow();assert.equal(f.skipPresentation(),false);const id=f.beginVerification(0);assert.equal(f.skipPresentation(),false);f.acceptVerified(id,true,1);assert.equal(f.skipPresentation(),true);assert.equal(f.stage,'workspace');f.returnAccess();assert.equal(f.skipPresentation(),false)
 for(const fraction of[.01,.2,.5,.99]){const flow=new DashboardFlow();flow.startDemo(0);flow.update(ENTRY_TIMING.demoVerification);flow.update(ENTRY_TIMING.demoVerification+ENTRY_TIMING.confirmed);flow.update(ENTRY_TIMING.demoVerification+ENTRY_TIMING.confirmed+fraction*ENTRY_TIMING.entering);flow.returnAccess();flow.update(1e6);assert.equal(flow.stage,'access');assert.equal(entryVisuals(flow.snapshot()).scene,0)}
})
test('request status types as a finite local track without changing indeterminate auth progress',()=>{
 const f=new DashboardFlow();f.beginVerification(0);f.update(120);assert.equal(f.progress,0);assert.equal(f.statusProgress,.5);assert.equal(entryVisuals(f.snapshot()).statusReveal,.5);assert.equal(f.stage,'verifying');f.update(240);assert.equal(f.statusProgress,1);assert.equal(f.progress,0);assert.equal(f.moving,false);f.update(60000);assert.equal(f.stage,'verifying')
})
test('arrival skip reveals access without waiting or fabricating authorization',()=>{const f=new DashboardFlow();assert.equal(f.skipArrival(),true);assert.equal(f.stage,'access');assert.equal(f.skipPresentation(),false);assert.equal(f.demo,false);assert.equal(f.skipArrival(),false)})
test('visible institution brand is singular 2718lab while compatibility API names remain untouched',()=>{
 const app=fs.readFileSync(new URL('./App.vue',import.meta.url),'utf8'),login=fs.readFileSync(new URL('./LoginPanel.vue',import.meta.url),'utf8'),html=fs.readFileSync(new URL('../index.html',import.meta.url),'utf8');assert.match(app,/<strong>2718lab<\/strong>/);assert.match(app,/>2718lab<\/a>/);assert.doesNotMatch(app,/>SYLANNE|>Sylanne|>2718LABS/);assert.doesNotMatch(login,/SYLANNE \/ WORKBENCH|Sylanne 所有者/);assert.match(html,/<title>2718lab/);assert.match(fs.readFileSync(new URL('./api/contract.ts',import.meta.url),'utf8'),/Sylanne3 Owner session login v1/)
})
test('hidden model fallback controls are inert until workspace',()=>{const app=fs.readFileSync(new URL('./App.vue',import.meta.url),'utf8');assert.match(app,/aria-label="圆弧光学档案导航" :aria-hidden="loginVisible\|\|exitState.blocked" :inert="loginVisible\|\|exitState.blocked"/);assert.match(app,/class="terminal-focus" :inert="route.stage==='arriving'&&entryMotion.statusReveal<.08"/);assert.match(app,/class="skip-intro" @click="skipIntro"/);const css=fs.readFileSync(new URL('./style.css',import.meta.url),'utf8');assert.match(css,/\.workspace-shell \.brand,\.terminal-brand\{top:5svh\}/);assert.match(css,/585px \+ 95px \* var\(--scene-progress,0\)/);assert.match(css,/615px \+ 145px \* var\(--scene-progress,0\)/)})

test('slower decorative entry preserves zero auth delay and a readable welcome hold after rings settle',()=>{
 assert.equal(ENTRY_TIMING.minimumVerification,0)
 assert.equal(ENTRY_TIMING.arrival+ENTRY_TIMING.demoVerification+ENTRY_TIMING.confirmed+ENTRY_TIMING.entering,8500)
 const settled=entryVisuals({stage:'confirmed',progress:.72,demo:true});assert.equal(settled.ringRadius,110);assert.equal(settled.welcomeOpacity,0)
 const welcome=entryVisuals({stage:'confirmed',progress:.96,demo:true});assert.equal(welcome.ringOpacity,0);assert.equal(welcome.welcomeOpacity,1);assert.equal(welcome.welcomeLine2,1);assert.equal(welcome.welcomeLine3,1)
 for(const p of[0,.1,.2,.3,.4]){const v=entryVisuals({stage:'entering',progress:p,demo:true});assert.equal(v.welcomeOpacity,1);assert.equal(v.scene,0)}
 assert.ok(ENTRY_TIMING.confirmed*.08+ENTRY_TIMING.entering*.4>=1200)
 const app=fs.readFileSync(new URL('./App.vue',import.meta.url),'utf8');assert.match(app,/>WELCOME BACK</);assert.doesNotMatch(app,/brand-official-logo/);assert.match(app,/<image :href="officialLogo"/)
})
test('no late duplicate emblem appears in either frontend workspace header or offline chrome',()=>{
 const app=fs.readFileSync(new URL('./App.vue',import.meta.url),'utf8'),cpu=fs.readFileSync(new URL('../../model-scripts/render_archive_arc_v17.py',import.meta.url),'utf8')
 const header=app.slice(app.indexOf('<header class="brand">'),app.indexOf('</header>',app.indexOf('<header class="brand">')))
 assert.doesNotMatch(header,/<img|<svg|officialLogo/);assert.match(header,/>2718lab<\/a>/)
 const chrome=cpu.slice(cpu.indexOf('def workspace_chrome('),cpu.indexOf('def finish_chrome('));assert.doesNotMatch(chrome,/OFFICIAL_LOGO|official_logo\(/)
 assert.match(cpu,/label='WELCOME BACK'/)
})
test('full welcome hold remains immediately skippable and reduced motion reaches the semantic endpoint',()=>{
 for(const progress of[0,.3,.8]){const f=new DashboardFlow();f.startDemo(0);f.update(ENTRY_TIMING.demoVerification);f.update(ENTRY_TIMING.demoVerification+ENTRY_TIMING.confirmed);f.update(ENTRY_TIMING.demoVerification+ENTRY_TIMING.confirmed+ENTRY_TIMING.entering*progress);assert.equal(f.skipPresentation(),true);assert.equal(f.stage,'workspace')}
 const live=new DashboardFlow();live.setReduced(true);const generation=live.beginVerification(0);live.update(1e6);assert.equal(live.stage,'verifying');assert.equal(live.acceptVerified(generation,true,1e6),true);assert.equal(live.stage,'workspace')
})
