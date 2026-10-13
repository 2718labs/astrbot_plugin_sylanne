<script setup lang="ts">
import { computed,nextTick,onMounted,onBeforeUnmount,ref,watch } from 'vue'
import ArchiveArc from './ArchiveArc.vue'
import {officialLogo} from './assets/2718labs-logo.ts'
import LoginPanel from './LoginPanel.vue'
import ContentPanel from './ContentPanel.vue'
import UtilityPanel from './UtilityPanel.vue'
import ReplyControlsPanel from './ReplyControlsPanel.vue'
import {useBackend} from './use-backend'
import {ArcEngine,demoEntries,editableTarget,modulo,type ArcSnapshot} from './arc-engine'
import {DashboardFlow,entryVisuals,nearestArchiveLogical,type DashboardSnapshot} from './dashboard-flow'
import {LOGO_BRUSHES,logoBrushProgress} from './entry-choreography'
import {panelExchange} from './panel-exchange'
import {readActivityMode} from './read-activity'
import {SoftAudio} from './soft-audio'
import {useTheme} from './theme'
import {useDisplayAlias} from './ui-preferences'
import {LogoutFlow,logoutVisuals} from './logout-flow'
import {captureExitScene,type ExitSceneSnapshot} from './scene-presentation'
const theme=useTheme(),displayAlias=useDisplayAlias(),exit=new LogoutFlow(),exitRevision=ref(0)
const exitState=computed(()=>{void exitRevision.value;return {active:exit.active,blocked:exit.blocked,progress:exit.progress,result:exit.result,message:exit.message}})
const exitMotion=computed(()=>logoutVisuals(exitState.value.progress))
let exitPresented=false
const exitSnapshot=ref<ExitSceneSnapshot|null>(null)
function refreshExit(){exitRevision.value++}
function revealIfOutside(element:HTMLElement|null){if(!element||typeof element.getBoundingClientRect!=='function'||typeof element.scrollIntoView!=='function')return;const box=element.getBoundingClientRect(),height=window.innerHeight;if(height&&((box.bottom<=0)||(box.top>=height)))element.scrollIntoView({block:'nearest',behavior:reduced.value?'instant':'smooth'})}
function presentExit(){if(exitPresented||exit.active||exit.result==='none')return;exitPresented=true;flow.returnAccess(exit.message);request();void nextTick(()=>{accessScreen.value?.focus({preventScroll:true});revealIfOutside(accessScreen.value)})}
function clearExit(){if(exit.clear()){exitPresented=false;exitSnapshot.value=null;refreshExit()}}
const credentialRequested=ref(false),setupRequested=ref(false)
const backend=useBackend(),engine=new ArcEngine(),flow=new DashboardFlow(performance.now()),sound=new SoftAudio()
const frame=ref<ArcSnapshot>(engine.snapshot()),route=ref<DashboardSnapshot>(flow.snapshot()),reduced=ref(false),muted=ref(sound.muted),volume=ref(sound.volume),asset=ref<'loading'|'ready'|'failed'>('loading'),assetMessage=ref(''),modelRevision=ref(0)
const browseControls=ref<HTMLElement|null>(null),detail=ref<HTMLElement|null>(null),detailClose=ref<HTMLButtonElement|null>(null),accessScreen=ref<HTMLElement|null>(null),transitionCancel=ref<HTMLButtonElement|null>(null)
const presentedFrame=computed(()=>exitSnapshot.value?.frame??frame.value)
const entry=computed(()=>demoEntries[presentedFrame.value.selected]!),detailOpen=computed(()=>route.value.stage==='workspace'&&(frame.value.mode==='opening'||frame.value.mode==='detail')),expanded=computed(()=>frame.value.mode!=='browse'),loginVisible=computed(()=>route.value.stage!=='workspace'),canOpen=computed(()=>route.value.stage==='workspace'&&frame.value.mode==='browse'&&frame.value.count>0)
const utilityKind=computed(()=>entry.value.id==='demo-logs'?'logs':entry.value.id==='demo-settings'?'settings':null)
function moduleStatus(id:string){if(id==='demo-contact')return 'HOLD';if(id==='demo-life')return backend.canRead.value?'项目控制':'待核验';if(id==='demo-logs'||id==='demo-settings'){const management=backend.management;if(backend.state.mode==='offline')return '未接入';if(management.state.capabilities.status==='loading')return '核验中';const caps=management.state.capabilities.data?.capabilities;if(id==='demo-logs'&&caps?.logs.available)return '可读取';if(id==='demo-settings'&&caps?.settings.available)return caps.settings.writable_fields.includes('enabled')?'可配置':'只读';return management.state.capabilities.status==='idle'?'待核验':'不可用'}return backend.canRead.value?'授权读取':backend.management.state.runtime.data&&!backend.runtimeReadable.value?'不可用':'待核验'}
const opticalActivity=computed(()=>readActivityMode(backend.state,route.value.demo,route.value.stage==='workspace'))
const entryMotion=computed(()=>entryVisuals(route.value))
const typedCode=computed(()=>terminalCode.value.slice(0,Math.ceil(terminalCode.value.length*entryMotion.value.statusReveal)))
const gateLabel=computed(()=>{const label=route.value.demo?'DEMO INDEX READY':terminalCode.value;return label.slice(0,Math.ceil(label.length*Math.min(1,route.value.progress/.45)))})
function skipIntro(){if(flow.skipArrival()){request();void nextTick(()=>accessScreen.value?.focus({preventScroll:true}))}}
function skipEntry(){if(flow.skipPresentation())request()}
const transitionVisible=computed(()=>route.value.stage==='confirmed'||route.value.stage==='entering'||route.value.stage==='verifying')
const accessInteractive=computed(()=>route.value.stage!=='workspace')
const transitionTitle=computed(()=>route.value.stage==='verifying'?(route.value.demo?'演示载入':'核验会话'):route.value.stage==='confirmed'?(route.value.demo?'演示索引就绪':'访问已授权'):route.value.stage==='entering'?'档案索引':backend.state.error?'访问暂未完成':'访问档案')
const terminalCode=computed(()=>route.value.demo?'DEMO / NO AUTH':backend.state.auth==='authenticated'?'SESSION VERIFIED':backend.state.busy?'SESSION PENDING':backend.state.mode==='offline'?'OFFLINE / NO AUTH':backend.requiresHttps.value?'HTTPS REQUIRED':'ACCESS ARCHIVE')
async function requestAccess(){if(exitState.value.blocked||backend.state.busy||transitionVisible.value||backend.requiresHttps.value)return;clearExit();if(backend.state.mode==='offline'){startDemo();return}if(backend.state.auth==='authenticated'){continueVerified();return}await backend.checkSession()}
function requestCredentials(){if(exitState.value.blocked)return;clearExit();setupRequested.value=false;credentialRequested.value=true}
function requestSetup(){if(exitState.value.blocked)return;clearExit();setupRequested.value=true;credentialRequested.value=true}

const entryStyle=computed(()=>({'--status-reveal':entryMotion.value.statusReveal,'--logo-caption':entryMotion.value.logoCaption,'--old-opacity':entryMotion.value.logoOpacity,'--logo-x':`${entryMotion.value.logoX}%`,'--logo-y':`${entryMotion.value.logoY}%`,'--logo-scale':entryMotion.value.logoScale,'--logo-opacity':entryMotion.value.logoOpacity,'--logo-reveal':entryMotion.value.logoReveal,'--gate-spread':entryMotion.value.spread,'--gate-resolve':entryMotion.value.resolve,'--gate-center-x':`${50+50*entryMotion.value.scene}%`,'--gate-center-y':`${50+47*entryMotion.value.scene}%`,'--entry-arrival':entryMotion.value.arrival,'--entry-scene':entryMotion.value.scene,'--entry-arc-opacity':entryMotion.value.arcOpacity,'--entry-arc-offset':`${entryMotion.value.arcOffset}px`,'--entry-arc-scale':entryMotion.value.arcScale,'--entry-access-opacity':entryMotion.value.accessOpacity,'--entry-overlay-opacity':entryMotion.value.overlayOpacity,'--entry-ring-scale':entryMotion.value.ringScale,'--entry-workspace-opacity':entryMotion.value.workspaceOpacity,'--entry-workspace-offset':`${entryMotion.value.workspaceOffset}px`}))
// Freeze the departing panel pose: engine.back() must not replay browse beneath logout.
const panelMotion=computed(()=>panelExchange(frame.value.phase,exitSnapshot.value?.frame.phase))
const browseStyle=computed(()=>({'--browse-exit':panelMotion.value.browseExit,opacity:panelMotion.value.browseOpacity,visibility:panelMotion.value.browseExit===1?'hidden' as const:'visible' as const}))
const detailInteractive=computed(()=>!exitState.value.blocked&&detailOpen.value&&panelMotion.value.detailReveal>.08)
const detailReveal=computed(()=>panelMotion.value.detailReveal)
const detailStyle=computed(()=>({opacity:detailReveal.value*exitMotion.value.detail,transform:`translateX(${panelMotion.value.detailX+exitMotion.value.detailX}px)`, '--detail-progress':detailReveal.value}))
const feedback=computed(()=>detailOpen.value?'详情已打开，信息读取状态见面板':frame.value.mode==='closing'?'返回浏览，玻璃正在恢复清透':entry.value.id==='demo-access'?'访问状态以实际核验结果为准':frame.value.message)
const entrySubtitle=computed(()=>entry.value.id==='demo-access'?'后台登录、所有者验证与角色范围':entry.value.subtitle)
const authorityCopy=computed(()=>route.value.demo?'离线界面演示 · 未获得真实权限':backend.state.auth==='authenticated'?'后台登录与所有者会话已核验':backend.state.mode==='offline'?'离线预览 · 后端未连接':'真实会话待核验')
let raf=0,media:MediaQueryList|null=null,alive=true,lastDock=0,returnFocus:HTMLElement|null=null
function refresh(){frame.value=engine.snapshot();route.value=flow.snapshot()}
function sync(now=performance.now()){raf=0;exit.update(now,reduced.value);refreshExit();presentExit();frame.value=engine.update(now);route.value=flow.update(now);if(frame.value.dockRevision!==lastDock){lastDock=frame.value.dockRevision;if(!document.hidden)sound.cue('dock')};if(!raf&&(engine.moving||flow.moving||exit.active)&&!document.hidden&&alive)raf=requestAnimationFrame(sync)}
function request(){refresh();if(!raf&&alive&&!document.hidden){engine.wake(performance.now());raf=requestAnimationFrame(sync)}}
function unlock(){void sound.unlock()}
function previous(){if(detailOpen.value||loginVisible.value||exitState.value.blocked)return;engine.step(-1);request()}
function next(){if(detailOpen.value||loginVisible.value||exitState.value.blocked)return;engine.step(1);request()}
function select(logical:number){if(loginVisible.value||exitState.value.blocked)return;if(!expanded.value)returnFocus=document.activeElement instanceof HTMLElement?document.activeElement:null;if(engine.select(logical)){backend.selectArchive(demoEntries[modulo(Math.round(logical),demoEntries.length)]!.id);sound.cue('open')}request()}
function selectDisk(logical:number){if(loginVisible.value||exitState.value.blocked)return;if(!expanded.value)returnFocus=document.activeElement instanceof HTMLElement?document.activeElement:null;if(engine.toggleSelect(logical)){if(engine.mode==='closing'||engine.mode==='browse'){backend.invalidateView();sound.cue('back')}else{backend.selectArchive(demoEntries[engine.selected]!.id);sound.cue('open')}}request()}
function selectEntry(index:number){const nearest=nearestArchiveLogical(engine.position,index,demoEntries.length);if(nearest!==null)select(nearest)}
function open(){select(Math.round(engine.target))}
function back(){if(engine.back())sound.cue('back');backend.invalidateView();request()}
function showAccess(){credentialRequested.value=false;back();sound.silence();backend.invalidateNavigation();flow.returnAccess(backend.state.auth==='authenticated'?'当前真实会话已核验，可核对范围或退出':'等待真实会话核验');request();void nextTick(()=>accessScreen.value?.focus({preventScroll:true}))}
function verified(){if(backend.state.auth!=='authenticated'||backend.state.mode!=='same-origin'||flow.demo||flow.stage!=='verifying')return;flow.acceptVerified(flow.generation,true,performance.now());const fromCredentials=credentialRequested.value;credentialRequested.value=false;request();if(fromCredentials)void nextTick(()=>transitionCancel.value?.focus({preventScroll:true}))}
function closeLogin(){credentialRequested.value=false;sound.silence();backend.dismissLogin();flow.returnAccess(backend.state.auth==='authenticated'?'已有真实会话，可继续进入工作台':'已返回入口；未完成的核验已取消');request();void nextTick(()=>accessScreen.value?.focus({preventScroll:true}))}
function continueVerified(){if(backend.state.auth!=='authenticated'||backend.state.mode!=='same-origin')return;flow.beginVerification(performance.now());verified()}
function cancelEntry(){credentialRequested.value=false;sound.silence();backend.dismissLogin();flow.returnAccess('已返回入口；未完成的核验或演示已取消');request();void nextTick(()=>accessScreen.value?.focus({preventScroll:true}))}
function startDemo(){if(exitState.value.blocked||backend.state.mode!=='offline'||!accessInteractive.value)return;clearExit();backend.dismissLogin();backend.invalidateNavigation();engine.back();flow.startDemo(performance.now());sound.cue('verify');request()}
async function logout(){
 if(exitState.value.blocked||backend.state.busy)return
 const offline=backend.state.mode==='offline',generation=exit.begin(performance.now(),offline,reduced.value)
 if(generation===null)return
 exitSnapshot.value=captureExitScene(frame.value,engine.velocity,engine.phaseVelocity)
 exitPresented=false;refreshExit();credentialRequested.value=false;sound.silence();engine.back();backend.invalidateNavigation();request()
 // Local read authority is revoked immediately by the existing backend routine.
 // Visual timing and an actual Owner logout result remain separate.
 const pending=offline?null:backend.logout()
 presentExit()
 if(pending){const confirmed=await pending;if(!alive||!exit.settle(generation,confirmed))return;refreshExit();if(exitPresented){flow.returnAccess(exit.message);request()}else request()}
}

function keydown(e:KeyboardEvent){if(e.defaultPrevented||e.isComposing||e.keyCode===229)return;if(exitState.value.blocked){if(e.key==='Escape')e.preventDefault();return;}if(e.key==='Escape'){if(detailOpen.value){e.preventDefault();back();return}if(flow.moving||backend.state.busy||transitionVisible.value){e.preventDefault();cancelEntry();return}}if(detailOpen.value)return;if(e.ctrlKey||e.metaKey||e.altKey||editableTarget(e.target as HTMLElement)||loginVisible.value)return;if(detail.value?.contains(e.target as Node))return;if(e.key==='ArrowUp'||e.key==='ArrowDown'){unlock();e.preventDefault();e.key==='ArrowUp'?previous():next()}else if(e.key==='Enter'&&e.target===browseControls.value){e.preventDefault();open()}}
function dragStart(y:number){if(detailOpen.value||loginVisible.value||exitState.value.blocked)return;engine.beginDrag(y,performance.now());request()}
function drag(y:number){if(detailOpen.value||loginVisible.value||exitState.value.blocked)return;engine.drag(y,performance.now());request()}
function dragEnd(cancelled:boolean){engine.endDrag(cancelled);request()}
function wheel(delta:number,mode:number,height:number){if(detailOpen.value||loginVisible.value||exitState.value.blocked)return;if(engine.wheel(delta,mode,height,performance.now()))request()}
function detailWheel(e:WheelEvent){if(e.defaultPrevented||!detailOpen.value||e.ctrlKey||e.metaKey)return;e.stopPropagation()}
function motionChanged(){reduced.value=media?.matches??false;theme.setReducedMotion(reduced.value);engine.setReduced(reduced.value);flow.setReduced(reduced.value);request()}
function toggleMotion(){reduced.value=!reduced.value;theme.setReducedMotion(reduced.value);engine.setReduced(reduced.value);flow.setReduced(reduced.value);request()}
function changeVolume(event:Event){volume.value=Number((event.target as HTMLInputElement).value);sound.setVolume(volume.value)}
function toggleSound(){muted.value=!muted.value;sound.setMuted(muted.value);if(!muted.value)unlock()}
function visibility(){if(document.hidden){sound.silence();cancelAnimationFrame(raf);raf=0;engine.endDrag(true)}else request()}
watch(()=>backend.state.auth,(auth,previousAuth)=>{if(route.value.demo||exitState.value.blocked)return;if(auth==='checking'){flow.beginVerification(performance.now());sound.cue('verify');request()}else if(auth==='authenticated'&&previousAuth!=='authenticated'){verified()}else if((auth==='locked'||auth==='error'||auth==='offline'||auth==='https_required')&&(route.value.stage==='workspace'||route.value.stage==='entering'||route.value.stage==='confirmed'||route.value.stage==='verifying')){back();flow.authLost();request()}},{flush:'sync'})
watch(()=>backend.state.error,(error,previous)=>{if(error&&error!==previous&&!route.value.demo)sound.cue('error')})
watch(transitionVisible,async visible=>{if(visible){await nextTick();transitionCancel.value?.focus({preventScroll:true})}})
watch(detailOpen,async opened=>{if(opened){await nextTick();if(detailOpen.value&&browseControls.value?.contains(document.activeElement)) (document.activeElement as HTMLElement)?.blur()}},{flush:'post'})
watch(detailInteractive,async interactive=>{if(interactive){await nextTick();if(detailInteractive.value){detailClose.value?.focus({preventScroll:true});revealIfOutside(detailClose.value)}}else if(detail.value?.contains(document.activeElement)){(document.activeElement as HTMLElement)?.blur()}},{flush:'post'})
watch(()=>frame.value.mode,async mode=>{if(mode==='browse'&&!exitState.value.blocked){await nextTick();if(frame.value.mode!=='browse')return;const target=returnFocus&&document.contains(returnFocus)&&returnFocus.getClientRects().length?returnFocus:browseControls.value;target?.focus({preventScroll:true})}},{flush:'post'})
watch(()=>route.value.stage,async(stage,previousStage)=>{if(stage==='confirmed'||stage==='workspace'&&previousStage==='verifying')sound.cue('success');if(stage==='workspace'&&previousStage!=='workspace'){await nextTick();browseControls.value?.focus({preventScroll:true})}})
onMounted(()=>{media=window.matchMedia('(prefers-reduced-motion: reduce)');motionChanged();media.addEventListener('change',motionChanged);document.addEventListener('visibilitychange',visibility);document.addEventListener('keydown',keydown)})
onBeforeUnmount(()=>{alive=false;cancelAnimationFrame(raf);media?.removeEventListener('change',motionChanged);document.removeEventListener('visibilitychange',visibility);document.removeEventListener('keydown',keydown);sound.dispose()})
</script>
<template>
 <main class="archive-app" :class="{'is-open':expanded,'reduce-motion':reduced,'login-visible':loginVisible,'is-demo':route.demo,'is-exiting':exitState.active}" :data-stage="route.stage" :style="{...entryStyle,'--scene-progress':frame.phase,'--exit-workspace':exitMotion.workspace,'--exit-arc':exitMotion.arc}" @keydown.capture="unlock" @pointerdown.capture="unlock">
  <section class="arc-stage" :class="{'entry-arc':loginVisible}" aria-label="圆弧光学档案导航" :aria-hidden="loginVisible||exitState.blocked" :inert="loginVisible||exitState.blocked">
   <ArchiveArc :key="modelRevision" :frame="frame" :entries="demoEntries" :reduced="reduced" :theme="theme.darkMix.value" :exit-progress="exitState.progress" :exit-snapshot="exitSnapshot" :activity="opticalActivity" :entry-progress="entryMotion.scene" :disabled="loginVisible||exitState.blocked" @wheel="wheel" @drag-start="dragStart" @drag="drag" @drag-end="dragEnd" @select="selectDisk" @open="open" @asset="(state,message)=>{asset=state;assetMessage=message}"/>
   <p v-if="asset==='loading'" class="asset-note" role="status">正在载入档案模型，文字导航可用</p>
   <div v-if="asset==='failed'" class="asset-fallback"><h2>三维视图暂不可用</h2><p>请使用左侧文字导航，模型载入失败不影响会话状态。</p><details><summary>查看原因</summary>{{assetMessage}}</details><button @click="modelRevision++">重试载入模型</button></div>
  </section>
  <ReplyControlsPanel v-if="backend.state.mode==='same-origin' && backend.state.auth==='authenticated' && backend.scopeValid.value && !route.demo" :backend="backend" :inline-target="detailOpen ? '#reply-controls-mobile-slot' : null"/>
  <section v-if="route.stage==='workspace'||route.stage==='entering'" class="workspace-shell" :inert="route.stage!=='workspace'||exitState.blocked" :aria-hidden="route.stage!=='workspace'">
   <header class="brand"><a href="#" @click.prevent="back" aria-label="2718lab 返回档案浏览">2718lab</a><p>OPTICAL ARCHIVE<br>ACCESS SYSTEM</p></header>
   <nav class="workspace-nav" aria-label="会话操作"><span class="connection-state" :title="authorityCopy">{{route.demo?'离线预览':'所有者会话'}}</span><button class="workspace-logout" @click="logout" :disabled="backend.state.busy||exitState.blocked" :title="route.demo?'返回入口，离线预览没有真实登录会话':'退出本页所有者会话'" aria-describedby="workspace-session-note">登出<svg aria-hidden="true" viewBox="0 0 16 16" width="14" height="14"><path d="M6 3H3v10h3M7 8h6m-3-3 3 3-3 3" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg></button><span id="workspace-session-note" class="visually-hidden">{{route.demo?'离线预览：登出会返回入口，不涉及真实会话':'仅退出本页所有者会话'}}</span></nav>
   <section ref="browseControls" class="archive-copy" :style="browseStyle" :inert="expanded" :aria-hidden="expanded" tabindex="0" aria-label="档案浏览控制">
    <p class="eyebrow">OPTICAL ARCHIVE / 光学档案</p><p class="index-label">{{String(presentedFrame.selected+1).padStart(2,'0')}} / {{String(frame.count).padStart(2,'0')}} <span>{{route.demo?'演示导航槽位':'导航槽位'}}</span></p>
    <h1>{{entry.title}}</h1><p class="subtitle">{{entrySubtitle}}</p>
    <p class="browse-explanation">浏览只预览档案。点击盘体或下方模块，打开对应仪表盘。真实内容仍由会话与角色权限核验。</p>
    <div class="browse-toolbar"><div class="browse-actions"><button @click="previous" aria-label="上一份档案，上方向键">上一份</button><button @click="next" aria-label="下一份档案，下方向键">下一份</button></div><button class="open-action" :disabled="!canOpen" @click="open">打开仪表盘 <span aria-hidden="true">↗</span></button></div>
    <nav class="module-list" aria-label="键盘可达的档案模块"><button v-for="(item,index) in demoEntries" :key="item.id" :aria-current="presentedFrame.selected===index?'page':undefined" @click="selectEntry(index)"><span class="module-index">{{String(index+1).padStart(2,'0')}}</span><span>{{item.title}}</span><span class="module-status">{{moduleStatus(item.id)}}</span><span aria-hidden="true">↗</span></button></nav>
    <p v-if="route.demo" class="demo-boundary">离线界面演示。这里没有验证身份、读取真实记录或获得发送权限。</p>
   </section>
   <div class="guidance" :style="browseStyle" :aria-hidden="expanded"><p>滚轮 / ↑↓ / 拖动浏览 · 单击打开，再次单击收起</p><p class="feedback" role="status" aria-live="polite">{{feedback}}</p></div>
  </section>
  <section v-if="loginVisible" ref="accessScreen" tabindex="-1" class="access-screen terminal" :class="{'terminal-active':transitionVisible,'terminal-form':credentialRequested}" aria-label="工作台访问入口">
   <header class="terminal-brand"><strong>2718lab</strong><span>OPTICAL ARCHIVE<br>ACCESS SYSTEM</span></header>
   <p class="terminal-boundary">{{backend.state.mode==='offline'?'离线演示 · 未验证身份':'AstrBot / Owner · 独立会话'}}</p>
   <div class="terminal-field" aria-hidden="true">

    <svg class="terminal-rings" viewBox="-426 -240 852 480" :style="{opacity:entryMotion.ringOpacity}" aria-hidden="true">
     <circle class="gate-outer" :r="entryMotion.ringRadius" :transform="`rotate(${entryMotion.outerAngle})`"/>
     <circle class="gate-white" :r="entryMotion.whiteRadius" :transform="`rotate(${entryMotion.whiteAngle})`"/>
     <circle class="gate-inner" r="42" :transform="`rotate(${entryMotion.innerAngle})`"/>
     <g :transform="`rotate(${entryMotion.dotAngle})`"><circle class="gate-dot" cx="63" cy="0" r="2.3"/><circle class="gate-dot" cx="-54" cy="25" r="1.8"/></g>
     <text class="gate-status" y="5" text-anchor="middle">{{gateLabel}}</text>
    </svg>

   </div>
   <figure class="logo-subject" :class="{'logo-behind-form':credentialRequested}" aria-label="2718lab">
    <svg class="official-logo-construction" viewBox="0 0 200 200" role="img" aria-label="2718lab 官方标志">
     <defs><mask id="official-logo-mask" maskUnits="userSpaceOnUse" x="0" y="0" width="200" height="200">
      <path v-for="brush in LOGO_BRUSHES" :key="brush.id" :d="brush.d" pathLength="1" stroke="white" stroke-width="16" stroke-linecap="square" stroke-linejoin="miter" fill="none" stroke-dasharray="1" :stroke-dashoffset="1-logoBrushProgress(entryMotion.logoReveal,brush.start,brush.end)"/>
      <circle cx="100" cy="102" r="15" fill="white" :opacity="entryMotion.logoCenter"/>
      <rect width="200" height="200" fill="white" :opacity="entryMotion.logoFull"/>
     </mask></defs>
     <image :href="officialLogo" width="200" height="200" mask="url(#official-logo-mask)"/>
    </svg><figcaption>2718lab</figcaption>
   </figure>
   <div class="welcome-lockup" :style="{opacity:entryMotion.welcomeOpacity}" aria-hidden="true"><p>WELCOME BACK</p><h2 :style="{opacity:entryMotion.welcomeLine2}">2718lab</h2><span :style="{opacity:entryMotion.welcomeLine3}">{{route.demo?'OFFLINE DEMONSTRATION / NO AUTH':backend.state.auth==='authenticated'?'VERIFIED SESSION / ARCHIVE INDEX':'ACCESS ARCHIVE / SESSION PENDING'}}</span></div>
   <div v-if="!credentialRequested" class="terminal-focus" :inert="route.stage==='arriving'&&entryMotion.statusReveal<.08">
    <p class="terminal-code" :aria-label="terminalCode"><span aria-hidden="true">{{typedCode}}</span></p>
    <h1>{{transitionTitle}}</h1>
    <div v-if="transitionVisible" class="terminal-proof" role="status" aria-live="polite" aria-atomic="true">
     <template v-if="route.demo"><span>界面演示</span><span>没有授予真实权限</span></template>
     <template v-else><span>AstrBot <b>{{backend.state.dashboard==='authenticated'?'已核验':'待核验'}}</b></span><span>Owner <b>{{backend.state.owner==='unlocked'?'已核验':'待核验'}}</b></span></template>
    </div>
    <template v-else>
     <p v-if="exitState.result!=='none'" class="logout-result" :class="{'terminal-error':exitState.result==='failed'}" :role="exitState.result==='failed'?'alert':'status'" aria-live="polite">{{exitState.message}}</p>
     <button v-if="exitState.result==='failed'" class="retry-logout" @click="logout">重试退出</button>
     <p v-if="backend.state.error" class="terminal-error" role="alert">{{backend.state.error}}</p>
     <p v-else-if="backend.state.mode==='offline'" class="terminal-note">仅预览界面与动效</p>
     <p v-else class="terminal-note">{{backend.state.auth==='authenticated'?'当前会话已核验':'使用当前后台与所有者会话'}}</p>
     <button class="terminal-enter" :disabled="backend.requiresHttps.value||backend.state.busy||exitState.blocked" @click="requestAccess">{{backend.state.mode==='offline'?'进入离线演示':backend.requiresHttps.value?'需要 HTTPS':backend.state.error?'重试访问':'访问'}} <svg class="access-arrow" viewBox="0 0 30 12" aria-hidden="true"><path d="M1 6h26M22 1l5 5-5 5"/></svg></button>
     <button v-if="backend.state.mode!=='offline'" class="terminal-credentials" :disabled="backend.requiresHttps.value||exitState.blocked" @click="requestCredentials">{{backend.state.auth==='authenticated'?'查看范围与会话':'使用配对凭据'}}</button>
     <button v-if="backend.state.mode!=='offline'" class="terminal-credentials" :disabled="exitState.blocked" @click="requestSetup">{{backend.requiresHttps.value?'HTTPS 配置说明':'高级配置 / LLM'}}</button>
    </template>

   </div>
   <div v-else class="terminal-auth"><LoginPanel :backend="backend" :setup-first="setupRequested" @close="closeLogin" @verified="verified"/><button v-if="backend.state.busy" class="cancel-entry" @click="cancelEntry">取消本次核验</button><button v-if="backend.state.auth==='authenticated'" class="continue-entry primary-button" @click="continueVerified">进入已核验工作台</button></div>
   <div v-if="transitionVisible||route.stage==='arriving'" class="entry-controls"><button v-if="route.stage==='arriving'" class="skip-intro" @click="skipIntro">跳过片头</button><button v-if="transitionVisible" ref="transitionCancel" class="terminal-cancel" @click="cancelEntry">{{route.stage==='verifying'?'取消':'返回入口'}}</button><button v-if="route.stage==='confirmed'||route.stage==='entering'" class="skip-entry" @click="skipEntry">立即进入</button></div>
   <div class="terminal-baseline"><span>{{transitionVisible?'02 / INDEX':'01 / ACCESS'}}</span><details v-if="!transitionVisible"><summary>访问说明</summary><p>{{backend.state.mode==='offline'?'当前为离线前端，不调用认证 API、不读取真实数据。':'先登录同源 AstrBot 后台，再核验独立所有者会话。配对凭据只用于已有安装的签名挑战，私钥始终留在本机。'}}</p></details><span>{{transitionVisible?'2718lab / FILE SYSTEM':displayAlias.alias.value||'所有者工作台'}}</span></div>
  </section>
  <section v-show="route.stage==='workspace'&&(detailOpen||panelMotion.detailVisible)" ref="detail" class="inline-dashboard" :style="detailStyle" :inert="!detailInteractive" :aria-hidden="!detailInteractive" role="region" aria-labelledby="dashboard-title" aria-describedby="dashboard-authority" tabindex="-1" @wheel="detailWheel"><header class="dashboard-heading"><div><p class="eyebrow">{{String(presentedFrame.selected+1).padStart(2,'0')}} / MODULE DASHBOARD</p><h2 id="dashboard-title">{{entry.id==='demo-life'?'项目与作品':entry.title}}</h2><p id="dashboard-authority">{{authorityCopy}}</p></div><button ref="detailClose" class="dialog-close" @click="back" aria-label="关闭详情并返回浏览">返回浏览 <span aria-hidden="true">×</span></button></header><nav class="detail-modules" aria-label="切换档案详情"><button v-for="(item,index) in demoEntries" :key="item.id" :aria-current="presentedFrame.selected===index?'page':undefined" @click="selectEntry(index)">{{item.title}}</button></nav><div class="dashboard-scroll"><UtilityPanel v-if="utilityKind&&route.stage==='workspace'" :key="entry.id" :kind="utilityKind" :backend="backend"/><ContentPanel v-else-if="!utilityKind" :backend="backend" :entry-id="entry.id" @request-login="showAccess"/><div id="reply-controls-mobile-slot"></div></div><footer class="dashboard-footer"><span>{{route.demo?'界面演示 · 读写灯光效为模拟 · 所有后端权限保持关闭':'实际权限由服务端逐次核验'}}</span><span>Esc 返回 · 关闭不退出会话</span></footer></section>
  <p v-if="exitState.active" class="exit-status" role="status" aria-live="polite">{{exitState.result==='offline'?'正在返回入口':'正在锁定并退出会话'}}</p>
  <footer class="global-footer"><p>{{backend.state.mode==='offline'?'前端离线预览 · 后端未连接':backend.requiresHttps.value?'HTTP 静态入口 · HTTPS 后可核验会话与配置':'同源界面 · 本地服务提供实际会话与信息'}}</p><div class="footer-controls"><label class="theme-control">外观 <select :value="theme.preference.value" @change="theme.setPreference(($event.target as HTMLSelectElement).value)"><option value="system">跟随系统</option><option value="light">浅色</option><option value="dark">深色</option></select></label><button :aria-pressed="!muted" @click="toggleSound">{{muted?'开启轻音':'关闭轻音'}}</button><label class="sound-volume" for="sound-volume">音量 <input id="sound-volume" type="range" min="0" max="1" step="0.05" :value="volume" :disabled="muted" @input="changeVolume" :aria-valuetext="`${Math.round(volume*100)}%`"></label><button :aria-pressed="reduced" @click="toggleMotion">{{reduced?'恢复动效':'减少动态效果'}}</button></div></footer>
 </main>
</template>
