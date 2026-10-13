import {unit,track,interpolate,LOGO_SLIDE,RING_CONTRACTION} from './entry-choreography.ts'
/** Presentation state only. Offline demonstrations never change backend authority. */
export type DashboardStage = 'arriving' | 'access' | 'verifying' | 'confirmed' | 'entering' | 'workspace'
export interface DashboardSnapshot { stage:DashboardStage; demo:boolean; generation:number; progress:number; message:string; statusProgress?:number }
export const ENTRY_TIMING = Object.freeze({ arrival:2800, minimumVerification:0, demoVerification:900, confirmed:2100, entering:2700 })
const clamp=(value:number)=>Math.min(1,Math.max(0,Number.isFinite(value)?value:0))
const ease=(value:number)=>{const p=clamp(value);return p*p*p*(p*(p*6-15)+10)}
/** Shared presentation values for the browser and offline previews; none grants authority. */
export function entryVisuals(state:Pick<DashboardSnapshot,'stage'|'progress'|'demo'> & {statusProgress?:number}){
 const p=unit(state.progress),isArrival=state.stage==='arriving',confirmed=state.stage==='confirmed',entering=state.stage==='entering',done=state.stage==='workspace'
 const arrival=isArrival?p:1,draw=isArrival?unit(p/.58):1,slide=isArrival?unit((p-.58)/.42):1
 const scene=done?1:entering?track(p,.40,1):0,ringProgress=confirmed?unit(p/.72):entering||done?1:0
 const oldOpacity=confirmed?1-track(p,0,.10):entering||done?0:1
 const welcome=confirmed?track(p,.78,.90):entering?1-track(p,.40,.54):0
 return {arrival,scene,spread:state.stage==='verifying'||confirmed||entering||done?1:0,
 logoX:50-interpolate(LOGO_SLIDE,slide)/852*100,logoY:49.3,logoScale:1,logoOpacity:oldOpacity,logoReveal:draw,
 logoFull:track(draw,.92,1),logoCenter:track(draw,.72,.98),logoCaption:track(draw,.58,1),statusReveal:isArrival?track(p,.72,1):state.stage==='verifying'?unit(state.statusProgress??1):1,
 resolve:ringProgress,ringRadius:interpolate(RING_CONTRACTION,ringProgress),whiteRadius:interpolate(RING_CONTRACTION,Math.min(1,ringProgress*1.12))*.88,
 ringOpacity:confirmed?track(p,0,.08)*(1-track(p,.72,.78)):0,outerAngle:42-155*track(ringProgress,0,.8),whiteAngle:110+193*track(ringProgress,.03,.88),innerAngle:-35+122*track(ringProgress,.08,1),dotAngle:30-215*ringProgress,
 welcomeOpacity:welcome,welcomeLine2:confirmed?track(p,.84,.92):entering?1:0,welcomeLine3:confirmed?track(p,.88,.96):entering?1:0,
 arcOpacity:done?1:entering?track(p,.40,.55):0,arcOffset:0,arcScale:1,
 accessOpacity:done?0:1,overlayOpacity:1-scene,ringScale:1,
 workspaceOpacity:done?1:entering?track(p,.60,.92):0,workspaceOffset:0}
}

export class DashboardFlow {
 stage:DashboardStage='arriving';demo=false;generation=0;progress=0;statusProgress=1;message='访问入口准备中'
 private started:number;private reduced=false;private proof=false
 constructor(now=0){this.started=now}
 snapshot():DashboardSnapshot{return {stage:this.stage,demo:this.demo,generation:this.generation,progress:this.progress,message:this.message,statusProgress:this.statusProgress}}
 beginVerification(now:number){if(this.stage==='verifying'&&!this.demo)return this.generation;++this.generation;this.demo=false;this.proof=false;this.stage='verifying';this.started=now;this.progress=0;this.statusProgress=0;this.message='正在核验 Dashboard 与 Owner 会话';return this.generation}
 acceptVerified(generation:number,sessionProof:boolean,now:number){
  if(generation!==this.generation||!sessionProof||this.demo||this.proof||this.stage!=='verifying')return false
  this.proof=true;this.message='真实会话已核验'
  if(this.reduced)this.finish();else if(now-this.started>=ENTRY_TIMING.minimumVerification)this.confirm(now)
  return true
 }
 startDemo(now:number){if(this.demo&&this.stage!=='access')return this.generation;++this.generation;this.demo=true;this.proof=false;this.stage=this.reduced?'workspace':'verifying';this.started=now;this.progress=this.reduced?1:0;this.statusProgress=this.reduced?1:0;this.message='离线界面演示 · 未验证身份，未获得真实权限';return this.generation}
 returnAccess(message='等待真实会话核验'){++this.generation;this.stage='access';this.demo=false;this.proof=false;this.progress=0;this.statusProgress=1;this.message=message;return this.generation}
 authLost(){if(this.demo)return false;this.returnAccess('会话已锁定或失效，请重新核验');return true}
 setReduced(value:boolean){this.reduced=value;if(!value)return;if(this.stage==='arriving'){this.stage='access';this.progress=0;this.message='等待真实会话核验'}else if(this.stage==='confirmed'||this.stage==='entering'||this.stage==='verifying'&&(this.demo||this.proof))this.finish()}
 private confirm(now:number){this.stage='confirmed';this.started=now;this.progress=0;this.message=this.demo?'演示衔接已就绪 · 未验证真实身份':'真实会话已核验'}
 skipArrival(){if(this.stage!=='arriving')return false;this.stage='access';this.progress=0;this.message='等待真实会话核验';return true}
 skipPresentation(){if(this.stage!=='confirmed'&&this.stage!=='entering')return false;if(!this.demo&&!this.proof)return false;this.finish();return true}
 private finish(){this.stage='workspace';this.progress=1}
 update(now:number){
  const elapsed=Math.max(0,now-this.started)
  if(this.stage==='arriving'){this.progress=clamp(elapsed/ENTRY_TIMING.arrival);if(this.progress>=1){this.stage='access';this.progress=0;this.message='等待真实会话核验'}}
  else if(this.stage==='verifying'){
   this.statusProgress=this.reduced?1:unit(elapsed/240)
   // A real request remains indeterminate until the existing backend supplies proof.
   this.progress=this.demo?clamp(elapsed/ENTRY_TIMING.demoVerification):0
   if(this.demo&&this.progress>=1||this.proof&&elapsed>=ENTRY_TIMING.minimumVerification)this.confirm(now)
  }else if(this.stage==='confirmed'){this.progress=clamp(elapsed/ENTRY_TIMING.confirmed);if(this.progress>=1){this.stage='entering';this.started=now;this.progress=0}}
  else if(this.stage==='entering'){this.progress=clamp(elapsed/ENTRY_TIMING.entering);if(this.progress>=1)this.finish()}
  return this.snapshot()
 }
 get moving(){return this.stage==='arriving'||this.stage==='confirmed'||this.stage==='entering'||this.stage==='verifying'&&(this.demo||this.proof||this.statusProgress<1)}
}
export interface FocusableLike {focus:(options?:{preventScroll?:boolean})=>void;disabled?:boolean;hidden?:boolean|string;tabIndex?:number;getAttribute?:(name:string)=>string|null}
export function cycleDialogFocus<T extends FocusableLike>(items:readonly T[],active:T|null,reverse:boolean):T|null{const usable=items.filter(i=>!i.disabled&&!i.hidden&&i.tabIndex!==-1&&i.getAttribute?.('aria-hidden')!=='true');if(!usable.length)return null;const index=usable.indexOf(active as T);return usable[index<0?(reverse?usable.length-1:0):(index+(reverse?-1:1)+usable.length)%usable.length]!}
export function nearestArchiveLogical(position:number,index:number,count:number){if(!Number.isFinite(position)||!Number.isInteger(index)||count<1||index<0||index>=count)return null;const logical=Math.round(position),current=((logical%count)+count)%count,half=Math.floor(count/2),delta=(((index-current+half)%count)+count)%count-half;return logical+delta}
