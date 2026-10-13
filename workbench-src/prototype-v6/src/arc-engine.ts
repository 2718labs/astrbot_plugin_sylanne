import {advanceRadial,radialMoving,type RadialSample} from './arc-selection.ts'
import {advanceRepulsion,repulsionMoving,type RepulsionSample} from './arc-repulsion.ts'
export type Mode = 'browse' | 'opening' | 'detail' | 'closing'
export interface Entry { id:string; title:string; subtitle:string; availability:'available'|'hold'|'unknown'; reason?:string; fields:string[] }
export const demoEntries:Entry[]=[
 {id:'demo-persona',title:'人格方案',subtitle:'方案的版本与来源',availability:'available',fields:['方案标识','版本','作者来源','组成与规则数量']},
 {id:'demo-memory',title:'记忆来源',subtitle:'让记录的来处清楚可见',availability:'available',fields:['来源标识','来源类型','记录时间','断言状态']},
 {id:'demo-life',title:'生活档案',subtitle:'内容投影接入待核对',availability:'unknown',reason:'本样机尚未接入生活档案的授权投影，不能据此读取或生成内容',fields:[]},
 {id:'demo-contact',title:'主动联系',subtitle:'等待发送归属确认',availability:'hold',reason:'发送归属与在途状态尚未确认，保持 HOLD；样机不能发送消息',fields:[]},
 {id:'demo-access',title:'访问状态',subtitle:'独立授权会话尚未接入',availability:'unknown',reason:'尚未连接 Owner 会话，不能把演示状态视为已授权',fields:[]},
 {id:'demo-logs',title:'运行日志',subtitle:'运行记录与事件详情尚未接入',availability:'unknown',reason:'日志接口未连接，不能读取真实日志',fields:[]},
 {id:'demo-settings',title:'插件设置',subtitle:'配置结构与实际值边界',availability:'unknown',reason:'配置读写接口未连接，仅展示只读 schema',fields:[]},
]
export const modulo=(value:number,count:number)=>((value%count)+count)%count
export function editableTarget(target:{tagName?:string;isContentEditable?:boolean;closest?:(selector:string)=>unknown}|null){return !!target&&(target.isContentEditable||['INPUT','TEXTAREA','SELECT'].includes(target.tagName??'')||!!target.closest?.('[contenteditable="true"],[role="textbox"]'))}
export function wheelItems(delta:number,mode:number,pageHeight:number){const px=delta*(mode===1?16:mode===2?pageHeight:1);return Math.max(-1.25,Math.min(1.25,px/125))}
export function damp(position:number,velocity:number,target:number,dt:number,omega=18){const offset=position-target,e=Math.exp(-omega*dt),t=(velocity+omega*offset)*dt;return {position:target+(offset+t)*e,velocity:(velocity-omega*t)*e}}
export interface ArcSnapshot { position:number; selected:number; logical:number; count:number; mode:Mode; phase:number; settled:boolean; message:string; dockRevision:number; repulsion?:readonly RepulsionSample[];radial?:readonly RadialSample[] }
export class ArcEngine {
 position=0;target=0;velocity=0;mode:Mode='browse';phase=0;phaseVelocity=0;reduced=false;message='滚轮、上下方向键或拖动浏览档案';dockRevision=0
 private repulsion:RepulsionSample[]=[];private radial:RadialSample[]=[];private lastTime:number|null=null;private wheelDeadline=0;private dragging=false;private dragOrigin=0;private dragPointer=0;private dragPrevious=0;private dragTime=0;private lastDock=0;private selectedOnOpen=0
 readonly entries:readonly Entry[]
 constructor(entries:readonly Entry[]=demoEntries){this.entries=entries}
 get count(){return this.entries.length}
 get logical(){return this.mode!=='browse'?this.selectedOnOpen:Math.round(this.position)}
 get selected(){return this.count?modulo(this.logical,this.count):0}
 get settled(){return !this.dragging&&!this.wheelDeadline&&Math.abs(this.position-this.target)<.0008&&Math.abs(this.velocity)<.008}
 get canBrowse(){return this.count>1}
 snapshot():ArcSnapshot{return {position:this.position,selected:this.selected,logical:this.logical,count:this.count,mode:this.mode,phase:this.phase,settled:this.settled,message:this.message,dockRevision:this.dockRevision,repulsion:this.repulsion.map(sample=>({...sample})),radial:this.radial.map(sample=>({...sample}))}}
 private drive(){if(this.mode==='opening'||this.mode==='detail')this.mode='closing';this.message='正在浏览档案'}
 wheel(delta:number,deltaMode:number,height:number,now:number){if(!this.canBrowse||this.dragging||!Number.isFinite(delta))return false;const amount=wheelItems(delta,deltaMode,height);if(!amount)return false;this.target+=amount;this.wheelDeadline=now+130;this.drive();if(this.reduced){this.target=Math.round(this.target);if(!amount||this.target===this.position)this.target=this.position+Math.sign(amount);this.position=this.target;this.velocity=0;this.wheelDeadline=0;this.dock()}return true}
 step(direction:number){if(!this.canBrowse||!Number.isFinite(direction)||!direction)return false;this.dragging=false;this.wheelDeadline=0;this.target=Math.round(this.target)+Math.sign(direction);this.drive();if(this.reduced){this.position=this.target;this.velocity=0;this.dock()}return true}
 choose(logical:number){if(!this.count||!Number.isFinite(logical))return false;this.dragging=false;this.wheelDeadline=0;this.target=Math.round(logical);this.drive();if(this.reduced){this.position=this.target;this.velocity=0;this.dock()}return true}
 beginDrag(y:number,now:number){if(!this.canBrowse||!Number.isFinite(y))return false;this.dragging=true;this.wheelDeadline=0;this.dragOrigin=this.position;this.dragPointer=y;this.dragPrevious=this.position;this.dragTime=now;this.target=this.position;this.velocity=0;this.drive();return true}
 drag(y:number,now:number){if(!this.dragging||!Number.isFinite(y))return false;const next=this.dragOrigin-(y-this.dragPointer)/120;const dt=Math.max(.008,(now-this.dragTime)/1000);this.velocity=Math.max(-5,Math.min(5,(next-this.dragPrevious)/dt));this.position=next;this.target=next;this.dragPrevious=next;this.dragTime=now;this.drive();return true}
 endDrag(cancelled=false){if(!this.dragging)return false;this.dragging=false;const projection=cancelled||this.reduced?0:Math.max(-.3,Math.min(.3,this.velocity*.05));this.target=Math.round(this.position+projection);if(cancelled)this.velocity=0;if(this.reduced){this.position=this.target;this.velocity=0;this.dock()}return true}
 select(logical:number){
  if(!this.count||!Number.isFinite(logical))return false
  const index=modulo(Math.round(logical),this.count)
  if((this.mode==='opening'||this.mode==='detail')&&this.selected===index)return false
  // Every new selection intentionally navigates the shortest cyclic path to
  // the center, resolved from the displayed pose rather than a queued target.
  // Preserve navigation, neighbor and radial velocities on interrupted retargets:
  // changing the destination never teleports the displayed geometry.
  const next=index+Math.round((this.position-index)/this.count)*this.count
  this.dragging=false;this.wheelDeadline=0;this.target=next;this.selectedOnOpen=next
  this.mode='opening';this.message='正在选择档案并展开左侧内容'
  if(this.reduced){this.position=this.target;this.velocity=0;this.phase=1;this.phaseVelocity=0;this.mode='detail';this.syncRepulsion(0);this.dock()}
  return true
 }
 toggleSelect(logical:number){
  if(!this.count||!Number.isFinite(logical))return false
  if((this.mode==='opening'||this.mode==='detail')&&this.selected===modulo(Math.round(logical),this.count))return this.back()
  return this.select(logical)
 }
 requestOpen(){return this.select(Math.round(this.target))}
 back(){if(this.mode==='browse'||this.mode==='closing')return false;this.mode='closing';this.message='正在收起内容';return true}
 setReduced(value:boolean){this.reduced=value;if(value){this.dragging=false;this.wheelDeadline=0;this.target=Math.round(this.target);this.position=this.target;this.velocity=0;this.phase=this.mode==='opening'||this.mode==='detail'?1:0;this.phaseVelocity=0;if(this.mode==='opening')this.mode='detail';if(this.mode==='closing')this.mode='browse';this.syncRepulsion(0);this.dock()}}
 private get repulsionSelection(){return this.mode==='opening'||this.mode==='detail'?this.selectedOnOpen:null}
 private syncRepulsion(dt:number){this.repulsion=advanceRepulsion(this.repulsion,visibleSlots(this.position,this.count).map(slot=>slot.logical),this.repulsionSelection,dt,this.reduced);this.radial=advanceRadial(this.radial,visibleSlots(this.position,this.count).map(slot=>slot.logical),this.repulsionSelection,dt,this.reduced)}
 private dock(){const logical=Math.round(this.position);if(logical!==this.lastDock){this.lastDock=logical;this.dockRevision++}const entry=this.entries[this.selected];this.message=entry?entry.availability==='available'?`已停靠：${entry.title}。可展开内容与读取控制`:`已停靠：${entry.title}。${entry.reason}`:'没有可浏览的档案'}
 /** Rebase only the integration clock when the host starts a dormant frame loop.
  * Idle/hidden wall time predates the new action and must not advance its springs.
  * Do not call for requests while a frame is already queued: ongoing motion keeps
  * the full elapsed interval, its current pose, and every retained velocity. */
 wake(now:number){if(Number.isFinite(now))this.lastTime=now}
 update(now:number){const dt=this.lastTime===null?1/60:Math.max(0,Math.min(.1,(now-this.lastTime)/1000));this.lastTime=now
  if(this.wheelDeadline&&now>=this.wheelDeadline){this.wheelDeadline=0;this.target=Math.round(this.target)}
  if(!this.dragging){if(this.reduced){this.position=this.target;this.velocity=0}else{const result=damp(this.position,this.velocity,this.target,dt,18);this.position=result.position;this.velocity=result.velocity}if(!this.wheelDeadline&&Math.abs(this.target-this.position)<.0008&&Math.abs(this.velocity)<.008){const changed=this.position!==this.target||this.velocity!==0;this.position=this.target;this.velocity=0;if(changed)this.dock()}}
  if(this.mode==='opening'||this.mode==='closing'){const target=this.mode==='opening'?1:0;const result=this.reduced?{position:target,velocity:0}:damp(this.phase,this.phaseVelocity,target,dt,10);this.phase=Math.max(0,Math.min(1,result.position));this.phaseVelocity=result.velocity;if(Math.abs(this.phase-target)<.0008&&Math.abs(this.phaseVelocity)<.008){this.phase=target;this.phaseVelocity=0;this.mode=target?'detail':'browse';this.message=target?'内容已展开；读取状态见左侧':'内容已收起，可继续浏览'}}
  if(this.mode==='browse'&&!this.dragging&&Math.abs(this.position)>10000&&this.count){const shift=Math.trunc(this.position/this.count)*this.count;this.position-=shift;this.target-=shift;this.lastDock-=shift;this.selectedOnOpen-=shift;this.repulsion=this.repulsion.map(sample=>({...sample,logical:sample.logical-shift}));this.radial=this.radial.map(sample=>({...sample,logical:sample.logical-shift}))}
  this.syncRepulsion(dt)
  return this.snapshot()
 }
 get moving(){return repulsionMoving(this.repulsion,this.repulsionSelection)||radialMoving(this.radial,this.repulsionSelection)||!!this.wheelDeadline||(!this.dragging&&(Math.abs(this.position-this.target)>.00001||Math.abs(this.velocity)>.00001))||this.mode==='opening'||this.mode==='closing'}
}
export interface ArcSlot {slot:number;logical:number;index:number;offset:number;angle:number;opacity:number;visible:boolean}
// Physical GLB instances and finite record indices deliberately have separate
// identities. The extra end shingles repeat the finite records, not new records.
export const ARC_POOL_SIZE=9,ARC_STEP_ANGLE=Math.PI/12.8
export const ARC_VISIBLE_START=-3.80,ARC_VISIBLE_END=2.90,ARC_EDGE_FADE=.28
export function visibleSlots(position:number,count:number):ArcSlot[]{if(!count)return[];if(count===1)return[{slot:0,logical:0,index:0,offset:0,angle:0,opacity:1,visible:true}];const base=Math.floor(position);return Array.from({length:ARC_POOL_SIZE},(_,i)=>{const logical=base+i-4,offset=logical-position;return {slot:modulo(logical,ARC_POOL_SIZE),logical,index:modulo(logical,count),offset,angle:-offset*ARC_STEP_ANGLE,opacity:Math.max(0,Math.min(1,(offset-ARC_VISIBLE_START)/ARC_EDGE_FADE,(ARC_VISIBLE_END-offset)/ARC_EDGE_FADE)),visible:offset>ARC_VISIBLE_START&&offset<ARC_VISIBLE_END}})}
