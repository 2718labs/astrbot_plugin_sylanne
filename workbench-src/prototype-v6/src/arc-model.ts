import {repulsionAngle} from './arc-repulsion.ts'
import {radialOffset} from './arc-selection.ts'
import * as THREE from 'three'
import type {ArcSlot,ArcSnapshot} from './arc-engine'
export const requiredNodes=['SYL_archive_root','ARCHIVE_body','LID_panel','OPTIC_main','OPTIC_small','OPTIC_bridge','MARK_status','HIT_archive','ANCHOR_label'] as const
export function inspectModel(root:THREE.Object3D){
 const map=new Map<string,THREE.Object3D>(),counts=new Map<string,number>()
 root.traverse(n=>{map.set(n.name,n);counts.set(n.name,(counts.get(n.name)??0)+1)})
 const invalid=requiredNodes.filter(n=>counts.get(n)!==1)
 if(invalid.length)throw new Error(`档案模型节点缺失或重名：${invalid.join('、')}`)
 return map
}
// The disks remain a sequential radial shingle stack at the lower-right corner.
// Explicit selection repels neighbors along the arc without changing depth or scale.
export function arcLayout(aspect:number){
 const halfWidth=aspect*5,radius=Math.max(5.9,Math.min(9.0,halfWidth*.48+5.08))
 return {halfWidth,radius,cx:halfWidth+.02,cy:-4.70,scale:Math.min(1.40,Math.max(1.04,halfWidth/3.78)),focusAngle:Math.PI/4-Math.PI/12.8}
}
export const smoothRange=(value:number,start:number,end:number)=>{
 const t=Math.max(0,Math.min(1,(value-start)/(end-start)));return t*t*(3-2*t)
}
export function slotTransform(slot:ArcSlot,state:ArcSnapshot,aspect:number){
 const layout=arcLayout(aspect),selected=slot.logical===state.logical
 const theta=layout.focusAngle+slot.angle+repulsionAngle(state.repulsion,slot.logical)
 const radius=layout.radius+radialOffset(state.radial,slot.logical)
 return {
  x:layout.cx-radius*Math.cos(theta),
  y:layout.cy+radius*Math.sin(theta),
  z:slot.offset*1.70,
  rotationX:.10,rotationY:-.20,rotationZ:-theta,rotationOrder:'ZYX' as const,
  scale:layout.scale,lidRotationY:0,selected
 }
}

// Selection no longer translates the group. Kept as a stable layout helper.
export function readingStageShift(phase:number,aspect:number){
 void phase;void aspect
 return {x:0,y:0}
}
