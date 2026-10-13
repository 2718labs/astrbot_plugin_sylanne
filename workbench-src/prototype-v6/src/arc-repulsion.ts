/** Angular displacement is keyed by physical logical identity, never record index. */
export interface RepulsionSample { logical:number; angle:number; velocity:number }
export const REPULSION_MAX_ANGLE=.045 // 2.58 degrees, comfortably below one shingle pitch.
export const REPULSION_OPEN_OMEGA=12,REPULSION_CLOSE_OMEGA=7
export function repulsionTarget(logical:number,selected:number|null){
 if(selected===null||logical===selected)return 0
 const distance=logical-selected
 // True local falloff: first neighbor strongest, distant copies barely move.
 return -Math.sign(distance)*REPULSION_MAX_ANGLE/Math.pow(Math.abs(distance),1.65)
}
export function repulsionAngle(samples:readonly RepulsionSample[]|undefined,logical:number){return samples?.find(s=>s.logical===logical)?.angle??0}
export function advanceRepulsion(previous:readonly RepulsionSample[],logicals:readonly number[],selected:number|null,dt:number,reduced=false,selectedAnchorAngle=0):RepulsionSample[]{
 const byLogical=new Map(previous.map(sample=>[sample.logical,sample]))
 const omega=selected===null?REPULSION_CLOSE_OMEGA:REPULSION_OPEN_OMEGA
 return logicals.map(logical=>{
  const target=logical===selected?selectedAnchorAngle:repulsionTarget(logical,selected),old=byLogical.get(logical)??{logical,angle:0,velocity:0}
  if(reduced)return {logical,angle:target,velocity:0}
  // Exact critically damped spring, retaining position AND velocity on retarget.
  const elapsed=Math.max(0,Math.min(.1,dt)),offset=old.angle-target,e=Math.exp(-omega*elapsed),t=(old.velocity+omega*offset)*elapsed
  let angle=target+(offset+t)*e,velocity=(old.velocity-omega*t)*e
  if(Math.abs(angle-target)<1e-6&&Math.abs(velocity)<1e-5){angle=target;velocity=0}
  // Guard adversarial rapid reversals without allowing shingle reordering.
  if(Math.abs(angle)>REPULSION_MAX_ANGLE){angle=Math.sign(angle)*REPULSION_MAX_ANGLE;if(Math.sign(velocity)===Math.sign(angle))velocity=0}
  return {logical,angle,velocity}
 })
}
export function repulsionMoving(samples:readonly RepulsionSample[],selected:number|null,selectedAnchorAngle=0){return samples.some(s=>Math.abs(s.angle-(s.logical===selected?selectedAnchorAngle:repulsionTarget(s.logical,selected)))>1e-6||Math.abs(s.velocity)>1e-5)}
