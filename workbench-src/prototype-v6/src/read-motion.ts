// Central proximity controls optical feedback; only an explicit selection spins
// the large OPTIC_main annulus. Neither feedback path opens details or reads data.
export interface ReadingMotion { glow:number; speed:number; angle:number; logical:number|null }
export const makeReadingMotion=():ReadingMotion=>({glow:0,speed:0,angle:0,logical:null})
export function isReadingSelected(logical:number,state:{logical:number;mode:string}){
 return (state.mode==='opening'||state.mode==='detail')&&logical===state.logical
}
// Compact smoothstep support: adjacent disks crossfade at the midpoint, while
// all other disks stay clear. This uses physical position, never rounded focus.
export function readingFocusWeight(logical:number,position:number){
 const t=Math.max(0,1-Math.abs(logical-position))
 return t*t*(3-2*t)
}
export function bindReadingIdentity(motion:ReadingMotion,logical:number){
 // Pool recycling occurs outside the visible arc; new identities inherit no glow.
 if(motion.logical!==logical){motion.logical=logical;motion.glow=0;motion.speed=0;motion.angle=0}
 return motion
}
export function updateReadingMotion(motion:ReadingMotion,logical:number,selected:boolean,dt:number,reduced:boolean,focus=0){
 bindReadingIdentity(motion,logical)
 const elapsed=Math.max(0,Math.min(.1,dt)),target=selected?1:Math.max(0,Math.min(1,focus))
 // Symmetric response makes both arrival and departure gradual, without a
 // threshold flash. Selection retains its glow even while the arc docks.
 motion.glow=reduced?target:target+(motion.glow-target)*Math.exp(-elapsed*4.6)
 if(Math.abs(motion.glow-target)<.0005)motion.glow=target
 const speed=selected&&!reduced?.13:0,rate=selected?2.4:3.2,decay=Math.exp(-elapsed*rate)
 if(reduced){motion.speed=0}else{
  // Exact velocity integral preserves angle across close/reselect and dt changes.
  motion.angle=(motion.angle+speed*elapsed+(motion.speed-speed)*(1-decay)/rate)%(Math.PI*2)
  motion.speed=speed+(motion.speed-speed)*decay
  if(!selected&&motion.speed<.0005)motion.speed=0
 }
 return motion
}
