/** Small world-space radial extraction, separate from navigation and panel phase. */
export interface RadialSample {logical:number;offset:number;velocity:number}
export const SELECTION_RADIAL_DISTANCE=.10
export function radialOffset(samples:readonly RadialSample[]|undefined,logical:number){return samples?.find(s=>s.logical===logical)?.offset??0}
export function advanceRadial(previous:readonly RadialSample[],logicals:readonly number[],selected:number|null,dt:number,reduced=false):RadialSample[]{
 const byLogical=new Map(previous.map(s=>[s.logical,s])),time=Math.max(0,Math.min(.1,dt))
 return logicals.map(logical=>{const target=logical===selected?SELECTION_RADIAL_DISTANCE:0,old=byLogical.get(logical)??{logical,offset:0,velocity:0};if(reduced)return {logical,offset:target,velocity:0};const omega=target?12:7,difference=old.offset-target,e=Math.exp(-omega*time),travel=(old.velocity+omega*difference)*time;let offset=target+(difference+travel)*e,velocity=(old.velocity-omega*travel)*e;if(Math.abs(offset-target)<2e-6&&Math.abs(velocity)<2e-5){offset=target;velocity=0}return {logical,offset,velocity}})
}
export function radialMoving(samples:readonly RadialSample[],selected:number|null){return samples.some(s=>Math.abs(s.offset-(s.logical===selected?SELECTION_RADIAL_DISTANCE:0))>2e-6||Math.abs(s.velocity)>2e-5)}
