/** Auth-free choreography. Measured source relationships adapted to Sylanne's own geometry.
 * No source PV image, emblem, voice or soundtrack is part of this implementation. */
export const unit=(v:number)=>Math.min(1,Math.max(0,Number.isFinite(v)?v:0))
export const smooth=(v:number)=>{const p=unit(v);return p*p*(3-2*p)}
export const track=(p:number,a:number,b:number)=>smooth((p-a)/(b-a))
export function interpolate(keys:readonly (readonly [number,number])[],time:number){
 const t=Number.isFinite(time)?time:0
 if(t<=keys[0]![0])return keys[0]![1]
 for(let i=1;i<keys.length;i++){const a=keys[i-1]!,b=keys[i]!;if(t<=b[0])return a[1]+(b[1]-a[1])*((t-a[0])/(b[0]-a[0]))}
 return keys[keys.length-1]![1]
}
// Source f260–292: size stays constant; 131 / 852 screen widths left.
export const LOGO_SLIDE = [[0,0],[.1,2],[.17,9],[.33,54.5],[.5,94],[.67,114],[.83,125],[1,131]] as const
// Source radius samples, excluding the deliberately omitted rapid-flash substitutions.
export const RING_CONTRACTION = [[0,580],[.10,398],[.20,289],[.30,218],[.40,172],[.50,143],[.58,129],[.70,120],[.85,113],[1,110]] as const
/** Broad reveal brushes over the original PNG, NOT replacement logo paths.
 * Masks follow four existing angular corner strokes, two central curved strokes,
 * and the colored center. Original pixels are restored in full at completion. */
export const LOGO_BRUSHES = [
 {id:'upper-left',d:'M44 89 L44 53 L89 53 L89 76',start:0,end:.38},
 {id:'lower-right',d:'M155 112 L155 146 L111 146 L111 128',start:.08,end:.46},
 {id:'upper-right',d:'M111 75 L111 53 L155 53 L155 89',start:.17,end:.55},
 {id:'lower-left',d:'M89 129 L89 146 L44 146 L44 112',start:.25,end:.63},
 {id:'upper-bridge',d:'M36 101 L54 101 C77 101 76 78 100 78 C114 78 122 89 128 99',start:.34,end:.79},
 {id:'lower-bridge',d:'M164 101 L145 101 C122 101 123 126 100 126 C85 126 77 117 72 105',start:.42,end:.89},
] as const
export function logoBrushProgress(arrival:number,start:number,end:number){return track(unit(arrival),start,end)}
/** One shared parent transform, then a real oblique orthographic camera traversal.
 * All files preserve their own radial pose, spacing, lid and selected depth.
 * End pose is exactly the pre-existing workspace, not a different final layout. */
export function entryScenePose(progress:number){
 const p=unit(progress),q=1-smooth(p),drift=1-track(p,0,.84)
 return {rootX:-3.4*drift,rootY:.75*q,rootZ:-1.5*q,rootRotationX:.24*q,rootRotationY:-.48*q,rootRotationZ:.12*q,
 cameraX:5.2*q,cameraY:1.8*q,cameraZ:20,cameraZoom:1-.22*q,targetX:0,targetY:0,targetZ:0}
}
