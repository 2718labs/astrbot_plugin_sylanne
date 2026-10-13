import * as THREE from 'three'
import {visibleSlots,ARC_STEP_ANGLE,type ArcSnapshot,type ArcSlot} from './arc-engine.ts'
import {arcLayout,readingStageShift} from './arc-model.ts'
import {entryScenePose} from './entry-choreography.ts'
import {LOGOUT_DURATION} from './logout-flow.ts'

export type SceneTheme='light'|'dark'|number
export const themeWeight=(theme:SceneTheme)=>typeof theme==='number'?Math.min(1,Math.max(0,Number.isFinite(theme)?theme:0)):theme==='dark'?1:0
const unit=(value:number)=>Math.min(1,Math.max(0,Number.isFinite(value)?value:0))
const smooth=(value:number)=>{const t=unit(value);return t*t*(3-2*t)}
/** A minimum virtual width fits the same radial model on portrait displays.
 * The entire scene remains bottom anchored; no selected card gets a special scale.
 * DPR affects raster size only, never projection or ray coordinates. */
export function sceneViewport(width:number,height:number,dpr=1){
 const w=Math.max(1,Number.isFinite(width)?width:1),h=Math.max(1,Number.isFinite(height)?height:1)
 const aspect=w/h,layoutAspect=Math.max(.95,aspect),halfWidth=layoutAspect*5,halfHeight=halfWidth/aspect
 return {width:w,height:h,aspect,layoutAspect,halfWidth,halfHeight,rootY:5-halfHeight,dpr:Math.min(1.5,Math.max(1,Number.isFinite(dpr)?dpr:1))}
}
export function pointerNdc(x:number,y:number,box:{left:number;top:number;width:number;height:number}){
 if(box.width<=0||box.height<=0)return null
 return {x:((x-box.left)/box.width)*2-1,y:1-((y-box.top)/box.height)*2}
}
/** The entrance's Z rotation decreases from +.12 to 0. Continue that sign
 * around the arc's own lower-right center, never rewind the entry track.
 * Opacity stays intact until the geometry is safely past the viewport edge. */
export const EXIT_ARC_TURN=-2.25
export function exitScenePose(progress:number){
 const p=unit(progress),t=smooth(p)
 return {x:.8*t,y:0,z:0,rotationY:0,rotationZ:EXIT_ARC_TURN*t,opacity:1-smooth((p-.94)/.06),relaxation:1-t}
}
/** Compatibility helper for passive snapshots. Never mutate the engine. */
export function sceneExitFrame(frame:ArcSnapshot,progress:number):ArcSnapshot{
 if(progress<=0)return frame
 const amount=exitScenePose(progress).relaxation
 return {...frame,repulsion:frame.repulsion?.map(s=>({...s,angle:s.angle*amount,velocity:s.velocity*amount}))}
}
export interface ExitSceneSnapshot {frame:ArcSnapshot;slots:ArcSlot[];velocity:number;phaseVelocity:number}
/** Capture exactly the most recently displayed pose before back()/pointer cancel.
 * Preserve physical instances, labels, overlap order, and edge visibility. */
export function captureExitScene(frame:ArcSnapshot,velocity=0,phaseVelocity=0):ExitSceneSnapshot{
 return {frame:{...frame,repulsion:frame.repulsion?.map(s=>({...s})),radial:frame.radial?.map(s=>({...s}))},slots:visibleSlots(frame.position,frame.count).map(s=>({...s})),velocity:Number.isFinite(velocity)?velocity:0,phaseVelocity:Number.isFinite(phaseVelocity)?phaseVelocity:0}
}
/** Analytic inertial coast has the same initial velocity and eases to rest.
 * It cannot snap to a queued selection, reround a slot, or recycle a label.
 * Repulsion retains its position AND velocity while critically damping to zero. */
export function sampleExitScene(snapshot:ExitSceneSnapshot,progress:number){
 const p=unit(progress),seconds=p*LOGOUT_DURATION/1000,tau=.075/(1+Math.abs(snapshot.velocity)/10),coast=tau*(1-Math.exp(-seconds/tau))
 const delta=snapshot.velocity*coast,source=snapshot.frame
 const frame={...source,position:source.position+delta,phase:unit(source.phase+snapshot.phaseVelocity*coast),radial:source.radial?.map(s=>({...s,offset:s.offset+s.velocity*coast,velocity:s.velocity*Math.exp(-seconds/tau)})),repulsion:source.repulsion?.map(s=>{const e=Math.exp(-18*seconds),a=s.velocity+18*s.angle;return {...s,angle:(s.angle+a*seconds)*e,velocity:(s.velocity-18*a*seconds)*e}})}
 const slots=snapshot.slots.map(s=>({...s,angle:s.angle+delta*ARC_STEP_ANGLE}))
 return {frame,slots}
}
/** Same matrix is used by WebGL and the CPU preview. At progress zero the
 * pivot conjugation is exactly identity, including on a resized viewport. */
export function sceneRootMatrix(entryProgress:number,exitProgress:number,aspect:number,rootY:number,frame:ArcSnapshot){
 const pose=entryScenePose(entryProgress),exit=exitScenePose(exitProgress),layout=arcLayout(aspect),shift=readingStageShift(frame.phase,aspect)
 const base=new THREE.Matrix4().compose(new THREE.Vector3(pose.rootX,pose.rootY+rootY,pose.rootZ),new THREE.Quaternion().setFromEuler(new THREE.Euler(pose.rootRotationX,pose.rootRotationY,pose.rootRotationZ)),new THREE.Vector3(1,1,1))
 const x=layout.cx+shift.x,y=layout.cy+shift.y
 return base.multiply(new THREE.Matrix4().makeTranslation(x+exit.x,y,0)).multiply(new THREE.Matrix4().makeRotationZ(exit.rotationZ)).multiply(new THREE.Matrix4().makeTranslation(-x,-y,0))
}
export function sceneLighting(theme:SceneTheme){
 const t=themeWeight(theme),color=(a:string,b:string)=>new THREE.Color(a).lerp(new THREE.Color(b),t),n=(a:number,b:number)=>a+(b-a)*t
 return {sky:color('#ffffff','#c7dded'),ground:color('#bac8ce','#202c37'),hemisphere:n(1.85,1.1),key:color('#ffffff','#e2edf4'),keyIntensity:n(2.5,2.15),rim:color('#e9f3f4','#a9cdd4'),rimIntensity:n(1.25,1.85),exposure:n(1.06,.92)}
}
/** Geometry and embedded label textures are untouched. Light mode keeps original
 * material values; dark glass is physically shaded, never screen/filter inverted. */
/** The official labels are transparent printed-ink decals, not white plates.
 * Physical glass stays lighter than the UI page, so retain its original dark
 * printing until late in the same theme clock. Never interpolate opposite inks:
 * that erased every source color into identical linear gray at weight .5.
 * Source RGB identity, alpha and UVs are untouched on each polarity branch. */
export const LABEL_INK_POLARITY_CROSSOVER = .8
export const labelInkPolarity = (theme:SceneTheme) => themeWeight(theme) >= LABEL_INK_POLARITY_CROSSOVER ? 1 : 0
export function labelInkColor(color:THREE.Color,theme:SceneTheme){
 return labelInkPolarity(theme) ? new THREE.Color(1-color.r,1-color.g,1-color.b) : color.clone()
}
export const LABEL_INK_SHADER=`diffuseColor.rgb = mix(diffuseColor.rgb, vec3(1.0) - diffuseColor.rgb, step(${LABEL_INK_POLARITY_CROSSOVER.toFixed(1)}, archiveDarkInk));`
function labelInkMaterial(material:THREE.MeshStandardMaterial,theme:SceneTheme){
 let uniform=material.userData.archiveDarkInk as {value:number}|undefined
 if(!uniform){
  uniform={value:themeWeight(theme)};material.userData.archiveDarkInk=uniform
  material.onBeforeCompile=shader=>{
   shader.uniforms.archiveDarkInk=uniform!
   shader.fragmentShader='uniform float archiveDarkInk;\n'+shader.fragmentShader
   shader.fragmentShader=shader.fragmentShader.replace('#include <map_fragment>','#include <map_fragment>\n'+LABEL_INK_SHADER)
   shader.fragmentShader=shader.fragmentShader.replace('#include <emissivemap_fragment>',`#include <emissivemap_fragment>\ntotalEmissiveRadiance += diffuseColor.rgb * (0.22 * step(${LABEL_INK_POLARITY_CROSSOVER.toFixed(1)}, archiveDarkInk));`)
  }
  material.customProgramCacheKey=()=> 'archive-embedded-label-ink-v23'
  material.needsUpdate=true
 }
 uniform.value=themeWeight(theme)
}
export function themeSceneMaterial(material:THREE.Material,nodeName:string,theme:SceneTheme,glow=0){
 if(!(material instanceof THREE.MeshStandardMaterial))return
 const key='sceneThemeOriginalColor'
 if(!material.userData[key])material.userData[key]=material.color.clone()
 if(nodeName==='ARCHIVE_label'){
  material.color.set('#ffffff')
  material.emissive.set('#000000');material.emissiveMap=null;material.emissiveIntensity=0
  labelInkMaterial(material,theme)
  return
 }
 if(nodeName.startsWith('ARCHIVE_body')&&material.name==='MAT_archive_shell'){
  material.color.lerp(new THREE.Color('#334752').lerp(new THREE.Color('#647984'),unit(glow)),themeWeight(theme))
 }else if(nodeName.startsWith('LID_panel')&&material.name==='MAT_archive_lid'){
  material.color.copy(material.userData[key]).lerp(new THREE.Color('#8499a4'),themeWeight(theme))
 }
}
