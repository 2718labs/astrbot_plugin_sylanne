import * as THREE from 'three'
import { OPTICAL_ACTIVITY_MAX } from './read-activity.ts'
const shellCold=new THREE.Color('#D4DEE1'),frostCold=new THREE.Color('#E9EFEF')
// Rear optical tray is the privacy layer. Rings sit in front of this surface.
export function readingMaterial(material:THREE.Material,nodeName:string,fade:number,glow:number,availability:string,activityBoost=0){
 const base=material.userData.originalOpacity as number,frost=Math.max(0,Math.min(1,glow))
 material.opacity=base*fade
 if(!(material instanceof THREE.MeshStandardMaterial)){syncMaterialTransparency(material);return}
 if(nodeName.startsWith('ARCHIVE_body')&&material.name==='MAT_archive_shell'){
  material.opacity=(base+(.96-base)*frost)*fade;material.color.copy(shellCold).lerp(frostCold,frost);material.roughness=.55+.35*frost
 }
 if(nodeName.startsWith('LID_panel')&&material.name==='MAT_archive_lid'){material.opacity=(base+.07*frost)*fade;material.roughness=.50+.35*frost}
 if(nodeName==='MARK_status')material.color.set(availability==='available'?'#adbf67':'#839198')
 if(nodeName.startsWith('OPTIC_small')){material.emissive.set('#b7d98f');material.emissiveIntensity=frost*(material.name.includes('amber')?.68:.22)*(1+Math.max(0,Math.min(OPTICAL_ACTIVITY_MAX,Number.isFinite(activityBoost)?activityBoost:0)))}else{material.emissive.setHex(0);material.emissiveIntensity=0}
 syncMaterialTransparency(material)
}

/** Opaque/transparent changes affect Three's shader program, not only draw sorting. */
export function syncMaterialTransparency(material:THREE.Material){
 const transparent=material.opacity<1
 if(material.transparent!==transparent){material.transparent=transparent;material.needsUpdate=true}
 material.depthWrite=!transparent
}
