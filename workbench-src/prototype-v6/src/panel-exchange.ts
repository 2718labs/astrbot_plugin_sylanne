import {smoothRange} from './arc-model.ts'
/** One reversible timeline: the browsing block clears before detail ink arrives.
 * No local timers or direction-dependent resets; interrupted gestures retain pose.
 */
export function panelExchange(phase:number,departurePhase?:number){
 const progress=Math.max(0,Math.min(1,departurePhase??phase))
 const browseExit=smoothRange(progress,0,.42)
 const detailReveal=smoothRange(progress,.42,.90)
 return {browseExit,browseOpacity:1-smoothRange(progress,.20,.42),detailReveal,detailX:-28*(1-detailReveal),detailVisible:detailReveal>0}
}
