import { ref } from 'vue'

const DISPLAY_ALIAS_KEY='2718lab.display-alias'
const alias=ref('')
let loaded=false
/** A browser display label only. It never names a D01 persona or grants a scope. */
export function useDisplayAlias(){
  if(!loaded&&typeof window!=='undefined'){loaded=true;try{const value=window.localStorage.getItem(DISPLAY_ALIAS_KEY);if(typeof value==='string')alias.value=value.slice(0,80)}catch{/* Preferences remain usable in this tab. */}}
  function set(value:string){alias.value=value.slice(0,80);try{window.localStorage.setItem(DISPLAY_ALIAS_KEY,alias.value)}catch{/* No server state is inferred from local storage. */}}
  return{alias,set}
}
