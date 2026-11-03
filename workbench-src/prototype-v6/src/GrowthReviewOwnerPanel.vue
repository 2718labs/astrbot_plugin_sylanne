<script setup lang="ts">
import {computed,onBeforeUnmount,ref,watch,toRaw} from 'vue'
import type {BackendController} from './use-backend.ts'
import type {GrowthReviewAttempt,GrowthReviewItem,GrowthReviewKind,GrowthReviewState} from './api/growth-review.ts'
import {operationIdV1} from './api/browser-crypto.ts'
import type {ProjectContextOptions} from './api/project-context.ts'
const props=defineProps<{backend:BackendController}>()
const refsText=ref(''),options=ref<ProjectContextOptions|null>(null),selected=ref('')
const result=ref<GrowthReviewState|null>(null),busy=ref(false),message=ref(''),acknowledged=ref('')
const pending=computed(()=>props.backend.growthReviews.pending.value)
const eligible=computed(()=>props.backend.canRead.value&&props.backend.runtimeReadable.value&&!busy.value)
const labels:Record<GrowthReviewItem['state'],string>={not_required:'当前没有适用成长重评要求',pending:'等待所有者明确核对',stale:'重评依据已变化，需重新标记',owner_confirmed_keep:'保留原义务的确认当前有效'}
const baselineLabels:Record<GrowthReviewItem['baseline_state'],string>={no_growth:'当前没有适用成长',birth_current:'首建原件确认出生于当前人格',birth_stale:'首建依据属于其他人格版本',baseline_unknown:'首建依据不完整，仍需明确重评'}
let generation=0
function clear(){++generation;result.value=null;options.value=null;selected.value='';acknowledged.value='';message.value=''}
watch(()=>[props.backend.state.scope,props.backend.state.auth,props.backend.state.owner,props.backend.runtimeReadable.value],clear,{flush:'sync'})
watch(refsText,()=>{++generation;result.value=null;acknowledged.value='';message.value=''},{flush:'sync'})
watch(selected,value=>{if(value)refsText.value=value})
onBeforeUnmount(()=>{++generation})
const current=(token:number,scope:string)=>token===generation&&scope===props.backend.state.scope&&props.backend.canRead.value&&props.backend.runtimeReadable.value
function references(){return refsText.value.split(/\r?\n/).map(value=>value.trim()).filter(Boolean)}
async function discover(){
 if(!eligible.value)return
 const token=generation,scope=props.backend.state.scope
 busy.value=true;options.value=null;message.value='正在读取当前获准项目引用。'
 try{const value=await props.backend.projectContext.read(scope);if(current(token,scope)){options.value=value;message.value=value.items.length?'选择真实项目或 recipe 后，明确读取它的当前重评状态。':'当前没有获准项目；可以填写已有目标、承诺、计划或习惯的真实引用。'}}
 catch{if(current(token,scope))message.value='项目目录未取得，请核验当前会话与角色范围。'}finally{busy.value=false}
}
async function read(){
 if(!eligible.value)return
 const refs=references()
 if(!refs.length||refs.length>16||new Set(refs).size!==refs.length){message.value='请填写1至16个不重复的真实对象引用，每行一个。';return}
 const token=++generation,scope=props.backend.state.scope
 busy.value=true;result.value=null;acknowledged.value='';message.value='正在独立读取当前人格与对象版本、重评状态。'
 try{const value=await props.backend.growthReviews.read(scope,refs);if(current(token,scope)){result.value=value;message.value=value.coverage==='complete'?'当前选择的重评状态已读取。标记与保留确认需要分别明确提交。':'本次读取有缺失对象，请查看缺失说明。'}}
 catch{if(current(token,scope))message.value='当前重评状态未取得，未使用旧状态。请核验授权、实际成长采用与对象引用。'}finally{busy.value=false}
}
async function submit(item:GrowthReviewItem|null,kind:GrowthReviewKind,replay=false){
 if(!eligible.value)return
 let attempt:GrowthReviewAttempt
 if(replay){if(!pending.value||pending.value.scope!==props.backend.state.scope)return;attempt=structuredClone(toRaw(pending.value))}
 else{
  if(pending.value||!item?.request||!result.value?.items.includes(item)||!item.permitted_controls.includes(kind))return
  if(kind.startsWith('confirm_')&&acknowledged.value!==item.ref)return
  attempt={scope:props.backend.state.scope,kind,input:{activity_id:item.activity_id,audience_ref:'owner',parent_budget_lease_ref:item.parent_budget_lease_ref,request:structuredClone(toRaw(item.request))},operationId:operationIdV1()}
  props.backend.growthReviews.pending.value=attempt
 }
 const token=++generation,scope=attempt.scope
 busy.value=true;result.value=null;acknowledged.value='';message.value=replay?'正在核验或补交原请求，操作ID与输入保持原样。':'正在独立核验当前 Owner、Source 和对象版本并提交本次选择。'
 let received=false
 try{
  const receipt=await props.backend.growthReviews.submit(scope,attempt.kind,attempt.input,attempt.operationId)
  received=true
  if(props.backend.growthReviews.pending.value?.operationId===attempt.operationId)props.backend.growthReviews.pending.value=null
  if(!current(token,scope))return
  message.value=receipt.coverage==='complete'?'已取得操作原件，正在另起只读操作核验当前重评状态。':'本次原件记录等待原始依据，正在另起只读操作核验当前状态。'
  const observed=await props.backend.growthReviews.read(scope,[attempt.input.request.target_ref])
  if(!current(token,scope))return
  result.value=observed
  const row=observed.items[0],expected=attempt.kind.startsWith('confirm_')?'owner_confirmed_keep':'pending'
  message.value=row?.state===expected&&row.review_operation_id===attempt.operationId?'独立回读已确认本次'+(expected==='pending'?'标记生效；仍需所有者另行明确确认保留原义务。':'保留确认当前生效。'):'操作原件已取得；当前状态按独立回读显示，未把回执视为本次选择已生效。'
 }catch{
  if(current(token,scope))message.value=received?'操作原件已取得，但独立回读未完成。请明确重读；不会再次提交。':'操作结果尚未确认，可能已经保存。已保留原操作ID与精确输入，只能明确核验或补交原请求。'
 }finally{busy.value=false}
}
</script>
<template>
 <section class="growth-review" aria-labelledby="growth-review-title" :aria-busy="busy">
  <h4 id="growth-review-title">成长后的义务重评</h4>
  <p>先读取当前对象，分别提交重评标记与保留原义务的确认。确认只记录本次保留选择，新增工作仍需实际准入。</p>
  <button :disabled="!eligible" @click="discover">读取真实项目引用</button>
  <label v-if="options?.items.length">选择项目或 recipe
   <select v-model="selected" :disabled="busy"><option value="">请选择已有对象</option><optgroup v-for="(item,index) in options.items" :key="item.project_ref" :label="'项目 '+(index+1)"><option :value="item.project_ref">{{item.project_ref}}</option><option :value="item.recipe_ref">{{item.recipe_ref}}</option></optgroup></select>
  </label>
  <label for="growth-review-targets">已有目标、承诺、计划、Life 项目、recipe 或习惯的引用，每行一个（最多16项）
   <textarea id="growth-review-targets" v-model="refsText" rows="3" :disabled="busy"/>
  </label>
  <button :disabled="!eligible" @click="read">独立读取当前重评状态</button>
  <template v-if="result">
   <article v-for="item in result.items" :key="item.ref">
    <h5>{{item.ref}}</h5><p>{{labels[item.state]}}</p><p>出生依据：{{baselineLabels[item.baseline_state]}}</p>
    <dl><div><dt>当前对象版本</dt><dd>{{item.revision}}</dd></div><div><dt>当前人格</dt><dd>{{item.head_id}} · activation {{item.activation_revision}}</dd></div><div><dt>成长操作</dt><dd>{{item.growth_operation_id??'当前无适用成长'}}</dd></div><div><dt>重评版本</dt><dd>{{item.review_revision}}</dd></div></dl>
    <template v-for="kind in item.permitted_controls" :key="kind">
     <label v-if="kind.startsWith('confirm_')" class="acknowledge"><input type="checkbox" :checked="acknowledged===item.ref" :disabled="!eligible||!!pending" @change="acknowledged=acknowledged===item.ref?'':item.ref"/>我已核对该对象，明确选择在当前人格下保留原义务</label>
     <button :disabled="!eligible||!!pending||(kind.startsWith('confirm_')&&acknowledged!==item.ref)" @click="submit(item,kind)">{{kind.startsWith('confirm_')?'确认保留原义务':'标记此对象需要重评'}}</button>
    </template>
   </article>
   <ul v-if="result.missing_inputs.length"><li v-for="reason in result.missing_inputs" :key="reason">{{reason}}</li></ul>
  </template>
  <template v-if="pending"><p>原请求尚未确认：{{pending.operationId}}。对象：{{pending.input.request.target_ref}}。</p><button :disabled="!eligible" @click="submit(null,pending.kind,true)">核验或补交原请求（保留原操作ID）</button></template>
  <p v-if="!backend.canRead.value">先核验当前所有者会话、角色范围与实际运行状态。</p>
  <p v-if="message" role="status" aria-live="polite">{{message}}</p>
 </section>
</template>
<style scoped>
.growth-review{font-size:12px;line-height:1.8;overflow-wrap:anywhere;margin-bottom:28px}h4{font-size:16px;font-weight:500;margin:0 0 14px}h5{font-size:12px;font-weight:500;margin:14px 0}p{color:var(--muted)}label{display:grid;gap:8px;margin:12px 0}textarea,select{box-sizing:border-box;width:100%;min-height:44px;font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--line);padding:10px}button{display:block;font:inherit;min-height:44px;padding:10px 0;text-align:left;cursor:pointer}button:disabled{color:var(--muted);cursor:default}button:focus-visible,textarea:focus-visible,select:focus-visible,input:focus-visible{outline:2px solid var(--ink);outline-offset:3px}.acknowledge{display:flex;align-items:flex-start;gap:8px}.acknowledge input{min-height:24px}article{border-top:1px solid var(--line);margin-top:16px}dl>div{display:flex;justify-content:space-between;gap:16px}dd{margin:0}
</style>
