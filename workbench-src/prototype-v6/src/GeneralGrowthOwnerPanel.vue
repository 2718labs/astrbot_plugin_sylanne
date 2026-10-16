<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { operationIdV1 } from './api/browser-crypto.ts'
import type { BackendController } from './use-backend.ts'
import {
  GENERAL_GROWTH_KINDS, GENERAL_GROWTH_FIELDS, isGeneralGrowthKind, validateGeneralGrowthInput,
  pendingGeneralGrowthAttempts as pending, type GeneralGrowthKind, type GeneralGrowthAttempt,
} from './api/general-growth.ts'
const props=defineProps<{backend:BackendController}>()
const labels:Record<GeneralGrowthKind,string>={
 freeze_general_growth_intent_v1:'冻结成长意图',
 register_general_growth_trial_start_v1:'登记试验 start',
 derive_general_growth_trial_v1:'从已结算进度登记试验结果',
 adopt_general_growth_v1:'Owner 明确采用成长提案',
}
const fieldLabels:Record<string,string>={
 interpretation_ref:'解释原件',trigger_original_ref:'原 outcome trigger',general_growth_intent_ref:'成长意图引用',
 growth_proposal_ref:'成长提案引用',counterevidence_query_ref:'反证查询原件',required_trial_refs:'所需试验引用（每行一个）',
 trial_start_refs:'一一对应的 start 原件（每行一个）',original_ref:'本次待登记原件引用',
 completed_trial_ref:'已计划的完成试验引用',project_ref:'Life 项目引用',recipe_ref:'Life recipe 引用',
 step_id:'Life step',life_plan_original_ref:'已签 Life plan 原件',settled_progress_ref:'已结算进度原件',
 trial_original_refs:'已完成试验原件（每行一个）',
}
const kind=ref(''),draft=ref<Record<string,string>>({})
const activity=ref(''),audience=ref(''),parentLease=ref(''),headKey=ref(''),headRevision=ref('')
const busy=ref(false),message=ref(''),attempt=ref<GeneralGrowthAttempt|null>(pending.get(props.backend.state.scope)??null)
const fields=computed(()=>isGeneralGrowthKind(kind.value)?GENERAL_GROWTH_FIELDS[kind.value].filter(name=>name!=='planned_head'):[])
const canSubmit=computed(()=>props.backend.canRead.value&&!busy.value&&attempt.value===null&&isGeneralGrowthKind(kind.value))
const locked=computed(()=>busy.value||attempt.value!==null)
function clearDraft(){draft.value={};headKey.value='';headRevision.value='';message.value=''}
watch(kind,clearDraft)
watch(()=>props.backend.state.scope,scope=>{
 kind.value='';activity.value='';audience.value='';parentLease.value='';clearDraft();attempt.value=pending.get(scope)??null
})
function makeAttempt():GeneralGrowthAttempt{
 if(!isGeneralGrowthKind(kind.value))throw new Error('请选择本次 Owner 操作。')
 const selected=kind.value,request:Record<string,unknown>={}
 for(const name of GENERAL_GROWTH_FIELDS[selected]){
  if(name==='planned_head'){request[name]={key:headKey.value.trim(),revision:Number(headRevision.value)};continue}
  const text=(draft.value[name]??'').trim()
  if(['required_trial_refs','trial_start_refs','trial_original_refs'].includes(name))
   request[name]=text.split(/\r?\n/).map(item=>item.trim()).filter(Boolean)
  else if(['project_ref','recipe_ref','step_id','life_plan_original_ref'].includes(name))request[name]=text||null
  else request[name]=text
 }
 const input=validateGeneralGrowthInput(selected,{activity_id:activity.value.trim(),audience_ref:audience.value.trim(),
  parent_budget_lease_ref:parentLease.value.trim(),request})
 return {scope:props.backend.state.scope,kind:selected,input,operationId:operationIdV1()}
}
async function submit(retry=false){
 if(busy.value)return
 if(!retry){
  if(!canSubmit.value)return
  try{attempt.value=makeAttempt()}catch(error){message.value=error instanceof Error?error.message:'请核对原件字段。';return}
 }
 const current=attempt.value
 if(!current||current.scope!==props.backend.state.scope||!props.backend.canRead.value)return
 pending.set(current.scope,current);busy.value=true;message.value='正在提交本次明确 Owner 请求…'
 try{
  const receipt=await props.backend.generalGrowth.submit(current.scope,current.kind,current.input,current.operationId)
  pending.delete(current.scope)
  if(current.scope!==props.backend.state.scope)return
  attempt.value=null
  message.value='已返回本次领域原件：'+receipt.original_digest+'。请在实际成长状态中核对结果。'
 }catch(error){
  if(current.scope===props.backend.state.scope)
   message.value=(error instanceof Error?error.message:'结果尚未确认。')+' 已保留原操作身份；核对实际状态后可用该身份重试。'
 }finally{busy.value=false}
}
</script>
<template>
 <section class="general-growth-owner" aria-label="Owner 成长操作" :aria-busy="busy">
  <h4>Owner 成长操作</h4>
  <p>按真实提案、试验与反证原件提交明确选择。等待 Owner 采用时，选择“Owner 明确采用成长提案”并填写已完成试验原件。会话需具备当前角色的 consolidation 授权。</p>
  <div class="general-growth-field"><label for="general-growth-kind">本次操作</label>
   <select id="general-growth-kind" v-model="kind" :disabled="locked">
    <option value="">请选择</option><option v-for="item in GENERAL_GROWTH_KINDS" :key="item" :value="item">{{labels[item]}}</option>
   </select>
  </div>
  <template v-if="isGeneralGrowthKind(kind)">
   <div class="general-growth-field"><label for="general-growth-activity">原 activity</label><input id="general-growth-activity" v-model="activity" :disabled="locked" autocomplete="off"></div>
   <div class="general-growth-field"><label for="general-growth-audience">实际受众引用</label><input id="general-growth-audience" v-model="audience" :disabled="locked" autocomplete="off"></div>
   <div class="general-growth-field"><label for="general-growth-parent">原 parent budget lease</label><input id="general-growth-parent" v-model="parentLease" :disabled="locked" autocomplete="off"><p>沿原父授权与绝对期限填写；Derive 使用 start 已签的父 lease。</p></div>
   <div v-for="name in fields" :key="name" class="general-growth-field">
    <label :for="'general-growth-'+name">{{fieldLabels[name]}}</label>
    <textarea :id="'general-growth-'+name" v-model="draft[name]" :disabled="locked" :rows="name.endsWith('_refs')?3:1" autocomplete="off" spellcheck="false"></textarea>
   </div>
   <template v-if="kind==='register_general_growth_trial_start_v1'">
    <div class="general-growth-field"><label for="general-growth-head">已计划 Graph head 的 key</label><input id="general-growth-head" v-model="headKey" :disabled="locked" autocomplete="off"></div>
    <div class="general-growth-field"><label for="general-growth-revision">已计划 Graph head 的 revision</label><input id="general-growth-revision" v-model="headRevision" :disabled="locked" type="number" min="1" step="1"></div>
    <p>Life 项目、recipe、step、plan 四项填写真实完整组；普通 Action 试验四项留空。</p>
   </template>
   <button class="general-growth-action" :disabled="!canSubmit" @click="submit()">{{labels[kind]}}</button>
  </template>
  <p v-if="attempt" class="general-growth-status">待确认操作：{{labels[attempt.kind]}} · {{attempt.operationId}}</p>
  <p v-if="message" class="general-growth-status" role="status">{{message}}</p>
  <button v-if="attempt" class="general-growth-action" :disabled="busy||!backend.canRead.value" @click="submit(true)">使用原操作身份重试</button>
 </section>
</template>
<style scoped>
.general-growth-owner{margin-top:24px;padding-top:16px;border-top:1px solid var(--line)}
.general-growth-owner p{font-size:12px;color:var(--muted);line-height:1.7}
.general-growth-field{margin:12px 0}.general-growth-field label{display:block;margin-bottom:6px}
.general-growth-field :is(input,select,textarea){box-sizing:border-box;width:100%;padding:9px;min-height:42px;border:1px solid var(--line);border-radius:3px;font:inherit;color:var(--ink);background:var(--surface)}
.general-growth-action{min-height:44px;padding:9px 13px;font:inherit;color:var(--ink);background:var(--button);border:1px solid var(--line);border-radius:3px;cursor:pointer}
.general-growth-action:disabled{background:var(--disabled-bg);color:var(--disabled-ink);cursor:default}
.general-growth-status{overflow-wrap:anywhere}
.general-growth-owner :is(button,input,select,textarea):focus-visible{outline:2px solid var(--focus);outline-offset:3px}
</style>
