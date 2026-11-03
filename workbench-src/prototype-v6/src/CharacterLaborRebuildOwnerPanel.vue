<script setup lang="ts">
import {computed,onBeforeUnmount,ref,watch} from 'vue'
import type {BackendController} from './use-backend.ts'
import {WorkbenchApi} from './api/client.ts'
import {operationIdV1} from './api/browser-crypto.ts'
import type {CurrentActionItem} from './api/commitment-fulfillment.ts'
import {validateLaborRebuildInput,type LaborOptions,type LaborPreview,type LaborRebuildInput,type LaborRebuildReceipt} from './api/character-labor-rebuild.ts'
const props=defineProps<{backend:BackendController}>()
const api=new WorkbenchApi({enabled:props.backend.state.mode==='same-origin'})
const pending=props.backend.laborRebuild.pending
const actionRefs=ref(''),actions=ref<CurrentActionItem[]>([]),selectedActionRef=ref(''),parentBudget=ref(''),policyKey=ref('')
const options=ref<LaborOptions|null>(null),preview=ref<LaborPreview|null>(null),receipt=ref<LaborRebuildReceipt|null>(null)
const previewOwner=ref(''),message=ref(''),busy=ref(false)
let generation=0
const eligible=computed(()=>props.backend.state.mode==='same-origin'&&props.backend.state.auth==='authenticated'
 &&props.backend.state.dashboard==='authenticated'&&props.backend.state.owner==='unlocked'&&props.backend.scopeValid.value&&!props.backend.state.busy)
const locked=computed(()=>!eligible.value||busy.value||pending.value!==null)
const selectedAction=computed(()=>actions.value.find(a=>a.ref===selectedActionRef.value))
const selectedPolicy=computed(()=>options.value?.options.find(p=>p.policy_ref+'|'+p.policy_revision===policyKey.value))
const reasonLabels:Record<string,string>={recipe_not_nonpreemptible_source_note_v2:'原方案不属于此重建流程',policy_recipe_mismatch:'政策与原方案不匹配',policy_work_kind_or_reality_mismatch:'工作种类或现实性不匹配',policy_expired:'政策已过期',current_profile_absent:'当前身体配置不可用',current_body_absent:'当前身体状态不可用'}
function clearVisible(){++generation;api.clearSession();actionRefs.value='';actions.value=[];selectedActionRef.value='';parentBudget.value='';policyKey.value='';options.value=null;preview.value=null;previewOwner.value='';receipt.value=null;message.value=''}
watch(()=>[props.backend.state.scope,props.backend.state.auth,props.backend.state.dashboard,props.backend.state.owner],clearVisible,{flush:'sync'})
watch(()=>[selectedActionRef.value,parentBudget.value],()=>{options.value=null;policyKey.value='';preview.value=null;previewOwner.value='';receipt.value=null})
watch(policyKey,()=>{preview.value=null;previewOwner.value='';receipt.value=null})
onBeforeUnmount(()=>{++generation;api.clearSession();actions.value=[];options.value=null;preview.value=null;receipt.value=null})
function errorText(error:unknown){return error instanceof Error?error.message:'本次结果尚未核验。'}
function current(token:number,scope:string){return token===generation&&scope===props.backend.state.scope&&eligible.value}
async function readActions(){
 if(locked.value)return
 const refs=actionRefs.value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean)
 if(refs.length<1||refs.length>16||new Set(refs).size!==refs.length){message.value='请填写1至16个不重复的实际 Action 引用，每行一个。';return}
 const scope=props.backend.state.scope,token=++generation
 busy.value=true;actions.value=[];selectedActionRef.value='';message.value='正在核验当前 Action 元数据…'
 try{const value=await api.readCurrentCommitmentAction(scope,refs);if(!current(token,scope))return;actions.value=value.items;message.value=value.coverage==='complete'?'请选择本次已核验的 Action。政策读取仍会独立核验其签名 A 原件。':'当前覆盖不完整；可用项仍须后续独立核验。'}catch(error){if(token===generation)message.value=errorText(error)}finally{busy.value=false}
}
async function readOptions(){
 if(locked.value||!selectedAction.value||!parentBudget.value.trim())return
 const a=selectedAction.value,scope=props.backend.state.scope,token=++generation
 busy.value=true;options.value=null;policyKey.value='';preview.value=null;message.value='正在核验签名 A、原方案和完整政策目录…'
 try{const value=await api.readCharacterLaborRebuildOptions(scope,{action_intent_ref:a.ref,activity_id:a.activity_id,audience_ref:a.audience_ref,parent_budget_lease_ref:parentBudget.value.trim()});if(!current(token,scope))return;options.value=value;message.value=value.policy_count?'政策目录读取完成，请明确选择可用政策。':'完整目录中没有可供选择的政策。'}catch(error){if(token===generation)message.value=errorText(error)}finally{busy.value=false}
}
function selectionInput():LaborRebuildInput{
 const a=selectedAction.value,p=selectedPolicy.value,o=options.value
 if(!a||!p?.eligible||!o)throw new Error('请先读取实际 Action 并明确选择可用政策。')
 return validateLaborRebuildInput(props.backend.state.scope,{activity_id:o.activity_id,audience_ref:o.audience_ref,parent_budget_lease_ref:o.parent_budget_lease_ref,request:{selector:{action_intent_ref:a.ref,policy_ref:p.policy_ref,policy_revision:p.policy_revision},expected_choice_digest:null}})
}
async function readPreview(){
 if(locked.value)return
 const scope=props.backend.state.scope,token=++generation
 busy.value=true;preview.value=null;previewOwner.value='';message.value='正在读取当前签名选择与正式 checkpoint 元数据…'
 try{const input=selectionInput(),identity=await api.readOwnerSessionIdentity();if(!current(token,scope))return;const value=await api.previewCharacterLaborRebuild(scope,input);if(!current(token,scope))return;preview.value=value;previewOwner.value=identity.owner_binding_digest;message.value='预览已核验。确认后会以新 READ 复查本次选择，再提交正式重建。'}catch(error){if(token===generation)message.value=errorText(error)}finally{busy.value=false}
}
async function submit(){
 if(!eligible.value||busy.value)return
 const scope=props.backend.state.scope,token=++generation
 busy.value=true;receipt.value=null
 try{
  const identity=await api.readOwnerSessionIdentity()
  if(!current(token,scope))return
  if(!pending.value){
   if(!preview.value||previewOwner.value!==identity.owner_binding_digest)throw new Error('当前 Owner 与原预览身份不一致，请重新核验预览。')
   const p=preview.value
   const input=validateLaborRebuildInput(scope,{activity_id:p.activity_id,audience_ref:p.audience_ref,parent_budget_lease_ref:p.parent_budget_lease_ref,request:{selector:{...p.selector},expected_choice_digest:p.choice_digest}})
   Object.freeze(input.request.selector);Object.freeze(input.request);Object.freeze(input)
   pending.value=Object.freeze({scope,operationId:operationIdV1(),ownerBindingDigest:identity.owner_binding_digest,input})
  }
  const attempt=pending.value
  if(attempt.scope!==scope||attempt.ownerBindingDigest!==identity.owner_binding_digest)throw new Error('待确认请求属于原 Owner 与角色范围。请恢复原身份后核验同一 UUID。')
  message.value='正在核验原 UUID 的签名绑定和当前 Owner；未知结果不会创建新请求。'
  const value=await api.submitCharacterLaborRebuild(attempt.scope,attempt.input,attempt.operationId)
  if(pending.value===attempt)pending.value=null
  if(!current(token,scope))return
  receipt.value=value;preview.value=null;previewOwner.value='';options.value=null;policyKey.value=''
  message.value=value.coverage==='complete'?'已取得本次正式重建回执。当前身体状态需另行读取。':'已取得本次操作回执，但覆盖仍不完整，请查看缺失项。'
 }catch(error){if(token===generation)message.value=errorText(error)+(pending.value?' 原 UUID 和输入已保留，请用下方按钮核验。':'')}finally{busy.value=false}
}
function restoreScope(){if(pending.value&&eligible.value)props.backend.setScope(pending.value.scope)}
</script>
<template>
 <section class="labor-rebuild" aria-label="角色劳动身体重建" :aria-busy="busy">
  <h4>角色劳动身体重建</h4><p>从实际 Action、签名政策与服务器核验的 checkpoint 重建。此处读取选择元数据；身体正文只在正式 Source 授权后由后端使用。</p>
  <fieldset :disabled="locked"><legend>选择实际 Action</legend>
   <label for="labor-action-refs">实际 Action 引用（每行一个，最多16个）</label><textarea id="labor-action-refs" v-model="actionRefs" rows="3" autocomplete="off" spellcheck="false"></textarea>
   <button type="button" @click="readActions">读取当前 Action 元数据</button>
   <label for="labor-action">本次已读取的 Action</label><select id="labor-action" v-model="selectedActionRef"><option value="">请选择</option><option v-for="a in actions" :key="a.ref" :value="a.ref">{{a.action_id}} · 版本 {{a.action_revision}} · {{a.state}}</option></select>
   <p v-if="selectedAction">原 activity：{{selectedAction.activity_id}}<br>实际受众：{{selectedAction.audience_ref}}</p>
   <label for="labor-parent">原父预算引用</label><input id="labor-parent" v-model="parentBudget" autocomplete="off" spellcheck="false">
   <button type="button" :disabled="!selectedAction||!parentBudget.trim()" @click="readOptions">读取实际政策目录</button>
   <template v-if="options"><p>完整目录：{{options.policy_count}} 项 · 核验时刻（UTC）：{{new Date(options.as_of_utc*1000).toISOString()}}</p><label for="labor-policy">明确选择政策</label><select id="labor-policy" v-model="policyKey"><option value="">请选择</option><option v-for="p in options.options" :key="p.policy_ref+'|'+p.policy_revision" :value="p.policy_ref+'|'+p.policy_revision" :disabled="!p.eligible">{{p.policy_ref}} · 版本 {{p.policy_revision}} · {{p.eligible?'可选择':'当前不可用'}}</option></select><ul v-for="p in options.options.filter(p=>!p.eligible)" :key="p.policy_ref+'|'+p.policy_revision"><li v-for="reason in p.unavailable_reasons" :key="reason">{{p.policy_ref}}：{{reasonLabels[reason]||reason}}</li></ul><button type="button" :disabled="!selectedPolicy?.eligible" @click="readPreview">核验本次重建预览</button></template>
  </fieldset>
  <div v-if="preview" class="labor-preview"><h5>已核验预览</h5><p>配置：{{preview.profile_id}}<br>checkpoint：{{preview.checkpoint.ref}} · 版本 {{preview.checkpoint.revision}}<br>来源：{{preview.checkpoint.origin_kind}} · {{preview.checkpoint.producer_operation_id}}</p><button type="button" :disabled="locked" @click="submit">确认本次选择并重建</button></div>
  <div v-if="pending" class="labor-pending"><h5>原请求待确认</h5><p>范围：{{pending.scope}}<br>UUID：{{pending.operationId}}<br>归属提示：{{pending.ownerBindingDigest}}</p><p>本页内存保留原输入；换 Owner 或切换页面不会自动重发。刷新整个页面前请保留 UUID。</p><button v-if="pending.scope!==backend.state.scope" type="button" :disabled="!eligible||busy" @click="restoreScope">切回原角色范围</button><button type="button" :disabled="!eligible||busy||pending.scope!==backend.state.scope" @click="submit">以原 Owner 核验同一 UUID</button></div>
  <p v-if="message" role="status">{{message}}</p><details v-if="receipt"><summary>本次正式回执</summary><p>UUID：{{receipt.operationId}}<br>输入摘要：{{receipt.inputDigest}}<br>原件摘要：{{receipt.originalDigest}}<br>覆盖：{{receipt.coverage}}</p><ul v-if="receipt.missingInputs.length"><li v-for="missing in receipt.missingInputs" :key="missing">{{missing}}</li></ul></details>
 </section>
</template>
<style scoped>
.labor-rebuild{padding-top:18px;margin-top:20px;border-top:1px solid var(--line);font-size:12px;line-height:1.75;color:var(--ink);overflow-wrap:anywhere}.labor-rebuild h4{font-size:17px;font-weight:500;margin:0 0 8px}.labor-rebuild h5{font-size:13px;font-weight:500;margin:12px 0 8px}.labor-rebuild p{color:var(--muted)}.labor-rebuild fieldset{border:0;padding:0;margin:0}.labor-rebuild label{display:block;margin:12px 0 6px}.labor-rebuild :is(input,textarea,select){box-sizing:border-box;width:100%;min-height:44px;border:1px solid var(--line);border-radius:3px;background:var(--surface);color:var(--ink);padding:9px;font:inherit}.labor-rebuild textarea{resize:vertical}.labor-rebuild button{min-height:44px;padding:9px 13px;margin:10px 8px 0 0;border:1px solid var(--line);border-radius:3px;background:var(--button);color:var(--ink);font:inherit;cursor:pointer}.labor-rebuild :disabled{color:var(--disabled-ink);cursor:default}.labor-rebuild :is(button,input,textarea,select,summary):focus-visible{outline:2px solid var(--focus);outline-offset:3px}.labor-preview,.labor-pending{padding:12px;border:1px solid var(--line);margin:12px 0}.labor-rebuild ul{padding-left:20px}
</style>
