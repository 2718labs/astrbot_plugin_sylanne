<script setup lang="ts">
import {computed,onBeforeUnmount,ref,watch} from 'vue'
import {operationIdV1} from './api/browser-crypto.ts'
import type {BackendController} from './use-backend.ts'
import {validateCommitmentCommandInput,type CommitmentCommandAttempt,type CommitmentCommandResult} from './api/commitment-communication.ts'
const props=defineProps<{backend:BackendController}>()
const activity=ref(''),budget=ref(''),source=ref(''),route=ref(''),c02=ref('')
const commitmentId=ref(''),counterparty=ref(''),terms=ref(''),establishment=ref<'unilateral'|'bilateral'>('unilateral')
const selectedRef=ref(''),selectedRevision=ref<number|''>(''),literal=ref(''),until=ref(''),acknowledged=ref(false)
const busy=ref(false),message=ref(''),lastDispatch=ref<{operation_id:string;job_ref:string;outbox_ref:string}|null>(null)
const pending=computed(()=>props.backend.commitments.pending.value)
const approval=computed(()=>props.backend.commitments.approval.value)
const eligible=computed(()=>props.backend.canRead.value&&!busy.value)
const canCreate=computed(()=>eligible.value&&!pending.value&&!!activity.value&&!!budget.value&&!!source.value&&!!route.value&&!!commitmentId.value&&!!counterparty.value&&!!terms.value)
const canApprove=computed(()=>eligible.value&&!pending.value&&!!activity.value&&!!budget.value&&!!source.value&&!!route.value&&!!selectedRef.value&&typeof selectedRevision.value==='number'&&Number.isSafeInteger(selectedRevision.value)&&selectedRevision.value>=1&&literal.value.length>0&&literal.value.length<=2048&&!!until.value)
const canSubmit=computed(()=>eligible.value&&!pending.value&&!!approval.value&&!!c02.value&&acknowledged.value)
let generation=0
function clear(){++generation;activity.value=budget.value=source.value=route.value=c02.value='';commitmentId.value=counterparty.value=terms.value='';selectedRef.value=literal.value=until.value='';selectedRevision.value='';acknowledged.value=false;message.value='';lastDispatch.value=null}
watch(()=>[props.backend.state.scope,props.backend.state.auth],clear,{flush:'sync'})
watch(approval,()=>{acknowledged.value=false;lastDispatch.value=null})
onBeforeUnmount(()=>{++generation})
function applyResult(result:CommitmentCommandResult){
 if(result.kind==='create'){
  selectedRef.value=result.commitment.ref;selectedRevision.value=result.commitment.revision;source.value=result.commitment.source_ref
  props.backend.commitments.approval.value=null
  message.value='私人承诺已登记。请明确选择批准文本与期限，再登记独立沟通授权。'
 }else if(result.kind==='approve'){
  props.backend.commitments.approval.value=result.approval
  acknowledged.value=false
  message.value=result.approval?'沟通授权原件已保存。请核对下方具体对象、实际路由与完整文本，再明确提交。':`授权已登记，原件引用：${result.metadata?.scope_ref}，版本：${result.metadata?.revision}。本次仅取得已提交元数据；原请求保留，尚未取得当前完整授权摘要。`
 }else{
  lastDispatch.value=result
  message.value='实际发送准备已提交，已取得任务与发件箱原件。发送、送达和对方确认仍由正常 Host gates 与真实回执决定。'
 }
}
async function run(attempt:CommitmentCommandAttempt,replay=false){
 if(!eligible.value||attempt.scope!==props.backend.state.scope||(!replay&&pending.value))return
 try{validateCommitmentCommandInput(attempt.kind,attempt.scope,attempt.input)}catch{message.value='请核对实际原件引用、版本、会话 audience 和完整请求字段；尚未提交。';return}
 const token=generation,scope=attempt.scope
 if(!replay)props.backend.commitments.pending.value=attempt
 busy.value=true;message.value=replay?'正在核验或补交同一操作ID与精确输入。':'正在提交当前明确选择。'
 try{
  const result=await props.backend.commitments.run(attempt)
  if(!(result.kind==='approve'&&result.approval===null)&&props.backend.commitments.pending.value?.operationId===attempt.operationId)props.backend.commitments.pending.value=null
  if(token!==generation||scope!==props.backend.state.scope||!props.backend.canRead.value)return
  applyResult(result)
 }catch{
  if(token===generation)message.value='结果尚未确认，可能已保存或进入发送准备。原操作ID与精确输入已保留；请显式核验同一请求，勿新建替代提交。'
 }finally{busy.value=false}
}
function create(){if(canCreate.value)void run({scope:props.backend.state.scope,kind:'create',operationId:operationIdV1(),input:{activity_id:activity.value,audience_ref:route.value,parent_budget_lease_ref:budget.value,request:{commitment_id:commitmentId.value,counterparty_ref:counterparty.value,semantic_scope:terms.value,establishment_kind:establishment.value,source_refs:[source.value],deadline_ref:null}}})}
function approve(){
 if(!canApprove.value||typeof selectedRevision.value!=='number')return
 const expiry=Date.parse(until.value)/1000
 if(!Number.isFinite(expiry)||expiry<=Date.now()/1000){message.value='请选择尚未到期的明确授权期限。后端仍会核验实际工作期限。';return}
 void run({scope:props.backend.state.scope,kind:'approve',operationId:operationIdV1(),input:{activity_id:activity.value,audience_ref:route.value,parent_budget_lease_ref:budget.value,request:{commitment:{ref:selectedRef.value,version:selectedRevision.value},source_ref:source.value,approved_literal:literal.value,valid_until_utc:expiry}}})
}
function submit(){
 if(!canSubmit.value||!approval.value)return
 const a=approval.value
 if(a.valid_until_utc<=Date.now()/1000){message.value='该批准原件已到期。请明确登记新的授权，不能延长原请求期限。';return}
 void run({scope:props.backend.state.scope,kind:'submit',operationId:operationIdV1(),input:{scope_ref:a.scope_ref,c02_operation_id:c02.value,source_ref:a.source_ref,deadline_utc:a.valid_until_utc}})
}
const expiry=(value:number)=>new Date(value*1000).toISOString()
</script>
<template>
 <section class="commitment-controls" aria-labelledby="commitment-title" :aria-busy="busy">
  <h4 id="commitment-title">旧式自由表述承诺与文本沟通</h4>
  <p>此入口保留自由表述私人意向，不提供结构化条款履约结算。先登记私人承诺，再为实际对象与当前入站来源批准完整文本。最后一次明确提交会进入正常发送准备，并可能由 Host 发送该文本。</p>
  <p v-if="!backend.canRead.value" role="status">请先核验当前所有者会话和角色范围。</p>
  <details><summary>实际工作与来源定位</summary>
   <label>当前活动引用<input v-model="activity" :disabled="busy||!!pending" autocomplete="off"></label>
   <label>现有获准父预算引用<input v-model="budget" :disabled="busy||!!pending" autocomplete="off"></label>
   <label>该对象的实际入站 Source 引用<textarea v-model="source" :disabled="busy||!!pending" rows="2" spellcheck="false"></textarea></label>
   <label>实际入站会话 audience 引用<input v-model="route" :disabled="busy||!!pending" autocomplete="off"></label>
   <p>使用当前真实原件中的引用。授权期限必须处于既有工作期限内，预算和 Source 资格仍由后端独立核验。</p>
  </details>
  <details><summary>1 · 创建私人承诺</summary>
   <label>承诺标识（commitment: 开头）<input v-model="commitmentId" :disabled="busy||!!pending" autocomplete="off"></label>
   <label>具体对象引用（entity: 开头）<input v-model="counterparty" :disabled="busy||!!pending" autocomplete="off"></label>
   <label>承诺事项<textarea v-model="terms" :disabled="busy||!!pending" rows="3"></textarea></label>
   <label>承诺形式<select v-model="establishment" :disabled="busy||!!pending"><option value="unilateral">单方承诺</option><option value="bilateral">双方约定意向</option></select></label>
   <button :disabled="!canCreate" @click="create">登记私人承诺</button>
  </details>
  <details open><summary>2 · 登记具体沟通授权</summary>
   <label>实际承诺引用<textarea v-model="selectedRef" :disabled="busy||!!pending" rows="2" spellcheck="false"></textarea></label>
   <label>该承诺的当前图版本<input v-model.number="selectedRevision" type="number" min="1" step="1" :disabled="busy||!!pending"></label>
   <label>批准发送的完整文本<textarea v-model="literal" maxlength="2048" rows="5" :disabled="busy||!!pending"></textarea></label>
   <label>本次授权到期时间（本地时间）<input v-model="until" type="datetime-local" step="1" :disabled="busy||!!pending"></label>
   <button :disabled="!canApprove" @click="approve">保存这段文本的独立沟通授权</button>
  </details>
  <div v-if="approval" class="approved">
   <h5>3 · 核对已批准原件并明确提交</h5>
   <dl><div><dt>具体对象</dt><dd>{{approval.target_ref}}</dd></div><div><dt>平台</dt><dd>{{approval.platform_ref}}</dd></div><div><dt>实际会话路由</dt><dd>{{approval.conversation_ref}}</dd></div><div><dt>场景</dt><dd>{{approval.scene_ref}}</dd></div><div><dt>承诺</dt><dd>{{approval.commitment_ref}} · 版本 {{approval.commitment_revision}}</dd></div><div><dt>有效至</dt><dd>{{expiry(approval.valid_until_utc)}}</dd></div><div><dt>授权原件</dt><dd>{{approval.scope_ref}}</dd></div></dl>
   <p class="literal">{{approval.approved_literal}}</p>
   <label>同一入站来源的实际 C02 操作ID<input v-model="c02" :disabled="busy||!!pending" autocomplete="off"></label>
   <label class="acknowledgement"><input v-model="acknowledged" type="checkbox" :disabled="busy||!!pending">我已核对上述具体对象、实际路由和完整文本，明确提交该 Scope 下的沟通。</label>
   <button :disabled="!canSubmit" @click="submit">提交上述批准文本，进入正式发送准备</button>
  </div>
  <div v-if="pending" role="status"><p>原操作ID：{{pending.operationId}}。阶段：{{pending.kind==='create'?'创建私人承诺':pending.kind==='approve'?'登记沟通授权':'提交批准文本'}}。</p><button :disabled="!eligible" @click="run(pending,true)">核验或补交原请求（保持操作ID、Scope 和输入）</button></div>
  <dl v-if="lastDispatch"><div><dt>实际发送准备操作</dt><dd>{{lastDispatch.operation_id}}</dd></div><div><dt>任务</dt><dd>{{lastDispatch.job_ref}}</dd></div><div><dt>发件箱</dt><dd>{{lastDispatch.outbox_ref}}</dd></div></dl>
  <p v-if="message" role="status" aria-live="polite">{{message}}</p>
 </section>
</template>
<style scoped>
.commitment-controls{font-size:12px;line-height:1.8;overflow-wrap:anywhere}.commitment-controls h4{font-size:16px;font-weight:500;margin:0 0 14px}.commitment-controls p{color:var(--muted)}details,.approved{border-top:1px solid var(--line);padding:12px 0}summary{cursor:pointer;min-height:32px}label{display:grid;gap:7px;margin:12px 0}input,textarea,select{box-sizing:border-box;width:100%;min-height:42px;font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--line);padding:9px}textarea{resize:vertical}.acknowledgement{display:flex;align-items:start;gap:10px}.acknowledgement input{width:18px;min-height:18px;margin-top:3px}.literal{white-space:pre-wrap;padding:12px;border:1px solid var(--line)}dl{margin:12px 0}dl>div{display:grid;grid-template-columns:100px 1fr;gap:12px;padding:7px 0;border-bottom:1px solid var(--line)}dd{margin:0}dt{color:var(--muted)}button{font:inherit;min-height:44px;width:100%;padding:10px 0;text-align:left;cursor:pointer}button:disabled{color:var(--muted);cursor:default}button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:2px solid var(--ink);outline-offset:3px}
</style>
