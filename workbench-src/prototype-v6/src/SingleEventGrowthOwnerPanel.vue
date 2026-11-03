<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { operationIdV1 } from './api/browser-crypto.ts'
import type { BackendController } from './use-backend.ts'
import { SINGLE_EVENT_KINDS, SINGLE_EVENT_REQUEST_FIELDS, SINGLE_EVENT_TERMS_FIELDS,
  isSingleEventKind, validateSingleEventGrowthInput, type SingleEventKind } from './api/single-event-growth.ts'
const props=defineProps<{backend:BackendController}>()
const labels:Record<SingleEventKind,string>={
 register_single_event_growth_policy_v1:'登记一次性单事件 Policy',prepare_single_event_growth_v1:'核验并冻结实际输入',
 adopt_single_event_growth_v1:'Owner 明确采用此输入',review_single_event_growth_v1:'提交本次真实后续复核',
 read_single_event_growth_v1:'独立重读当前采用与复核状态',
}
const kind=ref(''),requestText=ref(''),activity=ref(''),audience=ref(''),parent=ref('')
const busy=ref(false),message=ref('')
const attempt=computed(()=>props.backend.singleEventGrowth.pending.value)
const view=computed(()=>props.backend.singleEventGrowth.view.value)
const locked=computed(()=>busy.value||attempt.value!==null)
const fields=computed(()=>isSingleEventKind(kind.value)?SINGLE_EVENT_REQUEST_FIELDS[kind.value]:[])
const canSubmit=computed(()=>props.backend.canRead.value&&!locked.value&&isSingleEventKind(kind.value))
watch(()=>[props.backend.state.scope,props.backend.state.auth,props.backend.state.owner],()=>{
 kind.value='';requestText.value='';activity.value='';audience.value='';parent.value='';message.value=''
},{flush:'sync'})
function selectCurrent(read:boolean){
 const v=view.value
 if(!v||!v.adoption_ref||!v.review_revision||locked.value)return
 kind.value=read?'read_single_event_growth_v1':'review_single_event_growth_v1'
 requestText.value=JSON.stringify(read?{adoption_ref:v.adoption_ref}:{adoption_ref:v.adoption_ref,
  expected_review_revision:v.review_revision,continuity_interpretation_ref:null},null,2)
 message.value=read?'请核对当前 activity、受众与原父预算后，提交独立读取。':'已带入独立重读取得的精确 review 版本；请填写实际 post-adoption continuity 原件。'
}
function selectInput(){
 if(!view.value?.input_ref||locked.value)return
 kind.value='adopt_single_event_growth_v1';requestText.value=JSON.stringify({input_ref:view.value.input_ref},null,2)
}
async function submit(recover=false){
 if(busy.value)return
 let current=attempt.value
 if(!recover){
  if(!canSubmit.value||!isSingleEventKind(kind.value))return
  try{
   const input=validateSingleEventGrowthInput(kind.value,{activity_id:activity.value.trim(),audience_ref:audience.value.trim(),
    parent_budget_lease_ref:parent.value.trim(),request:JSON.parse(requestText.value)})
   current={scope:props.backend.state.scope,kind:kind.value,operationId:operationIdV1(),input}
  }catch(error){message.value=error instanceof Error?error.message:'请核对完整具名输入。';return}
 }
 if(!current||current.scope!==props.backend.state.scope||!props.backend.canRead.value)return
 busy.value=true;message.value='正在核验当前 Owner、Source、原件与固定窗口…'
 try{
  const receipt=await props.backend.singleEventGrowth.submit(current)
  if(current.scope!==props.backend.state.scope)return
  message.value=receipt.view?'已返回该 UUID 的实际领域回执。采用后请独立重读；qualified 也受原 expiry 和当前 Source/反证约束。'
   :'该操作已返回实际领域回执，但尚无完整单事件状态；请核对实际 missing_inputs 与当前原件。'
 }catch(error){if(current.scope===props.backend.state.scope)message.value=(error instanceof Error?error.message:'结果未确认。')+' 原 UUID 与输入已保留；不会自动重发。'}
 finally{busy.value=false}
}
function utc(value:number|null){return value===null?'未返回':String(value)+' UTC 秒'}
</script>
<template>
 <section class="single-event-growth" aria-label="Owner 单事件成长" :aria-busy="busy">
  <h4>单事件成长与限期复核</h4>
  <p>仅用于 Owner 明确批准的一次真实事件、一个当前人格块与有限适用范围。既有试验、完整反证、独立 Source 授权及 continuity 仍逐项核验。</p>
  <template v-if="view">
   <p>以下为该 UUID 回执中的读取时状态；本页不订阅后台变化，每次提交仍由服务端独立核验当前性。</p>
   <dl><dt>实际 Policy</dt><dd>{{view.policy_ref}} · {{view.policy_digest}}</dd>
    <dt>实际输入</dt><dd>{{view.input_ref??'尚未冻结'}}</dd><dt>采用原件</dt><dd>{{view.adoption_ref??'尚未采用'}}</dd>
    <dt>复核状态</dt><dd>{{view.disposition??'尚未形成复核义务'}} · revision {{view.review_revision??'—'}}</dd>
    <dt>复核最早时间</dt><dd>{{utc(view.review_not_before_utc)}}</dd><dt>复核截止</dt><dd>{{utc(view.review_due_utc)}}</dd>
    <dt>固定读出截止</dt><dd>{{utc(view.readout_valid_until_utc)}}</dd>
   </dl>
   <p v-if="view.missing_conditions.length">仍缺：{{view.missing_conditions.join('；')}}</p>
   <button v-if="view.input_ref&&!view.adoption_ref" :disabled="locked" @click="selectInput">使用这份已登记输入填写采用请求</button>
   <button v-if="view.adoption_ref" :disabled="locked" @click="selectCurrent(true)">填写独立重读请求</button>
   <button v-if="view.operation_kind==='read_single_event_growth_v1'&&view.adoption_ref" :disabled="locked" @click="selectCurrent(false)">使用本次重读的版本填写复核请求</button>
  </template>
  <label for="single-event-kind">本次明确操作</label><select id="single-event-kind" v-model="kind" :disabled="locked">
   <option value="">请选择</option><option v-for="item in SINGLE_EVENT_KINDS" :key="item" :value="item">{{labels[item]}}</option>
  </select>
  <template v-if="isSingleEventKind(kind)">
   <label for="single-event-activity">实际 activity</label><input id="single-event-activity" v-model="activity" :disabled="locked" autocomplete="off">
   <label for="single-event-audience">实际受众引用</label><input id="single-event-audience" v-model="audience" :disabled="locked" autocomplete="off">
   <label for="single-event-parent">原 parent budget lease</label><input id="single-event-parent" v-model="parent" :disabled="locked" autocomplete="off">
   <p>请求固定字段：{{fields.join('、')}}。版本与摘要须来自当前实际原件；不填写 Owner 身份、资格判断或试验完成标记。</p>
   <details v-if="kind==='register_single_event_growth_policy_v1'"><summary>Policy terms 的固定字段</summary><p>{{SINGLE_EVENT_TERMS_FIELDS.join('、')}}</p><p>时间均为有限 UTC 秒；GraphVersion 使用真实 key/revision。semantic_identity 仍需已安装 V3 plasticity/observer Policy；value/trait 仍需真实 General FULL 试验。</p></details>
   <label for="single-event-request">完整具名请求 JSON</label><textarea id="single-event-request" v-model="requestText" :disabled="locked" rows="12" autocomplete="off" spellcheck="false"></textarea>
   <button :disabled="!canSubmit" @click="submit()">{{labels[kind]}}</button>
  </template>
  <p v-if="attempt">待确认：{{labels[attempt.kind]}} · {{attempt.operationId}}</p>
  <button v-if="attempt" :disabled="busy||!backend.canRead.value" @click="submit(true)">以原 UUID 和原输入核验／恢复结果</button>
  <p v-if="message" role="status">{{message}}</p>
 </section>
</template>
<style scoped>
.single-event-growth{margin-top:24px;padding-top:16px;border-top:1px solid var(--line)}
.single-event-growth p,.single-event-growth dd{font-size:12px;line-height:1.7;overflow-wrap:anywhere;color:var(--muted)}
.single-event-growth label{display:block;margin:12px 0 6px}.single-event-growth dd{margin:0 0 10px}
.single-event-growth :is(input,select,textarea){box-sizing:border-box;width:100%;padding:9px;min-height:42px;border:1px solid var(--line);border-radius:3px;font:inherit;color:var(--ink);background:var(--surface)}
.single-event-growth button{min-height:44px;margin:6px 8px 6px 0;padding:9px 13px;font:inherit;color:var(--ink);background:var(--button);border:1px solid var(--line);border-radius:3px;cursor:pointer}
.single-event-growth button:disabled{background:var(--disabled-bg);color:var(--disabled-ink);cursor:default}
.single-event-growth :is(button,input,select,textarea):focus-visible{outline:2px solid var(--focus);outline-offset:3px}
</style>
