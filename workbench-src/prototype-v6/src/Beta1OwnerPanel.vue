<script setup lang="ts">
import {computed,onBeforeUnmount,ref,watch,toRaw} from 'vue'
import type {BackendController} from './use-backend.ts'
import {operationIdV1} from './api/browser-crypto.ts'
import {BETA1_OPERATIONS,emptyValue,validateBeta1Input,type Beta1Domain,type Beta1Kind,type Beta1Input,type Beta1State,type Beta1Receipt,type EditorSpec,type Beta1Attempt,pendingBeta1Attempts as attempts} from './api/beta1-owner.ts'
import StructuredFields from './StructuredFields.vue'
import {pendingFrozenJointCommands,type FrozenJointCommandReceipt,type JointCommandSelectionInput} from './api/beta1-owner.ts'
const props=defineProps<{backend:BackendController;domain:Beta1Domain}>()
const titles:Record<Beta1Domain,string>={self:'能力与策略管理',world:'世界与时间截面',habit:'习惯管理',long_window:'长期计划与协作窗口'}
const options=computed(()=>Object.entries(BETA1_OPERATIONS).filter(([,item])=>item.domain===props.domain))
const kind=ref<Beta1Kind|null>(null),request=ref<unknown>(null),activity=ref(''),audience=ref(''),lease=ref('')
const refs=ref(''),state=ref<Beta1State|null>(null),receipt=ref<Beta1Receipt|null>(null),message=ref(''),readMessage=ref(''),busy=ref(false),reading=ref(false)
const selected=computed(()=>kind.value?BETA1_OPERATIONS[kind.value]:null)
const attemptKey=()=>props.backend.state.scope+'|'+props.domain
const pending=ref<Beta1Attempt|null>(attempts.get(attemptKey())??null)
const namedChoice=ref(''),namedMessage=ref(''),namedPending=ref<{scope:string;windowRef:string;nodeId:string;operationId:string}|null>(null)
const namedOptions=computed(()=>state.value?.domain==='long_window'?state.value.items.filter(item=>item.type_name==='d08.joint_window.v1'&&item.state==='preparing').flatMap(item=>(item.managed_nodes??[]).map(node=>({key:item.ref+'|'+node.node_id,windowRef:item.ref,nodeId:node.node_id,label:node.node_id+' · '+node.executor_kind+' · 版本 '+item.revision}))):[])
watch(()=>[props.backend.state.scope,props.domain],()=>{namedChoice.value='';namedMessage.value='';namedPending.value=null})
const freezePlan=ref(''),freezeJointPlan=ref(''),freezeNode=ref(''),freezeKind=ref<'draft_file'|'contact'>('draft_file'),freezeInput=ref(''),freezeRole=ref(''),freezeMessage=ref(''),frozen=ref<FrozenJointCommandReceipt|null>(null)
const freezePending=ref(pendingFrozenJointCommands.get(props.backend.state.scope)??null)
const longPlans=computed(()=>state.value?.domain==='long_window'?state.value.items.filter(item=>item.type_name==='d08.long_term_plan.v1'&&!['paused','stopped','closed'].includes(item.state)):[])
watch(()=>props.backend.state.scope,scope=>{freezePlan.value='';freezeJointPlan.value='';freezeNode.value='';freezeInput.value='';freezeRole.value='';freezeMessage.value='';frozen.value=null;freezePending.value=pendingFrozenJointCommands.get(scope)??null})
let generation=0
const eligible=computed(()=>props.backend.canRead.value&&props.backend.state.owner==='unlocked'&&props.backend.state.dashboard==='authenticated')
const canUse=computed(()=>eligible.value&&!busy.value)
const locked=computed(()=>!canUse.value||pending.value!==null)
function clear(){++generation;kind.value=null;request.value=null;activity.value='';audience.value='';lease.value='';refs.value='';state.value=null;receipt.value=null;message.value='';readMessage.value='';pending.value=attempts.get(attemptKey())??null}
watch(()=>[props.backend.state.scope,props.domain],clear)
watch(eligible,value=>{if(!value){++generation;state.value=null;receipt.value=null;request.value=null;pending.value=null;kind.value=null;message.value='';readMessage.value=''}else{pending.value=attempts.get(attemptKey())??null}})
watch(kind,value=>{request.value=value?emptyValue(BETA1_OPERATIONS[value].request as EditorSpec,props.backend.state.scope):null;receipt.value=null;message.value=''})
onBeforeUnmount(()=>{++generation;state.value=null;receipt.value=null;pending.value=null})
async function read(){
 if(!canUse.value||reading.value||props.domain==='self')return
 const actual=refs.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean)
 if(!actual.length||actual.length>16||new Set(actual).size!==actual.length){readMessage.value='请填写1至16个不重复的实际对象引用，每行一个。';return}
 const token=++generation,scope=props.backend.state.scope,domain=props.domain
 reading.value=true;state.value=null;readMessage.value='正在读取当前版本与来源核验结果…'
 try{const result=await props.backend.beta1.read(scope,domain,actual);if(token!==generation||scope!==props.backend.state.scope||!props.backend.canRead.value)return;state.value=result;readMessage.value=result.coverage==='complete'?'本次当前状态读取完成。':'本次状态未完整核验，请查看缺失输入和阻断原因。'}catch(error){if(token===generation)readMessage.value=error instanceof Error?error.message:'读取未完成；当前状态尚未核验。'}finally{reading.value=false}
}
async function freezeCommand(){
 if(!canUse.value)return
 if(!freezePending.value){
  if(!longPlans.value.some(plan=>plan.ref===freezePlan.value)){freezeMessage.value='请先独立读取并选择实际长期计划。';return}
  const input:JointCommandSelectionInput={long_plan_ref:freezePlan.value,joint_plan_ref:freezeJointPlan.value.trim(),node_id:freezeNode.value.trim(),executor_kind:freezeKind.value,input_original_ref:freezeInput.value.trim(),role_ref:freezeKind.value==='draft_file'?freezeRole.value.trim():null}
  if(!input.joint_plan_ref||!input.node_id||!input.input_original_ref||input.executor_kind==='draft_file'&&!input.role_ref){freezeMessage.value='请填写真实已接受 JointPlan、其中节点及实际输入原件；Artifact还需实际角色引用。';return}
  freezePending.value={input,operationId:operationIdV1()};pendingFrozenJointCommands.set(props.backend.state.scope,freezePending.value)
 }
 const pendingCommand=freezePending.value,scope=props.backend.state.scope,token=++generation
 busy.value=true;frozen.value=null;freezeMessage.value='正在读取实际原件和当前 Source、Owner、角色及 Root，核验后冻结命令…'
 try{if(!pendingCommand.prepared){pendingCommand.prepared=await props.backend.beta1.prepareCommand(scope,pendingCommand.input,pendingCommand.operationId);pendingFrozenJointCommands.set(scope,pendingCommand)}
  freezeMessage.value='待提交输入已固定；正在重新核验当前 Source 与 Owner 并冻结同一命令…'
  const value=await props.backend.beta1.freezeCommand(scope,pendingCommand.prepared,pendingCommand.operationId);if(token!==generation||scope!==props.backend.state.scope)return;frozen.value=value;freezePending.value=null;pendingFrozenJointCommands.delete(scope);state.value=null;freezeMessage.value='已取得真实冻结命令原件。尚未注册执行器，也未创建 Action、job 或模型调用。'}catch(error){if(token===generation)freezeMessage.value=(error instanceof Error?error.message:'冻结结果尚未确认。')+' 本次请求身份 '+pendingCommand.operationId+' 已保留。'}finally{busy.value=false}
}
async function prepareNode(){
 if(!canUse.value)return
 if(!namedPending.value){const choice=namedOptions.value.find(item=>item.key===namedChoice.value);if(!choice)return;namedPending.value={scope:props.backend.state.scope,windowRef:choice.windowRef,nodeId:choice.nodeId,operationId:operationIdV1()}}
 const pendingNode=namedPending.value,token=++generation
 busy.value=true;namedMessage.value='正在独立核验实际命令原件、当前窗口和原授权…'
 try{const result=await props.backend.beta1.prepareNode(pendingNode.scope,pendingNode.windowRef,pendingNode.nodeId,pendingNode.operationId);if(token!==generation||pendingNode.scope!==props.backend.state.scope)return;namedMessage.value='已提交实际操作 '+result.actualOperationId+'，原件摘要 '+result.originalDigest+'。当前节点状态需另行读取。';namedPending.value=null;state.value=null;namedChoice.value=''}catch(error){if(token===generation)namedMessage.value=(error instanceof Error?error.message:'结果尚未确认。')+' 已保留本次操作身份 '+pendingNode.operationId+'。'}finally{busy.value=false}
}
async function submit(retry=false){
 if(!canUse.value)return
 if(!retry){
  if(!kind.value||pending.value)return
  try{const input=validateBeta1Input(kind.value,{activity_id:activity.value.trim(),audience_ref:audience.value.trim(),parent_budget_lease_ref:lease.value.trim(),request:structuredClone(toRaw(request.value)) as Record<string,unknown>});pending.value={scope:props.backend.state.scope,kind:kind.value,input,operationId:operationIdV1()}}catch(error){message.value=error instanceof Error?error.message:'请核对实际输入。';return}
 }
 const current=pending.value
 if(!current||current.scope!==props.backend.state.scope)return
 const token=++generation
 attempts.set(attemptKey(),current)
 busy.value=true;state.value=null;receipt.value=null;message.value='正在提交本次明确操作…'
 try{const result=await props.backend.beta1.submit(current.scope,current.kind,current.input,current.operationId);if(token!==generation||current.scope!==props.backend.state.scope||!props.backend.canRead.value)return;receipt.value=result;attempts.delete(current.scope+'|'+props.domain);pending.value=null;message.value='已取得本次领域原件回执。当前运行状态尚未核验，请另行读取。'}catch(error){if(token===generation)message.value=(error instanceof Error?error.message:'结果尚未确认。')+' 当前操作身份已保留，请先核对当前状态。'}finally{busy.value=false}
}
</script>
<template>
 <section class="beta-owner" :aria-label="titles[domain]" :aria-busy="busy||reading">
  <h4>{{titles[domain]}}</h4>
  <p>使用当前已解锁 Owner 与实际角色范围 {{backend.state.scope||'尚未选择'}}。原件、来源和授权引用均需来自真实安装；本页不会生成 Root、业务身份或预算许可。</p>
  <div v-if="domain!=='self'" class="beta-state">
   <h5>当前状态</h5><p>未完成本次独立读取前，状态保持未核验。仅显示当前版本的有限元数据。</p>
   <label :for="'beta-refs-'+domain">实际对象引用（每行一个，最多16个）</label><textarea :id="'beta-refs-'+domain" v-model="refs" rows="3" :disabled="!canUse||reading" autocomplete="off" spellcheck="false"></textarea>
   <button type="button" :disabled="!canUse||reading" @click="read">{{reading?'正在核验…':'读取当前状态'}}</button>
   <p v-if="readMessage" role="status">{{readMessage}}</p><p v-if="!state">当前状态：未核验</p>
   <template v-if="state"><p>覆盖：{{state.coverage==='complete'?'完整':state.coverage==='partial'?'部分':'不可用'}}</p><ul v-if="state.missing_inputs.length"><li v-for="item in state.missing_inputs" :key="item">缺失：{{item}}</li></ul><article v-for="item in state.items" :key="item.ref" class="beta-state-item"><h5>{{item.type_name}} · 版本 {{item.revision}}</h5><p>{{item.ref}}</p><p>当前状态：{{item.state}}</p><ul><li v-for="reason in item.reason_codes" :key="reason">{{reason}}</li></ul><details><summary>来源与关联依据</summary><ul><li v-for="source in item.source_refs" :key="source">来源：{{source}}</li><li v-for="related in item.related_refs" :key="related">关联：{{related}}</li></ul></details></article></template>
  </div>
  <div v-if="domain==='long_window'" class="beta-state">
   <h5>冻结实际 prospective 命令</h5><p>在采用 Window 草案前，为 Artifact/Contact 选择真实业务原件。完整 Root、grant、phase 和执行身份均由服务器从已安装协议及真实原件读取；本表不填写这些授权字段。SourceNote 沿已有 Decision/Consume 原件链，无需此步骤。</p>
   <label for="freeze-long-plan">本次已核验长期计划</label><select id="freeze-long-plan" v-model="freezePlan" :disabled="!canUse||!!freezePending"><option value="">请先读取实际长期计划</option><option v-for="plan in longPlans" :key="plan.ref" :value="plan.ref">{{plan.ref}} · 版本 {{plan.revision}}</option></select>
   <label for="freeze-joint-plan">真实已接受 JointPlan 引用</label><input id="freeze-joint-plan" v-model="freezeJointPlan" :disabled="!canUse||!!freezePending" autocomplete="off">
   <label for="freeze-node">该 JointPlan 中的实际节点</label><input id="freeze-node" v-model="freezeNode" :disabled="!canUse||!!freezePending" autocomplete="off">
   <label for="freeze-kind">原执行器</label><select id="freeze-kind" v-model="freezeKind" :disabled="!canUse||!!freezePending"><option value="draft_file">Artifact 原前瞻输入</option><option value="contact">Contact 原前瞻 birth</option></select>
   <label for="freeze-input">{{freezeKind==='draft_file'?'实际 ArtifactTaskScope 原件引用':'实际 Contact prospective 原件引用'}}</label><input id="freeze-input" v-model="freezeInput" :disabled="!canUse||!!freezePending" autocomplete="off">
   <template v-if="freezeKind==='draft_file'"><label for="freeze-role">当前实际角色引用</label><input id="freeze-role" v-model="freezeRole" :disabled="!canUse||!!freezePending" autocomplete="off"></template>
   <button type="button" :disabled="!canUse||(!freezePlan&&!freezePending)" @click="freezeCommand">{{freezePending?'按原请求身份核对冻结':'核验并冻结所选命令'}}</button><p v-if="freezeMessage" role="status">{{freezeMessage}}</p>
   <details v-if="frozen"><summary>真实冻结原件与 Window 节点承诺</summary><dl><dt>原件</dt><dd>{{frozen.commandOriginalRef}}</dd><dt>原件摘要</dt><dd>{{frozen.commandOriginalDigest}}</dd><dt>实际冻结操作</dt><dd>{{frozen.actualOperationId}}</dd><dt>节点</dt><dd>{{frozen.nodeId}}</dd><dt>typed_request_ref（保留原输入引用）</dt><dd>{{frozen.typedInputOriginalRef}}</dd><dt>typed_input_original_digest</dt><dd>{{frozen.typedInputOriginalDigest}}</dd><dt>typed_request_digest</dt><dd>{{frozen.typedRequestDigest}}</dd></dl><p>将这些真实承诺用于本次明确采用的 Window 草案。冻结回执不表示窗口已就绪；采用后请独立读取当前状态。</p></details>
   <h5>准备实际窗口节点</h5><p>先独立读取当前 Window。选择已采用节点后，服务器读取其冻结命令并重新核验原 Root、Owner、Source 和期限；不会创建新执行身份或自动唤醒任务。</p>
   <label for="named-window-node">当前可选择节点</label><select id="named-window-node" v-model="namedChoice" :disabled="!canUse||!!namedPending"><option value="">请先读取并选择实际节点</option><option v-for="item in namedOptions" :key="item.key" :value="item.key">{{item.label}}</option></select>
   <button type="button" :disabled="!canUse||(!namedChoice&&!namedPending)" @click="prepareNode">{{namedPending?'按原操作身份核对提交':'核验并准备所选节点'}}</button><p v-if="namedMessage" role="status">{{namedMessage}}</p>
  </div>
  <h5>明确管理操作</h5><label :for="'beta-kind-'+domain">选择操作</label><select :id="'beta-kind-'+domain" v-model="kind" :disabled="locked"><option :value="null">请选择</option><option v-for="[key,item] in options" :key="key" :value="key">{{item.label}}</option></select>
  <template v-if="selected">
   <p>本次用途：{{selected.purpose}}。管理命令仍须通过当前域、Source、Owner、预算和期限校验。</p>
   <label :for="'beta-activity-'+domain">原 activity</label><input :id="'beta-activity-'+domain" v-model="activity" :disabled="locked" autocomplete="off">
   <label :for="'beta-audience-'+domain">实际受众引用</label><input :id="'beta-audience-'+domain" v-model="audience" :disabled="locked" autocomplete="off">
   <label :for="'beta-lease-'+domain">原父预算引用</label><input :id="'beta-lease-'+domain" v-model="lease" :disabled="locked" autocomplete="off">
   <StructuredFields :spec="selected.request as EditorSpec" v-model="request" :path="'beta-request-'+domain" :scope="backend.state.scope" :disabled="locked"/>
   <p>填写完整原件与预期版本后，点击下方按钮提交本次选择。长期计划只描述目标；进入窗口、正式条款与各方接受分别核验。习惯沿原 Root 与期限执行，错过不自动补跑。</p>
   <button type="button" :disabled="locked" @click="submit()">{{selected.label}}</button>
  </template>
  <p v-if="message" role="status">{{message}}</p>
  <p v-if="pending">待确认操作：{{pending.operationId}}。离开页面前请保留该身份；页面切换不会自动重放。</p>
  <button v-if="pending" type="button" :disabled="!canUse" @click="submit(true)">使用原操作身份重新核对提交</button>
  <details v-if="receipt"><summary>本次写入回执（当前状态需独立核验）</summary><p>操作 {{receipt.operationId}}</p><p>输入摘要 {{receipt.inputDigest}}</p><p>领域原件摘要 {{receipt.originalDigest}}</p></details>
 </section>
</template>
<style scoped>
.beta-owner{padding-top:18px;margin-top:20px;border-top:1px solid var(--line);font-size:12px;line-height:1.75;color:var(--ink);overflow-wrap:anywhere}.beta-owner h4{font-size:17px;font-weight:500;margin:0 0 8px}.beta-owner h5{font-size:13px;font-weight:500;margin:16px 0 8px}.beta-owner p{color:var(--muted);margin:8px 0}.beta-owner>label,.beta-state>label{display:block;margin:12px 0 6px}.beta-owner :is(input,select,textarea){box-sizing:border-box;width:100%;min-height:44px;border:1px solid var(--line);border-radius:3px;background:var(--surface);color:var(--ink);padding:9px;font:inherit}.beta-owner textarea{resize:vertical}.beta-owner button{min-height:44px;padding:9px 13px;margin:10px 8px 0 0;border:1px solid var(--line);border-radius:3px;background:var(--button);color:var(--ink);font:inherit;cursor:pointer}.beta-owner :disabled{color:var(--disabled-ink);cursor:default}.beta-owner :is(button,input,select,textarea,summary):focus-visible{outline:2px solid var(--focus);outline-offset:3px}.beta-state{padding-bottom:16px;border-bottom:1px solid var(--line)}.beta-state-item{padding:12px;border:1px solid var(--line);border-radius:3px;margin:10px 0}.beta-owner summary{cursor:pointer;min-height:36px}.beta-owner ul{padding-left:20px}
</style>
