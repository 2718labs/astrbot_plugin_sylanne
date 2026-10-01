<script setup lang="ts">
import {ref,reactive,watch,onBeforeUnmount} from 'vue'
import {WorkbenchApi} from '../../../webui-src/src/api/client.js'
import {workflowForPage} from '../../../webui-src/src/workflows.js'
const props=defineProps<{scope:string;csrf:string;sessionEpoch:number}>()
const emit=defineEmits<{locked:[message:string]}>()
const api=new WorkbenchApi()
const form=reactive({display_name:'',blueprint:'',model_capability_ref:'',budget_ref:'',scene_ref:'',visibility:'',acknowledgement:false})
const busy=ref(false),problem=ref('')
const receipts=ref<Array<Record<string,unknown>>>([])
const candidates=ref<Array<{platform_ref:string;conversation_ref:string;visibility:string;scene_ref:string}>>([])
let epoch=0
const attempts=new Map<string,string>()
function clear(){++epoch;api.clearSession();busy.value=false;problem.value='';receipts.value=[];candidates.value=[];attempts.clear();Object.assign(form,{display_name:'',blueprint:'',model_capability_ref:'',budget_ref:'',scene_ref:'',visibility:'',acknowledgement:false})}
watch(()=>[props.scope,props.csrf,props.sessionEpoch],clear)
onBeforeUnmount(clear)
async function run(mode:'role-init'|'setup'|'candidates'){
 if(busy.value)return
 const e=epoch,scope=props.scope.trim(),csrf=props.csrf
 const current=()=>e===epoch&&props.scope.trim()===scope&&props.csrf===csrf
 problem.value='';api.csrfToken=csrf||null
 try{
  if(!csrf||!/^[^/\s]+\/[^/\s]+$/.test(scope))throw new Error('请先解锁 Owner 并填写已授权的 bot/persona 范围。')
  api.csrfToken=csrf
  if(mode==='candidates'){
   busy.value=true;const result=await api.sceneCandidates();if(current())candidates.value=result;return
  }
  const [action,input]=workflowForPage(mode,{...form})
  const fingerprint=JSON.stringify([scope,action,input]);if(!attempts.has(fingerprint))attempts.set(fingerprint,crypto.randomUUID())
  const operationId=attempts.get(fingerprint)!
  busy.value=true
  const data=await api.command(action,{scope,purpose:'workbench_user_action',audience:'owner',input,operationId})
  if(!current())return
  if(data.status==='unauthorized'){clear();emit('locked',data.problem?.message??'Owner 授权失效');return}
  if(data.status!=='ready'||data.receipt?.operation_id!==operationId)throw new Error(data.problem?.message??`操作未确认，请保留操作 ID ${operationId}。相同输入重试不会更换 ID。`)
  const expected=mode==='role-init'?'role_initialized':'scene_bound'
  if(data.receipt.phase!==expected)throw new Error(`回执阶段 ${data.receipt.phase??'unknown'}，尚不能认定${expected}完成。`)
  if(!receipts.value.some(r=>r.operation_id===operationId))receipts.value.push(data.receipt)
  form.acknowledgement=false
 }catch(error){if(current()){problem.value=error instanceof Error?error.message:'请求未确认';if(!api.hasSession){clear();emit('locked','Owner 会话失效，请重新核验。')}}}
 finally{if(current())busy.value=false}
}
function select(index:number){const item=candidates.value[index];if(item){form.scene_ref=item.scene_ref;form.visibility=item.visibility;form.acknowledgement=false}}
</script>
<template>
 <section class="role-setup"><h2>角色初始化与场景绑定</h2><p>针对当前已授权范围 {{scope||'（未填写）'}}。服务端重新核验所有选择；不会自动发送测试消息。</p><p v-if="problem" class="notice" role="alert">{{problem}}</p>
 <div class="setup-columns"><form class="panel" @submit.prevent="run('role-init')"><fieldset :disabled="busy||!csrf"><h3>1 · 初始化角色</h3><label>角色名称<input v-model="form.display_name" required maxlength="80" /></label><label>角色预设<select v-model="form.blueprint" required><option value="">明确选择预设</option><option value="d01.persona.warm-listener.v1">温和倾听者</option><option value="d01.persona.curious-maker.v1">好奇探索者</option></select></label><label>模型能力引用<input v-model="form.model_capability_ref" required placeholder="来自可信安装资料" autocomplete="off" /></label><label>预算引用<input v-model="form.budget_ref" required placeholder="来自可信安装资料" autocomplete="off" /></label><button class="accent" type="submit">明确提交角色初始化</button></fieldset></form>
 <form class="panel" @submit.prevent="run('setup')"><fieldset :disabled="busy||!csrf"><h3>2 · 绑定实际场景</h3><p>候选仅来自宿主实际观察的会话。点选不会绑定。</p><button class="quiet" type="button" @click="run('candidates')">读取近期场景候选</button><ul><li v-for="(item,index) in candidates" :key="item.scene_ref"><button type="button" class="quiet" @click="select(index)">{{item.platform_ref}} · {{item.conversation_ref}} · {{item.visibility}}</button></li></ul><label>场景引用<input v-model="form.scene_ref" required placeholder="scene:conversation-v1:…" autocomplete="off" /></label><label>可见范围<select v-model="form.visibility" required><option value="">请选择</option><option value="private">私聊</option><option value="group">群聊</option></select></label><label class="ack"><input v-model="form.acknowledgement" type="checkbox" required /><span>我确认此场景和可见范围适用于当前角色，并明确申请绑定</span></label><button class="accent" type="submit">明确提交场景绑定</button></fieldset></form></div>
 <div v-if="receipts.length" class="panel"><h3>服务端真实回执</h3><pre v-for="receipt in receipts" :key="String(receipt.operation_id)">{{JSON.stringify(receipt,null,2)}}</pre></div><p>网络失败或 HOLD 不等于提交失败；相同输入重试沿用操作 ID。刷新页面前请保存回执和操作 ID。</p>
 </section>
</template>
<style scoped>
.role-setup{margin-top:30px}.role-setup>p{font-size:12px;line-height:1.6}.setup-columns{display:grid;grid-template-columns:1fr 1fr;gap:20px}.role-setup fieldset{border:0;margin:0;padding:0;min-width:0}.role-setup label{display:grid;gap:6px;font-size:12px;margin:14px 0}.role-setup input,.role-setup select{width:100%;padding:10px;background:#faf8f2;border:1px solid #bcb5a8;color:#34312b;font:12px/1.5 var(--font-mono)}.role-setup .ack{grid-template-columns:20px 1fr;align-items:start}.role-setup input[type=checkbox]{width:17px;height:17px}.role-setup pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:300px;overflow:auto;font:11px/1.6 var(--font-mono)}.role-setup li{overflow-wrap:anywhere}.role-setup button:disabled{opacity:.5}.role-setup .panel>p,.role-setup fieldset>p{font-size:12px;line-height:1.6}@media(max-width:900px){.setup-columns{grid-template-columns:1fr}}
</style>
