<script setup lang="ts">
import {operationIdV1} from './api/browser-crypto.ts'
import { computed, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import { pendingProjectContextAttempts as pending, type ProjectContextOptions, type ProjectContextAttempt } from './api/project-context.ts'
const props=defineProps<{backend:BackendController}>()
const options=ref<ProjectContextOptions|null>(null),target=ref(''),role=ref(''),norms=ref<string[]>([])
const busy=ref(false),message=ref(''),uncertain=ref(false)
const selected=computed(()=>options.value?.items.find(item=>item.project_ref===target.value)??null)
const attempt=ref<ProjectContextAttempt|null>(pending.get(props.backend.state.scope)??null)
uncertain.value=attempt.value!==null
const canRead=computed(()=>props.backend.canRead.value&&!busy.value)
const canSave=computed(()=>canRead.value&&selected.value!==null&&role.value!==''&&!uncertain.value)
function choose(){role.value=selected.value?.social_role??'';norms.value=[...(selected.value?.norm_refs??[])]}
watch(target,choose)
watch(()=>props.backend.state.scope,scope=>{options.value=null;target.value='';role.value='';norms.value=[];message.value='';attempt.value=pending.get(scope)??null;uncertain.value=attempt.value!==null})
async function read(){
 if(!canRead.value)return
 const scope=props.backend.state.scope;busy.value=true;message.value='正在读取已采用目录与当前项目…'
 try{const current=await props.backend.projectContext.read(scope);if(scope!==props.backend.state.scope)return;options.value=current
  if(!current.items.some(item=>item.project_ref===target.value))target.value=''
  choose();message.value=current.items.length?'请选择实际项目、角色和适用规范。':'当前没有可配置的获准草稿项目。'
 }catch(error){options.value=null;message.value=error instanceof Error?error.message:'项目读取失败。'}finally{busy.value=false}
}
async function save(retry=false){
 if(busy.value)return
 if(!retry){if(!canSave.value||!options.value||!selected.value)return;attempt.value={scope:props.backend.state.scope,
  options:options.value,item:selected.value,role:role.value,norms:[...norms.value],id:operationIdV1()}}
 const current=attempt.value;if(!current||current.scope!==props.backend.state.scope)return
 pending.set(current.scope,current)
 busy.value=true;message.value='正在提交当前 Owner 的明确项目选择…'
 try{await props.backend.projectContext.adopt(current.scope,current.options,current.item,current.role,current.norms,current.id)
  pending.delete(current.scope);uncertain.value=false;message.value='已返回该操作原件。请读取当前绑定核对采用结果。'
 }catch(error){uncertain.value=true;message.value=(error instanceof Error?error.message:'结果未确认。')+' 保留原操作身份，请先读取当前绑定。'}finally{busy.value=false}
}
</script>
<template>
 <section class="owner-project-context" aria-label="项目角色与规范" :aria-busy="busy">
  <h4>项目角色与规范</h4><p>从当前已采用目录作出明确选择。项目仍沿原授权、预算与工具范围执行。</p>
  <button class="configuration-action" :disabled="!canRead" @click="read">读取项目与目录</button>
  <p v-if="message" role="status">{{message}}</p>
  <template v-if="options">
   <div class="configuration-field"><label for="owner-context-project">当前项目</label><select id="owner-context-project" v-model="target" :disabled="busy||uncertain"><option value="">请选择项目</option><option v-for="(item,index) in options.items" :key="item.project_ref" :value="item.project_ref">项目 {{index+1}} · {{item.project_ref}}</option></select></div>
   <template v-if="selected">
    <p>{{selected.binding_ref?'已有当前绑定，请核对后保存明确修订。':'该项目尚未采用角色选择。'}}</p>
    <div class="configuration-field"><label for="owner-context-role">角色</label><select id="owner-context-role" v-model="role" :disabled="busy||uncertain"><option value="">请选择目录角色</option><option v-for="item in options.catalogue.roles" :key="item" :value="item">{{item}}</option></select></div>
    <fieldset :disabled="busy||uncertain"><legend>适用规范</legend><label v-for="item in options.catalogue.norms" :key="item"><input v-model="norms" type="checkbox" :value="item">{{item}}</label></fieldset>
    <button class="configuration-action" :disabled="!canSave" @click="save()">采用明确选择</button>
   </template>
  </template>
  <button v-if="uncertain&&attempt?.scope===backend.state.scope" class="configuration-action" :disabled="busy" @click="save(true)">使用原操作身份重试</button>
 </section>
</template>
<style scoped>
.owner-project-context{margin-top:24px;border-top:1px solid var(--line);padding-top:16px}
fieldset{border:1px solid var(--line);margin:12px 0;padding:12px}fieldset label{display:flex;align-items:center;gap:8px;margin:8px 0}
</style>
