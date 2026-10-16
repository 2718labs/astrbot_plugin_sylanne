<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { SelfViewProjection } from './api/conditioned-self.ts'
const props=defineProps<{backend:BackendController}>()
const data=ref<SelfViewProjection|null>(null),busy=ref(false),message=ref('')
let generation=0
const canRead=computed(()=>props.backend.canRead.value&&!busy.value)
const labels:Record<string,string>={sample_threshold_met:'样本达到政策门槛',qualified:'已核验策略',limited:'适用范围有限',unknown:'仍有未知',stale:'需要复核',
 candidate:'待明确采用',narrowed:'已收窄适用范围',rolled_back:'已回退'}
const tasks:Record<string,string>={artifact_draft:'作品起草',source_note:'来源笔记',life_activity:'Life 活动'}
const methods:Record<string,string>={'CP-tone-order:full-draft-then-check':'完整起草后检查',
 'CP-tone-order:tone-sample-then-full-draft':'先确认语气样本，再完整起草'}
const utc=(value:number)=>new Date(value*1000).toLocaleString('zh-CN',{hour12:false,timeZone:'UTC'})+' UTC'
function invalidate(){++generation;data.value=null;message.value=''}
watch(()=>props.backend.state.scope,invalidate)
watch(()=>props.backend.canRead.value,value=>{if(!value)invalidate()})
onBeforeUnmount(invalidate)
async function read(){
 if(!canRead.value)return
 const token=++generation,scope=props.backend.state.scope
 data.value=null;busy.value=true;message.value='正在核对当前角色与实际能力证据…'
 try{
  const current=await props.backend.selfView.read(scope)
  if(token!==generation||scope!==props.backend.state.scope||!props.backend.canRead.value)return
  data.value=current;message.value='已读取本次角色状态。未知结果保留为未知；策略采用仍需所有者明确操作。'
 }catch(error){
  if(token===generation)message.value=error instanceof Error?error.message:'本次读取未完成，请重新核对会话。'
 }finally{busy.value=false}
}
</script>
<template>
 <section class="self-view" aria-label="当前角色的能力与策略" :aria-busy="busy">
  <div class="self-heading"><div><h4>能力与策略</h4><p>查看哪些能力已有实际结果支持、在哪些条件下适用，以及仍待确认的限制。</p></div>
   <button type="button" :disabled="!canRead" @click="read">{{busy?'正在读取…':'读取当前状态'}}</button>
  </div>
  <p v-if="message" class="self-status" role="status">{{message}}</p>
  <template v-if="data">
   <p class="self-version">当前人格版本 {{data.personaRevision}} · {{data.capabilities.length}} 项能力 · {{data.strategies.length}} 项策略</p>
   <h5>有条件的能力</h5>
   <p v-if="!data.capabilities.length">本次有效读取没有返回已登记的条件能力。</p>
   <article v-for="item in data.capabilities" :key="item.ref" class="self-card">
    <div class="self-heading"><strong>{{tasks[item.taskClass]}}</strong><span>{{labels[item.qualification]}}</span></div>
    <dl class="self-counts"><div><dt>结果符合预期</dt><dd>{{item.matched}}</dd></div><div><dt>实际反例</dt><dd>{{item.counterexamples}}</dd></div><div><dt>结果未知</dt><dd>{{item.unknown}}</dd></div></dl>
    <p>独立观测单位 {{item.observationUnits}} · 当前政策最低实际结果 {{item.minimumVerified}} · 已有结果覆盖 {{(item.coverage*100).toFixed(1)}}%</p>
    <p>本次校准：{{item.configuredSampleThresholdMet?'达到配置的样本门槛':'尚未达到配置的样本门槛'}}。样本门槛不表示能力已被全面验证。</p>
    <p>已采用版本的复核状态：{{labels[item.qualification]}} · 有效至 {{utc(item.validUntil)}}</p>
    <details><summary>查看适用范围与依据</summary><p>适用条件：{{item.conditionRef}}</p><ul><li v-for="scope in item.scopeRefs" :key="scope">{{scope}}</li></ul><p>校准政策：{{item.calibrationPolicyRef}}</p><p>复核原件：{{item.reviewRef}}</p></details>
   </article>
   <h5>当前策略</h5>
   <p v-if="!data.strategies.length">本次有效读取没有返回已登记的条件策略。</p>
   <article v-for="item in data.strategies" :key="item.ref" class="self-card">
    <div class="self-heading"><strong>{{methods[item.preferredMethod]}}</strong><span>{{labels[item.qualification]}}</span></div>
    <p>备选方式：{{methods[item.alternativeMethod]}} · 复核有效至 {{utc(item.validUntil)}}</p>
    <details><summary>查看适用条件、例外与依据</summary><p>适用条件：{{item.conditionRef}}</p><ul><li v-for="exclusion in item.exclusions" :key="exclusion">{{exclusion}}</li></ul><p>复核原件：{{item.reviewRef}}</p></details>
   </article>
   <section v-if="data.unknowns.length" class="self-unknowns"><h5>仍待确认</h5><ul><li v-for="value in data.unknowns" :key="value">{{value}}</li></ul></section>
   <details v-if="data.limitRefs.length||data.commitmentRefs.length"><summary>当前限制与承诺依据</summary><ul><li v-for="value in data.limitRefs" :key="'limit:'+value">限制：{{value}}</li><li v-for="value in data.commitmentRefs" :key="'commitment:'+value">承诺：{{value}}</li></ul></details>
  </template>
 </section>
</template>
<style scoped>
.self-view{margin-top:24px;padding-top:16px;border-top:1px solid var(--line);color:var(--ink);overflow-wrap:anywhere}
.self-view p{font-size:12px;line-height:1.7;color:var(--muted)}.self-heading{display:flex;justify-content:space-between;align-items:start;gap:12px;flex-wrap:wrap}
.self-heading h4,.self-heading p{margin:0 0 8px}.self-view h5{font-size:13px;margin:20px 0 10px}
.self-heading button{min-height:44px;padding:9px 13px;border:1px solid var(--line);border-radius:3px;background:var(--button);color:var(--ink);font:inherit;cursor:pointer}
.self-heading button:disabled{background:var(--disabled-bg);color:var(--disabled-ink);cursor:default}.self-card{margin:10px 0;padding:14px;border:1px solid var(--line);border-radius:3px}
.self-counts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:14px 0}.self-counts div{min-width:0}.self-counts dt{font-size:11px;color:var(--muted)}.self-counts dd{margin:4px 0 0;font-size:19px;font-variant-numeric:tabular-nums}
.self-view details{font-size:12px;line-height:1.7}.self-view summary{min-height:32px;cursor:pointer}.self-view ul{padding-left:18px}.self-view :is(button,summary):focus-visible{outline:2px solid var(--focus);outline-offset:3px}.self-status{padding:10px 0}
@media(max-width:420px){.self-counts{gap:7px}.self-heading button{width:100%}}
</style>
