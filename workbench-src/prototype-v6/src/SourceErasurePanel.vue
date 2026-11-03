<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { SourceErasureReceipt } from './api/source-erasure.ts'
import { operationIdV1 } from './api/browser-crypto.ts'
import { UUID4 } from './api/contract.ts'
const props = defineProps<{backend:BackendController; sourceId:string}>()
const emit = defineEmits<{'select-source':[sourceId:string]}>()
const confirmation=ref(''), acknowledgement=ref(false), recoveryId=ref(''), busy=ref(false), message=ref('')
const receipt=ref<SourceErasureReceipt|null>(null)
const pending=computed(()=>props.backend.sourceErasures.pending.value)
const samePending=computed(()=>pending.value?.scope===props.backend.state.scope&&pending.value.sourceId===props.sourceId)
const permitted=computed(()=>props.backend.canRead.value&&!busy.value&&!!props.sourceId)
const canSubmit=computed(()=>permitted.value&&!pending.value&&acknowledgement.value&&confirmation.value===props.sourceId&&!recoveryId.value)
const canRecover=computed(()=>permitted.value&&(samePending.value||(!pending.value&&UUID4.test(recoveryId.value))))
let generation=0
function clear(){++generation;confirmation.value='';acknowledgement.value=false;recoveryId.value='';receipt.value=null;message.value=''}
watch(()=>[props.sourceId,props.backend.state.scope,props.backend.state.auth],clear,{flush:'sync'})
onBeforeUnmount(clear)
async function submit(recover:boolean){
  if(!(recover?canRecover.value:canSubmit.value))return
  const token=generation,scope=props.backend.state.scope,sourceId=props.sourceId
  const attempt=pending.value??{scope,sourceId,operationId:recover?recoveryId.value:operationIdV1()}
  props.backend.sourceErasures.pending.value=Object.freeze({...attempt})
  busy.value=true;message.value='正在核验并提交同一来源删除操作；不会自动重试。'
  try{
    const result=await props.backend.sourceErasures.submit(attempt)
    if(token!==generation||scope!==props.backend.state.scope||!props.backend.canRead.value)return
    receipt.value=result
    message.value=result.phase==='authority_pending'?'已取得待处理原件，尚未取得 accepted 原件。':'已取得 Authority accepted 与 Graph 屏障原件；物理清理各分面尚未确认完成。'
  }catch{if(token===generation)message.value='结果尚未确认，可能已受理。请保存原操作ID，只核验或补交同一请求。'}
  finally{busy.value=false}
}
</script>
<template>
  <section v-if="sourceId||pending" class="source-erasure" aria-labelledby="source-erasure-title" :aria-busy="busy">
    <h4 id="source-erasure-title">删除来源及其授权闭包</h4>
    <p>这会请求独立删除权威处理当前来源及依赖闭包。来源更正、删除来源和卸载插件是不同操作；删除不会撤回已发送到外部平台的内容。</p>
    <p v-if="pending" class="original" role="status">原操作ID：<code>{{pending.operationId}}</code>。请保存此ID；页面刷新后可在原来源下填入它继续核验。</p>
    <button v-if="pending&&!samePending&&pending.scope===backend.state.scope" :disabled="!backend.canRead.value||busy" @click="emit('select-source',pending.sourceId)">回到原来源核验</button>
    <template v-if="sourceId">
      <p>当前来源：<code>{{sourceId}}</code></p>
      <template v-if="!pending">
        <label>确认来源ID<input v-model="confirmation" autocomplete="off" :disabled="busy"/></label>
        <label class="ack"><input v-model="acknowledgement" type="checkbox" :disabled="busy"/>我确认请求删除此来源及后台核定的依赖闭包。</label>
        <button :disabled="!canSubmit" @click="submit(false)">提交来源删除请求</button>
        <label>已有删除操作ID<input v-model="recoveryId" autocomplete="off" :disabled="busy" placeholder="恢复原请求时填写 UUID"/></label>
      </template>
      <button v-if="samePending||recoveryId" :disabled="!canRecover" @click="submit(true)">核验或补交原删除请求</button>
    </template>
    <p v-if="message" role="status" aria-live="polite">{{message}}</p>
    <dl v-if="receipt">
      <div><dt>权威阶段</dt><dd>{{receipt.phase==='authority_pending'?'pending · 待处理':'accepted · 已受理'}}</dd></div>
      <div><dt>删除水位</dt><dd>{{receipt.deletion_epoch}}</dd></div>
      <template v-if="receipt.phase==='authority_accepted'">
        <div><dt>范围原件</dt><dd><code>{{receipt.scope_digest}}</code></dd></div>
        <div><dt>Graph 屏障</dt><dd><code>{{receipt.graph_barrier_digest}}</code></dd></div>
      </template>
      <div><dt>分面清理</dt><dd>未取得完整清理收据；不标记完成</dd></div>
    </dl>
  </section>
</template>
<style scoped>
.source-erasure{margin-top:20px;padding:18px;border:1px solid var(--line);border-radius:4px;overflow-wrap:anywhere}.source-erasure h4{margin:0 0 12px;font-size:14px;font-weight:500}.source-erasure p,label,dl{font-size:12px;line-height:1.8}label{display:grid;gap:8px;margin:12px 0}input:not([type=checkbox]){box-sizing:border-box;width:100%;min-height:44px;padding:8px;font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--line)}.ack{display:flex;gap:8px;align-items:center;min-height:44px}button{font:inherit;min-height:44px;text-align:left;cursor:pointer;padding:10px 0;border-top:1px solid var(--line);width:100%}button:disabled{color:var(--muted);cursor:default}button:focus-visible,input:focus-visible{outline:2px solid var(--ink);outline-offset:3px}dl>div{display:grid;gap:4px;margin:12px 0}dt{color:var(--muted)}dd{margin:0}code{font-size:11px;user-select:all}.original{padding:10px;border:1px solid var(--line)}
</style>
