<script setup lang="ts">
import {operationIdV1} from './api/browser-crypto.ts'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import { sourceCorrectionInput, sourceCorrectionRequestDigest, type SourceCorrectionContext, type SourceCorrectionInput } from './api/source-correction.ts'

const props = defineProps<{ backend: BackendController; sourceId: string }>()
const emit = defineEmits<{ 'select-source': [sourceId: string] }>()
const context = ref<SourceCorrectionContext | null>(null), selected = ref<string[]>([]), statement = ref(''), busy = ref(false), message = ref('')
const pending = computed(() => props.backend.sourceCorrections.pending.value)
const samePending = computed(() => pending.value?.scope === props.backend.state.scope && pending.value.sourceId === props.sourceId)
const canRead = computed(() => props.backend.canRead.value && !!props.sourceId && !busy.value)
const canSubmit = computed(() => canRead.value && !pending.value && !!context.value && !!selected.value.length && !!statement.value.trim())
const canReplay = computed(() => canRead.value && samePending.value && !!statement.value.trim())
let generation = 0
function clear() { ++generation; context.value = null; selected.value = []; statement.value = ''; message.value = '' }
watch(() => [props.sourceId, props.backend.state.scope, props.backend.state.auth], clear, { flush: 'sync' })
onBeforeUnmount(clear)
const current = (token: number, scope: string, sourceId: string) => token === generation && scope === props.backend.state.scope && sourceId === props.sourceId && props.backend.canRead.value
async function read() {
  if (!canRead.value) return
  const token = generation, scope = props.backend.state.scope, sourceId = props.sourceId
  busy.value = true; context.value = null; selected.value = []; message.value = '正在读取当前来源与可更正解释。'
  try {
    const result = await props.backend.sourceCorrections.read(scope, sourceId)
    if (!current(token, scope, sourceId)) return
    context.value = result
    message.value = result.targets.length ? '请选择需要更正的当前解释，再填写你的说明。' : '该来源没有当前可更正解释；不能提交空目标更正。'
  } catch { if (token === generation) message.value = '更正依据未取得。请核验当前所有者权限、来源资格和运行状态，再明确重读。' }
  finally { busy.value = false }
}
async function submit() {
  if (!(pending.value ? canReplay.value : canSubmit.value)) return
  const token = generation, scope = props.backend.state.scope, sourceId = props.sourceId
  busy.value = true
  try {
    const prior = pending.value
    let input: SourceCorrectionInput, operationId: string
    if (prior) {
      input = { ...prior.input, source_refs: [...prior.input.source_refs], target_refs: [...prior.input.target_refs], statement: statement.value }
      operationId = prior.operationId
      if (await sourceCorrectionRequestDigest(scope, input, operationId) !== prior.requestDigest) {
        message.value = '说明与原请求不一致，未提交。请输入原说明来核验或补交同一操作；不会换用新操作ID。'; return
      }
    } else {
      input = sourceCorrectionInput(context.value!, statement.value, selected.value); operationId = operationIdV1()
      const requestDigest = await sourceCorrectionRequestDigest(scope, input, operationId)
      if (!current(token, scope, sourceId)) return
      props.backend.sourceCorrections.pending.value = { scope, sourceId, operationId, requestDigest,
        input: { schema: input.schema, correction_kind: input.correction_kind, source_refs: [...input.source_refs],
          target_refs: [...input.target_refs], access_epoch: input.access_epoch, deletion_epoch: input.deletion_epoch } }
    }
    if (!current(token, scope, sourceId)) return
    message.value = '正在提交来源更正，不会自动重试。'
    const receipt = await props.backend.sourceCorrections.submit(scope, input, operationId)
    if (props.backend.sourceCorrections.pending.value?.operationId === operationId) props.backend.sourceCorrections.pending.value = null
    if (!current(token, scope, sourceId)) return
    context.value = null; selected.value = []; statement.value = ''
    message.value = `来源更正已保存（操作 ${receipt.operation_id}）。解释、情感和关系的重评尚待真实结果核验。`
  } catch { if (token === generation) message.value = '更正结果尚未确认，可能已经保存。原操作ID已保留；只能明确核验或补交原请求。' }
  finally { busy.value = false }
}
</script>

<template>
  <section v-if="sourceId || pending" class="source-correction" aria-labelledby="source-correction-title" :aria-busy="busy">
    <h4 id="source-correction-title">纠正依据</h4>
    <p>补充你的真实说明；这会提交新的来源声明，不会直接抹去过去的感受或将解释标为已修复。</p>
    <template v-if="pending">
      <p class="correction-pending" role="status">有一项更正结果待核验，操作ID：{{ pending.operationId }}。原说明不会在离开页面后保留。</p>
      <button v-if="!samePending && pending.scope === backend.state.scope" class="text-action" :disabled="!backend.canRead.value || busy" @click="emit('select-source', pending.sourceId)">回到原来源核验</button>
    </template>
    <template v-if="sourceId">
      <p class="correction-source">当前来源：{{ sourceId }}</p>
      <button class="text-action" :disabled="!canRead" @click="read">读取当前更正依据</button>
      <fieldset v-if="context?.targets.length && !pending" :disabled="busy"><legend>选择需要更正的当前解释</legend>
        <label v-for="item in context.targets" :key="item.target_ref"><input v-model="selected" type="checkbox" :value="item.target_ref"><span>{{ item.claim }}</span></label>
      </fieldset>
      <label v-if="context?.targets.length || samePending" class="correction-statement" for="source-correction-statement">{{ samePending ? '重新输入原请求的说明' : '你的更正说明' }}
        <textarea id="source-correction-statement" v-model="statement" maxlength="4096" rows="4" :disabled="busy" autocomplete="off"></textarea>
      </label>
      <button v-if="!pending && context?.targets.length" class="read-action" :disabled="!canSubmit" @click="submit">提交来源更正</button>
      <button v-if="samePending" class="read-action" :disabled="!canReplay" @click="submit">核验或补交原更正请求（保留原操作ID）</button>
    </template>
    <p v-if="message" role="status" aria-live="polite">{{ message }}</p>
  </section>
</template>

<style scoped>
.source-correction{margin-top:20px;padding:18px;border:1px solid var(--line);border-radius:4px;overflow-wrap:anywhere}.source-correction h4{margin:0 0 12px;font-size:14px;font-weight:500}.source-correction p{font-size:12px;line-height:1.8}.correction-source,.correction-pending{color:var(--muted)}fieldset{margin:12px 0;padding:12px;border:1px solid var(--line)}fieldset label{display:flex;align-items:center;gap:10px;min-height:44px;margin:8px 0;font-size:12px;line-height:1.7}.correction-statement{display:grid;gap:8px;font-size:12px;margin:16px 0}textarea{box-sizing:border-box;width:100%;resize:vertical;min-height:100px;font:inherit;line-height:1.8;padding:10px;background:var(--surface);color:var(--ink);border:1px solid var(--line);border-radius:3px}button{min-height:44px;text-align:left;font:inherit;cursor:pointer;padding:10px 0}.read-action{width:100%;border-top:1px solid var(--line)}button:focus-visible,textarea:focus-visible,input:focus-visible{outline:2px solid var(--ink);outline-offset:3px}button:disabled{cursor:default;color:var(--muted)}
</style>
