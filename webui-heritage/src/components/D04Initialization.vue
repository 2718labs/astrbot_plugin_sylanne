<script setup lang="ts">
import { ref, shallowRef, watch, onBeforeUnmount } from 'vue'
import { initializationInput, initializationForm, initializationProjection, validInitializationProfile } from '../../../webui-src/src/d04_initialization.js'
const props = defineProps<{ scope: string; csrf: string; sessionEpoch: number }>()
const emit = defineEmits<{ locked: [message: string] }>()
const API = '/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1/commands'
type Reply = {status?: string; projection?: Record<string, unknown>; receipt?: Record<string, unknown>; problem?: {message?: string; code?: string}}
let epoch = 0
let draft: Record<string, unknown> = {}
const attempts = new Map<string, string>()
const profile = shallowRef<Record<string, unknown> | null>(null)
const receipt = shallowRef<Record<string, unknown> | null>(null)
const busy = ref(false)
const problem = ref('')
const form = ref<HTMLFormElement | null>(null)
const markup = ref(initializationForm({}, null))
const projectionMarkup = ref(initializationProjection(null, null))
function draw() {
  markup.value = initializationForm(draft, profile.value)
  projectionMarkup.value = initializationProjection(profile.value, receipt.value)
}
function clear() {
  ++epoch; draft = {}; attempts.clear(); profile.value = null; receipt.value = null; busy.value = false; problem.value = ''; draw()
}
watch(() => [props.scope, props.csrf, props.sessionEpoch], clear)
onBeforeUnmount(() => { ++epoch })
function capture() {
  if (form.value) Object.assign(draft, Object.fromEntries(new FormData(form.value).entries()))
}
function change(event: Event) {
  if ((event.target as HTMLElement)?.id !== 'initialization-mode') return
  capture(); delete draft.confirm; delete draft.profile_reviewed; draw()
}
async function post(action: string, input: Record<string, unknown>, operationId: string): Promise<Reply | null> {
  const scope = props.scope.trim(), csrf = props.csrf, originalEpoch = epoch, sessionEpoch = props.sessionEpoch
  if (!/^[^/\s]+\/[^/\s]+$/.test(scope) || !csrf) throw new Error('请先解锁 Owner，并从档案页选择已授权的 bot/persona 范围。')
  const response = await fetch(API, {method:'POST', credentials:'same-origin', cache:'no-store', headers:{'content-type':'application/json','x-csrf-token':csrf}, body:JSON.stringify({schema_version:'d12.contract.v1',action,scope,purpose:action.startsWith('read_') ? 'workbench_view':'workbench_user_action',audience:'owner',operation_id:operationId,input})})
  if (originalEpoch !== epoch || props.scope.trim() !== scope || props.csrf !== csrf || props.sessionEpoch !== sessionEpoch) return null
  const data = await response.json() as Reply
  if (originalEpoch !== epoch) return null
  if (response.status === 401 || response.status === 403 || data.status === 'unauthorized') {
    clear(); emit('locked', data.problem?.message ?? 'Owner 会话失效，请重新核验。'); return null
  }
  if (!response.ok) throw new Error(data.problem?.message ?? `HTTP ${response.status}`)
  return data
}
async function readProfile() {
  profile.value = null
  const data = await post('read_d04_initialization_profile', {}, crypto.randomUUID())
  if (!data) return
  if (data.status !== 'ready' || !validInitializationProfile(data.projection)) throw new Error(data.problem?.message ?? '当前安装资料尚未通过核验。')
  profile.value = data.projection ?? null
  const current = profile.value?.current as Record<string, unknown> | undefined
  draft.expected_revision = Number.isSafeInteger(current?.mapping_revision) ? String(current?.mapping_revision) : ''
  draft.expected_version = Number.isSafeInteger(current?.clock_version) ? String(current?.clock_version) : ''
}
async function load() {
  if (busy.value) return
  capture(); profile.value = null; problem.value = ''; busy.value = true; const e = epoch
  try { await readProfile() } catch(error) { if (e === epoch) problem.value = error instanceof Error ? error.message : '安装资料读取失败' }
  finally { if (e === epoch) { busy.value = false; draw() } }
}
async function submit() {
  if (busy.value) return
  capture(); problem.value = ''; const e = epoch
  try {
    const mode = String(draft.mode ?? 'd04_root_draft')
    // Read checkbox state freshly: unchecked fields are absent from FormData.
    const values = form.value ? Object.fromEntries(new FormData(form.value).entries()) : {}
    const input = initializationInput(mode, values, profile.value)
    const fingerprint = JSON.stringify([props.scope.trim(), mode, input])
    if (!attempts.has(fingerprint)) attempts.set(fingerprint, crypto.randomUUID())
    busy.value = true
    const operationId = attempts.get(fingerprint)!
    const data = await post(mode, input, operationId)
    if (!data || e !== epoch) return
    if (data.status !== 'ready') throw new Error(data.problem?.message ?? `操作尚未确认：${data.status ?? 'unavailable'}；重试会保留操作 ID ${operationId}`)
    if (data.receipt?.operation_id !== operationId || typeof data.receipt?.phase !== 'string') throw new Error(`未取得匹配的权威回执；请保留操作 ID ${operationId}`)
    receipt.value = data.receipt
    await readProfile()
  } catch(error) { if (e === epoch) problem.value = error instanceof Error ? error.message : '操作未确认' }
  finally { if (e === epoch) { busy.value = false; draw() } }
}
</script>
<template>
  <section class="page d04-init">
    <div class="eyebrow">WORKBENCH / EXPLICIT INITIALIZATION</div><h1>感受核心初始化</h1>
    <p class="lead">每一步由当前 Owner 明确选择。草稿、编译、采用、预算与时钟是不同操作；只有对应权威回执表示该步骤完成。</p>
    <div class="owner-lock"><div><strong>{{ scope || '未选择角色范围' }} · {{ csrf ? 'OWNER UNLOCKED' : 'OWNER LOCKED' }}</strong><p>从档案页填写已授权范围。切换范围或重新核验会话会清除这里的临时内容。</p></div><button class="quiet" :disabled="busy || !csrf" @click="load">{{ busy ? '核验中…' : '读取当前初始化资料' }}</button></div>
    <p v-if="problem" class="notice" role="alert">{{ problem }}</p>
    <div class="d04-columns"><section class="panel d04-profile" v-html="projectionMarkup"></section><section class="panel"><h2>明确选择并提交</h2><form ref="form" @submit.prevent="submit" @change="change"><fieldset :disabled="busy || !csrf"><div class="d04-fields" v-html="markup"></div><button type="submit" class="accent">{{ busy ? '正在核验，请勿重复提交' : '明确提交所选步骤' }}</button></fieldset></form></section></div>
  </section>
</template>
<style scoped>
.d04-columns{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(300px,1fr);gap:20px}.d04-profile{min-width:0}.d04-init :deep(pre){white-space:pre-wrap;overflow-wrap:anywhere;max-height:65vh;overflow:auto;color:#37342e;font:11px/1.6 var(--font-mono)}.d04-init :deep(code){overflow-wrap:anywhere}.d04-init :deep(p){line-height:1.65}.d04-init :deep(label){display:grid;gap:7px;margin:14px 0;font-size:12px}.d04-init :deep(input),.d04-init :deep(select),.d04-init :deep(textarea){width:100%;padding:10px;border:1px solid #bcb5a8;background:#faf8f2;color:#34312b;font:12px/1.5 var(--font-mono)}.d04-init :deep(textarea){min-height:220px;resize:vertical}.d04-init :deep(.acknowledgement){display:grid;grid-template-columns:20px 1fr;align-items:start}.d04-init :deep(input[type=checkbox]){width:17px;height:17px}.d04-init :deep(summary){cursor:pointer}.d04-init fieldset{border:0;padding:0;margin:0;min-width:0}.d04-init :deep(input[readonly]){background:#eae6dd}.d04-init :deep(button:disabled){opacity:.5;cursor:not-allowed}@media(max-width:1100px){.d04-columns{grid-template-columns:1fr}}
</style>
