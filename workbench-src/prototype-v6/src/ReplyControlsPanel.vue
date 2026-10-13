<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import type { BackendController } from './use-backend'
import { makeStopReplyRequest, type ReplyControlMetadata, type ReplyControlStatus, type StopReplyRequest, type NaturalBubbleMetadata, type NaturalFeeMetadata } from './api/reply-controls.ts'

const props = defineProps<{ backend: BackendController; inlineTarget?: string | null }>()
const narrowScreen = window.matchMedia('(max-width: 600px)')
const mobile = ref(narrowScreen.matches), expanded = ref(!narrowScreen.matches)
const inline = computed(() => mobile.value && !!props.inlineTarget)
function screenChanged(event: MediaQueryListEvent) { mobile.value = event.matches; expanded.value = !event.matches }
function expansionChanged(event: Event) { expanded.value = (event.currentTarget as HTMLDetailsElement).open }
onMounted(() => narrowScreen.addEventListener('change', screenChanged))
onBeforeUnmount(() => narrowScreen.removeEventListener('change', screenChanged))
const items = ref<ReplyControlMetadata[]>([]), selected = ref(''), busy = ref(false), nextCursor = ref<string | null>(null)
const message = ref('读取当前回复后，可以停止它的后续工作。')
const statuses = reactive<Record<string, ReplyControlStatus>>({})
const attempts = new Map<string, StopReplyRequest>()
let generation = 0
const scope = computed(() => props.backend.state.scope)
const target = computed(() => items.value.find(item => item.cycle_job_ref === selected.value))
const current = computed(() => target.value ? statuses[target.value.cycle_job_ref] : undefined)
const batch = computed(() => target.value?.natural_batch)
const phases: Record<string, string> = { queued: '排队', running: '执行中', waiting: '等待', deferred: '等待条件', draining: '结束中', completed: '已完成', failed: '失败', cancelled: '已取消', pending_confirmation: '结果待核验' }
const canStop = computed(() => {
  const item = target.value
  if (!item || busy.value || current.value?.cancellation_confirmed) return false
  if (current.value?.original_ref || item.original_ref || attempts.has(item.cycle_job_ref)) return true
  return !['completed', 'failed', 'cancelled'].includes(item.job_phase)
})

watch(scope, () => { ++generation; items.value = []; selected.value = ''; nextCursor.value = null; message.value = '读取当前角色的回复控制。' })
function bubbleResult(child: NaturalBubbleMetadata) {
  if (child.authority_state === 'unavailable') return '执行观察待核验'
  if (child.authority_state === 'unresolved') return '执行结果未知'
  if (child.authority_state === 'absent') return child.admission_ref ? '已准入，执行原件暂缺' : '待当前准入'
  const outcomes: Record<string, string> = { accepted: '平台已接受，送达未确认', delivered: '已送达，已读未知', handed_off: '已交接，结果待核验', unknown: '发送结果未知', failed_before_acceptance: '接受前失败', read: '平台报告已读，独立已读状态待核验' }
  return child.observation_outcome ? outcomes[child.observation_outcome] ?? '结果待核验' : '结果待核验'
}
function continuation(child: NaturalBubbleMetadata) {
  if (child.continuation_state === 'cancelled') return '后续已停止'
  if (child.continuation_state === 'superseded') return '原批次已被有依据的新输入取代'
  if (child.continuation_state === 'ready') return '后续仍须当前准入'
  const reasons: Record<string, string> = { owner_stop: '后续已停止', scoped_source_changed: '来源资格变化，等待重新核验', deadline_expired: '原截止已过', predecessor_unknown: '等待前段结果核实', qualification_unavailable: '等待当前资格核验', relevant_new_turn: '会话依据变化，等待重新核验' }
  return child.reason_code ? reasons[child.reason_code] ?? '后续暂缓' : '后续暂缓'
}
function feeLabel(fee: NaturalFeeMetadata) {
  const actual = fee.actual?.model_microusd
  if (fee.status === 'pending_confirmation' || fee.status === 'pending_overrun') return '费用待核验，原预留仍保留'
  if (actual !== undefined) return `${(actual / 1_000_000).toFixed(6)} USD${fee.status === 'overrun' ? ' · 已记录超额' : ''}`
  return fee.status === 'overrun' ? '实际费用已记录超额' : '实际费用已核实'
}
function showStatus(result: ReplyControlStatus) {
  statuses[result.cycle_job_ref] = result
  message.value = result.cancellation_confirmed ? '本次回复已停止。'
    : result.state === 'pending_confirmation' ? '正在停止，已开始工作的结果仍待确认。'
    : '停止请求已生效；已开始的工作可能仍在结束。'
}
async function refresh(cursor: string | null = null) {
  if (busy.value || !props.backend.scopeValid.value) return
  const revision = generation, requestedScope = scope.value
  busy.value = true
  try {
    const result = await props.backend.replyControls.read(requestedScope, cursor)
    if (revision !== generation) return
    items.value = result.items; nextCursor.value = result.next_cursor
    if (!result.items.some(item => item.cycle_job_ref === selected.value)) selected.value = result.items[0]?.cycle_job_ref ?? ''
    message.value = result.items.length ? '已读取当前回复的真实状态。' : '当前没有可控制的回复。'
  } catch { if (revision === generation) { items.value = []; selected.value = ''; nextCursor.value = null; message.value = '控制状态未取得，请核验当前所有者会话后重试。' } }
  finally { busy.value = false }
}
async function stop() {
  const item = target.value
  if (!item || busy.value) return
  const revision = generation, requestedScope = scope.value
  busy.value = true; message.value = '正在提交停止请求。'
  try {
    const existing = current.value?.original_ref ?? item.original_ref
    if (existing) {
      const result = await props.backend.replyControls.status(requestedScope, existing)
      if (revision === generation) showStatus(result)
      return
    }
    // An uncertain request keeps its original UUID and exact payload.
    let request = attempts.get(item.cycle_job_ref)
    if (!request) { request = makeStopReplyRequest(item); attempts.set(item.cycle_job_ref, request) }
    const result = await props.backend.replyControls.stop(request)
    statuses[result.cycle_job_ref] = result
    if (revision === generation) showStatus(result)
  } catch { if (revision === generation) message.value = '停止结果尚未确认。再次核验会使用原请求，不会新建一次停止操作。' }
  finally { busy.value = false }
}
</script>

<template>
  <Teleport defer :to="inlineTarget ?? 'body'" :disabled="!inline">
  <aside class="reply-controls" :class="{ 'reply-controls-inline': inline }" aria-labelledby="reply-controls-title" :aria-busy="busy">
    <details :open="expanded" @toggle="expansionChanged">
    <summary id="reply-controls-title">当前回复<span>{{ expanded ? '收起控制' : '展开控制' }}</span></summary>
    <div class="reply-controls-heading"><h2>当前回复</h2><button :disabled="busy || !backend.scopeValid.value" @click="refresh()">读取状态</button></div>
    <label v-if="items.length" class="reply-target">要控制的回复
      <select v-model="selected" :disabled="busy"><option v-for="(item, index) in items" :key="item.cycle_job_ref" :value="item.cycle_job_ref">回复 {{ index + 1 }} · {{ phases[item.job_phase] ?? item.job_phase }}</option></select>
    </label>
    <button v-if="nextCursor" :disabled="busy" @click="refresh(nextCursor)">读取下一页回复</button>
    <p role="status" aria-live="polite">{{ message }}</p>
    <section v-if="batch" class="reply-bubbles" aria-label="本次回复的气泡结果">
      <p v-if="batch.details_state === 'manifest_not_adopted'">完整气泡批次尚未采用，当前没有逐泡执行事实。</p>
      <p v-else-if="batch.details_state === 'bubble_details_unavailable'">当前无法核验逐泡原件，发送与读取状态待核验。</p>
      <ol v-else>
        <li v-for="child in batch.children" :key="child.effect_id">
          <strong>气泡 {{ child.index + 1 }} · {{ bubbleResult(child) }}</strong>
          <span>{{ continuation(child) }}</span>
          <span>{{ child.actual_intent_ref ? '交流意图已实际采用' : '交流意图尚未采用' }}</span>
          <span v-for="fee in child.fees" :key="fee.settlement_ref">{{ feeLabel(fee) }}</span>
        </li>
      </ol>
      <p>本批模型费用{{ batch.parent_fees.length ? '记录' : '待核验' }}<span v-for="fee in batch.parent_fees" :key="fee.settlement_ref"> · {{ feeLabel(fee) }}</span></p>
    </section>
    <button v-if="target" class="reply-stop" :disabled="!canStop" @click="stop">{{ current?.original_ref || target.original_ref || attempts.has(target.cycle_job_ref) ? '重新核验停止' : '停止本次回复' }}</button>
    </details>
  </aside>
  </Teleport>
</template>

<style scoped>
.reply-controls{position:fixed;left:24px;bottom:24px;z-index:30;width:min(310px,calc(100vw - 48px));padding:14px 18px;background:var(--surface,#f2f5f5);color:var(--ink);border:1px solid var(--line);border-radius:12px;font-size:12px;max-height:40svh;overflow:auto}
.reply-bubbles ol{list-style:none;padding:0;margin:8px 0}.reply-bubbles li{display:grid;gap:4px;padding:8px 0;border-top:1px solid var(--line)}.reply-bubbles strong{font-weight:500}.reply-bubbles span{line-height:1.6;color:var(--muted)}
.reply-controls-heading{display:flex;align-items:center;justify-content:space-between;gap:12px}.reply-controls h2{font-size:13px;margin:0;font-weight:500}.reply-controls p{line-height:1.7;color:var(--muted);margin:8px 0}.reply-target{display:grid;gap:6px}.reply-target select{font:inherit;color:inherit;background:var(--surface);border:1px solid var(--line);border-radius:5px;padding:8px;min-height:44px;max-width:100%}.reply-stop{width:100%;text-align:left;border-top:1px solid var(--line);padding:8px 0}.reply-controls button{font-size:12px;min-height:44px}
.reply-controls summary{display:none}
@media(max-width:600px){
  .reply-controls{left:12px;bottom:12px;width:calc(100vw - 24px);padding:10px 14px}
  .reply-controls summary{display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:44px;cursor:pointer;font-size:13px;list-style:none}
  .reply-controls summary::-webkit-details-marker{display:none}
  .reply-controls summary span{font-size:12px;color:var(--muted)}
  .reply-controls summary:focus-visible{outline:2px solid var(--ink);outline-offset:3px;border-radius:3px}
  .reply-controls-inline{position:static;width:100%;max-height:none;overflow:visible;margin:16px 0 0;padding:10px 14px;z-index:auto}
  .reply-controls-inline .reply-controls-heading h2{display:none}
}
</style>
