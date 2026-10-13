<script setup lang="ts">
import {operationIdV1} from './api/browser-crypto.ts'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { ProjectContextOptions } from './api/project-context.ts'
import { WorkbenchApiError } from './api/client.ts'
import { projectControlInput, type ProjectControlAction, type ProjectControlContextV2, type ProjectControlProvenance } from './api/project-control.ts'

const props = defineProps<{ backend: BackendController }>()
const options = ref<ProjectContextOptions | null>(null), selected = ref(''), context = ref<ProjectControlContextV2 | null>(null), busy = ref(false), message = ref('')
const last = ref<Pick<ProjectControlProvenance, 'after_plan_state' | 'noop' | 'execution_summary' | 'control_original_ref'> | null>(null)
const pending = computed(() => props.backend.projectControls.pending.value)
const eligible = computed(() => props.backend.canRead.value && !busy.value)
const knownProject = computed(() => !!selected.value && !!options.value?.items.some(item => item.project_ref === selected.value))
const samePending = computed(() => pending.value?.scope === props.backend.state.scope && pending.value.input.project_ref === selected.value)
const canRead = computed(() => eligible.value && knownProject.value)
const canPause = computed(() => canRead.value && !pending.value && !!context.value?.permitted_controls.includes('pause_project_v1'))
const canResume = computed(() => canRead.value && !pending.value && !!context.value?.permitted_controls.includes('resume_project_v1'))
const stateLabel: Record<string, string> = { active: '进行中', waiting: '等待条件', paused: '已暂停新增工作', satisfied: '目标已满足', abandoned: '已放弃', superseded: '已被新计划替代' }
let generation = 0
function clear() { ++generation; options.value = null; selected.value = ''; context.value = null; last.value = null; message.value = '' }
watch(() => [props.backend.state.scope, props.backend.state.auth], clear, { flush: 'sync' })
onBeforeUnmount(clear)
const current = (token: number, scope: string, projectRef: string) => token === generation && scope === props.backend.state.scope && projectRef === selected.value && props.backend.canRead.value
async function discover() {
  if (!eligible.value) return
  const token = generation, scope = props.backend.state.scope
  busy.value = true; options.value = null; context.value = null; last.value = null; message.value = '正在读取当前所有者可选择的真实项目。'
  try {
    const result = await props.backend.projectContext.read(scope)
    if (token !== generation || scope !== props.backend.state.scope || !props.backend.canRead.value) return
    options.value = result
    if (!result.items.some(item => item.project_ref === selected.value)) selected.value = ''
    message.value = result.items.length ? '选择项目后会重新核验当前计划与控制权限。目录中的引用只用于选择项目。' : '当前目录没有可选择的获准项目；项目可能尚未初始化。'
  } catch { if (token === generation) message.value = '项目目录未取得。请核验当前所有者授权和实际项目安装；没有使用示例项目。' }
  finally { busy.value = false }
}
async function read() {
  if (!canRead.value) return
  const token = generation, scope = props.backend.state.scope, projectRef = selected.value
  busy.value = true; context.value = null; last.value = null; message.value = '正在读取当前计划、版本和实际控制范围。'
  try {
    const result = await props.backend.projectControls.readV2(scope, projectRef)
    if (!current(token, scope, projectRef)) return
    context.value = result; message.value = '已读取当前项目控制上下文。提交时仍需后端重新核验。'
  } catch { if (token === generation) message.value = '当前项目控制未取得，可能未初始化、未授权或依据已变化。请重新核验后重读。' }
  finally { busy.value = false }
}
watch(selected, () => { ++generation; context.value = null; last.value = null; message.value = ''; if (canRead.value) void read() }, { flush: 'sync' })
function returnToPending() {
  if (!pending.value || pending.value.scope !== props.backend.state.scope || !options.value?.items.some(item => item.project_ref === pending.value!.input.project_ref)) {
    message.value = '原操作的项目不在当前获准目录。请核验原项目权限，不会新建替代控制。'; return
  }
  selected.value = pending.value.input.project_ref
}
async function control(action: ProjectControlAction, replay = false) {
  if (replay ? !(canRead.value && samePending.value) : !(action === 'pause_project_v1' ? canPause.value : canResume.value)) return
  const scope = props.backend.state.scope, projectRef = selected.value, token = generation
  const attempt = replay ? pending.value! : { scope, action, operationId: operationIdV1(), input: projectControlInput(context.value!, action) }
  if (!replay) props.backend.projectControls.pending.value = attempt
  busy.value = true; message.value = replay ? '正在核验或补交原项目控制请求，操作ID与输入保持原样。' : '正在提交明确选择的项目控制。'
  let received = false
  try {
    const receipt = await props.backend.projectControls.submit(scope, attempt.action, attempt.input, attempt.operationId)
    received = true
    if (props.backend.projectControls.pending.value?.operationId === attempt.operationId) props.backend.projectControls.pending.value = null
    if (!current(token, scope, projectRef)) return
    last.value = { after_plan_state: receipt.control.after_plan_state, noop: receipt.control.noop,
      execution_summary: receipt.control.execution_summary, control_original_ref: receipt.control.control_original_ref }
    context.value = null
    message.value = receipt.control.noop ? '原件确认本次没有改变计划状态。已有操作仍按实际原件核实。'
      : attempt.action === 'pause_project_v1' ? '暂停新增工作已保存；已有操作仍可能等待核实，未宣称全部取消。'
      : '恢复选择已保存；是否可立即新增工作仍由实际等待条件和后端准入决定。'
    const observed = await props.backend.projectControls.readV2(scope, projectRef)
    if (current(token, scope, projectRef)) context.value = observed
  } catch (error) {
    if (token !== generation) return
    context.value = null
    if (!received && error instanceof WorkbenchApiError && error.code === 'project_control_basis_changed') {
      if (props.backend.projectControls.pending.value?.operationId === attempt.operationId) props.backend.projectControls.pending.value = null
      message.value = '提交依据已变化，本次控制未采用。请重读当前计划，再重新选择操作；不会自动替换版本或重交。'
    } else message.value = received ? '操作原件已取得，当前状态回读未完成。请明确重读，不会自动再提交。'
      : '项目控制结果未知，可能已经保存。原操作ID与精确输入已保留，只能显式核验或补交原请求。'
  } finally { busy.value = false }
}
</script>

<template>
  <section class="project-controls" aria-labelledby="project-controls-title" :aria-busy="busy">
    <h4 id="project-controls-title">项目控制</h4>
    <p>暂停只阻止新增工作。已经开始的操作、未知结果与待结算费用保留原件，仍可能需要核实。</p>
    <button class="text-action" :disabled="!eligible" @click="discover">读取获准项目目录</button>
    <p v-if="!backend.canRead.value" role="status">先核验当前所有者会话、角色范围和实际运行状态。</p>
    <label v-if="options?.items.length" for="project-control-project">选择真实项目
      <select id="project-control-project" v-model="selected" :disabled="busy"><option value="">请选择项目</option><option v-for="(item, index) in options.items" :key="item.project_ref" :value="item.project_ref">项目 {{ index + 1 }} · {{ item.project_ref }}</option></select>
    </label>
    <button v-if="knownProject" class="text-action" :disabled="!canRead" @click="read">重读当前控制状态</button>
    <template v-if="context">
      <dl><div><dt>当前计划</dt><dd>{{ stateLabel[context.plan_state] ?? context.plan_state }}</dd></div><div><dt>目标状态</dt><dd>{{ stateLabel[context.goal_state] ?? context.goal_state }}</dd></div>
        <div><dt>在途</dt><dd>{{ context.execution_summary.inflight }}</dd></div><div><dt>结果未知</dt><dd>{{ context.execution_summary.unknown }}</dd></div><div><dt>待结算</dt><dd>{{ context.execution_summary.settlement_pending }}</dd></div>
      </dl>
      <p>当前恢复预览：{{ context.resume_preview.state ? stateLabel[context.resume_preview.state] : '无可用恢复选择' }}。数量为零也不单独证明外部效果已静止。</p>
      <ul v-if="context.resume_preview.reasons.length"><li v-for="(reason,index) in context.resume_preview.reasons" :key="index">{{ reason }}</li></ul>
      <h5>当前记录的下一步</h5>
      <p v-if="context.next_step">{{ context.next_step.action_kind }} · {{ context.next_step.node_ref }}<span v-if="context.next_step.wait_condition"> · 等待条件：{{ context.next_step.wait_condition }}</span>。该记录不代表已经获得执行许可。</p>
      <p v-else>{{ context.checkpoint?.basis_status === 'stale' ? '检查点与当前计划版本不一致，等待实际重评。' : '当前没有可核验的下一步记录。' }}</p>
      <p v-if="context.checkpoint?.wait_reason">实际等待原因：{{ context.checkpoint.wait_reason }}</p>
      <p>计划中的待核实效果：{{ context.pending_effects.total_count }}<span v-if="context.pending_effects.truncated">（这里只列出前 32 项）</span>。</p>
      <h5>共享父预算池账面状态</h5>
      <template v-if="context.budget">
        <p>此池可能同时用于多个项目，金额不代表本项目独占额度或新增工作的执行许可。当前授权有效至 {{ context.budget.grant_expires_utc }}；核验状态：{{ context.budget.qualification_state === 'hold' ? '暂停准入' : context.budget.qualification_state === 'unknown' ? '存在未知或不完整依据' : '未评估执行资格' }}。</p>
        <dl v-for="row in context.budget.dimensions" :key="row.dimension">
          <div><dt>单位</dt><dd>{{ row.dimension }} · {{ row.unit ?? '单位未取得' }} · {{ context.budget.currency }}</dd></div>
          <div><dt>总上限</dt><dd>{{ row.limit }}</dd></div><div><dt>当前授权单次上限</dt><dd>{{ row.grant_ceiling ?? '未知' }}</dd></div><div><dt>已花费</dt><dd>{{ row.spent }}</dd></div>
          <div><dt>已预留（含子额度）</dt><dd>{{ row.reserved }}</dd></div><div><dt>未确认费用</dt><dd>{{ row.unconfirmed }}</dd></div>
          <div><dt>子额度分配</dt><dd>{{ row.allocated ?? '窗口不完整，金额未知' }}</dd></div><div><dt>账面剩余</dt><dd>{{ row.remaining }}</dd></div>
        </dl>
      </template>
      <p v-else>未取得与本项目原件绑定的当前预算信息，金额未知。</p>
      <ul v-if="context.missing.length"><li v-for="reason in context.missing" :key="reason">{{ reason }}</li></ul>
      <button v-if="context.permitted_controls.includes('pause_project_v1') && !pending" class="control-action" :disabled="!canPause" @click="control('pause_project_v1')">暂停项目新增工作</button>
      <button v-if="context.permitted_controls.includes('resume_project_v1') && !pending" class="control-action" :disabled="!canResume" @click="control('resume_project_v1')">按当前依据恢复项目</button>
    </template>
    <template v-if="pending">
      <p role="status">有一项项目控制结果尚未确认。原操作ID：{{ pending.operationId }}。</p>
      <button v-if="!samePending" class="text-action" :disabled="!eligible" @click="returnToPending">回到原项目核验</button>
      <button v-if="samePending" class="control-action" :disabled="!canRead" @click="control(pending.action, true)">核验或补交原控制请求（保留原操作ID）</button>
    </template>
    <p v-if="last">本次操作原件中的计划状态：{{ stateLabel[last.after_plan_state] ?? last.after_plan_state }}{{ last.noop ? ' · 状态未改动' : '' }}。</p>
    <p v-if="message" role="status" aria-live="polite">{{ message }}</p>
  </section>
</template>

<style scoped>
.project-controls{font-size:12px;line-height:1.8;overflow-wrap:anywhere}.project-controls h4{font-size:16px;font-weight:500;margin:0 0 14px}.project-controls p{margin:10px 0;color:var(--muted)}label{display:grid;gap:8px;margin:14px 0}select{box-sizing:border-box;width:100%;max-width:100%;min-height:44px;font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--line);border-radius:3px;padding:10px}dl{margin:14px 0}dl>div{display:flex;justify-content:space-between;gap:16px;padding:8px 0;border-bottom:1px solid var(--line)}dt{color:var(--muted)}dd{margin:0}button{font:inherit;min-height:44px;padding:10px 0;text-align:left;cursor:pointer}.control-action{display:block;width:100%;border-top:1px solid var(--line);margin-top:10px}button:disabled{color:var(--muted);cursor:default}button:focus-visible,select:focus-visible{outline:2px solid var(--ink);outline-offset:3px}
</style>
