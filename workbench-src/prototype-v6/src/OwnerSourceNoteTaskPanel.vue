<script setup lang="ts">
import {operationIdV1} from './api/browser-crypto.ts'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { ProjectContextOptions } from './api/project-context.ts'
import { ownerTaskInputDigest, ownerTaskRequest, OWNER_MATERIAL_MAX_CHARACTERS, type OwnerMaterialStatus, type OwnerTaskOptions, type OwnerTaskStatus } from './api/owner-source-note-task.ts'
const props = defineProps<{ backend: BackendController }>()
const projects = ref<ProjectContextOptions | null>(null), project = ref(''), options = ref<OwnerTaskOptions | null>(null)
const selected = ref(''), requestedUntil = ref(''), busy = ref(false), message = ref(''), status = ref<OwnerTaskStatus | null>(null)
const attempt = computed(() => props.backend.ownerTasks.attempts.get(props.backend.state.scope))
const materialText = ref(''), materialStatus = ref<OwnerMaterialStatus | null>(null)
const materialAttempt = computed(() => props.backend.ownerMaterials.attempts.get(props.backend.state.scope))
const materialCharacters = computed(() => Array.from(materialText.value).length)
const materialBytes = computed(() => new TextEncoder().encode(materialText.value).byteLength)
const eligible = computed(() => props.backend.canRead.value && !busy.value)
const canImportMaterial = computed(() => eligible.value && !materialAttempt.value && !!materialText.value.trim() && materialCharacters.value <= OWNER_MATERIAL_MAX_CHARACTERS)
const knownProject = computed(() => projects.value?.items.some(item => item.project_ref === project.value) === true)
const item = computed(() => options.value?.items[Number(selected.value)] ?? null)
const deadline = computed(() => requestedUntil.value ? new Date(requestedUntil.value).getTime() / 1000 : NaN)
const canSubmit = computed(() => eligible.value && !attempt.value && !!options.value && selected.value !== '' && !!item.value
  && options.value.deadline_upper_bound_utc !== null && Number.isFinite(deadline.value)
  && deadline.value > options.value.observed_utc && deadline.value <= options.value.deadline_upper_bound_utc)
const terminal = computed(() => status.value && ['completed','failed','cancelled'].includes(status.value.state)
  && status.value.job_phase !== null && ['completed','failed','cancelled'].includes(status.value.job_phase)
  && !status.value.pending_effect_refs.length)
const stateLabels: Record<OwnerTaskStatus['state'], string> = { not_found:'尚未观察到提交原件',focus_saved_task_not_saved:'Focus 已保存，任务尚未保存',accepted:'任务原件已接受',pending_start:'已保存，尚待实际启动',active:'任务实际运行中',draining:'取消处理中',waiting:'任务等待当前条件',completed:'任务阶段已完成',failed:'任务阶段失败',cancelled:'任务阶段已取消',conflict:'原操作与请求摘要冲突',unknown:'结果尚未确认' }
let generation = 0
const current = (token: number, scope: string) => token === generation && scope === props.backend.state.scope && props.backend.canRead.value
function clear() { ++generation; projects.value = null; project.value = ''; options.value = null; selected.value = ''; requestedUntil.value = ''; status.value = null; materialText.value = ''; materialStatus.value = null; message.value = '' }
watch(() => [props.backend.state.scope, props.backend.state.auth, props.backend.runtimeReadable.value], clear, { flush:'sync' })
watch(project, () => { ++generation; options.value = null; selected.value = ''; requestedUntil.value = ''; message.value = '' }, { flush:'sync' })
onBeforeUnmount(clear)
async function importMaterial() {
  if (!canImportMaterial.value) return
  const token = generation, scope = props.backend.state.scope, content = materialText.value, operationId = operationIdV1()
  busy.value = true
  let dispatched = false
  try {
    const inputDigest = await props.backend.ownerMaterials.prepare(scope, content, operationId)
    if (!current(token, scope)) return
    props.backend.ownerMaterials.attempts.set(scope, { scope, operationId, inputDigest })
    materialText.value = ''; materialStatus.value = null; dispatched = true
    message.value = '正在保存 Owner 材料来源原件，不会外发或自动重试。'
    const receipt = await props.backend.ownerMaterials.submit(scope, content, operationId)
    if (!current(token, scope)) return
    options.value = null; selected.value = ''; requestedUntil.value = ''
    message.value = '材料来源原件已保存（操作 ' + receipt.operation_id + '）。请只读核验实际Source，再重新读取任务选择项；此结果不授权执行。'
  } catch { if (token === generation) message.value = dispatched
    ? '材料保存结果尚未确认，原操作ID和摘要已保留，原文已清空；只能查询原操作，不重新发送原文。'
    : '材料尚未发送：请输入非空原文，并使完整请求符合现有64KiB命令上限。未截断原文，也未登记未知提交。'
  } finally { busy.value = false }
}
async function inspectMaterial() {
  if (!eligible.value || !materialAttempt.value) return
  const token = generation, scope = props.backend.state.scope, prior = materialAttempt.value
  busy.value = true; materialStatus.value = null; message.value = '正在只读核验原材料来源提交。'
  try { const data = await props.backend.ownerMaterials.status(scope, prior.operationId, prior.inputDigest)
    if (!current(token, scope) || materialAttempt.value?.operationId !== prior.operationId) return
    materialStatus.value = data
    if (data.state === 'accepted') { options.value = null; selected.value = ''; requestedUntil.value = ''
      message.value = '本次实际材料Source已核验。请重新读取任务选择项和当前来源许可，不会自动选择或执行。'
    } else message.value = '材料原请求尚未取得匹配确认，保留原UUID，只查询，不重发原文。'
  } catch { if (token === generation) message.value = '原材料Source状态未取得，可能缺少当前Owner、Source或原件资格；没有恢复旧正文或重新提交。' }
  finally { busy.value = false }
}
function beginAnotherMaterial() {
  if (!eligible.value || materialStatus.value?.state !== 'accepted') return
  props.backend.ownerMaterials.attempts.delete(props.backend.state.scope)
  materialStatus.value = null; materialText.value = ''
}
async function discover() {
  if (!eligible.value) return
  const token = generation, scope = props.backend.state.scope
  busy.value = true; projects.value = null; options.value = null; message.value = '正在读取当前获准项目目录。'
  try { const data = await props.backend.projectContext.read(scope); if (!current(token, scope)) return
    projects.value = data; message.value = data.items.length ? '选择真实项目，再读取来源便笺任务的兼容选择项。' : '当前没有可选择的获准项目。'
  } catch { if (token === generation) message.value = '当前项目目录未取得，请核验所有者会话、来源资格和实际运行状态。' }
  finally { busy.value = false }
}
async function readOptions() {
  if (!eligible.value || !knownProject.value) return
  const token = generation, scope = props.backend.state.scope, projectRef = project.value
  busy.value = true; options.value = null; selected.value = ''; requestedUntil.value = ''; message.value = '正在读取实际来源、角色和已注册 Body/effect policy。'
  try { const data = await props.backend.ownerTasks.options(scope, projectRef); if (!current(token, scope) || projectRef !== project.value) return
    options.value = data; message.value = data.items.length && data.deadline_upper_bound_utc !== null
      ? '请选择实际兼容组合，并明确任务截止时间。保存时后端还会重验当前权限与原期限。'
      : '当前没有可提交的兼容组合或原期限；不会填入示例来源、策略或权限。'
  } catch { if (token === generation) message.value = '任务选择项未取得，可能缺少当前来源、角色、策略或所有者权限。请明确重读。' }
  finally { busy.value = false }
}
async function submit() {
  if (!canSubmit.value || !options.value || !item.value) return
  const token = generation, scope = props.backend.state.scope
  busy.value = true
  try {
    const request = ownerTaskRequest(options.value, item.value, deadline.value), operationId = operationIdV1()
    const inputDigest = await ownerTaskInputDigest(request)
    if (!current(token, scope)) return
    props.backend.ownerTasks.attempts.set(scope, { scope, operationId, inputDigest })
    options.value = null; selected.value = ''; requestedUntil.value = ''; status.value = null
    message.value = '正在保存来源便笺管理任务，不会自动重发。'
    const receipt = await props.backend.ownerTasks.submit(scope, request, operationId)
    if (!current(token, scope)) return
    message.value = '任务原件已保存（操作 ' + receipt.operation_id + '）。这不表示已执行或已产生作品，请显式核验后台任务。'
  } catch { if (token === generation) message.value = '提交结果尚未确认，可能已经保存。原操作ID已保留；只能查询原请求，不会重发或自动换ID。' }
  finally { busy.value = false }
}
async function inspect() {
  if (!eligible.value || !attempt.value) return
  const token = generation, scope = props.backend.state.scope, prior = attempt.value
  busy.value = true; status.value = null; message.value = '正在只读核验原操作、任务阶段与原截止时间。'
  try { const data = await props.backend.ownerTasks.status(scope, prior.operationId, prior.inputDigest)
    if (!current(token, scope) || attempt.value?.operationId !== prior.operationId) return
    status.value = data; message.value = ['not_found','unknown','conflict'].includes(data.state)
      ? '原请求尚未取得匹配的确认结果。保持原操作ID，仅查询，不重新提交。'
      : '只读状态来自本次实际后台记录；原截止时间不因核验而延长，作品正文需另行打开核验。'
  } catch { if (token === generation) message.value = '原任务状态未取得；当前权限、来源或原件可能已变化。保留原操作ID，没有使用旧状态或重发任务。' }
  finally { busy.value = false }
}
function beginAnother() {
  if (!eligible.value || !terminal.value) return
  props.backend.ownerTasks.attempts.delete(props.backend.state.scope); status.value = null
  options.value = null; selected.value = ''; requestedUntil.value = ''; message.value = '请重新读取当前选择项，再明确提交另一项任务；原任务原件仍由后台保留。'
}
const time = (value: number) => new Date(value * 1000).toISOString()
</script>
<template>
  <section class="owner-source-note-task" aria-labelledby="owner-source-note-task-title" :aria-busy="busy">
    <h4 id="owner-source-note-task-title">保存来源便笺管理任务</h4>
    <p>使用已存在的真实来源和已注册策略。保存任务原件不等于执行完成，模型选择不会授予 Self、Body 或预算权限。</p>
    <p v-if="!backend.canRead.value" role="status">先核验当前所有者会话、角色范围和实际运行状态。</p>
    <div v-if="backend.canRead.value" class="owner-material-entry">
      <h5>导入你提供的材料</h5>
      <p>原文保存为 Owner authored Source，断言与独立性保留 unknown；不会伪装平台消息、C02 或客观事实，也不会外发。</p>
      <template v-if="materialAttempt">
        <p>材料原操作ID：<code>{{ materialAttempt.operationId }}</code>原文不会在 pending metadata 中保留。</p>
        <button :disabled="!eligible" @click="inspectMaterial">只读核验原材料Source（不重发原文）</button>
        <dl v-if="materialStatus"><div><dt>本次实际状态</dt><dd>{{ materialStatus.state === 'accepted' ? '材料Source已保存' : materialStatus.state === 'conflict' ? '原请求摘要冲突' : '尚未取得匹配确认' }}</dd></div>
          <div v-if="materialStatus.state === 'accepted'"><dt>实际Source / 版本</dt><dd>{{ materialStatus.source_id }} / {{ materialStatus.source_revision }}<code>{{ materialStatus.source_ref }}</code></dd></div>
        </dl>
        <button v-if="materialStatus?.state === 'accepted'" :disabled="!eligible" @click="beginAnotherMaterial">导入另一份材料</button>
      </template>
      <template v-else>
        <label for="owner-material-text">你的材料原文
          <textarea id="owner-material-text" v-model="materialText" rows="5" :disabled="busy" autocomplete="off"></textarea>
        </label>
        <p>{{ materialCharacters }} / {{ OWNER_MATERIAL_MAX_CHARACTERS }} 个Unicode字符 · {{ materialBytes }} 个UTF-8字节。完整命令仍受现有64KiB传输上限；原文不会自动裁剪。</p>
        <button :disabled="!canImportMaterial" @click="importMaterial">保存Owner材料Source原件</button>
      </template>
    </div>
    <template v-if="backend.canRead.value && attempt">
      <p role="status">原操作ID：<code>{{ attempt.operationId }}</code>提交结果或后台阶段尚待显式核验。</p>
      <button :disabled="!eligible" @click="inspect">只读核验原来源便笺任务（不重发）</button>
      <dl v-if="status" class="owner-task-status">
        <div><dt>本次实际状态</dt><dd>{{ stateLabels[status.state] }}</dd></div>
        <div><dt>实际 job / 阶段</dt><dd>{{ status.job_id ?? '尚未取得 job 原件' }} / {{ status.job_phase === 'draining' ? '取消处理中' : status.job_phase ?? '未观察到阶段' }}</dd></div>
        <div><dt>实际步骤</dt><dd>{{ status.step ?? '未观察到步骤' }}</dd></div>
        <div><dt>当前等待依据</dt><dd>{{ status.wait_reason ?? '本次未返回等待原因' }}</dd></div>
        <div><dt>仍待核验的实际 effect</dt><dd>{{ status.pending_effect_refs.length }}<code v-for="ref in status.pending_effect_refs" :key="ref">{{ ref }}</code></dd></div>
        <div><dt>原截止时间 UTC</dt><dd>{{ status.original_deadline_utc === null ? '未取得原期限' : time(status.original_deadline_utc) }}</dd></div>
      </dl>
      <button v-if="terminal" :disabled="!eligible" @click="beginAnother">另建一项任务（重新读取当前选择项）</button>
    </template>
    <template v-else-if="backend.canRead.value">
      <button :disabled="!eligible" @click="discover">读取任务所属项目</button>
      <label v-if="projects?.items.length" for="owner-task-project">实际项目
        <select id="owner-task-project" v-model="project" :disabled="busy"><option value="">请选择项目</option>
          <option v-for="(value,index) in projects.items" :key="value.project_ref" :value="value.project_ref">项目 {{ index + 1 }} · {{ value.project_ref }}</option>
        </select>
      </label>
      <button v-if="knownProject" :disabled="!eligible" @click="readOptions">读取来源便笺任务选择项</button>
      <template v-if="options?.items.length && options.deadline_upper_bound_utc !== null">
        <label for="owner-task-selectors">实际来源、角色与策略组合
          <select id="owner-task-selectors" v-model="selected" :disabled="busy"><option value="">请选择已读取的兼容组合</option>
            <option v-for="(value,index) in options.items" :key="index" :value="String(index)">来源 {{ index + 1 }} · {{ value.body_source_ref }} · {{ value.body_policy_id }} v{{ value.body_policy_version }}</option>
          </select>
        </label>
        <details v-if="selected !== '' && item"><summary>查看本次实际选择项</summary><dl>
          <div><dt>来源</dt><dd>{{ item.body_source_ref }}</dd></div><div><dt>Recipe</dt><dd>{{ item.recipe_ref }}</dd></div>
          <div><dt>目标实体 / 角色绑定</dt><dd>{{ item.target_entity_ref }} / {{ item.role_binding_ref }}</dd></div>
          <div><dt>Body / effect policy</dt><dd>{{ item.body_policy_id }} v{{ item.body_policy_version }} / {{ item.effect_policy_ref }}</dd></div>
        </dl></details>
        <label for="owner-task-deadline">明确任务截止时间（当前设备本地时间）
          <input id="owner-task-deadline" v-model="requestedUntil" type="datetime-local" :disabled="busy">
        </label>
        <p>本次原件上限 UTC：{{ time(options.deadline_upper_bound_utc) }}。后端将取实际 Root、角色、策略及请求原期限的交集；核验不会续期。</p>
        <button class="save-owner-task" :disabled="!canSubmit" @click="submit">保存来源便笺任务原件</button>
      </template>
    </template>
    <p v-if="message" role="status" aria-live="polite">{{ message }}</p>
  </section>
</template>
<style scoped>
.owner-source-note-task{margin-top:24px;border-top:1px solid var(--line);padding-top:20px;font-size:12px;line-height:1.8;overflow-wrap:anywhere}.owner-source-note-task h4{font-size:16px;font-weight:500;margin:0 0 12px}.owner-source-note-task p{color:var(--muted)}label{display:grid;gap:8px;margin:14px 0}select,input,textarea{width:100%;max-width:100%;min-width:0;box-sizing:border-box;min-height:44px;padding:10px;font:inherit;background:var(--surface);color:var(--ink);border:1px solid var(--line);border-radius:3px}textarea{resize:vertical;line-height:1.8}.owner-material-entry{margin:18px 0;padding:14px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.owner-material-entry h5{font-size:14px;font-weight:500;margin:0 0 10px}button{min-height:44px;font:inherit;text-align:left;padding:10px 0;cursor:pointer}button:disabled{cursor:default;color:var(--muted)}.save-owner-task{display:block;width:100%;border-top:1px solid var(--line)}dl{margin:12px 0}dl>div{display:grid;grid-template-columns:minmax(80px,1fr) minmax(0,2fr);gap:10px;border-bottom:1px solid var(--line);padding:10px 0}dt{color:var(--muted)}dd{margin:0;min-width:0}code{display:block;overflow-wrap:anywhere;font-size:10px}button:focus-visible,select:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--ink);outline-offset:3px}
</style>
