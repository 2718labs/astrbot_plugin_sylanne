<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import RoleSetup from './components/RoleSetup.vue'
import OwnerAccess from './components/OwnerAccess.vue'
import D04Initialization from './components/D04Initialization.vue'
import LifeArchiveCore, { type ArchiveEntry } from './components/archive/LifeArchiveCore.vue'

const API = '/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1'
type Status = { schema_version: string; runtime_stage: string; reason_code: string }
type Session = { status?: string; owner_session?: string; csrf_token?: string; problem?: { code?: string; message?: string } }
type Workspace = { status?: string; projection?: { namespace?: { bot: string; persona: string }; access_generation?: number; views?: Array<{ view_type: string; status: string; snapshot_epoch?: number }>; view_diagnostics?: Array<{ view_type: string; read_status: string; coverage?: string; problem_code?: string }>; unavailable_domains?: Record<string, string> }; problem?: { code?: string; message?: string } }
type ViewResult = { status?: 'loading' | 'empty' | 'unauthorized' | 'stale' | 'partial' | 'unavailable' | 'ready'; projection?: { view_type?: string; namespace?: { bot?: string; persona?: string }; data?: Record<string, unknown>; access_generation?: number; snapshot_epoch?: number; coverage?: { requested_types?: string[]; returned_atoms?: number; truncated?: boolean }; next_cursor?: string | null }; problem?: { code?: string; message?: string } }

const page = ref<'archive' | 'status' | 'initialization'>('archive')
const status = ref<Status | null>(null)
const statusProblem = ref('')
const ownerSession = ref<Session | null>(null)
const ownerProblem = ref('')
const csrf = ref('')
const scope = ref('')
const workspace = ref<Workspace | null>(null)
const workspaceBusy = ref(false)
const workspaceProblem = ref('')
const selectedView = ref('')
const selectedProjection = ref<ViewResult | null>(null)
const viewBusy = ref(false)
const viewProblem = ref('')
const viewCursor = ref<string | null>(null)
const requestGeneration = ref(0)
const stageLabel = computed(() => ({ limited: '受限运行', blocked: '运行受阻', enrollment_required: '等待安装登记', ready: '运行就绪', stopped: '已停止' } as Record<string, string>)[status.value?.runtime_stage ?? ''] ?? '状态未知')
const selectedDiagnostic = computed(() => workspace.value?.projection?.view_diagnostics?.find(item => item.view_type === selectedView.value))
const archiveEntries = computed<ArchiveEntry[]>(() => (workspace.value?.projection?.views ?? []).map(view => ({
  id: view.view_type,
  label: view.view_type,
  status: view.status === 'available' ? 'available' : 'unavailable',
  detail: selectedView.value === view.view_type && selectedDiagnostic.value
    ? `READ ${selectedDiagnostic.value.read_status} · COVERAGE ${selectedDiagnostic.value.coverage ?? 'NOT DISCLOSED'}${selectedDiagnostic.value.problem_code ? ` · ${selectedDiagnostic.value.problem_code}` : ''}`
    : undefined,
})))

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API}${path}`, { credentials: 'same-origin', cache: 'no-store' })
  if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('W10 API unavailable: expected JSON response')
  const data = await response.json().catch(() => ({})) as T
  if (!response.ok) throw Object.assign(new Error((data as { problem?: { message?: string; code?: string } }).problem?.message ?? `HTTP ${response.status}`), { code: (data as { problem?: { code?: string } }).problem?.code })
  return data
}

async function refresh() {
  const generation = ++requestGeneration.value
  viewBusy.value = false
  workspaceBusy.value = false
  selectedProjection.value = null
  statusProblem.value = ''
  ownerProblem.value = ''
  const [s, o] = await Promise.allSettled([getJson<Status>('/status'), getJson<Session>('/session')])
  if (generation !== requestGeneration.value) return
  if (s.status === 'fulfilled' && s.value.schema_version === 'sylanne.install-status.v1') status.value = s.value
  else if (s.status === 'fulfilled') statusProblem.value = 'W10 status payload schema is unavailable'
  else statusProblem.value = s.reason instanceof Error ? s.reason.message : '安装状态暂不可用'
  if (o.status === 'fulfilled' && o.value.status === 'ready') { ownerSession.value = o.value; csrf.value = o.value.csrf_token ?? '' }
  else if (o.status === 'fulfilled') { ownerSession.value = o.value; csrf.value = ''; ownerProblem.value = o.value.problem?.message ?? 'Owner session is locked' }
  else { ownerSession.value = null; csrf.value = ''; ownerProblem.value = o.reason instanceof Error ? o.reason.message : 'Owner 会话状态暂不可用'; workspace.value = null; selectedProjection.value = null }
  if (!csrf.value) { workspace.value = null; selectedProjection.value = null }
}

function invalidateScope() {
  requestGeneration.value++
  workspaceBusy.value = false
  workspace.value = null
  workspaceProblem.value = ''
  selectedView.value = ''
  selectedProjection.value = null
  viewProblem.value = ''
  viewCursor.value = null
  viewBusy.value = false
}

async function openWorkspace() {
  const generation = ++requestGeneration.value
  viewBusy.value = false
  workspace.value = null
  workspaceProblem.value = ''
  selectedProjection.value = null
  viewProblem.value = ''
  viewCursor.value = null
  const normalizedScope = scope.value.trim()
  if (!/^[^/\s]+\/[^/\s]+$/.test(normalizedScope)) { workspaceProblem.value = '请填写已授权的 bot/persona 范围；此处不会创建角色或授权。'; return }
  if (!csrf.value) { workspaceProblem.value = 'Owner 会话锁定；解锁后才能读取工作区目录。'; return }
  workspaceBusy.value = true
  try {
    const response = await fetch(`${API}/commands`, { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'content-type': 'application/json', 'x-csrf-token': csrf.value }, body: JSON.stringify({ schema_version: 'd12.contract.v1', action: 'open_workspace', scope: normalizedScope, purpose: 'workbench_view', audience: 'owner', operation_id: crypto.randomUUID(), input: { client_protocol: 'd12.contract.v1' } }) })
    const data = await response.json() as Workspace
    if (generation !== requestGeneration.value) return
    if (!response.ok) throw Object.assign(new Error(data.problem?.message ?? `HTTP ${response.status}`), { data })
    if (data.status === 'unauthorized') {
      csrf.value = ''; ownerSession.value = null; ownerProblem.value = data.problem?.message ?? 'Owner 权限已撤销'; workspace.value = null
      return
    }
    workspace.value = data
    selectedView.value = data.projection?.views?.[0]?.view_type ?? ''
  } catch (error) {
    if (generation !== requestGeneration.value) return
    workspaceProblem.value = error instanceof Error ? error.message : '工作区目录暂不可用'
    const failure = error as Error & { data?: Workspace }
    if (failure.data?.status === 'unauthorized' || ['owner_session_locked', 'csrf_denied', 'capability_denied'].includes(failure.data?.problem?.code ?? '')) {
      csrf.value = ''; ownerSession.value = null; ownerProblem.value = failure.message; workspace.value = null
    }
  } finally { if (generation === requestGeneration.value) workspaceBusy.value = false }
}

function safeFieldName(name: string) {
  return !/(secret|token|password|private|credential|authorization|bearer|debug|raw)/i.test(name)
}

function boundedValue(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') return value.length > 400 ? `${value.slice(0, 400)}…` : value
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value
  if (Array.isArray(value)) return value.slice(0, 8).map(item => boundedValue(item, depth + 1)).concat(value.length > 8 ? ['…'] : [])
  if (typeof value === 'object') {
    if (depth >= 2) return '[nested value omitted]'
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).filter(([key]) => safeFieldName(key)).slice(0, 12).map(([key, item]) => [key, boundedValue(item, depth + 1)]))
  }
  return '[unsupported value]'
}

function presentValue(value: unknown) {
  const bounded = boundedValue(value)
  return typeof bounded === 'string' ? bounded : JSON.stringify(bounded)
}

function selectView(viewType: string) {
  requestGeneration.value++
  workspaceBusy.value = false
  viewBusy.value = false
  selectedView.value = selectedView.value === viewType ? '' : viewType
  selectedProjection.value = null
  viewCursor.value = null
  viewProblem.value = ''
}

async function readCharacterView(viewType: string, cursor: string | null = null) {
  const generation = ++requestGeneration.value
  const requestedScope = scope.value.trim()
  const catalogueEntry = workspace.value?.projection?.views?.find(item => item.view_type === viewType)
  selectedView.value = viewType
  selectedProjection.value = null
  viewCursor.value = null
  viewProblem.value = ''
  if (!catalogueEntry || catalogueEntry.status !== 'available') { viewProblem.value = '视图未由当前服务端目录标记为可读取。'; return }
  if (!csrf.value) { viewProblem.value = 'Owner 会话锁定；读取请求未发送。'; return }
  viewBusy.value = true
  try {
    const response = await fetch(`${API}/commands`, { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'content-type': 'application/json', 'x-csrf-token': csrf.value }, body: JSON.stringify({ schema_version: 'd12.contract.v1', action: 'read_character_view', scope: requestedScope, purpose: 'workbench_view', audience: 'owner', operation_id: crypto.randomUUID(), input: { view_type: viewType, ...(cursor ? { cursor } : {}) } }) })
    if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('W10 API unavailable: expected JSON response')
    const data = await response.json() as ViewResult
    if (generation !== requestGeneration.value || requestedScope !== scope.value.trim() || selectedView.value !== viewType) return
    if (!response.ok) throw Object.assign(new Error(data.problem?.message ?? `HTTP ${response.status}`), { data })
    if (!data.status || !['loading', 'empty', 'unauthorized', 'stale', 'partial', 'unavailable', 'ready'].includes(data.status)) throw new Error('W10 returned an unknown projection state')
    if (data.status === 'unauthorized') {
      requestGeneration.value++; viewBusy.value = false
      workspace.value = null; selectedProjection.value = null; viewCursor.value = null
      csrf.value = ''; ownerSession.value = null; ownerProblem.value = data.problem?.message ?? 'Owner 权限已撤销'
      viewProblem.value = ownerProblem.value
      return
    }
    if (data.status === 'ready' && (data.projection?.view_type !== viewType || data.projection?.namespace?.bot !== requestedScope.split('/')[0] || data.projection?.namespace?.persona !== requestedScope.split('/')[1])) throw new Error('W10 projection scope or view did not match the request')
    selectedProjection.value = data
    if (data.status !== 'ready') viewProblem.value = data.problem?.message ?? ({ empty: '该视图当前为空。', stale: '视图快照已过期；请重新打开工作区后再读取。', partial: '服务端返回部分状态；本页不会拼接或保留多页数据。', unauthorized: '当前 Owner 无权读取此视图。', unavailable: '该视图当前不可用。', loading: '视图仍在载入。' } as Record<string, string>)[data.status] ?? '投影不可用。'
    viewCursor.value = data.status === 'ready' ? data.projection?.next_cursor ?? null : null
  } catch (error) {
    if (generation !== requestGeneration.value || requestedScope !== scope.value.trim() || selectedView.value !== viewType) return
    viewProblem.value = error instanceof Error ? error.message : '投影读取暂不可用'
    const failure = error as Error & { data?: ViewResult }
    if (failure.data?.status === 'unauthorized' || ['owner_session_locked', 'csrf_denied', 'capability_denied', 'owner_scope_denied'].includes(failure.data?.problem?.code ?? '')) {
      requestGeneration.value++; viewBusy.value = false
      workspace.value = null; selectedProjection.value = null; viewCursor.value = null
      csrf.value = ''; ownerSession.value = null; ownerProblem.value = failure.message
    }
  } finally { if (generation === requestGeneration.value) viewBusy.value = false }
}

onMounted(() => { void refresh() })
</script>

<template>
  <div class="shell">
    <header class="topbar">
      <a class="wordmark" href="#/archive" @click.prevent="page = 'archive'"><svg viewBox="0 0 36 36" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 3.5c7.9 0 14.5 6.4 14.5 14.4S26 32.5 18 32.5 3.5 26 3.5 18 10 3.5 18 3.5Z"/><path d="M10 20.8c2.3-7.4 4.9-9.7 8-6.9 3.5 3.1 5.9 2.8 8-.8M10.8 25c2.2 1.2 4.6 1.7 7.1 1.4"/><circle cx="18" cy="18" r="2.2" fill="currentColor"/></svg>SYLANNE<span> / EMBODIMENT</span></a>
      <div class="top-status"><i :class="['lamp', status?.runtime_stage === 'ready' ? 'ready' : '']"></i>{{ stageLabel }}</div>
    </header>
    <nav class="rail" aria-label="工作台导航">
      <button :class="{ active: page === 'archive' }" @click="page = 'archive'"><b>01</b><span>档案阵列</span></button>
      <button :class="{ active: page === 'status' }" @click="page = 'status'"><b>02</b><span>运行状态</span></button>
      <button :class="{ active: page === 'initialization' }" @click="page = 'initialization'"><b>03</b><span>核心初始化</span></button>
      <div class="rail-caption">SYLANNE LAB · ALPHA 1</div>
    </nav>
    <main>
      <section v-show="page === 'archive'" class="archive page">
        <div class="eyebrow">WORKBENCH / ARCHIVE INDEX</div>
        <h1>工作台档案阵列</h1>
        <p class="lead">从服务器读取当前授权范围的目录与投影。档案条目只读；下方初始化与场景绑定须明确提交，感受核心在独立页面逐步配置。</p>
        <div class="owner-lock"><span class="lock-icon">⌑</span><div><strong>OWNER SESSION · {{ csrf ? 'UNLOCKED' : 'LOCKED' }}</strong><p>{{ csrf ? '已取得当前会话 CSRF 令牌，目录请求由服务端再次核验授权。' : (ownerProblem || '独立 Owner 签名会话未解锁。当前仅展示安装状态。') }}</p></div><button class="quiet" @click="refresh">刷新会话</button></div>
        <OwnerAccess :unlocked="Boolean(csrf)" @ready="refresh" @locked="() => { csrf = ''; ownerSession = null; invalidateScope() }" />
        <div class="archive-grid">
          <section class="scope-panel panel">
            <div class="section-index">A / SCOPE</div><h2>定位已授权范围</h2>
            <label for="scope">Bot / Persona</label>
            <div class="scope-entry"><input id="scope" v-model="scope" placeholder="bot-id/persona-id" autocomplete="off" @input="invalidateScope" @keydown.enter="openWorkspace"/><button class="accent" :disabled="workspaceBusy" @click="openWorkspace">{{ workspaceBusy ? '读取中…' : '读取目录' }}</button></div>
            <p class="hint">范围必须来自现有 Owner 授权。服务器不提供角色清单，因此不会预填虚构档案。</p>
            <div v-if="workspaceProblem" class="notice">{{ workspaceProblem }}</div>
            <div v-if="workspace?.projection" class="namespace"><span>ACTIVE NAMESPACE</span><strong>{{ workspace.projection.namespace?.bot }} / {{ workspace.projection.namespace?.persona }}</strong><small>授权代数 {{ workspace.projection.access_generation ?? '未披露' }}</small></div>
          </section>
          <section class="catalog-panel panel">
            <div class="section-index">B / CATALOGUE</div><h2>可读视图</h2>
            <div v-if="!workspace" class="empty-state"><span>◇</span><strong>等待真实目录</strong><p>Owner 解锁并读取已授权范围后，服务端返回的视图才会出现在这里。</p></div>
            <div v-else-if="workspace.status !== 'ready'" class="notice">目录不可用：{{ workspace.problem?.code ?? workspace.status }} · {{ workspace.problem?.message ?? '服务端未返回就绪投影。' }}</div>
            <template v-else>
              <LifeArchiveCore :entries="archiveEntries" :selected-id="selectedView" :loading="viewBusy" :read-status="selectedProjection?.status" @select="selectView" @open="readCharacterView" />
              <p v-if="viewProblem" class="notice">{{ viewProblem }}</p>
              <div v-if="selectedProjection?.status === 'ready' && selectedProjection.projection" class="projection-result"><div class="projection-meta">{{ selectedProjection.projection.view_type }} · EPOCH {{ selectedProjection.projection.snapshot_epoch ?? '—' }} · GENERATION {{ selectedProjection.projection.access_generation ?? '—' }}</div><div v-if="selectedProjection.projection.coverage" class="projection-meta">{{ selectedProjection.projection.coverage.returned_atoms ?? 0 }} atoms · {{ selectedProjection.projection.coverage.truncated ? 'PAGE TRUNCATED' : 'PAGE COMPLETE' }}</div><dl v-if="selectedProjection.projection.data && Object.keys(selectedProjection.projection.data).some(safeFieldName)" class="projection-data"><div v-for="([key, value]) in Object.entries(selectedProjection.projection.data).filter(([name]) => safeFieldName(name)).slice(0, 12)" :key="key"><dt>{{ key }}</dt><dd>{{ presentValue(value) }}</dd></div></dl><p v-else class="empty-state">服务端投影没有可展示字段。</p><button v-if="viewCursor" class="quiet view-read" :disabled="viewBusy" @click="readCharacterView(selectedView, viewCursor)">读取下一页（替换当前页）</button></div>
              <p v-else-if="selectedProjection?.status === 'empty'" class="empty-state">此视图当前没有内容。</p>
              <div v-else-if="selectedDiagnostic" class="projection-meta">CATALOG READ {{ selectedDiagnostic.read_status }} · COVERAGE {{ selectedDiagnostic.coverage ?? 'NOT DISCLOSED' }}<template v-if="selectedDiagnostic.problem_code"> · PROBLEM {{ selectedDiagnostic.problem_code }}</template></div>
              <div v-if="!(workspace.projection?.views?.length)" class="empty-state"><strong>暂无可读视图</strong><p>服务器返回空目录。</p></div>
              <div v-for="(reason, domain) in workspace.projection?.unavailable_domains ?? {}" :key="domain" class="unavailable"><span>{{ domain }}</span><b>UNAVAILABLE</b><small>{{ reason }}</small></div>
            </template>
          </section>
        </div>
        <RoleSetup :scope="scope" :csrf="csrf" :session-epoch="requestGeneration" @locked="message => { csrf = ''; ownerSession = null; ownerProblem = message; workspace = null; selectedProjection = null }" />
        <div class="capability-strip"><span>当前页面能力</span><b>安装状态：只读</b><b>视图目录：只读</b><b>角色内容：授权视图只读</b><b>初始化 / 场景绑定：明确提交并等待权威回执</b></div>
      </section>
      <section v-show="page === 'status'" class="page status-page">
        <div class="eyebrow">WORKBENCH / INSTALLATION</div><h1>真实运行状态</h1><p class="lead">状态来自当前 W10 安装状态端点；本页不以 UI 动画或本地缓存推断运行健康。</p>
        <div class="status-card panel"><div class="status-large"><i :class="['lamp', status?.runtime_stage === 'ready' ? 'ready' : '']"></i><div><span>RUNTIME STAGE</span><strong>{{ status?.runtime_stage ?? 'UNAVAILABLE' }}</strong><small>{{ stageLabel }}</small></div></div><div class="status-fields"><div><span>SCHEMA</span><b>{{ status?.schema_version ?? '—' }}</b></div><div><span>REASON CODE</span><b>{{ status?.reason_code ?? (statusProblem || '—') }}</b></div><div><span>OWNER SESSION</span><b>{{ ownerSession?.owner_session ?? (ownerProblem || 'LOCKED') }}</b></div></div><button class="quiet" @click="refresh">重新读取状态</button></div>
        <p class="status-note">状态值由宿主返回。若请求失败，界面会保留为不可用，不会使用开发模拟数据填充。</p>
      </section>
      <D04Initialization v-show="page === 'initialization'" :scope="scope" :csrf="csrf" :session-epoch="requestGeneration" @locked="message => { csrf = ''; ownerSession = null; ownerProblem = message; workspace = null; selectedProjection = null }" />
    </main>
    <footer><span>SYLANNE LAB · LOCAL WORKBENCH</span><span>ALPHA 1 · OWNER WORKBENCH</span></footer>
  </div>
</template>

<style>
:root{--bg:#131b1c;--text:#eef3ef;--text-muted:#9aa9a4;--accent:#ce984b;--accent-rgb:206,152,75;--glow:rgba(206,152,75,.18);--font-head:'Segoe UI',Arial,sans-serif;--font-mono:Consolas,'Courier New',monospace}
*{box-sizing:border-box}html,body{min-height:100%;background:var(--bg);color:var(--text);font-family:var(--font-head)}body{background-image:linear-gradient(90deg,transparent 0 49.9%,rgba(119,166,150,.035) 50%,transparent 50.1%),radial-gradient(ellipse at 78% 15%,#30413d55,transparent 44%)}#app{height:100vh;overflow:auto}.shell{min-height:100vh;padding:0 5vw 64px 132px}.topbar{height:76px;border-bottom:1px solid #ffffff18;display:flex;align-items:center;justify-content:space-between}.wordmark{display:flex;align-items:center;gap:12px;font-size:16px;letter-spacing:.21em;color:#eff4ef;text-decoration:none;font-weight:700}.wordmark svg{width:28px;height:28px;color:var(--accent)}.wordmark span{font:10px var(--font-mono);color:#8ca49a;letter-spacing:.16em}.top-status{font:10px var(--font-mono);letter-spacing:.12em;color:#b7c5be;display:flex;align-items:center;gap:10px;text-transform:uppercase}.lamp{width:8px;height:8px;border-radius:50%;display:inline-block;background:#d7a95c;box-shadow:0 0 10px #d7a95c66}.lamp.ready{background:#70c2a2;box-shadow:0 0 12px #70c2a288}.rail{position:fixed;left:0;top:0;bottom:0;width:98px;border-right:1px solid #ffffff18;padding:102px 10px 22px;display:flex;flex-direction:column;gap:8px;background:#111819e8;z-index:2}.rail button{background:transparent;border:1px solid transparent;color:#9aa7a2;padding:12px 10px;text-align:left;display:flex;flex-direction:column;gap:7px;transition:.2s}.rail button b{font:10px var(--font-mono);color:#d2a45d}.rail button span{font-size:12px}.rail button.active{border-color:#d0a45c66;background:#d0a45c18;color:#eef4ef;box-shadow:inset 2px 0 #69bba5}.rail-caption{margin-top:auto;writing-mode:vertical-rl;color:#687b73;font:9px var(--font-mono);letter-spacing:.16em}.page{max-width:1280px;margin:22px auto 0}.eyebrow,.section-index{font:9px var(--font-mono);letter-spacing:.2em;color:#d2a45d;text-transform:uppercase}.page h1{font-size:32px;letter-spacing:.045em;font-weight:600;margin:8px 0 6px;color:#f3f6f2}.lead{max-width:770px;color:#aebcb5;line-height:1.55;font-size:13px;margin:0 0 12px}.owner-lock{display:flex;align-items:center;gap:16px;border:1px solid #ffffff;background:linear-gradient(105deg,#f5f2eb,#e7eee9);color:#21312d;padding:11px 20px;min-height:60px;box-shadow:0 12px 30px #0002;margin:0 0 12px;position:relative}.owner-lock:before{content:'SESSION / AUTHORITY';position:absolute;right:18px;top:9px;color:#84958c;font:8px var(--font-mono);letter-spacing:.15em}.lock-icon{font-size:20px;color:#458e79}.owner-lock strong{font:10px var(--font-mono);letter-spacing:.12em;color:#3f3729}.owner-lock p{color:#62716b;margin:5px 0 0;font-size:12px}.quiet,.accent{border:1px solid #b4a388;background:#f4f7f3;color:#34312b;padding:9px 13px;font:10px var(--font-mono);letter-spacing:.04em;transition:.18s}.quiet{margin-left:auto}.quiet:hover,.accent:hover{background:#d8e8df;border-color:#a97b3b}.accent{background:#a97b3b;border-color:#a97b3b;color:#f3f8f3;font-weight:600}.accent:disabled{opacity:.45}.archive-grid{display:grid;grid-template-columns:minmax(290px,.78fr) minmax(440px,1.22fr);gap:16px}.panel{border:0;background-color:#ebe7df;background-image:linear-gradient(#607e7110 1px,transparent 1px),linear-gradient(90deg,#607e7110 1px,transparent 1px),linear-gradient(145deg,#f5f2eb,#e9e4dc);background-size:24px 24px,24px 24px,auto;color:#2b2925;padding:16px;min-height:310px;box-shadow:0 18px 45px #0002;position:relative;overflow:hidden}.panel:after{content:'';position:absolute;right:0;top:0;width:24px;height:24px;border-top:2px solid #d0a45c;border-right:2px solid #d0a45c;pointer-events:none}.panel h2{font-weight:600;font-size:16px;margin:8px 0 21px;color:#21332d;letter-spacing:.02em}.panel .section-index{color:#a47634}.scope-panel label{display:block;color:#716b61;font:9px var(--font-mono);letter-spacing:.1em;margin-bottom:7px}.scope-entry{display:flex;gap:8px}.scope-entry .accent{white-space:nowrap;flex-shrink:0}.scope-entry input{width:100%;min-width:0;background:#f8f5ef;border:1px solid #c8c0b3;padding:12px;color:#34312b;font:12px var(--font-mono);outline:none}.scope-entry input:focus{border-color:#a97b3b;box-shadow:0 0 0 2px #a97b3b20}.hint{font-size:11px;line-height:1.65;color:#777167}.namespace{border-top:1px solid #cfc7bb;margin-top:24px;padding-top:15px;display:flex;flex-direction:column;gap:6px}.namespace span,.namespace small{color:#777167;font:9px var(--font-mono);letter-spacing:.08em}.namespace strong{font:12px var(--font-mono);color:#3f3729}.empty-state{min-height:166px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;color:#777167;font-size:12px}.empty-state>span{font-size:27px;color:#579881;margin-bottom:8px}.empty-state strong{font-size:13px;font-weight:600;color:#43574f}.empty-state p{max-width:280px;font-size:11px;line-height:1.6}.catalog-entry{border-bottom:1px solid #cfc7bb}.catalog-row{width:100%;display:grid;grid-template-columns:26px 1fr auto 16px;align-items:center;gap:11px;padding:13px 7px;color:#34312b;text-align:left;background:transparent;border:0;transition:.18s}.catalog-row:hover,.catalog-row.selected{background:#f2e5ce}.catalog-row:focus-visible{outline:2px solid #a47634;outline-offset:-2px}.row-mark{color:#a47634;font-size:17px}.row-name{font:12px var(--font-mono);color:#282724}.row-name small{display:block;font:10px var(--font-head);color:#777167;margin-top:4px}.row-meta,.chevron{font:9px var(--font-mono);color:#777167}.row-detail{display:block;margin:0 8px 12px 44px;color:#655f53;font-size:11px;line-height:1.6}.diagnostic{display:block;margin:2px 0 4px;color:#8e672f;font:9px var(--font-mono);letter-spacing:.04em}.notice{border-left:2px solid #b08a44;padding:9px 12px;color:#66522f;background:#f2ead7;font-size:11px;line-height:1.6;margin:9px 0}.view-read{display:inline-block;margin:8px 0 6px}.projection{border-top:1px solid #cfc7bb;margin-top:9px;padding-top:11px}.projection-meta{color:#777167;font:9px var(--font-mono);margin:6px 0}.projection-data{margin:10px 0 4px}.projection-data div{padding:8px 0;border-bottom:1px solid #cfc7bb}.projection-data dt{color:#966d33;font:9px var(--font-mono);letter-spacing:.07em;margin-bottom:4px}.projection-data dd{margin:0;color:#37342e;font-size:11px;line-height:1.6;overflow-wrap:anywhere}.unavailable{display:grid;grid-template-columns:1fr auto;gap:5px;padding:11px 5px;border-bottom:1px solid #cfc7bb;font:10px var(--font-mono)}.unavailable span{color:#554f45}.unavailable b{color:#a27b35;font-size:9px}.unavailable small{grid-column:1/-1;color:#738078}.capability-strip{display:flex;gap:16px;flex-wrap:wrap;border-top:1px solid #ffffff20;margin-top:18px;padding:14px 0;color:#95a69d;font:9px var(--font-mono)}.capability-strip b{font-weight:400;color:#e0d8cb}.status-card{max-width:820px}.status-card .quiet{margin-left:0}.status-large{display:flex;gap:15px;align-items:center;padding:12px 0 21px;border-bottom:1px solid #cfc7bb}.status-large .lamp{width:10px;height:10px}.status-large div{display:flex;flex-direction:column;gap:5px}.status-large span,.status-fields span{font:9px var(--font-mono);letter-spacing:.14em;color:#777167}.status-large strong{font:25px var(--font-mono);color:#34312b}.status-large small{color:#777167;font-size:11px}.status-fields{display:grid;grid-template-columns:1fr 1fr;gap:18px;padding:18px 0}.status-fields div{display:flex;flex-direction:column;gap:7px}.status-fields b{font:11px var(--font-mono);color:#37342e;overflow-wrap:anywhere}.status-note{color:#a5b4ac;font-size:11px;margin-top:14px}footer{position:fixed;bottom:0;left:98px;right:0;height:36px;border-top:1px solid #ffffff18;background:#111819ee;display:flex;align-items:center;justify-content:space-between;padding:0 5vw;color:#73847b;font:8px var(--font-mono);letter-spacing:.12em;z-index:3}@media(max-width:900px){.shell{padding:0 22px 62px 90px}.rail{width:70px;padding:90px 5px 18px}.rail button{padding:10px 6px}.rail button span{font-size:10px}.archive-grid{grid-template-columns:1fr}.page{margin-top:32px}.catalog-panel{min-height:240px}}@media(max-width:560px){.shell{padding:0 13px 60px 62px}.rail{width:52px}.topbar{height:62px}.wordmark{font-size:13px;letter-spacing:.11em}.wordmark svg{width:24px}.wordmark span{display:none}.top-status{font-size:8px}.page{margin-top:25px}.page h1{font-size:25px}.lead{font-size:12px}.owner-lock{align-items:flex-start;flex-wrap:wrap;padding:14px}.owner-lock:before{display:none}.owner-lock .quiet{margin-left:37px}.archive-grid{gap:11px}.panel{padding:16px}.scope-entry{flex-wrap:wrap}.scope-entry .accent{width:100%}.row-meta{display:none}.catalog-row{grid-template-columns:22px 1fr 15px}footer{left:52px;padding:0 12px;font-size:7px}.status-fields{grid-template-columns:1fr}}
</style>






