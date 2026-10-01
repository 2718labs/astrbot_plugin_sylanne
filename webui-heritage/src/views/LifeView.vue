<script setup lang="ts">
// Life simulation observation panel. Old dashboard (UI/index.html, pre-rebuild
// — see git history at 0ab2671/1f8a21f) refreshed this page on its OWN 30s
// timer while the tab was active (lifeTickId), separate from the 5s
// /api/state poll. Reproduced here: onMounted does an immediate fetch of all
// four /api/life/* endpoints, then a 30s setInterval; cleared onUnmounted.
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { apiFetch } from '../api/client'
import { num } from '../composables/useAdapt'
import { useI18n } from '../composables/useI18n'
import {
  conciseFeedbackError,
  useInteractionFeedback,
} from '../composables/useInteractionFeedback'
import type {
  LifeAuditEntry,
  LifeAuditResponse,
  LifeEvent,
  LifeEventsResponse,
  LifeProject,
  LifeProjectsResponse,
  LifeSkill,
  LifeStatusResponse,
  SettingsResponse,
} from '../api/types'
import Card from '../components/ui/Card.vue'
import Badge from '../components/ui/Badge.vue'
import BarRow from '../components/ui/BarRow.vue'
import StatGrid from '../components/ui/StatGrid.vue'
import Timeline, { type TimelineItem } from '../components/ui/Timeline.vue'
import EmptyState from '../components/ui/EmptyState.vue'
import Toggle from '../components/ui/Toggle.vue'
import Select from '../components/ui/Select.vue'
import Button from '../components/ui/Button.vue'
import Modal from '../components/ui/Modal.vue'

const { t } = useI18n()
const feedback = useInteractionFeedback()

// ---- data: own 30s poll of /api/life/* (status/events/projects/audit) ----

const status = ref<LifeStatusResponse | null>(null)
const events = ref<LifeEventsResponse | null>(null)
const projects = ref<LifeProjectsResponse | null>(null)
const audit = ref<LifeAuditResponse | null>(null)
const fetchError = ref('')
// Set once the first fetchAll() has settled (any outcome), so a persistently
// failing /api/life/status alone doesn't leave the whole page stuck on the
// loading spinner forever — the other three panels degrade independently.
const attempted = ref(false)

let timer: number | null = null
let inflight = false

async function fetchAll(): Promise<void> {
  if (inflight) return
  inflight = true
  try {
    // allSettled, not all — one 5xx (e.g. audit endpoint down) must not blank
    // the other three panels. Each settled result is applied independently;
    // a rejected one just leaves its ref as whatever it last held (its own
    // EmptyState/loading branch handles null).
    const [s, e, p, a] = await Promise.allSettled([
      apiFetch<LifeStatusResponse>('/api/life/status'),
      apiFetch<LifeEventsResponse>('/api/life/events'),
      apiFetch<LifeProjectsResponse>('/api/life/projects'),
      apiFetch<LifeAuditResponse>('/api/life/audit'),
    ])
    if (s.status === 'fulfilled') status.value = s.value
    if (e.status === 'fulfilled') events.value = e.value
    if (p.status === 'fulfilled') projects.value = p.value
    if (a.status === 'fulfilled') audit.value = a.value
    const firstRejected = [s, e, p, a].find((r) => r.status === 'rejected') as
      | PromiseRejectedResult
      | undefined
    fetchError.value = firstRejected
      ? firstRejected.reason instanceof Error
        ? firstRejected.reason.message
        : 'fetch failed'
      : ''
  } finally {
    attempted.value = true
    inflight = false
  }
}

function start(): void {
  stop()
  void fetchAll()
  timer = window.setInterval(() => void fetchAll(), 30000)
}
function stop(): void {
  if (timer !== null) {
    clearInterval(timer)
    timer = null
  }
}

onMounted(start)
onUnmounted(stop)

// ---- initial control values: GET /api/settings ONCE on mount ----

const enabled = ref(false)
const shareIntensity = ref('standard')

onMounted(async () => {
  try {
    const settings = await apiFetch<SettingsResponse>('/api/settings')
    const values = settings.values || {}
    enabled.value = !!values['sylanne_alpha_life_simulation_enabled']
    const iv = String(values['sylanne_alpha_life_simulation_share_intensity'] || 'standard')
    if (['off', 'low', 'standard', 'high'].includes(iv)) shareIntensity.value = iv
  } catch {
    // keep defaults; controls still usable, just unseeded
  }
})

const shareIntensityOptions = [
  { label: 'off', value: 'off' },
  { label: 'low', value: 'low' },
  { label: 'standard', value: 'standard' },
  { label: 'high', value: 'high' },
]

// ---- view models ----

const available = computed(() => status.value?.available === true)

// Old lifeRelTime(): s/m/h/d relative age from a unix-seconds timestamp.
function relTime(ts: number): string {
  if (!ts) return '—'
  const now = Date.now() / 1000
  const diff = Math.max(0, now - ts)
  if (diff < 60) return Math.floor(diff) + 's'
  if (diff < 3600) return Math.floor(diff / 60) + 'm'
  if (diff < 86400) return Math.floor(diff / 3600) + 'h'
  return Math.floor(diff / 86400) + 'd'
}

// relTime() + ' ago', but omitting the suffix when there's no timestamp to
// be "ago" from (relTime returns '—' for a missing/zero ts) — avoids the
// nonsensical '— ago'.
function relTimeAgo(ts: number): string {
  const base = relTime(ts)
  return base === '—' ? base : base + ' ago'
}

const phase = computed(() => status.value?.world?.phase || '—')

function activityLabel(act: unknown): string {
  if (!act) return '—'
  if (typeof act === 'string') return act
  if (typeof act === 'object') {
    const o = act as Record<string, unknown>
    const label = o.label ?? o.name ?? o.kind ?? o.activity_id ?? ''
    return String(label || '—')
  }
  return String(act)
}

const rhythmStats = computed(() => {
  const s = status.value
  return [
    { label: 'current_activity', value: activityLabel(s?.current_activity) },
    { label: 'sim_count', value: num(s?.counts, ['simulation_count'], 0) },
    { label: 'outreach_count', value: num(s?.counts, ['outreach_count'], 0) },
    {
      label: 'seconds_since_tick',
      value: (() => {
        const v = s?.world?.seconds_since_tick
        return v !== undefined && v !== null ? String(v) : '—'
      })(),
    },
  ]
})

const energyValue = computed(() => num(status.value?.world, ['energy'], 0))
const focusValue = computed(() => num(status.value?.world, ['focus'], 0))

const eventList = computed<LifeEvent[]>(() => events.value?.events || [])

const timelineItems = computed<TimelineItem[]>(() =>
  // newest first, mirrors old dashboard's reverse iteration
  [...eventList.value]
    .slice()
    .reverse()
    .map((ev) => {
      const imp = num(ev, ['importance'], 0)
      const notable = imp > 0.7
      let text = String(ev.text || '')
      if (notable) text = '★ ' + text
      let tag = String(ev.event_type || '—')
      if (ev.shared) tag += ' · shared'
      else if (ev.wants_to_share) tag += ' · wants_share'
      return {
        time: relTimeAgo(num(ev, ['timestamp'], 0)),
        text,
        tag,
      }
    }),
)

const projectList = computed<LifeProject[]>(() => projects.value?.projects || [])
const skillList = computed<LifeSkill[]>(() => projects.value?.skills || [])

function projectProgress(p: LifeProject): number {
  return Math.max(0, Math.min(1, num(p, ['progress'], 0)))
}

interface AuditRow {
  session: string
  entry: LifeAuditEntry
}

const auditRows = computed<AuditRow[]>(() => {
  const a = audit.value?.audit || {}
  const rows: AuditRow[] = []
  for (const sess of Object.keys(a)) {
    for (const entry of a[sess] || []) {
      rows.push({ session: sess, entry })
    }
  }
  rows.sort((x, y) => {
    const tx = num(x.entry, ['ts', 'timestamp'], 0)
    const ty = num(y.entry, ['ts', 'timestamp'], 0)
    return ty - tx
  })
  return rows.slice(0, 15)
})

function auditSessionLabel(sess: string): string {
  return sess === '_global' ? '_global' : sess.slice(0, 10)
}

// ---- controls: POST /api/life/controls ----

const controlsMsg = ref('')
const controlsMsgIsError = ref(false)

async function postControl(action: string, value?: unknown): Promise<void> {
  const body: Record<string, unknown> = { action }
  if (value !== undefined) body.value = value
  try {
    const resp = await apiFetch<{ ok?: boolean; error?: string }>('/api/life/controls', {
      method: 'POST',
      body,
    })
    if (resp && resp.ok) {
      controlsMsgIsError.value = false
      controlsMsg.value = 'Applied: ' + action
      feedback.show(t('feedback.operation_applied'), 'success')
    } else {
      controlsMsgIsError.value = true
      controlsMsg.value = (resp && resp.error) || 'Failed'
      const detail = conciseFeedbackError(resp?.error, '')
      feedback.show(
        detail
          ? `${t('feedback.operation_failed')} · ${detail}`
          : t('feedback.operation_failed'),
        'error',
      )
    }
    void fetchAll()
  } catch (e) {
    controlsMsgIsError.value = true
    controlsMsg.value = 'Request error'
    const detail = conciseFeedbackError(e, '')
    feedback.show(
      detail
        ? `${t('feedback.operation_failed')} · ${detail}`
        : t('feedback.operation_failed'),
      'error',
    )
  }
}

function onToggleEnabled(v: boolean): void {
  enabled.value = v
  void postControl('toggle_enabled', v)
}

function onSetShareIntensity(v: string): void {
  shareIntensity.value = v
  void postControl('set_share_intensity', v)
}

// ---- clear-* confirm modals ----

type ClearKind = 'events' | 'projects' | 'plan'

const confirmOpen = ref(false)
const confirmKind = ref<ClearKind | null>(null)

const CLEAR_ACTION: Record<ClearKind, string> = {
  events: 'clear_journal',
  projects: 'clear_projects',
  plan: 'clear_plan',
}
const CLEAR_LABEL_KEY: Record<ClearKind, string> = {
  events: 'life.clear_events',
  projects: 'life.clear_projects',
  plan: 'life.clear_plan',
}

function openClearConfirm(kind: ClearKind): void {
  confirmKind.value = kind
  confirmOpen.value = true
}

async function confirmClear(): Promise<void> {
  const kind = confirmKind.value
  confirmOpen.value = false
  if (!kind) return
  await postControl(CLEAR_ACTION[kind])
  confirmKind.value = null
}

function cancelClear(): void {
  confirmOpen.value = false
  confirmKind.value = null
}

// ---- diagnostics export ----

const exportingDiag = ref(false)

async function exportDiagnostics(): Promise<void> {
  exportingDiag.value = true
  try {
    const data = await apiFetch<Record<string, unknown>>('/api/life/diagnostics')
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'sylanne-life-diagnostics-' + Date.now() + '.json'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    setTimeout(() => URL.revokeObjectURL(url), 1000)
    controlsMsgIsError.value = false
    controlsMsg.value = 'Diagnostics JSON downloaded'
    feedback.show(t('feedback.diagnostics_exported'), 'success')
  } catch (e) {
    controlsMsgIsError.value = true
    controlsMsg.value = 'Diagnostics download failed'
    const detail = conciseFeedbackError(e, '')
    feedback.show(
      detail
        ? `${t('feedback.diagnostics_failed')} · ${detail}`
        : t('feedback.diagnostics_failed'),
      'error',
    )
  } finally {
    exportingDiag.value = false
  }
}
</script>

<template>
  <div class="page-split">
    <div class="pane-left">
      <template v-if="status && !available">
        <Card :title="t('life.rhythm')">
          <EmptyState message-key="common.empty">
            {{ t('common.empty') }}
          </EmptyState>
        </Card>
      </template>

      <template v-else-if="status">
        <Card :title="t('life.rhythm')">
          <template #action>
            <Badge variant="accent">{{ phase }}</Badge>
          </template>
          <StatGrid :items="rhythmStats" :cols="2" />
          <BarRow
            :label="t('life.energy')"
            :value="energyValue"
            :display="energyValue.toFixed(2)"
          />
          <BarRow
            :label="t('life.focus')"
            :value="focusValue"
            color="var(--cyan)"
            :display="focusValue.toFixed(2)"
          />
        </Card>

        <Card :title="t('life.projects')">
          <div v-if="projectList.length" class="project-list">
            <div v-for="(p, i) in projectList" :key="p.title ? p.title + i : i" class="project-item">
              <div class="project-head">
                <strong>{{ p.title || p.kind || '—' }}</strong>
                <div class="project-badges">
                  <Badge variant="neutral">{{ p.kind || '—' }}</Badge>
                  <Badge variant="neutral">{{ p.state || '—' }}</Badge>
                </div>
              </div>
              <BarRow
                label="progress"
                :value="projectProgress(p)"
                :display="projectProgress(p).toFixed(2)"
              />
              <div class="project-meta mono">
                share={{ p.share_policy || '—' }} · eff={{ Number(p.effectiveness || 0).toFixed(2) }}
              </div>
            </div>
          </div>
          <EmptyState v-else message-key="common.empty" />
        </Card>

        <Card :title="t('life.skills')">
          <div v-if="skillList.length" class="skill-list">
            <div v-for="(s, i) in skillList" :key="s.name ? s.name + i : i" class="skill-item">
              <span class="skill-name">{{ s.name || '—' }}</span>
              <BarRow
                label="effectiveness"
                :value="num(s, ['effectiveness'], 0)"
                :display="Number(s.effectiveness || 0).toFixed(2)"
              />
              <div class="skill-meta mono">
                ✓{{ s.success_count || 0 }} ✗{{ s.failure_count || 0 }}
              </div>
            </div>
          </div>
          <EmptyState v-else message-key="common.empty" />
        </Card>
      </template>

      <template v-else-if="attempted">
        <Card :title="t('life.rhythm')">
          <EmptyState message-key="common.empty" />
        </Card>
      </template>

      <div v-else class="loading-state">
        <span class="mono">{{ t('common.loading') }}</span>
      </div>
    </div>

    <div class="pane-right">
      <template v-if="status && available">
        <Card :title="t('life.events')" class="card-events">
          <Timeline v-if="timelineItems.length" :items="timelineItems" />
          <EmptyState v-else message-key="common.empty" />
        </Card>

        <Card :title="t('life.audit')">
          <div v-if="auditRows.length" class="audit-list">
            <div v-for="(r, i) in auditRows" :key="i" class="audit-item">
              <div class="audit-head">
                <strong class="mono">{{ r.entry.feedback_status || r.entry.kind || '—' }}</strong>
                <span class="audit-session mono">{{ auditSessionLabel(r.session) }}</span>
              </div>
              <div class="audit-meta mono">
                {{ relTimeAgo(num(r.entry, ['ts', 'timestamp'], 0)) }}
                <span v-if="r.entry.intent_id" class="audit-reason">[{{ r.entry.intent_id }}]</span>
              </div>
            </div>
          </div>
          <EmptyState v-else message-key="common.empty" />
        </Card>

        <Card :title="t('life.controls')" class="card-controls">
          <div class="control-row">
            <Toggle :model-value="enabled" @update:model-value="onToggleEnabled">
              {{ t('life.enabled') }}
            </Toggle>
          </div>
          <div class="control-row">
            <label class="control-label mono">{{ t('life.share_intensity') }}</label>
            <Select
              :model-value="shareIntensity"
              :options="shareIntensityOptions"
              @update:model-value="onSetShareIntensity"
            />
          </div>
          <div class="control-buttons">
            <Button variant="secondary" size="sm" @click="openClearConfirm('events')">
              {{ t('life.clear_events') }}
            </Button>
            <Button variant="secondary" size="sm" @click="openClearConfirm('projects')">
              {{ t('life.clear_projects') }}
            </Button>
            <Button variant="secondary" size="sm" @click="openClearConfirm('plan')">
              {{ t('life.clear_plan') }}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              :loading="exportingDiag"
              @click="exportDiagnostics"
            >
              {{ t('life.export_diag') }}
            </Button>
          </div>
          <div
            v-if="controlsMsg"
            class="control-msg mono"
            :class="{ 'is-error': controlsMsgIsError }"
          >
            {{ controlsMsg }}
          </div>
        </Card>
      </template>
    </div>

    <Modal v-model:open="confirmOpen" :title="confirmKind ? t(CLEAR_LABEL_KEY[confirmKind]) : ''" size="sm">
      <p class="confirm-desc">{{ confirmKind ? t(CLEAR_LABEL_KEY[confirmKind]) : '' }}?</p>
      <template #footer>
        <Button variant="secondary" @click="cancelClear">{{ t('common.cancel') }}</Button>
        <Button variant="danger" @click="confirmClear">{{ t('common.confirm') }}</Button>
      </template>
    </Modal>
  </div>
</template>

<style scoped>
.pane-left > .card + .card,
.pane-right > .card + .card {
  margin-top: var(--space-8);
}

.project-list,
.skill-list,
.audit-list {
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
}

.project-item {
  border: 1px solid var(--card-border);
  border-radius: var(--r-md);
  padding: var(--space-5);
}

.project-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  margin-bottom: var(--space-3);
  font-size: var(--font-sm);
}

.project-badges {
  display: flex;
  gap: var(--space-2);
  flex: none;
}

.project-meta {
  font-size: var(--font-xs);
  color: var(--text-muted);
  margin-top: var(--space-2);
}

.skill-item {
  border-bottom: 1px dashed var(--card-border);
  padding-bottom: var(--space-4);
}
.skill-item:last-child {
  border-bottom: none;
  padding-bottom: 0;
}

.skill-name {
  font-size: var(--font-sm);
  color: var(--text);
}

.skill-meta {
  font-size: var(--font-xs);
  color: var(--text-muted);
  margin-top: var(--space-1);
}

.audit-item {
  border-left: 2px solid var(--cyan);
  padding: var(--space-3) var(--space-5);
}

.audit-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  font-size: var(--font-sm);
}

.audit-session {
  color: var(--text-muted);
  font-size: var(--font-xs);
}

.audit-meta {
  color: var(--text-muted);
  font-size: var(--font-xs);
  margin-top: var(--space-1);
}

.audit-reason {
  color: var(--amber);
  margin-left: var(--space-2);
}

.control-row {
  margin-bottom: var(--space-6);
}

.control-label {
  display: block;
  font-size: var(--font-xs);
  color: var(--text-muted);
  margin-bottom: var(--space-3);
  letter-spacing: 0.5px;
}

.control-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-5);
  margin-top: var(--space-6);
}

.control-msg {
  margin-top: var(--space-5);
  font-size: var(--font-xs);
  color: var(--accent);
  min-height: 14px;
}
.control-msg.is-error {
  color: var(--red);
}

.confirm-desc {
  margin: 0;
  font-size: var(--font-sm);
  color: var(--text);
  text-align: center;
}

.loading-state {
  height: 100%;
  min-height: 200px;
  display: grid;
  place-items: center;
  color: var(--text-muted);
  font-size: var(--font-sm);
  letter-spacing: 1px;
  opacity: 0.7;
}
</style>
