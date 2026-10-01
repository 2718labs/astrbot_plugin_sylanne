<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { apiFetch, ApiError } from '../api/client'
import { useI18n } from '../composables/useI18n'
import {
  conciseFeedbackError,
  useInteractionFeedback,
} from '../composables/useInteractionFeedback'
import type { ProviderInfo, SettingsSchemaEntry } from '../api/types'
import type { ModelRoutingState, SettingsResponseWithModelRouting } from '../types'
import {
  AUXILIARY_PROVIDER_KEY,
  EMBEDDING_ENABLED_KEY,
  EMBEDDING_PROVIDER_KEY,
  MANUAL_PROVIDER_VALUE,
  buildDirtySettingsPayload,
  buildModelRoutingViewModel,
  buildProviderOptions,
  partitionSettingsSchema,
  type ModelRoutingLabels,
} from '../config/modelRouting'
import Card from '../components/ui/Card.vue'
import Badge from '../components/ui/Badge.vue'
import Button from '../components/ui/Button.vue'
import Toggle from '../components/ui/Toggle.vue'
import TextInput from '../components/ui/TextInput.vue'
import NumberInput from '../components/ui/NumberInput.vue'
import Select from '../components/ui/Select.vue'
import ErrorState from '../components/ui/ErrorState.vue'
import type { SelectOption } from '../components/ui/Select.vue'

const { t } = useI18n()
const feedback = useInteractionFeedback()

// computed so it re-renders on language switch (t() reads lang.value)
const MANUAL_INPUT_LABEL = computed(() => t('config.manual_input'))

// ── Grouping: exact port of CONFIG_GROUP_PREFIXES / classifyConfigKey from
// the old dashboard (UI/index.html @ 8655acd). Order matters — first prefix
// match wins, longer/more-specific prefixes are listed before their broader
// parents. Any 'sylanne_alpha_*' key not otherwise matched, and anything
// else, falls through to Advanced.
interface GroupRule {
  prefix: string
  groupKey: string
}

const CONFIG_GROUP_PREFIXES: GroupRule[] = [
  { prefix: 'sylanne_persona_', groupKey: 'config.identity' },
  { prefix: 'sylanne_webui_', groupKey: 'config.webui' },
  { prefix: 'sylanne_group_', groupKey: 'config.webui' },
  { prefix: 'sylanne_alpha_realtime_', groupKey: 'config.realtime' },
  { prefix: 'sylanne_alpha_stream_', groupKey: 'config.realtime' },
  { prefix: 'sylanne_alpha_proactive_', groupKey: 'config.realtime' },
  { prefix: 'sylanne_alpha_intercept_', groupKey: 'config.realtime' },
  { prefix: 'sylanne_alpha_embedding_', groupKey: 'config.memory' },
  { prefix: 'sylanne_alpha_main_assessor_', groupKey: 'config.memory' },
  { prefix: 'sylanne_alpha_background_', groupKey: 'config.memory' },
  { prefix: 'sylanne_alpha_life_simulation_', groupKey: 'config.life' },
  { prefix: 'sylanne_alpha_transcription_', groupKey: 'config.advanced' },
]

// Group render order (old dashboard: Identity, WebUI, Realtime, Memory &
// Assessment, Life Simulation, Advanced).
const GROUP_ORDER = [
  'config.identity',
  'config.webui',
  'config.realtime',
  'config.memory',
  'config.life',
  'config.advanced',
] as const

function classifyConfigKey(key: string): string {
  for (const rule of CONFIG_GROUP_PREFIXES) {
    if (key.startsWith(rule.prefix)) return rule.groupKey
  }
  return 'config.advanced'
}

// ── Data ──
const schema = ref<Record<string, SettingsSchemaEntry>>({})
const providers = ref<ProviderInfo[]>([])
const routingMetadata = ref<ModelRoutingState>({})
const loaded = ref(false)
const loadError = ref(false)
const advancedOverridesOpen = ref(false)

// Dirty-tracked local values, seeded from values[key] ?? schema[key].default.
const values = reactive<Record<string, unknown>>({})
// Keys the user has actually touched — only these go in the save payload.
const dirtyKeys = reactive<Set<string>>(new Set())
// Manual-entry mode for provider_id fields where the stack swaps to a plain
// text input (old dashboard's "Manual Input..." option).
const manualProviderKeys = reactive<Set<string>>(new Set())
// Keys whose value came back from load() as the '********' mask sentinel —
// sticky for this load so the control doesn't swap away from TextInput
// mid-edit (e.g. an int field like *_max_tokens re-becoming a NumberInput
// while the user is still typing over the mask).
const maskedKeys = reactive<Set<string>>(new Set())

// Backend masks sensitive values (secrets, but also plain int/float fields
// whose key merely contains 'token', e.g. *_max_tokens) as this sentinel —
// regardless of the field's schema type. NumberInput would coerce it via
// Number('********') -> NaN -> 0, silently showing a fake 0.
const MASK_SENTINEL = '********'

const saving = ref(false)
const saveError = ref('')
const justSaved = ref(false)
let savedTimer: ReturnType<typeof setTimeout> | undefined

async function load(): Promise<void> {
  loaded.value = false
  loadError.value = false
  try {
    const resp = await apiFetch<SettingsResponseWithModelRouting>('/api/settings')
    schema.value = resp.schema || {}
    providers.value = resp.providers || []
    routingMetadata.value = resp.model_routing || {}
    const respValues = resp.values || {}
    for (const key of Object.keys(values)) delete values[key]
    dirtyKeys.clear()
    manualProviderKeys.clear()
    maskedKeys.clear()
    for (const key of Object.keys(schema.value)) {
      const meta = schema.value[key]
      const v = respValues[key]
      values[key] = v !== undefined ? v : meta?.default !== undefined ? meta.default : ''
      if (values[key] === MASK_SENTINEL) maskedKeys.add(key)
      if (key.indexOf('provider_id') !== -1) {
        const val = values[key]
        const known = providers.value.some((p) => p.id === val)
        if (val && !known) manualProviderKeys.add(key)
      }
    }
    loaded.value = true
  } catch {
    loadError.value = true
    loaded.value = true
  }
}

onMounted(load)

interface ConfigItem {
  key: string
  label: string
  control: 'toggle' | 'number' | 'select' | 'provider' | 'text' | 'masked'
  options?: SelectOption[]
  numberStep?: number
}

function configItem(key: string, meta: SettingsSchemaEntry): ConfigItem {
  const isProvider = key.indexOf('provider_id') !== -1
  let control: ConfigItem['control']
  let options: SelectOption[] | undefined
  let numberStep: number | undefined
  if (maskedKeys.has(key)) {
    control = 'masked'
  } else if (meta.type === 'bool') {
    control = 'toggle'
  } else if (meta.type === 'int' || meta.type === 'float') {
    control = 'number'
    numberStep = meta.type === 'float' ? 0.01 : 1
  } else if (meta.options && meta.options.length) {
    control = 'select'
    options = meta.options.map((option) => ({ label: option, value: option }))
  } else if (isProvider) {
    control = 'provider'
  } else {
    control = 'text'
  }

  return {
    key,
    label: meta.description || key,
    control,
    options,
    numberStep,
  }
}

const schemaPartition = computed(() => partitionSettingsSchema(schema.value))

const groups = computed(() => {
  const byGroup: Record<string, ConfigItem[]> = {}
  for (const [key, meta] of Object.entries(schemaPartition.value.normal)) {
    const groupKey = classifyConfigKey(key)
    if (!byGroup[groupKey]) byGroup[groupKey] = []
    byGroup[groupKey].push(configItem(key, meta))
  }
  return GROUP_ORDER.filter((g) => byGroup[g] && byGroup[g].length).map((g) => ({
    groupKey: g,
    items: byGroup[g],
  }))
})

// Two-pane split, old dashboard's schema-group flow: left = first three
// present groups (Identity, WebUI, Realtime), right = the rest (Memory &
// Assessment, Life Simulation, Advanced) with the save bar appended at the
// end of the right pane — never spanning the seam.
const leftGroups = computed(() => groups.value.slice(0, 3))
const rightGroups = computed(() => groups.value.slice(3))
const advancedProviderItems = computed(() =>
  Object.entries(schemaPartition.value.advancedProviders).map(([key, meta]) =>
    configItem(key, meta),
  ),
)

const routingLabels = computed<ModelRoutingLabels>(() => ({
  currentConversation: t('config.current_conversation'),
  followCurrentChat: t('config.follow_current_chat'),
  automaticMultimodal: t('config.automatic_multimodal'),
  automaticEmbedding: t('config.automatic_embedding'),
  selectEmbedding: t('config.select_embedding'),
  embeddingUnavailable: t('config.embedding_unavailable'),
  embeddingDisabled: t('config.embedding_disabled'),
  manualInput: t('config.manual_input'),
}))

const modelRouting = computed(() =>
  buildModelRoutingViewModel(
    {
      schema: schema.value,
      values,
      providers: providers.value,
      model_routing: routingMetadata.value,
    },
    routingLabels.value,
  ),
)

function providerOptions(key: string): SelectOption[] {
  let list = providers.value
  if (key.indexOf('embedding') !== -1) {
    list = list.filter((provider) => provider.type === 'embedding')
  } else {
    list = list.filter((provider) => provider.type !== 'embedding')
  }
  return buildProviderOptions(list, {
    kind: key.indexOf('embedding') !== -1 ? 'embedding' : 'text',
    automaticLabel: t('config.automatic_inherit'),
    manualLabel: MANUAL_INPUT_LABEL.value,
  })
}

function providerSelectValue(key: string): string {
  if (manualProviderKeys.has(key)) return '__manual__'
  return String(values[key] ?? '')
}

function onProviderSelect(key: string, val: string): void {
  if (val === MANUAL_PROVIDER_VALUE) {
    const current = strValue(key)
    const isKnown = providers.value.some((provider) => provider.id === current)
    if (isKnown) setValue(key, '')
    manualProviderKeys.add(key)
    return
  }
  manualProviderKeys.delete(key)
  setValue(key, val)
}

function setValue(key: string, val: unknown): void {
  values[key] = val
  dirtyKeys.add(key)
}

function boolValue(key: string): boolean {
  return Boolean(values[key])
}
function numValue(key: string): number {
  const n = Number(values[key])
  return Number.isNaN(n) ? 0 : n
}
function strValue(key: string): string {
  return values[key] === undefined || values[key] === null ? '' : String(values[key])
}

// Dependent-row visibility: reproduces the old dashboard's two forms of
// hide-when-off — a sibling '<prefix>enabled' toggle, or a 'use_<suffix>'
// toggle gating a same-named field. Not literally documented as
// classifyConfigKey/data-depends logic (that lived in renderConfigGroup),
// so this is a best-effort port; see caveats.
function dependsVisible(item: ConfigItem, items: ConfigItem[]): boolean {
  if (item.key.endsWith('_enabled')) return true
  for (const other of items) {
    if (other.control !== 'toggle') continue
    const m = other.key.match(/^(.+_)enabled$/)
    if (m && item.key.startsWith(m[1]) && item.key !== other.key) {
      return boolValue(other.key)
    }
  }
  for (const other of items) {
    if (other.control !== 'toggle') continue
    const m2 = other.key.match(/^(.+_)use_(.+)$/)
    if (m2 && item.key.indexOf(m2[1] + m2[2]) !== -1 && item.key !== other.key) {
      return boolValue(other.key)
    }
  }
  return true
}

async function save(): Promise<void> {
  if (!dirtyKeys.size) return
  saving.value = true
  saveError.value = ''
  const payload = buildDirtySettingsPayload(values, dirtyKeys)
  try {
    await apiFetch('/api/settings', { method: 'POST', body: payload })
    dirtyKeys.clear()
    justSaved.value = true
    if (savedTimer) clearTimeout(savedTimer)
    savedTimer = setTimeout(() => {
      justSaved.value = false
    }, 2500)
    feedback.show(t('feedback.settings_saved'), 'success')
  } catch (e) {
    saveError.value = e instanceof ApiError ? e.message : String(e)
    const detail = conciseFeedbackError(e, saveError.value)
    feedback.show(
      detail
        ? `${t('feedback.settings_failed')} · ${detail}`
        : t('feedback.settings_failed'),
      'error',
    )
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="page-split">
    <div class="pane-left">
      <ErrorState v-if="loadError" :message-key="'config.fetch_failed'">
        <template #action>
          <Button variant="primary" @click="load">{{ t('common.retry') }}</Button>
        </template>
      </ErrorState>

      <template v-else-if="loaded">
        <Card v-for="group in leftGroups" :key="group.groupKey" :title="t(group.groupKey)">
          <div
            v-for="item in group.items"
            :key="item.key"
            class="config-row"
            v-show="dependsVisible(item, group.items)"
          >
            <span class="config-label">{{ item.label }}</span>
            <div class="config-control">
              <TextInput
                v-if="item.control === 'masked'"
                :model-value="strValue(item.key)"
                @update:model-value="(v) => setValue(item.key, v)"
              />
              <Toggle
                v-else-if="item.control === 'toggle'"
                :model-value="boolValue(item.key)"
                @update:model-value="(v) => setValue(item.key, v)"
              />
              <NumberInput
                v-else-if="item.control === 'number'"
                :model-value="numValue(item.key)"
                :step="item.numberStep ?? 1"
                @update:model-value="(v) => setValue(item.key, v)"
              />
              <Select
                v-else-if="item.control === 'select'"
                :model-value="strValue(item.key)"
                :options="item.options || []"
                @update:model-value="(v) => setValue(item.key, v)"
              />
              <template v-else-if="item.control === 'provider'">
                <Select
                  v-if="!manualProviderKeys.has(item.key)"
                  :model-value="providerSelectValue(item.key)"
                  :options="providerOptions(item.key)"
                  @update:model-value="(v) => onProviderSelect(item.key, v)"
                />
                <TextInput
                  v-else
                  :model-value="strValue(item.key)"
                  :placeholder="MANUAL_INPUT_LABEL"
                  @update:model-value="(v) => setValue(item.key, v)"
                />
              </template>
              <TextInput
                v-else
                :model-value="strValue(item.key)"
                @update:model-value="(v) => setValue(item.key, v)"
              />
            </div>
          </div>
        </Card>
      </template>

      <div v-else class="loading-state">
        <span class="mono">{{ t('common.loading') }}</span>
      </div>
    </div>

    <div class="pane-right">
      <template v-if="loaded && !loadError">
        <Card data-testid="model-strategy" :title="t('config.model_strategy')">
          <template #action>
            <Badge
              v-if="modelRouting.advancedOverrideCount"
              variant="neutral"
            >
              {{ modelRouting.advancedOverrideCount }} {{ t('config.overrides_active') }}
            </Badge>
          </template>

          <p class="strategy-intro">{{ t('config.model_strategy_hint') }}</p>

          <div class="config-row">
            <div class="routing-copy">
              <span class="config-label">{{ t('config.chat_model') }}</span>
              <span class="routing-note">{{ t('config.chat_model_hint') }}</span>
            </div>
            <span class="routing-value mono">{{ modelRouting.chat.label }}</span>
          </div>

          <div class="config-row">
            <div class="routing-copy">
              <span class="config-label">{{ t('config.auxiliary_model') }}</span>
              <span class="routing-note">{{ t('config.auxiliary_model_hint') }}</span>
            </div>
            <div class="config-control control-stack">
              <Select
                :model-value="providerSelectValue(AUXILIARY_PROVIDER_KEY)"
                :options="modelRouting.auxiliary.options"
                @update:model-value="(value) => onProviderSelect(AUXILIARY_PROVIDER_KEY, value)"
              />
              <TextInput
                v-if="manualProviderKeys.has(AUXILIARY_PROVIDER_KEY)"
                :model-value="strValue(AUXILIARY_PROVIDER_KEY)"
                :placeholder="MANUAL_INPUT_LABEL"
                @update:model-value="(value) => setValue(AUXILIARY_PROVIDER_KEY, value)"
              />
            </div>
          </div>

          <div class="config-row">
            <div class="routing-copy">
              <span class="config-label">{{ t('config.image_understanding') }}</span>
              <span class="routing-note">{{ t('config.image_understanding_hint') }}</span>
            </div>
            <span class="routing-value mono">{{ modelRouting.transcription.label }}</span>
          </div>

          <div class="config-row">
            <div class="routing-copy">
              <span class="config-label">{{ t('config.embedding_memory') }}</span>
              <span class="routing-note">{{ t('config.embedding_memory_hint') }}</span>
            </div>
            <div class="config-control control-stack">
              <div class="inline-control">
                <Toggle
                  :model-value="modelRouting.embedding.enabled"
                  @update:model-value="(value) => setValue(EMBEDDING_ENABLED_KEY, value)"
                />
                <Badge
                  v-if="modelRouting.embedding.required"
                  variant="red"
                >
                  {{ t('config.selection_required') }}
                </Badge>
                <span
                  v-else-if="!modelRouting.embedding.enabled || modelRouting.embedding.mode === 'unavailable'"
                  class="routing-note mono"
                >
                  {{ modelRouting.embedding.label }}
                </span>
              </div>
              <template
                v-if="modelRouting.embedding.enabled && modelRouting.embedding.mode !== 'unavailable'"
              >
                <Select
                  :model-value="providerSelectValue(EMBEDDING_PROVIDER_KEY)"
                  :options="modelRouting.embedding.options"
                  @update:model-value="(value) => onProviderSelect(EMBEDDING_PROVIDER_KEY, value)"
                />
                <TextInput
                  v-if="manualProviderKeys.has(EMBEDDING_PROVIDER_KEY)"
                  :model-value="strValue(EMBEDDING_PROVIDER_KEY)"
                  :placeholder="MANUAL_INPUT_LABEL"
                  @update:model-value="(value) => setValue(EMBEDDING_PROVIDER_KEY, value)"
                />
              </template>
            </div>
          </div>

          <div class="config-row advanced-toggle-row">
            <div class="routing-copy">
              <span class="config-label">{{ t('config.advanced_overrides') }}</span>
              <span class="routing-note">{{ t('config.advanced_overrides_hint') }}</span>
            </div>
            <div class="inline-control">
              <Badge variant="neutral">
                {{ modelRouting.advancedOverrideCount }} {{ t('config.overrides_active') }}
              </Badge>
              <Toggle v-model="advancedOverridesOpen" />
            </div>
          </div>

          <div v-if="advancedOverridesOpen" class="advanced-overrides">
            <p v-if="!advancedProviderItems.length" class="routing-note">
              {{ t('config.no_advanced_overrides') }}
            </p>
            <div
              v-for="item in advancedProviderItems"
              :key="item.key"
              class="config-row"
            >
              <span class="config-label">{{ item.label }}</span>
              <div class="config-control control-stack">
                <Select
                  :model-value="providerSelectValue(item.key)"
                  :options="providerOptions(item.key)"
                  @update:model-value="(value) => onProviderSelect(item.key, value)"
                />
                <TextInput
                  v-if="manualProviderKeys.has(item.key)"
                  :model-value="strValue(item.key)"
                  :placeholder="MANUAL_INPUT_LABEL"
                  @update:model-value="(value) => setValue(item.key, value)"
                />
              </div>
            </div>
          </div>
        </Card>

        <Card v-for="group in rightGroups" :key="group.groupKey" :title="t(group.groupKey)">
          <div
            v-for="item in group.items"
            :key="item.key"
            class="config-row"
            v-show="dependsVisible(item, group.items)"
          >
            <span class="config-label">{{ item.label }}</span>
            <div class="config-control">
              <TextInput
                v-if="item.control === 'masked'"
                :model-value="strValue(item.key)"
                @update:model-value="(v) => setValue(item.key, v)"
              />
              <Toggle
                v-else-if="item.control === 'toggle'"
                :model-value="boolValue(item.key)"
                @update:model-value="(v) => setValue(item.key, v)"
              />
              <NumberInput
                v-else-if="item.control === 'number'"
                :model-value="numValue(item.key)"
                :step="item.numberStep ?? 1"
                @update:model-value="(v) => setValue(item.key, v)"
              />
              <Select
                v-else-if="item.control === 'select'"
                :model-value="strValue(item.key)"
                :options="item.options || []"
                @update:model-value="(v) => setValue(item.key, v)"
              />
              <template v-else-if="item.control === 'provider'">
                <Select
                  v-if="!manualProviderKeys.has(item.key)"
                  :model-value="providerSelectValue(item.key)"
                  :options="providerOptions(item.key)"
                  @update:model-value="(v) => onProviderSelect(item.key, v)"
                />
                <TextInput
                  v-else
                  :model-value="strValue(item.key)"
                  :placeholder="MANUAL_INPUT_LABEL"
                  @update:model-value="(v) => setValue(item.key, v)"
                />
              </template>
              <TextInput
                v-else
                :model-value="strValue(item.key)"
                @update:model-value="(v) => setValue(item.key, v)"
              />
            </div>
          </div>
        </Card>

        <div class="save-bar">
          <ErrorState v-if="saveError" :message="saveError" class="save-error" />
          <Badge v-if="justSaved" variant="green">{{ t('config.saved') }}</Badge>
          <Button
            variant="primary"
            :loading="saving"
            :disabled="!dirtyKeys.size"
            @click="save"
          >
            {{ t('config.save') }}
          </Button>
        </div>
      </template>
    </div>
  </div>
</template>

<style scoped>
/* .pane-left/.pane-right supply the grid, scroll, and edge-fade — see
 * base.css .page-split. Only inter-card spacing within each pane is ours. */
.pane-left > .card + .card,
.pane-right > .card + .card {
  margin-top: var(--space-8);
}

.config-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-6);
  padding: var(--space-5) 0;
  border-bottom: 1px solid var(--card-border);
}
.config-row:last-child {
  border-bottom: none;
}

.config-label {
  font-size: var(--font-sm);
  color: var(--text);
  flex: 1 1 auto;
  min-width: 0;
}

.strategy-intro {
  margin: 0 0 var(--space-3);
  color: var(--text-muted);
  font-size: var(--font-sm);
  line-height: 1.6;
}

.routing-copy {
  display: flex;
  flex: 1 1 auto;
  min-width: 0;
  flex-direction: column;
  gap: var(--space-2);
}

.routing-note {
  color: var(--text-muted);
  font-size: var(--font-xs);
  line-height: 1.45;
}

.routing-value {
  max-width: 48%;
  color: var(--text-muted);
  font-size: var(--font-xs);
  line-height: 1.45;
  text-align: right;
}

.config-control {
  flex: 0 0 auto;
  width: 200px;
  max-width: 45%;
}

.control-stack {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.inline-control {
  display: inline-flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--space-4);
}

.advanced-toggle-row {
  border-bottom: none;
}

.advanced-overrides {
  padding: 0 var(--space-5);
  border: 1px solid var(--card-border);
  border-radius: var(--r-sm);
  background: var(--input-bg);
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

.save-bar {
  position: sticky;
  bottom: 0;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: var(--space-6);
  margin-top: var(--space-8);
  padding: var(--space-6) var(--space-8);
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: var(--r-lg);
  box-shadow: 0 2px 20px rgba(0, 0, 0, 0.22);
}

.save-error {
  flex: 1 1 auto;
  padding: var(--space-3) var(--space-6);
}

@media (max-width: 900px) {
  .config-control {
    max-width: 55%;
  }
}

@media (max-width: 620px) {
  .config-row {
    align-items: flex-start;
    flex-direction: column;
    gap: var(--space-4);
  }

  .config-control,
  .routing-value {
    width: 100%;
    max-width: none;
    text-align: left;
  }

  .inline-control {
    justify-content: flex-start;
  }
}
</style>
