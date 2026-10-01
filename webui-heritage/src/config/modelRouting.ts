import type { ProviderInfo, SettingsSchemaEntry } from '../api/types'
import type {
  SettingsResponseWithModelRouting,
  TieredSettingsSchemaEntry,
} from '../types'

export const MANUAL_PROVIDER_VALUE = '__manual__'
export const AUXILIARY_PROVIDER_KEY = 'sylanne_alpha_aux_provider_id'
export const EMBEDDING_ENABLED_KEY = 'sylanne_alpha_embedding_memory_enabled'
export const EMBEDDING_PROVIDER_KEY = 'sylanne_alpha_embedding_memory_provider_id'

export const MODEL_STRATEGY_KEYS = new Set<string>([
  AUXILIARY_PROVIDER_KEY,
  EMBEDDING_ENABLED_KEY,
  EMBEDDING_PROVIDER_KEY,
])

export const ADVANCED_PROVIDER_KEYS = [
  'sylanne_alpha_main_assessor_provider_id',
  'sylanne_alpha_life_simulation_provider_id',
  'sylanne_alpha_rel_register_provider_id',
  'sylanne_alpha_qzone_provider_id',
  'sylanne_alpha_transcription_provider_id',
  'sylanne_alpha_assessor_provider_id',
  'emotion_provider_id',
] as const

export type ProviderKind = 'text' | 'embedding'
export type AuxiliaryRoutingMode = 'inherit' | 'explicit'
export type EmbeddingRoutingMode =
  | 'disabled'
  | 'unavailable'
  | 'auto'
  | 'selection_required'
  | 'explicit'

export interface ProviderOption {
  label: string
  value: string
}

export interface ProviderOptionsConfig {
  kind: ProviderKind
  automaticLabel: string
  manualLabel: string
}

export interface ModelRoutingLabels {
  currentConversation: string
  followCurrentChat: string
  automaticMultimodal: string
  automaticEmbedding: string
  selectEmbedding: string
  embeddingUnavailable: string
  embeddingDisabled: string
  manualInput: string
}

export const DEFAULT_MODEL_ROUTING_LABELS: Readonly<ModelRoutingLabels> = {
  currentConversation: '跟随 AstrBot 当前会话',
  followCurrentChat: '跟随当前聊天模型',
  automaticMultimodal: '自动检测多模态模型',
  automaticEmbedding: '自动选择 Embedding 模型',
  selectEmbedding: '请选择 Embedding 模型',
  embeddingUnavailable: '未发现可用的 Embedding 模型',
  embeddingDisabled: '未启用',
  manualInput: '手动输入…',
}

export interface ReadonlyRoutingRow {
  mode: string
  label: string
}

export interface ProviderRoutingRow {
  key: string
  mode: AuxiliaryRoutingMode
  value: string
  selectValue: string
  label: string
  options: ProviderOption[]
  manual: boolean
}

export interface EmbeddingRoutingRow {
  key: string
  mode: EmbeddingRoutingMode
  enabled: boolean
  required: boolean
  value: string
  providerId: string
  selectValue: string
  label: string
  options: ProviderOption[]
  manual: boolean
}

export interface ModelRoutingViewModel {
  chat: ReadonlyRoutingRow
  auxiliary: ProviderRoutingRow
  transcription: ReadonlyRoutingRow
  embedding: EmbeddingRoutingRow
  advancedOverrideCount: number
}

export interface SettingsSchemaPartition {
  normal: Record<string, SettingsSchemaEntry>
  modelStrategy: Record<string, SettingsSchemaEntry>
  advancedProviders: Record<string, SettingsSchemaEntry>
}

type UnknownRecord = Record<string, unknown>

function asRecord(value: unknown): UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as UnknownRecord)
    : {}
}

function cleanString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function hasOwn(record: Readonly<Record<string, unknown>>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key)
}

function isEnabled(value: unknown): boolean {
  return value === true || value === 1 || value === 'true' || value === '1'
}

function providerType(provider: ProviderInfo): string {
  return cleanString(provider.type).toLowerCase()
}

function providerMatchesKind(provider: ProviderInfo, kind: ProviderKind): boolean {
  const type = providerType(provider)
  return kind === 'embedding' ? type === 'embedding' : type !== 'embedding'
}

function providersForKind(
  providers: readonly ProviderInfo[],
  kind: ProviderKind,
): ProviderInfo[] {
  const seen = new Set<string>()
  const result: ProviderInfo[] = []

  for (const provider of providers) {
    const id = cleanString(provider.id)
    if (!id || seen.has(id) || !providerMatchesKind(provider, kind)) continue
    seen.add(id)
    result.push(provider)
  }

  return result
}

function providerDisplayLabel(id: string, providers: readonly ProviderInfo[]): string {
  const provider = providers.find((item) => cleanString(item.id) === id)
  return cleanString(provider?.name) || cleanString(provider?.id) || id
}

function routingSection(routing: UnknownRecord, key: string): UnknownRecord {
  return asRecord(routing[key])
}

function nonNegativeInteger(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) return undefined
  return value
}

export function buildProviderOptions(
  providers: readonly ProviderInfo[],
  config: ProviderOptionsConfig,
): ProviderOption[] {
  const options: ProviderOption[] = [{ label: config.automaticLabel, value: '' }]

  for (const provider of providersForKind(providers, config.kind)) {
    const id = cleanString(provider.id)
    options.push({ label: cleanString(provider.name) || id, value: id })
  }

  options.push({ label: config.manualLabel, value: MANUAL_PROVIDER_VALUE })
  return options
}

export function partitionSettingsSchema(
  schema: Readonly<Record<string, SettingsSchemaEntry>> = {},
): SettingsSchemaPartition {
  const normal: Record<string, SettingsSchemaEntry> = {}
  const modelStrategy: Record<string, SettingsSchemaEntry> = {}
  const advancedProviders: Record<string, SettingsSchemaEntry> = {}

  for (const [key, entry] of Object.entries(schema)) {
    if (entry.invisible) continue
    const tier = cleanString((entry as TieredSettingsSchemaEntry).ui_tier)
    if (MODEL_STRATEGY_KEYS.has(key) || tier === 'primary') modelStrategy[key] = entry
    else if (tier === 'advanced_provider') advancedProviders[key] = entry
    else normal[key] = entry
  }

  return { normal, modelStrategy, advancedProviders }
}

export function buildDirtySettingsPayload(
  values: Readonly<Record<string, unknown>>,
  dirtyKeys: Iterable<string>,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {}

  for (const key of dirtyKeys) {
    if (Object.prototype.hasOwnProperty.call(values, key)) payload[key] = values[key]
  }

  return payload
}

function derivedAdvancedOverrideCount(
  schema: Readonly<Record<string, SettingsSchemaEntry>>,
  values: Readonly<Record<string, unknown>>,
): number {
  const keys = new Set<string>(ADVANCED_PROVIDER_KEYS)
  for (const [key, entry] of Object.entries(schema)) {
    if (cleanString((entry as TieredSettingsSchemaEntry).ui_tier) === 'advanced_provider') {
      keys.add(key)
    }
  }

  let count = 0
  for (const key of keys) {
    if (cleanString(values[key])) count += 1
  }
  return count
}

function embeddingModeFromInventory(count: number): EmbeddingRoutingMode {
  if (count === 0) return 'unavailable'
  if (count === 1) return 'auto'
  return 'selection_required'
}

function metadataEmbeddingMode(value: unknown): EmbeddingRoutingMode | undefined {
  switch (cleanString(value)) {
    case 'disabled':
    case 'unavailable':
    case 'auto':
    case 'selection_required':
    case 'explicit':
      return cleanString(value) as EmbeddingRoutingMode
    default:
      return undefined
  }
}

export function buildModelRoutingViewModel(
  response: SettingsResponseWithModelRouting,
  labels: Readonly<ModelRoutingLabels> = DEFAULT_MODEL_ROUTING_LABELS,
): ModelRoutingViewModel {
  const schema = response.schema ?? {}
  const values = response.values ?? {}
  const providers = response.providers ?? []
  const routing = asRecord(response.model_routing)
  const auxiliaryRouting = routingSection(routing, 'auxiliary')
  const transcriptionRouting = routingSection(routing, 'transcription')
  const embeddingRouting = routingSection(routing, 'embedding')
  const chatRouting = routingSection(routing, 'chat')

  const textProviders = providersForKind(providers, 'text')
  const embeddingProviders = providersForKind(providers, 'embedding')

  const auxiliaryValue = hasOwn(values, AUXILIARY_PROVIDER_KEY)
    ? cleanString(values[AUXILIARY_PROVIDER_KEY])
    : cleanString(auxiliaryRouting.provider_id)
  const auxiliaryOptions = buildProviderOptions(providers, {
    kind: 'text',
    automaticLabel: labels.followCurrentChat,
    manualLabel: labels.manualInput,
  })
  const auxiliaryKnown = textProviders.some(
    (provider) => cleanString(provider.id) === auxiliaryValue,
  )
  const auxiliaryManual = Boolean(auxiliaryValue) && !auxiliaryKnown

  const transcriptionProviderId = hasOwn(values, 'sylanne_alpha_transcription_provider_id')
    ? cleanString(values.sylanne_alpha_transcription_provider_id)
    : cleanString(transcriptionRouting.provider_id)

  const reportedEmbeddingMode = metadataEmbeddingMode(embeddingRouting.mode)
  const embeddingEnabled = hasOwn(values, EMBEDDING_ENABLED_KEY)
    ? isEnabled(values[EMBEDDING_ENABLED_KEY])
    : reportedEmbeddingMode !== undefined && reportedEmbeddingMode !== 'disabled'
  const configuredEmbeddingId = hasOwn(values, EMBEDDING_PROVIDER_KEY)
    ? cleanString(values[EMBEDDING_PROVIDER_KEY])
    : cleanString(embeddingRouting.provider_id)
  let embeddingMode: EmbeddingRoutingMode
  if (!embeddingEnabled) embeddingMode = 'disabled'
  else if (configuredEmbeddingId) embeddingMode = 'explicit'
  else if (
    reportedEmbeddingMode === 'auto' ||
    reportedEmbeddingMode === 'selection_required' ||
    reportedEmbeddingMode === 'unavailable'
  ) {
    embeddingMode = reportedEmbeddingMode
  } else {
    embeddingMode = embeddingModeFromInventory(embeddingProviders.length)
  }

  const automaticEmbeddingId =
    embeddingMode === 'auto'
      ? cleanString(embeddingRouting.provider_id) || cleanString(embeddingProviders[0]?.id)
      : ''
  const effectiveEmbeddingId = configuredEmbeddingId || automaticEmbeddingId
  const embeddingKnown = embeddingProviders.some(
    (provider) => cleanString(provider.id) === configuredEmbeddingId,
  )
  const embeddingManual = Boolean(configuredEmbeddingId) && !embeddingKnown
  const embeddingOptions = buildProviderOptions(providers, {
    kind: 'embedding',
    automaticLabel:
      embeddingMode === 'selection_required'
        ? labels.selectEmbedding
        : labels.automaticEmbedding,
    manualLabel: labels.manualInput,
  })

  let embeddingLabel = labels.embeddingDisabled
  if (embeddingMode === 'unavailable') embeddingLabel = labels.embeddingUnavailable
  else if (embeddingMode === 'selection_required') embeddingLabel = labels.selectEmbedding
  else if (effectiveEmbeddingId) {
    embeddingLabel = providerDisplayLabel(effectiveEmbeddingId, embeddingProviders)
  } else if (embeddingMode === 'auto') embeddingLabel = labels.automaticEmbedding

  const reportedOverrideCount = nonNegativeInteger(routing.advanced_override_count)
  const fallbackOverrideCount = derivedAdvancedOverrideCount(schema, values)
  const localOverrideStateKnown =
    ADVANCED_PROVIDER_KEYS.some((key) => hasOwn(values, key)) ||
    Object.entries(schema).some(
      ([key, entry]) =>
        cleanString((entry as TieredSettingsSchemaEntry).ui_tier) ===
          'advanced_provider' && hasOwn(values, key),
    )
  const advancedOverrideCount = localOverrideStateKnown
    ? fallbackOverrideCount
    : (reportedOverrideCount ?? fallbackOverrideCount)

  return {
    chat: {
      mode: cleanString(chatRouting.mode) || 'current_conversation',
      label: labels.currentConversation,
    },
    auxiliary: {
      key: AUXILIARY_PROVIDER_KEY,
      mode: auxiliaryValue ? 'explicit' : 'inherit',
      value: auxiliaryValue,
      selectValue: auxiliaryManual ? MANUAL_PROVIDER_VALUE : auxiliaryValue,
      label: auxiliaryValue
        ? providerDisplayLabel(auxiliaryValue, textProviders)
        : labels.followCurrentChat,
      options: auxiliaryOptions,
      manual: auxiliaryManual,
    },
    transcription: {
      mode: transcriptionProviderId ? 'override' : cleanString(transcriptionRouting.mode) || 'auto',
      label: transcriptionProviderId
        ? providerDisplayLabel(transcriptionProviderId, textProviders)
        : labels.automaticMultimodal,
    },
    embedding: {
      key: EMBEDDING_PROVIDER_KEY,
      mode: embeddingMode,
      enabled: embeddingEnabled,
      required: embeddingMode === 'selection_required',
      value: configuredEmbeddingId,
      providerId: effectiveEmbeddingId,
      selectValue: embeddingManual ? MANUAL_PROVIDER_VALUE : configuredEmbeddingId,
      label: embeddingLabel,
      options: embeddingOptions,
      manual: embeddingManual,
    },
    advancedOverrideCount,
  }
}
