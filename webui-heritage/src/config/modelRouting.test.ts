import { describe, expect, it } from 'vitest'
import type { SettingsResponse } from '../api/types'
import configViewSource from '../views/ConfigView.vue?raw'
import {
  ADVANCED_PROVIDER_KEYS,
  MANUAL_PROVIDER_VALUE,
  buildDirtySettingsPayload,
  buildModelRoutingViewModel,
  buildProviderOptions,
  partitionSettingsSchema,
} from './modelRouting'

const providers = [
  { id: 'chat-main', name: 'Main Chat', type: 'llm' },
  { id: 'chat-aux', name: 'Small Helper', type: 'llm' },
  { id: 'legacy-text', name: 'Legacy Text' },
  { id: 'embed-a', name: 'Embedding A', type: 'embedding' },
  { id: 'embed-b', name: 'Embedding B', type: 'embedding' },
]

function response(overrides: Partial<SettingsResponse> = {}): SettingsResponse {
  return {
    schema: {},
    values: {},
    providers,
    ...overrides,
  }
}

describe('buildModelRoutingViewModel', () => {
  it('shows zero required provider choices in automatic mode', () => {
    const vm = buildModelRoutingViewModel(
      response({
        values: {
          sylanne_alpha_aux_provider_id: '',
          sylanne_alpha_embedding_memory_enabled: false,
        },
        model_routing: {
          chat: { mode: 'current_conversation' },
          auxiliary: { mode: 'inherit', provider_id: '' },
          transcription: { mode: 'auto' },
          embedding: { mode: 'disabled', provider_id: '' },
          advanced_override_count: 0,
        },
      }),
    )

    expect(vm.chat).toEqual({
      mode: 'current_conversation',
      label: '跟随 AstrBot 当前会话',
    })
    expect(vm.auxiliary.value).toBe('')
    expect(vm.auxiliary.label).toBe('跟随当前聊天模型')
    expect(vm.auxiliary.manual).toBe(false)
    expect(vm.auxiliary.options[0]).toEqual({ label: '跟随当前聊天模型', value: '' })
    expect(vm.auxiliary.options.map((option) => option.value)).not.toContain('embed-a')
    expect(vm.auxiliary.options.at(-1)?.value).toBe(MANUAL_PROVIDER_VALUE)
    expect(vm.embedding.mode).toBe('disabled')
    expect(vm.advancedOverrideCount).toBe(0)
  })

  it('keeps backend-reported legacy overrides visible as an active count', () => {
    const vm = buildModelRoutingViewModel(
      response({
        values: {
          sylanne_alpha_life_simulation_provider_id: 'life-model',
          sylanne_alpha_qzone_provider_id: 'qzone-model',
        },
        model_routing: { advanced_override_count: 2 },
      }),
    )

    expect(vm.advancedOverrideCount).toBe(2)
  })

  it('uses current local values when backend override metadata is stale', () => {
    const vm = buildModelRoutingViewModel(
      response({
        values: {
          sylanne_alpha_life_simulation_provider_id: 'stale-local-value',
        },
        model_routing: { advanced_override_count: 0 },
      }),
    )

    expect(vm.advancedOverrideCount).toBe(1)
  })

  it('falls back to local override counting when backend metadata is invalid', () => {
    const vm = buildModelRoutingViewModel(
      response({
        values: {
          sylanne_alpha_life_simulation_provider_id: 'life-model',
        },
        model_routing: { advanced_override_count: -1 },
      }),
    )

    expect(vm.advancedOverrideCount).toBe(1)
  })

  it('derives legacy override count when talking to an older backend', () => {
    const vm = buildModelRoutingViewModel(
      response({
        values: {
          sylanne_alpha_life_simulation_provider_id: 'life-model',
          sylanne_alpha_qzone_provider_id: '  qzone-model  ',
          sylanne_alpha_transcription_provider_id: '',
        },
      }),
    )

    expect(vm.advancedOverrideCount).toBe(2)
  })

  it('requires embedding choice only when automatic selection is ambiguous', () => {
    const vm = buildModelRoutingViewModel(
      response({
        values: {
          sylanne_alpha_embedding_memory_enabled: true,
          sylanne_alpha_embedding_memory_provider_id: '',
        },
      }),
    )

    expect(vm.embedding.mode).toBe('selection_required')
    expect(vm.embedding.required).toBe(true)
    expect(vm.embedding.options.map((option) => option.value)).toEqual([
      '',
      'embed-a',
      'embed-b',
      MANUAL_PROVIDER_VALUE,
    ])
  })

  it('reports actionable zero and automatic one-provider embedding states', () => {
    const zero = buildModelRoutingViewModel(
      response({
        providers: providers.filter((provider) => provider.type !== 'embedding'),
        values: { sylanne_alpha_embedding_memory_enabled: true },
      }),
    )
    const one = buildModelRoutingViewModel(
      response({
        providers: providers.filter((provider) => provider.id !== 'embed-b'),
        values: { sylanne_alpha_embedding_memory_enabled: true },
      }),
    )

    expect(zero.embedding.mode).toBe('unavailable')
    expect(zero.embedding.providerId).toBe('')
    expect(one.embedding.mode).toBe('auto')
    expect(one.embedding.providerId).toBe('embed-a')
    expect(one.embedding.label).toBe('Embedding A')
  })

  it('preserves known and manual explicit provider IDs', () => {
    const known = buildModelRoutingViewModel(
      response({ values: { sylanne_alpha_aux_provider_id: 'chat-aux' } }),
    )
    const manual = buildModelRoutingViewModel(
      response({
        values: {
          sylanne_alpha_aux_provider_id: 'private-provider',
          sylanne_alpha_embedding_memory_enabled: true,
          sylanne_alpha_embedding_memory_provider_id: 'private-embedding',
        },
      }),
    )

    expect(known.auxiliary).toMatchObject({
      mode: 'explicit',
      value: 'chat-aux',
      selectValue: 'chat-aux',
      label: 'Small Helper',
      manual: false,
    })
    expect(manual.auxiliary).toMatchObject({
      mode: 'explicit',
      value: 'private-provider',
      selectValue: MANUAL_PROVIDER_VALUE,
      label: 'private-provider',
      manual: true,
    })
    expect(manual.embedding).toMatchObject({
      mode: 'explicit',
      providerId: 'private-embedding',
      selectValue: MANUAL_PROVIDER_VALUE,
      manual: true,
    })
  })

  it('uses derived routing metadata when values omit the canonical auxiliary key', () => {
    const vm = buildModelRoutingViewModel(
      response({
        model_routing: {
          auxiliary: { mode: 'explicit', provider_id: 'chat-aux' },
          transcription: { mode: 'override', provider_id: 'chat-main' },
        },
      }),
    )

    expect(vm.auxiliary.value).toBe('chat-aux')
    expect(vm.auxiliary.label).toBe('Small Helper')
    expect(vm.transcription).toEqual({ mode: 'override', label: 'Main Chat' })
  })

  it('lets current form values override stale load-time routing metadata', () => {
    const vm = buildModelRoutingViewModel(
      response({
        values: {
          sylanne_alpha_aux_provider_id: '',
          sylanne_alpha_embedding_memory_enabled: true,
          sylanne_alpha_embedding_memory_provider_id: '',
        },
        model_routing: {
          auxiliary: { mode: 'explicit', provider_id: 'chat-aux' },
          embedding: { mode: 'disabled', provider_id: '' },
        },
      }),
    )

    expect(vm.auxiliary.mode).toBe('inherit')
    expect(vm.embedding.enabled).toBe(true)
    expect(vm.embedding.mode).toBe('selection_required')
  })

  it('derives the override badge from current form values instead of stale metadata', () => {
    const vm = buildModelRoutingViewModel(
      response({
        values: {
          sylanne_alpha_life_simulation_provider_id: 'life-model',
          sylanne_alpha_main_assessor_provider_id: '',
        },
        model_routing: {
          advanced_override_count: 0,
        },
      }),
    )

    expect(vm.advancedOverrideCount).toBe(1)
  })
})

describe('provider option helpers', () => {
  it('prepends inheritance, filters by provider type, deduplicates, and appends manual input', () => {
    const options = buildProviderOptions(
      [
        ...providers,
        { id: 'chat-aux', name: 'Duplicate', type: 'llm' },
        { id: '', name: 'Blank', type: 'llm' },
      ],
      {
        kind: 'text',
        automaticLabel: 'Inherit',
        manualLabel: 'Manual',
      },
    )

    expect(options).toEqual([
      { label: 'Inherit', value: '' },
      { label: 'Main Chat', value: 'chat-main' },
      { label: 'Small Helper', value: 'chat-aux' },
      { label: 'Legacy Text', value: 'legacy-text' },
      { label: 'Manual', value: MANUAL_PROVIDER_VALUE },
    ])
  })
})

describe('Task 6 pure integration helpers', () => {
  it('does not expose the removed synchronous fast-assessor provider', () => {
    expect(ADVANCED_PROVIDER_KEYS).not.toContain(
      'sylanne_alpha_fast_assessor_provider_id',
    )
    expect(configViewSource).not.toContain('sylanne_alpha_fast_assessor_')
  })

  it('partitions visible schema without duplicating advanced provider rows', () => {
    const schema = {
      sylanne_persona_name: { type: 'string', default: '' },
      sylanne_alpha_aux_provider_id: { type: 'string', default: '', ui_tier: 'primary' },
      sylanne_alpha_life_simulation_provider_id: {
        type: 'string',
        default: '',
        ui_tier: 'advanced_provider',
      },
      sylanne_alpha_embedding_memory_enabled: { type: 'bool', default: false },
      sylanne_alpha_embedding_memory_provider_id: {
        type: 'string',
        default: '',
        ui_tier: 'primary',
      },
    } as unknown as NonNullable<SettingsResponse['schema']>

    const partition = partitionSettingsSchema(schema)

    expect(Object.keys(partition.normal)).toEqual(['sylanne_persona_name'])
    expect(Object.keys(partition.modelStrategy)).toEqual([
      'sylanne_alpha_aux_provider_id',
      'sylanne_alpha_embedding_memory_enabled',
      'sylanne_alpha_embedding_memory_provider_id',
    ])
    expect(Object.keys(partition.advancedProviders)).toEqual([
      'sylanne_alpha_life_simulation_provider_id',
    ])
  })

  it('does not count embedding selection as an advanced text-model override', () => {
    const vm = buildModelRoutingViewModel(
      response({
        values: {
          sylanne_alpha_embedding_memory_provider_id: 'embed-a',
        },
      }),
    )

    expect(vm.advancedOverrideCount).toBe(0)
  })

  it('builds a dirty-only payload and preserves an explicit empty inheritance value', () => {
    const payload = buildDirtySettingsPayload(
      {
        sylanne_alpha_aux_provider_id: '',
        sylanne_alpha_life_simulation_provider_id: 'life-model',
        untouched: 'do-not-send',
      },
      new Set([
        'sylanne_alpha_aux_provider_id',
        'sylanne_alpha_life_simulation_provider_id',
        'missing',
      ]),
    )

    expect(payload).toEqual({
      sylanne_alpha_aux_provider_id: '',
      sylanne_alpha_life_simulation_provider_id: 'life-model',
    })
  })
})

describe('ConfigView model strategy source contract', () => {
  const source = configViewSource

  it('renders the model strategy before ordinary right-pane groups', () => {
    const strategy = source.indexOf('data-testid="model-strategy"')
    const ordinaryGroups = source.indexOf('v-for="group in rightGroups"')

    expect(strategy).toBeGreaterThan(-1)
    expect(ordinaryGroups).toBeGreaterThan(strategy)
  })

  it('keeps advanced provider overrides locally collapsed', () => {
    expect(source).toContain('v-model="advancedOverridesOpen"')
    expect(source).toContain('v-if="advancedOverridesOpen"')
  })
})
