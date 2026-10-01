import type { SettingsResponse, SettingsSchemaEntry } from './api/types'

export interface ModelRoutingTargetState {
  mode?: string
  provider_id?: string
  [key: string]: unknown
}

export interface ModelRoutingState {
  chat?: ModelRoutingTargetState
  auxiliary?: ModelRoutingTargetState
  transcription?: ModelRoutingTargetState
  embedding?: ModelRoutingTargetState
  advanced_override_count?: unknown
  [key: string]: unknown
}

export type SettingsResponseWithModelRouting = SettingsResponse & {
  model_routing?: ModelRoutingState
}

export type SettingsUiTier = 'primary' | 'advanced_provider'

export type TieredSettingsSchemaEntry = SettingsSchemaEntry & {
  ui_tier?: SettingsUiTier | string
}
