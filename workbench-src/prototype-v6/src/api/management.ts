import {operationIdV1} from './browser-crypto.ts'
/** PROPOSED management extension. Not an assertion that any backend implements it. */
import { isInteger, isRecord, UUID4 } from './contract.ts'
export const MANAGEMENT_SCHEMA = 'sylanne.workbench-management.v1'
export const MANAGEMENT_PREFIX = '/management/v1'
export const LOG_LIMIT = 50
export const MANAGEMENT_RESPONSE_MAX_BYTES = 512 * 1024
export type ApplySemantics = 'read_only' | 'next_restart' | 'immediate'
export type LogLevel = 'INFO' | 'WARNING' | 'ERROR'
export interface ManagementCapabilities {
  schema_version: 'sylanne.workbench-capabilities.v1'; installation_id: string; access_generation: number
  capabilities: {
    logs: { available: boolean; reason_code: string; max_page_size: 50; redaction: 'server_allowlist.v1' }
    settings: { available: boolean; reason_code: string; writable_fields: ('enabled')[]; apply_semantics: ApplySemantics }
  }
}
export interface LogFilter { level: 'ALL' | LogLevel; query: string }
export interface LogEntry { event_id: string; occurred_at: string; level: LogLevel; event_code: string; summary: string; redacted: true }
export interface LogPage { schema_version: 'sylanne.workbench-logs.v1'; installation_id: string; access_generation: number; entries: LogEntry[]; next_cursor: string | null; snapshot_id: string; redaction: 'server_allowlist.v1' }
export interface SettingsSnapshot { schema_version: 'sylanne.workbench-settings.v1'; installation_id: string; access_generation: number; revision: string; values: { enabled: boolean; authority_profile: string }; writable_fields: ('enabled')[]; apply_semantics: ApplySemantics }
export interface SettingsReceipt { schema_version: 'sylanne.workbench-settings-receipt.v1'; installation_id: string; access_generation: number; operation_id: string; revision: string; applied: 'immediate' | 'next_restart' }
export class ManagementContractError extends Error { constructor() { super('Invalid management contract'); this.name = 'ManagementContractError' } }
function invalid(): never { throw new ManagementContractError() }
function exact(v: unknown, keys: string[]): asserts v is Record<string, unknown> {
  if (!isRecord(v) || Object.keys(v).length !== keys.length || keys.some(k => !(k in v))) invalid()
}
const text = (v: unknown, max: number, empty = false): v is string => typeof v === 'string' && v.length >= (empty ? 0 : 1) && v.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v)
const code = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(v)
const fields = (v: unknown): v is ('enabled')[] => Array.isArray(v) && (v.length === 0 || v.length === 1 && v[0] === 'enabled')
const semantics = (v: unknown): v is ApplySemantics => typeof v === 'string' && ['read_only', 'next_restart', 'immediate'].includes(v)
function bound(v: Record<string, unknown>, caps: ManagementCapabilities) { if (v.installation_id !== caps.installation_id || v.access_generation !== caps.access_generation) invalid() }
export function managementRequest(extra: object = {}, operationId = operationIdV1()) {
  if (!UUID4.test(operationId)) invalid()
  return { schema_version: MANAGEMENT_SCHEMA, operation_id: operationId, ...extra }
}
export function binding(caps: ManagementCapabilities) { return { installation_id: caps.installation_id, access_generation: caps.access_generation } }
export function validateCapabilities(body: unknown): ManagementCapabilities {
  exact(body, ['schema_version', 'installation_id', 'access_generation', 'capabilities'])
  if (body.schema_version !== 'sylanne.workbench-capabilities.v1' || !text(body.installation_id, 128) || !isInteger(body.access_generation, 1)) invalid()
  exact(body.capabilities, ['logs', 'settings'])
  const logs = body.capabilities.logs, settings = body.capabilities.settings
  exact(logs, ['available', 'reason_code', 'max_page_size', 'redaction'])
  exact(settings, ['available', 'reason_code', 'writable_fields', 'apply_semantics'])
  if (typeof logs.available !== 'boolean' || !code(logs.reason_code) || logs.max_page_size !== LOG_LIMIT || logs.redaction !== 'server_allowlist.v1' || (logs.available && logs.reason_code !== 'available') ||
      typeof settings.available !== 'boolean' || !code(settings.reason_code) || !fields(settings.writable_fields) || !semantics(settings.apply_semantics) || (settings.available && settings.reason_code !== 'available') ||
      (!settings.available && (settings.writable_fields.length || settings.apply_semantics !== 'read_only')) ||
      (settings.writable_fields.length === 0) !== (settings.apply_semantics === 'read_only')) invalid()
  return body as unknown as ManagementCapabilities
}
export function validateLogFilter(filter: LogFilter, cursor: string | null) {
  exact(filter, ['level', 'query'])
  if (typeof filter.level !== 'string' || !['ALL','INFO','WARNING','ERROR'].includes(filter.level) || !text(filter.query, 128, true) || cursor !== null && !text(cursor, 2048)) invalid()
}
export function validateLogPage(body: unknown, caps: ManagementCapabilities): LogPage {
  exact(body, ['schema_version', 'installation_id', 'access_generation', 'entries', 'next_cursor', 'snapshot_id', 'redaction']); bound(body, caps)
  if (body.schema_version !== 'sylanne.workbench-logs.v1' || !caps.capabilities.logs.available || body.redaction !== 'server_allowlist.v1' || !text(body.snapshot_id, 128) || !Array.isArray(body.entries) || body.entries.length > LOG_LIMIT || body.next_cursor !== null && !text(body.next_cursor, 2048)) invalid()
  let previous: { time: number; id: string } | null = null
  const ids = new Set<string>()
  for (const row of body.entries) {
    exact(row, ['event_id','occurred_at','level','event_code','summary','redacted'])
    if (!text(row.event_id, 128) || ids.has(row.event_id) || !text(row.occurred_at, 40) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(row.occurred_at) || !Number.isFinite(Date.parse(row.occurred_at)) || typeof row.level !== 'string' || !['INFO','WARNING','ERROR'].includes(row.level) || !code(row.event_code) || !text(row.summary,1000) || row.redacted !== true) invalid()
    const time = Date.parse(row.occurred_at)
    if (new Date(time).toISOString().slice(0,19) !== row.occurred_at.slice(0,19)) invalid()
    if (previous && (time > previous.time || time === previous.time && row.event_id >= previous.id)) invalid()
    previous = {time, id: row.event_id}; ids.add(row.event_id)
  }
  if (body.entries.length === 0 && body.next_cursor !== null) invalid()
  return body as unknown as LogPage
}
export function validateSettings(body: unknown, caps: ManagementCapabilities): SettingsSnapshot {
  exact(body, ['schema_version','installation_id','access_generation','revision','values','writable_fields','apply_semantics']); bound(body,caps)
  exact(body.values, ['enabled','authority_profile'])
  if (!caps.capabilities.settings.available || body.schema_version !== 'sylanne.workbench-settings.v1' || !text(body.revision,128) || typeof body.values.enabled !== 'boolean' || !text(body.values.authority_profile,64) || !fields(body.writable_fields) || !semantics(body.apply_semantics) || JSON.stringify(body.writable_fields) !== JSON.stringify(caps.capabilities.settings.writable_fields) || body.apply_semantics !== caps.capabilities.settings.apply_semantics) invalid()
  return body as unknown as SettingsSnapshot
}
export function validateReceipt(body: unknown, caps: ManagementCapabilities, current: SettingsSnapshot, operationId: string): SettingsReceipt {
  exact(body, ['schema_version','installation_id','access_generation','operation_id','revision','applied']); bound(body,caps)
  if (body.schema_version !== 'sylanne.workbench-settings-receipt.v1' || body.operation_id !== operationId || !text(body.revision,128) || body.revision === current.revision || typeof body.applied !== 'string' || !['immediate','next_restart'].includes(body.applied) || body.applied !== caps.capabilities.settings.apply_semantics) invalid()
  return body as unknown as SettingsReceipt
}

/** Management errors are not legacy D12 problems: validate their own exact envelope. */
export function validateManagementProblem(body: unknown, status: number): {code:string;retryable:boolean} {
  exact(body, ['schema_version','problem'])
  if (body.schema_version !== 'sylanne.workbench-error.v1' || !isRecord(body.problem)) invalid()
  const p=body.problem
  exact(p, 'fields' in p ? ['code','retryable','fields'] : ['code','retryable'])
  if (!code(p.code) || typeof p.retryable !== 'boolean' || ('fields' in p && (!Array.isArray(p.fields) || p.fields.length !== 1 || p.fields[0] !== 'enabled'))) invalid()
  const paired: Record<string,number> = {revision_conflict:409,capabilities_changed:409,operation_conflict:409,snapshot_changed:409,cursor_expired:410,validation_failed:422,rate_limited:429}
  if (paired[p.code] !== undefined && paired[p.code] !== status) invalid()
  if ('fields' in p && (status !== 422 || p.code !== 'validation_failed')) invalid()
  return {code:p.code,retryable:p.retryable}
}
