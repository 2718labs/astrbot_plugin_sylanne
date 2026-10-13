import { hasFields, isInteger, isText, validateScope } from './contract.ts'

export interface RelationDimension {
  dimension: string; status: string; availability: string; source_qualification: 'qualified' | 'unavailable' | 'unknown'
  estimate: number | 'unknown'; influence_status: 'not_evaluated' | 'unapplied_pending' | 'legacy_unresolved' | 'bounded_applied'
  diagnostic_error?: 'unregistered_legacy_relationship_state'; domain?: string; context_id?: string; time_status?: 'current' | 'time_unavailable' | 'stale'
  subjective_confidence?: number | null; evidence_coverage?: 'complete' | 'partial' | 'unknown'; independent_external_families?: number
}
export interface RelationsProjection {
  namespace: { bot: string; persona: string }; access_generation: number; view_type: 'relations'
  data: { relations: { subject_entity_ref: string; dimensions: RelationDimension[] }[]; coverage: 'complete' }
  snapshot_epoch?: number; coverage?: { requested_types: string[]; returned_atoms: number; truncated: boolean }; next_cursor?: string | null
}
export class RelationsContractError extends Error { constructor() { super('关系分面的正式字段不兼容。') } }
function invalid(): never { throw new RelationsContractError() }
const available = ['unknown', 'available', 'unavailable', 'stale', 'blocked_rebuild', 'rebuilt', 'sanitized', 'reset']
const finite = (value: unknown, low: number, high: number): value is number => typeof value === 'number' && Number.isFinite(value) && value >= low && value <= high
export function validateRelationsProjection(value: unknown, scope: string): RelationsProjection {
  validateScope(scope)
  if (!hasFields(value, ['namespace', 'access_generation', 'view_type', 'data'], ['snapshot_epoch', 'coverage', 'next_cursor'])
    || !hasFields(value.namespace, ['bot', 'persona']) || `${value.namespace.bot}/${value.namespace.persona}` !== scope
    || !isInteger(value.access_generation, 1) || value.view_type !== 'relations' || !hasFields(value.data, ['relations', 'coverage'])
    || value.data.coverage !== 'complete' || !Array.isArray(value.data.relations) || value.data.relations.length > 100
    || value.snapshot_epoch !== undefined && !isInteger(value.snapshot_epoch)
    || value.next_cursor !== undefined && value.next_cursor !== null && !isText(value.next_cursor)) invalid()
  if (value.coverage !== undefined && (!hasFields(value.coverage, ['requested_types', 'returned_atoms', 'truncated']) || !Array.isArray(value.coverage.requested_types)
    || !value.coverage.requested_types.every(isText) || !isInteger(value.coverage.returned_atoms) || typeof value.coverage.truncated !== 'boolean')) invalid()
  const subjects = new Set<string>()
  for (const row of value.data.relations) {
    if (!hasFields(row, ['subject_entity_ref', 'dimensions']) || !isText(row.subject_entity_ref) || subjects.has(row.subject_entity_ref) || !Array.isArray(row.dimensions)) invalid()
    subjects.add(row.subject_entity_ref)
    const dimensions = new Set<string>()
    for (const item of row.dimensions) {
      const rich = typeof item === 'object' && item !== null && 'domain' in item
      if (!hasFields(item, ['dimension', 'status', 'availability', 'source_qualification', 'estimate', 'influence_status', ...(rich ? ['domain', 'context_id', 'time_status', 'subjective_confidence', 'evidence_coverage', 'independent_external_families'] : [])], rich ? [] : ['diagnostic_error'])
        || !isText(item.dimension) || item.status !== item.availability || !available.includes(item.availability as string)
        || !['qualified', 'unavailable', 'unknown'].includes(item.source_qualification as string)) invalid()
      const identity = [item.dimension, rich ? item.domain : '', rich ? item.context_id : ''].join(':')
      if (dimensions.has(identity)) invalid(); dimensions.add(identity)
      if (rich) {
        if (!isText(item.domain) || typeof item.context_id !== 'string' || !/^[0-9a-f]{32}$/.test(item.context_id)
          || !['available', 'blocked_rebuild', 'unknown', 'stale'].includes(item.availability as string) || item.source_qualification !== 'qualified'
          || !['current', 'time_unavailable', 'stale'].includes(item.time_status as string)
          || !['complete', 'partial', 'unknown'].includes(item.evidence_coverage as string) || !isInteger(item.independent_external_families) || item.independent_external_families > 16
          || item.availability === 'available' && (!finite(item.estimate, -1, 1) || !finite(item.subjective_confidence, 0, 1) || item.influence_status !== 'bounded_applied')
          || item.availability !== 'available' && (item.estimate !== 'unknown' || item.subjective_confidence !== null || item.influence_status !== 'unapplied_pending')) invalid()
      } else if (item.estimate !== 'unknown' || !['not_evaluated', 'unapplied_pending', 'legacy_unresolved'].includes(item.influence_status as string)
        || item.diagnostic_error !== undefined && item.diagnostic_error !== 'unregistered_legacy_relationship_state') invalid()
    }
  }
  return value as unknown as RelationsProjection
}
