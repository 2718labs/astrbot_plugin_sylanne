import { hasFields, isInteger, isRecord, isText } from './contract.ts'

export interface ProjectContextItem {
  project_ref: string; recipe_ref: string; source_ref: string; c02_operation_id: string
  activity_id: string; audience_ref: string; parent_budget_lease_ref: string
  binding_ref: string | null; social_role: string | null; norm_refs: string[]
}
export interface ProjectContextOptions {
  schema: 'd03.owner-artifact-project-context-options.v1'
  namespace: { bot_id: string; persona_id: string }
  catalogue: { head_ref: string; head_revision: number; candidate_ref: string; roles: string[]; norms: string[] }
  items: ProjectContextItem[]
}
export interface ProjectContextAttempt {
  scope: string; options: ProjectContextOptions; item: ProjectContextItem
  role: string; norms: string[]; id: string
}
// Preserve an uncertain command across advanced-setting tab navigation.
export const pendingProjectContextAttempts = new Map<string, ProjectContextAttempt>()
const texts = (value: unknown, max: number): value is string[] => Array.isArray(value)
  && value.length <= max && value.every(item => isText(item) && item.length <= 4096)
  && new Set(value).size === value.length
export function validateProjectContextOptions(value: unknown, scope: string): ProjectContextOptions {
  if (!hasFields(value, ['schema','namespace','catalogue','items'])
    || value.schema !== 'd03.owner-artifact-project-context-options.v1'
    || !hasFields(value.namespace, ['bot_id','persona_id'])
    || value.namespace.bot_id + '/' + value.namespace.persona_id !== scope
    || !hasFields(value.catalogue, ['head_ref','head_revision','candidate_ref','roles','norms'])
    || !isText(value.catalogue.head_ref) || !isInteger(value.catalogue.head_revision)
    || value.catalogue.head_revision < 1 || !isText(value.catalogue.candidate_ref)
    || !texts(value.catalogue.roles, 128) || !texts(value.catalogue.norms, 128)
    || !Array.isArray(value.items) || value.items.length > 64) throw new Error('当前项目目录或范围无效。')
  const refs = new Set<string>()
  const allowedNorms = value.catalogue.norms
  for (const item of value.items) {
    if (!hasFields(item, ['project_ref','recipe_ref','source_ref','c02_operation_id','activity_id','audience_ref',
      'parent_budget_lease_ref','binding_ref','social_role','norm_refs'])
      || !isText(item.project_ref)
      || !['project_ref','recipe_ref','source_ref','c02_operation_id','activity_id','audience_ref','parent_budget_lease_ref']
        .every(key => isText(item[key]) && item[key].length <= 4096)
      || item.binding_ref !== null && !isText(item.binding_ref)
      || item.social_role !== null && (!isText(item.social_role) || !value.catalogue.roles.includes(item.social_role))
      || !texts(item.norm_refs, 32) || item.norm_refs.some(ref => !allowedNorms.includes(ref))
      || refs.has(item.project_ref)) throw new Error('当前项目配置原件不兼容。')
    refs.add(item.project_ref)
  }
  return value as unknown as ProjectContextOptions
}

export function projectContextInput(options: ProjectContextOptions, item: ProjectContextItem,
  socialRole: string, normRefs: string[]) {
  if (!options.items.includes(item) || !options.catalogue.roles.includes(socialRole)
    || !texts(normRefs, 16) || normRefs.some(ref => !options.catalogue.norms.includes(ref)))
    throw new Error('请选择本次已读取目录中的角色与规范。')
  return { activity_id: item.activity_id, audience_ref: item.audience_ref,
    parent_budget_lease_ref: item.parent_budget_lease_ref,
    request: { project_ref: item.project_ref, recipe_ref: item.recipe_ref, source_ref: item.source_ref,
      social_role: socialRole, norm_refs: [...normRefs] } }
}

export function validateProjectContextReceipt(value: unknown, operationId: string) {
  if (!hasFields(value, ['schema','operation_id','action','input_digest','original_digest','original'])
    || value.schema !== 'd12.domain-operation-receipt.v1' || value.operation_id !== operationId
    || value.action !== 'domain_adopt_owner_artifact_project_context_v1'
    || !isText(value.input_digest) || !/^[0-9a-f]{64}$/.test(value.input_digest)
    || !isText(value.original_digest) || !/^[0-9a-f]{64}$/.test(value.original_digest)
    || !isRecord(value.original) || value.original.operation_id !== operationId)
    throw new Error('项目配置没有返回对应操作原件。')
  return value
}
