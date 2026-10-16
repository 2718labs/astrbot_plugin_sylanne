
import { hasFields, isInteger, isRecord, isText } from './contract.ts'

export const GENERAL_GROWTH_KINDS = [
  'freeze_general_growth_intent_v1','register_general_growth_trial_start_v1',
  'derive_general_growth_trial_v1','adopt_general_growth_v1',
] as const
export type GeneralGrowthKind = typeof GENERAL_GROWTH_KINDS[number]
export type GeneralGrowthAction = `domain_${GeneralGrowthKind}`
export interface GeneralGrowthHead { key: string; revision: number }
export interface FreezeGeneralGrowthRequest {
  interpretation_ref: string; trigger_original_ref: string; general_growth_intent_ref: string
  growth_proposal_ref: string; counterevidence_query_ref: string
  required_trial_refs: string[]; trial_start_refs: string[]
}
export interface RegisterGeneralGrowthTrialStartRequest {
  original_ref: string; general_growth_intent_ref: string; growth_proposal_ref: string
  completed_trial_ref: string; planned_head: GeneralGrowthHead
  project_ref: string | null; recipe_ref: string | null; step_id: string | null; life_plan_original_ref: string | null
}
export interface DeriveGeneralGrowthTrialRequest {
  original_ref: string; general_growth_intent_ref: string; growth_proposal_ref: string; settled_progress_ref: string
}
export interface AdoptGeneralGrowthRequest {
  general_growth_intent_ref: string; growth_proposal_ref: string; trigger_original_ref: string
  trial_original_refs: string[]; counterevidence_query_ref: string
}
export interface GeneralGrowthRequests {
  freeze_general_growth_intent_v1: FreezeGeneralGrowthRequest
  register_general_growth_trial_start_v1: RegisterGeneralGrowthTrialStartRequest
  derive_general_growth_trial_v1: DeriveGeneralGrowthTrialRequest
  adopt_general_growth_v1: AdoptGeneralGrowthRequest
}
export interface GeneralGrowthInput<K extends GeneralGrowthKind = GeneralGrowthKind> {
  activity_id: string; audience_ref: string; parent_budget_lease_ref: string; request: GeneralGrowthRequests[K]
}
export interface GeneralGrowthReceipt {
  schema: 'd12.domain-operation-receipt.v1'; operation_id: string; action: GeneralGrowthAction
  input_digest: string; original_digest: string; original: Record<string, unknown> & { operation_id: string }
}
export const GENERAL_GROWTH_FIELDS: Record<GeneralGrowthKind, readonly string[]> = {
  freeze_general_growth_intent_v1: ['interpretation_ref','trigger_original_ref','general_growth_intent_ref',
    'growth_proposal_ref','counterevidence_query_ref','required_trial_refs','trial_start_refs'],
  register_general_growth_trial_start_v1: ['original_ref','general_growth_intent_ref','growth_proposal_ref',
    'completed_trial_ref','planned_head','project_ref','recipe_ref','step_id','life_plan_original_ref'],
  derive_general_growth_trial_v1: ['original_ref','general_growth_intent_ref','growth_proposal_ref','settled_progress_ref'],
  adopt_general_growth_v1: ['general_growth_intent_ref','growth_proposal_ref','trigger_original_ref',
    'trial_original_refs','counterevidence_query_ref'],
}
export function isGeneralGrowthKind(value: string): value is GeneralGrowthKind {
  return (GENERAL_GROWTH_KINDS as readonly string[]).includes(value)
}
const locator = (value: unknown): value is string => isText(value) && value.length <= 4096
const originals = (value: unknown): value is string[] => Array.isArray(value) && value.length > 0
  && value.length <= 16 && value.every(locator) && new Set(value).size === value.length
export function validateGeneralGrowthInput<K extends GeneralGrowthKind>(kind: K, value: unknown): GeneralGrowthInput<K> {
  if (!hasFields(value,['activity_id','audience_ref','parent_budget_lease_ref','request'])
    || ![value.activity_id,value.audience_ref,value.parent_budget_lease_ref].every(locator)
    || !hasFields(value.request,[...GENERAL_GROWTH_FIELDS[kind]]))
    throw new Error('请填写本次实际操作、受众、原预算及完整原件定位。')
  const request=value.request
  const special = kind==='freeze_general_growth_intent_v1' ? ['required_trial_refs','trial_start_refs']
    : kind==='register_general_growth_trial_start_v1' ? ['planned_head','project_ref','recipe_ref','step_id','life_plan_original_ref']
    : kind==='adopt_general_growth_v1' ? ['trial_original_refs'] : []
  if (GENERAL_GROWTH_FIELDS[kind].filter(name=>!special.includes(name)).some(name=>!locator(request[name])))
    throw new Error('成长请求缺少实际原件引用。')
  if (kind==='freeze_general_growth_intent_v1') {
    if (!originals(request.required_trial_refs) || !originals(request.trial_start_refs)
      || request.required_trial_refs.length!==request.trial_start_refs.length)
      throw new Error('冻结请求需一一对应的非空试验原件与 start 引用，每组最多16项。')
  } else if (kind==='register_general_growth_trial_start_v1') {
    if (!hasFields(request.planned_head,['key','revision']) || !locator(request.planned_head.key)
      || !isInteger(request.planned_head.revision) || request.planned_head.revision<1)
      throw new Error('试验 start 需已获准 planned head 的真实引用与正版本。')
    const group=['project_ref','recipe_ref','step_id','life_plan_original_ref'].map(name=>request[name])
    if (!(group.every(item=>item===null) || group.every(locator)))
      throw new Error('Life 项目、recipe、step 与已签 plan 四项需完整填写；普通 Action 试验四项均为 null。')
  } else if (kind==='adopt_general_growth_v1' && !originals(request.trial_original_refs)) {
    throw new Error('Owner 采用需实际完成的非空试验原件集，最多16项。')
  }
  return value as unknown as GeneralGrowthInput<K>
}
export function validateGeneralGrowthReceipt(value: unknown, kind: GeneralGrowthKind, operationId: string): GeneralGrowthReceipt {
  if (!hasFields(value,['schema','operation_id','action','input_digest','original_digest','original'])
    || value.schema!=='d12.domain-operation-receipt.v1' || value.operation_id!==operationId
    || value.action!==`domain_${kind}`
    || !isText(value.input_digest) || !/^[0-9a-f]{64}$/.test(value.input_digest)
    || !isText(value.original_digest) || !/^[0-9a-f]{64}$/.test(value.original_digest)
    || !isRecord(value.original) || value.original.operation_id!==operationId)
    throw new Error('未返回该 Owner 操作的真实领域原件。')
  return value as unknown as GeneralGrowthReceipt
}
export interface GeneralGrowthAttempt {
  scope: string; kind: GeneralGrowthKind; input: GeneralGrowthInput; operationId: string
}
export const pendingGeneralGrowthAttempts = new Map<string, GeneralGrowthAttempt>()
