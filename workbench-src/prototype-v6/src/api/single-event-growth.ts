import { hasFields, isRecord, isText } from './contract.ts'

export const SINGLE_EVENT_KINDS = ['register_single_event_growth_policy_v1','prepare_single_event_growth_v1',
  'adopt_single_event_growth_v1','review_single_event_growth_v1','read_single_event_growth_v1'] as const
export type SingleEventKind = typeof SINGLE_EVENT_KINDS[number]
export interface SingleEventHead { key:string; revision:number }
export interface SingleEventGrowthInput {
  activity_id:string; audience_ref:string; parent_budget_lease_ref:string; request:Record<string,unknown>
}
export interface SingleEventGrowthView {
  schema:'d01.single-event-growth-view.v1'; operation_kind:SingleEventKind; operation_id:string
  policy_ref:string; policy_digest:string; input_ref:string|null; input_digest:string|null
  adoption_ref:string|null; adoption_revision:number|null; review_ref:string|null; review_revision:number|null
  disposition:'pending'|'qualified'|'opposed'|'unknown'|'expired'|null; target_block:string|null
  adopted_claim_digest:string|null; review_not_before_utc:number|null; review_due_utc:number|null
  readout_valid_until_utc:number|null; missing_conditions:string[]
}
export interface SingleEventGrowthReceipt {
  schema:'d12.domain-operation-receipt.v1'; operation_id:string; action:string; input_digest:string
  original_digest:string; original:Record<string,unknown>&{operation_id:string}; view:SingleEventGrowthView|null
}
export interface SingleEventGrowthAttempt {
  scope:string; kind:SingleEventKind; operationId:string; input:SingleEventGrowthInput
}
export const SINGLE_EVENT_REQUEST_FIELDS:Record<SingleEventKind,readonly string[]>={
  register_single_event_growth_policy_v1:['terms'],
  prepare_single_event_growth_v1:['input_ref','policy_ref','growth_request','general_growth_intent_ref','continuity_interpretation_ref'],
  adopt_single_event_growth_v1:['input_ref'],
  review_single_event_growth_v1:['adoption_ref','expected_review_revision','continuity_interpretation_ref'],
  read_single_event_growth_v1:['adoption_ref'],
}
export const SINGLE_EVENT_TERMS_FIELDS = ['namespace','policy_ref','revision','expected_persona_head','persona_head_id',
  'target_block','target_kind','base_claim_digest','event_source','event_source_digest','event_provenance_root',
  'event_interpretation','event_interpretation_digest','context_source_refs','scope_versions','exclusion_versions',
  'plasticity_policy_ref','plasticity_policy_digest','observer_policy_ref','observer_policy_digest','valid_from_utc',
  'adopt_before_utc','review_not_before_utc','review_due_utc','readout_valid_until_utc','required_outcome_versions'] as const
const locator=(v:unknown):v is string=>isText(v)&&v.length<=4096
const digest=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v)
const positive=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>0
const time=(v:unknown):v is number=>typeof v==='number'&&Number.isFinite(v)
const heads=(v:unknown):v is SingleEventHead[]=>Array.isArray(v)&&v.length<=128&&v.every(head)
  &&new Set(v.map(x=>x.key)).size===v.length
const refs=(v:unknown,max=128):v is string[]=>Array.isArray(v)&&v.length<=max&&v.every(locator)&&new Set(v).size===v.length
function head(v:unknown):v is SingleEventHead{return hasFields(v,['key','revision'])&&locator(v.key)&&positive(v.revision)}
export function isSingleEventKind(v:string):v is SingleEventKind{return (SINGLE_EVENT_KINDS as readonly string[]).includes(v)}
export function validateSingleEventGrowthInput(kind:SingleEventKind,v:unknown):SingleEventGrowthInput {
  if(!hasFields(v,['activity_id','audience_ref','parent_budget_lease_ref','request'])
    ||![v.activity_id,v.audience_ref,v.parent_budget_lease_ref].every(locator)
    ||!hasFields(v.request,[...SINGLE_EVENT_REQUEST_FIELDS[kind]]))throw new Error('请填写本次实际 activity、受众、父预算与完整具名请求。')
  const r=v.request
  if(kind==='register_single_event_growth_policy_v1'){
    const t=r.terms
    if(!hasFields(t,[...SINGLE_EVENT_TERMS_FIELDS])||!hasFields(t.namespace,['bot_id','persona_id'])
      ||![t.namespace.bot_id,t.namespace.persona_id,t.policy_ref,t.persona_head_id,t.target_block,t.event_provenance_root,t.observer_policy_ref].every(locator)
      ||!positive(t.revision)||!['value','trait','semantic_identity'].includes(String(t.target_kind))
      ||![t.expected_persona_head,t.event_source,t.event_interpretation].every(head)
      ||![t.base_claim_digest,t.event_source_digest,t.event_interpretation_digest,t.observer_policy_digest].every(digest)
      ||!refs(t.context_source_refs)||!heads(t.scope_versions)||t.scope_versions.length===0
      ||!heads(t.exclusion_versions)||!heads(t.required_outcome_versions)
      ||!(t.plasticity_policy_ref===null&&t.plasticity_policy_digest===null
        ||locator(t.plasticity_policy_ref)&&digest(t.plasticity_policy_digest))
      ||t.target_kind==='semantic_identity'&&t.plasticity_policy_ref===null
      ||![t.valid_from_utc,t.adopt_before_utc,t.review_not_before_utc,t.review_due_utc,t.readout_valid_until_utc].every(time))
      throw new Error('单事件 policy 需要当前已核原件、精确版本/摘要、明确有限范围及原始 UTC 窗口。')
    if(!(Number(t.valid_from_utc)<Number(t.adopt_before_utc)&&Number(t.adopt_before_utc)<=Number(t.review_due_utc)
      &&Number(t.review_due_utc)<=Number(t.readout_valid_until_utc)&&Number(t.valid_from_utc)<=Number(t.review_not_before_utc)
      &&Number(t.review_not_before_utc)<Number(t.review_due_utc)))throw new Error('登记、采用、复核与读出期限顺序不成立。')
  }else if(kind==='prepare_single_event_growth_v1'){
    const g=r.growth_request
    if(![r.input_ref,r.policy_ref,r.continuity_interpretation_ref].every(locator)
      ||!(r.general_growth_intent_ref===null||locator(r.general_growth_intent_ref))
      ||!hasFields(g,['growth_proposal_ref','trigger_original_ref','trial_original_refs','counterevidence_query_ref'])
      ||![g.growth_proposal_ref,g.trigger_original_ref,g.counterevidence_query_ref].every(locator)
      ||!refs(g.trial_original_refs,16)||g.trial_original_refs.length===0)throw new Error('输入需既有实际提案、完整非空试验、反证与 continuity 原件。')
  }else if(kind==='adopt_single_event_growth_v1'){
    if(!locator(r.input_ref))throw new Error('请选择已登记的实际单事件输入。')
  }else if(kind==='review_single_event_growth_v1'){
    if(!locator(r.adoption_ref)||!positive(r.expected_review_revision)
      ||!(r.continuity_interpretation_ref===null||locator(r.continuity_interpretation_ref)))throw new Error('复核需独立重读所得的实际采用引用、review 版本和 post-adoption continuity。')
  }else if(!locator(r.adoption_ref))throw new Error('请选择实际采用原件。')
  return v as unknown as SingleEventGrowthInput
}
export function validateSingleEventGrowthView(v:unknown,kind:SingleEventKind,op:string):SingleEventGrowthView {
  if(!hasFields(v,['schema','operation_kind','operation_id','policy_ref','policy_digest','input_ref','input_digest',
    'adoption_ref','adoption_revision','review_ref','review_revision','disposition','target_block','adopted_claim_digest',
    'review_not_before_utc','review_due_utc','readout_valid_until_utc','missing_conditions'])
    ||v.schema!=='d01.single-event-growth-view.v1'||v.operation_kind!==kind||v.operation_id!==op
    ||!locator(v.policy_ref)||!digest(v.policy_digest)||!(v.input_ref===null||locator(v.input_ref))
    ||!(v.input_digest===null||digest(v.input_digest))||!(v.adoption_ref===null||locator(v.adoption_ref))
    ||!(v.adoption_revision===null||positive(v.adoption_revision))||!(v.review_ref===null||locator(v.review_ref))
    ||!(v.review_revision===null||positive(v.review_revision))||!(v.target_block===null||locator(v.target_block))
    ||!(v.adopted_claim_digest===null||digest(v.adopted_claim_digest))
    ||![null,'pending','qualified','opposed','unknown','expired'].includes(v.disposition as null|string)
    ||![v.review_not_before_utc,v.review_due_utc,v.readout_valid_until_utc].every(x=>x===null||time(x))
    ||!refs(v.missing_conditions))throw new Error('单事件状态没有返回本次实际原件与完整固定字段。')
  return v as unknown as SingleEventGrowthView
}
export function validateSingleEventGrowthReceipt(v:unknown,kind:SingleEventKind,op:string):SingleEventGrowthReceipt {
  if(!hasFields(v,['schema','operation_id','action','input_digest','original_digest','original'])
    ||v.schema!=='d12.domain-operation-receipt.v1'||v.operation_id!==op||v.action!=='domain_'+kind
    ||!digest(v.input_digest)||!digest(v.original_digest)||!isRecord(v.original)||v.original.operation_id!==op)
    throw new Error('尚未收到该 UUID 的实际领域回执。')
  const view=v.original.single_event_growth===undefined?null:validateSingleEventGrowthView(v.original.single_event_growth,kind,op)
  return {...v,view} as unknown as SingleEventGrowthReceipt
}
