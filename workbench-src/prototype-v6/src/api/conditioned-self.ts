import { hasFields, isInteger, isRecord, isText } from './contract.ts'

export interface SelfCapabilityRow {
  ref:string; id:string; taskClass:string; qualification:string; conditionRef:string
  scopeRefs:string[]; matched:number; counterexamples:number; unknown:number; observationUnits:number
  minimumVerified:number; coverage:number; calibrationPolicyRef:string; reviewRef:string; validUntil:number
  configuredSampleThresholdMet:boolean
}
export interface SelfStrategyRow {
  ref:string; id:string; qualification:string; conditionRef:string; preferredMethod:string
  alternativeMethod:string; exclusions:string[]; reviewRef:string; validUntil:number
}
export interface SelfViewProjection {
  scope:string; operationId:string; readOperationId:string; viewDigest:string; personaRevision:number
  capabilities:SelfCapabilityRow[]; strategies:SelfStrategyRow[]; limitRefs:string[]
  commitmentRefs:string[]; unknowns:string[]
}
const digest=(value:unknown):value is string=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value)
function fail():never{throw new Error('当前自我视图不兼容或未绑定本次读取；没有显示旧结果。')}
function texts(value:unknown):string[]{
  if(!Array.isArray(value)||value.length>128||!value.every(isText))return fail()
  return value
}
function pairs(value:unknown):[string,Record<string,unknown>][] {
  if(!Array.isArray(value)||value.length>128||!value.every(item=>Array.isArray(item)&&item.length===2&&isText(item[0])&&isRecord(item[1])))return fail()
  return value as [string,Record<string,unknown>][]
}
function time(value:unknown):number {
  if(typeof value!=='number'||!Number.isFinite(value)||!Number.isFinite(new Date(value*1000).getTime()))return fail()
  return value
}
function text(value:unknown):string{return isText(value)?value:fail()}
export function validateSelfViewProjection(value:unknown,scope:string,operationId:string):SelfViewProjection {
  if(!hasFields(value,['schema','scope','operation_id','read_operation_id','request_digest','view_digest','view'])
    ||value.schema!=='d12.self-view-projection.v4'||value.scope!==scope||value.operation_id!==operationId
    ||!digest(value.request_digest)||!digest(value.view_digest)||!isText(value.read_operation_id)
    ||!hasFields(value.view,['runtime_identity','persona_head','semantic_projection','capabilities','strategies',
      'current_limit_refs','commitment_refs','read_versions','meaningful_unknowns','calibrations','schema'])
    ||value.view.schema!=='d01.self-view.v4'||!hasFields(value.view.persona_head,['key','revision'])
    ||!isText(value.view.persona_head.key)||!isInteger(value.view.persona_head.revision,1))return fail()
  const view=value.view
  const calibrations=new Map<string,Record<string,unknown>>()
  for(const [ref,item] of pairs(view.calibrations)){
    if(calibrations.has(ref)||item.schema!=='d01.conditioned-calibration-view.v1'||item.capability_revision_ref!==ref)return fail()
    calibrations.set(ref,item)
  }
  const capabilityPairs=pairs(view.capabilities)
  if(calibrations.size!==capabilityPairs.length||new Set(capabilityPairs.map(([ref])=>ref)).size!==capabilityPairs.length)return fail()
  const capabilities=capabilityPairs.map(([ref,item]):SelfCapabilityRow=>{
    const calibration=calibrations.get(ref)
    if(!calibration)return fail()
    const counts=calibration.verified_outcome_counts
    if(item.schema!=='d01.conditioned-capability-revision.v1'||!['artifact_draft','source_note','life_activity'].includes(String(item.task_class))||!['sample_threshold_met','limited','unknown','stale'].includes(String(item.qualification))
      ||!Array.isArray(counts)||counts.length!==2||!Array.isArray(counts[0])||!Array.isArray(counts[1])
      ||counts[0].length!==2||counts[1].length!==2||counts[0][0]!=='matched'||counts[1][0]!=='counterexample'
      ||!isInteger(counts[0][1])||!isInteger(counts[1][1])||!isInteger(calibration.unknown_count)
      ||!isInteger(calibration.observation_unit_count)||!isInteger(calibration.minimum_verified_outcomes,1)
      ||counts[0][1]+counts[1][1]+calibration.unknown_count!==calibration.observation_unit_count
      ||typeof calibration.coverage!=='number'||!Number.isFinite(calibration.coverage)
      ||calibration.coverage<0||calibration.coverage>1||!digest(calibration.calibration_policy_digest)
      ||typeof calibration.configured_sample_threshold_met!=='boolean')return fail()
    return {ref,id:text(item.capability_id),taskClass:text(item.task_class),qualification:text(item.qualification),
      conditionRef:text(item.condition_predicate_ref),scopeRefs:texts(item.scope_refs),matched:counts[0][1],
      counterexamples:counts[1][1],unknown:calibration.unknown_count,observationUnits:calibration.observation_unit_count,
      minimumVerified:calibration.minimum_verified_outcomes,coverage:calibration.coverage,
      calibrationPolicyRef:text(calibration.calibration_policy_ref),configuredSampleThresholdMet:calibration.configured_sample_threshold_met,
      reviewRef:text(item.last_review_ref),validUntil:time(item.valid_until)}
  })
  const strategies=pairs(view.strategies).map(([ref,item]):SelfStrategyRow=>{
    const methods=['CP-tone-order:full-draft-then-check','CP-tone-order:tone-sample-then-full-draft']
    if(item.schema!=='d01.conditioned-strategy-revision.v1'||!['candidate','qualified','narrowed','rolled_back','unknown'].includes(String(item.qualification))
      ||!methods.includes(String(item.preferred_method))||!methods.includes(String(item.alternative_method)))return fail()
    return {ref,id:text(item.strategy_id),qualification:text(item.qualification),conditionRef:text(item.condition_predicate_ref),
      preferredMethod:text(item.preferred_method),alternativeMethod:text(item.alternative_method),exclusions:texts(item.exclusions),
      reviewRef:text(item.review_ref),validUntil:time(item.valid_until)}
  })
  return {scope,operationId,readOperationId:value.read_operation_id,viewDigest:value.view_digest,
    personaRevision:value.view.persona_head.revision,capabilities,strategies,
    limitRefs:texts(view.current_limit_refs),commitmentRefs:texts(view.commitment_refs),unknowns:texts(view.meaningful_unknowns)}
}
