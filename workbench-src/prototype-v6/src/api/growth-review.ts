import {hasFields,isInteger,isRecord,isText} from './contract.ts'

export const GROWTH_REVIEW_KINDS=['mark_goal_growth_review_v1','confirm_goal_growth_review_v1','mark_life_growth_review_v1','confirm_life_growth_review_v1'] as const
export type GrowthReviewKind=typeof GROWTH_REVIEW_KINDS[number]
export interface GrowthReviewRequest {target_ref:string;expected_target_revision:number;growth_operation_id:string;expected_head_id:string;expected_activation_revision:number;expected_review_revision:number}
export interface GrowthReviewInput {activity_id:string;audience_ref:'owner';parent_budget_lease_ref:string;request:GrowthReviewRequest}
export interface GrowthReviewAttempt {scope:string;kind:GrowthReviewKind;input:GrowthReviewInput;operationId:string}
export interface GrowthReviewItem {ref:string;type_name:string;revision:number;state:'not_required'|'pending'|'stale'|'owner_confirmed_keep';baseline_state:'no_growth'|'birth_current'|'birth_stale'|'baseline_unknown';review_revision:number;review_operation_id:string|null;head_id:string;activation_revision:number;growth_operation_id:string|null;request:GrowthReviewRequest|null;permitted_controls:GrowthReviewKind[];activity_id:string;parent_budget_lease_ref:string}
export interface GrowthReviewState {scope:string;operationId:string;items:GrowthReviewItem[];coverage:'complete'|'partial';missing_inputs:string[]}
const requestFields=['target_ref','expected_target_revision','growth_operation_id','expected_head_id','expected_activation_revision','expected_review_revision']
function fail():never {throw new Error('重评控制响应不匹配，请重新读取当前对象。')}
export function validateGrowthReviewRequest(value:unknown):GrowthReviewRequest {
 if(!hasFields(value,requestFields)||![value.target_ref,value.growth_operation_id,value.expected_head_id].every(isText)||!isInteger(value.expected_target_revision,1)||!isInteger(value.expected_activation_revision,1)||!isInteger(value.expected_review_revision,0))fail()
 return value as unknown as GrowthReviewRequest
}
export function validateGrowthReviewInput(kind:GrowthReviewKind,input:GrowthReviewInput) {
 if(!GROWTH_REVIEW_KINDS.includes(kind)||!hasFields(input,['activity_id','audience_ref','parent_budget_lease_ref','request'])||!isText(input.activity_id)||!isText(input.parent_budget_lease_ref)||input.audience_ref!=='owner')fail()
 validateGrowthReviewRequest(input.request)
 return input
}
export function validateGrowthReviewState(value:unknown,scope:string,refs:string[],id:string):GrowthReviewState {
 if(!hasFields(value,['schema','scope','operation_id','domain','items','coverage','missing_inputs'])||value.schema!=='d12.beta1-owner-state.v1'||value.scope!==scope||value.operation_id!==id||value.domain!=='growth_review'||!['complete','partial'].includes(String(value.coverage))||!Array.isArray(value.items)||value.items.length>16||!Array.isArray(value.missing_inputs)||!value.missing_inputs.every(isText))fail()
 const seen=new Set<string>()
 for(const row of value.items) {
  if(!hasFields(row,['ref','type_name','revision','state','baseline_state','review_revision','review_operation_id','head_id','activation_revision','growth_operation_id','request','permitted_controls','activity_id','parent_budget_lease_ref'])||!isText(row.ref)||!refs.includes(row.ref)||seen.has(row.ref)||!isText(row.type_name)||!isInteger(row.revision,1)||!isInteger(row.review_revision,0)||!isInteger(row.activation_revision,1)||!isText(row.head_id)||!isText(row.activity_id)||!isText(row.parent_budget_lease_ref)||!['not_required','pending','stale','owner_confirmed_keep'].includes(String(row.state))||!['no_growth','birth_current','birth_stale','baseline_unknown'].includes(String(row.baseline_state))||row.review_operation_id!==null&&!isText(row.review_operation_id)||row.growth_operation_id!==null&&!isText(row.growth_operation_id)||!Array.isArray(row.permitted_controls)||row.permitted_controls.some((kind:unknown)=>!GROWTH_REVIEW_KINDS.includes(kind as GrowthReviewKind)))fail()
  seen.add(row.ref)
  if(row.request!==null) {
   const request=validateGrowthReviewRequest(row.request)
   if(request.target_ref!==row.ref||request.expected_target_revision!==row.revision||request.expected_review_revision!==row.review_revision||request.expected_head_id!==row.head_id||request.expected_activation_revision!==row.activation_revision||request.growth_operation_id!==row.growth_operation_id)fail()
  } else if(row.state!=='not_required'||row.permitted_controls.length)fail()
  if((row.baseline_state==='birth_current'||row.baseline_state==='no_growth')&&(row.state!=='not_required'||row.request!==null||row.permitted_controls.length))fail()
  const domain=row.type_name.startsWith('d08.')?'goal':row.type_name.startsWith('d10.')?'life':null
  if(!domain||row.permitted_controls.some((kind:string)=>kind!==(row.state==='pending'&&row.review_operation_id?'confirm_':'mark_')+domain+'_growth_review_v1')||row.state==='owner_confirmed_keep'&&row.permitted_controls.length)fail()
 }
 if(value.coverage==='complete'&&(seen.size!==refs.length||value.missing_inputs.length))fail()
 return {scope,operationId:id,items:value.items as GrowthReviewItem[],coverage:value.coverage as GrowthReviewState['coverage'],missing_inputs:value.missing_inputs}
}
export function validateGrowthReviewReceipt(value:unknown,kind:GrowthReviewKind,id:string) {
 if(!hasFields(value,['schema','operation_id','action','input_digest','original_digest','original'])||value.schema!=='d12.domain-operation-receipt.v1'||value.operation_id!==id||value.action!=='domain_'+kind||!isRecord(value.original)||value.original.operation_id!==id||!['complete','waiting_for_original'].includes(String(value.original.coverage))||![value.input_digest,value.original_digest].every(item=>typeof item==='string'&&/^[0-9a-f]{64}$/.test(item)))fail()
 return {operationId:id,coverage:value.original.coverage as 'complete'|'waiting_for_original'}
}
