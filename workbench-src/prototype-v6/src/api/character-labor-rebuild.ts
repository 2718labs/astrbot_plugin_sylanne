import {hasFields,isInteger,isRecord,isText,UUID4,validateScope} from './contract.ts'
import {atomType} from './commitment-communication.ts'
import {projectControlDigest} from './project-control.ts'
export interface LaborContext {activity_id:string;audience_ref:string;parent_budget_lease_ref:string}
export interface LaborSelector {action_intent_ref:string;policy_ref:string;policy_revision:number}
export interface LaborOptionsInput extends LaborContext {action_intent_ref:string}
export interface LaborPolicyOption {policy_ref:string;policy_revision:number;policy_digest:string;profile_id:string;recipe_ref:string;recipe_revision:number;valid_until_utc:number;eligible:boolean;unavailable_reasons:string[]}
export interface LaborOptions extends LaborOptionsInput {schema:'d02.character-labor-rebuild-options.v1';coverage:'complete';as_of_utc:number;policy_count:number;options:LaborPolicyOption[]}
export interface LaborPreview extends LaborContext {schema:'d02.character-labor-rebuild-selection.v1';selector:LaborSelector;choice_digest:string;profile_id:string;checkpoint:{ref:string;revision:number;origin_kind:'body_policy_install_v1'|'w01';producer_operation_id:string}}
export interface LaborRebuildInput extends LaborContext {request:{selector:LaborSelector;expected_choice_digest:string|null}}
export interface LaborRebuildAttempt {readonly scope:string;readonly operationId:string;readonly ownerBindingDigest:string;readonly input:Readonly<LaborRebuildInput>}
export interface LaborRebuildReceipt {operationId:string;inputDigest:string;originalDigest:string;coverage:'complete'|'partial';missingInputs:string[]}
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v)
const contextFields=['activity_id','audience_ref','parent_budget_lease_ref']
function fail():never{throw new Error('角色劳动重建的实际选择或回执不匹配，请保留原操作身份。')}
function context(value:Record<string,unknown>):boolean{return contextFields.every(key=>isText(value[key]))}
export function validateLaborOptionsInput(scope:string,input:LaborOptionsInput):LaborOptionsInput{
 validateScope(scope)
 if(!hasFields(input,[...contextFields,'action_intent_ref'])||!context(input)||!atomType(input.action_intent_ref,scope,'d08.action_intent.v1'))fail()
 return input
}
export function validateLaborRebuildInput(scope:string,input:LaborRebuildInput):LaborRebuildInput{
 validateScope(scope)
 if(!hasFields(input,[...contextFields,'request'])||!context(input)||!hasFields(input.request,['selector','expected_choice_digest'])
   ||!hasFields(input.request.selector,['action_intent_ref','policy_ref','policy_revision'])||!atomType(input.request.selector.action_intent_ref,scope,'d08.action_intent.v1')
   ||!isText(input.request.selector.policy_ref)||!isInteger(input.request.selector.policy_revision,1)
   ||input.request.expected_choice_digest!==null&&!hash(input.request.expected_choice_digest))fail()
 return input
}
export function validateLaborOptions(value:unknown,scope:string,input:LaborOptionsInput):LaborOptions{
 validateLaborOptionsInput(scope,input)
 if(!hasFields(value,['schema',...contextFields,'action_intent_ref','coverage','as_of_utc','policy_count','options'])
   ||value.schema!=='d02.character-labor-rebuild-options.v1'||value.coverage!=='complete'||typeof value.as_of_utc!=='number'||!Number.isFinite(value.as_of_utc)||value.action_intent_ref!==input.action_intent_ref
   ||contextFields.some(key=>value[key]!==input[key as keyof LaborOptionsInput])||!isInteger(value.policy_count)||value.policy_count>128
   ||!Array.isArray(value.options)||value.options.length!==value.policy_count)fail()
 const reasons=['recipe_not_nonpreemptible_source_note_v2','policy_recipe_mismatch','policy_work_kind_or_reality_mismatch','policy_expired','current_profile_absent','current_body_absent']
 for(const row of value.options){if(!hasFields(row,['policy_ref','policy_revision','policy_digest','profile_id','recipe_ref','recipe_revision','valid_until_utc','eligible','unavailable_reasons'])
   ||![row.policy_ref,row.profile_id,row.recipe_ref].every(isText)||!isInteger(row.policy_revision,1)||!isInteger(row.recipe_revision,1)||!hash(row.policy_digest)
   ||typeof row.valid_until_utc!=='number'||!Number.isFinite(row.valid_until_utc)||typeof row.eligible!=='boolean'||!Array.isArray(row.unavailable_reasons)
   ||!row.unavailable_reasons.every(v=>typeof v==='string'&&reasons.includes(v))||new Set(row.unavailable_reasons).size!==row.unavailable_reasons.length
   ||row.eligible!==(row.unavailable_reasons.length===0))fail()}
 if(new Set(value.options.map(row=>row.policy_ref+'|'+row.policy_revision)).size!==value.options.length)fail()
 return value as unknown as LaborOptions
}
export function validateLaborPreview(value:unknown,scope:string,input:LaborRebuildInput):LaborPreview{
 validateLaborRebuildInput(scope,input)
 if(input.request.expected_choice_digest!==null||!hasFields(value,['schema',...contextFields,'selector','choice_digest','profile_id','checkpoint'])
   ||value.schema!=='d02.character-labor-rebuild-selection.v1'||!hasFields(value.selector,['action_intent_ref','policy_ref','policy_revision'])
   ||Object.entries(input.request.selector).some(([k,v])=>(value.selector as Record<string,unknown>)[k]!==v)||contextFields.some(key=>value[key]!==input[key as keyof LaborContext])
   ||!hash(value.choice_digest)||!isText(value.profile_id)||!hasFields(value.checkpoint,['ref','revision','origin_kind','producer_operation_id'])
   ||!isText(value.checkpoint.ref)||!atomType(value.checkpoint.ref,scope,'d02.body_state.v1')||!isInteger(value.checkpoint.revision,1)
   ||!['body_policy_install_v1','w01'].includes(String(value.checkpoint.origin_kind))||!isText(value.checkpoint.producer_operation_id))fail()
 return value as unknown as LaborPreview
}
export async function validateLaborRebuildReceipt(value:unknown,scope:string,operationId:string,input:LaborRebuildInput):Promise<LaborRebuildReceipt>{
 validateLaborRebuildInput(scope,input)
 if(!UUID4.test(operationId)||input.request.expected_choice_digest===null
   ||!hasFields(value,['schema','operation_id','action','input_digest','original_digest','original'])
   ||value.schema!=='d12.domain-operation-receipt.v1'||value.operation_id!==operationId||value.action!=='domain_rebuild_character_labor_body'
   ||value.input_digest!==await projectControlDigest(input)||!hash(value.original_digest)||!isRecord(value.original))fail()
 const o=value.original
 if(o.schema!=='sylanne.domain-production-receipt.v1'||o.domain!=='d02'||o.operation_kind!=='rebuild_character_labor_body'||o.operation_id!==operationId
   ||o.activity_id!==input.activity_id||!['complete','partial'].includes(String(o.coverage))||!Array.isArray(o.missing_inputs)||!o.missing_inputs.every(isText)
   ||!hash(o.original_digest)||!hash(o.receipt_digest)||!isRecord(o.receipt)||o.receipt.status!=='committed'||o.receipt.operation_id!==operationId)fail()
 return {operationId,inputDigest:value.input_digest as string,originalDigest:value.original_digest,coverage:o.coverage as 'complete'|'partial',missingInputs:o.missing_inputs as string[]}
}
