import { canonicalJson, hasFields, isRecord, UUID4 } from './contract.ts'

export const SCHEME_FIELDS=['d01.persona_plan','d02.body_profile','d03.context_scheme','d04.affect_scheme','d04.authored_root','d05.relationship_scheme','d06.encoding_projection_policy','d07.attention_policy','d08.action_schemas','d09.expression_policy','d10.activity_recipe'] as const
export type SchemeField=typeof SCHEME_FIELDS[number]
export type SchemeValues=Partial<Record<SchemeField,unknown>>
export interface CreatorConfiguration{
  schema:'d12.creator-configuration.v1';draft_ref:string;exists:boolean;draft_revision:number;draft_digest:string|null;fields:SchemeValues;field_sources:Partial<Record<SchemeField,string>>;budget_ref:string|null
  active_head_ref:string|null;active_head_revision:number;graph_revision:number;access_epoch:number;delete_epoch:number;access_generation:number
  supported_fields:{path:SchemeField;label:string;editable:boolean}[]
  action_permissions:{save:boolean;compile:boolean;preview:boolean;activate:boolean}
  field_templates:SchemeValues
}
export interface CreatorDraftSaveReceipt{schema:'d12.creator-draft-save.v1';operation_id:string;draft_ref:string;draft_revision:number;draft_digest:string;graph_revision:number;access_epoch:number;delete_epoch:number;changed_fields:SchemeField[];status:'draft_saved_not_adopted'}
export interface CompiledSchemeReceipt{operation_id:string;phase:'compiled_candidate_recorded';compiled_digest:string;draft_ref:string;draft_revision:number;graph_revision:number;source_input_digest:string;budget_receipt_digest:string}
export interface PreviewSchemeReceipt{operation_id:string;phase:'isolated_preview_recorded';compiled_digest:string;preview_seal:string;isolation_result_digest:string;actual_cost_receipt_ref:string}
export interface AdoptedSchemeReceipt{operation_id:string;phase:'scheme_adopted';compiled_digest:string;previous_head_revision:number;active_head_ref:string;active_head_revision:number;graph_revision:number}
export const DOMAIN_INPUT_ACTIONS=['domain_input_freeze_values','domain_input_prepare_growth_input','domain_input_derive_growth_trial','domain_input_initialize_body','domain_input_install_passive_body_policy','domain_input_install_body_effect_policy','domain_input_record_body_component','domain_input_install_relationship_policy','domain_input_register_boundary_intent','domain_input_create_goal','domain_input_register_joint_plan_intent','domain_input_register_party_consent','domain_input_create_life_project','domain_input_set_contact_policy','domain_input_create_contact_opportunity','domain_input_register_life_plan','domain_input_register_life_outcome','domain_input_register_life_plan_v2','domain_input_register_life_outcome_v2','domain_input_register_semantic_question','domain_input_register_simulation','domain_input_register_offline_schedule','domain_input_register_offline_interval'] as const
export type DomainInputAction=typeof DOMAIN_INPUT_ACTIONS[number]
export interface DomainInputIntent{activity_id:string;audience_ref:string;parent_budget_lease_ref:string;request:Record<string,unknown>}
export interface DomainInputReceiptSummary{schema:'d12.domain-operation-receipt.v1';operation_id:string;action:DomainInputAction;input_digest:string;original_digest:string}
export class CreatorContractError extends Error{constructor(){super('Invalid creator configuration contract')}}
const text=(v:unknown,max=4096):v is string=>typeof v==='string'&&v.length>=1&&v.length<=max
const integer=(v:unknown,min=0):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=min
const digest=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v)
const field=(v:unknown):v is SchemeField=>SCHEME_FIELDS.includes(v as SchemeField)
function invalid():never{throw new CreatorContractError()}
export function validateSchemeValues(value:unknown):asserts value is SchemeValues{if(!hasFields(value,[],[...SCHEME_FIELDS]))invalid()}
export function validateCreatorConfiguration(body:unknown):CreatorConfiguration{
  if(!hasFields(body,['schema','draft_ref','exists','draft_revision','draft_digest','fields','field_sources','budget_ref','active_head_ref','active_head_revision','graph_revision','access_epoch','delete_epoch','access_generation','supported_fields','action_permissions','field_templates'])||body.schema!=='d12.creator-configuration.v1'||!text(body.draft_ref)||typeof body.exists!=='boolean'||!integer(body.draft_revision)||!integer(body.active_head_revision)||(body.active_head_revision===0?body.active_head_ref!==null:!text(body.active_head_ref))||!integer(body.graph_revision)||!integer(body.access_epoch)||!integer(body.delete_epoch)||!integer(body.access_generation,1)||body.budget_ref!==null&&!text(body.budget_ref)||!hasFields(body.action_permissions,['save','compile','preview','activate'])||Object.values(body.action_permissions).some(v=>typeof v!=='boolean')||!hasFields(body.field_templates,SCHEME_FIELDS.filter(path=>path!=='d04.authored_root'))||Object.values(body.field_templates).some(value=>value===null||typeof value!=='object'))invalid()
  validateSchemeValues(body.fields)
  if(!hasFields(body.field_sources,[],[...SCHEME_FIELDS])||Object.keys(body.fields).sort().join('|')!==Object.keys(body.field_sources).sort().join('|')||Object.values(body.field_sources).some(v=>!text(v))||!Array.isArray(body.supported_fields)||body.supported_fields.length>SCHEME_FIELDS.length)invalid()
  if(body.exists?(!integer(body.draft_revision,1)||!digest(body.draft_digest)):(body.draft_revision!==0||body.draft_digest!==null||Object.keys(body.fields).length!==0))invalid()
  const seen=new Set<string>()
  for(const row of body.supported_fields){if(!hasFields(row,['path','label','editable'])||!field(row.path)||seen.has(row.path)||!text(row.label,128)||typeof row.editable!=='boolean'||row.path==='d04.authored_root'&&row.editable)invalid();seen.add(row.path)}
  return body as unknown as CreatorConfiguration
}
export function draftSaveInput(current:CreatorConfiguration,fields:SchemeValues){validateSchemeValues(fields);if(canonicalJson(fields['d04.authored_root'])!==canonicalJson(current.fields['d04.authored_root']))invalid();const editable=Object.fromEntries(Object.entries(fields).filter(([path])=>path!=='d04.authored_root'));return{draft_ref:current.draft_ref,expected_draft_revision:current.draft_revision,expected_draft_digest:current.draft_digest,expected_graph_revision:current.graph_revision,expected_access_epoch:current.access_epoch,expected_delete_epoch:current.delete_epoch,fields:editable}}
export function validateDraftSaveReceipt(body:unknown,current:CreatorConfiguration,operationId:string):CreatorDraftSaveReceipt{
  if(!hasFields(body,['schema','operation_id','draft_ref','draft_revision','draft_digest','graph_revision','access_epoch','delete_epoch','changed_fields','status'])||body.schema!=='d12.creator-draft-save.v1'||body.status!=='draft_saved_not_adopted'||body.operation_id!==operationId||!UUID4.test(operationId)||body.draft_ref!==current.draft_ref||body.draft_revision!==current.draft_revision+1||!digest(body.draft_digest)||body.graph_revision!==current.graph_revision+1||body.access_epoch!==current.access_epoch||body.delete_epoch!==current.delete_epoch||!Array.isArray(body.changed_fields)||body.changed_fields.length===0||body.changed_fields.some(v=>!field(v)||v==='d04.authored_root')||new Set(body.changed_fields).size!==body.changed_fields.length)invalid()
  return body as unknown as CreatorDraftSaveReceipt
}
export function validateSchemeReceipt(action:'compile_scheme'|'preview_scheme'|'activate_scheme',body:unknown,operationId:string,input:Record<string,string>):CompiledSchemeReceipt|PreviewSchemeReceipt|AdoptedSchemeReceipt{
  if(action==='compile_scheme'){
    if(!hasFields(body,['operation_id','phase','compiled_digest','draft_ref','draft_revision','graph_revision','source_input_digest','budget_receipt_digest'])||body.operation_id!==operationId||body.phase!=='compiled_candidate_recorded'||!digest(body.compiled_digest)||body.draft_ref!==input.draft_ref||!integer(body.draft_revision,1)||!integer(body.graph_revision)||!digest(body.source_input_digest)||!digest(body.budget_receipt_digest))invalid()
  }else if(action==='preview_scheme'){
    if(!hasFields(body,['operation_id','phase','compiled_digest','preview_seal','isolation_result_digest','actual_cost_receipt_ref'])||body.operation_id!==operationId||body.phase!=='isolated_preview_recorded'||body.compiled_digest!==input.compiled_digest||!digest(body.preview_seal)||!digest(body.isolation_result_digest)||!text(body.actual_cost_receipt_ref))invalid()
  }else if(!hasFields(body,['operation_id','phase','compiled_digest','previous_head_revision','active_head_ref','active_head_revision','graph_revision'])||body.operation_id!==operationId||body.phase!=='scheme_adopted'||body.compiled_digest!==input.compiled_digest||!integer(body.previous_head_revision)||!text(body.active_head_ref)||!integer(body.active_head_revision,(body.previous_head_revision as number)+1)||!integer(body.graph_revision))invalid()
  return body as unknown as CompiledSchemeReceipt|PreviewSchemeReceipt|AdoptedSchemeReceipt
}
export function validateLegacyCreatorDraft(body:unknown,scope:string){
  if(!hasFields(body,['schema','namespace','draft_ref','draft_revision','fields','field_sources','active_head_ref','active_head_revision','graph_revision','access_epoch','delete_epoch','access_generation'])||body.schema!=='d12.creator_draft_view.v1'||!hasFields(body.namespace,['bot','persona'])||`${body.namespace.bot}/${body.namespace.persona}`!==scope||!text(body.draft_ref)||!integer(body.draft_revision)||!text(body.active_head_ref)||!integer(body.active_head_revision)||!integer(body.graph_revision)||!integer(body.access_epoch)||!integer(body.delete_epoch)||!integer(body.access_generation,1))invalid()
  validateSchemeValues(body.fields)
  if(!hasFields(body.field_sources,[],[...SCHEME_FIELDS])||Object.keys(body.fields).sort().join('|')!==Object.keys(body.field_sources).sort().join('|')||Object.values(body.field_sources).some(v=>!text(v)))invalid()
  return body
}
export function validateDomainInputReceipt(body:unknown,action:DomainInputAction,operationId:string):DomainInputReceiptSummary{
  if(!hasFields(body,['schema','operation_id','action','input_digest','original_digest','original'])||body.schema!=='d12.domain-operation-receipt.v1'||body.operation_id!==operationId||body.action!==action||!digest(body.input_digest)||!digest(body.original_digest)||!isRecord(body.original)||body.original.operation_id!==operationId)invalid()
  // Raw W01 originals can contain private authority provenance. UI receives only this finite safe summary.
  return{schema:'d12.domain-operation-receipt.v1',operation_id:operationId,action,input_digest:body.input_digest,original_digest:body.original_digest}
}
