import { canonicalJson, hasFields, isInteger, isRecord, isText, UUID4, validateScope } from './contract.ts'
import { sha256HexV1 } from './browser-crypto.ts'

export const COMMITMENT_PREPARE_ACTION = 'prepare_current_commitment_communication_v1'
export type CommitmentCommandKind = 'create' | 'approve' | 'submit'
export interface CommitmentCreateRequest {commitment_id:string;counterparty_ref:string;semantic_scope:string;establishment_kind:'unilateral'|'bilateral';source_refs:string[];deadline_ref:string|null}
export interface CommitmentApprovalRequest {commitment:{ref:string;version:number};source_ref:string;approved_literal:string;valid_until_utc:number}
export interface CommitmentDomainInput<R> {activity_id:string;audience_ref:string;parent_budget_lease_ref:string;request:R}
export interface CommitmentPrepareInput {scope_ref:string;c02_operation_id:string;source_ref:string;deadline_utc:number}
export type CommitmentCommandInput = CommitmentDomainInput<CommitmentCreateRequest> | CommitmentDomainInput<CommitmentApprovalRequest> | CommitmentPrepareInput
export interface CommitmentCommandAttempt {scope:string;kind:CommitmentCommandKind;input:CommitmentCommandInput;operationId:string}
export interface CreatedCommitment {ref:string;revision:number;counterparty_ref:string;semantic_scope:string;source_ref:string}
export interface ApprovedCommitmentScope {scope_ref:string;commitment_ref:string;commitment_revision:number;target_ref:string;source_ref:string;platform_ref:string;conversation_ref:string;scene_ref:string;approved_literal:string;valid_until_utc:number;approval_operation_id:string}
export interface CommitmentPreparedAction {ref:string;revision:number;activity_id:string}
export type CommitmentCommandResult = {kind:'create';commitment:CreatedCommitment} | {kind:'approve';approval:ApprovedCommitmentScope|null;metadata?:{scope_ref:string;revision:number;digest:string;approval_operation_id:string}} | {kind:'submit';operation_id:string;job_ref:string;outbox_ref:string;action:CommitmentPreparedAction}
const domainKinds={create:'input:create_commitment',approve:'input:register_commitment_communication'} as const
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v)
function invalid():never {throw new Error('承诺操作的正式请求或回执不匹配，请保留原请求核验。')}
export function atomType(ref:string,scope:string,type:string):boolean {
 let value:unknown
 try {value=JSON.parse(ref)}catch{return false}
 return Array.isArray(value)&&value.length===6&&value[1]===scope.split('/')[0]&&value[2]===scope.split('/')[1]&&value[4]===type
}
export async function inputDigest(input:object):Promise<string>{
 const ascii=canonicalJson(input).replace(/[\u007f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'))
 return sha256HexV1(new TextEncoder().encode(ascii))
}
export function validateCommitmentCommandInput(kind:CommitmentCommandKind,scope:string,input:CommitmentCommandInput):void {
 validateScope(scope)
 if(kind==='submit'){
  if(!hasFields(input,['scope_ref','c02_operation_id','source_ref','deadline_utc'])||!isText(input.scope_ref)||!['d08.commitment_communication_intent.v1','d08.commitment_communication_intent.v2'].some(type=>atomType(input.scope_ref as string,scope,type))||!isText(input.source_ref)||!atomType(input.source_ref,scope,'memory.source')||!isText(input.c02_operation_id)||typeof input.deadline_utc!=='number'||!Number.isFinite(input.deadline_utc))invalid()
  return
 }
 if(!hasFields(input,['activity_id','audience_ref','parent_budget_lease_ref','request'])||!isText(input.activity_id)||!isText(input.parent_budget_lease_ref)||!isText(input.audience_ref))invalid()
 const r=input.request
 if(kind==='create'){
  if(!hasFields(r,['commitment_id','counterparty_ref','semantic_scope','establishment_kind','source_refs','deadline_ref'])||!isText(r.commitment_id)||!r.commitment_id.startsWith('commitment:')||!isText(r.counterparty_ref)||!r.counterparty_ref.startsWith('entity:')||!isText(r.semantic_scope)||!['unilateral','bilateral'].includes(String(r.establishment_kind))||!Array.isArray(r.source_refs)||r.source_refs.length!==1||!isText(r.source_refs[0])||!atomType(r.source_refs[0],scope,'memory.source')||r.deadline_ref!==null&&!isText(r.deadline_ref))invalid()
 }else if(!hasFields(r,['commitment','source_ref','approved_literal','valid_until_utc'])||!hasFields(r.commitment,['ref','version'])||!isText(r.commitment.ref)||!atomType(r.commitment.ref,scope,'d08.commitment.v1')||!isInteger(r.commitment.version,1)||!isText(r.source_ref)||!atomType(r.source_ref,scope,'memory.source')||typeof r.approved_literal!=='string'||r.approved_literal.length<1||r.approved_literal.length>2048||typeof r.valid_until_utc!=='number'||!Number.isFinite(r.valid_until_utc))invalid()
}
export async function validateCommitmentCommandReceipt(value:unknown,scope:string,kind:CommitmentCommandKind,input:CommitmentCommandInput,id:string):Promise<CommitmentCommandResult>{
 validateCommitmentCommandInput(kind,scope,input)
 const action=kind==='submit'?COMMITMENT_PREPARE_ACTION:kind==='create'?'domain_input_create_commitment':'domain_input_register_commitment_communication'
 if(!UUID4.test(id)||!hasFields(value,['schema','operation_id','action','input_digest','original_digest','original'])||value.operation_id!==id||value.action!==action||!hash(value.input_digest)||!hash(value.original_digest)||value.input_digest!==await inputDigest(input)||!isRecord(value.original))invalid()
 const o=value.original
 if(kind==='submit'){
  const r=input as CommitmentPrepareInput
  if(value.schema!=='d12.commitment-communication-receipt.v1'||!hasFields(o,['status','operation_id','scope_ref','commit_receipt','job_ref','outbox_ref'])||o.status!=='commitment_communication_dispatch_committed'||o.scope_ref!==r.scope_ref||!isText(o.operation_id)||!isText(o.job_ref)||!isText(o.outbox_ref)||!isRecord(o.commit_receipt)||o.commit_receipt.status!=='committed'||o.commit_receipt.operation_id!==o.operation_id)invalid()
  if(!Array.isArray(o.commit_receipt.write_versions)||!isText(o.commit_receipt.activity_id))invalid()
  const actions=o.commit_receipt.write_versions.filter((row:unknown)=>hasFields(row,['key','revision'])&&isText(row.key)&&isInteger(row.revision,1)&&atomType(row.key,scope,'d08.action_intent.v1')) as {key:string;revision:number}[]
  if(actions.length!==1)invalid()
  const actionKey=JSON.parse(actions[0]!.key) as string[]
  if(actionKey[0]!=='activity'||actionKey[3]!==o.commit_receipt.activity_id)invalid()
  return {kind:'submit',operation_id:o.operation_id,job_ref:o.job_ref,outbox_ref:o.outbox_ref,action:{ref:actions[0]!.key,revision:actions[0]!.revision,activity_id:o.commit_receipt.activity_id}}
 }
 if(value.schema!=='d12.domain-operation-receipt.v1'||o.schema!=='sylanne.domain-production-receipt.v1'||o.operation_kind!==domainKinds[kind]||o.operation_id!==id||o.domain!=='d08'||o.coverage!=='complete'||!isRecord(o.receipt)||o.receipt.status!=='committed'||o.receipt.operation_id!==id||!Array.isArray(o.receipt.write_versions))invalid()
 const expectedType=kind==='create'?'d08.commitment.v1':'d08.commitment_communication_intent.v1'
 const writes=o.receipt.write_versions.filter((row:unknown)=>Array.isArray(row)&&row.length===2&&isText(row[0])&&row[1]===1&&atomType(row[0],scope,expectedType)) as [string,number][]
 if(writes.length!==1)invalid()
 if(kind==='create'){
  const r=(input as CommitmentDomainInput<CommitmentCreateRequest>).request
  return {kind:'create',commitment:{ref:writes[0]![0],revision:1,counterparty_ref:r.counterparty_ref,semantic_scope:r.semantic_scope,source_ref:r.source_refs[0]!}}
 }
 const r=(input as CommitmentDomainInput<CommitmentApprovalRequest>).request
 const metadata=o.commitment_communication_scope_metadata
 if(metadata!==undefined){
  if(!hasFields(metadata,['scope_ref','revision','digest','approval_operation_id'])||metadata.scope_ref!==writes[0]![0]||metadata.revision!==1||!hash(metadata.digest)||metadata.approval_operation_id!==id)invalid()
 }
 const a=o.commitment_communication_scope
 if(a===undefined){if(metadata===undefined)invalid();return {kind:'approve',approval:null,metadata:metadata as {scope_ref:string;revision:number;digest:string;approval_operation_id:string}}}
 if(!hasFields(a,['scope_ref','commitment_ref','commitment_revision','target_ref','source_ref','platform_ref','conversation_ref','scene_ref','approved_literal','valid_until_utc','approval_operation_id'])||a.scope_ref!==writes[0]![0]||a.commitment_ref!==r.commitment.ref||a.commitment_revision!==r.commitment.version||a.source_ref!==r.source_ref||a.approved_literal!==r.approved_literal||a.valid_until_utc!==r.valid_until_utc||a.approval_operation_id!==id||![a.target_ref,a.platform_ref,a.conversation_ref,a.scene_ref].every(isText))invalid()
 return {kind:'approve',approval:a as unknown as ApprovedCommitmentScope}
}
