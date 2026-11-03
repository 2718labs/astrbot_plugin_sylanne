import {hasFields,isRecord,isText,isInteger,UUID4,makeOwnerLoginRequest,validateChallenge,decodeBase64,canonicalJson,type OwnerFields,type OwnerLoginRequest,type ChallengeResult} from './contract.ts'
import {validateSourceInspectionWorkflowInput,validateSourceInspectionWorkflowResponse,type SourceInspectionWorkflowInput,type SourceInspectionWorkflowView} from './source-owner-read.ts'
export type InspectionKind='workflow'|'recovery'|'reconciliation'
export interface ConsoleLocator {authority_id:string;authority_namespace:string;installation_id:string;scope:string;console_profile_id:string}
export interface ConsoleSession {schema:'sylanne.maintenance-console-session.v1';status:'locked'|'authenticated'|'unavailable';transport_profile:'full_http'|'https';origin:string;locator:ConsoleLocator;owner:OwnerLoginRequest|null;csrf_token:string|null}
export interface RecoveryOptions {schema:'d12.source-inspection-recovery-options.v1';scope:string;installation_id:string;parent_workflow_operation_id:string;parent_accepted_digest:string;parent_state:string;parent_phase:string;parent_hold_digest:string|null;pause_operation_id:string;lifecycle_state:string;lifecycle_epoch:number;lifecycle_head_digest:string;storage_identity_digest:string;resource_binding_digest:string;resource_deadline_utc:number;boundary_kind:'not_observed'|'no_child'|'incomplete'|'completed'|'unknown'|'active_completed';allowed_dispositions:string[];can_resume_completed:boolean}
export interface RecoveryInput {parent_workflow_operation_id:string;pause_operation_id:string;expected_lifecycle_epoch:number;expected_lifecycle_head_digest:string;deadline_utc:number}
export interface ReconciliationInput {parent_workflow_operation_id:string;parent_accepted_digest:string;parent_hold_digest:string;expected_lifecycle_epoch:number;expected_lifecycle_head_digest:string;expected_storage_identity_digest:string;expected_resource_binding_digest:string;deadline_utc:number;disposition:'reconcile_only'|'continue_remaining'|'terminate_paused'|'reconcile_active_completed';child_migration_operation_id:string|null}
export interface RecoveryView {schema:string;scope:string;installation_id:string;operation_id:string;request_digest:string;state:string;phase:string;hold_code:string|null;effective_deadline_utc:number;[key:string]:unknown}
export type InspectionView=SourceInspectionWorkflowView|RecoveryView
export interface PendingInspection {kind:InspectionKind;operation_id:string;input?:SourceInspectionWorkflowInput|RecoveryInput|ReconciliationInput;confirmed:boolean}
export class ConsoleRequestError extends Error {constructor(message:string,readonly code:string,readonly uncertain=false){super(message)}}
const sha=(v:unknown)=>typeof v==='string'&&/^(sha256:)?[a-f0-9]{64}$/.test(v)
function invalid():never{throw new ConsoleRequestError('维护响应与当前请求不一致。','response_invalid')}
function validateSession(v:unknown):ConsoleSession{
 if(!hasFields(v,['schema','status','transport_profile','origin','locator','owner','csrf_token'])||v.schema!=='sylanne.maintenance-console-session.v1'||!['locked','authenticated','unavailable'].includes(String(v.status))||!['full_http','https'].includes(String(v.transport_profile))||v.origin!==location.origin||!hasFields(v.locator,['authority_id','authority_namespace','installation_id','scope','console_profile_id'])||Object.values(v.locator).some(x=>!isText(x)))invalid()
 if((v.transport_profile==='https')!==(location.protocol==='https:')||!(v.status==='authenticated'?isRecord(v.owner)&&isText(v.csrf_token):v.owner===null&&(v.csrf_token===null||v.status==='unavailable'&&isText(v.csrf_token))))invalid()
 return v as unknown as ConsoleSession
}
function validateOptions(v:unknown,session:ConsoleSession,parent:string):RecoveryOptions{
 const fields=['schema','scope','installation_id','parent_workflow_operation_id','parent_accepted_digest','parent_state','parent_phase','parent_hold_digest','pause_operation_id','lifecycle_state','lifecycle_epoch','lifecycle_head_digest','storage_identity_digest','resource_binding_digest','resource_deadline_utc','boundary_kind','allowed_dispositions','can_resume_completed']
 if(!hasFields(v,fields)||v.schema!=='d12.source-inspection-recovery-options.v1'||v.scope!==session.locator.scope||v.installation_id!==session.locator.installation_id||v.parent_workflow_operation_id!==parent||!sha(v.parent_accepted_digest)||!(v.parent_hold_digest===null||sha(v.parent_hold_digest))||!isText(v.pause_operation_id)||!UUID4.test(v.pause_operation_id)||!isInteger(v.lifecycle_epoch)||!sha(v.lifecycle_head_digest)||!sha(v.storage_identity_digest)||!sha(v.resource_binding_digest)||typeof v.resource_deadline_utc!=='number'||!Number.isFinite(v.resource_deadline_utc)||!['not_observed','no_child','incomplete','completed','unknown','active_completed'].includes(String(v.boundary_kind))||!Array.isArray(v.allowed_dispositions)||v.allowed_dispositions.some(x=>!['reconcile_only','continue_remaining','terminate_paused','reconcile_active_completed'].includes(x))||typeof v.can_resume_completed!=='boolean'||![v.parent_state,v.parent_phase,v.lifecycle_state].every(isText))invalid()
 return v as unknown as RecoveryOptions
}
function validateRecovery(v:unknown,session:ConsoleSession,pending:PendingInspection):RecoveryView{
 const common=['schema','scope','installation_id','operation_id','request_digest','state','phase','hold_code','effective_deadline_utc']
 const keys=pending.kind==='recovery'?['parent_workflow_operation_id','pause_operation_id','expected_lifecycle_epoch','expected_lifecycle_head_digest','deadline_utc']:['parent_workflow_operation_id','parent_accepted_digest','parent_hold_digest','expected_lifecycle_epoch','expected_lifecycle_head_digest','expected_storage_identity_digest','expected_resource_binding_digest','deadline_utc','disposition','child_migration_operation_id','classification']
 if(!hasFields(v,[...common,...keys])||v.schema!==(pending.kind==='recovery'?'d12.source-inspection-recovery-view.v1':'d12.source-inspection-held-reconciliation-view.v1')||v.scope!==session.locator.scope||v.installation_id!==session.locator.installation_id||v.operation_id!==pending.operation_id||!sha(v.request_digest)||!isText(v.state)||!isText(v.phase)||!(v.hold_code===null||isText(v.hold_code))||typeof v.effective_deadline_utc!=='number'||!Number.isFinite(v.effective_deadline_utc)||typeof v.deadline_utc!=='number'||v.effective_deadline_utc>v.deadline_utc||pending.input!==undefined&&Object.entries(pending.input).some(([k,x])=>canonicalJson(v[k])!==canonicalJson(x)))invalid()
 return v as unknown as RecoveryView
}
export class MaintenanceConsoleClientV1 {
 session:ConsoleSession|null=null;challenge:ChallengeResult|null=null;#inflight=false
 async #json(path:string,method='GET',body?:unknown):Promise<unknown>{
  const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),10000)
  try{const response=await fetch(path,{method,signal:abort.signal,credentials:'same-origin',mode:'same-origin',cache:'no-store',referrerPolicy:'same-origin',headers:{...(body===undefined?{}:{'Content-Type':'application/json'}),...(method==='POST'&&this.session?.csrf_token?{'X-CSRF-Token':this.session.csrf_token}:{})},...(body===undefined?{}:{body:JSON.stringify(body)})})
  const value:unknown=await response.json();if(!response.ok){if(!hasFields(value,['error'])||!isText(value.error))invalid();throw new ConsoleRequestError('维护请求未完成：'+value.error,value.error)}return value}finally{clearTimeout(timer)}
 }
 async status(){const value=validateSession(await this.#json('/api/session/status'));this.session=value;return value}
 async begin(fields:OwnerFields){this.challenge=null;const request=makeOwnerLoginRequest(fields,location.origin);const value=validateChallenge(await this.#json('/api/session/challenge','POST',{request}),request);this.challenge=value;return value}
 async complete(signature:string){const current=this.challenge;this.challenge=null;if(!current||Date.parse(current.challenge.expires_at_utc)<=Date.now()||decodeBase64(signature).length!==64)throw new ConsoleRequestError('挑战已过期或签名无效，请重新取得挑战。','challenge_invalid');const value=await this.#json('/api/session/complete','POST',{challenge:current.challenge,signature_base64:signature});if(!hasFields(value,['status'])||value.status!=='authenticated')invalid();return this.status()}
 async logout(){this.challenge=null;try{const value=await this.#json('/api/session/logout','POST',{});if(!hasFields(value,['status'])||value.status!=='locked')invalid()}finally{this.session=null}}
 async options(parent:string){if(!UUID4.test(parent))invalid();const value=await this.#json('/api/inspection/'+parent+'/recovery-options');if(!this.session||!hasFields(value,['inspection_recovery_options']))invalid();return validateOptions(value.inspection_recovery_options,this.session,parent)}
 async #result(value:unknown,pending:PendingInspection):Promise<InspectionView|null>{
  if(!this.session)invalid();if(hasFields(value,['status','operation_id','kind'])&&value.status==='pending_confirmation'){if(value.operation_id!==pending.operation_id||value.kind!==pending.kind)invalid();return null}
  const key=pending.kind==='workflow'?'inspection_workflow':pending.kind==='recovery'?'inspection_recovery':'inspection_reconciliation';if(!hasFields(value,[key]))invalid()
  if(pending.kind==='workflow'){const result=validateSourceInspectionWorkflowResponse({status:'ready',projection:value[key]},this.session.locator.scope,pending.operation_id,'read',pending.input as SourceInspectionWorkflowInput|undefined);if(result?.installation_id!==this.session.locator.installation_id)invalid();return result}
  return validateRecovery(value[key],this.session,pending)
 }
 async submit(pending:PendingInspection){
  if(!pending.input||this.#inflight||pending.confirmed)throw new ConsoleRequestError('请只查询原操作结果。','read_original_required');if(!this.session||this.session.status!=='authenticated')throw new ConsoleRequestError('请先完成当前Owner签名登录。','owner_required')
  if(pending.kind==='workflow')validateSourceInspectionWorkflowInput(pending.input,this.session.locator.scope,pending.operation_id)
  this.#inflight=true;pending.confirmed=true
  try{return await this.#result(await this.#json('/api/inspection/'+(pending.kind==='workflow'?'accept':pending.kind==='recovery'?'resume-completed':'reconcile-held'),'POST',{operation_id:pending.operation_id,input:pending.input}),pending)}catch(e){if(e instanceof ConsoleRequestError)throw e;throw new ConsoleRequestError('结果未确认，请用原UUID只读查询。','outcome_unknown',true)}finally{this.#inflight=false}
 }
 async read(pending:PendingInspection){return this.#result(await this.#json('/api/inspection/'+pending.operation_id+'?kind='+pending.kind),pending)}
}
