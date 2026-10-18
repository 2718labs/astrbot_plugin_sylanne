import {operationIdV1} from './browser-crypto.ts'
import { DEFAULT_API_BASE, hasFields, UUID4 } from './contract.ts'
import { WorkbenchApiError, requireWorkbenchTransport, workbenchTransportAvailable, httpsResponseError, type FetchLike, type FetchResponse } from './client.ts'

export const CONFIGURATION_SCHEMA = 'sylanne.webui-configuration.v1'
export const OPTIONAL_MODEL_SLOTS = ['encode','context_reply','natural_generation','natural_review','appraisal','d07_cognition','contact_generation','contact_review','life_content','life_numeric'] as const
export const MODEL_SLOTS = ['reply',...OPTIONAL_MODEL_SLOTS] as const
export const RELATIONSHIP_MODEL_SLOT = 'd07_relationship_cognition' as const
export const GROWTH_MODEL_SLOT = 'growth_cognition' as const
export const GENERAL_GROWTH_MODEL_SLOT = 'general_growth_cognition' as const
export const ARTIFACT_OBSERVATION_MODEL_SLOT = 'artifact_observation_cognition' as const
export type ConfigurationSlot = typeof MODEL_SLOTS[number] | typeof RELATIONSHIP_MODEL_SLOT | typeof GROWTH_MODEL_SLOT | typeof GENERAL_GROWTH_MODEL_SLOT | typeof ARTIFACT_OBSERVATION_MODEL_SLOT
export type OptionalModelSlot = typeof OPTIONAL_MODEL_SLOTS[number]
export type ModelSlot = typeof MODEL_SLOTS[number]
export interface ModelSelection { version: 1; auxiliary_provider_id: string; overrides: Record<OptionalModelSlot,string> }
export interface ConfigurationValues { enabled:boolean; authority_profile:string; llm_provider_id:string; model_selection:ModelSelection }
export interface ProviderOption { provider_id:string; model_id:string }
export interface InstalledModel { provider_id:string; model_id:string; provider_config_digest:string; max_output_tokens:number }
export interface ConfigurationModelSlot { slot:ConfigurationSlot; selected_provider_id:string|null; model_id:string|null; provider_config_digest:string|null; installed:InstalledModel|null; state:'selected'|'pending'|'installed'; reason_code:string }
export interface InstalledPolicy { profile_id:string|null; installation_id:string|null; workflow_version:2|3|4|5|6|7|8|9|null; configured_model_slots:ConfigurationSlot[]; limits:Partial<Record<ConfigurationSlot,number>>; provider_options:ProviderOption[] }
export interface ConfigurationSnapshot {
  schema_version:typeof CONFIGURATION_SCHEMA; revision:number; values:ConfigurationValues; startup_values:ConfigurationValues
  writable_fields:['enabled','authority_profile','llm_provider_id','model_selection']; model_slots:ConfigurationModelSlot[]
  installed_policy:InstalledPolicy; apply_semantics:'next_reload'
}
interface ConfigurationWire extends ConfigurationSnapshot { csrf_token:string }
export type ConfigurationPatch = Partial<ConfigurationValues>
const REQUEST_MAX_BYTES=64*1024,RESPONSE_MAX_BYTES=512*1024
const code=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_.:-]{1,128}$/.test(v)
const text=(v:unknown,max:number,empty=false):v is string=>typeof v==='string'&&v.length>=(empty?0:1)&&v.length<=max
const positive=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=1
const digest=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v)
function invalid(status=0):never{throw new WorkbenchApiError('配置响应未通过精确协议校验。',{code:'invalid_response',status})}
export function validateConfigurationValues(value:unknown):asserts value is ConfigurationValues{
  if(!hasFields(value,['enabled','authority_profile','llm_provider_id','model_selection'])||typeof value.enabled!=='boolean'||!text(value.authority_profile,64)||!text(value.llm_provider_id,256,true))invalid()
  const selection=value.model_selection
  if(!hasFields(selection,['version','auxiliary_provider_id','overrides'])||selection.version!==1||!text(selection.auxiliary_provider_id,256,true)||!hasFields(selection.overrides,[...OPTIONAL_MODEL_SLOTS])||Object.values(selection.overrides).some(v=>!text(v,256,true)))invalid()
}
export function validateConfigurationWire(body:unknown):ConfigurationWire{
  if(!hasFields(body,['schema_version','revision','csrf_token','values','startup_values','writable_fields','model_slots','installed_policy','apply_semantics'])||body.schema_version!==CONFIGURATION_SCHEMA||!positive(body.revision)||!text(body.csrf_token,256)||body.apply_semantics!=='next_reload')invalid()
  validateConfigurationValues(body.values);validateConfigurationValues(body.startup_values)
  const policy=body.installed_policy
  const expectedSlots=hasFields(policy,['profile_id','installation_id','workflow_version','configured_model_slots','limits','provider_options'])?(policy.workflow_version===9?[...MODEL_SLOTS,RELATIONSHIP_MODEL_SLOT,GROWTH_MODEL_SLOT,GENERAL_GROWTH_MODEL_SLOT,ARTIFACT_OBSERVATION_MODEL_SLOT]:policy.workflow_version===8?[...MODEL_SLOTS,RELATIONSHIP_MODEL_SLOT,GROWTH_MODEL_SLOT,GENERAL_GROWTH_MODEL_SLOT]:[6,7].includes(policy.workflow_version as number)?[...MODEL_SLOTS,RELATIONSHIP_MODEL_SLOT,GROWTH_MODEL_SLOT]:policy.workflow_version===5?[...MODEL_SLOTS,RELATIONSHIP_MODEL_SLOT]:[...MODEL_SLOTS]):[...MODEL_SLOTS]
  if(JSON.stringify(body.writable_fields)!==JSON.stringify(['enabled','authority_profile','llm_provider_id','model_selection'])||!Array.isArray(body.model_slots)||body.model_slots.length!==expectedSlots.length)invalid()
  for(const [index,row]of body.model_slots.entries()){
    if(!hasFields(row,['slot','selected_provider_id','model_id','provider_config_digest','installed','state','reason_code'])||row.slot!==expectedSlots[index]||!['selected','pending','installed'].includes(row.state as string)||!code(row.reason_code))invalid()
    if(row.selected_provider_id===null){if(row.model_id!==null||row.provider_config_digest!==null)invalid()}
    else if(!text(row.selected_provider_id,256)||row.model_id!==null&&!text(row.model_id,256)||row.provider_config_digest!==null&&!digest(row.provider_config_digest))invalid()
    if(row.installed!==null&&(!hasFields(row.installed,['provider_id','model_id','provider_config_digest','max_output_tokens'])||!text(row.installed.provider_id,256)||!text(row.installed.model_id,256)||!digest(row.installed.provider_config_digest)||!positive(row.installed.max_output_tokens)))invalid()
    if(row.state==='installed'&&(!row.installed||row.selected_provider_id!==row.installed.provider_id||row.model_id!==row.installed.model_id||row.provider_config_digest!==row.installed.provider_config_digest))invalid()
  }
  if(!hasFields(policy,['profile_id','installation_id','workflow_version','configured_model_slots','limits','provider_options'])||policy.profile_id!==null&&!text(policy.profile_id,64)||policy.installation_id!==null&&!text(policy.installation_id,128)||![null,2,3,4,5,6,7,8,9].includes(policy.workflow_version as null|number)||!Array.isArray(policy.configured_model_slots)||policy.configured_model_slots.some(v=>!expectedSlots.includes(v as ConfigurationSlot))||new Set(policy.configured_model_slots).size!==policy.configured_model_slots.length||!hasFields(policy.limits,[],expectedSlots)||Object.values(policy.limits).some(v=>!positive(v))||!Array.isArray(policy.provider_options))invalid()
  const providers=new Set<string>()
  for(const option of policy.provider_options){if(!hasFields(option,['provider_id','model_id'])||!text(option.provider_id,256)||!text(option.model_id,256)||providers.has(option.provider_id))invalid();providers.add(option.provider_id)}
  return body as unknown as ConfigurationWire
}
export function configurationPatch(before:ConfigurationValues,after:ConfigurationValues):ConfigurationPatch{
  validateConfigurationValues(after)
  const patch:ConfigurationPatch={}
  for(const key of ['enabled','authority_profile','llm_provider_id','model_selection'] as const){if(JSON.stringify(before[key])!==JSON.stringify(after[key]))Object.assign(patch,{[key]:after[key]})}
  return patch
}
function configurationError(body:unknown,status:number):WorkbenchApiError{
  const transport=httpsResponseError(status,body);if(transport)return transport
  if(status===401)return new WorkbenchApiError('AstrBot 后台登录已失效，请重新登录。',{code:'host_session_missing',status})
  if(!hasFields(body,['schema_version','problem'])||body.schema_version!=='sylanne.webui-configuration-error.v1'||!hasFields(body.problem,['code','retryable'])||!code(body.problem.code)||typeof body.problem.retryable!=='boolean')invalid(status)
  const allowed:Record<string,number>={origin_denied:403,csrf_invalid:403,invalid_json:400,validation_failed:400,configuration_changed:409,idempotency_conflict:409,request_too_large:413,configuration_unavailable:503,unknown_outcome:503}
  if(allowed[body.problem.code]!==status)invalid(status)
  return new WorkbenchApiError('配置操作未完成。请重新读取真实值后再明确操作。',{code:body.problem.code,status,retryable:body.problem.retryable})
}
async function boundedJson(response:FetchResponse):Promise<unknown>{
  if(!response.body){const value=await response.json();if(new TextEncoder().encode(JSON.stringify(value)).byteLength>RESPONSE_MAX_BYTES)invalid(response.status);return value}
  const reader=response.body.getReader(),decoder=new TextDecoder('utf-8',{fatal:true});let bytes=0,result=''
  try{while(true){const chunk=await reader.read();if(chunk.done)break;bytes+=chunk.value.byteLength;if(bytes>RESPONSE_MAX_BYTES){await reader.cancel();invalid(response.status)}result+=decoder.decode(chunk.value,{stream:true})}return JSON.parse(result+decoder.decode())}finally{reader.releaseLock()}
}
export class ConfigurationApi{
  #csrf:string|null=null;#generation=0;#requests=new Set<AbortController>();#read:Promise<ConfigurationSnapshot>|null=null
  readonly enabled:boolean;readonly origin:string;readonly baseUrl=DEFAULT_API_BASE;#fetch:FetchLike;#timeout:number
  constructor({enabled=false,origin=typeof location==='undefined'?'http://localhost':location.origin,fetchImpl=globalThis.fetch as FetchLike,timeoutMs=10000}:{enabled?:boolean;origin?:string;fetchImpl?:FetchLike;timeoutMs?:number}={}){this.enabled=enabled;this.origin=origin;this.#fetch=fetchImpl;this.#timeout=timeoutMs}
  get transportAvailable(){return workbenchTransportAvailable(this.origin)}
  get secureTransport(){return this.transportAvailable&&new URL(this.origin).protocol==='https:'}
  clear(){++this.#generation;this.#csrf=null;this.#read=null;for(const request of this.#requests)request.abort();this.#requests.clear()}
  async #json(method:'GET'|'POST',payload?:object):Promise<ConfigurationSnapshot>{
    if(!this.enabled)throw new WorkbenchApiError('离线预览未读取或保存真实配置。',{code:'offline'})
    requireWorkbenchTransport(this.origin)
    const fetcher=this.#fetch
    if(method==='POST'&&!this.#csrf)throw new WorkbenchApiError('请先读取真实配置，取得独立配置校验令牌。',{code:'configuration_read_required'})
    const generation=this.#generation,abort=new AbortController();this.#requests.add(abort);let timer:ReturnType<typeof setTimeout>|undefined,listener:(()=>void)|undefined
    try{
      const result=await Promise.race([
        (async()=>{const response=await fetcher(`${this.baseUrl}/configuration/v1`,{method,credentials:'same-origin',mode:'same-origin',cache:'no-store',referrerPolicy:'same-origin',signal:abort.signal,headers:{accept:'application/json',...(method==='POST'?{'content-type':'application/json','X-Sylanne-Configuration-CSRF':this.#csrf!}:{})},...(payload?{body:JSON.stringify(payload)}:{})});let body:unknown;try{body=await boundedJson(response)}catch{invalid(response.status)}if(!response.ok)throw configurationError(body,response.status);return validateConfigurationWire(body)})(),
        new Promise<never>((_,reject)=>{timer=setTimeout(()=>{reject(new WorkbenchApiError('配置请求超时，提交结果尚未确认。',{code:'timeout',retryable:true}));abort.abort()},this.#timeout);listener=()=>{if(generation!==this.#generation)reject(new WorkbenchApiError('页面或会话已经变化，旧配置请求已作废。',{code:'session_changed'}))};abort.signal.addEventListener('abort',listener,{once:true})}),
      ])
      if(generation!==this.#generation)throw new WorkbenchApiError('旧配置响应已丢弃。',{code:'session_changed'})
      this.#csrf=result.csrf_token
      const {csrf_token:_csrf,...snapshot}=result
      return snapshot
    }catch(error){if(error instanceof WorkbenchApiError){if(error.code!=='https_required'&&[401,403].includes(error.status)&&generation===this.#generation)this.clear();throw error}throw new WorkbenchApiError('配置连接失败，结果未确认。',{code:'network_unavailable',retryable:true})}
    finally{if(timer)clearTimeout(timer);if(listener)abort.signal.removeEventListener('abort',listener);this.#requests.delete(abort)}
  }
  read():Promise<ConfigurationSnapshot>{if(this.#read)return this.#read;const job=this.#json('GET').finally(()=>{if(this.#read===job)this.#read=null});this.#read=job;return job}
  update(snapshot:ConfigurationSnapshot,patch:ConfigurationPatch,operationId=operationIdV1()):Promise<ConfigurationSnapshot>{
    if(!UUID4.test(operationId)||!hasFields(patch,[],['enabled','authority_profile','llm_provider_id','model_selection'])||Object.keys(patch).length===0)throw new WorkbenchApiError('配置补丁不符合当前协议。',{code:'invalid_input'})
    validateConfigurationValues({...snapshot.values,...patch})
    const payload={schema_version:CONFIGURATION_SCHEMA,operation_id:operationId,expected_revision:snapshot.revision,patch}
    if(new TextEncoder().encode(JSON.stringify(payload)).byteLength>REQUEST_MAX_BYTES)throw new WorkbenchApiError('配置请求超过当前接口上限。',{code:'invalid_input'})
    return this.#json('POST',payload)
  }
}
