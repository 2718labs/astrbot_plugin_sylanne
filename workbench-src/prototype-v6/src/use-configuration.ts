import {operationIdV1} from './api/browser-crypto.ts'
import { computed, reactive, ref, toRaw } from 'vue'
import { ConfigurationApi, configurationPatch, type ConfigurationSnapshot, type ConfigurationValues, type ModelSlot } from './api/configuration.ts'
import { canonicalJson } from './api/contract.ts'
import { WorkbenchApiError, HTTPS_REQUIRED_MESSAGE } from './api/client.ts'

type ConfigurationStatus='idle'|'loading'|'ready'|'saving'|'verifying'|'saved'|'pending_reload'|'conflict'|'unknown'|'error'|'https_required'
const unknownMessage='提交结果未知，配置可能已保存。请显式重新读取真实配置；不会重放保存请求。'
export function createConfiguration(api:ConfigurationApi,eligible:()=>boolean,onAuthError:(error:unknown)=>void){
  const state=reactive<{status:ConfigurationStatus;data:ConfigurationSnapshot|null;draft:ConfigurationValues|null;message:string;needsRead:boolean;operationId:string|null}>({status:'idle',data:null,draft:null,message:'',needsRead:true,operationId:null})
  const reading=ref(false),writing=ref(false);let generation=0,uncertain=false
  const canRead=computed(()=>eligible()&&!reading.value&&!writing.value)
  const canEdit=computed(()=>eligible()&&!reading.value&&!writing.value&&!state.needsRead&&!!state.data&&!!state.draft)
  const dirty=computed(()=>!!state.data&&!!state.draft&&canonicalJson(state.data.values)!==canonicalJson(state.draft))
  const canSave=computed(()=>canEdit.value&&dirty.value)
  const pendingReload=computed(()=>!!state.data&&canonicalJson(state.data.values)!==canonicalJson(state.data.startup_values))
  function invalidate(){++generation;uncertain=uncertain||writing.value;api.clear();state.data=null;state.draft=null;state.needsRead=true;state.status=uncertain?'unknown':'idle';state.message=uncertain?unknownMessage:''}
  function authFailure(error:unknown){if(error instanceof WorkbenchApiError&&(error.code==='https_required'||error.status===401||error.status===403&&error.code==='origin_denied'))onAuthError(error)}
  async function read(){
    if(!canRead.value)return
    const token=generation;reading.value=true;state.status='loading';state.data=null;state.draft=null;state.needsRead=true;state.message='正在读取实际保存目标、启动配置与模型安装匹配。'
    try{const data=await api.read();if(token!==generation||!eligible())return;state.data=data;state.draft=structuredClone(toRaw(data.values));state.needsRead=false;uncertain=false;state.operationId=null;state.status=pendingReload.value?'pending_reload':'ready';state.message=pendingReload.value?'已读取真实保存目标。与本次启动配置不同，重新加载插件后生效。':'已读取当前实际配置。'}
    catch(error){if(token!==generation)return;authFailure(error);if(token!==generation)return;state.status=error instanceof WorkbenchApiError&&error.code==='https_required'?'https_required':uncertain?'unknown':'error';state.message=state.status==='https_required'?HTTPS_REQUIRED_MESSAGE:uncertain?unknownMessage:'配置读取失败、登录失效或返回不兼容。请重新读取；未使用默认值替代。'}
    finally{reading.value=false}
  }
  function setBasic(key:'enabled'|'authority_profile',value:boolean|string){if(!canEdit.value||!state.draft)return;if(key==='enabled'&&typeof value==='boolean')state.draft.enabled=value;else if(key==='authority_profile'&&typeof value==='string')state.draft.authority_profile=value}
  function selectModel(slot:ModelSlot|'auxiliary',providerId:string){
    if(!canEdit.value||!state.data||!state.draft)return
    if(providerId!==''&&!state.data.installed_policy.provider_options.some(option=>option.provider_id===providerId))return
    if(slot==='reply')state.draft.llm_provider_id=providerId
    else if(slot==='auxiliary')state.draft.model_selection.auxiliary_provider_id=providerId
    else state.draft.model_selection.overrides[slot]=providerId
  }
  function resetDraft(){if(canEdit.value&&state.data)state.draft=structuredClone(toRaw(state.data.values))}
  async function save(){
    if(!canSave.value||!state.data||!state.draft)return
    const snapshot=state.data,target=structuredClone(toRaw(state.draft)),patch=configurationPatch(snapshot.values,target),token=generation,operationId=operationIdV1()
    state.operationId=operationId;writing.value=true;state.status='saving';state.message='正在保存真实本机配置。不会自动重试。'
    let returned=false
    try{
      const receipt=await api.update(snapshot,patch,operationId);if(token!==generation||!eligible())return
      returned=true;state.status='verifying';state.message='已收到保存响应，正在独立读取并核对版本和值。'
      const readback=await api.read();if(token!==generation||!eligible())return
      if(readback.revision!==receipt.revision||canonicalJson(readback.values)!==canonicalJson(target))throw new WorkbenchApiError('配置回读不一致。',{code:'readback_mismatch'})
      state.data=readback;state.draft=structuredClone(toRaw(readback.values));state.needsRead=false;uncertain=false;state.status=pendingReload.value?'pending_reload':'saved';state.message=pendingReload.value?'保存目标已独立回读确认；待重新加载插件生效。当前运行许可没有因此改变。':'保存目标已独立回读确认。实际模型请求仍需当前安装授权。'
    }catch(error){
      if(token!==generation)return;authFailure(error);if(token!==generation)return
      const rejected=!returned&&error instanceof WorkbenchApiError&&(error.code==='https_required'||(error.status===409&&['configuration_changed','idempotency_conflict'].includes(error.code))||(error.status===400&&error.code==='validation_failed')||(error.status===403&&error.code==='csrf_invalid')||(error.status===413&&error.code==='request_too_large'))
      uncertain=!rejected;state.data=null;state.draft=null;state.needsRead=true;state.status=error instanceof WorkbenchApiError&&error.code==='https_required'?'https_required':rejected&&error instanceof WorkbenchApiError&&error.status===409?'conflict':uncertain?'unknown':'error';state.message=state.status==='https_required'?HTTPS_REQUIRED_MESSAGE:uncertain?unknownMessage:'配置版本、校验令牌或输入已变化。请显式重新读取后再保存；不会覆盖当前值。'
    }finally{writing.value=false}
  }
  return{state,canRead,canEdit,canSave,dirty,pendingReload,reading,writing,invalidate,read,setBasic,selectModel,resetDraft,save}
}
export type ConfigurationController=ReturnType<typeof createConfiguration>
