import {operationIdV1} from './api/browser-crypto.ts'
import { computed, reactive, ref, toRaw } from 'vue'
import { canonicalJson } from './api/contract.ts'
import type { CreatorConfiguration, SchemeField, SchemeValues, CompiledSchemeReceipt, PreviewSchemeReceipt, AdoptedSchemeReceipt } from './api/creator.ts'
import { WorkbenchApiError, type WorkbenchApi } from './api/client.ts'

const unknownMessage='领域操作结果未知，可能已保存或计费。请显式读取当前草稿；不会自动重放同一操作。'
export function createCreatorConfiguration(api:Pick<WorkbenchApi,'readConfigurationDraft'|'saveCreatorDraft'|'schemeCommand'|'invalidateCreator'>,eligible:()=>boolean,scope:()=>string,onAuthError:(error:unknown)=>void){
  const state=reactive<{status:'idle'|'loading'|'ready'|'saving'|'saved_not_adopted'|'conflict'|'unknown'|'unavailable'|'error';data:CreatorConfiguration|null;draft:SchemeValues|null;message:string;needsRead:boolean;operationId:string|null;compiled:CompiledSchemeReceipt|null;preview:PreviewSchemeReceipt|null;adopted:AdoptedSchemeReceipt|null}>({status:'idle',data:null,draft:null,message:'',needsRead:true,operationId:null,compiled:null,preview:null,adopted:null})
  const reading=ref(false),writing=ref(false);let generation=0,uncertain=false
  const canRead=computed(()=>eligible()&&!reading.value&&!writing.value)
  const canEdit=computed(()=>eligible()&&!reading.value&&!writing.value&&!state.needsRead&&!!state.data&&!!state.draft&&state.data.action_permissions.save)
  const dirty=computed(()=>!!state.data&&!!state.draft&&canonicalJson(state.data.fields)!==canonicalJson(state.draft))
  const canSave=computed(()=>canEdit.value&&dirty.value)
  const d09Only=computed(()=>!!state.data&&Object.keys(state.data.fields).length===1&&'d09.expression_policy'in state.data.fields)
  const previewFields=computed(()=>!!state.data&&Object.keys(state.data.fields).length>0&&Object.keys(state.data.fields).every(path=>['d07.attention_policy','d09.expression_policy'].includes(path)))
  const canCompile=computed(()=>eligible()&&!reading.value&&!writing.value&&!state.needsRead&&!dirty.value&&!!state.data?.action_permissions.compile&&state.data.exists&&!!state.data.budget_ref)
  const canPreview=computed(()=>eligible()&&!reading.value&&!writing.value&&!state.needsRead&&!dirty.value&&!!state.data?.action_permissions.preview&&previewFields.value&&!!state.compiled&&!!state.data.budget_ref&&state.data.active_head_revision>0)
  const canActivate=computed(()=>eligible()&&!reading.value&&!writing.value&&!state.needsRead&&!dirty.value&&!!state.data?.action_permissions.activate&&d09Only.value&&!!state.preview&&!!state.compiled&&state.data.active_head_revision>0)
  function invalidate(){++generation;uncertain=uncertain||writing.value;api.invalidateCreator();state.data=null;state.draft=null;state.compiled=null;state.preview=null;state.adopted=null;state.needsRead=true;state.status=uncertain?'unknown':'idle';state.message=uncertain?unknownMessage:''}
  function fail(error:unknown){if(error instanceof WorkbenchApiError&&[401,403].includes(error.status))onAuthError(error)}
  async function read(){
    if(!canRead.value)return
    const token=generation,currentScope=scope();reading.value=true;state.status='loading';state.data=null;state.draft=null;state.compiled=null;state.preview=null;state.adopted=null;state.needsRead=true;state.message='正在读取当前 Owner 授权的方案草稿与版本基线。'
    try{const data=await api.readConfigurationDraft(currentScope);if(token!==generation||currentScope!==scope()||!eligible())return;state.data=data;state.draft=structuredClone(toRaw(data.fields));state.needsRead=false;uncertain=false;state.operationId=null;state.status='ready';state.message=data.exists?'已读取真实方案草稿；它不等于当前已采纳方案。':'当前没有方案草稿。可在本次实际 CAS 基线下保存首份草稿，不会生成已采纳 head。'}
    catch(error){if(token!==generation)return;fail(error);if(token!==generation)return;state.status=uncertain?'unknown':error instanceof WorkbenchApiError&&error.code!=='invalid_response'?'unavailable':'error';state.message=uncertain?unknownMessage:'当前 Owner 创建权限、Graph 路径或方案端口尚未满足。未读取私有字段，请检查实际条件后重新读取。'}finally{reading.value=false}
  }
  function setField(path:SchemeField,value:unknown){if(!canEdit.value||!state.data||!state.draft||!state.data.supported_fields.some(row=>row.path===path&&row.editable)||path==='d04.authored_root')return;state.draft[path]=value;state.compiled=null;state.preview=null;state.adopted=null}
  function removeField(path:SchemeField){if(!canEdit.value||!state.data||!state.draft||!state.data.supported_fields.some(row=>row.path===path&&row.editable)||path==='d04.authored_root')return;delete state.draft[path];state.compiled=null;state.preview=null;state.adopted=null}
  async function save(){
    if(!canSave.value||!state.data||!state.draft)return
    const token=generation,currentScope=scope(),snapshot=state.data,fields=structuredClone(toRaw(state.draft)),operationId=operationIdV1();state.operationId=operationId;writing.value=true;state.status='saving';state.message='正在按当前真实 CAS 基线保存草稿；不会自动重放。'
    try{const receipt=await api.saveCreatorDraft(currentScope,snapshot,fields,operationId);if(token!==generation||currentScope!==scope()||!eligible())return;const data=await api.readConfigurationDraft(currentScope);if(token!==generation||currentScope!==scope()||!eligible())return;if(data.draft_revision!==receipt.draft_revision||data.draft_digest!==receipt.draft_digest||canonicalJson(data.fields)!==canonicalJson(fields))throw new WorkbenchApiError('草稿独立回读不一致。',{code:'draft_readback_mismatch'});state.data=data;state.draft=structuredClone(toRaw(data.fields));state.needsRead=false;uncertain=false;state.status='saved_not_adopted';state.compiled=null;state.preview=null;state.adopted=null;state.message='方案草稿已保存并独立回读确认；尚未编译、预览或采纳到运行方案。'}
    catch(error){if(token!==generation)return;fail(error);if(token!==generation)return;const conflict=error instanceof WorkbenchApiError&&error.code==='creator_conflict';uncertain=!conflict;state.data=null;state.draft=null;state.needsRead=true;state.status=conflict?'conflict':'unknown';state.message=conflict?'草稿、Graph 或访问基线已变化，请重新读取后明确合并；不会覆盖。':unknownMessage}finally{writing.value=false}
  }
  async function scheme(action:'compile_scheme'|'preview_scheme'|'activate_scheme'){
    if(!(action==='compile_scheme'?canCompile.value:action==='preview_scheme'?canPreview.value:canActivate.value)||!state.data)return
    const token=generation,currentScope=scope(),operationId=operationIdV1(),input:Record<string,string>=action==='compile_scheme'?{draft_ref:state.data.draft_ref,budget_ref:state.data.budget_ref!}:action==='preview_scheme'?{compiled_digest:state.compiled!.compiled_digest,budget_ref:state.data.budget_ref!}:{compiled_digest:state.compiled!.compiled_digest,preview_seal:state.preview!.preview_seal};state.operationId=operationId;writing.value=true;state.message='正在执行明确选择的领域操作；不自动重放，也不解除其他领域门槛。'
    try{const receipt=await api.schemeCommand(action,currentScope,input,operationId);if(token!==generation||currentScope!==scope()||!eligible())return;if(action==='compile_scheme'){state.compiled=receipt as CompiledSchemeReceipt;state.preview=null;state.adopted=null;state.message='已记录真实编译候选原件；不是已采纳方案。'}else if(action==='preview_scheme'){state.preview=receipt as PreviewSchemeReceipt;state.message='已记录真实隔离预览原件；未写入正式行为状态。'}else{const adopted=receipt as AdoptedSchemeReceipt,data=await api.readConfigurationDraft(currentScope);if(token!==generation||currentScope!==scope()||!eligible())return;if(data.active_head_ref!==adopted.active_head_ref||data.active_head_revision!==adopted.active_head_revision||data.graph_revision!==adopted.graph_revision)throw new WorkbenchApiError('采用后 head 独立回读不一致。',{code:'adoption_readback_mismatch'});state.data=data;state.draft=structuredClone(toRaw(data.fields));state.adopted=adopted;state.message='当前 D09 方案采用原件与 head 回读一致。其他领域草稿仍不能据此声称已采纳。'}}
    catch(error){if(token!==generation)return;fail(error);if(token!==generation)return;uncertain=true;state.needsRead=true;state.status='unknown';state.compiled=null;state.preview=null;state.adopted=null;state.message=unknownMessage}finally{writing.value=false}
  }
  return{state,reading,writing,canRead,canEdit,dirty,canSave,d09Only,canCompile,canPreview,canActivate,invalidate,read,setField,removeField,save,compile:()=>scheme('compile_scheme'),preview:()=>scheme('preview_scheme'),activate:()=>scheme('activate_scheme')}
}
