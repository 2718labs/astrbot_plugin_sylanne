import {operationIdV1} from './api/browser-crypto.ts'
import {computed,reactive,ref,shallowRef,toRaw} from 'vue'
import {canonicalJson} from './api/contract.ts'
import type {CreatorConfiguration,SchemeField,SchemeValues,CompiledSchemeReceipt,PreviewSchemeReceipt,AdoptedSchemeReceipt} from './api/creator.ts'
import {WorkbenchApiError,type WorkbenchApi} from './api/client.ts'
type SchemeAction='compile_scheme'|'preview_scheme'|'activate_scheme'
type PendingCreatorAttempt={readonly scope:string;readonly operationId:string;readonly ownerBindingDigest:string;readonly snapshot:CreatorConfiguration;readonly compiled:CompiledSchemeReceipt|null}&(
 {readonly action:'save_creator_draft';readonly fields:SchemeValues}|{readonly action:SchemeAction;readonly input:Record<string,string>})
const unknownMessage='领域操作结果未知，可能已保存或计费。原 UUID 与输入已保留，请恢复原 Owner 后显式核验；读取当前草稿不会替代原回执。'
function frozenCopy<T>(value:T):T{const copy=structuredClone(toRaw(value));function freeze(item:unknown){if(item!==null&&typeof item==='object'){Object.values(item).forEach(freeze);Object.freeze(item)}}freeze(copy);return copy}
export function createCreatorConfiguration(api:Pick<WorkbenchApi,'readConfigurationDraft'|'saveCreatorDraft'|'schemeCommand'|'invalidateCreator'|'readOwnerSessionIdentity'>,eligible:()=>boolean,scope:()=>string,onAuthError:(error:unknown)=>void){
 const state=reactive<{status:'idle'|'loading'|'ready'|'saving'|'saved_not_adopted'|'conflict'|'unknown'|'unavailable'|'error';data:CreatorConfiguration|null;draft:SchemeValues|null;message:string;needsRead:boolean;operationId:string|null;compiled:CompiledSchemeReceipt|null;preview:PreviewSchemeReceipt|null;adopted:AdoptedSchemeReceipt|null}>({status:'idle',data:null,draft:null,message:'',needsRead:true,operationId:null,compiled:null,preview:null,adopted:null})
 const reading=ref(false),writing=ref(false),pending=shallowRef<PendingCreatorAttempt|null>(null)
 let generation=0,uncertain=false
 const pendingAttempt=computed(()=>pending.value?{scope:pending.value.scope,operationId:pending.value.operationId,action:pending.value.action,ownerBindingDigest:pending.value.ownerBindingDigest}:null)
 const canRead=computed(()=>eligible()&&!reading.value&&!writing.value)
 const canRecover=computed(()=>canRead.value&&pending.value?.scope===scope())
 const canEdit=computed(()=>canRead.value&&!pending.value&&!state.needsRead&&!!state.data&&!!state.draft&&state.data.action_permissions.save)
 const dirty=computed(()=>!!state.data&&!!state.draft&&canonicalJson(state.data.fields)!==canonicalJson(state.draft))
 const canSave=computed(()=>canEdit.value&&dirty.value)
 const d09Only=computed(()=>!!state.data&&Object.keys(state.data.fields).length===1&&'d09.expression_policy'in state.data.fields)
 const previewFields=computed(()=>!!state.data&&Object.keys(state.data.fields).length>0&&Object.keys(state.data.fields).every(path=>['d07.attention_policy','d09.expression_policy'].includes(path)))
 const canCompile=computed(()=>canRead.value&&!pending.value&&!state.needsRead&&!dirty.value&&!!state.data?.action_permissions.compile&&state.data.exists&&!!state.data.budget_ref)
 const canPreview=computed(()=>canRead.value&&!pending.value&&!state.needsRead&&!dirty.value&&!!state.data?.action_permissions.preview&&previewFields.value&&!!state.compiled&&!!state.data.budget_ref&&state.data.active_head_revision>0)
 const canActivate=computed(()=>canRead.value&&!pending.value&&!state.needsRead&&!dirty.value&&!!state.data?.action_permissions.activate&&d09Only.value&&!!state.preview&&!!state.compiled&&state.data.active_head_revision>0)
 function invalidate(){++generation;uncertain=!!pending.value;api.invalidateCreator();state.data=null;state.draft=null;state.compiled=null;state.preview=null;state.adopted=null;state.needsRead=true;state.operationId=pending.value?.operationId??null;state.status=uncertain?'unknown':'idle';state.message=uncertain?unknownMessage:''}
 function fail(error:unknown){if(error instanceof WorkbenchApiError&&[401,403].includes(error.status))onAuthError(error)}
 function current(token:number,currentScope:string){return token===generation&&currentScope===scope()&&eligible()}
 async function read(){
  if(!canRead.value)return
  const token=generation,currentScope=scope();reading.value=true;state.status='loading';state.data=null;state.draft=null;state.compiled=null;state.preview=null;state.adopted=null;state.needsRead=true;state.message='正在读取当前 Owner 授权的方案草稿与版本基线。'
  try{const data=await api.readConfigurationDraft(currentScope);if(!current(token,currentScope))return;state.data=data;state.draft=structuredClone(toRaw(data.fields));state.needsRead=!!pending.value;uncertain=!!pending.value;state.operationId=pending.value?.operationId??null;state.status=uncertain?'unknown':'ready';state.message=uncertain?unknownMessage:data.exists?'已读取真实方案草稿；它不等于当前已采纳方案。':'当前没有方案草稿。可在本次实际 CAS 基线下保存首份草稿。'}
  catch(error){if(token!==generation)return;fail(error);if(token!==generation)return;state.status=uncertain?'unknown':error instanceof WorkbenchApiError&&error.code!=='invalid_response'?'unavailable':'error';state.message=uncertain?unknownMessage:'当前 Owner 创建权限、Graph 路径或方案端口尚未满足。请检查实际条件后重新读取。'}finally{reading.value=false}
 }
 function setField(path:SchemeField,value:unknown){if(!canEdit.value||!state.data||!state.draft||!state.data.supported_fields.some(row=>row.path===path&&row.editable)||path==='d04.authored_root')return;state.draft[path]=value;state.compiled=null;state.preview=null;state.adopted=null}
 function removeField(path:SchemeField){if(!canEdit.value||!state.data||!state.draft||!state.data.supported_fields.some(row=>row.path===path&&row.editable)||path==='d04.authored_root')return;delete state.draft[path];state.compiled=null;state.preview=null;state.adopted=null}
 function confirmed(attempt:PendingCreatorAttempt){if(pending.value===attempt)pending.value=null;uncertain=!!pending.value}
 async function run(attempt:PendingCreatorAttempt,token:number){
  if(attempt.action==='save_creator_draft'){
   const receipt=await api.saveCreatorDraft(attempt.scope,attempt.snapshot,attempt.fields,attempt.operationId);confirmed(attempt)
   if(!current(token,attempt.scope))return
   const data=await api.readConfigurationDraft(attempt.scope);if(!current(token,attempt.scope))return
   if(data.draft_revision!==receipt.draft_revision||data.draft_digest!==receipt.draft_digest||canonicalJson(data.fields)!==canonicalJson(attempt.fields))throw new WorkbenchApiError('草稿独立回读不一致。',{code:'draft_readback_mismatch'})
   state.data=data;state.draft=structuredClone(toRaw(data.fields));state.needsRead=false;state.status='saved_not_adopted';state.compiled=null;state.preview=null;state.adopted=null;state.message='方案草稿已保存并独立回读确认；尚未编译、预览或采纳到运行方案。'
  }else{
   const receipt=await api.schemeCommand(attempt.action,attempt.scope,attempt.input,attempt.operationId);confirmed(attempt)
   if(!current(token,attempt.scope))return
   const data=await api.readConfigurationDraft(attempt.scope);if(!current(token,attempt.scope))return
   state.data=data;state.draft=structuredClone(toRaw(data.fields));state.needsRead=false;state.status='ready'
   if(attempt.action==='compile_scheme'){
    const compiled=receipt as CompiledSchemeReceipt
    state.compiled=data.draft_ref===compiled.draft_ref&&data.draft_revision===compiled.draft_revision?compiled:null;state.preview=null;state.adopted=null;state.message=state.compiled?'已记录真实编译候选原件；不是已采纳方案。':'已恢复原编译回执；当前草稿已变化，原候选未作为当前可采用候选。'
   }else if(attempt.action==='preview_scheme'){
    const preview=receipt as PreviewSchemeReceipt
    state.compiled=data.draft_digest===attempt.snapshot.draft_digest&&attempt.compiled?.compiled_digest===preview.compiled_digest?attempt.compiled:null
    state.preview=preview;state.adopted=null;state.message='已记录原 UUID 的真实隔离预览回执；未写入正式行为状态。'
   }else{
    const adopted=receipt as AdoptedSchemeReceipt
    if(data.active_head_ref!==adopted.active_head_ref||data.active_head_revision!==adopted.active_head_revision||data.graph_revision!==adopted.graph_revision)throw new WorkbenchApiError('采用后 head 独立回读不一致。',{code:'adoption_readback_mismatch'})
    state.compiled=null;state.preview=null;state.adopted=adopted;state.message='当前 D09 方案采用原件与 head 回读一致。其他领域草稿仍不能据此声称已采纳。'
   }
  }
 }
 function requestFailure(error:unknown,token:number){if(token!==generation)return;fail(error);if(token!==generation)return;state.needsRead=true;state.compiled=null;state.preview=null;state.adopted=null;state.status=pending.value?'unknown':'error';uncertain=!!pending.value;state.message=pending.value?unknownMessage:state.operationId?'原回执已收到，但当前状态回读尚未确认。请重新读取；不会重放已确认操作。':'当前 Owner 身份尚未通过核验，未创建新的领域操作。'}
 async function save(){
  if(!canSave.value||!state.data||!state.draft)return
  const token=generation,currentScope=scope(),snapshot=frozenCopy(state.data),fields=frozenCopy(state.draft)
  writing.value=true;state.status='saving';state.operationId=null;state.message='正在核验实际 Owner 并固定本次保存输入。'
  try{const identity=await api.readOwnerSessionIdentity();if(!current(token,currentScope))return;const attempt:PendingCreatorAttempt=Object.freeze({action:'save_creator_draft',scope:currentScope,operationId:operationIdV1(),ownerBindingDigest:identity.owner_binding_digest,snapshot,fields,compiled:null});pending.value=attempt;state.operationId=attempt.operationId;await run(attempt,token)}catch(error){requestFailure(error,token)}finally{writing.value=false}
 }
 async function scheme(action:SchemeAction){
  if(!(action==='compile_scheme'?canCompile.value:action==='preview_scheme'?canPreview.value:canActivate.value)||!state.data)return
  const token=generation,currentScope=scope(),snapshot=frozenCopy(state.data),compiled=state.compiled?frozenCopy(state.compiled):null
  const input:Record<string,string>=action==='compile_scheme'?{draft_ref:state.data.draft_ref,budget_ref:state.data.budget_ref!}:action==='preview_scheme'?{compiled_digest:state.compiled!.compiled_digest,budget_ref:state.data.budget_ref!}:{compiled_digest:state.compiled!.compiled_digest,preview_seal:state.preview!.preview_seal}
  writing.value=true;state.operationId=null;state.message='正在核验实际 Owner 并固定本次操作；不会自动重放。'
  try{const identity=await api.readOwnerSessionIdentity();if(!current(token,currentScope))return;const attempt:PendingCreatorAttempt=Object.freeze({action,scope:currentScope,operationId:operationIdV1(),ownerBindingDigest:identity.owner_binding_digest,snapshot,compiled,input:Object.freeze(input)});pending.value=attempt;state.operationId=attempt.operationId;await run(attempt,token)}catch(error){requestFailure(error,token)}finally{writing.value=false}
 }
 async function recover(){
  if(!canRecover.value||!pending.value)return
  const attempt=pending.value,token=generation;writing.value=true;state.message='正在核验原 Owner，随后恢复同一 UUID 的正式回执。'
  try{const identity=await api.readOwnerSessionIdentity();if(!current(token,attempt.scope))return;if(identity.owner_binding_digest!==attempt.ownerBindingDigest)throw new Error('原请求属于另一 Owner 身份，请恢复原身份后核验。');await run(attempt,token)}catch(error){requestFailure(error,token)}finally{writing.value=false}
 }
 return{state,reading,writing,canRead,canEdit,dirty,canSave,d09Only,canCompile,canPreview,canActivate,pendingAttempt,canRecover,recover,invalidate,read,setField,removeField,save,compile:()=>scheme('compile_scheme'),preview:()=>scheme('preview_scheme'),activate:()=>scheme('activate_scheme')}
}
