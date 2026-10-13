import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ref, createRenderer, h, nextTick } from 'vue'
import * as Vue from 'vue'
import { parse, compileScript } from '@vue/compiler-sfc'
import ts from 'typescript'
import { readFile } from 'node:fs/promises'
import { useBackend, type BackendController } from './use-backend.ts'
import { ConfigurationApi, MODEL_SLOTS, OPTIONAL_MODEL_SLOTS, validateConfigurationWire, type ConfigurationValues } from './api/configuration.ts'
import { createConfiguration } from './use-configuration.ts'
import { WorkbenchApi, type FetchResponse } from './api/client.ts'
import { createCreatorConfiguration } from './use-creator-configuration.ts'
import { SCHEME_FIELDS, draftSaveInput, validateCreatorConfiguration, type CreatorConfiguration } from './api/creator.ts'
import { useDisplayAlias } from './ui-preferences.ts'

const origin='https://configuration-test.invalid',scope='test-bot/test-persona'
const values=():ConfigurationValues=>({enabled:false,authority_profile:'default',llm_provider_id:'provider-a',model_selection:{version:1,auxiliary_provider_id:'',overrides:Object.fromEntries(OPTIONAL_MODEL_SLOTS.map(slot=>[slot,''])) as ConfigurationValues['model_selection']['overrides']}})
const installed={provider_id:'provider-a',model_id:'model-a',provider_config_digest:'a'.repeat(64),max_output_tokens:4096}
function wire(current=values(),revision=1,startup=values()){
  return{schema_version:'sylanne.webui-configuration.v1',revision,csrf_token:'synthetic-configuration-csrf',values:current,startup_values:startup,writable_fields:['enabled','authority_profile','llm_provider_id','model_selection'],apply_semantics:'next_reload',
    model_slots:MODEL_SLOTS.map(slot=>{const selected=slot==='reply'?current.llm_provider_id:current.model_selection.overrides[slot]||current.model_selection.auxiliary_provider_id||(slot==='encode'?'provider-a':'');const observed=selected==='provider-a'?installed:selected?{...installed,provider_id:selected,model_id:'model-b',provider_config_digest:'b'.repeat(64)}:null,old=slot==='reply'||slot==='encode'?installed:null;return{slot,selected_provider_id:observed?.provider_id??null,model_id:observed?.model_id??null,provider_config_digest:observed?.provider_config_digest??null,installed:old,state:!observed?'pending':old?old.provider_id===selected?'installed':'pending':'selected',reason_code:!observed?'model_unselected':old?old.provider_id===selected?'none':'model_provider_mismatch':'model_awaiting_installation'}}),
    installed_policy:{profile_id:'default',installation_id:'test-installation',workflow_version:3,configured_model_slots:['reply','encode'],limits:{reply:4096,encode:4096},provider_options:[{provider_id:'provider-a',model_id:'model-a'},{provider_id:'provider-b',model_id:'model-b'}]}}
}
function response(body:unknown,status=200):FetchResponse{return{ok:status>=200&&status<300,status,json:async()=>body}}
function deferred<T>(){let resolve!:(value:T)=>void;const promise=new Promise<T>(done=>{resolve=done});return{promise,resolve}}
const tick=()=>new Promise(done=>setTimeout(done,0))
const session={status:'ready',dashboard_session:'authenticated',owner_session:'unlocked',csrf_token:'synthetic-owner-csrf'}
function creator(fields:CreatorConfiguration['fields']={'d09.expression_policy':{schema:'test-d09',version:1}},revision=1,draftDigest='c'.repeat(64),graphRevision=1):CreatorConfiguration{return{schema:'d12.creator-configuration.v1',draft_ref:'actual-draft-ref',exists:true,draft_revision:revision,draft_digest:draftDigest,fields,field_sources:Object.fromEntries(Object.keys(fields).map(path=>[path,'actual-server-source'])),budget_ref:'actual-server-budget-ref',active_head_ref:'actual-active-head',active_head_revision:1,graph_revision:graphRevision,access_epoch:1,delete_epoch:1,access_generation:1,supported_fields:SCHEME_FIELDS.map(path=>({path,label:path,editable:path!=='d04.authored_root'})),field_templates:Object.fromEntries(SCHEME_FIELDS.filter(path=>path!=='d04.authored_root').map(path=>[path,{version:1}])),action_permissions:{save:true,compile:true,preview:true,activate:true}}}

test('configuration uses actual SDK options, independent private CSRF, exact four-key POST and separate GET readback',async()=>{
  let current=values(),revision=1;const calls:{url:string;init:RequestInit}[]=[]
  const api=new ConfigurationApi({enabled:true,origin,fetchImpl:async(url,init)=>{calls.push({url,init});if(init.method==='POST'){const body=JSON.parse(String(init.body));assert.deepEqual(Object.keys(body).sort(),['schema_version','operation_id','expected_revision','patch'].sort());assert.equal((init.headers as Record<string,string>)['X-Sylanne-Configuration-CSRF'],'synthetic-configuration-csrf');assert.equal((init.headers as Record<string,string>)['x-csrf-token'],undefined);assert.equal(body.expected_revision,1);current={...current,...body.patch};revision++}return response(wire(current,revision))}})
  const controller=createConfiguration(api,()=>true,()=>{});assert.equal(calls.length,0);await controller.read();assert.equal('csrf_token'in controller.state.data!,false)
  controller.selectModel('encode','provider-b');await controller.save()
  assert.equal(calls.length,3);assert.ok(calls.every(call=>call.url.endsWith('/configuration/v1')));assert.ok(calls.every(call=>call.init.credentials==='same-origin'&&call.init.mode==='same-origin'&&call.init.cache==='no-store'))
  assert.equal(controller.state.status,'pending_reload');assert.equal(controller.state.data?.values.model_selection.overrides.encode,'provider-b');assert.equal(controller.state.data?.startup_values.model_selection.overrides.encode,'');assert.equal(controller.state.data?.model_slots.find(row=>row.slot==='encode')?.state,'pending')
})
test('configuration exact schema rejects raw provider config, unknown fields, incompatible slots and false installed matching',()=>{
  const base=wire();assert.equal(validateConfigurationWire(base).revision,1)
  for(const bad of [{...base,schema_version:'future'},{...base,raw_config:'synthetic-secret'},{...base,values:{...base.values,raw_key:'synthetic-secret'}},{...base,installed_policy:{...base.installed_policy,provider_options:[{provider_id:'provider-a',model_id:'model-a',key:'synthetic-secret'}]}},{...base,model_slots:base.model_slots.slice(1)},{...base,model_slots:base.model_slots.map(row=>row.slot==='reply'?{...row,model_id:'other-model'}:row)}])assert.throws(()=>validateConfigurationWire(bad),{code:'invalid_response'})
})
test('configuration conflict and unknown save outcomes do not retry, and a readback mismatch cannot become saved',async()=>{
  for(const mode of ['conflict','unknown','readback'] as const){let posts=0,reads=0,current=values();const api=new ConfigurationApi({enabled:true,origin,fetchImpl:async(_url,init)=>{if(init.method==='POST'){posts++;if(mode==='conflict')return response({schema_version:'sylanne.webui-configuration-error.v1',problem:{code:'configuration_changed',retryable:false}},409);current={...current,enabled:true};if(mode==='unknown')return response({schema_version:'sylanne.webui-configuration-error.v1',problem:{code:'unknown_outcome',retryable:false}},503);return response(wire(current,2))}reads++;return response(wire(mode==='readback'&&reads>1?{...current,authority_profile:'other'}:current,reads>1?3:1))}});const controller=createConfiguration(api,()=>true,()=>{});await controller.read();controller.setBasic('enabled',true);await controller.save();assert.equal(posts,1);assert.equal(controller.canSave.value,false);assert.equal(controller.state.status,mode==='conflict'?'conflict':'unknown');assert.ok(controller.state.operationId);await controller.save();assert.equal(posts,1)}
})
test('configuration invalidation aborts late reads and preserves unknown mutation status without restoring a token',async()=>{
  const late=deferred<FetchResponse>();let first=true,signal:AbortSignal|null|undefined
  const api=new ConfigurationApi({enabled:true,origin,fetchImpl:async(_url,init)=>{if(first){first=false;return response(wire())}signal=init.signal;return late.promise}}),controller=createConfiguration(api,()=>true,()=>{})
  await controller.read();controller.setBasic('enabled',true);const pending=controller.save();await tick();controller.invalidate();assert.equal(signal?.aborted,true);late.resolve(response(wire({...values(),enabled:true},2)));await pending;assert.equal(controller.state.status,'unknown');assert.equal(controller.state.data,null);assert.equal(controller.canSave.value,false)
})
test('Owner draft discovery and save use actual purpose, CAS basis and mandatory independent full-field readback',async()=>{
  let current=creator(),writes=0;const calls:{body:any;headers:Record<string,string>}[]=[]
  const api=new WorkbenchApi({enabled:true,origin,fetchImpl:async(url,init)=>{if(url.endsWith('/session'))return response(session);const body=JSON.parse(String(init.body));calls.push({body,headers:init.headers as Record<string,string>});if(body.action==='save_creator_draft'){writes++;assert.equal(body.input.expected_draft_digest,current.draft_digest);assert.equal(body.input.expected_graph_revision,1);current=creator(body.input.fields,2,'d'.repeat(64),2);return response({status:'ready',receipt:{schema:'d12.creator-draft-save.v1',operation_id:body.operation_id,draft_ref:current.draft_ref,draft_revision:2,draft_digest:current.draft_digest,graph_revision:2,access_epoch:1,delete_epoch:1,changed_fields:['d09.expression_policy'],status:'draft_saved_not_adopted'}})}return response({status:'ready',projection:current})}})
  const controller=createCreatorConfiguration(api,()=>true,()=>scope,()=>{});await controller.read();controller.setField('d09.expression_policy',{schema:'test-d09',version:2});await controller.save()
  assert.equal(writes,1);assert.equal(calls.length,3);assert.ok(calls.every(call=>call.body.purpose==='workbench_user_action'&&call.body.audience==='owner'&&call.body.scope===scope));assert.ok(calls.every(call=>call.headers['x-csrf-token']==='synthetic-owner-csrf'&&call.headers['X-Sylanne-Configuration-CSRF']===undefined));assert.equal(controller.state.status,'saved_not_adopted');assert.equal(controller.state.adopted,null)
})
test('Creator permissions, server budget and current head govern actions; eleven editable fields never imply eleven adopted domains',async()=>{
  for(const patch of [{action_permissions:{save:false,compile:false,preview:false,activate:false}},{budget_ref:null},{active_head_revision:0,active_head_ref:null},{fields:{'d01.persona_plan':{version:1}},field_sources:{'d01.persona_plan':'actual-source'}}]){
    const snapshot={...creator(),...patch};const api=new WorkbenchApi({enabled:true,origin,fetchImpl:async url=>response(url.endsWith('/session')?session:{status:'ready',projection:snapshot})});const controller=createCreatorConfiguration(api,()=>true,()=>scope,()=>{});await controller.read();assert.equal(controller.canPreview.value,false);assert.equal(controller.canActivate.value,false);if('budget_ref'in patch||'action_permissions'in patch)assert.equal(controller.canCompile.value,false)
  }
  assert.throws(()=>validateCreatorConfiguration({...creator(),supported_fields:creator().supported_fields.map(row=>row.path==='d04.authored_root'?{...row,editable:true}:row)}))
})
test('Creator conflict and late scope changes cannot overwrite or resurrect a private configuration',async()=>{
  const currentScope=ref(scope),late=deferred<FetchResponse>();let write=false
  const api=new WorkbenchApi({enabled:true,origin,fetchImpl:async(url,init)=>{if(url.endsWith('/session'))return response(session);const body=JSON.parse(String(init.body));if(body.action==='save_creator_draft')return response({status:'stale',problem:{code:'draft_current_basis_changed',retryable:false}});return write?late.promise:response({status:'ready',projection:creator()})}}),controller=createCreatorConfiguration(api,()=>true,()=>currentScope.value,()=>{})
  await controller.read();controller.setField('d09.expression_policy',{version:2});await controller.save();assert.equal(controller.state.status,'conflict');assert.equal(controller.canSave.value,false)
  write=true;const pending=controller.read();await tick();currentScope.value='other/persona';controller.invalidate();late.resolve(response({status:'ready',projection:creator()}));await pending;assert.equal(controller.state.data,null);assert.equal(controller.canEdit.value,false)
})
test('browser display alias uses only the real preference key and is a shared consumed display ref, not domain state',()=>{
  const original=Object.getOwnPropertyDescriptor(globalThis,'window'),writes:{key:string;value:string}[]=[]
  Object.defineProperty(globalThis,'window',{configurable:true,value:{localStorage:{getItem:()=>null,setItem:(key:string,value:string)=>writes.push({key,value})}}})
  try{const settings=useDisplayAlias(),consumer=useDisplayAlias();settings.set('Local desk');assert.equal(consumer.alias.value,'Local desk');assert.deepEqual(writes,[{key:'2718lab.display-alias',value:'Local desk'}])}finally{if(original)Object.defineProperty(globalThis,'window',original);else Reflect.deleteProperty(globalThis,'window')}
})
test('Creator discovery rejects untrusted action permissions and template fields, while registered domain input returns only safe receipt metadata',async()=>{
  const base=creator()
  for(const bad of [{...base,action_permissions:{...base.action_permissions,extra:true}},{...base,field_templates:{...base.field_templates,'d04.authored_root':{calibrated:true}}},{...base,field_templates:{...base.field_templates,'d09.expression_policy':'arbitrary prompt'}},{...base,fields:{...base.fields,raw_owner_id:'not-a-setting'}}])assert.throws(()=>validateCreatorConfiguration(bad))
  const api=new WorkbenchApi({enabled:true,origin,fetchImpl:async(url,init)=>{if(url.endsWith('/session'))return response(session);const body=JSON.parse(String(init.body));return response({status:'ready',receipt:{schema:'d12.domain-operation-receipt.v1',operation_id:body.operation_id,action:body.action,input_digest:'a'.repeat(64),original_digest:'b'.repeat(64),original:{operation_id:body.operation_id,private_provenance:'synthetic-not-for-ui'}}})}})
  const result=await api.domainInput('domain_input_install_relationship_policy',scope,{activity_id:'actual-activity',audience_ref:'actual-audience',parent_budget_lease_ref:'actual-budget',request:{policy:{version:1}}},crypto.randomUUID())
  assert.equal('original'in result,false);assert.equal(JSON.stringify(result).includes('private_provenance'),false)
})
test('explicit D09 compile preview adopt uses actual receipt identities and independently reads the adopted head',async()=>{
  let current=creator();const actions:string[]=[],api=new WorkbenchApi({enabled:true,origin,fetchImpl:async(url,init)=>{
    if(url.endsWith('/session'))return response(session)
    const body=JSON.parse(String(init.body));actions.push(body.action)
    if(body.action==='compile_scheme')return response({status:'ready',receipt:{operation_id:body.operation_id,phase:'compiled_candidate_recorded',compiled_digest:'e'.repeat(64),draft_ref:current.draft_ref,draft_revision:1,graph_revision:1,source_input_digest:'f'.repeat(64),budget_receipt_digest:'a'.repeat(64)}})
    if(body.action==='preview_scheme')return response({status:'ready',receipt:{operation_id:body.operation_id,phase:'isolated_preview_recorded',compiled_digest:'e'.repeat(64),preview_seal:'b'.repeat(64),isolation_result_digest:'a'.repeat(64),actual_cost_receipt_ref:'synthetic-cost-locator'}})
    if(body.action==='activate_scheme'){current={...current,active_head_revision:2,graph_revision:2};return response({status:'ready',receipt:{operation_id:body.operation_id,phase:'scheme_adopted',compiled_digest:'e'.repeat(64),previous_head_revision:1,active_head_ref:current.active_head_ref,active_head_revision:2,graph_revision:2}})}
    return response({status:'ready',projection:current})
  }}),controller=createCreatorConfiguration(api,()=>true,()=>scope,()=>{})
  await controller.read();assert.equal(controller.canCompile.value,true);await controller.compile();assert.equal(controller.state.adopted,null);assert.equal(controller.canPreview.value,true)
  await controller.preview();assert.equal(controller.state.adopted,null);assert.equal(controller.canActivate.value,true);await controller.activate();assert.equal(controller.state.adopted?.active_head_revision,2)
  assert.deepEqual(actions,['read_configuration_draft','compile_scheme','preview_scheme','activate_scheme','read_configuration_draft'])
})
test('unknown Owner save outcome retains a stable operation id and cannot automatically submit again',async()=>{
  let writes=0
  const api=new WorkbenchApi({enabled:true,origin,fetchImpl:async(url,init)=>{if(url.endsWith('/session'))return response(session);const body=JSON.parse(String(init.body));if(body.action==='save_creator_draft'){writes++;return response({status:'unavailable',problem:{code:'unknown_outcome',retryable:false}},503)}return response({status:'ready',projection:creator()})}}),controller=createCreatorConfiguration(api,()=>true,()=>scope,()=>{})
  await controller.read();controller.setField('d09.expression_policy',{version:2});await controller.save();const operation=controller.state.operationId
  assert.equal(controller.state.status,'unknown');assert.ok(operation);await controller.save();assert.equal(writes,1);assert.equal(controller.state.operationId,operation)
})
test('navigation hidden logout and unmount invalidate both Host and private Creator observations before late responses',async()=>{
  for(const action of ['navigation','hidden','logout','unmount'] as const){
    const descriptors=['document','window'].map(key=>[key,Object.getOwnPropertyDescriptor(globalThis,key)] as const),listeners=new Map<string,Function>(),events={hidden:false,addEventListener(name:string,fn:Function){listeners.set(name,fn)},removeEventListener(name:string){listeners.delete(name)}}
    Object.defineProperty(globalThis,'document',{configurable:true,value:events});Object.defineProperty(globalThis,'window',{configurable:true,value:events})
    const lateConfig=deferred<FetchResponse>(),lateCreator=deferred<FetchResponse>(),signals:AbortSignal[]=[];let backend!:BackendController,stopped=false
    const renderer=createRenderer<any,any>({createElement:type=>({type,children:[]}),createText:text=>({text}),createComment:text=>({text}),setText(){},setElementText(){},parentNode:node=>node.parent,nextSibling:()=>null,insert(node,parent){node.parent=parent;parent.children.push(node)},remove(){},patchProp(){}})
    const app=renderer.createApp({setup(){backend=useBackend({enabled:true,origin,fetchImpl:async(url,init)=>{if(url.endsWith('/session'))return response(session);if(url.endsWith('/owner/logout'))return response({status:'ok',owner_session:'locked'});signals.push(init.signal!);return url.endsWith('/configuration/v1')?lateConfig.promise:lateCreator.promise}});return()=>h('div')}})
    try{app.mount({children:[]});await backend.checkSession();backend.setScope(scope);const host=backend.configuration.read(),privateRead=backend.creator.read();await tick();if(action==='navigation')backend.invalidateNavigation();else if(action==='hidden'){events.hidden=true;listeners.get('visibilitychange')!()}else if(action==='logout')await backend.logout();else{app.unmount();stopped=true};assert.equal(signals.length,2);assert.ok(signals.every(signal=>signal.aborted));lateConfig.resolve(response(wire()));lateCreator.resolve(response({status:'ready',projection:creator()}));await Promise.all([host,privateRead]);assert.equal(backend.configuration.state.data,null);assert.equal(backend.creator.state.data,null);assert.equal(backend.configuration.canSave.value,false);assert.equal(backend.creator.canSave.value,false)}
    finally{lateConfig.resolve(response(wire()));lateCreator.resolve(response({status:'ready',projection:creator()}));if(!stopped)app.unmount();await nextTick();for(const[key,descriptor]of descriptors){if(descriptor)Object.defineProperty(globalThis,key,descriptor);else Reflect.deleteProperty(globalThis,key)}}
  }
})
test('real missing draft head remains null and ordinary save preserves but never submits a dedicated authored Root',()=>{
  const missing={...creator(),exists:false,draft_revision:0,draft_digest:null,fields:{},field_sources:{},active_head_ref:null,active_head_revision:0}
  assert.equal(validateCreatorConfiguration(missing).active_head_ref,null)
  const root={candidate_id:'synthetic-readonly-root'},current=creator({'d09.expression_policy':{version:1},'d04.authored_root':root}),target={...current.fields,'d09.expression_policy':{version:2}}
  const payload=draftSaveInput(current,target);assert.deepEqual(Object.keys(payload.fields),['d09.expression_policy']);assert.deepEqual(target['d04.authored_root'],root)
  assert.throws(()=>draftSaveInput(current,{...target,'d04.authored_root':{candidate_id:'untrusted-edit'}}))
})
async function component(name:string):Promise<any>{
  const filename=new URL(`./${name}.vue`,import.meta.url),source=await readFile(filename,'utf8'),{descriptor}=parse(source,{filename:filename.pathname})
  const compiled=compileScript(descriptor,{id:name,inlineTemplate:true,templateOptions:{compilerOptions:{hoistStatic:false}}})
  const javascript=ts.transpileModule(compiled.content,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText
  const modules:Record<string,any>={vue:Vue}
  for(const match of javascript.matchAll(/^import\s+.+?\s+from\s+['"]([^'"]+)['"];?\s*$/gm)){const path=match[1]!;if(path!=='vue')modules[path]=path.endsWith('.vue')?{default:await component(path.slice(2,-4))}:await import(new URL(path,filename).href)}
  const injected=javascript.replace(/^import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"];?\s*$/gm,(_match,names,path)=>`const {${names.replace(/\bas\b/g,':')}}=Modules[${JSON.stringify(path)}];`).replace(/^import\s+(\w+)\s+from\s+['"]([^'"]+)['"];?\s*$/gm,(_match,name,path)=>`const ${name}=Modules[${JSON.stringify(path)}].default;`).replace('export default ','return ')
  return new Function('Modules',injected)(modules)
}
test('actual advanced Vue panel exposes seven groups, real SDK model options, explicit Chinese typed examples and consumed preferences without automatic requests',async()=>{
  const Panel=await component('ConfigurationPanel'),descriptors=['document','window','Document','ShadowRoot'].map(key=>[key,Object.getOwnPropertyDescriptor(globalThis,key)] as const)
  class DocumentStub{hidden=false;activeElement=null;addEventListener(){}removeEventListener(){}}
  const events=new DocumentStub()
  Object.defineProperty(globalThis,'Document',{configurable:true,value:DocumentStub});Object.defineProperty(globalThis,'ShadowRoot',{configurable:true,value:class{}})
  Object.defineProperty(globalThis,'document',{configurable:true,value:events});Object.defineProperty(globalThis,'window',{configurable:true,value:{addEventListener:events.addEventListener,removeEventListener:events.removeEventListener,localStorage:{getItem:()=>null,setItem(){}}}})
  type Node={type:string;text:string;children:Node[];parent:Node|null;props:Record<string,any>;tagName:string;listeners:Record<string,Function>;getRootNode:()=>typeof events;addEventListener:(name:string,fn:Function)=>void;removeEventListener:(name:string)=>void;setAttribute:(name:string,value:unknown)=>void;removeAttribute:(name:string)=>void}
  const make=(type:string,text=''):Node=>({type,text,children:[],parent:null,props:{},tagName:type.toUpperCase(),listeners:{},getRootNode:()=>events,addEventListener(name,fn){this.listeners[name]=fn},removeEventListener(name){delete this.listeners[name]},setAttribute(name,value){this.props[name]=value},removeAttribute(name){delete this.props[name]}})
  const renderer=createRenderer<Node,Node>({createElement:type=>make(type),createText:text=>make('text',text),createComment:text=>make('comment',text),setText:(node,text)=>{node.text=text},setElementText:(node,text)=>{node.text=text;node.children=[]},parentNode:node=>node.parent,nextSibling:node=>node.parent?.children[node.parent.children.indexOf(node)+1]??null,insert(node,parent,anchor=null){if(node.parent)this.remove(node);node.parent=parent;const index=anchor?parent.children.indexOf(anchor):-1;if(index<0)parent.children.push(node);else parent.children.splice(index,0,node)},remove(node){if(node.parent){const index=node.parent.children.indexOf(node);if(index>=0)node.parent.children.splice(index,1);node.parent=null}},patchProp(node,key,_old,value){node.props[key]=value}})
  const root=make('root');let backend!:BackendController,calls=0
  const app=renderer.createApp({setup(){backend=useBackend({enabled:true,origin,fetchImpl:async(url,init)=>{calls++;if(url.endsWith('/session'))return response(session);if(url.endsWith('/configuration/v1'))return response(wire());return response({status:'ready',projection:creator()})}});return()=>h(Panel,{backend})}})
  const renderErrors:unknown[]=[];app.config.errorHandler=error=>{renderErrors.push(error)}
  const text=(node:Node):string=>node.text+node.children.filter(child=>child.type!=='comment').map(text).join('')
  const find=(node:Node,predicate:(node:Node)=>boolean):Node|undefined=>{if(predicate(node))return node;for(const child of node.children){const found=find(child,predicate);if(found)return found}}
  const button=(label:string)=>{const node=find(root,node=>node.type==='button'&&text(node)===label);assert.ok(node,`missing ${label}`);return node}
  try{
    app.mount(root);await nextTick();assert.equal(calls,0);for(const label of ['基本','模型策略','角色与场景','注意与表达','记忆与关系','Life 与联系','资源与安装'])assert.ok(button(label))
    await button('读取当前配置').props.onClick();await nextTick();await button('模型策略').props.onClick();await nextTick();assert.match(text(root),/provider-a · model-a/);assert.match(text(root),/provider-b · model-b/);assert.match(text(root),/与已安装模型身份匹配/);assert.match(text(root),/model_unselected/)
    await backend.checkSession();backend.setScope(scope);await button('角色与场景').props.onClick();await nextTick();await backend.creator.read();await nextTick();assert.match(text(root),/人格方案|身体方案|场景方案/)
    const before=JSON.stringify(backend.creator.state.draft),readsBefore=calls;await button('从结构示例开始').props.onClick();await nextTick();assert.notEqual(JSON.stringify(backend.creator.state.draft),before);assert.equal(calls,readsBefore);assert.equal(backend.creator.state.adopted,null);assert.match(text(root),/不是当前配置、校准结果或已采纳方案/)
    await button('基本').props.onClick();await nextTick();assert.match(text(root),/不是 D01 人格名称/);assert.deepEqual(renderErrors,[])
  }finally{app.unmount();await nextTick();for(const[key,descriptor]of descriptors){if(descriptor)Object.defineProperty(globalThis,key,descriptor);else Reflect.deleteProperty(globalThis,key)}}
})

test('configuration V4 installation keeps actual slot identities and future versions remain rejected',async()=>{
  const fixture=wire(),version4={...fixture,installed_policy:{...fixture.installed_policy,workflow_version:4}}
  const api=new ConfigurationApi({enabled:true,origin,fetchImpl:async()=>response(version4)})
  const observed=await api.read()
  assert.equal(observed.installed_policy.workflow_version,4)
  assert.deepEqual(observed.installed_policy.configured_model_slots,['reply','encode'])
  assert.equal(observed.model_slots.find(row=>row.slot==='encode')?.installed?.provider_config_digest,'a'.repeat(64))
  assert.throws(()=>validateConfigurationWire({...version4,installed_policy:{...version4.installed_policy,workflow_version:5}}),{code:'invalid_response'})
  assert.throws(()=>validateConfigurationWire({...version4,model_slots:version4.model_slots.map(row=>row.slot==='reply'?{...row,provider_config_digest:'b'.repeat(64)}:row)}),{code:'invalid_response'})
})

test('configuration V5 appends the actual relationship slot without changing legacy override keys',async()=>{
  const current=values();current.model_selection.auxiliary_provider_id='provider-b'
  const base=wire(current),relationship={slot:'d07_relationship_cognition',selected_provider_id:'provider-b',model_id:'model-b',provider_config_digest:'b'.repeat(64),
    installed:{provider_id:'provider-b',model_id:'model-b',provider_config_digest:'b'.repeat(64),max_output_tokens:1024},state:'installed',reason_code:'none'}
  const version5={...base,model_slots:[...base.model_slots,relationship],installed_policy:{...base.installed_policy,workflow_version:5,
    configured_model_slots:[...base.installed_policy.configured_model_slots,'d07_relationship_cognition'],limits:{...base.installed_policy.limits,d07_relationship_cognition:1024}}}
  const api=new ConfigurationApi({enabled:true,origin,fetchImpl:async()=>response(version5)})
  const observed=await api.read()
  assert.equal(observed.installed_policy.workflow_version,5)
  assert.equal(observed.model_slots.at(-1)?.slot,'d07_relationship_cognition')
  assert.equal(observed.model_slots.at(-1)?.installed?.provider_id,'provider-b')
  assert.deepEqual(Object.keys(observed.values.model_selection.overrides),[...OPTIONAL_MODEL_SLOTS])
  assert.equal('d07_relationship_cognition'in observed.values.model_selection.overrides,false)
  assert.throws(()=>validateConfigurationWire({...version5,installed_policy:{...version5.installed_policy,workflow_version:4}}),{code:'invalid_response'})
  assert.throws(()=>validateConfigurationWire({...version5,model_slots:base.model_slots}),{code:'invalid_response'})
  assert.throws(()=>validateConfigurationWire({...version5,model_slots:[...base.model_slots,{...relationship,provider_config_digest:'a'.repeat(64)}]}),{code:'invalid_response'})
})


test('configuration V6 preserves eleven legacy rows and ten overrides while appending exact relation and growth observations',()=>{
  const base=wire(),named=(slot:string)=>({slot,selected_provider_id:null,model_id:null,provider_config_digest:null,installed:null,state:'pending',reason_code:'model_unselected'})
  const current={...base,model_slots:[...base.model_slots,named('d07_relationship_cognition'),named('growth_cognition')],
    installed_policy:{...base.installed_policy,workflow_version:6}}
  const decoded=validateConfigurationWire(current)
  assert.equal(decoded.model_slots.length,13);assert.deepEqual(decoded.model_slots.slice(0,11).map(row=>row.slot),[...MODEL_SLOTS])
  assert.deepEqual(decoded.model_slots.slice(11).map(row=>row.slot),['d07_relationship_cognition','growth_cognition'])
  assert.equal(Object.keys(decoded.values.model_selection.overrides).length,10);assert.equal(decoded.model_slots.at(-1)?.state,'pending')
  assert.throws(()=>validateConfigurationWire({...current,model_slots:current.model_slots.slice(0,12)}),{code:'invalid_response'})
  assert.throws(()=>validateConfigurationWire({...current,model_slots:[...base.model_slots,named('growth_cognition'),named('d07_relationship_cognition')]}),{code:'invalid_response'})
  assert.throws(()=>validateConfigurationWire({...current,installed_policy:{...current.installed_policy,workflow_version:5}}),{code:'invalid_response'})
  assert.throws(()=>validateConfigurationWire({...current,values:{...base.values,model_selection:{...base.values.model_selection,overrides:{...base.values.model_selection.overrides,growth_cognition:''}}}}),{code:'invalid_response'})
})
