import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRenderer, h } from 'vue'
import * as Vue from 'vue'
import { renderToString } from '@vue/server-renderer'
import { parse, compileScript } from '@vue/compiler-sfc'
import ts from 'typescript'
import { readFile } from 'node:fs/promises'
import { WorkbenchApi, type FetchLike, type FetchResponse } from './api/client.ts'
import { useBackend, type BackendController } from './use-backend.ts'

const origin = 'https://setup-test.invalid'
const plan = { schema: 'sylanne.host-model-selection.v1', authority_profile: 'default', provider_id: 'actual-provider', model_id: 'actual-model', provider_config_digest: 'a'.repeat(64) }
const snapshot = { schema_version: 'sylanne.workbench-setup-status.v1', profile_id: 'default', host_enabled: true, authority_enabled: true, effective_enabled: true,
  model_selection: { provider_id: 'actual-provider', model_id: 'actual-model', state: 'authorized' }, runtime: { stage: 'limited', reason_codes: ['active_role'] },
  installer: { supported: true, mode: 'fresh_install_only', requires_administrator: true }, model_plan: plan }
const session = { status: 'ready', dashboard_session: 'authenticated', owner_session: 'unlocked', csrf_token: 'synthetic-session-only' }
function response(body: unknown, status = 200): FetchResponse { return { ok: status >= 200 && status < 300, status, json: async () => body } }
const tick = () => new Promise(done => setTimeout(done, 0))
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done }); return { promise, resolve } }
function client(fetchImpl: FetchLike, enabled = true) { return new WorkbenchApi({enabled, origin, fetchImpl}) }
async function mounted(fetchImpl: FetchLike) {
  const descriptors = ['document', 'window'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)] as const), listeners = new Map<string, Function>()
  const events = { hidden: false, addEventListener(name: string, fn: Function) { listeners.set(name, fn) }, removeEventListener(name: string) { listeners.delete(name) } }
  for (const [key] of descriptors) Object.defineProperty(globalThis, key, {configurable:true,value:events})
  let backend!: BackendController
  const renderer = createRenderer<any, any>({createElement:type=>({type,children:[]}),createText:text=>({text}),createComment:text=>({text}),setText(){},setElementText(){},parentNode:node=>node.parent,nextSibling:()=>null,insert(node,parent){node.parent=parent;parent.children.push(node)},remove(){},patchProp(){}})
  const app = renderer.createApp({setup(){backend=useBackend({enabled:true,origin,fetchImpl});return()=>h('div')}})
  app.mount({children:[]})
  return {backend,events,listeners,stop(){app.unmount();for(const [key,descriptor] of descriptors){if(descriptor)Object.defineProperty(globalThis,key,descriptor);else Reflect.deleteProperty(globalThis,key)}}}
}
test('setup is an explicit same-origin Dashboard GET and never establishes Owner or D12 authorization', async () => {
  const calls: {url:string;init:RequestInit}[] = []
  const m = await mounted(async (url,init) => {calls.push({url,init});return response(snapshot)})
  try {
    assert.equal(typeof m.backend.setup, 'object'); assert.equal(calls.length,0)
    await m.backend.setup.read(); assert.equal(calls.length,1)
    assert.ok(calls[0]!.url.endsWith('/workbench/v1/setup/v1/status')); assert.equal(calls[0]!.init.method,'GET')
    assert.equal(calls[0]!.init.credentials,'same-origin'); assert.equal(calls[0]!.init.mode,'same-origin'); assert.equal(calls[0]!.init.cache,'no-store')
    assert.equal(calls[0]!.init.body,undefined); assert.equal((calls[0]!.init.headers as Record<string,string>)['x-csrf-token'],undefined)
    assert.equal(m.backend.state.auth,'locked'); assert.equal(m.backend.state.owner,'unknown'); assert.equal(m.backend.canRead.value,false); assert.equal(m.backend.management.canDiscover.value,false)
    assert.equal(m.backend.setup.state.data?.model_selection.model_id,'actual-model')
  } finally {m.stop()}
})
test('setup exact fields, safe model plan binding and Host AND Authority enablement reject incompatible responses', async () => {
  assert.equal(typeof client(async()=>response(snapshot)).setupStatus,'function')
  const invalids = [
    {...snapshot,schema_version:'future'}, {...snapshot,private_path:'canary-private'}, {...snapshot,effective_enabled:false},
    {...snapshot,authority_enabled:null,effective_enabled:true}, {...snapshot,model_selection:{...snapshot.model_selection,key:'canary-secret'}},
    {...snapshot,model_plan:{...plan,token:'canary-secret'}}, {...snapshot,model_plan:{...plan,provider_config_digest:'sha256:'+plan.provider_config_digest}},
    {...snapshot,model_plan:{...plan,provider_id:'different'}}, {...snapshot,model_plan:{...plan,authority_profile:'different'}},
    {...snapshot,runtime:{...snapshot.runtime,reason_codes:Array(17).fill('safe')}}, {...snapshot,installer:{...snapshot.installer,mode:'upgrade'}},
    {...snapshot,model_selection:{provider_id:null,model_id:null,state:'unselected'}}, {...snapshot,model_plan:null},
  ]
  for (const body of invalids) await assert.rejects(client(async()=>response(body)).setupStatus(), {code:'invalid_response'})
  const stopped = {...snapshot,host_enabled:false,effective_enabled:false}
  assert.deepEqual(await client(async()=>response(stopped)).setupStatus(),stopped)
})
test('setup offline does not fetch, repeated GETs coalesce, and malformed errors never echo raw diagnostics', async () => {
  let count=0; const offline=client(async()=>{count++;return response(snapshot)},false)
  assert.equal(typeof offline.setupStatus,'function'); await assert.rejects(offline.setupStatus(),{code:'offline'}); assert.equal(count,0)
  const late=deferred<FetchResponse>(), api=client(async()=>{count++;return late.promise})
  const a=api.setupStatus(), b=api.setupStatus(); assert.equal(a,b); assert.equal(count,1); late.resolve(response(snapshot)); await a
  const failed=client(async()=>response({schema_version:'sylanne.workbench-error.v1',problem:{code:'setup_unavailable',retryable:true,raw:'canary-secret'}},503))
  await assert.rejects(failed.setupStatus(),e=>e instanceof Error && !e.message.includes('canary-secret') && (e as any).code==='invalid_response')
})
test('safe setup export contains exactly the five observed model plan fields and requires a current observation', async () => {
  const m=await mounted(async()=>response(snapshot))
  try {
    assert.equal(typeof m.backend.setup,'object'); assert.equal(m.backend.setup.exportPlan(),null)
    await m.backend.setup.read(); const exported=m.backend.setup.exportPlan(); assert.ok(exported)
    assert.deepEqual(JSON.parse(exported),plan); assert.deepEqual(Object.keys(JSON.parse(exported)).sort(),['schema','authority_profile','provider_id','model_id','provider_config_digest'].sort())
    m.backend.setup.invalidate(); assert.equal(m.backend.setup.exportPlan(),null); assert.equal(m.backend.setup.canExport.value,false)
  } finally {m.stop()}
})
test('setup HTTP 401 purges observations and existing Owner identity without replaying a request', async () => {
  let rejected=false, setupCalls=0
  const m=await mounted(async url=>url.endsWith('/session')?response(session):(setupCalls++,response(rejected?{status:'unauthorized',problem:{code:'host_session_missing',retryable:false}}:snapshot,rejected?401:200)))
  try {
    assert.equal(typeof m.backend.setup,'object'); await m.backend.checkSession(); await m.backend.setup.read(); assert.ok(m.backend.setup.state.data)
    rejected=true; await m.backend.setup.read(); assert.equal(setupCalls,2); assert.equal(m.backend.setup.state.data,null); assert.equal(m.backend.state.auth,'locked'); assert.equal(m.backend.setup.exportPlan(),null)
  } finally {m.stop()}
})
for (const action of ['navigation','scope','logout','hidden','pagehide','popstate','unmount'] as const) test(`setup ${action} invalidates a pending observation and its late model plan`, async()=>{
  const late=deferred<FetchResponse>(); let signal:AbortSignal|null|undefined
  const m=await mounted(async (url,init)=>{if(url.endsWith('/owner/logout'))return response({status:'ok',owner_session:'locked'});signal=init.signal;return late.promise})
  let stopped=false
  try {
    assert.equal(typeof m.backend.setup,'object'); const pending=m.backend.setup.read(); await tick()
    if(action==='navigation')m.backend.invalidateNavigation()
    else if(action==='scope')m.backend.setScope('other/persona')
    else if(action==='logout')await m.backend.logout()
    else if(action==='hidden'){m.events.hidden=true;m.listeners.get('visibilitychange')!()}
    else if(action==='unmount'){m.stop();stopped=true}
    else m.listeners.get(action)!()
    assert.equal(signal?.aborted,true); late.resolve(response(snapshot)); await pending
    assert.equal(m.backend.setup.state.data,null); assert.equal(m.backend.setup.exportPlan(),null); assert.equal(m.backend.canRead.value,false)
  } finally {late.resolve(response(snapshot));if(!stopped)m.stop()}
})
async function setupComponent() {
  const filename=new URL('./SetupPanel.vue',import.meta.url), source=await readFile(filename,'utf8')
  const {descriptor}=parse(source,{filename:filename.pathname})
  const compiled=compileScript(descriptor,{id:'SetupPanel',inlineTemplate:true})
  const javascript=ts.transpileModule(compiled.content,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText
    .replace(/^import\s+\{([^}]+)\}\s+from\s+['"]vue['"];?\s*$/gm,(_match,names)=>`const {${names.replace(/\bas\b/g,':')}}=VueRuntime;`)
    .replace('export default ','return ')
  return new Function('VueRuntime',javascript)(Vue)
}
test('actual setup component renders native provider-selector steps and observed fields without a key form or authorization claim', async()=>{
  const component=await setupComponent()
  let calls=0
  const m=await mounted(async()=>{calls++;return response({...snapshot,host_enabled:false,effective_enabled:false})})
  try{
    const initial=await renderToString(Vue.createSSRApp({render:()=>h(component,{backend:m.backend})}))
    assert.equal(calls,0); assert.match(initial,/安装配置与模型|llm_provider_id/); assert.match(initial,/未入驻|尚未入驻/)
    await m.backend.setup.read()
    const html=await renderToString(Vue.createSSRApp({render:()=>h(component,{backend:m.backend})}))
    assert.match(html,/actual-provider/); assert.match(html,/actual-model/); assert.match(html,/未启用（false）/); assert.match(html,/已许可（true）/)
    assert.match(html,/尚未同时满足启用条件/); assert.match(html,/--model-selection/); assert.match(html,/llm-selection.json/)
    assert.match(html,/与安装主模型一致；请求仍需当前授权/); assert.match(html,/本次启动 Authority 许可/); assert.match(html,/next_restart/)
    assert.match(html,/匹配状态不授予 Owner/); assert.doesNotMatch(html,/<input|<select|<textarea/)
    assert.equal(m.backend.state.auth,'locked'); assert.equal(m.backend.management.canDiscover.value,false)
  }finally{m.stop()}
})
test('model metadata or registry change without a safe plan is displayed normally and cannot be exported',async()=>{
  const changed={...snapshot,model_selection:{provider_id:'actual-provider',model_id:'sdk-observed-model',state:'changed'},model_plan:null,runtime:{stage:'blocked',reason_codes:['provider_model_metadata_changed']}}
  const m=await mounted(async()=>response(changed))
  try{
    await m.backend.setup.read()
    assert.equal(m.backend.setup.state.status,'ready');assert.equal(m.backend.setup.state.data?.model_selection.state,'changed')
    assert.equal(m.backend.setup.canExport.value,false);assert.equal(m.backend.setup.exportPlan(),null)
    assert.equal(m.backend.state.auth,'locked');assert.equal(m.backend.canRead.value,false);assert.equal(m.backend.management.canDiscover.value,false)
    const component=await setupComponent(), html=await renderToString(Vue.createSSRApp({render:()=>h(component,{backend:m.backend})}))
    assert.match(html,/当前模型或配置已变更，需要重新安装绑定/);assert.match(html,/provider_model_metadata_changed/);assert.match(html,/sdk-observed-model/)
    assert.match(html,/<button[^>]*disabled[^>]*>导出 llm-selection\.json<\/button>/)
  }finally{m.stop()}
})
test('setup returns each real selection state without fabricating a plan, and bounds actual HTTP response bytes',async()=>{
  for(const state of ['unselected','unavailable','unsupported','changed','awaiting_installation','authorized'] as const){
    const observed=['changed','awaiting_installation','authorized'].includes(state)
    const body={...snapshot,model_selection:{provider_id:state==='unselected'?null:'actual-provider',model_id:observed?'actual-model':null,state},model_plan:observed?plan:null}
    assert.deepEqual(await client(async()=>response(body)).setupStatus(),body)
  }
  await assert.rejects(client(async()=>new Response(JSON.stringify(snapshot)+' '.repeat(16*1024))).setupStatus(),{code:'invalid_response'})
})
