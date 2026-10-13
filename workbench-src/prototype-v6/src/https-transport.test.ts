import {test} from 'node:test'
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import * as Vue from 'vue'
import {renderToString} from '@vue/server-renderer'
import {parse,compileScript} from '@vue/compiler-sfc'
import ts from 'typescript'
import {WorkbenchApi,HTTPS_REQUIRED_MESSAGE,type FetchResponse} from './api/client.ts'
import {ConfigurationApi,MODEL_SLOTS,OPTIONAL_MODEL_SLOTS,type ConfigurationValues} from './api/configuration.ts'
import {useBackend,type BackendController} from './use-backend.ts'

const origin='https://transport-test.invalid',scope='test-bot/test-persona'
const session={status:'ready',dashboard_session:'authenticated',owner_session:'unlocked',csrf_token:'synthetic-only-session-csrf'}
function response(body:unknown,status=200):FetchResponse{return{ok:status>=200&&status<300,status,json:async()=>body}}
const values=():ConfigurationValues=>({enabled:false,authority_profile:'default',llm_provider_id:'',model_selection:{version:1,auxiliary_provider_id:'',overrides:Object.fromEntries(OPTIONAL_MODEL_SLOTS.map(slot=>[slot,''])) as ConfigurationValues['model_selection']['overrides']}})
function configuration(){return{schema_version:'sylanne.webui-configuration.v1',revision:1,csrf_token:'synthetic-only-config-csrf',values:values(),startup_values:values(),writable_fields:['enabled','authority_profile','llm_provider_id','model_selection'],apply_semantics:'next_reload',model_slots:MODEL_SLOTS.map(slot=>({slot,selected_provider_id:null,model_id:null,provider_config_digest:null,installed:null,state:'pending',reason_code:'model_unselected'})),installed_policy:{profile_id:null,installation_id:null,workflow_version:null,configured_model_slots:[],limits:{},provider_options:[]}}}
async function component(name:string):Promise<any>{
  const filename=new URL(`./${name}.vue`,import.meta.url),source=await readFile(filename,'utf8'),{descriptor}=parse(source,{filename:filename.pathname})
  const compiled=compileScript(descriptor,{id:name,inlineTemplate:true,templateOptions:{compilerOptions:{hoistStatic:false}}})
  const javascript=ts.transpileModule(compiled.content,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText
  const modules:Record<string,any>={vue:Vue}
  for(const match of javascript.matchAll(/^import\s+.+?\s+from\s+['"]([^'"]+)['"];?\s*$/gm)){const path=match[1]!;if(path!=='vue')modules[path]=path.endsWith('.vue')?{default:await component(path.slice(2,-4))}:await import(new URL(path,filename).href)}
  const injected=javascript.replace(/^import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"];?\s*$/gm,(_match,names,path)=>`const {${names.replace(/\bas\b/g,':')}}=Modules[${JSON.stringify(path)}];`).replace(/^import\s+(\w+)\s+from\s+['"]([^'"]+)['"];?\s*$/gm,(_match,name,path)=>`const ${name}=Modules[${JSON.stringify(path)}].default;`).replace('export default ','return ')
  return new Function('Modules',injected)(modules)
}
async function backend(apiOrigin:string,fetchImpl:any){let result!:BackendController;await renderToString(Vue.createSSRApp({setup(){result=useBackend({enabled:true,origin:apiOrigin,fetchImpl});return()=>Vue.h('div')}}));return result}

test('HTTP clients use real session/config protocol and keep independent CSRF',async()=>{
  const calls:RequestInit[]=[]
  const api=new WorkbenchApi({enabled:true,origin:'http://transport-test.invalid',fetchImpl:async(_url,init)=>{calls.push(init);return response(session)}})
  await api.openSession()
  assert.equal(api.hasSession,true);assert.equal(api.secureTransport,false);assert.equal(api.transportAvailable,true)
  const config=new ConfigurationApi({enabled:true,origin:'http://transport-test.invalid',fetchImpl:async(_url,init)=>{
    calls.push(init)
    if(init.method==='POST'){
      assert.equal((init.headers as Record<string,string>)['X-Sylanne-Configuration-CSRF'],'synthetic-only-config-csrf')
      const saved=configuration();saved.revision=2;saved.values.enabled=true;return response(saved)
    }
    return response(configuration())
  }})
  const before=await config.read(),saved=await config.update(before,{enabled:true})
  assert.equal(saved.revision,2);assert.equal(saved.values.enabled,true)
  assert.equal(config.secureTransport,false);assert.equal(config.transportAvailable,true)
  for(const init of calls){assert.equal(init.mode,'same-origin');assert.equal(init.credentials,'same-origin');assert.equal(init.referrerPolicy,'same-origin')}
})

test('actual page origin cannot be bypassed by another protocol argument; HTTPS retains its original flow',async()=>{
  let calls=0
  const api=new WorkbenchApi({enabled:true,origin,fetchImpl:async()=>{calls++;return response(session)}})
  const config=new ConfigurationApi({enabled:true,origin,fetchImpl:async()=>{calls++;return response(configuration())}})
  await api.openSession();const saved=await config.read();assert.equal(api.hasSession,true);assert.equal(saved.revision,1);assert.equal(calls,2)
  const old=Object.getOwnPropertyDescriptor(globalThis,'location')
  Object.defineProperty(globalThis,'location',{configurable:true,value:{origin:'http://transport-test.invalid',protocol:'http:'}})
  try{await assert.rejects(api.installationStatus(),{code:'origin_denied',status:403});await assert.rejects(config.update(saved,{enabled:true}),{code:'origin_denied',status:403});assert.equal(calls,2)}
  finally{if(old)Object.defineProperty(globalThis,'location',old);else delete(globalThis as any).location}
})

test('known flat and problem HTTPS refusals are transport errors, not lost authentication or permissive config errors',async()=>{
  for(const body of [{reason_code:'https_required'},{problem:{code:'https_required',retryable:false}}]){
    let calls=0
    const api=new WorkbenchApi({enabled:true,origin,fetchImpl:async()=>{calls++;return calls===1?response(session):response(body,403)}})
    await api.openSession();await assert.rejects(api.installationStatus(),{code:'https_required',status:403,retryable:false});assert.equal(api.hasSession,true)
    const config=new ConfigurationApi({enabled:true,origin,fetchImpl:async()=>response(body,403)})
    await assert.rejects(config.read(),{code:'https_required',status:403,retryable:false})
  }
  for(const body of [{reason_code:'csrf_invalid'},{reason_code:'https_required',extra:true},{input:{reason_code:'https_required'}}]){
    const config=new ConfigurationApi({enabled:true,origin,fetchImpl:async()=>response(body,403)})
    await assert.rejects(config.read(),{code:'invalid_response'})
  }
  const b=await backend(origin,async(url:string)=>url.endsWith('/session')?response(session):response({reason_code:'https_required'},403))
  assert.equal(await b.checkSession(),true);await b.setup.read()
  assert.equal(b.state.errorCode,'https_required');assert.equal(b.state.dashboard,'authenticated');assert.equal(b.state.owner,'unlocked');assert.equal(b.requiresHttps.value,true);assert.equal(b.configuration.canRead.value,false)
})

test('HTTP controller and actual Login SFC retain usable login and configuration controls',async()=>{
  let calls=0
  const b=await backend('http://transport-test.invalid',async()=>{calls++;return response(session)})
  assert.equal(b.state.auth,'locked');assert.equal(b.state.errorCode,'');assert.equal(b.requiresHttps.value,false)
  assert.equal(b.configuration.canRead.value,true);assert.equal(b.canSignedLogin.value,true)
  const old=Object.getOwnPropertyDescriptor(globalThis,'window')
  Object.defineProperty(globalThis,'window',{configurable:true,value:{location:{protocol:'http:',origin:'http://transport-test.invalid'}}})
  try{
    const panel=await component('LoginPanel'),html=await renderToString(Vue.createSSRApp({render:()=>Vue.h(panel,{backend:b,setupFirst:true})}))
    assert.match(html,/传输未加密/);assert.match(html,/可选 HTTPS \/ Docker 配置步骤/)
    assert.match(html,/登录当前后台/);assert.match(html,/读取当前配置/)
    assert.doesNotMatch(html,/<button[^>]*disabled[^>]*>读取当前配置/)
    assert.doesNotMatch(html,/<button[^>]*disabled[^>]*>核验已有会话/)
    assert.doesNotMatch(html,/<button[^>]*disabled[^>]*>使用已配对的所有者凭据/)
    assert.doesNotMatch(html,/HTTP 静态入口 · 需要 HTTPS|href="https:\/\/transport-test.invalid/)
    assert.equal(calls,0)
    assert.equal(await b.checkSession(),true);assert.equal(calls,1)
  }finally{if(old)Object.defineProperty(globalThis,'window',old);else delete(globalThis as any).window}
})

test('brand-sensitive native fetch works through HTTPS and HTTP clients',async()=>{
  const calls:{url:string;method:string|undefined}[]=[]
  async function nativeFetch(this:unknown,url:string,init:RequestInit):Promise<FetchResponse>{
    if(this!==undefined&&this!==globalThis)throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation")
    calls.push({url,method:init.method})
    if(url.endsWith('/session'))return response(session)
    if(url.endsWith('/status'))return response({schema_version:'sylanne.install-status.v1',runtime_stage:'ready',reason_code:'none'})
    assert.ok(url.endsWith('/configuration/v1'))
    if(init.method==='POST'){
      assert.equal((init.headers as Record<string,string>)['X-Sylanne-Configuration-CSRF'],'synthetic-only-config-csrf')
      const saved=configuration();saved.revision=2;saved.values.enabled=true
      return response(saved)
    }
    return response(configuration())
  }
  // The control reproduces the browser's API-instance receiver failure before
  // any request. Success below exercises the actual clients, not source text.
  await assert.rejects(({fetch:nativeFetch}).fetch('/session',{method:'GET'}),{name:'TypeError',message:"Failed to execute 'fetch' on 'Window': Illegal invocation"})
  assert.equal(calls.length,0)
  const api=new WorkbenchApi({enabled:true,origin,fetchImpl:nativeFetch})
  await api.openSession();assert.equal(api.hasSession,true)
  assert.deepEqual(await api.installationStatus(),{stage:'ready',reason:'none'})
  const config=new ConfigurationApi({enabled:true,origin,fetchImpl:nativeFetch})
  const before=await config.read(),saved=await config.update(before,{enabled:true})
  assert.equal(saved.revision,2);assert.equal(saved.values.enabled,true)
  assert.deepEqual(calls.map(call=>call.method),['GET','GET','GET','POST'])
  const count=calls.length
  const httpApi=new WorkbenchApi({enabled:true,origin:'http://transport-test.invalid',fetchImpl:nativeFetch})
  const httpConfig=new ConfigurationApi({enabled:true,origin:'http://transport-test.invalid',fetchImpl:nativeFetch})
  await httpApi.openSession()
  const httpBefore=await httpConfig.read(),httpSaved=await httpConfig.update(httpBefore,{enabled:true})
  assert.equal(httpSaved.values.enabled,true);assert.equal(calls.length,count+3)
})


test('HTTP browser crypto uses CSPRNG UUIDv4 and original SHA256 without secure-only APIs',async()=>{
  const {operationIdV1,sha256HexV1}=await import('./api/browser-crypto.ts')
  const real=globalThis.crypto,descriptor=Object.getOwnPropertyDescriptor(globalThis,'crypto')
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues:real.getRandomValues.bind(real)}})
  try{
    const ids=new Set(Array.from({length:32},()=>operationIdV1()))
    assert.equal(ids.size,32);for(const id of ids)assert.match(id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    assert.equal(sha256HexV1(new TextEncoder().encode('abc')),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    const bytes=new TextEncoder().encode('真实原件\n🙂')
    const expected=Buffer.from(await real.subtle.digest('SHA-256',bytes)).toString('hex')
    assert.equal(sha256HexV1(bytes),expected)
  }finally{if(descriptor)Object.defineProperty(globalThis,'crypto',descriptor);else delete(globalThis as any).crypto}
})
