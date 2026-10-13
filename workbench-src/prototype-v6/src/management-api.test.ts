import { test } from 'node:test'
import assert from 'node:assert/strict'
import { WorkbenchApi, type FetchLike, type FetchResponse } from './api/client.ts'
import { UUID4 } from './api/contract.ts'
import { validateCapabilities, validateLogPage, validateSettings, validateReceipt, type ManagementCapabilities, type SettingsSnapshot } from './api/management.ts'
export const caps: ManagementCapabilities = {schema_version:'sylanne.workbench-capabilities.v1',installation_id:'fixture-installation',access_generation:1,capabilities:{logs:{available:true,reason_code:'available',max_page_size:50,redaction:'server_allowlist.v1'},settings:{available:true,reason_code:'available',writable_fields:['enabled'],apply_semantics:'next_restart'}}}
const settings: SettingsSnapshot = {schema_version:'sylanne.workbench-settings.v1',installation_id:caps.installation_id,access_generation:1,revision:'fixture-revision-1',values:{enabled:false,authority_profile:'default'},writable_fields:['enabled'],apply_semantics:'next_restart'}
const page = {schema_version:'sylanne.workbench-logs.v1',installation_id:caps.installation_id,access_generation:1,entries:[{event_id:'evt-2',occurred_at:'2026-10-04T00:00:02Z',level:'INFO',event_code:'runtime.started',summary:'Fixture redacted startup event',redacted:true},{event_id:'evt-1',occurred_at:'2026-10-04T00:00:01Z',level:'WARNING',event_code:'runtime.limited',summary:'Fixture limited runtime',redacted:true}],next_cursor:'fixture-cursor',snapshot_id:'fixture-snapshot',redaction:'server_allowlist.v1'}
const session = {status:'ready',dashboard_session:'authenticated',owner_session:'unlocked',csrf_token:'fixture-csrf'}
const response = (body:unknown,status=200):FetchResponse => ({ok:status>=200&&status<300,status,json:async()=>body})
const clone = <T>(v:T):T => structuredClone(v)
const api = (fetchImpl:FetchLike,timeoutMs=1000) => new WorkbenchApi({enabled:true,origin:'https://fixture.invalid',fetchImpl,timeoutMs})
const tick = () => new Promise(done=>setTimeout(done,0))
function deferred<T>() {let resolve!:(v:T)=>void;const promise=new Promise<T>(done=>resolve=done);return {promise,resolve}}

test('management is offline zero-fetch and requires actual negotiated capability before read or write',async()=>{
 let count=0;const offline=new WorkbenchApi({fetchImpl:async()=>{count++;return response(caps)}})
 await assert.rejects(offline.managementCapabilities(),{code:'offline'});assert.equal(count,0)
 const a=api(async()=>{count++;return response(caps)})
 assert.throws(()=>a.queryLogs(caps,{level:'ALL',query:''}),{code:'capability_unavailable'})
 assert.throws(()=>a.readSettings(caps),{code:'capability_unavailable'})
 assert.throws(()=>a.updateSettings(caps,settings,true),{code:'capability_unavailable'});assert.equal(count,0)
})
test('negotiation and log query use isolated route with exact CSRF-bound UUID4 contracts',async()=>{
 const calls:{url:string,init:RequestInit}[]=[];const a=api(async(url,init)=>{calls.push({url,init});return response(url.endsWith('/session')?session:url.endsWith('/capabilities')?caps:page)})
 const actual=await a.managementCapabilities();const result=await a.queryLogs(actual,{level:'ALL',query:''});assert.equal(result.entries.length,2)
 assert.equal(calls.length,3)
 for(const {url,init}of calls.slice(1)){assert.ok(url.includes('/workbench/v1/management/v1/'));assert.equal(init.method,'POST');assert.equal(init.credentials,'same-origin');assert.equal(init.mode,'same-origin');assert.equal(init.cache,'no-store');assert.equal((init.headers as Record<string,string>)['x-csrf-token'],'fixture-csrf');const body=JSON.parse(String(init.body));assert.ok(UUID4.test(body.operation_id));assert.equal(body.schema_version,'sylanne.workbench-management.v1');assert.ok(!('scope' in body));assert.ok(!('actor' in body))}
 assert.deepEqual(Object.keys(JSON.parse(String(calls[1]!.init.body))).sort(),['operation_id','schema_version'])
 const body=JSON.parse(String(calls[2]!.init.body));assert.deepEqual(body.filter,{level:'ALL',query:''});assert.equal(body.limit,50);assert.equal(body.cursor,null);assert.equal(body.installation_id,caps.installation_id)
})
test('404 and 501 discovery fail closed while retaining independently valid session',async()=>{
 for(const status of [404,501]){const a=api(async url=>url.endsWith('/session')?response(session):response(null,status));await assert.rejects(a.managementCapabilities(),{code:'capability_unsupported',status});assert.equal(a.hasSession,true);assert.throws(()=>a.readSettings(caps),{code:'capability_unavailable'})}
})
test('unavailable and readonly capability forbid writes without requests; negotiated caps cannot be expanded by client mutation',async()=>{
 const readonly=clone(caps);readonly.capabilities.settings.writable_fields=[];readonly.capabilities.settings.apply_semantics='read_only'
 let count=0;const a=api(async url=>{count++;return response(url.endsWith('/session')?session:readonly)})
 const actual=await a.managementCapabilities();assert.throws(()=>a.updateSettings(actual,settings,true),{code:'capability_unavailable'});assert.equal(count,2)
 actual.capabilities.settings.writable_fields=['enabled'];actual.capabilities.settings.apply_semantics='next_restart';assert.throws(()=>a.readSettings(actual),{code:'capability_unavailable'});assert.equal(count,2)
 const unavailable=clone(caps);unavailable.capabilities.logs.available=false;unavailable.capabilities.logs.reason_code='installation_permission_unavailable';assert.equal(validateCapabilities(unavailable).capabilities.logs.available,false)
})
test('capability strict version, bounds, field and permission combinations reject',()=>{
 for(const body of [{...caps,schema_version:'future'},{...caps,unexpected:true},{...caps,access_generation:0},{...caps,capabilities:{...caps.capabilities,logs:{...caps.capabilities.logs,redaction:'none'}}},{...caps,capabilities:{...caps.capabilities,settings:{...caps.capabilities.settings,writable_fields:['authority_profile']}}},{...caps,capabilities:{...caps.capabilities,settings:{...caps.capabilities.settings,available:false}}}]) assert.throws(()=>validateCapabilities(body))
})
test('redacted log projection rejects raw fields, bad ordering, duplicates, limits and namespace drift',()=>{
 assert.equal(validateLogPage(page,caps).entries.length,2)
 for(const changed of [{...page,installation_id:'another'},{...page,access_generation:2},{...page,raw:'secret'},{...page,entries:[{...page.entries[0],token:'canary-secret'}]},{...page,entries:[{...page.entries[0],redacted:false}]},{...page,entries:[page.entries[1],page.entries[0]]},{...page,entries:[page.entries[0],page.entries[0]]},{...page,entries:Array(51).fill(page.entries[0])},{...page,entries:[],next_cursor:'cursor'}]) assert.throws(()=>validateLogPage(changed,caps))
 assert.equal(validateLogPage({...page,entries:[],next_cursor:null},caps).entries.length,0)
})
test('invalid log filter is rejected locally after negotiation',async()=>{
 let count=0;const a=api(async url=>{count++;return response(url.endsWith('/session')?session:caps)});const actual=await a.managementCapabilities()
 for(const filter of [{level:'DEBUG',query:''},{level:'ALL',query:'x'.repeat(129)},{level:'ALL',query:'',raw:true}]) assert.throws(()=>a.queryLogs(actual,filter as never),{code:'invalid_response'})
 assert.equal(count,2)
})
test('settings exact fields preserve false value and reject authority profile writes or ambiguous permissions',()=>{
 assert.equal(validateSettings(settings,caps).values.enabled,false)
 for(const body of [{...settings,values:{...settings.values,enabled:'false'}},{...settings,values:{...settings.values,secret:'canary'}},{...settings,values:{...settings.values,authority_profile:''}},{...settings,writable_fields:['authority_profile']},{...settings,apply_semantics:'immediate'}]) assert.throws(()=>validateSettings(body,caps))
})
test('settings update has only enabled patch, expected revision and stable operation receipt binding',async()=>{
 let sent:any;const a=api(async(url,init)=>{if(url.endsWith('/session'))return response(session);if(url.endsWith('/capabilities'))return response(caps);sent=JSON.parse(String(init.body));return response({schema_version:'sylanne.workbench-settings-receipt.v1',installation_id:caps.installation_id,access_generation:1,operation_id:sent.operation_id,revision:'fixture-revision-2',applied:'next_restart'})})
 const actual=await a.managementCapabilities();const receipt=await a.updateSettings(actual,settings,true);assert.equal(receipt.revision,'fixture-revision-2');assert.deepEqual(sent.patch,{enabled:true});assert.equal(sent.expected_revision,settings.revision)
 assert.deepEqual(Object.keys(sent).sort(),['schema_version','operation_id','installation_id','access_generation','expected_revision','patch'].sort())
 assert.throws(()=>validateReceipt({...receipt,operation_id:'wrong'},caps,settings,sent.operation_id));assert.throws(()=>validateReceipt({...receipt,revision:settings.revision},caps,settings,sent.operation_id));assert.throws(()=>validateReceipt({...receipt,applied:'immediate'},caps,settings,sent.operation_id))
})
test('save conflict, validation error and unknown network do not auto-retry mutations or show raw diagnostics',async()=>{
 for(const [status,code]of [[409,'revision_conflict'],[422,'validation_failed'],[500,'operation_outcome_unknown']] as const){let updates=0;const a=api(async url=>{if(url.endsWith('/session'))return response(session);if(url.endsWith('/capabilities'))return response(caps);updates++;return response({schema_version:'sylanne.workbench-error.v1',problem:{code,retryable:false}},status)});const actual=await a.managementCapabilities();await assert.rejects(a.updateSettings(actual,settings,true),e=>e instanceof Error&&!e.message.includes('canary-private')&&(e as any).code===code);assert.equal(updates,1)}
})
test('concurrent settings updates are gated rather than coalesced or replayed',async()=>{
 const wait=deferred<FetchResponse>();let posts=0;const a=api(async url=>{if(url.endsWith('/session'))return response(session);if(url.endsWith('/capabilities'))return response(caps);posts++;return wait.promise});const actual=await a.managementCapabilities();const first=a.updateSettings(actual,settings,true);const rejected=assert.rejects(first,{code:'session_changed'});await assert.rejects(a.updateSettings(actual,settings,false),{code:'action_pending'});await tick();assert.equal(posts,1);a.clearSession();await rejected
})
test('navigation invalidation aborts utility requests but keeps auth; old response cannot restore caps or be reused',async()=>{
 const wait=deferred<FetchResponse>();let first=true;let signal:AbortSignal|null|undefined;const a=api(async(url,init)=>{if(url.endsWith('/session'))return response(session);if(first){first=false;signal=init.signal;return wait.promise}return response(caps)})
 const pending=a.managementCapabilities();const rejected=assert.rejects(pending,{code:'session_changed'});await tick();a.invalidateManagement();assert.equal(signal?.aborted,true);await rejected;assert.equal(a.hasSession,true)
 const fresh=await a.managementCapabilities();wait.resolve(response({...caps,installation_id:'stale'}));await tick();assert.throws(()=>a.readSettings({...fresh,installation_id:'stale'}),{code:'capability_unavailable'})
})
test('logout aborts pending logs, purges capability, and 401 rejects without an automatic new session',async()=>{
 const wait=deferred<FetchResponse>();let signal:AbortSignal|null|undefined;const a=api(async(url,init)=>{if(url.endsWith('/session'))return response(session);if(url.endsWith('/capabilities'))return response(caps);signal=init.signal;return wait.promise});const actual=await a.managementCapabilities();const pending=a.queryLogs(actual,{level:'ALL',query:''});const rejected=assert.rejects(pending,{code:'session_changed'});await tick();a.clearSession();assert.equal(signal?.aborted,true);await rejected;assert.equal(a.hasSession,false)
 const unauthorized=api(async url=>url.endsWith('/session')?response(session):response({schema_version:'sylanne.workbench-error.v1',problem:{code:'owner_session_locked',retryable:false}},401));await assert.rejects(unauthorized.managementCapabilities(),{status:401});assert.equal(unauthorized.hasSession,false)
})
test('management timeout aborts and never reports a late update as success',async()=>{
 const wait=deferred<FetchResponse>();let updates=0;let signal:AbortSignal|null|undefined;const a=api(async(url,init)=>{if(url.endsWith('/session'))return response(session);if(url.endsWith('/capabilities'))return response(caps);updates++;signal=init.signal;return wait.promise},10);const actual=await a.managementCapabilities();await assert.rejects(a.updateSettings(actual,settings,true),{code:'timeout'});assert.equal(signal?.aborted,true);assert.equal(updates,1)
})

test('array-to-string coercion never admits malformed management enums',()=>{
 assert.throws(()=>validateCapabilities({...caps,capabilities:{...caps.capabilities,settings:{...caps.capabilities.settings,apply_semantics:['next_restart']}}}))
 assert.throws(()=>validateLogPage({...page,entries:[{...page.entries[0],level:['INFO']}]},caps))
 assert.throws(()=>validateSettings({...settings,apply_semantics:['next_restart']},caps))
})
test('malformed management errors and wrong HTTP/code pairs cannot classify uncertain writes as known rejection',async()=>{
 for(const [status,body] of [[500,{schema_version:'sylanne.workbench-error.v1',problem:{code:'validation_failed',retryable:false}}],[422,{schema_version:'wrong',problem:{code:'validation_failed',retryable:false}}],[409,{schema_version:'sylanne.workbench-error.v1',problem:{code:'revision_conflict',retryable:false,message:'canary-secret'}}]] as const){
  const a=api(async url=>url.endsWith('/session')?response(session):url.endsWith('/capabilities')?response(caps):response(body,status));const actual=await a.managementCapabilities();await assert.rejects(a.updateSettings(actual,settings,true),{code:'invalid_response',status})
 }
})
test('management response byte limit rejects an oversized real HTTP body before decoding fields', async () => {
  const a = api(async url => url.endsWith('/session') ? response(session) : new Response(JSON.stringify(caps) + ' '.repeat(512 * 1024), { headers: { 'content-type': 'application/json' } }))
  await assert.rejects(a.managementCapabilities(), { code: 'invalid_response' })
  assert.equal(a.hasSession, true)
})
