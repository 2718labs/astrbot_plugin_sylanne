import { ownerTaskRequest, ownerTaskInputDigest, validateOwnerTaskOptions, validateOwnerTaskStatus, validateOwnerTaskReceipt, ownerMaterialInputDigest, validateOwnerMaterialStatus, validateOwnerMaterialText } from './api/owner-source-note-task.ts'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { WorkbenchApi, WorkbenchApiError, validateCharacterView, validateWorkspace, type FetchLike, type FetchResponse } from './api/client.ts'
import { DEFAULT_API_BASE, CONTACT_HOLD, UUID4, makeReadCommand, makeOwnerLoginRequest, signingPayload, type OwnerFields, type OwnerChallenge } from './api/contract.ts'
import { makeStopReplyRequest, type ReplyControlMetadata } from './api/reply-controls.ts'
import { projectControlDigest, projectControlInput, validateProjectControlContext, validateProjectControlContextV2, type ProjectControlAction, type ProjectControlInput } from './api/project-control.ts'
import { sourceCorrectionInput, sourceCorrectionRequestDigest, validateSourceCorrectionContext } from './api/source-correction.ts'
import { projectContextInput, type ProjectContextOptions } from './api/project-context.ts'
const scope = 'test-bot/test-persona'
const session = { status: 'ready', dashboard_session: 'authenticated', owner_session: 'unlocked', csrf_token: 'mock-server-csrf-not-a-real-token' }
const workspace = { status: 'ready', projection: { namespace: { bot: 'test-bot', persona: 'test-persona' }, access_generation: 1,
  views: [{ view_type: 'creation', status: 'available' }, { view_type: 'd06.memory_sources.v1', status: 'available' }], view_diagnostics: [], unavailable_domains: { d10: 'no_public_projection_contract' }, command_routes: [] } }
const creation = { status: 'ready', projection: { view_type: 'creation', namespace: { bot: 'test-bot', persona: 'test-persona' }, access_generation: 1,
  data: { candidates: [{ plan_id: 'mock-plan', version: 1, authored: true, block_count: 2, value_rule_count: 1 }] }, coverage: { requested_types: ['d01.persona_plan.v1'], returned_atoms: 1, truncated: false }, snapshot_epoch: 1, next_cursor: null } }
const memory = { status: 'ready', projection: { view_type: 'd06.memory_sources.v1', namespace: { bot: 'test-bot', persona: 'test-persona' }, access_generation: 1,
  data: { sources: [{ source_id: 'mock-source', source_kind: 'statement', assertion_status: 'asserted', recorded_at: '2026-10-03T00:00:00Z', qualification: 'not_recorded' }], coverage: 'complete' } } }
const fields: OwnerFields = { authority_id: 'test-authority', authority_namespace: 'test-bot/test-persona', installation_id: 'test-install', identity_provider: 'test-provider', account_ref: 'test-owner', account_incarnation: 'first', credential_id: 'test-credential', credential_epoch: '1' }
const origin = 'https://mock.sylanne.invalid'
function response(body: unknown, status = 200): FetchResponse { return { ok: status >= 200 && status < 300, status, json: async () => body } }
function client(fetchImpl: FetchLike, extra: { timeoutMs?: number } = {}) { return new WorkbenchApi({ enabled: true, origin, fetchImpl, ...extra }) }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done }); return { promise, resolve } }
function challengeBody() {
  const request = makeOwnerLoginRequest(fields, origin), now = Date.now()
  const challenge: OwnerChallenge = { kind: 'owner_session_login_challenge_v1', schema: 'sylanne3.authority.owner-session.v1', request,
    nonce: 'a'.repeat(43), principal_epoch: 0, boot_id: 'b'.repeat(43), issued_at_utc: new Date(now - 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'), expires_at_utc: new Date(now + 60000).toISOString().replace(/\.\d{3}Z$/, 'Z') }
  return { schema_version: 'sylanne.owner-login.v1', challenge, signing_payload_base64: Buffer.from(signingPayload(challenge)).toString('base64') }
}
test('offline default cannot fetch, authenticate, or send contact', async () => {
  let calls = 0; const api = new WorkbenchApi({ fetchImpl: async () => { ++calls; return response(session) } })
  await assert.rejects(api.openSession(), { code: 'offline' }); await assert.rejects(api.openWorkspace(scope), { code: 'offline' })
  assert.equal(CONTACT_HOLD, true); await assert.rejects(api.sendContact(), { code: 'contact_hold' }); assert.equal(calls, 0); assert.equal(api.hasSession, false)
})
test('same-origin relative route only; external/unsafe URLs and unsupported mutation rejected locally', () => {
  for (const baseUrl of ['https://example.com/api', '//example.com/api', '/api?token=secret', '/api#fragment', '/api/../evil', '/api\\evil']) assert.throws(() => new WorkbenchApi({ baseUrl }))
  assert.throws(() => makeReadCommand('configure_or_control' as never, scope))
  assert.throws(() => makeReadCommand('open_workspace', 'invalid scope'))
  assert.throws(() => makeReadCommand('open_workspace', scope, undefined, null, '00000000-0000-1000-8000-000000000000'))
})
test('read request has exact D12 fields, canonical UUID4 and page_size=100 for contextual D06 projection', async () => {
  const calls: { url: string; init: RequestInit }[] = []
  const api = client(async (url, init) => { calls.push({ url, init }); return response(url.endsWith('/session') ? session : memory) })
  const result = await api.readView(scope, 'd06.memory_sources.v1')
  assert.equal(result.projection?.data.sources?.[0]?.qualification, 'not_recorded'); assert.equal(calls.length, 2)
  assert.equal(calls[0]!.url, `${DEFAULT_API_BASE}/session`); assert.equal(calls[1]!.url, `${DEFAULT_API_BASE}/commands`)
  for (const { init } of calls) { assert.equal(init.credentials, 'same-origin'); assert.equal(init.mode, 'same-origin'); assert.equal(init.cache, 'no-store'); assert.equal(init.referrerPolicy, 'same-origin'); assert.equal((init.headers as Record<string,string>).authorization, undefined); assert.equal((init.headers as Record<string,string>).origin, undefined) }
  assert.equal((calls[0]!.init.headers as Record<string,string>)['x-csrf-token'], undefined)
  assert.equal((calls[1]!.init.headers as Record<string,string>)['x-csrf-token'], session.csrf_token)
  const payload = JSON.parse(calls[1]!.init.body as string)
  assert.deepEqual(Object.keys(payload).sort(), ['schema_version','action','scope','purpose','audience','operation_id','input'].sort()); assert.ok(UUID4.test(payload.operation_id)); assert.deepEqual(payload.input, { view_type: 'd06.memory_sources.v1', page_size: 100 }); assert.equal(payload.audience, 'owner'); assert.equal(payload.purpose, 'workbench_view')
  await api.readView(scope, 'd06.memory_sources.v1', 'opaque-page-2')
  assert.deepEqual(JSON.parse(calls[2]!.init.body as string).input, { view_type: 'd06.memory_sources.v1', cursor: 'opaque-page-2', page_size: 100 })
  assert.equal('csrfToken' in api, false)
})
test('host-only or invalid session never enables POST', async () => {
  for (const body of [{ status:'ready',csrf_token:'dashboard-only' }, { ...session, owner_session:'locked' }, { ...session, csrf_token:'' }, null]) {
    let calls = 0; const api = client(async () => { ++calls; return response(body) })
    await assert.rejects(api.openWorkspace(scope), { code:'invalid_response' }); assert.equal(calls, 1); assert.equal(api.hasSession, false)
  }
})
test('legacy successful responses reject unknown fields and versions before exposing content or authorization', async () => {
  for (const body of [{ ...session, extra: true }, { ...session, schema_version: 'future' }]) {
    const api = client(async () => response(body))
    await assert.rejects(api.openSession(), { code: 'invalid_response' }); assert.equal(api.hasSession, false)
  }
  const status = { schema_version: 'sylanne.install-status.v1', runtime_stage: 'ready', reason_code: 'none' }
  await assert.rejects(client(async () => response({ ...status, extra: true })).installationStatus(), { code: 'invalid_response' })
  await assert.rejects(client(async () => response({ status: 'ok', owner_session: 'locked', extra: true })).ownerLogout(), { code: 'invalid_response' })
  const body = challengeBody()
  await assert.rejects(client(async () => response({ ...body, extra: true })).ownerChallenge(fields))
  const completed = client(async url => response(url.endsWith('/owner/challenge') ? body : { status: 'authenticated', owner_session: 'unlocked', extra: true }))
  await completed.ownerChallenge(fields)
  await assert.rejects(completed.ownerComplete(Buffer.alloc(64).toString('base64')), { code: 'invalid_response' })
  for (const changed of [{ ...workspace, extra: true }, { ...workspace, schema_version: 'future' }, { ...workspace, projection: { ...workspace.projection, extra: true } }, { ...workspace, projection: { ...workspace.projection, views: [{ ...workspace.projection.views[0], extra: true }] } }]) {
    assert.throws(() => validateWorkspace(changed, scope), { code: 'invalid_response' })
  }
  for (const changed of [{ ...creation, projection: { ...creation.projection, extra: true } }, { ...creation, projection: { ...creation.projection, coverage: { ...creation.projection.coverage, extra: true } } }]) {
    assert.throws(() => validateCharacterView(changed, scope, 'creation'), { code: 'invalid_response' })
  }
})
test('401 session failure prevents command; a later explicit retry can obtain a fresh session', async () => {
  let unlocked = false, posts = 0
  const api = client(async (url) => { if(url.endsWith('/session')) return unlocked ? response(session) : response({status:'unauthorized',problem:{code:'owner_session_locked'}},401); ++posts; return response(workspace) })
  await assert.rejects(api.openWorkspace(scope), {code:'owner_session_locked',status:401}); assert.equal(posts,0); assert.equal(api.hasSession,false)
  unlocked = true; assert.equal((await api.openWorkspace(scope)).status, 'ready'); assert.equal(posts,1)
})
test('403 CSRF rejection clears auth and never automatically replays POST', async () => {
  let calls = 0
  const api = client(async (url) => { ++calls; return url.endsWith('/session') ? response(session) : response({status:'unauthorized',problem:{code:'csrf_denied',retryable:false}},403) })
  await assert.rejects(api.openWorkspace(scope), {code:'csrf_denied',status:403,retryable:false}); assert.equal(calls,2); assert.equal(api.hasSession,false)
})
test('401/403 from content do not expose prior or unauthorized projections', async () => {
  for(const status of [401,403]) {
    const api=client(async url=>response(url.endsWith('/session')?session:{...creation,status:'unauthorized',problem:{code:'owner_scope_denied'}},url.endsWith('/session')?200:status))
    await assert.rejects(api.readView(scope,'creation'),{status}); assert.equal(api.hasSession,false)
  }
  const api=client(async url=>response(url.endsWith('/session')?session:{status:'unauthorized',problem:{code:'authority_unavailable'}}))
  await assert.rejects(api.readView(scope,'creation'),{status:403});assert.equal(api.hasSession,false)
})
test('500 produces safe failure with no raw backend message, cached data or retry', async () => {
  let calls=0;const api=client(async()=>{++calls;return response({problem:{code:'runtime_unavailable',message:'secret-sensitive-server-details'}},500)})
  await assert.rejects(api.openSession(),error=>error instanceof WorkbenchApiError && error.status===500 && !error.message.includes('secret-sensitive'));assert.equal(calls,1);assert.equal(api.hasSession,false)
})
test('timeout aborts a stalled fetch and late session cannot restore auth', async () => {
  const late=deferred<FetchResponse>();let signal:AbortSignal|null|undefined
  const api=client(async(_url,init)=>{signal=init.signal;return late.promise},{timeoutMs:10})
  await assert.rejects(api.openSession(),{code:'timeout'});assert.equal(signal?.aborted,true);late.resolve(response(session));await new Promise(done=>setTimeout(done,0));assert.equal(api.hasSession,false)
})
test('invalid JSON, arrays and wrong projection types fail closed', async () => {
  const invalidJson=client(async()=>({ok:true,status:200,json:async()=>{throw new Error('not json')}}));await assert.rejects(invalidJson.openSession(),{code:'invalid_response'})
  for(const body of [[],{}, {...creation,projection:{...creation.projection,namespace:{bot:'other',persona:'role'}}}, {...creation,projection:{...creation.projection,data:{candidates:[{plan_id:'x',version:'1',authored:true,block_count:1,value_rule_count:0}]}}}]) {
    const api=client(async url=>response(url.endsWith('/session')?session:body));await assert.rejects(api.readView(scope,'creation'),{code:'invalid_response'})
  }
})
test('source metadata does not accept body/confidence or invented qualification',()=>{
  assert.equal(validateCharacterView(memory,scope,'d06.memory_sources.v1').status,'ready')
  for(const source of [{...memory.projection.data.sources[0],body:'private text'}, {...memory.projection.data.sources[0],qualification:'verified'}]) assert.throws(()=>validateCharacterView({...memory,projection:{...memory.projection,data:{sources:[source],coverage:'complete'}}},scope,'d06.memory_sources.v1'),{code:'invalid_response'})
})
test('empty/partial/stale are explicit and nonready projection leakage is rejected',()=>{
  for(const status of ['empty','partial','stale','unavailable','loading']) assert.equal(validateCharacterView({status},scope,'creation').status,status)
  assert.throws(()=>validateCharacterView({...creation,status:'partial'},scope,'creation'),{code:'invalid_response'})
  assert.throws(()=>validateWorkspace({...workspace,projection:{...workspace.projection,views:[{view_type:'invented-config',status:'available'}]}},scope),{code:'invalid_response'})
})
test('repeated reads coalesce with one session and one stable operation_id',async()=>{
  const wait=deferred<FetchResponse>();let gets=0,posts=0;let sentId=''
  const api=client(async(url,init)=>{if(url.endsWith('/session')){++gets;return response(session)}++posts;sentId=JSON.parse(init.body as string).operation_id;return wait.promise})
  const a=api.openWorkspace(scope),b=api.openWorkspace(scope);assert.equal(a,b);await new Promise(done=>setTimeout(done,0));assert.equal(gets,1);assert.equal(posts,1);assert.ok(UUID4.test(sentId));wait.resolve(response(workspace));await Promise.all([a,b])
})
test('late session after lock is discarded; newly checked session remains valid',async()=>{
  const old=deferred<FetchResponse>();let gets=0;const api=client(async()=>++gets===1?old.promise:response(session))
  const earlier=api.openSession();api.clearSession();await api.openSession();old.resolve(response({...session,csrf_token:'old-token'}));await assert.rejects(earlier,{code:'session_changed'});assert.equal(api.hasSession,true)
})
test('late unauthorized old request cannot revoke a newly checked session',async()=>{
  const old=deferred<FetchResponse>();const api=client(async url=>url.endsWith('/session')?response(session):old.promise)
  const read=api.readView(scope,'creation');await new Promise(done=>setTimeout(done,0));api.clearSession();await api.openSession();old.resolve(response({problem:{code:'owner_scope_denied'}},403));await assert.rejects(read,{code:'session_changed'});assert.equal(api.hasSession,true)
})
test('Owner flow sends only paired metadata and signed challenge with cookies, no CSRF/password/key fields',async()=>{
  const body=challengeBody();const calls:{url:string;init:RequestInit}[]=[]
  const api=client(async(url,init)=>{calls.push({url,init});return response(url.endsWith('/owner/challenge')?body:url.endsWith('/owner/complete')?{status:'authenticated',owner_session:'unlocked'}:session)})
  await api.ownerChallenge(fields);await api.ownerComplete(Buffer.alloc(64,1).toString('base64'));assert.equal(api.hasSession,true)
  assert.equal(calls.length,3);for(const {init}of calls){assert.equal(init.credentials,'same-origin');assert.equal((init.headers as Record<string,string>)['x-csrf-token'],undefined);assert.ok(!String(init.body).includes('password'));assert.ok(!String(init.body).includes('private_key'))}
  assert.deepEqual(Object.keys(JSON.parse(calls[0]!.init.body as string)),['request']);assert.deepEqual(Object.keys(JSON.parse(calls[1]!.init.body as string)),['challenge','signature_base64'])
  await assert.rejects(api.ownerComplete(Buffer.alloc(64,1).toString('base64')),{code:'challenge_expired'});assert.equal(calls.length,3)
})
test('Owner challenge verifies full signed payload and request equality independent of JSON order',async()=>{
  const body=challengeBody();body.challenge.request=Object.fromEntries(Object.entries(body.challenge.request).reverse()) as typeof body.challenge.request
  const api=client(async()=>response(body));assert.ok((await api.ownerChallenge(fields)).challenge)
  for(const changed of [{...body,signing_payload_base64:Buffer.from('altered bytes').toString('base64')},{...body,challenge:{...body.challenge,nonce:'wrong'}},{...body,challenge:{...body.challenge,expires_at_utc:new Date(Date.now()-1).toISOString()}}]){
    const broken=client(async()=>response(changed));await assert.rejects(broken.ownerChallenge(fields));assert.equal(broken.hasSession,false)
  }
})
test('Owner HTTP challenge keeps exact origin and original protocol; no invented register/login endpoint',async()=>{
  let calls=0;const api=new WorkbenchApi({enabled:true,origin:'http://localhost',fetchImpl:async()=>{++calls;return response({})}})
  await assert.rejects(api.ownerChallenge(fields),/Owner 挑战响应无效/)
  assert.equal(calls,1);assert.equal('login' in api,false);assert.equal('register' in api,false)
  assert.equal(makeOwnerLoginRequest(fields,'http://localhost').dashboard_origin,'http://localhost')
  assert.throws(()=>makeOwnerLoginRequest({...fields,credential_epoch:'01'},origin));assert.throws(()=>makeOwnerLoginRequest(fields,'https://example.com/path'))
})
test('repeated signature submission coalesces; timed-out completion cannot replay one-use challenge',async()=>{
  const wait=deferred<FetchResponse>();let completes=0;const api=client(async url=>{if(url.endsWith('/owner/challenge'))return response(challengeBody());if(url.endsWith('/session'))return response(session);++completes;return wait.promise},{timeoutMs:15})
  await api.ownerChallenge(fields);const sig=Buffer.alloc(64).toString('base64');const a=api.ownerComplete(sig),b=api.ownerComplete(sig);assert.equal(a,b);await assert.rejects(a,{code:'timeout'});assert.equal(completes,1);await assert.rejects(api.ownerComplete(sig),{code:'challenge_expired'});assert.equal(completes,1);wait.resolve(response({status:'authenticated',owner_session:'unlocked'}));assert.equal(api.hasSession,false)
})
test('cancelled challenge and logout cannot restore old authorization',async()=>{
  const wait=deferred<FetchResponse>();const api=client(async url=>url.endsWith('/owner/challenge')?wait.promise:response({status:'ok',owner_session:'locked'}))
  const pending=api.ownerChallenge(fields);api.cancelOwnerChallenge();wait.resolve(response(challengeBody()));await assert.rejects(pending,{code:'session_changed'});assert.equal(api.hasSession,false);await api.ownerLogout();assert.equal(api.hasSession,false)
})

// Mount the composable in an SSR component so lifecycle hooks have a real Vue owner.
async function controller(fetchImpl: FetchLike, enabled = true) {
  const { createSSRApp, h } = await import('vue')
  const { renderToString } = await import('@vue/server-renderer')
  const { useBackend } = await import('./use-backend.ts')
  let backend!: ReturnType<typeof useBackend>
  await renderToString(createSSRApp({ setup() { backend = useBackend({ enabled, origin, fetchImpl: async (url, init) => url.endsWith('/status') ? response({schema_version:'sylanne.install-status.v1',runtime_stage:'ready',reason_code:'none'}) : fetchImpl(url, init) }); return () => h('div') } }))
  // Existing D12 tests explicitly perform the now-required runtime check before the user's read.
  const ensureRuntime = async () => { if (!backend.runtimeReadable.value) await backend.management.checkRuntime() }
  return { ...backend, openWorkspace: async () => { await ensureRuntime(); await backend.openWorkspace() }, readView: async (view: Parameters<typeof backend.readView>[0]) => { await ensureRuntime(); await backend.readView(view) } }
}
test('closing login after a verified session preserves auth; explicit logout clears displayed data', async () => {
  const backend = await controller(async url => response(url.endsWith('/session') ? session : url.endsWith('/owner/logout') ? { status:'ok',owner_session:'locked' } : workspace))
  await backend.checkSession(); backend.setScope(scope); await backend.openWorkspace(); backend.dismissLogin()
  assert.equal(backend.state.auth,'authenticated');assert.equal(backend.canRead.value,true);assert.ok(backend.state.workspace.data)
  await backend.logout();assert.equal(backend.state.auth,'locked');assert.equal(backend.state.workspace.data,null);assert.equal(backend.canRead.value,false)
})
test('scope change and rapid archive switch discard older in-flight content',async()=>{
  const old=deferred<FetchResponse>();const backend=await controller(async(url,init)=>{
    if(url.endsWith('/session'))return response(session)
    const request=JSON.parse(init.body as string)
    return request.action==='open_workspace'?response(workspace):request.input.view_type==='creation'?old.promise:response(memory)
  })
  await backend.checkSession();backend.setScope(scope);await backend.openWorkspace();const first=backend.readView('creation');await new Promise(done=>setTimeout(done,0));await backend.readView('d06.memory_sources.v1');old.resolve(response(creation));await first
  assert.equal(backend.state.view.data?.view_type,'d06.memory_sources.v1');backend.setScope('another-bot/another-persona');assert.equal(backend.state.view.data,null);assert.equal(backend.state.workspace.data,null)
})
test('unauthorized view refresh clears prior content and capability catalogue',async()=>{
  let authorized=true;const backend=await controller(async(url,init)=>{
    if(url.endsWith('/session'))return response(session)
    const request=JSON.parse(init.body as string)
    if(request.action==='open_workspace')return response(workspace)
    return authorized?response(creation):response({status:'unauthorized',problem:{code:'owner_session_locked'}},401)
  })
  await backend.checkSession();backend.setScope(scope);await backend.readView('creation');assert.ok(backend.state.view.data);authorized=false;await backend.readView('creation')
  assert.equal(backend.state.auth,'locked');assert.equal(backend.state.view.data,null);assert.equal(backend.state.workspace.data,null);assert.equal(backend.canRead.value,false)
})
test('dismissal during challenge discards response and remains locked without false success',async()=>{
  const old=deferred<FetchResponse>();const backend=await controller(async()=>old.promise)
  const pending=backend.beginOwnerLogin(fields);backend.dismissLogin();old.resolve(response(challengeBody()));await pending
  assert.equal(backend.state.auth,'locked');assert.equal(backend.state.challenge,null);assert.equal(backend.state.error,'')
})
test('logout failure stays locked and clearly reports unconfirmed Authority result',async()=>{
  const backend=await controller(async url=>url.endsWith('/session')?response(session):response({problem:{code:'owner_logout_authority_unavailable'}},503))
  await backend.checkSession();await backend.logout();assert.equal(backend.state.auth,'locked');assert.equal(backend.state.errorCode,'owner_logout_authority_unavailable');assert.match(backend.state.error,/尚未确认/)
})
test('archive switch without a subsequent read invalidates late earlier content and preserves auth',async()=>{
  const old=deferred<FetchResponse>();const backend=await controller(async(url,init)=>{
    if(url.endsWith('/session'))return response(session)
    return JSON.parse(init.body as string).action==='open_workspace'?response(workspace):old.promise
  })
  await backend.checkSession();backend.setScope(scope);backend.selectArchive('demo-persona');await backend.openWorkspace();const earlier=backend.readView('creation');await new Promise(done=>setTimeout(done,0));backend.selectArchive('demo-contact');assert.equal(backend.state.view.data,null);old.resolve(response(creation));await earlier
  assert.equal(backend.state.view.data,null);assert.equal(backend.state.viewType,null);assert.equal(backend.state.view.status,'idle');assert.equal(backend.state.auth,'authenticated');assert.equal(backend.canRead.value,false)
})
test('view unmount barrier discards a pending response without logging out',async()=>{
  const old=deferred<FetchResponse>();const backend=await controller(async(url,init)=>url.endsWith('/session')?response(session):JSON.parse(init.body as string).action==='open_workspace'?response(workspace):old.promise)
  await backend.checkSession();backend.setScope(scope);await backend.openWorkspace();const earlier=backend.readView('creation');await new Promise(done=>setTimeout(done,0));backend.invalidateView();old.resolve(response(creation));await earlier
  assert.equal(backend.state.auth,'authenticated');assert.equal(backend.state.view.data,null)
})
test('logout while a view is pending blocks its late completion',async()=>{
  const old=deferred<FetchResponse>();const backend=await controller(async(url,init)=>{
    if(url.endsWith('/session'))return response(session)
    if(url.endsWith('/owner/logout'))return response({status:'ok',owner_session:'locked'})
    return JSON.parse(init.body as string).action==='open_workspace'?response(workspace):old.promise
  })
  await backend.checkSession();backend.setScope(scope);await backend.openWorkspace();const earlier=backend.readView('creation');await new Promise(done=>setTimeout(done,0));await backend.logout();old.resolve(response(creation));await earlier
  assert.equal(backend.state.auth,'locked');assert.equal(backend.state.view.data,null);assert.equal(backend.state.workspace.data,null)
})

test('controller offline actions never fetch or authenticate', async () => {
  let calls = 0
  const backend = await controller(async () => { ++calls; return response(session) }, false)
  assert.equal(await backend.checkSession(), false)
  assert.equal(await backend.beginOwnerLogin(fields), false)
  assert.equal(await backend.completeOwnerLogin(Buffer.alloc(64).toString('base64')), false)
  backend.setScope(scope); await backend.openWorkspace(); await backend.readView('creation'); await backend.logout()
  assert.equal(calls, 0); assert.equal(backend.state.auth, 'offline'); assert.equal(backend.canRead.value, false)
})
test('Owner complete endpoint success is insufficient until fresh /session succeeds', async () => {
  const gate = deferred<FetchResponse>(); let sessions = 0
  const backend = await controller(async url => url.endsWith('/owner/challenge') ? response(challengeBody()) : url.endsWith('/owner/complete') ? response({ status: 'authenticated', owner_session: 'unlocked' }) : (++sessions, gate.promise))
  await backend.beginOwnerLogin(fields)
  assert.equal(backend.state.dashboard, 'authenticated'); assert.equal(backend.state.auth, 'locked')
  const pending = backend.completeOwnerLogin(Buffer.alloc(64).toString('base64'))
  await new Promise(done => setTimeout(done, 0))
  assert.equal(sessions, 1); assert.equal(backend.state.auth, 'checking'); assert.equal(backend.canRead.value, false)
  gate.resolve(response({ ...session, owner_session: 'locked' })); assert.equal(await pending, false)
  assert.equal(backend.state.auth, 'locked'); assert.equal(backend.state.owner, 'locked')
})
test('dismissal during signature completion discards late success and fresh session', async () => {
  const completion = deferred<FetchResponse>(); let sessionCalls = 0
  const backend = await controller(async url => url.endsWith('/owner/challenge') ? response(challengeBody()) : url.endsWith('/owner/complete') ? completion.promise : (++sessionCalls, response(session)))
  await backend.beginOwnerLogin(fields); const pending = backend.completeOwnerLogin(Buffer.alloc(64).toString('base64'))
  backend.dismissLogin(); completion.resolve(response({ status: 'authenticated', owner_session: 'unlocked' })); assert.equal(await pending, false)
  assert.equal(backend.state.auth, 'locked'); assert.equal(backend.state.challenge, null); assert.equal(backend.state.busy, false); assert.equal(sessionCalls, 0); assert.equal(backend.state.error, '')
})
test('logout immediately supersedes pending verification without old busy or auth restoration', async () => {
  const olderSession = deferred<FetchResponse>(), logoutGate = deferred<FetchResponse>()
  const backend = await controller(async url => url.endsWith('/session') ? olderSession.promise : logoutGate.promise)
  const check = backend.checkSession(); const lock = backend.logout()
  assert.equal(backend.state.auth, 'locked'); assert.equal(backend.state.authOperation, 'logout'); assert.equal(backend.state.busy, true)
  olderSession.resolve(response(session)); await check
  assert.equal(backend.state.auth, 'locked'); assert.equal(backend.state.busy, true); assert.equal(backend.state.authOperation, 'logout')
  logoutGate.resolve(response({ status: 'ok', owner_session: 'locked' })); assert.equal(await lock, true)
  assert.equal(backend.state.busy, false); assert.equal(backend.state.logoutStatus, 'confirmed')
})
test('logout immediately supersedes pending signed completion and blocks a late /session', async () => {
  const completion = deferred<FetchResponse>(); let sessions = 0
  const backend = await controller(async url => url.endsWith('/owner/challenge') ? response(challengeBody()) : url.endsWith('/owner/complete') ? completion.promise : url.endsWith('/owner/logout') ? response({ status: 'ok', owner_session: 'locked' }) : (++sessions, response(session)))
  await backend.beginOwnerLogin(fields); const complete = backend.completeOwnerLogin(Buffer.alloc(64).toString('base64')); await backend.logout()
  completion.resolve(response({ status: 'authenticated', owner_session: 'unlocked' })); assert.equal(await complete, false)
  assert.equal(sessions, 0); assert.equal(backend.state.auth, 'locked'); assert.equal(backend.state.owner, 'locked')
})
test('cancelled session cannot overwrite a newer successfully checked session', async () => {
  const old = deferred<FetchResponse>(); let checks = 0
  const backend = await controller(async () => ++checks === 1 ? old.promise : response(session))
  const first = backend.checkSession(); backend.dismissLogin(); assert.equal(await backend.checkSession(), true)
  old.resolve(response({ problem: { code: 'host_session_missing' } }, 401)); assert.equal(await first, false)
  assert.equal(backend.state.auth, 'authenticated'); assert.equal(backend.state.dashboard, 'authenticated'); assert.equal(backend.state.error, '')
})
test('navigation purges view and workspace but preserves verified authorization and CSRF', async () => {
  let sessions = 0
  const backend = await controller(async (url, init) => url.endsWith('/session') ? (++sessions, response(session)) : JSON.parse(init.body as string).action === 'open_workspace' ? response(workspace) : response(creation))
  await backend.checkSession(); backend.setScope(scope); await backend.readView('creation'); assert.ok(backend.state.view.data)
  backend.invalidateNavigation(); assert.equal(backend.state.auth, 'authenticated'); assert.equal(backend.canRead.value, false); assert.equal(backend.state.workspace.data, null); assert.equal(backend.state.view.data, null)
  await backend.readView('creation'); assert.equal(sessions, 1); assert.ok(backend.state.view.data)
})
test('archive switch invalidates pending catalogue and does not reuse its coalesced old promise', async () => {
  const old = deferred<FetchResponse>(); let commands = 0
  const backend = await controller(async url => url.endsWith('/session') ? response(session) : ++commands === 1 ? old.promise : response(workspace))
  await backend.checkSession(); backend.setScope(scope); backend.selectArchive('demo-persona'); const first = backend.openWorkspace()
  await new Promise(done => setTimeout(done, 0)); assert.equal(commands, 1) // Establish the actual pending catalogue after the runtime check.
  backend.selectArchive('demo-access'); await backend.openWorkspace(); assert.equal(backend.state.workspace.status, 'stale'); assert.equal(commands, 1)
  old.resolve(response(workspace)); await first; assert.equal(backend.state.workspace.data, null); assert.equal(backend.state.auth, 'authenticated')
  await backend.openWorkspace(); assert.equal(commands, 2); assert.ok(backend.state.workspace.data)
})
test('close/reopen of same view cannot display an invalidated API-coalesced result', async () => {
  const old = deferred<FetchResponse>(); let reads = 0
  const backend = await controller(async (url, init) => url.endsWith('/session') ? response(session) : JSON.parse(init.body as string).action === 'open_workspace' ? response(workspace) : ++reads === 1 ? old.promise : response(creation))
  await backend.checkSession(); backend.setScope(scope); await backend.openWorkspace(); const first = backend.readView('creation'); await new Promise(done => setTimeout(done, 0))
  backend.invalidateView(); await backend.readView('creation'); assert.equal(backend.state.view.status, 'stale'); assert.equal(reads, 1)
  old.resolve(response(creation)); await first; assert.equal(backend.state.view.data, null)
  await backend.readView('creation'); assert.equal(reads, 2); assert.ok(backend.state.view.data)
})
test('projection loading, empty, partial, stale and unavailable remain explicit without fake rows', async () => {
  for (const status of ['loading', 'empty', 'partial', 'stale', 'unavailable'] as const) {
    const backend = await controller(async (url, init) => url.endsWith('/session') ? response(session) : JSON.parse(init.body as string).action === 'open_workspace' ? response(workspace) : response({ status }))
    await backend.checkSession(); backend.setScope(scope); await backend.readView('creation')
    assert.equal(backend.state.view.status, status); assert.equal(backend.state.view.data, null); assert.notEqual(backend.state.view.message, '')
  }
})
test('empty ready projection preserves authorized zero rows instead of inventing records', async () => {
  const backend = await controller(async (url, init) => url.endsWith('/session') ? response(session) : JSON.parse(init.body as string).action === 'open_workspace' ? response(workspace) : response({ ...creation, projection: { ...creation.projection, data: { candidates: [] } } }))
  await backend.checkSession(); backend.setScope(scope); await backend.readView('creation')
  assert.equal(backend.state.view.status, 'empty'); assert.equal(backend.state.view.data?.data.candidates?.length, 0)
})
test('a settled backend loading response allows an explicit retry rather than staying busy forever', async () => {
  let reads = 0, directories = 0
  const backend = await controller(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    return JSON.parse(init.body as string).action === 'open_workspace' ? response(++directories === 1 ? { status: 'loading' } : workspace) : response(++reads === 1 ? { status: 'loading' } : creation)
  })
  await backend.checkSession(); backend.setScope(scope); await backend.openWorkspace()
  assert.equal(backend.state.workspace.status, 'loading'); assert.notEqual(backend.state.workspace.pending, true)
  await backend.openWorkspace(); assert.equal(backend.state.workspace.status, 'ready'); assert.equal(directories, 2)
  await backend.readView('creation'); assert.equal(backend.state.view.status, 'loading'); assert.notEqual(backend.state.view.pending, true)
  await backend.readView('creation'); assert.equal(backend.state.view.status, 'ready'); assert.equal(reads, 2)
})


const replyMetadata: ReplyControlMetadata = {
  schema: 'd12.owner-reply-control-metadata.v1', namespace: { bot_id: 'test-bot', persona_id: 'test-persona' },
  installation_id: 'mock-installation', cycle_job_ref: 'mock-existing-cycle', c02_operation_id: 'mock-existing-c02',
  cancel_generation: 0, job_phase: 'waiting', original_ref: null, stop_state: null,
}
function replyStatus(operationId: string) {
  return { status: 'ready', control: { schema: 'd12.owner-stop-reply-status.v1', namespace: replyMetadata.namespace,
    cycle_job_ref: replyMetadata.cycle_job_ref, operation_id: operationId, original_ref: 'd12authority:' + 'c'.repeat(64),
    original_digest: 'sha256:' + 'd'.repeat(64), state: 'cancel_requested', cancel_generation: 1, cancellation_confirmed: false } }
}
test('reply controls authenticate through the explicit metadata session and keep content session separate', async () => {
  const calls: { url: string; init: RequestInit }[] = []
  const api = client(async (url, init) => { calls.push({ url, init }); return response(url.endsWith('/reply-control-session') ? session : { status: 'ready', items: [replyMetadata], next_cursor: null }) })
  const items = await api.readReplyControls(scope)
  assert.equal(items.items[0]?.cycle_job_ref, replyMetadata.cycle_job_ref)
  assert.deepEqual(calls.map(call => call.url), [DEFAULT_API_BASE + '/reply-control-session', DEFAULT_API_BASE + '/commands'])
  const command = JSON.parse(calls[1]!.init.body as string)
  assert.equal(command.action, 'read_reply_controls'); assert.equal(command.purpose, 'workbench_user_action')
  assert.deepEqual(command.input, {}); assert.equal((calls[1]!.init.headers as Record<string, string>)['x-csrf-token'], session.csrf_token)
  assert.equal(api.hasSession, false)
})
test('an uncertain reply stop is explicitly retried with the same UUID and exact payload without confirming completion', async () => {
  const posted: unknown[] = []; let failed = false
  const api = client(async (url, init) => {
    if (url.endsWith('/reply-control-session')) return response(session)
    const command = JSON.parse(init.body as string); posted.push(command)
    if (!failed) { failed = true; throw new Error('mock response lost after send') }
    return response(replyStatus(command.operation_id))
  })
  const request = makeStopReplyRequest(replyMetadata)
  await assert.rejects(api.stopReply(request), { code: 'network_unavailable' })
  assert.equal(posted.length, 1)
  const result = await api.stopReply(request)
  assert.deepEqual(posted[0], posted[1]); assert.equal(result.operation_id, request.operation_id)
  assert.equal(result.cancellation_confirmed, false); assert.equal(result.state, 'cancel_requested')
})
test('reply control metadata and confirmed status reject cross-scope data and inconsistent completion', async () => {
  const wrong = client(async url => response(url.endsWith('/reply-control-session') ? session
    : { status: 'ready', items: [{ ...replyMetadata, namespace: { bot_id: 'other-bot', persona_id: 'test-persona' } }], next_cursor: null }))
  await assert.rejects(wrong.readReplyControls(scope), { code: 'invalid_response' })
  const request = makeStopReplyRequest(replyMetadata)
  const inconsistent = replyStatus(request.operation_id)
  inconsistent.control.cancellation_confirmed = true
  const api = client(async url => response(url.endsWith('/reply-control-session') ? session : inconsistent))
  await assert.rejects(api.stopReply(request), { code: 'invalid_response' })
})

const projectOptions: ProjectContextOptions = {
  schema: 'd03.owner-artifact-project-context-options.v1', namespace: replyMetadata.namespace,
  catalogue: { head_ref: 'mock-catalogue-head', head_revision: 1, candidate_ref: 'mock-catalogue', roles: ['editor'], norms: ['norm:review'] },
  items: [{ project_ref: 'mock-project', recipe_ref: 'mock-recipe', source_ref: 'mock-task-source',
    c02_operation_id: 'mock-c02', activity_id: 'mock-activity', audience_ref: 'mock-current-audience',
    parent_budget_lease_ref: 'mock-parent-lease', binding_ref: null, social_role: null, norm_refs: [] }],
}
test('owner project choice uses current catalogue and retains the exact uncertain operation payload', async () => {
  const posted: Record<string, unknown>[] = []; let first = true
  const api = client(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    const body = JSON.parse(init.body as string)
    if (body.action === 'read_owner_artifact_project_context_options') return response({status:'ready',projection:projectOptions})
    posted.push(body)
    if (first) { first=false; throw new Error('mock response lost after actual send') }
    return response({status:'ready',receipt:{schema:'d12.domain-operation-receipt.v1',operation_id:body.operation_id,
      action:body.action,input_digest:'a'.repeat(64),original_digest:'b'.repeat(64),original:{operation_id:body.operation_id}}})
  })
  const options = await api.readOwnerProjectContexts(scope), item=options.items[0]!, id=crypto.randomUUID()
  assert.equal(item.social_role,null)
  await assert.rejects(api.adoptOwnerProjectContext(scope,options,item,'editor',['norm:review'],id),{code:'network_unavailable'})
  assert.equal(posted.length,1)
  await api.adoptOwnerProjectContext(scope,options,item,'editor',['norm:review'],id)
  assert.deepEqual(posted[0],posted[1])
  assert.deepEqual(posted[0]!.input,projectContextInput(options,item,'editor',['norm:review']))
  assert.equal(posted[0]!.purpose,'workbench_user_action');assert.equal(posted[0]!.audience,'owner')
})
test('owner project choice rejects foreign namespace and an unselected catalogue role before mutation', async () => {
  const api=client(async url=>response(url.endsWith('/session')?session:{status:'ready',projection:{...projectOptions,
    namespace:{bot_id:'foreign-bot',persona_id:'test-persona'}}}))
  await assert.rejects(api.readOwnerProjectContexts(scope),/目录或范围/)
  assert.throws(()=>projectContextInput(projectOptions,projectOptions.items[0]!,'',[]),/请选择/)
  assert.throws(()=>projectContextInput(projectOptions,projectOptions.items[0]!,'administrator',['norm:review']),/请选择/)
})


test('source cursor pages replace the visible page and refresh from the first page', async () => {
  const inputs: Record<string, unknown>[] = []
  const backend = await controller(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    const command = JSON.parse(init.body as string)
    if (command.action === 'open_workspace') return response(workspace)
    inputs.push(command.input)
    const second = command.input.cursor === 'source-page-2'
    return response({ ...memory, projection: { ...memory.projection, snapshot_epoch: 4,
      data: { ...memory.projection.data, sources: [{ ...memory.projection.data.sources[0]!, source_id: second ? 'page-2-source' : 'page-1-source' }] },
      next_cursor: second ? null : 'source-page-2' } })
  })
  await backend.checkSession(); backend.setScope(scope); await backend.readView('d06.memory_sources.v1')
  assert.equal(backend.viewPaging.page, 1); assert.equal(backend.canNextView.value, true)
  await backend.nextView()
  assert.deepEqual(backend.state.view.data?.data.sources?.map(item => item.source_id), ['page-2-source'])
  assert.equal(backend.viewPaging.page, 2); assert.equal(backend.canNextView.value, false)
  await backend.readView('d06.memory_sources.v1')
  assert.equal(backend.viewPaging.page, 1)
  assert.deepEqual(inputs.map(input => input.cursor ?? null), [null, 'source-page-2', null])
})

test('source cursor pages reject a changed snapshot and late responses after local invalidation', async () => {
  const late = deferred<FetchResponse>(); let pages = 0
  const backend = await controller(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    const command = JSON.parse(init.body as string)
    if (command.action === 'open_workspace') return response(workspace)
    if (++pages === 3) return late.promise
    return response({ ...memory, projection: { ...memory.projection, snapshot_epoch: pages,
      next_cursor: 'source-page-next' } })
  })
  await backend.checkSession(); backend.setScope(scope); await backend.readView('d06.memory_sources.v1')
  await backend.nextView(); assert.equal(backend.state.view.status, 'stale'); assert.equal(backend.state.view.data, null)
  const pending = backend.readView('d06.memory_sources.v1'); await new Promise(done => setTimeout(done, 0))
  backend.invalidateNavigation(); late.resolve(response(memory)); await pending
  assert.equal(backend.state.view.data, null); assert.equal(backend.viewPaging.page, 0)
})

test('mounted network loss clears the Owner session and reconnect requires explicit session verification', async () => {
  const { createRenderer, h } = await import('vue')
  const { useBackend } = await import('./use-backend.ts')
  const savedWindow = Object.getOwnPropertyDescriptor(globalThis, 'window'), savedDocument = Object.getOwnPropertyDescriptor(globalThis, 'document')
  const browserWindow = new EventTarget(), browserDocument = Object.assign(new EventTarget(), { hidden: false })
  Object.defineProperty(globalThis, 'window', { configurable: true, value: browserWindow })
  Object.defineProperty(globalThis, 'document', { configurable: true, value: browserDocument })
  const renderer = createRenderer<object, object>({ insert() {}, remove() {}, createElement: () => ({}), createText: () => ({}), createComment: () => ({}), setText() {}, setElementText() {}, parentNode: () => null, nextSibling: () => null, patchProp() {} })
  let backend!: ReturnType<typeof useBackend>, calls = 0
  const app = renderer.createApp({ setup() {
    backend = useBackend({ enabled: true, origin, fetchImpl: async url => { ++calls; return response(url.endsWith('/session') ? session : { schema_version: 'sylanne.install-status.v1', runtime_stage: 'ready', reason_code: 'none' }) } })
    return () => h('div')
  } })
  try {
    app.mount({}); await backend.checkSession(); backend.setScope(scope); await backend.management.checkRuntime()
    assert.equal(backend.canRead.value, true)
    browserWindow.dispatchEvent(new Event('offline'))
    assert.equal(backend.state.auth, 'locked'); assert.equal(backend.state.dashboard, 'unknown')
    assert.equal(backend.state.workspace.data, null); assert.equal(backend.state.view.data, null)
    const count = calls; assert.equal(await backend.checkSession(), false); assert.equal(calls, count)
    browserWindow.dispatchEvent(new Event('online'))
    assert.equal(backend.state.auth, 'locked'); assert.equal(backend.canRead.value, false); assert.equal(calls, count)
    assert.equal(await backend.checkSession(), true)
  } finally {
    app.unmount()
    if (savedWindow) Object.defineProperty(globalThis, 'window', savedWindow); else Reflect.deleteProperty(globalThis, 'window')
    if (savedDocument) Object.defineProperty(globalThis, 'document', savedDocument); else Reflect.deleteProperty(globalThis, 'document')
  }
})

test('reply control keyset cursor reaches work beyond the first 32 without mixing source cursors', async () => {
  const inputs: unknown[] = [], cursor = JSON.stringify([0, 9, 'reply-31'])
  const first = Array.from({ length: 32 }, (_, index) => ({ ...replyMetadata, cycle_job_ref: 'reply-' + index, job_phase: index === 0 ? 'running' : 'waiting' }))
  const api = client(async (url, init) => {
    if (url.endsWith('/reply-control-session')) return response(session)
    const command = JSON.parse(init.body as string); inputs.push(command.input)
    return response({ status: 'ready', items: command.input.cursor ? [{ ...replyMetadata, cycle_job_ref: 'reply-32', job_phase: 'pending_confirmation' }] : first,
      next_cursor: command.input.cursor ? null : cursor })
  })
  const page = await api.readReplyControls(scope); assert.equal(page.items.length, 32); assert.equal(page.items[0]?.job_phase, 'running')
  const second = await api.readReplyControls(scope, page.next_cursor)
  assert.equal(second.items[0]?.cycle_job_ref, 'reply-32'); assert.equal(second.items[0]?.job_phase, 'pending_confirmation')
  assert.equal(second.next_cursor, null); assert.deepEqual(inputs, [{}, { cursor }])
})


const correctionSourceRef = '["event","test-bot","test-persona","mock-source","memory.source","record"]'
const correctionTargetRef = '["event","test-bot","test-persona","mock-interpretation","memory.interpretation","current"]'
const correctionOperationId = '11111111-2222-4333-8444-555555555555'
const correctionContext = { schema: 'd12.source-correction-context.v1' as const, namespace: { bot_id: 'test-bot', persona_id: 'test-persona' },
  source_refs: [correctionSourceRef], source_revision: 2, source_digest: '1'.repeat(64),
  targets: [{ target_ref: correctionTargetRef, revision: 4, digest: '2'.repeat(64), claim: '没有回复是拒绝' }], access_epoch: 3, deletion_epoch: 2 }
const correctionInput = sourceCorrectionInput(correctionContext, '当时在忙😀', [correctionTargetRef])
const correctionDigest = 'sha256:f3e948371fd42af46df9b56a34e479c8999fc1224be8124fc2cb58d789fa41da' // Independently calculated with the existing Python W01 JSON/hash algorithm.
function correctionReceipt() {
  return { schema: 'd12.source_correction_receipt.v1', phase: 'source_correction_committed', operation_id: correctionOperationId,
    request_digest: correctionDigest, correction_source_ref: 'mock-actual-correction-source', source_refs: [correctionSourceRef], invalidated_target_refs: [correctionTargetRef],
    reevaluation_outbox_ref: 'mock-actual-reevaluation-outbox', audit_event_ref: 'mock-actual-audit', graph_revision: 7, access_epoch: 3, deletion_epoch: 2 }
}

test('source correction reads actual row ID and submits exact Owner-bound W01 command with Python Unicode digest', async () => {
  const commands: Record<string, any>[] = []
  const api = client(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    const command = JSON.parse(init.body as string); commands.push(command)
    return response(command.action === 'read_source_correction_context_v1' ? { status: 'ready', projection: correctionContext } : { status: 'ready', receipt: correctionReceipt() })
  })
  const context = await api.readSourceCorrectionContext(scope, 'mock-source')
  assert.deepEqual(commands[0]!.input, { source_id: 'mock-source' }); assert.equal(commands[0]!.purpose, 'workbench_user_action')
  assert.equal(await sourceCorrectionRequestDigest(scope, correctionInput, correctionOperationId), correctionDigest)
  const receipt = await api.submitSourceCorrection(scope, sourceCorrectionInput(context, '当时在忙😀', [correctionTargetRef]), correctionOperationId)
  assert.equal(receipt.phase, 'source_correction_committed'); assert.equal(receipt.reevaluation_outbox_ref, 'mock-actual-reevaluation-outbox')
  assert.equal(commands[1]!.action, 'correct_or_edit'); assert.equal(commands[1]!.operation_id, correctionOperationId)
  assert.deepEqual(commands[1]!.input, correctionInput); assert.equal(commands[1]!.audience, 'owner')
})

test('source correction rejects foreign refs, unsupported targets, unselected targets and mismatched receipt', async () => {
  assert.throws(() => validateSourceCorrectionContext(correctionContext, 'other-bot/test-persona', 'mock-source'))
  assert.throws(() => validateSourceCorrectionContext(correctionContext, scope, 'other-source'))
  assert.throws(() => validateSourceCorrectionContext({ ...correctionContext, targets: [{ ...correctionContext.targets[0]!, target_ref: '["event","test-bot","test-persona","belief","d07.belief_revision.v1","current"]' }] }, scope, 'mock-source'))
  assert.throws(() => sourceCorrectionInput(correctionContext, '说明', [])); assert.throws(() => sourceCorrectionInput(correctionContext, '说明', ['unselected-target']))
  const empty = validateSourceCorrectionContext({ ...correctionContext, targets: [] }, scope, 'mock-source'); assert.equal(empty.targets.length, 0)
  const api = client(async url => response(url.endsWith('/session') ? session : { status: 'ready', receipt: { ...correctionReceipt(), request_digest: 'sha256:' + '3'.repeat(64) } }))
  await assert.rejects(api.submitSourceCorrection(scope, correctionInput, correctionOperationId), { code: 'invalid_response' })
})

test('source correction unknown result explicitly replays the original request and navigation keeps metadata without statement', async () => {
  const posts: unknown[] = []; let failed = true
  const backend = await controller(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    const command = JSON.parse(init.body as string); posts.push(command)
    if (failed) { failed = false; return response({ problem: { code: 'source_correction_outcome_unknown' } }, 500) }
    return response({ status: 'ready', receipt: correctionReceipt() })
  })
  await backend.checkSession(); backend.setScope(scope)
  backend.sourceCorrections.pending.value = { scope, sourceId: 'mock-source', operationId: correctionOperationId, requestDigest: correctionDigest,
    input: { schema: correctionInput.schema, correction_kind: correctionInput.correction_kind, source_refs: [...correctionInput.source_refs],
      target_refs: [...correctionInput.target_refs], access_epoch: correctionInput.access_epoch, deletion_epoch: correctionInput.deletion_epoch } }
  await assert.rejects(backend.sourceCorrections.submit(scope, correctionInput, correctionOperationId))
  backend.invalidateNavigation(); assert.equal(backend.sourceCorrections.pending.value?.operationId, correctionOperationId)
  assert.equal('statement' in backend.sourceCorrections.pending.value!.input, false)
  const receipt = await backend.sourceCorrections.submit(scope, correctionInput, correctionOperationId)
  assert.equal(receipt.operation_id, correctionOperationId); assert.deepEqual(posts[0], posts[1])
  await backend.logout(); assert.equal(backend.sourceCorrections.pending.value, null)
})


const projectPauseId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', projectResumeId = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff'
const mockControlContext = { schema: 'd12.project-control-context.v1' as const, namespace: { bot_id: 'test-bot', persona_id: 'test-persona' },
  project_ref: 'project:mock', plan_ref: 'plan:mock', plan_revision: 7, goal_ref: 'goal:mock', goal_state: 'active', plan_state: 'active' as const,
  pause_original_ref: null, permitted_controls: ['pause_project_v1'] as ProjectControlAction[], execution_summary: { inflight: 1, unknown: 0, settlement_pending: 1 },
  resume_preview: { state: null, reasons: [] as string[] }, graph_revision: 12, context_digest: '25a28bf164a18921c322dff1e59b7004e973197220a4795f4ae32be99b9e67d8' }
async function mockProjectReceipt(action: ProjectControlAction, input: ProjectControlInput, operationId: string, noop = false) {
  const pause = action === 'pause_project_v1', before = pause ? 'active' : 'paused', after = noop ? before : pause ? 'paused' : 'waiting'
  const control = { schema: 'd08.project-control-original.v1', project_ref: input.project_ref, plan_ref: input.plan_ref, control: pause ? 'pause' : 'resume',
    before_plan_revision: input.expected_plan_revision, after_plan_revision: input.expected_plan_revision + (noop ? 0 : 1),
    before_plan_state: before, after_plan_state: after, before_plan: { schema: 'd08.personal_plan.v1', state: before }, after_plan: { schema: 'd08.personal_plan.v1', state: after },
    pause_origin: pause ? operationId : input.pause_original_ref, noop, execution_summary: { inflight: 1, unknown: noop ? 1 : 0, settlement_pending: 1 }, control_original_ref: operationId }
  const commit = { status: 'committed', operation_id: operationId, operation_digest: 'a'.repeat(64), activity_id: 'mock-project-control', effect_id: null,
    commit_seq: 10, read_versions: [], write_versions: [], invalidated_epochs: [], ledger_refs: [], outbox_refs: [] }
  const payload = { schema: 'd08.current-' + action + '.v1', request: input, namespace: mockControlContext.namespace,
    identity: { activity_id: 'mock-project-control', effect_id: null, phase: 'project-control', attempt_id: 'project-control', operation_id: operationId, canonical_input_digest: 'c'.repeat(64) },
    authority: {}, parent_budget: null, now_utc: 1.0, owner_guard: {}, policy_refs: [], read_versions: [], query_coverage: [], observed_originals: [],
    provenance: { project_control: control }, writes: [], coverage: noop ? 'partial' : 'complete', missing_inputs: noop ? ['actual_wait_condition_missing'] : [], continuation_ref: null }
  const original = { schema: 'sylanne.domain-production-receipt.v1', domain: 'd08', operation_kind: action, operation_id: operationId, activity_id: 'mock-project-control',
    original_ref: 'd08-current:controlled-fixture', original_digest: 'b'.repeat(64), receipt: commit, receipt_digest: 'd'.repeat(64), job_states: [], coverage: payload.coverage,
    missing_inputs: payload.missing_inputs, continuation_ref: null, outbox: [], produced_originals: [],
    actual_original: { domain: 'd08', operation_kind: action, request_digest: 'e'.repeat(64), original_digest: 'b'.repeat(64), payload, read_versions: [], receipt: commit } }
  return { schema: 'd12.project-control-receipt.v1', operation_id: operationId, action, input_digest: await projectControlDigest(input), original_digest: 'f'.repeat(64), original }
}

test('project control binds actual context commitment and fresh Plan CAS to pause and resume originals', async () => {
  const posted: Record<string, any>[] = []; let paused = false
  const api = client(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    const command = JSON.parse(init.body as string); posted.push(command)
    if (command.action === 'read_project_control_context_v1') {
      const { context_digest: _digest, ...base } = mockControlContext
      const current = paused ? { ...base, plan_state: 'paused', plan_revision: 8, pause_original_ref: projectPauseId,
        permitted_controls: ['resume_project_v1'], resume_preview: { state: 'waiting', reasons: ['actual_wait_required'] } } : base
      return response({ status: 'ready', projection: { ...current, context_digest: await projectControlDigest(current) } })
    }
    if (command.action === 'pause_project_v1') paused = true
    return response({ status: 'ready', receipt: await mockProjectReceipt(command.action, command.input, command.operation_id) })
  })
  const context = await api.readProjectControlContext(scope, mockControlContext.project_ref)
  assert.equal(context.context_digest, mockControlContext.context_digest) // Independent Python integer/string-only context commitment.
  const pause = await api.submitProjectControl(scope, 'pause_project_v1', projectControlInput(context, 'pause_project_v1'), projectPauseId)
  assert.equal(pause.control.after_plan_state, 'paused'); assert.equal(pause.control.execution_summary.inflight, 1)
  const fresh = await api.readProjectControlContext(scope, mockControlContext.project_ref)
  const resumeInput = projectControlInput(fresh, 'resume_project_v1')
  assert.equal(resumeInput.expected_plan_revision, 8); assert.equal(resumeInput.pause_original_ref, projectPauseId)
  const resumed = await api.submitProjectControl(scope, 'resume_project_v1', resumeInput, projectResumeId)
  assert.equal(resumed.control.after_plan_state, 'waiting')
  assert.deepEqual(posted[0]!.input, { project_ref: mockControlContext.project_ref })
  for (const command of posted) { assert.equal(command.purpose, 'workbench_user_action'); assert.equal(command.audience, 'owner') }
})

test('project control rejects altered context, wrong project provenance and mismatched input digest; blocked resume remains paused', async () => {
  await assert.rejects(validateProjectControlContext(mockControlContext, 'other-bot/test-persona', mockControlContext.project_ref))
  await assert.rejects(validateProjectControlContext({ ...mockControlContext, plan_revision: 9 }, scope, mockControlContext.project_ref))
  const input = { project_ref: mockControlContext.project_ref, plan_ref: mockControlContext.plan_ref, expected_plan_revision: 8, pause_original_ref: projectPauseId }
  const blocked = await mockProjectReceipt('resume_project_v1', input, projectResumeId, true)
  const api = client(async url => response(url.endsWith('/session') ? session : { status: 'ready', receipt: blocked }))
  const result = await api.submitProjectControl(scope, 'resume_project_v1', input, projectResumeId)
  assert.equal(result.control.noop, true); assert.equal(result.control.after_plan_state, 'paused'); assert.equal(result.control.execution_summary.unknown, 1)
  const wrong = structuredClone(blocked); wrong.original.actual_original.payload.provenance.project_control.project_ref = 'other-project'
  const bad = client(async url => response(url.endsWith('/session') ? session : { status: 'ready', receipt: wrong }))
  await assert.rejects(bad.submitProjectControl(scope, 'resume_project_v1', input, projectResumeId), { code: 'invalid_response' })
  const mismatch = client(async url => response(url.endsWith('/session') ? session : { status: 'ready', receipt: { ...blocked, input_digest: '0'.repeat(64) } }))
  await assert.rejects(mismatch.submitProjectControl(scope, 'resume_project_v1', input, projectResumeId), { code: 'invalid_response' })
})

test('project control unknown explicitly keeps its original CAS request and stale rejection never auto-resubmits', async () => {
  const posts: unknown[] = [], input = { project_ref: mockControlContext.project_ref, plan_ref: mockControlContext.plan_ref, expected_plan_revision: 7 }
  const backend = await controller(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    const command = JSON.parse(init.body as string); posts.push(command)
    return posts.length === 1 ? response({ problem: { code: 'project_control_outcome_unknown' } }, 500)
      : response({ status: 'ready', receipt: await mockProjectReceipt('pause_project_v1', input, projectPauseId) })
  })
  await backend.checkSession(); backend.setScope(scope)
  backend.projectControls.pending.value = { scope, action: 'pause_project_v1', operationId: projectPauseId, input }
  await assert.rejects(backend.projectControls.submit(scope, 'pause_project_v1', input, projectPauseId)); assert.equal(posts.length, 1)
  backend.invalidateNavigation(); assert.equal(backend.projectControls.pending.value?.input.expected_plan_revision, 7)
  await backend.projectControls.submit(scope, 'pause_project_v1', input, projectPauseId); assert.deepEqual(posts[0], posts[1])
  const stale = client(async url => response(url.endsWith('/session') ? session : { status: 'stale', problem: { code: 'project_control_basis_changed', retryable: false } }))
  await assert.rejects(stale.submitProjectControl(scope, 'pause_project_v1', input, projectPauseId), { code: 'project_control_basis_changed' })
  await backend.logout(); assert.equal(backend.projectControls.pending.value, null)
})


test('owner artifact V2 reads only actual option selectors and verifies complete base64 bytes before plaintext', async () => {
  const text = '<script>只能作为文本</script>\n真实受控文件内容', bytes = Buffer.from(text, 'utf8'), digest = await crypto.subtle.digest('SHA-256', bytes)
  const hash = Buffer.from(digest).toString('hex'), projectRef = 'project:controlled-artifact', item = { progress_ref: 'progress:controlled', artifact_ref: 'artifact:controlled', artifact_version: 2, content_digest: hash, content_length_bytes: bytes.length }
  const options = { schema: 'd12.owner-artifact-options.v1', namespace: { bot_id: 'test-bot', persona_id: 'test-persona' }, project_ref: projectRef, items: [item] }
  const projection = { schema: 'd12.owner-artifact-read-result.v2', namespace: options.namespace, installation_id: 'mock-install', project_ref: projectRef, ...item,
    content_type: 'text/plain; charset=utf-8', body_encoding: 'base64', body_base64: bytes.toString('base64') }
  const posts: Record<string, any>[] = []
  const api = client(async (url, init) => { if (url.endsWith('/session')) return response(session); const command = JSON.parse(init.body as string); posts.push(command)
    return response({ status: 'ready', projection: command.action === 'read_owner_project_artifact_options_v1' ? options : projection }) })
  const choices = await api.readOwnerArtifactOptions(scope, projectRef), body = await api.readOwnerArtifactBody(scope, choices, choices.items[0]!)
  assert.equal(body.body, text); assert.equal(body.content_digest, hash); assert.equal(body.content_length_bytes, bytes.length)
  assert.deepEqual(posts[0]!.input, { project_ref: projectRef })
  assert.deepEqual(posts[1]!.input, { project_ref: projectRef, progress_ref: item.progress_ref, expected_artifact_version: 2, expected_content_digest: hash })
  for (const command of posts) { assert.equal(command.purpose, 'workbench_view'); assert.equal(command.audience, 'owner'); assert.equal('path' in command.input, false); assert.equal('namespace' in command.input, false) }
  const badHash = client(async url => response(url.endsWith('/session') ? session : { status: 'ready', projection: { ...projection, body_base64: Buffer.from('different').toString('base64') } }))
  await assert.rejects(badHash.readOwnerArtifactBody(scope, choices, choices.items[0]!), { code: 'invalid_response' })
  const privateData = client(async url => response(url.endsWith('/session') ? session : { status: 'ready', projection: { ...projection, read_binding: {} } }))
  await assert.rejects(privateData.readOwnerArtifactBody(scope, choices, choices.items[0]!), { code: 'invalid_response' })
})

test('owner artifact V2 does not fall back on stale/missing bodies, V1 text or invalid UTF8', async () => {
  const data = Buffer.from([255]), hash = Buffer.from(await crypto.subtle.digest('SHA-256', data)).toString('hex')
  const options = { schema: 'd12.owner-artifact-options.v1' as const, namespace: { bot_id: 'test-bot', persona_id: 'test-persona' }, project_ref: 'project:controlled',
    items: [{ progress_ref: 'progress:controlled', artifact_ref: 'artifact:controlled', artifact_version: 1, content_digest: hash, content_length_bytes: 1 }] }
  const projection = { schema: 'd12.owner-artifact-read-result.v2', namespace: options.namespace, installation_id: 'mock-install', project_ref: options.project_ref, ...options.items[0]!,
    content_type: 'text/plain; charset=utf-8', body_encoding: 'base64', body_base64: data.toString('base64') }
  const invalid = client(async url => response(url.endsWith('/session') ? session : { status: 'ready', projection }))
  await assert.rejects(invalid.readOwnerArtifactBody(scope, options, options.items[0]!), { code: 'invalid_response' })
  const legacy = client(async url => response(url.endsWith('/session') ? session : { status: 'ready', projection: { ...projection, schema: 'd12.owner-artifact-read-result.v1', body: 'cached' } }))
  await assert.rejects(legacy.readOwnerArtifactBody(scope, options, options.items[0]!), { code: 'invalid_response' })
  let posts = 0
  const missing = client(async url => { if (url.endsWith('/session')) return response(session); ++posts; return response({ status: 'stale', problem: { code: 'artifact_version_unavailable', retryable: false } }) })
  await assert.rejects(missing.readOwnerArtifactBody(scope, options, options.items[0]!), { code: 'artifact_version_unavailable' }); assert.equal(posts, 1)
})

test('reply metadata V2 preserves accepted/read-unknown, predecessor hold and actual pending fees without double counting', async () => {
  const fee = { settlement_ref: 'fee:parent', status: 'pending_confirmation', currency: 'USD', actual: null, unconfirmed: { usd_micros: 9 } }
  const child = { index: 0, operation_id: 'child:0', effect_id: 'effect:0', actual_intent_ref: 'intent:0', admission_ref: 'admission:0', continuation_state: 'ready', reason_code: null,
    authority_state: 'observed', observation_outcome: 'accepted', observation_ref: 'observation:0', read_state: 'unknown', fees: [] as unknown[] }
  const row = { ...replyMetadata, schema: 'd12.owner-reply-control-metadata.v2', natural_batch: { schema: 'd12.natural-batch-metadata.v1', parent_original_id: replyMetadata.c02_operation_id,
    roster_revision: 1, details_state: 'adopted', parent_fees: [fee], children: [child, { ...child, index: 1, operation_id: 'child:1', effect_id: 'effect:1', actual_intent_ref: null, admission_ref: null,
      continuation_state: 'held', reason_code: 'predecessor_unknown', authority_state: 'unresolved', observation_outcome: null, observation_ref: null }] } }
  const make = (value: unknown) => client(async url => response(url.endsWith('/reply-control-session') ? session : { status: 'ready', items: [value], next_cursor: null }))
  const page = await make(row).readReplyControls(scope), batch = page.items[0]!.natural_batch!
  assert.equal(batch.children[0]!.observation_outcome, 'accepted'); assert.equal(batch.children[0]!.read_state, 'unknown'); assert.equal(batch.children[1]!.reason_code, 'predecessor_unknown')
  assert.equal(batch.parent_fees[0]!.actual, null); assert.equal(batch.parent_fees[0]!.unconfirmed.usd_micros, 9)
  const unavailable = { ...row, natural_batch: { ...row.natural_batch, details_state: 'bubble_details_unavailable', roster_revision: null, children: [] } }
  const held = await make(unavailable).readReplyControls(scope)
  assert.equal(held.items[0]!.natural_batch!.details_state, 'bubble_details_unavailable')
  assert.equal(held.items[0]!.natural_batch!.parent_fees[0]!.unconfirmed.usd_micros, 9)
  assert.equal(held.items[0]!.natural_batch!.children.length, 0)
  await assert.rejects(make({ ...unavailable, natural_batch: { ...unavailable.natural_batch, children: [child] } }).readReplyControls(scope), { code: 'invalid_response' })

  const duplicate = structuredClone(row); duplicate.natural_batch.children[0]!.fees = [fee]
  await assert.rejects(make(duplicate).readReplyControls(scope), { code: 'invalid_response' })
  const falselyRead = structuredClone(row); falselyRead.natural_batch.children[0]!.read_state = 'read'
  await assert.rejects(make(falselyRead).readReplyControls(scope), { code: 'invalid_response' })
  await assert.rejects(make({ ...row, body: 'private text' }).readReplyControls(scope), { code: 'invalid_response' })
})

test('relations rich projection preserves scoped dimensions and unknown estimates without exposing private context', async () => {
  const rich = { dimension: 'trust', domain: 'collaboration', context_id: 'a'.repeat(32), status: 'available', availability: 'available',
    time_status: 'current', source_qualification: 'qualified', estimate: -0.25, subjective_confidence: 0.6, evidence_coverage: 'partial',
    independent_external_families: 2, influence_status: 'bounded_applied' }
  const unknown = { ...rich, context_id: 'b'.repeat(32), status: 'unknown', availability: 'unknown', time_status: 'time_unavailable',
    estimate: 'unknown', subjective_confidence: null, influence_status: 'unapplied_pending' }
  const legacy = { dimension: 'rapport', status: 'unknown', availability: 'unknown', source_qualification: 'unknown', estimate: 'unknown', influence_status: 'legacy_unresolved' }
  const projection = { namespace: { bot: 'test-bot', persona: 'test-persona' }, access_generation: 1, snapshot_epoch: 2, view_type: 'relations',
    data: { relations: [{ subject_entity_ref: 'entity:colleague', dimensions: [rich, unknown, legacy] }], coverage: 'complete' },
    coverage: { requested_types: ['d05.dimension_estimate.v2'], returned_atoms: 3, truncated: true }, next_cursor: 'real-opaque-cursor' }
  const posts: any[] = []
  const api = client(async (url, init) => { if (url.endsWith('/session')) return response(session); posts.push(JSON.parse(init.body as string)); return response({ status: 'ready', projection }) })
  const first = await api.readRelationsView(scope), dimensions = first.projection!.data.relations[0]!.dimensions
  assert.equal(dimensions.length, 3); assert.equal(dimensions[0]!.estimate, -0.25); assert.equal(dimensions[1]!.estimate, 'unknown'); assert.equal(dimensions[1]!.subjective_confidence, null)
  await api.readRelationsView(scope, first.projection!.next_cursor!)
  assert.deepEqual(posts[1].input, { view_type: 'relations', page_size: 100, cursor: 'real-opaque-cursor' })
  assert.equal(posts[1].purpose, 'workbench_view'); assert.equal(posts[1].audience, 'owner')
  const make = (value: unknown) => client(async url => response(url.endsWith('/session') ? session : { status: 'ready', projection: value }))
  await assert.rejects(make({ ...projection, namespace: { bot: 'other', persona: 'test-persona' } }).readRelationsView(scope), { code: 'invalid_response' })
  const exposed = structuredClone(projection); Object.assign(exposed.data.relations[0]!.dimensions[0]!, { context_ref: 'private-source-context' })
  await assert.rejects(make(exposed).readRelationsView(scope), { code: 'invalid_response' })
  const numericUnknown = structuredClone(projection); numericUnknown.data.relations[0]!.dimensions[1]!.estimate = 0.5
  await assert.rejects(make(numericUnknown).readRelationsView(scope), { code: 'invalid_response' })
})


test('L05 v2 observes shared ledger without double-charging allocations and withholds stale next-step authority', async () => {
  const { context_digest: oldDigest, ...base } = mockControlContext
  const pool = { scope: 'shared_parent_pool', lease_ref: 'actual-project-parent', lease_version: 5, state: 'active', currency: 'USD',
    grant_ref: 'actual-current-grant', grant_version: 3, grant_expires_utc: '2026-10-08T00:00:00Z', qualification_state: 'hold',
    allocation_coverage: 'complete', dimensions: [{ dimension: 'model_tokens', unit: 'model_tokens', limit: 1000, grant_ceiling: 100,
      spent: 100, reserved: 300, unconfirmed: 200, allocated: 250, remaining: 400 }] }
  const observed = { ...base, schema: 'd12.project-control-context.v2',
    checkpoint: { checkpoint_ref: 'actual-checkpoint', revision: 2, plan_revision: 6, state: 'waiting', basis_status: 'stale', wait_reason: 'actual_outcome_pending' },
    next_step: null, pending_effects: { refs: ['actual-pending-effect'], total_count: 1, truncated: false }, budget: pool,
    missing: ['checkpoint_plan_basis_stale_requires_reevaluation', 'current_budget_or_grant_inactive_or_expired'] }
  const signed = async (value: unknown) => ({ ...(value as Record<string, unknown>), context_digest: await projectControlDigest(value) })
  const posted: Record<string, any>[] = []
  const api = client(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    posted.push(JSON.parse(String(init.body)))
    return response({ status: 'ready', projection: await signed(observed) })
  })
  const current = await api.readProjectControlContextV2(scope, base.project_ref)
  assert.equal(posted[0]!.action, 'read_project_control_context_v2'); assert.deepEqual(posted[0]!.input, { project_ref: base.project_ref })
  assert.equal(current.next_step, null); assert.equal(current.budget!.qualification_state, 'hold')
  assert.equal(current.budget!.dimensions[0]!.remaining, 400); assert.equal(current.budget!.dimensions[0]!.allocated, 250)
  assert.equal(current.budget!.dimensions[0]!.unconfirmed, 200)
  const absent = await validateProjectControlContextV2(await signed({ ...observed, budget: null, missing: ['project_original_budget_origin_missing'] }), scope, base.project_ref)
  assert.equal(absent.budget, null)
  const partial = await validateProjectControlContextV2(await signed({ ...observed, budget: { ...pool, qualification_state: 'unknown', allocation_coverage: 'partial',
    dimensions: [{ ...pool.dimensions[0], allocated: null }] } }), scope, base.project_ref)
  assert.equal(partial.budget!.dimensions[0]!.allocated, null)
  await assert.rejects(validateProjectControlContextV2(await signed({ ...observed, next_step: { node_ref: 'task:old', action_kind: 'draft', depends_on: [], wait_condition: null } }), scope, base.project_ref))
  await assert.rejects(validateProjectControlContextV2(await signed({ ...observed, budget: { ...pool, dimensions: [{ ...pool.dimensions[0], remaining: 150 }] } }), scope, base.project_ref))
  await assert.rejects(validateProjectControlContextV2(await signed({ ...observed, budget: { ...pool, allocation_coverage: 'partial' } }), scope, base.project_ref))
  await assert.rejects(validateProjectControlContextV2(await signed({ ...observed, namespace: { bot_id: 'other', persona_id: 'test-persona' } }), scope, base.project_ref))
  await assert.rejects(validateProjectControlContextV2({ ...await signed(observed), budget: null }, scope, base.project_ref))
  await assert.rejects(validateProjectControlContextV2(mockControlContext, scope, base.project_ref))
})


test('Owner SourceNote uses nine selector scalars and reconciles lost acknowledgement by original UUID without resubmission', async () => {
  // Controlled wire fixture only: no true Owner, Source, paid or execution qualification.
  const ref = (kind: string, name: string) => JSON.stringify(['event','test-bot','test-persona',name,kind,'record'])
  const projectRef = ref('d10.life_project.v1','mock-owner-project')
  const row = { body_source_ref:ref('memory.source','mock-owner-source'),recipe_ref:ref('d10.activity_recipe.v1','mock-recipe'),
    target_entity_ref:ref('d03.entity_anchor','mock-target'),role_binding_ref:ref('d03.role_binding','mock-role'),
    body_policy_id:'mock-registered-note-policy',body_policy_version:1,effect_policy_ref:'mock-effect-policy' }
  const projected = { schema:'d12.owner-source-note-task-options.v1',namespace:{bot_id:'test-bot',persona_id:'test-persona'},
    project_ref:projectRef,observed_utc:1790000000,deadline_upper_bound_utc:1790000300,items:[row] }
  const operationId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', posted: Record<string, any>[] = []
  let publicDigest = '', submissions = 0
  const api = client(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    const command = JSON.parse(String(init.body)); posted.push(command)
    if (command.action === 'read_owner_source_note_task_options_v1') return response({status:'ready',projection:projected})
    if (command.action === 'domain_submit_owner_source_note_task_v1') {
      ++submissions; throw new Error('controlled lost response after mutation boundary')
    }
    assert.equal(command.action,'read_owner_source_note_task_status_v1')
    return response({status:'ready',projection:{schema:'d12.owner-source-note-task-status.v1',
      namespace:projected.namespace,owner_operation_id:operationId,input_digest:publicDigest,state:'pending_start',
      job_id:null,job_phase:null,step:null,wait_reason:null,pending_effect_refs:[],original_deadline_utc:1790000200,observed_utc:1790000001}})
  })
  const options = await api.readOwnerTaskOptions(scope,projectRef), request = ownerTaskRequest(options,options.items[0]!,1790000200)
  publicDigest = await ownerTaskInputDigest(request)
  await assert.rejects(api.submitOwnerSourceNoteTask(scope,request,operationId),{code:'network_unavailable'})
  const status = await api.readOwnerSourceNoteTaskStatus(scope,operationId,publicDigest)
  assert.equal(status.state,'pending_start'); assert.equal(submissions,1)
  assert.equal(posted[0]!.purpose,'workbench_view'); assert.equal(posted[2]!.purpose,'workbench_view')
  assert.equal(posted[1]!.purpose,'workbench_user_action')
  assert.deepEqual(Object.keys(posted[1]!.input),['request'])
  assert.equal(Object.keys(posted[1]!.input.request).length,9)
  assert.equal(posted[1]!.operation_id,operationId)
  assert.deepEqual(posted[2]!.input,{owner_operation_id:operationId,input_digest:publicDigest})
  assert.notEqual(posted[2]!.operation_id,operationId)
  await assert.rejects(api.submitOwnerSourceNoteTask(scope,{...request,parent_budget_lease_ref:'forged-root'} as typeof request,operationId),{code:'invalid_response'})
  assert.equal(submissions,1)
  assert.throws(()=>validateOwnerTaskOptions({...projected,items:[{...row,role_binding_ref:JSON.stringify(['event','other','test-persona','role','d03.role_binding','record'])}]},scope,projectRef))
  assert.throws(()=>validateOwnerTaskStatus({...status,input_digest:'0'.repeat(64)},scope,operationId,publicDigest))
  const original = {schema:'sylanne.domain-production-receipt.v1',domain:'d08',operation_kind:'submit_owner_source_note_task_v1',
    operation_id:operationId,activity_id:'mock-owner-task',original_ref:'mock-domain-original',original_digest:'1'.repeat(64),
    receipt:{status:'committed',commit_seq:1},receipt_digest:'2'.repeat(64),job_states:[],coverage:'complete',missing_inputs:[],
    continuation_ref:null,outbox:['mock-task-event'],produced_originals:[]}
  const receipt = {schema:'d12.domain-operation-receipt.v1',operation_id:operationId,action:'domain_submit_owner_source_note_task_v1',
    input_digest:publicDigest,original_digest:'3'.repeat(64),original}
  assert.equal((await validateOwnerTaskReceipt(receipt,operationId,request)).original,original)
  await assert.rejects(validateOwnerTaskReceipt({...receipt,input_digest:'0'.repeat(64)},operationId,request))
  await assert.rejects(validateOwnerTaskReceipt({...receipt,original:{...original,operation_kind:'other_operation'}},operationId,request))
})


test('Owner material keeps exact Unicode text and original UUID while rejecting oversized commands before dispatch', async () => {
  // Controlled metadata fixture only; no true Source adoption/Owner/install/Body claim.
  const content = '  我提供的材料😀\n保留\t原文。  ', operationId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
  const inputDigest = await ownerMaterialInputDigest(content), posted: Record<string, any>[] = []
  let mutations = 0
  const sourceId = 'mock-actual-material', sourceRef = JSON.stringify(['event','test-bot','test-persona',sourceId,'memory.source','record'])
  const status = { schema:'d12.owner-material-source-status.v1',namespace:{bot_id:'test-bot',persona_id:'test-persona'},
    owner_operation_id:operationId,input_digest:inputDigest,state:'accepted',source_ref:sourceRef,source_id:sourceId,source_revision:1,observed_utc:1790000000 }
  const api = client(async (url, init) => {
    if (url.endsWith('/session')) return response(session)
    const command = JSON.parse(String(init.body)); posted.push(command)
    if (command.action === 'domain_admit_owner_material_source_v1') { ++mutations; throw new Error('controlled lost material acknowledgement') }
    assert.equal(command.action,'read_owner_material_source_status_v1')
    return response({status:'ready',projection:status})
  })
  assert.equal(await api.prepareOwnerMaterialSubmission(scope,content,operationId),inputDigest)
  await assert.rejects(api.prepareOwnerMaterialSubmission(scope,'x'.repeat(65536),operationId),{code:'invalid_input'})
  assert.equal(posted.length,0)
  assert.throws(()=>validateOwnerMaterialText('   \n\t'))
  assert.throws(()=>validateOwnerMaterialText('😀'.repeat(65537)))
  await assert.rejects(api.submitOwnerMaterial(scope,content,operationId),{code:'network_unavailable'})
  const found = await api.readOwnerMaterialStatus(scope,operationId,inputDigest)
  assert.equal(found.source_ref,sourceRef); assert.equal(mutations,1)
  assert.deepEqual(posted[0]!.input,{request:{text:content}})
  assert.equal(posted[0]!.operation_id,operationId); assert.equal(posted[0]!.purpose,'workbench_user_action')
  assert.deepEqual(posted[1]!.input,{owner_operation_id:operationId,input_digest:inputDigest})
  assert.equal(posted[1]!.purpose,'workbench_view'); assert.notEqual(posted[1]!.operation_id,operationId)
  assert.throws(()=>validateOwnerMaterialStatus({...status,source_id:'other-id'},scope,operationId,inputDigest))
  assert.throws(()=>validateOwnerMaterialStatus({...status,state:'unknown'},scope,operationId,inputDigest))
  assert.throws(()=>validateOwnerMaterialStatus({...status,input_digest:'0'.repeat(64)},scope,operationId,inputDigest))
})
