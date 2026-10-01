import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'

const html = await readFile(new URL('../../../../webui-heritage/dist/index.html', import.meta.url))
const prefix = '/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1'
let readDelayMs = 0
const json = (response, status, value, headers = {}) => {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers })
  response.end(JSON.stringify(value))
}

const server = createServer(async (request, response) => {
  if (request.method === 'GET' && request.url?.startsWith('/__test/view-delay')) {
    const delay = Number(new URL(request.url, 'http://127.0.0.1').searchParams.get('ms'))
    readDelayMs = Number.isFinite(delay) ? Math.max(0, Math.min(3000, delay)) : 0
    response.writeHead(204).end()
    return
  }
  if (request.method === 'GET' && request.url === `${prefix}/status`) {
    return json(response, 200, { schema_version: 'sylanne.install-status.v1', runtime_stage: 'ready', reason_code: 'none' })
  }
  if (request.method === 'GET' && request.url === `${prefix}/session`) {
    return json(response, 200, { status: 'ready', dashboard_session: 'authenticated', owner_session: 'unlocked', csrf_token: 'stub-csrf' }, {
      'set-cookie': 'sylanne_owner_session=browser-test-session; HttpOnly; SameSite=Strict; Path=/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1',
    })
  }
  if (request.method === 'POST' && request.url === `${prefix}/commands`) {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    let body
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { return json(response, 400, { status: 'unavailable', problem: { code: 'invalid_json' } }) }
    if (request.headers['x-csrf-token'] !== 'stub-csrf'
      || !request.headers.cookie?.includes('sylanne_owner_session=browser-test-session')
      || body?.schema_version !== 'd12.contract.v1' || body?.scope !== 'demo-bot/demo-persona'
      || body?.purpose !== 'workbench_view' || body?.audience !== 'owner') {
      return json(response, 403, { status: 'unauthorized', problem: { code: 'test_contract_mismatch', message: 'stub rejected request contract' } })
    }
    if (body.action === 'open_workspace') return json(response, 200, {
      status: 'ready', projection: {
        namespace: { bot: 'demo-bot', persona: 'demo-persona' }, access_generation: 3,
        views: [{ view_type: 'overview', status: 'available', snapshot_epoch: 12 },
          { view_type: 'memory', status: 'unavailable' }],
        view_diagnostics: [{ view_type: 'overview', read_status: 'ready', coverage: 'complete', snapshot_epoch: 12 }],
        unavailable_domains: { memory: 'provider_not_installed' },
      },
    })
    if (body.action === 'read_character_view' && body.input?.view_type === 'overview' && !('page_size' in body.input)) {
      if (readDelayMs > 0) await new Promise(resolve => setTimeout(resolve, readDelayMs))
      return json(response, 200, {
      status: 'ready', projection: {
        view_type: 'overview', namespace: { bot: 'demo-bot', persona: 'demo-persona' }, access_generation: 3,
        snapshot_epoch: 12, coverage: { requested_types: ['d01.persona_plan.v1'], returned_atoms: 1, truncated: false }, next_cursor: null,
        data: { summary: 'Stubbed W10 projection', credential_token: 'must-not-render', sections: [{ title: 'Visible section', debug_dump: 'must-not-render', body: 'Bounded preview' }] },
      },
      })
    }
    return json(response, 400, { status: 'unavailable', problem: { code: 'test_action_mismatch' } })
  }
  if (request.method === 'GET') {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
    return response.end(html)
  }
  response.writeHead(404).end()
})

server.listen(4175, '127.0.0.1', () => process.stdout.write('W10 preview stub listening at http://127.0.0.1:4175/\n'))
