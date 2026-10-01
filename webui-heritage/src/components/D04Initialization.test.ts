import { describe, it, expect } from 'vitest'
import { createSSRApp } from 'vue'
import { renderToString } from 'vue/server-renderer'
import D04Initialization from './D04Initialization.vue'
import { readFileSync } from 'node:fs'

describe('packaged explicit D04 initialization', () => {
  it('renders locked controls with all seven real command choices and no adopted defaults', async () => {
    const html = await renderToString(createSSRApp(D04Initialization, {scope:'bot/persona', csrf:'', sessionEpoch:0}))
    expect(html).toContain('OWNER LOCKED')
    expect(html).toMatch(/<fieldset disabled/)
    for (const action of ['d04_root_draft','d04_root_budget','compile_scheme','activate_scheme','d04_root_coupling','d04_semantic_mapping','d11_role_clock']) expect(html).toContain(`value="${action}"`)
    expect(html).not.toContain(' checked')
    expect(html).not.toContain('value="1"')
  })
  it('production bundle includes real initialization commands and no external bundle requests', () => {
    const html = readFileSync(new URL('../../dist/index.html', import.meta.url), 'utf8')
    expect(html).toContain('read_d04_initialization_profile')
    expect(html).toContain('d04_root_budget')
    expect(html).toContain('明确提交所选步骤')
    expect(html).not.toMatch(/<script[^>]+src=/)
    expect(html).not.toMatch(/<link[^>]+href=["'][^"']+\.css/)
  })
})

import OwnerAccess from './OwnerAccess.vue'
import RoleSetup from './RoleSetup.vue'
import { vi } from 'vitest'
describe('shipped Owner and role setup controls', () => {
  it('renders only local-signature fields and requires secure Owner origin', async () => {
    vi.stubGlobal('location',{origin:'https://localhost:6185'})
    try {
      const html=await renderToString(createSSRApp(OwnerAccess,{unlocked:false}))
      expect(html).toContain('获取签名挑战')
      expect(html).toContain('credential_id')
      expect(html).not.toMatch(/name="(?:password|private_key|api_key)"/)
    } finally {vi.unstubAllGlobals()}
  })
  it('role setup has no chosen preset/scene and is locked without session', async () => {
    const html=await renderToString(createSSRApp(RoleSetup,{scope:'bot/persona',csrf:'',sessionEpoch:0}))
    expect(html).toContain('明确提交角色初始化')
    expect(html).toContain('明确提交场景绑定')
    expect(html).toMatch(/<fieldset disabled/)
    expect(html).not.toContain(' checked')
    expect(html).not.toMatch(/value="d01\.persona\.[^"]+" selected/)
  })
  it('shipped bundle includes signed Owner and real scene commands', () => {
    const html=readFileSync(new URL('../../dist/index.html',import.meta.url),'utf8')
    for(const text of ['/owner/challenge','/owner/complete','/owner/logout','/scene-candidates','create_character','bind_scene']) expect(html).toContain(text)
  })
})
