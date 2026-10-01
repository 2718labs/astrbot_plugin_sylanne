import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const source = await readFile(new URL('../../../../webui-heritage/src/App.vue', import.meta.url), 'utf8')

test('heritage shell uses the W10 same-origin Owner session and CSRF contract', () => {
  assert.match(source, /\/api\/v1\/plugins\/extensions\/astrbot_plugin_sylanne\/workbench\/v1/)
  assert.match(source, /getJson<Session>\('\/session'\)/)
  assert.match(source, /credentials:\s*'same-origin'/)
  assert.match(source, /'x-csrf-token':\s*csrf\.value/)
  assert.match(source, /purpose:\s*'workbench_view',\s*audience:\s*'owner'/)
  assert.match(source, /action:\s*'open_workspace'/)
  assert.match(source, /action:\s*'read_character_view'/)
  assert.match(source, /input:\s*\{\s*view_type:\s*viewType,\s*\.\.\.\(cursor \? \{ cursor \} : \{\}\)/)
  assert.doesNotMatch(source, /action:\s*'read_character_view'.{0,500}page_size/s)
  assert.match(source, /cursor \? \{ cursor \} : \{\}/)
  assert.match(source, /function safeFieldName\(name: string\)/)
  assert.match(source, /secret\|token\|password\|private\|credential\|authorization\|bearer\|debug\|raw/)
  assert.match(source, /value\.slice\(0, 400\)/)
  assert.doesNotMatch(source, /\/api\/scopes|Authorization\s*:\s*Bearer|localStorage\.getItem\(['"](?:token|access_token)/i)
})

test('late character reads cannot cross scope or selected-view generations', () => {
  assert.match(source, /const requestGeneration = ref\(0\)/)
  assert.match(source, /function invalidateScope\(\)\s*\{\s*requestGeneration\.value\+\+/)
  assert.match(source, /function selectView\(viewType: string\)\s*\{\s*requestGeneration\.value\+\+/)
  assert.match(source, /generation !== requestGeneration\.value \|\| requestedScope !== scope\.value\.trim\(\) \|\| selectedView\.value !== viewType/)
  assert.match(source, /workspaceBusy\.value = false/)
})
