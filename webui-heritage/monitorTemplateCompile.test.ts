import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parse } from 'vue/compiler-sfc'

describe('MonitorView template', () => {
  it('compiles the v-if/v-else pair around the single observation chamber', () => {
    const source = readFileSync(new URL('./src/views/MonitorView.vue', import.meta.url), 'utf8')
    const result = parse(source, { filename: 'MonitorView.vue' })
    expect(result.errors).toEqual([])
  })
})
