import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const outputPaths = [
  new URL('./dist/index.html', import.meta.url),
  new URL('../resources/workbench/index.html', import.meta.url),
]

describe('delivered plugin pages', () => {
  it('are byte-identical and use repository-safe LF line endings', () => {
    const outputs = outputPaths.map((path) => readFileSync(path, 'utf8'))

    expect(outputs[0]).toBe(outputs[1])
    for (const output of outputs) {
      expect(output).not.toContain('\r')
    }
  })
})
