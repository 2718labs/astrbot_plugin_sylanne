import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const login = readFileSync(new URL('./src/views/LoginView.vue', import.meta.url), 'utf8')
  .replace(/\r\n?/g, '\n')

describe('standalone login failure recovery', () => {
  it('keeps the submitted token editable and announces a persistent field error', () => {
    expect(login).toContain("const loginError = ref('')")
    expect(login).toContain("loginError.value = t('login.error')")
    expect(login).not.toContain("token.value = ''")
    expect(login).toContain('aria-describedby="tokenError"')
    expect(login).toContain('role="alert"')
    expect(login).toContain('id="tokenError"')
    expect(login).toContain('@input="clearLoginError"')
  })

  it('returns focus to the token field with its value selected for correction', () => {
    expect(login).toContain('tokenInputEl.value?.focus()')
    expect(login).toContain('tokenInputEl.value?.select()')
  })
})
