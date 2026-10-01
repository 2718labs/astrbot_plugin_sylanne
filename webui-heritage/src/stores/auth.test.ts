import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

const {
  apiFetchMock,
  clearTokenMock,
  fetchScopeCatalogMock,
  getTokenMock,
  setTokenMock,
  usesHostAuthenticationMock,
} = vi.hoisted(() => ({
  apiFetchMock: vi.fn(),
  clearTokenMock: vi.fn(),
  fetchScopeCatalogMock: vi.fn(),
  getTokenMock: vi.fn(),
  setTokenMock: vi.fn(),
  usesHostAuthenticationMock: vi.fn(),
}))

vi.mock('../api/client', () => ({
  apiFetch: apiFetchMock,
  clearToken: clearTokenMock,
  fetchScopeCatalog: fetchScopeCatalogMock,
  getToken: getTokenMock,
  setToken: setTokenMock,
  usesHostAuthentication: usesHostAuthenticationMock,
  ApiError: class ApiError extends Error {
    status = 0
  },
}))

import { useAuthStore } from './auth'

describe('authentication scope boundary', () => {
  beforeEach(() => {
    apiFetchMock.mockReset()
    clearTokenMock.mockReset()
    fetchScopeCatalogMock.mockReset()
    getTokenMock.mockReset()
    setTokenMock.mockReset()
    usesHostAuthenticationMock.mockReset()
    getTokenMock.mockReturnValue('')
    usesHostAuthenticationMock.mockReturnValue(false)
    fetchScopeCatalogMock.mockResolvedValue({ ok: true, scopes: [] })
    setActivePinia(createPinia())
  })

  it('validates a submitted standalone token without reading an unscoped state', async () => {
    const auth = useAuthStore()

    await expect(auth.login('token')).resolves.toBe(true)

    expect(fetchScopeCatalogMock).toHaveBeenCalledOnce()
    expect(apiFetchMock).not.toHaveBeenCalled()
  })

  it('validates an existing token through the catalog before admitting the dashboard', async () => {
    getTokenMock.mockReturnValue('persisted-token')
    const auth = useAuthStore()

    await expect(auth.verifyExisting()).resolves.toBe(true)

    expect(fetchScopeCatalogMock).toHaveBeenCalledOnce()
    expect(apiFetchMock).not.toHaveBeenCalled()
  })
})
