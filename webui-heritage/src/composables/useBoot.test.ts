import { afterEach, expect, it, vi } from 'vitest'
import * as bootModule from './useBoot'

type WaitForBootVerification = (
  verification: Promise<boolean>,
  timeoutMs: number,
) => Promise<boolean>

afterEach(() => {
  bootModule.useBoot().consumeArrival()
  vi.useRealTimers()
})

it('bounds a boot verification that never settles', async () => {
  vi.useFakeTimers()
  const waitForBootVerification = (
    bootModule as unknown as {
      waitForBootVerification?: WaitForBootVerification
    }
  ).waitForBootVerification

  expect(waitForBootVerification).toBeTypeOf('function')
  if (!waitForBootVerification) return

  const result = waitForBootVerification(new Promise<boolean>(() => undefined), 50)
  await vi.advanceTimersByTimeAsync(50)

  await expect(result).resolves.toBe(false)
})

it('cancels a pending arrival when dashboard navigation fails', () => {
  const boot = bootModule.useBoot()

  boot.requestArrival()
  expect(boot.arrivalPending.value).toBe(true)
  expect(boot.cancelArrival).toBeTypeOf('function')

  boot.cancelArrival()
  expect(boot.arrivalPending.value).toBe(false)
  expect(boot.consumeArrival()).toBe(false)
})
