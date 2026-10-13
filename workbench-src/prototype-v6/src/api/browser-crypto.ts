import {sha256} from '@noble/hashes/sha2.js'
import {bytesToHex} from '@noble/hashes/utils.js'

/** UUIDv4 uses browser CSPRNG on both HTTP and HTTPS; no clock/random fallback. */
export function operationIdV1():string{
  const bytes=crypto.getRandomValues(new Uint8Array(16))
  bytes[6]=(bytes[6]!&0x0f)|0x40
  bytes[8]=(bytes[8]!&0x3f)|0x80
  const text=bytesToHex(bytes)
  return text.slice(0,8)+'-'+text.slice(8,12)+'-'+text.slice(12,16)+'-'+text.slice(16,20)+'-'+text.slice(20)
}

/** Same SHA-256 bytes as WebCrypto, without a secure-context-only browser API. */
export function sha256HexV1(bytes:Uint8Array):string{return bytesToHex(sha256(bytes))}
