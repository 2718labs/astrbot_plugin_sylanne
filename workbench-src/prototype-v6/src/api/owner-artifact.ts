import {sha256HexV1} from './browser-crypto.ts'
import { hasFields, isInteger, isText, validateScope } from './contract.ts'

export interface OwnerArtifactItem { progress_ref: string; artifact_ref: string; artifact_version: number; content_digest: string; content_length_bytes: number }
export interface OwnerArtifactOptions { schema: 'd12.owner-artifact-options.v1'; namespace: { bot_id: string; persona_id: string }; project_ref: string; items: OwnerArtifactItem[] }
export interface OwnerArtifactReadInput { project_ref: string; progress_ref: string; expected_artifact_version: number; expected_content_digest: string }
export interface OwnerArtifactBody { schema: 'd12.owner-artifact-read-result.v2'; namespace: { bot_id: string; persona_id: string }; installation_id: string;
  project_ref: string; progress_ref: string; artifact_ref: string; artifact_version: number; content_digest: string; content_length_bytes: number;
  content_type: 'text/plain; charset=utf-8'; body: string }
export class OwnerArtifactContractError extends Error { constructor() { super('作品读取的正式字段不兼容。') } }
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
function invalid(): never { throw new OwnerArtifactContractError() }
function namespace(value: unknown, scope: string) { return hasFields(value, ['bot_id', 'persona_id']) && `${value.bot_id}/${value.persona_id}` === validateScope(scope) }
export function validateOwnerArtifactOptions(value: unknown, scope: string, projectRef: string): OwnerArtifactOptions {
  if (!hasFields(value, ['schema', 'namespace', 'project_ref', 'items']) || value.schema !== 'd12.owner-artifact-options.v1' || !namespace(value.namespace, scope)
    || value.project_ref !== projectRef || !isText(value.project_ref) || !Array.isArray(value.items) || value.items.length > 32) invalid()
  const seen = new Set<string>()
  for (const item of value.items) {
    if (!hasFields(item, ['progress_ref', 'artifact_ref', 'artifact_version', 'content_digest', 'content_length_bytes']) || !isText(item.progress_ref)
      || !isText(item.artifact_ref) || seen.has(item.progress_ref as string) || !isInteger(item.artifact_version, 1) || !digest(item.content_digest)
      || !isInteger(item.content_length_bytes, 1) || item.content_length_bytes > 524288) invalid()
    seen.add(item.progress_ref as string)
  }
  return value as unknown as OwnerArtifactOptions
}
export function ownerArtifactReadInput(options: OwnerArtifactOptions, item: OwnerArtifactItem): OwnerArtifactReadInput {
  if (!options.items.includes(item)) invalid()
  return { project_ref: options.project_ref, progress_ref: item.progress_ref, expected_artifact_version: item.artifact_version, expected_content_digest: item.content_digest }
}
export async function validateOwnerArtifactBody(value: unknown, scope: string, input: OwnerArtifactReadInput, item: OwnerArtifactItem): Promise<OwnerArtifactBody> {
  if (!hasFields(value, ['schema', 'namespace', 'installation_id', 'project_ref', 'progress_ref', 'artifact_ref', 'artifact_version', 'content_digest', 'content_length_bytes', 'content_type', 'body_encoding', 'body_base64'])
    || value.schema !== 'd12.owner-artifact-read-result.v2' || !namespace(value.namespace, scope) || !isText(value.installation_id)
    || value.project_ref !== input.project_ref || value.progress_ref !== input.progress_ref || value.artifact_ref !== item.artifact_ref
    || value.artifact_version !== input.expected_artifact_version || value.content_digest !== input.expected_content_digest
    || value.content_length_bytes !== item.content_length_bytes || value.content_type !== 'text/plain; charset=utf-8' || value.body_encoding !== 'base64' || typeof value.body_base64 !== 'string'
    || value.body_base64.length > 699052 || value.body_base64.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.body_base64)) invalid()
  const binary = atob(value.body_base64), bytes = Uint8Array.from(binary, character => character.charCodeAt(0))
  if (btoa(binary) !== value.body_base64) invalid()
  if (bytes.byteLength !== value.content_length_bytes) invalid()
  const hash = sha256HexV1(bytes)
  if (hash !== value.content_digest) invalid()
  let body: string
  try { body = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) } catch { invalid() }
  const { body_encoding: _encoding, body_base64: _encoded, ...publicFields } = value
  return { ...publicFields, body } as unknown as OwnerArtifactBody
}
