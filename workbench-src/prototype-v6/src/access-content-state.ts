import type { BackendState } from './use-backend.ts'
import type { CharacterProjection, ViewType } from './api/contract.ts'
export const ARCHIVE_META: Record<string, { title: string; code: string; description: string; boundary: string; view: ViewType | null; fields: readonly { key: string; label: string }[] }> = {
  'demo-persona': { title: '人格方案', code: 'D01 / CREATION', description: '查看当前角色的人格方案版本与结构信息。', boundary: '仅显示当前账户有权查看的方案信息。人格正文与编辑功能尚未接入。', view: 'creation', fields: [{ key: 'plan_id', label: '方案标识' }, { key: 'version', label: '版本' }, { key: 'authored', label: '作者资格' }, { key: 'block_count', label: '组成数量' }, { key: 'value_rule_count', label: '价值规则数量' }] },
  'demo-memory': { title: '记忆来源', code: 'D06 / MEMORY SOURCES', description: '查看当前账户有权查看的来源类型、断言状态与记录时间。', boundary: '这里仅呈现来源元数据。资格「未记录」不代表已验证；不公开记忆正文、置信度或原始证据。', view: 'd06.memory_sources.v1', fields: [{ key: 'source_id', label: '来源标识' }, { key: 'source_kind', label: '来源类型' }, { key: 'assertion_status', label: '断言状态' }, { key: 'recorded_at', label: '记录时间' }, { key: 'qualification', label: '资格记录' }] },
  'demo-life': { title: '生活档案', code: 'LIFE / UNAVAILABLE', description: '生活记录功能尚未接入。', boundary: '生活数据、计划与历史暂时无法读取。这里不会生成演示记录。', view: null, fields: [] },
  'demo-contact': { title: '主动联系', code: 'CONTACT / HOLD', description: '发送归属与在途状态未确认，主动联系保持暂停。', boundary: '没有发送、试发、排队或补发能力。可用功能列表也不会解除 HOLD。', view: null, fields: [] },
  'demo-access': { title: '访问状态', code: 'ACCESS / VERIFIED LAYERS', description: 'AstrBot 后台登录、独立所有者会话与角色范围分别核验。', boundary: '手填角色范围不会获得权限。仅显示当前账户有权查看的信息。', view: null, fields: [] },
}
export const CONTENT_STATUS_LABELS = { idle: '尚未读取', loading: '读取中', empty: '没有记录', ready: '信息已读取', unauthorized: '未获授权', disabled: '未连接', error: '读取失败', unavailable: '内容未接入', stale: '结果已作废', partial: '读取不完整' } as const
export function dashboardLabel(state: BackendState) { return state.dashboard === 'authenticated' ? '已核验' : state.dashboard === 'missing' ? '未登录' : '尚未核验' }
export function ownerLabel(state: BackendState) { return state.owner === 'unlocked' ? '已核验并解锁' : state.owner === 'locked' ? '本页已锁定' : '尚未核验' }
/** Never render protected rows merely because a previously populated object remains in memory. */
export function visibleProjection(state: BackendState, entryId: string): CharacterProjection | null {
  const view = ARCHIVE_META[entryId]?.view, projection = state.view.data
  if (state.auth !== 'authenticated' || state.mode !== 'same-origin' || !view || state.viewType !== view || !['ready', 'empty'].includes(state.view.status) || projection?.view_type !== view) return null
  if (`${projection.namespace.bot}/${projection.namespace.persona}` !== state.scope || state.workspace.status !== 'ready' || !state.workspace.data?.views.some(v => v.view_type === view && v.status === 'available')) return null
  return projection
}
export function challengeExpired(expiresAt: string | undefined, now = Date.now()) { return !!expiresAt && (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= now) }
