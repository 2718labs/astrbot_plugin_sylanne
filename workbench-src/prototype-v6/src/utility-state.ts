import type { BackendState } from './use-backend.ts'
import type { ManagementState } from './use-management.ts'

export type UtilityKind = 'logs' | 'settings'
export type UtilityAccessState = 'offline' | 'checking' | 'locked' | 'error' | 'undiscovered' | 'unavailable' | 'unsupported' | 'ready'
export type UtilitySessionState = Pick<BackendState, 'mode' | 'auth' | 'dashboard' | 'owner' | 'busy'>

/** A verified session does not create a logs/configuration API capability. */
export function utilityAccessState(state: UtilitySessionState, capabilities?: ManagementState['capabilities'], kind?: UtilityKind): UtilityAccessState {
  if (state.mode === 'offline' || state.auth === 'offline') return 'offline'
  if (state.auth === 'checking' || state.busy) return 'checking'
  if (state.auth === 'error') return 'error'
  if (state.auth !== 'authenticated' || state.dashboard !== 'authenticated' || state.owner !== 'unlocked') return 'locked'
  if (capabilities?.status === 'loading') return 'checking'
  if (capabilities?.status === 'unsupported') return 'unsupported'
  if (capabilities?.status === 'error') return 'error'
  if (capabilities?.status === 'ready' && capabilities.data && kind) return capabilities.data.capabilities[kind].available ? 'ready' : 'unavailable'
  return 'undiscovered'
}

export const UTILITY_ACCESS_COPY: Record<UtilityAccessState, { label: string; description: string }> = {
  offline: { label: '离线预览', description: '后端未连接。这里仅展示界面结构，没有读取实际数据。' },
  checking: { label: '会话处理中', description: '会话尚在处理，本页没有读取日志或配置。' },
  locked: { label: '访问尚未核验', description: '当前会话未完成核验。实际内容尚不可读取。' },
  error: { label: '会话核验未完成', description: '当前会话状态未能确认。请在访问验证中核对连接状态。' },
  undiscovered: { label: '会话已核验 · 管理接口待核验', description: '请明确核验当前安装的管理权限，再读取实际日志或配置。' },
  unavailable: { label: '此项能力不可用', description: '当前安装或授权未提供此项能力，操作保持关闭。' },
  unsupported: { label: '管理扩展未提供', description: '后端未提供兼容的管理扩展，未使用示例数据代替。' },
  ready: { label: '管理接口已核验', description: '本页仅开放当前安装级权限允许的操作。' },
}

export const UTILITY_META = {
  logs: {
    code: 'WORKBENCH / RUNTIME',
    title: '运行日志',
    description: '查看运行记录与事件详情。',
    unavailableTitle: '日志接口尚未接入',
    unavailableMessage: '尚未取得当前安装的日志读取能力，无法读取记录或执行筛选。',
    boundary: '未读取记录，不代表运行期间没有事件。',
  },
  settings: {
    code: 'WORKBENCH / CONFIGURATION',
    title: '插件设置',
    description: '核对插件配置结构与宿主配置依赖。',
    unavailableTitle: '实际配置尚不可读取',
    unavailableMessage: '尚未取得并读取当前安装的实际配置。以下默认值仅为配置结构说明。',
    boundary: '结构默认值不代表当前安装的实际配置。',
  },
} as const

/** Verified _conf_schema.json fields only. These are schema defaults, never live values. */
export const PLUGIN_SETTING_SCHEMA = {
  enabled: { type: 'boolean', defaultValue: false },
  authority_profile: { type: 'string', defaultValue: 'default', minimumLength: 1, maximumLength: 64 },
} as const
