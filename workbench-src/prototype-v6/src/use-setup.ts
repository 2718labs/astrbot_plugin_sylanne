import { computed, reactive, ref } from 'vue'
import { WorkbenchApiError, type WorkbenchApi } from './api/client.ts'
import type { SetupStatus } from './api/setup.ts'

export function createSetup(api: Pick<WorkbenchApi, 'setupStatus' | 'invalidateSetup'>, eligible: () => boolean, onAuthError: (error: unknown) => void) {
  const state = reactive<{status:'idle'|'loading'|'ready'|'unauthorized'|'error';data:SetupStatus|null;message:string}>({status:'idle',data:null,message:''})
  let generation = 0
  const active = ref(false)
  const canRead = computed(() => eligible() && !active.value && state.status !== 'loading')
  const canExport = computed(() => eligible() && state.status === 'ready' && !!state.data?.model_plan)
  function invalidate() { ++generation; api.invalidateSetup(); state.status='idle'; state.data=null; state.message='' }
  async function read() {
    if (!canRead.value) return
    const token = generation; active.value=true; state.status='loading'; state.data=null; state.message='正在读取 AstrBot 的实际模型选择与安装许可。'
    try {
      const data = await api.setupStatus()
      if (token !== generation || !eligible()) return
      state.status='ready'; state.data=data; state.message='这是当前配置观察。Owner 身份、角色权限与模型调用授权仍分别核验。'
    } catch (error) {
      if (token !== generation) return
      if (error instanceof WorkbenchApiError && [401,403].includes(error.status)) {
        invalidate(); onAuthError(error); state.status='unauthorized'; state.message='后台登录或同源来源核验失效，请从当前 AstrBot Dashboard 重新进入。'
      } else { state.status='error'; state.data=null; state.message='安装配置读取失败或版本不兼容。没有使用默认值或旧观察替代，请显式重新读取。' }
    } finally { active.value=false }
  }
  function exportPlan(): string | null {
    if (!canExport.value || !state.data?.model_plan) return null
    const plan = state.data.model_plan
    return JSON.stringify({schema:plan.schema,authority_profile:plan.authority_profile,provider_id:plan.provider_id,model_id:plan.model_id,provider_config_digest:plan.provider_config_digest},null,2)+'\n'
  }
  return {state,canRead,canExport,read,invalidate,exportPlan}
}
