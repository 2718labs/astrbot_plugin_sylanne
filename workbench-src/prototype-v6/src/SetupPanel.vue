<script setup lang="ts">
import { computed, onBeforeUnmount } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { ModelSelectionState } from './api/setup.ts'

const props = defineProps<{backend:BackendController}>()
const setup = props.backend.setup
const state = computed(() => setup.state)
const selectionCopy: Record<ModelSelectionState,string> = {
  unselected:'尚未选择 LLM', unavailable:'所选提供方当前不可用', unsupported:'所选提供方不支持当前 LLM 接口',
  changed:'当前模型或配置已变更，需要重新安装绑定', awaiting_installation:'已观察当前模型，等待正式安装绑定', authorized:'与安装主模型一致；请求仍需当前授权',
}
function downloadPlan() {
  const plan = setup.exportPlan()
  if (!plan) return
  const url=URL.createObjectURL(new Blob([plan],{type:'application/json;charset=utf-8'})), anchor=document.createElement('a')
  anchor.href=url; anchor.download='llm-selection.json'; anchor.click(); URL.revokeObjectURL(url)
}
onBeforeUnmount(() => setup.invalidate())
</script>
<template>
  <section class="installation-setup" aria-label="安装配置与 LLM 状态" :aria-busy="state.status==='loading'">
    <header><p class="setup-code">INSTALLATION / LLM</p><h3>安装配置与模型</h3><p>从当前 AstrBot 后台读取实际选择。此入口只需后台登录，尚未入驻或解锁 Owner 时也可查看。</p></header>
    <div class="setup-actions"><button class="setup-action" :disabled="!setup.canRead.value" @click="setup.read">{{state.status==='loading'?'正在读取实际配置…':state.data?'重新读取安装配置':'读取安装配置 / LLM 状态'}}</button><button class="setup-action" :disabled="!setup.canExport.value" @click="downloadPlan">导出 llm-selection.json</button></div>
    <p v-if="state.message" class="setup-message" :role="state.status==='error'||state.status==='unauthorized'?'alert':'status'">{{state.message}}</p>
    <dl v-if="state.data" class="setup-facts">
      <div><dt>当前配置档案</dt><dd>{{state.data.profile_id}}<small>仅为当前选择，不能据此认定已经注册安装。</small></dd></div>
      <div><dt>实际 LLM 提供方</dt><dd>{{state.data.model_selection.provider_id??'尚未观察到可用选择'}}</dd></div>
      <div><dt>实际模型</dt><dd>{{state.data.model_selection.model_id??'尚未观察到可用模型'}}</dd></div>
      <div><dt>安装绑定状态</dt><dd>{{selectionCopy[state.data.model_selection.state]}}<small>匹配状态不授予 Owner、角色读取或模型调用权限。</small></dd></div>
      <div><dt>本次启动 Host 启用</dt><dd>{{state.data.host_enabled?'已启用（true）':'未启用（false）'}}</dd></div>
      <div><dt>本次启动 Authority 许可</dt><dd>{{state.data.authority_enabled===null?'本次启动尚未取得许可采样':state.data.authority_enabled?'已许可（true）':'未许可（false）'}}</dd></div>
      <div><dt>本次启动有效启用</dt><dd>{{state.data.effective_enabled?'两项启动许可同时满足':'尚未同时满足启用条件'}}</dd></div>
      <div><dt>实际运行阶段</dt><dd>{{state.data.runtime.stage}}<small v-if="state.data.runtime.reason_codes.length">{{state.data.runtime.reason_codes.join(' · ')}}</small></dd></div>
      <div><dt>正式安装器</dt><dd>{{state.data.installer.supported?'当前平台支持全新安装':'当前平台尚不支持此安装器'}}<small>只用于全新安装，需要管理员明确批准。</small></dd></div>
    </dl>
    <ol class="setup-steps">
      <li>在本 WebUI 的“模型策略”分组选择主 LLM、共享辅助 Provider 与公共工作槽覆盖。选项来自实际 AstrBot SDK；插件配置页只保留必要入口，不在本页输入密钥或创建静态模型列表。</li>
      <li>保存本机配置后，明确点击“读取安装配置 / LLM 状态”，核对 SDK 当前提供方、模型与本次启动许可。运行要求本次启动采样的 Host enabled 与 Authority enabled 同时为 true；状态读取不把保存值变为即时启用。</li>
      <li>有有效模型观察时可导出 <code>llm-selection.json</code>，交给随包正式安装器的 <code>--model-selection</code> 参数。该文件只有五个模型观察字段，不是授权；本页不会执行安装或调用模型。</li>
      <li>入驻后仍须完成独立 Owner 签名核验。设置面板显示当前真实保存值；Authority enabled 保存按 <code>next_restart</code> 生效，重启前此处仍显示本次启动许可。不代替 Host 启用，也不解除 Numeric、Contact、C09、D04 门槛。</li>
    </ol>
  </section>
</template>
<style scoped>
.installation-setup{color:var(--ink,#354348);font-size:12px;line-height:1.75;border-top:1px solid var(--line,#cbd6d8);margin-top:24px;padding-top:20px}.setup-code{font-size:10px;letter-spacing:.15em;color:var(--muted,#617177);margin:0 0 8px}.installation-setup h3{font-size:18px;font-weight:500;margin:0 0 10px}.installation-setup p{margin:8px 0;color:var(--muted,#617177)}.setup-actions{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}.setup-action{font:inherit;min-height:44px;padding:9px 14px;color:var(--ink,#354348);background:var(--surface,#f2f6ef);border:1px solid var(--line,#cbd6d8);border-radius:3px;cursor:pointer}.setup-action:disabled{cursor:default;color:var(--muted,#617177)}.setup-action:focus-visible{outline:2px solid var(--focus,#587020);outline-offset:3px}.setup-facts{margin:16px 0}.setup-facts>div{display:grid;grid-template-columns:minmax(110px,.7fr) minmax(0,1.3fr);gap:16px;padding:10px 0;border-bottom:1px solid var(--line,#cbd6d8)}.setup-facts dt{color:var(--muted,#617177)}.setup-facts dd{margin:0;overflow-wrap:anywhere}.setup-facts small{display:block;font-size:10px;color:var(--muted,#617177)}.setup-steps{padding-left:20px;color:var(--muted,#617177)}.setup-steps li{padding:7px 0}.installation-setup code{font-size:11px;overflow-wrap:anywhere}.setup-message{overflow-wrap:anywhere}@media(max-width:420px){.setup-facts>div{grid-template-columns:1fr;gap:4px}}
</style>
