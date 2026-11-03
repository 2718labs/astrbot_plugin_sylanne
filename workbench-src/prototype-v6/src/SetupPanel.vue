<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { ModelSelectionState } from './api/setup.ts'
import { WorkbenchApi, WorkbenchApiError, type OnboardingChoices, type ObservedSceneChoice,
  type CreateCharacterInput, type BindSceneInput, type RoleInitializationReceipt, type SceneBindingReceipt } from './api/client.ts'
import { operationIdV1 } from './api/browser-crypto.ts'
import CreatorConfigurationPanel from './CreatorConfigurationPanel.vue'

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

const onboardingApi = new WorkbenchApi({ enabled: props.backend.state.mode === 'same-origin' })
const onboarding = ref<OnboardingChoices | null>(null), observedScenes = ref<ObservedSceneChoice[]>([])
const displayName = ref(''), blueprint = ref(''), sceneRef = ref(''), acknowledged = ref(false)
const onboardingBusy = ref(false), onboardingMessage = ref(''), showCreator = ref(false)
const creationReceipt = ref<RoleInitializationReceipt | null>(null), bindingReceipt = ref<SceneBindingReceipt | null>(null)
const pendingOnboarding=props.backend.onboardingRecovery.pending
const ownerIdentityDigest=ref('')
let onboardingGeneration = 0
const onboardingEligible = computed(() => props.backend.state.mode === 'same-origin'
  && props.backend.state.auth === 'authenticated' && props.backend.state.dashboard === 'authenticated'
  && props.backend.state.owner === 'unlocked' && props.backend.scopeValid.value && !props.backend.state.busy)
const selectedBlueprint = computed(() => onboarding.value?.creation.choices.find(item => item.blueprint === blueprint.value))
const selectedScene = computed(() => observedScenes.value.find(item => item.scene_ref === sceneRef.value))
const creationBlockers: Record<string, string> = {
  creation_catalogue_unavailable: '当前发行目录未通过真实清单核验，不能提供方案。',
  creation_resources_currently_unavailable: '实际模型、预算或当前 Source 元数据读取受阻；没有使用默认许可。',
  initial_owner_creation_authorization_required: '当前 Owner 已不处于允许首次创建的授权版本；请读取现有角色或核实原创建收据。',
  signed_owner_creation_session_required: '创建需要当前已签名的 Owner 会话。',
  installed_creation_resources_unavailable: '当前安装没有与本角色匹配的正式模型和预算资料。',
  installed_creation_model_unavailable: '当前安装尚无可用于创建的正式主模型。',
  creation_selector_reader_unavailable: '当前后端未安装创建选择项目录。',
  creation_capability_denied: '当前 Owner 会话没有创建能力。',
  role_initialization_policy_unavailable: '当前安装未配置正式角色初始化提供方。',
  installed_onboarding_scope_unavailable: '所选角色范围不属于当前已安装的 Owner 范围。',
}
function clearOnboarding() {
  ++onboardingGeneration; onboardingApi.clearSession(); onboarding.value = null; observedScenes.value = []
  displayName.value = ''; blueprint.value = ''; sceneRef.value = ''; acknowledged.value = false
  ownerIdentityDigest.value=''; creationReceipt.value = null; bindingReceipt.value = null; showCreator.value = false; onboardingMessage.value = ''
  onboardingBusy.value = false
}
watch(() => [props.backend.state.auth, props.backend.state.dashboard, props.backend.state.owner, props.backend.state.scope],
  clearOnboarding, { flush: 'sync' })
function onboardingError(error: unknown) {
  return error instanceof WorkbenchApiError ? error.message + '（' + error.code + '）' : '当前输入或正式响应未通过核验。'
}
async function readOnboarding() {
  if (!onboardingEligible.value || onboardingBusy.value || pendingOnboarding.value) return
  const generation = ++onboardingGeneration, scope = props.backend.state.scope
  onboardingBusy.value = true; onboarding.value = null; observedScenes.value = []; blueprint.value = ''; sceneRef.value = ''; acknowledged.value = false
  try {
    await props.backend.setup.read()
    if (generation !== onboardingGeneration || !onboardingEligible.value) return
    if (props.backend.setup.state.status !== 'ready') throw new WorkbenchApiError('先读取当前安装与模型状态。', { code: 'setup_status_unavailable' })
    const identity=await onboardingApi.readOwnerSessionIdentity()
    if(generation!==onboardingGeneration||!onboardingEligible.value||scope!==props.backend.state.scope)return
    ownerIdentityDigest.value=identity.owner_binding_digest
    const current = await onboardingApi.readOnboardingChoices(scope)
    if (generation !== onboardingGeneration || !onboardingEligible.value || scope !== props.backend.state.scope) return
    onboarding.value = current
    onboardingMessage.value = current.creation.reason_code ? (creationBlockers[current.creation.reason_code] ?? '创建目录受阻：' + current.creation.reason_code) : '请选择服务端本次验证的方案；模型与预算引用只读，提交时再次核验。'
    if (current.binding_route_available) {
      try {
        const scenes = await onboardingApi.readObservedSceneChoices(scope)
        if (generation !== onboardingGeneration || !onboardingEligible.value) return
        observedScenes.value = scenes
        if (!scenes.length) onboardingMessage.value += ' 当前没有近期已观察场景；请先在目标会话产生真实宿主入站，再手动刷新。'
      } catch (error) { if (generation === onboardingGeneration) onboardingMessage.value += ' 场景候选读取受阻：' + onboardingError(error) }
    }
  } catch (error) { if (generation === onboardingGeneration) onboardingMessage.value = onboardingError(error) }
  finally { if (generation === onboardingGeneration) onboardingBusy.value = false }
}
async function submitOnboarding(action: 'create_character' | 'bind_scene') {
  if (!onboardingEligible.value || onboardingBusy.value || pendingOnboarding.value || !ownerIdentityDigest.value) return
  const scope = props.backend.state.scope, operationId = operationIdV1()
  if (action === 'create_character') {
    const choice = selectedBlueprint.value, name = displayName.value.trim()
    if (!choice || !name || name.length > 80) return
    pendingOnboarding.value = Object.freeze({action,scope,operationId,ownerBindingDigest:ownerIdentityDigest.value,
      input:Object.freeze({display_name:name,blueprint:choice.blueprint,
        model_capability_ref:choice.model_capability_ref,budget_ref:choice.budget_ref})})
  } else {
    const scene = selectedScene.value
    if (!onboarding.value?.binding_route_available || !scene || !acknowledged.value) return
    pendingOnboarding.value = Object.freeze({action,scope,operationId,ownerBindingDigest:ownerIdentityDigest.value,
      input:Object.freeze({scene_ref:scene.scene_ref,visibility:scene.visibility,acknowledgement:true as const})})
  }
  await verifyOnboardingAttempt()
}
async function verifyOnboardingAttempt() {
  const attempt = pendingOnboarding.value
  if (!attempt || !onboardingEligible.value || onboardingBusy.value || attempt.scope !== props.backend.state.scope) return
  const generation = onboardingGeneration
  let committed = false
  onboardingBusy.value = true; onboardingMessage.value = '正在核验原操作 ' + attempt.operationId + '。'
  try {
    const identity=await onboardingApi.readOwnerSessionIdentity()
    if(generation!==onboardingGeneration||!onboardingEligible.value||attempt.scope!==props.backend.state.scope)return
    ownerIdentityDigest.value=identity.owner_binding_digest
    if(identity.owner_binding_digest!==attempt.ownerBindingDigest)
      throw new WorkbenchApiError('此原操作属于另一已核验 Owner；请恢复原身份后核实，未重发请求。',{code:'onboarding_owner_changed'})
    const receipt = attempt.action === 'create_character'
      ? await onboardingApi.createCharacter(attempt.scope, attempt.input, attempt.operationId)
      : await onboardingApi.bindObservedScene(attempt.scope, attempt.input, attempt.operationId)
    committed = true
    if(pendingOnboarding.value?.operationId===attempt.operationId)pendingOnboarding.value=null
    if (generation !== onboardingGeneration || !onboardingEligible.value || attempt.scope !== props.backend.state.scope) return
    const actualScope = receipt.namespace.bot + '/' + receipt.namespace.persona
    onboarding.value = null; observedScenes.value = []
    props.backend.setScope(actualScope); props.backend.invalidateView()
    if (receipt.phase === 'role_initialized') {
      creationReceipt.value = receipt; displayName.value = ''; blueprint.value = ''; showCreator.value = true
      onboardingMessage.value = '角色已由真实收据确认，当前范围 ' + actualScope + '。正在读取 Creator，读取受阻会单独显示。'
    } else {
      bindingReceipt.value = receipt; sceneRef.value = ''; acknowledged.value = false
      onboardingMessage.value = '已确认正式场景绑定收据；没有发送测试消息。'
    }
    await props.backend.openWorkspace()
    if (generation !== onboardingGeneration || !onboardingEligible.value) return
    if (receipt.phase === 'role_initialized') await props.backend.creator.read()
  } catch (error) {
    if (generation === onboardingGeneration) onboardingMessage.value = committed
      ? '原提交已由真实收据确认，后续目录读取受阻：' + onboardingError(error)
      : '结果尚未确认，保留原操作 ' + attempt.operationId + '；仅可按原请求核实。' + onboardingError(error)
  } finally { if (generation === onboardingGeneration) onboardingBusy.value = false }
}

onBeforeUnmount(() => { setup.invalidate(); clearOnboarding() })
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

    <section class="onboarding-panel" aria-labelledby="onboarding-heading" :aria-busy="onboardingBusy">
      <h4 id="onboarding-heading">创建角色与绑定场景</h4>
      <p>使用当前已安装的角色范围 {{backend.state.scope || '尚未选择'}}。Owner 核验、方案、模型和预算均由正式后端读取；不能在此填写许可引用。</p>
      <p v-if="!onboardingEligible" role="status">先完成实际安装、独立 Owner 签名登录，并选择该 Owner 已获授权的 bot/persona 范围。</p>
      <button class="setup-action" :disabled="!onboardingEligible || onboardingBusy || !!pendingOnboarding" @click="readOnboarding">读取当前创建与场景目录</button>
      <p v-if="onboardingMessage" class="setup-message" role="status">{{onboardingMessage}}</p>
      <form v-if="onboarding" class="onboarding-form" @submit.prevent="submitOnboarding('create_character')">
        <h5>创建角色</h5>
        <p v-if="onboarding.creation.reason_code">{{creationBlockers[onboarding.creation.reason_code] ?? onboarding.creation.reason_code}}</p>
        <label for="onboarding-display-name">角色名称</label>
        <input id="onboarding-display-name" v-model="displayName" maxlength="80" autocomplete="off" :disabled="onboardingBusy || !!pendingOnboarding || !onboarding.creation.choices.length">
        <label for="onboarding-blueprint">已验证方案</label>
        <select id="onboarding-blueprint" v-model="blueprint" :disabled="onboardingBusy || !!pendingOnboarding || !onboarding.creation.choices.length">
          <option value="">请选择本次真实目录中的方案</option>
          <option v-for="item in onboarding.creation.choices" :key="item.blueprint" :value="item.blueprint">{{item.label}}</option>
        </select>
        <p v-if="selectedBlueprint">{{selectedBlueprint.description}}</p>
        <p v-if="selectedBlueprint">当前模型与预算已由服务端逐项核验；提交仍须原正式提供方重新批准，不会增加配额或调用模型。</p>
        <button class="setup-action" type="submit" :disabled="!onboardingEligible || onboardingBusy || !!pendingOnboarding || !selectedBlueprint || !displayName.trim()">明确创建所选角色</button>
      </form>
      <form v-if="onboarding?.binding_route_available" class="onboarding-form" @submit.prevent="submitOnboarding('bind_scene')">
        <h5>绑定已观察场景</h5>
        <p>只列出当前 Owner 可读的近期宿主观察。正式 D03 仍会重验当前角色、可见范围与场景身份。</p>
        <label for="onboarding-scene">真实会话候选</label>
        <select id="onboarding-scene" v-model="sceneRef" :disabled="onboardingBusy || !!pendingOnboarding || !observedScenes.length" @change="acknowledged=false">
          <option value="">请选择近期观察到的会话</option>
          <option v-for="item in observedScenes" :key="item.scene_ref" :value="item.scene_ref">{{item.visibility==='group'?'群聊':'私聊'}} · {{item.platform_ref}} · {{item.conversation_ref}}</option>
        </select>
        <label v-if="selectedScene" class="onboarding-ack"><input v-model="acknowledged" type="checkbox" :disabled="onboardingBusy || !!pendingOnboarding">确认将当前角色绑定到以上{{selectedScene.visibility==='group'?'群聊':'私聊'}}可见范围</label>
        <button class="setup-action" type="submit" :disabled="!onboardingEligible || onboardingBusy || !!pendingOnboarding || !selectedScene || !acknowledged">明确绑定所选场景</button>
      </form>
      <div v-if="pendingOnboarding" class="onboarding-pending" role="status">
        <p>原操作：{{pendingOnboarding.operationId}} · {{pendingOnboarding.action==='create_character'?'创建角色':'绑定场景'}} · 原范围 {{pendingOnboarding.scope}}。原 UUID、输入和 Owner 归属在本页内存中保留到实际收据确认，切换面板或登录状态不会生成新 UUID。</p>
        <p>恢复时先独立核验当前 Owner 归属，再由后端重新检查原请求的会话、CSRF 与领域授权。不同 Owner 不会重发此操作；重新载入整个页面前请记录原 UUID。</p>
        <button v-if="backend.state.scope!==pendingOnboarding.scope" class="setup-action" :disabled="onboardingBusy" @click="backend.setScope(pendingOnboarding.scope)">切回原操作范围</button>
        <button class="setup-action" :disabled="!onboardingEligible || onboardingBusy || backend.state.scope!==pendingOnboarding.scope" @click="verifyOnboardingAttempt">核验原 Owner 并按原请求核实结果</button>
      </div>
      <dl v-if="creationReceipt || bindingReceipt" class="setup-facts">
        <div v-if="creationReceipt"><dt>创建收据</dt><dd>{{creationReceipt.operation_id}}<small>{{creationReceipt.role_ref}} · Graph {{creationReceipt.graph_revision}}</small></dd></div>
        <div v-if="bindingReceipt"><dt>场景绑定收据</dt><dd>{{bindingReceipt.operation_id}}<small>{{bindingReceipt.scene_ref}} · 版本 {{bindingReceipt.binding_revision}}</small></dd></div>
      </dl>
      <CreatorConfigurationPanel v-if="showCreator && onboardingEligible" :backend="backend" group="persona"/>
    </section>

  </section>
</template>
<style scoped>
.installation-setup{color:var(--ink,#354348);font-size:12px;line-height:1.75;border-top:1px solid var(--line,#cbd6d8);margin-top:24px;padding-top:20px}.setup-code{font-size:10px;letter-spacing:.15em;color:var(--muted,#617177);margin:0 0 8px}.installation-setup h3{font-size:18px;font-weight:500;margin:0 0 10px}.installation-setup p{margin:8px 0;color:var(--muted,#617177)}.setup-actions{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}.setup-action{font:inherit;min-height:44px;padding:9px 14px;color:var(--ink,#354348);background:var(--surface,#f2f6ef);border:1px solid var(--line,#cbd6d8);border-radius:3px;cursor:pointer}.setup-action:disabled{cursor:default;color:var(--muted,#617177)}.setup-action:focus-visible{outline:2px solid var(--focus,#587020);outline-offset:3px}.setup-facts{margin:16px 0}.setup-facts>div{display:grid;grid-template-columns:minmax(110px,.7fr) minmax(0,1.3fr);gap:16px;padding:10px 0;border-bottom:1px solid var(--line,#cbd6d8)}.setup-facts dt{color:var(--muted,#617177)}.setup-facts dd{margin:0;overflow-wrap:anywhere}.setup-facts small{display:block;font-size:10px;color:var(--muted,#617177)}.setup-steps{padding-left:20px;color:var(--muted,#617177)}.setup-steps li{padding:7px 0}.installation-setup code{font-size:11px;overflow-wrap:anywhere}.setup-message{overflow-wrap:anywhere}@media(max-width:420px){.setup-facts>div{grid-template-columns:1fr;gap:4px}}
.onboarding-panel{border-top:1px solid var(--line);margin-top:24px;padding-top:18px}.onboarding-panel h4{font-size:17px;font-weight:500}.onboarding-form{display:grid;gap:9px;margin-top:18px;padding-top:14px;border-top:1px solid var(--line)}.onboarding-form h5{font-size:14px;font-weight:500;margin:0}.onboarding-form :is(input:not([type=checkbox]),select){width:100%;box-sizing:border-box;min-height:44px;padding:8px 10px;font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--line);border-radius:3px}.onboarding-form .setup-action{justify-self:start}.onboarding-ack{display:flex;align-items:flex-start;gap:10px}.onboarding-ack input{margin-top:5px}.onboarding-pending{margin-top:16px;overflow-wrap:anywhere}.onboarding-form :is(input,select):focus-visible{outline:2px solid var(--focus);outline-offset:3px}
</style>
