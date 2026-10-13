<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { OwnerFields } from './api/contract.ts'
import { challengeExpired, dashboardLabel, ownerLabel } from './access-content-state.ts'
import ConfigurationPanel from './ConfigurationPanel.vue'
import DashboardAccessPanel from './DashboardAccessPanel.vue'
const props = defineProps<{ backend: BackendController; setupFirst?: boolean }>()
const emit = defineEmits<{ close: []; verified: [] }>()
const fields = ref<OwnerFields>({ authority_id: '', authority_namespace: '', installation_id: '', identity_provider: '', account_ref: '', account_incarnation: '', credential_id: '', credential_epoch: '' })
const signature = ref(''), scope = ref(props.backend.state.scope), signingOpen = ref(false), composing = ref(false), now = ref(Date.now())
const labels: [keyof OwnerFields, string][] = [['authority_id', 'Authority 标识'], ['authority_namespace', 'Authority 命名空间'], ['installation_id', '安装标识'], ['identity_provider', '身份提供方'], ['account_ref', '所有者账户引用'], ['account_incarnation', '账户代际'], ['credential_id', '配对凭据标识'], ['credential_epoch', '凭据版本']]
const state = computed(() => props.backend.state)
const offline = computed(() => state.value.mode === 'offline')
const busy = computed(() => state.value.busy)
const expired = computed(() => challengeExpired(state.value.challenge?.challenge.expires_at_utc, now.value))
const signatureReady = computed(() => /^[A-Za-z0-9+/]{86}==$/.test(signature.value.trim()) && !expired.value)
const readyFields = computed(() => Object.values(fields.value).every(value => value.trim()))
const authCopy = computed(() => ({ offline: '后端未连接', checking: '正在核验身份', locked: '工作台等待核验', authenticated: '身份已通过后端核验', error: '暂时无法核验会话', https_required: 'HTTP 静态入口 · 需要 HTTPS' }[state.value.auth]))
const busyCopy = computed(() => ({ none: '', session: '正在核验已有会话…', challenge: '正在取得一次性挑战…', complete: '正在核验签名与会话…', logout: '正在确认所有者退出…' }[state.value.authOperation]))
function close() { signature.value = ''; props.backend.dismissLogin(); emit('close') }
function handleKeydown(event: KeyboardEvent) { if (event.key !== 'Escape' || composing.value || event.isComposing || event.keyCode === 229) return; event.stopPropagation(); event.preventDefault(); close() }
async function check() { if (await props.backend.checkSession()) emit('verified') }
function dashboardAuthenticated() { props.backend.state.dashboard = 'authenticated'; void props.backend.configuration.read() }
async function begin() { signature.value = ''; now.value = Date.now(); await props.backend.beginOwnerLogin({ ...fields.value }) }
async function complete() { const submitted = signature.value.trim(); signature.value = ''; if (await props.backend.completeOwnerLogin(submitted)) emit('verified') }
function cancel() { signature.value = ''; props.backend.cancelChallenge() }
function editPairing() { if (state.value.challenge) cancel() }
function updateScope() { props.backend.setScope(scope.value) }
function toggleSigning() { if (signingOpen.value) cancel(); signingOpen.value = !signingOpen.value }
let clock: ReturnType<typeof setInterval> | undefined
watch(() => state.value.challenge, () => { signature.value = ''; now.value = Date.now() })
watch(expired, value => { if (value) signature.value = '' })
watch(() => state.value.scope, value => { scope.value = value })
onMounted(() => { clock = setInterval(() => { now.value = Date.now() }, 1000) })
onBeforeUnmount(() => { if (clock) clearInterval(clock); signature.value = ''; for (const key of Object.keys(fields.value) as (keyof OwnerFields)[]) fields.value[key] = ''; props.backend.dismissLogin() })
</script>
<template>
  <section class="login-panel" :class="{'is-checking':busy,'has-error':!!state.error,'is-verified':state.auth==='authenticated'}" aria-labelledby="login-title" :aria-busy="busy" @keydown="handleKeydown" @compositionstart="composing = true" @compositionend="composing = false">
    <header class="panel-heading"><div><p class="eyebrow">2718lab / WORKBENCH ACCESS</p><h2 id="login-title">{{setupFirst?'高级配置 / LLM':'所有者凭据'}}</h2></div><button class="close-button" type="button" aria-label="返回工作台入口" @click="close">返回 <span class="arrow-icon" aria-hidden="true"></span></button></header>
    <div class="access-grid">
      <div class="access-form-region">
        <DashboardAccessPanel v-if="!offline" @authenticated="dashboardAuthenticated" />
        <ConfigurationPanel v-if="setupFirst" :backend="backend" />
        <div class="session-status" role="status" aria-live="polite" aria-atomic="true"><span class="status-point" :class="{ verified: state.auth === 'authenticated' }" aria-hidden="true"></span><strong>{{ authCopy }}</strong></div>
        <p v-if="offline" class="offline-note">当前是离线前端。这里没有后端请求，也不能核验身份；离线界面演示不会授予真实权限。</p>
        <p v-else-if="!backend.requiresHttps.value" class="login-note">请先登录当前 AstrBot 后台，再核验所有者会话。两层验证均有效后才能进入工作台。</p>
        <dl class="auth-layers"><div><dt>AstrBot 后台登录</dt><dd>{{ dashboardLabel(state) }}</dd></div><div><dt>2718lab 所有者</dt><dd>{{ ownerLabel(state) }}</dd></div></dl>
        <p v-if="state.error" class="panel-error" role="alert">{{ state.error }}</p>
        <div v-if="busy" class="verification-status"><span class="verification-meter" aria-hidden="true"></span><p class="action-progress" role="status">{{ busyCopy }}</p><span class="verification-code" aria-hidden="true">REQUEST / WAITING</span></div>
        <p v-if="state.logoutStatus === 'confirmed'" class="action-progress" role="status">所有者退出已确认。AstrBot 后台登录保持独立。</p>
        <p v-else-if="state.logoutStatus === 'unconfirmed'" class="field-hint" role="status">本页保持锁定，所有者退出结果未确认。可以重试退出。</p>
        <button v-if="state.auth !== 'authenticated'" class="primary-button full-button" :disabled="offline || backend.requiresHttps.value || busy" @click="check">{{ backend.requiresHttps.value ? '需要 HTTPS 后核验会话' : state.auth === 'error' || state.error ? '重试核验已有会话' : '核验已有会话' }} <span class="arrow-icon forward" aria-hidden="true"></span></button>
        <form v-if="state.auth === 'authenticated'" class="scope-form" @submit.prevent="updateScope">
          <label for="role-scope">当前授权角色范围</label><input id="role-scope" v-model="scope" placeholder="bot/persona" maxlength="192" autocomplete="off" spellcheck="false" :disabled="busy" aria-describedby="scope-hint"><p id="scope-hint" class="field-hint">从本机安装记录填写。手填范围不会获得额外权限。</p><button class="primary-button" :disabled="busy || !scope.trim()" type="submit">选择角色范围</button>
        </form>
        <div v-if="state.auth !== 'authenticated'" class="owner-details">
          <button class="signing-toggle" type="button" :aria-expanded="signingOpen" aria-controls="owner-signing" :disabled="backend.requiresHttps.value || busy" @click="toggleSigning">使用已配对的所有者凭据 <span class="disclosure-mark" :class="{ open: signingOpen }" aria-hidden="true"></span></button>
          <div v-if="signingOpen" id="owner-signing">
            <p class="login-note">填写安装记录，取得挑战，并将载荷交给你已有的本机凭据签名工具。不在这里输入私钥。</p>
            <form @submit.prevent="begin">
              <fieldset class="pairing-fields" :disabled="offline || backend.requiresHttps.value || busy"><legend class="sr-only">已配对安装信息</legend>
                <label v-for="[key, label] in labels" :key="key" :for="'owner-' + key"><span>{{ label }}</span><span class="field-id">{{ key }}</span><input :id="'owner-' + key" v-model="fields[key]" :inputmode="key === 'credential_epoch' ? 'numeric' : 'text'" maxlength="256" autocomplete="off" spellcheck="false" @input="editPairing"></label>
              </fieldset>
              <p v-if="!offline && !backend.canSignedLogin.value" class="field-hint">请从 AstrBot 提供的安全工作台地址使用签名验证。</p>
              <button class="secondary-button" type="submit" :disabled="!backend.canSignedLogin.value || !readyFields">{{ state.challenge ? '重新取得一次性挑战' : '取得签名挑战' }}</button>
            </form>
            <form v-if="state.challenge" class="signature-form" @submit.prevent="complete">
              <label for="owner-payload">待签名载荷 · Base64</label><textarea id="owner-payload" :value="state.challenge.signingPayloadBase64" readonly rows="4" spellcheck="false" aria-describedby="challenge-expiry"></textarea><p id="challenge-expiry" class="field-hint" :class="{ expired }" role="status">{{ expired ? '挑战已过期，请重新取得。' : '有效至 ' + state.challenge.challenge.expires_at_utc + '。签名包含工作台来源与账户标识。' }}</p>
              <label for="owner-signature">本机 Ed25519 签名 · Base64</label><textarea id="owner-signature" v-model="signature" rows="3" maxlength="128" autocomplete="off" spellcheck="false" :disabled="backend.requiresHttps.value || busy || expired" placeholder="粘贴本机签出的 64 字节签名"></textarea>
              <div class="signature-actions"><button type="submit" class="primary-button" :disabled="backend.requiresHttps.value || busy || !signatureReady">核验签名并解锁</button><button type="button" class="text-button" @click="cancel">取消挑战</button></div>
            </form>
            <p v-else-if="state.errorCode === 'challenge_expired' || state.errorCode === 'owner_login_rejected' || state.errorCode === 'timeout'" class="field-hint">一次性挑战不自动重放。请重新取得挑战再签名。</p>
          </div>
        </div>
        <button v-if="state.auth === 'authenticated' || state.logoutStatus === 'unconfirmed' || state.authOperation === 'complete' || state.authOperation === 'session'" class="text-button logout-button" :disabled="state.authOperation === 'logout'" @click="backend.logout">{{ state.logoutStatus === 'unconfirmed' ? '重试确认所有者退出' : '锁定并退出所有者会话' }}</button>
        <p class="login-footnote">返回会丢弃未完成的挑战与签名；已核验的会话会保留。</p>
        <ConfigurationPanel v-if="!setupFirst" :backend="backend" />
      </div>
    </div>
  </section>
</template>
<style scoped>
.login-panel{color:var(--ink,#354348);width:100%;max-width:1040px;container-type:inline-size;container-name:access-panel;font-size:14px;line-height:1.7}.panel-heading{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;padding-bottom:24px;border-bottom:1px solid var(--line,#d4ddd9)}.eyebrow{font-size:10px;letter-spacing:.16em;color:var(--muted,#617177);margin:0 0 12px}.panel-heading h2{font-weight:450;font-size:clamp(25px,3vw,36px);letter-spacing:.025em;margin:0}.close-button{font-size:12px;white-space:nowrap;display:flex;gap:12px;align-items:center}.close-button span{font-size:20px}.access-grid{display:grid;grid-template-columns:minmax(220px,.88fr) minmax(0,1.12fr);gap:clamp(28px,5vw,64px);padding:32px 0 0}.login-lead{font-size:25px;line-height:1.55;letter-spacing:.025em;margin:0 0 18px;color:var(--ink,#354348)}.context-copy,.security-note{font-size:12px;color:var(--muted,#617177);margin:0;max-width:360px}.access-steps{list-style:none;padding:0;margin:28px 0}.access-steps li{display:flex;gap:15px;padding:14px 0;border-top:1px solid var(--line,#d4ddd9)}.access-steps li>span{font-size:10px;letter-spacing:.1em;color:#7a8d64;padding-top:2px}.access-steps strong{font-weight:500;font-size:12px}.access-steps p{margin:3px 0 0;font-size:11px;color:var(--muted,#617177)}.security-note{font-size:10px;margin-top:8px}.security-details summary{font-size:10px;cursor:pointer;min-height:32px}.disclosure-mark{width:8px;height:8px;border-right:1px solid currentColor;border-bottom:1px solid currentColor;transform:rotate(-45deg);margin-right:4px}.disclosure-mark.open{transform:rotate(45deg)}.arrow-icon{display:inline-block;width:7px;height:7px;border-top:1px solid currentColor;border-right:1px solid currentColor}.arrow-icon.forward{transform:rotate(45deg)}.session-status{display:flex;align-items:center;gap:10px;font-size:13px}.session-status strong{font-weight:500}.status-point{width:7px;height:7px;background:#9aa7a3;border-radius:50%}.status-point.verified{background:#859d58}.offline-note,.login-note{font-size:12px;color:var(--muted,#617177);line-height:1.8}.offline-note{background:#eaf0e8;padding:14px 16px;margin:16px 0;border:1px solid #d5dfd0;border-radius:3px}.auth-layers{margin:20px 0 24px}.auth-layers>div{display:flex;justify-content:space-between;gap:20px;border-bottom:1px solid var(--line,#cbd6d8);padding:12px 0;font-size:12px}.auth-layers dd{margin:0;color:var(--muted,#617177);text-align:right}button{font:inherit;min-height:44px;cursor:pointer}button:disabled{cursor:default}.primary-button,.secondary-button{background:#dde7ce;color:#354348;min-height:44px;padding:11px 17px;border:1px solid #bac9a5;border-radius:3px;font-size:12px}.full-button{width:100%;display:flex;align-items:center;justify-content:space-between}.primary-button:disabled,.secondary-button:disabled{background:#edf0ed;color:#697879;border-color:#d3dada}.secondary-button{background:transparent;margin-top:15px}.owner-details{margin-top:24px;padding-top:8px;border-top:1px solid var(--line,#cbd6d8)}.signing-toggle{font-size:12px;cursor:pointer;width:100%;display:flex;align-items:center;justify-content:space-between;padding:7px 0;text-align:left}.signing-toggle>span{font-size:18px}.pairing-fields{border:0;padding:0;margin:20px 0 0;display:grid;grid-template-columns:1fr 1fr;gap:15px 18px}.pairing-fields label{display:flex;flex-direction:column;gap:3px;font-size:11px;min-width:0}.field-id{font-size:9px;color:var(--muted,#617177);letter-spacing:.015em;overflow-wrap:anywhere}.login-panel input,.login-panel textarea{box-sizing:border-box;display:block;width:100%;font:inherit;font-size:12px;background:#f9fbf7;color:#354348;border:1px solid #bdcacc;border-radius:3px;padding:10px;min-height:44px}.login-panel input:disabled{background:#edf0ee}.login-panel textarea{resize:vertical;overflow-wrap:anywhere}.signature-form,.scope-form{margin-top:22px}.signature-form>label,.scope-form>label{display:block;font-size:12px;margin:14px 0 7px}.signature-actions{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin:15px 0}.field-hint,.login-footnote,.action-progress{font-size:10px;color:var(--muted,#617177);line-height:1.8}.action-progress{font-size:12px}.login-footnote{margin:24px 0 0}.text-button{font-size:12px;padding:8px 0}.logout-button{margin-top:18px;color:#79533e}.panel-error{font-size:12px;color:#874933;border-left:2px solid #a36a50;padding:10px 12px;background:#f2e9e2}.expired{color:#874933}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}input:focus-visible,textarea:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid #587020;outline-offset:3px}@container access-panel (max-width:720px){.access-grid{grid-template-columns:1fr;gap:24px;padding-top:24px}.access-context{padding-bottom:20px;border-bottom:1px solid var(--line,#d4ddd9)}.login-lead{font-size:22px}.login-lead br{display:none}.access-steps{margin:20px 0;display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}.access-steps li{gap:8px}.context-copy,.security-note{max-width:none}}@media(max-width:420px){.pairing-fields{grid-template-columns:1fr}.access-steps{grid-template-columns:1fr}.access-steps li{padding:10px 0}.panel-heading h2{font-size:24px}}

/* A real request is indeterminate; only backend state can produce the verified mark. */
.session-status{min-height:28px}.status-point{transition:background-color .25s ease,box-shadow .25s ease}.is-checking .status-point{background:#87966f;animation:session-breathe 1.6s ease-in-out infinite}.is-verified .status-point{box-shadow:0 0 0 4px #8a9c6420}.has-error .status-point{background:#a57c61}
.verification-status{display:grid;grid-template-columns:1fr auto;gap:8px 12px;align-items:center;padding:16px 0 20px}.verification-meter{grid-column:1/-1;position:relative;display:block;height:1px;background:#d4dccb;overflow:hidden}.verification-meter:after{content:'';position:absolute;inset:0;width:32%;background:#71825c;animation:session-scan 1.45s ease-in-out infinite}.verification-status .action-progress{margin:0;font-size:11px}.verification-code{font-size:7px;letter-spacing:.1em;color:#7b8671}.step-complete strong{color:#5c704a}.step-waiting>span{animation:session-breathe 1.6s ease-in-out infinite}.full-button{transition:background-color .2s ease,border-color .2s ease}.full-button:not(:disabled):hover{background:#d4dfc5;border-color:#9eaf84}.panel-error{animation:session-message-in .25s ease both}
@keyframes session-scan{from{transform:translateX(-110%)}to{transform:translateX(420%)}}@keyframes session-breathe{0%,100%{opacity:.45}50%{opacity:1}}@keyframes session-message-in{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:translateY(0)}}
@media(prefers-reduced-motion:reduce){.verification-meter:after{animation:none;width:100%;opacity:.5}.is-checking .status-point,.step-waiting>span,.panel-error{animation:none}.status-point,.full-button{transition:none}}

.access-grid{display:block;padding-top:20px}.panel-heading h2{font-size:25px}.eyebrow{letter-spacing:.12em}.panel-heading{padding-bottom:18px}.offline-note{background:none;padding:0;border:0}.primary-button,.secondary-button,.login-panel input,.login-panel textarea{border-radius:0}.login-panel{max-width:570px}.pairing-fields{gap:12px 18px}
</style>
