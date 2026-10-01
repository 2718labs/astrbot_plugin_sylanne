<script setup lang="ts">
import {ref, reactive, watch, onBeforeUnmount, nextTick} from 'vue'
import {WorkbenchApi} from '../../../webui-src/src/api/client.js'
import {makeOwnerLoginRequest} from '../../../webui-src/src/api/contract.js'
const props=defineProps<{unlocked:boolean}>()
const emit=defineEmits<{ready:[]; locked:[]}>()
const api=new WorkbenchApi()
const fields=[['authority_id','Authority ID'],['authority_namespace','Authority 命名空间'],['installation_id','安装 ID'],['identity_provider','身份提供方'],['account_ref','Owner 账号引用'],['account_incarnation','账号实例'],['credential_id','已登记凭据 ID'],['credential_epoch','凭据版本']]
const draft=reactive<Record<string,string>>({})
const busy=ref(false), problem=ref(''), signature=ref(''), payload=ref('')
const challenge=ref<Record<string,unknown>|null>(null)
let epoch=0
const secure=globalThis.location?.origin?.startsWith('https://') ?? false
function clearChallenge(){challenge.value=null;payload.value='';signature.value=''}
watch(()=>props.unlocked,()=>{++epoch;busy.value=false;clearChallenge()})
onBeforeUnmount(()=>{++epoch;clearChallenge();api.clearSession()})
async function start(){
 if(busy.value)return
 const e=++epoch;problem.value='';clearChallenge()
 try{
  const request=makeOwnerLoginRequest(draft,globalThis.location.origin)
  busy.value=true;const result=await api.ownerChallenge(request)
  if(e!==epoch)return
  challenge.value=result.challenge;payload.value=result.signingPayloadBase64
 }catch(error){if(e===epoch)problem.value=error instanceof Error?error.message:'挑战未取得'}
 finally{if(e===epoch)busy.value=false}
}
async function complete(){
 if(busy.value||!challenge.value)return
 const e=++epoch;busy.value=true;problem.value=''
 try{
  if(!signature.value.trim())throw new Error('请填入本机签名的标准 Base64，不要填写私钥。')
  await api.ownerComplete(challenge.value,signature.value.trim());if(e!==epoch)return
  clearChallenge();emit('ready')
 }catch(error){if(e===epoch){clearChallenge();problem.value=error instanceof Error?error.message:'签名未确认'}}
 finally{if(e===epoch)busy.value=false}
}
async function logout(){
 if(busy.value)return
 ++epoch;busy.value=true;problem.value='';clearChallenge();api.clearSession();emit('locked');await nextTick()
 const e=++epoch;busy.value=true
 try{await api.ownerLogout()}catch(error){if(e===epoch)problem.value=error instanceof Error?error.message:'页面已锁定，但服务端退出未确认'}finally{if(e===epoch)busy.value=false}
}
function restart(){++epoch;busy.value=false;clearChallenge();problem.value=''}
</script>
<template>
 <section class="owner-access panel"><h2>Owner 签名登录</h2><p>先完成管理员安装登记与 Owner 配对。这里仅提交挑战签名，私钥始终留在你本机。</p>
 <p v-if="problem" class="notice" role="alert">{{problem}}</p>
 <template v-if="unlocked"><p>当前 Owner 会话已核验。</p><button class="quiet" :disabled="busy" @click="logout">退出 Owner 并清空页面</button></template>
 <p v-else-if="!secure" class="notice">请从已配置的受信 HTTPS 工作台入口打开，以建立签名会话。</p>
 <form v-else-if="!challenge" @submit.prevent="start"><div class="owner-fields"><label v-for="[name,label] in fields" :key="name">{{label}}<input v-model="draft[name!]" :name="name" required autocomplete="off" /></label></div><button class="accent" :disabled="busy">获取签名挑战</button></form>
 <form v-else @submit.prevent="complete"><p>将 Base64 解码为原始字节，用已登记的 Ed25519 私钥在本机签名；只粘贴 64 字节签名的标准 Base64。</p><label>待签名原文 Base64<textarea :value="payload" readonly spellcheck="false" /></label><p>挑战有效期：{{challenge.expires_at_utc}}</p><label>签名 Base64<textarea v-model="signature" required autocomplete="off" spellcheck="false" /></label><button class="accent" :disabled="busy">验证签名并解锁</button><button type="button" class="quiet" @click="restart">取消并重新开始</button></form>
 </section>
</template>
<style scoped>
.owner-access{margin:20px 0}.owner-access p{font-size:12px;line-height:1.65}.owner-fields{display:grid;grid-template-columns:1fr 1fr;gap:12px}.owner-access label{display:grid;gap:6px;font-size:12px;margin:10px 0}.owner-access input,.owner-access textarea{width:100%;padding:10px;background:#faf8f2;border:1px solid #bcb5a8;color:#34312b;font:12px/1.5 var(--font-mono)}.owner-access textarea{min-height:100px;resize:vertical;overflow-wrap:anywhere}.owner-access button{margin:10px 12px 0 0}.owner-access button:disabled{opacity:.5}@media(max-width:600px){.owner-fields{grid-template-columns:1fr}}
</style>
