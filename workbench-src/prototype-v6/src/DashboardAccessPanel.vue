<script setup lang="ts">
import {computed,onBeforeUnmount,onMounted,ref} from 'vue'
import {hasFields,isInteger} from './api/contract.ts'
import {HTTP_TRANSPORT_MESSAGE} from './api/client.ts'
const emit=defineEmits<{authenticated:[]}>()
const username=ref(''),password=ref(''),code=ref(''),busy=ref(false),message=ref(''),listener=ref<string|null>(null),modules=ref<Record<string,boolean>|null>(null),originPending=ref(false),tlsLoaded=ref(false)
const secure=computed(()=>window.location.protocol==='https:')
const controlsMessage=ref('后台登录后可读取模块许可。')
let alive=true
const labels=['主体与人格','身体与需求','世界与情境','情绪与调节','社会关系','记忆系统','注意与认知','动机与执行','对话与表达','生活与主动行为','运行内核与宿主','工作台与交付','短期上下文']
async function readControls(){
  const response=await fetch('/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1/host-controls/v1',{credentials:'same-origin',mode:'same-origin',cache:'no-store',referrerPolicy:'same-origin',signal:AbortSignal.timeout(8000)})
  if(!response.ok){if(alive)controlsMessage.value=response.status===401?'后台登录后可读取模块许可。':'模块许可读取失败，请检查插件版本及入口状态。';return}
  const data=await response.json()
  if(!alive||data.schema_version!=='sylanne.host-controls.v1')return
  modules.value=data.modules.startup_values
  controlsMessage.value=''
  originPending.value=!!data.required_origin&&data.required_origin!==window.location.origin
  return true
}
async function login(){
  if(busy.value)return
  busy.value=true;message.value='正在核验 AstrBot 后台登录。'
  const submitted=password.value;password.value=''
  try{
    const response=await fetch('/api/v1/auth/login',{method:'POST',credentials:'same-origin',mode:'same-origin',referrerPolicy:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:username.value,password:submitted,code:code.value,trust_device_flag:false}),signal:AbortSignal.timeout(10000)})
    const result=await response.json()
    if(!alive)return
    if(response.ok&&result.status==='ok'){
      code.value='';message.value='后台登录已确认。高级配置可读取；Owner 会话需单独核验。'
      emit('authenticated');await readControls()
    }else message.value=result.data?.totp_required?'AstrBot 要求二次验证码，请填写后重新输入密码。':'后台登录未通过，请核对账户、密码与二次验证码。'
  }catch{if(alive)message.value='登录结果未确认。请先核对已有会话，再决定是否重新登录。'}
  finally{if(alive)busy.value=false}
}
onMounted(async()=>{
  try{
    const response=await fetch('/webui/status',{credentials:'omit',cache:'no-store',signal:AbortSignal.timeout(8000)})
    if(response.ok){const data=await response.json();if(alive&&hasFields(data,['schema_version','startup_values','scheme','state','reason_code'],['bound_addresses','access_hint'])&&data.schema_version==='sylanne.webui-listener-status.v1'&&hasFields(data.startup_values,['enabled','bind','port'])&&typeof data.startup_values.enabled==='boolean'&&typeof data.startup_values.bind==='string'&&isInteger(data.startup_values.port)&&data.startup_values.port<=65535&&['http','https'].includes(data.scheme as string)&&['disabled','stopped','starting','blocked','listening'].includes(data.state as string)&&typeof data.reason_code==='string'&&/^[A-Za-z0-9_.:-]{1,128}$/.test(data.reason_code)){listener.value=`${String(data.scheme).toUpperCase()} · ${data.state} · 端口 ${Array.isArray(data.bound_addresses)&&data.bound_addresses.length?data.bound_addresses[0].port:data.startup_values.port}`;tlsLoaded.value=data.scheme==='https'&&data.state==='listening'}}
    if(await readControls())emit('authenticated')
  }catch{if(alive)listener.value='独立入口状态未取得，可显式刷新页面。'}
})
onBeforeUnmount(()=>{alive=false;password.value='';code.value=''})
</script>
<template>
 <section class="dashboard-access" aria-label="后台登录与模块状态">
  <p v-if="listener" class="connection-status" role="status">独立 WebUI：{{listener}}</p>
  <p v-if="!secure" class="connection-warning" role="status">{{HTTP_TRANSPORT_MESSAGE}}</p>
  <p v-if="tlsLoaded" class="connection-status" role="status">独立 WebUI 已加载 HTTPS 证书并开始监听。请用与证书匹配的域名/IP，在浏览器中确认所打开地址的证书有效。</p>
  <details class="tls-guidance">
   <summary>可选 HTTPS / Docker 配置步骤</summary>
   <ol>
    <li>在 AstrBot 全局配置页找到“启用 WebUI HTTPS”“SSL 证书文件路径”“SSL 私钥文件路径”，启用 HTTPS 并填写 PEM 文件路径；需要时填写 CA 证书。对应设置为 <code>dashboard.ssl.enable</code>、<code>dashboard.ssl.cert_file</code>、<code>dashboard.ssl.key_file</code> 与可选的 <code>dashboard.ssl.ca_certs</code>。保留原 <code>dashboard</code> 的其它配置。</li>
    <li>也可修改实际全局配置 <code>data/cmd_config.json</code>。标准 <code>/AstrBot</code> Docker 目录下为 <code>/AstrBot/data/cmd_config.json</code>；使用自定义 data-dir 时，以进程实际数据目录中的 <code>cmd_config.json</code> 为准。</li>
    <li>证书与私钥文件须在 AstrBot 进程/容器内可读。以下仅是容器路径示例：<code>/AstrBot/data/certs/webui-cert.pem</code> 和 <code>/AstrBot/data/certs/webui-key.pem</code>。将证书目录挂载到容器对应目录；配置填写文件路径。证书必须匹配实际访问的域名或 IP。</li>
    <li>环境变量可使用 <code>DASHBOARD_SSL_ENABLE</code>、<code>DASHBOARD_SSL_CERT</code>、<code>DASHBOARD_SSL_KEY</code>、<code>DASHBOARD_SSL_CA_CERTS</code>，对应别名为 <code>ASTRBOT_DASHBOARD_SSL_ENABLE</code>、<code>ASTRBOT_DASHBOARD_SSL_CERT</code>、<code>ASTRBOT_DASHBOARD_SSL_KEY</code>、<code>ASTRBOT_DASHBOARD_SSL_CA_CERTS</code>。启用值使用 <code>true</code>，证书变量填写容器内可读路径。</li>
    <li>Docker 使用默认独立入口时映射 <code>2718:2718</code>；自定义端口需匹配容器内实际 listener 端口。完成全局 TLS 配置后，重启实际 AstrBot 进程，再核对启动日志与 listener 状态。</li>
    <li>只有独立入口状态为 <code>listening</code> 且协议为 <code>https</code>，才能说明 HTTPS 证书已加载并开始监听。HTTP 页面不会把当前地址直接替换成 HTTPS。重启后，在浏览器打开与证书匹配的 HTTPS 地址，再验证页面、证书与地址栏。</li>
   </ol>
  </details>
  <details>
   <summary>AstrBot 后台登录</summary>
   <form @submit.prevent="login">
    <label>账户<input v-model="username" autocomplete="username" required :disabled="busy"></label>
    <label>密码<input v-model="password" type="password" autocomplete="current-password" required :disabled="busy"></label>
    <label>二次验证码（已启用时）<input v-model="code" autocomplete="one-time-code" :disabled="busy"></label>
    <button type="submit" :disabled="busy">{{busy?'核验中':'登录当前后台'}}</button>
   </form>
  </details>
  <p v-if="message" role="status">{{message}}</p>
  <p v-if="controlsMessage" role="status">{{controlsMessage}}</p>
  <p v-if="originPending" class="connection-warning">当前端口来源与已安装 Owner 来源不匹配。高级 Host 配置可用；Owner 操作保持阻断，需管理员按正式安装协议登记当前精确的 HTTP/HTTPS 来源。</p>
  <details v-if="modules"><summary>D01–D13 当前模块许可</summary><ul><li v-for="(label,index) in labels" :key="index">D{{String(index+1).padStart(2,'0')}} {{label}}：{{modules['d'+String(index+1).padStart(2,'0')]?'允许新工作':'已关闭新工作'}}</li></ul><p>在 AstrBot 插件配置页切换并重载后生效；允许仍需当前授权。</p></details>
 </section>
</template>
<style scoped>
.dashboard-access{padding:12px 0 20px;border-bottom:1px solid var(--line);font-size:12px}.connection-status{color:var(--muted)}.connection-warning{line-height:1.8;color:var(--ink)}details{margin:12px 0}summary{cursor:pointer;padding:8px 0}form{display:grid;gap:12px;padding:12px 0}label{display:grid;gap:6px}input,button{font:inherit;min-height:44px;padding:8px 12px;border:1px solid var(--line);color:var(--ink);background:var(--panel-bg,transparent)}button{cursor:pointer}input:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid var(--ink);outline-offset:3px}ul{padding-left:18px;line-height:1.9}
</style>
