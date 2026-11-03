<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { OwnerSourceMetadata, OwnerSourcePage, OwnerSourceDetail } from './api/source-owner-read.ts'
import { WorkbenchApiError } from './api/client.ts'
import SourceCorrectionPanel from './SourceCorrectionPanel.vue'
import SourceErasurePanel from './SourceErasurePanel.vue'
const props = defineProps<{ backend: BackendController }>()
const page = ref<OwnerSourcePage | null>(null), detail = ref<OwnerSourceDetail | null>(null)
const busy = ref(false), message = ref(''), correctionSource = ref(''), pageNumber = ref(0)
let generation = 0
const eligible = computed(() => props.backend.canRead.value && !busy.value)
function clearRead() { ++generation; page.value = null; detail.value = null; message.value = ''; pageNumber.value = 0 }
function clear() { clearRead(); correctionSource.value = '' }
watch(() => [props.backend.state.scope, props.backend.state.auth, props.backend.state.owner, props.backend.canRead.value, props.backend.state.workspace.data?.access_generation], clear, { flush: 'sync' })
watch(() => props.backend.sources.generation.value, clearRead, { flush: 'sync' })
onBeforeUnmount(clear)
const current = (token: number, scope: string) => token === generation && scope === props.backend.state.scope && props.backend.canRead.value
function readError(error: unknown) {
  return error instanceof WorkbenchApiError && error.code === 'legacy_metadata_unavailable' ? '旧记录缺少正式来源元数据投影，当前目录或正文尚不能读取。请前往“高级配置 → 记忆与关系 → 旧来源记录维护”，在 Host 在线时受理正式维护；保留原操作查询完成后，再独立重读。' : error instanceof WorkbenchApiError && error.code === 'source_cursor_stale' ? '目录快照已变化或游标已失效，请从第一页重新读取。' : error instanceof WorkbenchApiError && ['source_read_deferred', 'source_read_incomplete'].includes(error.code) ? '本次读取尚未完成，未显示部分目录或正文。请手动重试；没有推定已到末页。' : '当前来源读取未完成。请核验会话和权限后重新读取。'
}
async function load(next = false) {
  if (!eligible.value || next && !page.value?.next_cursor) return
  const cursor = next ? page.value!.next_cursor : null, number = next ? pageNumber.value + 1 : 1
  const token = ++generation, scope = props.backend.state.scope
  busy.value = true; page.value = null; detail.value = null; correctionSource.value = ''; message.value = '正在读取当前获准来源目录。'
  try { const result = await props.backend.sources.page(scope, cursor); if (!current(token, scope)) return
    page.value = result; pageNumber.value = number; message.value = result.sources.length ? '目录仅显示来源信息。打开正文会独立核验当前来源与权限。' : '本次当前授权目录没有返回记录。'
  } catch (error) { if (current(token, scope)) { pageNumber.value = 0; message.value = readError(error) } }
  finally { busy.value = false }
}
async function open(selected: OwnerSourceMetadata) {
  if (!eligible.value || !page.value?.sources.includes(selected)) return
  const token = ++generation, scope = props.backend.state.scope
  busy.value = true; detail.value = null; correctionSource.value = ''; message.value = '正在核验所选版本的正文读取资格。'
  try { const result = await props.backend.sources.detail(scope, selected); if (!current(token, scope)) return
    detail.value = result; message.value = '正文来自本次独立授权读取；来源断言状态不等于事实资格。'
  } catch (error) { if (current(token, scope)) { page.value = null; pageNumber.value = 0; message.value = readError(error) } }
  finally { busy.value = false }
}
function closeDetail() { ++generation; detail.value = null }
</script>
<template>
  <section class="sources-panel" aria-labelledby="sources-title" :aria-busy="busy">
    <h4 id="sources-title">来源目录与正文</h4>
    <p>当前页只保留获准来源信息。正文须逐条打开，下一页会替换本页。</p>
    <button :disabled="!eligible" @click="load(false)">从第一页读取来源目录</button>
    <p v-if="page">第 {{ pageNumber }} 页 · 本次 {{ page.sources.length }} 条</p>
    <article v-for="source in page?.sources" :key="source.source_id" class="source-card">
      <h5>{{ source.source_id }}</h5>
      <dl><div><dt>版本</dt><dd>{{ source.revision }}</dd></div><div><dt>来源类型</dt><dd>{{ source.source_kind }}</dd></div><div><dt>断言状态</dt><dd>{{ source.assertion_status }}</dd></div><div><dt>记录时间</dt><dd>{{ source.recorded_at }}</dd></div><div><dt>资格记录</dt><dd>未记录 · {{ source.qualification }}</dd></div></dl>
      <button :disabled="!eligible" @click="open(source)">独立授权读取此版本正文</button>
      <button :disabled="!eligible" @click="correctionSource = source.source_id; closeDetail()">查看更正与删除依据</button>
    </article>
    <button v-if="page?.has_more" :disabled="!eligible" @click="load(true)">读取下一页</button>
    <p v-else-if="page">本次快照中已无后续获准记录。</p>
    <article v-if="detail" class="source-body" aria-label="本次获准来源正文"><h5>{{ detail.source.source_id }} · 版本 {{ detail.source.revision }}</h5><pre tabindex="0">{{ detail.source.text }}</pre><button @click="closeDetail">关闭正文</button></article>
    <p v-if="message" role="status" aria-live="polite">{{ message }}</p>
    <template v-if="backend.canRead.value"><SourceCorrectionPanel :backend="backend" :source-id="correctionSource" @select-source="correctionSource = $event"/><SourceErasurePanel :backend="backend" :source-id="correctionSource" @select-source="correctionSource = $event"/></template>
  </section>
</template>
<style scoped>
.sources-panel{font-size:12px;line-height:1.8;overflow-wrap:anywhere}.sources-panel h4{font-size:16px;font-weight:500}.source-card,.source-body{border:1px solid var(--line);padding:16px;margin:16px 0;border-radius:4px}h5{font:inherit;font-weight:500;margin:0 0 12px}dl{margin:0}dl>div{display:flex;justify-content:space-between;gap:14px;border-top:1px solid var(--line);padding:8px 0}dd{margin:0;text-align:right}button{min-height:44px;padding:10px 0;font:inherit;text-align:left;display:block;cursor:pointer}button:disabled{cursor:default;color:var(--muted)}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:55svh;overflow:auto;font:inherit}button:focus-visible,pre:focus-visible{outline:2px solid var(--ink);outline-offset:3px}
</style>
