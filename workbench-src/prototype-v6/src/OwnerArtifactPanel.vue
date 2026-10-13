<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { ProjectContextOptions } from './api/project-context.ts'
import type { OwnerArtifactOptions, OwnerArtifactBody } from './api/owner-artifact.ts'

const props = defineProps<{ backend: BackendController }>()
const projects = ref<ProjectContextOptions | null>(null), project = ref(''), options = ref<OwnerArtifactOptions | null>(null), selected = ref('')
const body = ref<OwnerArtifactBody | null>(null), busy = ref(false), message = ref('')
let generation = 0
const eligible = computed(() => props.backend.canRead.value && !busy.value)
const knownProject = computed(() => projects.value?.items.some(item => item.project_ref === project.value) === true)
const item = computed(() => options.value?.items.find(value => value.progress_ref === selected.value))
const canOptions = computed(() => eligible.value && knownProject.value)
const canOpen = computed(() => eligible.value && !!options.value && !!item.value)
const current = (token: number, scope: string) => token === generation && scope === props.backend.state.scope && props.backend.canRead.value
function clear() { ++generation; projects.value = null; project.value = ''; options.value = null; selected.value = ''; body.value = null; message.value = '' }
watch(() => [props.backend.state.scope, props.backend.state.auth, props.backend.runtimeReadable.value], clear, { flush: 'sync' })
onBeforeUnmount(clear)
async function discover() {
  if (!eligible.value) return
  const token = generation, scope = props.backend.state.scope
  busy.value = true; projects.value = null; options.value = null; body.value = null; message.value = '正在读取当前获准项目目录。'
  try { const data = await props.backend.projectContext.read(scope); if (!current(token, scope)) return; projects.value = data
    if (!data.items.some(value => value.project_ref === project.value)) project.value = ''
    message.value = data.items.length ? '请选择真实项目，再读取其已核验作品版本。' : '当前没有可选择的获准项目。'
  } catch { if (token === generation) message.value = '项目目录未取得，请核验当前所有者权限和实际运行状态。' }
  finally { busy.value = false }
}
async function readOptions() {
  if (!canOptions.value) return
  const token = generation, scope = props.backend.state.scope, projectRef = project.value
  busy.value = true; options.value = null; selected.value = ''; body.value = null; message.value = '正在读取当前项目的真实作品原件目录。'
  try { const data = await props.backend.artifacts.options(scope, projectRef); if (!current(token, scope) || projectRef !== project.value) return
    options.value = data; message.value = data.items.length ? '请选择明确的作品版本；打开时会再次核验当前权限、来源和文件。' : '该项目没有当前可读取的已采用作品。'
  } catch { if (token === generation) message.value = '作品目录未取得或超出本次有界读取范围。请重读，不会使用示例或缓存。' }
  finally { busy.value = false }
}
watch(project, () => { ++generation; options.value = null; selected.value = ''; body.value = null; message.value = ''; if (canOptions.value) void readOptions() }, { flush: 'sync' })
watch(selected, () => { ++generation; body.value = null; message.value = '' }, { flush: 'sync' })
async function open() {
  if (!canOpen.value || !options.value || !item.value) return
  const token = generation, scope = props.backend.state.scope, snapshot = options.value, target = item.value
  busy.value = true; body.value = null; message.value = '正在通过当前所有者读取完整已核验文本。'
  try { const result = await props.backend.artifacts.read(scope, snapshot, target); if (!current(token, scope)) return
    body.value = result; message.value = '完整文本与所选原件的版本、字节长度和哈希一致。读取结果不增加执行权限。'
  } catch { if (token === generation) message.value = '作品正文未取得。可能已失效、未授权、文件版本变化或超出当前读取范围；没有显示旧正文或未经核验的前缀。' }
  finally { busy.value = false }
}
</script>

<template>
  <section class="owner-artifact" aria-labelledby="owner-artifact-title" :aria-busy="busy">
    <h4 id="owner-artifact-title">作品阅读</h4><p>选择已采用的真实文本版本。此入口不提交新作品，不代替模型或工具执行。</p>
    <button :disabled="!eligible" @click="discover">读取获准项目</button>
    <p v-if="!backend.canRead.value" role="status">先核验当前所有者会话、角色范围和实际运行状态。</p>
    <label v-if="projects?.items.length" for="artifact-project">作品所属项目<select id="artifact-project" v-model="project" :disabled="busy"><option value="">请选择项目</option><option v-for="(value,index) in projects.items" :key="value.project_ref" :value="value.project_ref">项目 {{ index + 1 }} · {{ value.project_ref }}</option></select></label>
    <button v-if="knownProject" :disabled="!canOptions" @click="readOptions">重读作品版本目录</button>
    <label v-if="options?.items.length" for="artifact-version">要打开的真实版本<select id="artifact-version" v-model="selected" :disabled="busy"><option value="">请选择作品版本</option><option v-for="value in options.items" :key="value.progress_ref" :value="value.progress_ref">版本 {{ value.artifact_version }} · {{ value.content_length_bytes }} 字节 · {{ value.artifact_ref }}</option></select></label>
    <button v-if="item" class="open-artifact" :disabled="!canOpen" @click="open">打开所选作品</button>
    <article v-if="body" class="artifact-text" aria-label="已核验作品正文"><p>版本 {{ body.artifact_version }} · {{ body.content_length_bytes }} 字节</p><pre tabindex="0">{{ body.body }}</pre><details><summary>查看本次作品摘要</summary><code>{{ body.content_digest }}</code></details></article>
    <p v-if="message" role="status" aria-live="polite">{{ message }}</p>
  </section>
</template>

<style scoped>
.owner-artifact{margin-top:24px;border-top:1px solid var(--line);padding-top:20px;font-size:12px;line-height:1.8;overflow-wrap:anywhere}.owner-artifact h4{font-size:16px;font-weight:500;margin:0 0 12px}.owner-artifact p{color:var(--muted)}label{display:grid;gap:8px;margin:14px 0}select{width:100%;max-width:100%;box-sizing:border-box;min-height:44px;padding:10px;font:inherit;background:var(--surface);color:var(--ink);border:1px solid var(--line);border-radius:3px}button{min-height:44px;font:inherit;text-align:left;padding:10px 0;cursor:pointer}button:disabled{cursor:default;color:var(--muted)}.open-artifact{display:block;width:100%;border-top:1px solid var(--line)}.artifact-text{margin:16px 0;padding:14px;border:1px solid var(--line);border-radius:4px}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:55svh;overflow:auto;font:inherit;line-height:1.9;color:var(--ink);margin:12px 0}code{display:block;overflow-wrap:anywhere;font-size:10px}button:focus-visible,select:focus-visible,pre:focus-visible,summary:focus-visible{outline:2px solid var(--ink);outline-offset:3px}
</style>
