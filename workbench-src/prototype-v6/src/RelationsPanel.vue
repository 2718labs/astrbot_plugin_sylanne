<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { RelationsProjection } from './api/relations.ts'
const props = defineProps<{ backend: BackendController }>()
const projection = ref<RelationsProjection | null>(null), page = ref(0), busy = ref(false), message = ref('')
let generation = 0
const catalogue = computed(() => props.backend.state.workspace.data)
const eligible = computed(() => props.backend.canRead.value && !busy.value && catalogue.value?.views.some(view => view.view_type === 'relations' && view.status === 'available') === true)
const numberLabel = (value: number | 'unknown' | null | undefined) => typeof value === 'number' ? String(value) : '未知'
const statusLabel = (value: string) => ({ available: '当前可用', unavailable: '不可用', unknown: '未知', stale: '已过期', blocked_rebuild: '等待重建', rebuilt: '已重建', sanitized: '已清理', reset: '已重置', current: '当前有效', time_unavailable: '当前时间未核验', qualified: '来源符合查看条件', complete: '完整', partial: '部分', bounded_applied: '在既有边界内应用', unapplied_pending: '尚未应用', not_evaluated: '未评估', legacy_unresolved: '旧状态尚未核实' }[value] ?? value)
function clear() { ++generation; projection.value = null; page.value = 0; message.value = '' }
watch(() => [props.backend.state.scope, props.backend.state.auth, props.backend.runtimeReadable.value, catalogue.value?.access_generation], clear, { flush: 'sync' })
onBeforeUnmount(clear)
async function read(next = false) {
  if (!eligible.value || next && !projection.value?.next_cursor) return
  const previous = projection.value, token = generation, scope = props.backend.state.scope, cursor = next ? previous!.next_cursor! : null
  const nextPage = next ? page.value + 1 : 1
  busy.value = true; projection.value = null; message.value = '正在读取当前获准的关系维度。'
  try {
    const result = await props.backend.relations.read(scope, cursor)
    if (token !== generation || scope !== props.backend.state.scope || !props.backend.canRead.value) return
    if (result.status !== 'ready' || !result.projection) { message.value = '当前关系投影未就绪，请核验状态后明确重读。'; return }
    const data = result.projection
    if (data.access_generation !== catalogue.value?.access_generation || next && previous && (data.access_generation !== previous.access_generation || data.snapshot_epoch !== previous.snapshot_epoch)) {
      page.value = 0; message.value = '关系快照或访问版本已变化，请从第一页重读。'; return
    }
    projection.value = data; page.value = nextPage
    message.value = data.data.relations.length ? '只显示本次读取的当前页；主观估计不会改变权限或承诺关系修复完成。' : '本次读取没有公开关系维度。'
  } catch { if (token === generation) message.value = '关系维度未取得，请核验当前会话、角色范围和实际运行状态。' }
  finally { busy.value = false }
}
</script>
<template>
  <section class="relations-panel" aria-labelledby="relations-panel-title" :aria-busy="busy">
    <h4 id="relations-panel-title">关系维度</h4>
    <p>分别查看对象、领域和情境中的主观估计。来源符合查看条件，不代表可信度自动提高；未知状态保留为未知。</p>
    <button :disabled="!eligible" @click="read()">{{ busy ? '正在读取关系…' : projection ? '从第一页刷新关系' : '读取获准关系维度' }}</button>
    <template v-if="projection">
      <p>第 {{ page }} 页 · {{ projection.data.relations.length }} 个对象{{ projection.coverage?.truncated || projection.next_cursor ? ' · 还有未显示记录' : '' }}</p>
      <article v-for="relation in projection.data.relations" :key="relation.subject_entity_ref" class="relation-card">
        <h5>{{ relation.subject_entity_ref }}</h5>
        <section v-for="dimension in relation.dimensions" :key="JSON.stringify([dimension.dimension, dimension.domain, dimension.context_id])" class="dimension-row">
          <h6>{{ dimension.dimension }}</h6>
          <dl>
            <div v-if="dimension.domain"><dt>领域</dt><dd>{{ dimension.domain }}</dd></div>
            <div v-if="dimension.context_id"><dt>情境标识</dt><dd>{{ dimension.context_id }}</dd></div>
            <div><dt>可用状态</dt><dd>{{ statusLabel(dimension.availability) }}</dd></div>
            <div v-if="dimension.time_status"><dt>时间状态</dt><dd>{{ statusLabel(dimension.time_status) }}</dd></div>
            <div><dt>主观估计</dt><dd>{{ numberLabel(dimension.estimate) }}{{ typeof dimension.estimate === 'number' ? '（范围 −1 至 1）' : '' }}</dd></div>
            <div v-if="dimension.subjective_confidence !== undefined"><dt>主观置信度</dt><dd>{{ numberLabel(dimension.subjective_confidence) }}</dd></div>
            <div><dt>来源资格</dt><dd>{{ statusLabel(dimension.source_qualification) }}</dd></div>
            <div v-if="dimension.evidence_coverage"><dt>证据覆盖</dt><dd>{{ statusLabel(dimension.evidence_coverage) }}</dd></div>
            <div v-if="dimension.independent_external_families !== undefined"><dt>独立外部来源族</dt><dd>{{ dimension.independent_external_families }}</dd></div>
            <div><dt>影响状态</dt><dd>{{ statusLabel(dimension.influence_status) }}</dd></div>
          </dl>
          <p v-if="dimension.diagnostic_error">旧关系状态尚未注册，估计保持未知。</p>
        </section>
        <p v-if="!relation.dimensions.length">此对象没有当前公开的维度。</p>
      </article>
      <button v-if="projection.next_cursor" :disabled="!eligible" @click="read(true)">读取下一页关系</button>
    </template>
    <p v-if="message" role="status" aria-live="polite">{{ message }}</p>
  </section>
</template>
<style scoped>
.relations-panel{margin-top:24px;border-top:1px solid var(--line);padding-top:20px;font-size:12px;line-height:1.8;overflow-wrap:anywhere}.relations-panel h4{font-size:16px;font-weight:500;margin:0 0 12px}.relations-panel p{color:var(--muted)}button{min-height:44px;font:inherit;text-align:left;padding:10px 0;cursor:pointer}button:disabled{cursor:default;color:var(--muted)}.relation-card{margin:16px 0;border:1px solid var(--line);padding:14px;border-radius:4px}h5{font-size:13px;font-weight:500;margin:0 0 12px}h6{font-size:12px;font-weight:500;margin:0 0 10px}.dimension-row{padding:14px 0;border-top:1px solid var(--line)}dl{margin:0}dl>div{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,1.2fr);gap:10px;padding:5px 0}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}button:focus-visible{outline:2px solid var(--ink);outline-offset:3px}
</style>
