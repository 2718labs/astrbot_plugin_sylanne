<script setup lang="ts">
import { computed, onBeforeUnmount } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { LogFilter } from './api/management.ts'
import { PLUGIN_SETTING_SCHEMA, UTILITY_ACCESS_COPY, UTILITY_META, utilityAccessState, type UtilityKind } from './utility-state.ts'
import ConfigurationPanel from './ConfigurationPanel.vue'

const props = defineProps<{ kind: UtilityKind; backend: BackendController }>()
const management = computed(() => props.backend.management)
const state = computed(() => management.value.state)
const meta = computed(() => UTILITY_META[props.kind])
const access = computed(() => utilityAccessState(props.backend.state, state.value.capabilities, props.kind))
const accessCopy = computed(() => UTILITY_ACCESS_COPY[access.value])
const prefix = computed(() => `utility-${props.kind}`)
const settings = computed(() => state.value.settings.data)
const selected = computed(() => management.value.selectedEvent.value)
const applyCopy = computed(() => ({ read_only: '仅可读取，当前授权不允许保存。', next_restart: '更改保存后，下次重启生效。', immediate: '更改保存后立即生效。' }[settings.value?.apply_semantics ?? 'read_only']))
function levelChange(event: Event) { management.value.setLogFilter({ level: (event.target as HTMLSelectElement).value as LogFilter['level'] }) }
function queryChange(event: Event) { management.value.setLogFilter({ query: (event.target as HTMLInputElement).value }) }
function enabledChange(event: Event) { management.value.setEnabled((event.target as HTMLSelectElement).value === 'true') }
onBeforeUnmount(() => management.value.invalidate())
</script>

<template>
  <section class="utility-panel" :data-utility-kind="kind" :data-access-state="access" :aria-label="meta.title" :aria-describedby="`${prefix}-intro`" @wheel.stop>
    <p :id="`${prefix}-intro`" class="utility-intro">{{ meta.description }}</p>
    <div class="utility-content">
      <ConfigurationPanel v-if="kind==='settings'" :backend="backend" />
      <div class="utility-connection" role="status" aria-live="polite">
        <p class="utility-status"><span class="utility-status-dot" aria-hidden="true"></span>{{ accessCopy.label }}</p>
        <p>{{ accessCopy.description }}</p>
        <p v-if="state.capabilities.message">{{ state.capabilities.message }}</p>
        <p v-if="state.capabilities.data && access === 'unavailable'">原因标识：{{ state.capabilities.data.capabilities[kind].reason_code }}</p>
        <button class="utility-action capability-check" :disabled="!management.canDiscover.value" @click="management.discover">{{ state.capabilities.status === 'loading' ? '正在核验管理接口…' : state.capabilities.data ? '重新核验管理接口' : '核验管理接口' }}</button>
      </div>

      <section class="runtime-check" aria-label="独立安装运行状态">
        <div><h3>安装运行状态</h3><p v-if="state.runtime.data">runtime_stage：{{ state.runtime.data.stage }} · reason_code：{{ state.runtime.data.reason }}</p><p v-else>实际运行阶段尚未读取。</p><p v-if="state.runtime.message" role="status">{{ state.runtime.message }}</p><p v-else>与管理权限和前端连接状态分别核验。</p></div>
        <button class="utility-action" :disabled="!management.canRuntime.value" @click="management.checkRuntime">{{ state.runtime.status === 'loading' ? '正在核验运行状态…' : '核验运行状态' }}</button>
      </section>

      <template v-if="kind === 'logs'">
        <div class="utility-section-heading"><h3>运行记录</h3><span class="utility-section-tag">{{ management.canLogs.value ? 'SERVER-REDACTED / 服务端脱敏' : 'UNCONNECTED / 未接入' }}</span></div>
        <div class="log-filters" :aria-describedby="`${prefix}-reason`">
          <label class="log-level" :for="`${prefix}-level`"><span>日志级别</span><select :id="`${prefix}-level`" :value="state.logs.filter.level" :disabled="!management.canLogs.value" :aria-describedby="`${prefix}-reason`" @change="levelChange"><option value="ALL">全部级别</option><option>INFO</option><option>WARNING</option><option>ERROR</option></select></label>
          <label class="log-search" :for="`${prefix}-query`"><span>搜索日志</span><div class="search-field"><svg aria-hidden="true" viewBox="0 0 20 20" fill="none"><circle cx="8.5" cy="8.5" r="5.5"/><path d="m13 13 4 4"/></svg><input :id="`${prefix}-query`" type="search" :value="state.logs.filter.query" :disabled="!management.canLogs.value" :placeholder="management.canLogs.value ? '搜索已脱敏事件' : '接口接入后可搜索'" maxlength="128" :aria-describedby="`${prefix}-reason`" autocomplete="off" @input="queryChange"></div></label>
          <button class="utility-action log-refresh" :disabled="!management.canRefreshLogs.value" :aria-describedby="`${prefix}-reason`" @click="management.refreshLogs">{{ state.logs.status === 'loading' ? '正在读取日志…' : '刷新日志' }}</button>
        </div>
        <p v-if="management.canLogs.value" :id="`${prefix}-reason`" class="utility-read-message" role="status" aria-live="polite">{{ state.logs.message || '尚未读取日志。请选择筛选条件并刷新；只搜索授权的脱敏文本。' }}</p>
        <div class="log-register" :aria-describedby="`${prefix}-reason`" :aria-busy="state.logs.status === 'loading'">
          <div class="log-register-heading" aria-hidden="true"><span>时间 / 级别</span><span>事件摘要</span><span>详情</span></div>
          <ul v-if="state.logs.page && state.logs.page.entries.length" class="log-entries" aria-label="本页脱敏事件">
            <li v-for="event in state.logs.page.entries" :key="event.event_id"><div><time :datetime="event.occurred_at">{{ event.occurred_at }}</time><span>{{ event.level }}</span></div><div><span class="log-event-code">{{ event.event_code }}</span><p>{{ event.summary }}</p></div><button class="utility-action" :aria-label="`查看事件 ${event.event_code} 详情`" :aria-pressed="selected?.event_id === event.event_id" @click="management.selectEvent(event.event_id)">详情</button></li>
          </ul>
          <div v-else-if="management.canLogs.value" class="utility-unavailable"><h4>{{ state.logs.status === 'empty' ? '本次读取无事件' : state.logs.status === 'loading' ? '正在读取事件' : '尚无可显示的记录' }}</h4><p>{{ state.logs.status === 'empty' ? '有效响应已确认当前筛选结果为空。' : '未取得有效结果前，不代表运行期间没有事件。' }}</p></div>
          <div v-else class="utility-unavailable log-unavailable">
            <svg class="utility-state-icon" aria-hidden="true" viewBox="0 0 32 32" fill="none"><rect x="7" y="4" width="18" height="24" rx="2"/><path d="M12 11h8M12 16h8M12 21h4"/></svg>
            <h4>{{ meta.unavailableTitle }}</h4><p :id="`${prefix}-reason`">{{ meta.unavailableMessage }}</p><p class="utility-boundary">{{ meta.boundary }}</p>
          </div>
        </div>
        <div v-if="state.logs.page" class="log-pagination"><span>第 {{ state.logs.pageNumber }} 页 · 本页 {{ state.logs.page.entries.length }} 条</span><button class="utility-action" :disabled="!management.canRefreshLogs.value" @click="management.refreshLogs">从第一页刷新</button><button class="utility-action" :disabled="!management.canNext.value" @click="management.nextLogs">下一页</button></div>
        <article v-if="selected" class="log-event-detail" aria-label="脱敏事件详情"><div class="utility-section-heading"><h3>事件详情</h3><button class="utility-action" @click="management.selectEvent(null)">收起详情</button></div><dl><div><dt>事件标识</dt><dd>{{ selected.event_id }}</dd></div><div><dt>时间</dt><dd>{{ selected.occurred_at }}</dd></div><div><dt>级别 / 事件码</dt><dd>{{ selected.level }} / {{ selected.event_code }}</dd></div></dl><p>{{ selected.summary }}</p><p class="setting-hint">仅显示与列表相同的服务端脱敏字段，不提供原始日志。</p></article>
        <aside v-else class="log-detail-note" aria-label="日志详情状态"><div><h4>{{ state.logs.page?.entries.length ? '选择事件查看详情' : '详情尚不可用' }}</h4><p>仅可查看已读取事件的安全字段。</p></div><button class="utility-action" disabled :aria-describedby="`${prefix}-reason`">查看详情</button></aside>
      </template>

      <template v-else>
        <div class="utility-section-heading"><h3>{{ settings ? '实际配置' : '配置结构' }}</h3><span class="utility-section-tag">{{ settings ? 'VERIFIED READ / 已读取' : 'SCHEMA / 2 FIELDS' }}</span></div>
        <div class="settings-notice" role="status" aria-live="polite"><h4>{{ settings ? '当前安装配置' : meta.unavailableTitle }}</h4><p :id="`${prefix}-reason`">{{ state.settings.message || meta.unavailableMessage }}</p><p class="utility-boundary">{{ settings ? applyCopy : meta.boundary }}</p></div>
        <div class="setting-groups" :aria-busy="management.active.settings || management.active.update">
          <section class="setting-group" :aria-labelledby="`${prefix}-runtime-title`">
            <div class="setting-group-heading"><span class="utility-section-number" aria-hidden="true">01</span><h4 :id="`${prefix}-runtime-title`">运行设置</h4></div>
            <div class="setting-field">
              <label :for="`${prefix}-enabled`">启用插件 <small>enabled · BOOLEAN</small></label>
              <select v-if="settings" :id="`${prefix}-enabled`" :value="String(state.settings.draftEnabled)" :disabled="!management.canEdit.value" :aria-describedby="`${prefix}-enabled-hint ${prefix}-reason`" @change="enabledChange"><option value="false">关闭（false）</option><option value="true">启用（true）</option></select>
              <select v-else :id="`${prefix}-enabled`" disabled :aria-describedby="`${prefix}-enabled-hint ${prefix}-reason`"><option>当前值未读取</option></select>
              <dl class="setting-schema"><div><dt>本机结构默认值</dt><dd>关闭（{{ PLUGIN_SETTING_SCHEMA.enabled.defaultValue }}）</dd></div><div v-if="settings"><dt>已读取 Authority 许可</dt><dd>{{ settings.values.enabled ? '启用（true）' : '关闭（false）' }}</dd></div></dl>
              <p :id="`${prefix}-enabled-hint`" class="setting-hint">{{ settings ? applyCopy + ' 此值是 Authority 启用许可；实际运行还要求本机 Host enabled 为 true，不等同于暂停或恢复。' : '当前 Authority 许可未知。本机结构默认值不代表实际安装值。' }}</p>
            </div>
          </section>
          <section class="setting-group" :aria-labelledby="`${prefix}-authority-title`">
            <div class="setting-group-heading"><span class="utility-section-number" aria-hidden="true">02</span><h4 :id="`${prefix}-authority-title`">宿主配置</h4></div>
            <div class="setting-field">
              <label :for="`${prefix}-authority`">权限配置标识 <small>authority_profile · STRING</small></label>
              <input :id="`${prefix}-authority`" type="text" :value="settings?.values.authority_profile ?? '当前值未读取'" disabled readonly autocomplete="off" :aria-describedby="`${prefix}-authority-hint ${prefix}-reason`">
              <dl class="setting-schema"><div><dt>结构默认值</dt><dd>{{ PLUGIN_SETTING_SCHEMA.authority_profile.defaultValue }}</dd></div><div><dt>标识长度</dt><dd>{{ PLUGIN_SETTING_SCHEMA.authority_profile.minimumLength }}–{{ PLUGIN_SETTING_SCHEMA.authority_profile.maximumLength }} 个字符</dd></div></dl>
              <p :id="`${prefix}-authority-hint`" class="setting-hint">由宿主配置选用。本页始终只读，不提供权限配置切换。</p>
            </div>
          </section>
        </div>
        <p v-if="settings" class="setting-hint">已读取版本：{{ settings.revision }}。保存使用版本核对，不会覆盖其他操作的新版本。</p>
        <div class="settings-actions"><p>Authority 许可由真实授权服务管理；本机配置在 AstrBot 原生配置面板设置。未知结果必须先重新读取。</p><div><button class="utility-action" :disabled="!management.canReadSettings.value" :aria-describedby="`${prefix}-reason`" @click="management.readSettings">{{ management.active.settings ? '正在读取配置…' : '读取配置' }}</button><button class="utility-action utility-save" :disabled="!management.canSave.value" :aria-describedby="`${prefix}-reason`" @click="management.saveSettings">{{ state.settings.status === 'verifying' ? '正在回读确认…' : management.active.update ? '正在保存设置…' : '保存设置' }}</button></div></div>
      </template>
    </div>
  </section>
</template>

<style scoped>
/* The shared dashboard owns the heading, navigation, close action and scrolling. */
.utility-panel{width:100%;min-width:0;color:var(--ink,#354348);font-size:12px;line-height:1.7;overflow-wrap:anywhere}
.utility-intro{margin:0 0 10px;color:var(--muted,#617177);font-size:11px}
.utility-content{min-width:0}.utility-connection{padding-bottom:12px;margin-bottom:15px;border-bottom:1px solid var(--line,#cbd6d8)}.utility-connection>p{margin:4px 0 0;color:var(--muted,#617177);font-size:11px}.utility-connection>.utility-status{display:flex;align-items:center;gap:8px;margin:0;color:var(--ink,#354348);font-size:11px}.utility-status-dot{width:5px;height:5px;border-radius:50%;background:#899991;flex:none}
.utility-section-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 12px}.utility-section-heading h3{margin:0;font-size:15px;font-weight:500}.utility-section-tag{font-size:9px;letter-spacing:.09em;color:var(--muted,#617177);text-align:right}
.log-filters{display:grid;grid-template-columns:96px minmax(0,1fr) auto;align-items:end;gap:10px;margin-bottom:12px}.log-filters label>span{display:block;margin-bottom:5px;font-size:11px}.utility-panel select,.utility-panel input{box-sizing:border-box;width:100%;min-width:0;min-height:40px;padding:8px 10px;border:1px solid #cbd4d1;border-radius:3px;background:#f0f3f0;color:#67756f;font-family:inherit;font-size:11px;line-height:1.5;opacity:1;-webkit-text-fill-color:#67756f}.utility-panel input::placeholder{color:#67756f;opacity:1}.utility-panel select:disabled,.utility-panel input:disabled{cursor:not-allowed}.search-field{position:relative}.search-field input{padding-left:30px}.search-field svg{position:absolute;left:9px;top:12px;width:16px;height:16px;stroke:#84918a;stroke-width:1.2;pointer-events:none}.utility-action{min-height:40px;border:1px solid #cbd4d1;border-radius:3px;font-size:11px;padding:8px 11px;white-space:nowrap}.utility-action:disabled{color:#67756f;background:#edf1ec;cursor:not-allowed;opacity:1}.log-refresh{display:flex;align-items:center;justify-content:center}
.log-register{border:1px solid #d3ddd4;border-radius:3px;overflow:hidden;background:#f8faf6}.log-register-heading{display:grid;grid-template-columns:100px 1fr 30px;gap:12px;padding:10px 13px;border-bottom:1px solid #dbe2d8;font-size:10px;color:var(--muted,#617177);background:#eef2eb}.log-register-heading>span:last-child{text-align:right}.utility-unavailable{text-align:center;padding:19px 16px}.utility-state-icon{width:24px;height:24px;stroke:#8c9b8b;stroke-width:1.2;margin-bottom:5px}.utility-unavailable h4{font-size:14px;font-weight:450;margin:0 0 7px}.utility-unavailable p{max-width:390px;margin:0 auto;font-size:11px;color:var(--muted,#617177);line-height:1.9}.utility-unavailable .utility-boundary{margin-top:9px;font-size:10px}.log-detail-note{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 0 0}.log-detail-note h4{margin:0 0 4px;font-size:11px;font-weight:500}.log-detail-note p{margin:0;font-size:11px;color:var(--muted,#617177)}.log-detail-note .utility-action{flex:none}
.settings-notice{background:#edf2e8;border-left:2px solid #a8b697;padding:10px 12px;margin-bottom:15px}.settings-notice h4{font-size:12px;font-weight:500;margin:0 0 5px}.settings-notice p{margin:0;font-size:11px;color:var(--muted,#617177)}.settings-notice .utility-boundary{margin-top:6px;font-size:10px}.setting-groups{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:20px}.setting-group{min-width:0}.setting-group-heading{display:flex;align-items:center;gap:8px;margin-bottom:10px}.setting-group-heading h4{margin:0;font-size:13px;font-weight:500}.utility-section-number{color:#82917e;font-size:10px}.setting-field label{display:block;font-size:12px;margin:0 0 8px}.setting-field label small{display:block;font-size:9px;letter-spacing:.025em;color:var(--muted,#617177);overflow-wrap:anywhere;margin-top:4px}.setting-schema{margin:8px 0 0}.setting-schema>div{display:flex;justify-content:space-between;gap:10px;padding:5px 0;border-bottom:1px solid #dce3d9;font-size:10px}.setting-schema dt{color:var(--muted,#617177)}.setting-schema dd{margin:0;text-align:right;overflow-wrap:anywhere}.setting-hint{font-size:10px;color:var(--muted,#617177);margin:7px 0 0;line-height:1.9}.settings-actions{display:flex;align-items:center;justify-content:space-between;gap:14px;border-top:1px solid var(--line,#cbd6d8);margin-top:15px;padding-top:12px}.settings-actions>p{margin:0;color:var(--muted,#617177);font-size:10px}.settings-actions>div{display:flex;gap:10px;flex:none}.utility-action.utility-save:disabled{background:#e7ecdf;border-color:#c5cfb8}
.utility-panel button:focus-visible,.utility-panel input:focus-visible,.utility-panel select:focus-visible{outline:2px solid #587020;outline-offset:3px}.utility-panel button:disabled:hover{text-decoration:none}
@media(max-width:650px){.log-filters{grid-template-columns:96px minmax(0,1fr)}.log-refresh{grid-column:1 / -1;min-height:38px}.setting-groups{gap:16px}.settings-actions{align-items:flex-start;flex-direction:column}.settings-actions>div{width:100%}.settings-actions .utility-action{flex:1}}
@media(max-width:430px){.utility-section-tag{font-size:8px}.log-filters{grid-template-columns:1fr}.log-refresh{grid-column:auto}.log-register-heading{grid-template-columns:90px 1fr 26px;padding:9px 11px;gap:8px}.utility-unavailable{padding:18px 12px}.setting-groups{grid-template-columns:1fr;gap:18px}.setting-group+.setting-group{border-top:1px solid var(--line,#cbd6d8);padding-top:15px}.log-detail-note{align-items:flex-start;gap:12px}}
@media(prefers-reduced-motion:reduce){.utility-panel,.utility-panel *{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
.capability-check{margin-top:10px}.utility-action:not(:disabled){cursor:pointer;background:var(--button);color:var(--ink,#354348);border-color:var(--line)}.utility-panel input:not(:disabled),.utility-panel select:not(:disabled){background:var(--surface);border-color:var(--line);color:var(--ink,#354348);-webkit-text-fill-color:var(--ink,#354348)}.runtime-check{display:flex;gap:16px;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line,#cbd6d8);padding:0 0 14px;margin:0 0 18px}.runtime-check h3{font-size:13px;font-weight:500;margin:0 0 4px}.runtime-check p{font-size:12px;color:var(--muted,#617177);margin:3px 0}.runtime-check button{flex:none}.utility-read-message{font-size:13px;margin:0 0 10px;color:var(--muted,#617177)}.log-entries{list-style:none;margin:0;padding:0}.log-entries li{display:grid;grid-template-columns:100px minmax(0,1fr) auto;gap:12px;padding:12px 13px;border-bottom:1px solid var(--line);align-items:start}.log-entries li:last-child{border-bottom:0}.log-entries time,.log-entries li>div:first-child>span{display:block;font-size:12px}.log-entries p{font-size:13px;margin:4px 0 0;white-space:pre-wrap}.log-event-code{font-size:12px;color:var(--muted,#617177)}.log-pagination{display:flex;gap:8px;align-items:center;justify-content:flex-end;margin-top:12px}.log-pagination>span{margin-right:auto;font-size:12px}.log-event-detail{margin-top:16px;border:1px solid var(--line);border-radius:3px;padding:14px;background:var(--surface)}.log-event-detail dl{margin:0}.log-event-detail dl>div{display:flex;gap:16px;justify-content:space-between;padding:4px 0}.log-event-detail dt{flex:none;color:var(--muted,#617177)}.log-event-detail dd{margin:0;text-align:right}.log-event-detail>p{white-space:pre-wrap}
@media(max-width:430px){.runtime-check{align-items:flex-start;flex-direction:column;gap:8px}.log-entries li{grid-template-columns:80px minmax(0,1fr);gap:8px;padding:10px}.log-entries li>button{grid-column:2;justify-self:start}.log-pagination{flex-wrap:wrap}.log-pagination>span{width:100%}.log-event-detail dl>div{flex-direction:column;gap:2px}.log-event-detail dd{text-align:left}}
</style>
