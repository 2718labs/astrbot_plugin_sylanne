<script setup lang="ts">
import { computed, ref, watch, toRaw } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { SchemeField } from './api/creator.ts'
import {CREATOR_FIELDS,emptyValue,validateEditorValue} from './api/beta1-owner.ts'
import StructuredFields from './StructuredFields.vue'
const props=defineProps<{backend:BackendController;group:string}>()
const creator=props.backend.creator,state=computed(()=>creator.state),scope=ref(props.backend.state.scope)
const drafts=ref<Partial<Record<SchemeField,unknown>>>({}),errors=ref<Partial<Record<SchemeField,string>>>({}),pendingFields=ref(new Set<SchemeField>())
const fieldGroups:Record<string,SchemeField[]>={persona:['d01.persona_plan','d02.body_profile','d03.context_scheme'],attention:['d04.affect_scheme','d04.authored_root','d07.attention_policy','d08.action_schemas','d09.expression_policy'],memory:['d05.relationship_scheme','d06.encoding_projection_policy'],life:['d10.activity_recipe']}
const rows=computed(()=>state.value.data?.supported_fields.filter(row=>(fieldGroups[props.group]??[]).includes(row.path))??[])
const labels:Record<SchemeField,string>={'d01.persona_plan':'人格方案','d02.body_profile':'身体方案','d03.context_scheme':'场景方案','d04.affect_scheme':'情感方案','d04.authored_root':'情感 Root 专属结构','d05.relationship_scheme':'关系方案','d06.encoding_projection_policy':'记忆编码投影','d07.attention_policy':'注意策略','d08.action_schemas':'行动结构','d09.expression_policy':'表达策略','d10.activity_recipe':'生活活动方案'}
const notes:Record<SchemeField,string>={
 'd01.persona_plan':'分别配置人格块与价值规则。语义身份的成长与当前采用另走真实证据链；原始人格 claim 不能代替已核验成长。',
 'd02.body_profile':'身体方案仅定义当前角色的适用轴与工作类型。',
 'd03.context_scheme':'分别维护场景角色与规范。',
 'd04.affect_scheme':'分别维护版本、情感轴与参数边界。保存不运行 Numeric 或解除 D04 门槛。',
 'd04.authored_root':'Root 专属资源、签名与采用路径由后端管理，普通配置保持只读。',
 'd05.relationship_scheme':'分别维护关系维度与贡献语义；设置不产生双方同意。',
 'd06.encoding_projection_policy':'配置编码投影权重；来源与授权在实际读取时核验。',
 'd07.attention_policy':'权重总和需为1；当前主焦点1项、辅助3项仍按后端协议核验。',
 'd08.action_schemas':'分别维护动作与必需检查，不执行、发送或跳过检查。',
 'd09.expression_policy':'当前 D09 head 已初始化后才可预览和采用表达策略。',
 'd10.activity_recipe':'配置活动步骤与可抢占属性，实际 Life 与 Contact 沿原许可执行。',
}
watch(()=>state.value.data,data=>{drafts.value=data?structuredClone(toRaw(state.value.draft??data.fields)):{};errors.value={};pendingFields.value.clear()},{immediate:true})
watch(()=>props.backend.state.scope,value=>{scope.value=value;drafts.value={};errors.value={};pendingFields.value.clear()})
function edit(path:SchemeField,value:unknown){drafts.value={...drafts.value,[path]:value};pendingFields.value.add(path)}
function begin(path:SchemeField){const spec=CREATOR_FIELDS[path];if(!spec||!creator.canEdit.value)return;drafts.value={...drafts.value,[path]:emptyValue(spec,props.backend.state.scope)};pendingFields.value.add(path);errors.value[path]=''}
function apply(path:SchemeField){try{const spec=CREATOR_FIELDS[path];if(!spec)throw new Error('此专属字段不支持普通编辑。');const value=structuredClone(toRaw(drafts.value[path]));validateEditorValue(spec,value,labels[path]);creator.setField(path,value);pendingFields.value.delete(path);errors.value[path]=''}catch(error){errors.value[path]=error instanceof Error?error.message:'字段不完整，未修改领域草稿。'}}
function remove(path:SchemeField){creator.removeField(path);const next={...drafts.value};delete next[path];drafts.value=next;pendingFields.value.delete(path)}
</script>
<template>
 <section class="creator-configuration" aria-label="当前 Owner 领域方案配置">
  <div class="creator-access"><label for="creator-configuration-scope">当前角色范围</label><input id="creator-configuration-scope" v-model="scope" maxlength="192" autocomplete="off" spellcheck="false"><button class="creator-action" :disabled="backend.state.busy||!scope.trim()" @click="backend.setScope(scope)">应用范围</button><button class="creator-action" :disabled="!creator.canRead.value" @click="creator.read">{{creator.reading.value?'正在读取当前草稿…':'读取真实配置草稿'}}</button><p>范围只选择当前授权角色。读取仍要求 Owner 解锁、实际 workbench.create 授权与 Graph 端口。</p></div>
  <p v-if="state.message" :role="['error','unknown','conflict'].includes(state.status)?'alert':'status'">{{state.message}}</p>
  <dl v-if="state.data" class="creator-facts"><div><dt>草稿版本</dt><dd>{{state.data.draft_revision}} · {{state.data.exists?'实际草稿':'尚无草稿'}}</dd></div><div><dt>已采纳 Head 版本</dt><dd>{{state.data.active_head_revision}}</dd></div><div><dt>Graph / 访问 / 删除版本</dt><dd>{{state.data.graph_revision}} / {{state.data.access_epoch}} / {{state.data.delete_epoch}}</dd></div><div><dt>真实预算定位</dt><dd>{{state.data.budget_ref?'服务端已提供，仍须核验当前额度与期限':'当前没有，不能编译或预览'}}</dd></div></dl>
  <p v-if="state.data&&!rows.length">当前目录未提供此组可编辑域。</p>
  <article v-for="row in rows" :key="row.path" class="creator-field"><h5>{{labels[row.path]}} <small>{{row.path}} · {{row.editable?'配置草稿':'专属路径只读'}}</small></h5><p>{{notes[row.path]}}</p>
   <template v-if="row.editable&&CREATOR_FIELDS[row.path]"><StructuredFields v-if="drafts[row.path]!==undefined" :spec="CREATOR_FIELDS[row.path]!" :model-value="drafts[row.path]" @update:model-value="edit(row.path,$event)" :path="'creator-'+row.path" :scope="backend.state.scope" :disabled="!creator.canEdit.value"/><p v-else>此字段尚未加入当前草稿。</p><p v-if="errors[row.path]" role="alert">{{errors[row.path]}}</p><div><button v-if="drafts[row.path]===undefined" class="creator-action" :disabled="!creator.canEdit.value" @click="begin(row.path)">建立空白方案表单</button><button v-else class="creator-action" :disabled="!creator.canEdit.value" @click="apply(row.path)">应用此字段到内存草稿</button><button class="creator-action" :disabled="!creator.canEdit.value||!(row.path in (state.draft??{}))" @click="remove(row.path)">从草稿移除此字段</button></div><p>空白表单只生成待填写字段；不预填角色、原件或授权。字段应用后还需保存并独立回读。</p></template>
   <p v-else>专属结构由真实后端维护。{{state.data?.field_sources[row.path]?'当前来源：'+state.data.field_sources[row.path]:'尚未读取来源'}}</p>
  </article>
  <p v-if="pendingFields.size" role="status">有 {{pendingFields.size}} 项表单修改尚未应用到内存草稿，请逐项应用后保存。</p>
  <div class="creator-actions"><button class="creator-action" :disabled="!creator.canSave.value||pendingFields.size>0" @click="creator.save">{{creator.writing.value?'领域操作进行中…':'保存方案草稿并独立回读'}}</button><button class="creator-action" :disabled="!creator.canCompile.value||pendingFields.size>0" @click="creator.compile">发起授权编译</button><button class="creator-action" :disabled="!creator.canPreview.value||pendingFields.size>0" @click="creator.preview">发起已支持的隔离预览</button><button class="creator-action" :disabled="!creator.canActivate.value||pendingFields.size>0" @click="creator.activate">明确采用当前 D09 候选</button></div>
  <p>保存后状态为 saved_not_adopted。编译、隔离预览与采用仍分别要求实际 action_permissions、预算与版本基线。预览当前支持已初始化的 D07/D09，可能消费已批准预算；方案采用当前支持 D09。能力与策略采用使用上方独立 Owner 操作；其余域不因草稿保存或编译而显示已运行。</p>
  <p v-if="state.compiled">已记录编译候选：{{state.compiled.compiled_digest}}</p><p v-if="state.preview">已记录隔离预览，尚未采用。</p><p v-if="state.adopted">当前 D09 Head 已按真实采用原件独立回读一致。</p><p v-if="state.operationId">本次领域操作：{{state.operationId}}；结果未知时不会自动重放。</p>
 </section>
</template>
<style scoped>
.creator-configuration{margin:16px 0;font-size:12px;line-height:1.8}.creator-configuration p{color:var(--muted);margin:8px 0;overflow-wrap:anywhere}.creator-access{display:flex;flex-wrap:wrap;gap:10px;align-items:center}.creator-access label{font-size:12px}.creator-access input{max-width:280px;min-height:44px;font:inherit;background:var(--surface);color:var(--ink);border:1px solid var(--line);padding:8px}.creator-access p{flex-basis:100%}.creator-facts>div{display:flex;gap:16px;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--line)}.creator-facts dd{margin:0;text-align:right;overflow-wrap:anywhere}.creator-field{padding:18px 0;border-top:1px solid var(--line)}.creator-field h5{font-size:14px;font-weight:500;margin:0}.creator-field h5 small{display:block;font-size:11px;color:var(--muted)}.creator-field>div,.creator-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.creator-action{font:inherit;min-height:44px;padding:9px 12px;background:var(--button);color:var(--ink);border:1px solid var(--line);border-radius:3px;cursor:pointer}.creator-action:disabled{background:var(--disabled-bg);color:var(--disabled-ink);cursor:default}.creator-configuration :is(button,input):focus-visible{outline:2px solid var(--focus);outline-offset:3px}
</style>
