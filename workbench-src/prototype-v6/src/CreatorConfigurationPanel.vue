<script setup lang="ts">
import { computed, ref, watch, toRaw } from 'vue'
import type { BackendController } from './use-backend.ts'
import type { SchemeField } from './api/creator.ts'

const props=defineProps<{backend:BackendController;group:string}>()
const creator=props.backend.creator,state=computed(()=>creator.state),scope=ref(props.backend.state.scope)
const texts=ref<Partial<Record<SchemeField,string>>>({}),errors=ref<Partial<Record<SchemeField,string>>>({})
const fieldGroups:Record<string,SchemeField[]>={persona:['d01.persona_plan','d02.body_profile','d03.context_scheme'],attention:['d04.affect_scheme','d04.authored_root','d07.attention_policy','d08.action_schemas','d09.expression_policy'],memory:['d05.relationship_scheme','d06.encoding_projection_policy'],life:['d10.activity_recipe']}
const rows=computed(()=>state.value.data?.supported_fields.filter(row=>(fieldGroups[props.group]??[]).includes(row.path))??[])
const labels:Record<SchemeField,string>={'d01.persona_plan':'人格方案','d02.body_profile':'身体方案','d03.context_scheme':'场景方案','d04.affect_scheme':'情感方案','d04.authored_root':'情感 Root 专属结构','d05.relationship_scheme':'关系方案','d06.encoding_projection_policy':'记忆编码投影','d07.attention_policy':'注意策略','d08.action_schemas':'行动结构','d09.expression_policy':'表达策略','d10.activity_recipe':'生活活动方案'}
const notes:Record<SchemeField,string>={
  'd01.persona_plan':'版本化 PersonaPlan 的 blocks 与价值规则；不是任意 prompt 覆盖或浏览器显示别名。',
  'd02.body_profile':'BodyProfile 的 profile_id、namespace、version、applicable_axes、work_kinds；namespace 必须仍为当前角色。',
  'd03.context_scheme':'对象必须包含 schema、roles、norms；场景角色与规范由当前域编译器校验。',
  'd04.affect_scheme':'AffectScheme 的轴与版本结构；保存草稿不运行 Numeric、不解除 D04 原门槛。',
  'd04.authored_root':'当前 Root 专属字段只读；专属资源、签名与采用路径仍由后端管理，普通配置不可改。',
  'd05.relationship_scheme':'对象包含 schema、dimensions、contribution_semantics；不会凭设置产生双方同意。',
  'd06.encoding_projection_policy':'严格 EncodingProjectionPolicyV1；不填原始证据、私有消息或模型密钥。',
  'd07.attention_policy':'严格 AttentionPolicy；预算与当前授权由服务端逐次核验，配置不签发预算。',
  'd08.action_schemas':'ActionSchema 列表与 RequiredCheckSpec；只是动作结构，不执行、发送或跳过检查。',
  'd09.expression_policy':'严格 D09ExpressionPolicyV1；现有已初始化 D09 head 才能走实际预览/采用闭环。',
  'd10.activity_recipe':'严格 ActivityRecipe；配置候选不等于 Life 已运行，也不解除 Contact HOLD。',
}
watch(()=>state.value.draft,draft=>{const next:Partial<Record<SchemeField,string>>={};if(draft)for(const[path,value]of Object.entries(draft))next[path as SchemeField]=JSON.stringify(value,null,2);texts.value=next;errors.value={}},{immediate:true})
watch(()=>props.backend.state.scope,value=>{scope.value=value})
function apply(path:SchemeField){try{const value=JSON.parse(texts.value[path]??'');if(value===null||typeof value!=='object')throw new Error();creator.setField(path,value);errors.value[path]=''}catch{errors.value[path]='需要有效的结构化 JSON 对象或数组。未修改领域草稿。'}}
function fromTemplate(path:SchemeField){const template=state.value.data?.field_templates[path];if(!creator.canEdit.value||template===undefined||path==='d04.authored_root')return;const value=structuredClone(toRaw(template));texts.value[path]=JSON.stringify(value,null,2);creator.setField(path,value);errors.value[path]=''}
</script>
<template>
  <section class="creator-configuration" aria-label="当前 Owner 领域方案配置">
    <div class="creator-access"><label for="creator-configuration-scope">当前角色范围</label><input id="creator-configuration-scope" v-model="scope" maxlength="192" autocomplete="off" spellcheck="false"><button class="creator-action" :disabled="backend.state.busy||!scope.trim()" @click="backend.setScope(scope)">应用范围</button><button class="creator-action" :disabled="!creator.canRead.value" @click="creator.read">{{creator.reading.value?'正在读取当前草稿…':'读取真实配置草稿'}}</button><p>范围只选择当前授权角色，不授予权限。没有 Owner 解锁、实际 workbench.create 授权或 Graph 端口时不读取私有字段。</p></div>
    <p v-if="state.message" :role="['error','unknown','conflict'].includes(state.status)?'alert':'status'">{{state.message}}</p>
    <dl v-if="state.data" class="creator-facts"><div><dt>草稿版本</dt><dd>{{state.data.draft_revision}} · {{state.data.exists?'实际草稿':'尚无草稿'}}</dd></div><div><dt>已采纳 head 版本</dt><dd>{{state.data.active_head_revision}}</dd></div><div><dt>Graph / 访问 / 删除版本</dt><dd>{{state.data.graph_revision}} / {{state.data.access_epoch}} / {{state.data.delete_epoch}}</dd></div><div><dt>真实预算定位</dt><dd>{{state.data.budget_ref?'服务端已提供；仍须核验 current quote/expiry':'当前没有，不能编译或预览'}}</dd></div></dl>
    <p v-if="state.data&&!rows.length">当前目录未提供此组可编辑域。这里不会创建不存在的设置。</p>
    <div v-for="row in rows" :key="row.path" class="creator-field"><label :for="'creator-'+row.path">{{labels[row.path]}} <small>{{row.path}} · {{row.editable?'配置草稿':'专属路径只读'}}</small></label><p>{{notes[row.path]}}</p><textarea :id="'creator-'+row.path" v-model="texts[row.path]" :readonly="!row.editable" :disabled="!creator.canEdit.value" rows="8" spellcheck="false" autocomplete="off" placeholder="从真实读取值编辑；新增字段需要遵循该域严格类型规范"></textarea><p v-if="errors[row.path]" role="alert">{{errors[row.path]}}</p><div v-if="row.editable"><button class="creator-action" :disabled="!creator.canEdit.value" @click="fromTemplate(row.path)">从结构示例开始</button><button class="creator-action" :disabled="!creator.canEdit.value" @click="apply(row.path)">应用到内存草稿</button><button class="creator-action" :disabled="!creator.canEdit.value||!(row.path in (state.draft??{}))" @click="creator.removeField(row.path)">从草稿移除此字段</button></div><p v-if="row.editable">结构示例需要按角色目标审阅；不是当前配置、校准结果或已采纳方案。点击仅生成未保存草稿，不编译、预览或执行。</p></div>
    <div class="creator-actions"><button class="creator-action" :disabled="!creator.canSave.value" @click="creator.save">{{creator.writing.value?'领域操作进行中…':'保存方案草稿并独立回读'}}</button><button class="creator-action" :disabled="!creator.canCompile.value" @click="creator.compile">发起授权编译</button><button class="creator-action" :disabled="!creator.canPreview.value" @click="creator.preview">发起已支持的隔离预览</button><button class="creator-action" :disabled="!creator.canActivate.value" @click="creator.activate">明确采用当前 D09 候选</button></div>
    <p>保存只承诺 <code>saved_not_adopted</code>。按钮同时要求实际 action_permissions、预算定位和当前版本基线；预算定位不授权。预览当前仅支持实际已初始化的 D07/D09，可能消费已批准预算；采用仅支持 D09。其余域不能因保存或编译而标为已运行；D04 Root 专属线及 Numeric / Contact / C09 / D04 HOLD 不绕过。</p>
    <p>领域输入 producer 的 activity、audience、budget 引用与独立读回尚未提供到此页，不开放假保存开关。</p>
    <p v-if="state.compiled">已记录编译候选：{{state.compiled.compiled_digest}}</p><p v-if="state.preview">已记录隔离预览，未自动采用。</p><p v-if="state.adopted">当前 D09 head 已按真实采用原件独立回读一致。</p><p v-if="state.operationId">本次领域操作：{{state.operationId}}；结果未知时不会自动重放。</p>
  </section>
</template>
<style scoped>
.creator-configuration{margin:16px 0;font-size:12px;line-height:1.8}.creator-configuration p{color:var(--muted);margin:8px 0;overflow-wrap:anywhere}.creator-access{display:flex;flex-wrap:wrap;gap:10px;align-items:center}.creator-access label{font-size:12px}.creator-access input{max-width:280px;min-height:44px;font:inherit;background:var(--surface);color:var(--ink);border:1px solid var(--line);padding:8px}.creator-access p{flex-basis:100%}.creator-facts>div{display:flex;gap:16px;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--line)}.creator-facts dd{margin:0;text-align:right;overflow-wrap:anywhere}.creator-field{padding:18px 0;border-top:1px solid var(--line)}.creator-field label{display:block;font-size:14px}.creator-field label small{display:block;font-size:11px;color:var(--muted)}.creator-field textarea{box-sizing:border-box;width:100%;min-height:180px;resize:vertical;font:12px/1.7 monospace;background:var(--surface);color:var(--ink);border:1px solid var(--line);border-radius:3px;padding:12px}.creator-field>div,.creator-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.creator-action{font:inherit;min-height:44px;padding:9px 12px;background:var(--button);color:var(--ink);border:1px solid var(--line);border-radius:3px;cursor:pointer}.creator-action:disabled{background:var(--disabled-bg);color:var(--disabled-ink);cursor:default}.creator-configuration :is(button,input,textarea):focus-visible{outline:2px solid var(--focus);outline-offset:3px}
</style>
