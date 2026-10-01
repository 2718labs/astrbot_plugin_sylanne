# D03 世界与情境操作合同 v1

日期：2026-09-23。设计版本 `d03.contract.v1`；参见 [主规格](03-world-context.md)、[验收](03-context-acceptance.md) 与 [公共合同](../architecture/module-collaboration-contracts.md)。所有类型和命令为拟实施合同。

## A. 信封、结果和权限

共用 D06/D07 的 schema、issuer、owner_scope、activity/effect/attempt/operation、parent_task、purpose/audience/provider_policy、input_refs/read_versions、查询/访问/删除 epochs、policy_version、budget/deadline/causation；追加 `scene_ref, viewpoint_ref, identity_mapping_version, role_binding_version, norm_version, audience_version, time_mapping_version, requested_slots`。空槽位需说明不适用，不能省略必要视角。

D03 只提交本域对象候选。来源内容/资格由 D06 验证，宿主入站身份由 D11 验证，D07 的事实信念不能由 D03 写入。模型输出只是解析提案。角色 owner 与模块写权限不是同一键；跨角色请求走 D06 transfer，不能因同 platform user id 自动访问另一角色私域。

返回 `complete/partial/deferred/unavailable/stale/conflict/rejected/pending_confirmation`，包括 requested/answered/missing_slots、coverage、versions、费用和 continuation。complete 只表示请求范围已回答，也可能回答 unknown。权限、删除、不存在对无权主体统一 unavailable；获准审计才能区分细因。

## B. 操作目录

| ID / 操作 | 输入/负责方 | 输出及边界 |
| --- | --- | --- |
| C01 `anchor_ingress` | D11 已核验 envelope + D06 ingress receipt | 源关联、账号锚点、确定入站/说话事件；陈述内容尚未证实 |
| C02 `resolve_mentions` | 来源片段、场景、时间、合法候选集合 | MentionResolution/歧义/覆盖；同名不自动合并 |
| C03 `structure_events` | 有源片段、引用/否定范围、参与者候选和时间 | WorldEvent/事件关联候选、现实性和资格；不创建事实信念 |
| C04 `assemble_context` | D04/D07/D08/D09 等请求视角/槽位/范围/预算 | ContextFrame、覆盖、缺口及失效依赖；历史搜索只走 D06 |
| C05 `check_identity_perspective` | D08 RequiredCheck，经 D06 装配 | 对象/受众/可见性/当前性回执、有效期、missing_items；不授权发送 |
| C06 `resolve_identity_change` | 获准 D12 或可靠宿主变更；预览、依据/影响范围 | 身份映射/别名版本、阻断和领域重建通知；不合并权限 |
| C07 `correct_context` | D06 来源更正、迟到消息、事件关联/时间纠正 | 当前失效屏蔽、新版本/待重建、历史引用；不重写旧来源 |
| C08 `apply_visibility_or_erase` | D06/D11 删除/撤权/成员变化回执 | 即时屏蔽、清理闭包与缺口；依独立删除日志和最新恢复水位 |
| C09 `map_time` | 原时间表达、所知时区、精度、规则版本、可选已签发 CharacterClockMapping | UTC/外部区间及 ContextTimeView、歧义/缺失；不写角色生活倍率/时钟，不代替 D08 定义承诺 |
| C10 `inspect_configure_transfer` | 获准 D12 查看/编辑/隔离导入/实验 | 预览、版本化行政编辑或可见诊断；审计不进入角色视角 |

## B.1 `RoleBinding` 与规范适用合同

`RoleBinding` 的写者是 D03，字段为 `role_binding_id, subject_persona_ref, social_role, target_entity_ref?, group_ref?, scene_ref?, scope_selector, visibility_scope, norm_refs, effective_interval, precedence, source_refs, binding_version, status`。至少一个 target/group/scene 限定必填；`subject_persona_ref` 只能引用 D01 身份，不能复制人格字段。`norm_refs` 指向版本化 `NormReference`，后者含发布/来源、适用行为类别、受众范围、约束级别、有效期、例外和 supersedes 链。RoleBinding 不能携带 AccountBinding、访问 grant、D05 关系维度、D08 承诺或 D11 派发资格。

新增 C05a `resolve_role_binding`：D01/D07/D08/D09 经 D06 提出 `subject_persona_ref + target/group/scene + requested_action_kind + purpose`，D03 以场景成员、身份映射、绑定/规范查询域、来源/访问/删除 epochs 装配 `RoleBindingResolution`。结果含 matched_bindings、applicable_norm_refs、conflicts、coverage、missing_items、examined_versions、valid_until 和完整 read_set；不匹配返回确定的 no_applicable_binding（仅说明已检查范围），范围不足/权限不足返回 partial/unavailable。它不返回私密原文，也不等于允许行动。

绑定的创建、修订、失效和撤销使用 C10 获准配置或有来源的场景/协商事实，并原子提升 `role_binding_version`、屏蔽依赖它的 ContextFrame/未派发资格、写重建 outbox。D03 不从 AccountBinding、昵称、单次称呼、D07 的 PerspectiveClaim 或 D05 关系投影自动创建/扩展绑定。迁移旧 `SocialScene/Participation/GroundingRecord/PerspectiveClaim` 时仅生成 `legacy_role_evidence` 候选；缺 scope、source、visibility 或 version 的候选不得成为适用绑定。

D01 消费 Resolution 以做情境人格/策略投影；D05 单独核对关系边界；D08 只把它作为 RequiredCheck 的一个输入，并保留承诺/行动决定；D09 只读经 D08/D05/D06 限制后的结果。RoleBinding 缺失、冲突、失效或规范未知时，禁止将视角合并、把私聊来源转为群聊可说、替他人确认、创建或扩张承诺；不依赖这些结论的受控澄清/公开事实回应可由 D08 重新装配后考虑。

## C. 入站、解析和事件身份

入站幂等键为宿主登记的 `(platform_namespace, bot_scope, conversation_id, message_id, source_revision)`。D06 保存载荷摘要/来源；D03 规范事件映射引用这个 ingress receipt。相同键异载荷拒绝，合法编辑必须得到新 revision/更正关系。宿主没有稳定消息 ID 时 D11 创建接收身份并明确重复检测能力有限，不用相同文本 hash 宣称完全去重。

源准入成功、语义解析失败是合法中间结果：pending_parse 对象只包含已证实宿主槽位，不能暴露模型未采用内容。重试保持 operation，若版本改变则先核实收据再用新 attempt；原源不重复写，未采用候选仍受来源删除约束。

WorldEvent 外部事件锚点的创建与“它确实发生”的证据资格分开。C03 可以创建 candidate_event 引用以组织多个说法；D07 决定信念，D08 执行结果只认 D11 回执。多个见证关联同一事件仍保留不同 source_family，转述/摘要关联原家族，不能因合并事件而合并独立证据或复制一次发生计数。

当前读集覆盖源版本、实体映射、提及候选查询域、场景/受众和访问 epochs。新实体或别名并发出现属于负查询失效，需要 CAS；失败 candidate 不进入任何人的已知事实。来源/事件/映射引用和 outbox 必须共同提交；源已准入无需与后续全语义解析做无限长事务。

## D. ContextFrame 与 RequiredCheck

`ContextFrame` 包括 frame_id、question_scope、perspective、time_cutoff、source_refs、participants、resolved/unresolved_mentions、scene/audience、events、observations、reported_claims、interpretation_refs、simulated_refs、missing_slots、coverage、read_set、semantic_dependencies、historical_refs、epochs、valid_until、continuation。内容限定在请求用途和预算内，不返回无关私密原文。

实际投递给角色、角色有权限取用、D07 已注意到、另一个参与者可能知道这四项分别表示。D03 不查询工作台全景再伪装成角色所知。过去视角用 learned_at 和当时访问/角色可见的版本；权限删除仍按当前规则覆盖历史访问权，不能以“当时能看”绕过当前撤权。

`IdentityPerspectiveReceipt` 包括 provider=D03、RequiredCheck_id、subject/target、examined_scope/versions、identity_status、audience_status、visibility/realism qualifiers、missing_items、valid_until、source_closure。D03 只满足自己负责的槽位，缺任一行动必需项就不能让 D06 标为全套已满足。普通聊天可以保留未知；要求精确身份/私密定向的动作在未知时不合格。

框架被截断、超页或解析失败时 coverage 显式列原因；完整检索只在请求范围内成立。D07 的假设/推断作为 interpretation_ref 返回，不降格为原始事实，也不冒充独立来源。模型外送先做来源闭包检查，最终 D11 投递再验一次。

## E. 身份变更事务与下游恢复

C06 分 preview、adopt、rebuild 三个可恢复阶段。preview 列依据、旧/新映射、影响域和权限差异；adopt 在同一事务存 IdentityResolution、提升 identity_epoch、屏蔽当前受影响投影并写 outbox；rebuild 各域按源贡献和原实体归属重建，通过后发布域就绪回执。D03 合并不能把私密授权并集扩大，也不能直接写 D05 关系或 D08 承诺目标。

撤销合并引用原 decision_id，保留原 anchors，追加新版本映射。自动可逆部分重建，不可分配混合贡献返回 unresolved 并保持投影阻断。已经实际发生的外部发言不撤销，只有 D08 可提出澄清动作。D11 若多域无法同步原子修复，用当前代际阻断 + durable outbox，不让消费者把“通知发出”当“所有领域已修复”。

账号绑定含有效期和验证依据；账号更名通常只改 alias，账号转让/多人共用产生新的有时效关系或歧义。跨平台同人自述可生成待确认身份提案，不构成访问私域的授权。身份采用需要与权限授予分别取得可核实回执。

## F. 时间、迟到和修正

C09 保留原时间文本 source_span、参考消息的发生/获知时间、时区依据、规则版本、解析区间/精度和未知。时间表达缺关键参照返回 ambiguous/unknown，不能用宿主当前日期替换历史“昨天”。D03 只负责这些外部/日历语义；D10 提角色生活时钟政策/推进候选，D11 唯一登记/签发 CharacterClockMapping 与实际片段。C09 可引用该已签发映射产出 ContextTimeView，不能创建新的生活倍率/时钟权威。未来日程收到后仍是计划内容；D08/D10 分别负责承诺/排程，D02/D04 消费同一已签发映射版本。

C07 区分源错了、角色晚知道了、现实后来改变了、实体映射错了、文字被编辑了。迟到消息不默认推翻旧事实；原错误资格被确认后先屏蔽，再发布更正版本/领域通知。旧版本可在合法历史视角查到“当时依据”，不能继续作为当前真值。所有引用类型都参加删除，即使不属于当前失效 DAG。

时区切换或规则版本更新不回写原事件秒值来伪造一致性；新解释附解析版本和差异。不可可靠定序的跨平台消息维持偏序/未知，处理先后不是世界先后。幂等执行 key 不依赖模糊自然语言时间，避免澄清时间生成第二次同一来源。

## G. 安全过滤、删除与缓存

源文本、引文、工具输出中的指令不改 schema/owner/purpose、平台 sender 或模块写者；模型解析输出不得将任意片段标成“宿主证实”。系统角色、工具名称和发送者字段必须来自宿主回执。内容审核/语义判断不保证绝对理解正确，保留独立场景检查。

跨域内容依赖在查询、提交、模型调用和投递时同步核验 origin source/grant/access/delete epochs；源不可核验则 unavailable，异步通知仅用于清理。缓存键含视角/用途/身份映射/受众/时间界限及来源代际；缓存过期不自动使用陈旧身份支持行动。

D06 独立删除日志接受并屏蔽后，D03 删除所有可恢复内容及派生别名/事件/视角/作业/缓存/导入，不仅删除原文。必要无内容墓碑隔离访问。备份恢复必须验证最新删除水位，无法证明新鲜性就隔离。身份映射内容被删后，不能凭旧别名悄悄重新合并。

## H. 预算、异常和版本

容量采用主规格 §10 的开发默认值，父预算、递归深度和解引节点跨域共享。格式失败可在剩余父预算内有限重试；缺预算只保留确定 envelope 事实和缺口，不伪造完整解析。半成品与挂起作业持久化语义阶段、读集、源权限及取消代际，重启先查旧提交收据。

不兼容 schema/实体类型返回 rejected，迁移保留稳定身份/旧来源引用和删除规则。来源服务不可用时不能退回无权限原文 cache；身份索引不可用时不能用昵称简化替代。详细失败、当前源码缺口及未来手动联合场景见验收方案。
