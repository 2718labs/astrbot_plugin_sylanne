# D09 协作合同 v1（设计）

日期：2026-09-23。配套 [主规格](09-dialogue-expression.md) 与 [验收方案](09-dialogue-acceptance.md)。公共信封沿用 [全系统合同](../architecture/module-collaboration-contracts.md)、[D06 A](06-memory-contracts.md)、[D07 A](07-cognition-contracts.md)。拟议类型不是当前 API。

## A. 信封与身份

包含 schema/contract、owner、合法写者、activity/effect/attempt/phase operation、parent_task、call_id、D08 intent_ref、D03 scene/audience refs、按需的 `RoleBindingResolution` refs、purpose/provider policy、input refs、完整正/负查询读集、access/deletion/policy/conversation/cancellation epochs、预算租约、单调 deadline、语义时间与因果来源。表达用途固定 expression；生成供应商外送也是一次需授权的暴露，不能等最终发用户时才检查。

同 operation 的规范化参数必须相同；新 attempt 保留 effect、父预算及既有暴露账。执行结果未知先核实原记录。当前前置条件、长期语义依赖、历史成因分别标注，所有内容引用均参加权限和删除闭包。返回 complete/partial/deferred/unavailable/stale/conflict/rejected/pending_confirmation，含实际完成范围、已暴露/未暴露、费用、缺口和续接条件；不能向无权者透露被屏蔽来源存在。

一次交流由 `communication_action_id/contact_id` 标识，D08 的批授权或限定子资格绑定不可变有限 `segment_id, segment_effect_id, payload_digest, dependencies` 清单、总预算和有效期。每段独立 effect/dispatch，逐段消费资格；技术重试保持原段身份。超出清单、载荷/效果范围或预算须 D08 新决策，不能换 contact_id 绕过对象的无回应闸门。

首段交接后，无回应闸门记录其 originating contact_id：仍在原有限授权清单内的后段可在当前同意/静默/受众与有效期核验后继续，不被自己的首段当作第二次主动联系；其他 contact 或扩展后的新段没有此资格。明确停止/撤同意仍阻断原 contact 的未准入段。

## B. 操作目录

| ID / 操作 | 负责协作 | 输入 → 输出 | 不变式 |
| --- | --- | --- | --- |
| C01 `update_dialogue_track` | D03/D07 → D09 | 合法入站与已采用理解 → 主题/问题槽位候选 | 不自行解释事实或完成承诺 |
| C02 `prepare_blueprint` | D08 → D09，各域供投影 | 意图、受众、来源/心理投影 → 蓝图与缺口 | 必需许可不能靠措辞补齐 |
| C03 `realize_language` | D09 → D11 模型服务 | 蓝图、冻结读集与预算 → 草稿/声明映射/费用 | 候选不写上游状态；供应商权限先验 |
| C04 `verify_and_stage` | D09 与领域资格提供方 → D11 | 草稿、声明映射、各段/整体检查 → 合格段计划或拒绝 | 不把生成成功当发送成功 |
| C05 `admit_and_deliver_segment` | D08 意图 → D11 | 批授权/限定子资格、contact_id、合格段及其 effect、全部回执 → admission/执行回执 | D11 唯一真实发送者，逐段重验；主动联系核 D10 ContactPolicyCheck |
| C06 `interrupt_or_resume` | 新输入/D08/D11 → D09 | 取消代际、原回执、未答槽位 → 停止/新装配/待核实 | 已暴露不回滚，unknown 不重发 |
| C07 `settle_dialogue_progress` | D11/D08 → D09 | 真实投递/结果回执 → 对话进度、贡献候选 | 平台接受不等于已读、赞同或关系修复 |
| C08 `revise_or_erase_expression` | D06/领域修订 → D09/D11 | 更正/删除及依赖闭包 → 屏蔽、清理、澄清候选 | 删除日志优先，不能留影子草稿 |
| C09 `inspect_configure_preview` | 获准 D12 → D09 | 配置/预览/诊断命令 → 版本化配置或隔离预览 | 预览不发送、不记真实经历 |

## C. 核心对象与核验

`ExpressionBlueprint` = intent_ref、scenario/version、target identities、audience envelope、required/optional slots、allowed fact/judgment/self-understanding refs、unknown/simulated labels、disclosure range、style constraints、promise grants、media grants、segment dependencies、valid_until、read set、content dependency closure、budget/cancel refs。

`VerifiedSegment` = communication_action/contact_id、批授权或限定子资格、stable segment/segment_effect、immutable body/media digest、semantic unit、claim→source/qualification mapping、per-segment and batch validation receipts、preceding acceptance requirements、audience、permissions、intended position、expiry。改变字词或附件即使只是“优化语气”也生成新的内容版本并重新核验/获得匹配资格，不能沿用旧摘要回执；可能已交接的原 effect 先核实，不能用改稿覆盖。

`ExposureReceipt` 来自 D11：segment ID、实际 payload digest、目的地、admission seq、handoff time、provider receipt/status、可核实外部 ID、结果可信范围、费用。D09 只引用，不能通过自行创建 delivered 标记制造执行事实。

验证器必须区分允许的主观误判与不合格外部断言，采用 D04 SelfUnderstanding 及 D07 stance/evidence 资格。模型语义复核是有失败率的机制，使用独立保留场景评测；机械验证仅证明字段/引用/权限符合要求，不宣称理解正确。

## D. 准备与提交

1. D08 给已选交流意图及 RequiredCheck；D06 装配表达证据，D03/D05/D04/D07/D01 提供各自投影。社会角色措辞、规范或义务表述需要 D03 `RoleBindingResolution`，但它不能把语言候选升级为许可、承诺或可投递资格；缺失必需字段不开始外送模型。
2. D02 预留角色表达劳动，D11 预留实际费用。D09 事务外构思/生成/核验，记录每次 call。若这次构思被标作实际内部经历，依公共活动合同由 D06 登记，引用新感受/理解的必要域状态一起提交；纯格式检查不制造人物经历。
3. D11 原子验证完整快照、D09 写者能力、角色劳动分项账和必要来源；提交蓝图/合格段/对话检查点、实际劳动结算、需要的经历/领域状态和待执行 outbox。若并非角色活动，仅保留技术准备与真实费用。该 outbox 不绕过下一步 admission。
4. 每段 D11 C08 同步重验源授权及删除代际、D08 意图及有限段资格与全部 RequiredCheck、成员/目标、取消、内容 digest、依赖段回执及预算。主动联系显式核 D10 ContactPolicyCheck、quota/无回应闸门版本及当前同意/静默/受众，后续段不能继承已经过期的首段检查。原子 claim 当前 segment_effect，contact_id 额度只占一次；任一段已交接或 unknown 不释放，只有零段交接且全部已声明段可证明未执行才释放。claim/权限撤回的排序按 D11 admission 线性化语义，不声称网络交接后仍可保证追回。
5. 平台回执由 D11 持久化，D08 结算外部行动，D09 通过幂等 outbox 消费更新进度。若 D09 消费落后，读出联结权威执行账，不反向把未知当未发送。

D09 原子表达准备与 D06 回忆或 D07 认知若属于同一活动只附加必要写集，复用其唯一完成收据，不能重复创建第二次经历。单独构思是新 activity 并共享父预算。

## E. 节奏、暴露和打断

默认缓冲核验后发送。段序不能依赖尚未核验的未来文本纠正当前可见含义；后段 prerequisite 明确要求前段确定接受，否则 blocked。收到新消息的 conversation_epoch 变化先判断相依范围；明确停止提升取消代际，D11 阻断未 admission 段。已交接段保存 unknown/accepted 实际状态。

恢复时核实所有原段回执；未暴露且仍有意图的内容用新 attempt 重装配。不能把取消前的调用费用、已发段和说过的话清零。后续新的对话活动可有新 effect，但必须引用已暴露集合避免重复。

实时 typing、媒体预览、可见编辑、转录前缀均属于暴露，不能拿非正文通道绕过合同。无法隔离未核验流的宿主不启用流式能力；能力降级是配置能力选择，不改变角色情绪。

## F. 错误、修订、删除与幂等

| 条件 | 返回/动作 | 恢复规则 |
| --- | --- | --- |
| 引用/承诺/受众资格不齐 | partial/rejected | D08 缩小/更改意图后新装配 |
| 语义或格式检查失败 | rejected + 费用 | 同父额度最多 1 次修复，无效候选不采用 |
| 上游版本或群成员变化 | stale | 屏蔽旧段，先核实执行后新 attempt |
| 模型超时或真实额度不足 | deferred/unavailable | 保留任务与已用费，不伪造角色情绪 |
| 确定平台未接受 | failed 执行回执 | D08 保持资格且 D11 政策允许时以稳定 effect 重试 |
| 已交接但结果未知 | pending_confirmation | 查原平台/执行收据，不自动新 ID 发送 |
| 删除或撤权 | 不可用/屏蔽 | 同步阻断及 D06 独立日志清理，平台范围单列 |
| 取消时数据库仍提交中 | pending_confirmation | D11 join/核实真实提交结果，不并发重放 |

内容更正 invalidation 和 outbox 同时提交；清理不足时受影响域不可输出。挂起任务、话题摘要、生成缓存与媒体的清理都受最新删除日志约束。关闭/重启不自动推送积压话语，先重验当前意图、时机及用户设置。

## G. 版本与提供者接受条件

D03 提供可核验场景身份及按需 `RoleBindingResolution`；D04 提供非全知自述范围；D05 提供边界；D06 提供 expression 资格闭包并装配既有 D03 RequiredCheck provider；D07 提供判断资格；D08 提供意图和有限段授权；D02 提供分项劳动回执；D10 提供 ContactPolicyCheck；D11 提供耐久 admission/执行/预算及 contact 配额原子账；D12 提供受限配置。RoleBinding 无匹配、冲突、过期、覆盖不足或规范未知时，D09 不得声称相应许可/义务，也不能自行建立社会角色索引。缺失任一必需能力返回不可用，不能在 D09 建旁路补真值。参数/语义改变提升版本；接受条件以验收稿的联合场景证明，不以文件存在替代。
