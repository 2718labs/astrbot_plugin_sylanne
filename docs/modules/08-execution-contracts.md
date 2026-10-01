# D08 操作与跨域执行合同 v1（设计）

日期：2026-09-23。配套 [主规格](08-goals-execution.md)、[验收](08-execution-acceptance.md)。拟议版本 `d08.contract.v1`，并非现有 API；遵循 [公共合同](../architecture/module-collaboration-contracts.md)、[D06](06-memory-contracts.md) 和 [D07](07-cognition-contracts.md)。

## A. 信封与结果

沿用公共 `schema_version, owner_scope, activity_id, effect_id, attempt_id, operation_id, parent_task_id, issuer_module, purpose, audience, provider_policy, input_refs, read_versions, query_scope_epoch, access_epoch, deletion_epoch, policy_version, budget_lease, deadline, causation_id`；增加 goal/commitment/plan revision、能力版本、RequiredCheck、precondition/postcondition schema、risk_class、compensation_ref 和 effect_scope。多段消息增加 communication_action/contact_id、batch_revision、不可变 segment/effect 清单及各段载荷摘要/限定子资格。所用内容带时间与现实性，不能用空字段跳过实际所需的身份/权限验证。

同一冻结命令重传复用 operation，改参数拒绝。新 attempt 先查旧收据，保留原 activity/effect 和父预算；外部 effect 未知时不得通过新 action ID 绕过冻结。D11 保留各类型唯一写者和不可伪造收据，模型仅生成候选。结果为 `complete/partial/deferred/unavailable/stale/conflict/rejected/pending_confirmation`，均含完成范围、语义未知、费用、收据、缺口、后续合法动作。complete 必须说明是“计划已采纳”还是“效果已验证”，不能共用成功标签掩盖层级。

## B. 操作目录

| ID / 操作 | 负责与协作 | 输入 → 输出 | 强制条件 |
| --- | --- | --- | --- |
| C01 `propose_goal` | D01/D02/D04/D07/D10/D12 → D08 | 动机/请求、范围、证据 → 愿望/Goal 候选 | 不自动写承诺，不把不可控目标偷换为已实现 |
| C02 `adopt_or_revise_goal` | D08 → D11 | 候选、谓词、价值/资源视图 → 版本化目标与决定收据 | 采纳、取消、重开都有理由/依赖；义务独立 |
| C03 `evaluate_options` | D08 → D01/D02/D04/D05/D07 | 冻结候选与情境 → 合格候选、偏序、未知/冲突 | 先硬资格再比较；评价不执行动作 |
| C04 `propose_commitment` | D08 ↔ D09/D11 | 对象、许诺范围、条件/期限、沟通资格 → offer 与 communicated/unknown 更新 | 生成措辞不是传达证明；已有明确许诺不能因无确认而消失 |
| C05 `negotiate_joint_plan` | D08 ↔ D03/D06/D09 | 计划版本、各方提议/接受来源 → 按参与者的确认矩阵 | 沉默不是接受，跨角色无全局事务 |
| C06 `prepare_action` | D08 → D06/各检查提供者 | 冻结参数、RequiredCheck、读集、资源 → ActionIntent 与未满足项 | 缺一个必查回执不签资格 |
| C07 `dispatch_action` | D08 → D11；D09/D10 实现受限内容 | 意图、表达/活动/工具载荷、资格 → admission、交接及运行收据 | D11 最终重验；D09/D10 不能直接派发 |
| C08 `observe_and_settle` | D11/D03/D10/D06 → D08 | 收据、后置观察、来源、部分效果 → ActionOutcome、Goal/承诺进展与 outbox | 证据等级不升级；消费一次，unknown 不重放 |
| C09 `cancel_replan_compensate` | D08/D12 ↔ D11/D10/D09 | 原效果、停止原因、新约定/补救 → 取消边界/新计划/补救意图 | 已交接不保证追回，补救独立获得资格 |
| C10 `suspend_resume` | D08 ↔ D07/D10/D11 | 游标/资源/期限/版本 → 续接、重新装配或等待 | 已消费费用保留，未决动作先核实 |
| C11 `provide_required_check` | D06/D08 → D08 | 明确对象/期限/行动范围 → 承诺/冲突/执行状态回执 | 权威精确读取，不能以检索未命中断言没有义务 |
| C12 `inspect_edit_erase_transfer` | 获准 D12 → D08/D06/D11 | 诊断、配置、更正、删除/迁移命令 → 预览或有范围收据 | 共享权限与删除屏障；行政编辑不造实际经历 |

## C. 资格、目标谓词与承诺语义

`GoalPredicate` 使用注册 `artifact_verified/action_postcondition/communicated/recipient_acknowledged/domain_state/explicit_confirmation` 及有界组合，声明参数、有效时间、对象和观察提供者。自然语言是说明，不是执行谓词。未知、检索缺口、业务未满足和技术不可用分开。

`RequiredCheckSpec` 列 provider、scope、criteria_version、目标用途及 freshness 条件；回执含 examined_versions/query_epoch、结果、missing_items、valid_until。D03 核对身份/视角；任何声称社会角色授权或义务的行动还必须从 D03 获得 `RoleBindingResolution`，其 scope 含主体、目标/群体/场景、行动类别及 purpose，并携 binding/norm/read-set 版本。D05 核对适用明确边界；D06 核对来源/撤权；D08 核对承诺/冲突/未决效果；D11 核对权限/能力/派发。主动联系另需 D10 `ContactPolicyCheck`，核对 contact_id/对象/类别/时窗、当前同意/静默、配额/无回应闸门和策略版本；它新增于原五类，不替换 D05 或 D11。D06 统一装配，D11 最终核验。各类行动 schema 注册所需集合，调用方只能增加要求，不能删必需项。RoleBinding 无匹配、范围不足、冲突、过期或规范未知均不满足这项 RequiredCheck；边界不存在须有完成该查询域检查的回执，空结果不是提供者缺席。

`CommitmentSpec` 含承诺主体、受益/责任对象、语义范围、条件、期限/时区、建立标准、交付/履行标准、沟通/确认 refs、修订链及争议。承诺 `communicated` 仅依策略认可的传达收据；acknowledged 需对应入站证据。单方许诺与双方协议不同，提供者按类型选择建立谓词，不统一要求对方确认才负责任。已发送但结果未知保留 pending_confirmation/communication_unknown 和冲突占位。

`JointPlanRevision` 含每个参与者的接受范围和版本、退出规则。后续协议不倒改此前义务；本角色提交只对自己的图原子生效。其他角色共享通过 D06 TransferRef，每次使用同步验源权限，离线不可核验即 unavailable。不能把共享草稿当作每个角色的接受收据。

`DeadlineSpec` 含约定来源/原文范围、时区/规则版本、确定 instant，或明确约定的 floating 规则、DST gap/fold 策略、解析资格及 plan revision。宿主时区、夏令时库、显示设置改变不改写已协商 deadline；只能按原规则重算唤醒，变更约定须新合法 plan revision。D10 schedule revision 不能替代改约，同一承诺的旧期限在新版本未获合法接受期间继续有效。含糊日期先求证，不把系统默认时区伪装成约定。

## D. 决策、活动与实际派发

1. D07 提供已提交的相关认知/注意结果，D08 冻结目标与行动候选；必要推演只产生模拟材料。
2. D06 装配 RequiredCheck 与证据，D02/D11 给不同资源预留，D01 等提供相关候选视图。
3. D08 提案通过类型、目标谓词、预算、完整读集与权限验证后，Goal/决定/ActionIntent/贡献键/outbox 在同一角色事务采纳。需要新的认知或回忆体验先通过 D07/D06 唯一组合提交，D08 不能引用未提交候选或再写体验。
4. D09 生成获准表达，D10 生成获准活动执行描述；D08 检查范围相等/收窄。新事实、承诺、效果参数或对象变化必须重新采用，不允许重用原资格。
5. D11 final admission 原子重验输入及所有 RequiredCheck、资源租约/权限/删除代际，持久写 effect 的 dispatch claim 与一次性资格。多段消息由 D08 签有限批意图和固定清单内子资格，每段独立 effect/admission；D10 政策下的主动额度按 contact_id 在首个段 admission 时一次原子占用，后续段检查同一占用但仍重验当前同意/静默/边界及完整资格。网络交接不在此数据库事务内；sender 核验资格及取消状态后立即交接。
6. 交接与查询结果进入 D11 收据。D08 按后置条件采纳 Outcome；完成目标/履约变更、贡献去重、相关 outbox 一致提交。D05/D04/D01 消费各自合法材料，不由 D08 代写。

撤权屏障与 admission 先后串行化；撤权先发生就阻止派发，admission 后撤权尽力阻止尚未交接。平台已交接不承诺追回。未知提交只查原 operation；未知外部效果只查原 effect/provider request，不以新预算、新活动或超时为重发理由。

同一 contact 任一段交接/unknown 均保留整次主动额度；只有全部段确定未交接且其资格已取消/不可再派发时才按政策释放。不可变清单外追加或扩展语义范围要重新决策并签新批次版本，已暴露 effect 不变。新 contact 仍需 D10 对象无回应闸门和 D05 修复限制检查，不得换 ID 越过；候选过期也不释放已交接/unknown 联系的无回应状态。

## E. 重试、取消、部分效果与补救

工具注册 `idempotent_with_key/read_only/non_idempotent`、查询能力、可撤销范围、后置观察标准及超时语义。幂等声明须来自适配器契约及后续验收，不能让模型自行标注。即使幂等，也须复用 provider idempotency key 和冻结参数；重复调用费用真实累计。

known_not_accepted 可按原 effect 重新派发；accepted/running/unknown 先核查。非幂等且无核查能力的 unknown 默认停止自动执行，保留待核查，并根据已有可表达资格说明未知。若用户明确选择再次尝试，创建独立新行动，记录可能重复效果、范围和新授权；不得把它伪装为保证安全的技术重试。

取消请求有 `requested/blocked_before_handoff/stop_requested/confirmed_stopped/too_late/unknown`，与业务 Outcome 分离。停进程、超时或释放本地 lease 不能证明远程工具已停。部分效果逐项记录；补救是新的 ActionIntent，另查当前权限和风险，不复用原资格或自动保证成功。真实错误依然是历史，删除另按 D06 执行。

## F. 并发、预算与生命周期

目标/承诺读取包括相关查询域 epoch，捕获新增互斥义务；多个会话采纳相冲突许诺需 D11 的冲突域序列化/CAS。D10 提供可行排程/占用版本，D02 提供角色资源有效租约，D11 提供真实执行额度；过期预留释放，新装配不重复记账。没有长期资源承诺能力时不得把短 lease 当作明天一定可用的保证。

父决策预算含全部辅助调用、检索、步骤和实际调用；暂停/拆步骤/跨域都不重置。D02 实际劳动按 role activity/component；D11 成本按 call_id。取消不撤销已发生劳动，纯技术核查不写成角色新体验。计划窗口 8 步、比较 6 候选、辅助调用 2 次为有限默认上限，配置须整数非负且有硬总量；到零返回 deferred。

重启恢复依次应用删除/权限水位、加载未决 effect、核实 dispatch/提交收据、重验计划，再恢复注意/生活任务。离线期间未运行步骤不标完成；只计算有依据的期限状态。持久订阅注册与当前水位核验由 D11 原子处理，避免完成事件发生于查询和订阅之间。

## G. 更正、删除、审计和迁移

更正影响当前资格立即失效；已执行事实不可回滚为未发生。D06 删除屏障覆盖决定理由、许诺原文、参数、载荷、模型缓存、诊断、备份/导入、已持久操作原文。允许最小不可还原的 effect/删除身份防重放，仍受元数据权限。无法保留有效履约内容时状态 unavailable，而不是编造重建内容。

D12 读产品投影或获准诊断；角色只能获得其可知信息。工作台撤销/编辑需经过 C09/C12，直接把状态改 fulfilled 被拒绝，除非是具名行政修正并标明证据/原因，且不伪造外部收据。导入未决 action 不自动执行；复制角色不得继承执行资格。schema 升级需 D11 类型目录迁移，未知版本拒绝。

## H. 提供方接入及联合例

D01 接受策略/价值比较请求；D02 提供报价/实际分项结算；D03 提供身份/视角、结果来源及按需 `RoleBindingResolution`；D04 接受受阻/结果评价；D05 提供边界检查/关系贡献；D06 装配来源/必查与删除；D07 提供决策认知与注意；D09 接受固定意图；D10 接受本角色活动/排程；D11 提供事务/派发/真实收据；D12 提供授权产品命令。以上为明确设计职责，尚需实现验证。

联合例：答应明晚发画稿，实际发现资源不足 → D08 保留承诺，D07 分配协商注意，D05 提供对方沟通边界，D09 表达改期提议 → D11 发出但结果 unknown → D08 保留旧义务及未知提案，不当作改期成功 → 原消息被查询确认并收到对方同意 → 新 plan revision 生效 → D10 完成实际作品、D11 派发并提供相应收据 → D08 按约定交付谓词结算，D05/D04 分别评价修复与感受。
