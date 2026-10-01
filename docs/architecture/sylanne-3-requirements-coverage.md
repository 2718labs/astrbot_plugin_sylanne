# Sylanne 3.0 旧需求逐项设计覆盖

日期：2026-09-23；2026-09-27 增补范围说明。审计对象仍为[旧需求账](../../rewrite/REQUIREMENTS.md)的 **62 项**：R0 5、M 13、D 12、ECO 7、MEM 15、OPS 10。本表只判断旧要求的设计覆盖，不判断实现或运行通过。新增 D13 的 A01–A08 是独立新增验收，不回填为旧账第 63 项；当前设计入口见[十三域索引](sylanne-3-design-index.md)与[耦合总装](sylanne-3-thirteen-module-coupling.md)，公共语义见[协作合同](module-collaboration-contracts.md)。

`DESIGN` 表示所列章节已有具体机制、责任与失败/验收出口；`REVISED` 表示后续明确方向替代了旧机制，保留的要求已映射；`OPEN` 表示当前设计缺少旧要求的一部分，需所列所有者补齐或显式裁决。全部状态均附带 **完整实现未验收、对应运行场景未执行**，不能将 DESIGN 解释为产品 DONE。章节号以链接文件中的实际标题为准。

## 1. 全局规则

| ID | 设计结论与精确位置 | 状态 / 剩余设计责任 |
| --- | --- | --- |
| R0-01 | [D11 主稿](../modules/11-runtime-host.md) §5 根 main.py 初始化 RuntimeContext，§7 原生加载不回退旧核，§14 全域入口接线，§15 明示当前 Store/Engine 切片；[D06 合同](../modules/06-memory-contracts.md) §H 禁止 fixture/旧核心双权威。旧账指定的 rewrite/sylanne3 及退役路径继续作为实施约束。 | DESIGN；实际冷启动、导入扫描与真实宿主追踪待执行。 |
| R0-02 | [D11 主稿](../modules/11-runtime-host.md) §§3、6：同源图、写者能力、完整读写集、跨 Owner 原子写入；[D12 主稿](../modules/12-workbench-delivery.md) §2 禁止工作台通用改节点。 | DESIGN |
| R0-03 | [十二域索引](sylanne-3-design-index.md) 全域唯一归属；[联合验收](sylanne-3-integration-acceptance.md) §§1–3 区分合同、语义、纵向、现场及交付；[D04 原稿](../modules/04-emotion.md) §4.3 不固定最终维数；本表 62 项均有设计结论。 | DESIGN；矩阵闭合仅是设计覆盖，不代表实现或场景通过。 |
| R0-04 | [D11 主稿](../modules/11-runtime-host.md) §§8–9 分开三时钟、四类误差和四类预算；[数值合同](../modules/11-runtime-numerics.md) §§2–5 分别核查残差、时间和截断。 | DESIGN |
| R0-05 | [D11 主稿](../modules/11-runtime-host.md) §§7–9 ComputeAtom 注册、未认证 SCC 拒绝、作业暂停续接；[D04 补充](../modules/04-emotion-completion.md) §4 联合条件与拒绝提交；[数值合同](../modules/11-runtime-numerics.md) §§1–6 证明范围及未实现边界。 | DESIGN；稳定证书不证明语义正确。 |

## 2. 核心机制

| ID | 设计结论与精确位置 | 状态 / 剩余设计责任 |
| --- | --- | --- |
| M-01 | [D11 主稿](../modules/11-runtime-host.md) §§3–4 七视图同源、Owner/类型目录/版本与边分类；[公共合同](module-collaboration-contracts.md) §§1–2 唯一领域写者及共同来源时间信封。 | DESIGN |
| M-02 | [D11 主稿](../modules/11-runtime-host.md) §3 Bot/persona namespace 内关系对象、scene、event、activity Owner；[D01 补充](../modules/01-persona-completion.md) §2 新会话延续、暂停/复制/迁移；[D06 主稿](../modules/06-memory.md) §15 跨场景与角色隔离。 | DESIGN |
| M-03 | [D07 主稿](../modules/07-attention-cognition.md) §§4–6 Concern 身份、解决谓词、open/waiting/parked/resolved/relinquished、独立归档、合并/分裂与条件唤醒。旧“活跃”由 FocusState/票据表示，不丢生命周期。 | DESIGN |
| M-04 | [D01 原稿](../modules/01-persona.md) §§2–6 分层人格、价值冲突、策略与连续性；[补充](../modules/01-persona-completion.md) §§1–4 来源、独立经历/反例、试用、版本激活及修订。 | DESIGN |
| M-05 | [D04 原稿](../modules/04-emotion.md) §§3–8 对象化意义、多时间尺度、自我理解、调节/元情绪与行动读出；[补充](../modules/04-emotion-completion.md) §§4–5 有界输入及共享成本；[验收](../modules/04-emotion-acceptance.md) §B T02–T05/T25 干预和行为出口。 | DESIGN |
| M-06 | [D04 原稿](../modules/04-emotion.md) §1.1 明确取代心理阶段机；§§3.2、6–8 保留即时反应、持续感受/心境、元评价和调节/恢复；[补充](../modules/04-emotion-completion.md) §§2、5、7 与 [验收](../modules/04-emotion-acceptance.md) §B T01/T03–T05/T14–T16。 | REVISED；五种功能并存，不再验“五阶段必经转移”，详见 §7。 |
| M-07 | [D06 主稿](../modules/06-memory.md) §§4、10、12 原源、活动、贡献及解释修订分开；[D04 补充](../modules/04-emotion-completion.md) §6 错误驱动截断但实际感受不倒改；[D08 主稿](../modules/08-goals-execution.md) §§8–9 外部后果与补救。 | DESIGN |
| M-08 | [D05 主稿](../modules/05-relationships.md) §§3–8 有向对象/领域/场景维度、局部贡献、边界、互惠及修复；[合同](../modules/05-relationship-contracts.md) §§B–E 注册操作/贡献/资格；[公共合同](module-collaboration-contracts.md) §§1–2 禁止旁路写者。 | DESIGN；关系过程允许部分改善，不强制固定关系阶段。 |
| M-09 | [D07 主稿](../modules/07-attention-cognition.md) §§4、10、12 SimulationBranch 冻结快照/现实性/预算/停止；[合同](../modules/07-cognition-contracts.md) §§C–E 采用与反馈；[联合验收](sylanne-3-integration-acceptance.md) §1 S11。 | DESIGN |
| M-10 | [D08 主稿](../modules/08-goals-execution.md) §§3、5、7–8 候选、偏序、硬条件、RequiredCheck 和执行资格；[D09 主稿](../modules/09-dialogue-expression.md) §§5–7 多意图蓝图与核验；[D11 主稿](../modules/11-runtime-host.md) §11 最终 admission。 | DESIGN |
| M-11 | [D10 主稿](../modules/10-life-proactivity.md) §§3–8、13 项目/步骤/产物/习惯、恢复和有限模拟；[D01 补充](../modules/01-persona-completion.md) §§2–3 成长材料出口；[D05 主稿](../modules/05-relationships.md) §§5、14 共同史与关系后果。 | DESIGN |
| M-12 | [D11 主稿](../modules/11-runtime-host.md) §§7–8 即时 DAG、明确延迟、联合 SCC；[数值合同](../modules/11-runtime-numerics.md) §§1–5 认证、局部边界与误差；[D04 补充](../modules/04-emotion-completion.md) §4 不以逐块稳定替代联合证明。 | DESIGN |
| M-13 | [D11 主稿](../modules/11-runtime-host.md) §§6、11–12 同 namespace 跨 Owner 原子提交、独立执行日志、claim/观测/unknown 与备份；[公共合同](module-collaboration-contracts.md) §§2–3 跨角色 transfer 非全局事务。 | DESIGN；外部效果不承诺无条件 exactly-once。 |

## 3. 十二个协作系统

各行的主稿、合同、验收共同构成设计证据；“未来用例存在”仅说明可验证要求已定义。

| ID | 已回答的领域设计与精确位置 | 状态 |
| --- | --- | --- |
| D01 | [人格原稿](../modules/01-persona.md) §§2–8；[完整补充](../modules/01-persona-completion.md) §§1–6；[合同](../modules/01-persona-contracts.md) §§B–D；[验收](../modules/01-persona-acceptance.md) §B T01–T24：跨会话人格、历史连续、成长/编辑及受限行为投影。 | DESIGN |
| D02 | [身体主稿](../modules/02-body-needs.md) §§3–8：模拟身体/需求、连续恢复、报价/结算、离线与能力读出；[合同](../modules/02-body-contracts.md) §§C–F；[验收](../modules/02-body-acceptance.md) §2。 | DESIGN |
| D03 | [情境主稿](../modules/03-world-context.md) §§3–9：事件/账号/人分立，SceneFrame/ContextFrame/PerspectiveGrant、引用否定、当时所知与 RoleBinding；[合同](../modules/03-context-contracts.md) §B.1、§§C–G；[验收](../modules/03-context-acceptance.md) §2 T08–T20/T33–T38。新类型不能把传输当知情，社会角色不能从账号绑定推得。 | DESIGN |
| D04 | [情绪原稿](../modules/04-emotion.md) §§4–9；[补充](../modules/04-emotion-completion.md) §§2–6；[合同](../modules/04-emotion-contracts.md) §§B–D；[验收](../modules/04-emotion-acceptance.md) §B：意义驱动、混合感受、调节/元情绪和行为读出。 | REVISED；旧五阶段验收按 M-06 替代。 |
| D05 | [关系主稿](../modules/05-relationships.md) §§3–12；[合同](../modules/05-relationship-contracts.md) §§C–G；[验收](../modules/05-relationship-acceptance.md) §2：对象/领域隔离、明确边界、渐进修复及删除。 | DESIGN |
| D06 | [记忆主稿](../modules/06-memory.md) §§3–16；[合同](../modules/06-memory-contracts.md) §§B–H；[验收](../modules/06-memory-acceptance.md) §§1、3：来源/主观痕迹/回忆、巩固遗忘、旧 RecallRequest 迁移、强制触发、预算与停止；策略和自传由所属域接受。 | DESIGN |
| D07 | [认知主稿](../modules/07-attention-cognition.md) §§4–13；[合同](../modules/07-cognition-contracts.md) §§C–H；[验收](../modules/07-cognition-acceptance.md) §2：有限注意、竞争解释、反事实、反思及可续任务。 | DESIGN |
| D08 | [执行主稿](../modules/08-goals-execution.md) §§3–12；[合同](../modules/08-execution-contracts.md) §§C–H；[验收](../modules/08-execution-acceptance.md) §2：目标谓词、承诺/联合计划、候选资格与未知结果。 | DESIGN |
| D09 | [表达主稿](../modules/09-dialogue-expression.md) §§3–12；[合同](../modules/09-dialogue-contracts.md) §§C–F；[验收](../modules/09-dialogue-acceptance.md) §2：话题/蓝图/核验、节奏、多段中断及逐段结果。 | DESIGN |
| D10 | [生活主稿](../modules/10-life-proactivity.md) §§3–12；[合同](../modules/10-life-contracts.md) §§C–G；[验收](../modules/10-life-acceptance.md) §2：项目/日程/习惯、有限离线、真实产物与主动准入。 | DESIGN |
| D11 | [运行主稿](../modules/11-runtime-host.md) §§3–14；[数值合同](../modules/11-runtime-numerics.md) §§1–6；[操作合同](../modules/11-runtime-contracts.md) §§C–G；[验收](../modules/11-runtime-acceptance.md) §2：图、原生/线程、预算/恢复、宿主与副作用。 | DESIGN |
| D12 | [工作台主稿](../modules/12-workbench-delivery.md) §§3–15；[合同](../modules/12-workbench-contracts.md) §§C–I；[验收](../modules/12-workbench-acceptance.md) §2：创作/观察/纠错、隔离实验、迁移、包与恢复。 | DESIGN |

## 4. 生态机制

| ID | 设计结论与精确位置 | 状态 / 剩余设计责任 |
| --- | --- | --- |
| ECO-01 | [D07 主稿](../modules/07-attention-cognition.md) §§4–6 类型票据、条件唤醒、份额、组轮转及持续超载延期；[合同](../modules/07-cognition-contracts.md) §F 持久服务量；[D11 主稿](../modules/11-runtime-host.md) §9 真实运行额度。 | DESIGN；公平结论带可运行/可获额度前提。 |
| ECO-02 | [D07 主稿](../modules/07-attention-cognition.md) §§6–7、12 中断、票据过期、恢复重验/费用不清零；[合同](../modules/07-cognition-contracts.md) §§F、H；[D10 主稿](../modules/10-life-proactivity.md) §§6、8 不补造漏 tick。 | DESIGN |
| ECO-03 | [D08 主稿](../modules/08-goals-execution.md) §§3、6、9 联合计划/参与者确认/履行/改约；[合同](../modules/08-execution-contracts.md) §C 承诺语义；[联合验收](sylanne-3-integration-acceptance.md) §1 S05。 | DESIGN |
| ECO-04 | [D03 主稿](../modules/03-world-context.md) §3 社会角色绑定；[D03 合同](../modules/03-context-contracts.md) §B.1 RoleBinding/NormReference、C05a 解析、版本/作用域/可见范围与缺失拒绝；D01/D05/D08 分别保留人格、边界和行动权威。 | DESIGN；已复核新增绑定合同，不能以账号绑定或关系印象自动扩权。 |
| ECO-05 | [D10 主稿](../modules/10-life-proactivity.md) §§1、3–5、8 区分真实作品、模拟活动、计划及未完成；[D08 主稿](../modules/08-goals-execution.md) §§8–9 执行结果；[联合验收](sylanne-3-integration-acceptance.md) §1 S09/S11。 | DESIGN |
| ECO-06 | [D01 原稿](../modules/01-persona.md) §§4–6；[补充](../modules/01-persona-completion.md) §§1–4 独立来源、反例、作用域、试用、撤销及历史；[合同](../modules/01-persona-contracts.md) §B C04–C07；[验收](../modules/01-persona-acceptance.md) §B T08–T13。 | DESIGN |
| ECO-07 | [D09 主稿](../modules/09-dialogue-expression.md) §§5、8–12；[合同](../modules/09-dialogue-contracts.md) §§C–F；[公共合同](module-collaboration-contracts.md) §3 有限段清单、每段 effect/admission、联系额度；[联合验收](sylanne-3-integration-acceptance.md) §1 S07/S08。 | DESIGN |

## 5. 记忆与回忆预算

| ID | 设计结论与精确位置 | 状态 / 剩余设计责任 |
| --- | --- | --- |
| MEM-01 | [D06 主稿](../modules/06-memory.md) §4 将旧 EvidenceUnit/Episode/Recall 职责分别具体化为 EvidenceSpan/MemoryEpisode/RecallActivity/Recollection，Source/解释所属域分立；§12 历史视角；[合同](../modules/06-memory-contracts.md) §§A、B1、C1；[验收](../modules/06-memory-acceptance.md) §3 T05/T14/T20。 | DESIGN；名称变化不赋予推测事实资格。 |
| MEM-02 | [D06 主稿](../modules/06-memory.md) §§4–5 分段/家族/痕迹与来源先保存；[合同](../modules/06-memory-contracts.md) §§B C01/C02、D、E 持久 pending、领域校验、一致写入及索引追赶。 | DESIGN |
| MEM-03 | [D06 主稿](../modules/06-memory.md) §6 精确领域核查、一般候选、冲突反证及有限覆盖；§14 权限分区可选向量；[合同](../modules/06-memory-contracts.md) §§B2、E 同步授权和回源。无权查询者不获得“存在但删掉”的泄漏。 | DESIGN |
| MEM-04 | [D06 主稿](../modules/06-memory.md) §6 旧 RecallRequest 状态/字段迁移表；[合同](../modules/06-memory-contracts.md) §§A、B C03、B1 兼容适配、H 持久 job/attempt/receipt：触发→必查→工作集→搜索→证据→带槽位终态，未知字段拒绝。 | DESIGN；旧请求控制职责迁往 D07/D06/D11，不构建旁路旧状态库；软件控制状态不与 D04 非心理状态机冲突。 |
| MEM-05 | [D06 主稿](../modules/06-memory.md) §6.2 列出六类强制触发及普通问候不搜历史的边界；[合同](../modules/06-memory-contracts.md) §B/C03 定义 trigger.kind、必查与 no_history_search 收据；[验收](../modules/06-memory-acceptance.md) T39 冻结漏触发、无用触发及错误提前停止三项指标。 | DESIGN |
| MEM-06 | [D06 主稿](../modules/06-memory.md) §14、[合同](../modules/06-memory-contracts.md) §H 已明确工作集复核 0 辅助生成、每通道初始 32、融合 64、128 节点/2 跳、共享 2 次辅助尝试及精确分页不截责任；[D07 主稿](../modules/07-attention-cognition.md) §12 父预算共享。 | DESIGN；0 次仅指已有合格引用的读取复核，新主观重建仍计费。 |
| MEM-07 | [D06 主稿](../modules/06-memory.md) §14 定义版本化有界“证据收益−延迟−调用费用−上下文干扰”续检和连续两轮无缺口减少停止；[合同](../modules/06-memory-contracts.md) §B/H 持久化继续/停止收据、真实费用与注意成本来源；[验收](../modules/06-memory-acceptance.md) T38/T40 核对预算、权限、必查与同历史对照。 | DESIGN |
| MEM-08 | [D06 主稿](../modules/06-memory.md) §§7–10 候选不等于回忆、同源外部事件与真实内部活动分别去重；[合同](../modules/06-memory-contracts.md) §C 唯一回忆提交；[D07 主稿](../modules/07-attention-cognition.md) §§5–6 冷却/配额/恢复。 | DESIGN |
| MEM-09 | [D06 主稿](../modules/06-memory.md) §§6、10、14 局部脏重建、覆盖/负结果代际、可选向量；[合同](../modules/06-memory-contracts.md) §§E–F 正负读集/缓存键/当前授权/行动前重验；[验收](../modules/06-memory-acceptance.md) §3 T25–T27。 | DESIGN；有效域/代际及请求有效期限制负结果，缓存命中不跳过授权。 |
| MEM-10 | [D06 主稿](../modules/06-memory.md) §§2、10–11 巩固、语义/摘要、关系、策略、自传和压缩出口；[合同](../modules/06-memory-contracts.md) §D 所属域采用/版本检查；[D01 补充](../modules/01-persona-completion.md) §§1–4 独立依据与反例。 | DESIGN |
| MEM-11 | [D06 主稿](../modules/06-memory.md) §12；[合同](../modules/06-memory-contracts.md) §§C、D 先失效再重建；[D01 补充](../modules/01-persona-completion.md) §4、[D05 主稿](../modules/05-relationships.md) §8、[D08 主稿](../modules/08-goals-execution.md) §§9、12 各域重建且不倒改已发结果。 | DESIGN |
| MEM-12 | [D06 主稿](../modules/06-memory.md) §§11、13；[合同](../modules/06-memory-contracts.md) §G 删除写前日志/屏蔽、分面清理、历史/混合派生/旧备份；[D12 主稿](../modules/12-workbench-delivery.md) §14 产品删除回执与外部范围。 | DESIGN |
| MEM-13 | [D06 主稿](../modules/06-memory.md) §14 模型/维度/预处理/版本/分区和新代际；§4 IndexGeneration 批次/水位；[合同](../modules/06-memory-contracts.md) §E 先分权限、再回源/覆盖；[验收](../modules/06-memory-acceptance.md) §3 T27 换代与无向量。 | DESIGN |
| MEM-14 | [D06 主稿](../modules/06-memory.md) §§4、6、14 IndexGeneration/MaintenanceJob、原子 outbox/水位；[合同](../modules/06-memory-contracts.md) §§E、H 版本幂等追赶、查询域代际、权限/水位缓存与可恢复游标；[验收](../modules/06-memory-acceptance.md) §3 T25/T26/T30。 | DESIGN |
| MEM-15 | [D06 合同](../modules/06-memory-contracts.md) §§G、J 类型目录、schema 门禁/迁移/回滚；[D11 主稿](../modules/11-runtime-host.md) §4 影子库、字段/来源映射、旧版本解码与删除/执行历史保护；[D12 主稿](../modules/12-workbench-delivery.md) §12 预览/损失/恢复。 | DESIGN |

## 6. 产品、迁移与现场

| ID | 设计结论与精确位置 | 状态 / 剩余设计责任 |
| --- | --- | --- |
| OPS-01 | [D12 主稿](../modules/12-workbench-delivery.md) §§11–12 隔离导入/预览/映射/冲突/回退；[D06 主稿](../modules/06-memory.md) §16 导入资格；[D11 主稿](../modules/11-runtime-host.md) §4 目录与旧核心禁回退。 | DESIGN |
| OPS-02 | [D12 主稿](../modules/12-workbench-delivery.md) §§3、5–10 页面、创作、观察、因果诊断和隔离实验；[合同](../modules/12-workbench-contracts.md) §§C–F 版本投影/操作/传输；[验收](../modules/12-workbench-acceptance.md) §2。 | DESIGN |
| OPS-03 | [D06 主稿](../modules/06-memory.md) §16 记忆时间线、主观/事实、来源/联想、未来事项、成长、纠错/删除/检索实验；[D12 主稿](../modules/12-workbench-delivery.md) §§3、6、9–10；[D06 合同](../modules/06-memory-contracts.md) §B C07/C08。 | DESIGN |
| OPS-04 | [D12 主稿](../modules/12-workbench-delivery.md) §5 方案编译预览与迁移；[合同](../modules/12-workbench-contracts.md) §C；[D11 主稿](../modules/11-runtime-host.md) §§4、14 原子版本切换；[D01 补充](../modules/01-persona-completion.md) §§2、6 编辑/成长分立。 | DESIGN |
| OPS-05 | [D11 主稿](../modules/11-runtime-host.md) §§7–9 有限线程/原生批计算、取消实际占槽、CAS 有序提交与预算；[合同](../modules/11-runtime-contracts.md) §§C–E；[验收](../modules/11-runtime-acceptance.md) §2 真实宿主及故障验证。 | DESIGN；async 声明和旧线性核均不算非阻塞重型求解验收。 |
| OPS-06 | [D12 主稿](../modules/12-workbench-delivery.md) §§4、12–13 安装/恢复/平台与 ABI 矩阵；[合同](../modules/12-workbench-contracts.md) §G；[D11 主稿](../modules/11-runtime-host.md) §§7、14 可信清单与排除物；[联合验收](sylanne-3-integration-acceptance.md) §2 实测包大小/组成。 | DESIGN；无实际构件或平台结果。 |
| OPS-07 | [联合验收](sylanne-3-integration-acceptance.md) §§1–2 私群聊、可见性、结果未知、工具/附件、重连/重启矩阵；[D03 合同](../modules/03-context-contracts.md) §§C–D 传输与知情分立；[D11 主稿](../modules/11-runtime-host.md) §11 外部收据。 | DESIGN；真实平台未执行。 |
| OPS-08 | [联合验收](sylanne-3-integration-acceptance.md) §2 全规模档/压力组合/延迟/内存/费用；[D06 验收](../modules/06-memory-acceptance.md) §4 独立保留集、冻结参数与质量；[D11 主稿](../modules/11-runtime-host.md) §13 可观测指标。 | DESIGN；阈值须实施后基线校准再事前冻结，不能事后调门槛。 |
| OPS-09 | [联合验收](sylanne-3-integration-acceptance.md) §2 明列四路线、事件关系/反证/触发/后台整合消融、同历史同模型同预算及先安全后质量；[D06 验收](../modules/06-memory-acceptance.md) §4 补充情感记忆对照。 | DESIGN；尚无对照结果。 |
| OPS-10 | [联合验收](sylanne-3-integration-acceptance.md) §1.1 连续完整顺序轨迹：同一项目/角色/权限贯穿责任未确认、私下困难、公开抱怨、中断、离线与真实完成、错误转述更正及新会话续谈；每步列域职责和未来收据断言。 | DESIGN；已核对新增八步轨迹，全部仍是未来验收，非实际回放结果。 |

## 7. 旧要求与新方向的显式协调

**M-06 与 D04。** 旧账的“五阶段”不能按原文恢复成情绪状态机。用户后续明确拒绝固定情绪标签/阶段开关，[D04 原稿 §1.1](../modules/04-emotion.md) 已裁决。保留五项能力：即时反应由对象化 AffectProcess/FeelingBlock 表达；事项持续感受和心境为不同时间尺度；资源负荷归 D02；元评价为 SelfUnderstanding/有限元情绪；恢复、重评、克制、修复分别由连续演化、RegulationAttempt、D08/D09 行动和 D05 修复承担。它们可并行、迟到、失败，不规定先后必经。验收改为分量干预、真实时间/资源、无伪造事件、调节效果与停止条件，不验“从愤怒阶段跳到和解阶段”。任务、投递、检索控制的离散生命周期仍合法。

**旧账状态与当前设计状态。** 原账 62 行中 DONE=0、PARTIAL=22、TODO=40；这是其记录的实现/验收口径，不是当前设计覆盖数。其 R0-01/02/04/05 为 PARTIAL，R0-03 为 TODO；本表给出设计位置不将它们改为运行 DONE。原账正文存在 173 Python 与 Foundation 表 122 核心、尾部 67+9 等不同历史切片数字；本轮不复跑、不合并这些数字，也不把旧证据归给当前完整设计。源码当前能力以各域验收稿的源码差距为实施入口，不能由旧账或新文档推定实际已接线。

**完成边界。** D03 已补独立社会角色绑定（ECO-04）；D06 已补旧检索状态承接、强制触发、候选预算和有界续检/两轮停止（MEM-04–07）；联合验收已补 OPS-10 连续轨迹。这些条款均位于领域规格、合同与未来验收，本表不创建旁路接口或代替模块设计。

## 8. 本次完成审计

已逐 ID 建立 62 行，分组数量与旧账一致，没有以“十二域都有文件”代替逐需求检查。当前 **60 DESIGN、2 REVISED、0 OPEN**；REVISED 为 M-06、D04，后续用户明确否定的旧情绪阶段机已按连续非状态机设计替代。该计数仅表明旧要求在设计层有对应结论，未声称实现、场景或产品验收通过。

本次检查为文档读取、章节/本地链接与 ID 核对；未执行编译、运行测试、模型调用、宿主操作、包构建、提交、推送或 PR。各 OPEN 的关闭必须依据新增实际章节重新审核，不因作者报告“已补”自动改状态。未来实现按各域验收稿和联合验收执行；人工场景同时观察源/版本/收据与平台实际表现，不能只看生成台词。
