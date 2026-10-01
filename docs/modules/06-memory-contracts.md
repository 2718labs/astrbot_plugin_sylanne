# D06 跨模块协作合同 v1（设计）

日期：2026-09-23。主规格见 [06-memory.md](06-memory.md)。本文固定本轮推荐的语义与责任，尚未实现；类型名不是当前源码 API，不表示其他模块已集成。所有接口在同一进程/共享运行时内即可实现，不要求新增网络服务或每模块一个 Agent。

## A. 共用信封与返回语义

所有命令包含 `schema_version, operation_id, parent_task_id, issuer_module, owner_scope, purpose, audience, provider_policy, input_refs, read_versions, query_scope_epoch, access_epoch, deletion_epoch, policy_version, budget_lease, deadline, causation_id`；时间另含源发生、获知、拟处理区间。命令只携带申请，最终提交序列由 D11 签发。

- `owner_scope` 为 Bot/persona；涉及对象由 D03 稳定实体引用表示。不同角色的私人记录不能因同名或同向量合并。
- 身份分三层：稳定的 `activity_id/effect_id` 标识一次实际活动/作用；`attempt_id` 标识一次冻结输入的装配，阶段 `operation_id=(activity_id, phase, attempt_id)` 绑定含版本/额度/截止时间的规范化命令；同一尝试的传输重试复用该 operation_id。重用 operation_id 改参数返回冲突。输入过期或续接需新装配时创建新 attempt，保留 activity/effect 身份、贡献键和父预算，实际已用费用不归零。D11 对活动完成收据及 effect_id 有唯一约束：旧尝试已完成则新尝试返回已完成或冲突，不再次提交体验。开始新 attempt 前先核实旧尝试可能已提交的收据。
- D11 注册写者能力表：调用方只能提交所属类型的候选，组合事务保留每个写者的责任及读写集；自由模型输出没有提交权限。
- `purpose` 沿用当前存储枚举：普通检索/联想/重建映射 `context`，表达投影用 `expression`，长期更新/巩固/成长证据用 `consolidation`，获准诊断用 `audit`。同时涉及多用途时分别验证，不能以 context 获准替代 consolidation。新用途只能经版本化迁移加入。
- 时间预算以宿主单调时钟控制；事件与获知时间用于语义。超时不等于正在执行的线程/数据库操作已被杀死，按 C04/C09 核实收据。
- 通用结果为 `complete / partial / unavailable / deferred / stale / conflict / rejected`，包含实际消费、有效输入版本与重试/续接条件。`complete` 必须指明完成的是哪个请求域和哪些槽位，不表示角色全知。
- 权限拒绝、删除和不存在不能向普通调用方泄露存在性；授权审计可见详细原因。可对外表达的结果还要经过 C06。

## B. 核心合同目录

| ID / 操作 | 发起与负责方 | 输入 | 输出与不变式 |
| --- | --- | --- | --- |
| C01 `admit_source` | D11 宿主或 D10/D12 → D06 | 来源内容/类别、时间、身份、现实性、导入/活动资格 | source_ref、access_ref、ingress_receipt、待编码项；收到陈述不等于证实陈述内容 |
| C02 `prepare_encoding` | D06 编排；D03/D07/D04/D01/D05 提供各域候选 | 合法来源包、当时可知视角、固定角色快照 | 事件分段、痕迹、意义/体验引用候选及写集；无永久写入 |
| C03 `retrieve_or_associate` | D07/D08/D01/D05 等 → D06 | 问题/线索、类型化 trigger/causation、实体/事项、所需槽位、`as_known_at`/`valid_at`、探索模式、领域必查项、工作集引用、预算/停止语义 | EvidencePack、CandidateSet、路径、覆盖/缺口、费用、`continuation_receipt`、`stop_reason`/续接前沿；不产生实际回忆 |
| C04 `realize_recollection` | D07 选择；D06/D04/D02 联合；D11 提交 | SelectionTicket、重建/情感候选、资源回执和读集 | 唯一内部经历与当前体验的组合提交收据；重试不新增经历 |
| C05 `revise_or_consolidate` | 对应语义域接受；D06 编排存取 | 新依据、修订目标/类型、受影响来源及策略 | 当前解释/痕迹/投影候选、失效清单、领域重评事件；不自动写人格或信任 |
| C06 `prepare_expression` | D09/D08 → D06/D11 | 当前受众/用途、事实槽位、主观自述引用、行动意图 | 获准表达投影、完整依赖与最终投递 admission；不回写历史配合台词 |
| C07 `erase_memory` | D12 获准命令 → D06/D11/所有受影响域 | 目标、范围、授权与删除请求身份 | 立即逻辑屏蔽＋阶段化清理任务/回执，备份和外部范围分别报告 |
| C08 `inspect_or_transfer` | D12 → D06/领域所有者 | 审计视角或导入/导出预览、目的地与权限 | 可见诊断、快照清单或隔离导入批次；实验不污染真实经历 |
| C09 `schedule_memory_job` | D07/D10/D06 → D11 | 工作类型、优先级、费用申请、快照/前沿、恢复点 | durable job/lease、取消与消费回执；后台也受总预算 |

### B1. 对外的两个包

`MemoryEvidencePack` 包含 `pack_id, query_scope, coverage, slot_results, allowed_spans, interpretation_refs, obligation_receipts, contradictions, unavailable_slots, provenance_families, versions, access/deletion_epoch, index_watermark, cost, continuation`。覆盖不足与命题未知分开；一条文本包含关键词不能满足已验证事实槽位。

`CandidateSet` 是 D07 的输入：每项有片段/关联引用、触发原因、激活分解、相关关切、允许用途、预计展开成本。候选不自报“角色已经想起”。当前 `RecallPolicy.recall_experience` 只作为建议标志，不能代替 SelectionTicket，尤其不能因存在证据就在 `INSUFFICIENT` 终态创建经历。

**MEM-05 触发合同。** C03 的 `trigger.kind` 只能取 `explicit_past_request / unresolved_reference / correction_or_conflict / commitment_execution / repair_basis / time_or_activity_status / optional_association`，另带可审计的解析依据和 `trigger_policy_version`。前六类均为强制触发：D06 必须启动相应精确读取或返回其受限/资源失败，D07 不能以注意分数撤销它；是否进入人物注意仍由 D07 票据裁决。`optional_association` 只可用于获准的可选探索。无上述依据的普通问候产生 `no_history_search` 收据，不能伪装为 optional trigger；已有获准工作集的最小会话复核另记为 `working_set_only`。D08 的 RequiredCheck、D11 的权限/删除门和 final admission 不因任何 trigger 结果减少。

**MEM-07 续接合同。** 每个可比较 C03 回合写入 `continuation_receipt={policy_version, policy_scope, frontier_id, evidence_gain, latency_cost, call_cost, context_interference, weights, threshold, decision, missing_prerequisites, no_progress_count, budget_before_after, stop_reason}`。四项及 threshold 都是有限 `[0,1]`；权重非负且和为 1，`decision=continue` 仅在已通过预算/截止/权限/入口准入且加权净值严格大于阈值时合法。D11 提供真实延迟/调用费用报价和结算引用，D07 提供上下文干扰报价及焦点票据，D06 只计算声明范围内的证据收益。该回执随 job/attempt 持久化，恢复、重试或拆分不得重置其计数或余额。它只排序可选前沿：RequiredCheck、强制触发、权限/删除和 final admission 始终独立执行或明确失败，绝不允许负净值变成跳过或完成回执。

**MEM-04 兼容适配。** 旧 `RecallRequest` 的 `request_id` 进入 `causation_id` 和兼容关联键；trigger、gaps、required_checks、timeout/budget 分别映射为 C03 的触发/槽位/`RequiredCheck`、deadline/budget lease。旧状态依次映射为 D07 Concern（或一次性请求）→ RequiredCheck → `assemble_working_set` → C03 搜索 → EvidencePack 核查 → 带槽位的结果状态。持久恢复使用 C09 的 job/attempt/receipt，而不是持久化一个可绕开 D07/D11 的旧请求对象。适配器须保存旧到新字段映射、合同版本和停止原因，未知字段或无法保真映射返回 `rejected`/隔离，不能静默降级。

`RecollectionView` 包含 `recollection_id, activity_id, selection_ref, recalled_fragments, detail_statuses, then_interpretation_refs, now_interpretation_refs, feeling_experience_refs, self_understanding_refs, subjective_confidence, provenance_eligibility, actual_interval, commit_seq, expression_projection_ref`。片段资格/主观确信分列；回忆原因路径不是必须完整公开的自述。

### B2. 领域必查回执

D08 根据拟议行动声明 `RequiredCheck`，基础注册提供者为 D08（承诺/执行）、D05（明确边界）、D03（身份/视角）、D06（来源/撤销）、D11（权限/投递）；全模块收敛新增主动联系必需的 D10 `ContactPolicyCheck`，验证同意、静默、频率、无回应闸门和 contact 配额版本。提供者目录独立版本化扩展，不能由调用方删掉行动 schema 的必需项。返回 `provider, scope, examined_versions, result, missing_items, valid_until`；缺一个所需回执就不签发该行动资格。D06 负责统一预算和装配，不凭字符串匹配代替领域判断；多段 contact 的一次占用与逐段重验按 [公共合同 §3](../architecture/module-collaboration-contracts.md)。

## C. 一次实际回忆的完整顺序

1. **准入与选择。** D11 给父任务真实预算；D07 从合格候选选择片段，分配稳定 `activity_id`，生成 SelectionTicket，列目的、上下文版本、选择原因、预期活动区间和费用边界。冷却可拒绝重复内容，但同一窗口合法的第二次独立活动有新 ID。
2. **资源预留。** D02 按认知活动类别报价并返回带版本/到期时间的 reservation；D11 预留实际调用额度。无余额可延期或缩小活动，不伪造已投入体验。
3. **事务外准备。** D06 提出回忆重建，D07 产出解释选择候选，D04 产出当前感受/自我理解候选；每次模型调用先检查供应商处理权限并计费。所有候选绑定同一活动与冻结读集，不能互相把尚未提交的输出当作历史事实。
4. **闭包检查。** D11 合并各域声明的读写集、权限代际、资源票据和新键缺失版本。D06 校验来源/内容资格与内部活动身份；D04 校验数值/时间合同；D07 校验票据仍有效。跨域反馈在下一活动发生，联合数值块内部耦合由 D11 管理，不构造失效 DAG 的自环。
5. **一致提交。** 同一角色命名空间中，`Recollection/ExperienceRef + 本次采用的 D07 解释/选择版本 + D04 当前体验及必要自我理解版本 + D07 选择消费标记 + D02 本次实际角色成本结算 + contribution ledger + index/notification outbox` 一次生效。已有有效解释可只列读集；新增且被本次采用的解释必须包含在本次写集，禁止引用尚未提交的候选。D04 允许签发经过实际评价的无情感变化结果，回忆不必强制改变心情；这与评价服务没运行不同。被选定的细节可提取性更新若无需额外判断，作为声明的可选写集同时生效；缺席则由后续幂等任务处理，不是部分成功。延后的是一般化解释、长期信念/人格/关系修订和巩固，不延后本次回忆的必要引用。
6. **后续消费。** D01/D05/D08 消费 outbox 时按 `effect_id` 去重，读取仍有效的依据才提交自己的变化；任一消费者离线，通知保留待处理。D06 不等待所有消费者上线才承认已经发生的内部回忆，但依赖其未完成结果的行动不得假装已更新。

回忆状态只在第 5 步提交后称为已发生。第 3 步实际花掉的 CPU、token 与外部调用费用不因取消消失；D02 对确实已做的注意劳动可另作幂等费用结算，引用取消活动但不生成虚假的完成体验。未消费预留释放。提交中取消/超时先查相同 operation receipt：已提交就报告已提交并按新信息做修订，不擅自补偿性删除历史；未知则保持待核实，不能重发新 ID。

### C1. 实际内部活动与想象内容分开

`activity_execution = committed/internal` 与 `recalled_content_origin = observed/reported/authored/simulated/inferred/unknown` 是正交维度。实际想起虚构故事可以引发真实提交的感受，故事仍然虚构。

新 Recollection 是领域类型，不把模拟内容改成一个 `source_kind=internal` 的已观察事实。记录 `content_refs`（被回忆对象）和 `activity_basis_refs`（选择/执行凭据），两类引用都参与权限与删除闭包；外部事实证据资格沿 content_refs 传播，内部执行资格只由 D11 收据证明。当前 SourceRecord 的严格父链规则继续生效，不靠删父引用绕过它。

### C2. 跨角色与跨命名空间

第 5 步原子性只承诺同一命名空间的联合提交。跨角色获准分享通过导出受限引用/接收端导入事务及收据完成，不声称全局原子：任一失败可重试相同 transfer_id，复制出的来源资格不能扩宽。`TransferRef` 保存 origin_scope、源记录/版本、transfer_grant、源 access/deletion epochs 及接收者范围。接收端每次提取、模型外送、提交和投递 admission 都由 D11 统一门口同步核验全部来源域授权；本地共享撤权屏障把源撤权和这些准入串行排序，不能只查接收端代际。源端不可核验即 unavailable。异步通知只负责缓存/内容清理，不能作为授权仍有效的证明。

本版支持同一 D11 协调器可验证的跨命名空间引用；跨实例引用若不能提供上述同步源核验则拒绝在线使用，只能作为 D12 明示范围的静态导出处理，不能延用即时撤权保证。分享不自动成为双方共同经历，是否实际交流另由投递结果决定。

## D. 编码与更新的提交边界

C01 先提交 `SourceRecord + SourceAccess + ingress_receipt + pending_encoding/outbox`，即使模型暂不可用也不丢来源。C02 的来源组织与痕迹可以在后续事务生效，角色经历只引用当时确实提交的 D04/领域状态。当前回复如果依赖尚未完成的编码/评价，必须等待必要结果或缩小为已有依据支持的表达，不读取半成品。

C05 由语义所有者批准自己的候选写入，D06 负责来源/投影、依赖和贡献记录；当意义修订与其失效标记必须共同生效时由 D11 合并事务。被推翻的当前解释先逻辑失效，再后台重建，不能留一段“仍算有效直到重建完”的窗口。

经验贡献区分 `external_event_evidence / internal_recollection / interpretation_revision / simulated_trial / administrative_edit`。来源家族去重限制外部证据，活动 ID 去重限制实际内部次数，二者不能互换。D01 策略/人格、D05 关系、D08 承诺各有消费目标和贡献链；一次共同来源可影响不同目标，但每条贡献必须说明依据和用途许可。

## E. 并发读取、索引与缓存

当前源码的 namespace epoch 粗粒度变化会使长查询失效。完整实现选择：D11 提供有界一致读取快照、按查询域维护的 data/interpretation epochs，并单独维护即时 access/deletion epochs。读集验证命中项，域代际捕获新增但未命中的反证；不能只保留命中行版本。

按查询域的代际由 D11 索引/类型目录注册，至少覆盖类型、实体/事项和时间分区，无法准确归域时使用更宽的 epoch 而非漏失效。连续情绪更新不应无条件使无关来源查询失败；真正参与此回忆的感受快照则在完整读集中检查。迁移前继续使用现有严格 epoch，可以返回 stale/retry，但不得宣称高并发稳定吞吐。

本地模型提案、外部调用和长图遍历不持有 SQLite 写事务；快照读取和增量结果在最终提交/使用前重验证。来源更新与 outbox 原子发布；索引消费者按对象版本幂等追赶。若索引水位落后且无法在预算内补齐，返回 partial；必查责任依赖权威精确读取而不是向量水位。

缓存键包括请求域、用途/受众、策略版本、读集、查询域 epoch、访问/删除 epoch、跨域 TransferRef 授权集合与索引覆盖。撤权优先于重建；进程内缓存也在每次使用前复核本域和全部来源域资格，不能只等异步失效通知。权限分区索引先限制可访问候选，再回源验证；不要将全库私密候选送远程重排。

## F. 最终表达与撤权竞态

D06/D09 先生成 ExpressionProjection，清楚区分可陈述外部事实、可表达的主观印象、禁止的引用与无法回答的槽位。私人内容的抽象影响默认仍受源约束；只有具名、可审核的领域转换合同才允许输出一个不含敏感推断的新投影，不能一概认为“只输出心情就安全”。

D11 在最终 `delivery_admission` 事务中，原子核验投递意图依赖及当前权限/删除代际并签发一次性 dispatch 资格；同一协调器将撤权与 admission 串行排序。撤权先发生，则不再派发；admission 先发生，撤权尽力取消尚未交接的任务，但必须诚实报告在途边界。跨数据库与平台网络无法保证同一原子事务；已经交给平台或结果未知的内容不能声称被追回。

从 admission 到网络交接之间尽量短且支持取消，sender 必须通过此门口，不允许 D06/D09 直接发。发送后若需要纠正，由 D08 新建澄清行动；原发送结果与未知状态仍保留。为复核而读数据不产生第二次主观回忆。

## G. 删除、备份和类型迁移

C07 使用独立于可回滚业务备份的写前删除日志。D11 在统一准入屏障内分配单调 deletion_seq，把无原文的删除意图和恢复最低水位持久写入该日志，再在权威命名空间撤权、提升删除代际并记录同一序号。只有独立日志已耐久且权威屏蔽已确认才返回“删除已接受/逻辑屏蔽完成”；任一步未确认都返回 pending_confirmation，不返回成功。写前日志已有意图但业务库未提交时，准入门口先按意图挡读，恢复后幂等补做屏蔽。普通业务备份不能覆盖或回滚该日志与恢复水位。

所有消费者据删除屏障停止受影响的当前读出；随后遍历当前依赖、历史来源、联想理由与内容缓存。删除任务持久保存每一存储面的游标/回执，不靠一个全局 boolean 表示全部已完成。规模化删除可分批，屏蔽必须先于分批清理。

如果历史日志或幂等表包含规范化操作原文，也属于清理范围。仅允许留必要的非内容标识/不可逆校验用于防重放；哈希不被当作可公开文本，仍按元数据权限保护。D01/D04/D05 等对混合派生状态报告 `rebuilt/sanitized/reset/unavailable`，净化未完成不开放相关投影。

类型目录迁移是新增 trace/association/recollection 等类型前置条件：备份和目标 catalogue 校验、schema 版本门禁、事务化迁移/检查点、迁移失败回滚、再开库校验；旧进程不能同时写入新目录。当前 GraphStore 严格比较完整 registry 与已存 catalogue，直接增加类型再重开并不可行。迁移回滚仍遵守独立删除清单；原始旧数据副本保留不等于免于用户删除。

旧备份恢复先处于隔离模式，验证独立日志连续性和已确认删除的最新耐久恢复水位，清单必须覆盖该水位；仅能读取一个格式完整但新旧不明的清单不够。应用删除清单及最新权限后重建索引/派生内容；独立日志/水位丢失、被一并回滚或最新性无法证明时不开放服务。导入已知删除的源身份不能重新激活它；同文但身份未知的手工输入由显式导入审查处理，不承诺用内容哈希识别所有改写副本。

## H. 运行与宿主接线

D11 提供异步 memory coordinator，接收宿主入站/活动/时间事件，使用持久 job 表、共享预算和有界 worker；D07 控制人物注意，D11 控制真实执行容量，二者都通过才可运行。索引重建/巩固最低优先级但有公平份额，不能饿死前台或一直无进展。

后台作业包含 phase、input snapshot、frontier、used/reserved budget、activity/operation IDs、retry reason、deadline、cancellation epoch、`continuation`、`continuation_receipt`、`stop_reason`、`no_progress_count` 及每轮缺口/入口摘要；暂停后恢复不重置费用、不重复提交。一个非抢占数据库操作可能超出软截止时间；结果过时即拒绝使用，收据核查处理可能已提交的写入。

候选预算在 C03 中按通道记账：已获准工作集的复核有 0 次辅助生成预算；工作集外的每个实体/时间/词法、个人关联或语义通道最多产生 32 个初始候选，去重融合后最多 64，联想传播最多 2 跳/128 节点。精确责任读取另行分页，不被候选截断。辅助生成每父任务最多 2 次，失败/超时照实记账。D06 每个合格回合回传缺口是否减少和 MEM-07 续接回执；D07/D11 在连续两轮无减少、无入口、权限阻断、截止或预算耗尽时写入停止收据。可选前沿还须通过已版本化的“证据收益−延迟−调用费用−上下文干扰”判定；收益策略不可阻断 D08 必查、MEM-05 强制触发或 D11 准入。新版本化来源/反证、权限恢复或新前沿可重开；重试、过期结果和拆分子任务不得重置计数。

当前图的全图环检测和反向失效闭包可能随规模增加；D11 需增加增量循环验证、失效代际屏蔽/分批标记与真实规模测量，不能用 D06 的候选/跳数上限承诺底层事务恒定延迟。设计先保正确性，达不到响应预算就报告 deferred/partial，不将过期数据伪装为完整结果。

宿主切换条件：真正入口创建/注入 GraphStore、领域 registry、memory coordinator 与 domain check providers；入站来源、行动证据、最终 admission、回执与重启恢复形成一条实际路径。旧 fixture `Store → Engine` 可作为测试参考，不能与新图同时成为线上权威或作为退役旧核心回退。不得在只添加类型/类后宣称 AstrBot 已接入记忆。

## I. 联合场景：分享作品、等待、再理解

1. D10 或宿主提供真实作品/消息来源；D03 组织事件与对象；D01 的分享偏好、D05 关系、D07 期待成为版本化输入；D04 计算当时感受，D06 编码保存。
2. 未收到回复只形成观察缺口。D07 可保留多种解释，D04 可有失落；D08 没有资格据此声称用户已读或违约。
3. 后来线索触发 D06 联想，D07 选择活动 R1。D06 重建片段，D04 评价当前感受，D02/D11 计费；C04 原子提交本次回忆。即使网络模型重试十次，也只有一个 R1。
4. 同窗口另一次获准真实重温是 R2，可产生另一次当前体验；外部等待/消息仍是原事件，D05 不增加新的失约事实。
5. 新信息解释当时有急事，D07 更新归因，D06/D11 使错误当前解释与派生读出失效，D04 撤销旧责任驱动但不倒改过去失落；D01/D05 接收有去重身份的重评通知。
6. D09 可表达“后来明白了，但当时确实有些失落”，使用获准的真实体验和解释投影；D08/D11 决定是否以及何时发送。若受众换为群聊，私密解释链不随这句话自动公开。

## J. 合同版本与交付

本稿采用 `d06.contract.v1` 作为设计版本标识。实施注册时应发布确切 schema、写者表与兼容读取策略，字段移除或资格语义改变必须提升版本并迁移；未识别版本返回 rejected，不由模型猜字段。公共接口变更在主任务协调，模块实现不另造一套临时数据结构长期运行。

本文已给出 D06 所需的责任与失败语义；实现前仍需各提供方按合同实现并经过联合场景验收。那是实现完成条件，不是把本次设计留成未作出的选择。
