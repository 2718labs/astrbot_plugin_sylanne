# D05 关系协作合同 v1（设计）

日期：2026-09-23。配套 [主规格](05-relationships.md) 与 [验收](05-relationship-acceptance.md)。拟议 `d05.contract.v1`，遵循 [公共合同](../architecture/module-collaboration-contracts.md)、[D06](06-memory-contracts.md)、[D07](07-cognition-contracts.md) 及 [D08](08-execution-contracts.md)。

## A. 信封、身份和结果

采用公共 owner/module 写者、activity/effect/attempt/operation、parent budget、purpose/audience/provider policy、来源/现实性、完整读集与 query/access/deletion epochs、deadline 和 causation。增列 subject_entity/version、relationship_domain、dimension_schema_version、boundary_scope、contribution_kind/key、interpretation_refs 与 repair_revision。请求不能自由宣称对方的内心为权威数据。

同一 operation 改参数拒绝；技术重试不新增互动，重装配保留 activity/effect/贡献目标和累计成本。提供者不可用不假装“无边界”。结果为 `complete/partial/deferred/unavailable/stale/conflict/rejected/pending_confirmation`，含覆盖域、有效版本、费用、缺口、可用投影与恢复条件。敏感对象不存在/权限拒绝对普通调用方不泄漏差异。

## B. 操作目录

| ID / 操作 | 负责方与协作 | 输入 → 输出 | 必须保持 |
| --- | --- | --- | --- |
| C01 `resolve_relationship` | D05 → D03/D06 | 稳定对象/场景、合法历史范围 → 分域 Profile 或未知 | 有向且不按昵称合并，群体/成员分开 |
| C02 `evaluate_contribution` | D03/D04/D06/D07/D08/D10 → D05 | 实际材料、解释/感受与现实性 → 局部维度/期待候选 | 外部事件、内部回忆、模拟和编辑分型 |
| C03 `adopt_relationship_revision` | D05 → D11 | 候选、完整读集、贡献键 → 版本修订与 outbox | 与消费原子提交，不代写情绪/承诺 |
| C04 `declare_or_revise_boundary` | D03/D08/D12/本角色决定 → D05/D11 | 明确来源/声明方、行为/对象/范围、期限 → 新规则/冲突/失效通知 | 内部生效与对方知情分开，放宽需合法新依据 |
| C05 `provide_required_check` | D08/D06 → D05 | 行动类/对象/受众/时间、完整适用规则域 → pass/deny/conflict/unknown 回执 | 明确硬边界不可用好感抵消；可引用 D03 RoleBindingResolution 作情境输入，但覆盖不足不 pass |
| C06 `prepare_relationship_projection` | D07/D08/D09/D10/D12 → D05/D06 | 任务/用途/受众 → 信任/距离建议、可用维度/未知及依赖 | 主观立场不升级证据，披露意愿不授内容权限 |
| C07 `propose_or_update_repair` | D07/D08/D12/本角色 → D05 | 争议事项、责任解释、补救/回应依据 → 修复状态、意图建议/未解决项 | 修复提议不执行，未回复不造拒绝事实 |
| C08 `revise_interpretation` | D07/D03/D06 → D05/D11 | 更正/反证/身份映射/依赖 → 立即失效及重建任务 | 历史感受不倒改，旧错误不得继续当当前责任依据 |
| C09 `advance_or_archive` | D10/D11/获准 D12 → D05 | 有依据时间区间、规则和唤醒/归档条件 → 时间重评/调度状态 | 时间流逝不是新互动或自动不信任，归档不免责 |
| C10 `inspect_edit_erase_transfer` | D12 → D05/D06/D11 | 诊断/配置/删除/迁移 → 有范围投影、预览与回执 | 不造共同经历；删除闭包及恢复水位有效 |

## C. 维度与贡献语义

`DimensionEstimate` 含 name/domain/context、estimate 或 unknown、subjective_conviction、evidence_coverage、support/counter_refs、independent_families、interpretation_version、prior_origin、valid_time 和 applicable_effects。内部确信再强也不改变 D06 来源资格。新增维度需要 D12 配置与 D11 schema 版本迁移，不能由模型任意生成不可解释变量。

外部贡献键为 `owner, canonical_event/source_family, subject, target_dimension, contribution_semantics`；补充证据更新同一贡献的 revision，不能换算子版本再消费。不同独立事件可各有贡献，独立性未知不增加样本数。来源家族由 D06 管，事件身份由 D03 管；不能用去重哈希替代语义身份。

回忆贡献键使用 committed recollection activity 与目标维度，同时保留原 content source family。真实回忆能影响她当前亲近/戒备，但外部行为计数从原事件集合读取，不从活动次数累加。重评同一回忆贡献是 revision，不新经历。模拟产生的当前真实体验可用于她自己的舒适/披露意愿，不能作为对方做过某事的材料。

bounded_delta 按每维/贡献类型的合法配置裁剪，同时核对该来源家族当前总影响和累计漂移阈值。达到阈值返回需要复评/停止更新，不能拆分新 target 名绕过；已登记维度 schema 控制目标集合。此机制约束无止境放大，不宣称心理学定律，也不阻止有独立重大依据的显著变化。

## D. 边界和行动资格

`BoundaryRule` 区分 runtime policy 引用、对方明确要求、本角色内部规则、双方已沟通约定、inferred preference。规则包含谁限制谁、行为类、受众/场景、valid interval、exception 条件、source/communicated/acknowledged refs、修订主体及 scope version。未知不填默认允许；不适用须有明确范围排除理由。

C05 输出 `provider=d05, scope, examined_versions, query_epoch, result, missing_items, valid_until`，与 D08 RequiredCheck 同形。提供方从权威边界索引/精确数据读取，检查新增规则的查询域 epoch；向量相似查询不作全覆盖证明。D11 final admission 再验版本/源权限，不能只相信生成草稿时的 pass。

需要社会角色语义时，D05 经 D06 请求 D03 `RoleBindingResolution`，并把其 binding/norm/read-set 版本列为情境依赖；D05 不持久复制绑定。无绑定、回执冲突/过期、规范未知或覆盖不足时，C05 仍按自身边界域返回 unknown/conflict/适用结果，绝不从“角色应当如此”推导新的 BoundaryRule 或 pass。

本角色内部边界可限制自己的新行动；若声称对方违反已知边界，则需其知情/约定依据及具体行为来源。对方 “暂时不要联系” 一旦成为合法明确规则，修复邀请、换频道追问和通过其他角色代发同样按规则范围检查，不能伪装内部活动绕过。规则含例外则需满足具名例外条件，不由模型自由扩大。

规则冲突返回 conflict，D08 选择求证/等待等合法行动。更宽许可不能静默覆盖范围更窄的有效禁止；修订者权限、明确意图和版本链决定是否替代。与 D11 运行权限冲突时以其限制为硬上界。

## E. 修复、错误解释与提交

RepairProcess 的 dispute_id 锚定事项；不同事项可并存，一个事项的成功不能结清全部关系。提议、实际传达、对方回应、实践完成、维度重评分别带收据/来源。D08 拥有承诺与补救结果，D05 不自行把 apology_delivered 等同 fulfilled 或 repaired。D04 拥有残留感受；D05 不提交情绪清零候选。

C03 事务采用受影响维度、边界/修复版本、合法引用、贡献记录与 outbox；需要新的 D07/D04 活动时先完成对应联合提交，再引用其收据。组合提交只限同一 owner，不保证不同角色对同一关系同时改变。跨角色交流看实际投递与获准 transfer，不把 A 的想法写进 B。

C08 先在 D11 屏障标记受影响当前投影/待发资格失效，再异步重建。重建用有效检查点和现存合法贡献，不简单减去旧 delta：历史有非线性裁剪、不同上下文和后续依赖。状态分别报 rebuilt/sanitized/reset/unavailable。历史真实伤心可以留在 D04/D06，不能继续证明被推翻的恶意归因。

默认每事项一个未决主动修复邀请，唯一键为 owner/dispute/action-kind；传达未知占用该位置直至核查。明确回应、新接触许可或实质新证据可以触发重新评估，不以超时自动创建新邀请。正常来信回应仍走当前边界与 D08 资格，不受不适用的主动邀请冷却误阻。

## F. 时间、预算和恢复

时间推进只影响有明确定义的当前有效性、熟悉度或等待条件。按事件时间/获知时间/当前时间分别查询；断线不造关系事件。D11 持久任务和原子水位订阅提供唤醒，D05 只注册条件。归档保留权威边界及 D08 未完成责任的可查询性，不将其藏到 RequiredCheck 无法访问的区域。

父任务共享预算；8 维/16 家族/2 辅助调用为有限初始值，涉及必查边界不以这些候选上限截断权威检查。不能在预算不足时静默舍弃反证；返回 partial/deferred，外部行动仍缺资格。取消记录实际劳动/调用消费，重新装配不退费用或重复记互动。

重启先应用 D06 删除/访问水位，再加载关系图、贡献和未决修复，核实原提交，再恢复通知/调度。旧进程不得写新 schema。对象身份映射事务核对影响范围，冲突维度保持争议，去重键采用规范映射并保留历史别名，避免合并后同一经历被重复结算。

## G. 隐私、删除与产品访问

关系投影含全部内容与成因引用，包括在界面隐藏的支持来源；每次外送/采用/投递同步验全部源授权。不能仅删除用户可见名字就认为已经脱敏。诊断和角色自述分开，行政编辑不成为对方真实认可的证据。

删除日志/恢复水位完全复用 D06，不另造关系删除账。清理涵盖冲突原因、维度、边界来源、修复草稿、交互模式、缓存/操作原文；剩余元数据只作必要防重放/访问限制且不可还原被删内容。若有独立的显式联系配置，它的来源与保留授权必须原先独立存在，不能在删除时把原文偷偷转换成“新设置”。无合法独立设置则边界资格 unavailable，不自动放宽或恢复主动联系。

D12 更正/删除/迁移先预览对象与影响范围；明确授权的用户操作直接执行对应命令，不凭技能添加重复审批。复制/导入关系不生成新的共同史，接收角色的自我定位和对方确认分开；隔离实验永不调用真实发送通道。当前版本兼容由 D11 类型目录迁移注册，未知 schema 明确拒绝。
