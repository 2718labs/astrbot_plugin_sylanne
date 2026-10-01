# D01 协作合同 v1（设计）

配套[完整补充](01-persona-completion.md)及[验收](01-persona-acceptance.md)。采用 `d01.contract.v1`；共用 [D06 A](06-memory-contracts.md) 信封和[全系统合同](../architecture/module-collaboration-contracts.md)，不是当前可调用 API。

## A. 公共语义

每项包含 owner、schema/writer、activity/effect/attempt/operation、purpose/audience/provider_policy、完整正负读集、来源家族与现实性、data/access/deletion epochs、policy_version、父预算/截止时间、源发生/获知/有效时间。D01 特有 `persona_head, target_blocks, plasticity_policy, continuity_anchor, growth_proposal_ref`。非相关字段显式空，最终提交身份由 D11 签发。

返回 complete/partial/deferred/unavailable/stale/conflict/rejected/pending_confirmation，带完成范围、成本、覆盖、缺口与续接条件。complete 不是“人格客观正确”；敏感来源不存在与权限拒绝不向普通调用方区分。模型只提案，D01 唯一接受人格语义，D11 验证写者与事务。

## B. 操作目录

| ID | 发起 → 负责方 | 输入 → 输出 | 必须满足 |
| --- | --- | --- | --- |
| C01 initialize_or_migrate | D12 → D01/D11 | 方案/差异/可塑性 → 预览或新版本 | authored 与成长区分；运行身份不可自然改变 |
| C02 project_persona | D04/D07/D08/D09 → D01/D06 | 情境/目的/受众 → PersonaView | 源权限和有效性闭包；社会角色策略经 D06 装配 D03 `RoleBindingResolution`，缺失不填默认人格 |
| C03 evaluate_values | D08/D07 → D01 | 冻结候选/价值视图 → 偏序/冲突/缺口 | 不压成无理由总分，不签行动资格 |
| C04 propose_growth | D07/D10/领域结果 → D01 | 问题/来源家族/局部差异 → 提案/核查需求 | 重复反思不是新来源，反例必须查 |
| C05 request_trial | D01 → D08/D10 | 有限策略/作用域/观察判据 → 计划引用/结果 | D08 才能批准执行，未知结果不计成功 |
| C06 activate_revision | D01 → D11 | 当前头/证据/试用/连续性/消费 → 新版本收据 | CAS + 状态/ledger/头/通知同事务 |
| C07 revise_or_erase | D03/D06/D12 → D01/D11 | 更正/删除屏障 → 阻断/重建/净化回执 | 删除优先，失效观点不作为有效回退 |
| C08 inspect_or_export | D12 → D01/D06 | 合法视角/范围/目的地 → 受限投影/清单 | transfer 源权复核；诊断不注入角色 |

## C. 必需类型与采用边界

`PersonaPlan` 指明字段语义、未知值、可塑性、只读规则和来源；`PersonaRevision` 包含局部差异、旧头、支持/反例、家族独立性、连续性记录和生效范围；`GrowthContribution` 键为 owner/family/target/change_kind，修订替换值；`AutobiographyProjection` 的 canonical ID/语义由 D01 签署，D06 存取不另建可写解释。

成长内部反思若实际发生走 D07 C04 联合认知事务；D01 C06 只是采用后续人格修订，不再创建同次思考经历。若采用需要新 D04/D07 结果，先使用其已提交引用，或 D11 组合必要写集，禁止悬空新引用。策略实际劳动费用以 call/component 补差，不能完成时重复扣报价。

C06 必须检查当前激活头、每个写键含新键缺失版本、人格政策、完整证据与反例域、权限/删除、预算/租约。失效依赖仅声明长期支撑；活动租约/焦点/旧头属于前置读集，历史人格快照属成因引用，均参加删除闭包。

`RoleBindingResolution` 仅可作为 C02 的情境策略输入：请求显式携带主体、目标/群体/场景、行动类别和 purpose，回执读集含 binding/norm/身份映射/可见性版本及 `valid_until`。D01 不缓存或写入社会角色库；回执为 no_applicable_binding、partial/unavailable/conflict/stale 或规范未知时，只输出不依赖该结论的 PersonaView，并将社会角色策略标为未知。它不替代 D05 边界、D08 RequiredCheck 或 D11 权限。

## D. 失败、跨域与迁移

未知提交先查相同收据；已生效返回原结果，新 attempt 保留贡献与预算。任一必要校验失败整笔不生效。必需反例没完成延后，不把模型确信当补偿。最新人格已部分失效时可输出未受影响字段及缺口，不能输出整份旧视图。

跨域共享遵循 D06 transfer：每次内部使用、模型外送、提交和投递同步核验源授权；源不可核实返回 unavailable。D09 文本只读受限投影；D08/D11 最终投递再验。成长导致现有承诺冲突只提出重评，D08 决定合法履行/改约，D01 不删承诺。

删除清理所有含内容副本和作业中间态；独立 deletion journal 与恢复低水位由 D11 提供，D01 各存储面报告 rebuilt/sanitized/reset/unavailable，不自报全域已清完。注册升级在 D11 catalogue 迁移后启用，未知 schema 拒绝，禁止旧进程双写。计划迁移与自然成长均保留审计差异，但审计历史服从删除。
