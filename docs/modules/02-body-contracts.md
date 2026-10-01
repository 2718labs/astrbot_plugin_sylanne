# D02 身体与需求操作合同 v1

日期：2026-09-23。设计合同 `d02.contract.v1`；配套 [主规格](02-body-needs.md)、[验收](02-body-acceptance.md)，遵循 [全系统公共合同](../architecture/module-collaboration-contracts.md)。类型名为拟实施 schema，不是当前 API。

## A. 通用信封与所有权

继承 D06/D07 的 schema、owner_scope、issuer、activity/effect/attempt/operation、parent_task、purpose/audience/provider_policy、read_versions、查询/访问/删除 epochs、policy_version、budget_lease、deadline、causation。追加 `body_profile_version, body_cursor, clock_mapping_version, work_kind, reservation_refs, component_refs`。读取图中的精力余额不能代替预留资格。

同 attempt 重传保持 operation 和载荷摘要；变参数拒绝。新 attempt 先核实旧收据，保留 activity/effect、已发生组件、父预算和时间片段身份。D02 仅签候选，D11 负责提交序列、唯一约束、组合提交及 outbox；Owner 与模块写者分离。用途沿用 context/expression/consolidation/audit，跨用途分别验证。

返回 `complete/partial/deferred/unavailable/stale/conflict/rejected/pending_confirmation`，附覆盖区间、实际消费、保留额度、有效版本、缺口和下一步。响应必须说明是报价完成、推进完成还是结算完成；任何 complete 都不等于角色某个目标实现。普通调用方不获悉被拒绝私密对象是否存在。

## B. 操作目录

| ID / 操作 | 请求者与输入 | 输出和不变式 |
| --- | --- | --- |
| C01 `read_body` | D01/D04/D07/D08/D09/D10/D12：用途、视角、所需轴/区间 | BodyProjection、可知范围/版本/覆盖；精确诊断值与角色感知分开 |
| C02 `quote_work` | 各活动域：组件、时间上界、通道、恢复条件、当前版本 | BodyQuote、各项最坏消耗及有效期；不扣数值、不发生体验 |
| C03 `reserve_work` | D07/D08/D10 联合 D11：quote、父租约、主焦点/执行票据 | 原子 reservation 与可用余额占用；无任一资格不占用其他域资源 |
| C04 `settle_components` | D11 凭领域合法劳动：唯一组件、实际片段、原预留 | 分项 BodySettlement/新 BodyState/剩余额度；取消与最终完成共用去重账 |
| C05 `release_or_cancel` | D11/D08：活动、取消代际、已知执行状态 | 释放未用额度、已用回执或待核实；不撤销实际发生过的劳动 |
| C06 `advance_body` | D10/D11：时间映射、起止、合法驱动/参数边界 | 新游标、身体/需求候选、误差证据、partial 续点；无依据不生成生活 |
| C07 `apply_need_effect` | D10/D04/D08 等：合法结果、需求轴、effect 和贡献依据 | 限幅去重的满足/负荷候选及理由；不能把预期效果当已实现 |
| C08 `revise_or_erase` | D03/D06/D12 经 D11：修正/删除/身份变化及闭包 | 即时屏蔽、重算或隔离/重建清单；删除遵守 D06 独立日志 |
| C09 `configure_or_transfer` | 获准 D12：新配置、预览/导入范围、版本和来源 | 校验/迁移预览或 administrative_edit 收据；实验/正式隔离 |

## C. 核心数据与资源守恒

`BodyQuote` 至少包含引用的 BodyState/Profile、activity、work_kind、成本表版本、`fixed_components[]`、`duration_components[]`、各组件上界、起止/通道约束、最低起始条件、valid_until。固定和持续项的 cost_component 不能重复覆盖同一成本类别，D02 注册的策略必须能机械判别覆盖冲突。

`BodyReservation` 包含 reservation_id、quote 摘要、effect、父租约、最坏上界、已消费、未用、待核实、过期时间、取消代际、状态。对每个可扣减余额区分 gross E、encumbered、available 和 shortfall：encumbered 是尚未消费且仍有效/待核实的承诺上界之和，`available=max(0,E-encumbered)`，`shortfall=max(0,encumbered-E)`。shortfall>0 显式返回 reservation_shortfall，阻断新片段；它不同于已经发生支出的 overrun。报价不改数值；预留只改承诺，结算同步减少实际余额和对应剩余承诺，释放不增加实际余额。未来恢复不能先借成当前余额，未知收据预留不能为消除 shortfall 而提前释放。

`BodySettlement` 包含稳定组件键、来源回执、actual_interval、time_mapping、扣减/驱动分项、前后版本、已采用/已核实状态。D11 的费用 call_id 可与其关联，但实际计算费用和身体扣量没有固定换算率。D11 重传/查询数据库等技术工作不自动生成 BodySettlement。角色体验只有 D06 的合法内部经历路径可创建。

连续劳动在积分器中的率是实际结算的身体效果；预留上界必须包住其最大可能精力下降及执行窗口中已经获准的背景净下降，结算同时记该下降及对应消耗承诺，不再额外扣同一份 E。未核实劳动区间阻断确定身体游标，不能先按空闲恢复后再补扣。连续恢复使 E 上升不返还已用贡献，也不复活已经释放的旧预留。新的驱动/参数或恢复条件变化先使未开始的片段报价失效并释放/重报，再推进可能影响余额的变化；进行中或结果未知的组件保持未核实承诺。状态修正后 shortfall>0 进入 reservation_shortfall 并暂停追加劳动，不能让旧 quote 成为透支权；若核实证明超支已经发生才进入 E 节 overrun。两种异常都保留 gross E 与承诺差额，不隐藏为普通零余额，也不虚构恢复。

## D. 与认知、回忆和生活的联合提交

普通认知采用 D07 C04，实际回忆采用 D06 C04。D02 输出未结算组件写集，协调器验证既有 BodySettlement 和预留版本，然后把剩余身体结算与活动/选择/必要感受/经历/outbox 一起提交。不得另发一笔完整费用或第二个已发生经历。单纯取消没有新认知采用时，也可由 D11 提交已发生组件和释放，不伪装活动成功。

生活活动由 D08 合格意图和 D10 执行记录提供实际片段，D03 标注现实性；恢复效果和需求满足在其相应领域结果结算事务中一并采用，D02 的成功不是整个生活活动成功。若活动是明确的角色模拟，模拟内部活动可以真实发生，外部物理效果不得升级成真实测量。

每个时间通道先由 D11 分配唯一片段。D02 在 quote 内列允许并行的通道及整体上界；同角色同通道区间采用并集而非模块报告相加。同一 segment 的多个来源视图仍是同一劳动。主焦点重叠拒绝冲突，合法并行分项以各自通道身份结算；恢复与高负荷活动是否共存由事先的速率表决定，不由后来的台词解释。

## E. 取消、到期、超额和不确定结果

未启动且可证明无消费时释放；已知消费先结算再释放；正在执行/结果未知保留该组件上界并标 pending_confirmation。过期后拒绝新组件，迟到原组件仅可在原归属/预算内核实。未知结果不能创建新 effect 重做或用新预留掩盖旧消费。

上界不够时，在下一个可停止边界拒绝追加。不可取消计算仍由 D11 记录真实成本；角色劳动的长度/作用由原获准片段边界确定，不因工具晚返而无限延长。若发现已发生角色劳动确实超出声明上界，overrun 进入核实/修复：阻断新支出，保留精确待结算负债单独项，身体可用量视为零，不能写负 E、丢弃支出或伪造一个恢复事件抵销。D12 诊断可见原因，正常投影只说明资源不可用。

## F. 时间、数值及反馈合同

`advance_body` 需证明 from 等于已提交游标、区间及驱动/参数历史覆盖完整、映射不倒退。时间语义唯一分工：D03 解析外部/日历区间、时区与精度，D10 提角色生活政策/推进候选，D11 唯一登记/签发 CharacterClockMapping 与实际片段；D02 不接受任何域另发的生活倍率或时间游标凭证。分段常率更新采用主规格 §4 公式；数值校验拒绝非有限参数、负速率、负 dt、越界初值和未知算子。向前区间和身体游标、已用驱动贡献、状态版本同事务提交；重复请求返回旧回执。

解析区间没有独立“每 tick”刺激，切段由输入/参数/时间映射和参数版本固定的节律网格边界造成。网格与请求划分无关，同区间分批计算必须使用相同速率。D04–D02 反馈默认读取上一已提交快照；需要即时联合耦合必须获得 D11 注册数值块，不能自行加持久化依赖环。算法误差、输入覆盖不足和时间缺口分别报告，不都写成身体状态未知。

离线缺少实际活动时可推进配置允许的被动动力，不能发布“休息过/做梦过”经历。旧来源修正后的重算不发新的活动满足贡献。重算失败时受影响投影保持 unavailable；历史动作引用原版，避免“现在重算了所以当时没有累”的倒写。

## G. 删除、隐私、配置与版本

来源授权在候选准备、提交、表达采用与最后投递同步核验。跨角色投影沿 D06 TransferRef 机制，撤销不能依靠异步通知的速度。D02 不导出敏感成因来换取通用“压力标签”；受限聚合也参加完整引用闭包。

删除请求由 D06/D11 独立写前日志先持久化并屏蔽当前读取。D02 清理 BodyProjection、NeedContribution、WorkSegment 内容、历史快照、作业、缓存、诊断、导入及其派生；最小无内容结算键保留去重，不能作为绕过屏蔽的查询索引。无法证明删除影响已经移除的聚合值隔离并按主规格重建。恢复从最新删除水位验证，不导入旧租约或释放凭证复用。

配置编辑有预览和版本边界；改变轴语义或删轴不能直接沿用旧值，应提供可验证迁移或显式重新初始化。新版本未知返回 rejected。合同升级由总装协调，不能用旧 fixture 的 energy_delta 假充完整兼容。全部运行与语义场景见验收方案，本轮仅设计审查。
