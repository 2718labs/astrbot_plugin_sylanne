# D10 协作合同 v1（设计）

日期：2026-09-23。配套 [主规格](10-life-proactivity.md)、[验收方案](10-life-acceptance.md)。沿用 [公共合同](../architecture/module-collaboration-contracts.md)、D06/D07 的活动身份、写者/来源/预算/删除规则。所有命名是待实现规格。

## A. 信封与共同资格

每个命令携 schema、owner、issuer、activity/effect/attempt/operation、parent_task/call、project/recipe/version/step/occurrence refs、D08 intent/RequiredCheck refs、time mapping、purpose/audience/provider policy、reality、完整读集与正负查询域、access/deletion/policy/cancel epochs、预算和单调截止。元数据本身按来源权限处理。

purpose 按实际操作选 context/consolidation/expression/audit，各用途分别检查；把活动内容交外部模型也先核验供应商政策。现实性必填，不因写在 LifeProject 中而自动视作现实。返回 complete/partial/deferred/unavailable/stale/conflict/rejected/pending_confirmation，明确真实完成、模拟推进、已用成本、未知范围、恢复点与下次条件。

## B. 操作目录

| ID / 操作 | 发起与提供者 | 输入 → 输出 | 强制边界 |
| --- | --- | --- | --- |
| C01 `propose_life_project` | D01/D07/D12 → D10/D08 | 偏好/邀请/实际线索 → 项目候选、D08 目标提案 | D10 不创建已承诺目标 |
| C02 `plan_activity_step` | D10 → D08/D07/D02/D11 | recipe、进展、资源/时机 → 获准步骤或缺口 | 具体行动意图与资源匹配才执行 |
| C03 `execute_activity_step` | D08 意图 → D11/所属活动域 | 有界步骤及全部资格 → 实际执行/领域活动回执 | 工具由 D11，认知/回忆复用 D07/D06 唯一活动 |
| C04 `adopt_life_progress` | D10 联合 D08/D06/D02 → D11 | 真回执、产物、候选进展 → checkpoint/实际区间/引用 | 目标结果由 D08；不重复经历或费用 |
| C05 `register_schedule_or_habit` | D10/D12 → D11，D01 策略 | 时区/规则/策略及授权 → durable occurrence 规则 | 日程不等于实际执行，习惯人格属 D01 |
| C06 `advance_permitted_interval` | D11 恢复 → D10/D02/相关域 | 合格模拟/连续区间、参数与 checkpoint → 有误差边界的推进候选/未处理范围 | 不补造停机认知、工具、社交或作品 |
| C07 `offer_proactive_opportunity` | D10 → D08 | 内容来源、对象、窗口、同意/静默/配额 → 行动候选或延期/过期 | 机会绝非发送许可 |
| C08 `claim_contact_window` | D08/D09 → D11/D10/D05 | contact_id/有限段资格、ContactPolicyCheck、当前意图/表达/来源 → 原子 admission 配额回执 | 逐段重验，按 contact 一次占额；任一段交接/unknown 不释放 |
| C09 `pause_resume_retire` | D08/D02/用户输入 → D10/D11 | 活动/项目状态与新条件 → 暂停/重装配/归档 | 归档不解除承诺，未知执行先核实 |
| C10 `revise_erase_inspect` | D06/D12 → D10/各所有者 | 修订/删除/配置/迁移命令 → 屏蔽、版本回执或隔离预览 | 最新删除水位先验，不编辑他域真值 |

## C. 领域对象约束

`LifeProject`：project_id、owner、topic/reality、D01 preference refs、D08 goal/plan refs、artifact versions、milestones、next_step、blocking reason、schedule refs、source/permission closure。关闭项目只关闭 D10 组织状态；若仍有 D08 承诺必须显示未解除并由 D08 处理。

`ActivityRecipe`：version、allowed step types、intent scope、inputs/outputs、world_kind、resource classes、tool allowlist、yield boundary、progress predicate、stop/wake、offline eligibility、time mapping、error/interval bounds。产物存在与进展由外部回执/领域已采用结果验证，不接受自由文本“我做完了”。

`LifeCheckpoint`：step seq、completed effect refs、accepted artifact versions、pending result refs、actual interval union、role time cursor、已耗/预留费用、recipe/policy/read versions、cancel generation、next wake。实际劳动、技术调用和模拟区间分型；它不保存可以独立改写 D07 感受/认知的旁路状态。

`ProactiveOpportunity`：stable cause/project milestone + target + category 去重键，合法内容、意义、窗口/expiry、consent refs、D05 boundaries、D08 goal/action candidates、RequiredCheck、配额策略版本、no_response gate。内容换措辞或重试不创建新普通联系机会。

`ContactPolicyCheck`：contact_id、stable target/channel/category、consent scope/version、quiet window/version、quota policy/ledger version、对象无回应闸门版本、D05 boundary refs、audience version、允许的 D08 有限段清单/子资格、有效期与完整源权限读集。D10 签语义政策回执，D11 C08 显式核验并原子消费/登记 quota 账；回执不是可无限重用的发送许可。

## D. 活动采用与副作用顺序

1. D10 候选提交 D08 选择具体步骤；D07 注意与 D02/D11 预留同当前快照匹配。计划批准不能替代后续每一步的工具权限与参数检查。
2. D11 注册稳定活动/步骤执行 claim；实际调用事务外发生。D07/D06 执行认知/回忆时使用自身唯一组合提交，D10 消费其回执。纯技术文件检查不制造人物体验。
3. 新的 D10 自有模拟或非认知活动，D11 原子提交 `ActivityInstance/checkpoint + D10 project progress + 必要 D08 step/domain-result candidate + D06 真实/模拟经历引用 + 必要 D04 输出 + D02 分项实际结算 + contribution ledger + outbox`。D08 的外部结果只能来自真实执行回执；D04 可验证无变化或明确不依赖，不以服务失败冒充无变化。
4. 消费已提交 D07/D06 活动时，仅更新 D10 项目进度/D08 步骤结果及引用，使用同 effect 的 contribution 去重，不再新建同一次经历或扣同笔劳动。若项目与已采用活动暂未关联成功，回执保留待关联；重复消费最终补齐，不重新执行。
5. 真工具调用仍走 D08 qualified intent→D11 final admission→外部执行→D11 receipt→D08 结果。D10 不把数据库项目完成事务与不可回滚外部写入伪装为一笔全局事务。unknown 始终保存 pending result 并先核实。

若新的项目进展依赖新作品，artifact 必须先以耐久 staging 保存并获得实际存在性/完整性回执；事务采用引用后才能发布进度。崩溃留下未采用 staging 为受权限/删除管理的孤儿清理对象，不能成为作品履历。作品外部发布是另一个行动，不由 staging 自动执行。

## E. 日程与离线推进

D11 持久发生序号/occurrence，键绑定 schedule version、规则实例和有效时刻；时区更新不复用已发 ID。订阅注册与事件水位原子核对，避免刚好错过唤醒。错过默认合并为一项仍有意义的续作，明确提醒依 D08 承诺决定到期动作，不能重启洪泛。

D08 DeadlineSpec 保存已协商的时区/instant 或明确 floating 规则；D10 浮动日程调整不能改变其绑定承诺的期限。宿主换时区仅影响明定浮动规则的未来排程，冲突返回待 D08 协商的新计划版本，不自动按新宿主时间改约。

离线推进仅接收具有 offline eligibility 的 recipe/连续块，冻结 [cursor,target) 参数、时间映射与取消/来源版本。遇到新选择/外界/权限边界截断，输出 processed_intervals、remaining_intervals、error certificate、checkpoint；误差不合格不提交。采用 CAS 游标/区间覆盖去重，不能重复积分或跨过未处理间隙。

角色模拟标记与历史事实不会因计算确认而升级；允许补算的角色事件时间与本次实际计算/获知时间分别存。真实停机认知没有回执就保持未发生，产物没有实际字节/领域采纳就保持未产生。

## F. 主动联系准入

C07 输出合格机会仍只是 D08 的候选。D08 确认 communication_action/contact_id 和不可变有限 segment_id/segment_effect/载荷摘要清单的批授权或限定子资格，D09 生成合格表达；D11 C08 显式同步核验 ContactPolicyCheck、quota/对象无回应闸门版本、对象/来源、当前同意类别/时段、D05 边界、静默、D08 RequiredCheck、受众/平台限制及全部删除/访问代际。每个后续段均重验当前条件，不能沿用已过期首段回执。

D11 在同一 admission 事务内登记当前 segment_effect 的独立 dispatch、contact_id 的一次配额占用和耐久 outbox claim，避免两个机会并发穿透计数；不是 C07 创建时就永久扣额度。段重试不重复占联系额度；任一段交接或 unknown 都不能释放，只有零段交接且全部已声明段可证明未执行才释放。真实平台接受只表示发送，不更新“对方想聊”。删除/撤销同意提升代际并阻断未 admission 的段；已交接不可保证追回。扩段超授权清单或预算必须经 D08 新决策，换 contact_id 不解除对象闸门。

普通分享的无回应闸门由 D03 已观察到的相关回应或明确解除该限制的授权变化解除，模型猜测“应该有空了”不能解除。机会 expiry 仅清候选，已交接/unknown 的对象闸门继续；新里程碑、新项目或新 contact_id 不能绕过。用户请求提醒独立授权仍受平台总额度和预算，过期由 D08 决定如何说明；不能把普通分享改标签为提醒绕闸门。

闸门保存 originating contact_id 与原有限分段授权版本。该 contact 原清单内仍有必要的后段可在逐段现行资格有效时继续，不被首段形成的闸门误杀；换 contact、扩清单或新决策产生的新段不继承这项例外。用户明确停止、撤同意或当前静默仍优先阻断，前段 unknown 时遵守 D09 段间依赖暂停。

## G. 故障与删除恢复

| 条件 | 处理 | 不允许 |
| --- | --- | --- |
| 没有可推进步骤/新机会 | 记录下一条件，保持静默不调用模型 | 为显得活着随机造日记 |
| 资源不足、休息需求或硬前台抢占 | 有界暂停、释放未用额、持久 checkpoint | 把延期说成完成或占住所有焦点 |
| 版本/方法/来源变化 | 先屏蔽受影响候选，核实旧执行后重装配 | 用旧 artifact/权限继续分享 |
| 真实执行或采用结果未知 | 原 call/operation 核实 | 新 ID 重放潜在副作用 |
| 模拟误差/映射失效 | 停留最后有效游标，返回未处理区间 | 接受数值失败再补台词 |
| 同意/静默策略变更 | 取消未准入机会，刷新当前限制 | 亲密度或心情豁免硬边界 |
| 删除/旧备份恢复 | D06 日志屏蔽所有活动/产物派生后恢复 | 履历、标题或外发队列复活删除源 |
| 不兼容方法/项目导入 | 隔离并报告具体损失/缺字段 | 猜测补齐真实经历和费用 |

最新删除日志不可被业务备份回滚。必要审计保留无内容收据，普通角色读取不获得敏感存在性。清理未完成的内容与进度投影不服务；外部副本仅按可核实能力处理。

## H. 提供者接受与演进

D01 策略、D02 报价/恢复、D03 时钟/现实性、D04 体验、D05 联系边界、D06 来源与删除、D07 注意/活动、D08 意图/目标结果、D09 表达、D11 调度/执行、D12 配置共同通过联合场景后才可启用相应生活能力。缺失能力按 recipe 局部禁用或延期；不得以退役 fixture 模拟全功能。版本升级须预览日程、checkpoint 和产物迁移，保留真实历史并执行最新删除闭包。
