# D04 协作合同 v1（设计）

配套[完整补充](04-emotion-completion.md)、[原稿](04-emotion.md)与[验收](04-emotion-acceptance.md)。`d04.contract.v1` 不是现有代码 API；遵循[全系统合同](../architecture/module-collaboration-contracts.md)及 D06/D07 已有组合提交合同。

## A. 信封与结果

沿用 D06 A 的 schema/owner/writer、activity/effect/attempt/operation、purpose/audience/provider_policy、完整读集/查询域/权限/删除代际、父预算、截止时间与现实性。另有 affect_process/meaning/basis/parameter refs、source_family、contribution_key、time_mapping、from/to cursor、causal_root/meta_depth、requested_tolerances、numeric_certificate refs。actual commit_seq 仅 D11 填写。

结果 complete/partial/deferred/unavailable/stale/conflict/rejected/pending_confirmation，包含覆盖的对象/区间、实际费用、误差、未推进区间及续接条件。无感受变化须经过实际有效评价或纯确定推进，不能冒充服务缺失；合法多种感受不要求汇成单标签。

## B. 操作目录

| ID | 发起 → 负责 | 输入 → 输出 | 关键条件 |
| --- | --- | --- | --- |
| C01 prepare_appraisal | D03/D06/D07/D10 → D04 | 事件/解释/人格等冻结视图 → 意义/驱动候选 | 对象、现实性、来源份额、未知/竞争解释不丢失 |
| C02 assemble_affect_block | D04 → D11 | 基底/状态/参数/输入/耦合/Ω → 已受理联合块或拒绝 | 共同势/矩阵/域/输入有界证据，不能逐块代替联合 |
| C03 advance_and_adopt | D04/组合协调器 → D11 | 已受理块/区间/读集/资源 → 数值候选/提交收据 | 证书合格；感受/游标/贡献/体验/必要解释同事务 |
| C04 regulate | D07/D08/D10 → D04/D02 | 策略/动机/真实执行回执 → 尝试及观察效果 | 尝试≠成功；角色费用独立，D04 不执行外部动作 |
| C05 interpret_feeling | D07 → D04 | 可见线索/感受快照/反思 → 自我理解候选/采用版本 | 允许迟到误判，与他人事实 D07 和长期自我观 D01 分开 |
| C06 project_readout | D07/D08/D09/D12 → D04/D06 | 用途/受众/对象 → 倾向/感受自述/受限诊断 | 无发送资格、无角色全知、不直接回写状态 |
| C07 correct_or_erase | D03/D06/D07/D12 → D04/D11 | 更正/删除/版本范围 → 截断/重建/净化回执 | 更正不倒改经历；删除包括历史内容和混合派生 |
| C08 configure_or_resume | D12/D11 → D04 | 方案/检查点/时间/预算 → 预览/迁移/续算/已完成 | 参数跳变有账；重试不重复增加角色体验剂量、体验时长或已结算劳动贡献，新增实际计算费用仍累计 |

## C. 数值提供方与原子性

D04 提供 NumericalBlockSpec：registered basis/units、z0、baseline、共同 J/R/K/α/a/G、参数/输入界及 Ω、驱动类型/积分剂量、跳变点、完整时间映射、耦合闭包及截断要求、请求容差和读出。D11 提供 NumericalCertificate：所用算子/方法版本、区间、假设校验、非线性残差与解误差界、离散能量余额、时间 defect 及误差上界、邻域截断界、检查点/费用/停止原因。D04 接受语义与用途，D11 接受执行数值条件；两个签署均必需，不能让模型声明“稳定”代替证书。

[D11 数值合同 §§1–5](11-runtime-numerics.md)中的离散梯度/AVF 步长收缩、残差/(1-q)误差、含残差的离散能量以及独立时间重建误差为提供方义务。本域不假设小残差就代表连续解精确；每种误差必须满足各自请求容差。证书缺项、出界、输入过期、未处理跳变、不可认证耦合一律不提交对应区间，返回明确缺口。未认证基底/算子不得以临时线性近似替代完整产品机制。

一次 C03 包含 Feeling/Mood 当前版本、时间游标、驱动消费/替换、必要 SelfUnderstanding、D06 ExperienceRef、D02 已执行成本补差和 outbox；被本次引用的新 D07 解释同时提交或必须已存在。回忆协调只走 D06 C04，普通思考走 D07 C04；纯数值连续推进不生成重复聊天/回忆事件，其区间体验按原活动/区间唯一标识记录。

CAS 检查初态、输入/驱动和参数版本、每个写键含新键不存在版本、时间游标、预算/租约、来源/查询域/撤权及删除。旧游标、租约是提交前置条件，历史解释是成因，长期有效驱动是失效依赖，数值耦合是块内关系；四类均适用权限/删除，不能互换以绕 DAG。

## D. 失败与恢复

输入评价失败保留未知待评价；旧归因已经无效立即切断对应驱动。无争议独立块可继续，无法分离的联合块延期，不任意跳过耦合。暂停保存原区间、已算但未提交候选、费用/游标和取消代际，恢复先查原提交收据再校验当前输入；未知不得新活动重放。

取消后技术费用仍入 D11，已做人物劳动按 D02 call/component 结算，未用预留释放。真实计算精修不增长人物区间。已提交结果不能因为取消倒删历史；必要时新建有来源修订。公平和硬期限由 D07/D11 管理，D04 不自启永久后台循环。

隐私投影继承所有内容来源约束，每次外送/使用/提交/最终投递同步核验 transfer 源权。仅输出“难过”也不能自动去密。D11 final admission 负责最后串行授权，D04 不直接投递。删除先独立日志/逻辑屏蔽再清理，不能把历史轨迹当免删日志；恢复检查最新删除水位，未知则隔离。

参数/schema/基底迁移由 D12 预览、D04 校验、D11 原子启用，旧 writer 禁止双写。坐标映射无法保持意义/数值约束时拒绝迁移或在明确选择下重置并报告损失；既往参数版本与实际经历仍属历史，删除规则照常覆盖。
