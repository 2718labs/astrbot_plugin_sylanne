# D13 短期上下文协作合同 v1（设计）

日期：2026-09-27。公共身份、写者能力和恢复规则继承[十三域耦合总装](../architecture/sylanne-3-thirteen-module-coupling.md)与[全系统合同](../architecture/module-collaboration-contracts.md)。W00 已落五个不可变 DTO 及回合/锚点类型；C01–C08 的生产操作与来源签发尚未接线。D03 的 `ContextFrame` 名称和语义保持不变；D13 返回 `ShortContextSliceV1`，D11 才装配最终 `ModelInputFrameV1`。

## 操作目录

| 操作 | 输入 → 输出 | 责任边界 |
| --- | --- | --- |
| C01 `project_window` | D06 合格来源＋D03 scene/audience/受信时间＋D09 已提交回合顺序＋D11 实际投递/工具状态 → `ConversationWindowProjectionV1` | 四域各签自己字段，由 D11 一致装配；草稿、未封闭工具回合、unknown 结果不作完成事实。 |
| C02 `plan_precompression` | 最近 72h 原文、D11 冻结对话预算/后台余量、现有候选 → 前缀区间、一次作业请求或无操作 | 默认约 60% 预制；同会话最多一份运行/待用；不能循环对同一区间付费。 |
| C03 `compile_block` | 原始已结束回合、固定来源/受众版本、D11 job/fence/预算 → `CompressedTurnBlockV2` 候选及费用 | 先确定性折叠，再必要时一次模型辅助；压缩模型调用禁用 D13 历史带，不从旧块编译。 |
| C04 `adopt_standby` | 候选、原始闭包/current epochs、job fence → 待用块或拒绝 | D13 核说话者/顺序/限定/遗漏与来源；D11 事务原子保存，迟到 worker 不采用。 |
| C05 `assemble_slice` | `ShortContextRequestV1`、当前合法窗口、可选待用块、已提交焦点 → `ShortContextSliceV1` | D13 只选可裁的近期脉络；硬检查和当前领域权威不在 slice 内，query 变化不重编块。 |
| C06 `activate_block` | 待用块、当前窗口/费用条件、版本读集 → 激活引用/前缀替换原因 | 本地一次 CAS 切换；前台不等模型，不在块/原文间逐轮抖动。 |
| C07 `invalidate_or_retire` | 来源/受众/对话/执行资格变更，可信 72h 截止或删除 → 同步不可读及清理任务 | D06 定义删除，D11 物理回收；D13 不自行删除权威来源或给块续命。 |
| C08 `inspect_usage` | D12 授权视角＋D11 实际调用回执 → 覆盖、遗漏、待用/到期、前台延迟、费用与 unknown | 默认无私密原文；前缀摘要不冒充供应商缓存命中。 |

## 冻结字段与禁环

`ConversationWindowProjectionV1` 至少包含 namespace/owner、conversation、D03 scene/audience refs+versions、已结束回合边界与 D09 顺序水位、D06 source/access refs+revisions、D11 实际投递/工具状态、受信 UTC、coverage/missing、完整读集/删除/activation epochs。D13 不能凭模型文本补缺的来源或身份。D11 受信入站时间控制 72 小时，不用 D10 角色生活倍率或块最后使用时刻。

`ShortContextRequestV1` 至少包含 requesting_domain、purpose、conversation/scene/audience、当前 query/指代、可选**已提交** D07 焦点版本、可裁历史额度、provider/model/template/tool profile、父预算和显式 opt-in。D07 形成当前焦点所用的调用不得反过来要求当前尚未提交的焦点；可用当前 query 和已提交 D09 话题完成确定性选择。

`CompressedTurnBlockV2` 只从连续合法原始回合编译，保存来源闭包/版本、时间线、细节槽、确切锚点、遗漏范围、编译版本、job/candidate 身份与不晚于最早回合受信 UTC+72h 的截止。`ShortContextSliceV1` 保存本轮选中原文/块/槽、时间锚、覆盖/缺口、完整来源依赖、有效期、估算 token 与稳定前缀摘要；没有长期记忆写入权。D11 `ModelInputFrameV1` 单独拼入当前输入、D03 按用途视角、D06 必需证据、所属域当前投影与 RequiredCheck，最终计数、冻结摘要和外送资格由 D11 负责。

跨域读取、外送、采用和最终投递分别重验当前来源/access/delete/受众/activation。更正影响块内容时立即阻断；D07 焦点、D04 心境或 D08 承诺单独变化通常只重装配本轮，而不重编历史块。D13 选槽次数不更新 D07 注意、D06 强度、D05 关系或 D09 对话状态。源发生实际新进展后，D06/D09 各写自己的权威版本；D13 不以自身摘要作为新来源制造反馈环。
