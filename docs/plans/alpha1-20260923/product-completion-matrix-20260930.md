# Alpha1 当前产品闭环与验收账

更新时间：2026-09-30 12:44 UTC。对照 `backend-integration-20260930.md` §5.1–5.3、`backend-completion-20260930.md` 与十三域设计。此表记录实际范围，不是发布完成声明。现有 W09 界面保留，界面重设计仍暂停。

| 域 | 已接入的真实生产路径 | 已实际验证 | 仍需闭合或验收 |
|---|---|---|---|
| D01 人格 | 真实 Owner 角色初始化；当前角色；冻结候选/情境的价值比较；实际成长提案/试用读取和采用 | 真实安装包 Owner→D01；真实 C02→签名 values 输入→当前价值结果/后续通知 | 成长的正向独立经历、实际试用/反例→采用；作者编辑迁移与完整连续性场景仍不能由角色初始化替代 |
| D02 身体/资源 | 明确 Owner Body 政策；真实被动推进；D07/C04 原始工作预留/实际费用与身体效果；实际效果读取 | 安装包公开 Body 初始化/政策→状态 revision 2；D07 实际模型工作已走到身体结算；根与联合数值实际 CPU 路径 | D07 四种安装模式及 C04 真正空结果/费用闭环已通过；普通 D10 已结清效果→身体写集正向场景 |
| D03 情境 | 实际 Host 来源、绑定场景、自我身份/视角、当前角色/边界/受众；Owner 创建与绑定路线 | 首次 Owner 双向真实 mTLS；真实 C02、W09 创建/绑定与下游各域样本 | D10 内部结构经历的实际 D03 世界事件/视角接缝已编译，正向验收待真实生活/离线生产器；C09 RELEASED 后的共同 current-location 与 self-identity 源身份继续资格已编译接线；旧字节/严格扩展4项、既有 self 8项与 D03 投影13项通过，真正新 ingress/self projection 尚待实际冷释放 fixture |
| D04 感受 | 实际 Owner 根/专用预算/ABI2；显式 mapping/角色时钟；真实付费 appraisal；三块 drive；72D full/LOO 轨迹；独立 claim/terminal；新进程冷恢复；实际 CPU 与六状态原子采用 | 多轮真实安装包正常 rate 1、后台数学队列、GraphWorker 可响应、冷恢复禁 FFI、篡改拒绝、实际费用和精确重放；低预算根失败保留费用 | post-joint C04 baseline 与真实空结果费用/精确重放已通过；正向 C04 仍需真实 D06 关联 producer；最新完整候选需要统一最终复验。工程映射仍 engineering_unvalidated；**代码缺口：rate 1 普通停留超过64角色时间单位时，现4096×1/64步限会拒绝完整区间；尚无受信 bounded multi-job full/LOO 轨迹继续/费用/最终采用路径，8秒验收不能替代长期闲置恢复** |
| D05 关系 | 真实来源贡献/关系投影、Owner 边界意图/政策、当前重评与真实后续 outbox | 安装包真实 host-event 贡献、关系投影与 outbox；严格原件/Schema | 更完整修复、撤回、边界改变→实际行动重新资格链；不得把 reported 文本当独立 observed 事实 |
| D06 记忆 | 实际入站 C02 模型/预算/费用/记忆采用；来源/访问/修订/删除闭包；C04 当前关联算法、编码 baseline/投影与原件恢复合同 | 自然生成完整模型路径259项含 C02；新 C04 baseline 已在真实 authored joint 输出后采用，并在后续 Body 写入后精确重放；实际 authored proof 冷解码2项、既有7项通过 | C04 prepare/精确重放→独立一次执行→真实 CPU/Body 费用已执行；初始无关联边场景返回真实空候选，完整安装空结果/真实费用/禁止执行的精确重放1项通过214.45秒（c04-empty-1137.log）。已确认 compile_association/prepare_association 没有生产调用，真正两源关联→合法回忆/解释正向尚缺 producer 与验收；D10 结构经历 D03+Episode 独立 lane 与固定 outbox 接线已编译，真实生产器验收待完成；状态明确 encoding_pending，不能当成完成 SubjectiveTrace |
| D07 注意/认知 | 真实关注/有限队列/焦点；Concern、反思、模拟的付费模型作业、当前源资格、独立结果/费用、专用子预算、恢复调度 | 现有注意与自然回复链；新增实际认知验收已跨 prepare、真实受控 provider、独立终态、CPU/Body 结算 | 四种完整安装模式均已通过244.37秒：Concern/真实问题/resolved 与 waiting 反思、三分支 hypothetical simulation、未知终态不重发、撤权后历史费用。临时 result 缓存释放后3种相关模式已再通过173.29秒（d07-cache-1145.log），resolved 反思使用此前未改路径的通过证据；最终候选需统一针 |
| D08 行动 | 真实自然响应 P2 communication criterion/final admission/单次 dispatch；来源化目标、双边/联合计划输入；当前 action recovery/RequiredCheck | 自然响应 final/lost ACK/reopen；真实公开未执行 goal；当前精确 recheck 路线已编译 | 一般候选选择→ActionIntent、通用承诺兼容、联合节点行动发行、一般目标/outcome 完成链仍有代码缺口；双边/联合计划正向需真实语义同意/出站原件 |
| D09 表达 | 真实自然生成→原件读取→审阅→表达采用→有限批 final→出站观察；实际提供方/模型和预算绑定 | 新 V4 自然链及未知/撤销/重开259项；真实双 mTLS FirstOwner 后续协议 | 最新候选统一回归；真实外部平台/付费模型属于操作者配置后的手动场景 |
| D10 生活/主动性 | 实际生活/离线原件读取与 composite staging；当前 ContactPolicy/机会/边界资格；结构经历 outbox | 真实当前 ingress actor→合格 contact opportunity/outbox；无伪 contact claim | 真实 logical-runtime lifecycle 捕获/签名来源及 Owner schedule/interval 输入、独立 offline claim/terminal/固定配对 RPC 已编译接线；terminal→Graph 桥、真实恢复调度与完整验收仍在实现；生活计划/已结清 outcome→D02/D06/D10 正向；主动联系实际 claim/final/unknown 全链 |
| D11 预算/调度 | 实际签名 quote/grant/reserve；独立模型/CPU claim/terminal；Body 与费用；未知占用；角色时钟；固定后续任务 | D13259项，根与联合数值实际费用/超额，真实背景 outbox 精确等待/重放；共享 W0940项 | D07 与 C04 空结果已通过；offline terminal→Graph adoption/accounting 桥与恢复调度未完成；跨原件清除后全部单位占用/历史费用统一最终验收 |
| D12 工作台/安装维护 | 明确 Owner 登录/角色/根/政策操作；首次 Owner 反向 mTLS；实际原生迁移/目标新身份；整 Host pause/resume；C11 受管备份/兼容包/固定启动入口 | FirstOwner 最后2项22.96秒；迁移/状态/会话52项；实际子进程 native+13目录 bootstrap；只读真实四库 candidate2项 | C11 实际进程 forward/不兼容 abort/失败候选 rollback 已分别通过，包含真实备份、pointer、新进程 native/13域 readiness 与精确重放；最终 Linux 安装/用户指南/包针；不使用旧 V1 shadow 假迁移 |
| D13 短期上下文 | 72小时；原文、确定性与显式预算模型压缩；后台提前预制；全 wire 原始签名计数；同事务真实预算；六阶段冻结重放；实际出站记录 | 新完整259项通过，真实签名/SQL/Authority/恢复，未调用付费模型 | 操作者真实 counter/provider-cache 能力配置；不支持外部可验证清除的 surface 必须 HOLD |

## 跨域与安装闸门

- 已通过的普通域安装验收 snapshot1006：Owner/root/clock→Body→C02→values/relationship/goal/contact；严格 signed helper/12-stage codecs；实际 outbox consumer 的精确 waiting disposition 与重放。该样本没有把目标或机会标成已执行行动。
- C09：首次实际四进程 PREPARED→SWITCHED→RELEASED→fresh source Owner read/ordinary survivor write 已1项通过20.72秒（1033日志）。同安装第二次删除已实际提交 pending、通过经审核的 Graph barrier 并 accepted；实际 successor registry 与四角色文件映射已走到 generation-2 Graph candidate，Core 对同一已签位置/GRAPH 成员的消费已编译；最终 close/checkpoint/scan→PREPARED 连续排他证明仍在修复，且已保存候选后普通启动改变文件指纹的 retained INTENT 重试正确 HOLD。该无执行来源样本没有证明非空 paid/D07 历史清除，也没有证明 RELEASED 后新 C02/model/self-identity；共同 location qualifier 的 model/self 消费已编译且旧路径回归通过，新的跨冷释放正向仍是明确验收闸门。受控本地 cache 证明不能替代真实外部模型提供方的可验证清除。
- 已完成 canonical top-level `sylanne3` 加载与实际 AstrBot SDK/独立 Authority 字节一致验收。没有通过改 serializer 或旧 digest 来兼容命名空间错误。
- 新 `snapshot-alpha1-test` 为独立测试快照模式，版本确切 `3.0.0-alpha1`，保留现有 W09。实际快照包严格来源/全部工程 inventory/独立无PATH冷加载与证据篡改拒绝2项通过。正式 clean-Git/公开 release 闸门未宣称通过。
- 交付前必须冻结最终源、原生库与资产，记录该针的真实验收证据和未验证场景。当前任何 development/backend candidate 都不是已经完成的整套交付。
