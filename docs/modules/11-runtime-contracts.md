# D11 操作合同 v1（设计）

配套 [主规格](11-runtime-host.md)、[数值合同](11-runtime-numerics.md)。日期 2026-09-23；版本 `d11.contract.v1`。接口是待实现的领域无关运行能力，不能视为当前 GraphStore 同名方法。

## A. 信封与提供者注册

所有命令沿用 D06/D07 信封：schema、合法 issuer/capability、owner_scope、activity/effect/attempt/phase operation、input refs/完整 read_versions、query/access/delete epochs、policy/plan/operator versions、purpose/audience/provider_policy、budget lease、deadline、causation。需外部动作时另有 action/dispatch/call 身份；时钟信息包含 occurred/learned/character_interval/monotonic deadline，最终提交序号由 D11 签发。

ProviderDescriptor 包含契约版本、请求/响应 schema hash、owner capabilities、支持模态/用途/平台、超时/取消/幂等特性、实际费用报告模式、健康及恢复能力。未知版本拒绝；启动对必需提供者进行 schema/权限配对，缺项影响对应能力就绪，不由模型临时猜一个返回值。

## B. 操作目录

| ID / 操作 | 输入 | 返回与原子/失败边界 |
| --- | --- | --- |
| C01 `register_compile_activate` | D12 方案、领域目录/算子/参数、能力/预算 | 编译报告与 manifest；激活原子切 epoch，不迁移历史、不部分启用不兼容目录 |
| C02 `admit_ingress` | 宿主可信信封、限长来源/附件引用 | 来源/事件接纳与 pending/outbox 同事务；重复相同事件返回原回执，超载不假确认 |
| C03 `read_snapshot` | 域能力、purpose/audience、键/查询范围 | 一致版本与正/负查询 epochs；受限不可见，不以旧缓存泄露存在性 |
| C04 `reserve_and_schedule` | 领域活动、注意/资源要求、父额度、job | D02 预留引用/真实 lease/持久 job 一致登记；waiting 不持有执行槽，只释放可证明未执行且已撤销后续执行资格的未用额度，未知执行保留待核实占用 |
| C05 `execute_atom_batch` | 冻结 plan/snapshot、有限批输入与继续点 | 候选/精度向量/费用/continuation；事务外执行，超时不伪称已退出，无效证书不能提交 |
| C06 `commit_domain_bundle` | 完整合法写集、必要经历/结算/去重/outbox | 同 namespace 原子收据；stale/conflict/rejected 无部分变更，未知结果保留原身份核实 |
| C07 `invoke_model` | 合格 provider、用途、受限内容、schema 与额度 | call 回执、候选、计费/未知费用；无权外送拒绝，失败仍计预算，工具建议无执行资格 |
| C08 `admit_dispatch` | D08 intent/有限段子资格、基础必查、主动联系的 D10 ContactPolicyCheck、D09/工具参数、依赖 | 授权/撤权串行门口的一次性 claim；contact 首次配额/无回应闸门原子占用，后段复用且逐段重验；不等于已交平台或已成功 |
| C09 `execute_and_observe` | 已 claim dispatch、adapter 能力与幂等 key | pending/sending/ack/delivered/failed/unknown 等可观测收据；外部 unknown 不自行变 failed 重发 |
| C10 `invalidate_or_erase` | 合法修订或获准删除、闭包/范围 | 修订即时失效；删除独立日志先行＋权威屏蔽后 accepted；物理清理分面回执 |
| C11 `checkpoint_resume_cancel` | 原 activity/job/call、租约与快照 | completed/deferred/stale/draining/pending_confirmation；实际退出才释放 worker；重启先核实旧副作用 |
| C12 `migrate_backup_restore` | D12 预览/确认、版本清单、删除/权限水位 | 隔离预览、校验/切换/恢复收据；不可证明最新性拒开放，旧库不重启旧核心 |
| C13 `inspect_health_costs` | 授权视角、范围与时间 | 脱敏健康/成本/积压/精度/因果引用；诊断不是角色内心或新来源 |

## C. 数据事务与执行事务

数据库事务保护状态一致性，外部副作用由单独 durable dispatch 保护，二者不能合成跨网络原子承诺。C06 不持锁等模型/发送/工具。注册的跨域 bundle 内各写者分别验证各自字段，由 D11 检查完整依赖及一并提交。

外部交接之前还须耐久写入独立于业务备份的 ExecutionJournal：`execution_seq, effect_id, command_digest, dispatch_generation, activation_generation, admission_ref, phase`；准备与观测追加而非覆盖，最新恢复水位由权威维护，不被普通业务恢复回滚。sender 只有同时确认 journal 准备和合法业务 claim、当前 fencing/权限后才能交接。任何一面不明就 pending_confirmation；准备可能未发也不能无依据重放。业务结果事务可通过独立日志幂等补齐。日志缺失或最新性不明则隔离，恢复旧快照先为 journal 全部未决/unknown effect 建禁止重放占位。

`admission_ref` 不能是只能从已回滚业务库解出的引用。交接前，journal 同时耐久保存经所属域验证的最小 `RecoveryConstraintFootprint`：namespace、稳定 activity/effect、外部幂等/查询引用、冲突域不透明键，以及适用的 communication_action/contact_id、原有限段资格摘要、D10 对象闸门键/配额桶与时窗/占用量、D02 待核实 reservation/component 引用和上界、D11 父预算引用及已用/待核实额度。它只恢复限制和核查身份，不恢复发送权限、领域成功或完整内容；不得仅靠 command_digest 推断对象和额度。原始载荷及非必要身份内容不进入此足迹，必要元数据仍受访问与删除规则约束。

业务快照早于首次 claim 时，恢复先按原 contact_id 合并占用一次，按原 segment/effect 恢复未决项；对象无回应闸门不能因配额时窗已过而解除。D02 未决承诺与 D11 费用分别恢复，未知不写零、不作为可用余额；缺失父账或无法核实的上界使对应预算域不可准入。只有耐久核查证明未交接且原资格已不可再派发，或合法领域解除回执，才可缩小相应限制。足迹缺失/删去后无法定位限制域时阻断该 namespace 的新增外部派发，无法定位 namespace 时隔离恢复；不能只拦原 effect 而放行新 ID 联系同一对象。后续解除/释放观测追加到独立日志并提升水位，避免下一次旧库恢复丢失已核实的限制状态。

communication_action/contact_id 是一次交流身份，segment/effect 是每段独立外部效果；不可变有限段清单/限定子资格由 D08 签发。C08 首段把 D10 配额与对象闸门占用和段 claim 一起提交；后段消费自己的 effect，不重扣 contact，仍核验当前同意/静默/权限/行动版本。只有零段交接且全部可证明未执行才释放，任一 unknown 保留占用。机会过期不解除对象无回应闸门；扩段不能借新 ID 绕过限制。

成功收据至少含 namespace、operation digest、activity/effect、commit_seq、读版本、写版本/失效代际、ledger/费用/索引 outbox 引用。存储原始命令若含敏感内容也进入删除范围，幂等查重不能变成永久原文库；保留必要无内容标识时仍受元数据权限保护。

活动分技术执行与角色经历：技术核查只留 runtime receipt，实际角色劳动引用 D02 work_kind/区间；D06/D07/D04 的经历写集按其合同要求提交，不能由 D11 以“运行过”擅自认定人物体验。联合提交消费 call/component 去重键，已部分结算只补未结算成本。模拟内容来源资格沿引用链传播，与实际内部活动执行正交。

提交前必须核验旧版本和写键缺失版本、query scope 增量 epochs、源权限/删除 epochs、目录/方案/算子/policy、焦点与资源租约、跨域 grant。即时权限检查不等待索引/通知。前置 CAS 条件不自动写作长期语义父边；历史成因仍可供删除/审计遍历。

## D. 调度与持久恢复

job 包含阶段、deadline、work kind、恢复前沿、冻结输入、数值区间/残差、父额度、已用费用、租约持有者、fencing token、cancel epoch、wake 条件。所有写入验证 fencing token：旧 worker 失租后的迟到结果不得提交，即使进程仍在计算。只有确证旧执行不再持有外部派发资格才可由新 worker 续接；未知发送不能靠重领 lease 重发。

两层公平：Bot/persona 实际资源轮转与 D07 的人物任务轮转。不可运行任务不占 worker，持久延期有上限/背压和最迟复查；待处理来源存在业务库但不能无限复制进内存。调度批次受 atom 数、内存和最大原生步数限制，长原子必须自己可分片。

恢复检索原 activity/effect 收据、dispatch/call 状态、删除日志及目录再继续；已完成返回原结果，未知查询，未提交且输入仍合法才续算。取消不是撤销已提交结果；后续修订须新事件。关机/卸载要等待实际退出或保持受限 draining，不丢失尚未核实的收据。

C04 的原子预留失败与执行后的失败分开：前者不产生任何部分预留；后者先按 call/component 补齐实际劳动/费用，仅释放确定未用且资格已撤销的部分。租约到期、取消请求、模型超时或角色余额下降都不证明旧执行未发生。D02 返回 `reservation_shortfall` 时停止追加角色劳动片段，保留 gross/encumbered/available/shortfall 和待核实承诺；已发生超支才进入 overrun，不能靠释放 unknown 预留消除差额。失败候选可不采用，真实已用成本仍通过结算事务保留。

## E. 模型与工具外送

C07/C09 都先验证目的地政策和字段最小化，固定命令摘要、版本、幂等能力。HTTP 超时后费用/效果可未知，retry 必须经过操作分类：纯读取可受预算重试；有幂等证明的写入复用键；非幂等或资格未知的写入先核实。不得把所有供应商/工具失败统一当可重试。

模型输出解析为域候选，字段白名单/来源/现实性/权限检查后才进入 C06；词义合理性另有评估。ExpressionSegment 引用已采用状态和拟行动，各段生成可在事务外，暴露给用户前必须已获 D09 核验＋C08。流式未核验 token 不能先发再删除以假装受控。

账户凭据引用来自宿主安全配置，域 schema、工作台导出和日志不含明文。供应商不满足当前内容权限时可改用另一个已获准且满足显式用户模型要求的 provider；没有合格路径就 unavailable，不默认外送。

## F. 类型迁移、删除与单实例

C12 维护模式禁止旧/新 writer 同时写同 namespace；新 manifest 激活前验证记录总数/来源闭包/必需域、目录、删除与执行恢复水位。数据库文件备份可以回退，独立删除日志、ExecutionJournal 和最新撤权信息不可被旧备份覆盖。恢复先合并执行日志已知/未决/unknown 记录与其配额/冲突占位；无载荷也不能忘记有未决效果，更不能自动重发。迁移产生 administrative/migration 来源，不增加成长/履约贡献。

独立删除日志序号由统一准入屏障签发，意图先耐久，业务屏蔽后确认；pending intent 也阻断读取。持久 journal 水位与业务库兼容性/完整性不能只靠一个标志文件推断。没有最新水位证明时隔离恢复，人工接受数据丢失也不能静默打开已知被删除内容。

本机激活使用进程锁加持久 fencing generation，跨机搬迁要求原端受检停写/撤销激活资格并交接最新删除/权限/外部结果水位。无法验证原端停止时目的地保持隔离，不自动双活。普通分享导出按受限副本处理，不能继承源运行资格。

跨机唯一资格由 D12 提交搬迁命令、D11 单一 MigrationAuthority 持有与签发 activation_generation；所有内容读取、模型外送、下载、订阅、采用、写入、投递及重启检查它，不能只挡写。旧代际或权威不可核验时仅无内容诊断。删除与执行 journal 最新性和独立防回滚锚一同交接，复制旧文件不构成资格；由唯一权威撤销目标后才可另签源新代际回退。

## G. 失败分类与可用性

| 类别 | 处置 |
| --- | --- |
| schema/能力/目录不兼容 | rejected，字段/提供者诊断；不调用旧核心 |
| 权限撤回/删除/来源域不可核验 | 立即挡读/外送/采用；对普通调用隐藏存在性 |
| input stale/focus conflict | 新 attempt 重装配，保留 activity/cost/贡献身份 |
| 数值证书不足/截断或时间界未知 | 继续精修/扩域或 deferred，显示未推进区间 |
| 预算耗尽/过载 | partial/deferred，明示覆盖和等待；必需资格不能降级 |
| 事务/外部结果未知 | pending_confirmation/unknown，查原回执，不新ID重发 |
| 存储空间不足/损坏 | 停止写入与发送准入，保持已有证据可读范围或隔离恢复；不假接纳来源 |
| 原生库缺失/崩溃/ABI不符 | 对相关能力 unavailable，作业恢复/诊断；无需用户编译但需正确平台包 |
| 下游域暂离线 | outbox 持久重试；受影响当前读出阻断，其他独立有效域可继续 |

上述结果只证明特定请求状态。ready 不自动表示真实平台认证、数值心理有效性或全功能已验收，D12 需显示能力矩阵。
