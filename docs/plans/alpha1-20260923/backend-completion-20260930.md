# alpha1 全部后端完成账（2026-09-30）

状态：**当前源码只读盘点；没有本次运行验收，也没有 DONE 判定**。本账依据本工作树中的生产源码，结合 `task_plan.md`、`architecture-gate.md`、`current-todo-20260927.md`、`acceptance/requirements-runtime.md`、9/28 backend evidence/late checkpoint、十三域主稿/合同/验收与联合验收稿。并行写者仍在修改 D04/C04/D13/GraphCoordinator/RuntimeContext，因此下列“存在/未找到”是读取时的接口情况，交接后须由唯一写者更新实际结果。它不覆盖既有脏改动，不授权 push、PR、合并或发布。

本次仅读取文件与搜索生产调用者；**没有执行编译、测试、模型、平台发送、运行库操作或 Git 写入**。历史聚焦用例与旧 CI 只作为定位入口，不累加测试数量、源行数量或所谓完成百分比。源码接线、受控机制验证、真实环境验收、冻结构件四种状态分开记录。

## 1. 本轮范围与判断方法

9/28 用户范围是**完整 alpha1 全部非前端部分**：D01–D13、W10/D12 服务端、Windows 真实宿主/私群/附件/工具、Authority、Rust 原生核、纠错/删除/恢复/搬迁、升级、规模/费用/对照、候选构件全部保留。W11 客户端与键盘、窄屏、读屏的界面操作暂缓；不能连带暂缓服务端权限、领域写入口、实验隔离、导入导出、升级恢复或各页所需的权威投影。

本账采用三个非完成标签：

| 标签 | 含义 |
| --- | --- |
| 接线可定位 | 当前可找到生产调用链与权威端口；仍需最终源码的产品验收。 |
| 领域候选/受控切片 | 类型、算法或夹具路径存在，但没有对应完整产品驱动/当前权威采用或纵向收据。 |
| 明确 HOLD/缺环境 | 服务端直接拒绝、缺受信提供者/正式 pin，或缺真实宿主、平台、Mac 等环境。不能以替身放行。 |

原 62 项运行账的 OPEN/PARTIAL 是历史验收状态，不能据其较早的“未接通”描述重复开发当前已经接通的接口。本账只增补当前映射，不改写历史证据或将任何需求标 DONE。

## 2. 当前生产路径及历史描述更正

当前入口 `main.py:Sylanne3Plugin.initialize` 已按 `assemble_v2_installation → load_verified_affect_scheme/load_verified_context_scheme → RuntimeContext.start_v2` 装配，随后 provisioning、reverse handoff、Owner 登录/工作台挂载与恢复扫描。`RuntimeContext(... dependencies=None)` 仍出现，但这是旧通用 dependencies 参数；**不能再据这个字面量断言 start_v2 完全未接线**。安装路径仍要求真实安装档、manifest、角色/Owner/场景与模型/预算等资格，未配对时 enrollment_required。

当前主消息链可定位到：

`main.ingress → host.astrbot.assemble_astrbot_ingress → RuntimeContext.handle_ingress → W01 installed ingress → D03/D04 pre-encoding → encoding job/model/terminal/cost → C02 → D07 post-C02 competition → D08 natural plan → generation + paid review → D09 verified batch → W01 final → Authority P2/reverse graph claim → AstrBotV2TextSender → durable observation → accepted focus completion/deferred release`。

`main.py` 也有 first-ingress/C02/model/natural dispatch/D07 released attention/D13 original schedule 的启动恢复扫描。late checkpoint 已记录真 Owner 同库、daemon 冷重开、双 paid RPC、accepted/unknown、撤权等受控切片；它们不能转写成真实 QQ、真实付费 provider 或正式安装验收。

需保留的源码边界：

* `domain_registry.py` 明确注册 D01–D13 的真实 provider；complete 仅证明目录可构造且 D04 active scheme 已给定，**不证明每域完整行为已生产接线**。
* `RuntimeContext.refresh_capabilities` 仍输出 limited 并保留 scene_binding/dispatch 的全局缺项；消息时的逐请求资格另走各端口。不能只看全局 health 或某次 reply readiness 代替十三域完成判断。
* `host/astrbot_dispatch.py` 的实际发送是 OneBot `send_private_msg` / `send_group_msg` 的**文本**；自然 batch resolver 要求 segment_index=0、segment_count=1、media_refs 为空。多段/媒体完整产品链不能从该单段正例推定。
* `host/astrbot.py` 已解析受信临时目录或 data URI 的附件字节，支持带非空 caption 的附件入站；无 caption 媒体明确拒绝。入站附件原件存在不等于 outbound 媒体、工具或完整多模态模型能力已具备。
* `host/astrbot_model_call.py` 当前 OpenAI Chat Completions adapter 拒绝 tool_calls/function_call；生产树未找到 ToolProvider/execute_tool/tool_executor 的真正调用链。工具真实执行、资格、预算、unknown 与来源化观察是独立未闭合项。

## 3. 十三域实现、生产出口与余项

每域全部验收条目以链接文件为准。下表不是把一个领域缩成一条；它指出必须补齐的产品驱动与跨域后果。验收稿内的条目与 62 项、S/T 场景大量重叠，不能相加成开发任务总数。

| 域 / 设计与验收入口 | 当前源码可定位部分 | 全部后端仍需闭合的产品条件 |
| --- | --- | --- |
| D01：[主稿](../../modules/01-persona.md) / [验收](../../modules/01-persona-acceptance.md) | `domains/d01` 有 PersonaPlan/ValueRule、active-role resolution、growth candidate、continuity revision；W01/Workbench 有真实 Owner 角色初始化与当前角色读；D12 有 creation 投影。 | `evaluate_values`、`issue_growth_candidate`、`compile_persona_authoring_migration` 在非 domains 生产源码未找到调用者；真实候选比较的人格约束、独立经历驱动成长、自传修订/撤销、作者编辑的一块迁移与跨会话版本连续性仍需产品入口及收据。不能把初始角色可创建当人格/成长完成。 |
| D02：[主稿](../../modules/02-body-needs.md) / [验收](../../modules/02-body-acceptance.md) | BodyProfile/State、报价/预留/shortfall、被动解析演化、actual/outcome verifier、CPU measured settlement；W01 已有安装资源、C02/C04 相邻账接口。 | `advance_passive_body`、`apply_settled_work_effect` 在非 domains 生产源码未找到调用者；需要身体/需求的可信时钟推进、劳动/休息恢复、日程和候选可承接量的真实后果，unknown 预留保持与已测量实际结算。CPU 窄执行器不能代表模型/异步/工具全部资源执行。 |
| D03：[主稿](../../modules/03-world-context.md) / [验收](../../modules/03-context-acceptance.md) | 真实宿主 namespace/稳定会话/消息源；scene binding、RoleBinding、self identity、group audience、cross-scene social/current prebatch checks。 | 稳定实体 account 合并/拆分/撤销、历史 perspective/as_known_at、多人知情范围/turn order 的正式驱动与版本化纠错；群聊实机资格不能用私聊 donor 代替。neutral scene_participant 安装方案只是窄方案，不能代表全部社会规范。 |
| D04：[主稿](../../modules/04-emotion.md) / [验收](../../modules/04-emotion-acceptance.md) | 数值 scheme/ABI2、source drive、full/LOO、joint original、authored root V3、编码与当前投影候选持续由专门写者接线。 | 受信正式 native/package pin、当前完整来源/解释/祖先闭包、V3 authored 根与首 joint、Mood/Feeling/意义/自我理解/调节成本的真实采用和表达消费；旧 joint 缺历史闭包不可回填。完整混合情绪干预和连续状态恢复仍须最终产品验收。 |
| D05：[主稿](../../modules/05-relationships.md) / [验收](../../modules/05-relationship-acceptance.md) | 分对象 contribution/registered dimensions、BoundaryRule、受众披露/prebatch checks、来源更正的 reevaluation candidate；relations 投影要求完整 fenced snapshot。 | 当前 schema 的关系 projection 是 subject_entity_ref/dimension/status；未找到非 domains 的 RelationshipContribution 生产构造/采用驱动。需真实外部相处和内部回忆分别计贡献、同来源去重、渐进关系更新/冲突修复/冷却、跨群隔离以及更正后重建。只有边界 pass 与状态投影不足以形成关系生活。 |
| D06：[主稿](../../modules/06-memory.md) / [验收](../../modules/06-memory-acceptance.md) | fast source/C02、附件持久源、current memory/qualified expression、C04/current association/recollection、纠错/撤权、投影索引/迁移、consolidation candidate、volatile vector。 | C04 V3 真实执行/原子结算/体验采用正例；全部召回状态机和责任/语义/竞争三路检索、必查触发与停止对照、各巩固出口/遗忘、分权限向量代际和索引追赶；`prepare_consolidation_candidate`/VolatileVectorGeneration 在非 domains 没找到产品驱动。C09 接受屏障与物理 closed/reopen 必须分开。 |
| D07：[主稿](../../modules/07-attention-cognition.md) / [验收](../../modules/07-cognition-acceptance.md) | first interpretation、post-C02 双票/primary/auxiliary、accepted focus completion、deferred release 与 main 恢复扫描；concern round/reflection transition/simulation 为候选算法。 | 当前双票回复不覆盖持续 Concern 创建/轮转/配额/冷却/归档、背景公平服务、反思续接、反事实模拟及真实内部活动成本/体验的生产驱动；非 domains 未找到 concern/reflection/simulate 对应调用者。D07-only compile/preview 不等于当前通用 adopt 已支持。 |
| D08：[主稿](../../modules/08-goals-execution.md) / [验收](../../modules/08-execution-acceptance.md) | Goal/Commitment/JointPlan/RequiredCheck/ActionIntent、自然表达计划与 final、五提供者现行核验、取消/recovery、bilateral acknowledgement 候选。 | 生产 `prepare_goal_candidate` 目前定位于 reply/final；多人双方确认、长期多目标/联合计划、deadline/暂停恢复、履约实际产出、补救新意图、工具执行尚无完整产品驱动。未找到 bilateral acknowledgement 非 domains 调用者。不能以 reactive reply goal 覆盖所有行动生活。 |
| D09：[主稿](../../modules/09-dialogue-expression.md) / [验收](../../modules/09-dialogue-acceptance.md) | natural generation/review/batch、当前 D09-only adopted policy 的 final 消费、turn order/completion、interruption；文本单段 P2 有受控路径。 | 真群聊与多段 per-effect 发送/插话/更正/重启轨迹，话题/节奏/已暴露与未暴露区分、附件/媒体输出及与动作匹配；单段自然回复不代表节奏/多段全部验收。 |
| D10：[主稿](../../modules/10-life-proactivity.md) / [验收](../../modules/10-life-acceptance.md) | LifeProject/ActivityRecipe/Outcome、ContactPolicy/Claim/机会、current contact、offline interval/observed tick 候选；final 可以核主动联系约束。 | `adopt_life_progress`、`plan_offline_simulation_slice`、`advance_observed_offline_ticks_v1`、`claim_contact_window` 在非 domains 未找到生产调用者。需生活项目/兴趣/习惯、可信时钟唤醒、有限离线推进、真实来源化作品/活动产出、主动机会→ContactPolicyCheck→有限批→unknown/无回应闸门结算的完整链。 |
| D11：[主稿](../../modules/11-runtime-host.md) / [数值](../../modules/11-runtime-numerics.md) / [验收](../../modules/11-runtime-acceptance.md) | GraphCoordinator/ProductionGraphStore、Authority Core/双日志/mTLS/fence、预算/jobs、C02/natural 恢复、固定块 ABI2 与 loader。 | 所有域的真实驱动接入同一 budget/job/时钟；宿主公平/取消/背压/迟到结果、真实工具 dispatcher、迁移/旧备份所有内容入口、C09 物理存储代际、升级影子库切换与全部恢复约束；正式 installed callbacks/OS ACL/clock/publisher trust 与新 pin 必须有安装态证据。 |
| D12：[主稿](../../modules/12-workbench-delivery.md) / [验收](../../modules/12-workbench-acceptance.md) | 服务端 HTTP/Origin/session、真实 Owner auth/grants、角色创建/绑定、窄字段 compile、D07/D09 付费预览、D09-only active-head adopt、source correction/revoke、C09 prepare/current accepted、窄 view-health export。 | 当前 `CurrentDomainViewRegistry` 仅见 D01 creation、D05 relations、D06 memory 的公开 field projection 合同；其余域缺公有视图合同不自动推出原子。一般创作/多域 adopt、一般实验、分享/私史备份/复制、迁移 preview/execute、安装升级、控制与停用卸载仍需权威服务入口。 |
| D13：[主稿](../../modules/13-short-context.md) / [验收 A01–A08](../../modules/13-short-context-acceptance.md) | raw slice/prefix/确定性预压缩、current window、已完成 turns、主模型身份选择/重读、queued original schedule/expiry/restart scan、paid lifecycle 候选。 | 同主模型/完整 frozen wire 调用前精确 tokenizer 缺真实 AstrBot provider 接口；确定性政策 `model_assist=False` 与 d13_compute_units 不能支付模型调用。paid quote/original/admission/actual usage/结果核验/即时激活及缓存双账必须由当前专门写者闭环，未有最终付费压缩产品正例。 |

以上“未找到调用者”采用 PowerShell 对 `rewrite/sylanne3/**/*.py` 的具体 symbol 搜索，并排除该 symbol 自己的 `domains` 定义。它是定位证据，不排除未来动态调用或并行新接线；不据此替领域裁决设计。

## 4. 旧 62 项逐项映射

下列 62 行保留原 ID。每行都在本轮服务端范围；D12/OPS 的界面动作由第 6 节拆分。它们的本次验收状态均是**未执行**，不是把静态结果改写成旧账 DONE。

| ID | 当前对应链/模块 | 完成前还需的具体后端证明 |
| --- | --- | --- |
| R0-01 | main/start_v2/installed loader | 冻结包 Windows 根入口冷启动、退役旧核心无运行回退、唯一 trace。 |
| R0-02 | typed graph/Authority fences/bundles | 当前目录能力/负读集/CAS/旁路拒绝与跨 Owner 原子提交。 |
| R0-03 | 十三域与 W10/host/package | 本账各域行为、运行诊断、迁移/平台链全部闭合。 |
| R0-04 | D11 budget/jobs/clock/native | 四预算/四误差/三时钟在真实 host 的可回放指标。 |
| R0-05 | catalogue/operators/native continuation | 未认证循环拒绝、停止/恢复、认证能力适用边界。 |
| M-01 | GraphStore/typed projections | 七同源视图、来源交叉引用/回放，无第二可写领域真值。 |
| M-02 | namespace/role/scene/activation | 跨会话与角色生命周期、越权、迁移所有内容入口。 |
| M-03 | D07 Concern/D08 commitment | Concern 生命周期/冷却及跨会话承诺驱动与收据。 |
| M-04 | D01 values/growth/authoring | 价值干预、设定迁移与独立经历学习去重。 |
| M-05 | D04/D02/D07→D08/D09 | 分量单变量干预真实改变候选/动作，反证与读出隔离。 |
| M-06 REVISED | D04 continuous affect | 连续混合情绪/调节恢复成本；不恢复旧五阶段机。 |
| M-07 | correction/invalidations/settlements | 更正后的贡献重建；历史感受/已发/费用/模拟不倒改。 |
| M-08 | D05 dimensions/audiences | 对象×领域×场景关系更新/传播与私密回放。 |
| M-09 | D07 simulation/D12 experiments | 隔离快照与预算；不写真实关系、自传、执行权。 |
| M-10 | D01/D08 required checks/final | 价值与硬约束分离，候选比较与现行发送资格。 |
| M-11 | D08/D10 project/life | 项目暂停/恢复、真实产出、有限离线推进。 |
| M-12 | D04/D11 SCC/native | 联合 SCC、完整/局部残差边界与拒绝诊断。 |
| M-13 | bundles/claims/execution | 原子提交、unknown 原身份恢复、重启不重发。 |
| D01 | 第 3 节 D01 | 多会话、设定迁移、价值/人格行为对照及成长采用。 |
| D02 | 第 3 节 D02 | 需求竞争、劳动/休息/恢复与实际行动成本。 |
| D03 | 第 3 节 D03 | 多人/视角/事实性、稳定身份与投递/阅读分开。 |
| D04 | 第 3 节 D04 | 连续情绪采用、表达/行动联测。 |
| D05 | 第 3 节 D05 | 私群/跨群隔离、局部关系更新和渐进修复。 |
| D06 | 第 3 节 D06 | 形成/检索/巩固/遗忘/纠错/删除后重启。 |
| D07 | 第 3 节 D07 | 必查、Concern、公平/冷却、反思和中断续接。 |
| D08 | 第 3 节 D08 | 长期多目标/承诺/实际执行/unknown/补救。 |
| D09 | 第 3 节 D09 | 蓝图/付费核验、多段中断去重与群受众拒绝。 |
| D10 | 第 3 节 D10 | 生活触发、安静时段、离线、实际作品和主动交流。 |
| D11 | 第 3 节 D11 | 暂停/恢复/冲突/取消/陈旧结果/成本/积压。 |
| D12 | 第 3、6 节 | 全服务端编辑/实验/投影/迁移/升级与因果轨迹。 |
| ECO-01 | D11 tenant/D07 concern fairness | 持续高优先级流下服务或审计延期，无重复消费。 |
| ECO-02 | attention tickets/jobs | 暂停/过期/重启现行复核，不补造 tick。 |
| ECO-03 | D08 bilateral/commitment | 双方确认、履约、改约和未确认未知。 |
| ECO-04 | D03 RoleBinding/visibility | 缺绑定拒绝、跨角色可见范围与版本。 |
| ECO-05 | D08/host tool/output sources | 文件/工具实际收据；模拟/计划/失败不升级完成。 |
| ECO-06 | D01/D06 consolidation/strategy | 独立经验与反例、作用域、撤销、历史策略。 |
| ECO-07 | D09 finite segments/dispatcher | 未发段现行重验/撤销，已发与重启不重发。 |
| MEM-01 | Source/Episode/Interpretation/Recall | 时间视角/来源家族去重、真实持久回放。 |
| MEM-02 | encoding/C02/projection index | 有界提取、主体资格、提交崩溃后索引水位。 |
| MEM-03 | retrieval/recall/current evidence | 责任/语义/竞争三通道与无命中原因。 |
| MEM-04 | recall_flow/jobs | 请求全字段、终态、原身份恢复。 |
| MEM-05 | trigger/required recall | 冻结标注集的漏触发/无用触发/提前停止。 |
| MEM-06 | recall policy/D11 budget | 三档全部通道上限，超时/格式失败费、精确分页。 |
| MEM-07 | bounded recall/C04 | 同历史质量/成本、反例/责任覆盖与停止收据。 |
| MEM-08 | recollection/experience | 十次读取只一责任，实际活动独立费用与冷却。 |
| MEM-09 | source/head/access/deletion epochs | 反证/删除/撤权/向量关闭后的失效与覆盖诊断。 |
| MEM-10 | consolidation candidates | 所有巩固出口，独立实例/反例与过期拒发。 |
| MEM-11 | correction dependency closures | 摘要/关系/策略/自传/计划失效和重建审计。 |
| MEM-12 | C09 erasure/rebase | physical/backup/export 清理、closed/reopen 不复活。 |
| MEM-13 | vector channel/generation | 分权限代际、覆盖切换、跨代拒绝与无向量回退。 |
| MEM-14 | projection index/caches | 提交崩溃追赶、正/负查询与缓存覆盖失效。 |
| MEM-15 | projection/migration registry | 离线 preview/中断续接/rollback/历史查询。 |
| OPS-01 | D12 transfer/legacy migration | 真实映射/丢失/冲突/权限预览与原操作恢复。 |
| OPS-02 | Workbench fields/experiments | 各域权威视图、隔离实验与运行诊断；前端展示暂缓。 |
| OPS-03 | memory view/correction | 合同事件/纠错影响预览/不污染查询实验。 |
| OPS-04 | D12 compile/preview/adopt | 各域完整设置、作用范围、历史回退与目录迁移。 |
| OPS-05 | Windows AstrBot/workers | 实机公平/取消/非阻塞/顺序提交/陈旧拒收。 |
| OPS-06 | installer/manifest/ABI/upgrade | 正式包冷装、错架构诊断、升级回滚、真实体积清单。 |
| OPS-07 | OneBot private/group/media/tools | 实机收发/可见性/accepted-delivered-read-unknown/重连。 |
| OPS-08 | G6 production workload | 同 frozen 包 1k/10k/100k、P50/P95/RSS/追赶/日成本。 |
| OPS-09 | G6 four controls/ablations | 同输入/模型/预算四对照、安全门后质量/费用消融。 |
| OPS-10 | 第 5 节八步轨迹 | 同角色 A/B 私群共同项目完整连续回放与实际收据。 |

D13 A01–A08 与耦合 C01–C12 单独保留，不伪装为旧账第 63 项。主模型身份/授权/缓存/窗口费用与 C09 删除闭包必须进入相关 G1/G3/G6。

## 5. S01–S16 与 OPS-10

代表性测试**只说明验收入口存在，本次未运行**。下列路径位于 `rewrite/tests/alpha1/`，宿主入口位于 `rewrite/host_tests/alpha1/`。

| 场景 | 已有入口/机制 | 全轨迹未完成条件 |
| --- | --- | --- |
| S01 含糊短答 | D03 message_arrival/D07 cognition/D09 source_reply | 同输入 D03–D07–D04–D05–D06–D09 各资格与行为对照。 |
| S02 解释纠错 | runtime source_correction_commit、D05/D07 reevaluation | 历史感受/渐进关系/已发内容/补救新意图同轨。 |
| S03 两次回忆不同心境 | integration/test_s03_two_moods_recollection、C04 real-owner/current-input | 两次真实 C04/V3 活动、同一外部事件、当时感受/当前重建及费用。 |
| S04 承诺与疲劳 | D02 body、D08 execution | D10 日程、已确认 DeadlineSpec、shortfall、新劳动延期与合格改约。 |
| S05 A 未确认 B 催促 | D08 bilateral acknowledgement/D03 prebatch social | 多人视角、未确认责任和真实群对话驱动。 |
| S06 私密困难/群抱怨 | D05 audience/Authority reply closure | 私聊进入内部推理后群可见文本与 P2 双重拒泄露。 |
| S07 已发首段/后段失效 | D09 verified batch/runtime current segment | 真多段 effect、首段交接、后段更正/插话撤销及重启日志。 |
| S08 主动 unknown/新里程碑 | D10 contact/runtime current contact/restore | 真主动联系驱动、原 contact 配额/无回应闸门、旧备份不重发。 |
| S09 离线跨日 | D10 offline_interval/offline_ticks、D02 dynamics | 当前可信时钟与生产推进、真实作品/工具产出、未知回应。 |
| S10 工作台改设定 | D12 compile/preview、runtime scheme gate | D01/D02/D04 多域采用/算子切换/未提交任务重验；D09 窄采用已存在。 |
| S11 想象/现实接受 | D07 simulation/D08 candidate | 实际内部活动/费用和后续现实事件、责任/关系严格分列。 |
| S12 余额恶化且劳动未知 | integration/test_s12_resource_shortfall_graph | 生产实际 D02/D11/承诺/平台 unknown 同轨；受控持久图负例不够。 |
| S13 撤权在途 | signed Owner revoke、current fenced reads/paid/P2 | 来源 grant 与 Owner grant 分开；同模型在途/未发 effect/current caches 全轨。 |
| S14 旧备份/删除与主动 claim | stale_graph/cross_process_restore、C09/Authority logs | 最新双日志、D10 配额/D02/D11 未决资源恢复足迹、净化代际物理 closed/reopen。 |
| S15 搬迁源备份复活 | v2_migration_service/store/RPC/installed proof modules | D12 明确缺 prepare/execute 产品入口；真实两端 generation、所有读/订阅/下载/模型/发送门。 |
| S16 迁移/升级失败 | migration registry/resource/Authority deletion migrations | 一般旧用户包导入、影子库切换、升级/降级 crash/disk-full 与双日志不回滚。 |

OPS-10 必须一条顺序轨迹：①项目/A/B/私群/时区/角色设定；②B 催促、A 未确认；③A 私密说明、重新归因但群不泄露；④各方确认后计划/承诺/资源/日程；⑤多段表达中更正或插话、首段已发后段撤销；⑥离线跨日、真实结果到达后履约/生活/关系结算；⑦错误转述与合格更正使依赖链失效而历史保留；⑧跨会话关闭/重启续谈、已发/unknown/承诺/权限不丢失。当前 integration/host tests 是分段机制，未找到该八步完整产品 runner。完成、纠错、重启三处要求原协议故障验收，不能新增临时过渡测试拼出 PASS。

## 6. D12 T01–T40 的后端/前端拆分

### 6.1 当前服务端命令与视图的确切边界

`workbench_api/service.py` / `issuer.py`：

| 命令 | 当前路由 | 剩余服务端条件 |
| --- | --- | --- |
| open_workspace/read_character_view/read_creator_draft | 真实 Owner/Origin/session/graph read route | 所有设计视图的 field contract 与分页/订阅/撤权重验。现有公开合同仅定位 `creation` / `relations` / `d06.memory_sources.v1`。 |
| create_character/bind_scene | 当前 Owner onboarding→W01 typed commit | 真实冷安装创建/绑定与跨私群实际对话；不能自动发测试。 |
| compile_scheme | D01–D10 支持一组受限整字段，另 D04 authored_root V3 | 完整设计可编辑参数、领域 validator 与上下游迁移；字段编译不代表能采用。 |
| preview_scheme | D07/D09 当前策略与付费报告 | 全域合法方案的隔离 preview/差异/费用/故障收据。 |
| activate_scheme | 当前通用 adopt 读 compilation 域仅接受 D09；D04 authored-root 走专用接口 | D07 及其余领域合法 head CAS/重建/回退/消费者接线。D04 V3 当前专门写者更新后另附收据。 |
| correct_or_edit | 窄 source correction/source_access_revocation | 一般作者编辑/背景说明与受影响关系/人格/计划等再采用。 |
| run_experiment | 只接受 `d12.scheme_preview.v1` 的 D07/D09 immutable report | 通用快照/反事实/查询/行为实验、取消/费用/撤权，不发消息不写真实贡献。 |
| diagnose_and_export_support | 只接受 view_health、view_status_only、retention bounded | 完整因果诊断与可授权数据导出；当前窄支持包不代表一般备份/分享。 |
| erase_or_retire | 当前 C09 prepare + current accepted 端口 | 累计 closed/ACK、物理净化所有受管副本/重开与角色停用/退休。 |
| prepare_transfer/execute_transfer | **服务层明确 unavailable；issuer route=False** | 共享/备份/复制/整角色迁移模式，当前双端 proof/损失/conflict、唯一激活与恢复。 |
| install_or_upgrade | **服务层明确 unavailable；issuer route=False** | 受信 release/admin installer、目录/native ABI、影子迁移/切换/回退。 |
| configure_or_control | **服务层明确 unavailable；issuer route=False** | 实际领域配置/暂停/取消/停用/卸载，不能用可调用目录冒充成功。 |

### 6.2 全 T 场景范围

| T ID | 本轮服务端必验 | 暂缓的纯界面部分 |
| --- | --- | --- |
| T01 | 无 Rust 正式冷装、ABI/版本/存储和启动 | 安装页视觉交互。 |
| T02 | 原子最小角色创建、绑定与默认值来源 | 页面向导。 |
| T03 | 各视图状态/覆盖/错误协议与真实数据 | 逐页日常操作体验。 |
| T04 | 每域 typed writer、无改图后门 | 编辑表单。 |
| T05 | 单域/schema unavailable、无关域可继续 | 错误展示。 |
| T06 | 严格字段/数字/脚本拒绝与领域诊断 | 字段提示排版。 |
| T07 | 旧 draft digest/concurrent adopt 拒绝和三方差异 | 冲突比较界面。 |
| T08 | 单 active head、重建阻断/回退/水位 | 激活进度界面。 |
| T09 | authored/reported/background/admin edit 资格分开 | 来源选择交互。 |
| T10 | 各域版本/因果，不伪造通用总分 | 同屏呈现。 |
| T11 | 时间/分页覆盖/未知，未扫完不称无记录 | 时间线交互。 |
| T12 | source correction、后果与原历史 | 纠错向导。 |
| T13 | observer/maintainer/creator 服务端权限 | 按钮显隐。 |
| T14 | 未认证/Origin/过期 session 拒内容和旧能力 | 登录体验。 |
| T15 | 切域/撤权后 cursor/订阅重新资格、缓存失效 | 清屏/重连状态。 |
| T16 | 全局搜索/diagnostics 无存在性泄露 | 搜索布局。 |
| T17 | model/numeric/semantic/unknown 分阶段事实诊断 | 诊断呈现。 |
| T18 | 实验无发送/工具/正式贡献权，实际费结算 | 实验页面。 |
| T19 | 实验撤权/删除同步重验 | 状态反馈。 |
| T20 | 实验建议重新领域编译，不升级故事 | 采用建议交互。 |
| T21 | 分享/私史备份/复制、默认无私史/凭据 | 模式选择界面。 |
| T22 | export 封装/下载前删除/撤权重验与净化 | 下载界面。 |
| T23 | 旧备份双日志最新性/已删/已发/unknown 恢复 | 隔离恢复界面。 |
| T24 | 创建/纠错端点的准确操作合同仍保留 | **键盘/窄屏/缩放/焦点/颜色辅助整体暂缓**。 |
| T25 | source 旧 generation 所有内容入口拒绝、新端双锚 | 搬迁 UI。 |
| T26 | 旧好感/未知来源映射和丢失预览 | 导入 UI。 |
| T27 | 导入 crash/cancel/replay 原批次与半开放拒绝 | 导入进度 UI。 |
| T28 | path/reparse/archive bomb/size budget 拒绝 | 上传交互。 |
| T29 | upgrade crash/disk-full、单版本/双锚/未决足迹 | 升级进度 UI。 |
| T30 | 在途任务 drain/unknown、数据保留/删除/卸载 | 停用 UI。 |
| T31 | 新写入后无合法 downgrade mapping 拒绝 | 降级 UI。 |
| T32 | 架构/ABI/库/hash 加载前具体拒绝 | 修复引导页。 |
| T33 | Windows 全插件实机；Linux x86_64/Mac arm64 原生 | 各平台客户端外观。 |
| T34 | 私群/重载/断线/model failure 与真实收据 | 可见前端反馈。 |
| T35 | 正式包逐文件 hash/来源/SBOM/许可/size/排除 | 无前端豁免项。 |
| T36 | drafts/experiments/support/backups 删除闭包及物理退役 | 删除向导。 |
| T37 | bounded pagination/graph/upload budgets 与其他会话不阻塞 | 大图虚拟化。 |
| T38 | 维护/实验 cancel/timeout/original receipt/budget/fee | 队列控制页。 |
| T39 | 时区/DST/units/invalid fields 服务端语义必验 | **读屏删除及参数操作暂缓**。 |
| T40 | 后端安装→相处→纠错→实验→迁移/恢复全轨 | 全页面连续操作暂缓。 |

## 7. G0–G7、现有验收入口与缺环境

| 门 | 当前可复用的最终验收入口 | 仍缺与不能替代的条件 |
| --- | --- | --- |
| G0 | 原 Authority/graph/current/fence/recovery tests；production bundle/原操作恢复端口 | 当前完整领域编译与实际 fault/restore/fencing；C09 物理代际、migration 全入口不能因局部 TLS/SQL 通过。前端编译按本轮范围暂缓，后端编译先行。 |
| G1 | 十三域验收稿、62 项、当前 registered provider | 第 3 节各领域行为驱动和最终轨迹；目录 complete 不是 DONE。 |
| G2 | `rewrite/native` Rust、`scripts/alpha1/native_kernel_smoke.py`、固定块 math、D04/C04 既有 gates | D04 formal pin/完整来源/采用、语义/人物单变量干预；ABI2 单次数学证书不等于全产品认证。 |
| G3 | `integration` 的 S03/S12/S13/S14/C04/C09、true-owner/daemon/natural/restore tests | S01–S16 和 OPS-10 全轨，不拼接不同 donor/hash/时间的局部日志为同一轨迹。 |
| G4 服务端 | WorkbenchService→issuer→当前 W01 Owner routes、T 服务端部分 | 第 6 节未接命令/视图、一般实验/编辑/迁移/升级。W11 UI 验收暂缓并明确分列。 |
| G5 | `rewrite/host_tests/alpha1`、installed true-owner daemon/natural handoff 受控入口 | **真实 Windows AstrBot + 真实 model/provider + OneBot 私群/附件/工具**；restart/reconnect/hot unload。accepted、delivered、read 分开，当前发送 adapter 仅能证明 accepted 或 unknown。 |
| G6 | `integration/g6_graph_scale_probe.py`、`scripts/alpha1/benchmark_backend_sources.py` | 两脚本都是合成直接 GraphStore 软件基线；缺生产 Authority/GraphCoordinator/完整域/模型/平台积压、同包阈值、实际 provider 缓存/日费用、OPS-09 四对照/消融。不能重跑这两个脚本就宣布 G6。 |
| G7 | `audit_backend_candidate.py` build/audit、`verify_formal_cold_install.py`、delivery assets/Native probe | 真实 formal version/clean frozen source/runtime_verified catalogue/native hash/外部 publisher root、installer/ACL/clock、完整 root→十三域→W10 trace 与 upgrade restore。diagnostic_only ZIP 明确 cold_install_pass=false。 |

### 7.1 已存在脚本的用法边界（本次没有执行）

| 脚本/入口 | 适用工作 | 验收边界 |
| --- | --- | --- |
| `rewrite/tools/verify.py`、`verify_host.py` | 已有核心/受控 SDK 验证入口 | 旧 fixture/受控 host，不证明真实平台或全部 backend。不要无理由反复跑全套。 |
| `rewrite/tests/alpha1/integration/g6_graph_scale_probe.py --size 1000/10000/100000 --output ...` | 同源码 GraphStore 软件梯度 | 独立进程、合成数据、直接图路径；9/28 已有历史梯度，不需以重跑代替产品 G6。 |
| `scripts/alpha1/benchmark_backend_sources.py --full --output ...` | 有界合成 source ladder | 源码自述 never a product OPS-08 pass。默认 100 sources 不是正式验收规模。 |
| `scripts/alpha1/native_kernel_smoke.py`、`probe_current_platform_package.py` | 平台 ABI2 load/代表性求解 | dev-probe/diagnostic 与正式 candidate 分开；在对应 OS 本机执行。 |
| `scripts/alpha1/cross_platform_build.py --backend-only-dev-probe` | 开发原生核构建/包探针 | 不可改名当 alpha1。Mac cross-check 不是 dylib 本机加载。 |
| `scripts/alpha1/audit_backend_candidate.py build/audit` | 最终包逐文件核验与外部 inventory | 需 expected-source-commit/catalogue/native/platform、formal 版本和冻结树；先前构建前置规则见 `scripts/alpha1/BACKEND-CANDIDATE.md`。 |
| `scripts/alpha1/verify_formal_cold_install.py --package ... --expected-manifest-sha256 ...` | 隔离正式包机械加载与资源/native 资格 | 不替 publisher distribution root、真实 host、model、平台或完整域验收。 |
| `windows_backend_cold_diagnostic.py` / `authority_staging_probe.py` | 诊断目录/源码 staging 子进程和 mTLS | 产物明确 diagnostic_only / cold_install_pass=false。 |
| `authority_installer.py`、`authority_windows_service.py`、`authority_windows_scm.py` | 管理员 Windows 服务部署现有入口 | 仍需正式 package/publisher trust、真实 ACL/服务身份/clock、Core/graph/journals/受信 callbacks 全装配，不能从脚本文件存在推定安装通过。 |
| `authority_execution_schema_upgrade.py` | 既有执行日志特定 schema 维护 | 不是一般插件数据升级/降级/影子库迁移与 D12 install_or_upgrade。 |

正式最终验收应由主任务在产品链闭合后按冻结验收合同执行必要场景；本盘点不新增测试，也不建议用临时过渡测试推进标记。

### 7.2 必须逐项取得的外部/安装提供者

1. **Windows 产品宿主**：实际 AstrBot 版本/运行 Python/安装根与 package hash、Authority 与独立两日志/Owner/private key/scene 配对；冷装、初始化、热卸载、停止在途、重开在真实进程证明。
2. **Publisher/安装信任**：外部固定 trust root/manifest 与 native/正式 C04 V3 pin；安装者 OS token/ACL/服务身份、文件路径/句柄排他；不能由候选包自证可信。
3. **可信时钟**：与安装 clock_policy/source_id/误差上界相符的实际授时提供者及时间误差收据；clock handshake 本身不是物理 UTC 精度证明。
4. **真实模型/预算/usage**：生产 provider/model/config、授权凭据、父预算/currency、失败/unknown/真实费用、输入/缓存 usage。受控 Mock paid receipt 不是外部付费实测。
5. **D13 exact pre-call wire counter**：当前适配器只有响应后 usage/字符估算；缺同完整 frozen wire 的受信 exact count 提供者，不能降低为 estimate 自动放行 paid compression。
6. **真实平台**：已授权私聊/群聊操作者与测试账户/adapter/current scene；OneBot accepted/unknown、断线、在途撤权、群私隔离；工具/文件/媒体动作还需真实 provider 与原观察 verifier。
7. **迁移/恢复设备或隔离安装**：两端 current pairing/graph snapshot/Owner head/latest deletion+execution proofs、唯一 generation，源端旧备份全部内容入口拒绝；当前 D12 transfer routes 明确缺接线。
8. **受管物理库存/备份**：C09 graph/core/journal 净化新代际与 V4 恢复事实、writer isolation、DB/WAL/SHM/备份/导出/缓存冷复扫、旧副本退役与 ACK；只有 tombstone/pending/accepted 不等于 closed。
9. **Mac arm64 实机**：对应源码 native build/link/load/native tests/代表性 solve；Windows `cargo check --target aarch64-apple-darwin` 缺 xcrun/SDK/linker，历史 CI 不覆盖本轮最终源码。Linux x86_64 历史 WSL 原生核可用但须绑定最终源码/native hash；Linux arm64/Mac x86_64 不挡本轮。
10. **G6 冻结输入/阈值/评价**：硬件、真实模型、预算、1k/10k/100k 数据指纹、可用性阈值，四对照/消融的同输入质量评审和实际费用；不得看结果再降低阈值。

## 8. 交接完成条件

本账交给主任务作为完整后端漏项索引。每个写者只更新自己获派接口的“当前 source → 正式产品入口 → 领域行为后果 → 原操作/fault/recovery → 当前源码/包指纹 → 实际验收收据”，不能提交运行数据、凭据、完整日志或 native build outputs。单一 GraphCoordinator/RuntimeContext 写者负责共享接线，领域写者不能开旁路库。

主任务应以最终源码重新核对本账中失效的静态“未找到调用者”项，然后按实际产品链做必要验收；所有缺环境项逐条给手动方法与资格前提。源代码实现全部完成与 G0–G7 实机/构件验收全部通过必须各自诚实标记。当前不存在可据本盘点授予的正式 alpha1 完成状态。
