# 2026-09-30 全后端总装实施契约

本页为 Astra high 根据当前源码与已有合同作出的实施裁决；状态是**待实现/待产品验收**，不是完成证书。用户本轮范围是完整十三域及工作台服务端、宿主、数值核、恢复、规模、后端构件；前端暂缓，不 push、不建 PR、不发布。当前共享工作树的唯一文件写者继续有效。本页不改源码、不执行模型/平台发送、不访问真实运行数据库、不运行测试。

依据为 `architecture-gate.md`、`task_plan.md`、`c04-internal-work-protocol.md`、`c04-current-association-v3.md`、`d04-appraisal-admission-v2.md`、`d04-joint-product-path.md`、`d04-joint-state-output-v1.md`，以及各域 contracts 与 `docs/architecture/sylanne-3-thirteen-module-coupling.md`。本页补足可执行接缝，不取消这些合同的领域所有权、恢复、数值或真实费用约束。C09 跨存储控制指针由本轮 C09 专属裁决负责，本页仅消费其清理/迁移准入原件。

## 1. 本次静态核对的具体差距

1. `GraphCoordinator.prepare_internal_work_v1` 是固定 HOLD。现有 `InternalWorkBindingV1`、`C04InternalWorkPreparedV1`、V3 冻结输入、安装条件投影、结果解码及五写 adoption plan 可复用；缺的是当前 Owner 准备事务与生产调用。
2. `c04_adoption_plan_v3.py` 当前把调用方 interpretation 解码后再调用 `current_interpretation_write` 生成 expected。它证明写格式一致，尚不证明命题/立场/家族由受信当前 D07 产生。最终采用必须改用下述安装 issuer 重导。
3. `c04_cpu_quote_policy.py` 的 `d02_settlement_refs=("c04.cpu:"+quote_id,)` 不是合法 AtomKey，而 D02 成本阶段会调用 `AtomKey.from_token`。必须在签名前生成正式 activity settlement key，同步严格复读；不得在签发后修改 quote。
4. `AdminD04SemanticDrivePolicyV1` 仅验证调用方剂量上限，`family_drive_v2.py` 明确还缺语义映射采用原件。root/joint/baseline 可用不等于 appraisal→drive 已打通。
5. D01 values/growth、D02 passive/work effect、D07 Concern/reflection/simulation、D08 bilateral、D10 life/offline/contact 的纯域实现必须接生产事件驱动与 W01 提交；可导入、已注册、静态返回候选都不能签 G1 完成。
6. D12 transfer/install/control 与完整隔离实验须接真实维护服务。`experiment` 仅复用 scheme preview 不覆盖领域实验。迁移/升级/配置不能由浏览器提交引用后直接造成功。
7. 打包器现有独立 `--backend-alpha1-candidate`，保留 `candidate_only/HOLD` 且校验生产资源与实际 registry。`scripts/alpha1/BACKEND-CANDIDATE.md` 开头要求先过所有门再构建的文字已不适用于验收候选阶段，应由 W12 同步修正文档。

上述为本次阅读时观察到的缺口；并行写者可能正在修改相应文件。不得据此覆盖其已完成工作，应按当前接口交接。

## 2. C04 prepare V3 的真实外部 API

新增 `GraphCoordinator.prepare_internal_work_v3(authority, lease, *, envelope, cue_source_ref, context_tags, budget, body_policy_id, body_policy_version, cpu_policy_id, cpu_policy_version, reservation_id, execution_id)`。`budget` 为 `AssociationBudgetV3(max_hops,max_edges,max_nodes,max_iterations,max_candidates)`，沿用现有上限 2/128/128/64/32。请求可以降低已安装上限，不能提高。`authority/lease` 来自当前签名 Owner，namespace/activity/operation/effect/purpose/audience/deadline/父预算来自 envelope。

当前 focus/ticket/Mood、各 source 的编码 operation、projection policy/readout、算法 ID/build 都由 W01 安装态和当前图解析，不接受调用方指定一份权威 work、任意 callable、binding、quote、CPU actual、terminal 或已认证坐标。若内部帮助函数接收预构造 `AssociationWorkInputV3`，它只是候选；W01 必须从当前 collector、安装 D04/D07 issuer 重导并逐字段相等后采用。

返回版本化 `PreparedAssociationWorkV3` 结果：原 prepared、binding、冻结 input 的可复读引用与摘要、资源原件引用、job/operation 查询引用和 `prepared` 状态。返回 prepared 不表示实际回忆、执行完成、费用结算或最终采用。

### 2.1 事务与签发顺序

安装 schema 在运行事务前完成；尤其 `install_c04_frozen_association_original_v3` 使用 `executescript`，不能在已经开启的 prepare 事务中调用。执行顺序固定如下。

1. 围栏外取得可信时钟、Authority 当前 anchor、activation generation 和操作状态。相同 operation 先查原件；同 ID 不同请求摘要返回 conflict。claim 或未知执行存在时仅查询。
2. 开始 Owner `write` fence；由 `_owner_binding_in_fence` 核当前 session/grant/能力 `c04.internal_work.prepare`、主体、namespace、audience/purpose 与 generation。Authority RPC 结束后再进入共享业务库 `BEGIN IMMEDIATE`，不持图锁等待 RPC。
3. 复读当前元数据、Owner 依赖、D07 focus/ticket/签发来源/TTL、D06 来源访问/更正/祖先闭包、D04 当前 Mood/checkpoint/已采用 joint output、每个可选 source 的历史 baseline，及关联边的有界正负查询。collector 完成覆盖证明；有界截断如实入 input，不假称完整检索。
4. 从当前 D07 合格 cue 签准备 SelectionTicket，从 D04 安装资产重导每源 V3 条件投影，构造内容输入。cue 必须有其自己的 baseline/condition。某候选缺合格 baseline 时不参与条件排序；排除记录属于覆盖/缺口，不以今天 Feeling 回填历史。
5. 用 **pre-quote envelope** 调 `C04InternalCpuQuotePolicyAuthorityV1.request_quote`，其中 `resource_lease_versions` 为空。D02ResourceIssuer 对返回的真实 ResourceQuote 签发并持久保存。保留这份 pre-quote 请求字节，不因后续 guard 增补而重写原请求。
6. 读取 BodyProfile/BodyState 及活动预留的完整当前集合；由 `D02BodyQuoteAuthority.issue_fixed_quote_and_reservation` 签固定 BodyQuote 与 Reservation。当前状态、全部在用/unknown 预留、政策/报价有效期进入读集，不能仅检查新 activity 是否为空。
7. 通过 W01 的 D02 CAS 写 Reservation；预留不减少 BodyState 的 gross energy。若使用 reserve receipt hook，同一事务内在该 CAS 后读当前 graph epoch，将它作为冻结 input 的观察 epoch。内容 head 仍须与第 3 步一致。prepared 中 body state revision 是实际当前值，reservation revision 是新保留后的值；不凭预设 `+1` 代替实际收据。
8. 冻结 input 的语义 digest 不含未来结算/terminal/bundle digest；graph epoch 是观察元数据。构造 `InternalWorkBindingV1`：准确 namespace/activity/operation/execution/input、两种 quote 的原 ref/version/digest、BodyReservation AtomKey、component ID、父预算/generation、安装 algorithm/build。`policy_ref` 固定等于 CPU policy 规范身份，即现有 CPU quote 的 `snapshot_ref = "c04cpupolicy:" + canonical_digest(cpu_policy)[:48]`；Body policy 通过独立 quote 原件绑定，算法数值政策在 work.policy 内绑定，三者不混用。
9. binding 完整后才调用 D11 reserve：`operation_id = "c04-internal-budget:" + binding.binding_digest`，reservation digest 为 `binding.binding_digest`，ceiling 为签名 quote 原值。这样不存在“先 reserve 需要 binding、binding 又依赖 reserve receipt”的循环。prepared 记录原 reserve receipt JSON 字节的 SHA256，与现 `d11_c04_internal_cost.py` 的复读算法一致。
10. 记录 `C04InternalWorkPreparedV1`、`AssociationWorkInputV3` 原件及唯一 persistent job，全部仍在同一业务事务。input 必须与新 Reservation 之后的 graph epoch 一致，但冻结内容闭包不包含会在随后成本结算中必然改变的 D02/D11 账务 head。
11. CAS receipt、原件、job 都成功才提交事务并完成围栏。签名 quote/body quote 或 reserve 任一失败全部回滚。不得留下无 frozen input 的可执行 prepared，或先提交资源占用再尝试补 input。

实际 helper 可以把“生成原件候选”和“CAS 后记录”分成两个函数，但必须由同一 W01 事务包裹。与 reserve CAS 关联的 request/receipt 摘要分别保存；不得用最终 adopted bundle 摘要提前命名 prepare。

source→baseline解析采用安装选择政策`latest_eligible_encoding.v1`：只考虑同namespace、同source精确当前revision、拥有真实encoding/joint原件、as_known_at不晚于可信prepare时刻、当前audience/purpose仍合格的认证baseline。按`as_known_at降序、encoding_operation_id字典升序、original_digest升序`选第一；同operation异digest是冲突而非合法并列。cue无合格项则HOLD，非cue可排除并记录缺口，旧unknown不能作候选。冻结选择原件及候选集合/缺席查询覆盖；final若出现新的baseline使latest选择改变则stale，不在原work内换原件。受限枚举不完整时deferred，不用未完成查询的LIMIT结果假称最新。

当前Mood由D01活跃lineage与已采用D04 current head解析，不能扫描全表后挑唯一/第一个Mood。authored与legacy数据并存时，活跃lineage必须明确唯一；authored Mood也须拥有已采用joint输出和当前checkpoint证明，仅root初始化不够。现C04 V3 wire对legacy `mood_field/feeling_state/numeric_checkpoint`作严格类型约束，authored路径须新增显式schema variant与decoder/build pin，不能把authored token伪装legacy或静默放宽旧wire。排序数值函数可以复用，来源schema和签发资格不能混用。

本轮具体分版冻结为`c04.current_association.authored.v3.input`及`ProjectionMemberAuthoredV3/D04EncodingBaselineAuthoredOriginalV3/D04CurrentSalienceConditionAuthoredV3/AssociationTargetAuthoredV3`；nested schema同样携带authored discriminator。legacy DTO拒authored，新DTO拒legacy，mixed input整批拒绝。沿原canonical serializer/digest算法，schema/type discriminator本身进入摘要；旧wire与旧digest逐字保持。activation/ranking数学不变时algorithm ID可继续`d06.association_activation.v3`，但新build pin必须覆盖实际新增codec/collector/issuer/政策/算法依赖字节。terminal result绑定实际authored input digest，禁止转成legacy再hash。

prepare 必须同事务创建 queued job，不能等 final 才造 completed 归档。job kind 使用已注册 `d06.c04_internal_cpu.v1` 或 catalogue 已有的等价固定键，continuation 只引用固定 binding/input/prepared/algorithm/build/execution 身份。worker 每次先 Authority inspect：无 claim 且当前执行资格完整才执行首次启动；claim-only 转 waiting_for_confirmation/inspect-only；有 terminal 只导入、结算和尝试合法采用。job lease 重取不重新授予启动权，不能生成新 execution ID。final CAS 原 job 状态；成本已结但采用 stale 的状态必须区别于成功回忆。job 创建本身不触发同步执行。

### 2.2 prepare 与最终 read set 的版本意义

`content_reads` 包含来源/访问/更正及祖先、关联边和查询覆盖、focus/ticket、Mood/checkpoint、D04 baseline/安装资产、角色/解释必要依赖。缺席 key 用实际 revision 0 读证明；存在但 invalid 的行仍有自己的 revision/value digest，不能改写为缺席。

`prepare_accounting_reads` 包含 BodyState/Profile/已有 reservations、CPU/Body policy、父预算/签名 grant、原 quote 和准备 CAS 的读集。它证明当时合法预留。`settled_original_refs` 证明随后同一 binding 的实际 D02/D11 入账。最终采用核当前身体资格和真实已付收据，不要求成本结算前的身体 revision 仍是当前。

禁止最终将 `graph_epoch == work.graph_epoch` 作为一刀切条件。成本结算推进 epoch 是合法的。最终重读内容闭包、查询覆盖和有意义的权限/Owner/代际；发现新边、权限/更正、Focus/Mood 或资产变化则拒绝旧采用。prepare 存储函数内的 epoch 精确一致仅证明其写入当刻的一致快照。

### 2.3 原件释放与执行资格

Authority 读取 prepared/frozen 原件须经过安装配对、namespace/安装身份、当代 Owner/来源访问/删除屏障校验，并绑定预期 binding 和 input digest。获得 frozen bytes 不表示可以任意执行：仅已安装 `d06.association_activation.v3` 及其确切 build 能消费首次 claim 启动权。

claim 前撤权拒绝新执行；claim 后撤权仍允许按原身份追加已经发生的终态/真实 CPU，不能继续解封被撤销正文或采用经历。重新查询 terminal 可返回有权限的无内容费用收据；输出正文解封另核当前用途/访问。禁止用“费用必须结算”为由扩大内容权限。

Authority 完整/failed terminal 必须先进入独立耐久链。crash 导致 claim-only 为 unknown，保持占用；不补跑、不把 actual 写零、不换 execution ID。terminal 已耐久但业务 ACK 丢失，导入同 terminal；未 claim 取消只有独立权威能证明启动权未消费且取消已耐久时才释放。具体 generation 和内容清理规则消费 C09 裁决，不另造指针。

### 2.4 过期、撤权后的历史费用收口与 job CAS

源码现状是`plan_job_acquire`在`now>=deadline`拒绝取得worker lease，`commit_current_c04_body_cost_v2`要求当前Owner具备prepare能力且BodyState/Reservation仍等于prepared版本。前者是正确的新执行门，不应放宽；后者不能兼作撤权后的历史收口入口。

新增安装system入口`reconcile_historical_c04_cost_v1(namespace,operation_id,binding_digest,terminal_locator)`，它不是普通Owner内容命令。配对安装reconciler只获得该namespace的`historical_cost.reconcile`能力和当前holder/generation的专用accounting fence。原binding的旧generation、Owner grant、deadline、execution/input身份作为历史原件保持不变；当前迁移目标写入时另记录当前reconciliation generation和迁移关联，旧holder永远不能继续写。暂停/Owner撤权不撤销已发生支出之事实，但当前存储/迁移/删除屏障仍必须验证。

围栏外从Authority独立原件签发/复读`HistoricalInternalCostEvidenceV1`，只含namespace/install、原operation/activity/effect/execution/input/build/binding、claim/terminal IDs和原摘要、actual CPU、component completion ref/digest、quote/parent budget和历史generation。不得返回work/source/result正文。它是独立权威对原终态的无内容投影，须携带原proof digest及可验证投影身份；不能把调用方删掉output_json后的terminal重新hash冒充原签名。已有CPU importer可在持有合法完整proof的当前路径继续使用；撤权/已清理内容的恢复路径消费该专用投影并核同一原binding，不为计算费用重新解封内容。

在短accounting事务内逐项复读不可变prepared、ResourceQuote/BodyQuote、原D11 reserve及BodyReservation历史身份、已存在CPU/Body成本原件。只接受精确原件匹配，不能因quote已过有效期而否认当时已获准并真实发生的工作；也不能借历史quote启动新工作。CPU按独立terminal actual入账，沿用现有overrun表示，不截断上限。D02仅在原固定component完成收据真实可复读时按原fixed_cost结算；failed终态没有完成组件则不扣该组件，可释放已证明未消费部分；claim-only无权释放或记零。

D02历史路径从**当前同一账链**的BodyState/Reservation CAS，原prepared revision作为祖先身份，不强求账面永远停在准备时版本。必须证明当前state/profile lineage、原reservation quote/effect/component和消费账连续，按稳定component receipt去重；同terminal已结则返回原收据。不允许仅删除旧方法的Owner检查、直接向任意当前state扣款。新三写的state/reservation/settlement与immutable body cost original同事务；原实际费用不能由失败的体验采用撤回。

若当前身体余额不足、原件已清理、账链无法衔接或C09已经销毁BodyState，不重建已删除状态、不写负余额、不伪造完全结清。保存可验证的无内容historical cost/debt original，状态区分`settled/overrun/unpaid_requires_reconciliation/target_erased`，保留金额、原组件和原因，阻断新支出；后续真实修复另有收据。此时工作事实已记录，不宣称身体账已全部结清。C09的最终擦除要求仍决定哪些最小元数据可保留，不能以不可变账为由恢复正文。

历史job收尾新增`reconcile_c04_job_terminal_v1`，不调用acquire/普通worker transition，不改deadline、不换execution、不新建可执行job。它在最后一笔短事务复读实际成本收据并比较原prepared job与当前job整行摘要：namespace/op/activity/effect/execution/input/quote/budget/build、phase/fence/cancel_epoch、continuation/result/usage。CAS同时追加不可变`C04HistoricalJobClosureV1`并清lease、递增fence使旧worker无法final，cancel_epoch不降低；usage保持单调，独立closure保存精确actual。如旧usage与实测矛盾则显式anomaly，不篡改实际量凑单调。

job状态固定规则：

* claim-only/unknown没有终态成本：保留预算/身体占用，非终止job转`pending_confirmation`，deadline不动；恢复调度是原身份的查询工作，不能通过wake/acquire将过期job变回可执行。已取消job的phase保留，同时记录未决原件。
* 真实failed：记录实际CPU，无证明的身体组件不收费；按取消状态保留`cancelled`或转`failed`并引用历史closure。
* 真实completed但过期/撤权/代际改变而不具备采用资格：closure明确`execution=completed,adoption=not_adopted`。非已取消job取`failed`并用closure作为result_ref；已`cancelled`保留phase补账，避免`completed`被消费者误解为回忆已采用。若未全部结清，closure附accounting缺口，不发成功结清信号。
* 已有相同历史closure精确重放返回原件，异terminal/摘要conflict。已有合法最终adoption receipt的job不能被历史路径降级；只补尚缺费用记录并复核一致性。

成本原件可以先独立持久，job closure在末尾重核后提交；崩溃只重放缺阶段不重执行。当前成功经历采用仍需原running fence、有效deadline及当前Owner/来源资格。历史accounting能力不能进入final adoption、来源读、外送、身体新预留或执行入口。

## 3. D07 当前候选与 C04 最终采用

### 3.1 准备 cue 不是最终回忆选择

W01 必须使用 `read_qualified_focus_attention_ticket` 和当前原 attention issuance/采用记录；图中有一个 shape 正确的 ticket 不足够。准备 cue 在其合法 `source_refs` 中，时间、Owner、audience/purpose、祖先闭包完整。使用真实 cue SourceRecord 构造只含该源的 CandidateSet，调用已安装 `D07DomainProvider.select_recollection` 产生准备票即可，无需先运行 CPU 排序。

准备 activation=0 表示尚未排序，不能解释为实际排序结果或事实置信度。allowed purposes 是实际 source/access 交集。candidate set ID 按 `d07.c04-prepare-cue.v3`、namespace/operation/activity、cue ref/revision/content digest、focus/ticket refs/revisions/epoch、audience/purpose、policy/algorithm/build 规范摘要导出。prepare 票只保存于 work input，不写成已发生的最终 selection。最终票 ID 加不同 phase，以结果 digest 确定。

最终联想选中源可以是 cue 遍历发现的新合法 source，不要求预先在原 attention source_refs 中。它必须属于同一 frozen input 的合格 targets、同 Authority terminal result 和同一当前授权闭包；原 focus/ticket 必须未变。旧 `bind_current_c04_focus_v1` 中要求 selected 已在原 ticket 的约束不能原样套 V3。

### 3.2 合法解释 issuer

新增 D07 纯入口 `issue_current_recollection_interpretation_v3(work, result, selection, source_heads, interpretation_originals, installed_policy)`；它只由生产 W01 从当前/历史原件装配调用，不能接受 caller proposition 当作受信输出。它返回 typed candidate 和可重导的 provenance payload。

该接口支持以下真实语义来源，不强迫额外模型调用来制造回忆采用循环。

* `recollection_presence`：固定政策只签“本次回忆选中了来源 S 所记载的内容”这一主观回忆命题。它引用精确 source 原文或结构化指针，不推测他人意图。现有 DTO 必须显式记录 `stance=SUSPEND`、`evidence_status=INSUFFICIENT`、`subjective_conviction=0.0` 作为**对外界命题未作支持评估**的政策哨兵，并在 meaningful_unknowns 标注未重评外界真实性、语义校准未完成及原 assertion_status；这不是用零表示中性情绪，也不是自报来源假。若以后增加不同评估，应升政策版本，不暗改哨兵含义。
* `adopted_interpretation`：复读该 source 对应、当前仍有效的已采用 D07 interpretation/belief，严格保留其中 proposition/stance/conviction/evidence/unknowns，仅生成本次活动的派生引用，当前原件及其来源头进入 final read set。历史基线里的旧解释只能明确作 then-meaning，不能直接冒充 current。
* `paid_cognitive_candidate`：需要新语义解释时走独立已冻结认知请求→实际 D11 模型调用→耐久结果→成本→D07 adopted original。模型是候选来源，最终 W01 current admission 仍必需；费用与 call ID 不能由 DTO 自报。

source_families 来自 D06 祖先/贡献家族闭包，按唯一根规范去重，不把 source ID 一律当独立家族。conditioned salience/tone 只改变主观联想，不提高 evidence status 或 conviction。支持多个分支的上层可选策略必须在安装 policy 固定；同 operation 重导必须得到相同结果，不能为了通过 CAS 换分支。

candidate/provenance 摘要绑定 work.input_digest、result.result_digest、binding/execution/build、selected source ref/revision、focus/ticket 版本、current interpretation 原件、namespace/activity/operation、audience/purpose、Owner/access/delete epochs 和 activation generation。结果到达后当前权限或结果代际改变，保留已发生成本，拒绝其内容采用。

固定`recollection_presence`政策允许作为安装代码资产：Runtime仅从manifest pin的`domains/d07/current_issuer_v1.py` frozen常量构造`InstalledCurrentInterpretationPolicyV3`，记录policy_id/policy_version、mode、常量canonical digest、module SHA、installation/build；这些身份进入prepare/final provenance和重导。无需为此伪造资源READY或新schema资源。调用方不能替换常量/选mode；另外两类语义政策依其实际安装配置及原件独立准入。C04 source inventory/build必须真正hash该issuer、政策常量和依赖源码，不能只把文件名列入清单。

### 3.3 最终写事务

围栏外经安装 Authority verifier 复读真实 terminal；围栏内核 Owner、权限、安装身份、内容正负 read set、query coverage、原件及已结算费用。最终 bundle 仍严格为三个 domain proposals、五个领域写：D04 recollection experience、D06 recollection/projection、D07 selection/current interpretation。W01 调用上节 issuer 从真实原件重导 expected 五写，不从待验 candidate 自己重序列化作为资格。

五个新图键逐个预读 revision 0。job 状态、outbox、贡献去重、C04 adoption plan/receipt 写既有 runtime/原件表，与五写在同一业务事务提交。它们不是新增伪 domain proposal；若既有 job 是 typed runtime atom，应通过既有 runtime staging 协议同事务采用，不塞入 C04 五领域写集合。job/outbox 使用 operation+phase 的稳定 key，读现有 row version/state 或明确缺席；outbox 只通知后续调度，不是发言资格。

D02/D11 原件由同 binding、terminal、CPU actual、Body component、parent budget 精确交叉核验，最终只引用，不再写第二次 settlement/reserve。未采用的成功工作保留已付成本但没有经历。相同 ID 精确重试返回原 receipt；未知提交先查原 operation。取消/删除只能阻止未来采用，不能抹除已发生的计算支出。

## 4. D04 从评价到后续联合推进

### 4.1 生产 drive 输入

Owner 采用的 authored root revision 1 仅为初始化。`advance_current_d04_joint_v2` 必须读取当前成员 checkpoint/state、采用原件和继承误差，新的 continuation 执行 current CAS 与新的证明；不能每次回到 root 或重贴旧 proof。

新增生产 `prepare_current_d04_appraisal_v1` / `adopt_current_d04_appraisal_v1` / `compile_current_d04_drive_v1` 接缝。请求只指定有权的 source/场景与活动目的，运行时复读 D01 active role/PersonaView/RoleCondition、D03 perspective/entities/现实性、D05 boundary、D07 当前解释/竞争解释、D06 访问/更正/家族，以及版本化 mapping asset。先冻结 appraisal request、原始输入字节/来源 closure、安装 provider/template/model、quote/job/call ID。响应按原调用耐久保存且 D11 费用入账后，解析 `AppraisalBundle/MeaningFacet`，D04 验证并由 W01 采用主观评价原件。

`compile_current_d04_drive_v1` 的输入是这份 adopted appraisal ID 及目标当前成员引用；不得接受裸 signal/dose。已安装语义映射由机制信号、D01 角色/条件和固定 gain/分层规则确定 24D 剂量，保存每个未知维度与映射原因。`AdminD04SemanticDrivePolicyV1` 仍作上界门，不替代映射。角色专属规则来自 Owner 已采用创作配置或已有获准安装资产；缺实际配置时该实例明确缺配置，产品入口仍应完整可用，不全局恒 HOLD。

### 4.1.1 新编码观察原件与旧 C02 的区别

当 C02 原收据没有读取 Feeling/appraisal 时，不修改其 read_versions，也不把旧 unknown 基线升级为今天的值。新增专用 `record_current_encoding_context_v3`：当前 Owner 围栏内复读 source/perspective、已采用 appraisal/current interpretation、joint Feeling/checkpoint 与其采用 history，保存不可变 `EncodingContextObservationReceiptV3`，同事务签发**新 encoding operation** 的 baseline。原件绑定新 operation、可信 observed_at/as_known_at、完整正负读集、Owner/rights/install、joint adoption 引用及摘要。as_known_at 为本次合法观察时刻，不回写成 source.created_at。

业务 typed writes 可以为空，但必须真实插入专用 observation original 和 operation receipt；不产生新 D06 source、贡献或回忆经历。若现有 baseline service 复用 `CommitReceipt.read_versions`，必须同时验证专用 operation kind 与 observation original，不能接受任意空写 CommitReceipt。旧 unknown 原件继续保留，新 baseline 只能作为新时点编码后的回忆依据，不回填旧历史。

时间取当前 checkpoint.cursor，终点来自 W01 已登记 CharacterClockMapping 与请求的合法角色区间。D10 提候选，D11 唯一签时钟。驱动/耦合/政策边界变化则分段。时间映射、appraisal、perspective、interpretation、角色条件及其版本都入 drive acceptance original。全组件同家族 dose 只能按已安装分配政策拆份，份额总和不超过 1；不能每个块各吃一次总剂量。`SourcedNumericDrive.mapping_compiler_ref` 必须指向可复读安装签发原件，不是任意非空字串。

### 4.2 数值费用与图采用

W01 冻结完整 joint component 与数值工作 request；D11 为**该次 ABI2 full+全部 LOO/输出认证**签独立 CPU quote/reserve/job。安装数值执行服务拥有真实测量与 claim/terminal，调用固定 ABI2 实现；W02 纯数值函数不自行签费用。技术计算不自动消耗角色身体费用；只有该活动另有 D02 获准角色劳动组件并由真实完成收据证明时才结算该组件。

数值终态先耐久再导入 D11 actual；失败也记录实际费用，unknown 保留原执行身份。最终 adopted joint 事务引用已付成本，不为了旧 bundle 形状重复收费。C04 CPU terminal 只覆盖 association activation/ranking，不能用于证明数值积分费用；appraisal 模型费用也是独立原件。

W01 业务库中的 local claim/terminal 不能单独成为数值 CPU 权威原件。新增 D04 专用 typed numeric binding/terminal，复用独立 Authority journal/core CAS、安装签发和复读基础设施；不要强行借用含 BodyQuote 的 C04 binding。binding 至少含 namespace/install/Owner generation、operation/execution/input、algorithm/native、原 quote/父预算，terminal 绑定 full/LOO/output 摘要及 actual。同步单线程执行用 `thread_time_ns` 计量；`process_time_ns` 仅可在无其他并行任务的专用隔离进程归属本次工作，共享宿主进程 CPU 不能算作本任务实际量。若原生核使用多线程，须采用可归属该作业的 worker 计量并升量度政策，不能漏计或混入其他任务。

原有 D04 joint 文档中“最终一次提交 D02/D11 账”对于尚未结算的合法组件仍成立；采用本页独立已付内部数值工作协议时，最后事务写成本引用及采用身份，不再重复结算。必须以显式协议分支核验，不用空写蒙混旧 preflight。

### 4.3 ProductAdvanceEvidenceV2 的规范摘要

每个字段从下表的真实 payload 用 `canonical_digest({"schema":"d04.joint-evidence.<field>.v1", ...})` 构造。graph ref 集合按 token 排序，member 顺序使用固定 checkpoint_refs 顺序。数值均保留 binary64 位表示；若现合同已有规范 typed serializer，直接采用该 serializer 的确切类型/字段版本，不在同版本中混用 Python repr。payload 必须保存于 frozen work/数值原件可复读，不只存无从核查的 hash。

| 字段 | 必须计算的 payload |
| --- | --- |
| read_versions_digest | 完整实际 `GraphVersion` 排序集合，含所有新键/更正头缺席；不得用只含 source 的子集代替。 |
| snapshot_stamp_digest | namespace、catalogue、graph incarnation/revision/query epoch、access/delete epochs、schema versions；metadata 来自同次围栏。 |
| time_mapping_digest | mapping ref/version、已登记角色 clock head/version、role/solver 起止、每 member predecessor cursor；全部数值位模式。 |
| closure_digest | snapshot stamp、ordered member refs、完整 numeric scan rows（含 invalid）及 revision/value digest、全部有效/无效 coupling/drive、分页范围及完成证明。 |
| source_closure_digest | source/access/correction/ancestor 正负 heads、audience/purpose、D06 family 分组、appraisal acceptance 与 role/condition/mapping 原件引用和摘要。 |
| absent_reads_digest | 真实 revision 0 graph refs 及 typed negative query predicates/覆盖；存在 invalid 行不能算 absent。 |
| asset_digest | catalogue、manifest/native、每 member checkpoint assets、operator/readout/mapping/output policy 的 ID/version/hash、member/axis order。 |
| contribution_consumption_digest | 每 family contribution_key、appraisal/facet、原 dose 位模式、各 member 份额、有效区间、旧 ledger 版本与本次消费 key/量。 |
| numeric_input_digest | 实际装入 ABI2 的稳定 member/axis 顺序、K/R/J/A/coupling/drive、初值及继承误差盒、时间/精度参数，不能以候选库存摘要替代。 |
| full_transcript_digest / family_loo_transcripts | 本次真实 full 与每 family removal 的独立 native transcript 摘要；family→transcript 对照完整，缺项不可由 full 复制。 |
| output_write_set_digest | 安装 output issuer 从真实 full 输出导出的所有 next checkpoint/Feeling/Mood 与证书原件写集。初始 iterate 不作为下一状态。 |

这些字段由 W01/安装 issuer 唯一构造，最后重新读取/确定性复导。它们与 bundle digest 不形成自引用：先冻结输入与执行原件，再生成输出候选写集与最终 bundle，最后 evidence 绑定该 bundle；bundle 不再把 evidence 自身摘要包含回输入摘要。

## 5. 全领域行为总装接口与事件责任

本节 API 名是本轮待落实接缝，不声明它们现在已存在。全都以版本化 CommandEnvelope 为公共入口，复用共享图/job/outbox、D11 当前读和事务；禁止单独的域数据库。宿主 startup 注册已安装 handler，scheduler 从耐久 job 调用，D12 只能发具体意图。被缺配置阻断的实例应返回具体 missing_inputs，存在完整输入时必须走实质行为。

| 领域接缝 | 谁触发、调用何种现有纯域函数 | 持久结果和后续可观察行为 |
| --- | --- | --- |
| `evaluate_current_values_v1` | D07 决策与 D08 候选冻结后，W01 当前 D01 PersonaView + versioned candidate set → `PersonaDomain.evaluate_values`。 | 返回带 reads/coverage 的价值偏序/冲突，D08 重新校验并用于排序/RequiredCheck；不把值判断签成行动许可。 |
| `prepare_current_growth_v1` / `adopt_current_growth_v1` | 已结算 D07/D10/行动 outcome 触发；W01 读来源家族、必要反例、原成长贡献、连续性和 plasticity，调用 `issue_growth_candidate/validate_growth_candidate`。 | D01 revision/head/贡献/continuity 与 re-evaluation outbox 同事务；角色身份不由自然成长改写，既有 D08 承诺只触发重评。未完成 trial/反例用 durable pending job。 |
| `advance_current_body_v1` | D11 trusted tick / D10 合法生活区间，复读 clock、body cursor、被动参数历史和未核实劳动，调用 `advance_passive_body`。 | CAS 新 BodyState+cursor/区间收据；切段由真实参数边界决定，不能恢复穿越 unknown 劳动。重复区间不再推进。 |
| `apply_current_body_effect_v1` | D08/D10 实际 outcome 或 D04 合法影响，引用 original component/effect，调用 `apply_settled_work_effect`。 | effect 贡献去重与 state/settlement 同事务；角色身体、真实计算费用与外部物理测量分开。 |
| `serve_current_concern_v1` | C02/用户新输入、已采用内部事件、到期唤醒进入 D07；当前 ticket inventory+policy → `begin_concern_round/choose_concern_segment`。 | 冻结 round/choice、资源/job；实际认知终态后才 `settle_concern_segment` 消费一次服务计数。重新唤醒不凭空产生关注贡献。 |
| `advance_current_reflection_v1` | 上述 concern 服务中的真实认知活动；读取 checkpoint/new discriminating refs，调用 `compile_reflection_transition`。 | checkpoint+工作集/必要经历+费用引用+job 同事务；meta_depth<2，两个无进展片段挂起到新触发，不循环自证。 |
| `run_current_simulation_v1` | D07 合格预测任务；baseline+至多两个 alternatives、D06 原件、预算和明确假设。需要模型则独立真实 D11 job。 | D07 SimulationResult 与假设/未知/执行收据采用；分支属 hypothetical，不能写成 D06 外部事实或直接消费行动结果。 |
| `prepare_current_bilateral_plan_v1` / `adopt_current_bilateral_plan_v1` | D08 从 D03 当前双方身份、D05 边界、D06 可追溯的各方明确同意/承诺、当前目标版本构建 joint plan。 | 所需双方资格齐全才 CAS joint-plan/commitment/intent/RequiredCheck；一方提议不能代替另一方同意。条款变更使旧同意失效；每个实际 effect 单独执行/结算。 |
| `advance_current_life_v1` | 已获准 D08 activity plan 与 D11 实际片段 outcome → `LifeDomain.adopt_life_progress`。 | D10 project cursor/progress、D02 真实效果、合法 D06 内部经历/贡献与通知同事务；计划/quote 不记成已生活。 |
| `advance_current_offline_v1` | 重连/startup 发现已登记离线区间；W01 提供真实 clock mapping/区间和 observed ticks → `plan_offline_simulation_slice/advance_observed_offline_ticks_v1`。 | 有界续接 cursor+明确模拟经历；不虚构离线用户回复/发送成功，未观察 ticks 不补造外部事件。 |
| `prepare_current_contact_v1` | D10 的已采用 opportunity，当前 policy/claims/quiet hours/边界/配额 → `project_current_contact_v1/contact_policy_required_check`。 | D08 接资格并生成行动；claim_contact_window 与后续 dispatch admission 原子绑定。unknown 保留占用，delivered/read 分开；只在真实终态按原 effect 调 `observe_segment/release_contact`。 |

以上路径采用前都必须有生产 caller，不能仅把所有函数加到 `domain_registry`。主调用链为 host 入站/可信 tick→W01 冻结触发→D07 或 D10 proposal→D08 明确意图→D11 执行→原领域结果采用。D01 growth、D02 effect、D07 reflection 等从已提交 outbox 在后续有限活动推进；禁止一个图事务内同步递归调用所有域制造环。

### 5.1 六个生产 helper 的安全文件划分

以下新文件按域各一个唯一 Sol 写者；已有文件只读。如任一文件已由本轮其他写者创建，主任务先合并所有权，不覆盖现文件。每个写者拥有自己的 `domains/dXX/production_operations_v1.py`（typed request/result 与纯 proposal 包装）和 `runtime/dXX_production_operations_v1.py`（当前读取、受信原件复读、事务 staging），不得修改 `graph_coordinator.py`、`runtime_context.py`、`runtime_contracts.py`、公共 registry/catalogue 或其他域文件。W01 独占最后注册/调度/生产入口串接；D04 与 C04 专属写者保留原所有权，D07 新 helper 不修改 C04 interpretation issuer 文件。

实际派工优先于上述建议文件名：本轮 D07 写者已明确独占新 `runtime/d07_current_behavior_v1.py` 与 `domains/d07/current_issuer_v1.py`，并获派在 latter 实现本页当前 C04 纯 issuer；它们承担上述 D07 文件职责，不再新增另一组同功能文件。任何其他已有 C04 issuer 写者须与主任务完成单写者交接，不能并行改同一文件。

公共小合同由主任务指定一个唯一写者在 `runtime/domain_production_contracts_v1.py` 落地：

* `ProductionOperationLimitsV1`：max_source_roots、max_graph_heads、max_query_rows、max_writes、max_followup_jobs、max_role_segments。默认工程上限分别 32、1024、128/页、64、16、16；安装政策可进一步收窄，范围闭包超过上限必须返回带稳定 continuation 的 deferred/partial，不丢弃尾项冒充完整。已有域更严上限优先，例如 D07 working set 16 项/4096 token、模拟最多两个 alternative。该默认值是资源边界，尚非 G6 性能验收结论。
* `CurrentOperationFrameV1`：envelope、当前 `GraphSnapshot`、可信 now、Owner guard、activation generation、typed query coverage、installed policy refs/digests、已复读 trigger/terminal/cost originals 的身份。仅安装 current-frame port 构造；frame 不是传入即生效的授权 token，W01 commit 必须重新核 current fence/CAS。
* `StagedDomainOperationV1`：schema、domain/operation kind、namespace/activity/operation、request_digest、完整 read_versions/query coverage、`tuple[DomainProposal,...]`、既有 job/outbox 的 typed staging、original payload/digest、已付成本引用、coverage/missing/continuation。它是待提交产物，不包含 commit 成功状态；不接任意 callback、SQL、资源 receipt 字串或无结构字典作为证明。
* `DomainOperationReceiptV1`：同一 command 身份、prepared/terminal/original refs、真实 CommitReceipt 引用/摘要、写后版本、job 状态、费用引用、coverage/missing/continuation。由 W01 在实际提交后签发并提供当前复读，helper 不自行发 complete。

每域纯入口统一 `compile_<operation>_v1(frame: CurrentOperationFrameV1, request: ExactRequestType) -> StagedDomainOperationV1`；runtime 入口统一 `stage_<operation>_in_transaction_v1(db, *, frame, request, installed_readers) -> StagedDomainOperationV1`。后者要求已经处于 W01 当前事务，不调用 BEGIN/COMMIT、不做 Authority RPC/模型调用/native长计算。`installed_readers` 是启动时绑定的窄 typed ports，不接受每个请求传入一个 `lambda: True` 验证器。对依赖模型/执行结果的操作，prepare 阶段只写真实 job，完成阶段只能消费原 job 对应的独立 terminal。

W01 外部命令 `run_current_<operation>_v1(authority,lease,*,request)` 负责 envelope/Owner/fence、短事务内 staging、域 provider 校验、全部 CAS、收据/outbox。同请求重传复读原 receipt；不同请求不可复用 operation。现有 command DTO 已有这些身份时直接嵌入，不再发一套平行 op ID。

所有新 runtime original/中间态表必须向既有内容存储清单注册恢复、来源依赖、C09 删除/清理语义；不可变表示禁止篡改历史身份，不表示可以永久保留已撤销正文。family reader须递归核D06 parents/access/correction闭包，检查循环、缺祖先和范围超限，使用已存provenance_root/贡献原件而非“无parent即独立”的推断。

### 5.2 精确 typed 请求、原件与写集

下列 request 字段均是**意图/原件 locator**，字段有值不证明合法。frame 的 namespace/activity/operation/权限/时钟沿公共信封唯一取得。不存在的必要纯域编译器由本域包装文件新增，不得用通用任意图写绕 domain validator。

| 唯一写者 / 精确 request 与入口 | 实际取证和现有纯域复用 | 允许产生的阶段结果 |
| --- | --- | --- |
| D01：`EvaluateCurrentValuesRequestV1(candidate_set_ref,context_ref)` → `compile_evaluate_current_values_v1`；`AdoptCurrentGrowthRequestV1(growth_proposal_ref,trigger_original_ref,trial_original_refs,counterevidence_query_ref)` → `compile_adopt_current_growth_v1`。 | 当前 active role/PersonaView、实际冻结候选；成长提案/试用/必要反例从原件复读。调用 `evaluate_values`、`issue_growth_candidate`、`validate_growth_candidate`。source_ids 和 families 从 D06 原件推导，不能把 caller 列表当独立性证明。现 growth 要求 confirmed observed independent 源的门保留。 | value 只产生受权读结果及可审计原件，不签 D08 pass。growth 写 D01 plan/revision/activation/贡献与 continuity；未完成试用/反例生成 pending 状态及 D08/D10 后续请求，不递归执行试用。 |
| D02：`AdvanceCurrentBodyRequestV1(clock_mapping_ref,target_role_cursor,trigger_original_ref)` → `compile_advance_current_body_v1`；`ApplyCurrentBodyEffectRequestV1(component_terminal_ref,body_quote_ref,settlement_operation_ref,effect_policy_ref)` → `compile_apply_current_body_effect_v1`。 | body/profile/rates/clock/cursor/unknown 组件和区间全覆盖；调用 `advance_passive_body`。效果从真实 component 和安装政策推导 `fatigue_increase/load_increase`，再用 `apply_settled_work_effect`，不接受裸量。 | passive 写 D02 state/cursor/区间原件；effect 在实际 settlement 三写中原子合并；重复 settlement 的 duplicate 必须保持 no-op，不对已扣能量的旧原件再扣一次。 |
| D05：`AdoptCurrentRelationshipContributionRequestV1(trigger_original_ref,subject_entity_ref,dimension,semantics,policy_ref)`、`ReviseCurrentBoundaryRequestV1(boundary_ref,intent_original_ref,policy_ref)`、`ReevaluateCurrentRelationshipRequestV1(correction_head_ref)`，各自 `compile_*_v1`。 | D03 精确对象身份、D06 真实事件/family 和源权限、D05 安装维度/语义政策、完整 relation owner query；复用 `RelationshipContribution`、`qualify_contribution_for_audience`、`RelationshipProvider.validate`、`compile_d05_source_reevaluation`。边界基于 counterparty_explicit/mutual_agreement 时复读实际表达/确认及语义范围。 | D05 contribution 按 `(persona,family,entity,dimension,semantics)` 唯一去重，修订替换原贡献。boundary/current projection/失效原件仅本域写，后续 D08 recheck 用 outbox。projection 只能表达现 registered schema 能承载的状态；若需新数值关系状态，先让公共schema写者明确版本化，不能塞隐含额外字段。 |
| D07：`ServeCurrentConcernRequestV1(category,trigger_original_ref)`、`AdvanceCurrentReflectionRequestV1(reflection_ref,cognitive_terminal_ref)`、`RunCurrentSimulationRequestV1(simulation_request_ref,trigger_original_ref)`，各自 `compile_*_v1`。 | 完整当前可运行 ticket inventory/current policy、Concern round 原件；复用 `begin_concern_round/choose_concern_segment/settle_concern_segment`。反思 resolved slots/discriminating refs/causal depth 来自已采用认知结果和作业链，不来自 caller。simulation request/predictions 来自合法输入或真实原调用。 | prepare 写 round choice+job/资源引用；真实工作完成才写 round消费/WorkingSet/reflection checkpoint/SimulationResult及必需经历组合。等待新信息的反思不得同轮再次排队自己；simulation 的假设来源明确保持 hypothetical。 |
| D08：`AcknowledgeCurrentBilateralRequestV1(commitment_ref,inbound_source_ref,outbound_receipt_ref,acceptance_interpretation_ref)` → `compile_acknowledge_current_bilateral_v1`；`AdoptCurrentJointPlanRequestV1(joint_plan_proposal_ref,party_consent_original_refs)` → `compile_adopt_current_joint_plan_v1`。 | 使用真实 inbound actor/D03绑定、原已传达承诺/outbound状态、当前 source/access/correction、D07已采用且exact scope的接受解释。W01安装 `BilateralAcknowledgementReadV1` verifier 后调用 `prepare_coordinator_bilateral_acknowledgement_write_v1`；不能绕过普通 provider 对 acknowledged 写的禁止。joint plan 各方同意须逐一核其版本/条款。 | acknowledged commitment CAS及原件/outbox；joint plan/goal/intent须各自 domain validator，RequiredCheck结果由实际 providers签发。ACK只建立承诺，不能一并伪造行动已执行。 |
| D10：`AdvanceCurrentLifeRequestV1(project_ref,activity_outcome_ref)`、`AdvanceCurrentOfflineRequestV1(offline_interval_ref,clock_mapping_ref,continuation_ref)`、`PrepareCurrentContactRequestV1(opportunity_ref,contact_policy_ref,target_route_ref)`，各自 `compile_*_v1`。 | `adopt_life_progress` 消费D08计划+D11真实合法角色片段；offline只消费已登记observed ticks，用`plan_offline_simulation_slice/advance_observed_offline_ticks_v1`；contact用`project_current_contact_v1/contact_policy_required_check`核quiet hours/配额/claims/D05边界及路由。 | life/offline cursor与结果写D10，所需D02/D06写通过预声明bundle统一提交；contact只产合格机会/required check和D08请求，contact claim与后续final dispatch在专用事务绑定，unknown保留占用。 |

不存在“通用映射函数可以一次写任意域”的特权。普通 staging 的 domain proposals 只允许本域；生活/认知等明确需要多域同时生效时，使用预先注册的具体 bundle kind 和精确成员集，分别从对应域纯 issuer 取得 proposal，再由 W01 一次提交。已获资格的 body effect/experience 等不可拆成先写成功再异步补账；可分阶段的后续成长/目标重评才走 outbox。

### 5.3 有界生产调度和验收后果

一次 worker invocation 只处理一个已登记 operation 的一个有界阶段。RPC/模型/FFI 在事务外；结果进入独立日志后再开新的采用事务。出站 outbox 的 dedupe key 固定 `(namespace,causal_operation,receiver_domain,event_kind)`，job 唤醒不得伪造新的贡献来源；每次 dispatch最多产生安装上限数量的followup，超出保存 continuation。调度器不在同一 Python 调用栈递归调用接收域。

需要多个顺序阶段的域返回 queued/waiting_for_original/deferred/adopted等精确状态。不可对“queue成功”返回“成长/反思/生活已完成”。每个helper交接须列实际生产caller、typed请求/原件、允许写type集合、读范围/负查询、job/outbox与手动可观察变化；编译先过，完整链落地后才做必要产品验收，无临时过渡测试。

## 6. D12 服务端生命周期与实验

### 6.1 公共返回原件

新增 `domains/d12/backend_operation_contracts_v1.py`，由 D12 写者独占，仅依赖 stdlib/公共 DTO，不 import coordinator/host。冻结 `D12BackendOperationOriginalV1` 公共字段：schema、kind（transfer_plan/transfer_execution/control/maintenance/experiment）、namespace、operation_id、request_digest、plan_ref/plan_digest（显式可空）、activation_generation、owner_grant_ref/revision/digest、authority_refs（有类型 kind/ref/digest 序列）、state、coverage、missing_inputs、result_digest、original_ref、original_digest。具体业务 payload 用单独版本化 dataclass，不放宽成任意 Mapping。

生产 port 必须提供 `read_current_backend_operation_original_v1(authority,lease,original_ref)`；D12 在命令返回后从安装 port 当前围栏复读，核 operation/request/namespace/Owner/plan 和返回原件逐字段相等。类型正确、authority_refs 非空、摘要自洽都不能独自证明 durable。只有受信服务原件复读可决定状态；外部响应不得把 prepared/queued/unknown 统一翻成 complete。

### 6.2 C07/C08 搬迁

`resolve_current_transfer_plan_v1` 从 Owner 当前授权及服务端 artifact registry 解析 manifest_ref、target、scope_selection；ref 为 opaque ID，不能当本机路径，浏览器不能提交 `MigrationPlanV2`。复读 source 权限/删除/来源闭包、目的地配对 Authority 和权限、支持 schema/平台与损失范围。

`prepare_current_transfer_v1` 以当前读围栏记录不可变 plan。TransferPlan payload 必含 source/target installation 与 authority namespace、scope digest、manifest digest、source snapshot requirements、loss/coverage、原 Owner 和 policy 版本。返回预览和可复读 plan，不复制运行数据、不宣称目标已激活。

本轮落地的 `D12TransferPlanPayloadV1` 用一个 `authority_namespace` 表示源和目标由同一 Authority 管理的搬迁；producer 必须明确验证两者确实相同，不能丢弃目标 identity。跨 Authority 搬迁若后续需要，另升 payload 版本并完整保存两端身份，不能在本版本默默复用。

`execute_current_transfer_v1(plan_ref,expected_plan_digest,target_lease_ref)` 的合法顺序按 `AuthorityV2MigrationService` 实际合同固定为：**begin_transfer freeze→排空并 `read_current_source_snapshot_v2`→revoke_source(snapshot)→prepare_target→target recovery→activate_target(recovery)**。本页早先将 revoke 放在 snapshot 前的顺序已纠正，不能照旧序调用。

`begin_transfer` 将 namespace 从 active CAS到recovering，已阻断普通内容入口，并签发专用 `source_snapshot` permit。源快照在该permit下核实际图/独立日志锚/内容hash，形成真实 `SourceSnapshotReceiptV2`；`revoke_source`先核此receipt并调用受信 `_source_verifier`，成功才将holder置空并推进generation/revocation epoch。`prepare_target`仅在revoked之后运行并签`target_recovery` permit；目标完成实际导入、日志/Owner/删除屏障恢复后产生`TargetRecoveryReceiptV2`，再供`activate_target`校验。target_prepared不表示目标active。

每个阶段先独立耐久再ACK；执行原件记录transfer_id/stage/current authority head/target lease digest。freeze开始即不许普通源读写借旧Owner继续；源已撤权不能因目标超时退回普通出站。`read_current_transfer_status_v1`/recover只查询和继续原transfer的合法阶段，不生成新ID绕过unknown。

允许携带尚未终结的unknown工作迁移，但必须保留原execution/call/effect/quote/reservation/取消代际约束，不能要求所有unknown先变terminal，也不能在目标将unknown改为零。安装`InstalledMigrationReconciliationV1`先复读独立execution/model原件，既有target `holder.hold`核目标job/budget/body约束，产生无内容held proof与`unknown_constraints_digest`。在`activate_target`已有最终`_frozen`、Core CAS之前调用窄`require_current_reconciliation_in_tx(db,held,execution_head,deletion_head)`，只使用已有Core事务、已冻结journal head与已持graph hold的规范摘要重核；禁止重新BEGIN/嵌套_frozen、另取图锁/RPC或解封正文。receipt、held和当前reconciliation digest有任何相关变化则拒绝activate，按同transfer重做recovery，不现场覆盖原receipt。此service文件补丁由主任务协调唯一写者串行落地。

请求现有 `current_epochs` 可严格版本化为 schema、plan_digest、graph_revision、access_epoch、deletion_epoch、activation_generation；字段名称遵守现 wire。它是 expected CAS，不是调用方签发当前 epoch。C09 删除/快照可用性按专属协议复读。

D12 与运行时已交接的调用签名统一为 `prepare_current_transfer_v1/execute_current_transfer_v1/commit_current_control_v1(authority,lease,*,operation_id,request_digest,input_data)`，返回上述 typed original；维护入口可用同签名的 `install_or_upgrade_v1`，内部保留 prepare/execute 分阶段。统一复读为 `read_current_backend_operation_original_v1(authority,lease,*,original_ref)`。`input_data` 仅为已严格 schema 解析的命令意图，不携带可由浏览器自授的 prepared plan、authority head 或成功收据。

### 6.3 C11 安装/升级与 C12 配置/控制

`InstalledMaintenancePort.prepare_install_or_upgrade_v1/execute_install_or_upgrade_v1/read_maintenance_status_v1` 由配对安装服务实现，消费实际签名包 manifest、兼容矩阵、当前安装身份及 Owner 维护 capability。现 CLI installer 可作为此服务的受控实现，但不能 shell 拼接浏览器路径。固定阶段为检查/暂存→quiesce 原运行→可恢复 backup 与版本迁移→候选加载/就绪验证→activate；失败按原 operation 恢复到有资格的上个安装，保留原结果与恢复收据。旧核心不作为回退版本。

现 C11 命令可在一轮中 prepare+execute，但先写 durable plan 再执行，不把 CLI exit code 单独视为完整维护结果。缺权限/配置返回具体待满足项。计划展示和确认沿现有签名 Owner 流程，不虚构前端确认记录。

`prepare_current_control_v1/commit_current_control_v1` 只接受已注册控制类型和 schema；配置字段路由 D01–D13 对应 issuer，方案修改复用已编译/预览/采用合同。暂停/停用/恢复/卸载按真实 lifecycle protocol 改 generation、job/dispatch admission 与状态，不是只写一个界面 flag；未知执行不能被“停用”抹掉。control 原件与操作效果在同一业务事务或受信维护阶段闭合。

### 6.4 隔离实验不止 scheme preview

新增 `prepare_isolated_experiment_v1/run_isolated_experiment_v1/read_experiment_result_v1`。当前 Owner 明确选 sources/scope、方案对照、可观察结果、模型/CPU 预算、截止及种子；W01 授权复制到独立 experiment namespace，保存来源版本与现实性。由同一领域实现运行真实有界作业，使用独立父预算/费用且所有发送/tool effect port 禁止绑定生产权限。方案 preview 是一种 experiment_kind，其余认知/回忆/生活/表达实验可消费同一运行器。

结果含各实验实际阶段、输入/资产/执行原件摘要、费用、覆盖/未知及比较值；无真实执行不标 complete。实验结论不进入正式人格/经历/承诺，只有 Owner 后续显式采用形成新的 domain administrative_edit/策略版本。清理按 C09，结果正文复读仍核来源权利。不得建立永久无授权复制数据库。

D12 路由可统一调用 `run_current_experiment_v1(authority,lease,*,operation_id,request_digest,input_data)`，其内部仍须冻结、执行、原件采用；当前方案预览与 health projection 保留各自具体用途，不伪装成通用实验执行器。

### 6.5 C10 诊断与支持导出

公共 original 的 kind 扩展为 `support_export`，具体 `D12SupportExportPayloadV1` 包含 allowed_data、retention_policy、managed artifact_ref、payload_digest、redaction_original_ref、source epochs、scope_digest、expiry、coverage。`export_current_support_v1` 使用同一当前命令签名，由服务端读取获授权投影/执行原件生成实际脱敏构件，写内容摘要与脱敏原件；浏览器的 ref 不授予本机路径访问。

生成可以在锁外，发布/解封判定必须在当前 Owner 围栏中重核源头和权限并 CAS 原件。下载再次核当前资格；封装期间或下载前撤权则阻断且按 C09 清理。两次没有围栏的前后 Owner 检查不能冒充原子发布。诊断只可引用真实 operation、依赖和运行收据，缺因果证据显式 unknown，不从投影任意字段拼出虚构因果链。

## 7. D13 的结果、费用、待用及恢复顺序

W01 接 D13 时复用真实窗口、独立 D11 model job、当前来源资格与 exact wire。后台压缩技术费用只进 D11，不扣 D02 身体。Authority terminal 已耐久后，先受权复读并将该结果正文/摘要在共享库持久记录；再结算同 call 的费用并终结 job；最后 D13 核 block/coverage/72h TTL，生成 standby 候选。在实现可原子合并时，上述顺序仍保持逻辑依赖，不能 standby 先暴露再补账。

结果已持久而费用失败的恢复只补原费用；费用已付而 standby 未落盘只从原结果编译。unknown 只查原 call，不能换 call 重发。current activation 另核 conversation/scene/audience/source/access/delete/order、TTL 与 generation，再 CAS standby→active。D13 不写 D06 fact、D07 解释或 D08 承诺；过期、撤权和 C09 清理不因“曾经付费”被豁免。

### 7.1 保守 token 上界的生产激活分支

保留 `D13ExactActivationEvidenceV1` 的精确计数语义，另增 `D13BoundedActivationEvidenceV1`，通过明确schema/tagged union分派。后者绑定installation/provider/model/config、wire format、token-bound policy ID/version/fingerprint、两份完整exact-wire摘要、raw/compressed各自非负整数lower/upper、context limit、output/tool reserve与available input capacity、current window/read-set/standby摘要、允许保守切换的安装政策。所有界满足`0 <= lower <= upper`，bool不能作integer；不能将UTF8估数贴为精确token或可证明上界。

安装 `D13BoundedActivationVerifierV1` 从当前两份完整wire复读并重导界，返回typed verified receipt。覆盖包括system、工具定义/格式、当前输入、必须证据和全部历史，模型/序列化/模板/计数资产身份完全一致；若供应商格式的token开销无可验证上界，则该policy不可签发此receipt。W01当前围栏进一步核source/TTL/standby代际及真实预算，不把caller bool视为证明。

决策明确分四种：raw.upper<=capacity默认keep_raw；raw.lower>capacity且compressed.upper<=capacity可按proven pressure激活；raw.lower<=capacity<raw.upper且compressed.upper<=capacity也可按安装政策保守激活，但理由只能是`raw_fit_unproven_compressed_fit_certified`；compressed.upper>capacity不得以本证据激活。第三种证明压缩wire能安全装入，没有证明真实raw超窗，不宣称费用节省或精确70%压力。无需为了已获安全压缩上界再强求raw精确值，否则产生无必要的循环门。

前台费用仍按compressed完整wire的无缓存最坏价格经D11准入；已付预制费是沉没成本，不二次扣费，累计实验/G6成本仍计入。精确证据旧接口不能自动接受bounded字段，旧布尔raw_window_fits/proven_future_saving仅保留诊断或明确非付费旧路径语义。

`required_model_tokens`至少为`compressed_input_upper + output_reserve + billable_tool_token_reserve`；现tool_reserve若未拆分计费与纯上下文保留量，保守将其全部计入预算下限。已经位于完整wire内的工具定义/消息开销已包含在input upper，不重复计入；tool reserve只指尚未进入wire的额外量。计数源必须是受信已安装provider完整wire计数端点的绑定响应，或manifest pin的本地tokenizer及该provider序列化/开销证明政策。普通`count_tokens`整数、preflight ready、事后usage都不是完整输入的事前证据。实际主回复2messages与context_reply 3messages分别通过各自真实request builder冻结，不能用一条workflow的计数授权另一条。当前stock无合格counter的组合明确计数未验证，不能假造counter适配器宣称foreground完成。

### 7.2 D13 历史进入真实自然回复的完整 wire

本次继续核对发现：`model_broker/natural_reply.py`已有3messages的`NaturalReplyInputV2`，模板明确支持低信任D13，但只收真实compressed blocks的`stable_history`；当前GraphCoordinator以`plan,(),now,expiry`构造，实际历史为空。因此产品接点是**当前自然generation→真实paid review→D09采用→D11 final dispatch**，不向严格2messages的source_reply v1偷偷附加历史，也不拿只许逐字引文的context_reply v1替代自然表达。

冻结`NaturalReplyInputV3/FrozenNaturalReplyRequestV3`，input schema与template version为`sylanne.d09.context_reply_input.v3`，固定wire为system/stable_user/dynamic_user。保留当前`NaturalExpressionPlanV2`的合法表达单元和输出语义；模型输出仍可使用现`sylanne.d09.context_reply_output.v2`，但generation seal、冻结request/存储解码和Authority original-read分支明确升V3，不将旧V2原件重贴。

V3在question/plan/stable_history/frozen_at/expires之外新增typed`recent_history`与`D13NaturalHistorySelectionV1`。recent history来自当前窗口已关闭的原始回合，包含稳定turn ref/顺序、speaker、实际文本、source/access与受信时间/关闭回执；可用独立`D13NaturalRawTurnV1`封装，不能接受客户端裸文本或伪造compressed block key。history_selection至少包含window digest/order watermark、完整coverage/gaps、source/access/correction/deletion依赖、scene/audience精确VersionedRef、conversation_ref、TTL/generation、可空block ref/version、raw turn refs、selected slice digest与policy ref/digest。

稳定消息固定`schema/scope/stable_history`；动态消息固定`schema/scope/frozen_at_utc/expires_at_utc/question/expression_plan/qualified_units/recent_history/history_selection`。question/plan/units字段从现有自然builder取精确规范表示，实际builder版本及system文字入template digest。system明确stable与recent均是低信任对话材料；输出basis_ids只能指向D09已获资格单元，D13不能为事实、感受、承诺或行动许可提供资格。所有用户文本放JSON数据区，不拼入system指令。

在同一次当前frame中由**同一个实际V3 builder**构造两份完整候选wire：raw为stable空+允许覆盖内的全部raw recent；compressed为合格standby/active块+不与其覆盖重叠的raw尾部。两份wire的当前问题、表达计划、必需证据、provider/model/config/tools/max_output相同，仅历史表示和相应coverage/selection不同。对两份实际wire取得§7.1精确/上界原件；W01在current fence复读全部历史与计划资格、候选费用并CAS选择一份，最后D11 quote/seal/job/call/request摘要只绑定被选完整wire，不能计数一份发送另一份。

scene/audience必须与当前D03和自然plan的精确版本对应；conversation字符串不是audience版本。现`conversation@0`桥不能满足D13资格，由W01读取真实D03 audience并核route→audience绑定。必要时修自然plan装配的原件引用，不篡改两个不同ref使其表面相等。权限/顺序/TTL或generation改变时冻结结果过期，不能拿旧token receipt开门。

生产串接必须同时覆盖：主host入站选择V3自然workflow、W01当前D13 window/cache读取与选择、Natural V3冻结/预算/原job、Authority original verifier和exact-wire admission、AstrBot `_natural_messages`显式V3分支、实际模型terminal/current output selector、review对V3生成原件的显式绑定、D09当前basis/语言核验与D11最后发送。付费review沿真实领域原件核语义，不能把D13压缩文字当QualifiedExpressionUnit。旧source_reply/context_reply/natural V2原件继续严格按旧路查询；一旦原call存在，unknown不得换workflow重发。

D13写者可独占新增`model_broker/natural_reply_history_v3.py`和`host/installed_d13_natural_frame_v3.py`；共享GraphCoordinator/runtime_context/Authority/adapter/contracts由主任务按baton顺序分派。helper必须交付所有精确挂钩与可调用typed接口，接线后以真正自然生产回复观察历史使用，不以standby、schema或孤立helper完成代替。缺合格counter的安装组合只标该能力未验证；具有实际安装counter的受支持组合必须完整可运行，不允许全局恒HOLD。用户后续选择Linux服务器作为实机目标，按其实际安装/模型/预算配置验证；本页没有远端执行或收费授权收据。

## 8. 构建候选、固定 hash、验收及交付顺序

G0–G7 是**正式交付资格**的门，不能反过来阻止产生供这些门检验的构件。顺序固定为：完成实际后端接线→受影响 Python/Rust 编译→从当前精确源内容构建 `--backend-alpha1-candidate`→固定 ZIP/manifest/source inventory/catalogue/native/资产 hash→用该包冷安装与实际产品链验收→按受影响门记录结果→满足本轮后端门时形成后端验收结论。前端暂缓明确留账，不能宣称完整 UI 或全产品正式 alpha1。

候选模式沿用生产 loader、安装配对 Authority、签名 Owner、原件存储及真实 provider。`candidate_only/HOLD` 表示尚未取得交付资格，不应成为所有产品行为恒返回 HOLD 的运行开关。每次操作是否可执行由其安装/授权/原件/数值能力决定。不能通过把 dev adapter 改名、把 catalogue 手写成 READY 或假签 certificate 开门。

上述生产验收准入使用显式 **v2 candidate qualifier schema**，绑定当前安装pin与production qualification；旧v1 diagnostics qualifier继续按其历史严格语义验证，不能静默将旧v1件放宽为生产准入。解码器按schema精确分派，v1→v2必须重新取得实际安装/资格原件并生成新manifest/hash，不因字段近似自动升级。delivery资格仍独立等待受影响G门通过。

当前 `--backend-alpha1-candidate` 允许 dirty checkout，但必须固定包中每个源文件字节清单及实际源码摘要；Git HEAD 不能单独代表未提交内容。候选构建输出留在仓库外，不提交 native binary、ZIP、凭据、数据库或完整本地日志。后续任何实现/资源变动均形成新候选 hash，旧验收不能无条件沿用。若正式构件的 manifest/catalogue 资格位变更导致包 hash 改变，新的确切包必须重新做受影响的加载/冷安装/安装资格验证，保留旧候选到新包的可审计关联，不把旧 hash 的通过粘贴给新 hash。

W12 应统一 `BACKEND-CANDIDATE.md`、audit/build/cold-install 脚本的 candidate 与 delivery 两种资格语义。当前任务不授予正式发布、push、PR 或模型/平台实测权限；执行验收的写者按已有用户授权和实际环境开展，缺真实环境的门如实未验证。

## 9. 文件写者和交接

| 工作 | 写者边界与具体交接 |
| --- | --- |
| GraphCoordinator/runtime_context 总装 | W01 当前唯一写者；依次完成 D04 current continuation、C04 prepare/final、D13。其他 helper 写者不得直接改这些文件。 |
| C04 prepare helper | 本轮 c04_prepare 写者只改获派新 service/helper；消费本页协议，把可调用参数、CAS hook、返回原件交 W01。CPU quote policy 修复由获派该文件的 W01/主任务唯一写者完成。 |
| D07 C04 issuer | D07 域写者实现上节纯 issuer；W01 负责当前读取、来源资格、安装政策及 final deterministic replay。未分配时由主任务明确交接，不能两人改同文件。 |
| D04 appraisal/semantic/numeric cost helpers | 主任务分别分配新 runtime/域 helper 与 Authority/model driver，产不可变原件和复读端；W01 仅串接，不把 caller candidate 当受信服务。 |
| D01/D02/D07/D08/D10 行为 | 域写者补纯 proposal/schema；运行总装写者实现上表生产 handler/current port。注册表/schema 公共变化由唯一公共合同写者协调，W12 生成实际 catalogue。 |
| D12 生命周期 | D12 写者独占 `backend_operation_contracts_v1.py` 和工作台 routing/DTO；runtime lifecycle/maintenance helper 由主任务另派，不与 W01 争 GraphCoordinator。运行时 producer 与 reader 共用该 DTO，无循环 import。 |
| C09 | 消费专属当前 authority pointer/erase/rebase 端口；本页不另立控制指针或存储清理权威。 |
| 构件与验收 | W12 构建并 pin 候选；W13 记录该确切构件的实际轨迹与功能结果。编译数字、静态映射、脚本存在不代替验收。 |

## 10. 必要验收与手动场景

先编译受影响源码；完成实际产品链后只跑必要验收，不新增过渡测试，不反复跑历史全套。本页没有执行任何测试，也没有产品 PASS。

必要产品轨迹至少覆盖：真实 Owner/install 的 appraisal→drive→两次 current joint continuation→历史 baseline→当前 Mood 单因素不同的 C04 排序→一次执行和各一次费用→五写采用→D13 原结果费用/standby/activation；同 ID 重试无重复执行/扣费/经历；claim 后断线保持 unknown；terminal 已耐久后重启恢复；来源撤权或 Focus/Mood 变更拒绝采用但保留费用；final 注入故障无半份写集。

其余十三域必须出现上表的实际行为后果：成长改变后续 PersonaView/价值排序；身体 cursor/真实 effect 去重；Concern 公平轮次和 reflection 停止；simulation 维持 hypothetical；双方承诺真实资格；生活/offline 明确模拟与实际；contact quiet hours/配额/unknown；迁移源撤权与目标恢复；升级失败恢复；control generation/job 生效；隔离实验不影响生产。手动操作者使用单独获授权的实例与固定候选，保留 operation/effect/call IDs、读版本、实际收据和必要摘要；不得在真实用户运行库中为了验收临时改 READY、绕 Owner 或伪造来源。

尚未验证项必须逐条说明可重现手动入口、所需配置和可观察结果；“接口现在能调用”仅说明接线，不等于服务资格、数值/语义质量、宿主平台或完整后端已通过。
