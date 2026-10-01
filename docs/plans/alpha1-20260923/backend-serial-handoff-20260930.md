# 全后端串行接续

> 2026-09-30 最新状态：用户已明确暂停开发并要求交给 dot。当前交接入口为 `dot-handoff-20260930.md`，以该文、实际快照及 `VERIFICATION.json` 为准。最后用户允许的一个 D13 编码写手已经停止，10 文件仅部分落盘；下方历史“唯一写者”“下一项”和 PASS 记录不得当作最新全链状态。暂停后仅整理交接/源码归档，不继续功能实现。

用户后续要求可串行任务全部主对话直接完成，仅用户允许时才使用子代理。2026-09-30 全部活动写者已在安全落盘边界 released。下面是源码接续清单，不是产品通过声明。实机由用户在 Linux AstrBot 自行安装测试，本会话最终交付真实 ZIP/hash/手动方法，不再请求 SSH 或费用授权。

## 唯一写者

全部后续源码、共享入口、编译和构件由主对话持有。不得重启旧模块任务；保留原脏成果，不 Git 写/PR/push/merge/release；不得使用 rg.exe 或临时过渡测试。架构已冻结在 backend-integration-20260930.md 和 c09-storage-switch-v1.md，实施优先沿这些合同，不因找不到接线就制造新权威或伪原件。

## 主对话已接

- C04 host AuthorityClient / mTLS transport V3 execute/inspect，按实际算法匹配；服务端/daemon 原有 V3 支持。
- C09 v2_fence_store 认证 accepted deletion storage bridge；current_erasure/guard/recovery/closure 传实际 Core，旧 receipt 不改。五源一次内存编译通过。
- target activation 在最终 Core tx、Owner头复验和 require_idle 后调用 `holder.require_current_reconciliation_in_tx(db, held, execution_head, deletion_head)`。一源编译通过。
- `runtime/domain_production_contracts_v1.py`：bounded typed frame/query/original/policy/Owner/staged/job/outbox/receipt，不是授权 token。一次编译通过。
- native `d04_joint_product_math.py` 保存全部实际 family_transcript_originals，不复制 full。一次编译通过。
- 新 `authority_service/d04_numeric_journal_v3.py`：同一 mixed execution chain 的专用 entry codec/append，尚未接扫描与安装 service。

## D04 / C04 接续

W01 shared 已有 `_owner_domain_write_v3`、`prepare_internal_work_v3`、frozen input reader、current joint product freeze、`_commit_domain_bundle_fenced` 内部 C04 adoption issuance、Runtime V3 installed port。新 `c04_product_original_v3` 保存实际旧 envelope/deadline；`c04_product_lifecycle_v3` inspect/claim-only waiting；bundle 和固定 presence code-policy helpers 已落，但公共 final/driver未接。

实际 authored DTO 已分版，V3 数学 ID 复用、实际 build hash更新，旧 legacy/mixed 拒绝。需完成：当前图自动解析 focus/ticket/active lineage Mood；latest_eligible_encoding.v1 当前完整候选查询与排序；D07 true issuer替代 caller candidate 自重建；当前编码观察与新baseline（不得回填旧 C02/unknown）；同 tx五写+job/outbox/provenance/receipt；真正 inspect→首次execute→terminal→CPU/Body费用→final；原deadline/撤权后的独立historical-accounting fence/job closure（冻结合同§2.4），不要直接删Owner gate。

`d04_appraisal_driver_v3` 已有stage/seal/result durable/D11/adoption CAS原件；`d04_semantic_mapping_v3` 真实映射和evidence；`d04_numeric_cost_v3` 专用 quote/reserve/job/同步thread_time/measurement/importsettle。尚需schema安装、installed mapping producer/current reader、D01/D03/D05/D07资格、完整host appraisal driver。Host model_egress_executor 对 appraisal仍恒None，专用 Authority reader已落且只有prepare允许allow_unsealed_prepare。appraisal_cost部分结算当前会锁成不可变，需要原call补账区分partial/final。

Numeric contract已落；service需 claim/terminal/read exact DTO、Core head CAS、protected安装key/paired executor、实际measurement读器；scan/source facts/bindings/C09处理新 ENTRY_PREFIX。当前 prepared reader具体SQL已落，measurement reader在numeric_cost helper；二者只能启动受信安装，不能请求临时callback或浏览器CPU。Joint final还需独立已付CPU引用/贡献原件原子消费分支。

## D13 接续

后台 Graph六delegate和Runtime入口已接，真实schedule/acquire/seal/once-call/result durable→cost→standby/recovery模块已落；前台未接。`natural_reply_history_v3.py` 已有精确raw turns/history selection/NaturalReplyInputV3/FrozenV3/三消息canonical builder及output version parser；旧V2语义不放宽。

需新增 `runtime/natural_original_v3.py` generation/review typed seals；接真实 `natural_reply_job_v2.py`、`natural_generation_issue_v2.py`、`natural_review_issue_v2.py`、`natural_scoped_query_proof_v2.py` 显式V3分派、Authority三service、Host真实SDK builder/profile；Graph `_prepare_natural_generation_scope_locked` 目前历史为空，需当前D13 window+paid persistedcache/current读+activation CAS。raw/compressed完整wire只有history差异，实际D03 audience head，不能conversation@0。缺 installed official counter/pinnedtokenizer policy时typed unverified、standby保留，不UTF8/整数伪证；selected main必须actual natural_generation provider/model/config一致。bounded费用下限包含全部tool_reserve。

## D07 与其余域

D07三new files已编译：current_issuer_v1、d07_current_behavior_v1、installed_d07_behavior_port_v1。C04具体API `issue_current_association_interpretation_in_transaction_v3` 真实来源闭包+三种合法interpretation；presence固定code-policy需要manifest/source/build pin。Concern/reflection/simulation typedstage + concretegraph/job/costreader已有；仍需主对话 actual frame/envelope/Owner/graphCAS/hosttrigger注册和真实 D11 execution service四个端口。D01/D02/D05/D08/D10 bounded行为按架构§5.1–5.3 尚需串行实现与生产caller；不把已有纯函数/注册表当完成。

## D12 接续

service/issuer/async/DTO 已接六类原件。lifecycle_operations_v1、installed_maintenance_port_v1、workbench_lifecycle_port_v1、installed_migration_reconciliation_v1、target_verifier已落并五源编译通过；真实transfer顺序freeze→snapshot→revoke→targetprepare/import/reconciliation→activate。尚需 current command/status Owner fences（source revoked后exact original身份无内容查询）、HTTP status resolver、artifact registry/target factory、backup/share/import具体port、其余域/代际控制、真实maintenance executor、C06 experiment/C10 support export producer。

四新表直接bot/persona归属，需migration _DIRECT/C09处置登记：graph_d12_backend_operations_v1、graph_d12_backend_originals_v1、graph_d12_lifecycle_plans_v1、graph_d12_lifecycle_steps_v1。D07 graph_d07_behavior_original_v1已纳C09但migration需登记；D04 graph_d04_originals_v3/D13新表也逐一核对。

## C09 接续

control、WriterGate、maintenance、archive/source/frame/resolver/builder/Core bridge/V4已落部分。必须修 INTENT部分已有candidate恢复（按archive/issue/mirror继续，不重建覆盖）、deletion新文件封存前WAL/checkpoint/close、十二actualsurface清理/独立复读与close/apply/GraphACK/RELEASED、daemon/config/installer/lifecycle真实安装control/key/OSlease/current四路径/gate/currentbundlefactory。unknown resolution原件过滤/一次结算、精确D02/D11 parentbudget关联和newnumeric事实仍未完成；不能把Core clear当已RELEASED。

## 构件接续

中央 `verify_installed_backend_runtime_v1` 已落，返回兼容InstalledPackageVerification尾加scope/catalogue。v2 candidate qualification生产验收范围，旧v1 diagnostics严格保留，formal独立资格。builder绑定authoredpreset/source_inventory，C04V3 build固定所有实际pythonbytes，service有installed_runtime_verified（formal_build_verified仍真实formal）。尚未改 audit/cold/BACKEND-CANDIDATE.md；joint output二次loader/第二门残留formal，Core/server/C09reader/D11CPU门要换installed_runtime_verified；Graph/Runtime相关formal-only checks和outputpolicy调用需显式backendruntime；之后才仓库外build固定ZIP/hash并必要冷安装。

## 本轮合并检查

### 主对话后续已落源码（仍未进行产品验收）

- 实际 D04 numeric Authority 服务、同 mixed execution journal codec/扫描、protected build identity、mTLS RPC/client/port，以及 numeric erasure/current recovery/binding/费用原件兼容已经接线。claim-only 保留真实未知值和 CPU/Body 上界，没有用零代替未知。
- 新 `internal_accounting_v1.py` 用实际 C04 service/journal 的独立复读签发内容无关的历史 CPU/Body 投影和专用费用 fence；原已完成费用允许精确 finish ACK 恢复，不重开执行、不依赖已过期 Owner/deadline。
- 新 `c04_historical_accounting_v1.py`、`graph_c04_accounting_v1.py` 持久化实际费用、身体原件/差异和原作业终结。费用与终结各用原确定身份；费用不会因不采用而消失。缺 Body 资格保留 gap，不伪造已付。
- 新 `graph_c04_product_v3.py` 接 inspect→首次原作业 acquire/execute→terminal→独立历史费用→当前 Owner/fence/deadline/五写采用。当前采用同事务写实际 D11 completed job、runtime outbox、provenance。RuntimeContext 提供 prepare/advance V3；实际宿主自动触发与 claim-only 当前图持久化仍需收尾。
- 三个新增 C04 表安装并登记 migration DIRECT：历史费用尝试、原作业终结、采用 provenance。outbox ref 改为真实 D11 AtomKey，query epoch 改为 all。
- 最近上述七个受影响源内存 compile 和 C04 product module import 通过。此前十个 numeric/C09 受影响源编译通过；具体费用合同/host ports 编译及导入通过。没有产品 DB、临时测试、付费 SDK 或平台发送。
- 当前接线 C09 daemon/config：原 Windows 单实例锁改为真实 Windows/POSIX OS lease；严格 InstalledC09AuthorityV1 配置、受信安装 factory、先解析签名 current 四路径再 preflight/open、journals/Core current reader、RPC 共用 WriterGate/独立 maintenance route 已落。五源编译/daemon+config 导入通过后又修正 server._core 与实际 signer 安装两处；仍待受影响编译。
- C09 storage admission 对 accounting/recovery 与 business 同样关门，只维护路径可在 INTENT..CLEANED 使用。实际 maintenance 接 ProductionGraphStore。

下一项仍是 INTENT 已有 Graph/Core/execution/deletion 候选的精确冷恢复和新 deletion checkpoint/close；当前 builder 每次 fresh target/新 exec ID，不能安全恢复部分文件。daemon factory 的实际十二 surface/closeApply/current bundle 生产组装、切换后的旧 RPC/journal handles 替换仍未完成。不得因配置接口已接宣称冷开或 RELEASED 产品通过。

上述 INTENT builder 缺口已继续修正源码：control 显式安装 append-only `c09_storage_build_originals_v1` 扩展，签名记录 Graph/Authority build plan、四文件分配 inode、已完成文件处置和整个 candidate。执行日志 ID/新 anchor nonce/Graph incarnation 持久固定；重启不新建身份。新 `c09_build_originals_v1.py` 的封闭 DTO codec 与真实 cold file/root 校验只接受已安装类型，不从 JSON import。已提交但未写完成回执的登记 inode 在内存重新计算实际冻结来源的全部行/DDL/pragma 并与真实文件比较；不覆盖已提交候选。空文件分配在事务回滚恢复后可继续原构建；未登记非空/异身份/异来源/异内容残留保持 HOLD，不删证据。Graph builder 不再在失败后 unlink。新 Core/exec/deletion 候选显式 checkpoint，cold reader 用 closing 真实关句柄。Graph mirror 已存在时读 Core 已签 issue 原件并走已实现 replay 分支，避免对镜像后的文件再按镜像前 hash 新签。

最近五个 C09 受影响源编译通过，固定 DTO 的 type annotations 全部实际解析通过（未构造业务对象、未运行测试）。随后小改动：实际 OS lease 每次核对被锁句柄与路径 inode；CoreTransform 构造函数要求计划里原固定 nonce。后续从十二 surface 和正式 closed→累计 Graph ACK→scoped applied→RELEASED 继续，`CurrentErasureAuthority.close` 和 `AuthorityV2ScopedErasureStore.apply_verified_head` 当前仍为 HOLD 占位，不能调用 `_apply_controlled_head_for_storage_test` 冒充生产。

已继续新增 `authority_service/c09_graph_application_v1.py` 和 `c09_close_apply_v1.py`：实际 CLEANED/十二签名原件核验、deterministic 原 closed mutation/evidence/append、current continuation + prior accepted Core 原件 +实际头/permit校验、append/recover/CAS及已 closed独立复读；当前 production Graph空正文维护事件与 immutable cumulative ACK、完整证书 ancestry/永久 erased keys/旧 applied..closed suffix/实际 Coreclosed original 的复读；正式 scoped `apply_verified_head` 安装真实 Graph reader再走共享生产 CAS，原 storage-test wrapper单独保留且未作为产品调用。

GraphStore 安装 `graph_c09_cumulative_applications_v1`，登记 migration DIRECT 与 C09 commitment，新增具体 `cas_c09_recovery_identity_v1` 用真实 Core当前事务、受保护当前四路径/transition/Graph inode/实际anchor核对新 execution journal身份；普通 recovery CAS 的旧身份保护保持。closeApply 提供 closed→ACK→applied→Graph实际anchor同步→release签名。业务 applied guard 使用独立只读 Graph WAL snapshot和当前 Core locked reads，不嵌套 Core事务、不再次获取journal锁，避免 Core准入内的递归与锁反转。

八个受影响源编译和 installed close/application imports通过；目前没有构造产品运行库或进行 closed/ACK/RELEASED 运行验收。`CurrentErasureAuthority.close` 已改为绑定具体 installed cleanup 的 operation_id 入口；maintenance resume 已加单一 RLock。十二 concrete surface cleaners/current bundle factory、实际 Host/GraphWorker与控制日志接线、切换后旧 server/handles 替换、C09 后 Owner/worker 新世代资格以及冷恢复实体验收仍待完成，不把这些源码标为已通过。

全源545文件一次内存compile曾观察coordinator syntax诊断，最终落盘后该文件单次复读编译PASS；其他544源当时无syntax诊断。Coordinator及七个关键独立模块导入PASS，普通uv Python的RuntimeContext缺AstrBot依赖，使用既有isolated host env后再核其导入。没有产品测试、模型调用、平台发送或用户运行库构造。源码后续改变时仅做受影响必要编译，完整产品链完成后再一次验收。
