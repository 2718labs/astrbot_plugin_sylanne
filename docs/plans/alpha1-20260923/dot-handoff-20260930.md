# Sylanne 后端交接给 dot — 2026-09-30

> 状态：用户明确暂停本会话开发，交接当前未完成的开发源码。本文和源码快照不是安装候选、正式版本或产品验收通过证明。暂停后没有继续实现功能、修复源码、付费调用模型或发送平台消息。

## 1. 任务与交接点

用户要求完成完整重型 `embodiment-3.0.0-alpha1` 插件的全部后端，包含十三域协作、实际 AstrBot 生产接线、独立 Authority 服务、费用/恢复/删除/迁移、原生数值内核和 Linux 安装交付。不能把四个重点缺口完成当成全后端完成，也不能把开发适配器改名交付。

原总任务会话：`codex://threads/01a0c908-2e83-7453-9d34-25628e22b8e7`。任务已从该会话回收并在 `G:\Sylanne` 本地实施。最终实机在用户自己的 Linux AstrBot 服务器，由用户自行安装 ZIP 测试；不再要求 SSH、远程凭据或费用授权。当前交接源码包供 dot 继续开发，最终可安装 ZIP 尚未生成。

暂停时本地身份：

- 工作区：`G:\Sylanne`。
- 分支：`codex/alpha1-runtime-checkpoint-20260923`。
- HEAD：`72c9235bf025b66e0a83f02d34661a32abd3250b`。
- 工作区有大量修改和未跟踪源码；交接包必须包含当前实际文件，不能只执行 `git archive HEAD`。
- 模块 PR 的共同 base 是 `codex/embodiment-3-rewrite`；这与当前本地分支不同。没有创建 PR、push、merge、发布或源码提交。
- 原八个历史写者不再运行。最后只启用一个 Astra/high 只读架构审查和一个 gpt-6.1-sol/high 编码写手。写手已停止并交回回执；禁止自动重启旧模块任务。

源码快照配套 `SOURCE-MANIFEST.json` 给出实际纳入文件的 SHA256，`VERIFICATION.json` 区分交接时语法编译、未执行验证和产品状态。这些记录比旧 PASS 文字更新；签名安装信任根必须由后续受信安装生成，交接哈希不充当产品信任根。

## 2. 当前用户约束

最新用户 AGENTS 指令替换旧版：本机不准尝试 `rg.exe`，使用 PowerShell/Python；按代码层面最优解实施，先确保编译，严禁过度测试、严禁防御性编程。项目正文仍明确禁止临时过渡测试、无效测试和反复验证。用户指令高于 Skill；不因 Skill 强制扩大测试或派工。

串行任务由主任务直接完成，复用上下文；用户最后额外允许一个编码写手。架构级、战略级设计和科研数学推导使用 `gpt-6-astra / high`。子代理只允许 gpt-6.1-sol、gpt-6-luna、gpt-6-astra，名字包含任务、模型和强度。不要把这些 Codex 调度偏好误当成 dot 自身工具配置。

保留未相关脏成果；不改其他模块工作树；不自动恢复旧核心或旧接口作为运行回退。真实合同要求的授权、来源、当前代际和费用资格不能用假 DTO、零值或恒 True 代替，也不要额外堆叠假设性兜底。设计修改保持本地，不自动创建或更新设计 PR。未经后续授权不推送、合并、发布。

源码包排除运行数据库、凭据、私钥、环境、缓存、原生构建产物、完整本地日志和旧构件。已有测试源码可以保留给后续必要验收使用；本轮没有新增测试。

## 3. 先读哪些文件

以下路径相对源码根；便携包内源码根为 `Sylanne/`。

1. 本文：当前暂停点和未完成项。根目录 `START_HERE.md` 给出包的布局。
2. `docs/plans/alpha1-20260923/backend-integration-20260930.md`：当前 Astra 冻结的执行接缝，尤其 C04 §2.4、其余域 §5.1–5.3、D13 §7.1–7.2。
3. `docs/plans/alpha1-20260923/c09-storage-switch-v1.md`：C09 四库、唯一控制指针、INTENT→PREPARED→SWITCHED→CLEANED→RELEASED、十二实际清理表面与累计 Graph ACK。
4. `docs/plans/alpha1-20260923/backend-completion-20260930.md`：全后端范围和要求账，不只看当前四个缺口。
5. `docs/plans/alpha1-20260923/backend-serial-handoff-20260930.md`：历史串行实施记录。其较早的“唯一写者”“下一项”和编译记录是对应当时状态；以本文、实际源码和新回执为准。
6. `docs/plans/alpha1-20260923/architecture-gate.md`、`task_plan.md`：重型 alpha1 总入口；`docs/architecture/sylanne-3-design-index.md` 和 `module-collaboration-contracts.md`：域权威与协作。
7. 域合同：`c04-current-association-v3.md`、`c04-internal-work-protocol.md`、`d04-appraisal-admission-v2.md`、`d04-joint-product-path.md`、`d04-joint-state-output-v1.md`、`d13-product-reply-integration.md`、`d09-qualified-natural-expression-v2.md`、`v2-migration.md`。

区分用户确认、冻结裁决、旧助手草稿、源码已实现行为和运行验收。设计文件或注册表本身不证明生产链已接通。

## 4. 当前代码地图与已落盘行为

核心源码在 `rewrite/sylanne3/`；宿主入口 `main.py`、`rewrite/sylanne3/runtime_context.py`；共享图入口 `graph_coordinator.py`、`graph_store.py`；宿主 `host/`；独立服务 `authority_service/`；域实现 `domains/d01` 至 `domains/d13`；原生内核 `rewrite/native/`；安装与构件工具 `rewrite/tools/` 和 `scripts/alpha1/`。

### D04 数值与 C04 回忆

- `authority_service/d04_numeric_service_v3.py` 与 `d04_numeric_journal_v3.py`：实际 numeric Authority 服务、同一 mixed execution journal 的专用 entry codec/扫描、安装 build 身份、Core claim/terminal CAS、实际 prepared/measurement reader。相关 mTLS RPC、Host client/port 已接。数值删除与 current recovery/binding/费用事实已补兼容。
- `authority_service/internal_accounting_v1.py`：从实际 C04 service/journal 独立复读签发无内容的历史 CPU/Body 投影和专用费用 fence；精确已完成费用 finish ACK 可恢复，不因原 Owner 或 deadline 失效而抹掉真实费用。
- `runtime/c04_historical_accounting_v1.py`、`graph_c04_accounting_v1.py`：真实费用/身体原件与差异、独立原作业终结。缺 Body 资格保留 gap；unknown 不用 0 代替。
- `runtime/graph_c04_product_v3.py`：prepare 原件→inspect→首次原作业 acquire/execute→terminal→历史费用→当前 Owner/fence/deadline/五写采用。采用与实际 D11 completed job、runtime outbox/provenance 同事务。RuntimeContext 提供 prepare/advance V3。三个新增 C04 表已安装并加入 migration DIRECT。
- 当前 D07 SQL issuer 与安装代码政策已用于 C04 的真实 association interpretation；D04 authored/legacy wire 显式分版，不混贴 schema。

这些是源码接線，尚未做完整产品运行验收。剩余：真实 Host 自动触发、claim-only 当前图状态持久化/重获资格、防重复派发、Body lineage 当前性；D04 全 appraisal driver、installed mapping/current reader、D01/D03/D05/D07 资格、CPU 费用原件与贡献的一次性原子消费、部分结算/最终补账区分。

### C09 四库维护

新实现入口：

- `authority_service/c09_storage_control_v1.py`：独立签名控制日志、实际 Windows/POSIX OS lease、唯一 current 四路径与代际、append-only build originals。
- `c09_storage_maintenance_v1.py`：WriterGate、prepare/switch/resume、十二表面调用、close/apply/release 编排。
- `c09_build_originals_v1.py`：封闭 installed DTO codec、已登记 inode 的冷恢复、完成候选独立复读；已提交候选按冻结来源在内存重算比较，不覆盖旧文件。
- `c09_authority_storage_rebase.py`：实际 Core/execution/deletion 重建；新 execution ID、anchor nonce 和 continuation token 固定于 signed build plan。
- `c09_graph_application_v1.py`、`c09_close_apply_v1.py`：真实 CLEANED/十二原件→closed mutation/append/CAS→累计 Graph ACK→scoped applied→Graph anchor 同步→RELEASED 原件。
- `c09_process_identity_v1.py`、`c09_surface_cleanup_v1.py`：实际 OS PID/birth 退休、登记目录/旧文件清理与独立复读；通用 surface 证明仍需按下节整改，不能直接作为全清理资格。
- `daemon.py`、`deployment_config.py`、`mtls_server.py`：可配置安装 C09 reader/gate/factory、从唯一 current 解析四路径；RPC维护路由和业务关门已加。

Core clear 与“存在历史删除”不再永久禁止当前业务：新 `Core.require_current_content_ready_locked` 要求真实 current RELEASED、applied proof、namespace active/clear；相关 fences/迁移/result consumer/bridge 已替换旧 blanket history 拒绝。实际行为仍未验收。

暂停前主任务完成的最后四项源码修正：

1. continuation permit token 写进 `authority_build_plan`，`_CoreTransform` 不再重算时随机生成 token。
2. 路径函数拆成共同 installed path、regular file、directory，目录清理不再以 `is_file()` 拒绝真实目录。
3. 普通准入改为同 OS handle 的稳定 file identity；封存/切换/删除前保留完整 hash，不每次 RPC 遍历四库所有字节。
4. `v2_scoped_erasure_store.apply_verified_head` 统一 journals→Core→Graph 锁序；实际 CAS 抽成共享 locked helper，不在 Graph锁内反向进入 journals/Core。

第 1–3 项包含在暂停前一次 18 源编译中；第 4 项在一次机械提取后又修正了 Core tx 与 tail 变量作用域，暂停前没有再编译。交接时的一次语法记录覆盖实际快照；未进行该链运行验收。

### D13 前台自然回复

`model_broker/natural_reply_history_v3.py` 早已落 typed raw turns、history selection、NaturalReplyInputV3/Frozen V3、真实三消息 builder 和 current output parser。后台压缩 schedule/acquire/seal/once-call/result durable→费用→standby/recovery 已有模块及 Runtime/Graph delegate；前台此前仍 V2 空历史。

暂停时最后编码写手只实际写了 10 个文件：

| 路径（相对 rewrite/sylanne3） | 本次写入 |
|---|---|
| `runtime/natural_original_v3.py` | 新增独立 generation/review V3 seals 和按实际 frozen 类型选 template/refreeze helper。 |
| `runtime/natural_reply_job_v2.py` | V3 frozen/seal 显式解码与保存配对，原 call template 按版本核对。 |
| `runtime/natural_generation_issue_v2.py` | issuer 按实际 frozen 选择 V2/V3 generation seal。 |
| `runtime/natural_review_issue_v2.py` | current output parser 和 V2/V3 review seal 分派。 |
| `model_broker/natural_review.py` | review freezing 接受显式 V2/V3 generation seal；review wire仍 V1。 |
| `runtime/natural_scoped_query_proof_v2.py` | scope derivation/qualified projection 接显式 V2/V3 frozen。 |
| `authority_service/v2_natural_generation_content_service.py` | generation parser 按实际 frozen 版本。 |
| `authority_service/v2_natural_generation_output_service.py` | terminal/result selector 使用 current parser。 |
| `authority_service/v2_natural_paid_review_service.py` | paid review读取generation时按实际版本解析。 |
| `host/authority_profile.py` | natural_generation template allowlist 加 V3；没有改 installed defaults。 |

写手最后一次写入正常退出，但没有运行 compile/import；这些是未完成源码。交接语法记录不能把生产 V3 标为通过。GraphCoordinator、RuntimeContext、Host `_natural_messages`、natural original verifier、fence consumer、model egress admission 尚未由写手接 V3。

## 5. Astra 最新 C09 审查：已修与仍未修

包内 `ASTRA-REVIEW.md` 保存审查与裁决摘要。以下问题均须结合真实源码继续，不能只改文档 PASS：

| 问题 | 暂停点 |
|---|---|
| 已提交 Core candidate 重算随机 continuation token | 已改为 plan 固定 token；需产品恢复验收。 |
| 实际目录被 regular-file check 拒绝 | 已拆路径类型；未执行实际清理。 |
| 普通业务准入四库全量 hash | 已改 identity observation；完整 hash用于最终封存。 |
| scoped applied 的 Graph→journals/Core 反锁序 | 已改源码锁序，未运行该链。 |
| 第二次 C09 被上一 RELEASED operation 阻断 | **未修**：maintenance `RELEASED` 无条件返回，RPC仍对历史 active_operation 排他。应同operation精确恢复，不同operation从真实accepted run新prepare；排他仅对INTENT..CLEANED。 |
| PREPARED冷启动重开旧handles后直接switch | **未修**：switch必须共用关闭完整旧bundle、排空reader/worker、源最终fingerprint的前置步骤；不得重prepare或覆盖候选。 |
| 同进程热替换四库与真实process cache退休冲突 | **未修**：目前switch仍调用不完整的current_bundle_factory，仅替maintenance引用。采用下一段明确冷重启裁决，不先实现热替换再强制重启。 |
| generic Graph证明冒充模型缓存等表面清理 | **未修**：实际factory必须安装对应表面的reader/cleaner；Graph root只覆盖Graph分类行，登记目录覆盖本地文件，provider cache须实际受信配置及清除/不存在原件。缺支持保留HOLD。 |
| execution payload只证明旧文件消失 | **未修**：删除前复读sanitized resolver费用、typedunknown、原journal lineage与约束占用。 |
| RPC门禁仅登记Authority自己的incarnation | **未修**：须真实服务端peer/worker admission，绑定pointer/version/generation/epoch；不能每次请求替旧Host自动升级。直接Graph写、SDK/job/cache/recovery/accounting同生命周期。 |

冷重启裁决：原进程完成prepare、关闭旧handles、原子SWITCHED、业务保持关闭，返回可恢复 `restart_required` 并由受信本地服务supervisor退出/重启。新进程先持OSlease读唯一current，四库维护打开；核原Authority及全部登记缓存持有进程的PID/birth实际退休；完成十二surface→closed→累计ACK→applied→anchor同步→RELEASED；随后重新授予Host/worker/Owner当前代资格。保留Owner长期身份，旧会话/issue/pending/permit/nonce不能自动恢复执行资格。真实历史费用/unknown/未决占用保留。

## 6. D13 最新裁决与下一接点

D13 window与natural plan的audience原件都来自同一 `d03.account_binding` 的精确版本；保持相等合同，不新增映射权威。V3 question须直接用实际audience的VersionedRef；conversation字符串单独保存，不作图版本。旧V2 `VersionedRef(route.conversation_ref,audience.version)` 原件不追写。

真实接点：`GraphCoordinator._prepare_natural_generation_scope_locked` 同一当前frame复读D13window、paid persisted cache原件与非重叠raw尾部，构造相同实际V3builder的raw/compressed完整wire；只历史表示/selection不同，provider/model/config/tools/max_output一致。复读资格、计数、费用并CAS选择；D11 quote/seal/job/call/request摘要绑定被选完整wire。Host SDK实际发送该wire，paid review按生成V3原件核语义，D09资格不从D13文字取得，D11 final dispatch继续当前检查。

stock没有合格full-wire counter：可以冻结合法raw，并沿正常natural独立D11预算/quote/request admission，状态为 `raw / token_evidence_unverified / activation_not_attempted`。不声明fit，不填0，不将counter缺失变成全局恒HOLD。所有compressed实际选择、standby→active、旧active复用均需本次完整wire的实际installed exact/bounded原件。政策允许时compressed.upper<=capacity且raw跨界区间可用 `raw_fit_unproven_compressed_fit_certified`；不能拿普通整数、UTF8长度或事后usage伪造事前证明。平台超窗/unknown不得换workflow或call重发。

下一处精确挂钩：Host `astrbot_model_call._natural_messages/_request_allowed`；`natural_original_binding_verifier.py`；`host/v2_fence_port._natural_paid_consumer_facts_current`；`authority_service/v2_model_egress_service.py` natural branches；GraphCoordinator当前V2空history；RuntimeContextinstalled入口；new seal/frozen复读配对闭包。

## 7. 其余全后端未完成范围

- D07 Concern/reflection/simulation typed stage和concrete ports已有；真实W01 frame/envelope/Owner/Graph CAS/Host trigger注册、D11execution服务四端口尚需接。
- D01/D02/D05/D08/D10 bounded production行为和实际caller按冻结§5.1–5.3继续；纯函数、注册表或方案不能替代真实链。
- D12已有lifecycle operations/ports/reconciliation/target verifier，freeze→snapshot→revoke→targetprepare/import/reconcile→activate骨架；剩current command/status Owner fences、撤权后exact original身份的无内容查询、HTTP status resolver、artifact registry/targetfactory、backup/share/import实port、maintenance executor、C06experiment/C10supportexport producers及全流程。
- C09当前实际factory、Host/GraphWorker/控制日志/进程supervisor/新世代资格仍无闭合装配。还需核C04/newnumeric实际费用binding、unknown resolution原件/一次结算、D02/D11parentbudget精确关联和新增表migration/C09分类。
- 构件中央 `verify_installed_backend_runtime_v1` 与candidate v2资格已落；旧formal资格仍独立。audit/cold/BACKEND-CANDIDATE文档和残余formal-only gates需按actual backend runtime scope统一；不能把formal验证标True以绕门。
- 尚无最终Linux安装ZIP。需要在目标Linux ABI匹配平台编译native library，固定真实source/catalogue/native/manifest，必要冷安装及全链验收后再交用户。已有Windows/WSL旧构件/旧PASS不能证明当前dirty源码。

建议dot次序：先读取当前快照编译诊断与D13部分写入；按已冻结裁决补C09冷生命周期/factory和peer代际；完成numeric/C04/D07实际自动触发及费用闭合；完成D13前台wire；按全后端账补其他域和D12；最后仅做必要产品验收、Linux构件和手动说明。不得因本会话暂停就把工作缩成单一D13或四个gap。

## 8. 工具、编译与实际验证边界

已知本机可用：

- Python：`C:\Users\pidan\AppData\Roaming\uv\python\cpython-3.13.14-windows-x86_64-none\python.exe`，3.13.14。
- AstrBot隔离环境：`D:\bun\tmp\codex\sylanne3-host\Scripts\python.exe`，AstrBot4.28.1；不是用户Linux安装。普通uvPython无AstrBot依赖。
- Cargo：`C:\Users\pidan\.cargo\bin\cargo.exe`。依赖锁 `rewrite/native/Cargo.lock`；native crate `sylanne3_kernel`，cdylib/rlib。
- Python插件runtime无额外第三方依赖；AstrBot提供SDK。Authority依赖在 `requirements-authority.txt`。

暂停前已有受影响源内存compile、部分独立模块import结果，详见旧串行记录。此前完整Pythoncompile与cargo check是较早源码，不能用来证明最后改动。完整RuntimeContext host import未取得有效通过结果；有缺依赖/挂起尝试被取消，不报PASS。

交接时只进行一次对打包Python源码的内存语法编译和归档逐文件完整性核对，不创建pyc、不导入运行服务、不运行产品数据库/临时smoke/测试/收费SDK/平台发送。具体结果写在 `VERIFICATION.json`。暂停源码出现诊断则原样记录，不在暂停后继续修功能。

后续必要实机验收至少观察：当前Owner入站到真实自然generation/review/最终发送；D04实际数值与CPU/Body/unknown费用；C04重复inspect/claim-only/terminal及deadline或撤权后的只记费不采用；C09各崩溃阶段精确冷恢复/原进程退休/十二实证/第二轮维护/旧Host阻断及新代业务；D13 raw历史、真实counter缺失状态、有合格counter时压缩选择与过期source/TTL；D12备份迁移撤权及targetactivate。执行范围和费用应由后续用户实际安装配置确定，本包不授权收费调用。

## 9. 给 dot 的接手提示词

> 读取本包START_HERE、DOT-HANDOFF、ASTRA-REVIEW、D13-WRITER-RECEIPT和VERIFICATION，再核SOURCE-MANIFEST与实际源码。接续Sylanne完整重型embodiment-3.0.0-alpha1全部后端；当前快照未完成，用户最终自行Linux AstrBot安装ZIP。沿冻结backend-integration/c09-storage-switch合同与最新用户约束实施；先compile，避免过度/过渡测试和防御性编程；保留dirty成果，禁止旧核心运行回退、假原件/零unknown/恒True。不自动Git提交/PR/push/merge/release，不联系服务器。C09采用Astra确认冷重启生命周期，D13保持真实audience与actual full-wire计数边界。完成全账实际生产caller、费用和恢复，再做必要验收，最后交真实Linux安装ZIP/hash及未验证项手动说明。

如果dot仍在同一机器上工作，可以直接继续 `G:\Sylanne`，无需把ZIP覆盖回原目录；跨机器则解压 `Sylanne/` 到新目录，原Git HEAD/dirty状态作为溯源记录，包内没有 `.git`，不要假设其内容就是干净HEAD。不要直接把开发快照作为AstrBot安装包。
