# alpha1 非前端后续检查点（2026-09-28）

本页接续 [`20260928-backend-evidence.md`](20260928-backend-evidence.md) 的历史审计。以下是当前脏工作树中的局部实施与代理交接，不是冻结源码、正式 `3.0.0-alpha1` 构件或 G0–G7 完成判定。前端 W11 本轮暂缓；不推送、不开 PR。

| 路径 | 本轮实际证据 | 仍缺的产品闸门 |
| --- | --- | --- |
| 自然回复 V2 / K02a–K03 | 同一真实 Owner、mTLS、GraphStore 的受控 AstrBot 4.28.1 用例完成两次付费模型原件、final 同事务提交、P2 图认领和一次 `send_private_msg`；正常、OneBot 超时 unknown、final 后 Owner rev2 撤权及活跃 dispatch fence 内 pending 撤权四参数聚焦 `4 passed`。后两例首次与重试均 HOLD、平台 0 次；pending 发生在先前已提交 claim 后，effect 保持未决。另有独立丢观察 ACK 负例：Authority 记录已持久，首次结果 unknown，重启恢复 HOLD、平台仍只调用一次，聚焦 `1 passed`。模型回应和平台调用均在受控测试中。 | 正式安装下的全链 readiness、真实外部模型和平台交接；完整重启与迁移矩阵仍未验收。 |
| D06 Owner 撤权 / K06 S13 切片 | 真实签名 Owner 会话与 Authority 读栅栏：首次 D06 读成功；读栅栏内 actor 撤权返回 `busy/not_applied`；栅栏结束后撤权提交，原租约再读拒绝，源记录仍有效。原签名链和新场景聚焦 `2 passed`。 | 该切片是 actor 撤权，不是 Owner grant revoke，也未覆盖在途模型外送、最终 effect、旧备份和完整 S13。 |
| D12 工作台服务端 / K08 | W10 HTTP/service/issuer 已有精确 operation 输入与持久原件核对；D01–D08、D10 的窄方案字段已由对应领域编译为有类型候选，聚焦 `13 passed`。D09 新增窄表达策略的 typed 编译、持久候选白名单及 verifier 消费，聚焦 `23 passed`。W01 用真实 Owner 读→写栅栏、D11 已签名 `scheme_compile` 许可，将候选 ref 与不可变编译原件同事务落库；丢 finish ACK 同操作恢复、不支持字段回滚及签名许可拒绝等聚焦 `5 passed`。D07-only 预览已接当前方案、D11 持久 reserve/claim/settle、固定行为探针和不可变报告；主任务补做 WorkbenchService→issuer→真实 W01 compile/preview 与重复读取聚焦 `1 passed`，并据此修正 preview seal 上下层格式不一致。 | D09 策略尚未从已采用 active head 的受信图读取进生产表达；D07 预览仍需更多故障反例及采用后的真实注意力消费者；active-head CAS 与 C02–C12 服务端全流程仍 HOLD。 |
| 运行宿主 / K03、K09 | 新 C02 未就绪时 HOLD，旧 V1 原件仍按原身份恢复；双自然模型和四 Authority 读端的受控 readiness 装配正反例 `6 passed`。真实 mTLS 双连接核对本连接 grant，拒绝交叉 grant；旧 Host 三条驱动也改为各连接自己的 grant，聚焦 `4 passed`。 | 受控 readiness 正例使用测试前提；正式包 `start_v2`、真实平台私群/附件/工具及重启恢复未验。产品 readiness 仍为 False。 |
| 原生核与构件 / K10、K12 | W12 交接：Windows MSVC 和 WSL Linux 的 ABI2 Rust 原生核各 `cargo test --locked --release` 59 项通过，并构建及 smoke；macOS arm64 交叉 `cargo check` 通过。另有本地诊断 ZIP `3.0.0-dev.1`，SHA-256 `4989b9537cb9fdc7ea825f171ea1cbd84e472cda875bd2bc721f59d98dd87256`，逐文件校验通过。 | macOS 缺 SDK/linker，本机无 dylib 链接/加载；ZIP 只允许 `limited-diagnostics`，消息处理与发送禁用，非正式 alpha1。源码继续变化，尚无冻结包/冷安装验收。 |

上述测试数字均为对应代理的定向交接，主任务未在此页重新运行全套测试。D04 新增每成员 full/LOO 输出区间、家族去重剂量、来源/ABI2/纪元绑定的纯数值回执候选，编译及聚焦单测通过；它固定 HOLD，仍缺可信正式包的原生身份、W01 当前栅栏重读、锁外原生重放和原子持久采用。D06 C04 预检新增 D07/D02/D11 同活动、操作、报价及 job/outbox 身份绑定，聚焦 `6 passed`；同库真实 Owner/Graph/mTLS 时钟读取及错来源、超限误差反例聚焦 `1 passed`，但 `commit_current_c04_association_v1` 尚无真实 ProductionGraphStore 集成用例，真正体验提交仍需验收。D12 D09 的 `max_visible_chars` 已有 typed 候选和能改变机械验证结果的 consumer，但生产当前图尚未读取已采用策略，故仍 HOLD。D12 D07 的 13 组纯行为对照探针聚焦 `13 passed`，D11 预览费用持久预留/一次认领/已知或未知独立结算聚焦 `6 passed`；W01 当前方案联测有正例，宿主当前 D07 策略与 active-head 读取聚焦 `4 passed`，但生产仅一张固定信号的入站票，采用后尚无真实多票可见行为，adopt 继续 HOLD。D13 已将压缩模型固定绑定该会话主模型身份，并新增完整 wire/调用前精确计数的纯资格边界，聚焦 `11 passed`；当前宿主没有可信精确计数器，也没有已冻结的付费压缩任务/结果端口，自动付费压缩 HOLD。Owner grant revoke 的 pending 屏障、图 rev2、独立核验和 P2 阻断已有上述同库负例；Authority 已新增可在恢复读取内返回 rev1/rev2、pending 时 HOLD 的当前 Owner head，GraphStore 对真实 rev2 与旧 rev1 图备份的 CAS 负例通过，但该测试采用受控 pinned head，未跨 MigrationService/installed verifier 完成真实恢复。当前 `compose_owner_deployment` 尚无产品启动调用者，迁移 pairing/source snapshot/target recovery 的受信核验器亦只在测试夹具中提供；因此不能声称 Authority daemon 或 S14 已可冷安装。G0–G7 和正式 alpha1 继续 HOLD。

随后补入的切片：D04 新增锁外 package-bound full/LOO replay，编译和 `2 passed`，仍只返回未签 HOLD 候选；正式包、由 D06 当前来源推导的家族及 W01 写栅栏原子采用缺失。Authority 新增进程内冷打开与严格数据 manifest 解析，真实 mTLS 启停、重复实例锁、缺日志/Owner schema 拒绝等 `4 passed`；它没有安装器信任回调和模型/C04/迁移服务，不能从配置文件独立冷启动。管理员 CLI 在已打开 daemon 上完成受控配对/撤销切片 `4 passed`，但首次 creation ticket 因缺 W01 pinned original 核验显式 HOLD。独立 Authority 源码 staging ZIP 的隔离导入与逐文件哈希 `3 passed`，明示无 wheel、服务引导与 OS ACL，不能算正式包。C04 真同库测试现已到达 ProductionGraphStore 来源读取，随后因没有受信 D02 provider outcome verifier 阻断；测试夹具中的许可回调不能作为生产正例。

再后续的局部证据：无前端 Owner 命令通过已配对端口对一次性挑战签名，真实 Authority 会话库与受控传输桥聚焦 `5 passed`；未做真实 mTLS 命令、Windows 私钥安全加载或独立冷启动。D09-only 行为预览、当前方案读取与不可变报告接口聚焦 `11 passed`，W01 已将当前策略与 active-head 图版本接入同事务 final 校验，默认策略下双付费 final 回归 `1 passed`；真正 adopted head 与改长度的产品正例未完成。D13 付费作业身份、结果资格与精确激活纯域链聚焦 `24 passed`，W01 原付费结果核验与 W09 同主模型调用前精确计数未接，因此不能外送付费压缩。S14 管理员固定 source/target 身份和持久撤权切片聚焦 `2 passed`，尚未进入 daemon；源/目标图证明及实际迁移未验。

本地继续集成的交接：D09 已有 Owner 写栅栏下的采用端口，重读编译原件、D11 签名一次性预览及费用结算、同事务 active-head CAS 与恢复元数据；WorkbenchService→issuer→真实 W01 的编译、付费预览、采用及重复读取聚焦 `5 passed`。生产 final 对 D09-only active head 重读当前策略和图版本，默认策略的双付费路径已回归；改变长度策略的完整受信 Owner 正例仍在补初始 draft/head 写口和权限/预算，不能把原先测试中直接注入图原子的结果算产品验收。主任务另将 D07-only stale 预期改为当前 basis changed，聚焦 `1 passed`。Authority 已把首 Owner creation ticket 的真实 GraphStore 原件核验、验证与配对的同一维护锁、同 Core 冷开模型账本和真实 deletion/execution 日志头核验接入；daemon/管理员 CLI 聚焦 `10 passed`，默认双付费 final 回归 `1 passed`。这些仍是进程内受控装配；正式发布者信任根、服务身份/ACL、物理时钟来源与重新打开同一个 Core 的完整双付费链尚无验收。独立安装态策略回调固定证书摘要与 namespace/holder，并在管理员授权时重查 Windows token，聚焦 `3 passed`；它尚未由安装器接线，publisher 校验无正式 trust root 而明确拒绝。

D13 提前压缩必须和会话主模型、提供方、配置及完整冻结 wire 一致。对本地 AstrBot 4.28.1 源码的只读盘点显示，当前官方 OpenAI Chat Completions 路径仅在响应后产生 usage，宿主通用计数器只是字符估算；尚无能证明调用前精确占用的同 wire 接口，因此后台付费压缩的自动激活继续 HOLD。C04 的真同库预检缺 D02 持久同操作资源实际执行收据核验；不能借模型费用账本或 P2 执行日志冒充该收据。S14 只有固定双方身份与 source 图证明切片；目标持久快照、独立约束摘要及目标当前闭包尚无受信生产端口，整套搬迁和旧备份恢复仍 HOLD。

D02 现新增持久原件核验器：要求 active 报价、同 namespace/activity/operation 的 actual 和终态执行回执，其内容及摘要逐项吻合；聚焦 `8 passed`，缺表或任一证据即拒绝。生产资源执行器尚未写入该原件，运行时亦未注入此 verifier，所以它还不能令 C04 正式放行。W10 工作区现在列出命令路由状态，未接入的 C06–C12 命令在服务层即拒绝假成功；编译和服务/issuer 聚焦 `51 passed`。仓库仍缺这些动作所需的受信领域提交、支持包导出或通用实验端口，状态目录不等于操作已实现。

D09 采用后的受信自然回复对照现已完成：真实 Owner/mTLS/同一 GraphStore 中，公开 Workbench 服务先初始化 draft、编译、以真实 D11 许可付费预览，再采用最多 19 字方案。随后同一条 20 字自然观察经过双付费模型原件后在 final 被拒，图内无 D09 batch；默认方案下同样的 20 字观察通过 final/P2，并收到受控 OneBot accepted。与既有 accepted、unknown、撤权及 pending 场景合并聚焦 `7 passed`（26.73 秒），相关 Python 编译和 Ruff 通过。这个结果替代上文“adopted head 正例未完成”的旧状态；它仍不是正式 daemon 冷安装、真实外部模型或真实 QQ 验收。

D07 双票竞争的纯选择器已落地：同一旧票与新入站票按不同注意权重改变获选焦点，旧票胜出时新票进入辅助位并记录下一次唤醒时间；到期/取消旧票不阻断新票，已有未处理辅助票不会被静默丢弃。编译、Ruff 和聚焦 `3 passed`。它尚未接入 Owner 的两票当前图读取、完整 D06 来源闭包、同事务重验及延后回复恢复，不能算生产注意力调度；W01 正在实现这些图端口。

D07 图侧已从同一 GraphStore 事务回读旧焦点票、原入站受众及完整 D06 来源/访问/缺席纠错头闭包，原注意提交的扩展测试 `1 passed`。当前票不可变，正常回复完成后必须凭 Authority 已观察的执行终态做可重放的焦点完成 CAS；否则已发送旧票在剩余有效期内会无故延迟新消息。纯选择器现能排除传入的 `served_fraction=1` 候选，但不可变票的受信已服务派生、Authority→图完成端口和延后 C02 唤醒仍未接，D07 多票产品行为继续 HOLD。

Authority 另有独立同库 daemon 验证：先建原 C02 图并关闭安装期 Core/journals，随后 daemon `create=False` 重开同一 DB/Core；目标 AstrBot 4.28.1 wheel 的 mTLS client 完成 clock 握手，使用该 daemon Core 的 generation/review 两笔付费原件和 final COMMIT，撤源后当前读拒绝，聚焦 `1 passed`，编译和 Ruff 通过。两笔付费仍由测试直接调用 daemon 持有的 Authority service，尚未走 mTLS paid RPC；Owner 为受控图侧 fixture，P2 和正式安装信任未由此证明。

D07 完成判断发现 `CurrentEffectReadV2.state=observed` 也覆盖平台 `unknown`。Authority 当前读现从同 Core 的持久执行日志提取原平台 observation 的 outcome，mTLS 端拒绝缺失或非法 outcome；accepted/unknown 受控证据 `2 passed`，RPC 严格解析 `11 passed`。D07 焦点 CAS 必须另核 observed 且 outcome=accepted，不能只看状态或 Host 当次返回值。真 Owner donor 的 daemon 冷切第一阶段已过：旧 port、listener、Core 和 journals 依序关闭，新 daemon 在同 DB/Core/Owner 上打开，目标 AstrBot 4.28.1 wheel 对新 listener 的 mTLS handshake、installation grant、ingress clock 聚焦 `1 passed`（7.56 秒）。这一阶段尚无新 daemon 的双 paid RPC/P2 同 Core 正例。

后续新增两点：D07 真同库 unknown 负例 `1 passed`，Authority 虽记录 observed/outcome=unknown，焦点仍不变。accepted 清焦点暂被原 P2 dispatch 围栏阻断：观察已持久但围栏仍 active，不能从 Graph 或 Host 绕过；Authority 正在原观察的 `reconcile_mutation` 事务内用更新后的 permit/after-anchor 与确定性回执结束该围栏。accepted 和 unknown 都应释放围栏，焦点只在 accepted 时完成。真 Owner 冷开 daemon 的 generation/review 双付费和 final 已经通过新 daemon 的 mTLS 链路聚焦 `1 passed`；撤权/P2 与正式安装包仍未由此证明。

上述围栏阻断现已修复：Authority 在 verified observed receipt 的同一 Core 事务内结束 P2 dispatch 围栏，accepted 与 unknown 原日志聚焦 `2 passed`。W01 随后用真 Owner/同库做 accepted 清焦点、同操作重放幂等、错 final ID 拒绝及 unknown 不清焦点；明确选定两例联合 `2 passed`（14.46 秒），测试进程正常退出。若焦点已有 auxiliary，完成/晋升仍 HOLD，不能由这两例推定多票调度完成。另修 `DispatchRequest.content_fence` 对合法 Authority URL-safe token 中 `_` 的误拒，仅放宽该字段；固定 `_` 正例和控制字符反例聚焦 `1 passed`，Python 编译通过。

真 Owner 同库 daemon 冷切再扩大到双付费/撤权/P2：旧 Owner/Core、三条连接及 listener 全关后 `open_authority_daemon(create=False)` 重开；新 mTLS handshake/grant/clock，generation 与 review 各经新 AuthorityClient mTLS prepare/admit/observed terminal，Graph D11 成本与两结果及 final COMMIT；旧 Owner bearer token 因 boot_id 变化失效，持原 Ed25519 key 在新 mTLS session 重新签名登录后，公开 revoke→Graph rev2→Authority finalize，P2 同 effect 首次及重放均 HOLD、受控 OneBot 0 次。目标 AstrBot 4.28.1 wheel 下聚焦 `1 passed`（9.25 秒）。Provider 回复仍由受控 Mock 提供，这不是外部模型真实付费或正式 Windows 安装验收。D07 真多票的 D07-only adopted head 仍缺：当前生产 adopt 只接受 D09-only；不能用手造 active head 算验收。

后续集成进展：D07 qualified old primary 现在只有在当前焦点确实指向旧票、旧票及 D06 来源/访问/缺席纠错闭包全在同一 snapshot/VersionGuard 时才可胜出；领域侧编译、Ruff 与聚焦 `7 passed`。W01 公开了从原 C02 及提交 sidecar 只读恢复当前 D07 decision 的端口；真 Owner/mTLS 同库 donor 再经第二条独立 observed ingress、D03/D04、Authority encoding terminal、D11 cost 提交第二个 C02。双票聚焦 `1 passed`：默认权重 old-wins，图提交旧 primary／新 auxiliary、deferred/wake，且不启动 inbound paid generation；原 owned donor 回归 `2 passed`。旧票 P2 accepted 后 auxiliary 晋升及到时唤醒还在实施，不能将双票调度标为完成。

独立安装态 V2 Graph 派发核验器现从只读事务重新核唯一 admission/request、原 footprint 约束键、当前 Owner Graph issue proof/授权头、D08 三个当前原子和五检查收据、原自然 batch 与 D03/D05/D06 scoped 闭包；Python 编译、Ruff 和导入通过。Authority 新 V2 回调不复用旧 Core dispatch=False，daemon 以固定图路径/namespace map/受信时钟装配。真同库冷重开场景已过双 paid→final→P2 accepted，OneBot unknown 后不重发和 Owner rev2 拒发，聚焦 `3 passed`；首轮观察 `unknown` 的真实原因是安装配置缺 OneBot 观察身份，补齐后复用现有受信核验器而转绿。约束键篡改负例仍在补测，受控 Mock 模型与 OneBot 不代表外部服务验收。

D02 增加真实同步 CPU 资源动作入口：只接受已认证且仅有 `cpu_ms` 的签名 quote，在调用者 SQLite 事务内执行并测量同线程 CPU，写入同操作 actual 与终态执行回执后用原核验器签发 outcome；编译及聚焦 `10 passed`，正例确实执行 CPU 计算。W01 尚未在 C04 提交事务中接该端口，异步/模型资源动作也未接，因此 C04 产品仍 HOLD。W10 `run_experiment` 已有仅接受持久 D07/D09 scheme preview 的隔离服务端桥，缺 W01 的当前 typed report 受信读端口时在付费前拒绝；编译及聚焦 `53 passed`，通用实验与产品正例仍 HOLD。

W12 本地 Windows 后端诊断 ZIP `3.0.0-dev.1` 大小 2,153,551 字节，SHA-256 `3ae9d0aab6f0d2d4687d9f98a6cf532e0703d27c477675a2ce5ede1ce1df62bd`；隔离 `-I -S` 进程校验包和七项资源、加载 ABI2 DLL 并完成固定块求解，脚本编译和 Ruff 通过。该包未包含凭据/状态/日志；仍缺发布信任根、Authority 服务独立冷启动和真实 AstrBot 冷安装，明确标 `diagnostic_only`，不是冻结的正式 alpha1。

再后续窄验收：D07 真双票同库用例在旧票的真实 generation/review 双付费、final、P2 OneBot accepted 和 Authority observed 后，仅凭 accepted 终态执行焦点 CAS，第二票晋升，并跨连接从 `graph_d07_deferred_release_v2` 读回原第二 C02；聚焦 `1 passed`（11.75 秒）。宿主重启后的 release discovery/wake 和双票 unknown 反例尚在补。安装态 V2 pinned callback 在同一真双付费 donor 上正确约束键返回 True、追加篡改键返回 False、Owner rev2 后原键返回 False；冷重开 daemon 的 accepted／OneBot unknown 不重发／Owner rev2 拒发 `3 passed`。缺安装 OneBot observation verifier 时曾发生已实际发送却不能持久观察的 `unknown`，现已确认应在 `begin_handoff_v2` 前 HOLD，前置门和负例待落地。

W12 另以真实 Windows 子进程从隔离安装目录冷开 Authority：Graph、Core、删除和执行两日志重开、mTLS 连通、子进程干净停机；诊断 staging ZIP SHA-256 `c66b91847d674600cb685688bdef1a754d0086d3837cc5a6d68db3d105d0865f`。测试使用一次性状态/证书/回调，缺正式发布信任根与服务安装器，收据仍为 `diagnostic_only`、`cold_install_pass=false`，不能替代 G7。

D07 又公开了已晋升延期票的无内容分页发现端口：返回原 C02、attention/ticket/final 身份与游标/图戳；真 Owner 双票链在第一票 accepted 晋升后跨连接读回第二票，聚焦 `1 passed`（11.18 秒）。W09 宿主对该发现端口的重启恢复消费及双票 unknown 不晋升仍待验。D13 纯域补全压缩前缀与激活片的 `missing_ranges` 覆盖缺口：已知回合间序号空洞不会被呈现为连续历史，编译/Ruff/聚焦 `32 passed`；真实异步付费、持久候选/CAS 与同主模型调用前精确计数仍 HOLD。

Windows Authority 的签名验证与安装/升级/停用准备 CLI 已有本地机制：要求外部 Ed25519 发布根及固定根/包/清单哈希，错误签名或根摘要拒绝，使用一次性测试密钥的聚焦 `1 passed`，编译、Ruff 和 diff 检查通过。本机令牌非提升管理员，实际安装写入没有执行；生产发布根、SCM 服务封装与正式冷安装仍缺，CLI 只作 diagnostic staging。

D07 真双票 accepted/unknown 对照已参数化，聚焦 `2 passed`（13.96 秒）：第一票 accepted 才完成焦点 CAS、晋升第二票并使 release page 可见；unknown 保留旧焦点，第二票不可发现。Host/main 的受信恢复路由聚焦 `10 passed`，尚需把它与真同库双票的跨进程重启付费链分列验收。无 OneBot observation verifier 时 V2 begin_handoff 已改为发送前 typed HOLD，旧真 Owner 场景改为 OneBot 0，聚焦 `1 passed`。独立 Authority `content_fence` 对合法 URL-safe `_` 误拒亦已修，正例/控制字符反例聚焦 `1 passed`。

W01 受信 typed 预览报告读端口复用当前 Owner、方案/epoch、D11 settled cost 与 seal 校验；真 Owner/mTLS D09 19 字方案报告读取聚焦 `1 passed`。W10 随后以 WorkbenchService→issuer→真实 W01 跑 D07/D09 两种方案预览实验，持久报告摘要、同操作重放与无正式副作用聚焦 `2 passed`；这只覆盖限定的方案预览，不是任意实验。C10 的受限 `view_status` 本地支持包有导出、manifest/hash 与服务层权限，聚焦 `56 passed`；已安装 Owner grant 尚无 `workbench.diagnose` 证据，Host 未注入私有导出根，产品 C10 HOLD。

S14 目标证明器已针对真实持久 source/target SQLite 导入原件、目标行与摘要篡改及缺源库跑聚焦 `1 passed`；独立 unknown/cost 约束原件缺失仍 HOLD。Authority final activation CAS 已补 external verifier 前 Owner head 取样与最终冻结事务精确重读；真实 Owner 迁移恢复期间 reserve_revoke 被拒、受控 head-read race 最终 CAS 拒变更，聚焦 `1 passed`。目标图在 verifier→Core CAS 之间仍缺已证明的写入栅栏，不能激活。

G6 新脚本以真实 GraphStore 直接查询核跑 1k 合成来源软件基线，独立进程退出 0：批写 P50/P95 13.003/14.542 ms，分页查询 2.232/2.745 ms，峰值 Windows 工作集 45.3 MiB。10k/100k 在当前并发内存压力下未运行；它也没有生产 Authority 围栏、模型费用或 OPS-09 对照，正式 G6 HOLD。详细指纹和限制见本目录 `20260928-g6-graph-software-scale-baseline.md`。

C04 跨域时序已另定本地 `../c04-internal-work-protocol.md`：需要独立耐久 internal-work claim/terminal→真实 CPU 与结算→最终冻结 C04 bundle→现有图事务采用。D02 fixed-component builder 用原 BodyQuote 的固定费用，不按 cpu_ms 推身体能量。D06 C04 预检已从孤立一笔 settlement 改为 body_state/reservation/settlement 精确三写及旧 head/VersionGuard CAS，聚焦 `9 passed`；旧夹具仅 synthetic。Authority InternalWorkBinding/Terminal/Proof 类型与原件复读 Protocol 的编译/Ruff/聚焦 `3 passed`；独立日志写入/复读与真实身体初始账未接，C04 产品仍 HOLD。

后续更正与新增：D02 已将 `execute_local_cpu_action` 改为仅在数据库事务外执行并测量、返回未持久化结果；事务回滚不会被误当成资源工作未发生，claim 后缺终态仍按 unknown。`FixedBodyPolicyV1` 的签名、bot/persona 隔离的政策/报价原件、BodyProfile/State 初始写与同操作报价重放已有聚焦 `13 passed`，尚无正式安装的政策原件。D02 从 Authority verified terminal、prepared 原件和 quote 可构造**未签** resource outcome candidate；真实同链终态及当前 Owner/head 外部核验未完成前不签 outcome。Authority `internal_work_service.py` 目前为 fail-closed 适配器：缺同一 ExecutionJournal 的 typed claim/terminal/read 端口时各操作拒绝，适配器聚焦 `5 passed`；不能将此写成 C04 完成。W01 的 prepared 原件已持久化并做同 operation 精确读回，公开 prepare 还需受信政策、`d02.body_policy.install`、`c04.internal_work.prepare` 和固定 `d06.c04_internal_cpu.v1` 费用合同。

D07 宿主真同库双票纵向测试已到达第二票继续：第一票双模型付费、final、受控 OneBot accepted 后，原 Authority observed 使 auxiliary 晋升；新 Host 状态按公开 release page 发现原第二 C02，重读来源与进度，再经 Graph prepare 和 Authority generation paid/admit/terminal 一次，聚焦 `1 passed`。这是受控 Host readiness，正式 RuntimeContext 包冷启动与真实外部模型/QQ 仍未验。

S14 同机 target verifier 增加在 target SQLite `BEGIN IMMEDIATE` 持锁至 Authority 最终 Core CAS 的接口；另一连接在此期间无法写目标图与 import receipt，释放后可写，聚焦 `1 passed`。MigrationService 现在缺已安装 holder 即 HOLD，并要求 holder 与本服务同一 Authority 身份；最后 Owner head 在冻结事务内精确重读。迁移 local state 和 Owner race 聚焦 `7 passed`。仍缺受信 per-target 路径及独立 unknown/cost/deletion 约束原件，产品 activation HOLD。

W10 的限定 D07/D09 方案预览经真实 Owner W01 读端口返回当前报告，WorkbenchService→issuer 的两种正例 `2 passed`。C10 本地支持包仅覆盖 view_status，Host 仍须安装私有导出根和真实 `workbench.diagnose` grant；C07/C08 迁移、C09 删除、C11 安装、C12 控制均在调用普通 provider 前 HOLD。再次编译 W10 目录及其测试通过，相关前置拒绝聚焦 `5 passed`；不存在这些命令的真实正例。C09 最小缺口是 W01 Owner-fenced D06 closure、独立 deletion accepted/closed、图屏障与 cleanup 的同身份可复读收据。

W12 的独立 Windows Authority staging 后续具备控制台和 SCM service wrapper、签名验证的 prepare/install/upgrade/disable 门；一次性签名测试根、独立子进程 mTLS 冷开/关闭及 4 项发布窄测通过。最新 staging ZIP SHA-256 `38b5ca67f2960a208bfce0cc6b5a8d44867bdd8ffd029b2fc98bae3e12a50238`，仍标 diagnostic；无正式发布根、提升管理员令牌、锁定的 runtime/wheel，也未实际执行 SCM 注册/启动/升级，不能记 G7 通过。

C10 后续接通真 Owner HTTP 纵向：RuntimeContext 在私有 data_dir 注入 support_exports，issuer 复用同一 Owner read lease 完成 workspace/diagnostics，首授签名 grant 精确包含 `workbench.read` 与 `workbench.diagnose`；受控 HTTP 导出聚焦 `1 passed`，issuer 回归 `26 passed`，Python 编译/Ruff 通过。manifest 只含 view_status；正式安装和 ACL 未验。D13 领域确定性压缩候选已从原始回合编译带来源锚的顺序 beat、骨架、细节槽与真实遗漏区间，保留否定/纠错/unknown 和不同来源的真实重复；查询选择接本轮文本、受信再提及和 D06 已有证据去重，稳定前缀不随查询变化。D13 编译与目录聚焦 `36 passed`；付费模型调用和自动激活因缺主模型调用前精确 token 计数仍 HOLD。

C04 独立执行日志新建 v2 schema 在原 entries 表追加有类型 claim/terminal，共享原 seq/hash head；v1 不自动迁移且 internal append HOLD。Core reconciliation 可在原冻结锁序下只导入最末、与前驱精确相连的 claim/terminal，claim-only 冷开视为 unknown；journal/service、Core 和合同聚焦分别 `3/2/3 passed`，dispatch 原测试 `10 passed`。这些是底层能力，当前对外 claim 缺 W01 current prepared/Owner/签名报价核验，不能启动 CPU 或签资源 outcome。W01 公开政策安装、prepare 和 current prepared 读取三窄端口，编译/Ruff 通过；安装态 D02 signer 与明确 Owner capability 尚在接线，C04 仍 HOLD。

之后的 C04 正向准备切片：W01 以真同库签名 Owner/mTLS 跑政策安装、错能力/缺 signer/缺 quote/错 work_kind 拒绝，以及故障注入时 D02 quote、D11 reservation、图 reservation/sidecar 同事务回滚；公开 prepared/current read 受控正例聚焦 `2 passed`。该正例的 CPU ResourceQuote 由受控 signer 夹具签，不能称正式报价。安装态 BodyQuoteAuthority 现从受保护持久 D02 key 加 installation_id 领域分离派生，错 key/无 prepared admin profile HOLD；RuntimeContext 聚焦 `7 passed`。另新增签名的 C04 CPU resource ceiling policy 原件：固定 namespace、installation、算法、`cpu_ms` 上限和有效期；同操作 request 在当前 D11 grant/Owner 下产确定性单维 quote 候选、冲突/签名篡改拒绝，编译/Ruff/`2 passed`。Host 随后从受保护持久 D11 key 派生独立 policy signer 并注入 GraphCoordinator，缺资料 HOLD，聚焦 `2 passed`。W01 仍需把 policy 安装/签发 quote 与 prepared 在同事务接成真 Owner 产品正例。

Astra high 对 C04 最终时序做只读跨模块审计，结果写入 `../c04-internal-work-protocol.md`：已有 preflight 在最终事务内要求 D02/D11 三写，与“真实 CPU 先终态并结算、再决定采用经历”冲突，不能硬接。新阶段为可复读冻结输入→Authority 固定算法唯一执行及同链输出/组件收据→D02/D11 幂等成本导入→adoption v2 只引用已结算账、原子采用 D04/D06/D07。D06 纯 `AssociationWorkInputV2`/固定算法 `d06.association_activation.v2` 已有原始 Graph read/负读/分页覆盖/心境与选择票、语义 digest 排除观察 epoch、canonical JSON codec；编译/Ruff/聚焦 `5 passed`。W01 原图 collector 与 Authority 安装执行器、终态输出/真正组件收据、最终 adoption v2 尚在实施。D02 审计发现旧固定费用三写仅凭非空 receipt ref 可能误收费，已将生产 builder 明确 HOLD，并保留只读原件核对；编译/聚焦 `13 passed`。缺 Authority 证明指定计算组件确实完成前不能收固定身体费。

C09 Authority 内部已有独立删除日志 `pending→accepted→closed` 阶段追加、Core head CAS、冷开复读与重放，相关聚焦共 `44 passed`；图证据为标记明确的存储夹具。公开 accepted/closed 仍 HOLD。W09 补受信 pending 读端，经 Authority/mTLS/Host 同一冻结事务核当前 delete permit、原日志/Core head、Owner 授权，编译/Ruff/真实日志窄测 `1 passed`，Owner head 在该测为受控桩。W01 新图屏障原件 `graph_c09_erasure_barriers_v1` 可在原 GraphStore 事务核撤权与图/access/delete epoch CAS，回滚/触发器和 S15 聚焦 `1+6 passed`。D06 删除闭包目前仍列缓存、索引、进程本地及跨域历史缺口，不能靠图屏障底层或 pending DTO 宣称删除完成。独立盘点正在辨认这些 facet 的真实来源。

W12 另加显式停机的 ExecutionJournal v1→v2 升级门：受控一笔 v1 原 append 的全链/Core head/备份核验后只改 schema_version，v2 头不变，旧备份仍 v1；诊断安装状态、实例锁占用或头不符拒绝，编译/Ruff/聚焦 `2 passed`。正式升级仍需发布根、SCM STOPPED、排它安装实例与已安装资产绑定，未对产品状态执行。

后续 C04 定向检查：D06 `AssociationWorkInputV2` 的闭包校验现纳入已提交 D04 mood 的 `source_refs`，这些来源的 source/access/明确缺席 correction/祖先头必须随冻结输入保留；主任务运行该文件编译、Ruff 和 `6 passed`。W01 新增不可变完整输入表、canonical JSON/语义摘要回读与当前 Owner 读栅栏；原准备记录缺算法构建 pin 时明确 HOLD。Authority 的固定执行器在同一 execution chain 保存有界输出、真实 CPU、签名组件完成原件，重复 claim 不重跑，已撤权后的原 claim 仍能记录历史终态；执行器代理的编译/Ruff、`17 passed` 为局部验证。安装工厂要求 Authority 内部验证正式包 manifest pin，精确核对已加载 D06 两个源码路径与已验证包，并从当前图只读事务取得冻结输入；W12 staging 已包含算法源码和 verifier，隔离导入 `3 passed`。当前包仍为 diagnostic、没有正式外部 manifest pin/publisher 根，实际固定执行在产品入口 HOLD。

D04 `compile_c04_salience_original_v2` 已检查来源、资格、mood、编码基线及版本闭包，编译/Ruff、`2 passed`；当前正式 encoding baseline 的 salience/tone 为 unknown，因此返回 `verified_projection_issuer_missing`，不会伪造数字。W01 真 Owner donor 也缺可执行 C04 的已提交 SelectionTicket 和 mood；C04 的实际结算及 adoption v2 尚未通过。D06 删除的图内当前/历史引用清点已进入候选，D06 sidecar 另可只读限量盘点四张 `d06_index_*` 表和代际/阻断/连续性，相关定向 `15 passed`；但安装 sidecar 路径、Authority 同栅栏读端及进程缓存失效证明不存在，广义删除闭包与公开 accepted/closed 继续 HOLD。

随后 W01 将旧 `prepare_internal_work_v1` 的**新请求**改为立即 HOLD，发生在 D02 报价和 D11 预留之前；上文的旧版准备正例仅是历史切片，不能当作现在可执行的公共入口。历史 prepared 原件仍按原身份复读。W01 的 `commit_current_c04_body_cost_v2` 已编译，真 Owner 缺独立 D11 CPU 原件负例在不改 graph_history 或 D02 成本表的情况下拒绝；该组冻结输入/公共门/快照 `11 passed`，仅有第三方 jieba `pkg_resources` 弃用 warning。真实 Authority completed→D11 导入→D02 三写正例、D04 已认证 salience 与最终 adoption 仍未验收。D02/D11 隔离接口在受控签名终态的 `2 passed` 中覆盖失败 CPU、成功组件、23ms 对 10ms 报价超额与重放，不能替代真 Owner 安装链。

D04 编码投影新增纯数学与候选合同：固定编码基线汇总**全部**当时 feeling 块的 24B 个归一化轴与 6B 个得失对比项，当前心境只在回忆时通过另一个区间算子调制；同一编码摘要在两种心境下保持不变。v2 baseline/projection receipt 将全部 feeling↔checkpoint 版本、联合数值原件、政策/资产/原生核身份绑定，拒绝把当前心境收据写回历史基线。主任务合并运行这两个新文件编译/Ruff 与 `9 passed`；它们均为 unsigned/unadopted candidate。W12 将精确候选政策资产 `resources/catalogue/d04-interval-projection-policy.v2.json` 加入显式打包白名单和 manifest/ZIP 身份核验，SHA-256 `f41fdd7e5738eba1da582b3ccb5c83322650241d921a81b19c49c2a7f6b05a53`，发布窄测 `2 passed`。正式包当前因 policy 的 `semantic_calibration=unvalidated` 拒绝；当前 Owner 栅栏、joint adoption 验证与原子 v2 基线签发仍未落地，不能把计算读出当成已认证产品感受。

主任务在该批代理停止编辑后做了一次源码编译（`python -m compileall -q main.py rewrite/sylanne3 scripts/alpha1`）和 `git -c core.safecrlf=false diff --check`，均通过；随后生成了**本地阶段性实物**，路径位于忽略的 `dist/backend-candidate-20260928/`。Windows 后端 ZIP `astrbot_plugin_sylanne-3.0.0-dev.1-windows-x86_64-backend-alpha1-candidate.zip` 为 2,249,268 bytes，SHA-256 `7b5d9016007726f2d0d82ecfe22a844e16aa149362d59104e1d61ebd4f92d649`；调用 `verify_package` 校验 ZIP 结构、CRC、清单和原生目标通过。Authority `authority-staging-diagnostic.zip` 为 1,748,638 bytes，SHA-256 `32362cf2b38ed46010f662d3132b44f29f122fd8ea77977d80bdd93a624216a6`；`authority_staging_package.py verify` 按 manifest SHA-256 `952b89f6a7385d1614bdc90a384d59dd1925ca8fb4016644f43876df48d87d85` 通过。两个哈希均由文件重新计算确认。它们是此刻源码的开发候选/诊断包；后端包声明 `limited-diagnostics`，消息处理与发送禁用；Authority 包声明无 wheels、bootstrap 与冷安装通过证明。后续源码继续变动时须重建，不得把本段哈希作为最终 alpha1。

后端 ZIP 还做了一次独立目录的 Windows 冷解包：用 `python -I` 只把解包根加入导入路径，调用包内 `verify_backend_candidate_qualification`，得到 `qualified=True`、`reason=verified_backend_candidate_diagnostics_only`、manifest SHA-256 `07ab06b380b2056db7b372015f23f45e0c5a5ffa76b724315618b6fd915c5d26`、catalogue hash `e65c0544392a168525108854209edda031f8ea0d179b38987e585ca25030fe40`。此验证是诊断资格与包内 13 域注册一致性，不是 AstrBot 真实消息处理或平台发送验收。

阶段包构建后源码继续变化：D13 已将调用前同 wire 精确计数的 typed 证明穿过 D11 激活意图，缺证明、证明不匹配或压缩后超窗仍 HOLD，聚焦 `31 passed`；当前 W09 供应商没有该计数端口，不能按测试替身激活付费压缩。C04 新 `c04_adoption_preflight_v2` 和 Owner 读端可复读已冻结语义输入、D11 CPU/D02 身体结算原件及三笔 D02 图头/历史，不重复收费；编译/Ruff、聚焦 `3 passed`，最终 D04/D06/D07 写仍 HOLD。D04 v2 投影发行器将历史数值收据的提交前版本与当前 Owner CAS 版本分开，受控端口正例和 stale/包拒绝聚焦 `5 passed`；实际 W01 原件读取与误差分解仍未接入。C09 公开入口增加精确图屏障与分面清理声明合同，聚焦 `6 passed`；声明不是独立证明，公开 accepted/closed 仍 HOLD。上述结果是各代理窄测试交接，不能归因于之前 ZIP，也不构成完整验收。

主任务暂按计算调制指标且 `semantic_calibration=unvalidated` 的产品语义推进 D04，明确不宣称心理学效度。打包器现可在将来全部正式资源门通过时，将同一精确政策字节以 manifest `status=installed` 签入 formal-alpha1，并仍标 `semantic_calibration=unvalidated`；候选包继续写 `status=candidate`。这只修正发行器与打包器的合同冲突，并不提升当前 candidate-only catalogue 或补齐安装证明。修改后 `compileall`、Ruff 与 D04 政策包聚焦 `2 passed`。用户若收窄首发语义，应撤回正式启用路径。

D04 联合推进现可在同一次 W01 SQLite 写事务保存不可变 24 轴数值原件，绑定成员/来源版本、图历史、原生重放误差和政策/读出身份；其预检、写入与当前复读接口的编译/Ruff、聚焦 `5 passed`。当前没有安装态 W01 重放回调，不能仅凭候选提升为可信原件。Host C04 新增外部管理员 manifest pin 与受保护签名密钥组合入口，缺 pin 或诊断包拒绝，聚焦 `3 passed`；启动尚未调用该入口。主任务还把 D06 安装构建验证器从仅存在于开发脚本目录的逻辑移入会被插件打包的 `rewrite/sylanne3/host/installed_d06_build.py`，Authority factory 改读该模块，CLI 成为薄封装，Authority staging 明确包含新模块；受影响编译/Ruff 与 C04 executor + staging 聚焦 `8 passed`。此前阶段 ZIP 不含此新模块，已过时。

**本轮当前源码一致的本地构件**位于忽略目录 `dist/backend-candidate-20260928-current/`；构建时所有写者已停。Windows 后端候选 `astrbot_plugin_sylanne-3.0.0-dev.1-windows-x86_64-backend-alpha1-candidate.zip` 为 2,264,981 bytes、SHA-256 `7e46087b0449743605fc26c6f3afbe6ea1dbb65eadde536c5d52cb1cfc35636a`；Linux x86_64 glibc 后端候选 `astrbot_plugin_sylanne-3.0.0-dev.1-linux-x86_64-glibc-backend-alpha1-candidate.zip` 为 2,384,859 bytes、SHA-256 `33cacc01b5fe2cbdacff19412889817f92935ebdd76eaebd9ae586a19de8b5ea`。Authority `authority-staging-diagnostic.zip` 为 1,754,938 bytes、SHA-256 `3fa37312e0157a528594f7feffebe9355bd5848b114ccbbd3e14c6113f0e8bfe`，manifest SHA-256 `aff8098f3fd31946dffb11d142ed9718f7104d9624b982791ef76526dfaa2c29`。三个文件的 SHA 由文件重新计算，ZIP 内所有当前 `.py` 源码与工作树逐字节比对差异数均为 0；两插件包 `verify_package` 通过，Authority `verify` 通过。首轮 Windows 包曾在 W01 最后一笔修正前构建，已重建并只以上述新 SHA 为当前值。

Windows 后端包独立解到 `cold-extract-win/` 后，以 `python -I` 只导入解包根，`verify_backend_candidate_qualification` 返回 `qualified=True`、`reason=verified_backend_candidate_diagnostics_only`，manifest SHA-256 `b964f7d6c88164da3c7ad14cc8b3da039709e8e7885f14b613b51d0baaf29404`，13 域 catalogue hash 仍为 `e65c0544392a168525108854209edda031f8ea0d179b38987e585ca25030fe40`；包内新 D06 构建验证器只返回 `diagnostic_installed_source_only`，不会把候选冒充正式构建。Linux 本轮执行 `wsl.exe --exec python3 --version` 在 WSL `CreateInstance/MountDisk/HCS/ERROR_PATH_NOT_FOUND` 失败，故 Linux ZIP 只完成跨平台包结构、ELF 目标核验，未完成当前宿主冷解包运行。此前 W12 的 Windows/WSL Rust 59 项与加载结果属于历史源码构建证据，不能替代当前 Linux ZIP 冷安装。阶段状态继续为 `limited-diagnostics`，消息处理和发送禁用；Authority 仍无 wheels/服务引导/冷安装通过。

C09 图侧另有真实 GraphStore event + access 撤权 + 双 epoch CAS 的持久复读接口，聚焦 `2 passed`；同操作 replay 经提交后 Authority anchor 校验。主任务在最后一笔 replay 修正后重跑整个 Python `compileall`、相关 Ruff、该 `2 passed` 与 `git diff --check`，均通过。其公开 Owner+独立 Authority pending 正例仍缺，Authority accepted/closed 与跨域清理继续 HOLD。D06 sidecar 投影索引清理事务聚焦 `1 passed`，覆盖旧来源行删除、保留代际切换与幂等重试；它尚未持有 W01 安装路径/删除屏障，且不证明 SQLite WAL/空闲页、进程缓存或备份被清理。

用户本轮确认 D13 压缩理论上使用**对话主模型本身**。因此运行时应从当前主调用继承提供方、模型、配置和实际请求 wire，不单独固定压缩模型；在该提供方尚无与同一 wire 匹配的调用前精确 token 计数时，确定性后台候选可继续运行，付费压缩激活仍 HOLD。D13 代理核对当前源码已有持久调度、独占 claim、后台确定性编译、W01 原子待用采用与一次费用结算；修正源身份测试夹具后，编译/Ruff 与相关聚焦 `33 passed`。这不代表真实付费模型压缩已通过。

W12 的 `verify-disabled` 新增外部签名根/包/manifest pin、停机锁、安装目录文件集与字节、显式依赖根版本及隔离入口导入的复读诊断，编译和聚焦 `1 passed`。主任务另在临时目录用一次性测试签名包和外置 `cryptography==50.0.1` 依赖运行该核验，返回 `disabled_installed_diagnostic`、`entrypoints_imported=7`、依赖版本 `50.0.1`、`cold_install_pass=false`。此次测试以替身跳过提权/ACL，并非正式发行根、SCM 服务注册、运行或冷安装验收；依赖包留在本机临时目录，未提交源码。

W09 附件接入经当前产品合同核查仍拒绝非 Plain 消息：HostIngressEnvelope、D06 SourceAdmission/SourceRecord 与入站去重指纹都只有文本，放行会静默丢失附件并误记完整来源。需要版本化 D06 来源与附件内容身份、受限持久存储、权限/删除闭包及 Host 映射后再开放；该盘点未改源码，当前 Python 缺 AstrBot 包，相关宿主测试本轮无法收集。C09 公开请求同样还需 D12 Owner 鉴权→Authority durable pending 原件；只读图候选目前不能推进 accepted。

随后找到本地 AstrBot 4.28.1 wheel，解压到临时目录供测试导入（未安装/修改源代码）；非 Plain 消息拒绝用例 `1 passed`。D13 宿主消费用例初跑 `4 passed, 1 failed`：失败用例仍替身旧 reply-model 调度，但当前产品入口调用自然回复 v2，导致预期的 `reply` 事件缺失。主任务将测试替身改为当前 `_prepare_new_post_c02_natural_v2` 调用后，受影响文件编译/Ruff 与整组宿主聚焦 `5 passed`。这是测试对当前产品路径的同步，不证明外部付费压缩已启用。wheel 中 Image/Record/Video/File 能提供路径或异步解析接口，但 URL/文件名本身不能证明内容字节已读；媒体来源 schema 与受限存储仍需实现。

Astra high 对 C09 的只读战略审计发现，现有按源的单次原件被 namespace 全局 `deletion_phase`/history 内容门实现成一次性删除：第一笔 closed 后第二笔按源删除仍拒绝，且可能使 namespace 长期不可用。主任务将重复 scoped erasure 的操作阶段、聚合屏障和累计删除水位实施裁决单列为 [`c09-scoped-erasure-v2.md`](../c09-scoped-erasure-v2.md)。当前 Authority 本地 prepare 与 W01 单源计划原件继续做窄切片，不能把移除 history 检查或一次 pending 测试当完整删除验收。

W12 诊断 Authority staging 增加了随三份锁定 wheel 生成的专用第三方 notices 和 CycloneDX SBOM；两份文件均进入签名清单，复核时再从 wheel 字节核对。离线打包、安装与入口导入的聚焦测试通过；该次测试 ZIP 为 5,818,794 字节、SHA-256 `417b0d592e251b8ea3a69faf15266cf9503d2df0ff17f15bab096e11e68f26de`。这是随后源码继续变更前的诊断包指纹，不是当前 alpha1 成品；正式发行信任根、法律审核、真实提权/ACL 和 SCM 冷安装仍待验。

D04 新增安装态联合数值原件重放器：要求正式 pin 的包与 ABI2 full/LOO，沿相同政策/读出重算 24 轴区间与误差，再由运行时核对完整组件、当前来源/权限/drive 行及 provenance。编译、Ruff 和 9 项窄测通过。当前 W01 尚未提供正式完整组件复读与 Owner fence，也没有正式包正例，因此此处只证明受控重放合同，不能签发产品数值原件。

D13 同主模型的只读复核：`RuntimeContext` 已取已安装 `reply` workflow 的 provider/model/config，宿主在调用前重读当前 UMO 选择并核同一身份；冻结压缩 wire 也绑定该身份。当前预检明确向精确计数门传 `None`，所以仍 HOLD。AstrBot 4.28.1 wheel 内可见的 TokenCounter 是估算器，模型返回的 usage 在调用后才出现，两者都不能证明该 wire 的调用前精确 token 数。若供应商/模型提供精确预检能力，最小接点是绑定同一主模型身份与冻结 wire digest 的宿主计数端口，并在实际外送前复核；当前没有这种产品能力证据。

C04 安装态固定执行器此前已有同链 claim/terminal、受限 D06 算法及组件完成签名的受控实现；本轮补齐 service 端口前置门：缺正式构建 pin、非固定算法/build 的 claim，以及 V1/未签或篡改 terminal，均在触碰注入端口前拒绝。受影响编译、Ruff 与 10 项聚焦测试通过。正式 D06 包、完整 Body/D11 结算及最终 D04/D06/D07 原子采用仍缺，不能以该服务层验证宣称 C04 产品完成。

C09 Authority 的 ScopedErasureV2 A/B 存储和恢复切片已落地：单次操作阶段与 namespace 聚合 clear/pending/accepted 分开，保存唯一 active operation、累计应用水位和显式迁移 marker。零历史可启用；旧删除历史写 `hold_legacy_history` 并保持原链/Core 不动。真实签名 Owner 的聚焦场景验证 A pending、并发重叠拒绝、受控内部 synthetic accepted/closed/ACK 后 B 在 epoch 2 pending、旧 A 祖先收据可复读；断点冷开与同 ID 异范围也覆盖，编译/Ruff、9 项聚焦测试通过。这只是 Authority 存储证明：公开累计 Graph ACK 端口仍恒拒，accepted/closed、清理证明、mTLS 请求、内容重新开放及旧历史迁移均未形成产品正例；不能将受控内部 ACK 当作实际删除完成。

随后平台探针发现默认 WSL 发行版 `zhuoyi-Ubuntu-20.04` 失败不等于所有 Linux 环境不可用：显式运行 `wsl.exe --distribution AstrEmbodimentVerify --exec python3 --version` 成功返回 Python 3.12.3。当前 Linux ZIP 仍需在该发行版按最终源码重新构建后冷解包、导入和原生加载，不能把这次 Python 版本探针记为 Linux 包通过。

W01 媒体图事务交接：`commit_first_ingress_v2(..., source_admission_v2=...)` 为有说明文字的来源同时写原 v1 来源/权限/编码 job/outbox、不可变 `memory.source.v2` 描述和同库有界 BLOB；重试核字节，当前读核来源/权限/祖先/epochs/摘要，Owner 撤权与 C09 屏障清 BLOB。真实 ProductionGraphStore 聚焦媒体原子、回滚、重放、读/撤权 `3 passed`，旧目录追加迁移 `19 passed`，S15+C09 聚焦 `3 passed`；compileall、Ruff、diff check 通过。宿主桥仍在接线，纯附件及 URL-only 媒体仍 HOLD，现有模型请求也未消费图片字节；这不等于多模态产品验收。

在显式 `AstrEmbodimentVerify` WSL2 发行版直接对当前工作树的 Linux `.so` 运行 `scripts/alpha1/native_kernel_smoke.py`，退出 0：`native ABI2 smoke passed: target=linux-x86_64 abi=2 state=0.31175535656 residual=5.9e-15`。这是当前原生库加载和代表性求解证据，仍不是最终 Linux ZIP 冷安装、完整 Rust 测试或 Linux 宿主验收。

W09 已把 captioned-media 宿主接到 W01 事务：`HostIngressEnvelope` 携带已读字节的 `SourceAttachmentV2`，AstrBot 只接受真正 Plain 说明文字加内嵌或受信本地文件字节，`v2_ingress_adapter` 和安装态 RuntimeContext 将 `SourceAdmissionV2` 传给 GraphCoordinator。URL-only、纯媒体及旧 D06 handler 的降级路径明确拒绝；普通 Plain 流保持原路。解析/宿主聚焦 `7 passed`，安装态 worker 桥接 `1 passed`，变更文件 py_compile/Ruff 通过。这证明媒体来源可进入受控业务链，不证明模型实际看图或真实 OneBot 附件实机验收。

C09 正式 Scoped `prepare_request` 现在要求 constructor-pinned W01 `read_current_c09_erasure_plan_v1`，核同一签名 Owner、来源范围、授权、图 incarnation/epochs 与不可变计划的完整摘要，再在 Authority 核准 pending；旧 pending 重放仅核 Authority 原件，不续发新许可。真实签名 Owner、D06 SourceRecord/W01 计划的聚焦测试覆盖正常 pending/replay、更换 root 与 policy 拒绝，编译/Ruff、该测试文件 `9 passed`。先读图后 Authority reserve 仍有竞争窗口，必须在后续 Graph barrier 再复读；D12 入口、公开 accepted/closed、累计 Graph ACK、清理及内容重开仍 HOLD。

在同一 `AstrEmbodimentVerify` Linux 环境对当前 Rust 源码执行 `cargo test --locked --release --manifest-path rewrite/native/Cargo.toml --target x86_64-unknown-linux-gnu`，59/59 通过；随后的同目标 `cargo build --locked --release` 成功。对应 `.so` 当前 SHA-256 为 `757835845ea4c651fe4e058eda67cd36997462f70f0e70b707015844b3e0cfe0`，已先前在该环境 ABI2 加载和代表性求解。该组合证明当前 Linux 原生源码/库，尚未证明最终 ZIP 的冷安装。

W09 随后修复安装私聊来源策略与媒体 DTO 用途集合的错配：`reply_source_policy` 由 RuntimeContext 传至 v2 ingress 适配器，私聊启用时带 `expression`，无策略时保留原 `context/consolidation`。受影响编译/Ruff 与宿主聚焦 `8 passed`。模型编码仍只冻结文字；主模型是否支持图像无安装态证明，已存图片字节尚未进入模型请求，不能宣称视觉理解。

D04 当前完整组件 W01 Owner 读端已加：在真实 D12 Owner lease/session 下，通过 `_read_v2` 和同一 SQLite 快照读取全组件与 checkpoint/drive/来源家族，撤权或 epoch 变化拒绝。ProductionGraphStore 聚焦 `3 passed`，含真实签名 Owner 撤权拒读，编译/Ruff 通过。它返回未签的安装重放输入；`DomainBundle.product_advance`、写围栏目前仍只消费 V1，正式政策仍为候选，因此 V2 数值原件未在产品图事务采用。

C09 真实图屏障联测首先发现 Event payload 将 `affected_source_refs` 的 tuple 交给仅接 JSON list/dict 的序列化器，W01 改为 list 并通过真实 Owner+plan+pending 聚焦正例。Authority 随后新增仅从已绑定 W01 图读端双复读原 pending/屏障的 pending→accepted：独立日志 append 与 Core CAS 保留 Graph receipt 完整摘要、闭包、epoch/incarnation；缺屏障、伪造摘要和篡改 delete epoch 被拒且仍 pending。签名 Owner、W01 持久计划和真实图屏障的同链测试及该 Authority 文件共 `9 passed`，编译/Ruff 通过。旧公开 facade、closed、全表面清理、累计 Graph ACK、内容重新开放和 D12 实际入口仍 HOLD。

C04 费用侧复核发现已存在 `d11_c04_internal_cost.py` 的 typed V2 terminal 原件复读、真实 CPU（含超额）结算和不可变成本原件，以及 D02 只凭已完成 CPU 原件收固定组件费的局部路径；相关聚焦 `2 passed`，本轮不重复造导入器。产品阻断是它要求进程内 `AuthorityInternalWorkService`，但独立 Authority 与 Host 之间尚无 C04 execute/inspect/verified-terminal mTLS 端口，也无 W01 最终调度采用。此结论未改代码。

C09 accepted→closed 的只读审计确认，`REQUIRED_CLEANUP_SURFACES` 的 12 项目前只有 DTO 名单，尚无逐表面发行者的可信耐久收据与 Authority 固定读端。D06 sidecar index erase 只处理投影行且路径未安装；W01 图屏障只撤权和提高 epoch，不清理历史、缓存、job、导出、WAL/空闲页和受控备份；公开累计 Graph applied head 仍 HOLD。因此不能使用 caller `CleanupAttestation` 或内部测试 ACK 关闭删除、重新开放内容。当前缺口作为后续清理协议实施输入，未修改清理代码。

G6 GraphStore 合成软件规模探针随后在三个独立 Python 进程以同一 `graph_store.py` SHA-256 `bb792d25fb77cf042a1169b37acd336ae24830865b83d20d4131bbad2a77fb7d` 完成 1k/10k/100k，均退出 0；100k 批写 P95 30.300 ms、分页 P95 2.943 ms，DB 130,502,656 bytes。明细见 [`20260928-g6-graph-software-scale-baseline.md`](20260928-g6-graph-software-scale-baseline.md)。它绕过生产 Authority/协调器且无模型/平台费用、OPS-09 对照或冻结包，正式 G6 仍 HOLD。

C04 独立 Authority/Host 增加窄 mTLS terminal 验证端口与严格 wire codec：服务端只在安装了同 namespace execution journal 和正式构建的 `AuthorityInternalWorkService` 时，从原日志/当前 Core head 复读；默认未注入即 HOLD。Host Client 通过配对 grant 和 transport 正式方法调用；mTLS 缺服务、错频道 grant 与 wire 篡改聚焦 `2 passed`，编译/Ruff 通过。daemon 尚未由正式安装状态注入 C04 service，D11 费用导入器尚要求进程内 service，因此该 RPC 本身未打通产品成本采用。

随后 D11 新增异步远端 C04 terminal 导入：在业务图事务外经已配对 mTLS Client 让 Authority 复读原日志，再由同一成本结算路径核对 W01 prepared、quote、预算、execution/input/terminal/head，已安装态缺失即拒绝；本地导入也要求 formal build。C04 成本聚焦 `2 passed`、mTLS 缺服务/篡改聚焦 `2 passed`，编译/Ruff 通过。daemon 尚未用外部正式 manifest pin 与受保护持久密钥安装 C04 service，远端费用正例和最终经历采用仍 HOLD。

C09 清理 Phase 1 新增安装授权的 12 表面 `SurfaceRegistryV1`（真实目标/清理器/代际）、绑定 accepted Graph 屏障和执行 head 的 `CleanupRunV2`，以及仅列执行日志行长度/摘要的 `ExecutionPayloadInventoryV1`；默认全是 `unresolved_hold`/`inventory_only_hold`。配对 Core、scoped state 和日志复读后持久签发，另一实例复扫验证；原件不可原位更新/删除。真 Owner→plan→barrier→accepted 测试新增未授权安装拒绝和库存原件复读，文件共 `9 passed`，编译/Ruff 通过。当前日志 pending BLOB 进入哈希链且有更新/删除禁令，尚无版本化净化及 WAL/备份清理；测试日志还是空，不能宣称任何表面完成或 close。

D04 V2 `DomainBundle` 的回指摘要环已修复：`v2_digest_with` 仅从规范 bundle 摘要排除证据内的 `bundle_digest` 字段，保留其他证据字段，最终构造要求回指等于算得摘要；V1 和无产品证据规则不变。编译/Ruff/聚焦 `2 passed`。W01 的 V2 图提交仍在接线，且安装态输出签发规则缺失；不能把合同类型可构造视为产品数值采用。

Astra high 对 D04 输出语义只读裁决写入 [`d04-joint-state-output-v1.md`](../d04-joint-state-output-v1.md)：`full_step.iterate` 是初始猜测，真实 ABI2 结果在 full output；正式 24 轴 Scheme 的 Feeling/Mood 值取认证 identity-tanh readout 区间的有理中点 RN-even 代表值及向外误差，checkpoint latent 保存真实 ABI2 输出，Mood 使用独立块，语义校准仍为 `unvalidated`。现有 `coordinates==latent` 消费校验冲突，D04/W12/W01 已拆分实现，尚无正式 pin 或可提交正例。

D04 固定联合输出签发器 `joint_state_output_v1.py` 已实现并冻结 API：从真实 ABI2 full output 导出 24 轴检查点、Feeling/Mood 的 tanh 区间代表值及逐轴误差，绑定 full/LOO 原件、原生身份、受信政策、成员顺序和前驱收据；不接受调用者预填的下一状态。编译、Ruff 与 7 项聚焦数值测试通过，含真实 ABI2 transcript；正式包签发和 W01 原子采用尚未跑通。W12 固定政策资产 SHA-256 `7faef300b10792e3f09d3959b1c6c6e6be4c7abb1a843dcff42e2b12aa250911`，候选/正式 manifest 绑定及加载器的编译、Ruff、篡改聚焦测试 `1 passed`；该测试的 native 验证使用替身，正式包加载仍未验。W01 将在图事务内复核来源/Owner、由已验证的 root 或 prior joint CommitReceipt 摘要导出前驱、重签完整写集，并以专门不可变表保存输出原件；不能把原件塞进既有只保存 ledger/outbox 引用的 `graph_bundle_operations.receipt_json`。

W10 删除入口审计确认 HTTP 工作台尚无通向独立 Authority `prepare_request` 的配对 RPC：Client/transport/server 目前只提供供图写端复读的 pending 请求。内部 `CurrentErasureAuthority.prepare_request` 不能由 Host 直接调用；W10 此切片未改文件，入口仍 HOLD。C04 独立 daemon 的正式 manifest pin、持久签发密钥和 service 注入正在施工；候选包必须继续拒绝生产 claim/terminal。对 AstrBot 4.28.1 的媒体只读核查确认 OpenAI 适配器可承载 data URL 且 W01 能栅栏读取已存图片字节，但当前已选模型没有受信视觉能力标识，主请求仍是纯文本，图片费用上界也不存在，因此不能宣称模型已看图。C09 PREPARED 净化准备引入的暂时性 import cycle 已在其独占文件内修复，`runtime_contracts`、Core、execution journal 同进程导入通过；实际正文净化、十二表面清理与 closed 仍未验。

C04 daemon 随后从安装资产读取外部 formal manifest pin、独立 32 字节组件密钥和包路径，按既有 bridge 装配 service/executor；配对 mTLS 新增 execute/inspect 严格类型往返并保留 terminal 原件复读。编译、Authority 聚焦 `11 passed`，Host transport 聚焦 `16 passed, 15 subtests passed`。这验证配置与受控路由；正式包安装、真实持久密钥 ACL、Windows SCM 服务与 D11 全链成本采用仍未验。W01 D04 联合图事务已增专门不可变 output-original 表，与成员 CAS、numeric original 同事务记录；预检在当前 Owner 围栏内重建前驱 CommitReceipt 摘要并逐项比对输出。编译/Ruff 和 schema/回滚/默认 HOLD 聚焦 `3 passed`；当前读端及正式包正例还在接线。

D04 根初始化也查出旧 `coordinates==latent` 与正式 tanh 读出不一致。新纯 `root_projection_v2.py` 从可信初始盒与固定 identity-tanh 政策派生 24 轴 Feeling/Mood 区间代表值，Mood 独立；不改 V1 根类型。编译/Ruff、V2 与既有 V1 根测试 `11 passed`。W01 还须把真实 ABI2 初始盒回放、正式包 pin、V2 根输出原件及 root 写集接成同事务；V1 根消费仍不适用 V2。

W01 的 D04 V2 联合图写入与当前 Owner 读端已落地：专门不可变 output original 表同事务记录，写集逐位比对已安装数值签发器，root/prior joint 的前驱 CommitReceipt 摘要由图复读。受影响编译/Ruff、聚焦 D04 图/数值/V1 回归 `9 passed`，迁移快照 `1 passed`，diff check 通过。当前读端仍显式标 `current_output_original_pending_complete_source_replay`，因完整更正/祖先来源和产品消费接线未完成；正式 ABI2 图提交正例还需要外部 pin 的 formal 包。W12 更新 Windows 候选包冷解包诊断，新增政策原件/manifest 候选行预检和隔离进程安装态加载，编译/Ruff/篡改聚焦 `1 passed`；尚未对本轮最终源码重新打包运行。

C09 Host 表面库存查到只有 `data_dir/support_exports` 这一受管导出子集可在当前安装状态中精确定位；进程缓存缺 source→call 索引，供应商缓存无控制端，jobs/drafts 与诊断仍含 W01 图原件，受控备份无安装清单。新 Host 私有局部清理器会先停止 RuntimeContext worker，仅扫描该受管目录的规范 JSON，按确切作用域删除并复读文件名/旧 SHA；未知文件则 HOLD 不删。编译/Ruff、2 项聚焦测试通过。工作台 transport 可能跨越 RuntimeContext.stop，跨进程停写也未证明，所以这只是局部清理，不可签为六个 Host 表面或 C09 closed。

C09 Authority-owned 固定图计划核验器已落地：新请求在同一 Core 冻结事务内核 Owner session/ticket/current anchor，先建立 delete fence，再用安装固定 Graph SQLite 只读快照核原计划、Owner grant、来源祖先和累计水位，随后 reserve/pending；失败回滚围栏。精确 replay 不重读旧 Graph/session。daemon 只对已安装 scoped namespace 装配，mTLS `prepare_current_erasure_v1` 仅收 namespace/operation/source/Owner actor+session，返回 pending receipt 与 permit；编译和相关聚焦 `86 passed`。缺 AstrBot 包导致真实 Owner reopen 测试本次未收集，Host/W10 RPC 消费尚未接入，accepted/closed 未因此改变。C09 execution redaction PREPARED 后又生成无正文 V3 sidecar 与 Core pin，受控非空日志冷开与篡改测试通过；旧正文、旧 head、WAL、备份仍在，物理净化及维护 CAS 尚缺。

C04 后续只读盘点确认，已存在 Authority terminal 远端复读→D11 CPU 结算→W01 D02 身体结算与五域 bundle 单事务 CAS 基础，但 `commit_current_c04_adoption_v2` 仍硬性 HOLD。阻断一是 D04 encoding baseline v1 无认证 salience/tone 区间，现有 `compile_c04_salience_original_v2` 恒拒；二是 terminal 的 D06 算法输出尚未在最终同事务重建 D04/D06/D07 提案并核完整成本原件。D04 正核能否从固定数值政策唯一签发 encoding-time 区间；不能以调用者自填区间替代。

D04 现新增纯 `encoding_salience_v2.py`：从经认证联合输出原件的 Feeling 区间，按固定有理数政策推导编码时 salience/tone 区间及复验，不收调用方提供的区间；编译、Ruff、9 项聚焦测试通过。它还没有在 W01 当前输出、数值原件误差拆分、C04 准备和最终采用事务中安装，旧 C04 salience 门禁仍 HOLD，不能把纯投影称为可调用的完整联想。

W01 D04 初始根审计确认 `d04_root_original_store_v1` 只有独立表和读写辅助函数、GraphStore 正常建库未 provision 表，产品调用者为零；通用 D04 revision-0 写入明确 HOLD。纯 `root_projection_v2.py` 的 ABI2 初始盒/tanh 候选不能认证当前 Owner 或 D11 采用。新的 [D04 根采用 v2 实施合同](../d04-authored-root-adoption-v2.md)规定专用 Owner+D11 证据、Authority v2 写围栏、同事务 root 输入与输出原件及精确 rev1 写集；公开入口在这些落地和正式 pin 前保持 HOLD。现有 genesis HOLD 回归及纯投影聚焦 3 项通过、编译通过，没有产品正例。

在临时解包的 AstrBot 4.28.1 wheel 环境中，真实 Owner 冷重开纵向 `test_authority_daemon_true_owner_reopen.py` 首跑为 3 failed、1 passed。首个失败是自然 final 保存 write permit token 到 `DispatchRequest.content_fence`，发送阶段另签发 dispatch permit token，而新绑定校验错误要求两者相同；这与冷重开无关，未重开 accepted 对照也同样被挡住。修复正在保留两类许可各自证明的前提下缩到 Authority 绑定合同；当前不能把重开链路记为通过。

随后双许可绑定已按各自原件修正：Graph 冻结请求及 admission 摘要提供旧 write token 来源，Authority 对新 dispatch permit 另核；无效 token 格式仍拒。C09 新 Core schema verifier 曾误拒合法 final dispatch admission epoch trigger，改为精确接受该表的合法三联触发器后，Authority 绑定聚焦 `10 passed`。W00 新 `DomainBundle.root_adoption` 字段又暴露旧 C02 固定字段 codec 不兼容；已保持旧 C02 wire 和无 root/V1/V2 摘要不变、缺省解码 `root=None`，合同回归 `20 passed, 9 subtests passed`。最终在同一临时 AstrBot 4.28.1 wheel 环境重跑 `test_authority_daemon_true_owner_reopen.py`，accepted、unknown、revoked、missing_observation **4 passed**；这是当前源码的独立 Authority+真实 Owner 冷重开测试，不是正式包/真实平台实机验收。

C04 跨域只读战略审计已落实为 [V3 实施合同](../c04-current-association-v3.md)：编码时历史 Feeling 基线、回忆时当前 Mood 条件投影、逐目标来源区间、V3 冻结执行输入、Authority terminal、独立成本和最终五项领域写集必须连成同一可复读来源链。旧 V2 一个 cue 系数乘全部候选、caller 区间或再次写 D02/D11 settlement 不能作为产品正例；`semantic_calibration=unvalidated` 保留为主观关联边界。合同目前只定义实施路径，V3 编码/准备/采用未完成。

C09 独立 Authority 日志随后实现受限 PREPARED→V3 维护 CAS：安装态的原 C04 service 对 terminal 签名逐条复验，open claim 保留 unknown，Core 在同一 SQLite 事务绑定旧/新 head、seal/pin/证书与 nonce，冷开从 sanitized sidecar 和 switch 原件重读。编译、Ruff、受控非空日志聚焦 `3 passed`，真实 Owner 冷重开四分支也在上述 schema 修复后通过；但旧日志正文尚在原文件、WAL 与受控备份未清，12 表面与 public closed/reopen 仍 HOLD。W01 四类图表面清理审计确认历史/event/hash 链不能原位删除，D06 索引尚无安装路径/代际库存，Authority accepted 当前读端未接；现有 barrier 同事务 scrub 媒体 BLOB 只是屏障局部效果，不可当作 accepted 后完整清理。

W09 对 AstrBot 4.28.1 wheel 的只读核查表明 ProviderMeta 未提供可信当前模型视觉能力，图片 token 只按固定 765 估算；OpenAI adapter 支持 `image_url` 的 wire 语法本身不证明选中模型能看图或有费用上界。已存的 captioned image 仍未进入模型请求，图像外送须等待与 provider/model/config 绑定的视觉证明、冻结图片 read/checksum 和 D11 图片费用上界；相关三个文件编译通过，无图像实机正例。

C04 V3 合同新增严格规范 wire codec；编码基线绑定完整有序 interpretation 与 Feeling/checkpoint 成员集合、已采用 joint numeric/output 原件和四类数值误差，采用计划的每项写值亦入摘要。语法编译、V3 与旧 V2 输入回归 `8 passed`。D06 V3 算法按每个目标自己的 conditioned salience 排序，Authority 新一次性执行器严格解 V3 结果并签 terminal，编译/Ruff、聚焦 `8 passed`。V3 部署配置独立外部 manifest pin 和组件密钥，兼容旧 V2 配置，编译与配置聚焦 `1 passed`。Authority build/service/daemon/mTLS 正接线；W01 尚无不可变 V3 冻结输入原件，正式安装执行继续 HOLD。

D04 V3 纯 issuer 新增完整 source→Feeling 成员基线与当前 Mood 条件投影，显式分别绑定编码 joint 和 Mood joint operation，误差从 joint numeric original 的完整分解读取；编译/Ruff、聚焦 `9 passed`。W01 读端审计发现旧 joint prewrite closure 只冻结 source/access/drive/checkpoint/state，无法在今天还原编码当时的精确解释版本或 `as_known_at`。主任务裁决仅对**未来新 joint 操作**把可解析的 D07 interpretation graph ref 加入受信读集；`FeelingState.meaning_refs` 实际是 facet_id，不伪造 GraphVersion，须核已有 facet issuer 原件；perspective/ref 与 `as_known_at` 由 D11 编码基线在同一 Owner fenced read 冻结。旧不可变 joint 保持 HOLD，不用当前解释回填历史。W01 在该闭包与 D11 编码原件签发前不开放可误用的 C04 projection callback。

C09 V3 维护后又新增物理清理前置检查：在真实三行 execution SQLite 上核 V3 switch、accepted 原件和每行 PREPARED commitment，切换前/正文篡改拒绝；编译、聚焦 `1 passed`。现缺受信写者隔离、受管备份与 SQLite 文件库存，检查明确返回 HOLD，旧正文未擦、清理收据未签。V2+V3 混合终态日志还需安装态逐行算法 verifier 组合，目前单 C04 service 的净化路径安全拒绝，closed/reopen 不变。

C09 清理战略裁决落实为 [净化存储代际合同](../c09-storage-rebase-v1.md)：停写、在新文件重建 Graph/Authority/Core、Authority 认证旧/新 commitment、按库存清理旧应用可访问副本；需 Graph rebase 证书及可独立恢复 D02/D11/unknown/执行权的 V4 非正文事实。现有 V3 sidecar、Core switch 和物理前检不满足旧正文物理退役，`closed`、累计 ACK、重开仍 HOLD。合同是待实施路径，不是运行验收。

D12 已从唯一 `d04.authored_root` 当前草稿签发受限根意图，保留 D01 独立人格草稿；现有与新 D12 聚焦 `48 passed`、编译通过。根采用合同进一步绑定父 D11 budget lease/原件、D12 草稿 digest、root input digest 和受信 Owner session binding digest；旧 C02 wire 与无 root/V1/V2 digest 回归 `20 passed, 9 subtests passed`。低层 root 存储 helper 和 W01 专用 rev1 事务仍在接线，generic DomainBundle root 继续 HOLD。

C04 Authority V3 formal build/service/daemon/mTLS 路由已按单独 V3 pin/key 接通，聚焦 `13 passed`、编译/Ruff 通过；W01 尚无 V3 frozen work original 和外部正式资产 pin，不能称已安装执行。W01 为**未来新** Feeling joint 冻结实际 D07 interpretation atom/version/value digest 与来源/授权闭包，真实 GraphStore 聚焦 `6 passed`；旧 joint 缺历史透视、as_known_at 与 facet issuer，不能事后补签或开放 V3 投影。D04 纯 issuer 另将裸 SHA 显式规范化为 `sha256:` 后，旧 9 项及新 2 项聚焦通过。以上均未形成完整 C04 产品正例。

C09 Authority 新增 `read_current_accepted_erasure_v1` 的严格 mTLS wire 和只读端口：复读签名 Owner、Core/删除/execution 当前状态及 pending/accepted 原件，核最新版 delete permit、scope、operation 与 Graph barrier digest，不接受 caller 自填 accepted 证明。真实 Owner＋W01 Graph 聚焦 `1 passed`、编译/Ruff 通过；该测试未单独证明网络 TLS 握手或物理清理，Host 尚未消费此端口。

C09 P1 新增独立 `c09_storage_rebase_contract_v1.py`，把 Graph 逐表处置/累计 tombstone/新代际证书、严格 typed V4 执行/D02/D11/unknown/Graph 恢复事实及原件/已擦除读取结果定为规范合同；编译及聚焦 `3 passed`。P4 文件库存探针 `c09_installation_inventory_v2.py` 逐项登记受控 DB/WAL/SHM、备份、导出、临时与缓存，冷复扫对新增/删除/改写备份 HOLD，编译及聚焦 `4 passed`。两者都未接安装信任根、迁移或清理，不形成 closed 收据。

C09 V3 维护的混合日志验证已能对同一 namespace 的 V2/V3 C04 terminal 逐行按 immutable algorithm_ref 选择各自正式 pin/key/verifier，在 PREPARED 和 switch 前均复验；非空混合日志含 unknown/open 与错密钥反例的两项聚焦通过，编译/Ruff 通过。V3 sidecar 仍缺 D02/D11/unknown 结构化恢复事实，V4 issuer/独立复读在做，旧正文未退役。

D04 根的代码审计发现 V2 证据强制写事件型 `FeelingState v1`，而空白作者初态没有该类型必填的历史解释和来源；用假 D07/D06 ID 解锁会违背空白创作合同。[authored lineage v3](../d04-authored-lineage-v3.md)明确新 authored Feeling/Mood 类型、V3 根 phase、独立根原件及首个 joint 的真实驱动门禁，事件型 v1 不放宽。W01 已 provision root-v2 原件表并在 S15 隔离迁移保持同 namespace 原字节，聚焦新/重开 `2 passed`、迁移 `1 passed`；V2 产品根继续 HOLD，V3 域/合同/D11/W01 正接线。

D13 Host 能从当前 UMO 的实际主模型选择取得 provider/model/config 摘要并在发送前重读，exact pre-call tokenizer 在 AstrBot 当前适配器不可用，现有 paid gate 明确 HOLD 而不估算冒充。确定性任务政策 `model_assist=False`、技术预算仅 `d13_compute_units:1`，不能拿来支付模型调用。W01 正增独立签名付费 quote 的持久模型身份原件及激活复核；主模型选择变化应使旧候选失效。当前还没有付费压缩正例。

