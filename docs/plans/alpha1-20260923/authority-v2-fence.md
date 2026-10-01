# Authority v2 耐久栅栏合同

2026-09-23 战略裁决。目标是完整 `embodiment-3.0.0-alpha1` 的服务端权限与恢复线性化。当前 `sylanne3.authority.v1` 只能做受控 enrollment/部分锚查询；`ContentPermit` 不冻结执行日志头，服务可在另一内容操作持 permit 时追加日志。**v1 不得接通生产 `RuntimeDependencies`。** 本合同是待实现约束，不是已通过验收。

## 唯一不变量

同一 namespace 的每次内容操作从授权到图读完、SQL 提交或外部实际交接结束，必须持有服务端持久独占 `FencePermitV2`。这段时间内其他操作不能变更 activation、删除状态、执行日志头或恢复约束。alpha1 先串行化 read、adopt、write、model egress、dispatch、下载、订阅、删除、迁移和日志维护，不优化读并发；若多个 namespace 共用同一本物理日志，栅栏范围须扩大到整本日志，或强制每 namespace 独立日志。

唯一例外是 dispatch 栅栏所有者推进**自己**绑定 effect 的日志。每次推进都使栅栏 revision 增一并更新完整 anchor；旧 revision 立即失效。普通内容 permit 不能推进日志。任何客户端自报的当前 head、布尔 pass 或当前时间均不构成服务事实。

## 版本化类型与 RPC

协议升为 `sylanne3.authority.v2`，不能暗改 v1。`FencePermitV2` 至少绑定 authority ID、namespace、认证主体/holder、activation generation、操作种类、operation ID、不可猜 token、fence epoch/revision 与完整 pinned anchor；dispatch 另绑定 effect ID、command digest 和经验证的 footprint digest。`MutationReceiptV2` 至少包含 mutation ID、请求摘要、effect/phase、before/after anchor、更新的 permit revision 与耐久状态。未知字段、旧 revision、不同摘要复用 ID、跨主体或跨 namespace 均拒绝。

服务 RPC 需要 `begin_fence`、`validate_fence`、幂等 `finish_fence`、`get_operation`、服务拥有的 `execution_prepare/observe/settle` 与专用恢复操作。服务直接操作其独立日志；`observe_execution_head` 只留作内部恢复步骤，不能成为插件可调用的“我已写好”证明。连接断开、30 秒配对过期或进程重启均不自动释放耐久 fence，也不自动重发 unknown effect；重连必须重新认证并查询原操作。

`GraphCoordinator._content_fence` 必须传递实际 permit；`_admit_content`、恢复核验、图提交及最终外送均验证**同一个** permit/revision。业务 `SnapshotRequirements` 需包含完整日志身份/摘要水位；恢复合并后与业务事务一同持久更新。只检查依赖对象可调用不构成运行资格。

## 每次独立日志追加

1. 在服务端短事务内验证唯一 owner、当前 revision、确切 before-head 与 effect 证据，**先耐久提交** pending mutation，记录 request digest、唯一允许的追加、owner/operation/effect/command 身份。此时冻结其他准入。
2. 持有该耐久栅栏，由服务独占写入口追加绑定 mutation ID/请求摘要的日志条目并 fsync。不能让客户端先写日志再事后 CAS。
3. 第二个服务端短事务检查真实连续链及唯一下一条记录，更新 authority head、effect 约束、permit revision，持久化幂等结果，再返回成功。同 ID 同摘要重试返回原结果；异摘要拒绝。

日志 fsync 成功但第二事务失败时，pending fence 保留，所有新内容路径关闭。恢复只接受与 pending mutation 完全匹配且连续的唯一追加；可证未追加才允许取消准备，额外条目/错摘要/不连续均隔离。恢复日志不证明外部未发送，prepared/unknown effect 保留对象与预算约束；先查询原 effect，不能自动换 ID 重发。后续 observe/settle 若原 dispatch fence 已结束，必须申请绑定原 effect 的维护 fence。

## 锁序和外送终点

顺序固定为：取得服务耐久 fence 并结束短事务 → 进入图锁/业务事务 → 必要的只读服务校验 → 释放图锁 → 完成 fence。执行追加的 pending 阶段先结束 Authority 短事务，再单独持有 journal 写锁/fsync；最终确认若必须冻结 journal writer 横跨 Authority CAS，只允许 **journal 锁 → Authority 短事务**，其他路径不得同时持有这两把锁。持有 Authority/journal 锁时禁止等待图锁或调用业务回调。现有删除 `business_barrier` 与可能读图的 `dispatch_verifier` 必须移出服务事务并用绑定版本证据复核。等待旧 permit 排空只能在锁外等待或返回 busy。

B2.2 并发复核发现旧 Core 的 `current/current_anchor/check/begin_content_operation` 等在 core 锁内调用 journal verifier，实际形成相反锁序。alpha1 采用同一 Authority DB 的**持久 v2-only 服务模式**：旧 Core/LocalJournalBridge 的内容、删除、执行、恢复、迁移入口在触碰日志或业务回调前拒绝；不能只从 RPC 路由隐藏。模式切换遇到旧 permit、迁移或未收敛状态必须保持阻断，另一连接与重启也不能重开 v1。v2 查询/发 fence 在锁外取得认证与业务证据，再先取实际 journal writer guard、验证链，最后于同一 Authority 短事务重核 namespace、完整 anchor、pending 和 owner/revision 并读取或签发；两本日志守卫需固定总顺序。旧二进制/进程不识别该模式时，部署层仍须证明其已退出并不能并发写入。此裁决不把当前 B2.2 原型改记为并发安全。

B2.4 删除意图格式采用**同一删除日志文件的停机事务化 v2 迁移**。先在 Authority 耐久记录迁移阻断，要求无旧 permit、active fence、pending mutation 并排除旧服务进程；删除日志单事务核旧头、封存原 `deletion_events` 为只读历史前缀、记录格式切点并建立 v2 尾表。旧表必须增加 INSERT/UPDATE/DELETE 全拒绝屏障，旧记录不补造 mutation 身份。新读取器验证前缀与尾部连续链，保留全部 pending/accepted/closed 历史约束；Authority 在固定双日志锁序下确认同一头并结束迁移。任一边提交后崩溃仍保持迁移阻断，精确续办，不回退旧格式。安装还须证明旧进程与旧写句柄退出；触发器不能抵抗有任意 DDL 权限的未受信进程。

v2 删除事件至少绑定 mutation ID、请求摘要、namespace、删除 operation/phase、fence owner/epoch/revision、before-head 与业务证据摘要，全部进入链摘要并受唯一约束。删除 pending 先于日志提交；只有服务持有**同一 SQLite 写连接**的删除 guard 才能追加精确一条，随后按删除→执行→Authority 锁序检查 0/1/多条并提交 Authority 删除头、revocation epoch、permit revision 与幂等收据。0 条保持 pending，可继续原请求，不自动撤销删除；1 条须全字段/摘要吻合；多条或不匹配隔离。`business_barrier`、清理和图回调在 durable fence 下、所有服务锁外执行，其版本绑定证据在短事务中复核。B2.4a 已实现同文件旧前缀封存、禁写尾表、阻断与读链，尚无 v2 删除追加或删除闭环；B2.3b 的独立连接 guard 不能替代它。

### B2.4b 版本化删除合同裁决

保留现有执行专用 `PendingMutationV2`/`MutationReceiptV2` 的严格语义；另设 `DeletionPendingV1`、`DeletionMutationReceiptV1` 与 `DeletionEvidenceV1`，不得让执行收据改删除头。删除 pending 绑定原 `FencePermitV2`（`operation=delete`）、mutation/request、独立删除 operation、`absent→pending→accepted→closed` 的相位、固定 roots/epoch/policy、完整 before anchor、服务核验证据及唯一预期追加身份/摘要。删除 receipt 第一版只允许 committed：删除序号、fence revision、撤权 epoch 各前进一次，执行日志头、日志身份及 activation 不变。技术 mutation 的取消不能撤销已安装的删除请求。

证据分 `request_authorized`、`barrier_installed`、`cleanup_complete`：第一类由 Authority 的受信授权入口核验 D12 请求身份、目标/范围和政策；第二类必须绑定 D06 闭包及 D11 图事务、incarnation、访问/删除代际与屏障范围；第三类须逐存储面核清理游标、派生状态及明确外部/备份覆盖。Authority 仅接受安装绑定 issuer/verifier 核实后的规范证据记录；调用方摘要、签名字段、布尔回调或自称已验证都不构成资格。D06/D11 未接线前，只可做获真实授权的 `absent→pending` 意图及精确恢复，返回 `pending_confirmation`；accepted/closed 和按历史闭包放行保持关闭。

FenceStore 从 schema 2 显式升至 3，给 mutation 增加严格 kind 与删除证据字段，旧执行行原样保持执行类型。删除尾表从当前禁写 schema 1 显式升至可写 schema 2；只可在持久 migration blocker 下、核完整 DDL/切点且旧尾表为空后升级。已迁移与未迁移文件各有版本化入口，旧历史前缀仍不可写；中断时两库任何组合都保持阻断。旧 `get_operation`、codec、pending/receipt 与幂等读取依 kind 分支，跨类型拒绝。schema 2 事件链须含 schema/kind、append ID、请求/证据绑定、before-head，不能只移除 no-insert trigger。升级另用明确目标版本的 marker；B2.4a 的 complete 不等于新格式完成。

删除维护须有专用授权 fence，绑定原删除 operation；普通内容 `begin_fence` 的 clear/history 门不能全局放宽。恢复按原 pending 精确区分 0/1/>1 条：0 条保持 pending，1 条全字段/预期摘要吻合才完成 Authority CAS，额外或错身份条目隔离。旧前缀不冒充新 mutation；已保存证据可用于补 Authority 记录，但若当前图屏障或 incarnation 不可验证，内容仍关闭。先实现 DTO/codec 和存储显式迁移，再实现禁写尾表升级和 pending 追加；accepted/closed 分别等真实业务屏障与清理证明。

read 保护到授权内容实际读完；write/adopt 到 SQL commit 与 receipt 耐久；model egress 到 provider 字节交接；dispatch 到 prepare、约束合并、最终重验和平台 handoff；下载/订阅保护每个输出片段或整次输出。dispatch 内需要图操作时显式传递同一 owner token 的限定子操作，不提供按 holder 字符串自动重入。`claimed` 日志追加必须在最终外送验证之前完成，或追加后以新 permit revision/anchor 再线性化验证；不能先验证、再追加、再发送。

## 实施与验收次序

先落 v2 DTO/codec、耐久 fence、pending mutation 和幂等恢复；再改服务拥有的日志桥；随后移除业务回调锁反转；最后接图/恢复、D08/D11、ModelBroker 与 v2 mTLS RPC。每个阶段编译并跑有区分力的反例，不以 v1 loopback 或 callable mock 放行生产。

至少验证：暂停 read/write 时其他 owner 在追加**前**被拒且日志不动；同 owner 按序追加与旧 revision 拒绝；fsync 后服务提交失败、响应丢失与进程重启的精确恢复；删除/图提交/dispatch 并发无死锁；真实 mTLS 下跨主体 token、断线重连及幂等冲突拒绝。整机回滚保证仍以前提“外部 Authority 未一起回滚”为限。三平台真实服务安装、独立账户权限、证书与冷安装收据另行验收。
