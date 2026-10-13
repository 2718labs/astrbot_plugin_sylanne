# C09 V2：完整、有界、可恢复的分页重建

**目标版本：candidate 40（39 已冻结）。状态：共享承诺核心已实现并编译/import；完整生产链正在接线，未取得 installed resource qualification。**

本设计由 Root 授权，面向用户“全部 39 项闭合”的目标。37、38 的冻结源码和旧签名原件保持只读。预算 Root 续期与 A06 授权续接不在本设计范围。已有根目录计划由 Root 维护；本文件集中保存本项设计、来源和进度，不增加旁路状态库或独立临时计划目录。

## 1. 裁决

必须增加明确版本的分页 **producer → 闭包校验 → facts pin → candidate → certificate → mirror → PREPARED → cold switch/recovery** 全路径。仅将 `fetchall` 改成 `fetchmany`、给旧输出加 LIMIT、或声明有限 profile 后直接 HOLD，不能完成该实现目标。

V1 的行承诺、证书字节、签名域、历史原件和旧 replay 语义均不变。新 V2 的闭合摘要由真实冻结源、完整计数和有序 hash chain 推导，绝不把调用方给出的 `complete`、cursor、row count 或 typed DTO 当作权威。V2 的每批记录受资源约束，完整历史保存在现有受管理存储中；总记录数不因一个内存数组的容量而被截断。

可以复用：现有 Owner/accepted-erasure 权限、Control OS lease、writer gate、四文件选择与原 inode、实际 SourceLocation、域原件 decoder、逐行 disposition 规则、已消费身份与未结费用、关闭/扫描/切换阶段。不能原封复用：V1 全量 tuple DTO、全库内存重建、全量闭包 set/dict、巨型 PREPARED 嵌套 packet，以及依赖这些表示的 cold verifier。

## 2. 真实基线与缺口

| 链路 | 当前源行为 | V2 必须改变的表示或消费者 |
|---|---|---|
| `graph_coordinator.py` C09 barrier | 当前 Source 查询 `LIMIT 4097`，超过 4096 整体拒绝；随后 sources dict、affected set、完整 writes/receipt | 分页的真实 Source 计数、祖先/后代工作集、逐批 barrier 原件；不能将上限改成一个更大的全量列表 |
| `c09_erasure_barrier_store_v1.py` | 证书嵌 affected_source_refs；verify 再加载所有当前 Source | 新有界 barrier 摘要和逐批原件；V1 继续按旧合同验证 |
| `c09_graph_rebase_candidate_v1.py` | edges、历史 dependencies、已解码 values 全量累积；nested-reference fixed point | 持久工作集和有界边/记录访问；保持旧 nested-reference 语义 |
| Graph table capture | `_table_rows` 全表 fetchall，descriptions 持有全部表，之后叠加 dispositions/manifests | 单行/单页 iterator、持久去重与关联索引、完整 count/root |
| `_cold_graph_data_root` | 两轮全表读取/排序，累积全部 row digest 与 tombstones | 独立逐页核验和 root，不重建旧 tuple |
| `c09_build_originals_v1.open_registered_candidate_v1` | 已存在 target 时创建 `:memory:` 全库重算 | 在已登记 inode 上按原页重验/接续，不造第二全库 |
| `c09_model_budget_original_v1` / Graph recovery facts | 完整 ledger/事实集合返回和缓存 | Core/Graph 原件逐项 join，签分页 seal；不以 terminal DTO 代替实际 cost |
| `c09_authority_storage_rebase.py` | 三库全表 tuple；合并历史 facts dict；changed_rows 全量 tuple | 同一捕获引擎，按角色的有界事实/行与变更流 |
| Control PREPARED | 完整 Graph certificate、facts/inventory 等嵌套传递 | compact、显式 V2 的 sealed-stream 引用；不再复制全部页 |
| Graph erased/retention reader | 直接遍历 certificate 的 rows/erased tuples | 同一当前读资格下核验 sealed membership；不能仅信索引记录 |

额外已完成的独立小修不属于 V2：Rel 将 Graph target 的整文件 `read_bytes()` SHA256 改成 65536-byte 流式读取，保持相同 SHA256。它不解决上述全量对象问题。

## 3. 数字来源、能力边界和资源资格

唯一数值依据是用户 v3 输入 `G:/codex_handoffs/Sylanne/complete-agent-local-20261006/inputs/v3/Sylanne-complete-agent-backlog-v3.json` 的 `resource_profile`，文件 SHA256 `a4d715d8a155fecd54eaff80b471a27196ebeffa7fd287cac4600f17e727f884`。

| 项 | 设计值与用法 | 证据状态 |
|---|---|---|
| maintenance batch | 最多100完成记录、262144累计读写/编码字节、25ms本地执行片段；达到任一条件即保存 continuation 并让出 | 用户授权的 proposed 输入，尚未量测 |
| descriptor | 单个 queue/control request/response descriptor ≤65536 bytes；仅 locator、摘要和 scope | 同上 |
| active Graph arena | 所有输入、decoder、输出、SQLite/native buffer、额外拷贝合计预约≤8388608 bytes | 不是单个 JSON 上限，也不是已证明 RSS |
| Graph queue | 含运行8 slots，encoded bytes≤8388608；全局 descriptor≤256 | C09 沿现 scheduler，不另开无限后台队列 |
| read transaction | ≤250ms；不可用长读事务撑住整次重建 | 页间通过固定源身份与真实 freeze 维持一致性 |
| ordinary Graph write | 现最大64 writes仍保留；barrier页实际最多 min(64,100,bytes/time budget) | 不借维护100rows扩大业务64writes |
| storage | 测试数据总4294967296 bytes；Control/effect/fee保留268435456；WAL soft67108864/backpressure134217728 | 4GiB磁盘许可/可用量本次未核实；不得声称 installed |
| export | 16777216 bytes；超额导出只能明确分段/继续，不给单packet扩容 | 不把export cap当内部历史总量上限 |
| process | 2CPU、物理2000000000 bytes；app soft1024MiB/hard1280MiB；swap0 | Root有独立内核证据，本设计不冒充重测 |

原 Control export 的100000 rows/32MiB、Control selector 的64MiB、Life archive的旧上限是各自 V1/V2 原合同，不得借作全部 C09 的新总容量，也不擅自提高。新版一般闭包必须 durable/pageable；旧完整 export 仍保留原语义，需要新消费者时采用显式分页协议。

**单 cell 规则：** 未预留 arena 不得先 `json.loads` 再检查。普通完整物化 cell 不超过本批262144 bytes，且其 decoder/copies 已在8MiB arena内预约；更大的既有合法 TEXT/BLOB 必须走具名有界流式 codec/片段读取，不能借32MiB历史上限整块加载。固定原文签名要对完全相同的字节流验证。不能流式解释的未知 codec 明确 HOLD，不能忽略其行。Python/native decoder 的实际内存上界尚未证明时 resource qualification 仍未通过。

**磁盘规则：** 原四库、候选四库、已登记 journal/WAL、Control与证明页共同计入真实 quota。开始前独立读取已装磁盘范围/可用量，保留256MiB费用/控制区；构建过程中每批重复增长门。候选空间不足保持未完成状态，不删除权威历史、不借新Root、不扩大配额。不存在磁盘证明时不启动声称资源合格的重建。

## 4. 版本与具名 typed ABI

下列是待实现的生产合同名称与必需字段，不是现在新增的空 DTO 文件。每个类型都必须在同一实施批次接上实际 producer 和 consumer。

### 4.1 `C09CaptureScopeV2`

固定字段：`schema`, `authority_id`, `installation_id`, `authority_namespace`, `graph_namespace`, `operation_id`, `maintenance_generation`, `old_manifest_digest`, `expected_pointer_version`, `accepted_receipt_digest`, `barrier_digest`, `writer_freeze_digest`, `facts_pin_ref/facts_pin_intent_digest`, `profile_id/digest`, `codec_catalogue_digest`, `scope_digest`。

它由真实 installed Control/accepted reader 建立，调用方只能选原 operation。各角色源 seal 是后续按合法顺序绑定的实际记录，不要求提前伪造四库同时不变的 fingerprint：Graph 可先关闭；Core 仍须合法追加同操作 facts pin/Graph issue 后再封其源。

### 4.2 `C09FrozenRoleSourceV2`

`scope_digest`, `role`（仅graph/core/execution/deletion）, `source_path`, `source_identity`, `source_file_sha256`, `schema_root`, `source_stage_original_ref/digest`, `role_source_digest`。对应文件必须来自当前实际 manifest，不接受任意路径。源一旦为该角色封存，只能按相同 inode/bytes 接续；任何未声明变化都 HOLD。

### 4.3 `C09StreamIdentityV2` / `C09PageCursorV2`

流身份：scope、role source digest、closed `stream_kind`、table/family、schema digest、稳定PK定义、ordering version。stream_kind至少覆盖：schema catalogue、source ancestry、source descendants、dependency/nested closure、affected operations、row dispositions、target rows、generated rows、recovery facts各族、tombstones、filesystem/control metadata。

游标：stream identity digest、page ordinal、complete-record offset、前一链值、最后一个规范PK，以及可选的具名 cell fragment offset。游标只是定位；producer从实际已提交页恢复，不能相信 caller 的位置。只有内部保存的规范 scalar PK（text/integer/必要的bounded blob），不能把任意 SQL/column/expression放进请求。表/排序均取已核 schema。

### 4.4 `C09CapturePageV2`

`stream_id`, `page_index`, `record_offset`, `record_count`, `encoded_bytes`, `previous_page_digest`, `record_chain_before`, `record_chain_after`, `first_key_digest`, `last_key_digest`, `next_cursor`, `payload_digest`, `page_digest`, `schema`。payload是最多100条、262144 bytes内的实际 typed records；经IPC时只发≤64KiB descriptor/locator，不把本地256KiB page塞进旧64KiB response。

单行大cell片段不算“完成一行”；只有整个原文/typed row验证完成，record_count才加一。内存中可保留有限hash状态跨scheduler片段；进程崩溃可从该行起重新流式核验，不能序列化任意hash对象或把部分行当成完成。

### 4.5 `C09CompleteStreamV2`

`stream_id`, `schema_digest`, `record_count`, `encoded_bytes`, `page_count`, `record_root`, `page_root`, `eof_observation_digest`, `complete_count_original_ref/digest`, `stream_digest`, `schema`。

没有含义模糊的caller `complete=True`。真正完整只在真实EOF、独立count sweep、所有页连续与所有validator完成后才由producer签seal。空表明确count=0/page_count=0并承诺空流根。

### 4.6 Graph、Authority和Control结果

- `GraphRebaseCandidateV2`：固定scope/角色文件信息、schema/row-disposition/closure/tombstone streams的compact sealed roots、目标pre-mirror文件hash、candidate digest。不得包含完整 rows、全部affected refs或全部历史certificate。
- `GraphErasureRebaseCertificateV2`：现V1的固定身份、旧/新incarnation及epochs、accepted/barrier/inventory/事实pin承诺；改为streams的count/root引用；固定prior certificate digest/schema；新的derived/target/tombstone roots；固定component hashes和certificate digest。旧V1不重算为V2。
- `AuthorityGraphRebaseIssuedV2`：保持原安装维护签名权和精确candidate/证书/源inode/目标pre-mirror hash关联，使用新的签名域与closed schema。
- `GraphRebaseMirrorV2`：证书、实际Core issue digest、post-mirror文件hash/identity、重新读出的相同logical roots与cold receipt；只在实际mirror提交并关闭检查后产生。
- `RebasedFileV2` / `AuthorityStorageRebaseCandidateV2`：三角色文件与各自complete disposition/fact roots；`changed_rows`改root/count，不生成全量tuple。
- `StoragePreparedOriginalV2`：原四文件、指针CAS、accepted/barrier、writer退场、facts pin、完整当前inventory及四角色cold证明仍需真实；大向量改sealed stream locator。单header≤64KiB，多header目录自身作为完整分页stream，不能换成另一个无限tuple。

上述exact schema必须在codec/Control/issue/mirror/cold/erased read里显式分派。未知version拒绝；不得用“尝试V2失败再V1”绕过完整性。

## 5. 顺序、完整计数与根的规范

### 5.1 稳定扫描

表名、列、PK与collation来自已核 installed schema，输入不提供 SQL。普通表按真实稳定PK的固定类型/排序扫描；每页使用keyset predicate，禁止OFFSET后直接相信“取够了”。PK为NULL、混用非法类型、没有稳定唯一键或排序需要未登记磁盘临时文件时 HOLD，由该表的具名codec解决，不能隐式退回无序扫描。

页起点必须等于持久记录的前页终点。独立 metadata sweep 在同一冻结源上累计全表行数、encoded/raw长度信息并实际观察EOF；数据页再逐行读取/验证，最终两者的count一致。扫描途中被100行、bytes或25ms打断，只产生 continuation，不产生完整性结论。计数/长度扫描自身也分页；不能为了preflight执行一个不可让出的全库SUM/JSON decode。

### 5.2 与分页边界无关的 record root

使用现有canonical序列化和SHA256，但采用新V2域，绝不替换旧V1计算：

```
R0 = H(("sylanne3.c09.record-chain.v2", stream_identity))
Ri = H(("sylanne3.c09.record.v2", stream_id, i, R(i-1), canonical_record_i))
P0 = H(("sylanne3.c09.page-chain.v2", stream_id))
Pj = H(("sylanne3.c09.page.v2", stream_id, j, P(j-1),
        offset, count, bytes, R_before, R_after, first_key_digest, last_key_digest,
        payload_digest, next_position))
S  = H(("sylanne3.c09.complete-stream.v2", stream_id, N, total_bytes,
        page_count, RN, P_last, eof_observation, complete_count_original_digest))
```

next_position只含下一page index、record offset、累计bytes、record chain、最后PK；不含本页page root。先算Pj，再把它写入next_cursor.previous_page_digest，避免哈希自引用。record ordinal从1连续，page index从0连续。Root/certificate同时绑定N、bytes和sealed root。实际25ms让出可能影响页边界，因此 record root 不依赖页边界；replay/cold verifier读取已提交页原件的边界，不能自行分批后声称page root相同。保存前不完整的最后页可以重新计算，已提交页不得替换。

V2 row disposition复用V1四种语义及old/new row commitment；V2确定扫描顺序，不冒充V1按row_key_digest排序的manifest hash。每个旧行必须恰好得到一个disposition。无旧行对应的新tombstone、prefix marker等进入独立 `generated_rows` stream，记录具名producer与原件；不能隐含在target count里。

表级闭合必须证明：实际source count = disposition count；保留/重建/删除分类覆盖全部旧PK且不重复；target完整PK/count/root与实际转换结果加具名generated rows一致。各表摘要形成同样分页的catalogue stream；不因表数有限就重新堆一个可无限增长的header tuple。

### 5.3 membership读

持久索引只定位 `(stream_id, page_index, record_ordinal)`，不单独授予事实资格。读取必须在真实当前C09/Owner/Graph读资格下核对seal、page chain、count和实际page payload；可在一次受控读的生命周期内复用已核opaque capture view，不能缓存为跨epoch权限。

首次cold验证必须完整走完所有页。之后逐项retention/erased查询可沿同签名seal读已核页，并核其包含关系；不能只看一行key→digest索引或typed DTO。若为hash-chain而非Merkle表示，需要有界顺序验证链，不伪造O(1)成员证明。验证可分页继续；未完成时不能肯定返回retained/erased。

## 6. 唯一持久存储与恢复

### 6.1 不增加并行DB

- 四个target路径仍只能是当前Control真实INTENT登记的graph/core/execution/deletion candidate inode。
- V2 bodyless pages、row lookup与cursor保存在对应已登记SQLite candidate内的固定、closed metadata表；Control仅记录compact build plan、阶段seal和candidate/mirror摘要。
- 推荐固定表组：`c09_capture_streams_v2`、`c09_capture_pages_v2`、`c09_capture_members_v2`、`c09_capture_progress_v2`。确切DDL由Root/Rel在共同合同第一步落定；所有表必须同时加入schema/physical inventory/cold validators，没有未登记工作文件。
- pages只保存typed commitments、结构引用和disposition，不保存被删除源的原文、旧payload、未分类完整row或model response。原始内容只能从冻结源按有界片段读取，确定disposition后才写允许存活的target数据。
- 正常SQLite `-journal/-wal/-shm`仅在已有受管companion清单范围内临时存在，必须计量、关闭、checkpoint并经真实扫描消失后才能PREPARED；“分页”不许可未登记sidecar。

每个角色的proof metadata只由固定codec认定，不是任意新表豁免。target logical root排除**本次**会造成自引用的seal/certificate envelope，但单独完整计算proof-stream roots并绑定到certificate/role seal；旧metadata和旧certificate必须保留且按其版本核验。不得把用户body藏在一个名字叫proof的表里。

### 6.2 原子页与崩溃

同一candidate事务写入：本批最终target rows、对应disposition page、已验证计数/chain和下一cursor。事务提交后才允许向Control登记阶段完成。先写cursor再写数据、只写descriptor假装page已完成均禁止。

恢复只打开Control登记的同一inode。先核INTENT、source seal和已提交页/root，再继续下一页；未提交页重算。不得遇见非空candidate就清空重建，也不得沿V1 `:memory:`全库重算。若target已完整seal，必须完整cold重验并返回原摘要，不重发任何执行、签新grant或创造新operation。

Control append-only原件可沿现 `record_build_original_v1` 的OS lease/current INTENT/固定operation规则登记具名V2 compact原件，但消费者必须对V2 details做closed schema校验。逐批可恢复状态优先与candidate数据同事务存放，避免每页把全部prefix重复追加到Control；Control不能积累`all_pages` JSON。

### 6.3 正确的角色顺序与自引用边界

保持现合法依赖：真实accepted run → writer drain/INTENT → 捕获真实执行/费用facts → Graph关闭与Graph candidate → Core正式issue → Graph镜像 → Core/execution/deletion candidates → 最终关闭扫描 → PREPARED → pointer CAS → CLEANED/RELEASED。

Core在Graph issue之前不能被伪称已永久封存。每个 `FrozenRoleSourceV2` 在该角色最后一次允许的维护原件写入之后封存；后续只读。Graph的proof pages不在Graph mirror之后追加Authority三库页；后者放各自candidate，最终由Control PREPARED绑定四角色根，避免证书/文件hash循环。

Control export/selector、Authority recovery pin与PREPARED不会嵌所有页；传递compact sealed locator与根。实际物理file hash、最终inode、closed scan、writer退出、旧文件处置和Scope applied条件一项不少。V2不能把逻辑root相等当成物理处置完成。

## 7. 从producer到closure的有界全链

### 7.1 上游Owner计划与Source barrier必须覆盖100k场景

旧4096 Source入口不能作为V2一般闭包的最终实现。Root增加具名分页Source-plan/barrier producer，维持同一已授权one-source删除scope；不允许Caller增加roots、policy、Owner或Source权限。

`C09SourcePlanCaptureV2`绑定实际Owner计划、原Source、当前Owner head、namespace/Graph位置和完整祖先证据seal。祖先/后代集合放在当前Graph受管的C09专用持久工作集，以小batch推进；其记录是结构证明，不是新的Source内容或查询权限。每次恢复重新核原实际Owner/namespace与对应frame/fence。不能跳过超过单frame1024 heads的部分后肯定授权。

`C09GraphBarrierPageV2`必须绑定同一真实Core pending deletion和同一服务持有的barrier执行权限；每批使用既有Graph CAS，最多64业务写，记录准确before/after Graph版本和page receipt。未完成所有Source access撤销时，namespace保留原pending/隔离状态，业务不能在部分barrier之间穿过。缺页、另一业务写入、Owner/Source变化或丢失原permit均HOLD并仅允许原操作恢复；不能自动发新删除或换Root。

`C09GraphBarrierReceiptV2`只在全Source count/root与全部withdrawn access历史成员真实闭合后产生，绑定整批receipt chain及最终Graph/access/delete epochs；它不是V1“只加1”的假回执。Core accepted reader与后续Control只接受完整、同pending身份的V2 barrier。旧V1完全不改。该producer/consumer必须共同实施；没有此入口，100k case不能以末端分页宣称通过。

跨批一致性不能用宽泛epoch容差：允许变化必须精确归属于该操作的真实C09页事件/元数据与列明写集合，其余版本不匹配立即停。崩溃时保留实际partial withdrawal与费用/执行事实，不回滚成“没发生”、不把它报告为applied。恢复与最终安全释放由Root现Control/namespace生命周期接管，不能用普通业务job绕开。

### 7.2 Graph物理闭包

新 `C09ClosureIndexV2` 是同一受管Graph/candidate内的有限驻留、持久集合接口，不是`set[str]`的伪包装：

- `contains_atom(ref)`、`contains_source_id(id)`、`contains_operation(id)`执行精确索引查找。
- `iter_members(cursor,budget)`、`iter_frontier(cursor,budget)`每次至多本批预算。
- 扫描current/historical dependency、history.dependencies和全部已装typed provenance，按现规则追加被影响节点；只有完整一轮没有新增成员才能sealed fixed point。
- 旧 `_nested_hits` 对字符串内ref及嵌套JSON的命中语义必须保持。未知结构不能假设无引用。可以按bounded pattern pages多轮扫描或实现经验证的流式reference matcher；绝不能仅检查字段相等而漏掉旧substring规则。
- 遍历进度、visited/frontier、affected operations与成员count均持久化，不持有全edges/decoded values。一个超大JSON cell沿具名stream codec读取；节点深度/arena无法证明则HOLD，不把它当空值。

实际closure表里的token/ID只能是现允许保留的结构引用及commitment，不能另存待删原文。cold阶段从真实target markers、历史空依赖、edges缺失和tombstone索引逐页复核同一闭包根。

### 7.3 域原件与支付/执行闭包

Rel将现codec改为“逐条判定 + 有界indexed joins”的共享实现，V1可以继续包装它产生旧tuple；V2不得调用V1全量wrapper。

必须逐类覆盖：D04数值/series、D07准备/paid/Body/result、Contact各版本及Owner final/plan、Life原件/历史provenance/eligibility/worker/content、共享DomainOriginal/outbox、catalogue upgrades、budget rows、D13已擦内容的retained metadata、Owner SourceNote因果/责任链。未接类别仍整体HOLD，不能按表名一律preserve。

Core侧 model budget不能把“provider observed”当D11费用已消费：逐个call核原intent、binding、admission、terminal、fence、真实Graph cost原件和budget settle状态。UNKNOWN/未结费用/consumed identities及quota照旧保留。`capture_frozen_model_budget_originals_v2`每批产真实原件页，不返回完整list；历史与当前facts合并采用持久唯一键与冲突检查，不造全内存dict。

`PagedRecoveryFactsV2`固定五个family seal（execution、D02、D11、unknown、Graph），保留既有单fact语义。完整pin同时绑定family counts/roots、old journal anchor、原accepted/barrier与实际source seals；消耗方采用分页resolver。不能先把V4所有facts建出来再切页。

### 7.4 三库变换

`_CoreTransform`的consumed/effects/历史model/stop-reply/Owner等关联状态改成实际SQL索引读与同candidate持久键，不保留全族Python字典。`_ExecutionTransform`保持原journal prefix、未知footprint与真实新anchor关系；`_DeletionTransform`保持原删除原件与retained history。生成新prefix/anchor/retired marker使用同操作的原build plan nonce，仅一次，回放不得重生成。

Source row、target row、changed/generated rows各自有完整stream根。固定schema/SQL index/trigger以及FK/integrity验证仍执行；这些检查也不能长期阻塞普通scheduler，不满足25ms片段/250ms读事务时应在已隔离维护阶段由具名可让出的实现或已验证有界native任务执行，不能悄悄豁免资源profile。

## 8. 旧V1兼容与cold/mirror闭合

### 8.1 旧签名和大cell

V1文件/row/certificate的原始字节、SHA256、HMAC签名域与历史operation identity保持不变。新消费者先判实际schema，再使用对应验证器；不修改旧dataclass字段来“兼容”新根。

旧certificate/PREPARED/facts JSON可能本身超过一个新arena。V2通路不得调用旧全量`json.loads → tuple → asdict`回退。应由具名、流式的历史V1 reader从实际不可变cell分段验证规范JSON、旧字段顺序的原承诺、原签名和成员，输出只含必要scalar与stream view的**已验证历史视图**。这不是重新签一张V2历史证书。若该V1 codec尚未完成流式验证，就明确该历史输入未支持，不能截断或偷用大内存加载后宣布一般路径闭合。

单独的旧API可在其既有适用范围保持原返回类型，但candidate40的完整有界路径不得偷偷进入它。原文过大、未知codec、资源资格不足是实际HOLD；HOLD本身不能替代新V2实现与100k完整场景验收。

### 8.2 根与物理完成

1. producer对冻结源逐页判定，写完整候选与proof metadata，实际关闭页事务并seal。
2. 独立cold verifier重新打开同已登记candidate inode，检查schema、全部page chain/count、全部真实target rows、closed generated rows及全域关联；重算logical roots。它不能只是比较producer提供的两个hash。
3. Core以原权限独立核当前accepted/run、facts pin、Control指针/OS lease、实际candidate摘要和源/目标身份后签`AuthorityGraphRebaseIssuedV2`。
4. mirror将同一证书写入同candidate，关闭/checkpoint后再次cold验证；pre-mirror与post-mirror物理hash分别保存，不制造自引用。
5. 三库相同原则产生真实role seals，实际最终扫描仍核四源/四目标/全部已登记companion与进程退场。
6. Control V2 PREPARED核全部compact原件、实际scope和最终continuation，再原子切四文件指针；CLEANED/RELEASED仍取真实unlink/fsync/retired scan/Scoped applied原文。DTO或logic root不授权release。

read事务每批≤250ms。源文件已在相应角色seal后由现writer gate保持不可写，所以可结束一个SQL读事务并从同inode重开下一批；不需要持有跨全库的WAL reader。每批重核当前operation/文件身份/Control指针，最终重核完整文件hash；未知变化立即停。文件hash本身也分段、让出，不通过一次read_bytes加载。

### 8.3 当前读取消费者

`read_sanitized_graph_atom`、D13 retained metadata、SourceLocation lineage、migration/cold activation、storage reader等必须消费统一的 `VerifiedC09CertificateViewV2`：它可基于真正V1历史或真正V2 stream，但只有内部完整验证后才可建立，不能由JSON构造。当前guard、Source权限和C09位置资格仍独立核验。

视图提供`certificate_identity`、`contains_erased_key`、`require_row_disposition(table,key,old,new,kind)`等具名读，背后用实际sealed pages；不得将iterator转成dict/tuple作为缓存。若验证尚未完整，调用方得到明确continuation/HOLD，不得到肯定事实。一个page索引不是成员证明，一个历史证书不是当前Source访问权。

## 9. 实施ABI与单写者边界

以下分工是给Root的实施派发边界，本设计不自行启动代理。原则：共享authority/Control/fence入口由Root单写；Graph分页引擎及域codec由Rel单写；同一文件不得并写。

### 9.1 Root：合同、权限入口与Control

| 文件/模块 | 工作与实际消费者 |
|---|---|
| 新 `runtime/c09_paged_capture_contract_v2.py` | 本文具名typed scope/cursor/page/seal/candidate/certificate/mirror；必须与下面实际producer/consumer同批接线，不能只提交DTO |
| 新 `authority_service/c09_paged_capture_control_v2.py` | 实际Control实例/OS lease/profile读取、compact build-plan/seal原件、受管inode/cursor资格；沿现Control数据库，不创建旁路DB |
| `graph_coordinator.py` / `graph_store.py` | V2计划/Source barrier分页的真实Owner/Core pending/Graph CAS入口与恢复；旧V1保持原身份，64writes门保持 |
| `c09_storage_control_v1.py` | 新明确V2 PREPARED/schema dispatch、constant-size stage headers；旧字段集合/签名不改。V2大型历史读经stream view，不能由_current重新展开大JSON |
| `c09_storage_maintenance_v1.py` | cooperative batch driver、实际profile资源预约、角色封存顺序、bounded resume及final continuation |
| `c09_graph_rebase_issue_v1.py` / Core入口 | 新具名V2 issue/verify/历史读取，签名域显式区分；不扩大current/maintenance权限 |
| `c09_authority_storage_rebase.py` | 三库逐行transform和历史facts持久merge；移除V2路径全量_rows/_root/changed_rows/内存重建 |
| `c09_prepared_assembly_v1.py`、`c09_cold_intent_v1.py`、`c09_preopen_switch_v1.py` | V2compact packet、cold resume和四文件CAS，读取schema分派不得降级 |
| `c09_retired_final_scan_v1.py`、`c09_final_inventory_v3.py`、`c09_surface_cleanup_v1.py` | 逐页完整physical inventory/关联证明；真实退场、文件身份、处置与Root最终门不减 |
| `c09_control_inventory_export_v2.py`、`c09_control_selector_v2.py`、`c09_sanitized_history_v2.py` | 保旧export合同；新增明确分页消费者/stream header路由，不能把旧32/64MiB当新一般capture上限 |
| `current_source_location_v1.py`、daemon、D12 scheme installation | 安装并消费真实新view，跨generation/newincarnation和权限验证不变 |
| protected安装profile/factory | 绑定用户v3 numeric profile和实际独立host/disk证据；不能从请求传入数值开权限 |

### 9.2 Rel：Graph引擎、闭包与域原件

| 文件/模块 | 工作与实际消费者 |
|---|---|
| 新 `runtime/c09_paged_sql_v2.py` | 规范PK keyset、metadata count sweep、bytes/record/time gate、cell fragments、record/page chain；供Graph与Root三库共同消费 |
| 新 `runtime/c09_graph_rebase_candidate_v2.py` | 实际Graph builder、same-inode resume、逐页cold root、mirror执行；只消费真实scope/seals |
| 新 `runtime/c09_closure_index_v2.py` | 同受管存储内的visited/frontier/membership与完整fixed point；不返回整个set |
| 新 `runtime/c09_graph_originals_read_v5.py` | V1/V2显式历史验证view、Graph facts iterator、erased/retention成员读取；不是纯DTOwrapper |
| `c09_erasure_barrier_store_v1.py`、`c09_erasure_plan_original_v1.py` | Root定义的V2 header/page原件存取与逐页验证；Root负责其实际权限入口 |
| `domain_production_erasure_v1.py`、`domain_production_original_codec_v1.py` | shared原件/outbox有界joins、OwnerTask/Native failure历史、D13 retention membership新接口 |
| `c09_d04_originals_v3.py`、`c09_d04_series_originals_v1.py`、`c09_d07_execution_v1.py` | 逐行判定与bounded related-row读，旧tuple接口只为旧路径包装 |
| `c09_contact_originals_v1/v2.py`、Contact plan/final/owner codecs | 费用/未知效果/当前已admitted事实必须真实保留，删除内容不得误释放 |
| `c09_life_originals_v1.py`、Life worker/content/completed inventory/archive | 历史签名/producer/成员与已消费成本逐项核；流式处理大原件，不改真实发生事实 |
| `c09_budget_rows_v1.py`、`c09_model_budget_original_v1.py` | Root给定新capture API下的row-level真实Core/Graph预算join；不返回全集缓存 |
| `graph_migration_snapshot_v1.py`、`graph_catalogue_upgrade_v1.py` | 新固定表/codec分类和版本路由；不把旧全tuple迁移snapshot当V2capture实现 |

`c09_build_originals_v1.py`是共享边界：Root单写typed registry与compact build dispatch；Rel提交Graph candidate/stream schema清单，由Root接入。任何漏掉的精确type检查必须在实施前consumer search登记，不能靠鸭子类型蒙混。

### 9.3 具名调用面

- `begin_current_c09_capture_v2(installed_control, operation_id)`：Root独立读实际权限/位置/limits，返回opaque session handle与compact scope。
- `advance_c09_capture_v2(handle, expected_cursor_digest)`：调度一次100rows/bytes/time以内工作，返回`progress | sealed | hold`及≤64KiB descriptor；调用者不传行、count或complete。
- `read_c09_capture_page_v2(handle, stream_id, page_index)`：在实际scope下定位已提交页，返回bounded descriptor；payload由同受管存储读取，必要IPC使用独立bounded片段而不扩旧body限制。
- `seal_current_c09_stream_v2(handle, stream_id)`：实际EOF/count/chain/域验证完成才登记seal。
- `verify_current_c09_capture_v2(...)`：独立重读产生private verified view；不能由page JSON直接构造。
- `issue_current_graph_rebase_v2(...)`、`mirror_current_graph_rebase_v2(...)`：沿真实Core/Control权限，只接已闭合版本原件。
- `resume_c09_storage_v2(operation_id)`：从实际INTENT/current pointer/原candidate inode恢复，绝不换operation或新建替代事实。

## 10. 完整性与资源验收合同

实施先编译，再由Root在固定snapshot组织必要的永久验收。没有完整production path之前不新增过渡测试冒充资格，不反复重跑已过项。

至少需要以下独立证据：

1. **完整性负例同一有限fixture：** 缺页、重复/乱序、跨source cursor、false count、漏最后页、跨表/schema、合法大cell的fragment跨界、晚到nested依赖。每个失败必须无法issue/mirror/RELEASED，原Source和费用历史保留。
2. **真实完整重建：** 当前Owner/accepted/pending/barrier、真实Control lease/gate、至少两个实际页、四库真实原件、独立issue+mirror+cold switch；V1历史与V2新证书混合仍能精确retention/erased读。不能拿构造的DTO或raw SQL标签代替正式producer。
3. **恢复：** 在页提交后/Control seal前、mirror ACK未知、PREPARED前真实关闭三处有限恢复边界，核same inode/original operation/count/root，没有额外执行/重复费用/新权限。
4. **规模与资源：** 用户的1000/10000/100000 Source规模由实际合法producer建立或使用已认证的真实原件fixture；比较arena/queue/WAL/磁盘/reader事务年龄和whole-group memory.current/peak。未有合法100k producer时该层保持未验证，不能直接SQL造READY。真实4GiB隔离目录许可与可用量缺失时不启动该资源资格。
5. **调度：** 每个maintenance quantum记录actual rows/bytes/local time和continuation；超25ms单不可分割codec必须修复或保持profile未合格，不能只在外层循环统计“平均25ms”。完整100k cold recovery的60s是SLO提案，不是设计证明。

结构完整性、签名/权限、数据闭包、真实资源量测和用户体验是不同状态。不能用有限profile HOLD、纯hash单测、无OOM或一次成功代表“全部39项通过”。

## 11. 交付顺序与实施门

1. Root落共同typed合同与真正installed profile/capture入口；Rel落实际paged SQL+同candidate storage引擎。两者一起编译、接口读回，不提交未消费的空DTO。
2. 完成上游Source plan/barrier及持久closure/facts；此时仍不得宣称cleanup完成。
3. 完成Graph与Authority三库builder和所有域逐行validators，删除V2路径的全量集合/全库内存重算。
4. 完成Core issue、mirror、PREPARED/current reader、cold recovery、selector/export和retention成员读取的显式版本路由。
5. Root从源码矩阵确认没有V2绕回全tuple路径，固定candidate40，再执行必要永久family一次并保存首错；已冻结37/38不修改。

**设计完成条件：** 本文合同和文件边界完整；每一个新增原件都有实际producer、持久位置与消费者；不存在对未定义无限容量的依赖。**实现完成条件：** 上述五步与实际证据达到，不是本文写完。

## 12. 本次设计证据与进度

- 已读当前Graph rebase/closure/certificate、Core issue、Control build/PREPARED、cold reader、Authority三库transform入口与recovery facts消费者，按源合同识别了上游barrier与大cell/旧packet缺口。
- 已读用户v3全部resource_profile，保留`PROPOSED_NOT_MEASURED`。没有借用旧Control32MiB来伪造新总预算。
- 已明确Root/Rel单写者及共享typed/codec边界；没有spawn，没有为C09写运行DTO或产品实现，没有执行C09业务/模型/资源测试。
- 37/38冻结目录只读；本文件与永久evidence面向后续candidate40。期间独立授权的Life凭据修复由各单写者另行记录，不能当本设计的C09验收。
- 当前状态：**DESIGN_READY_FOR_ROOT_IMPLEMENTATION_HANDOFF**。Root预算续期仍不在本设计中。

## 13. next40 共享核心实施交接

Root 已明确将 `runtime/c09_paged_capture_contract_v2.py` 单写权交给 Astra；Root 与 Rel 的其他边界保持不变。该文件已经实现，编译及真实 Python import 通过；尚未执行完整 C09 生产/资源验收。

实际公共类型为 scope、frozen role source、stream identity、record commitment、cursor、page、independent census 和 complete seal。它们的 `.digest` 是只读属性；scope/source/identity/page/seal 同时有语义别名 `scope_digest` / `role_source_digest` / `stream_id` / `page_digest` / `stream_digest`。真正候选/证书/issue wrapper 在实际 owner 接其 callee 时落地，不提前堆未使用 DTO。

实际调用面：

```python
begin_c09_stream_v2(stream) -> C09PageCursorV2
append_c09_page_v2(stream, cursor, records) -> C09CapturePageV2
verify_c09_page_v2(stream, cursor, page, records) -> C09PageCursorV2
seal_c09_stream_v2(stream, cursor, census, *, data_eof_observation_digest) -> C09CompleteStreamV2
verify_c09_complete_stream_v2(stream, cursor, census, seal, *, data_eof_observation_digest) -> None
c09_paged_value_to_wire_v2(value) -> dict
c09_paged_value_from_wire_v2(raw, cls) -> exact named V2 value
```

`records` 是最多100个 `C09CaptureRecordV2(primary_key, commitment)` 的 tuple；commitment 来自实际域 codec 验证的原件/转换记录，页面不保存原文。独立 census 的字段是 `stream_id, record_count, last_key, eof_observation_digest, original_ref, original_digest`。实际 metadata sweep 不加载正文，因此 census 没有虚假的“等于proof编码bytes”字段；complete seal 的编码字节来自真实页，独立count/lastPK和两个真实EOF分别绑定。

stream key ordering 第一版明确支持 SQLite BINARY ASC 的固定 text/integer 复合PK；INTEGER限定SQLite有符号64位，bool/NULL/浮点/混型/未登记collation不受支持。更大cell或BLOB PK必须通过实际具名codec扩展，不能偷偷转换并称等价。每次append严格检查跨页key递增、原stream绑定、初始根、连续record/page位置、实际canonical payload字节。cold verifier重算持久页边界，不把重新切页后的page root冒充原根。

closed wire codec仅接受完整字段集和已列V2 exact types；原件JSON使用plain fields，承诺编码仍使用现canonical serializer的exact type标签。无V1尝试回退。构造typed值或提供digest不授予权限，Root/Rel必须从实际Control、源inode、持久cursor、独立census和data EOF建立这些值。

两项自引用修正已裁决并获Root确认：

1. 页根绑定 `next_position` 而非已含本页根的完整游标；游标随后绑定最终页根。
2. scope绑定已有且不可变的 `facts_pin_intent_digest` 与 `facts_pin_ref`，不预先绑定依赖本scope产出的family seal。完整family roots在后续真实facts pin completion中闭合。

实际维护时间、SQL字节、arena预约、事务年龄、磁盘/文件身份仍由installed Control和paged SQL producer执行。模块内100/262144/65536只是用户v3 proposed上限，不能标为实际资源资格。

## 14. Large-row feasibility boundary and pending invalidation overlay

Status: static source analysis, not a live database measurement and not a resource qualification. No Source body was manufactured, no runtime case was rerun, and frozen 39 remains unchanged.

The existing valid Source schema permits 65,536 text characters (`rewrite/sylanne3/memory_types.py`, `_MAX_TEXT_LENGTH`, `_text`, `SourceRecord.__post_init__`). Its stored canonical JSON uses `ensure_ascii=True` (`rewrite/sylanne3/contracts.py`, `canonical_json`). A permitted text of 65,536 BMP Chinese characters therefore needs 393,216 ASCII bytes for the escaped text alone: 384 KiB, or 1.5 times the proposed 256 KiB batch bound. The surrounding fields add more bytes. This is an existence/lower-bound argument for a schema-valid value, not evidence that such a row exists in the current installation. The previously discussed Native artifact and prepared-input sizes are separate evidence and are not being relabeled as Source rows.

`GraphStore._graph_commit_in_transaction` updates the existing atom revision/validity and inserts a new `graph_history` row containing the complete prior value. The actual physical write size of an existing overflow-row UPDATE has not been measured. The new history row and a new candidate database row are enough to expose the constraint: persisting the complete uncompressed single-TEXT value needs more than 256 KiB for that permitted value. `INSERT ... SELECT`, an earlier staging copy, and omitting Python materialization do not remove that durable-byte lower bound.

A C09-only pending invalidation overlay is a possible narrow solution for the invalidation stage. Its new immutable record must bind the actual namespace and operation, plan/pending/permit, original atom token/revision/body commitment, actual page/epoch and complete invalidation-frontier proof. The original large `graph_atoms` and `graph_history` payload rows remain untouched while the actual Core namespace is closed to business. C09 current readers, source classifiers, cold verification and candidate generation must explicitly understand this new variant. Completion requires the actual invalidation frontier, dependencies and pages to reach independent EOF. An invalidation-only page must use its real Graph/access/delete epoch changes. This overlay does not authorize reopening the old pending namespace and does not erase physical bodies before the normal new-storage cutover and cleanup.

The overlay alone does not solve preservation of an unrelated permitted large row in the new candidate. A complete design choice remains:

- Preserve the strict byte limit with a new versioned segmented-value store and fixed-size row references. Old immutable value bytes are read and copied in bounded chunks; the new current, query, history, restoration and C09 cold readers explicitly resolve this storage version. The legacy V1 wire/hash interpretation stays unchanged. All chunks, reference metadata, physical page writes, complete counts, EOF, lifetime and cleanup obligations need actual qualification. This is a storage-layout migration, not a small history-only patch.
- Preserve the current single-TEXT layout and explicitly authorize a measured exception for one large atomic row operation. This changes the strict 256 KiB contract and cannot be implemented silently. Model caps, original permissions and TTLs are unrelated and remain fixed. The exact measured I/O/CPU/RAM behavior would need separate acceptance.

Until that choice is made and implemented, bounded frontier/source work may continue, but neither the overlay proposal nor source compilation is a claim of complete large-row C09 resource qualification. The independent V7 counter and Native duplicate-validation work can continue without weakening this boundary.
