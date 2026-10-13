# C09 正式分段存储实施合同

状态：用户已批准分段存储并保留原上限；单名 Astra high 只读审查完成。Root 负责实现。源码、迁移、选定与资源运行资格分别记录；整体 HOLD。

## 已确认边界

旧快照、原始数据库/日志、业务原件字节与签名保持。原 batch 为 100 records / 262144 总读取+写入+编码字节 / 25 ms，read 250 ms，arena 8 MiB，普通写 64，2 CPU / 2 GB；不改变预算、期限、时钟容差或权限。SQL/codec 字节口径不能冒充 OS/WAL 物理写入量。

## 格式与真实资格

共同模块为 `rewrite/sylanne3/segmented_sql_cell_v1.py`。Graph 明确升级 `graph-storage.v3`；注册的 Core 大列使用独立 storage v2；业务 payload schema/旧签名域不改。固定四表：`segmented_storage_layout_v1`、`segmented_cells_v1`、`segmented_cell_segments_v1`、`segmented_cell_writes_v1`。单段原始 UTF-8/BLOB 最多 16384 bytes。

cell 头记录 codec、总字节、段数、完整原始 payload SHA、有序 segment root、来源 scope。cell ID 绑定实际 target storage instance、删除责任域、producer operation、logical locator/column；不跨删除责任域全局去重。段有 ordinal、byte offset、长度、独立 SHA。完整 bytes SHA 与段 root 各自计算，不互相冒充。

C09 target 仅由真实 `C09PagedCaptureSessionV2` 与已注册 `InstalledC09RolePairV2` 发行。布局 transition 必须是 Control 在当前真实 INTENT、accepted barrier/freeze 下签发的原件。普通读者只由真实 selected manifest v3/role handle 与当前具名 admission 派生。不得从 caller path、connection、layout bool、任意 CellRef 或 cursor 授资格。

## 写入与恢复

多量子先写 immutable segments 和同事务 cursor；真实 EOF 与独立段 census 完成后封 immutable header。最终短业务事务只发布已验 CellRef、真实 head/history/event/epoch CAS。相同 token 的相同 payload 可复用同 cell；历史失效不复制巨大 TEXT。

hash/parser 在每量子的私有副本前进；SQL commit/CAS 确认才替换 live state，回滚丢副本。重启按量子重读已提交前缀重建 hash/parser，核 prefix SHA/root 后继续。cursor/phase 不是 sealed 资格。缺段、多段、错序、错 offset/hash、跨 scope/role、未解释孤 payload 均拒绝发布/选择；不修饰坏 candidate 后选定。

## 旧格式迁移

旧源只读，在冻结来源/连续栅栏下逐 logical row/原始 cell 迁入尚未选定的四角色候选；不原地 ALTER 大表、全量 INSERT SELECT、VACUUM 或巨大 zeroblob。空目标预建正式索引。

已登记 rowid 表通过短只读事务的 readonly SQLite blobopen 获取 TEXT/BLOB 原始 bytes，逐量子核实际 UTF-8 encoding、PK-rowid、长度、schema/file identity；每量子关闭 handle。WITHOUT ROWID、所有 rowid alias shadowed 或未登记编码没有整体读取 fallback。参考：https://www.sqlite.org/c3ref/blob_open.html 。

若旧源尚未完成实际 Source 撤销，改为新目标撤销时发行新 `c09.source-revocation-target-plan.v3`，绑定旧 Source/access heads、accepted Core barrier 和真实 closure；target access/history/invalidation 每页有实际原件，最后核真实 EOF/epochs。旧 V2 已执行结果照旧验证，不重复计算。

## 消费者与最终选择

逐项迁移 graph_store current/history/events/dependencies、GraphCoordinator/domain/current Self/foreground/D13/ModelAdmission 与 Core typed accessors。禁止指针字符串伪装 JSON、SQL 文本重写、group_concat/兼容 view 拼整行。C09 仅 stream/VerifiedEOF；普通业务按注册 type limit 有界物化。json_extract 大列定位改用真实原件派生的有界索引，索引不是权威。

新 `storage_manifest.v3` 绑定 layout/schema、四角色 logical roots、cell/segment/ref census、physical roots。原 v1/v2 roots 不重释。所有真实 EOF/孤段检查完成后，对实际 expected source pointer/version/manifest/generation 和 Core/Owner 执行最终 CAS。重启仅读真正 selected 指针，不扫描目录挑 generation，不恢复旧授权。

## D13 原件生命周期

Counter draft 的 raw/compressed/input_json 含 Source 正文。完整依赖通过真实 frozen question/units/access/correction/history/paid/C02 lineage 进入现 closure；受撤销影响的完整 payload/segments 不进入新目标。不得删字段后沿用原 frame digest；必要退休事实另起 schema，绑定旧原件捕获承诺和真实 C09 accepted/retirement proof。消费旧 op/nonce/claim 的当前恢复资格；unknown claim 保留真占用，不补零 CPU、退款或重跑。

header/evidence/HTTP 原件按具名 codec 历史留存，不能 metadata 豁免：header 绑定真实 draft/frame 承诺；evidence 用原 key/policy 验 Ed 签名；HTTP 两阶段签名、counter/frame/call/admission/request/providerconfig/modelintent 相同，观测时刻在原期限内。它们仍只证明 pre-send，不能代替 provider terminal 或收费。

CPU quote/request、D11 CPU cost、D02 Body cost、accounting attempt 核真 HMAC、实际 prepared、独立 journal claim/terminal、reserve/settle、Graph settlement/job closure。C04InternalWorkPrepared 若具名完整 schema 无正文，保留原历史字节；Source refs 不等于正文。具名退休/当前性门拒绝重新执行。

## 必要验收

1. 合法 65536 BMP 字符 Source、跨 UTF-8/转义切段、实际 Core 大原件：原 bytes SHA/语义不变。静态 393216B 下界与旧39实测44506B区分。
2. 缺/多/孤/乱序/错 offset/段 SHA/总 SHA/跨 scope/role 的具体拒绝。
3. 段事务、seal、业务 CAS、pointer CAS、丢 ACK 的真实中断恢复；唯一合法指针，无重复历史/计费/claim 执行。
4. 原资源和时间界限实测、撤销/源变化/身份变化仍拒绝；编译和 DTO 不替代运行资格。


## V3 发行合同细化（2026-10-10 单名 Astra 只读审查）

manifest 精确采用 V2 字段加 segmented_root_algorithm、segmented_layouts、segmented_role_complete_original_digests 三字段；schema/signature domain 各自为 storage_manifest.v3 / manifest_signature.v3。原 paged-storage-roots.v2 与 member 字段意义保持。每角色 layout 仅 layout_id/schema_digest/storage_instance_id；新增 root 算法为 segmented-role-roots.v1。

PREPARED 使用独立 storage_prepared_original.v3 / c09_storage_operations_v3，增加同三字段并绑定实际 manifest。旧 bootstrap/PREPARED/selected reader 不发行 V3 资格。

四类真实 Control 完成流分别是 headers、segments、logical refs 与全覆盖 orphan join audit。每类绑定 actual scope、role、source role root、target device/inode、layout、storage instance、既有 role completion 和实际 Control store，持有完整 identity/count original/final cursor/complete stream/data EOF。页和 members 只写 Control，不写回目标以避免物理 hash 环。segments、refs 指向真实 headers 完成原件；audit 指向三者及实际 write-progress census/schema。audit 必须逐 headers/segments/refs/write-progress basis 产生 header_has_ref/segment_has_header/ref_matches_header/write_cursor_closed 关系 witness，序号全覆盖，record_count 等于真实扫描数之和，违规数零并独立观察四侧 EOF。字面量零、cursor sealed 或普通 DTO 不能作为完成资格。

Control 私有 selected-file handle 只授物理打开及固定 metadata；正文 reader 另需实际 Source/fence 或具名历史 admission。正式 runtime make_store 与 Authority factory 均须迁到此入口，禁止旧构造器自动建旧表。当前只落精确格式及旧版本拒绝，实际 V3 producer、PREPARED、私有 reader、选择和资源资格仍 HOLD。

历史空辅助 Source 流仅在同 family 的 signed disposition basis 零 count、实际 schema/注册 identity、规范空 genesis、实际 count/data EOF、无 pages/members 和独立双流 EOF 闭合时允许无 row witness；非空规则保持。

共享 canonical 计量使用 runtime_contracts 单一上下文。每次实际序列化各计一次，同 meter 嵌套不双重收费；Control 保持原非 ASCII UTF-8 签名字节。编码收费不代替预读取、arena、OS/WAL 和真实时间资格。


## 四流实际原件与无环发行顺序（2026-10-10）

实际 Control projection 表固定为 c09_segmented_headers_v3、c09_segmented_segments_v3、c09_segmented_logical_refs_v3、c09_segmented_orphan_audit_v3。raw stream family 使用真实表名；完整 PK 的前缀为 scope_digest、role，随后分别是 cell_id；cell_id、ordinal；family、logical_key_digest、column_name；basis_kind、basis_ordinal。索引、immutable triggers 和 table shape 各自精确核验。segments 只存描述，不存正文。

实际四流先完成 census/data EOF、真实 target 两次完整枚举、独立 page/member 核验与正向 orphan audit，发行 private physical sweep；它不授 selection/body admission。Graph 实际 pre/postmirror cold 必须逐物理行消费这项完整 sweep，随后保留 capture_role_complete_v2_graph。最后真实量子逐项保留签章四类完成原件并汇总 segmented_role_complete。最终签章才绑定已存在的 base role complete，原始 stream 不依赖未来 role digest 或 target hash。其他角色同序。postmirror 需要实际新扫，不从旧布尔值恢复资格。

四类完成 details 的 exact B 字段为：schema、operation_id、scope_digest、role、source_role_source_digest、target_identity、layout_id、layout_schema_digest、storage_instance_id、role_complete_original_digest、proof_store_id、identity、count_original、final_cursor、complete_stream、data_eof_observation_digest。target_identity 是真实 dev/inode 两整数；JSON wire 为两元素数组。

- headers：schema=sylanne3.c09.segmented-cell-headers-complete.v1；exact B；kind=segmented_cell_headers_complete_v1_<role>。
- segments：schema=sylanne3.c09.segmented-segments-complete.v1；B 加 cell_headers_complete_original_digest；kind=segmented_segments_complete_v1_<role>。
- refs：schema=sylanne3.c09.segmented-logical-refs-complete.v1；B 加 cell_headers_complete_original_digest；kind=segmented_logical_refs_complete_v1_<role>。
- audit：schema=sylanne3.c09.segmented-orphan-audit-complete.v1；B 加 cell_headers_complete_original_digest、segments_complete_original_digest、logical_refs_complete_original_digest、write_progress_count_original、write_progress_schema_digest、scan_counts、scan_eof_digests、violation_count；kind=segmented_orphan_audit_complete_v1_<role>。

scan_counts/scan_eof_digests 的 exact keys 为 headers、segments、refs、write_progress。它们来自真实 target 独立两遍枚举与实际 EOF；前三 count 同时等于对应完成流 count，write_progress count/EOF 来自真实两遍 C09CountOriginal。ref EOF 聚合全部登记逻辑表真实 EOF。audit 的 record_count 等于四侧 count 之和；违规数零只能在完整正向审计完成后产出。raw projection 的 count/data EOF 保持各自意义，不能冒充真实 target EOF。

role summary exact fields 为 schema、operation_id、scope_digest、role、source_role_source_digest、target_identity、layout_id、layout_schema_digest、storage_instance_id、role_complete_original_digest、cell_headers_complete_original_digest、segments_complete_original_digest、logical_refs_complete_original_digest、orphan_census_complete_original_digest。schema=sylanne3.c09.segmented-role-complete.v1；kind=segmented_role_complete_v1_<role>。所有外层沿真实 Control storage-build-original.v1 签章，不新造签名算法。既存原件重放也逐项重算 exact details；字段近义、错 scope/layout/base/stream/EOF 均 HOLD。

当前源码已接本切片；尚未运行实际安装/资源验收。整套四角色 V3 PREPARED、selected opener 与普通消费者仍未闭合，不将编译或 private sweep 接线计作运行 PASS。


## D13 Root 历史 qualification 重建（2026-10-11）

单名 Astra high 对实际 D06 producer 和 Core consumer 的只读审查已完成。主对话实施；不增加预算、期限、token 长度上限或测试旁路。当前完整资格仍 HOLD。

正式库存保持 Source lineage 的 DFS/LIFO 原访问顺序，第一个为 Root；Access/correction 分别按 token 全序排列，完整一一对应，correction revision 为零。最多 256 个唯一 Source，沿正式 visited 去重语义，不新增遇环即拒规则。raw/compressed 库存必须相同。该库存检查已写源码，不能代替真实 ancestry 证明。

下一实际 cursor 按 pending.pop、visited、pending.extend(actual parent_source_ids) 遍历。每个真实 Source 和 Access 都须完整流式 EOF、原 draft epoch 版本证明、audience/expression 授权；correction 必须证明在原 epoch 实际不存在。逐阶段仅实际共享量子正常退出后采用，拒绝候选不推进。Root 已完成的 Source/Access 原件可按同 capture/handle 复用，祖先不能由 Root 证明代替。

qualification 身份重建使用已完整承诺的 draft/collection history_selection access_epoch/deletion_epoch，两存在 variant 必须一致；不用冻结 Graph 当前 barrier 替换。graph_authority_epochs 无 history，且 barrier 可不推进 Graph epoch，所以不得倒扣或仅凭 Graph epoch 反推。

按 domains/d06/qualified_expression.py 的正式 plain canonical dict 输出。lineage 来源于真实遍历；完整 read_versions 按 token 排序，普通二元数组，无 DTO tag、无 graph_epoch 字段。Root text_range 的完整 canonical ASCII 标量含引号逐片段进入 source_excerpt，不用文本 SHA 替代正文。其余字段取真实 Root metadata、原 audience、原 span、float(original plan deadline) 与原 epoch。真正全部 EOF 和 ancestry 采用后再比较 qualification_digest。

相同 digest 只证明历史身份；原 deadline 来源仍需当时 attention、route、role、grant 和必要 producer 的独立原件，缺失则保持其具体 HOLD。历史资格不授当前表达、刷新授权或付费权限。


2026-10-11 源码进展：实际 Root cursor 已接齐正式祖先遍历、每祖先历史 Source/Access/correction 原件与权限 EOF，以及正式 qualification plain canonical digest 的分片重建。copy hash 独立；最终摘要在另一个真实共享量子比较并正常采用后才完成。静态复核发现的 DTO 字段错配（deletion_epoch）和 namespace/token/EOF metadata/数值临时资源计量均已修正。只完成编译及实际 Linux 导入，未执行运行资格/业务验收；独立 deadline 来源、完整 collection 绑定、paid block 原件和 retirement 仍 HOLD。


## Paid-derived 完整依赖合同修正（2026-10-11）

实际生产链 plan_paid_precompression_v2 → _plan_prefix → compile_extractive_model_output → standby → prepare_derived_payload_v1 保留按 turn 顺序去重的 completion/Source/Access 三元闭包。原 metadata/C09 payload 校验却要求每条依赖都是 memory.source，会拒绝真实 producer；未发现正式过滤入口。

源码现在保留原 plan/block/wire/commitment，用共享纯 validator 从同 namespace、实际 scene/conversation/sequence、Source 身份与对应 Access 重建正式逐 turn 三元闭包，再要求去重后的完整 tuple 全等。metadata 的 scene_ref 限定同 namespace scene-owned d03.role_binding；C09 独立 payload 从真实 turn anchor 校验正式 raw key，外部 metadata 场景 join 仍需原件证明。正 revision、64 turns、192 dependencies 和 65536/524288 字节上限保持；没有 Source-only 自动兼容分支。

metadata TypeSpec 的 sources descriptor 已同步修为 exact_ordered_turn_completion_source_access_closure。新安装须登记实际新 descriptor/hash；旧快照 PASS 不移植。真实原件、paid 资格、activation、资源运行资格仍各自 HOLD。metadata UTF8 复制由构造器实际计量；Core 原 encoded_delta 补偿移除，避免对新增 helper 成本双收。constructor 前还预留完整 scene/conversation/Source/Access/completion 输出及原 transport 费用，不扩大原共享量子预算。


metadata before revision 新增独立原 epoch 量子：复用既有完整 temporal proof 的创建事件、frozen epoch、真实 head、紧邻 successor 与实际成员证明。Root public 仍限 Source/Access；metadata public 只限实际 capture namespace 的 persona metadata key。standby R+1 只是候选，不添加不存在谓词；若后续实际发生转换，其 successor event 必须严格在 draft epoch 之后。既有比较、期限及预算不变。


## 历史 paid job/plan 实际原件链（2026-10-11）

runtime_jobs 只提供经过真实完整 Source member 认证的小 locator，不用冻结时 phase/fence/cancel/result冒充历史。具名消费者独立逐列读取真实 target 的全部 scalar/8 KiB TEXT 字节，重建原 c09_row_commitment_v2 域并与实际 disposition new commitment 对比；derived_removed 分支验证实际 absence。旧普通 point 消费器仍完整检查实际 target。

正式 activity runtime_job_key 只定位原 draft epoch 以内的实际历史 revision，另经封闭 job temporal 入口证明当时有效/current。完整 Graph RuntimeJobValue EOF和正式字段检查完成后核对历史 completed、cancel_epoch零、result_ref为实际block及locator/key相同。时间两列沿 PersistentJob 原35 Unicode字符合同，保留合法非ASCII ISO分隔符；其余ID和canonical JSON沿原ASCII物理格式。

完整 frozen continuation_json 依原MAX_JSON_BYTES=65536分片读取，canonical EOF SHA必须等于历史Graph job.continuation_digest；不同就HOLD，不只比较其中plan子树。实际plan原对象range二次分片重读得到plain digest，与continuation.plan_digest比较。正式原decoder已提为共享纯函数，旧job loader保留原digest/job/continuation关系检查；consumer不伪造PersistentJob。另一个独立量子计算typed canonical PrecompressionPlan digest，与Core block binding.plan_digest比较。

完整plan范围/依赖/scene/audience/candidate/三类epoch与实际before metadata/原selection对应；plan expiry可以被metadata进一步收紧，故不强求两者相等。copy状态/hash独立，parser callback不保留cursor，所有前进依实际正常量子采用。当前链仅接齐历史job/plan身份源码，完整payload、paid originals和retirement仍有明确HOLD，未运行业务/资源验收，不授paid权限。


## Derived payload 实际字节与 frozen 文本原件（2026-10-11）

实际 Source BLOB 固定键为metadata的bot/persona/block_ref。完整旧Source成员/ordinal/disposition已认证，实际BLOB以8 KiB分片累计length/SHA及canonical EOF，独立按c09_row_commitment_v2的BLOB SHA/size投影复核旧行。保留target分支实际读取完整target BLOB和小列并独立核SHA/new row commitment；derived_removed只在真实target absence后继续。旧Source本身缺正文则HOLD，不从metadata摘要恢复。

具名paid-extractive parser只保留正文canonical/UTF8摘要、字符数和真实范围，不物化完整block正文。根和各item限定正式plain字段；turn最多64、dependencies192、timeline每turn一项、detail每turn0至4且逐turn分组。sorted wire中detail/timeline早于turns，先保留metadata范围，后连接实际anchor/namespace/Source/Access完整closure/原始时间与plan/metadata。原BLOB时间float roundtrip规则在本消费者保持；通用DTO和SourceRecord允许int输入的合同不改。

每个frozen stable turn的实际Core text scalar范围独立分片重读，与对应真实payload timeline scalar canonical hash比较，sequence/speaker和完整数量也对应。之后按正式prefix与canonical转义换行从真实Source text范围重建稳定正文hash/字符数。每条frozen detail先在完整已承诺block范围库存取得唯一owner，再按sequence/Source/speaker/UTF8 hash与长度消费一个真实slot，避免跨block跳过、重复归属或单slot重复匹配。

当前已接这段源码并完成必要编译及实际Linux导入，未运行业务/资源资格。detail选择算法完整parity、原文substring/qualifier/omission/压缩收益，以及独立paid intent/call/result/settlement/Authority链仍明确HOLD；文本来源匹配不授paid资格，不意味着四角色安装或整体验收完成。


## Paid intent/call 外层原件与有界内层解码（2026-10-11）

具名消费者固定读取真实 graph_d13_paid_intent_originals_v1 / graph_d13_paid_call_originals_v1，以实际 namespace/job key、完整旧 Source member/ordinal/disposition 为依据。完整 original_json TEXT 逐 8 KiB 读取，不用摘要替代正文；旧行和独立 target 全行分别沿真实 TEXT 转义 tuple 域核验，removed 分支要求实际 absence。

original_digest 按 producer 的 plain root + schema 重建，只有 namespace/binding/非 null exact_count 的真实对象插入正式 DTO tag。frozen_json/request_json 仍是实际带引号和转义的字符串；不误用 SHA(original_json)。binding 原 plain digest 独立复核，与实际历史 continuation、metadata、operation、budget operation、fence 和三类 epoch 对应；queued job digest 不冒用 completed Graph job。

内层 decoder 复用 canonical parser 的跨片段转义状态，只解一层、仅接受实际 canonical ASCII wire。每批 decoded 输出有界，批量送入独立 inner parser，分别完成实际 encoded scalar 与 decoded object EOF。三个 parser 的实际 dict 和 base slots 均计入 arena/copy，输出及 bytes 副本按实际长度收费，未提高预算、期限或 parser 上限。

内层 range 始终是 decoded 坐标，不能直接当 SQL 物理偏移。小 metadata 通过重新从原 scalar 起点完整读取并解码，按真实 decoded range 收集；大 window/turns/messages/wire/envelope/payload 未整体物化。实际 frozen plan 与已认证历史 plan 做 plain canonical 全等；安装/model/config、输入/wire/read-closure 摘要声明、模板和 schema 与外层绑定对应。request 小字段限正式 text capability/template/model/call/timeout，输出 ceiling 再与 frozen installation 对应。这些仍只是身份与小 metadata 校验，不证明摘要声明对应真实 body。

当前 Source compile/Linux import 检查与业务验收分开。完整 window/turns/read closure/canonical input/messages/wire 重建、request typed envelope/digest、queued job/quote/grant/reservation/result/settlement/Authority 原件、detail selection parity 和 retirement/四角色安装仍 HOLD。不生成新快照，不复跑旧首次失败，不调用付费服务或修账。

本段静态审查实际发现并修复：parser base slots计量遗漏；call分支校验名字作用域错误；privacy/timeout改为复用正式合同；plan编码前先比较真实decoded plan范围与已认证plain plan范围长度，再按实际长度预留。最后小metadata阶段源码经Linux实际导入，最终哈希与Windows一致；未执行运行资源资格或业务节点。


## 实际 messages、canonical input/provider wire 对应（2026-10-11）

paid inner parser现在逐真实片段记录具名scalar的canonical SHA和单层decoded ASCII SHA/byte count，不物化正文。messages恰为system/user两个plain对象，每项只有字符串role/content；request payload只有字符串system_prompt/prompt。完整messages数组哈希取实际fragment与真实range的交集，包含全部括号、逗号和字段语法，不从scalar事件拼造。

实际canonical_input单层decoded SHA与frozen digest对应；messages完整数组SHA/bytecount与decoded messages_wire对应；system content对应正式SYSTEM_MESSAGE，user content/request prompt对应实际canonical_input的含引号转义scalar。optional exact count保留None；非null检查quality和实际provider/model/config/messages/wire identity，不把字节数推断为token。

canonical_input和canonical_wire decoded输出分别批量进入独立具名canonical object parser，完整EOF及bytecount/SHA与实际scalar摘要对应。input根schema/template/output schema检查正式常量，scope/plan/turns语义仍待后续；provider wire根六字段精确，安装身份和正整数max_output与真实installation全等，messages子树完整SHA/bytecount对应实际frozen messages。

中间输出、bytes副本和实际range切片逐层计量；独立hash、slots、buffer和copy计入原arena。静态检查发现并修正错误WeakSet接口、跨quantum文本backlog误拒和float/int wire表示混淆。审查者曾报告inner text未计量，实读reader before/after实际增量后撤销该项，没有新增重复收费。最终源码编译和实际Linux导入通过，不属于运行资格或业务验收。window/turns/read closure、request envelope/digest、结果/settlement、retirement及四角色安装仍HOLD。


## 实际 frozen window、selected turns、typed read closure/fingerprint（2026-10-11）

inner parser限定实际window和CompletedTurn完整字段，正文仅保存真实canonical scalar SHA/bytes/range与Unicode非空白状态，允许中文/emoji。非text metadata通过实际outer scalar完整decoded replay逐range取得，不造占位CompletedTurn。完整window没有64条上限，只检查正式严格递增、watermark、历史clock/scope；selected按plan筛选，沿原64上限要求完整连续、对应window原成员及已认证payload anchors。

namespace/scene/audience/三epoch、closed状态、float原存储表示、原window trusted time、plan expiry<=首selected turn+72h、missing_ranges及完整window/selected raw/Source/Access closure独立对应。没有用当前clock刷新旧授权。window scope、每个turn、selected关系分不同共享量子；metadata inventory新分配前沿actual arena预留，不扩大数量或预算。

typed read closure根按正式sorted字段输出，每条实际VersionedRef独立量子编码，保留read_set/source_dependencies数组原顺序和重复、允许正式revision-zero absence。完全输出后比较frozen read_closure_digest，不把集合检查替代原字节身份。

fingerprint沿正式plain root：namespace/scene/audience typed；selected turns通过实际Source scalar完整重放，取原decoded selected array范围，仅在实际CompletedTurn和四个ref对象start+1处插入正式type标签。实际text原字节不物化、不替换为SHA，missing_ranges按原公式裁剪。完整encoded EOF、decoded byte count和每turn五tag库存完成后比较plan.input_digest；hash/decoder状态独立复制，临时片段和tag按实际费用计量。

记录首次编辑/审查问题：一次定位断言失败和一次转义SyntaxError均在写入前失败，产品未被该失败写入；随后静态检查发现新增方法被放入RootAccess类，正常PaidIdentity路径会AttributeError，已移至PaidIdentity且AST验证归属、RootAccess无死方法残留。此前“缺少payload属性”报告来自旧快照，复读实际构造器后撤销；最终只保存真实已采用payload anchors且计arena。正式window及fingerprint静态审查已确认最终源码；actual Linux导入exit0且hash一致，尚未运行量子资源资格或业务验收。

canonical-input完整scope/plan/turn投影、历史Graph Source/Access/absence真实性、request envelope/digest及quote/grant/reservation/result/settlement/Authority仍HOLD。当前Source变更不替代新快照中的单次Numeric/fullD13/V7或all39alpha2验收。


## 实际 canonical input 完整投影（2026-10-11）

已采用window/selected turn/read closure/fingerprint后，具名cursor按正式plain根output_schema/plan/schema/scope/template_version/turns输出。plan仅八字段、scope十三字段、turn仅六字段；refs和namespace在此plain投影中不加type。missing_ranges输出完整window数组，逐pair处理，不误用fingerprint裁剪结果。

immutable actions只存正式语法、小metadata原对象和实际selected-turn text decoded范围。每个metadata primitive独立共享量子编码，按实际来源range或实际数值位长预留；不缓存整段prefix/suffix。text直接包含真实canonical引号和转义，不解为正文、不再次转义、不用SHA作正文。

实际outer frozen_json scalar只做一次顺序完整重放。最多保留一个8 KiB decoded片段，range结束后保留尾部，经过metadata量子后继续消费同一片段；未消费完不读下一片。输出结束仍排空真实原件到EOF；比较encoded/decoded字节数、完整decoded frozen SHA、actions/正文range完整数量，另一个量子比较expected projection SHA/bytecount与真实canonical_input decoded summary。

新增hash/decoder/pending/游标独立复制，actions保持只读共享并计arena。源码审查修正scope expiry固定128预留：正式plan允许finite int，现按实际bit_length十进制上界、float原格式预留，不改时间值或新加限制。两次工具/定位尝试在执行或写入前失败，未因这些失败写坏产品；实际最终源码compile、Linux实际导入和diff-check通过，静态审查未见剩余必修。尚未运行共享量子资源资格或完整业务验收。

本段结束停在historical_sources；描述符自洽不证明历史Graph Source/Access/correction/absence/权限原件，不替代request envelope/digest、签名、结果或settlement。后续各门保持HOLD，旧快照PASS不移植。


## Actual paid call envelope 和 formal request digest（2026-10-11）

从原ModelCallRequest wire分支抽取command_envelope_from_wire_v2，原exact fields、namespace/GraphVersion/AtomKey/Owner/query/VersionedRef构造、容器转换保持。helper自身plain roundtrip及原ModelCallRequest最后完整roundtrip都保留；不构造含占位payload的ModelCallRequest。codec沿原LF格式，CRLF引入的diff-check问题已修。

C09实际decoded envelope范围取得完整metadata，构造正式CommandEnvelope并对应job/activity/operation/worker fence、namespace、parent budget、access/delete epoch及selected依赖输入/reads。单条QueryEpoch必须是实际namespace的scope_ref=all；E_call来自其revision。producer在同一acquire commit回调中先存call original，后提交running job，因此它是pre-commit epoch，尚需实际worker attempt/pre_graph_epoch/event/运行job原件证明出处。原frozen window与call-time current guard两链保留，只按selected连接；不能把全部旧window reads强制验证在E_call current。

request digest沿正式plain根：purpose来自实际authority，template重命名，timeout转float，capabilities正式顺序；envelope typed、payload实际plain字节。单次actual request_json scalar完整replay复用有界projection cursor。ordinary DTO只在真实objectstart+1插tag；GraphVersion.key用真实对象range对应实际AtomKey DTO的特殊canonical token表示替换，不错误插普通AtomKey/Owner tags。实际source EOF/decoded SHA、两range、tag/replacement库存及正式digest比较完成后仍到historical_sources门。

构造器内部canonical outputs经既有meter_canonical_outputs逐次收费；input_refs canonical_digest另一个ASCII/UTF8副本按准确字节公式收费，key token三次实际结果计量。调用前预留按真实metadata构造编码结构计算，不重复DTO或序列化估算。修复原2L预算不足和AtomKey ensure_ascii=True下非ASCII双层转义计数：BMP/DEL/代理码点6/7，nonBMP12/14。两次静态必修意见均保留，最后确认关闭。实际source compile、Linux canonical import及diff-check通过，业务和运行资源资格未执行。

intent.complete只指已认证原件身份及自身投影对应，父metadata从未complete，不授付费/安装资格。完整历史Source/Access/correction/absence、acquire/schedule/queued job、quote/grant/reservation/permit/Authority、结果/settlement、detail parity与retirement继续HOLD。此次触及公共ModelCallRequest decoder，新独立快照必须完整D13复验；旧PASS不迁移。


## Actual paid acquire worker attempt 全行原件（2026-10-11）

新增具名facts getter固定graph_d13_worker_attempts_v2的真实12列/三TEXT主键，取9个小字段及完整Source member/ordinal/disposition。anchor/permit/receipt不点读整列；consumer逐8 KiB真实TEXT片段重建完整12列canonical tuple行域，三JSON列保留额外字符串转义，分别对Source old和独立target new commitment比较。derived_removed要求同键实际absence；原JSON均真实canonical EOF。成功acquire要求实际非NULL permit/receipt，缺失就具体HOLD，不从摘要造原件。

三个JSON身份字段再从实际Source分片重读，真实arena预留后解码，使用正式RestoreAnchor和FencePermitV2。匹配acquire operation/job+actor、worker request/job+intent+原timeout类型+privacy、attempt和finish公式、permit.write/attempt/pinned anchor/generation、真实job_id+call_original_digest receipt和pre_graph_epoch==E_call。permit.holder不冒用actor；pre_graph_revision不是epoch；尚未将业务job.operation_id误等于acquire operation。

静态发现四次新身份摘要只预留未实际计费，已统一私有metered digest入口：按真实quoted字段（含nonBMP）、集合语法和数字位长预留，单次serialize/ASCIIcopy实际len*2收费。固定4096和len*6预留撤除。最终compile、actual Linux import与diff-check通过，静态必修已关闭；业务、量子性能和安装资格未执行。

这里只证明worker旧Source/target原件及自身身份关系。Graph d13-paid event/event digest/epoch_reads、对应running job历史、真实Authority write fence/签名、selected Source历史权限及结算仍是后续独立门。不调用_d13_worker_replay_v2：该生产恢复可能finish active fence，不属于只读取证；本段未调用write/replay RPC。父metadata仍未complete，整体HOLD。


## Actual acquire Graph event 与 running history（2026-10-11）

worker/event只共享内部_D13PaidRowStreamV3机械层：真实Source/target全列流、canonical TEXT转义、metadata重读、独立copy/hash/arena和metered digest。两具名consumer的表、JSON列、WHERE和key均固定，不向调用者开放SQL/table/behavior flags。event独立身份逻辑，不继承worker身份条件。

Graph event取得真实完整Source member/disposition，四个JSON TEXT列均完整分片读并核10列row commitment，target独立同域或实际absence。invalidated只完成真实EOF及row域，不要求为空或新增长度上限。reads/revisions/epoch_reads实际重读后精确对照正式acquire的单条runtime.job读写和单条E_call epoch；event digest重建正式plain Event而非GraphCandidate，occurred_at来自同commit的实际learned_at（trusted_upper返回float），epoch_revision=E_call+1。

event revisions的唯一job正revision用于读取真实graph_history，valid和event四列外键必须精确指向该event。Source value完成canonical EOF后用正式RuntimeJobValue解码，running/fence1/cancel0/actor，以及保持不变的job/activity/业务operation/snapshot/continuation/budget/resource/deadline/operator字段与已有完成原件对应。job的业务operation不等于acquire operation。wake condition必须None、初始usage为实际metered canonical digest({})，不能同completed的最终usage比较；该静态遗漏已记录并修正。

运行job的time字段用实际PersistentJob._utc解析（允许合法offset和Unicode分隔符），请求deadline精确等于原job deadline/worker lease/binding expiry最小值，且晚于提交now；不固定lease duration。65536仅作为这条真实paid producer的充足消费上界（ID128 ASCII、UTC35、固定摘要/fence/cancel），不宣称RuntimeJobValue通用transport限制。真实history dependencies要求[]。

最终源码compile、actual Linux canonical import以及diff-check通过；静态必修关闭。业务与共享量子运行资格未执行。actual Authority write fence/签名、schedule/queued job、Source权限和结算等仍HOLD，父metadata未complete；不调用生产恢复或write RPC，不生成新快照、不复跑旧首次失败。


## Actual frozen Core paid acquire write fence（2026-10-11）

新具名cursor在真实worker/event/running完成后，只用same builder.pair.source的Core role。逐量子require_current连接实际signed capture_role_source_v2_core原件、role_source_digest/完整file SHA和schema root；不借Graph disposition、不要求未来Core fence表stream已sealed，不另开仅inode-check的basis连接作为来源。

固定authority_v2_fences十一列/主键，permit六身份、小列finished/pending NULL/finish id+digest与真实Graphworker原件全等。authority_id/namespace/installation_id/实际maintenance subject绑定已安装C09 factory；旧不同subject没有历史Grant原件就HOLD，不仅凭namespace冒认。实际Core authority_meta ID、namespace注册和last_epoch>=原fence epoch核验，不要求epoch相等。

permit真实BLOB分8 KiB完整读取，Graph实际ASCII permit_json长度作为同DTO Core UTF8字节上界，分别沿正式decode_bytes和canonical_bytes回验；Graph保存permit和旧pinned anchor全等。Core行承诺采用legacy table/columns/typed SQL cells/full BLOB hex域，不混Graph tuple域。BLOB副本、hex、canonical实际输出计费和预留保持原预算。旧RestoreAnchor.proof是authority_namespaces.anchor_nonce，不是数字签名；InstallationGrantV2是TLS认证身份DTO，不凭空查签名/Grant表。C09 signed role原件来自已安装control HMAC链，未读取/输出密钥。

首次自查纠正legacy._canonical实际返回bytes而非str（移除错误encode）；decode预留覆盖实际三输出，rowhex/copies也明确计费。静态审查无剩余功能必修，未使用blob_hash状态按clean-code要求已删除。最终compile、Linux实际canonical import和diff-check通过。未运行业务/量子资源资格，不调用服务构造/schema升级、liveget/validate/finish或worker replay RPC。

此完成只属历史finished write fence的冻结Core出处，不发行livepermit，不刷新授权。schedule/queued job、历史Source权限、模型结果/结算以及retirement/四角色安装仍HOLD；父metadata未complete。


## Actual queued create PersistentJob 原件（2026-10-11）

新增具名 runtime_job_operations create Source getter，固定七列及四 TEXT 主键。同一实际 Graph role 的完整 Source member、ordinal、disposition 为出处；consumer 全列分片重建原 TEXT 行 commitment，target 独立重读或 derived_removed 实际 absence。job_json 沿正式 _record_operation 的整份 MAX_JSON_BYTES=65536 上限，不把此界限移植到其他历史值。

actual paid call 持有同父 metadata 已完成的 actual intent 原件。完成 acquire/event/Core 历史 fence 后接 queued create；job JSON canonical ASCII EOF 后精确解码 PersistentJob 字段。queued/fence0/cancel0、无 lease/wake/result/effect、空 dict usage，sticky namespace/job/business operation/activity/snapshot/work kind/deadline/resource 与实际 completed RuntimeJobValue 对齐；budget_ref 映射 parent_budget_lease_ref，continuation 对已有独立摘要校验的历史原件全等，operator versions 单独核摘要。create digest 必须同 intent budget_reservation_digest，完整 typed PersistentJob digest 同 intent job_digest。

构造器 jobs._json 的 continuation/wake_condition/operator_versions 不走 runtime canonical meter，使用真实 Source parser 三字段范围收取 serializer 与 UTF8 副本实际字节。typed job 域是在 exact plain fields 上添加正式 PersistentJob root type；不能用 plain digest 或 JSON SHA 代替。首次粗倍率 size*6+2048 静态审查发现合法 50KiB job 永久超出 256KiB 量子，已修正为真实 constructor 字节预留，并把 constructor、typed digest、operator digest 分三个接续阶段；原 budget/profile 未放宽。

最终源码内存编译、Linux canonical 实际路径导入和 diff-check 通过；业务和资源资格未运行。此原件仅证明 queued create 与 intent、completed job 的出处关系，不恢复 job，不调用 create/acquire/worker replay RPC。schedule worker/event、历史 Source 权限、quote/grant/reservation/result/fact/settlement、retirement 和四角色安装仍 HOLD。未创建新快照，旧首次失败保持。


## Actual schedule input/worker/event/queued/Core 原件链及时间保留（2026-10-11）

新增 schedule_inputs 固定七列/三 TEXT 主键 Source getter，按实际 signed Source member/ordinal/disposition 验证 full Source/target row。payload_json 无整份 65536 限额，按 8 KiB 分片 canonical EOF 核实完整 plain payload_digest。实际六个 subtree 对应已采用 paid original 的 binding/ceiling/exact_count/decoded frozen、真实 queued create、历史 plain plan；真实 field SHA 和 byte ranges 比较，不以摘要字段造 body。scene_ref SQL 列对应真实 Scene AtomKey.owner.subject，不误用 token。

预调度 intent_digest 是 plain 根七字段 schema/plan/frozen/binding/exact_count/job/ceiling，不是 paid original.original_digest，也不是 asdict(schedule input) SHA。按 actual Source ranges 重放六个值，插入正式 nested DTO 类型标签及 schema literal；包括 Frozen/Window/Namespace/CompletedTurn/VersionedRef/Installation/Message/Plan/Binding/ExactCount/Job。job.continuation.plan 保持 plain；canonical_input/messages_wire/canonical_wire 保持原字符串。全部标签须从真实 object start 消费完毕；重放输出摘要同真实 intent_digest。完整 original plain Source EOF/hash 和 subtree parity 先行，未构造全量 frozen 文本副本。

具名 schedule worker 消费实际十二列 Source/target 全行，request digest 使用已证明的 typed schedule intent；原 attempt/finish 公式、Core permit、anchor、generation、job receipt 与正式 producer 全等。pre_graph_epoch 早于 acquire Ecall，不假设相邻 epoch。schedule/acquire 使用同内部 mechanical row/history/Core fence 校验，但各自具名 identity 和 origin，不调用 live recovery/get/validate/finish。

直接源码证据确认旧 schedule 仅保留 Event digest/CAS 列，没有那次 occurred_at 原件。worker 的 trusted_upper(clock) now 原先只是局部值，clock sample 本身也未持久化且包含提交时 elapsed；旧 frozen window、queued deadline、acquire learned_at 均不能替代。正式 producer 在同一 schedule transaction 内将既有 graph_bundle_operations receipt 改为 d13.paid_schedule.v2 四字段，保存 original_digest、同一 now 和 epoch.revision，compact ASCII finite JSON。未更改 request/retry digest、SQL DDL、budget/deadline。旧 v1 不补写、不重新规划；consumer 从真实 Source member读取版本后具体 HOLD：legacy schedule v1 lacks actual commit time original。

v2 bundle 完整 Source/target 行对照实际 worker/job。Event digest 用 receipt 实际 now 重建，event epoch 为真实 Epre+1；reads 完整 typed unique 库存，job 前置 read 与实际 event revision 对应，selected plan closure/scene/audience须被守卫，合法额外 reads 保留。不强等旧 window 的全部 readset，不固定 job revision=1。实际 graph_history valid/event FK/全 JSON EOF/空 dependencies 后，使用正式 job_value(actual queued PersistentJob) 全等验证。

具名 schedule Core fence 与 acquire 共用同严格 frozen Core source/subject/installation/authority、完整 permit BLOB/finished/null pending/finish/legacy row domain 证明；各自绑定实际 worker/event，不能冒用 acquire fence。父 metadata 仍未 complete；历史 Source 权限及模型 quote/grant/reservation/result/fact/settlement 后续门仍 HOLD。

两处静态计量遗漏已修正：AtomKey.from_token 内部重算 canonical token 输出按真实长度预留/收费；实际 tags.items/sorted/tuple 分配前按库存预留 arena。reads 用预留后的线性 dict，避免重复列表扫描。job_value serializer 由正式 meter context收费，三 UTF8 digest副本按真实 constructor ranges/2-2 收费。曾将 writer 行尾误转 CRLF，diff-check 捕获整文件格式问题后恢复原 LF；内容修改保持最小。

现有永久 test_installed_d13_paid_v1.py 在 standby saved_state 和 expired refusal 后 residual 新增 schedule 原件断言，读取真实 bundle/input/worker/create/event/history，并使用正式 restore intent/Event.digest/job_value 验证；不在执行前增加准备延迟，不新增临时测试或 fixture。最终产品与永久测试内存编译、实际 Linux canonical import及 diff-check通过，Astra high只读审查无剩余mustfix；本轮业务节点未执行、资源资格未验证、新快照未创建。此正式 schedule path改变要求新快照完整 D13 standby/cold/replay/expired复验，旧PASS不移植。


## Paid selected context 双 epoch 与大历史行分片（2026-10-11）

直接源码显示 require_historical_graph_reference_v3->_graph_disposition_key_v3 对目标整行 point.read_row；positive epoch 还会对大 head/successor/history/event 整行核承诺。合法 memory.source 即使已迁移为分段 cell，旧 point 读取仍可能永久超过原256KiB reservation。本轮新具名时点 locator 只读四个固定表的小字段、实际 Source schema和引用/epoch；没有提前证明target或输出完整授权。每个Source member/disposition另一个量子取证，不在一次getter内累积多个大cold member读取。

Source/Access/completion正引用检查 born<=E、历史valid1、冻结epoch/head及直接R+1 successor；successor有则E<successorBorn，无则head=R。correction0只接受真正没有Source history/head，或者实际首revision1的birth在E之后。无效或target删除不能冒充历史缺席。关联行列表全部完成前不前进到下一ref。

完整行cursor逐8KiB重建Source old tuple承诺和独立target new tuple承诺，所有value/dependencies/event JSON大列分片并完成Source canonical EOF。target读取实际shape及其全部列，逻辑PK合同保持；允许已注册value->value_cell_id迁移，不将worker的source/target同shape断言套在通用Graph行。derived_removed核实际target同键absence。并未靠sidecar sweep省略target本行承诺。

仅指定history(reference,R)的Source/Access value接现有正式语义parser。Source文本hash置于row cursor并独立copy，不塞进parser deepcopy状态；head/successor不会作为选中Source语义，target不feed该Source parser。实际Source全文与adopted frozen selected turn的scalar完整hash/byte length、speaker、source_id对应；Source/Access都要求context和conversation audience，Access active且source_id对应。没有用frozen文本构造替代SourceRecord。

每个selected turn的Source/Access/completion/correction0分别消费E_schedule和E_call，inventory来自真实schedule event reads与实际request.version_guard.read_versions；逐item取token并收费，不一次编码整个库存。不是event的E+1，也不是当前C09冻结epoch。call inventory最初误用了不存在的envelope.guard；静态审查捕获AttributeError后改为version_guard，并在实际Linux运行时核对正式字段。

这一片仍不是完整Source授权：方向需实际D09 slot/completion及inbound/outbound原件链，inbound额外Access expression/无parents/reported身份/Source72h，outbound祖先context/active/无环/distinct128及其真实readset，Owner/activation/scene/audience历史唯一性仍待接齐。未从source_kind或ID前缀推方向，没有给outbound祖先套72h，也没有把所有Source统一要求expression。外层明确HOLD这些门和结算，metadata未complete。

最终内存编译、actual Linux canonical import和diff-check通过；静态指定片除字段错误外无另一个mustfix，修复后导入验证字段真实存在。业务/量子运行资格未执行、新快照未创建。旧Root专用epoch point消费者尚待切换，不宣称整个C09大行恢复已闭合。没有调用paid服务、live恢复RPC、直接SQL修账或重跑旧首次失败。


## Actual D09 direction/slot 与 outbound 128 DFS（2026-10-11）

Context reader 顺序调整为真实 completion→Source→Access→slot→correction0。新具名D09 scalar metadata parser读取实际history.value的全部canonical EOF及精确字段；copy共享实际arena，并支持base copy的无arena构造中转，不在deepcopy塞hash。该value仍属于完整Source/独立target行承诺的一部分。时点locator的closed scene families明确加入正式turn_slot，不开放任意Graph type。

completion通过正式validate_turn_completion_v1，Source/Access/slot token比对实际frozen anchor，speaker/time/工具闭合状态对应已采用selected turn；scene参数使用真实role-binding key的subject，派生正式turn_completion/slot keys。payload.version与有效Graphrevision均1，防止仅validator(version>0)放行非producer版本。slot方向/scene/conversation/seq对应completion，并通过正式validator及origin type限制。

保存真实history Event FK而不拿completion时间重算Event digest。inbound要求slot/completion同一完整FK，session d13-inbound-turn；outbound completion属于d13-outbound-observation，但slot允许更早P2预留，不强加同事件。实际inbound/outbound seal/ingress/C02/batch/outbox/observation链仍单独待完成。

使用schedule bundle实际now和call实际learned_at分别做selected turn 0<=t-trusted<72h。inbound Source recorded_at==completion.trusted_utc、reported/reported、无parents、audiences精确conversation，Source72h窗口；Access另外保留正式reply-route expression。outbound root要求正式authored身份；不强加Source recorded/occurred与completion时间等式，允许先前unknown/accepted观察建Source、delivered时复用。

outbound真实Source parents接DFS，root包括在distinct128中，active检测环、seen去重共享已完成祖先。每个ancestor按对应epoch实际inventory取Source/Access正revision与correction0，沿同完整时点Source/target行证明，context/conversation/active Access逐个验证。没有给祖先套root文本/speaker/kind或72h；没有靠ID前缀/Sourcekind推方向。root五原件与ancestor三原件计数分离，状态copy的pending/active/seen独立，临时库存预留原arena。

静态必修：completion key派生最初len*12*6粗预留会永久误拒合法4096 ASCII conversation，已改为精确quoted长度、两次serializer+两次UTF8copy和固定hash-key token界限。formal validator内部AtomKey回编码、key函数conversation摘要与实际token生成均计费。没有另一次JSONserialize仅用来估长度，没有扩大原256KiB上限。静态公式review关闭mustfix。

最终Source内存compile、Linux actual canonical import及diff-check通过；业务/量子运行资格未执行、新snapshot未创建。外层HOLD准确更新为inbound/outbound original seals、Owner权限与结算未完成，metadata未complete；这不是完整C09或alpha2验收。不调用paid服务/sender，不直接SQL修账，不修改旧失败DB或重跑旧snapshot。


## Actual inbound seal/frozen Core 与 outbound adoption row（2026-10-11）

root五类历史ref完成后新增seal阶段。inbound getter固定graph_d13_inbound_turn_attempts_v1真实12列/三TEXT主键，以actualcompletion FK ingress operation定位完整Source member/disposition。consumer逐片完成三JSON及全Source/target行，真实anchor/permit/九字段D13InboundTurnReceiptV1重读解码。receipt类无post_init，因此exact fields和sequence/graph revision/epoch int均显式对照。namespace+ingress的全64 attempt公式、finish_d13_inbound_turn公式、正式order key、pre graph revision/epoch+1和实际completion birth epoch相互绑定。

历史inbound permit generation仅等于其真实saved RestoreAnchor.activation_generation，不误要求等于后来paid call generation；正式current window允许旧turn跨后续activation历史。turn_anchor与Core RestoreAnchor分开字段，冻结Core consumer选择actual inbound worker，复用同严格role origin/subject/namespace/installation、完整permit BLOB、finished/pending/finish/旧行域证明。不调用finish_saved/replay/current fenceRPC，不发行新permit。

inbound order key的实际conversation canonical serializer用正式meter context；真实UTF8副本和actual token另外收费，quoted长度预留。root进入seal→seal_fence后才next turn，private ingress/C02/arrival/Owner原件仍待完成，不将worker receipt当完整来源授权。

outbound getter从已证明completion的slot/evidence定位实际唯一graph_d13_outbound_observations_v1，固定十列/四TEXT主键，实际count bounded query拒绝歧义；不仅凭先取一行。完整Source/target行承诺与observation_json/original_json canonical EOF都消费。plain original_json SHA同saved original_digest，exact十一字段d13.outbound_adoption.v1，source/slot/batch/evidence/event operation与pre_epoch+1=completion birth对应，只用其中真正Graph adoption write permit，不混pending里的dispatch permit。

outbound停在明确observation_identity HOLD：typed MutationReceiptV2、durable committed observed delivered、真实Core dispatch、batch/outbox、Graph receipt、private origin链未证明，不将accepted/unknown或存在Graph行当成功；complete仍false。下一步需沿正式from_wire和runtime typed digest消费observation，并独立绑定两种permit原件。

最终内存compile、actual Linux canonical import、diff-check和Astra high局部只读审查通过；实际RestoreAnchor.activation_generation字段已在Linux确认。业务及原资源运行资格未执行、新snapshot未创建。旧失败DB/日志/snapshot保留，没有paid/sender或SQL修账/生产恢复调用；全系统、Contact/C09、D04与独立productionHost仍HOLD。

### 2026-10-11 出站实际 delivered DTO 与冻结 adoption Core fence 增量

完整 observation_json 经过原 Source/target row 承诺及 canonical EOF 后，沿正式 v2_contract.from_wire 重建 MutationReceiptV2。显式要求 durable committed、pending observed、PlatformObservationV2 delivered，操作 ID、Authority namespace、graph namespace 和 UTC observation timestamp 对齐实际 completion。保留实际 slot origin 供下一步 outbox 原件读取，未以模拟字段替代。

正式解码器内部 first observation 的前驱摘要是 Authority wire 域（ensure_ascii=False UTF8，sha256: 前缀），实际 observation digest 是 runtime typed DTO 域，分别核验。编码预留上界与实际费用分开，逐次包含 footprint spaced decode、compact roundtrip/hash、V1 account/destination JSON 回验及 claim wire/hash费用；完整 typed digest和adoption operation/finish公式各自在独立阶段计算。未扩大原资源预算，未增加新时钟或延长期限。

finished Core write fence 证明提取四个精确来源访问方法，原 acquire/schedule/inbound默认行为保留；outbound选择真实adoption operation、finish和permit pinned anchor。读取实际签名Core role origin、固定authority_v2_fences行、全permit BLOB、finished/pending/finish、Authority/namespace/epoch，不申请新permit或回放生产操作。

当前停在 dispatch_originals HOLD：独立dispatch mutation/journal、batch/outbox、Graph receipt和原来源授权仍需完成；本增量不能视为完整出站成功。最终编译及实际Linux canonical导入已执行，业务永久节点尚未执行，未冻结新快照。共享读取路径改动需纳入必要回归；未来新快照仍须完整D13 standby/cold/replay/expired复验。

### 2026-10-11 冻结 Core 三阶段 dispatch mutation 原件增量

出站 actual delivered observation 之后，独立读取 authority_v2_mutations 的完整十三列物理模式；生产 mutation_locked 返回去除 mutation_id 的十二列，未混用其索引。沿已经正式解码的嵌套 prepare/claim/observed receipt 与 exact wire，顺序定位三份真实 mutation ID。每阶段核 operation、namespace、subject、request、committed、execution 与 deletion_evidence NULL，并逐片完整比对 pending、receipt、updated_permit、footprint 四份 BLOB。UTF8 wire 与 footprint 默认ASCII编码域保持分开，先预留再产生期望编码。

conflict_keys_from_footprint 内部六类原始tuple的 JSON 文本/UTF8副本均计量，含重复tuple去重前成本；最终keys JSON单独核对。footprint namespace/effect/permit摘要和每阶段request材料的固定 phase=prepared字面值均验证。journal expected append摘要仅移除实际pending wire顶层expected_append_digest，保留所有嵌套字段，核实际journal_id、seq、previous_digest和完整wire材料。

本增量没有产出legacy全行row commitment，也没有证明实际journal行、observed predecessor、handoff starts/graph receipts。三个Core mutation原件均完成后仍进入明确dispatch_predecessors HOLD，batch/outbox/Graph receipt及原始来源授权未验证，不能认定完整出站历史链通过。未运行临时测试或业务永久节点、未调用RPC/模型/sender、未改账或重跑旧失败；编译和actual Linux导入证据独立记录，新快照未创建。

### 2026-10-11 actual execution journal 与 observed predecessor 增量

每个prepare/claim/observed以及实际predecessor mutation在正式append摘要核验后，选择真实execution role pair，检查same session/scope/current、control签名完整Source原件，以及complete facts old_journal_id。journal固定七列和seq INTEGER主键；实际六small分别匹配seq、mutation、request、append、previous、chain，按实际seq逐片完整消费pending BLOB并比对正式UTF8 wire。真实raw EOF SHA后通过require_execution_journal_stream_v3匹配既有_journal_commitment小tuple域和完整封存恢复索引，限定1..old_seq；不要求历史行仍是tail，不重扫整链或重组大BLOB调用旧point helper。

predecessor按真实predecessor_mutation_id独立读Core receipt BLOB至EOF，正式from_wire重建并纳入arena。全原BLOB必须等于canonical UTF8 wire，sha256:摘要、mutation/operation/effect、updated permit、after anchor与当前pending对应。claim前驱必须等于已证明claimed原件；非claim前驱必须是observed且同一claimed receipt，支持早期unknown，不擅自当作claim。实际predecessor reader直接传给共享mutation reader，避免immutable parent旧child指针；再完整核Core行、四BLOB、footprint/request、append digest与actual journal。

上述源码编译及actual Linux canonical import通过，局部Astra high只读审查无mustfix。完整业务节点和资源运行资格仍未执行，没有新snapshot。剩余handoff starts/graph receipts、batch/outbox/Graph receipt、legacy rowcommit、入站private identity/C02、授权结算、retirement/four-role cold recovery、Numeric及全39交付继续HOLD；没有模型/sender/生产RPC/SQL修账或旧失败重跑。

### 2026-10-11 actual Core handoff 两表与安装issuer增量

从完整Core/journal/前驱证明后独立读取authority_execution_handoff_starts_v1八列真实start。按实际handoff_id核operation、namespace、subject、claim wire digest、binding wire digest和graph_claim_ref，完整permit BLOB逐片对比claim提交后updated permit。claim/binding/context分别采用Authority UTF8 canonical wire摘要域，各阶段先预留、后按实际输出收费。再读取authority_execution_handoff_graph_receipts_v1三列，完整Graph receipt BLOB EOF、正式from_wire DTO、完整canonical相等、context/ref/namespace/incarnation核验。fresh start十个正式wire字段，包括replay=False、原permit、实际graph receipt，摘要必须等于实际delivered observation.start_digest。

issuer独立取维护实例直接绑定的daemon原AuthorityDeploymentConfig，核InstalledC09MaintenanceFactoryV1、factory自身namespace/peer对应installation、namespace binding、maintenance mTLS subject，以及配置reverse_handoff_issuers当前namespace映射。缺失实际配置或旧issuer轮换不匹配保持specific HOLD，不能新造config或凭DTO自声明补证明。

首次静态审查发现reverse profile与maintenance peer强等式不受生产合同支持，已移除。正式deploymentconfig允许reverse profile绑定该namespace的另一已安装peer；保留factory自身身份与实际issuer配置检查，不额外要求reverse profile相等。修正前后源码哈希和最终compile/import审查独立记录。

当前进入batch_originals HOLD，实际历史Graph claim的Source/disposition与birth event、batch/outbox、adoption Graph receipt和legacy row commitment仍未闭合。本增量是源码验证，不是完整handoff或业务永久节点验收；原预算/期限/身份边界和旧失败记录保留，新snapshot未创建，没有模型/sender/RPC回放或SQL修账。

### 2026-10-11 historical Graph dispatch claim 实际原件增量

新增独立read_d13_dispatch_claim_epoch_locator_v3正式入口，只接受dispatch_claim_key(namespace,effect)的immutable revision1；与原context locator复用private时间定位，不扩大原context的Source/Access/slot/completion/correction家族。persona owner的subject=None在dispatch分支先处理，不传给Source key合同。内部locator注解允许该实际None值。

_D13OutboundGraphClaimReadV3在actualCorehandoff与installedissuer完成后定位真实claim。完整Source/disposition与独立target行域证明复用既有rowstream；实际graph_history claim值由严格全scalar字段parser保存，graph_events、head和epoch等定位原件也完整消费。actualhistory birth tuple等于namespace/activity/dispatch-claim:effect，revision1、head1、graph:1与receiptepoch对应，且claimbirth严格早于completionbirth。

正式DispatchGraphClaimValueV1构造及namespace隐藏编码收费，actualclaim namespace先匹配再构造。逐项与Core原claim/handoff的operation/activity/effect/admission/incarnation/namespace/permit fence/revision/executionhead/context/binding/claimedreceipt对应；P2permit采用Authority wire摘要，actualclaim plain dict采用runtime摘要并匹配Coregraphreceipt。ownerwitness/currentevidence保存真实claim字段并受完整行与receiptdigest绑定，但独立授权原件尚未重验，不将这些摘要当作已验授权。

首次静态审查修正cursor新reference/locator的arena漏计，以及actualnamespace不同但按expectednamespace计费；最终源码compile/actualLinuxcanonicalimport和只读审查独立记录。仍进入batch_outbox_originals HOLD，batch/outbox/adoptionGraphreceipt、legacyrowcommit、入站授权、结算、冷恢复、Numeric和全39尚未闭合，业务永久节点未跑、新snapshot未创建、原预算期限身份与旧失败记录保留。

### 2026-10-11 guarded historical runtime outbox 原件增量

actual outbound cursor保存原schedule或call context epoch及实际guard inventory。只从已验证slot.origin_ref定位outbox，revision必须是该epoch guard中的正版本；新增独立read_d13_outbox_epoch_locator_v3入口只接受正式activity-owned runtime_outbox_key，不扩大context或immutableclaim入口。完整Source/disposition与独立target历史行消费复用既有rowstream，严格scalar metadata字段采用RuntimeOutboxValue正式字段集。

actual namespace/activity/operation/effect、delivered phase、dispatch generation对齐实际observation origin；按正式DTO构造检查并计内部job token正规编码，显式job token检查再收费，核job owner namespace/activity与job_id/name；最后formal runtime_outbox_key必须等原slot origin。idempotency_key与实际origin.footprint.external_idempotency_ref相等（natural_dispatch_admission_v2 299–302正式绑定，observation仅替换phase保留key）。

schedule与call可以各用不同guardedrevision，locator分别证明当时currentness，不用后来head代替。laterrevision birth不强等completionbirth；adoption当次版本的同event关系留给真实adoptionGraphReceipt证明。payload_ref对完整batchposition、原job预算/finalbundle仍未闭合，父cursor停在batch_value_original HOLD。v3batch后续必须流式接完整semanticmanifest/wholeoutput/selectedsegment，不能降成v2解析或为重复整JSON编码扩大256KiB单批预算。

最终内存compile、actualLinuxcanonicalimport与局部Astrahigh只读审查独立记录；业务永久节点/资源运行资格未执行、新snapshot未创建。全39、Numeric、Contact/C09、D04和productionHost独立身份仍按实际证据HOLD；没有paid/sender/生产RPC/SQL修账或旧失败重跑。

### 2026-10-11 完整natural batch root/ID/digest/body分片增量

新增独立read_d13_natural_batch_epoch_locator_v3入口，只接受正式activity owner、V2/V3自然batch key和immutable revision1。actualbatch引用来自真实adoption row，revision必须在原context epoch的guard inventory中；完整Source/disposition与独立target行证明完成后才使用实际history parser。原context入口权限家族不变。

_D13NaturalBatchJSONStreamV3完整消费canonical EOF，严格核V2/V3根字段集合、schema/version和正式producer的对象/数组/标量结构。只保留根scalar元数据、根字段完整范围以及segment.body canonical SHA/长度/decoded非空白状态，不缓存大正文或wholebatchdict。body摘要/长度与此前actualSource验证过的selectedfrozen turn text对应，scope/activity/operation/effect/scene/audience/id/type和qualification身份核对。

同一root field-range遍历建立两个正式plain JSON摘要：batch_digest只排根batch_digest；batch_id同时排根batch_id和batch_digest，分别采用V2natural-verified-batch和V3natural-semantic-batch前缀。两个域独立comma计数，V3完整semantic_manifest范围纳入二者，不删除嵌套同名字段。实际SQL重读总长度等完整parser.byte_count，逐片读与输出计量，未扩大原256KiB单quantum预算。

最终compile、actualLinuxcanonicalimport和Astrahigh局部只读审查独立记录。本层complete仅指完整原件/root身份/body等价；parent停在batch_payload_original HOLD，正式claims/排序uses/payload以及V3wholeoutput/逐segmentunit/selectedmanifest语义仍未完成，不把root通过冒充完整validator。jobbudget/adoptionreceipt、授权结算、冷恢复、Numeric、全39和独立生产Host继续HOLD；未运行业务永久节点、新snapshot未创建、旧失败/预算/期限/身份保留、没有paid/sender/RPC回放或SQL修账。

### 2026-10-11 actual segment payload/uses/ref 增量

完整batch parser扩严格八字段segment结构和其实际nestedranges，所有字段原canonical EOF已包含在Source/target行、rootID/digest中。payload cursor分别逐片读取claim_uses、media_refs、position、payload_digest、segment_id、effect_id小字段，JSON解码保留在原arena中，不读取整body为字符串。逐项exact四字段ClaimUse+ClaimKind构造后按(start,end)稳定排序，同span原顺序不改、不去重。

正式plain payload摘要按body→claim_uses→media_refs空列表顺序构造：body实际canonical范围逐片喂入，每个排序后的plain use dict独立编码/计量，带正确逗号和完整EOF。payload_digest等实际origin.payload_digest（仅去正式sha256:前缀），segment/effect/position0/media空匹配实际dispatch origin/footprint。outbox.payload_ref按已经实际formal batch key证明的type/ref/index重建正式d09-natural摘要，不调用helper、没有虚构重复token解析费用。

正式ClaimUse及payload_digest层不证明end<=decoded正文字符数、无重叠/全覆盖、claimtext/来源/eligibility或V3manifest关系。代码保留原uses并明确parent batch_claim_originals HOLD，这些后续必须逐项补齐；字符索引需Python str codepoint语义、代理对合并，不能用canonical或UTF8字节。最终compile/actualLinuxcanonicalimport和局部Astrahigh源码审查独立记录。业务永久节点/原资源资格尚未执行，新snapshot未创建，原预算期限身份/旧失败记录保留，未调用paid/sender/生产RPC或SQL修账。

### 2026-10-11 actual claims 与 Python正文切片增量

完整batchparser记录所有实际claim item和七字段ranges，严格字段/结构检查。每个object_start即登记空集合，空claim也必须通过完整七字段检查，不能因没有key被跳过。claims必须非空。actual current_reads按正式VersionedRef解码并拒绝重复token（包括不同revision同ref），没有强制全正版本或将source_refs收窄为memory.source，qualification fallback仍按原合同允许。

claimreader逐claim读取除text外metadata，沿正式ClaimKind/_nonempty/_names校验unique ID、disclosure、source refs、audiences与expression eligibility；每claim source refs覆盖actualbatchcurrentreads、当前batchaudience在其allowed audiences中。文本单独完整canonicalstring流式解码，检查非空白，仅保存无损fixed4byte big-endian codepoint域SHA和Python字符数，不用placeholder文本构造ExpressionClaim。

_D13ClaimCodepointStreamV3合法surrogatepair合一，孤立surrogate保留同内部无损域，跨片与EOF状态复制。body每个唯一span逐片完整扫描，按原Python body[start:end]截断语义只对窗口内codepoints计算摘要和长度，核实际claim文本/kind。正式合同并没有强制end<=bodylen、无重叠或全覆盖，本层不添加这些强限制；V3units更强边界后续独立核验。相同span只有完整EOF+相等后缓存，copy独立dict且计arena，reuse仍先核claim/kind再比hash/count，不跨body来源或跳检查。

首次静态审查修正空claim遗漏、重复currentreads静默去重；最终compile/actualLinuxcanonicalimport及Astrahigh局部审查独立记录。本层完成后parent停在batch_manifest_original HOLD，独立expression来源授权、V3manifest、jobbudget、adoptionreceipt未闭合。业务永久节点/资源资格未执行，新snapshot未创建；全39/Numeric/Contact/C09/D04/独立Host仍HOLD，预算期限身份/旧失败保留，没有paid/sender/生产RPC或SQL修账。

### 2026-10-11 V3 actual manifest/wholeoutput/selectedpart身份增量

完整batchparser记录V3 manifest六字段、generation output四字段及各part九字段actualranges/结构。part object_start即登记空集合，parts数量按正式MAX_SEMANTIC_SEGMENTS_V3=4限制且非空；完整canonical EOF字段核验，不缓存whole output或body。V2没有manifest，不造占位对象，仅完成该子层后进入独立后续授权/语义门。

manifestreader逐片读取actual paidreview/header，formalVersionedRef plan；完整generation_output actualcanonical范围SHA匹配paid_review.generation_output_digest。每part身份摘要使用typedVersionedRef、一次已核outputdigest和index，索引0使用root_operation/effect，其余按正式natural-segment派生，全部segmentid同公式、position等index、media空。rootIDs属于原第0泡，不硬等当前非零selectedchild origin；与实际原plan的更深来源绑定未冒称已验。

selectedoperation等actualbatchoperation；selectedpart七个其他内容字段（effect/segment/body/uses/payload/slots/media）逐片原canonical长度+SHA对应actualbatchsegment，位置差异按正式part index→rootposition0处理。所有字段及V3完整manifest原件已在Source/target/root摘要域里消费，typed摘要/实际输出计量保持原预算。

最终compile/actualLinuxcanonicalimport与Astrahigh首片静态审查独立记录。semantic_segments数量/分区与parts对应、units/Markdown不截断、每partclaims/payload及wholeoutput与实际paidjobs签名来源仍待完成，parent batch_semantic_originals明确HOLD。独立sourceexpression授权/jobbudget/adoptionreceipt/冷恢复/Numeric/全39未闭合，业务永久节点未跑、新snapshot未创建、旧失败/预算/期限/身份保留，没有paid/sender/RPC回放或SQL修账。

### 2026-10-11 actual V3 semantic partition/Markdown/part bodies增量

沿正式生产mechanically_verify_natural_reply_v2既有body1..2048 codepoints、units1..16上限（policy仅更严不能放大），先从实际generation_output bodycanonical范围流式完整EOF计Python字符，再只解码已经有界的该正文。解码len必须同计数，核原控制字符规则（ord<32仅允许换行/Tab）与semantic_segments1..4。不是宣称较宽TypeSpec本身拥有这些上限；超大结构合法原件仍specific production-mechanical-bound HOLD，不放宽数字。

直接复用纯natural_semantic_ranges_v3实际正文/units/segments，保留原Python分区、完整覆盖、非空段、qualifiedunit边界、fencedcode及Markdown列表不截断规则，不另造扫描器或做整JSON编码。正式ranges数量等actualmanifestparts，逐part actualbody范围先限定生产2048canonical最大长度、完整JSON读取后等真正outputbody slice。Source/target/root/output身份已由前层完整原件证明，schema使用前manifest actualheader核过的值。

最终compile/actualLinuxcanonicalimport与Astrahigh局部静态审查独立记录。V2该V3子层N/A完成，不代表V2paid输出上下界或授权；parent manifest_part_claims HOLD，每part units/claims/payload/slots以及actualplan/basis/policy/paidjob、Source权限还须独立闭合。业务永久节点/资源资格未执行、新snapshot未创建，全部alpha2/全39/Numeric/Contact/C09/D04/独立Host验收仍HOLD，预算期限身份和旧失败保留，没有paid/sender/生产RPC或SQL修账。

### 2026-10-11 每part单位/claims/payload及共同paidreview结构增量

wholeoutput units使用实际原全局index、basis原顺序重建natural-unit ID，正式七字段/type、ordered cursor coverage及空白gap/tail、basis/slot字符串unique、kind/speechact检查；按当前生产窄规则拒绝promise或非None promise grant，不为已有grant自动开放promise。originalplan的basis/slot/act membership与expiry还须实际原件，未冒称已经通过。

每part从实际范围读取claim_uses、covered_slots、payload_digest，按wholeunits原顺序筛选并平移start/end生成expectedClaimUse，实际tuple必须精确相等，slots等sortedunion。正文来源前层已actualpart验证的output正式slice，各use fixed4byte codepoint SHA/字符数/kind连真实qualifiedclaimtext。正式segment_payload_digest在已2048body/16units bounds下调用，预留2*upper、serializer hook收文本实际量、meter encoded增量再补同量UTF8副本，不再重编码测长、不以上界作实际账。

V2/V3共同paidreview reader核三个root digest的正式str/len64条件，完整actualpaidreview范围EOF后解码exact_PAID_FIELDS+receipt_digest，generation/review operation、call、reservation三对身份各不同。保留真实Originalvalue供随后paidjob读取，不以这些结构条件代替签名作业授权。V2每partV3子层N/A，但仍经过共同paidreview结构门。

最终compile/actualLinuxcanonicalimport和Astrahigh局部审查独立记录；parent batch_paid_job_originals HOLD，actualplan/basis/policy/paidjobs/rights/budget/adoptionreceipt、结算冷恢复、Numeric与全39安装交付未闭合。业务永久节点/资源资格尚未执行，新snapshot未创建；原预算期限身份/旧失败保留，没有paid/sender/生产RPC回放或SQL修账。

### 2026-10-11 actual natural generation/review preparation 首层增量

新增封闭generation/review Source getter，从actualbatchpaidreview original_operation_id及实际namespace唯一定位13small，再以真正parent_original_id的正式PK读完整Source/disposition。两张准备表18列、5大JSON（seal/frozen/readversions/queryepochs/typedrequestwire）按真实ASCII canonical EOF及完整Sourceold/Targetnew行域逐片消费，不wholeget或重新prepare。当前target两表仍原18列（segmented ref DDL只改graph_atoms/history.value）；严格same schema，实际derived_removed则证明target行缺失。

actualstate须terminal、workerfence exact正int、三epoch exact非负、request/terminal/output三字段非NULL且对齐paidreview对应值。首次静态审查确认不能仅靠两边NULL相等，已显式拒绝并保留修正记录。job/origin/call/reservation四身份从真实parent、namespace tuple和stage的正式plain域SHA前48计算；不误用typedNamespaceId、不把frozenwireSHA当typedModelCallRequestdigest。gen/review真正parent必须一致，completed实际reader保存独立字典供后续seal深读，每reader仍自身arena注册。

最终compile/actualLinuxcanonicalimport和Astrahigh局部源码审查独立记录。parent natural_seal_originals HOLD：actualacquire/seal/frozen/request/job/Coreterminal/结算/planrights未闭合，preparation terminal不等于已验执行或付款。业务永久节点/原资源资格未执行，新snapshot未创建，全39/Numeric/Contact/C09/D04/独立Host验收仍HOLD；预算期限身份与旧失败保留，没有paid/sender/生产RPC回放或SQL修账。


### 2026-10-11 actual natural seals/guard 与正式 V7 公共入口

正式 seal reader 读取两阶段真实完整 preparation Source 后再次逐片读取 seal/read/query 原件；正式 _seal exact class、namespace 与全部 DTO 字段匹配，acquire/job/origin/call/reservation 使用实际 parent/stage 公式。generation/review 版本、input/output/basis/policy/lease 相互匹配，installation_id 保留实际模型安装身份，不能随意等同 C09 storage installation。reads/queries 非空、exact shape、namespace/scope/duplicate 检查后，按正式 sorted pair 与 typed NamespaceId 根域逐片计算历史 guard。原 meter/arena 限制保留，不误等同 paid current guard。最终 actual Linux canonical import 与 Astra high exact Core 静态审查通过；业务资格仍未执行，parent frozen/request/job/terminal/settlement/rights HOLD。

实际正式 V7 review freeze/parse、issuer、current generation-output dispatcher 和共享语义输出解析遗漏已按原契约修复。新增永久回归保存首次 RED，最终33项通过；新增 issuer unknown subclass/cancelled 状态零 quotes/reservation/jobs 拒绝及有效对照2项通过。V6初次 issuer fixture在真实save后读取review时被测试替身误挡，已只替代generation、review委托真实读取；原日志保留，不计为生产根因。模型tests是明确 software inventory seam；issuer unit budget/original boundary是明确 seam，实际SQLite job/reservation/save/read未代换，不冒称安装授权或付费执行。真实 SDK MockTransport 只本地有限调用。

上述 V7 bugs 与 Numeric40首次 finish gate timeout、41单次 SIGSEGV 独立，不混作根因；当前共享 public path 变更要求新快照独立完整 D13/V7 安装复验，旧PASS不可移植。尚未冻结新快照，整体 all39/alpha2/Contact-C09/D04/生产独立Host HOLD，旧失败/DB/日志原件、原native hash、预算期限及身份边界保留。


### 2026-10-11 actual frozen typed roots / provider messages / stable prefix

两阶段 preparation 完整 Source 行证明后，actual frozen_json 直接逐1024字节读全列，并每片核真实Source table/PK/column/总长/当前Graph fence。独立frozen root按正式V2–V7 DTO field profile校验；V2无schema，V5实际Input/Frozen类型仍V4。共享typed commitment分离subtree prefix与input路径坐标，旧draft默认V7坐标不变；input和units完整typed摘要包含正式namespace/ref/DTO $type，Enum仍plain value，V5 tag仍V4，null ref不插tag。review actual canonical_input/wire字符串解码为原ASCII字节并核完整SHA。两阶段实际frozen installation、input/output/basis/policy等连接真正seal，未替代外部Authority grant。

provider/message独立层从actualfrozen根ranges重读，原messages数组或真实nestedstring decode到封闭inner codec。provider四字段exact，max_output exactint，不接受float/bool等价。gen三条system/user/user、review两条system/user，全部连续index、exact role/content字符串和完整EOF；outer/inner每contentSHA相等，provider/model/maxoutput等actualfrozen installation。system按真实version，V5选V5常量；review.userSHA等真正canonical_input SHA。每片decoder pending立即drain，保留copy及原arena。

generation正式stableprefix范围由innerwire第2条完整message exclusive object_end.end+12字节第三content语法获得，不信自报长度。actual stable_prefix_wire decoded计数/全SHA与真实wire前缀对照；前缀读到正式count后停止，不对尚未读完nestedstring调用finish，依赖已经完成的Source/fullwire EOF。正式prefixdigest保留V2六字段flat vsV3–7typed installation域以及V5 template。实际bytes输出/末片slice/serializer输出分别收费，预检upper保持原预算。

首次静态审查记录并修正newparser mandatory profile与basecopy不兼容、累积JSON decode前arena缺失，以及已有sharedtyped标签ASCIIencode/slice漏计；原失败hash与修复记收据。当前实际Linux canonical import及Astra high最终783094B/27bccaa2源码审查通过，Python格式trailing0/bareLF0。未做临时过渡测试，业务永久链与2CPU/2GB原25ms/256KiB/8MiB运行资格尚未执行。

parent仍natural_frozen_projection HOLD：gen stable/dynamic+V7semantic完整投影、review basis/body/qualified units/grants/output/policy正式refreeze关系、真实安装modelgrant/typedrequest/runtimejob/Coreadmission/observation/terminal/reserve-settle及Source/Owner/plan权限都须继续实际原件闭合。当前内容自洽不能冒称授权/执行/付款。未冻结新snapshot，全39/alpha2/Numeric/Contact-C09/D04/生产独立Host仍HOLD，旧快照及首次失败/DB/日志保留，原native真实hash、期限预算身份边界未放宽，没有真实paid/sender/RPC回放/SQL修账。


### 2026-10-11 shared actual Source / natural V7 four-stage reconstruction

新增单root _D13FrozenProjectionEvidenceV3，从actualfrozen root使用相对input路径，原列start/end绝不偏移。Draft raw/compressed实际对象各持独立evidence，同事件先取证再原stable验证；Natural generation V7直接转发根事件。删除旧draft projection maps/state/method，没有保留可变别名或第二份算法。context/unit/ref/history原检查暂留draft，不因分离projection而删除；其余pure-input下一步继续迁移。Natural不继承原draft4096 speaker局部界限，只用原arena/quantum。

封闭Source factory只从已完成实际CoreCapture（含同builder/root/EOF/quantum）或实际outbound full preparation/frozen/messages/prefix创建，保持真正表/列/PK/total/frozenroot范围与实际Graph身份；natural不伪造draft JSON/CoreCapture，也不套当前counter安装限制。Source_Current共享quantum起止核验，Source范围纯计算，每片SQL仍核真实type/total/length。所有旧counter variant/stage/quantum/current-installation/HTTP/template条件保留。

V7 projection及typed selected-slice recipe只有一份；times读取actual input scalar ranges，不借draft时钟。speaker首次出现顺序仍stable→recent→detail，speaker_dictionary用object/array pieces和首次actualspeaker scalar ranges，没有整字典编码。短literal/key统一preflight，canonical text hook、ASCIIbytes、key拼接真实收费。slice DTO tags来自actualsource typed offsets，lazy按piece生成，最多一个cache跨quantum，完成/换stage/换variant清空，预算不足且已有进度就让出；文本/ASCII/slice/逗号/输出分别入账，不一次编码全部1280tag。

Natural实际四stage对照semantic_projection_digest、gen messages1/2和actualhistory selected_slice_digest；完毕parent进入natural_input_semantics HOLD。这四摘要闭合不替代pure plan/unit/ref/history构造条件、完整refreeze或Source/Owner/安装grant/typedrequest/job/terminal/settle原件。V2–V6 typed原件仍读，正式recipe缺失明确HOLD，不能套V7重解释。

当前Core796007B/a6cd1873编译、实际Linux canonical import及Astra high局部静态审查通过，源码trailing0/bareLF0。原25ms/256KiB/8MiB运行资格和完整业务节点未执行；没有临时过渡测试或循环完整节点。新snapshot未创建，旧40/41 PASS/首次timeout及单次SIGSEGV不能移植，Numeric根因仍独立待查。全39/alpha2/Contact-C09/D04/生产独立Host继续HOLD，原native真实hash、预算期限身份未放宽，没有real paid/sender、生产RPC回放、SQL修账或发布。


### 2026-10-11 actual references/history selection/question-stable parts

四个actual input重建stage完成后，引用facts reader从同一真实frozen Source再逐1024片读全root。只在formal mapper的真实VersionedRef object建立exact ref/version frame，正式nonempty/exactnonnegative构造、zero允许、nullable qualification不造对象。实际schema/parent namespace及plan三引用、input F/E exactintfloat finite F<E核验；无当前clock、无失效授权刷新。Plan/Unit无__post_init__，不能据注解新加字段语义限制。

history selection逐scalar/refarray/row解析，依赖/readset/raw/block每个member必须实际对象，不允许null/标量被漏掉。coverage/gaps/page row按真实tuple结构逐项收，正式SelectionV2构造核ref.ref唯一、读闭包、4blocks/256raw、区间与page等原条件；对actualplan scene/audience/conversation，E被planvalid/selectionexpiry覆盖，没有强等selectionE。构造前按真实所有refs/rows/cells预留容器和constructor集合arena；block token的contracts.canonical_json输出没有runtime hook，成功后按已证明actual token字符长实计，不重复构造。O(n*m)大区间交叠检查未做有界运行资格，原25ms资源HOLD必须继续保留，后续不能加任意数组上限。

question/stable parts只保存actualheaders、正式ref/dependency对象和text scalar范围，不whole对象或文本重编码。既有lossless codepoint流按真实完整SourceEOF核Python字符/非空白/<=16384、直接原canonical scalar SHA；pair surrogate算一、孤立保留，不为这些类型新加strictUTF8。kind question/d13_history、finite expiry、依赖tupleunique、history非空deps、无access ref、plan audience、stable ref集合等于selectionblocks且E<=每part expiry。首次静态审查发现access_ref数组可被当作缺席，已修全部value-start只允许object/null，非null对象仍按context规则拒绝。

第一份history增量提案内存编译多行条件语法错误，未写产品，首次failure记录product c7原指纹；修正编译通过才写入。当前Core819518B/98ed0b3c编译、稳定前后指纹的实际Linuxcanonical import与Astrahigh局部静态审查通过，源码trailing0/bareLF0。业务节点/资源资格未执行，parent natural_turn_unit_semantics明确HOLD：stable/raw/detail turns、units/reviewbasis/refreeze、真实安装grant/request/job/terminal/settle/SourceOwner/plan权限及冷恢复仍需实际原件。V2–6 recipe仍未补，不套V7。新snapshot未创建，全39/alpha2/Numeric/Contact-C09/D04/生产独立Host HOLD，旧失败DB/日志/快照保留，原期限预算身份nativehash不放宽，无paid/sender/SQL修账/发布。


### 2026-10-11 actual raw/detail/stable/units and complete review/output binding

从同一 actual frozen Source 的 reference/history/context facts 接 recent closed turns、detail、stable 和 units。Raw 使用正式 nonblank、完整 refs/receipt/scope/sequence 和原72h F/E条件，stored trusted_utc 为正式 DTO 正规化后的 exact float，不把 metadata 转换为新时间。Detail 仅此 profile 用 strictUTF8/65536字节，空白正文允许，Source版本/依赖/排除recent来源/序号非降/expiry和去重保持正式条件。Stable 使用实际数组/member/text/header inventory，按正式block/sequence顺序，以 actual speaker/text canonical scalar body范围和正式sequence字面量重建每块正文，核原context SHA及Python字符数。

Plan/Unit无post_init，不据注解加span/文本/资格限制。实际正式decoder的对象、reference arrays、nullable qualification及五个array/null tuple转换门逐项检查；ClaimKind从D09正式模块导入。Basis scalar保留Python set equality，1/1.0/True不能用不同JSON SHA绕过唯一性；audience、purpose与原expiry比较保留。纯输入条件不能充当当前Source/Owner/安装授权。

Review root实际qualified_basis为直接Unit数组，inner canonical_input才为source_unit/promise_grant_refs wrappers。三域完整有序typed单位摘要绑定，inner按正式11字段V2 profile，完整V3输出重建摘要绑定generation paid输出与review root body/units，policy已strip且一致。Grant refs正式1024字符/nonblank/unique、各wrapper同tuple；opaque refs本身不是授权。Decoded JSON坐标不用于外层SQL范围读取。正式_generation_output直接消费已验证actual完整batch输出，原text hook与ASCII bytes分别计费，无第二次测量编码，逐unit核basis引用。

静态首次问题保留并修正：stable null/object/null member漏inventory；ClaimKind函数内错误导入；跨片正文以冒号结束时漏入完整output摘要。最新Core873816B/c6781581编译及唯一Astra high局部静态审查通过，bareLF0/trailing0。没有临时过渡测试，业务及原25ms/256KiB/8MiB资源资格未执行；large Selection O(n*m)与完整refreeze仍待有界正式路径。

Linux初次import无首stdout，Windows fallback因正式fcntl缺失退出，未加shim。普通WSL服务重启权限不足，管理员启动返回操作取消；用户随后报告手动重启，但独立/bin/true直接命令仍在10秒超时且无输出（不读产品、不用stdin、不跑fixture），相关导入子进程已按PID/启动时间关闭。三个服务Running不证明环境恢复，原因未定，也不证明历史Numeric timeout/SIGSEGV根因。环境与源码结果分别记录。

Parent停在natural_original_permissions HOLD，继续完整refreeze、真实grant/request/job/admission/observation/terminal/reserve-settle/plan/SourceOwner与四角色冷恢复。未冻结新快照，旧40/41首次失败和PASS仅属于旧快照，未重复运行或迁移。Native真实SHA2883b3bd4af107a953fe86c6ee785da1fc51688e36e7a9f5fef7d7016d91d56c已重核且未变；全39/alpha2、Contact-C09、D04、生产独立Host继续HOLD，期限预算身份不放宽，无真实paid/sender、SQL修账、push/merge/release。


### 2026-10-11 installed request and completed job checkpoint

Actual installed natural Authority, historical signed root/parent budgets, complete generation/review typed requests, and completed Source/target jobs now have source readers. The completed job result reference must equal its sealed call ID; it is checked in addition to completed/cancel/fence/resource/budget/continuation identity. A production acquire mismatch was found: frozen V2 review was assigned the V1 digest. The producer now selects the digest by the actual frozen input schema, as the existing binder requires. These are source/compile checks; runtime acceptance remains HOLD and the user will perform actual installation tests on the server. Acquisition clock and lease preimages must come from real persisted originals; Source recorded_at is not acquisition time. See D:\codex_handoffs\Sylanne\complete-agent-local-20261006\evidence\c09-natural-installed-typed-requests-completed-jobs-source-20261011.json for pins and boundaries. No new snapshot has been frozen.


### 2026-10-11 pre-mirror natural model facts entry

The actual producer _advance_models currently invokes the old frozen-model helper, whose acquire branches omit natural_generation/natural_review. An already frozen model lookup does not repair this entry. The reviewed implementation must use a closed _NaturalModelFactsOriginalReadV3 bound to the actual producer, actual selected Core call, immutable source pin, and current reserved budget. It must route using real job work_kind and use fresh producer _connections per quantum; no post-mirror SourceDescriptor or candidate-derived authority. Phases: locate; Core intent and original binding; natural seal/acquire/history; complete typed request range/hash; complete frozen wire range/hash; admission; observation including complete outer string and inner result JSON EOF; terminal/model-egress fence; signed quote/grant/lease/reserve; actual settlement and Graph cost original; existing C09ModelBudgetOriginalV1 assembly; existing merge. No facts are merged and models.after is not advanced before complete proof. Keep active reader only in-process with mode/scope/source lineage/execution-head binding; clear it on transaction failure and replay the unfinished call from its actual beginning on cold recovery/readback. Continue using existing model/executions/binding/d11 families, verification IDs, seals and final facts pin. Observation wire digest, typed terminal digest, natural plain terminal digest and model row commitment domains remain distinct. Unknown actual units retain upper bounds. No new clock, renewal, budget, default capability or proof boolean is introduced. This design is approved static review; its source implementation remains pending.
