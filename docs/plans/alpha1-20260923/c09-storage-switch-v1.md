# C09 四库代际切换与关闭协议 v1

2026-09-30。本文件是在 `c09-storage-rebase-v1.md` 已选方案下的实施冻结补充，由当前后端总装任务授权。**以下是必须实现的协议，不是已实现、已验收或已关闭删除的声明。** 本次仅新增本文，不操作真实运行库，不修改共享源码，不新增或执行过渡测试。

## 1. 审计结论与不可改变的边界

维护继续采用停写、Graph/Core/Execution/Deletion 四个新文件、Authority 认证、`PREPARED → SWITCHED → CLEANED`。不能就地拆除触发器、重新启用旧核心、把 V3 sidecar 当净化完成、把签名 DTO 当实时验证。

当前源码中的具体断点：

- `authority_service/c09_authority_storage_rebase.py` 有三种 transform 和候选 DTO，尚缺公共安装构建入口；重复 `_consume("execution_id", ...)` 混用了业务 operation 和删除 operation。
- `core.py` 的 current readers / maintenance authority 安装方法未形成 daemon 启动链；Graph issue 的不可变 `stage=PREPARED` 只是签发原件，不是 durable 路径选择器。
- `v2_execution_journal.py` 已识别 V4 prefix，但普通冷开仍落入旧 redaction seal 禁令。
- Core transform 将所有 active fence 拒绝，并移除 namespace 的 mutation；正在 accepted 的删除 fence 与 deletion 原件必须继续存在，否则不能推进 closed。
- seal、facts pin、facts、Graph issue 使用 namespace 主键单例；仅把 execution schema 白名单加入 4 不能完成第二次维护。
- `v2_fence_store.py` 的业务准入未全面查询 consumed ledger；仅保存消费事实不能阻止重新执行。
- `CurrentErasureAuthority.close`、`AuthorityV2ScopedErasureStore.apply_verified_head` 仍是 HOLD；`execution_physical_cleanup_v3.py` 是固定 blocker 的旧探针，不能通过删除 blocker 字符串验收。

## 2. 唯一路径权威：安装存储控制日志

新增安装器拥有的 `C09StorageControlV1`，使用一个独立 SQLite 控制文件，放在 Authority 受保护安装目录且排除在业务备份/恢复集合之外。它只存存储世代、签名清单、阶段、受控文件清理原件和单调删除水位；不复制 Graph、成本、执行或 namespace 业务状态，不成为旁路业务状态库。四个被重建的数据文件仍恰好是 graph/core/execution/deletion。

同一 installation 只有一个 current manifest 指针。Graph、Core、Host 配置不能各自保存可独立生效的 current 路径。旧配置中的四路径只用于安装控制日志初次登记时的身份核对；日志已经登记后，所有启动、恢复、备份、维护、worker 连接都先读此指针。缺失控制日志、签名校验失败或任一成员身份不符均保持维护，禁止重新使用静态路径或扫描目录选“最新文件”。

四路径 CAS 的最小单元是共享这些文件的安装 cohort。当前四文件实现只允许一个 execution namespace；多 namespace 安装必须在写维护 intent 前拒绝 `unsupported_storage_cohort`，不能只切一个 namespace 却留下共享 Core/Graph 的旧路径。后续扩展应将 execution 成员变为完整映射并一次 CAS 全部成员，不能循环逐 namespace 切换。

控制日志配置 `journal_mode=WAL`、`synchronous=FULL`、可靠本地文件系统；沿用 daemon OS 单实例锁，并增加所有写入口共同持有的安装维护闸门。指针更新只允许服务端持有该 OS 锁时执行。锁文件存在不是锁已被持有的证据。每个 worker admission 必须绑定 current pointer version / storage generation / process incarnation；接受删除时撤销旧 admission epoch，排空或终止旧 worker 后才构建候选。旧进程重新连接必须重新验证代际。

### 2.1 必须新增的严格 schema

下列是列级合同，实际 DDL 使用 STRICT、CHECK、外键及 immutable 原件 UPDATE/DELETE 拒绝触发器。可更新行只有 `c09_storage_current_v1`；其更新必须同事务追加签名 event。

```text
c09_storage_meta_v1(key PRIMARY KEY, value)
  schema_version=1, installation_id, authority_id, control_store_id, key_id

c09_storage_manifests_v1(
  manifest_digest PRIMARY KEY, installation_id, generation,
  manifest_json, issuer_id, key_id, signature,
  UNIQUE(installation_id,generation))

c09_storage_operations_v1(
  operation_id PRIMARY KEY, installation_id, namespace, generation,
  expected_pointer_version, old_manifest_digest, new_manifest_digest,
  prepared_original_json, prepared_digest UNIQUE, key_id, signature)

c09_storage_events_v1(
  installation_id, event_seq, operation_id, stage,
  prior_event_digest, event_json, event_digest UNIQUE, key_id, signature,
  PRIMARY KEY(installation_id,event_seq), UNIQUE(operation_id,stage))
  stage in {INTENT,PREPARED,SWITCHED,CLEANED,RELEASED}

c09_storage_current_v1(
  installation_id PRIMARY KEY, pointer_version, current_manifest_digest,
  active_operation_id, stage, last_event_seq, last_event_digest,
  deletion_watermark, cumulative_tombstone_root)

c09_storage_surface_evidence_v1(
  operation_id, surface, evidence_json, evidence_digest UNIQUE,
  issuer_id, key_id, signature, PRIMARY KEY(operation_id,surface))

c09_storage_retired_files_v1(
  installation_id, resource_id, generation, resolved_path,
  file_identity_json, content_sha256, retirement_event_digest,
  PRIMARY KEY(installation_id,resource_id,generation,resolved_path))
```

`INTENT` 是构建前停写意图，`RELEASED` 是 CLEANED 后重开门闩的事件，不改变三个必需维护阶段。允许 current.stage 为 bootstrap 时的 `READY`；以后只有 `RELEASED` 可服务业务。`INTENT` 与 `PREPARED` 的 current_manifest 仍为旧；`SWITCHED` 起永远为新。所有阶段失败只能修复/继续，不能回拨指针。event_seq/pointer_version/generation 均严格单调；同操作同阶段请求必须精确原件重放，异摘要冲突。

元数据中的 key_id 对应安装器已保护的密钥，不从候选文件、请求或 manifest 内载入密钥。延续已安装 HMAC-SHA256 模式即可，无需引入新 PKI；验签者必须直接使用安装的密钥材料，不把 caller 提供的摘要或 key 当权威。签名使用域分隔 `schema + "\n" + canonical_digest(body)`；body 包含所有字段，排除自身 digest/signature。规范 JSON 使用现有 canonical 序列化；摘要带不带 `sha256:` 由各 schema 明确，禁止模糊自动转换。

### 2.2 四路径 manifest 与 PREPARED 签名原件

`C09StorageManifestV1` 固定包含 `schema, authority_id, installation_id, cohort_namespaces, generation, prior_manifest_digest, members, inventory_manifest_digest, certificate_digest, graph_issue_digest, recovery_pin_digest, cumulative_tombstone_root, deletion_watermark, manifest_digest`。`members` 严格排序且角色集合恰为 graph/core/execution/deletion；每个 `StorageMemberV1` 包含：

```text
role, resolved_path, store_id, schema_version, namespace,
storage_generation, incarnation_or_journal_id,
device, file_id, prepared_size, prepared_mtime_ns, prepared_sha256,
logical_data_root, schema_objects_digest, cold_read_digest,
wal_policy, companion_resource_ids
```

路径必须绝对、解析最终目标、在登记安装资源内；拒绝 reparse/symlink/junction 替换、角色路径重叠和源/目标同文件。Windows 使用实际 volume/file identity（现有 stat 身份不足以证明 handle 独占），在同一打开句柄上核验路径与文件 ID。`prepared_*` 是封存时证据，正常运行后不能要求 size/mtime/hash 永远相等；普通启动验证稳定 file ID/store ID、逻辑 journal/Graph 证明及当前 head。切换前未允许业务写时必须完整重验 prepared 哈希。

`C09StoragePreparedOriginalV1` 必须包含：

```text
schema, authority_id, installation_id, namespace, operation_id,
maintenance_generation, expected_pointer_version,
old_manifest_digest, new_manifest_digest, prior_prepared_digest,
accepted_receipt_original, barrier_receipt_original,
accepted_receipt_digest, barrier_receipt_digest,
old_core_anchor_original, new_core_anchor_original, anchor_transition_original,
old_deletion_head_original,
old_execution_head_original, old_graph_head_original,
facts_pin_original, facts_digest, recovery_bindings_digest,
graph_certificate_original, graph_issue_original,
frozen_inventory_original, frozen_scan_digest,
writer_quiescence_original, source_final_fingerprints,
four_candidate_disposition_roots, four_candidate_cold_reads,
cumulative_tombstone_root, deletion_watermark,
component_verifier_hashes, prepared_digest, key_id, signature
```

Authority 必须在真实安装服务上读取这些原件、核验四库源与目标及实际冻结状态后签发。维护入口只接受 operation_id 和服务端登记目标/配置，不接受 caller facts、`writers_stopped=True`、自签摘要或现成 cleanup attestation。

顺序消除自引用：旧 Core 签 Graph issue → Graph 镜像证书并完成 checkpoint/close → 构建包含既有 issue/pin 的新 Core 与另两库 → 独立只读冷读四库 → 封存四库最终 hash/identity → 生成 manifest 与 detached PREPARED 签名 → 写安装控制日志。manifest/PREPARED 存在四库之外，不再写回已封存四库。旧 Graph issue 的 target hash 是镜像前候选哈希；最终 manifest 使用 `GraphRebaseMirrorV1` 的镜像后哈希，两个哈希不可混用。源 Core 签发产生的维护写入全部结束后才记录 `source_final_fingerprints`；不能用签发前 Core 文件哈希验证签发后源。

## 3. 耐久状态机与崩溃重开

`prepare_storage_rebase_v1` 先确认 accepted 原件与安装 OS 锁、撤销 admission，控制日志写 INTENT（旧指针不变），随后 checkpoint、排空句柄和构建。所有新文件以独占创建、不覆盖已有文件；候选失败残留仍属于登记 rebuild inventory，不静默删除证据或擅自重跑业务。

PREPARED 的控制日志事务同时保存新 manifest、签名原件与 event，CAS `pointer_version/old_manifest/active_operation`。任何先前仅构建完成但未写 PREPARED 的目标均不具备运行资格。

SWITCHED 前重新验证 PREPARED 签名、源最终指纹、四个目标最终指纹、停写 token 当前有效和所有旧业务句柄已排空；用单一控制日志事务追加 SWITCHED 并将 `current_manifest_digest=新清单`、`pointer_version += 1`。同事务推进 accepted 删除水位和累计 tombstone root，并永久登记旧文件身份。该事务是唯一线性化点；不逐个 rename 四个运行路径，不先发布新 Core 路径。

| 崩溃位置 | 唯一允许的恢复动作 |
|---|---|
| accepted 后、INTENT 前 | 旧库仅维护打开；accepted 阻止正文与新执行，重新取得真实锁再登记 INTENT。 |
| INTENT 后、构建未全完成 | 旧 manifest 仍唯一 current；识别已登记候选，验证后继续未完成维护步骤，业务继续封闭。 |
| PREPARED 后、SWITCHED 前 | 重验四目标、源指纹、原件链和冻结；完全相同则 CAS 切换，差异 HOLD，不能选部分新库。 |
| SWITCHED 后、新服务未装配 | 只从新 manifest 打开四库的维护视图；根据外部签名原件验证 V4 prefix，缺库也不能回旧库。 |
| 删除部分旧副本后、CLEANED 前 | 从每项删除前原件及当前文件状态继续清理；已不存在不是 N/A，必须有此前受签名的 inventory/retirement 证据。 |
| CLEANED 后、closed append 前 | 新库维护打开，从已有清理原件继续确定性的 closed mutation。 |
| closed append 后、Core CAS 前 | 用现有 deletion pending recovery 补该同一 mutation，禁止第二次追加。 |
| Core closed CAS 后、W01 ACK 前 | aggregate 仍 accepted，应用累计 tombstone 到新图并产生真正 ACK。 |
| W01 ACK 后、Core applied CAS 前 | 复读既有 ACK 和最新 deletion head，执行同一 applied CAS。 |
| Core applied CAS 后、RELEASED 前 | 复读 scoped clear、closed 原件、ACK、当前 Graph head 与 CLEANED，写 RELEASED；重启不得因 Core clear 单独开门。 |
| RELEASED 后 | 常规 V4 冷开及新代际 worker；旧路径、旧 permit、旧备份不能恢复执行权。 |

关闭业务连接和取得文件独占发生在切换前；清除旧文件发生在切换后。旧文件或外部句柄无法排空就停在维护，不把“文件能读”当可安全删除。CLEANED 只表示受控物理表面清理完成，不等于 closed 或正文已开放。

## 4. 安装装配和 V4 冷开桥

新增 `InstalledC09MaintenanceV1` 作为安装服务对象，提供真实 gate、control reader、签名器、inventory、surface cleaners 和原件读取器。`AuthorityDeploymentConfig` 增加受保护 control path/key path/installed inventory/maintenance factory 的严格配置；factory 来自安装代码，不能从请求字符串动态 import。

`open_authority_daemon` 必须改为：取得 OS instance lock → 只读验证 control/signature 并解析整套路径 → 创建 `VerifiedStorageOpenContextV1` → 开独立 journals → 构造 Core/verifier → 核对 context 与 Core/journals/Graph → 装配实际 C04/D02/D11 → 安装 current C09 readers 和 maintenance authority → 按阶段仅发布维护接口或正常接口。现有先 journal 后 Core 顺序通过这个预验证 context 解环，不传一个跳过校验的 bool。

`VerifiedStorageOpenContextV1` 不是任意 dataclass 能取得的授权。公开 API 接受 `InstalledC09StorageReaderV1`，由它在持锁时直接读控制日志并返回内部 context；journal 冷开再核对 context 的控制路径、pointer_version、manifest digest、store/file identity、签名原件和自身 V4 prefix。context 失效或 pointer 变化应拒绝。

V4 正常冷开要求 prefix 的 authority/namespace/old journal head/facts pin/Graph issue/new journal ID 与当前 manifest 对应 signed transition 一致，且阶段为 RELEASED、Core scoped 已 applied。SWITCHED/CLEANED 仅允许 maintenance 连接读与受限 closed/ACK 写，不给执行服务准入。历史 seal 属于旧 journal 时，由**已经验证的当前 transition**说明其被哪次替换取代；不可删 seal 或放宽 V1/V2 的 `require_no_execution_redaction`。旧 journal 即使还能打开，其 ID/path 不在 current manifest，仍拒绝业务。

把 `require_no_execution_redaction_locked` 的调用点逐一分为旧库防回滚和当前库业务准入：后者新增 `require_current_storage_generation_locked(context, action)`；不能全局略过 seal。所有 Core namespace anchors、FencePermit 与 writer admission 在切换后绑定新 execution journal/nonce/revocation epoch。accepted 删除控制 fence 的当前 permit 通过受认证 transition 在新 Core 内生成新版，旧 accepted receipt 原件保持不变。

此处禁止只改保存的 permit 让旧 receipt 的 `updated_revision/after_anchor` 对不上。新增 `C09AnchorTransitionV1`，字段固定为 `authority_id, installation_id, namespace, operation_id, old_manifest_digest, maintenance_generation, accepted_receipt_digest, original_fence_permit_digest, before_anchor, after_anchor, continuation_permit, transition_digest`，受 detached PREPARED 签名覆盖；after_anchor 由新 Core 候选真实行和新 execution genesis 计算。新 Core 在 `authority_c09_deletion_continuations_v1(namespace,operation_id,transition_json,transition_digest)` 保存它；原 receipt/permit blobs 仍逐字保留，通用历史 get_mutation 继续返回历史原件。新增 `read_current_deletion_continuation_v1` 给 close 专用路径读取当前 permit，`require_prior_deletion_transition_locked` 增加**经安装 storage verifier 验证过的过渡原件**分支：旧 accepted receipt.after_anchor 必须恰等于 before_anchor，当前 Core 必须恰等于 after_anchor；其余旧操作不得借此跨代。该行和 archive 表都加入 builder 已知表及处置清单。next-generation 只要复读该 continuation 即可继续 close，不能重新构造 caller anchor。

安装 current recovery reader 必须绑定同一个 Core、closure、current Graph、namespace、实际 D02 resource issuer/body authority 和实际 C04 服务字典；C04 内部算法签名器不能用通用 True verifier 代替。没有 C04 执行历史时允许空服务集合，但 reader 必须从已验证旧链证明不存在 internal C04 行；存在行而无对应服务则具体 HOLD。

## 5. 四库 builder、重复维护与恢复事实

### 5.1 Builder 公共入口与删除控制链

新增公共 `build_installed_authority_storage_rebase_candidate_v1(*, core, closure, maintenance, operation_id, subject, credential, graph_mirror, targets)`。它从 current installed original reader 获取已核验 pin/facts/rows，不接收外部 facts 或 raw rows；targets 仅能是 control INTENT 已登记路径。返回现有 `AuthorityStorageRebaseCandidateV1` 的完整实例及逐表处置清单；不签发、不切指针。

Core 逐行迁移规则必须区别：

1. 当前 C09 的 deletion pending/accepted 原件、所有后续 close 所需 deletion mutation/receipt 与 scoped state 原样保留。当前 active deletion fence 保留并通过转移证书派生新的 current permit；不能把活跃删除操作当活跃业务执行拒绝。
2. 已完成 execution mutation/正文从新库移除，保留原 commitment、消费身份及 V4 facts。所有 reference 可达正文都要列入清单，不能仅删 execution entries。
3. 未决 execution obligation 迁移为 typed unknown 与完整 footprint，保留 effect/conflict/quota/budget 占用。正在跑的 worker 必须先排空或转为有原件的 unknown；不能直接清零。
4. 已接受但尚未派发的 prepared execution 不可在净化后重新使用旧 source command；撤销其旧 dispatch capability，保留未派发事实和幂等键，只有经新一轮准入/存活来源生成的新 operation 才能执行。
5. 其他 namespace 行原样保留。未知非空表或未知正文列必须具体 HOLD，不默认 copy 或 purge。删除日志只存已分类结构原件，逐表证明后复制，不凭名称假定无正文。

### 5.2 不改写旧 V4 原件；增加 typed lineage

现有 `SanitizedRecoveryFactsV4` 缺少 business operation 和 D02/D11 对 execution 的完整绑定。新增受 PREPARED 签名约束的 `C09RecoveryBindingsV1`，不要给旧 dataclass 加默认字段并重算旧摘要。

```text
C09ExecutionBindingV1:
  execution_id, business_operation_id, execution_kind,
  input_commitment, first_consuming_operation_id,
  originating_journal_id, source_row_commitments,
  d02_quote_ids, d02_component_ids, d11_settlement_ids,
  dispatch_generation, prior_fact_frame_digest_or_none
C09RecoveryBindingsV1:
  authority_id, installation_id, namespace, operation_id,
  prior_transition_digest_or_none, prior_fact_frame_digests,
  execution_bindings, facts_digest, bindings_digest
```

business_operation_id 只从已验证 dispatch permit/internal binding/先前签名 binding 取得，绝不等于正在执行的 C09 operation，除非旧业务原件本来如此。consumed ledger 中 operation_id 固定表示原业务 operation；C09 签发来源由 facts_pin_digest/transition lineage 表达。相同 `(namespace,kind,item_id)` 必须 commitment 和业务 operation 全等才可重放；不同原件冲突，禁止 REPLACE。

第二次维护必须合并 `前代认证 facts + 当前 V4 后缀新执行`。前代事实保留原 frame bytes/digest；新增 frame 绑定前代链，不能把旧事实重新冒充当前原件。新 `_CoreTransform` 将 `authority_c09_consumed_execution_v1`、`authority_c09_unresolved_effects_v1` 及所有新合同表纳入已知 schema，预读并精确保留旧 ledger，再加入新后缀消费键。只有仍 unresolved 的 effect 进入新未知集合；已解决状态必须有 Authority 当前 settlement/resolution 原件，不能凭 absence 删除。

为避免 namespace 单例占位导致第二次失败，新增统一不可变归档：

```text
authority_c09_originals_archive_v1(
  namespace, operation_id, original_kind, original_digest,
  original_json, maintenance_generation,
  PRIMARY KEY(namespace,operation_id,original_kind))
```

新文件构建时将旧 seal/sidecar pin/switch/facts pin/facts/Graph issue 原件按原 bytes 归档，旧 namespace 单例表作为**当前维护槽**只装当前 operation 原件。第一代旧 schema 原件首次认证后也归档；原表触发器在源库不改。所有读取 helper 添加显式 operation/generation 选择；不得“取 namespace 第一行”验证第二代。旧签名原件的冻结 inventory digest 按历史 manifest 验证，不要求它等于第二代当前 inventory。Graph certificate/tombstone 历史表与归档同样永久承接。

`_ExecutionTransform` 接受严格 schema 1/2/4；V4 输入必须先核验原 prefix 和归档 transition 再解析当前 suffix。新 journal 用新 ID、seq=0/genesis 创建后缀，prefix 指向完整前代事实链及旧 suffix head。连续两次维护之间可以没有新执行；这时 `old_seq=0, old_digest=genesis` 合法，但只有**已认证 V4 prefix 非空**才可证明历史。新增版本化 `C09ExecutionSourceSealV4`/pin 原件承载 `prior_prefix_digest, suffix_head, suffix_row_commitments`，不要将既有 V3 的非空链检查改松。第一次没有 execution 历史也需显式 empty verified source 证明，不能编造一行。

### 5.3 D02/D11/unknown 读取与不重复扣费

新增 `InstalledSanitizedRecoveryResolverV4`，通过 current control → verified transition chain → archived/current pin → exact typed facts → bindings 读取。返回 `VerifiedSanitizedExecutionReadV4`（typed 状态、commitments、费用事实、unknown footprint、证明链），不返回伪造 terminal/body 原件。

成本账本消费逻辑区分 read 与 apply：D02 按 `(namespace,quote_id,component_id,outcome_id,settlement_id)`，D11 按 `(namespace,parent_budget_id,idempotency_id,settlement_id)` 唯一登记。已结算读取只复读原 float.hex/int 金额和 settlement commitment，不能再次调用 charge/complete/model executor。缺少实际结算时只能依赖已认证事实和当前 ledger CAS 执行一次，不能为补事实重跑业务。failed 不改成 completed；unknown 不改成 failed/zero。

所有 fence begin/record_pending、dispatch effect reserve、internal claim/terminal、append mutation/append_id、Graph outbox 重放入口必须查询历史 consumed ledger 与当前 journal。命中旧身份返回 typed already_consumed/sanitized read，不能因原 mutation 正文不存在就走“新请求”。`pending` 事实不能自动升级可执行，执行仍须当前 live command、generation、source gate、预算与新准入。

unknown 保留原 conflict_keys、object_gate_keys、quota_occupancies、budget/reservation constraints、external_query_ref、实际 dispatch generation。对旧 `authority_effects.execution_seq` 的解释必须带 originating journal ID，不能把旧 seq 对照新后缀。新增 `resolve_sanitized_unknown_v1` 仅消费安装平台查询/人工决议服务认证的 resolution 原件，以 effect_id + 原 obligation commitment CAS，再执行一次费用/占用结算；它从不重发旧动作。已有 Core 保存完整 footprint 与 resolver binding 后才可以删除旧 journal。

内部 C04 unknown 当前 extractor 缺 footprint：从真正 claim 的 D11 parent budget/配额预留和图侧 conflict 原件组装 typed footprint，由对应安装 verifier 认证。若历史确实不含恢复必需字段，返回具体 `internal_unknown_footprint_missing:<execution_id>`，保留 accepted/HOLD；不能填默认空值，不能以完成全部后端为由伪造可清理。

## 6. 清理十二表面、closed 与累计 ACK

为以下固定集合逐项配置安装 cleaner 和独立 rereader：

```text
graph_current_history, graph_dependency_history,
source_derived_caches, retrieval_indexes, process_local_caches,
model_prompt_caches, jobs_drafts, experiments_diagnostics,
imports_exports, execution_journal_payloads, sqlite_wal_free_pages,
controlled_backups
```

新增 `InstalledCleanupSurfaceOriginalV1` 至少包含 `surface, operation_id, installation_id, scope_digest, accepted_receipt_digest, switched_event_digest, inventory_manifest_digest, target_resource_ids, before_observations, action, after_observations, cumulative_tombstone_root, cleaner_version, independent_reader_version, evidence_digest, issuer_id, key_id, signature`。before/after 只存文件身份/结构事实/摘要与 counts，不装正文。action 只能是实际 purged/sanitized/reset；本轮实现**不接受 caller 的 N/A，也不以默认 not_applicable 凑齐十二项**。确实零实例的表面用安装枚举得到 empty inventory 和独立复读零实例的证据，显示 empty_verified 而非声明未安装；如原 wire DTO 无该值，应在内部原件记录 empty_verified 后由 verifier 映射为现有有效状态，不能无证据映射。

具体验收内容：Graph 当前/历史/依赖按证书 closure 与永久 erased keys 复读，混合来源派生值整值失效；缓存、索引、jobs、实验、导入导出遍历登记实际存储；进程缓存要求旧进程 generation 已退出或其 installed reset 有 ACK，不能只清磁盘目录；模型 prompt cache 需要已安装 provider 支持且可验证的清除/不存在证据，不可访问登记表面仍 HOLD；execution 用新 facts resolver 复读费用/unknown 并证旧正文不可达；SQLite 覆盖四个旧 DB/WAL/SHM、journal/temp、失败候选和 sidecar，不以 `VACUUM` 成功代替旧文件清除。

受控 backup 必须先验证原件与 namespace，生成含**累计** tombstone 和恢复义务的净化替代版本，独立核验后再删旧副本；不得把全量备份直接复制到新代际。每项删除前将其精确身份与原哈希耐久登记，删除后重新解析路径确认同身份文件不存在、替代副本有效。发现路径替换或归属不明保持 HOLD。库存更新在单独签名 inventory revision 中登记，不能悄悄覆盖 frozen inventory。

全部十二项独立验证通过后，Authority 复读当前四库与文件库存，将 surface receipt root 写 CLEANED 事件。然后只在当前新 Core/deletion journal 推进：

1. 新 `close_verified_cleanup_v1` 从安装 evidence store 读 CLEANED/十二原件并与 accepted/barrier/transition 比对，生成确定性 closed mutation ID。请求不能传 cleanup DTO 作为权威。
2. 复用 deletion append → pending recovery → Core CAS；scoped 记录 closed_seq/digest，aggregate **继续 accepted**。新 current permit/anchor 的版本由转换证明链接旧 accepted 原件，不能修改旧原件的 before/after anchors。
3. W01 在新 Graph 事务应用从历史 applied watermark 到 closed head 的完整累计操作/永久 erased keys，输出 `VerifiedGraphAppliedHeadV2` 所需原件，并补入 certificate chain digest、cumulative tombstone root、new incarnation、maintenance generation、Graph head/receipt commitment。
4. 正式 `apply_verified_head` 通过已安装 Graph reader 在固定 snapshot 复读原件，核验最新 Authority deletion head、全量累计 tombstone、当前 manifest 和 Graph head，才调用共享生产 CAS 核心；不得调用 `_apply_controlled_head_for_storage_test` 冒充产品流程。
5. Core finish deletion fence、applied watermark/epoch CAS、revoke epoch/nonce 更新成功后，安装器再次独立复读 Graph/closed/applied/CLEANED，写 RELEASED。只有此时开启新 generation worker 和正文服务。

`execution_physical_cleanup_v3.py` 保留旧探针历史语义，产品维护入口使用新 V1 四库清理验证器；不得删除固定 blocker 后宣称 V3 具有物理清理能力。

## 7. 旧备份与旧进程防复活

所有 restore/import/open 路径都使用受保护 current 控制日志，先验证 installation、namespace、generation、deletion watermark、累计 tombstone 与 consumed/unresolved roots；低于当前水位或缺认证链的副本只能进入隔离净化入口，不能注册 current、发送 dispatch 或提供正文。restore 产生新运行库也必须走正式新 generation CAS；“文件在原路径”“签名曾有效”“备份时间较新”均不构成现时准入。

控制日志和密钥不允许由业务 backup restore 覆盖；若管理员绕过服务同时回滚控制日志、密钥和所有安装状态，本协议不声称有硬件防回滚能力。产品受控恢复则必须拒绝回滚，不提供静默 fallback。旧 worker 即使保有旧 SQLite 句柄，其输出也因 generation/epoch/nonce 与 erased keys 被 Authority/Graph 双端拒绝，且旧受控文件清理必须等它退出/释放句柄才 CLEANED。

## 8. Sol 实施接口与独占文件分工

总装协调者先划定写权限；下列角色不能交叉修改同一文件。已有脏成果必须在原基础接续。常规实现使用允许的 Sol/Luna，架构变化交 Astra high；本文不派生新代理。

| 独占实现单元 | 文件与必须交付的函数 |
|---|---|
| A：控制日志与安装维护 | 新 `authority_service/c09_storage_control_v1.py`：严格 schema、`bootstrap_installed_storage_v1`（显式安装）、`read_verified_current_storage_v1`、`record_maintenance_intent_v1`、`record_prepared_storage_v1`、`switch_prepared_storage_v1`、`record_cleaned_storage_v1`、`release_cleaned_storage_v1`；新 `authority_service/c09_storage_maintenance_v1.py`：`InstalledC09MaintenanceV1`、quiescence、resume、inventory 与四库 orchestrator。不得直接写业务表。 |
| B：Core/journal/facts | `authority_service/c09_authority_storage_rebase.py`、`core.py`、`v2_execution_journal.py`、`erasure_closure_redaction_v3.py`、`erasure_recovery_pin_v4.py`、`c09_graph_rebase_issue_v1.py`、`c09_current_recovery_originals_v4.py`；新增 `authority_service/c09_recovery_resolver_v4.py`、`c09_originals_archive_v1.py`。负责 builder、archive、重复维护、V4 cold bridge、签发和 consumed 身份。 |
| C：Graph/cost 契约 | `runtime/c09_storage_rebase_contract_v1.py`、`runtime/c09_sanitized_recovery_extractor_v4.py`、`runtime/c09_graph_rebase_candidate_v1.py`、`runtime/c09_graph_originals_read_v4.py`、`runtime/c09_d02_c04_recovery_reader_v4.py`、`runtime/c09_d11_c04_recovery_reader_v4.py`、Graph erased barrier/ACK helper。负责 typed bindings、Graph 累计禁令、原 receipt commitment、D02/D11 exact read。需要修改 `graph_store.py` 时必须由总装单独授予该文件。 |
| D：fence/闭环 | `authority_service/v2_fence_store.py`、`v2_fence_service.py`、`v2_scoped_erasure_store.py`、`current_erasure_service.py`、`erasure_closure_inventory.py`；新增 `authority_service/c09_cleanup_verifier_v1.py`。负责所有消费准入、unknown resolution、真实 close/apply、surface receipts 与 fence 重开条件。 |
| 总装唯一所有者 | `authority_service/daemon.py`、`deployment_config.py`、Host/CLI/runtime 启动及 backup/restore 接入文件。负责配置装配、daemon 启动顺序、执行入口逐个接 resolver/consumed、停止和发布 worker。A/B/C/D 只提交精确接线接口，不同时编辑这些文件。 |

为避免 A/B 的 circular dependency，A 仅依赖 runtime typed 合同与 reader protocol；B 提供 `verify_prepared_storage_original_v1` 和具体签名方法，A 通过安装时绑定的真实服务调用。B 的 V4 journal 冷开只依赖只读 control verifier，不反过来构建 daemon。D 的 cleaner verifier 读取 A 的 stage 和 B 的 facts，不能自己改变路径。

必须按此顺序集成：typed contracts + control reader → archive/builder/current reader → journal cold bridge + consumed checks → A 四库 switch/resume → 十二表面 verifier + closed/ACK → daemon/Host/restore 正式接线。接口编译通过后才做下一层，不以运行一个永远 HOLD 的空接口视为完成。

## 9. 必要验收与本文件状态

先对实际修改模块做编译/导入检查；不新建过渡测试，不重复运行无新信息的检查。产品链路接齐后只安排一次有证据的安装验收，使用专用非生产受控目录与真实安装服务；不操作用户真实运行库。验收必须覆盖同一流程中的：

- 删除含 D02/D11 成本、completed/failed/unknown 的来源；非删源仍可读取；各成本事实复读相等且结算次数不增加，旧执行身份不能重领。
- PREPARED、SWITCHED、部分文件清除、CLEANED、closed journal 已 append 未 CAS、ACK 已写未 applied 的冷启动恢复；每处恢复都只用正确整套路径，正文状态符合上表。
- 完成一次后普通 daemon V4 冷开、新执行，再做第二次删源；第一次 erased keys/费用/unknown 义务仍在，第二代 chain 与 epoch 累计，两个删除都能完成真实 closed/ACK/RELEASED。
- 同 operation 异摘要、旧 worker、旧 backup restore、同 key 正文复活、缺表/未知正文、缺密钥或替换文件分别明确拒绝。
- 十二表面逐项原件及 independent reread；有 provider/句柄/历史字段无法确认时列明实际 HOLD，不伪造 N/A。

未执行的端到端项交付时必须给人工方法：停止对应安装服务后，用正式维护恢复命令重开该阶段；对照 control current/event、Authority closed/applied、Graph ACK/永久 erased keys 和磁盘登记文件；再以旧身份尝试读取/派发/备份恢复，核对拒绝与无重复费用。不要人工改 stage/READY/数据库行模拟通过。

本文件的完成状态仅为：协议审读与实施交接已冻结。实现、编译、独立冷启动、真实清理、两次维护和正式 closed/ACK 均须由后续实际源码与验收证据分别报告。
