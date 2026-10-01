# C09 accepted 后的受控清理与重新开放（实施裁决，未验收）

2026-09-28。适用范围是安装管理的来源后代闭包；外部已发送消息、供应商缓存、用户另存副本及系统快照须另列义务与证据，不能被默认为已清理。当前真实链路止于 plan→pending→Graph barrier→accepted；`closed`、累计 Graph ACK 和内容重开仍 HOLD。

## 受信清理原件

Authority 安装状态固定 `SurfaceRegistryV1`：实际数据库/表、索引、进程缓存、worker、导出目录和受控备份路径，以及每处清理器版本。accepted 后停止新的内容生产、导出和备份，冻结图闭包与安装库存，生成同一 operation 的 `CleanupRunV2`。不能由用户提交 12 个 `receipt_digest` 让 `close` 成功。

每个表面收据绑定 Authority/installation、operation、accepted 原件、闭包和库存摘要、表面与清理器版本、存储/进程代际、执行前后状态及独立复读结果，不记录正文。`not_applicable` 仅可由安装事实证明未配置且库存为空；实现缺失或扫描不完整必须 HOLD。

| 分工 | 必清理表面 |
| --- | --- |
| W01/D06 持久数据 | `graph_current_history`、`graph_dependency_history`、`source_derived_caches`、`retrieval_indexes` |
| Runtime/Host | `process_local_caches`、`model_prompt_caches`、`jobs_drafts` |
| Host 管理文件 | `experiments_diagnostics`、`imports_exports`、`controlled_backups` |
| Authority/维护器 | `execution_journal_payloads`、`sqlite_wal_free_pages` |

清理来源索引缺失时，可清空能安全重建的 namespace 缓存；不得因此删除整个人格的其他记忆。worker 须停止并换 generation，证明旧 worker 不能回写。受控备份及迁移临时副本必须在安装库存中逐一清理或重建。

## 不可变执行日志与 SQLite

现有独立 execution journal 把完整 pending payload 纳入哈希链并禁止原位更新/删除，C04 terminal 也可能带 `output_json`。只追加删除标志保留正文，直接改行又破坏链。需版本化净化表示：先验完整旧链并在 Core 保存迁移 marker、原 head 和逐行 commitment；Authority 签发净化证书，仅保留非正文执行、费用、unknown 事实及 commitment；新 verifier 核证书与不可回退版本，不再声称可重算已销毁原文。已消费的执行权永不因净化而重跑。若物理 head 改变，accepted→closed 的 anchor 必须走受限维护转换；禁止悄悄跳过精确链头校验。Core 嵌套 payload、图副本与恢复包也须纳入同一清理。

逻辑删改全部完成后，由安装维护器排空连接和写者，逐个登记 SQLite 文件做受控 `VACUUM`、WAL truncate checkpoint、完整性和文件状态复读；临时文件和旧副本进入库存。收据仅证明应用可访问文件与 SQLite 存储状态，不宣称擦除 SSD 历史块、系统快照或 pagefile。

## 关闭时序与验收

`accepted → 停写/冻结库存 → 12 表面清理和独立复读 → SQLite 整理/新进程代际 → Authority durable closed → Core CAS → W01 累计 tombstone/已应用原件 → Authority 复读 Graph head 并解除 fence`。各阶段同 operation 幂等；崩溃只补未完成步骤。旧图备份要补应用缺失闭包及清理，不能只把水位改新。

验收至少包括 12 项真实完成或真实 N/A、净化后旧正文不可读且日志链/成本/unknown 可验证、每个落盘点重启、旧 worker 不回写、旧备份不复活、两次删源后无关来源恢复可用。上述均是待实施合同，不能以现有图撤权屏障或内部测试 ACK 代替。
