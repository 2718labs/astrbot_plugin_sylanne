# C09 accepted 后的净化存储代际（alpha1 实施合同）

2026-09-28。本文细化 [C09 清理合同](c09-cleanup-closure-v2.md)；是实施裁决，不是已经完成的删除验收。适用范围是本代 alpha1 安装管理的数据及其受控副本。`accepted` 仍是读写隔离屏障，只有清理和复读真实完成后才能 `closed` 并重新开放内容。

## 选择

采用**停写维护、在新文件重建净化后的 Graph/Authority/Core 存储代际、Authority 认证过渡、清除旧应用可访问副本**。不在运行库原位拆除不可变触发器，不把 V3 sidecar 或 Core switch 当成物理清理。分源加密可降低未来成本，但不是本轮前置条件；它也不能清除已经存在的明文和混合来源派生物。

多 SQLite 文件无法一次原子切换。维护状态必须耐久地走 `PREPARED → SWITCHED → CLEANED`，每阶段绑定操作、旧/新文件身份、存储代际、内容排除核验和受控库存。崩溃重启只加载登记的当前代际；不一致时继续维护并保持内容封闭。切换后旧文件不能成为服务回退。

## 两项冻结合同

`GraphErasureRebaseCertificateV1` 绑定安装/namespace、C09 操作和 accepted/barrier 原件、冻结库存、旧图 incarnation/revision/epochs、新 incarnation/单调维护代际、逐表迁移清单、来源与派生闭包、永久 erased-key 集合、累计 tombstone root、新库数据 root/构件哈希及冷读结果。逐行处置只允许 `preserved_exact`、`payload_erased_retained_facts`、`derived_removed`、`rebuilt_from_surviving_sources`。保留能原样复验的旧 event/receipt commitment；净化过的旧原件只能经旧 commitment 加过渡证书验证，不能冒充原收据或重算已销毁正文。

`SanitizedRecoveryFactsV4` 在旧链仍可读且安装 verifier 已核验时签发，严格保存恢复所需的非正文结构事实：执行与已消费权、原 input/result/terminal/signature commitments；D02 quote/component/completed/outcome/settlement 与固定费用；D11 父预算、上限、实耗、settled/pending/debt 和幂等身份；unknown 的冲突键、派发代际、平台查询引用、配额/待核实费用及原 `RecoveryConstraintFootprint` 必需字段；Graph 操作、收据、写集 commitment 与未解决义务。不能用任意 `metadata`/`details` JSON 重新装入正文，不能把 unknown 清零或释放执行权。D02/D11 读取器需要识别认证后的事实，否则清理保持 HOLD。

旧 Graph 当前/历史正文、历史依赖与嵌套原件按闭包处理；混合来源派生值若依赖被删源，整值失效，只能从存活来源重建。无关来源及历史应原样保留。正文读返回明确 `erased`；不得以空 SourceRecord 或 revision=0 伪装。新增 `verify_erased_barrier_v2` 核原 barrier/accepted commitment、净化前闭包认证、累计 tombstone、新代际过渡证书与 Authority 当前删除水位；旧 `verify_c09_graph_barrier_v1` 不放宽。永久 erased-key 和新代际阻止旧 worker/CAS 及同 key 正文复活。第二次删源必须承接第一次的证书链和累计禁令。

## 文件与备份闭环

安装库存逐项登记实际数据库、WAL/SHM、临时重建文件、导出、缓存、受控备份及轮换副本的所有权、解析路径/文件身份、格式、代际、namespace、覆盖范围、水位和清理器版本；目录名本身不是完整库存。旧库和受控备份先独立核验，再各自生成带累计 tombstone 的净化版本；旧副本在句柄排空后清理。恢复入口必须先比对当前 Authority 删除水位和执行义务，旧代际只能进隔离净化流程。不可访问或来源归属不明的已登记副本保持 HOLD。

切换后逐项复读十二个安装表面，真实清理或由安装事实证明真实 N/A；排空旧进程和句柄，检查新库完整性与正文不可读，清除旧 DB/WAL/SHM/临时和受控副本。应用可访问文件清理不等于 SSD 历史块、系统快照、用户另存或供应商缓存的擦除。只有真实清理收据、Authority durable closed、Core CAS、W01 累计 tombstone/ACK、Authority 复读新图 head 全部成立，才能解除 fence 并启用新 worker 代际。

## 分工与最小验收

1. 公共合同/读取协议：编译；旧 receipt commitment 不变；净化事实不能伪装旧正文；缺少成本或 unknown 约束拒绝；同操作异摘要拒绝。
2. W01 Graph 净化重建：删源及后代历史不可读，无关来源保留，旧收据 commitment 可复读；erased barrier 可验，旧 CAS/同 key 重建拒绝；连续两次删除累计正确。
3. Authority/Core 净化恢复：旧库已清理后成本仍可幂等复读，completed/failed/unknown 语义不变，执行权不重发；支持净化前缀后的新执行与第二次维护。
4. 安装维护器与 Host：各耐久阶段冷重启、旧 worker 不回写、旧备份不复活、文件/WAL/临时副本真实清理，十二表面可复读，非删源可继续使用。不得用 caller 收据或伪造 N/A 关闭删除。

目前 V3 sidecar/物理清理前检、图屏障和 accepted 只覆盖上述合同的一部分。正式 `closed`、累计 ACK、正文重开仍 HOLD。
