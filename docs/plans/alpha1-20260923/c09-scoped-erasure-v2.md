# C09 按源删除的重复操作协议（实施裁决，未验收）

2026-09-28。Astra high 对当前 Authority/Graph 删除链做只读审计后，主任务采用此裁决作为后续实施方向。当前 `DeletionPendingV1`、图屏障和独立日志已经按 `(namespace, operation_id, roots)` 记录单次来源范围，但 Core 的 `deletion_phase`、`has_deletion_history` 内容栅栏和 bootstrap 将一次删除当成整个 namespace 的永久状态。第一次删除后第二次会被拒绝；不能靠删掉一个 history 检查修复。

## 状态与身份

`ScopedErasureV2` 的不可变身份绑定 namespace、operation ID、排序根来源、scope kind、策略/版本、请求摘要和严格递增的 deletion epoch。Owner 会话是当次授权证据，不进入重试的语义身份。单次操作保留 `absent → pending → accepted → closed` 原件；namespace 另维护唯一 `active_erasure_operation_id` 和聚合屏障 `clear | pending | accepted`。已关闭操作和独立日志永不清零。真正的整角色注销需单独操作种类，不能从 roots 推定。

新操作仅在当前 Owner 和 `workbench.erase` 授权、Graph 已应用的累计删除水位、独立删除/执行链头与 Core 均一致、无在途删除时开始。Authority 原子占用唯一 active operation，固定阶段 mutation；同 ID 同原件重放，同 ID 异 scope 拒绝。pending 立即提高撤权水位，旧 read/write/dispatch permit 失效；首版在整个闭环期间暂停该 namespace 内容活动。

## 屏障、清理与重新开放

W01 在一个图事务内重新确定来源后代闭包、撤销访问、提高 access/delete epoch 并存图屏障原件。Authority 的 accepted 必须独立复读该原件。closed 需要各清理表面真实收据；之后 Graph 应用关闭水位。只有 Graph 的累计应用证明与最新独立日志头匹配，Authority 才释放删除 fence、清空 active operation 并允许下一次删除。跨 Authority/Graph 读取在对方锁外完成。

删除历史保存不含正文的 tombstone、闭包 manifest 与摘要，并绑定独立日志的 scope/barrier/close 原件。启动、恢复、导入和旧备份回放都要证明 Graph 已应用最新累计删除头，且所有历史闭包不可访问；旧备份须隔离、补应用缺失闭包与清理，不能只改 metadata 水位。第二次删除可以与第一次闭包重叠：已删成员由原 tombstone 证明，不能恢复再删。旧操作的收据可作为已验证链祖先复读，不能要求它永远等于当前最新 head。

Owner 撤权后不签发新删除，但已接受的意图可由受限恢复路径完成原范围。任一 append、Core CAS、图屏障或 ACK 丢失只补原操作，绝不扩大 roots 或创建新 ID。链分叉、闭包缺口、清理未完成时保持 HOLD。

## 实施与迁移门

1. 版本化单次操作 DTO 与 namespace 聚合状态；证明 A closed 后 B 可以 pending，同 ID 冲突和并发 B/C 被拒。
2. 修改 pending/append/recovery/Core CAS；证明各落盘点重启、旧收据复读、Owner 撤权后原操作恢复。
3. Graph v2 屏障、累计 tombstone 和受信应用水位，接真实 accepted/closed 清理收据；证明两次不相交/交叠删除及旧备份不复活。
4. 统一 bootstrap、读写、派发和执行的 readiness；真 Owner 安装态重复删除后无关来源可用、旧 permit 不可用。

迁移时冻结 namespace，验证旧链与 Core，按独立日志重建操作状态；零历史映射 clear，唯一未结操作保留，矛盾/多未结保持 HOLD。旧 closed 只有取得图屏障、清理和累计应用证明才能映射 clear。保存迁移 marker 与旧链 cut/head，不重写历史；新版启用后旧 writer 拒绝运行。

当前 `CurrentErasureAuthority.prepare_request` 是局部 pending 入口，尚无受信 D12 删除计划、公开 mTLS 路由和可重复的 v2 phase；`accept/close` 仍 HOLD。此文是实施合同，不是代码或产品验收。
