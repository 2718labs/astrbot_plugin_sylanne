# V2-only Authority 迁移后端实施合同

日期：2026-09-28。状态：本地战略设计；尚未实现或通过 S15。来源是当前 V2-only Authority、GraphCoordinator 与旧迁移入口的只读核对。本文只约束新后端，不解封 Core 的旧事务迁移 API。

## 唯一权威与状态

迁移状态、激活代际和阶段收据仍写入现有 Authority DB；独立删除、执行日志仍是当前权威，不复制到迁移服务。`begin_transfer` 必须先在 Authority 的同一事务域挡住普通新 fence，且要求旧 read/write/model/dispatch fence 与 pending mutation 已清空。不能先普通下载再冻结源，否则两者之间的提交可能漏搬。

| 阶段 | Authority 原子结果 | 允许操作 |
| --- | --- | --- |
| begin | source active `g` → source recovering `g`；封存 plan、blocker 和源专用 migrate permit | 只允许原迁移导出及查询 |
| revoke | 核验封存快照并消费源 permit；holder 清空，revoked `g+1`，revocation epoch 增一 | 只允许管理查询 |
| prepare target | 目标签到 recovering `g+2` 与专用 recovery permit | 只允许隔离导入、最新日志恢复合并 |
| activate | 核验目标图恢复原件；同事务结束专用 permit、解除 blocker，active `g+2` | 目标重新申请普通内容 fence |

每阶段保存 `(transfer_id, phase, request_id, canonical_request_digest)` 和原收据。同一请求返回原结果，同 ID 异内容拒绝；`recover_transfer` 只返回阶段、原收据与当前状态，不推动代际。Authority 或客户端响应未知时保留原请求身份；不能换 ID 重试或让源端凭超时续服。

## 内容与恢复证明

源在 migrate permit 下封存该 namespace 的完整图/作业/预算恢复闭包及快照摘要、图 incarnation/revision/epoch、`SnapshotRequirementsV2` 和未完成工作摘要。迁移包的日志序号只是最低水位；目标必须向**同一 Authority**验证独立删除/执行日志的当前头、身份与连续前缀，并合并 prepared/unknown effect、D10 联系限制、D02 预留及 D11 未确认费用。删除历史不能被迁移清零；证据不足保持 recovering/HOLD。

目标图恢复必须在一个受信图事务内切换新 incarnation、`activation=g+2`、恢复水位和图收据。普通 `GraphStore.cas_graph_recovery_metadata()` 继续禁止代际变化；新建只供迁移专用 scope 使用的 CAS，不放宽普通读写。旧 Owner grant、预算未来授权和 worker 资格须按目标代际重新签发，历史费用与已发收据保留。普通图读、模型外送、订阅、下载、采用和发送在 source recovering、revoked 与 target recovering 阶段都拒绝。

迁移 DTO/服务可新增 `v2_migration_contract.py`、`v2_migration_store.py`、`v2_migration_service.py`；V2 Fence 的普通 `begin_fence` 不得泛用签发或结束 migrate/recovery permit。管理授权绑定 mTLS 主体、安装/holder、目标配对身份及当前 channel；安装配对本身不授迁移权限。恢复证明须由可信安装/图验证器核验，不能采信客户端的 `verified=true` 或其自报文件路径。远端验证在服务锁外执行，回到短事务重新 CAS 同一状态。

## 验收顺序

先完成本地管理状态机、幂等和崩溃窗口；再接 mTLS/客户端、W01 源快照与目标恢复；最后跑 S15 双进程源旧备份与目标新代际的真实读/外送/派发负例及目标正例。需覆盖活 fence 时 begin 返回 busy、源封存窗口并发写、各阶段丢 ACK、目标图已提交但 Authority 未 activate、旧快照与较新删除/执行日志、篡改水位/图收据、未授权管理端和 Authority 不可达。双进程夹具不等于物理跨设备或正式包冷安装。
