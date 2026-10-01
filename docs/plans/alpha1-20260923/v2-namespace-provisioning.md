# Authority v2 namespace 首次建库裁决

2026-09-23。此文件裁决空 namespace 的生产初始化顺序；它是实施合同，不是已通过验收。

## 当前阻断

`GraphCoordinator._check_guard` 要求 scheme、operator、policy、activation 的持久版本和真实父预算租约。现有 v2 模式关闭了 v1 管理写口；若先写这些旧行，`GraphStore.install_graph_recovery_genesis` 又会因 namespace 已有未封存历史拒绝。不能用直接 SQL 填行解除阻断。

## 唯一初始化操作

新增安装级 `provision_namespace_v2`，只接受管理员配对安装、已核验的目录/方案/政策版本和经 D11 核验的根预算政策。安装身份先调用 Authority 的显式 `namespace_genesis`；Authority 唯一签发激活代际并核对独立删除/执行日志零头。随后在**同一 v2 write fence** 内建立业务库。Authority RPC 在业务图锁外；业务库的所有初始写入在**一个 SQLite 事务**内完成：

1. 以稳定操作 ID 和规范摘要核对持久幂等收据；异摘要拒绝。
2. 重新核对无恢复元数据、无该 namespace 的历史行；无角色归属的旧时钟行继续阻断。
3. 从当前 Authority anchor 写入零头 `SnapshotRequirementsV2`。不可从业务快照自报现行水位。
4. 写经安装核验的 scheme/operator/policy 版本；activation 版本只是 Authority 事实的本地投影。
5. 通过 D11 原语建立真实根预算租约和必要的签名 grant，不自造默认额度或 D02 资源 quote。
6. 写安装操作的 ID、摘要、结果和图恢复 revision；整体提交后才在图锁外结束 fence。

`install_graph_recovery_genesis` 当前自行开事务，应提取一个仅协调器能力可调用、要求已有事务的 locked 原语，保留原有空库与零头校验。不能放宽 `_has_namespace_history`，也不能把通用 v1 管理写口重新开放。后续 guard 更新和子预算分配使用单独的 v2 授权业务操作。

Authority 和业务库不能宣称跨库原子。若业务提交或 finish 的响应未知，只按原操作 ID、摘要和同一 fence 请求标识对账；不能重复建根预算或换新 ID。业务已提交但 fence 尚未确认时保持停服。实例内重试记录不解决进程崩溃后的遗留 active fence，冷重启恢复须有持久化合同或管理员可审计恢复流程。

## 验收与保持阻断

至少验证：任一步失败无部分业务行；同请求重试不增加额度；异摘要拒绝；并发 fence 竞争不改业务库；提交后收尾响应丢失能以原请求对账；任一旧历史、伪版本或未经授权的预算均拒绝。测试夹具只能证明软件机制，不能替代真实安装政策。

已有历史却无恢复元数据、非零或不一致日志头、旧时钟归属不明、跨代/跨 incarnation、缺真实 D11 政策或安装方案时，继续 HOLD。此初始化操作不解除 dispatch、删除 accepted/closed、十二域和平台冷安装等门。
