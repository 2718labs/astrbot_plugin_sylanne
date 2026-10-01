# Authority v2 生产启动合同

2026-09-23，主任务工程裁决；不是用户另行确认的产品语义，也不是已实现/验收声明。目标为完整 `embodiment-3.0.0-alpha1`。本合同接续 [v2 耐久栅栏](authority-v2-fence.md)，取代把 v1 enrollment grant 当运行许可的接线方式。

## 两层状态

安装层只在管理员绑定的 mTLS 身份、受信包身份、服务能力版本、全部必需运行适配器和宿主生命周期均可用时标 `host_ready`。`host_ready` 不保证每个角色可读写。每个 namespace 单独处于 `unbound / recovering / active / unavailable / quarantined`；只有 `active` 且当前 v2 fence 获准的操作能接触内容。Authority 不可达时关闭其管辖 namespace 的内容路径。删除/执行日志服务、完整十二域、模型/派发/工作台适配器缺失属于安装能力缺失，不能降级为某一角色的局部故障。

安装握手与 grant 使用单独版本化 v2 DTO，绑定协议、mTLS 主体、Authority ID、管理员映射的 installation/holder、实际受信 manifest 摘要、publisher policy、服务能力版本及当前 TLS channel binding。安装 grant 不携带可供所有角色复用的 activation generation，也不因聊天配置自报的 holder/manifest 获得授权。客户端核对实际受用文件与受信 manifest；仅对 manifest 文件求哈希不足以证明其他代码和原生资产。

`namespace_bootstrap(namespace)` 在服务端固定删除日志→执行日志→Authority 短事务锁序下返回 holder、generation、activation phase、完整当前锚及删除/恢复阻断状态。它只证明一次读取时的事实；每次内容读写、模型外送和派发仍须申请同 namespace 的活 v2 fence。空角色初次激活、迁移与恢复由专用幂等管理命令办理，不因查询时发现空 namespace 自动签发 generation。多角色服务端按受认证 namespace 解析到各自服务对象，不能把现有单 namespace `_v2_fences` 复用为通用权威。

## 运行端口与线程边界

W00 先冻结 `InstallationGrantV2`、`NamespaceBootstrapV2`、`NamespaceRuntimeState`、`ContentFencePortV2`/显式 `FenceScope`、`SnapshotRequirementsV2` 及执行/删除 mutation 端口。`FenceScope` 含实际 permit、epoch/revision、pinned anchor；协调器的准入、恢复核验与最终提交必须复核同一 scope。服务追加执行日志后返回的新 revision/anchor 替换旧 scope；旧 revision 不得再放行外送。普通 read/write scope 无权推进独立日志。业务快照的 Authority/日志身份、序号、摘要、generation、revocation 和 incarnation 随图事务一同更新。

宿主 async 入口只 await 有界图工作队列。同步 `GraphCoordinator` 在图 worker 运行；同步 Authority adapter 把 RPC 投递到独立 I/O loop，仅由图 worker 有界等待，禁止宿主 event loop 上阻塞等结果或临时 `asyncio.run()`。服务端同步 dispatch/fsync 同样交由有界 worker，连接会话状态留在所属 loop 或受同步保护。取消宿主 await 不等于图/外送已停止；真实工作结束或恢复判定前不得提前 finish fence。获取耐久 fence → 图锁/事务 → 纯服务核验 → 图提交或读完 → 释放图锁 → finish；服务锁内不能回调图。

## 尚未解除的阻断

当前已有管理员绑定的 v2 安装 grant、namespace bootstrap 状态读取及 mTLS 双端交换；它们都不签发内容许可，也没有激活全局 generation。远程 dispatch、执行日志两阶段 mutation/精确恢复、删除闭环、v2 activation/migration、生产多 namespace 服务装配、显式 permit 贯穿协调器、真实 D06/D11 屏障与清理证据均未完成。D04 的显式 `AffectScheme` 注入仅是单方案开发接缝；生产活跃方案须按角色由 D12 原子采用版本决定。不能用 v1、进程内测试夹具、可调用性检查或单个绿测试把全局状态改为 ready。

验收至少包括：真实 mTLS 下 A 角色 active、B 未绑定时隔离；暂停图读/写时另一主体在日志追加前被拒且宿主/服务 loop 不阻塞；执行/删除日志 fsync 后 Authority CAS 前中断，重启后原 mutation 精确恢复、异摘要/旧 revision 拒绝，unknown 不产生新 effect。候选包冷安装、真实宿主和平台收据另按 G0–G7 记录。
