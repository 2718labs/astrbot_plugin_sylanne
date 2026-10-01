# S14 旧业务图恢复后的内容读取屏障：局部证据

日期：2026-09-28。测试文件：`rewrite/tests/alpha1/integration/test_s14_stale_graph_restore.py`，SHA-256 `B66A5F09F3E3A5A4CF6BA54B4E352B3EF4E44CFA426AF7DD996DDE6F8E4AC713`。这是本地源测试证据，不是候选包或真实宿主验收。

## 执行

在 `G:\Sylanne`：

```powershell
python -m compileall -q rewrite/tests/alpha1/integration/test_s14_stale_graph_restore.py
$env:PYTHONPATH='rewrite'; python -m pytest -q rewrite/tests/alpha1/integration/test_s14_stale_graph_restore.py
```

结果：编译退出码 0；pytest `1 passed in 1.16s`，退出码 0。首次编写过程遇到未注册 Provider 和图表列数错误，已修正并重新编译、定向运行；最终通过结果对应上述哈希。

## 实际覆盖

测试建立真实 `ProductionGraphStore`、`GraphCoordinator`、`AuthorityServiceCore`、`AuthorityV2FenceService`、独立持久 `DeletionJournal` 与 `AuthorityV2ExecutionJournal`。受控进程内 Authority port 只转发真实服务调用。私密图记录由测试直接植入作为来源夹具，不代表生产 D06 入站已接通。

图的旧恢复锚允许正常读到夹具记录；随后使用 SQLite backup API 留下旧业务图，并在独立删除日志持久写入该记录的删除 intent。旧图恢复后记录仍物理存在，但 `GraphCoordinator.read_snapshot` 在内容返回前受 Authority 拒绝，且未进入后续 fence 验证。执行日志保持独立 genesis 水位，测试仅确认其存在和当前水位，没有推进执行 claim。

## 验收边界

这证明 S14 的一项必要负例：独立删除日志领先旧业务快照时，旧图不能重新开放内容读取。它**不构成 S14 PASS**：尚未在同一轨迹中覆盖旧备份早于 D10 主动联系 claim、执行日志的未决 effect/约束足迹合并、资源与 contact 配额、下载/订阅/模型/派发全入口、恢复隔离预览，以及真实 AstrBot 宿主。也未验证任意磁盘同时回滚全部独立锚时的外部最新性证明。当前 62 项账与 G3 状态保持不变。
