# S13 Owner 撤权后当前读取：W01 接口更新后的局部证据

日期：2026-09-28。本记录更新先前 `20260928-s13-revocation-inflight-hold.md` 的接口状态：W01 已新增 `GraphCoordinator.revoke_source_access_v1`。旧记录所述“缺少公开撤权命令”不再适用；**S13 联合验收仍 HOLD**。

## 本次执行

测试文件 `rewrite/tests/alpha1/integration/test_s13_owner_revoke_d06_read.py`，SHA-256 `84F025CA0634112C95196A95C16018A3D35AFD8C6CC0E9CDA5E366FB5D271197`。在 `G:\Sylanne` 执行：

```powershell
python -m compileall -q rewrite/tests/alpha1/integration/test_s13_owner_revoke_d06_read.py
$env:PYTHONPATH='rewrite;G:\Sylanne\.codex-task-temp\astrbot-v4.28.1-contract\wheel-unpacked'; python -m pytest -q rewrite/tests/alpha1/integration/test_s13_owner_revoke_d06_read.py
```

编译退出码 0；定向 pytest `1 passed in 1.09s`，退出码 0。`owner_graph` 夹具采用真实 `ProductionGraphStore`、`GraphCoordinator`、持久 SQLite 图与 W01 的 Owner 授权路径；Authority Owner port 是**受控进程内替身**。测试证明同一来源在撤权前可由 D06 `MemoryRepository.read_source_evidence` 当前读取；`revoke_source_access_v1` 提交 access revision 2 和递增的 access epoch 后，当前读取返回无内容，原 source revision 1 未被抹去；重复同一请求返回原收据。D06 仓库读取是直接图读取机制，不等同宿主模型外送。

此前完成的一组定向命令：

```powershell
python -m compileall -q rewrite/sylanne3/graph_coordinator.py rewrite/sylanne3/authority_service/current_model_egress_graph_verifier.py rewrite/sylanne3/runtime/dispatch_current_source_budget.py rewrite/tests/alpha1/runtime/test_source_access_revocation_owner_v1.py rewrite/tests/alpha1/runtime/test_current_model_egress_graph_verifier.py rewrite/tests/alpha1/runtime/test_dispatch_current_source_budget.py
$env:PYTHONPATH='rewrite;G:\Sylanne\.codex-task-temp\astrbot-v4.28.1-contract\wheel-unpacked'; python -m pytest -q rewrite/tests/alpha1/runtime/test_source_access_revocation_owner_v1.py rewrite/tests/alpha1/runtime/test_current_model_egress_graph_verifier.py::test_v2_binding_requires_current_epoch_and_exact_acquire rewrite/tests/alpha1/runtime/test_current_model_egress_graph_verifier.py::test_access_epoch_or_original_ceiling_change_holds 'rewrite/tests/alpha1/runtime/test_dispatch_current_source_budget.py::test_current_source_budget_gate_holds_on_revocation_reservation_or_expiry[revoke_access]'
```

编译退出码 0；pytest `7 passed, 1 warning in 8.46s`，退出码 0。warning 来自 `jieba` 的 `pkg_resources` 弃用。这七个测试包括 W01 的四个撤权写入正反例、两个模型图当前性检查及一个 dispatch 来源 epoch 门；它们运行于不同安装夹具，不能相加成一次 S13 端到端轨迹。

## 顺序与在途边界

本次同源集成证明“D06 当前读取 → 撤权落库 → 后续 D06 当前读取拒绝”的顺序，以及撤权请求幂等。模型外送和 final dispatch 的局部测试各自证明原有 guard 会在来源/访问版本漂移时 HOLD，但没有在同一真实 Authority 身份、同一业务图、同一模型 call 与未发 effect 上重复此顺序。也没有制造“模型请求已交接宿主”和“首段已交接、后段未交接”两种 in-flight 收据，因此不能宣称撤回已发外送、不能宣称真实平台未发送，也不能把 unknown 结果标为未发生。

W01 和 W09 当前均无已验证的真实 Authority Service、Owner 签名会话、模型调用与 dispatch 共享身份装配夹具。下一门需在同一安装上先取得撤权前 model/final-admission 正向资格，提交上述真实 Owner 撤权收据，随后证明迟到模型采用与未发消息派发被阻断；另记录撤权前已交接的外部/平台观测范围、费用和执行日志。受控 port 只能算接口局部证据。状态维持 **HOLD**，不改 62 项与 G3。
