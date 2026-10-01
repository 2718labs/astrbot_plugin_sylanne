# S13 来源撤权与在途模型、未发消息：集成 HOLD

日期：2026-09-28。此记录只反映当前本地源码和执行环境；**S13 未通过**。未修改 62 项或 G3 状态。

## 所需的同一条轨迹

先以同一 `GraphCoordinator`、真实 Authority、业务图和独立删除/执行日志建立私聊来源、在途模型调用及未发段，确认撤权前模型与派发确有合法资格。然后通过公开的 D06 来源访问撤权命令提交新版本，并检查模型外送、迟到结果采用、最终派发都在当前来源核验处停止，保留已经交接的未知边界和真实费用。没有撤权前的正向资格，撤权后的拒绝不能归因于撤权。

## 当前可复现的阻断

`rewrite/sylanne3/graph_coordinator.py` 当前公开的是 `commit_source_correction_v1`，没有来源访问撤权提交入口。`rewrite/sylanne3/authority_service/core.py` 的 `revoke_source` 是搬迁时撤销源设备代际，并非 D06 私聊来源访问撤权。现有 `test_current_model_egress_graph_verifier.py` 的 `token_ingress_system` 使用测试 AuthorityPort 和合成恢复锚；模型外送服务 `prepare_fenced` 要求 draft 与真实认证 Authority anchor 完全一致。直接拼合会在撤权前因身份不一致 HOLD，不能测 S13 因果。现有 dispatch 来源预算测试也使用另一套单独安装夹具。需要由总装提供同一来源/锚/模型/dispatch 身份的生产装配和撤权命令，或明确版本化桥接合同。

本机执行的复现实验（`G:\Sylanne`，未运行 `rg.exe`）：

```powershell
python -m compileall -q rewrite/sylanne3/graph_coordinator.py rewrite/sylanne3/authority_service/current_model_egress_graph_verifier.py rewrite/sylanne3/authority_service/v2_model_egress_service.py rewrite/tests/alpha1/runtime/test_current_model_egress_graph_verifier.py rewrite/tests/alpha1/authority/test_v2_model_egress_store.py
$env:PYTHONPATH='rewrite'; python -m pytest -q rewrite/tests/alpha1/authority/test_v2_model_egress_store.py::test_fenced_prepare_is_atomic_and_recoverable
$env:PYTHONPATH='rewrite'; python -m pytest -q rewrite/tests/alpha1/runtime/test_current_model_egress_graph_verifier.py::test_v2_binding_requires_current_epoch_and_exact_acquire
$env:PYTHONPATH='rewrite'; python -m pytest -q 'rewrite/tests/alpha1/runtime/test_dispatch_current_source_budget.py::test_current_source_budget_gate_holds_on_revocation_reservation_or_expiry[revoke_access]'
```

结果：编译退出码 0；Authority 持久模型 prepare 测试 `1 passed in 1.20s`。初次运行后两条在 pytest 收集阶段失败，均为 `ModuleNotFoundError: No module named 'astrbot'`。总装随后提供隔离解包的确切 AstrBot 4.28.1 wheel，正确 Python 包目录是 `G:\Sylanne\.codex-task-temp\astrbot-v4.28.1-contract\wheel-unpacked`。未安装到当前 Python；使用该目录后补跑：

```powershell
$env:PYTHONPATH='rewrite;G:\Sylanne\.codex-task-temp\astrbot-v4.28.1-contract\wheel-unpacked'; python -m pytest -q rewrite/tests/alpha1/runtime/test_current_model_egress_graph_verifier.py::test_v2_binding_requires_current_epoch_and_exact_acquire rewrite/tests/alpha1/runtime/test_current_model_egress_graph_verifier.py::test_access_epoch_or_original_ceiling_change_holds 'rewrite/tests/alpha1/runtime/test_dispatch_current_source_budget.py::test_current_source_budget_gate_holds_on_revocation_reservation_or_expiry[revoke_access]'
```

结果 `3 passed, 1 warning in 7.72s`，退出码 0。警告为 `jieba` 引入已弃用的 `pkg_resources`。这三个既有测试仍是**分开的局部门**；wheel 只解决导入，不提供真实 QQ 或同一 S13 联合轨迹。

## 待总装解除

提供来源访问撤权的合法图事务入口，以及同一真实 Authority 安装身份下的模型请求和未发 dispatch 构造/观测入口。随后先验证撤权前两条正向资格，再提交撤权并单次运行跨域负例。隔离 wheel 可供合同测试，但真实平台行为仍需另验。当前没有新增 S13 PASS 测试，避免将三个局部门写作跨域验收。
