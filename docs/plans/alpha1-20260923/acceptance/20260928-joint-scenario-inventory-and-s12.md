# 联合场景现有证据盘点与 S12 持久图故障切片

日期：2026-09-28。依据当前源码和测试文件的只读盘点；除本页末尾列出的命令外，表中既有测试**未在本次重跑**。测试文件存在只表示可复核的局部机制，绝不自动构成场景 PASS。当前 G3、62 项状态不变。

| 场景 | 当前可复核的代表性测试或轨迹 | 尚未接线的联合条件 |
| --- | --- | --- |
| S01 含糊回复 | `d03/test_message_arrival.py`、`d07/test_cognition_domain.py`、`d09/test_source_reply.py` | 同一输入下 D03/D04/D05/D06/D07/D09 的事实、感受、关系与表达对照 |
| S02 后续解释 | `runtime/test_source_correction_commit_v2.py`、`d07/test_source_correction_belief.py`、`d05/test_source_correction_reevaluation.py` | 同一更正对历史感受、关系、已发 effect 与补救的连续回放 |
| S03 两次回忆 | `d06/test_recollection_coordinator_commit.py`、`d06/test_affective_recollection_view.py`、`integration/test_s03_two_moods_recollection.py`；本地候选链证据见 `acceptance/20260928-s03-two-moods-candidate.md` | 两种心境下两次实际 C04 活动、一次外部事件及 D02/D11 结算同轨 |
| S04 承诺与疲劳 | `d02/test_body_domain.py`、`d08/test_goal_execution_domain.py` | 已确认承诺与 shortfall、D10 调度和 D09 合格改约同轨 |
| S05 A 未确认 | `d08/test_bilateral_acknowledgement.py`、`d03/test_prebatch_social.py` | A/B 多人视角、群抱怨与责任资格贯穿真实对话 |
| S06 私聊与群聊 | `d05/test_contribution_audience.py`、`authority/test_reply_qualified_egress_closure.py` | 同一私聊来源进入内部推理后，群聊文本与最终发送双重受众验收 |
| S07 首段已发后段失效 | `d09/test_verified_batch.py`、`runtime/test_dispatch_current_segment.py`、`authority/test_v2_cross_process_restore.py` | 两个独立 effect、首段实际交接、后段更正/插话停止及重启不重发的同一执行日志 |
| S08 主动分享 unknown | `runtime/test_dispatch_current_contact.py`、`d10/test_contact_proposals.py`、`authority/test_v2_cross_process_restore.py` | unknown 后新里程碑、原 contact 配额、旧备份和多段当前验源同轨 |
| S09 离线跨日 | `d10/test_offline_interval.py`、`d02/test_body_dynamics.py` | D03/D11 同一时钟、被动演化、真实产出与未观测回应的跨日回放 |
| S10 工作台改设定 | `d12/test_scheme_command.py`、`runtime/test_registry_scheme_gate.py` | D01/D02/D04 合法编译、D11 活跃方案切换与未提交任务重验 |
| S11 想象与现实 | `d07/test_cognition_domain.py`、`d08/test_goal_execution_domain.py` | 内部模拟与后来外部接受事件的来源、责任、关系结算隔离 |
| S12 余额恶化且执行未知 | `d02/test_body_domain.py`、本次 `integration/test_s12_resource_shortfall_graph.py` | D11 实际费用、D08 承诺/片段和宿主 unknown 收据仍未贯穿；本次仅持久图读取切片 |
| S13 私聊撤权在途 | `d06/test_source_access_revocation.py`、`runtime/test_current_model_egress_graph_verifier.py`、`runtime/test_dispatch_current_source_budget.py`；本地 HOLD 记录 `acceptance/20260928-s13-revocation-inflight-hold.md` | 撤权候选尚未由公开 GraphCoordinator 命令提交并串起同一模型/待发 effect |
| S14 旧备份删除 | `integration/test_s14_stale_graph_restore.py`、`authority/test_v2_cross_process_restore.py` | 主动联系 claim 早于备份、D10 配额/未决资源、全入口恢复隔离未同轨 |
| S15 旧设备复活 | `runtime/test_migration_runtime.py`、`runtime/test_restore_authority.py` | 源/目标真实设备的所有读、外送、订阅和发送及双日志最新性同轨 |
| S16 失败迁移/升级 | `runtime/test_authority_v2_deletion_migration.py`、`release/test_delivery_migration_resource.py` | 旧用户包、D12 预览、目录/ABI、升级失败回滚与冷安装同轨 |
| OPS-10 连续剧情 | 当前 `integration/` 是 D06 编码、Owner 签名链、S12/S14 切片；`host_tests/alpha1/` 有首次入站、回复、私聊派发等分段测试 | 设计规定的八步同一角色、A/B、私群权限、纠错、unknown、崩溃及新会话完整轨迹尚无单一可运行测试或确切包收据 |

## 本次 S12 定向执行

新增 `rewrite/tests/alpha1/integration/test_s12_resource_shortfall_graph.py`，SHA-256 `6AF8CDF0948C2DAECEF06017F9BF092759B138D29D5D09E75D401ACA9508FB24`。用真实 `GraphStore` 持久化 D02 状态与预留，通过真实 `GraphCoordinator.query` 重建 `CurrentResourceLedger`；图写入仅作受控夹具，不冒充生产 DomainBundle。先证明余额 0.8、既有预留 0.5 时新 0.1 劳动可准入；随后将原 effect 置为执行结果未知、余额降至 0.2，并在关闭/重开 SQLite 后读取。预留仍为 `pending_confirmation`，gross/encumbered/available/shortfall 为 `0.2/0.5/0/0.3`，新劳动被 `reservation_shortfall` 延期，原预留片段同样不能启动。读取收据带当前图 epoch 和两个修订版本。

```powershell
python -m compileall -q rewrite/tests/alpha1/integration/test_s12_resource_shortfall_graph.py
$env:PYTHONPATH='rewrite'; python -m pytest -q rewrite/tests/alpha1/integration/test_s12_resource_shortfall_graph.py
```

结果：编译退出码 0；pytest `1 passed in 0.93s`，退出码 0。此测试仅证明 D02 持久图与协调器当前读取的 S12 必要负例，**S12 整体仍 HOLD**。它没有真实宿主执行结果、D11 费用账或 D08 未发片段，不能说明完整资源与派发恢复资格。
