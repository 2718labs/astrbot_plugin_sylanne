# S03 同一来源、两种心境回忆：候选链局部证据

日期：2026-09-28。测试：`rewrite/tests/alpha1/integration/test_s03_two_moods_recollection.py`，SHA-256 `B85B6A3EC04E16EE75B35AE02A0B4DE3A6C5EBE64814AD69305FF221225E40E3`。本次为本地 Python/SQLite 机制测试，**S03 整体仍 HOLD**。

## 执行与观察

```powershell
python -m compileall -q rewrite/tests/alpha1/integration/test_s03_two_moods_recollection.py
$env:PYTHONPATH='rewrite'; python -m pytest -q rewrite/tests/alpha1/integration/test_s03_two_moods_recollection.py
```

编译退出码 0；定向 pytest `1 passed in 1.47s`，退出码 0。没有重跑其他测试或全套。

受控夹具只把一条原始外部来源和 D04 mood 写进真实 SQLite `GraphStore`。测试从 D06 `retrieve_candidates` 实际检索来源，由 D07 `select_bounded_recollection` 生成两个不同 activity 的选择票据，并由 `GraphCoordinator.read_snapshot` 分别读取 revision 1 和 2 的心境。D06 `prepare_affective_recollection` 实际回源并重验来源/访问/心境。两次结果保留同一个 `source_ref` 与同样的来源字段，主观 tone/weight 随心境改变，且结果明确是 `candidate_hold`。图中外部来源仍只有一条。随后将访问状态经受控图写入改为 `withdrawn`，D06 当前来源读取不再返回内容。

## 未证明范围

图写入是测试夹具，尚非生产 `DomainBundle`。D07 选择票据未提交为独立活动收据；D04 心境来自受控图写入而非完整产品数值/来源资格；两次 C04 回忆及体验没有由 GraphCoordinator 原子采用；D02 实际劳动和 D11 模型费用没有真实结算，未执行真实宿主或自然语言表达。因而不能把两条候选算作“两次实际回忆”，也不能宣称 S03 PASS。下一门需同一来源下两次 C04 全必要写集、不同当前心境、一个外部事件计数及独立费用/活动收据的连续可回放提交。
