# G6 GraphStore 合成规模软件基线（2026-09-28）

状态：**局部软件基线 PASS；G6 正式验收 HOLD**。本页只记录当前 Windows 进程中对真实 `GraphStore.graph_commit`、`graph_snapshot`、`graph_query` 的合成负载。它绕过生产 `GraphCoordinator` 的 Authority/Owner 读写围栏；不测模型质量、真实 provider 费用、平台积压或 OPS-09。工作树为 dirty tree，没有冻结候选包。

可复跑脚本：[g6_graph_scale_probe.py](../../../../rewrite/tests/alpha1/integration/g6_graph_scale_probe.py)。每个规模须在**独立 Python 进程**运行；脚本临时建库、固定按索引生成来源、断言原子与事件数，结束后删除临时 DB。每 128 条提交一个图事件；随后按固定索引重放原事件、纠错 1% 来源、做 64 次单键快照、64 次七日交叉快照和 64 次 128 条分页查询。P50/P95 使用采样时长排序后的 nearest-rank 值，单位毫秒；批写的值是**每批**，不能当单条 P95。峰值内存取 Windows 进程 `peak_wset`，包含导入与 Python 运行时。

本轮先运行 `python -m py_compile rewrite/tests/alpha1/integration/g6_graph_scale_probe.py`，再在 `G:\Sylanne` 执行：

```powershell
$env:PYTHONPATH='rewrite'
python -m rewrite.tests.alpha1.integration.g6_graph_scale_probe --size 1000 --output G:\Sylanne\.codex-task-temp\g6-graph-scale-1k-20260928.json
```

命令退出码 0，JSON `status=completed`；本轮最终有效报告时间为 **2026-09-28 02:37:30 UTC**。原始本地报告只用于复核，不进入源码或构件。测量段耗时 0.447 秒（不含 Python 启动与指纹采集），数据库 1,982,464 字节，进程峰值工作集 45.3 MiB。完整性断言：1,000 个当前原子、18 个提交事件（8 批写 + 10 次纠错）、10 个不同纠错键；10 次原事件重放没有增加事件。

| 操作 | 样本数 | P50 ms | P95 ms |
| --- | ---: | ---: | ---: |
| 128 来源批写 | 8 | 13.003 | 14.542 |
| 原事件重复提交 | 10 | 3.484 | 4.135 |
| 单来源纠错提交 | 10 | 1.147 | 1.414 |
| 单键快照 | 64 | 0.038 | 0.051 |
| 七日交叉键快照 | 64 | 0.136 | 0.180 |
| 128 条分页查询 | 64 | 2.232 | 2.745 |

负载生成器 `index-arithmetic-v1` 的初始来源 SHA-256 为 `d69919568b0129a0105e24de340255a656d8a7a82116aaaf36cf1e5de7fbfc76`。进程指纹：Windows 11 build 26100、AMD64 Family 25 Model 68、16 逻辑 CPU、15,613.1 MiB 总内存、Python 3.13.14、SQLite 3.50.4、psutil 7.1.3、PID 以原报告为准。Python 位于 WindowsApps alias，二进制不可读，因此 executable SHA-256 为 `null`；路径与版本仍在原报告。Git HEAD `72c9235bf025b66e0a83f02d34661a32abd3250b`、`tracked_tree_dirty=true`、`metadata.yaml` SHA-256 `fdb5df7a0a3620ab5584408000c963d93462b24d761af4555d02cf6c440f11c2`。关键源码 SHA-256：`graph_store.py` `85ac7262cc31b7e7c1a90bbf4ce7cd2525d7546a9a66c6a557e62dd41940b2f4`、`graph_types.py` `1473c8988fb30612d642281a12c9b3e1ad130903bafba903287e84d4ae7f4365`、探针脚本 `059addaa6da85880f3373227f2119569b609a1cd13021b5bdedc5efc82168528`。正式包 SHA-256：**无**。

## 后续同源码 1k/10k/100k 软件梯度

在媒体 GraphStore 修改后，另以**三个独立 Python 进程**运行同一脚本 `--size 1000/10000/100000`，三项均退出 0、`status=completed`，各自临时库在结束时删除。三个报告的 `graph_store.py` SHA-256 均为 `bb792d25fb77cf042a1169b37acd336ae24830865b83d20d4131bbad2a77fb7d`，`graph_types.py` 与脚本指纹也一致；这组成同一 GraphStore 源码的软件梯度。原始 JSON 留在忽略目录 `dist/g6-1k-software-current-20260928.json`、`g6-10k-software-20260928.json`、`g6-100k-software-20260928.json`，未纳入插件包。

| 来源数 | 批写 P50/P95 ms | 分页 P50/P95 ms | 测量耗时 s | 进程峰值 MiB | DB bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 12.327 / 13.699 | 2.107 / 2.834 | 0.824 | 64.1 | 2,076,672 |
| 10,000 | 13.033 / 26.993 | 2.400 / 3.921 | 2.625 | 144.0 | 13,750,272 |
| 100,000 | 13.026 / 30.300 | 2.232 / 2.943 | 16.609 | 70.3 | 130,502,656 |

峰值工作集是 Windows 对**各独立进程**的测量值，可能受运行时页驻留与同时运行的宿主任务影响，不应把 100k 的 70.3 MiB 解读成比 10k 更省内存的算法定律。100k 完整性断言为 100,000 个原子、1,782 个事件；初始数据 SHA-256 为 `ff413706c6ada058f153749e9cb455f01f365b7444e13838346cc37c5e05ae80`。当前内存预检未放宽，三个规模均按原阈值完成。

正式 G6 仍 HOLD：本梯度是 dirty tree 的直接 GraphStore 合成基线，不含生产 Authority/GraphCoordinator、同一候选包、模型/平台真实费用与积压、OPS-09 四对照及消融，也未预先冻结产品可用性阈值。旧 02:37 UTC 的 1k 表是不同 GraphStore 字节的历史基线，不与上表拼接。
