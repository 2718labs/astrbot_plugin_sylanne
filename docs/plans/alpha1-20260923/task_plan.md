# alpha1 工作包与整合计划

2026-09-23。依据 [architecture-gate](architecture-gate.md)。目标是完整 `embodiment-3.0.0-alpha1`；本文件规定实施分工与验收边界。W00、W02 的受限增量及部分领域代码已经开始落盘，各包的实现与产品验收必须分开记录。2026-09-24 用户要求暂停远端 push，先在本地冲刺；设计文档仍留本地，模块 PR、合并与发布分别按实际验收和原授权边界处理。2026-09-27 平台验收收敛为一处 Windows 实机完整链路，Linux/macOS 主要核验当前 Rust 原生内核构建、加载和代表性求解；Rust 暂保留为数值核，十三域逻辑仍用 Python。平台运行证据边界见 [平台矩阵](acceptance/platform-matrix.md)。

2026-09-28 用户进一步要求本轮完成 alpha1 的**全部非前端部分**。W11 客户端及键盘、窄屏、读屏的界面验收暂缓；W10 工作台服务、D12 服务端权威、十三域、宿主、原生核、恢复、规模与后端构件仍在本轮范围。历史 G4/T01–T40 清单继续保留，但需把服务端可验项和待前端项分别标记，不能以 W11 未做冒充整套 UI 已通过，也不能把 backend-only 开发探针标成完整正式 alpha1 包。该范围变更不授予远端 push、PR、合并或发布权限。

## 工作包唯一文件写者

`R = rewrite/sylanne3`。以下目录为计划路径；不存在时由对应写者创建。每个包只准一名活动写者，共享文件不能由多个代理同时编辑；测试目录也按包独占。主任务协调验收与接口裁决，常规实现/补漏采用低一档执行代理；重大战略冲突才交 Astra high，不覆盖用户显式模型设置。

| 包 / 写者角色 | 唯一路径 | 交付内容 / 前置门 |
| --- | --- | --- |
| W00 公共合同 | `R/runtime_contracts.py`、`R/graph_types.py`、`rewrite/tests/alpha1/contracts/` | P0 DTO/Protocol、schema/hash、能力与错误枚举、旧类型迁移边界；先出可导入合同。写完移交冻结版本。 |
| W01 图与耐久协调器 | `R/graph_store.py`、`R/graph_runtime.py`、`R/store.py`、`R/runtime/`、`R/runtime_journal.py`、`rewrite/tests/alpha1/runtime/`、`rewrite/tests/test_runtime_journal.py` | 目录/权限/事务、双日志与锚、预算/job/时钟、admission/恢复/迁移；消费 W00。`R/runtime/` 不含 native/model/host 子包，避免路径重叠。 |
| W02 数值与算子 | `R/native.py`、`R/operators.py`、`R/native_runtime/`、`rewrite/native/src/`、`rewrite/native/Cargo.toml`、`rewrite/native/Cargo.lock`、`rewrite/tests/alpha1/numerics/` | ABI 2 稀疏非线性/误差/取消、目录能力验证、可信 manifest loader；W00 后可与 W01 并行。ABI 1 专项参照隔离。 |
| W03 记忆 | `R/memory_*.py`、`R/recall_policy.py`、`R/domains/d06/`、`rewrite/tests/alpha1/d06/` | D06 全来源/检索/回忆组合/修订/删除/transfer；W00 后编码，W01 后真实事务验收。 |
| W04 基础主体 | `R/domains/d01/`、`R/domains/d02/`、`rewrite/tests/alpha1/d01/`、`rewrite/tests/alpha1/d02/` | 人格连续性/成长、自传提案与身体/劳动资源；单写者兼两域，语义独立。 |
| W05 社会情境 | `R/domains/d03/`、`R/domains/d05/`、`rewrite/tests/alpha1/d03/`、`rewrite/tests/alpha1/d05/` | 稳定实体/事件/视角/RoleBinding 与分对象关系/边界/贡献。 |
| W06 情绪认知 | `R/domains/d04/`、`R/domains/d07/`、`rewrite/tests/alpha1/d04/`、`rewrite/tests/alpha1/d07/` | 连续感受/调节、Concern/焦点/反思/模拟与 D06 合法联合提交；接口可先行，W02–W05 集成后验收。 |
| W07 行动生活 | `R/domains/d08/`、`R/domains/d10/`、`rewrite/tests/alpha1/d08/`、`rewrite/tests/alpha1/d10/` | 目标/承诺/联合计划、活动/习惯/时钟提案、ContactPolicyCheck；依赖 W03–W06 合格视图及 W01 收据。 |
| W08 表达 | `R/domains/d09/`、`rewrite/tests/alpha1/d09/` | 表达蓝图/语言核验/分段/中断；依赖 W07 冻结行动 schema，不直接调平台。 |
| W09 宿主模型总装 | `main.py`、`R/runtime_context.py`、`R/domain_registry.py`、`R/model_broker/`、`R/host/`、`R/application.py`、`R/delivery.py`、`R/scheduler.py`、`R/contracts.py`、`R/semantics.py`、`rewrite/host_tests/alpha1/` | 根入口/十三域装配、供应商/平台/工具适配、生命周期；保留必要兼容但生产不路由旧 fixture。W00 可先写适配，G0/领域闭环后开放。 |
| W10 工作台服务 | `R/domains/d12/`、`R/workbench_api/`、`rewrite/tests/alpha1/d12/` | 登录/领域命令/投影订阅、创作/实验/数据与升级操作；基础权威全部调 W01，不复制执行日志/迁移服务。 |
| W11 工作台客户端 | `webui-src/`、`rewrite/tests/alpha1/workbench/` | 新 UI 全页面/状态/键盘/窄屏/读屏；依 W00/W10 API，契约替身只用于开发，不作验收数据。 |
| W12 交付整合 | `metadata.yaml`、`_conf_schema.json`、`resources/`、`R/_native/`、`release-manifest.json`、`scripts/alpha1/`、`rewrite/tools/build_plugin_package.py`、`rewrite/tests/alpha1/release/`、`rewrite/tests/test_plugin_package.py` | 配置映射、可信发布清单、资源构建/打包/排除/平台矩阵；源资产与生成构件分开，原生构建物不提交。W09 提配置 schema 需求，W12 唯一改根配置。 |
| W13 验收证据 | `docs/plans/alpha1-20260923/acceptance/`、`rewrite/tests/alpha1/integration/` | 62 项运行映射、S01–S16/OPS-10、规模/对照/冷安装证据摘要；只报告实际运行。原始含私密日志放受控数据区，不提交。 |
| W14 短期上下文 | `R/domains/d13/`、`rewrite/tests/alpha1/d13/` | D13 独占压缩块编译/验收/待用激活/本轮短期片选择；消费 W00 的合同与 W03/W05/W08/W01 的合格投影，物理存储/模型外送仍由 W01/W09 负责。先做无模型原文与确定性折叠闭环，后接有界异步模型压缩。 |

`R/domains/__init__.py` 仅 W09 写；各域目录内注册函数由各域写者导出，W09 集中装配。未列文件不默认归任何包，需要主任务指定。旧 `R/engine.py`、demo 和旧 UI/pages 不作为新产品实现入口；需要退役包装时由主任务明确分配，不能顺手清理。并行活动最多按可用代理槽与内存预算调度，不要求同时启动全部包。

## 批次与交接闸门

1. **B0 / 合同。** W00 先落 DTO/Protocol、schema hash、错误分类；W01/W02/W03/W09/W10 针对自身消费边界各确认一次。先 Python 导入/编译和边界编码校验，禁止后续代理自行更名共享字段。
2. **B1 / 可安全接域。** W01、W02、W03 并行；余槽 W04/W05，W11 可依 API 做界面结构。W01 权限/事务/双日志/预算/恢复故障门先过，才允许真实域采用和出站；W02 编译后跑数值必要独立参考，不能只 cargo check。
3. **B2 / 角色认知。** 接入 W04/W05/W03，再接 W06 和 W02；核对来源更正、真实感受、回忆、人格/关系贡献各自归属。共享图没有域旁路；测试替身不能签发必查 pass。
4. **B3 / 行动与上下文闭环。** W07/W08/W14 接 W09；检查合格意图→D13 可选近期对话片＋D06 精确证据/领域硬检查→表达/工具→final admission→执行日志→观测→D06/D08/D10 结算，以及多段 unknown/无回应门。真实宿主集成所需配置由 W12 接收。
5. **B4 / 产品。** W10/W11/W12 完成真实领域 UI 与生命周期、包路径和可信 loader 对接；工作台九类页面、实验、搬迁、升级、删除均可操作。先构建候选包供冷安装，不提前标交付。
6. **B5 / alpha1 验收。** W13 执行 architecture-gate G0–G7，逐项收据与哈希；主任务核验当前 source/config/包 fingerprint 与报告一致。未通过项留 HOLD，不删需求或借旧测试数字宣告完整。

每次交接先编译受影响 Python/Rust/前端，再跑一组覆盖本次不变式的必要测试。公共合同变动由 W00 单写者修订并通知全部消费者；域内部变化只重验相邻合同。无需无理由重复全套历史测试。

## 集成、发布与未验证项

这里的“合并闸门”首先指本地代码整合：路径所有权无冲突、依赖合同版本一致、编译通过、必要反例通过、读写权限与真实/模拟资格无旁路、证据可追溯。当前 checkpoint 只做本地提交，不推送远端；模块 PR 的共同 base 固定 `codex/embodiment-3-rewrite`，不能默认 main。创建模块 PR、合并和发布需分别依据授权与验收，不由 checkpoint 代替。

正式候选版本只在 G0–G7 全部通过后冻结为 `3.0.0-alpha1` 的确切包 hash；任何十三域/工作台/原生包/真实宿主门缺失均不具备交付资格。发包前由 W12/W13 填真实平台、宿主/Python 最低版本与测试版本、信任根来源、迁移权威部署、硬件/模型/预算阈值；这些尚未验证，不可由当前 metadata 推定。

后续手动验收重点：普通用户无 Rust 冷安装，创建/绑定真实私聊与群聊，执行 OPS-10 连续轨迹、纠错和来源撤权，多段中断/unknown 后重启，实验无副作用，旧备份恢复不复活删除和发送，搬迁后旧源只读请求也被拒，以及键盘/读屏完成删除与恢复。真实平台发送由测试操作者在获授权场景执行并记录收据；缺环境或资格应保持 HOLD，不能使用模拟收据替代。

本次策略文档完成后停止战略扩展；编码代理以 B0 开始。计划不意味着任何工作包已实现。

## AstrContinuum 能力内建补充（2026-09-27，本地设计）

[Sylanne API 侧虚拟 KV 上下文压缩设计 v8](astrcontinuum-for-sylanne.md) 与[十三域耦合总装](../../architecture/sylanne-3-thirteen-module-coupling.md)纳入本轮 alpha1：W00 冻结 `ConversationWindowProjectionV1/ShortContextRequestV1/CompressedTurnBlockV2/ShortContextSliceV1/ModelInputFrameV1`；W03 供应 D06 合格来源与删除闭包，W05 供应 D03 场景/受众版本，W08 供应 D09 已提交顺序/话题和表达消费者；W14 独占 D13 压缩块、稳定骨架/动态选槽、待用激活和 72 小时退役；W01 执行共享图作业、失效及物理缓存回收；W09 接不可变模型请求、显式 opt-in、供应商缓存能力与实际费用回执；W10/W11 展示授权覆盖、到期、缺口和输入/缓存费用；W13 将 C01–C12、D13 A01–A08 与 G6 对照纳入 G1/G3/G6 验收。约 60% 对话预算时有界后台预制，约 70% 前争取候选就绪，前台按窗口/费用条件无等待切换；这些比例是待 G6 验证的助手默认值。细节按本轮问题选择，单轮窗口和含压缩/缓存写入的累计输入费用同时受 D11 预算约束，三天外历史只通过 D06 记忆合同进入模型。独立 AstrContinuum 保留供其他机器人使用，Sylanne 只处理启用后的新会话；旧 Journal/Snapshot 迁移不进入 alpha1。此段只分配工作，不表示实现或通过验收，也不宣称能操作 API 服务端的真实 KV cache。
