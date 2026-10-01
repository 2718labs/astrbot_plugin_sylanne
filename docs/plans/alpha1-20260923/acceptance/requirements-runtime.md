# alpha1 运行验收账

截至 2026-09-23；只记录可复核的**当前运行**验收。`OPEN` 表示没有可用于
alpha1 的纵向运行证明；`PARTIAL` 表示存在历史或本轮受控切片，仍须对最终源码、
宿主和目标包重验。设计覆盖账的 62 项均为 `DESIGN`（M-06 为 `REVISED`），因此
设计映射、文档检查和类型存在均不得把任何行标为 `DONE`。

2026-09-27 当前口径覆盖下方历史快照中的平台范围：完整插件实机纵向验收先在一处
Windows x86_64 环境完成；Linux x86_64 与 macOS arm64 本轮主要验当前 Rust 原生核
构建、加载、原生测试和代表性求解。该平台门不替代十二域、G2 数值产品采用或其余
G0–G7 验收。下方按 2026-09-23 记录的“能力位均为 0”也已过时：ABI2 可条件性给
数学证书位，但 D04 产品读出仍 HOLD。历史命令、SHA 和收据仍按原日期保留。

历史锚点：`rewrite/artifacts/verification-20260922T124852.309287Z.json` 记录 173
个 Python 测试与 `compileall`；`host-verification-20260922T124852.707557Z.json`
记录 AstrBot SDK 4.28.1 的受控 adapter 测试和源码哈希。它们证明的是旧
Store/Engine/Graph/Memory/adapter 切片，不是实际 bot、外部模型、完整十二域或
alpha1 安装包。每次更新 `PARTIAL` 必须附当前 commit、源码哈希、命令、宿主版本
和收据；只有本表所列完整证明齐备才可改为 `DONE`。

## 裁决与共同门槛

- 目标路径以 `architecture-gate.md` 为准：`main.py -> RuntimeContext ->` 各域合法
  proposal -> `DomainBundle` -> D11 final admission -> 唯一 dispatcher；本轮
  `main.py` 已移除旧 `Application -> Engine` 入口，但真实纵向处理与独立权威未接通。
- M-06 的旧“必经五阶段状态机”已由用户后续裁决替代：验收连续、对象化的混合情绪
  和即时/持续/心境资源/元评价/调节恢复功能，**不**再验五阶段转移图。D04 仍为 OPEN。
- 所有 `DONE` 都还需要：冻结版本的十二域注册目录、静态旧核心禁用扫描、目标平台
  冷启动，及相关纵向收据；只有单元测试或本地 SQLite 不足以证明产品。

| ID | 现状 | alpha1 完成所需的具体运行证明 |
|---|---|---|
| R0-01 | PARTIAL：当前受控 AstrBot 4.28.1 SDK 入口，未激活。 | 目标包冷启动根 `main.py`，追踪 RuntimeContext 唯一路径；禁用旧导入扫描和现场日志。 |
| R0-02 | PARTIAL：历史 Store/Graph 原子切片。 | 跨域非法旁路写拒绝、读写集/投影回源和跨 Owner bundle 收据。 |
| R0-03 | OPEN。 | 十二域纵向剧情、配置/诊断/迁移/分发/现场矩阵全部通过。 |
| R0-04 | PARTIAL：历史调度/数值探针。 | 固定宿主负载下四预算、四误差、三时钟的指标和可回放收据。 |
| R0-05 | PARTIAL：历史算子拒环切片。 | 注册元数据、停止/恢复、未认证循环拒绝和数值证书边界测试。 |
| M-01 | OPEN。 | 七同源视图建图、交叉引用、版本/来源回放，并证明没有第二权威库。 |
| M-02 | PARTIAL：历史 namespace/Owner 切片。 | 跨会话场景回放、越权拒绝、角色生命周期和迁移审计。 |
| M-03 | OPEN。 | Concern 去重、冷却重激活、归档和跨会话承诺回放。 |
| M-04 | OPEN。 | 价值/社会场景行为对照、版本迁移、独立经历学习与重放去重。 |
| M-05 | OPEN。 | 多分量单变量干预、反证隔离、调节和行动合同读出。 |
| M-06 | OPEN：旧五阶段机已废止。 | 连续混合情绪功能的干预、恢复成本、终止与不伪造事件回放。 |
| M-07 | PARTIAL：历史来源/解释失效切片。 | 错误撤回后的贡献重建，经历/已发/真实消耗/模拟隔离审计。 |
| M-08 | OPEN。 | 对象-领域-场景关系隔离、注册传播和私密性纵向回放。 |
| M-09 | OPEN。 | 隔离反事实快照、预算耗尽、分支不写真实关系/自传。 |
| M-10 | OPEN。 | 硬约束与偏好分离、候选比较、发送前资格重检。 |
| M-11 | OPEN。 | 项目暂停恢复、真实产出收据和离线有限推进回放。 |
| M-12 | PARTIAL：历史 DAG/延迟/增量切片。 | 联合 SCC 认证、全量-局部残差/边界/误差报告和拒绝诊断。 |
| M-13 | PARTIAL：历史 CAS/受控投递切片。 | bundle 原子提交、持久 intent/claim、unknown 不重发及重启幂等。 |
| D01 | OPEN。 | 同角色多会话、设定版本迁移和人格行为对照。 |
| D02 | OPEN。 | 明示模拟的需求竞争，改变日程/行动/恢复成本且无生理测量宣称。 |
| D03 | OPEN。 | 场景/参与/视角/事实性回放，投递与阅读分离。 |
| D04 | OPEN。 | M-05/M-06 连续情绪验收及行动合同联测。 |
| D05 | OPEN。 | 私聊/群聊/跨群隔离，局部更新和渐进修复回放。 |
| D06 | OPEN。 | 写入、检索、巩固、遗忘、纠错的纵向删除后重启不复活测试。 |
| D07 | OPEN。 | 必查责任、Concern 配额冷却和中断后同任务恢复且不重复消费。 |
| D08 | OPEN。 | 多目标执行、资格状态、unknown 投递和补救回放。 |
| D09 | OPEN。 | 蓝图到表达核验，受众/事实/承诺越界拒绝与中断去重。 |
| D10 | OPEN。 | 时间/活动触发、安静时段、有限离线恢复和真实产出边界。 |
| D11 | PARTIAL：历史 SQLite/调度/adapter 切片。 | 故障注入的暂停、恢复、冲突、取消、陈旧结果、成本/积压观测。 |
| D12 | OPEN：D01 `creation` 有受控图查询投影；D08 `action` 明确拒绝。 | 创作者编译、隔离实验、预览/回退及权威因果轨迹；各视图逐条来源/受众授权。 |
| ECO-01 | OPEN。 | 高优先级持续流下公平服务或可审计延期，且证据不重复消费。 |
| ECO-02 | OPEN。 | 票据暂停/过期/恢复版本复核，不补造漏 tick。 |
| ECO-03 | OPEN。 | 双方确认、履约、改约和未确认不升级共识的回放。 |
| ECO-04 | OPEN。 | RoleBinding 缺失拒绝、跨角色可见性和版本追踪。 |
| ECO-05 | OPEN。 | 模拟/计划/失败与真实外部结果严格分离的文件或工具收据。 |
| ECO-06 | OPEN。 | 独立经验/反例、作用域、撤销和历史 Strategy 验收。 |
| ECO-07 | OPEN。 | 分段过期撤销、已发送保留及重启不重复投递。 |
| MEM-01 | PARTIAL：历史类型/权限切片。 | 时间视角、来源家族去重与持久 Evidence/Episode/Recall 回放。 |
| MEM-02 | PARTIAL：历史原子写/去重切片。 | 分段受限提取、主体校验、崩溃后索引水位追赶。 |
| MEM-03 | PARTIAL：历史精确/时间权限查询切片。 | 责任、语义、竞争证据三路检索及无命中原因区分。 |
| MEM-04 | PARTIAL：历史 recall policy 切片。 | 持久请求全字段与状态机终态/恢复收据。 |
| MEM-05 | PARTIAL：历史必查阻断切片。 | 标注集上的漏触发/无用触发/提前停止指标。 |
| MEM-06 | PARTIAL：历史预算计数切片。 | 三档全部通道上限、超时/格式失败计费和责任精确分页。 |
| MEM-07 | PARTIAL：历史谓词停止切片。 | 同历史质量-成本对照、反例/责任覆盖和停止原因收据。 |
| MEM-08 | PARTIAL：历史同源去重切片。 | RecallEvent/Experience 持久化、十次读取单责任、冷却恢复。 |
| MEM-09 | PARTIAL：历史 epoch/工作集复核切片。 | 反证/删除/权限切换失效、无向量降级与覆盖诊断。 |
| MEM-10 | OPEN。 | 各巩固出口、独立实例/反例、快照过期禁止发布。 |
| MEM-11 | PARTIAL：历史解释链失效切片。 | 摘要/关系/策略/自传/计划的失效集和重建审计。 |
| MEM-12 | PARTIAL：历史逻辑撤权切片。 | DeletionPlan、物理/备份/导出清理及重启不复活回执。 |
| MEM-13 | OPEN。 | 分权限向量代际、覆盖切换、跨代拒绝和关闭向量回退。 |
| MEM-14 | OPEN。 | 提交后崩溃、幂等水位追赶、正负缓存覆盖失效。 |
| MEM-15 | PARTIAL：历史严格 schema 切片。 | 离线迁移预览/中断恢复/回滚与历史版本查询。 |
| OPS-01 | OPEN。 | 离线迁移的映射/丢失/冲突/权限报告、暂停确认回滚。 |
| OPS-02 | OPEN。 | 全工作台视图从权威版本回源，隔离实验和运行诊断。 |
| OPS-03 | OPEN。 | 记忆工作台合同事件、纠错影响预览和不污染查询实验。 |
| OPS-04 | OPEN。 | 角色方案编译诊断、版本适用范围、迁移预览/历史回退。 |
| OPS-05 | PARTIAL：历史 Rust/受控宿主切片。 | 真实宿主的队列、公平、取消、事件循环非阻塞、顺序提交和陈旧拒绝。 |
| OPS-06 | OPEN。 | 目标平台安装包冷启动、架构/缺库诊断、升级回滚和大小组成清单。 |
| OPS-07 | OPEN。 | 真平台私聊/群聊、可见性、投递/阅读、unknown 与断线恢复收据。 |
| OPS-08 | OPEN。 | 固定硬件/模型/数据的 1k/10k/100k 压测、P50/P95、峰值内存和日成本。 |
| OPS-09 | OPEN。 | 同输入模型预算的四对照及安全门后质量/成本消融报告。 |
| OPS-10 | OPEN。 | 完整共同项目纵向剧情逐步收据，严格分开模拟/计划/已发/完成。 |

## 7067200 历史快照的不确定项

1. 本轮源码基线为远端 checkpoint 提交 `70672008993e5359669d31a90564cb76d4864cc9`，分支 `codex/alpha1-runtime-checkpoint-20260923`；本地仍有未推送的设计与进度文档。169 个源码、测试及 CI 文件的清单 SHA-256 为 `c60d1c67251cc2a764498be126fe2c79b87cf99dcd057fc2c29da3e5e41375c4`：对 `main.py`、根配置、`rewrite/sylanne3`、`rewrite/native/src`、`rewrite/tests/alpha1`、`rewrite/host_tests/alpha1`、包测试和 CI 工作流按相对 POSIX 路径排序，每行写 `路径 空格 文件SHA-256`，以换行连接后再计算 SHA-256；排除 `__pycache__` 与 `.pyc`。它不是候选包哈希。
2. 对该源码，Windows Python 3.11.15 执行 `PYTHONPATH=rewrite python -m pytest -q rewrite/tests/alpha1 rewrite/tests/test_plugin_package.py rewrite/tests/test_runtime_journal.py`：432 passed、2 skipped、20 subtests。WSL Ubuntu 24.04.4 / Python 3.12.3 同命令：434 passed、20 subtests。受控 AstrBot 4.28.1 的完整 `rewrite/host_tests/alpha1`：Windows Python 3.13.14 为 95 passed、5 skipped、11 subtests；Linux 为 88 passed、12 skipped、11 subtests。Windows/Linux Rust 各 39 passed（在本次 Python 增量前）；当前 Python 编译、Ruff、Git whitespace 检查通过。原默认 WSL 发行版的 VHD 路径已失效；当前 Linux 复验使用另一个隔离 Ubuntu 发行版。这些是组件和受控宿主证据，不是冷安装或真实平台收发。
3. Authority v2 已有服务端持久栅栏、执行准备日志桥、双日志守卫下的 current/begin/validate/finish、同文件删除历史前缀迁移和 FenceStore schema 3 的独立删除 DTO。v2 mTLS 已接通只读 fence 四步并从 TLS peer 证书派生主体；独立远程查询、删除 pending 写入口、可写 v2 尾表升级、accepted/closed 的真实 D06/D11 证据和生产装配仍缺；旧进程/句柄、路径替换及有 DDL 权限写者的部署排他也未验收。D06 删除闭包只是版本化候选，不是已安装屏障。G0 继续 HOLD。
4. `main.py` 取得配对状态后仍以 `dependencies=None` 建立 `RuntimeContext`；普通安装保持 enrollment_required/BLOCKED。D12 只有 D01 `creation` 的受控图投影，D08 `action` 在缺逐条来源/受众资格时保持 unavailable；十二域实际会话、模型外送和最终派发没有纵向收据。
5. D11 区间 verifier 有完整联合块的 q/残差/时间误差边界，独立源码复核未发现本轮局部实现的可证明低估；前步误差来源、事件边界和发布构建仍未闭合，ABI2 `certificate_flags=0`。G2 数值认证继续 HOLD。
6. 首发目标矩阵是 Windows x86_64、Linux x86_64/arm64、macOS arm64/x86_64。CI 已配置五组合的实际 OS/CPU 自检、Rust/包探针与完整 host pytest，但未推送执行；macOS 原生 ACL/TLS smoke 未在 macOS 运行。各组合的管理员冷安装、真实平台收发和确切正式包都缺，见 [平台矩阵](platform-matrix.md)。
7. 62 项运行验收账目前为 22 PARTIAL、40 OPEN、0 DONE。G0–G7 均不能因设计覆盖、局部测试、受控宿主或 dev-probe 包而改为通过。
8. D04 回忆感受与 D06/D07 不可变活动记录已分别通过真实图写入的邻接测试；完整 C04 五域事务仍被缺少同包 D11 job、签名 D02/D11 运行准入及首次费用回执预构阻断。当前没有真实回忆联合提交收据。

## 8e0e509 checkpoint 增量证据（2026-09-23）

- 当前远端分支 `codex/alpha1-runtime-checkpoint-20260923` 指向提交 `8e0e509d670f17a0a965d2858447c70944955c72`，Git tree 为 `9d4d72f800a77203c1eb21691d71578ee4f42117`。本地设计与进度文档仍未推送；以上源码身份不含这些本地文档。
- [GitHub CI 35840481035](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35840481035) 对该确切 SHA **12/12 作业成功**：Windows x86_64、Linux x86_64/arm64、macOS arm64/x86_64 各自运行组件编译、Rust、当平台 dev-probe 包构建/加载和 `pytest -q rewrite/tests/alpha1 rewrite/tests/test_plugin_package.py`；五组固定 AstrBot 4.28.1 SDK 宿主检查通过；Windows/Linux Python 3.13 core/native 检查通过。macOS 两组真实 ACL/TLS smoke 在该运行中通过。CI 收据是源码与受控宿主证据，不是管理员冷安装、真实聊天平台收发或正式 alpha1 包验收。
- 本地 Windows 对本次增量执行 `PYTHONPATH=rewrite python -m pytest -q rewrite/tests/alpha1 rewrite/tests/test_plugin_package.py`：428 passed、2 skipped、20 subtests；Python `compileall`、`ruff check main.py rewrite`、Git whitespace 检查通过。根 `verify.py` 更新后明确覆盖 19 个顶层核心测试文件：Windows Python 3.13 和隔离 WSL Linux Python 3.12 均 194 tests 通过；该命令在上述 CI 的 Windows/Linux Python 3.13 作业也通过。
- C04 受控纵向切片的 `test_c04_atomic_real_issuers.py` 为 3 passed：真实 D02/D04/D06/D07/D11 provider 与签名 D02 quote/outcome、D11 grant，证明图写、预算结算、持久 job/outbox 的同事务提交，及错费用回执整体回滚。这里的 provider outcome verifier 是测试夹具；默认生产 `domain_registry` 尚未从受信配置绑定 D04 `AffectScheme`，`main.py` 的 `RuntimeDependencies` 也仍未接通，不能据此宣称实际插件回忆已运行。
- 上方 62 行的分类保持 **22 PARTIAL、40 OPEN、0 DONE**；G0–G7 仍 HOLD。管理员冷安装、真实平台收发、Authority 生产装配、数值证书、工作台与完整纵向行为没有因这次 CI 自动获得验收。

## 36ec4c3 源码 checkpoint 增量证据（2026-09-23）

- 远端 `codex/alpha1-runtime-checkpoint-20260923` 已核对为 `36ec4c31c9d6c40fad047e8a80447804eea73439`，Git tree 为 `13842e32c91692257b33a4ea4f5c1a5bcdcedf9b`。其上三笔源码提交分别加入 v2 非 dispatch 内容栅栏的双端 RPC/多 namespace 路由、每角色安装与 bootstrap DTO、D04 活跃方案显式注入接缝。设计文档未随 checkpoint 推送。
- [GitHub CI 35843022173](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35843022173) 对该确切 SHA **12/12 作业成功**：五组 OS/CPU 组件编译、Rust 测试、当平台 dev-probe 构建加载与 alpha1/package pytest；五组固定 AstrBot 4.28.1 SDK 宿主 adapter/host pytest；Windows/Linux Python 3.13 core/native 检查。本地 Windows `PYTHONPATH=rewrite python -m pytest -q rewrite/tests/alpha1 rewrite/tests/test_plugin_package.py` 为 **441 passed、2 skipped、20 subtests passed**；`compileall`、`ruff check main.py rewrite`、`git diff --check` 通过。本机缺 AstrBot SDK，真实 SDK 宿主结果取自上述 CI。
- 这批验证的是源码组件、受控宿主与开发探针包。`RuntimeContext` 仍以 `dependencies=None` 阻断生产激活，D04 默认注册也尚未按角色取得受信活跃方案；v2 安装 grant/bootstrap RPC、dispatch/删除/执行 mutation、图协调器显式 permit、完整十二域/工作台纵向行为、管理员冷安装与真实平台收发仍缺。62 项仍为 **22 PARTIAL、40 OPEN、0 DONE**；G0–G7 保持 HOLD。

## bdfcc77 源码 checkpoint 增量证据（2026-09-23）

- 远端 `codex/alpha1-runtime-checkpoint-20260923` 已推送至 `bdfcc7715223b89f63dba6a15b56abe693873e94`，Git tree 为 `3d9dcca6aee6e30dd128fc70affe5394f4998778`。本批四笔提交补充 v2 显式 fence scope 与快照恢复要求、管理员绑定的安装 grant、namespace bootstrap 状态判定及其 mTLS 双端交换。只推送源码和测试；本地设计与进度文档仍未推送。
- [GitHub CI 35845001044](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35845001044) 对上述确切 SHA **12/12 作业成功**：五组目标 OS/CPU 的组件编译、Rust、开发探针包与 alpha1/package pytest，五组固定 AstrBot 4.28.1 SDK 宿主检查，以及 Windows/Linux Python 3.13 core/native 检查。该 CI 是源码、开发探针包与受控宿主证据，并非正式包冷安装或真实聊天平台验收。
- 本地 Windows 对本批源码执行 `PYTHONPATH=rewrite python -m pytest -q rewrite/tests/alpha1 rewrite/tests/test_plugin_package.py`：**457 passed、2 skipped、20 subtests passed**。namespace bootstrap 与安装 grant 的服务/RPC/TLS 联合聚焦测试为 **16 passed、12 subtests passed**；Python `compileall main.py rewrite/sylanne3`、`ruff check main.py rewrite`、Git whitespace 检查通过。独立只读复核未发现此 bootstrap 切片的具体阻断问题。
- v2 bootstrap 只是一次有锁状态观察，安装 grant 不带全局激活 generation。真实生产仍缺 per-namespace 管理激活/迁移、独立远程 dispatch 与执行/删除 mutation、图协调器贯穿同一活 fence scope、`RuntimeContext` 的完整依赖装配、D04 受信活跃方案、十二域/工作台纵向行为、管理员冷安装和真实平台收发。62 项维持 **22 PARTIAL、40 OPEN、0 DONE**；G0–G7 均为 HOLD。

## aa7e38d 源码 checkpoint 增量证据（2026-09-23）

- 远端 `codex/alpha1-runtime-checkpoint-20260923` 已核对为 `aa7e38d1822ea920dfe40206d40d6b56563a3430`，Git tree 为 `885f9a47b6aa05ff1dfe65890488f8ed1bcc3aff`。本批四笔提交依次加入 Authority v2 显式 namespace genesis、宿主启动时的 v2 安装事实、管理员映射且绑定 TLS peer 的 genesis RPC，以及业务图中的 v2 恢复要求和 CAS 元数据。只推送源码与测试；设计和验收文档仍在本地。
- [GitHub CI 35847824077](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35847824077) 对该确切 SHA **12/12 作业成功**：五组目标 OS/CPU 组件编译、Rust 测试、当平台 dev-probe 构建加载与 alpha1/package pytest，五组固定 AstrBot 4.28.1 SDK 宿主检查，以及 Windows/Linux Python 3.13 core/native 检查。
- 本地 Windows 聚焦验证：Authority genesis 与 bootstrap 14 passed；v2 多 namespace/content RPC 和真实 mTLS 回环 9 passed；图恢复元数据 11 passed；相关源码 `compileall`、Ruff 与 Git whitespace 检查通过。本机普通宿主测试收集缺 AstrBot SDK，真实 SDK 受控宿主结果来自上述 CI。
- 显式 genesis 已能在独立双日志守卫下激活空 namespace；旧角色状态不会被图元数据 genesis 静默重标，普通 CAS 固定 activation generation 并阻止水位回退。图元数据尚未接入 `GraphCoordinator` 的生产 admission/commit，四张时钟表缺角色归属时会全局阻断旧数据的 genesis；独立远程 dispatch、执行/删除 mutation、完整依赖装配、十二域/工作台纵向行为、正式包冷安装与真实平台收发仍缺。62 项维持 **22 PARTIAL、40 OPEN、0 DONE**；G0–G7 均为 HOLD。

## 0741dec 源码 checkpoint 增量证据（2026-09-23）

- 远端 `codex/alpha1-runtime-checkpoint-20260923` 已核对为 `0741dec4898c2c80c1dd6aef4f70c2f2296a29eb`，Git tree 为 `b56ca825c4f322b9977226502e0ce790b18ba933`。四笔源码提交加入 Authority RPC 的有界单线程派发、业务图 v2 只读准入、有界图 worker 接缝、宿主 v2 fence 桥接；本地设计与验收文档未推送。
- [GitHub CI 35850235227](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35850235227) 对该确切 SHA **12/12 作业成功**：五组目标 OS/CPU 组件、Rust 与 dev-probe 包检查，五组固定 AstrBot 4.28.1 SDK 宿主检查，以及 Windows/Linux core/native 检查。它仍是源码、开发探针包与受控宿主证据，不是正式包冷安装或真实聊天平台收发。
- 本地聚焦测试：v2 桥接/图读/旧协调器 **38 passed**，Authority RPC worker 与真实 mTLS 回环 **5 passed**，图 worker **4 passed**；相关 Python 编译、Ruff 和 Git whitespace 检查通过。v2 读与真实 AuthorityV2FenceStore 的 finish 合同有受控测试；宿主桥接的丢响应对账仍只在进程内，冷重启 active fence 运维恢复未验收。
- `GraphCoordinator` 的 v2 写路径仍 fail-closed：版本 guards 与父预算租约尚无受信 v2 初始化操作，先写旧状态又会被严格空库 genesis 拒绝。一次性安装级事务的设计裁决见 [v2 namespace provisioning](../v2-namespace-provisioning.md)。独立图 worker 尚未接入 `RuntimeContext`，`main.py` 仍以 `dependencies=None` 阻断生产激活。62 项仍为 **22 PARTIAL、40 OPEN、0 DONE**，G0–G7 保持 HOLD。

## 9dd01c2 源码 checkpoint 增量证据（2026-09-23）

- 远端分支已核对为 `9dd01c291dc5028662fd5661d7d555bdfbb10c10`，Git tree 为 `d0a537e7d60a98d81bf05f801750f1ba6fed6890`。相对上一 checkpoint，新增受协调器能力约束的 graph recovery genesis locked 原语：外层业务事务能同时回滚恢复元数据、guard 与预算账本；原公共接口和旧历史拒绝保持不变。
- [GitHub CI 35850858066](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35850858066) 对该确切 SHA **12/12 作业成功**，覆盖五组目标 OS/CPU 组件与固定 AstrBot 4.28.1 SDK 宿主检查，以及 Windows/Linux core/native 检查。本地含 v2 metadata/read 的聚焦测试 **23 passed**，调整后的 metadata 单组 **18 passed**；相关 Python 编译与 Ruff 通过。
- locked 原语只是安装级 `provision_namespace_v2` 的事务前置能力；尚未有真实安装政策、scheme/operator/policy 版本与 D11 根预算的授权装配，也没有 v2 bundle 写提交。因此 `main.py` 仍阻断生产激活，G0–G7 与五平台正式资格继续 HOLD；本地设计与验收文档未推送。

## 04554eb 源码 checkpoint 增量证据（2026-09-23）

- 远端 `codex/alpha1-runtime-checkpoint-20260923` 已核对为 `04554eb190766541bfdf8ffd299512730ef6aad3`，Git tree 为 `ea8acc0306f041d7633fa76be36f81022a423364`。本批三笔源码提交依次加入管理员 v2 安装政策及独立 D11 密钥读取、配对的 v2 genesis 与持久 fence 状态查询、Authority fence 下的图 namespace 初始化及已提交收据的冷重启对账。设计与验收文档未推送。
- [GitHub CI 35859672685](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35859672685) 对上述确切 SHA **12/12 作业成功**：五组目标 OS/CPU 组件、Rust 与 dev-probe 包检查，五组固定 AstrBot 4.28.1 SDK 宿主检查，以及 Windows/Linux core/native 检查。本地 Windows `PYTHONPATH=rewrite python -m pytest -q rewrite/tests/alpha1 rewrite/tests/test_plugin_package.py` 为 **526 passed、2 skipped、20 subtests passed**；受影响宿主权限与 profile 聚焦测试为 **77 passed、6 skipped**。`compileall main.py rewrite/sylanne3`、`ruff check main.py rewrite` 和源码 whitespace 检查通过。
- namespace 初始化只能证明明确管理员政策下的受控创世切片。普通 v2 内容写、独立 dispatch/删除/执行 mutation、D04 受信活跃方案、完整宿主依赖/图 worker 装配与真实纵向行为仍缺；`main.py` 仍以 `dependencies=None` 阻断生产激活。业务收据出现前遗留 active fence 的冷重启窗口尚无持久 intent 自动恢复。正式包冷安装与真实平台收发未执行；62 项仍为 **22 PARTIAL、40 OPEN、0 DONE**，G0–G7 保持 HOLD。

## 73efff7 源码 checkpoint 增量证据（2026-09-23）

- 远端 `codex/alpha1-runtime-checkpoint-20260923` 已核对为 `73efff7ebee2e62401720506dd1c6af1fa24bdb8`，Git tree 为 `1dd62bfe95521a6646d05bb849fe8e4487444c15`。相对 `04554eb`，新增安装目录逐文件与目标 OS/CPU/ABI2 校验、无需虚构 D02 的 D11 根 grant 签发、独占 Authority port 的 v2 图 worker 生命周期，以及一次受保护窗口内读取 TLS/profile/policy/D11 密钥的安装 bundle。后两笔修正仅调整测试收集目录和跨平台测试夹具。
- [GitHub CI 35862912715](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35862912715) 对上述确切 SHA **12/12 作业成功**，覆盖五组目标 OS/CPU 的组件、Rust、dev-probe 与 alpha1/package 检查，五组固定 AstrBot 4.28.1 SDK 宿主检查，以及 Windows/Linux core/native 检查。此前 [35861538915](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35861538915) 为 10/12：pytest 测试误放在无 pytest 的 core/unittest 收集目录；[35862424813](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35862424813) 为 11/12：macOS arm64 的平台错配夹具构造了 Windows arm64 无效目标。两项均为测试布置/夹具错误，已在最终 SHA 修正。
- 本地 Windows 对合并切片执行 `PYTHONPATH=rewrite python -m pytest -q rewrite/tests/alpha1 rewrite/tests/test_plugin_package.py rewrite/tests/test_installed_package.py`（移动测试前）为 **544 passed、2 skipped、20 subtests passed**；测试移到 alpha1 目录后安装校验定向 **10 passed**，`python rewrite/tools/verify.py` 为 PASS，profile/key 定向 **41 passed、2 skipped**，`compileall`、Ruff 与 Git whitespace 检查通过。这些结果不等于正式候选包或管理员冷安装。
- 当前 v2 `RuntimeContext` 只接受完整核验的正式包来打开图 worker，仍停在 `limited(namespace_activation)`；生产 `main.py` 未接入该安装 bundle，D04 活跃方案、稳定安装 intent、普通 v2 写/派发/删除、完整十二域纵向链路、正式包冷安装和真实平台收发仍缺。62 项保持 **22 PARTIAL、40 OPEN、0 DONE**；G0–G7 及五平台正式资格继续 HOLD。本地验收与设计文档不随源码 checkpoint 推送。
- 用户随后要求修正历史远端设计文字：上游 `codex/embodiment-3-rewrite` 的当前 tip 为 `a35955f17e88978ee44e470b493ff85746a9fb35`，checkpoint 当前 tip 为 `b1ef4b301fd99feffef6a770f5222b09a4020c34`。后者相对 CI 源码 SHA `73efff7` 只改七个已跟踪的文字文件，因此上方 12/12 是相同源码的 CI 证据，并非对 `b1ef4b3` 重新运行的 CI。更正采用追加提交；旧文字仍可从历史提交读取。

## 2fc42f8 源码 checkpoint 增量证据（2026-09-23）

- 远端 `codex/alpha1-runtime-checkpoint-20260923` 已核对为 `2fc42f884d925fb4f27807730e8741d51a49f9a1`，Git tree 为 `7ae51a370c6e4383e3e7e39c26c21032f2a17618`。本批加入业务收据前的持久安装意图及重启恢复、初始预算授权到期后的历史回执核验、受 manifest 固定的 D04 资产/目录加载，以及 `main.py` 的 v2 安装与图 worker 启动接线。目录重新导出补上 `d04.recollection_experience.v1`，仍为 `candidate_only/HOLD`。源码 checkpoint 不含本地设计与验收文档。
- [GitHub CI 35870829221](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35870829221) 对该确切 SHA **12/12 作业成功**：五组目标 OS/CPU 组件、Rust 和 dev-probe 检查，五组 AstrBot 4.28.1 SDK 宿主检查，以及 Windows/Linux core/native 检查。本地 Windows 对受影响运行时、D04 资产和安装程序集组合运行 **318 passed**；管理员 profile 聚焦测试 **24 passed**；改动文件编译、Ruff 和 staged whitespace 检查通过。前两次 CI 的失败均为旧启动/历史授权测试断言，已在最终 SHA 修正；不把失败运行写作产品通过。
- 入口在核验正式包与 D04 资产后仍保持 `limited(namespace_activation)`，不自动 provision 或接管消息。当前没有合格的实际 D04 参数/耦合资产、ABI2 数值证书、正式候选包和五平台管理员冷安装/真实聊天收据；普通 v2 内容写、派发、删除及完整十二域/工作台纵向链路亦未验收。62 项原分类与 G0–G7 HOLD 不因这批受控检查自动改变。

## b32ec2a 源码 checkpoint 增量证据（2026-09-23）

- 远端 `codex/alpha1-runtime-checkpoint-20260923` 已核对为 `b32ec2a9b24b770ba9a94a6d821e4ac7675f83ab`，Git tree 为 `3d5bb431646d309b88269d06514c668d8f04f348`。本批三笔源码提交分别增加 D04 正式包清单资产绑定、管理员安装中的独立 D02 签名密钥与 D02/D11 签发器装配，以及带持久 intent/业务收据的 v2 普通 `DomainBundle` 写栅栏。设计和验收文档未推送。
- [GitHub CI 35873635868](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35873635868) 对该确切 SHA **12/12 作业成功**：五组目标 OS/CPU 组件与五组 AstrBot 4.28.1 SDK 宿主检查、Windows/Linux core/native 检查。该结果仍是源码、dev-probe 与受控 SDK 证据。本地 Windows 包构建聚焦测试 **15 passed、5 subtests**，D02 安装/worker 聚焦测试 **29 passed、3 skipped**，W01 全运行时目录 **313 passed**；受影响文件编译、Ruff 和 staged whitespace 检查通过。
- 普通 v2 图写入现能在 Authority write fence 下原子提交图事件、预算/job/outbox 收据与恢复版本，并以原操作身份恢复已提交而 finish 结果丢失的尝试。**确定回滚但无业务收据的无效候选仍可能留下 active fence**，需要持久拒绝与精确 finish 协议；真实 D06 宿主入站、受信时钟、root grant 复用、独立 dispatch/删除和完整十二域链路尚未接通。当前仍没有正式候选包、五平台管理员冷安装或真实聊天收据；62 项原分类和 G0–G7 继续 HOLD。

## 362eab7 源码 checkpoint 增量证据（2026-09-23）

- 源码 checkpoint `362eab74c75643cc5cd252d0082099c24bbe92d4`（Git tree `075d6f26a7386f4695727fb8f41c6aa791e08cb3`）已推至 `codex/alpha1-runtime-checkpoint-20260923`；本地设计与验收文档未推送。其增量包含事务内图提交原语、v2 写失败的持久 `rejected_no_commit`、管理员可选入站时钟配置、Authority v2 时钟 RPC 与 worker 校验端口、D02/D11 显式 UTC 透传，以及 D06+D11 首次入站纯封包函数。
- [CI 35874759047](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35874759047)、[35875649936](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35875649936)、[35875886631](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35875886631)、[35876672053](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35876672053) 分别在精确 SHA `a31755b`、`9619469`、`4d9910e`、`4261723` 上完成 **12/12 作业成功**。这些结果不覆盖后续 `a984aa5` 与 `362eab7` 的独立完整 CI；本地对后者的首次入站封包/宿主 assembler 聚焦测试为 **11 passed**，受影响文件编译、Ruff 与 staged whitespace 检查通过。
- 已接通的时钟仅证明管理员配置读取、配对 Authority 样本交换和 worker 对来源/误差/往返上界的校验；没有已部署的管理员授时提供者或 UTC 物理精度收据。旧多阶段入站仍不能在 v2 作为正式产品入口；首次 D06 来源、D02 quote、D11 预算/job/outbox 与图业务收据的单事务入站尚未实现。完整十二域/工作台、独立 dispatch/删除、正式包、五平台管理员冷安装和真实平台收发继续缺失；62 项维持 **22 PARTIAL、40 OPEN、0 DONE**，G0–G7 均 HOLD。
