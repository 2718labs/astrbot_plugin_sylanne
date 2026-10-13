# Alpha2 开发检查点 — 2026-10-14

本分支保存实际 Alpha2 源码检查点，版本身份为 3.0.0-alpha2。它不是正式发布，也不表示 v3 的 39 项或全部领域验收通过。整体状态 HOLD；服务器 Linux x86_64 / AstrBot 4.28.2 的实测由使用者完成。

## 本次保存的源码

- 独立 2718lab WebUI（默认 0.0.0.0:2718）、必要插件配置入口、D01–D13 开关和 AstrBot 原生 LLM 选择。
- 经明确授权的完整 HTTP 登录、配置及 Owner 操作。Origin、CSRF、Owner 身份和 Host–Authority mTLS 检查保留；HTTP 的链路内容不加密。
- Contact 与 Life Numeric 的正式 V3–V7 workflow 容器分派，保留当前 Source、job、安装身份、grant、lease、reservation 和原期限。
- V7 Graph 导入证据的精确 schema、原签名事实保留及迁移登记；Core/Graph 双向完整核对、真实历史签名、正式前代退休证明和独立反向 census。
- C09 cold 摘要仅在实际资源量子成功退出后发布，使用同一预算 meter；paid Owner guard 链接表按正式 DDL、trigger 和行身份进入迁移清单。
- 既有修复、永久测试和前端源码保留。秘密、运行数据库、完整本地日志、缓存及重复前端构建输出不进入提交。

## 证据边界

当前本地必要 V7 回归为两个不同永久节点通过：真实 installer/迁移库存/精确身份/原件不可变，以及历史签名不能复活当前期限。首次库存失败直接发现 paid Owner guard 链接表遗漏，修复后只补验受阻节点；首次日志和 fixture 独立保留。它们不是完整 C09 安装或冷恢复 PASS。

HTTP 的真实 Windows SDK 浏览器验证属于此前独立快照的限定证据。旧快照 Numeric、D13 或其他 PASS 不迁移到本提交。

最后已冻结的安装 ZIP 为 HTTP candidate45：
- ZIP SHA256：b4dc12b958ee503f505628d2771cf16b3ca581b8eeedf077231b2f847c7968c9。
- 压缩大小：8,102,262 字节；这是旧 candidate45 的原件，不能宣称与本提交新增源码完全相同。
- 未变 Linux native SHA256：2883b3bd4af107a953fe86c6ee785da1fc51688e36e7a9f5fef7d7016d91d56c。原生安装产物独立保存，不把开发构建产物混入源码提交。

本分支是开发源码；正式安装使用经核验的独立平台包。构包、导入、实际启动、执行、结算和生产资格分别记录。

## 保留到 Beta1 的真实代码工作

1. D07 signed reflection_request 到有限续作、当前公平票据、Self parentage、实际模型 observer 和恢复消费者。
2. Contact 合格机会到 Plan、generation/review、独立 standing Owner background invocation、final/claim/P2 与实际调度。
3. Joint 计划的内容寻址执行绑定、各方真实 outcome、原 effect 的恢复、每次执行的依赖重查、后置条件及后继节点。
4. 一般 Life 成果到合法 D07 解释和 D01 成长候选、事前登记试用及反证；不能用方法学习特化替代全部人格成长。
5. 新快照的完整 Numeric 负例、D13 standby/cold/replay/expired、C09 物理退休和冷恢复、D04 FULL、独立生产 Host 与全部联合场景。

这些项尚未全部闭合，不以 waiting、源码编译或构包成功改记完成。Contact/C09、D04、生产 Host 保持各自独立资格边界。

## 后续开发和安装说明

Alpha2 分支作为基线保存；Beta1 在独立开发分支接续，原失败及旧快照保留。Beta1 的必要运行组件 ZIP 上限按 16,000,000 字节控制，同时报告 MiB，约 15MB 是容量目标，不填充数据达到大小。

服务器操作见 [Linux 安装与验证说明](linux-alpha2-server.md)，配置见 [WebUI 配置说明](webui-configuration.md)。没有真实付费模型或 sender 调用，没有直接 SQL 修账，没有合并或发布。
