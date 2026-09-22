# Sylanne · Embodiment 3.0 开发分支

这是整套重型角色插件的重新实现，当前版本为 `3.0.0-dev.1`，尚未达到完整产品或生产发布验收。

目标是持续的人格、复杂情绪、长期关系、多层记忆、认知与执行、日常生活和主动行为共同组成的角色系统。原子状态与增量调度用于降低无效计算，不用于缩减这些能力。

请先阅读 [重型系统总体设计](docs/architecture/embodiment-3-system.md) 和 [用户批准的原始方向](rewrite/design/user-approved-direction.md)。

## 当前代码

根目录 `main.py` 是唯一插件入口，新的运行时位于 `rewrite/sylanne3/`，Rust 数值内核位于 `rewrite/native/`。旧接口、旧核心、旧 WebUI 及旧打包路径退役，不提供运行时回退。旧版本可从 Git 标签 `Embodiment-2.5.1` 查阅；本次源码退役不删除现有用户数据。

当前已实现范围是计算与宿主接入的工程切片：版本化存储、受限求解、可中断调度、证据纠正、行动与投递记录、严格语义提议、持久化去重及显式 `/sylanne3` 命令。二维状态、三类有效评价和固定回复均为验证设施，不是最终人格或情绪模型。

尚未重写完成：分层所有权与跨域事务、完整人格/情绪/关系模型、多层记忆、认知与计划、生活与主动行为、角色工作台、旧数据迁移和原生二进制分发。旧版本功能不会因为接口切换而自动成为 3.0 功能。

## 本地开发与验证

要求 Python 3.11 或更新版本，以及 Rust 工具链。当前本地验证环境为 Windows x86_64、Python 3.13.14、AstrBot 4.28.1；实际结果见验收记录。插件使用宿主提供的 AstrBot API，Python 核心不依赖旧运行时。

```powershell
python rewrite/tools/verify.py
```

该命令编译原生内核并运行核心检查，回执保存在 `rewrite/artifacts/`。真实 SDK 检查使用隔离安装了 `astrbot==4.28.1` 的解释器运行：

```powershell
python rewrite/tools/verify_host.py
```

SDK 验证使用受控模型与平台输入，不等同于真实机器人在线验收。参见 [宿主测试与手动试用](rewrite/HOST_TESTING.md)、[基础验收](rewrite/ACCEPTANCE.md) 和 [本阶段验收](rewrite/HOST_ACCEPTANCE.md)。

## 开发入口

`enabled` 默认关闭。试用需使用匹配平台的原生库，在隔离 AstrBot 实例加载本仓库、启用该项并使用 `/sylanne3 <消息>`。详细步骤与未验证项见宿主测试文档。没有完整功能迁移前，不将本分支当作现有 2.5.1 的无损升级包。

此前的版本日志和 `docs/` 内旧规格作为历史资料保留；当前总体架构以本文链接的 3.0 设计为准。

许可证：AGPL-3.0-or-later。
