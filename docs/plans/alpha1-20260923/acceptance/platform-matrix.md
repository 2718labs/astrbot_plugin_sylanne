# alpha1 首发平台资格矩阵

目标是完整 `embodiment-3.0.0-alpha1`。2026-09-27 收敛后的平台验收为：一处 Windows
x86_64 实机跑通完整插件；Linux x86_64、macOS arm64 在对应系统验证当前 Rust 原生核
的构建、加载、原生测试和代表性求解。Linux arm64 与 macOS x86_64 是可继续运行的
兼容探针，不挡本轮。原生核结果不能写成该平台完整插件的实机验收。所有证据绑定
**系统、CPU、原生 ABI、源码/包哈希**；Windows 完整插件另外绑定 Python、AstrBot、
Authority、真实模型和平台收据。

| 目标组合 | 已登记的历史证据 | 资格 |
| --- | --- | --- |
| Windows x86_64 / MSVC | [73efff7 CI](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35862912715) 的 Windows 组件与 AstrBot 4.28.1 SDK 作业成功；本地 Windows 合并切片为 544 passed、2 skipped、20 subtests | 完整插件 HOLD：管理员冷安装、正式包、真实平台收发与全链路未完成 |
| Linux x86_64 / glibc | 同一 CI 的 Ubuntu x86_64 组件与 AstrBot 4.28.1 SDK 作业成功；当前工作树在 WSL2 Ubuntu 24.04.4 x86_64/glibc 2.39、rustc 1.98.1 上完成 `--backend-only-dev-probe`：ABI2 release 构建、隔离 ZIP 冷加载；`cargo test --locked` 为 59 passed。源码 HEAD `72c9235bf025b66e0a83f02d34661a32abd3250b`，工作树大量已修改/未跟踪，结果不等价于该 commit 的干净树；原生 SHA-256 `757835845ea4c651fe4e058eda67cd36997462f70f0e70b707015844b3e0cfe0`，ZIP SHA-256 `a660807e5840e0e220162cf2a11e2dbd126f27ddc5a6d96f4704afc60405552d`。全局能力仍为 `numerically_certified=false`（表示该 native 不宣称 blanket certification），但单次求解收据各为 `certificate_flags=1`，并通过独立参考误差界检查：标量固定块、耦合线性 2x2 端点/轨迹、非线性耦合 2x2 端点/257 点路径。D04 产品读出/来源闭包/采用资格不在此收据内。 | 当前 dirty 工作树的原生构建、冷加载、59 项 Rust 单测和代表性固定块求解数学检查已验；这不是 D04 产品资格或完整插件宿主验收 |
| Linux arm64 / glibc | 同一 CI 的 `ubuntu-24.04-arm` 组件与 AstrBot 4.28.1 SDK 作业成功，核对了 runner OS/CPU | 后续兼容探针；不挡本轮 |
| macOS arm64 | 同一 CI 的 `macos-15` 组件与 AstrBot 4.28.1 SDK 作业成功，含 Darwin ACL/TLS host smoke | 当前源码原生核目标：待对应 Mac 构建、加载、测试、代表性求解收据；完整插件宿主未验 |
| macOS x86_64 | 同一 CI 的 `macos-15-intel` 组件与 AstrBot 4.28.1 SDK 作业成功，含 Darwin ACL/TLS host smoke | 后续兼容探针；不挡本轮 |

上述 CI 标签的架构对应关系按 [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
登记；实际任务仍须核对运行日志中的 runner。当前 CI 配置见
[ci.yml](../../../../.github/workflows/ci.yml)。矩阵任务分别运行
Python 3.11 组件测试、Rust 测试和本机 dev-probe 包构建/严格加载；AstrBot 4.28.1
SDK 任务使用 Python 3.13。工作流对确切源码
`73efff7ebee2e62401720506dd1c6af1fa24bdb8` 已完成 12/12 作业；
这证明受控组件和宿主检查，不授予正式平台资格。
checkpoint 分支后续文档更正 tip 为 `b1ef4b301fd99feffef6a770f5222b09a4020c34`；
相对上述 CI SHA 未修改源码或测试，未因文字更正重复运行 CI。

较早源码 checkpoint 为 `2fc42f884d925fb4f27807730e8741d51a49f9a1`；
[CI 35870829221](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35870829221)
对该确切 SHA 的五组合组件与 AstrBot 4.28.1 SDK、Windows/Linux core/native 共
**12/12 作业成功**。它更新了上表的软件检查证据，五行正式平台资格继续 HOLD。

较早源码 checkpoint `b32ec2a9b24b770ba9a94a6d821e4ac7675f83ab`；
[CI 35873635868](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35873635868)
在该确切 SHA 上的五组合组件与 AstrBot 4.28.1 SDK、Windows/Linux core/native
共 **12/12 作业成功**。这仍不包含正式包、管理员冷安装或真实平台收发，五行资格保持 HOLD。

后续源码 checkpoint `362eab74c75643cc5cd252d0082099c24bbe92d4`
已推送；最近一次完整 CI 为 [35876672053](https://github.com/2718labs/astrbot_plugin_sylanne/actions/runs/35876672053)，
对应较早的精确 SHA `42617234c55081c3d3d05ce283ea18b3de965169`，五组合组件与固定 SDK 宿主、
Windows/Linux core/native 共 **12/12 作业成功**。`362eab7` 的后续增量目前只有本地聚焦验证，
因此矩阵继续按已验证的精确 SHA 标记。五行正式资格均为 HOLD。

Windows 完整插件转 READY 前须固定 Python/AstrBot/OS/CPU 与工具链、可信发行根、
包及 manifest 哈希，完成无 Rust 环境冷安装、根入口启动、真实平台交接与观察、
重启、删除/恢复及 G0–G7 的适用收据。普通未配对插件保持
`enrollment_required`，不能算成功启动。Linux/macOS 原生核目标须固定确切源码、
Rust 工具链和本机动态库哈希，并在对应系统执行构建、加载、原生测试和代表性求解；
它们不解锁完整插件的跨平台宿主宣称。ABI2 数学证书只认证适用的数值条件，D04
产品读出仍须通过来源、完整图闭包、继承误差和采用资格。

当前 Windows 完整插件仍 HOLD；Linux/macOS 当前源码原生核目标也待本轮收据。
`metadata.yaml` 继续使用开发版本，支持列表按实际验证边界填写。
