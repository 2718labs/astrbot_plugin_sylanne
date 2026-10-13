# Sylanne 3.0.0-alpha2 · AstrBot 插件安装候选

本包用于 AstrBot 的本地 ZIP 插件导入，包含 Sylanne 后端、2718lab 0.25.0 同源工作台，以及 Linux 原生内核。工作台保持 v24 视觉基线、原 GLB/logo 和选择、退出动效。当前属于本地测试快照，完整安装、真实授权业务与浏览器验收仍为 HOLD。

## 平台与包内容

本包的 native 目标为 **Linux x86_64/glibc**，安装加载核对使用官方 **AstrBot 4.28.2、Python 3.12.3**，此前源码回归使用 4.28.1。WSL2 内的 Linux AstrBot 属于该目标；Windows 原生 AstrBot、ARM64 和 musl 宿主需要各自匹配的原生包。metadata 中的 AstrBot 声明范围是 `>=4.28.1,<5.0.0`，该范围不表示每个版本都已完成验收。

ZIP 根目录包含 [main.py](main.py)、[metadata.yaml](metadata.yaml)、[_conf_schema.json](_conf_schema.json) 和 [release-manifest.json](release-manifest.json)。运行时代码位于 `rewrite/sylanne3/`，原生库为 `rewrite/sylanne3/_native/linux-x86_64/libsylanne3_kernel.so`。最终前端位于 [resources/workbench/index.html](resources/workbench/index.html)，其真实字节和 SHA256 由 [资源 manifest](resources/workbench/workbench-manifest.json) 记录。宿主提供 AstrBot SDK；独立 Authority 的依赖见 [requirements-authority.txt](requirements-authority.txt)。本包已携带原生库，安装用户无需构建 Rust。

## 导入和启动

新服务器的隔离安装、Docker 端口与同包复验入口见 [alpha2 服务器安装与复验](docs/install/linux-alpha2-server.md)。日常导入只需要插件安装 ZIP；工程源码与测试依赖单独用于复验，不导入 AstrBot。

1. 使用全新隔离数据目录中的匹配平台 AstrBot，在插件管理的本地 ZIP 上传入口选择本插件 ZIP。直接上传 ZIP，保留包内目录结构。首次测试保留默认 `enabled=false`。
2. 导入成功后核对插件名 `astrbot_plugin_sylanne`、版本 `3.0.0-alpha2` 和加载日志。导入只安装插件文件；完整运行仍由实际安装身份、当前授权和运行状态决定。
3. 由管理员按 [Linux 安装与生命周期说明](docs/install/linux-alpha1-lifecycle.md) 完成正式 Authority/Host 安装绑定。`authority_profile` 只选择已有的管理员配置档，不能代替安装授权。本快照的 release manifest 是新的身份输入，旧快照的授权或 PASS 不能自动沿用。
4. 在 AstrBot 的 Sylanne 配置中选择真实 LLM provider、已安装的 `authority_profile`，并明确本机运行许可 `enabled`。下拉选项来自 AstrBot 已启用的聊天模型 provider；模型名从所选 provider 的真实当前配置读取。空选择保持未选择，不自动使用列表中的第一个模型。保存配置会按 AstrBot 的正式插件重载流程重新检查。
5. 通过既有 Owner 签名器和正式配对、会话及授权协议取得当前安装权限；安装管理权限另行按真实服务授予。运行时需要本机 `enabled` 和 Authority 设置服务的 `enabled` 同时为真。工作台修改 Authority 设置仍按 `next_restart` 生效，不会覆盖本机许可。
6. 在实际可信 HTTPS AstrBot 宿主上打开下列工作台相对路径。先登录 Dashboard，再完成独立 Owner 解锁；Persona/Memory 读取及日志、设置操作分别按当前权限执行。

```text
/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench
```

工作台 API base 为 `/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1`。Cookie、CSRF、Origin、TLS 和安装身份检查保留原有契约。Owner 私钥留在本地签名器；凭据、会话和生产数据均不随包分发。

## 从旧包上传升级

旧版 bootstrap 会在同一 AstrBot 进程中留下独立的 `sylanne3.*` 缓存，普通插件重载不会移除它。新包先验证完整 runtime 源码和原生库的代码代次。同一代次可正常重载；同目录的旧缓存或代次变化只安装新代码并显示固定的 **BLOCKED / runtime_restart_required** 提示，不调用旧业务对象，也不创建新 Owner、worker、模型或发送任务。维护状态会从 SDK 的实际路由列表撤下本插件旧 HTTP 入口，只留下 Dashboard 登录后可读的提示页与状态两个 GET；其他插件路由保留。撤下入口不终止已开始的请求或任务。

上传成功后，停止并重新启动整个 AstrBot 进程；Docker 部署重新启动实际 AstrBot 容器。插件页面的 reload 按钮不能完成这次迁移。真正的新进程会加载新类、LLM 选择和 setup 入口。用户配置与数据保留；此处的安装成功只代表代码已替换，未证明 Authority/Host 绑定或旧进程任务已经完全终止。

若旧插件卸载或安装回滚阻止上述路径，可通过 SDK 停用/卸载旧插件并明确保留配置与数据，然后结束整个 AstrBot 进程，在新进程上传本包。不同安装目录、prefixed 双 runtime 或源文件/manifest 不匹配继续拒绝，不转维护模式。

## LLM 选择与配置生效

高级配置统一放在工作台「设置」，按基本与工作台、模型策略、角色与场景、注意与表达、记忆与关系、Life 与行动、资源与安装分组。Host 配置使用真实 AstrBot SDK 保存并独立读回；角色领域配置使用当前签名 Owner 的 W01 草稿 CAS。完整操作与旧版对应关系见 [WebUI 高级配置](docs/install/webui-configuration.md)。界面明确区分保存、启动采样、安装绑定、草稿与已采纳状态。

AstrBot 配置页保留本机运行许可 `enabled`、已登记 Authority 配置档 `authority_profile`、SDK 原生主 LLM 下拉 `llm_provider_id`、独立 WebUI 监听设置及 D01–D13 模块开关。详细模型与领域设置在独立 WebUI 保存并回读。默认监听 `0.0.0.0:2718`，Docker 映射 `2718:2718`；TLS、Dashboard/Owner 与正式安装匹配分别核验。工作台的“安装配置 / LLM”入口读取实际选择、当前模型、两层运行许可及安装匹配状态；这个只读入口不授予 Owner 或业务权限。

所选 provider、当前模型及配置 digest 必须与正式安装主模型一致，实际会话选择也继续按原执行契约核验。不同 provider、模型或配置不会自动改用旧模型，也不会修改已有安装授权。当前 adapter 支持范围由正式模型传输保持；不支持的选择明确显示为不可用。

未匹配安装时，可在工作台显式导出 `llm-selection.json`。该文件仅含公开的 profile/provider/model 及配置 digest，是安装计划输入；API key 和原始 provider 配置保留在可信本地文件中。按 [正式安装计划接线](docs/install/linux-alpha1-lifecycle.md) 将其交给 `install_linux.py --model-selection`，先执行真实 `--plan`。选择不会自动增加预算或延长期限；已有安装的模型变更需要既有合格的配置/包变更协议，fresh-only 安装器不会原地覆盖。

正式安装器管理的宿主使用受保护的固定 Host bootstrap。此类安装的更新应走既有受控包替换协议，保留固定 shim 和安装身份；普通 ZIP 上传不授予替换受保护部署的权限。新鲜安装的模板和 plan 用法见上述生命周期说明，系统安装、证书信任和新 Owner 授权分别需要管理员批准。

## 验证范围与手动检查

源码编译、前端契约与构建、真实 Authority/mTLS 管理接口的既有收据分别保持其原范围。插件 ZIP 的结构、实际导入来源、native 和 release manifest 应以本快照的新收据核对；源码检查和归档检查不等于完整宿主安装通过。

导入后手动确认插件加载、可信 HTTPS 静态入口、Dashboard/Owner 两层验证、真实授权 Persona/Memory 投影、日志分页及设置写入后真实读回。再检查实际 GPU/WebGL、光盘居中、键盘焦点、主题切换与退出；会话失效、页面隐藏和导航后旧响应不得恢复授权。最终包还需在第二个全新隔离目录复验关键链路。未执行的项目保持 NOT RUN；拒绝和首次失败保留原证据。

Numeric、Contact/C09、D04 完整验收与生产 Host 独立身份继续按各自实际证据保持 HOLD。本次包不调用真实付费模型或 sender，不修改生产数据库，不直接修账。

许可证：[AGPL-3.0-or-later](LICENSE)。第三方声明与依赖清单见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 和 [SBOM.cdx.json](SBOM.cdx.json)。


## 独立 WebUI 与模块许可

AstrBot 插件配置保留本机运行许可、Authority 配置档、主 LLM、独立 WebUI 和 D01–D13 十三个开关。高级人格、记忆、Life、模型工作流等设置位于 WebUI。默认独立监听 `0.0.0.0:2718`，保存端口或开关后重载插件生效。AstrBot 插件卡片的 WebUI/Page 可读取实际监听和当前十三项许可，并给出入口地址。

Docker 给 AstrBot 服务增加端口映射 `2718:2718`；与现有服务的端口并列。浏览器打开 `http://宿主机地址:2718/`。`0.0.0.0` 是监听地址，不能作为用户访问地址。修改容器内部端口后同步修改映射。

TLS 复用 AstrBot `dashboard.ssl` 的 `enable`、`cert_file`、`key_file` 与现有 SSL 环境设置。未配置 TLS 时可打开前端和监听状态，登录、配置 API、Owner 和业务操作拒绝 HTTP。已配置 HTTPS 时使用 `https://匹配证书的域名:2718/`；后台登录复用真实 AstrBot 登录与 HttpOnly Cookie。填写已启用的二次验证码；凭据不会写入浏览器存储。

Owner 登录和管理仍要求已安装 profile 中精确的 `workbench_origin`。端口变化会改变来源；管理员需要通过正式安装协议登记新 HTTPS 来源。监听服务不会改写 Origin、迁移旧授权或放宽生产 Host 身份边界。缺少证书、端口占用、Dashboard 未就绪会明确显示当前原因，不自动换端口或关闭 TLS 检查。

模块开关保存后在下次重载冻结。本机开关只限制各模块接收新工作；开启不安装 optional workflow、不产生 grant、不解除领域 HOLD。已有终态、结算、原件读取、安全撤销和恢复保持可用。D11/D12 关闭后仍可进入配置、登录与恢复入口。旧 queued job 的首次模型或 sender 调用仍要满足模块许可及原有全部当前性与预算检查。

从其他源码快照升级时，进程中的 canonical runtime 保持旧代际，进入维护页；须完整重启 AstrBot 才加载新的运行库和独立端口。不要通过删除运行数据、导入旧 grant 或直接修账来绕过维护状态。
