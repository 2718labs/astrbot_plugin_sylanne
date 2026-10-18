# Sylanne Alpha2 / Beta1 服务器安装与同包复验

目标是 Linux x86_64/glibc、AstrBot 4.28.2、Python 3.12.3。安装交付是一件可由 AstrBot 本地 ZIP 入口导入的插件包，包含 Python 运行库、已构建的独立 WebUI 和原生 `.so`，不包含虚拟环境、SDK、Rust 工具链、node_modules、工程测试、数据或凭据。服务器安装与实际运行由用户执行；源码编译、归档校验和前端构建分别按各自收据报告。

Beta1 候选已合入实际产品源码，包括普通 Foreground／OwnerTask、Host Borrowed、独立 Core Model、Host 派发／调用封口／结果归档及 Joint 的完整配方展开。最终工程来源、运行插件和检查范围以同次冻结清单及交付收据为准。已有快照与全部首次失败证据保留；源码接线与本地回归不代替服务器运行、39 项整体、Contact/C09 FULL、D04 FULL 或生产 Host 独立身份验收。

## 当前 Beta1 交付合同

当前产品版本为 `3.0.0-beta1`，独立快照模式为 `beta1-candidate`，运行资格范围为 `backend-beta1-server-test`。最终运行插件名为 `astrbot_plugin_sylanne-3.0.0-beta1-linux-x86_64-glibc-beta1-candidate.zip`。它必须仅包含运行组件，完整压缩大小不超过 **16,000,000 字节**；工程测试、准备工厂与取证实现另随同次冻结的工程附件交付，不上传 AstrBot。只有实际生成并核对收据的包才能列为交付件。

Beta1 需绑定当次独立工程源码清单、运行源码清单、manifest 与未变 native 原件。`beta1_source_closure` 与 `beta1_python_compile` 必须依据该清单的真实收据；`beta1_server_acceptance` 保持 `not_run`，不能由构包或旧快照结果自动改成通过。源码冻结后，使用同次 `build_plugin_package.py --beta1-candidate`；不要以历史 Alpha2 模式替代。

隔离导入和完整进程重启的步骤相同，实际加载版本改核 `3.0.0-beta1`。HTTP 与 HTTPS 均可使用完整工作台；保持 Dashboard、Owner、Origin、CSRF、签名和正式安装来源检查。Numeric 与 D13 的历史完整节点、准备工厂和旧 PASS 只对各自冻结源码有效。当前运行时已移除旧 fixture gateway 与 LOCAL_FIXTURE 计数执行分支；仍依赖这些接口的历史工程节点不能直接标为新版可运行，更不能移植旧 PASS。新版 Numeric/D13 完整安装、native interval 与 trace adoption 在取得同次有效入口和真实原件前保持 NOT_RUN/HOLD。每个新版场景使用独立新 Root／setup／数据与收据，保留正式模板的预算和绝对期限；不复活旧授权，具体实例和 pins 由服务器管理员准备。

下面保留 Alpha2 的安装协议、历史场景和资源要求作为参考。旧版文件名、builder 模式、授权及 PASS 只属于原快照；Beta1 运行时必须采用最终交付的相同版本入口、源码／工程 pins 和 Root 模板。Contact/C09 FULL、D04 FULL、生产 Host 独立身份以及未在 Beta1 新快照执行的其他完整节点，继续逐项记录实际资格。

## Beta1 新安装的显式 Root 范围

服务器管理员先用同次插件内 `scripts/alpha1/install_linux.py --template --template-version 5` 生成请求模板，填入真实安装、模型、预算及 UTC 绝对截止后运行原 `--plan`。v5 新安装的计划会明确列出 `d01.conditioned_self_child.v1`；七个条件 Self 子步骤仍各自核当前 Owner、Source、真实前驱、同次 Graph 版本和独立 Core 完成回执。旧 v2–v4 模板与已有签名 Root 不会因此增加 work kind；旧安装没有该范围时，不能通过改配置字符串使其生效。

v5 模板新增 `habit_runtime: false`。只有管理员为这次新安装明确选择 `true`，安装计划才列出 `habit_subscription_v1` 和真实 SourceNote 执行种类 `d10.life.source_note.v1`，并在新 profile 中生成绑定实际 namespace、installation ID、manifest、Root lease、grant ID/version/完整摘要的 `HabitRuntimePolicyV1`。该值不是签发 standing policy，也不启动 occurrence；每个安排仍须由当前 Owner 正式签发，按实际 Source、cue、取消代际、预算和原期限逐步准入。安装器保持请求中原来的预算、单次上限和截止，不修改旧 grant，也不提供旧授权刷新。

在 `--plan` 输出中核对 `added_work_kinds`、`habit_runtime`、`root_budget_limits` 和 `root_budget_max_ceiling`，再按原新安装流程执行。包体、manifest 和请求 pins 必须属于同一个最终 Beta1 快照；本段只说明已接入源码的安装选项，服务器运行结果仍为 `NOT_RUN`。

## 当前 Artifact V3：独立观察与固定完成回执

这条路线使用新安装请求模板 v6 与精确的 `AdminModelWorkflowsV9`；`--template --template-version 6` 只生成待填写的正式请求，不升级旧 profile、旧 Root 或旧 V2 call plan。真实安装须明确配置 `artifact_observation_cognition`、受保护 observer 资产和对应模型的真实计数规则。计数器的 `production` scope 表示经过正式安装核验，不能把 Mock 模型的规则用于冒充其他 provider 的计数结果。

已确认的 tone_sample 调用顺序是 C1、C2、样本生成、样本独立观察、完整生成、最终独立观察，共六次；整轮原输入 48,000、输出 8,000 及单次上限不变。普通 full 方法是一轮生成和一轮观察。Artifact 路线不再调用 C5/C6：只有真实 `satisfied` 历史、文件 readback 和已登记检查原件齐全，才能由 D06 产生完成 Source，再经 D08/D09、实际 P2、D13 送达采用和正式完成 W01。固定文字只说明已登记工作已完成，并展示真实内容 SHA-256 和收据 ID，不保证生成内容的正确性。普通对话保留 C5/C6；`partial`、`accepted`、`unknown` 均不能替代 `satisfied` 或 `delivered`。

高级配置能读取 V9 精确槽位，并显示受保护的“Artifact 独立观察认知”安装匹配。这个槽位不通过浏览器临时指定另一个 provider；修改安装模型仍按正式安装变更协议执行。

包外工程节点位于 `rewrite/host_tests/alpha1/test_b04_installed_lifecycle_v1.py`：

- `test_artifact_v3_installed_sdk_fresh_root_six_calls_and_delivered_receipt`：新 Root 的实际 SDK→六次有限 MockTransport→真实结算及 delivered 回执。
- `test_artifact_v3_installed_sdk_unknown_observation_never_satisfies_or_sends`：独立观察返回 unknown 时不得满足任务或发送完成回执。
- `test_artifact_v3_installed_sdk_live_core_binding_tamper_then_original_six_calls`：字段篡改的实际 Host/Core 拒绝；这不是有效跨 Root 原件测试，其 future/expired envelope 情况也不是已签发 frame 时间门的证明。
- `test_artifact_v3_installed_sdk_two_fresh_roots_actual_foreign_objects_then_one_valid_admission`：两套真正独立安装的有效原件，分别替换 grant basis、lease、reservation 对、模型配置和安装 grant，保留首拒绝的具体层级。它验证原件身份绑定，不把早于领域语义的拒绝记成更深层授权证明。
- `test_artifact_v3_installed_sdk_owner_stop_cancels_queued_d07_and_refuses_original_runner`：独立新 Root 在真实前三次调用之后，暂停实际 D07 async runner 的 acquire 之前入口；通过正式 Dashboard＋Owner 命令取消同一 queued 子任务，再恢复原 runner 一次，核对确切 job 拒绝、provider 零增量与无新增费用。父 cycle 仍可能是 draining；本节点不声明 Core admission、全部子任务停止或整轮 cancelled。

这些节点及 Root 准备、计数程序、Mock 模型、诊断和只读分段取证工具均在工程附件中，不进入插件运行 ZIP。当前本机只有源码整合和明确列出的受影响回归，以上完整 Linux 安装节点均为 **NOT_RUN**。缺少 setup 而 SKIP 也不表示通过。

单 Root 节点使用新的 `SYLANNE_ARTIFACT_V3_INSTALLED_SETUP`；双 Root 节点使用新的 `SYLANNE_ARTIFACT_V3_CROSS_ROOT_SETUP`。实际 Host helper 必须先由 Root 按工程清单 SHA 准备和保护；双 Root helper 路径及保护字段见同次 `artifact_v3_cross_root_witness_v1.py` 的文件头。需要具体内部拒绝原因的节点还要求 `SYLANNE_ARTIFACT_V3_AUTHORITY_DIAGNOSTIC_LOG` 指向现有 Core 诊断日志。检查器只记录安全异常类别、源码位置和哈希，不采集凭据或密钥；通用 RPC 错误本身不构成具体拒绝原因。

每个节点使用全新数据和独占证据目录，串行单次执行。双 Root 节点内部仅将两次实际 ingress 并行，以在各自原期限内取得原件；负例仍逐项核对，再唯一转交 A 的原请求。B 保留原 prepared 未消费状态，不自动释放、清账、重放或延长期限。原件若在准备过程中过期，记录精确到期差值并失败，不能记为跨授权拒绝通过。只读 forensic snapshot 校验实际 cell 的完整分段、origin、EOF、哈希和签名，不注册业务读取 Work，也不提供新的 Source 权限。

Owner StopReply 对 phase-C4、独立观察和固定回执的完整子任务清单、pending 状态、管理读取与实际 W01 投影已接入产品源码。Core/Host 使用实际 Owner 元数据读取 Work 和私有完成证明；C09 构建按原量子推进完整 EOF 后消费证明，fresh cold 从头独立核验，不重用构建期游标，也不扩大字节、时间或 arena 上限。D07 runner 收到原 acquire 拒绝时直接返回该拒绝，不再读取不存在的 acquired request。这些源码核对与局部回归不代表完整取消或冷恢复服务器节点已通过。

取消节点另需 `SYLANNE_ARTIFACT_V3_OWNER_HTTP_SESSION` 指向 Root 保护的当前真实会话 descriptor。其 schema 是 `sylanne.test.actual-owner-http-session.v1`，精确字段为 `schema`、`base_url`、`cookie`、`csrf_token`、`installation_id`、`manifest_digest`。`base_url` 是这个独立 fixture 正式登记的 loopback HTTP origin，例如 `http://127.0.0.1:2718`，不带 workbench 路径；必须与该安装的 exact workbench_origin 相同。实际请求使用 `/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1/commands`，并发送相同 Origin、当前 Dashboard＋Owner Cookie 和真实 CSRF。先通过正常后台登录和 Owner 配对取得这些原件；不可合成 session、挪用生产 Cookie 或改旧 profile 来源来满足测试。descriptor、Cookie 和 token 只留私有测试环境，不能贴入收据或交付包。

五个完整 Artifact 节点当前均为 NOT_RUN；Owner StopReply/C09 的完整运行、Contact/C09 FULL、D04 FULL、生产 Host 独立身份及 Numeric/D13 新快照验证仍按各自真实证据记录，整体资格保持 HOLD。

## Alpha2 安装交付与冻结输入（历史协议参考）

日常安装只上传 `astrbot_plugin_sylanne-3.0.0-alpha2-linux-x86_64-glibc-alpha2-candidate.zip`。按此包新生成的交付收据核对完整 ZIP SHA256 与包内 `release-manifest.json` SHA256。服务器复验另外使用同次冻结的 `current-source.zip`、`source-manifest.json` 与其外部 SHA256；它们是测试来源，不上传到插件管理器。

同次冻结之前应具备以下实际材料：

1. 所有产品源码合入完成，主任务记录明确的剩余项目；全部实际 Python 源码已在内存编译，前端构建资源与 `workbench-manifest.json` 已同步。不要把旧编译收据当作新源码验证。
2. 冻结来源包含打包器、安装文档、永久测试与 `scripts/alpha1/verify_server_installation.py`，保存完整成员大小及 SHA256。使用新目录保存 `source-input/`、源码 ZIP、source manifest 和 scoped snapshot evidence；旧目录不清理或覆盖。
3. 同次冻结中的目录/文件列表排除数据库、WAL/SHM、日志、API key、Owner 私钥、虚拟环境、缓存与开发构建树。插件打包继续使用既有 allowlist，前端只带构建资源。
4. 未变化原生原件为 `libsylanne3_kernel.so`，596248 bytes，SHA256 `2883b3bd4af107a953fe86c6ee785da1fc51688e36e7a9f5fef7d7016d91d56c`。包内路径是 `rewrite/sylanne3/_native/linux-x86_64/libsylanne3_kernel.so`。本次复用原件，不重建、不借其证明新业务 PASS。
5. 仅对新冻结 `source-input/` 调用既有 `rewrite/tools/build_plugin_package.py --alpha2-candidate`，传入实际原生原件、既有 development-handoff baseline manifest、对应 archive pin 与本次 scoped snapshot evidence。`source-manifest.json` 是新的工程冻结清单；它与 schema 为 `sylanne.dot.development-handoff.v1` 的历史 baseline 是两个不同输入，不能互换。
6. 单次构建后重新读取 ZIP CRC、全成员大小/hash、release manifest、source inventory、工程来源和原生 pin。独立输出 ZIP 使用 exclusive 创建；已有 ZIP 或中断后留下的 ZIP 都保留，下一次不得原地替换。

构建工具输出当前明确的 candidate 文件名。最终安装交付如需较短文件名，建议 `astrbot_plugin_sylanne-3.0.0-alpha2-linux-x86_64-glibc.zip`，同时保留收据中的原名和实际 SHA256；文件重命名不改变包内 qualification 或验收状态。只有包实际存在且收据完成后才列为交付件。

## 在隔离 AstrBot 中导入

使用一个新的 AstrBot 数据卷、插件目录和容器名，与生产 AstrBot 数据彻底分开。保留服务器上的原 AstrBot 卷、所有 Sylanne DB/WAL/SHM 和旧授权文件；新包上传不会完成旧数据迁移。

先确认实际容器内 Python/SDK 与目标版本一致，宿主为 x86_64/glibc。继续使用现有已确定的 AstrBot 4.28.2 镜像和启动方式，把 `2718:2718` 与现有 Dashboard/适配器端口映射并列。端口映射只开放独立前端；不要复制生产 OneBot token、LLM key 或 sender 到验证容器。镜像、SDK 和测试依赖来自服务器管理员已准备的环境，不随插件 ZIP 分发。

在这个隔离 AstrBot 的插件管理中上传插件 ZIP，核对名字 `astrbot_plugin_sylanne`、版本 `3.0.0-alpha2` 和实际加载日志。首次保留 `enabled=false`，导入不会代替正式 Authority/Host 安装绑定或 Owner 授权。若从另一源码代际上传，实际 AstrBot 进程可能报告 `runtime_restart_required`；完整重启此测试容器后再检查新进程加载，插件 reload 不能替代进程重启。

本机配置包括运行许可、已登记 Authority profile、SDK 主 LLM 下拉、独立 WebUI 设置和 D01–D13 开关。详细设置在独立 WebUI 保存并读取真实结果，见 [WebUI 配置](webui-configuration.md)。默认监听 `0.0.0.0:2718`；实际协议继承 AstrBot 的 Dashboard TLS 配置及对应环境变量。未启用 TLS 时访问 `http://服务器IP:2718/`；已启用 TLS 时访问 `https://证书对应域名:2718/`。不能把 `0.0.0.0` 当访问地址。

HTTP 和 HTTPS 均提供完整工作台入口，后台登录、配置读写及 Owner 操作继续验证实际 Dashboard Cookie、Origin、CSRF、签名和已登记安装来源。HTTP 传输未加密；此模式已由用户明确知情授权。TLS 为可选部署方式，按 [TLS 与正式安装生命周期](linux-alpha1-lifecycle.md) 配置实际证书后完整重启。无论协议，Owner 的 exact workbench_origin 必须与正式 profile 相同，不能静默迁移已有来源。

若浏览器出现 ERR_EMPTY_RESPONSE，先看插件启动日志中 Sylanne WebUI 输出的实际 state、scheme、bound_addresses 和 access_hint。只有 state=listening 且存在实际绑定地址才表示端口已成功绑定。HTTP 请求发往 TLS 端口可能直接被关闭；这与插件未启动、绑定失败或 Docker 未映射是不同原因，不能单凭浏览器截图判断。

不知道如何找日志时，可在服务器依次检查以下三点：

1. 在 AstrBot 插件配置里确认独立 WebUI 已启用，监听地址为 0.0.0.0，端口为 2718；如需调整，保存后重载插件。以启动日志打印的实际协议为准。
2. 在 Docker 管理界面确认 AstrBot 容器确实公开 2718/tcp 到宿主机 2718。管理员也可用以下只读命令查看已有映射：
   `docker ps --format '{{.Names}}\t{{.Ports}}'`
3. 先在容器内访问实际协议的 127.0.0.1:2718，再从宿主机和浏览器访问。HTTP 入口可用 `curl --max-time 5 -I http://127.0.0.1:2718/`；HTTPS 使用证书匹配域名和已配置的 CA 验证，不关闭证书检查。记录首次响应或首次错误及时间。

本机 Windows 的监听、Cookie、配置和普通非安全 HTTP 浏览器验证仅证明对应本地接口行为。服务器此前上传后的日志已明确报告 runtime restart required；用户完整重启后前端恢复，随后 HTTPS-only 页面门成为本轮修正对象。新包的 Linux/AstrBot4.28.2 完整安装仍须实际核验，不转移旧快照 PASS。


## 正式 Authority/Host 安装

需要正式完整运行时，从新包的实际提取目录执行安装器，先生成当前 v4 模板并填写真实 UID/GID、Host executable/entry pins、namespace、provider/configuration、资源与预算、原始期限和安装 origin：

```bash
python -B "$SYLANNE_INSTALLED_ROOT/scripts/alpha1/install_linux.py" \
  --template --template-version 4 > reviewed-install-request.json
```

模板包含必须明确选择的值，不能直接安装；文件留在隔离服务器的管理员私有目录。按实际 Host LLM observation 需要的 `--model-selection` 输入检查并执行真实 plan：

```bash
python -B "$SYLANNE_INSTALLED_ROOT/scripts/alpha1/install_linux.py" \
  --package "$SYLANNE_PACKAGE" \
  --package-sha256 "$SYLANNE_PACKAGE_SHA256" \
  --manifest-sha256 "$SYLANNE_MANIFEST_SHA256" \
  --request reviewed-install-request.json --plan
```

在确认此 plan 后，由服务器管理员针对这个新隔离安装执行同参数 `--install`，再按生成的固定 Host/Authority 启动配置继续。v4 模板支持固定 process supervisor；Docker 容器中没有真实 systemd unit 时，不填一个虚构的 unit。AstrBot ZIP 导入和正式 root-owned Host shim 管理是不同部署步骤，已受保护部署的更新按现有 package/configuration change 协议执行。完整正式身份建立、Owner 初始化、业务运行和 C09 冷恢复各自查验实际原件，见生命周期说明。

## 生产 Root lifetime 的独立安装原件

新源码提供 `scripts/alpha1/authority_linux_root_lifetime.py`。它的外层 Root observer 持续保管旧 cohort 的真实进程与 namespace 句柄；内层 PID1/Authority 消失后，必须先取得旧 cohort 完整退休原件，再允许新 Root 启动。服务器上的这一链路尚未实测；下面的操作由服务器管理员在隔离安装中执行。原始资源截止时间包含旧 cohort 的退出与完整 EOF；允许新工作和通信的截止点为原截止时间减去已安装 Host 的原 drain 时间。剩余时间不足 drain 时不启动新 Root，不能额外增加清理窗口。

准备 root 所有、祖先目录不可被 group/other 写入的 launch-scope JSON，其 schema 为 `sylanne3.installed-root-launch-scope.v3`。字段严格为 `schema`、`authority_id`、`installation_id`、`namespace_cohort`、`profile_id`、`outer_entry`、`python_executable`、`inner_entry`、`host_spec`、`authority_spec`、`control_socket_path`、`protected_state_directory`。五个 entry/spec 字段均为实际绝对 `path` 与实际文件 `sha256`；namespace cohort 只包含本次安装的一个正式 namespace。Host/Authority spec 使用已安装的正式原件，不能填 SDK fixture 身份。不要在 launch-scope 中自行填最终 spec digest 或资源批准引用。

先在真实 cgroup v2 下配置并核对这次生产安装获准的 `cpu.max`、`memory.max`、`pids.max` 与原始 UTC 截止时间。SDK 验证的资源值只属于相应 fixture，不能搬作生产批准。缺正式批准或身份不匹配时保留 HOLD。以下占位参数必须替换为管理员实际批准值；此命令不会创建资源额度，也不会启动服务：

```bash
sudo /实际安装/python /实际安装/scripts/alpha1/authority_linux_root_lifetime.py install-lifetime \
  --launch-scope /实际受保护目录/root-launch-scope.json \
  --output /实际受保护目录/root-resource-approval.json \
  --operation-ref '本次正式安装操作标识' \
  --unit-name '实际systemd单元名' \
  --cgroup-path '/实际cgroup绝对路径' \
  --cpu-max '实际cpu.max原值' \
  --memory-max '实际memory.max原值' \
  --pids-max '实际pids.max原值' \
  --deadline-utc '管理员原始UTC截止时间'
```

命令独占创建资源批准原件，再独占创建 `/etc/sylanne/supervision/root-lifetime.json`，最终重读两件并同步文件及父目录。若写入返回未知状态，先保存命令输出和现有原件；仅用同一次 operation 与相同参数重新完成缺失件。已有原件内容不匹配会拒绝，不能删文件重签、换 operation 或续期来掩盖首次失败。

配置实际 systemd 单元启动同一固定 Python 与 `authority_linux_root_lifetime.py`，不附行政子命令。外层 observer 运行后，管理员使用同一入口的 `start-root` 子命令请求首次内层 Root；后续恢复也通过这一正式入口。确认实际固定 argv、所有者、文件哈希、cgroup 限额及 observer 的持续身份，保存启动、握手与旧 cohort 退休原件。仅看到进程 running 不代表业务准入或 C09 冷恢复通过；observer custody 丢失、期限失效或旧 cohort 未完成 EOF 时应保持拒绝。

D13 派生块 metadata 的历史 V1 只绑定 Source；当前 V2 独立绑定每个 turn 的 completion／Source／access 有序三元组。新安装只生产和采用 V2，历史 V1 保留原解码与删除取证，不补造依赖、不转成当前授权。第 42 份快照首次构包因旧 catalogue 与新校验语义不一致而被拒，原目录及首次拒绝收据保留；它没有可安装 ZIP。修复后的新快照须以实际 registry 导出的 164-type catalogue 和独立包 SHA 为准，历史 TARGET163 不改写，也不自动成为新的迁移来源。

## Numeric 与完整 D13 的永久单次 runner

只在隔离 Linux 环境、同次新冻结源码和实际提取安装根上运行。环境需要已确定版本的 pytest、pytest-asyncio、httpx 和 Authority 依赖；runner 显式加载 pytest-asyncio，禁止自动加载无关 pytest 插件。测试依赖不写入插件 ZIP。

先列出确切 node；此命令只列出入口，不运行测试：

```bash
python -B "$SYLANNE_TEST_SOURCE_ROOT/scripts/alpha1/verify_server_installation.py" --list-nodes
```

所有永久 CLI 都由 fresh 单线程 Root observer 调用同一个 `run_owned_resource_profile_v1`，在真实 owned app 内执行固定范围。给一个新且不存在的 receipt 目录；它的父目录须已存在且位于声明 `fixture-root` 内，不能指向已保留的失败目录。普通 Numeric/D13 另需声明已核提取安装所在的 `installed-stage-root`，同样提供 dependency manifest 与 approved initial request 的外部 pins；各节点仍由原 fixture 独立生产正式授权，不复用旧 grant。以下例子只运行 Numeric 正例一次：

```bash
python -B "$SYLANNE_TEST_SOURCE_ROOT/scripts/alpha1/verify_server_installation.py" \
  --node numeric-positive \
  --package "$SYLANNE_PACKAGE" \
  --package-sha256 "$SYLANNE_PACKAGE_SHA256" \
  --manifest-sha256 "$SYLANNE_MANIFEST_SHA256" \
  --installed-root "$SYLANNE_D04_INSTALLED_ROOT" \
  --source-root "$SYLANNE_TEST_SOURCE_ROOT" \
  --source-manifest "$SYLANNE_SOURCE_MANIFEST" \
  --source-manifest-sha256 "$SYLANNE_SOURCE_MANIFEST_SHA256" \
  --output-dir "$SYLANNE_VERIFY_RUN" \
  --delivery-root "$SYLANNE_DELIVERY_ROOT" \
  --fixture-root "$SYLANNE_FIXTURE_ROOT" \
  --installed-stage-root "$SYLANNE_INSTALLED_STAGE_ROOT" \
  --cgroup-parent "$SYLANNE_CGROUP_PARENT" \
  --dependency-manifest "$SYLANNE_DEPENDENCY_MANIFEST" \
  --dependency-manifest-sha256 "$SYLANNE_DEPENDENCY_MANIFEST_SHA256" \
  --approved-install-request "$SYLANNE_APPROVED_INSTALL_REQUEST" \
  --approved-install-request-sha256 "$SYLANNE_APPROVED_INSTALL_REQUEST_SHA256"
```

`numeric-positive` 对应新固定 family `numeric_positive` 的一个正例；`numeric-authorization` 对应 `numeric_authorization_groups`，选择同文件正式六组参数化权限负例（installation/lease/reservation/configuration/worker/time），不含 registration；`numeric-registration` 对应 `numeric_registration` 的一个正式 registration/replay/cancel 节点；`d13` 对应 `d13_full` 的完整五节点，包含 standby/current/cold/no-charge replay、expired、授权 ceiling、V6 derived replay 与 expiry/lost-ack。这些新 family 保留旧 `numeric`、`numeric_authorization`、`d13` 三节点与 `d13_v6` 两节点的原含义。各 CLI 一次监管运行，选中 family 内串行，首失败即停，不拆成多个重试。不同选择项使用不同新 receipt 目录，不把它们放进自动循环。

runner 在创建 receipt 或启动 fixture 前核对外部 package/source pins、全部源码成员、ZIP CRC、release manifest、完整安装文件和包/工程源码逐成员配对。产品首先从提取包加载 canonical bootstrap，工程源码只提供测试及支持代码。文件名和 `::node` 分开定位；`--basetemp` 指向新 receipt 内尚不存在的 `fixture/`，不会替换旧 fixture。

输出包括 `run-input.json`、`run-result.json`、`resource/` 内独占创建的实际 stdout/stderr、resource metrics、`resource-run-original.json` 和完整 `fixture/`。Numeric、D13 与 SDK 的 pytest 场景另保存 `pytest-outcomes.json`：所选全部实例实际调用通过且 collected 等于固定 selector 的实例数、没有跳过或收集错误、实际 child exit0，并有真实 pidfd、空 populated、owned group 移除与所需 controller restoration 原件。C09 current 使用下节的 `root_controlled_four_phase` 合同及 `resource/actualphase-outcomes.json` 原件（schema `sylanne.actualphase-outcomes.v3`），核验四个实际 phase worker 的 birth、退出、逐阶段 cgroup EOF、顺序与最终 metadata assertions；不生成或借用 pytest collected 判定。缺少依赖、SKIP、超时、崩溃、资源不足或缺结果都保持 HOLD，保留首失败，下一项不自动运行。原 2 CPU/2 GB/1000 秒/8 MiB 约束应用于完整选定 fixture 子树，不推断整机资源 qualification。

Numeric 正例须分别查验专属实际 admission、有限 MockTransport 次数、observation/terminal、reservation/settlement、真实 native interval/result/CPU cost、joint adoption 和 trace 原件。仅 prepared/running/reserved 不证明执行或结算；负例须先有完整其余真实前提，再证明指定拒绝、零 provider 与无新增账务。共享 C09 fee helper、FULL executor、Source 材料读取或当前性路径改动后，D13 必须在新快照完整运行，旧快照 PASS 不迁移。FULL 的 C02／C04／draft 路径还须分别核对实际原件读取完成、READ→WRITE 重新观察，以及未提交失败的 fence 清理；不能用普通编译代替这些运行原件。

D13 standby 的人工验收使用同一隔离安装和新包原件，不新增 CLI，也不代替上述完整 D13 节点。按实际安装入口安排以下场景，逐项保留首次结果、实际日志与授权原件：

- 让实际业务产生多份匹配或不匹配当前 conversation 的 standby、active、retired 块，确认每个 valid typed cell 的四个固定标量、header/SHA/有序 segment root 和完整 EOF 均核验后才推进 cursor。即使已找到未过期 standby，也须完成整个 namespace census；negative 只有完整 EOF 才成立。
- 核对读取状态只保留一个最大 expiry 标量，不保留随块数增长的 expiry list/tuple；判定仍为最大 expiry 是否晚于真实 window 时间。大量历史块不能靠漏计内存通过原 pool 限额。
- 在首次准备后推进真实时间或等待读取跨越原 deadline，确认保持拒绝、不开始新付费调度。后续调用不刷新首次准备 deadline，也不延长已保存 intent/job 的原期限；需要更换场景时另行准备新隔离原件，保留旧失败。
- 在读取期间取消调用，或通过实际入口触发 mapper/lifetime 异常，确认同一个已接 Work 按原协议终结，proof/payload 与原 retention 清理各执行一次，process lease 在 mapper 结束或异常清理后释放。结果已正常转交时由原 consumer 的 `finally` 释放；不能因取消、弃置或异常遗留活 lease、复跑同一 Work 或新增账务。

这些条目当前均待实际服务器验收。后台、方法与 Authority 的本轮接线仍在编码中，本节不声明其完成或通过。

## C09 当前 V3 完整链路

`--node c09-current` 对应独立固定 family `c09_current` 的一个实际永久节点：

```text
rewrite/tests/alpha1/integration/test_c09_installed_life_archive_v1.py::test_installed_completed_life_segmented_four_role_current_v3
```

它执行同一 fresh 安装的非空 C04、draft 与 natural 原件，完成原 Life/Host retired 后，再沿真实 V3 segmented 四 roles 执行 business、prepare/switch、release、cold 四个不同实际进程。所有进程串行，属于同一次 owned resource 子树；每 phase 原 600 秒上限不扩大整个 1000 秒资源期限。原 2 CPU/2 GB/8 MiB 日志上限、首失败停止、SKIP 不通过及完整旧失败目录保留规则不变。此新 selector 不引用 legacy/codec 节点，也不迁移旧运行资格。

此 family 使用 `c09_root_phase_harness_v3.py` 的 `root_controlled_four_phase` 实际调度合同。Root 控制器只核已 pin 的源码、安装与 setup 元数据并调度四个固定 phase，不加载领域 bundle、业务 key 或业务 Source。每 phase 只有一个实际 OS worker：Root 在 GO 之前把其真实 PID/birth 放入 owned app cgroup；SDK/Authority 与实际 fixture 在该同一 worker PID 内运行。上一个 worker 必须退出且实际 app cgroup 完整 EOF 后，Root 才能启动下一个 phase；不会把 pytest controller 或其他角色从 census 排除来声称 singleton。

Root 使用 fresh Unix `SOCK_SEQPACKET` channel 和真实 `SO_PEERCRED` 核对 worker，环境接口为 `SYLANNE_QUAL_ROOT_CENSUS_SOCKET`、`SYLANNE_QUAL_ROOT_CENSUS_PHASE`。受保护的 `c09-sdk/peer-cohort.json` 实际字节 SHA 和 selection scope 与 Root setup 对齐；SDK 独立验证 descriptor/HMAC/安装许可。held channel 跨实际 activation commit 保持唯一 worker/start exclusion，release 必须带回原 hold request digest、nonce 与 token。Root 物理 census 和 SDK 安装资格分别核验，requested descriptor digest 仅作关联。

本 family 的实际结果写入 `resource/actualphase-outcomes.json`，schema 为 `sylanne.actualphase-outcomes.v3`，保留四个真实进程的 birth、exit、pidfd、按序 phase 原件、逐阶段 cgroup EOF，以及全 run 起止与资源记录。CLI 核真实四阶段 metadata assertions 和 cleanup 证据；它不写 pytest outcomes，不声称 `collected=1`。原永久 node/source pin 保留为固定资格入口。其它 pytest family 的收据合同保持不变。

metrics、stdout、stderr 的字节累计在四个 phase 间共享同一个 **8 MiB 总上限**，不会按 stream 或 phase 重置。leader pidfd 报退出后立即取真实 exit；失败或仍有实际 descendants 时立即清退 owned subtree，保留首错与原 stderr，核完整退休 EOF。现有 2 CPU、2 GB、全 run 1000 秒及 phase 600 秒上限不变。目录、日志与收据独占新建，首次失败不会重试或覆盖。该源码实现尚未在 Linux 运行；冻结新 package/source/dependency/setup 全部 pins 并取得对应实际 launch 授权后，才可执行此 harness，当前不能作为新安装/资源 PASS。


在前述共同 package/source/dependency/request/安装根参数之外，使用：

```text
--node c09-current
--phase-fixture-setup /srv/sylanne-qualification/root-setup/<fresh-id>/setup.json
--phase-fixture-setup-sha256 <EXTERNAL_SETUP_FILE_SHA256>
--phase-setup-root /srv/sylanne-qualification/root-setup
--engineering-inventory-sha256 <EXTERNAL_CANONICAL_ENGINEERING_FILES_SHA256>
--sdk-root /srv/sylanne-qualification/official-astrbot-4.28.2
```

服务器 Root 必须先由真实 `prepare_protected_phase_fixture_v2(..., source_note_initial=True, completed_life_content=True, sdk_root=<actualSDKRoot>)` 建立 fresh setup v3；保持原 typed initial config、同一个 namespace、隔离 data_dir、原 root plan，以及 Root 预置 mode-0640 的实际组件 key。setup JSON 沿原 Root 所有、mode-0644、祖先不可 group/other 写的保护规则；不能用普通用户 JSON 或历史请求替代。此步骤仍由服务器管理员执行，runner 不签发权限，也不补写原件。 当前 v3 setup 还必须由同次 Root 准备正式 C09 installation assets、cohort 与双路径 plan：使用实际 Root profile、TLS、public Authority ID、官方 typed inventory 和原预算，预置 control key、installation IDs 与已签 controlled SDK descriptor。business 与 cold 阶段仅消费这些原 key、roots 和 descriptor，不重新签发。旧 setup v3 若缺这些资产不能复用，也不能仅靠 schema 名称通过前置；controlled SDK 的实际 OS cohort 全集与持续启动排他仍须由正式 Root 原件闭合后才可执行该节点。

工程 companion 的父目录必须包含 `frozen-engineering-inventory.json`，schema 为 `sylanne.engineering-source-inventory.v1`；上述 pin 是其 `files` 数组按既有 canonical JSON 算法计算的 SHA256，须与文件中 `sha256` 及源 companion 的成员 pins 一致，不能使用整个 inventory 文件的 SHA256 代替。runner 将核对该值，并把精确 installed root、manifest、工程 root/inventory pin、protected setup pin 和实际 SDK root写入受控 spec/收据及子进程环境。C09 的四个普通 UID phase worker 保留各自实际 stdout/stderr 与进程原件；Root observer 保持 `resource/` 私有，并写入上述 `actualphase-outcomes.json`。CLI 核受控 spec 绑定的四阶段原件、完整顺序、metadata assertions 与真实 cleanup，不沿 pytest collected/skip 判定。实际 Runtime 仍待此新完整 snapshot 的一次服务器执行。

## V7 256-slot SDK 与资源前提

V7 的精确入口是：

```text
rewrite/host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_l03_actual_installed_sdk_d13_v7_256_current_core_count_paid_native_cold_replay
```

它需要实际 root 权限、PID/mount namespace、`unshare`/`nsenter`/bind mount、可写且允许委派的 cgroup v2 和 pidfd。普通受限 Docker 环境可能不提供这些能力；服务器管理员须使用可隔离的测试容器/虚拟机和已核对的委派资源环境。不能把生产数据卷挂进去，也不能把 capability 拒绝记为 PASS。

正式 V7 counter 还要求 fixture 已位于永久 `owned_resource_profile_v1` 监管器创建的 `/sylanne-owned-<UUID4>/app`。该监管器原有 2 CPU、2,000,000,000-byte run 总预算、app 1,342,177,280-byte memory.max/1,073,741,824-byte memory.high、无 swap 和原始最大 1000 秒外部截止保持不变。这个 profile 证明限定 fixture 子树的资源观察，不能证明整台服务器或生产容器配置。

V7 使用新 `SYLANNE_SDK_M1_PACKAGE`、`SYLANNE_SDK_M1_PACKAGE_SHA256`、`SYLANNE_SDK_M1_MANIFEST_SHA256`、`SYLANNE_SDK_M1_DEPENDENCY_MANIFEST` 和 `SYLANNE_SDK_M1_APPROVED_INSTALL_REQUEST`。dependency manifest 核对实际 executable 与每个 SDK/dependency 文件；profile 为 AstrBot4.28.2/Python3.12.3，必须从服务器真实字节重新准备外部 pin，历史本机依赖路径与 hash 不等于服务器环境。

由 `sdk_d13_v7_256_root_fixture_v1.approved_sdk_d13_v7_256_initial_request_v1` 对新安装准备已批准足额的初始 Root 总预算，原单次 6000/1024/7024 限额和原始期限不变。先审阅再签发新隔离授权，不改旧 grant、不复活过期对象；runner 不创建或刷新请求。

正式 `--node sdk-v7` 使用与 Numeric/D13 相同的永久资源监管器建立并核验 app，随后只运行这一个完整节点。它同样提供共同的交付根、receipt 根和真实 cgroup parent；SDK/request 输入使用以下新包的 V7 明确 pins（`--installed-stage-root` 对 SDK 场景不要求）：

```bash
--delivery-root "$SYLANNE_DELIVERY_ROOT" \
--fixture-root "$SYLANNE_FIXTURE_ROOT" \
--cgroup-parent "$SYLANNE_CGROUP_PARENT" \
--dependency-manifest "$SYLANNE_SDK_M1_DEPENDENCY_MANIFEST" \
--dependency-manifest-sha256 "$SYLANNE_SDK_M1_DEPENDENCY_MANIFEST_SHA256" \
--approved-install-request "$SYLANNE_SDK_M1_APPROVED_INSTALL_REQUEST" \
--approved-install-request-sha256 "$SYLANNE_SDK_M1_APPROVED_INSTALL_REQUEST_SHA256"
```

wrapper 必须由隔离服务器的 fresh 单线程 Root Python 调用，不能在已经导入 AstrBot/sylanne3 的进程里调用。它使用实际 `sys.executable`；SDK 根由已核外部 dependency manifest 的 `official_sdk_source` 派生，显式 `--sdk-root` 只允许同一真实值。交付布局仍严格要求 `delivery-root/<新快照>/插件ZIP` 和同快照 `source-input/rewrite/`，fixture/evidence 必须是声明 receipt 根的子路径，新目录独占创建。`--output-dir` 须位于 `--fixture-root` 内且不在 source-input 或安装代码内。裸 `--fixed-child` 仍检查真实 UUID4 app cgroup，不能伪造环境来跳过监管。其他已有固定 family 可继续通过 `OwnedResourceRunV1` 与 `run_owned_resource_profile_v1` 使用同一个正式监管器。新关键字输入是 `delivery_root`、`fixture_root`、`installed_stage_root`、`sdk_root`、`phase_setup_root`；对应环境输入为 `SYLANNE_QUAL_DELIVERY_ROOT`、`SYLANNE_QUAL_FIXTURE_ROOT`、`SYLANNE_QUAL_INSTALLED_STAGE_ROOT`、`SYLANNE_QUAL_SDK_ROOT`、`SYLANNE_QUAL_PHASE_SETUP_ROOT`。delivery/fixture 根必须显式提供；非 SDK family 另外明确 installed-stage 根，phase family 另外明确 root-owned 辅助资产根。解析值随 frozen spec 传给 child，不在 child 重新猜路径。实际 Python hash、完整 spec、cgroup parent、期限和日志上限写入 `resource-run-original.json`；phase outcomes 留在其已有普通用户 evidence 目录，其余 outcomes 留在 root-private observer evidence 中。缺参数或路径不匹配是拒绝，不默认回退到旧机器路径。

V7 需要真实 Core count、generation/review、native/cold/replay 和完整 C09 lifecycle 原件；parser 通过与完整 SDK 通过分别记录。

## A06 实际跨日 SDK 单次 phase

`--node sdk-real-elapsed` 的正式入口为：

```text
rewrite/host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_a06_actual_installed_sdk_real_elapsed_day0_day4_day5_resume
```

这个新独立 family 不移植普通两消息场景的资格。使用同一个隔离安装、外部 package/manifest/dependency/request pins 和同一个私有绝对持久根，按 `day0`、`day4`、`day5` 三个明确阶段调用；每个阶段都沿真实 owned resource profile、同一固定单节点、原 2 CPU/2 GB/1000 秒/8 MiB 运行。每次使用不同新 receipt 目录和资源 UUID，业务的 installation、namespace、四存储数据、Owner principal 与累计模型调用账本留在原持久根，不能随 resource 进程重启重置。

在普通 SDK 共同参数之外，添加：

```bash
--node sdk-real-elapsed \
--phase day0 \
--phase-root "$SYLANNE_REAL_ELAPSED_ROOT" \
--phase-approval "$SYLANNE_REAL_ELAPSED_APPROVAL" \
--phase-approval-sha256 "$SYLANNE_REAL_ELAPSED_APPROVAL_SHA256"
```

`day0` 可由 fixture 创建新 `0700` root-private 持久根；也可使用管理员创建的新空私有目录。`day4/day5` 必须明确指向原来已经存在的根，不能使用新根、清空目录、重新开始 day0 或修改旧 grant/session。持久根与每次新 `--output-dir`、fixture/evidence、工程源码和安装代码分开。wrapper 不删除这个根；实际 SDK fixture 保留 `private-phase-packet.json` 及 installed `b04-durable-fixture`，含私有凭据的内容只留隔离服务器。

初始批准文件须由管理员独立准备并给出外部 SHA256，schema 为 `sylanne.sdk-real-elapsed-initial-approval.v1`，包括原 approved v4 request 的 `canonical_digest`、精确 package/manifest pins 与新场景的 `max_total_calls=18`、`max_episode_calls=6`、`max_auxiliary_calls=2`。这个新场景的初始总范围在首次签发时明确批准；wrapper 不创建批准、不增加旧场景限额，也不刷新授权。day0 原预算截止必须本来就覆盖至少真实五天加300秒，原期限不足保持 HOLD。

只有真实 Source `learned_at` 原件证明已过去96小时，day4 才能继续；day5 与原 day4 Source 之间要再有实际24小时。时间未到返回 WAITING/SKIP，零 Host/input；SKIP 在监管器有效退出码为2，不能记 PASS。不 sleep、不 patch clock、不回填 `learned_at`。day4/day5 通过正式 fresh credential 初始化恢复同一 Owner principal，不复活原 session。`real_elapsed_phase_gate_v1` 及已保存私有 packet 复核 package/manifest/original approved request、Host/controller/helper pins 和实际已安装四文件身份；真实 SQL ledger 保留跨进程总调用计数。

每次收据记录实际 phase、相同持久根和批准 SHA，`resource-run-original.json` 还保存全部 spec。阶段成功只证明该阶段；整个真实跨日链须最后 day5 同时验证 day0/day4/day5 原件、原作品同 effect、实际修订及次日 SDK 新入站。源码、入口注册与软件格式校验不证明真实96h/24h已经发生。当前实际服务器执行全部 NOT_RUN。

## 首次拒绝与后续检查

每个选择项执行一次。首次拒绝、超时或崩溃后停止下一项，按实际进程控制结束此 fixture，保留完整 DB/WAL/SHM、私有内部收据和日志，不覆盖 receipt、不 SQL 修账、不重复运行未变化完整节点。只有已记录源码/fixture 修正并形成新的独立快照和 fresh fixture 后，才考虑新的执行。

本轮共享 Core 原件路径另有必须在最终包上实测的范围：D13 Counter 的 draft/header/evidence 使用同一次调用持有的 Core 资源 lease；Graph 子 Work 仅借用资源，仍保留其原 Source 授权期限。大 draft 必须先完成 canonical 分段准备，再在原 Core 事务内写 origin、segments、header 与原件 PK，并实际读回双 EOF 后提交。只出现 prepared 或 header 不能视作计数、provider 或结算完成。

在既有完整 D13／256 槽节点的 fresh fixture 中，同时核对以下实际原件：大于单片容量的 draft 确有多个有序 segment；原 Core PK 指向该 cell，origin 的 namespace／phase／source-location 与原件相符；完整 hash、字节数、segment count/root 和双 EOF 一致；相同操作的 prior 回放读取实际原件而不替换它。取消、失效授权、错误身份、改动 PK／origin／segment、提交失败时应拒绝，provider 与计费变化分别按原节点断言。失败立即保存首次日志、数据库及附属文件；不要循环重跑、改 TTL 或直接修账。这些情况目前没有服务器 PASS。

服务器安装后，手动确认插件真实版本、完整进程重启、`0.0.0.0:2718` 实际监听与宿主映射、所选 HTTP／HTTPS 协议（选择 HTTPS 时核对实际证书）、Dashboard 登录、Owner 解锁、配置写入/读回、十三项模块许可和两层 enabled 状态，再检查原 logo/GLB、键盘焦点、主题与退出。首次完整 Authority/Host 初始化、普通 SDK 消息、暂停/恢复、冷重启与 C09 原件分别保存；安装或UI可访问不代替这些业务验收。
