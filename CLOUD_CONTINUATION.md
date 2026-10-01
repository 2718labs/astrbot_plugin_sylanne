# Sylanne alpha1 云端接续

更新：2026-10-02。用户授权将本机当前接续成果推送到独立远端分支，再在云端完成后端。

## 任务与交付边界

继续完成重型 `embodiment-3.0.0-alpha1` 的 D01–D13 实际后端产品链路，最后生成用户自行安装到 Linux AstrBot 的 ZIP。当前是开发检查点，尚未完成后端验收，不能标为正式版本或可安装成品。

主任务入口：

- `AGENTS.md`：现行用户约束。串行工作由主对话完成；最多使用少量明确必要的代理。架构与战略决策使用 Astra/high；允许的代理模型见该文件。
- `docs/plans/alpha1-20260923/architecture-gate.md`、`task_plan.md`：实施目标。
- `docs/architecture/sylanne-3-design-index.md`、`module-collaboration-contracts.md`、`docs/modules/`：领域设计与合同。区分定案、草案和源码实际行为。
- `docs/plans/alpha1-20260923/local-continuation-20261001.md`：本次 dots 合并、本机续建和实际验收记录。
- `docs/plans/alpha1-20260923/product-completion-matrix-20260930.md`、`backend-completion-20260930.md`：历史未完成清单；必须用当前源码核对，不能把旧缺项逐条盲目重做。

用户要求先编译，严禁过度测试、临时过渡测试和反复验证。运行必要的永久产品验收；失败先定位真实原因再修。不得放宽数学、CPU、固定截止时间、真实原件/授权/来源检查；不得恢复已退役旧核心作运行回退。

## 工作树与来源

本机源目录是 `G:\Sylanne`，本次接续前本地 HEAD 为 `72c9235bf025b66e0a83f02d34661a32abd3250b`。此次独立云端分支从该本地源状态建立，包含现有本地源码改动、dots 三方合并和后续修复。既有远端 `codex/alpha1-runtime-checkpoint-20260923` 不被覆盖。

dots 来源 ZIP：`Sylanne-local-continuation-20260930-1632.zip`，SHA256 `5b8e6172091822a290aa007f5df4bb46391b3519f30af1ce59def4ec775f2a80`。本机已在仓库外解压、校验并逐文件三方合并；没有整树覆盖。合并、原始基线和本地备份保存在仓库外，本次 Git 分支提供实际合并后的源码。

提交包含源码、资源、现有永久验收、构建/安装工具和必要设计/接续文档。运行数据库、凭据、临时环境、完整本地日志、候选 ZIP、原生构建产物和 `.codex-*` 临时目录不进入远端。云端不能依赖本机 `/tmp/` 或盘符路径；需要自行构建安装候选。

集成基线仍为 `codex/embodiment-3-rewrite`。本次授权为独立开发分支推送，不自动创建 PR、合并或发布。

## 当前准确状态

### D04 多块轨迹

旧候选26的永久用例实际 **FAIL，920.63秒**。后继6981步/14块的数学和独立 CPU 原件完成，最终采用因固定600秒期限到期拒绝，实际费用已结算并有 Authority ACK。

计时证明最终 prefix 恢复耗时111.333717463秒；Authority记录27次恢复，即13次热完成读回和14次最终读回。后续源码已消除热路径的重复读回，并新增一次有限 prefix manifest 的真实 Authority read fence/Graph事务/共有祖先核验。客户端最终结构收集后，完整数学验证只在最终 derive 出口执行；公开冷恢复保持完整验证。

这批修改已编译并实际导入，**尚未运行安装行为验收**。Astra复核在用户转云时停止，没有最终复核结论。先审查下列边界再执行原永久用例：

- `host/installed_d04_series_driver_v1.py`、`runtime/d04_series_execution_v1.py`：同次 queue return、实际 terminal、落盘结算和 Authority ACK 后的私有 hot handoff。
- `authority_service/d04_series_service_v1.py`、`d04_series_rpc_v1.py`、`host/d04_series_transport_v1.py`：prefix manifest 一次当前资格读取。
- `runtime/d04_series_prefix_manifest_v1.py`、`d04_series_restore_v1.py`、`d04_series_adoption_v1.py`、`d04_series_codec_v1.py`：固定 finite prefix、packet字节/terminal承诺、完整数学出口。
- `runtime/c04_authority_port_v3.py`：prefix_manifest沿用restore的180秒RPC超时，root的600秒期限未改变。

永久用例：`rewrite/tests/alpha1/integration/test_d04_installed_series_v1.py::test_installed_multichunk_series_cold_adoption_and_successor_d06_read`。

### Life source-note 实际任务

真实 D01 首次初始化专用回执认证、后续真实 `d01/adopt_growth` 分派，以及共享语义输入范围已修；Root Action A、独立 Body命令B、registered plan已实际提交。

库存 RPC 的 decoder 两参数误用及 standalone RestoreAnchor 错误编码已修，保持实际 typed guard 和完整 mixed execution 库存。最新候选30 SHA256 `c53ada64c69b5940564de4b5a548f1a71827a181552ac0c357b0d6b2b87fe184`，844个包内Python语法通过；永久日志10最终 **FAIL，59.75秒，exit1**。

最新失败已越过库存 RPC，永久用例在 `prepare_life` 返回后查不到该命令的 `graph_domain_production_originals_v1` 原件。当前日志没有足够信息判定底层确定性拒绝原因。应检查实际返回的 receipt/refusal，以及 `domain_production_runtime_v1._last_refusal_exception_v1`，定位为什么该准备没有形成真实采用原件；不得凭断言猜测补表、伪造 receipt 或删除授权检查。尚未证明 CPU一次claim/实际artifact/最终采用链通过。

重点文件：`runtime/d01_life_activation_original_v1.py`、`d11_life_scope_v1.py`、`d08_source_note_action_v1.py`、`d02_life_body_preparation_v1.py`、`d08_life_admission_v1.py`、`d11_life_product_adapter_v1.py`、`d11_life_preparation_v1.py`、`d11_life_preparation_commit_v1.py`、`d11_life_adoption_v1.py`、`authority_service/d11_life_execution_inventory_v1.py`、`d11_life_rpc_v1.py`。

永久用例：`rewrite/tests/alpha1/integration/test_d11_installed_life_source_note_v1.py::test_installed_owner_source_note_once_execution_body_progress_and_final_ack`。原用例已有 chained RPC traceback 诊断，不打印请求、permit或凭据。

### 主动联系

已编写真实 current contact plan、独立付费 generation/review、原始 paired result/cost读取、C09原件分类、immutable whole batch、固定逐段身份、实际语义路线，以及Graph/Host模型运行安装入口。

最近新增的 `contact_qualification_v1.py`、`contact_claim_adoption_v1.py`、`domains/d08/contact_dispatch_check_v1.py`、`contact_final_issuer_v1.py`、`contact_dispatch_admission_v1.py` 是继续接线中的源码；**尚未形成完整可调用发送产品链，也未完成行为验证**。不要把这些独立模块当作已集成能力。

必须继续闭合：实际 W01 当前预提交/最终提交 reader与closed witness；六项provider重发和一致的整批占位；GCP独立contact分支及D11 admission；逐段真实parent grant/观测/当前检查；P2 claim、实际sender及D13观测；真实D11 handoff消费和C09冷恢复/物理处置。当前D08联系冲突读取尚未实现对本批已观测前段的原件认证与有限例外，因此后段不能靠普通 caller continuation 或 `completed_verified` 假值放行。

通用生产frame冻结器要求scope epoch与实际Graph head相等；不要通过改旧frame epoch或伪造 FenceScope 来做 E+1 contact检查。预提交和最终提交需要与原permit绑定的专用实际SQL projection reader。

### 其他域

历史D06关联实际验收曾PASS；旧offline调度链也曾PASS。之后共享源码有变化，不能把旧结果当作当前全包PASS。C09新的contact与Life原件冷恢复/物理清除、Owner LifeShare合法投影，以及其余13域缺项仍需对当前源码逐项核清。

## 云端环境与验收入口

本机已实际用Linux Python3.12.3、AstrBot4.28.1、pytest9.1.1、pytest-asyncio1.4.0、cryptography50.0.1，以及Cargo1.98.1运行安装验收。Windows Python3.13.14用于无副作用语法编译。此处版本记录是既有执行证据，不要求随意升级依赖。

本次推送前对已跟踪源码与明确选中的云端新增源码，共1614个Python文件进行一次无文件产物的语法编译，全部通过；没有新增或重跑pytest。这个结果只证明源码语法，不表示完整产品链已验收。

- Authority依赖：`requirements-authority.txt`。
- 原生源：`rewrite/native/Cargo.toml`、`Cargo.lock`；构建Linux `libsylanne3_kernel.so`。云端复用自己的Cargo缓存，不能依赖本机生成库。
- 构建入口：`rewrite/tools/build_plugin_package.py --project-root <repo> --target-os linux --target-arch x86_64 --target-libc glibc --native-library <built-so> --output-dir <outside-repo> --backend-alpha1-candidate`。这是开发候选；不能改用formal标志绕过验收。
- 先检查实际ZIP CRC、包内Python语法、manifest和新prefix模块，再在仓库外解压安装。
- 永久产品用例读取 `SYLANNE_D04_INSTALLED_ROOT=<actual-installed-root>`；Python导入必须实际来自安装包。源码目录导入或纯compile不能替代安装验收。
- D04/Life永久用例内有实际Owner、TLS、HTTP和受控模型fixture；用户真实Linux服务器与机器人测试由用户最后自行完成。

串行完成必要验证。不要重跑已闭合用例来凑数量；只在新修改、实际失败或未解决问题需要时运行。最终ZIP必须与最终提交/manifest/实际验收对应，并给出仍需用户手动测试的场景。
