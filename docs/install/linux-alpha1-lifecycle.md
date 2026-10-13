# Linux alpha1 installation and independent Host recovery

The fresh installer now accepts `sylanne3.linux-install-request.v2`. It creates a new installation only; it does not overwrite an existing or interrupted installation, upgrade packages, erase data, enable systemd units, or make model/platform calls.

## Explicit configuration

Print the complete template first:

    python scripts/alpha1/install_linux.py --template > request.json

The printed template is intentionally **not installable**: UID/GID, all spending ceilings, numeric iteration/time limits and expiry must be selected explicitly. Replace every `FILL_*` value. Zero semantic dose limits mean no allowed dose; they are not a calibrated neutral personality. Review all eight mechanisms and each fast/residual/slow bound before selecting nonzero values.

- `budget_limits` is the total root lease; `budget_max_ceiling` bounds each quoted operation
- `budget_valid_until_utc` is an explicitly chosen future UTC Unix timestamp in seconds, not an ISO date string; `currency` is an ISO-style uppercase code
- `model_quote` and `local_quote` are independent limits; each is checked against both root limits
- `cpu_ms` bounds measured full/LOO joint work; the current root-adoption contract separately uses `thread_cpu_ms`
- `d04_joint_numeric` explicitly supplies version 3, positive `cpu_ceiling_ms`, at most 256 `max_iterations`, finite positive binary64 `tolerance` no greater than 1, and at most 3600 `job_lifetime_seconds`
- `d04_semantic_drive` explicitly bounds the registered mapping/basis and all mechanism doses/family shares; these bounds do not adopt a mapping or replace Owner selection
- `host_lifecycle.supervisor` pins the actual AstrBot unit, canonical root-owned systemctl/fragment paths, fragment SHA256 and cgroup. Obtain these from the real service, not an example guess. The same unit must be used by C09 and lifecycle control
- Model configuration is read from the administrator-selected local file solely to bind its canonical digest. Do not paste provider secrets into a shared request or upload the file
- The current Linux composition supports one cache-disposition provider. Its `provider_cache.provider_id` must match every configured model workflow, including paid precompression. Multiple providers are rejected until complete adapter coverage is implemented. An absent pinned purge/read adapter cannot establish provider-cache erasure; this remains a maintenance blocker, not an empty-cache assumption

Optional D13 precompression policies and protected signed full-wire counter configuration are explicit objects or null. A missing counter retains raw/unverified selection; the installer never fabricates token counts or potential cache savings. For a fresh D13 wire policy, set its `installation` field to the explicit marker `$current_installation`; the installer binds it to the newly created installation and actual chosen provider/model/configuration digest/output limit. All prices, policy fingerprints, public key and capacities remain your explicit inputs. The external counter must independently produce matching signed evidence. `d13_paid_precompression` requires the corresponding real installed workflow and approved budget; null does not advertise it as active.

The corresponding D13 work kind is included only when its policy is explicitly configured. Deterministic precompression requires an explicit `d13_compute_units` allowance in both root limits. Paid precompression requires independent positive input/model-token and output-token bounds, within both the root budget and selected main-model quote. The installer does not increase any supplied limit to make an optional policy pass.

Use externally supplied package and manifest hashes to plan:

    python scripts/alpha1/install_linux.py --package alpha1.zip --package-sha256 <sha256> --manifest-sha256 <sha256> --request request.json

The default is plan-only; `--plan` also selects it explicitly. Planning verifies the pinned archive, its actual installed assets and the full generated policy in temporary storage before any system directories are created. `--install` is a separate consequential administrator action that creates local credentials and protected directories. Review the plan and operating environment before running it. Installing/enabling the generated systemd unit is another explicit administrator action. Keep Owner private keys local. Existing data requires a qualified migration; never delete an old store to force a fresh install.

## Bind the AstrBot LLM selection to a fresh installation plan

The plugin configuration uses AstrBot's native chat-provider selector,
`llm_provider_id`. The Workbench **安装配置 / LLM** view observes that actual
provider, its current model and its canonical configuration digest without
calling the model. It can export the public `llm-selection.json` observation.
This observation grants no rights and contains no original provider configuration
or credentials.

Pass that observation alongside the explicitly reviewed installation request:

```bash
python scripts/alpha1/install_linux.py \
  --package /path/to/astrbot-plugin.zip \
  --package-sha256 ACTUAL_PACKAGE_SHA256 \
  --manifest-sha256 ACTUAL_RELEASE_MANIFEST_SHA256 \
  --request reviewed-install-request.json \
  --model-selection llm-selection.json \
  --plan
```

Use the actual package and manifest hashes from the delivery receipt. The request's
`provider_config_path` remains an administrator-selected local input. The installer
checks its real provider ID, root `model` field, supported adapter, and full canonical
digest against the Host observation before preparing the profile. A changed model,
configuration or Authority profile is rejected; read the current selection again
and review a new plan. The selected ID/model update only the model and cache binding
in the request. Existing identity, resource ceilings, budget expiry, domain policies
and approved audiences retain their explicitly supplied values.

`--install` remains a separate administrator action for a new installation.
The current installer does not reconfigure an existing cohort; use the qualified
package/configuration change protocol for that case. It never writes an old profile
or revives old grants to make a selected model appear authorized.

The Host's `enabled` is a local deny/allow input. Runtime startup additionally
requires the actual Authority setting to be enabled. Disabling either keeps the
business engine stopped while authenticated installation management remains
available; a Workbench Authority-setting update still takes effect on the next
restart.

## Pause and resume

Whole-Host pause is distinct from a role-only logical pause. It stops the actual AstrBot service cgroup, which also removes W09. Resumption therefore uses the running independent Authority, not a button served by the stopped Host.

The independent client is:

    python scripts/alpha1/authority_linux_control.py --profile <installed-profile> <action> < input.json

It never reopens Authority databases. Input is bounded JSON via stdin, not credentials in process arguments. Actions:

1. `challenge`: `{ "request": <canonical registered Owner login request> }`. Output contains the real challenge and `signing_payload_base64`
2. Sign the decoded payload locally with the registered Owner Ed25519 key. `accept`: `{ "challenge": <same challenge>, "signature_base64": <64-byte signature in Base64> }`. Output includes the current session token; protect it and do not include it in support logs
3. `inspect`: current `owner_actor_id`, canonical `owner_session_request`, and `owner_session_token`. Output is the actual lifecycle head, including its epoch and operation
4. `status` / `continue`: the same current Owner fields plus the exact original `operation_id`. Continue resumes the existing durable operation; it does not allocate a new start
5. `resume`: the same current Owner fields plus `pause_operation_id`, a stable new UUID4 `operation_id`, and `expected_lifecycle_epoch` copied from actual inspection. Preserve that operation ID for every retry
6. `logout`: `{ "request": <same current request>, "token": <session token> }`

Do not infer paused/active from request acceptance. Completion requires the corresponding independent original stage. Unknown remote outcomes, costs and reservations remain recorded during pause. The business generation and immutable Owner grant are not rewritten for a compatible same-installation pause/resume.

A resumed Host is bootstrap-only until its actual PID birth/systemd invocation, externally pinned package, mapped ABI2 library, complete thirteen-domain catalogue, current four-file selection and retained execution constraints are independently verified. Ordinary Graph work remains closed. A timeout means inspect the same original; never blindly issue another process start.

## Validation boundary

Local acceptance uses real typed Owner/Core/Graph/journal and subprocess evidence, with a clearly identified systemd command fixture where applicable. This is not a claim of a privileged systemd deployment, real production AstrBot service, live model calls or platform sends. Package replacement/rollback is a separate qualified maintenance contract; the fresh installer is not an upgrade implementation.

### Fixed cohort startup and privileged package executor

A fresh installation now stages an independent bootstrap at
`/opt/sylanne/bootstrap`. The AstrBot plugin link points to its fixed Host shim;
the Authority unit invokes `bootstrap/authority_entry.py`. Both resolve the same
protected `/etc/sylanne/maintenance/selection.json`, rather than following a
mutable code-directory symlink. The selected Authority deployment/assets stay
root-private; the Host reads only its public profile. TLS and D02/D11/C04 keys
remain in their original credential directory.

The initial selection is signed only after the real initial C09 four-file seal.
Registered candidate packages do not become historical active versions merely
because they appear in the registry. A compatible switch must preserve fixed
bootstrap loader surfaces and all non-package identity/configuration fields.

`authority_linux_control.py first-owner-issue` accepts bounded stdin JSON with
`ticket`, `operation`, `grant_value`, `owner_session_request`, and
`owner_session_token`. Use the original administrator-paired creation and the
`sylanne-owner-console` signed session. Authority retains the bearer, registers
and reserves the exact claim, calls the installed live Host over pinned reverse
mTLS for the existing pending-grant Graph transaction, and independently
finalizes the proof. A lost acknowledgement must be retried with those same
original identities. An already-finalized retry returns its original receipt;
it does not issue another grant. A missing current Host, revoked session or
changed process/storage/cohort is HOLD. Ordinary W09 login still requires the
resulting real Owner view.

Review the immutable grant before issuing it. If the intended installation
includes Body policy configuration and C04 internal work, the selected Owner
capabilities must explicitly include `d02.body_policy.install`,
`c04.cpu_policy.install`, and `c04.internal_work.prepare`. Internal recall and
source use also need the corresponding `consolidation` and `context` purposes
and the actual allowed conversation audiences, in addition to the selected
workbench and expression purposes. These are separate from D11 work kinds and
spending limits. Do not copy a permissive audience list or add purposes to an
already-issued grant: choose the intended scope before issuance, or use the
qualified Owner grant-change path. A missing permission must remain denied.

The backend exposes the `c04_cpu_policy`, `c04_prepare`, `c04_advance`, and
`d07_cognition_budget` workbench operations. Their presence does not imply that
the retained W09 frontend already provides every corresponding control, nor
that a policy or child budget has been installed. Inspect the actual original
receipt and preserve its operation identity for retries.

Package acceptance and privileged execution are separate explicit steps. An
accepted switch reports `awaiting_privileged_executor`; closed admission may
already be `quiescing`. The fixed root executor receives only the original
operation UUID, never a caller-selected path, command, backup or readiness DTO:

```
python /opt/sylanne/bootstrap/maintenance_entry.py --operation ORIGINAL_UUID
```

Installed-file preflight is not evidence that this executor is running. Actual
retirement, coherent four-store backup, candidate compatibility, selection CAS,
new Authority and Host readiness and activation each require independent real
observations. Resume an interrupted executor with the same UUID. After a
successful active switch, a later rollback requires a new signed compatible
switch against the current data. It must never restore old Core/deletion/
execution journals over newer effects, cost or revocation history.

Implementation status: the fixed installer/bootstrap and first-Owner route are
implemented; the complete privileged package executor chain is still undergoing
integration. Do not infer whole-machine installation or upgrade acceptance from
component tests or source compilation.


## 独立 WebUI 与模块许可

AstrBot 插件配置保留本机运行许可、Authority 配置档、主 LLM、独立 WebUI 和 D01–D13 十三个开关。高级人格、记忆、Life、模型工作流等设置位于 WebUI。默认独立监听 `0.0.0.0:2718`，保存端口或开关后重载插件生效。AstrBot 插件卡片的 WebUI/Page 可读取实际监听和当前十三项许可，并给出入口地址。

Docker 给 AstrBot 服务增加端口映射 `2718:2718`；与现有服务的端口并列。浏览器打开 `http://宿主机地址:2718/`。`0.0.0.0` 是监听地址，不能作为用户访问地址。修改容器内部端口后同步修改映射。

TLS 复用 AstrBot `dashboard.ssl` 的 `enable`、`cert_file`、`key_file` 与现有 SSL 环境设置。未配置 TLS 时，HTTP 入口提供前端和公开监听状态，页面明确显示“需要 HTTPS”，并停用会话核验、登录和配置读取/保存。客户端也在发送请求前拒绝 HTTP；后端继续返回 `403 / https_required`。这表示安全 API 尚未开放，不是后端连接失败。

在 AstrBot 4.28.2 上启用 HTTPS：

1. 通过现有 AstrBot 管理后台的全局配置，设置“启用 WebUI HTTPS”“SSL 证书文件路径”“SSL 私钥文件路径”。对应字段为 `dashboard.ssl.enable`、`dashboard.ssl.cert_file`、`dashboard.ssl.key_file`；证书和私钥使用 PEM 文件，路径必须在实际 AstrBot 主机或容器内可读。访问域名或 IP 必须与证书中的身份匹配。
2. 若使用本机文件配置，修改实际数据目录的 `cmd_config.json` 中已有 `dashboard.ssl` 对象，并保留其他配置。标准 `/AstrBot` Docker 布局通常是 `/AstrBot/data/cmd_config.json`；自定义数据目录以宿主实际配置为准。例如，已挂载的证书和私钥可以使用 `/AstrBot/data/certs/webui-cert.pem` 与 `/AstrBot/data/certs/webui-key.pem`，这两个路径只是示例，不会由插件创建。
3. 若容器设置了环境覆盖，核对 `DASHBOARD_SSL_ENABLE`、`DASHBOARD_SSL_CERT`、`DASHBOARD_SSL_KEY` 与可选 `DASHBOARD_SSL_CA_CERTS`；SDK 同时支持 `ASTRBOT_DASHBOARD_SSL_*` 别名。环境设置优先于配置文件。CA 字段用于加载可选 CA 文件，不会替浏览器建立信任。
4. 保留 `2718:2718` 端口映射，完整重启 AstrBot 进程，让 Dashboard 和独立 listener 重新读取 TLS 设置。该端口启用 TLS 后使用 HTTPS，不再同时提供 HTTP 页面。
5. 打开 `https://匹配证书的域名或IP:2718/`，先确认浏览器正常验证证书，再通过页面中的真实 AstrBot 登录读取配置。高级配置读取和保存需要有效后台会话及同源检查；Owner 操作另外核验正式安装来源和配对身份。

后台登录复用真实 AstrBot 登录与 HttpOnly Cookie。填写已启用的二次验证码；凭据不会写入浏览器存储。当前 HTTP 页面不会根据端口或字段猜测一个可用 HTTPS 链接；重新启动后，以实际 `listening / https` 状态和浏览器证书验证为准。

Owner 登录和管理仍要求已安装 profile 中精确的 `workbench_origin`。端口变化会改变来源；管理员需要通过正式安装协议登记新的精确 HTTP/HTTPS 来源。监听服务不会改写 Origin、迁移旧授权或放宽生产 Host 身份边界。缺少证书、端口占用、Dashboard 未就绪会明确显示当前原因，不自动换端口或关闭 TLS 检查。

模块开关保存后在下次重载冻结。本机开关只限制各模块接收新工作；开启不安装 optional workflow、不产生 grant、不解除领域 HOLD。已有终态、结算、原件读取、安全撤销和恢复保持可用。D11/D12 关闭后仍可进入配置、登录与恢复入口。旧 queued job 的首次模型或 sender 调用仍要满足模块许可及原有全部当前性与预算检查。

从其他源码快照升级时，进程中的 canonical runtime 保持旧代际，进入维护页；须完整重启 AstrBot 才加载新的运行库和独立端口。不要通过删除运行数据、导入旧 grant 或直接修账来绕过维护状态。


### HTTP 工作台支持（2026-10-13 明确授权）

独立 WebUI 未启用 Dashboard TLS 时，HTTP 支持真实后台登录、配置保存和原 Owner 签名会话。HTTP 不加密；后台密码、验证码、Cookie、Owner token 和业务内容的明文风险已由本轮用户明确知情批准。TLS 是可选传输方式，显式启用却缺少有效证书时仍阻断，不自动降级。

Cookie 适配只作用于实际同源 HTTP 登录/退出的 SDK JWT；身份、Owner 签名/nonce、Origin、CSRF、当前凭据及 grant/lease 都继续核验。Host–Authority mTLS 和各领域权限不变。Owner 来源需要由正式安装配置登记精确的 HTTP/HTTPS origin，不自动迁移已有来源。
