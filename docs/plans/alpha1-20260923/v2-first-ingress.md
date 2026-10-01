# v2 首次入站：单事务实施合同

状态：2026-09-23 的主任务实施默认值；源码与验收收据优先。本文件留在本地设计区，不随源码 checkpoint 推送。

目标是让已配对、已 provision 的安装处理第一条 D06 宿主消息：同一个 GraphWorker 命令、同一个 Authority v2 `write` fence、同一个业务 SQLite 事务内写入首次 observation、D02 签名 quote、资源版本、D11 预算预留及 job/outbox、D06 来源和访问记录、图事件与业务收据。首次 observation 不得先单独提交，旧的 `observe_first → issue → seal → graph_commit` 多阶段路径不充当 v2 产品入口。

管理员 schema-2 profile 分别给出时钟来源及误差/往返上限、编码相对截止时长、单次 quote ceiling 与快照/资源/角色区间引用。缺任一配置时 v2 入站维持 HOLD。既有 `AdminInstallationPolicy` 的 root lease 与 **已签名 root grant** 在 namespace provision 时写入；首次入站复核这份 grant 的身份、签名、有效期、`d06.encode_source` 工作类型和 ceiling，不在同一 lease 上再造一个 grant。聊天事件只提供来源事实，不能提供授权或时钟。

在接触 Authority 写栅栏前，worker 取得配对样本，使用样本误差和本地往返得到保守 UTC 上界。第一次合格尝试以该上界冻结 `learned_at`，从管理员相对时长得到绝对截止，且截止不超过 root grant 有效期。另以稳定 operation ID 持久化 intent：原宿主内容指纹、安装/策略摘要、来源身份、冻结时间与截止、root grant 标识、Authority anchor、图恢复版本/epoch、确定性 fence attempt ID。重试必须重用这些原值；配置、内容、anchor 或图版本漂移时 HOLD，不用新操作 ID 洗掉冲突。

随后只用 intent 中的 attempt ID 请求 v2 `write` permit，并在业务事务前校验。事务里检查 intent、permit 对应的预状态和四个 revision-0 键，写首次 observation，签发 D02 quote，写 resource-lease guard；从现有签名 root grant 取得 D11 job，构造现有 D06+D11 封包，在提交前把 observation 的 `bundle_digest` 封好；调用协调器的事务内图提交原语。D02/D11 与截止检查使用同一配对样本的保守 UTC 上界，加上当前单调时钟经过的时间；在 graph guard 和收据钩子各校验一次，过期则回滚。图恢复 CAS、预算、job/outbox、图事件、操作收据与 fence 元数据必须跟首次 observation 同一 COMMIT。

COMMIT 成功后核对 permit、图恢复新版本与业务收据，使用持久的 finish request ID/digest 精确结束 Authority fence。业务事务确定回滚时，先持久化 `rejected_no_commit` 与原 permit/预版本，再以该拒绝身份精确结束；COMMIT 或网络结果未知时保持 HOLD，不能猜测回滚或换 attempt。既有通用 `graph_bundle_rejections_v2` 对通用 bundle intent 有外键：首次入站若尚无法在 begin 前确定 bundle digest，必须为原始入站 intent 建立匹配的持久拒绝关系，不能绕开外键或把拒绝只放进内存。重启先按原 intent/permit 查询：已有业务收据则验证 observation、图与原 permit 后续办 finish；已记录拒绝则续办 abort finish；无二者但已 begin 的状态只按原 attempt 对账，不开启新 fence。权限/来源撤销后，历史 committed 收据可供审计，不能据此重新获得当前内容读取资格。

最小反例验收：重复消息同一收据；同 operation 内容变化拒绝；首次 observation/quote/job/图写任一失败时无半提交；预算不足、root grant 类型/到期不符、时钟缺失/误差超限/跨截止均 HOLD；begin/finish 丢响应和 COMMIT 未知在冷重启后只对账原 attempt；旧多阶段路径不能在 v2 入口被调用。受控测试与五平台 CI 仅是软件证据；管理员时钟部署、冷安装及真实聊天收据另行验收。
