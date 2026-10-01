# K03 原子回复组装裁决

状态：2026-09-27 本地架构裁决，**尚未实现或验收**。本稿补足 [最终出站准入](dispatch-final-admission-v2.md) 之前的业务组装顺序。发送闸门继续 HOLD。

私聊对象与投递受众的分离及当前绑定验证见[私聊回复对象与投递地址](private-reply-target-binding-v1.md)。

## 为什么需要新入口

现有 `prepare_post_c02_private_reply_v1` 在 ActionIntent、ActionSchema、初始 cancellation 与 goal 入图之前要求 D08 的必查 PASS；真实 D08 检查却必须读取这些当前图行、完整冲突查询及独立执行水位。D11 的最终 admission 又要求 action、schema、cancellation、grant、batch、job/outbox 与 admission 在同一业务提交中。提前伪造“当前”快照或分两次业务提交都会留下不合格或半成品行动。

因此新增窄版 `assemble_post_c02_reply_v2(authority, lease, request)`：主机只交原 C02/source、已结算且已受信读取的模型结果身份与摘要、稳定 operation/activity/action/effect/attempt、被动私聊路由、单段正文与逐条来源化 claims、goal/action 语义草稿、安装与策略版本、截止时间。请求不能携带 `CheckReceipt`、`current_read_confirmed`、graph stamp 或任意检查回调。`assembly_request_digest` 只覆盖这些固定输入，不依赖未来的检查、grant、batch、admission、claim。

## 唯一事务序列

1. W01 按 request digest 查精确重放，取得 ordinary write fence、当前 Owner/来源/删除/激活资格、同 anchor 的 Authority absent-effect 与可信时钟。跨 Authority 调用遵循现有不持有图锁等待回调的规则。
2. 一个 SQLite 事务中的 coordinator-private `ReplyAssemblyTxV1` 检查完整原始读守卫，保留唯一最终图 epoch `E+1`；`stage_typed_writes` 实际写入 D08 goal、不可变 action/schema、revision 1 初始 cancellation，以及原签名 quote 对应 D02/D11 reservation。预算 reservation 摘要独立绑定原 operation、quote、ceiling、路由和请求身份，不能引用最终 bundle digest。
3. `read_current_check_scope` 从同一事务的真实行与独立 Authority 水位构造受信 scope，绑定 namespace/incarnation、permit/anchor、事务身份、原/最终 epoch、准确 action/schema ID、完整负查询与来源。只有这个 reader 可以为 D08 标记 `current_read_confirmed=True` 并签发必查票据。计划中的 `E+1`、组装的内存对象或 caller 布尔值都不是 PASS。
4. D03/D05 等前置检查从不可变请求中的 scene、audience、route、payload manifest 读取，不要求未来 D09 batch 已存在；所有检查完成后才产生 D08 communication grant，随后 D09 构造有限 verified batch。W01 逐字段核对 batch 与原 manifest，禁止拿伪造 batch 反向取得检查。
5. `seal` 再核完整读集、负查询、权限与 late-write closure；PASS 后不准改动 D08 冲突集合、goal/cancellation 或预算事实。一次封存完整 graph event、history、bundle、admission、job/outbox、operation 与恢复收据，并一次 COMMIT。图提交后 finish 原 ordinary fence；durable admission 与 finish 都成立后才可构造 Binding V2，进入既定 P0→P2→同 token 图 claim→Authority start。

`stage_typed_writes`、`read_current_check_scope`、`seal` 只能作为此固定流水线的私有能力，必须维护类型/领域所有权、CAS、不可变约束、依赖失效、history 与唯一图版本；不允许在 receipt hook 裸写 `graph_atoms`。现有 `commit_prepared_post_c02_reply_v1`、`_commit_domain_bundle_v2` 和 `GraphStore._graph_commit_core` 都在组装前冻结 digest 或写集，不能直接作为此入口，也不能嵌套调用开启第二 fence；可提取其中的守卫和恢复帮助函数。

## 身份与恢复

摘要链单向为 `request_digest → reservation/checks → grant → batch → final_bundle/admission → BindingV2 → claim`。新增 append-only assembly 恢复记录绑定原 request digest、最终 bundle digest、receipt 与 admission；Authority 只持身份与摘要，不复制领域真值。原 BindingV2 不包含尚未产生的 claim 摘要。

事务前失败无业务提交；COMMIT 响应不明只查原 request/operation/fence；图已提交而 fence finish 不明只完成原 finish。start 或平台结果不明只查原 operation，不能生成新 effect、替换 ID 或重发。

## 实施顺序与闸门

先冻结 request/result/scope/recovery DTO，再实现受限 staged primitive 与回滚/提交响应丢失恢复；随后接 D08 实际 SQL/Authority 检查、D09 grant-bound batch、D11 admission，最后做 P2 正向 final claim、新建 start 与唯一 sender。每片运行对应正例和故障反例。即使 staged primitive 可用，未有真实 provider、finish 恢复、同 P2 最终复验和平台 unknown 防重发证据前，K03 与实发保持 HOLD。
