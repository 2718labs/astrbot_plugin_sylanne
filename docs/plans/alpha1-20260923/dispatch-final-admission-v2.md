# D11 最终出站准入与同栅栏图认领

状态：2026-09-24 本地实施合同草案，**HOLD**。本稿收敛现有 `authority-v2-fence.md` 的 dispatch 限定子操作；它不是已经实现、通过测试或可发送的声明。

2026-09-27 前置业务组装顺序见 [K03 原子回复组装裁决](k03-atomic-reply-assembly-v2.md)；只有其真实单事务 admission 与原 write fence 完成后，才进入下述 P0/P2 最终交接。

## 必须先有的业务 admission

唯一业务图写者在普通 write fence 内原子登记 `sylanne.d11.dispatch_admission.v1`，随后结束该 write fence。记录至少绑定：

- namespace、graph incarnation、activity/effect/attempt/operation、dispatch generation、admission ref、图版本与完整请求摘要；
- D08 ActionIntent 完整内容摘要、ActionSchema/RequiredCheckSpec 全集及各自版本；D09 有限段清单、段序号、payload 摘要、固定平台账户与目的地；
- scene、Owner authorization head、D01 active role、D03 binding、对象、action、purpose、audience；
- 每个必查项的**实际** CheckReceipt、issuer、coverage、expiry、criteria 版本和完整正负读集、query epochs、来源/访问/删除水位；
- D02/D11 父预算 lease、同 operation 的持久 reservation、上限/币种/版本、必要 contact 占用与未决费用约束。

缺失 D05 边界或 D11 预算等任一受信检查者，或只持有 `verified_check_refs`/RequiredCheckSpec 哈希时，admission 不得提交。原 admission 是候选的耐久身份，不是发送许可。

`ExecutionBindingV1` 保持历史解析身份；新建 `ExecutionBindingV2` 绑定原 dispatch permit `P0`，并增加 graph namespace/incarnation、admission receipt digest/stamp、ActionIntent/schema/RequiredCheck 合同摘要、初始检查证据摘要，以及可跨进程验证的 UTC 截止和时钟策略。完整领域真值仍在同一业务图，不复制进 Authority。最终尚未生成的图 claim 摘要不放入原 binding，避免摘要循环。

## 唯一 handoff 序列

1. Authority 对原 effect 签发唯一 dispatch permit `P0`。独立执行 journal 的 prepared 与 claimed 依次追加、fsync 和 reconcile，得到 `P2` 与 anchor `A2`。`P2` 仅更新同一 token/epoch 的 revision 与 anchor，原 binding 始终持有 `P0`。
2. `begin_handoff` 在短事务与独立日志冻结下预检 `P2/A2`、原 claimed mutation、effect unresolved、subject/holder、删除头和当前 active permit；释放所有 Authority/journal 锁。
3. 受信回调以 `P2` 调用图端 `finalize_dispatch_graph_claim` 的**dispatch 限定子操作**，不可另开 write fence。图事务核对 admission 与原图、准确 prepared→claimed 日志链、Owner/角色/场景、D03/D05/D06/D08/D11 当前检查及主动联系时 D10、payload/路由、取消/worker fence、预算和同 effect 已占用的联系配额。当前读集与完整 RequiredCheckSpec 必须重建，不能接受调用者布尔标志代替可信读证据。
4. 图端按 `(namespace, effect, handoff_id, binding_digest, claimed_receipt_digest)` 精确幂等插入 claim 与恢复 metadata。只推进图 stamp；**不**追加 Authority 日志，不更换 dispatch fence，不推进 `A2`。不同摘要的重放拒绝。
5. Authority 再次冻结独立日志、短事务核对同一 `P2/A2`、effect 与图 claim 身份，耐久插入 handoff start。回调前后任一 Authority 状态变化则拒绝；已提交的图 claim 进入原 operation 恢复。
6. 唯一 dispatcher 只有拿到**本次新建** start、再次验证 UTC 截止、准确 payload/账户/目的地和同一 permit 当前性，才可调用平台。历史 start 重放只供查询/恢复，绝不能重新发送。平台结果未知时保留原 effect/预算/contact 占用，查询原操作；不能换 ID 再发。观察、图结算与 finish 继续使用同一 dispatch fence 的受限子操作和准确新 revision。

编排线程不得占着 GraphWorker 等待会回调该 worker 的 Authority RPC；回调不得递归调用 execution bridge。`handoff_id` 在整个跨存储恢复中固定。

## 恢复与实现顺序

先落版本化 admission/Binding V2 和真实持久写者，再接同 token dispatch 子操作、最终领域重验及图 claim，最后接 Authority start 的新建/重放区分与唯一 sender。每一步有实际负例和故障注入才解除相应 HOLD。

| 窗口 | 恢复规则 |
| --- | --- |
| admission 已提交，prepare 不明 | 查询原 fence/mutation，保留原 reservation 与 ID。 |
| journal 已 fsync，Authority 未确认 | pending 不释放；只 reconcile 准确的一条连续追加。 |
| claimed 已提交，图 claim 未提交 | 同 permit 重验；stale、撤权、过期均不发送。 |
| 图 claim 已提交，Authority start 不存在 | 以原 `handoff_id` 精确重放并完成 Authority CAS；图 claim 本身不能发送。 |
| start 已提交，响应或平台结果不明 | 只查原平台 operation；无可靠查询则 unknown，禁止历史 start 再发送。 |
| 观察已记录，图结算失败 | 按原 observation 幂等结算，不重复占用或释放预算/contact。 |

同事务候选组装见 [K03 原子回复组装](k03-atomic-reply-assembly-v2.md)；宿主默认回复与 Sylanne 后台发送的所有权交接见 [K03 宿主回复所有权](host-reply-ownership-v1.md)。截至 2026-09-27，已有局部 admission/claim/sender 构件和定向验证，但未完成真实五域同事务正例、宿主接管与唯一平台发送的联合验收。`ExecutionBindingV1.verified_check_refs` 不能作为必查通过证据，正常出站保持关闭。
