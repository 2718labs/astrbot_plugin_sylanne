# K03 宿主回复所有权

状态：2026-09-27 设计裁决，尚未通过生产端到端验收。适用于 AstrBot 4.28.1 当前私聊单段回复；群聊和主动发送另行验收。

AstrBot 在入站 handler 返回后才检查 `event.is_stopped()`。因此，C02 后台任务不能在 handler 已返回后调用 `stop_event()`，再向平台补发回复：此时宿主默认回复可能已经发生。发送资格和宿主回复所有权是两个独立条件。

## 单次入站的状态顺序

1. W01 按原 ingress/C02/source、operation/effect 建立耐久 reply job，状态为 `AWAITING_HOST_TAKEOVER`。模型调用、费用结算与 D03/D05/D06/D08/D09/D11 的同事务 admission 可异步进行；outbox 暂不可发送。
2. `main.ingress` 在安装策略给出的有界截止时间内 `await` 原 job 的 admission，就绪等待不占用事件循环或 GraphWorker。截止时间从 ingress 接受起算；具体默认值须结合实测模型延迟与宿主行为确定，不在本设计里硬编码。
3. 截止前仍 HOLD 或超时：handler 不停止事件，宿主可走默认回复；W01 永久关闭该 handler invocation 的接管机会，记录 `HOST_DEFAULT`。迟到模型结果只结算原费用，不能用此 operation/effect 发送 Sylanne 回复。
4. admission 就绪：已安装的宿主 adapter 在当前 handler 中同步调用 `stop_event()` 并确认 `event.is_stopped()`，然后签发仅代表这次实际拦截的 `HostReplySuppressionAckV1`。W01 用同一个 operation/effect 和该 ack 执行 `activate_reply_ownership_v1` CAS，持久记录 `SYLANNE_OWNED` 与 `HostReplyTakeoverReceiptV1`。
5. W01 final claim、Authority start/P2 与 W09 sender 都必须读取并绑定耐久 `SYLANNE_OWNED` 收据，再重验原有 D08/D09/D11、权限、效果和时钟。普通 DTO、调用者布尔值或仅有 admission 不足以发送。

Ack/receipt 至少绑定 namespace、graph incarnation、原 ingress/C02/source、业务 operation/effect、admission 摘要、安装身份、handler invocation nonce、宿主账号和私聊目标；W01 从已封存路由复核这些字段。后台任务不能自行生成 ack 或推断事件已停止。

## 故障语义

- 在 `stop_event()` 前超时/HOLD：宿主默认路径继续；晚到作业永不激活，预算与真实模型费用分别结算。
- `stop_event()` 后而 CAS 提交前崩溃：无法原子证明宿主是否已压制回复，记 `takeover_unknown` 并禁止自动发送；重启不得伪造 ack。
- CAS 提交但响应丢失：按原 activation operation 查询收据，不能换 effect 或另建 outbox。
- 已拥有而当前来源撤权、过期或检查失效：保持 HOLD/终止，不绕过 D09/D11 发送兜底文本。
- 平台调用后结果 unknown：保留原 effect、outbox 和费用，查询原平台操作；不能自动重发。

最小正式验收包含一次 admission 在截止前完成、宿主只压制一次且平台只发送一次的正例，以及 admission 前超时、stop 后提交前崩溃、CAS 回执丢失、平台结果 unknown 四个故障点。当前这些场景尚未跑通，K03 仍 HOLD。
