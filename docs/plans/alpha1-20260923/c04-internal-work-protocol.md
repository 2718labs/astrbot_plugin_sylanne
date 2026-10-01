# C04 内部工作先执行、再采用的耐久协议

2026-09-28 本地跨模块裁决。适用范围是一次受限的本地同步 CPU 工作及固定费用的 D02 身体组件；持续时间组件、异步 worker 和其他资源类别另需实际执行证据。本页是实施合同，不是 C04 已通过验收的声明。

## 事务顺序

1. W01 在共享业务库登记 `prepared`：固定 namespace、activity、operation、独立 execution ID、输入摘要、原 ResourceQuote、BodyQuote/Reservation、父预算、activation generation 与算法/政策版本。D11 预留 CPU，D02 保留身体组件；不提交 D06 经历。
2. D11 Authority 独立执行日志写入有类型的 `internal_work` claim。它证明工作**可能**已开始，因此 claim 后未见终态时只能按 unknown 恢复，不能自动重跑或把 actual 记为零。现有 `dispatch` binding 不能靠伪造平台字段复用。
3. 受限执行器以同一 execution/input 身份运行一次，保存真实终态与线程 CPU 计量。终态先进入独立耐久日志，再入共享业务原件；丢 ACK 时按原身份恢复，不重新执行。
4. D02 从原签名报价与终态签发 resource outcome，D11 对同一原件幂等结算 CPU。身体费用仅在受信收据证明指定组件确实完成时，按原 BodyQuote 的固定 `fixed_cost` 收取；`cpu_ms` 不换算身体能量。unknown 保留占用与明确覆盖缺口。
5. W01 从已结算原件构造**最终冻结** C04 adoption v2 bundle，再走写围栏与 `bundle.digest` / write-attempt 身份。最终图事务重新核 Owner、D06 来源和联想读集、D04 心境、D07 焦点、D02 当前身体账及版本；D02/D11 只引用已经结算的成本原件，不再预留或扣一次。D04/D06/D07 的经历写在最后一个事务中原子采用。事务拒绝不擦除执行/成本事实，也不生成经历。现有要求 D02/D11 在最终 proposal 再写三项的 preflight 不适用于这条已结算路径，必须新增明确合同，不能塞空写或重复账务凑形状。

身份至少绑定 namespace、activity、operation、execution ID 与输入摘要；阶段 mutation ID 确定且幂等。prepare 未 claim 只在证明执行权从未消费且取消已耐久时释放。claim 后无终态保持 unknown；终态已耐久但业务库未入账时重放原终态；C04 提交 ACK 丢失时先查原操作；旧业务备份开放前先合并独立日志的未决、unknown 和已观察效果。Authority 短事务结束后才进入图事务；不能持图锁等待日志写入。

## D02/D06 精确合同

先结算阶段的 D02 proposal 必须恰好写 persona 的 `d02.body_state.v1`，以及同 activity 的 `d02.reservation.v1`、`d02.settlement.v1`。这一阶段逐项核三写 owner/key、原 head 及下一版本、状态/预留余额变化、组件收据，且 settlement 内嵌的 state/reservation 与另外两写完全相同。BodyQuote 与 ResourceQuote 是不同原件，通过显式绑定关联，不要求它们的 ID 相同。最终 adoption v2 只复读和引用该已提交 settlement，不再写第二套身体账。当前单写 settlement 夹具和原有最终五域三写预检均不能作为这条新路径的产品正例。

`execute_local_cpu_action` 目前只在数据库事务外测量本地 CPU 工作，返回尚未持久化的结果；它不能独自签发终态或 outcome。若执行后到 Authority 终态落盘前中断，该 claim 只能按 unknown 恢复，不能自动重跑或假定成本为零。执行器须将运行与依据独立日志终态签发 outcome 分开。CPU actual 只覆盖明确命名的前置 action，不包括最终图事务的联想重验开销。

## 冻结输入与唯一执行器（2026-09-28 跨模块裁决）

W01 在 prepare 同事务写入可复读的 `AssociationWorkInputV2`，不只保存调用方 `canonical_input_digest`。它包含 cue、D07 ticket/focus、D04 salience 原件、audience/purpose/context tags、五个现有预算边界、完整且有界的 edge/source/access/correction/祖先链读集及明确的缺席 head、查询覆盖和截断状态。`input_digest` 只由这些语义输入计算；图 epoch 是独立观察元数据。输入不包含未来终态、结算或 `bundle.digest`。准备与结算自身会推进图 epoch，最终在当前 epoch 重新收集相同闭包并比较语义摘要和逐项版本；新的边、来源/权限/纠正、focus 或 mood 改变要拒绝。

Authority 只映射一个安装算法 `d06.association_activation.v2` 及其构建指纹；固定数值政策和纯 activation/ranking 函数来自受信代码。调用方不能提交任意 callable、结果或 `cpu_ms`。Authority 的 claim 与 Core CAS 成功且本调用首次取得一次性启动权后，释放 Graph/日志锁，再在自身受限进程的一个同步线程执行并测量 activation＋ranking。重试旧 claim 只能查询，重启后的 claim-only 永不补跑。终态在同一独立执行链耐久保存有界输出、算法/输入/结果摘要及组件完成收据；`component_receipt_ref` 非空本身不能证明组件完成，D02 必须由 Authority 复读原收据。

失败也按事实入账：已发生工作正常失败时保存实测 CPU，不收未完成组件的身体固定费；claim 后无终态是 unknown，实际用量不能填零；终态已持久时按原身份重放导入和结算。即使 Owner 在执行中撤权或删除，Authority 仍应允许为原 claim 记录历史终态与成本，但不得再授权新执行、读取已撤销正文或采用经历。已结算而最终采用拒绝时保留成本、没有经历。超出报价的真实 CPU 不截断成 ceiling；若账本不能结算超额，则留下完整实测与待处理状态并 HOLD。

实施顺序为：W01/D06 冻结输入与纯函数拆分；Authority 固定执行器、同链输出/收据和首次启动权；D02/D11 幂等成本导入与恢复；W01 adoption v2。每段先编译再跑覆盖本段不可变条件的窄测，最后以真实 Owner/安装态完整链验收。上述为待落地合同，现有 prepared、底层同链日志与 Core CAS 不能替代执行和最终采用。

## 当前验收门

真实 Owner 场景仍缺从 D02 正式初始化/报价/预留得到的 BodyState、Reservation 和原固定 BodyQuote，以及有类型的 Authority `internal_work` claim/terminal、恢复与费用原件。W01 的现有 C04 入口先要求冻结 bundle，不能在该写围栏内临时测量 actual 再重造 bundle。以上端口与成功采用、同 ID 不重跑、claim 后崩溃 unknown、终态后恢复、采用拒绝仍留成本等反例通过前，C04 产品保持 **HOLD**。
