# 首次编码 C02 终态恢复合同 v1（本地实施提案）

状态：2026-09-25 助手实施提案；尚未编码、验证或取得产品验收。本稿不扩大现有 V3 worker 租约权限，也不授权推送、合并或发布。

## 目标与准入

宿主重启且原 worker 租约过期后，只允许采用**同一次、已完成的模型结果**。不得续原租约、重新 acquire、重新派发模型或更换原 C02 业务 operation。原 worker 的 actor/fence 是历史来源；当前安装绑定的恢复主体和 Authority 当前 read/write fence 才是读取与采用资格。

恢复前必须同时核对：图侧原 V3 job/acquire/binding 的内容无关发现记录与 Authority 原始 intent 账本，在 installation、namespace、job、原 operation、acquire、call、binding digest、request digest 上完全一致；Authority 原调用为 observed/completed，admission、observation、terminal receipt 与已完成的 model fence 完整；原 job 未取消、未完成、未换 holder/fence，旧租约确已过期；当前来源/访问、D04 编码基线、图 incarnation、activation 和 Authority anchor 有效；原业务 UTC deadline 与签名预算授权仍有效。prepared、unknown、缺收据和不完整身份一律 HOLD。模型正文来自 Authority 保留的原 `result_json`，不得由新模型调用重建。

## 记录与幂等身份

`OriginalC02ResultKeyV1` 保存上述原始身份、原 intent digest、observation digest 和 terminal receipt digest。`TerminalRecoveryReadRequestV1` 另有 read_attempt_id 与固定 purpose；恢复主体由受信安装连接认证，不能由请求自报。`TerminalRecoveryReadFactV1` 证明该尝试已完成内容交接，并绑定当前 C02 write permit 与原业务 operation。

**业务结果摘要只取原调用和原终态结果**，不得包含 read_attempt_id、当前 actor、permit 或当前时间。每次读取尝试的证明仍独立保存并核验。首次构造恢复 C02 时，在原图数据库的版本化 intent 中冻结 envelope、报价引用、UTC deadline、bundle digest、原 job/CAS 版本或可逐字重建它们的规范输入；重启不能用新的 `now + duration` 改写摘要。旧已提交 C02 走原收据；已封存但未提交的 v1 C02 intent 首版 HOLD，不能偷偷改成 v2。

## 顺序

1. 先查稳定 C02 operation 的业务收据；已提交者只做原 write-fence 对账并返回 duplicate。
2. 精确查询 Authority 原模型终态；未知结果在此停止。原模型费用按原 call、quote 和父预算幂等核实或结算，不授予新派发资格。
3. 用当前 read fence 读取 Authority 保存的正文并完成耐久 handoff；响应未知按同一 read attempt 查询。交接后仍须重验撤权、删除和当前资格。
4. 以恢复专用 origin 校验构造 D06 C02 候选；原 worker fence 是来源，当前恢复主体是采用者。取得当前 write fence 后，在同一个图事务中重新核验原 binding、job/cancel/CAS、来源/访问、基线、签名报价、预算和已完成 read fact，原子提交 D06、job completed、消费和图收据。SQL 提交后精确完成 write fence，未知时查询原 operation。
5. C02 本地计算费用使用独立幂等后续事务：未测到的实际 CPU 用量记 `pending_confirmation` 并保留完整上限为 `unconfirmed`，不能写成零成本，也不能在内容提交失败时丢失已发生费用。

取消、删除与采用共用 Authority namespace fence 和图事务序列：取消先赢则恢复拒绝；采用先赢则后续取消不倒改已提交事实。普通旧 worker 路径继续因租约过期而拒绝。首版不接管已换 fence/holder 的 job。

## 验证门

必须以重启/租约过期且业务 deadline 未过的真实耐久数据证明一次采用、零次新增 provider dispatch；覆盖 unknown/prepared、身份错配、取消/删除/activation/来源变化、双恢复者竞争、read handoff/intent/SQL/Authority finish 各崩溃点、不同 read attempt 的同结果重放及不同结果冲突、报价和父预算篡改。原 v1 codec 与已封存 v1 intent 保持 HOLD。受信宿主报告被 Authority 接受不独立证明模型内容真实或供应商账单准确；现场验收须分列。
