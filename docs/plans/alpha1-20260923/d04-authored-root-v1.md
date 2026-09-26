# D04 authored root 与数值续接合同 v1

状态：2026-09-26 助手跨域实施提案；尚未完成 D11 采用、产品数值验证或 alpha1 验收。本文不授权推送、PR、合并或发布。

## 权威与首次采用

D12 只保存经当前 Owner 会话认证的作者选择、草稿与采用请求；D04 验证情绪语义和候选；D11 在当前 Authority v2 fence、同 namespace 图事务中核验并采用。浏览器字段、候选、预览、ABI2 capability bit 与发行 manifest 都不能单独成为写者凭证。

初始根是独立 `d04.authored-root.v1` 操作，不能伪装成零时长 product advance。图 revision 0 仅表示键不存在；成功采用写 revision 1，重试查原操作，同 ID 异摘要拒绝，并发第二根依 CAS 拒绝。候选必须冻结 namespace、Owner、D01 head、草稿和 preset 摘要、scheme/operator/parameter/coupling/readout 版本、各资产 hash、角色时钟起点、对象/意义块身份、完整正负读集、预算和过期时间。新角色的 D01 与 D04 必需初态共同采用；已有 D01 可显式补根，但不自动宣称完整可运行。

根的 `z₀` 是作者明确选择的潜状态，不是不存在的图值，也不是 `FeelingState.coordinates` 读出。24D 是一个对象/意义/来源块，不是角色总向量。共享图需持久 `d04.numeric-checkpoint.v1`：潜状态、有序初始 box、已认证初始误差、角色游标、完整块及资产身份、对应 feeling/mood 图版本和读出证明。初始误差为零只在初值及映射确切可表示时成立；其他情况由受信初始 box 验证器给出向外包络。数值误差与主观/心理语义不确定性分列。

空白创作不伪造过去经历、解释或外部对象来满足旧 `FeelingState` 的非空来源约束。采用版本化 authored lineage 或零对象块，旧真实事件写入路径的来源校验不放宽。候选必须绑定确切 D04 preset/方案资产，正式发行才允许已验收目录宣称可运行。

## 后续数值链

`d11.product-advance.v2` 显式写前驱类别 `root / advance / revision` 和前驱收据。每次从**当前图 checkpoint**读取潜状态和继承误差，以完整固定耦合块、驱动分段和确切写集调用受信 ABI2，事务外计算，事务内由已安装的纯验证 numeric issuer 核对完整输入/输出、原生库与 manifest 绑定、当前图版本和区间，再原子提交下一 checkpoint、feeling/mood 及收据。当前协调器的 numeric issuer 为 `None`、前驱只查 `graph_product_advances`，因此仅有 root 类型或 ABI2 数学证书无法推进产品状态。

当前 `_check_product_advance` 还按 type_name 只容纳一条 feeling 和一条 mood 写入，并拒绝同类型多写；这与按对象/意义/来源分块的 24D 根候选不一致。v2 推进必须按稳定 block ID 验证完整块集合、每块前驱及跨块耦合，不能把多块候选压成一个全角色向量或静默丢弃其余 feeling。

同游标语义修订保留潜状态与误差并写新前驱，否则现有精确父图版本检查会使后续推进断链。撤销设定是新修订，不倒退游标或重置误差；参数切换须显式传播映射误差，未支持映射保持 HOLD。普通 `math.tanh` 投影没有认证误差，不能把读出坐标作为潜状态或直接作为 D04 产品证明。

## 资格生成与 C02 边界

先独立验证候选资产身份（外部固定清单、规范路径、大小/hash、ABI、schema 与版本），再由受限验收 namespace 对同一生产协调器执行 root → 两次 advance → 同游标修订 → 再 advance；验收 scope 不具真实对外副作用。通过后产生绑定源码、资产、原生库、平台的外部证据，才生成正式目录资格。不能手改 `READY` 再用启动成功反证它自己；最终 ZIP 冻结后还要对**最终确切 hash**分别冷安装验证。

D04 首次入站 encoding baseline 继续保存原来源/视角/当时版本，已冻结 baseline 不因随后采用 root 而回填。当前 salience/tone 为 unknown 是有效状态；要把它们变为已知，另需具名、具来源与读出误差认证的 D04 投影合同。根不构成一次共同经历，C02 不能把 authored 初态当作模型观察。

实施次序：领域 DTO/codec 与 checkpoint → D12 预览和 Owner 采用请求 → D11 根原子事务和故障重放 → 纯 numeric issuer 与完整续接 → C02 隔离验证 → 正式目录和最终构件。每段只按实际证据解除对应 HOLD；完整 alpha1 仍按 G0–G7 验收。
