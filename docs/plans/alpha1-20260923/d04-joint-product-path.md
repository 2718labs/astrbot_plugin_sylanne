# D04 联合感受产品链：alpha1 实施裁决

2026-09-28，助手战略设计默认值；这是实施合同，不是已通过验收。目标是在共享图、Authority 栅栏和现有 Rust ABI2 上签发一个**当前区间的混合感受读出**。D04/D01 负责语义映射与人格参数，D06 负责来源、访问和更正，D11/W01 负责资源、数值原件与原子提交。不得用单块数学证书、模型文字或 candidate-only 耦合代替产品资格。

## 可签发的因果语义

逐来源反事实定义为：保持已提交的区间初态与联合算子不变，从本区间全部成员的 drive 中移除同一 D06 provenance/contribution 家族，再比较当前输出。它表示 `current_interval_drive_effect_given_committed_initial_state`，不表示来源对全部历史情绪的总影响，也不执行删除。派生/重复转述若不能独立拆分，就按一个家族移除；不把无 `parent_source_ids` 当成独立性证明。各区间可以跨零，不能把非线性的逐源差相加为百分比。

## 最小版本化合同

1. D04 耦合、drive 的新版本绑定受权来源与访问/更正版本、语义接受收据、映射资产/人格版本、时间映射和贡献家族。积分剂量到连续 rate 的定义统一；跨成员同源份额受同一贡献账约束，不可每块重复取得完整剂量。
2. 按区间而非单一 cursor 枚举完整无向 PSD 耦合连通组件。绑定 catalogue/manifest、graph incarnation/revision/epoch、全部有效和无效 numeric 行、D06 祖先与不存在读、access/delete epoch。边或 drive 在区间内变化则切段；超出一次工作预算时分页或待续，不裁断组件。明确零输入需要完整查询证明。
3. 保持每成员 24D checkpoint；新增不可变联合采纳原件和 `ProductAdvanceEvidenceV2`，记录有序成员集、各前驱/初始盒与继承误差、完整闭包摘要、共同区间、ABI2/资产、full 与各来源家族 LOO transcript、输出写集、贡献消费和幂等键。按每个稳定成员 ID 防区间重叠。V1 单 feeling/mood 的合同和图校验不能接受 N-block 联合推进。
4. 完整联合输入按稳定成员顺序装配块对角 K/R/J/A；每条合法边加 PSD 差分耦合，来源家族 drive 跨全部成员组成一个向量。量化成 binary64 的输入定义及误差显式记录；初始误差继承，不能清零。只在组件闭包证实时使用零遗漏耦合界。每个 full/LOO 分支均取得独立 ABI2 区间证书。
5. 产品读出对各分支使用相同已安装的 `C·tanh(z)` 资产和区间包络，然后向外舍入做 `[full.low−without.high, full.high−without.low]`。现有线性 `cᵀz` helper 只是条件性数学切片，不能签现有产品读出。

## 提交与消费次序

先由 D04/D01 提供有版本的映射与资产，D06 给出来源家族/访问资格；W01 接通 root checkpoint 的受信原件。短读事务冻结整个组件与不存在读，锁外执行 ABI2；最终 Authority 写栅栏内重读完整闭包并 CAS 全成员，纯本地核验证书，在一次图事务里提交全部成员状态/checkpoint、贡献消费、D02/D11 账和联合收据。任一版本变化整批拒绝；恢复先查原 operation receipt。Authority RPC 与 FFI 不在数据库锁内执行。

当前 mixed read port 只有在重证现行组件、来源资格和已提交联合证书后才签发，且读出本身不授权发送。缺获准的 appraisal/角色条件或语义映射校准证据时，保持未知，不由来源存在、签名或剂量上限臆造感受。

目前 `ProductAdvanceEvidenceV1` 只支持一份 feeling/mood，W01 issuer 槽为 `None`，current product frame 明确拒绝 mixed；新联合图闭包和 LOO helper 也仍返回 HOLD。因此 G2/K04 尚未通过。
