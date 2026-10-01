# D04 联合数值输出签发（实施裁决，未验收）

2026-09-28。现有 ABI2 `full_step.iterate` 是求解初始猜测，真实下一状态在对应 member 的 full output/state centers；不能把前者当下一 checkpoint。正式 24 轴 Scheme 的读出是 normalized tanh，而旧 `product_readout.py` 将 Feeling 坐标与 latent 逐位相等，语义冲突。V2 图事务须等安装态输出签发器，不接受调用者自填的状态写集。

固定 `d04.joint-state-output.v1`：只接受 manifest pin 的 24×24 identity tanh readout，member 与轴顺序按已认证 `member_refs`、`REGISTERED_AXIS_IDS`。每块下一 checkpoint 的 latent 逐位取 ABI2 真实输出 `y`，cursor 取 `role_end`；从真实 trajectory error 向外舍入构造每轴 latent 包围盒，整个盒须位于 `[0,4]`，越界 HOLD，不夹断。checkpoint 标量误差保守覆盖该盒的欧氏半径；原始 ABI2 联合误差另存原件，不用扩大后的数值冒充原生误差。

对 full readout 的每轴认证区间 `[L,U]`，Feeling/Mood 坐标取精确 binary64 有理中点的 round-to-nearest-even 值 `p`；同时存原区间与向外舍入的 `max(p-L,U-p)`。验证 `L≤p≤U`、有限值、轴身份与安装政策宽度门。不得再次调用平台 `math.tanh`、截断、采用区间外值或用 LOO 分支替代 full。所有二进制浮点位模式、端点和误差进入签发原件摘要。`p` 是认证区间代表值，语义校准仍标 `unvalidated`。

Feeling 只用自身 `kind=feeling` 块并保留 object/meaning/process，Mood 只用独立 `kind=mood` 块；不把 Feeling 汇总为 Mood。跨块影响来自本次认证联合耦合算子。输出层不再人为加时间尺度；来源集合取冻结且授权的前驱历史及当前驱动闭包，来源依赖不推断对象责任。

D04 新 `JointStateOutputPolicyV1`、`JointStateOutputOriginalV1` 与 `issue_joint_state_outputs_v1(installed_replay, frozen_predecessors, installed_policy)`，接口不接受候选坐标/下一 checkpoint/caller error/任意变换。原件绑定实际 full/LOO transcript、readout/政策/manifest、member/axis 顺序、前驱版本和完整写集摘要；须验证 `member.full.state_centers` 与真实 full transcript 输出绑定。W12 添加固定 `resources/catalogue/d04-joint-state-output-policy.v1.json` 并由 manifest pin 路径/长度/SHA/轴顺序/readout SHA/算法/宽度门；非 identity readout 拒绝。

W01 在图锁外跑 ABI2 与输出签发，最终同一图事务内重核完整读集和冻结来源，确定性复导并逐位比对所有 checkpoint/Feeling/Mood、原区间/误差，再原子写成员、数值原件、输出原件及贡献消费。`output_state_digest` 只能证明写字节，不能证明这些字节由此次 replay 导出。旧 `coordinates==latent` 消费校验应改为核 durable output original；根初始化同样须按新投影签发，旧根不能自动贴新版本标签。

聚焦门：实际 output 不等于输入 iterate；24×N member/axis 映射；有理中点/单 ULP/零宽区间/越界/误差向外舍入；替换 policy/readout/native 身份拒绝；修改任一坐标、latent、误差、成员序或当前来源拒绝；事务回滚无半份原件；Mood 不等于 Feeling 汇总。最终正式安装包 ABI2→输出签发→W01 提交→原件复读才可称数值与来源闭环，仍不宣称心理校准。
