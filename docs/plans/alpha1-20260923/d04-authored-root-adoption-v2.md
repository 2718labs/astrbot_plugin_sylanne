# D04 初始根采用 v2：D11 与 W01 的实施合同

2026-09-28。状态：主任务实施裁决，尚无产品正例。承接 [根候选与续接 v1](d04-authored-root-v1.md)、[联合输出裁决](d04-joint-state-output-v1.md)。本合同只处理 D04 初始根；普通 `DomainBundle` 不能自行获得 revision-0 D04 写权限。

## 唯一授权路径

D12 在当前 Owner 会话中提交作者选择及草稿；D11 冻结 `d11.d04-authored-root-adoption.v2` 操作、父预算、D01 head、草稿版本、安装 preset 和完整读集。D04 编译纯 `AuthoredRootCandidate`，受信 ABI2 初始盒验证器与固定 identity-tanh 政策给出 **候选**投影。D11 证据绑定 namespace、operation ID、Owner actor/session、D01 head、草稿/候选摘要、安装资产与原生 manifest 摘要、初始盒 transcript、投影摘要、准确的 checkpoint/Feeling/Mood 写集摘要、图读集与 bundle 摘要。DTO 或浏览器字段不签发权力；这些字段必须由 W01 在当前 Owner 与安装态下重建。

W01 提供专用 `commit_d04_authored_root_v2`，调用现有 Authority v2 write fence 和 `_commit_domain_bundle_fenced`，不开放 `commit_domain_bundle` 的通用首次 D04 状态写入。FFI 与输出预检在图锁外，最后同一图事务复读 Owner/D01/草稿/源资格/图版本及安装身份，以固定纯签发器重导完整写集并逐位核对。只对该专用入口、该 phase、该 evidence、该事务允许原来不存在的 D04 checkpoint、Feeling 与 Mood 键写成 revision 1；所有现有键、第二根、缺一个块、错顺序或错权限都拒绝。根不生成过往经历或外部来源。

## 原件与冷开

GraphStore 在正常安装 schema 时 provision `graph_d04_root_originals_v1` 及不可变的 root-v2 输出原件表。成功事务同时写 bundle/event、全部图状态、legacy 根输入原件、V2 初始盒与 readout 输出原件；任一步失败一起回滚。原件保存确定性重建所需的输入、逐轴 `[L,U]`/代表值/误差、完整写集与当前 CommitReceipt 摘要，不能只存一个候选 digest。冷开当前 Owner 读端应从同一快照复读原件、图历史和相关来源资格，再允许后续联合推进以根的 CommitReceipt 作为前驱。精确重试复读已提交原件；同 operation ID 异摘要冲突。

## 验收边界

先用正式 manifest pin 的安装态 ABI2 对真实 Owner 会话执行 root → joint advance；至少覆盖两块 Feeling 与一个独立 Mood、事务回滚、第二根冲突、草稿或 D01 head 变化、初始盒/readout/原生库替换、原件篡改和冷开复读。纯 root projection 测试及 Graph genesis HOLD 回归只证明局部能力。正式包、安装态根采用和续接未通过之前，公开根入口保持 HOLD；不得为了绿测在通用 `_check_product_advance` 放宽 revision-0 校验。
