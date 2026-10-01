# D04 空白创作初态的 authored lineage v3

2026-09-28。实施裁决；未有根采用或首次 joint 产品正例。本合同取代根采用 v2 中“空白初态写 `d04.feeling_state.v1`/`d04.mood_field.v1`”的假设。旧事件派生 v1 值和收据仍按原 schema 复读，不原地改写。

空白创作没有历史事件、D07 解释、D06 来源或外部对象。不能为满足 v1 的非空字段伪造这些原件，也不能放宽现有事件派生 `FeelingState`/`MoodField` 的校验。根候选的 authored facet 是作者选择的数值块身份，不是 D06 SourceRecord 或 MeaningFacet 解释。

新增有独立 type/schema/codec 的 `d04.authored_feeling_state.v1` 与 `d04.authored_mood_state.v1`，以同一根操作、Owner 草稿、preset/资产、稳定 block/facet ID、角色游标、24 轴受信读出及 checkpoint 为 lineage。历史来源与解释在 authored 状态中明确为空；状态只表达角色的作者初始参数，不能作为过去经历、外界事实、已观察情感或 C04 编码时基线。至少两个 Feeling 数值块和一个独立 Mood 块的数学结构仍保留。根候选/输入升版：可空对象/意义目标须明确标成 authored facet；若显式引用真实对象或意义，必须走其受信读集，不能由名称猜测。

专用 `d11.d04-authored-root-adoption.v3` / `RootAdoptionEvidenceV3` / 不可变原件 V3 核 D12 当前草稿、签名 Owner、D11 父预算与持久冻结、正式原生/方案 pin、ABI2 初始盒/读出、完整 rev1 写集，并在 W01 一次 Authority 围栏图事务提交。通用 `DomainBundle` 根路径继续 HOLD。已写的 V2 合同/辅助存储保持明确 HOLD，不把 V3 wire 解作 V2；可复用验证代码但不能复用旧授权摘要。

首次 `joint advance` 从 authored checkpoint 与这些 authored 状态读前驱，按 root original 验证 lineage，不把 `authored_source_id` 当 D06 来源，也不要求不存在的初始 D07 interpretation。新推进仍需真实合格的驱动、耦合来源与受限预算；没有驱动只能保持根，不凭空制造经历。推进可以延续 authored lineage；只有真实事件/解释经 D04/D07 独立签发时，才显式转换为事件派生状态和其来源/解释约束。C04 的编码基线只接受实际来源与事件派生 Feeling 的已认证联合输出，不能把 authored 初态当作某条记忆的历史感受。

实施顺序：D04 新类型/根候选与纯输出写集 issuer → W00 V3 root evidence/codec → D11 V3 签名冻结与预算原件 → W01 专用根事务/原件 → W01/D04 首次 joint 前驱读取和输出 → 真 Owner、正式 pin、root→joint 冷重开验收。每段分别编译和跑必要聚焦测试；只有最后的真实链路可解除产品 HOLD。
