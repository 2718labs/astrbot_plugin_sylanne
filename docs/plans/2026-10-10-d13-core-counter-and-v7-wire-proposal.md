# D13 Core 独立全请求计数与 V7 候选协议

状态：candidate40 架构提案；未实施、未运行256场景。C09 V2 实施与本提案独立推进。新模型模板需用户选择，本提案不修改 V6 模板、旧签名原件、单次配额或期限。

## 1. 已核实的两个独立阻塞

当前 `authority_service/d13_installed_counter_v1.py` 使用受保护程序，实际 stdin 上限是16777216字节，stdout与stderr分别65536字节。当前Host执行身份不能读取root:0600 counter私钥。扩大RPC body、chmod/setuid、复制密钥到Host、把私钥放进可读脚本均不是允许的解法。

V6本身还有独立的单次容量问题：`natural_reply_history_v6.py` 将 `asdict(history_selection)` 全部嵌入dynamic model message；`installed_d13_natural_frame_v6.py` 的压缩候选仍保留 `window.read_set` 全部证明。新的初始Root总预算只能解决累计预算，不能使一个超过6000 input/7024总上下文的请求变小。

静态下界条件是：tail256有128个不同的实际入站Source/C02与128个出站槽，每个入站至少保留correction absence、arrival、source、access四个不同VersionedRef。实际合法Owner类型中最短VersionedRef JSON为63字节，512个引用的数组至少 `512*63+511+2=32769` 字节。在本地有限Mock使用的 `ceil(HTTP UTF-8 bytes/4)` 规则下，输入至少8193；这尚未包括其他字段、真实较长ID、正文、双重JSON转义及HTTP billing metadata。因此该形状的V6场景静态HOLD。

证据文件 `D:/codex_handoffs/Sylanne/complete-agent-local-20261006/evidence/d13-v6-256-wire-lower-bound-core-counter-proposal-20261010.json` 保存了实际源hash、合法Owner最小编码及条件。它是数学下界，不是256业务吞吐、真实提供商tokenizer或实际资源测量。

## 2. 首选边界：Core独立重建，Host只传实际locator

新增具名 `InstalledD13CoreCounterV1`；只由受保护Core安装工厂持有签名私钥、pinned tokenizer/serialization/applicability资产和真实current-reader。Host只持有现mTLS client、pinned public key以及bounded selector；没有“签任意bytes”入口。

新请求 `D13CurrentWireCountSelectorV1` 至少绑定：

- 安装、authority、namespace、activation/storage generation；实际job/step/C02 cause、plan原件ref/version/digest及Owner responsibility。
- 原当前frame/Graph pointer和collection snapshot selector、question Source版本/权限、当前Owner grant ref/version/digest。
- 原D11 parent budget grant、lease及counter CPU reservation；原有效期和唯一count operation/nonce。
- 指定已安装的wire schema/template/policy digest；Host可给expected pair digests用于一致性检查，不能把它们当实际请求来源。

此selector单请求仍≤65536字节。Core沿实际原件重建collection、当前question/plan、已付费derived blocks与raw/compressed完整wire；Source/Owner/grant/lease/frame任一变化则原操作失效，不接受调用方附送“新证明”延续权限。

现V6 collector最多4页×64槽只用于固定256窗口，不能扩大到512；256次SDK episode的验收另核256个真实C02和合法tail256，不混淆两个计数。

Core的重建可能依赖Host此前暂态freeze。此时应在真实原件阶段落一个具名、不可变的frame intent selector，由Core以相同actual trusted time/absolute expiry重建；不能直接把Host JSON认证为独立输入。具体reader应复用 `d13_natural_frame_verifier_v6.py` 等actual原件链，只有明确新模板时才新增对应V7 verifier。

## 3. 真实CPU、计数与签名顺序

计数本身不是model admission。它先使用同一个实际job之下独立具名的counter CPU prepared/reservation；model token/cost quote与reservation仍在完整计数被正式接受后产生。不能反过来要求一个尚不知道tokens的model reservation来授权初始counter，造成协议循环。

顺序为：

1. Core具名入口核身份、current Owner/Source、原D11 job/grant/lease及count operation intent，保留真实counter CPU限额与期限。
2. Core独立生成/冻结实际wire pair，绑定expected原件和serializer/tokenizer pins。完整wire只在受保护执行边界内交给既有Native/internal-work风格的有限worker；不外发到Host签名。
3. worker在真正受管内核执行组里完成已安装计数，返回固定closed count result。读取真实kernel CPU terminal/计量原件，经现D02/D11 accounting链正式核验和结算；计数worker不持私钥。
4. Core重新核current frame、Owner/Source、grant/lease、绝对期限和实际完整wire身份，签一个具名、固定schema envelope，同时绑定实际CPU terminal与settlement原件。
5. Host以pinned public key验证，随后在原有短Graph transaction、真实current fence下导入。之后的quote、model reservation、W01 adoption、provider admission继续独立核验。

Core签名开销与worker CPU各自遵循真实既有accounting边界，不将`time.monotonic`、估计tokens或固定1000ms伪称内核CPU。原Root 120000ms是否足够256流程尚未测量；不能通过乘一个猜测系数声称足额。

超时/断联保留原count operation的unknown/prepared/实际CPU事实；只允许查询或恢复原操作，不能失败后无偿重发新nonce。客户端绝不能将一次DTO构造或counter签名解释为Source访问许可、已付模型调用或namespace恢复资格。

## 4. 新证据schema与历史兼容

新增 `sylanne3.d13.core-full-wire-evidence.v1` 及独立签名domain，不能往旧V6 `_FIELDS`偷偷加字段然后沿用其签名域。

固定payload包括：原operation/nonce和selector digest；原安装/namespace/frame/job/Owner/grant/lease及CPU reservation commitment；原raw/compressed完整request/frozen/collection/blockset commitments；原policy/template/tokenizer/serializer/applicability pins；确切或保守whole-HTTP上下界；原frozen/expiry；实际独立worker binding、kernel CPU terminal、D02/D11 settlement ref/digest；签名issuer/key id。

若现有fixed V6 count-original字段需要重用，应由新的explicit adapter只提取已验证same pair的语义，不能把新证据伪造为旧签名，也不能让旧verifier自动接受未知schema。历史V1/V6仍走原exact verifier，旧key/字节/hash保持。

原计数对象是实际provider request。有限Mock的保守上界需包含 `model/messages/stream/max_completion_tokens/metadata` 和真实HTTP serializer开销；内部natural wire的 `provider_id/model/messages/max_output_tokens` 不能冒充最终HTTP bytes。`bounded_full_wire` 的lower/upper与conservative-switch策略必须显式。真实provider tokenizer或计数endpoint需要实际pinned applicability，Mock byte/4不外推为真实模型计费。

新response仍≤65536字节。若固定证明vector实际超过此限，新增具名paged evidence locator在同受管存储取原件；不提高通用mTLS/旧counter response上限。

## 5. 仅当独立重建确实不可用时的输入分片备选

不优先实现Host推送16MiB任意JSON。若一个特定模板确实没有可用的Core原件重建路径，必须另立具名 `begin/append/seal current count input` 协议：同operation/scope、固定总上限、每片≤旧RPC body、严格ordinal/offset/previous digest、完整count/EOF、同受管quotas和崩溃恢复。每片digest只是传输完整性；seal后仍需Core用实际Source/Owner/frame验证内容，再才允许计数签名。

分片不形成新Source，不授权任意路径/SQL/blob。不能因为16MiB旧stdin支持存在，就认为新的网络16MiB body或无限spool被授权。本提案首选selector重建，避免新增此状态机。

## 6. V7 明确模型模板候选

如果用户选择新模板，建议新 `NaturalReplyInputV7` / `FrozenNaturalReplyRequestV7` / `InstalledD13WirePolicyV7`，全新INPUT_SCHEMA、TEMPLATE_DIGEST、signing domain和closed dispatcher。V6永远保持原template hash，不原位改名。

Core保留完整read_set、Source lineage/current permissions、collection/derived-paid-block证明和qualification；模型请求只包含新模板明确允许的有限语义材料：question、必要expression plan、qualified units、带序列/角色的已选正文、必要gap/coverage语义，以及对应完整Core provenance的固定commitment。完整原件仍进入frozen authority input digest和最终请求批准链；model-visible digest不作为授权，也不要求模型自行解释一个hash来替代业务语义。

此变更是明确新template的语义设计，不是修改V6后私自删证明或截断cert。Core/Native必须独立证明V7语义projection与完整actual originals对应；model response、review、adoption及C09 retention也全部显式支持V7。任何旧原件不能因版本未知而自动降级或丢弃。

仍保留现6000 input、1024 output、7024总上下文和原call ceilings/期限。新模板是否够用必须由独立Core counter对完整HTTP请求证明；正文过长或其他metadata超限保持真实HOLD。不预设“把read_set挪走就一定全256通过”，不暗改窗口、不增配额。UI/SDK反馈必须将容量HOLD、计数服务缺失、期限/CPU不足分开呈现。

## 7. 实施边界与最少必要验收

- Root：实际Core service实例、具名权限/RPC、protected factory/key ownership、current selectors、Native CPU原件/accounting、closed dispatch；不得给通用LLM credential增加任意签名能力。
- Astra：批准后的新wire projection合同、commitments与绑定审查。当前只交提案，不动V6源码。
- Bubble：真实Host counter client/已验证新证据消费、有限Mock真实HTTP upper校验、SDK固定node；不能创建Host可读counter私钥。
- Phase：固定runner/新隔离安装工厂与已批准初始Root；不修改旧grant或替换缺失CPU证据。

先编译，再在单一受控永久场景覆盖root:0600真实服务成功、Host直接读key失败、wrong namespace/job/Owner/frame/lease/nonce拒绝、counter返回签错原件拒绝、unknown后同operation恢复和CPU计账、完整HTTP bytes实际落在已签上界内。新模板授权后才在新的隔离安装运行256完整SDK family，保存首错；freeze39、旧V6和旧Root保持只读。未有真正完整counter与容量资格前，256驱动维持NOT_RUN/HOLD。