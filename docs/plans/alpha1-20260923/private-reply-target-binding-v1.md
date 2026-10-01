# K03 私聊回复对象与投递地址

状态：2026-09-27 后端集成裁决；当前代码及实发链路仍以逐项验收为准。前端与模型资产暂缓。

私聊回复涉及两个不同身份：D03/D05/D08 审核的对象是图内 `entity:account-v1:` 账户实体；平台投递使用原始宿主私聊路由和 JSON `conversation_ref`。账户实体只代表某个宿主命名空间中的账户端点，不推断自然人，也不从昵称或消息文本合并身份。不能把 JSON 路由填入 `target_entity_ref`，也不能把实体 ID 追加到 delivery audience 来满足集合检查。

原 C02 ingress 固定 namespace、完整 `platform_ref`、`sender_ref`、`conversation_ref`、source 和 operation。D03 的 `message_arrival` 已从前三项确定性生成账户 `EntityAnchor` 和受信 `message_received` WorldEvent；同一 arrival 业务事务还须创建或验证 `AccountBinding`，其 `verification_ref` 指向该事件。相同账户的后续到达复用同一实体，不同会话保留各自路由和受众。冲突、失效或多重当前绑定保持 HOLD。

K03 的受信当前读必须从原 C02/source 追溯 ingress identity，核对当前 D06 来源资格、D03 arrival event、active account anchor、唯一有效 AccountBinding、版本与负查询水位。返回的 `target_entity_ref` 进入 D03/D05 和 D08 `ActionIntent`；原 `conversation_ref` 仅进入 audience、D09 batch 与 D11 outbox。D08 communication grant 使用显式的实体对象到投递受众绑定证据，不能继续要求 `intent.target_ref in request.audiences`；D09/D11 同时冻结两者及其关联。

最终 admission、claim 和发送前重新读取绑定及来源版本。若账户重新绑定、证据撤销、来源删除或目的地变化，原 effect 保持 HOLD 或取消；不能静默换地址重发。重新证明只由后续受信 arrival 和 D03 修订流程完成，K03 不自行补建实体。正向验收至少覆盖同账户跨会话复用实体、每个会话独立投递；反例覆盖伪造 sender、跨平台同名、缺失/重复/失效绑定、版本变化和原 D05 deny。
