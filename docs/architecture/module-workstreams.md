# Sylanne 3.0 independent module design workstreams

用户在 2026-09-22 要求将所有模块拆成独立任务和不同工作树，由用户逐个设计，并通过 PR 汇总到同一上游。

**当前方式已更新（2026-09-27）：** 用户随后要求回收已有设计，改为在总装任务中逐步讨论，并新增 D13 短期上下文；十三模块的当前设计入口是[完整设计索引](sylanne-3-design-index.md)与[耦合总装](sylanne-3-thirteen-module-coupling.md)，历史来源见[设计回收记录](design-recovery-20260922.md)，工作副本在 `G:\Sylanne\docs\modules`。旧任务、分支及工作树保留作来源，暂不继续并行设计。当前设计修改留本地，不创建或更新设计 PR、不推送设计修改。以下模块所有权继续用于组织内容，不要求用户分别进入旧模块任务。

## Shared baseline and workflow

- Repository: `2718labs/astrbot_plugin_sylanne`.
- Shared integration branch and PR base: `codex/embodiment-3-rewrite`.
- Each module starts from the same committed integration baseline in a separate Codex-managed worktree. A module owns a distinct feature branch; its PR base is always the shared integration branch.
- This task (`01a0c908-2e83-7453-9d34-25628e22b8e7`, workspace `G:\Sylanne`) coordinates interfaces, shared changes, integration checks and PR review. No automatic merge/release is authorized by initial module creation.
- The initial module setup is complete. Further design now takes place in the integration task; do not automatically resume the old module tasks or implement their drafts.
- Current local drafts and their contracts/acceptance live in `docs/modules/` and are linked from the design index. On later implementation work, other modules consume the versioned public contract; they do not assume unmerged decisions are available.
- Before implementation, synchronize with the integration branch. Keep unrelated changes out of the PR. Cross-module dependency changes should be reviewed in the integration task and merged before dependent implementation PRs, or explicitly declared as blocked dependencies.
- Current design revisions stay local without PRs or pushes. Future implementation PRs, when requested, target the shared integration branch. Do not infer merge or release permission from a passing local test or from this workstream setup.
- Startup baseline checks use Git identity and commit equality. Build/test evidence is inherited only as historical baseline evidence; run relevant verification when implementing. Native DLLs, local runtime environments and ignored acceptance logs are not copied into these design worktrees.

## Module ownership

| ID | Module task | Owned design document | Responsibility and boundary |
|---|---|---|---|
| D01 | Sylanne 3.0 · 主体与人格 | `docs/modules/01-persona.md` | 身份、价值冲突、人格特质、自我认知、偏好和人格发展；记忆提供来源，自传存储/检索接口与 D06 协作。 |
| D02 | Sylanne 3.0 · 身体与需求 | `docs/modules/02-body-needs.md` | 模拟精力、疲劳、压力、需求竞争、节律、恢复与活动成本；活动执行属于 D10。 |
| D03 | Sylanne 3.0 · 世界与情境 | `docs/modules/03-world-context.md` | 实体与事件理解、多人场景、信息视角、事实/引用/假设与未知；不擅自修改记忆真源或其他人的身份。 |
| D04 | Sylanne 3.0 · 情绪与调节 | `docs/modules/04-emotion.md` | 对象化评价、混合情绪与连续演化、调节与元情绪、行为读出；不以情绪状态机组织过程；数值执行合同与 D11 协作。 |
| D05 | Sylanne 3.0 · 社会关系 | `docs/modules/05-relationships.md` | 分对象/领域/场景的信任、亲近、边界、互惠、冲突修复；承诺状态由 D08 拥有。 |
| D06 | Sylanne 3.0 · 记忆系统 | `docs/modules/06-memory.md` | 来源、主观痕迹、情感编码/重建、联想、回忆与维护；跨模块协议及验收见同目录 `06-memory-contracts.md`、`06-memory-acceptance.md`。继承已有持久化与有界回忆切片，不接管其他领域真值。 |
| D07 | Sylanne 3.0 · 注意与认知 | `docs/modules/07-attention-cognition.md` | 持续关切、有限注意/工作集、竞争解释/信念、反思/元认知、他者视角与隔离推演；复用 D06 检索和回忆提交。协作/验收见同目录 `07-cognition-contracts.md`、`07-cognition-acceptance.md`。 |
| D08 | Sylanne 3.0 · 动机与执行 | `docs/modules/08-goals-execution.md` | 目标、承诺、联合计划、行动候选、前置条件和结果结算；发送机制复用 D11，语言表达由 D09。 |
| D09 | Sylanne 3.0 · 对话与表达 | `docs/modules/09-dialogue-expression.md` | 话题连续性、表达意图、语气、节奏、打断、语言合同与生成核验；不绕过状态/权限/投递合同。 |
| D10 | Sylanne 3.0 · 生活与主动行为 | `docs/modules/10-life-proactivity.md` | 兴趣项目、日程、习惯、生活活动、离线推进及主动交流时机；真实产出与角色模拟明确区分。 |
| D11 | Sylanne 3.0 · 运行内核与宿主 | `docs/modules/11-runtime-host.md` | 共享类型图、事务/恢复、算子调度、Rust 数值核、预算、投递、AstrBot 生命周期及公共接口；负责基础设施，不替代领域语义。 |
| D12 | Sylanne 3.0 · 角色工作台与交付 | `docs/modules/12-workbench-delivery.md` | 角色创作、关系/记忆浏览、因果诊断、隔离实验、配置、迁移操作界面、原生分发和完整产品使用流程。 |
| D13 | Sylanne 3.0 · 短期上下文 | `docs/modules/13-short-context.md` | 72 小时内已提交对话的可删除压缩表示、异步预制、待用激活和本轮短期片选择；D06 仍拥有来源/记忆，D09 仍拥有对话/表达，D11 仍拥有预算/外送/物理回收。 |

## Current design and acceptance

- The [thirteen-module design index](sylanne-3-design-index.md) links each main specification, public contract and future acceptance. [Shared collaboration rules](module-collaboration-contracts.md), [integrated acceptance](sylanne-3-integration-acceptance.md) and the [historical requirement coverage matrix](sylanne-3-requirements-coverage.md) provide the cross-module view. These are local design artifacts, not implementation acceptance.
- `embodiment-3-system.md`, `embodiment-3-mechanisms.md`, `embodiment-3-ecosystem.md`, `embodiment-3-memory.md`, `embodiment-3-memory-theory.md` and `affective-memory-mechanism-proposal.md` remain historical inputs. Later explicit user decisions, including D04 non-state-machine emotion and affective memory encoding/recall, take precedence over conflicting older sketches.
- Requirement ledger: `rewrite/REQUIREMENTS.md`; accepted direction: `rewrite/design/user-approved-direction.md`.
- Current local evidence: `rewrite/MEMORY_ACCEPTANCE.md` records 173 core Python tests, 2 Rust tests and 9 controlled SDK tests. This is partial implementation evidence, not whole-product or live-platform acceptance.
- Implementation currently lives in `rewrite/sylanne3` with the new root plugin entry. Numeric and expression fixtures do not cap the final heavyweight product scope.

The task/worktree mapping is recorded separately after native worktree creation so the common baseline remains identical for all twelve modules.
