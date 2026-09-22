# Recall controller contract

`sylanne3.recall_policy` is a deterministic, in-memory routing state machine. It does not read a database, call a model, send a message, mutate memory, or prove that any supplied evidence is true. A trusted adapter creates structured requests, executes returned plans, and returns structured results.

## Request and result flow

1. Construct `RecallRequest(request_id, trigger, gaps, required_checks, budget, timeout_seconds)` using the `Trigger` enum, unique nonempty slot/check names, and a finite positive timeout.
2. Call `RecallPolicy(request).next()`. Production uses `time.monotonic`; tests may inject a monotonic callable through `RecallPolicy(request, clock=...)`.
3. For `exact_check`, `working_set`, `light_search`, or `deep_search`, execute only the returned `Plan`, then call `accept(SearchResult(...))` with the same request, operation, and action identity.
4. Repeat until `ready`, `clarify`, `insufficient`, or `deferred`.

The controller reserves the complete `Plan.reservation` before returning a dispatchable plan. Re-reading `next()` while it is pending returns that same plan and consumes nothing further. `accept()` validates and stages the whole evidence batch before atomically replacing evidence and missing-slot state. It refunds unused candidate, node, and model-call reservation. Replaying an identical result is idempotent; a conflicting replay, foreign request, wrong action, unknown operation, over-budget result, or conflicting source identity is rejected without partial acceptance.

All counts are strict nonnegative integers (`bool` is rejected). The total auxiliary model-call budget is at most two. Timeout, computed monotonic deadline, clock readings, and scores must be finite; timeout and deadline must also be positive. Enums, tuples, evidence objects, unique names, and cross-request identities are validated rather than coerced.

## Routing guarantees

- Required checks run before the working set and remain blockers until evidence marks them complete. `correction`, `commitment`, and `deadline` add a conservative built-in check; `uncertain` adds `trigger_classification`.
- A missing required check can never yield `ready`. Round budget limits dispatched work and does not represent elapsed time. The independent monotonic deadline is checked before dispatch. Any elapsed-time or work-budget exhaustion yields `insufficient`; exhaustion is not evidence sufficiency.
- The working set is a source-activation path. It may fill gaps and contribute evidence without any storage query.
- Remaining gaps use bounded light search and then, when useful capacity exists, bounded deep search. Deep search can reserve no more than two auxiliary calls. An empty working-set check does not count as a failed search round. Two consecutive completed search/check rounds that reduce neither gaps nor checks stop with `insufficient`.
- A result received at or after the monotonic deadline cannot add evidence, close a gap, or make the request `ready`. Its reported resource use is still charged, including auxiliary model calls, and an identical replay remains idempotent.
- Evidence is deduplicated by source ID. The adapter must make each ID refer to one already verified, concrete source version; this controller does not verify graph authority, provenance, or version currency. Repeated observations of that ID may add `fills` and `checks`; those task-coverage annotations are merged in stable order, and the stored score is their maximum. That maximum is a routing score, not calibrated confidence. A changed `source_family` or `external` classification conflicts and rejects the entire result atomically. External evidence diversity is counted by `source_family`, so multiple results from one family do not masquerade as new independent evidence.
- `activated_source_ids` reports accessed sources. `recall_experience` is decided separately from access: this version emits only a current-request candidate for explicit-history and association triggers with activated evidence. A database read is neither necessary nor sufficient on its own. The candidate does not itself create an external event, responsibility, durable experience, or permission.
- `context_gap` with an unresolved `referent` returns `clarify` after checking the working set. `maintenance` returns `deferred` immediately. Every plan has `action_authorized=False`: maintenance and recall never grant permission for outward action.

## Integration boundary

The host still must enforce ownership, audience, permissions, source/current-version validity, cancellation, quiet hours, and the actual candidate/node/model work. A future durable controller must enforce cross-request concern quotas, cooldown, reactivation, and persistence before turning a recall-experience candidate into durable state. The host also decides whether a ready evidence package may support a reply or action. This module is not wired into Sylanne's application, scheduler, persistence, event graph, model client, or delivery path.
