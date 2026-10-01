# Installed W09 Owner and D04 initialization UI

## Actual shipped source

The production workbench remains `webui-heritage/src/App.vue`, built as one self-contained HTML file. `webui-src` is not separately served by the alpha1 package. The Vue components import the explicit shared request/validation helpers from `webui-src`; Vite bundles them into the real output.

- `OwnerAccess.vue`: HTTPS-only signed Owner challenge, locally produced signature completion, logout. No private-key/password input, persistent browser storage or inferred identity.
- `RoleSetup.vue`: explicitly selected D01 preset and real model/budget references; actual recent-scene candidates; explicit scene/visibility binding confirmation. Exact operation/phase receipts; no automatic chat send.
- `D04Initialization.vue`: root draft, dedicated CPU budget, compilation, root adoption, authored topology, complete semantic profile adoption, explicit role clock. Each is a separate confirmed command; no hidden initial values, time rate, shares or adoption.
- Profile revisions are filled only from the fenced `projection.current.mapping_revision` and `clock_version`. Current preset and registered clock metadata remain visible. Missing metadata leaves CAS fields empty.

Same-input retries retain UUID4 operation IDs within the current page session. Double clicks are blocked while pending. Scope/session changes and unmounts invalidate responses and clear private temporary state. Navigation within the shipped shell preserves components so an uncertain operation is not silently assigned a new ID when returning. Browser refresh loses local attempts; users are instructed to retain operation IDs/receipts.

## Validation completed

- Vue/TypeScript production build: passed
- Heritage suite: 142 passed across 25 files
- Shared W09 Node contract/application/input suite: 55 passed
- Actual production HTML includes signed Owner, scene and D04 actions, no external JS/CSS bundles
- `verify_delivery_assets.verify_workbench`: passed, exact source build/resource byte identity and hash
- Production HTML at this checkpoint: 689111 bytes, SHA256 `3e296089fc19e4df3ede0d4a05b19567e574311ee8b41de2ff907593e77258ca`

The legacy build-output test referred to retired `UI/` and `pages/dashboard/` locations; its acceptance now compares the actual build and packaged `resources/workbench/index.html` instead.

This source snapshot has no Git metadata. Existing resource files were updated from the verified Vue build with exact SHA256/byte manifest entries; Git tracked-file evidence was not fabricated. The canonical resource verifier succeeded.

## Not claimed by these checks

No interactive real-browser visual test, live AstrBot deployment, actual paid model call or real chat delivery was performed. The integration worker is separately exercising the seven commands through real W09 HTTP/Owner/session fixtures. Browser SSR and request-harness checks are not that integration result.

Whole-Host maintenance controls are not exposed as a fake same-page resume flow. Stopping Host also stops W09; an independently reachable authenticated management route must exist before an operational resume UI can be offered.
