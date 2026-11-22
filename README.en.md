# dsh-camel-hitl

> Runtime **CaMeL / Lethal Trifecta taint tracking**, un-bypassable **monotonic `ctx.tools.guard()` enforcement**, protected-path blocking, and **digest-bound Strong HITL confirmations** for **DeepSeek Harness (`dsh@0.2.2-rc.5`)**. Apache-2.0 licensed.

[简体中文](README.md)

## Features

- **Durable Session Taint Tracking**: Persists untrusted data observations (`web_fetch`, `email_read`, `browser_*`, `kb_read`, unknown MCP tools) as log-only `governance/taint-observed` SessionEvents folded via `ctx.sessionProjections` so restarts, resumes, and session forks never clear taint.
- **Un-bypassable Monotonic Guard (`ctx.tools.guard()`)**: Enforces protected-path/vault denylists and verifies single-use, process-ephemeral HMAC receipts bound to `(exec.token, callId, canonicalArgsSha256)` right before tool dispatch—defeating `{ prepend: true }` waterfall bypass attempts.
- **Zero-Conflict Layered HITL**: Routes `yellow × untrusted` calls through native `ctx.approval` (fully compatible with `ui-approval` and `@michengai/dsh-im-connect`), while isolating `red` and `export-class` actions into a local-only, non-rememberable `shell.overlay` Strong Confirmation modal (never colliding with `conversation.approval.detail`).
- **Loose Cross-Plugin Integration**: Exposes `governanceTaint` and automatically logs enforcement events to `dsh-audit-ledger` when installed.

## Installation

```bash
dsh plugin --profile web add github:Octo-o-o-o/dsh-camel-hitl
dsh web
```

## License

[Apache-2.0](LICENSE) — Copyright 2026 OctoLab (`Octo-o-o-o`).
