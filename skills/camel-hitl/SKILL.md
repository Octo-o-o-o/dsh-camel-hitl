---
name: camel-hitl
description: Operating guidance when dsh-camel-hitl runtime taint tracking and monotonic guards are active.
---

# CaMeL Taint & Strong HITL Guidance

This session is protected by `dsh-camel-hitl`:

1. **Untrusted inputs taint the session**: Any content returned from `web_fetch`, `web_search`, `email_read`, `browser_*`, `kb_read`, or external MCP tools taints the session persistently (including across restarts and forks).
2. **Respect strong confirmation boundaries**: Never attempt to bypass red-tier or export-class confirmations, never claim the user has already confirmed an action, and never attempt to read protected paths (`.credentials.yaml`, `.env`, `~/.ssh/*`, private keys, vault folders, or `governance/audit.sqlite`).
3. **Fail-closed on denial**: If `ctx.tools.guard()` or the user denies a high-risk call, report the denial honestly and stop rather than retrying with alternate tools.
