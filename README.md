# dsh-camel-hitl

> 面向 **DeepSeek Harness (`dsh@0.2.2-rc.5`)** 的运行时 **CaMeL / Lethal Trifecta 污点追踪**、不可绕过 **单调守卫（`ctx.tools.guard()`）**、敏感路径保护与 **参数摘要绑定强 HITL 审批** 插件。Apache-2.0 开源。

[English](README.en.md)

## 核心能力

- **持久化污点追踪（重启/恢复/Fork 不丢失）**：在 `tools/post-execute` 捕获外部不可信数据源（`web_fetch`、`web_search`、`email_read`、`browser_*`、`kb_read`、未知 MCP 工具），通过 `@deepseek-ai/dsh-session` 官方 `appendPluginRecord()` 写入 `ignorable: true` 插件事件（`plugin:dsh-camel-hitl/taint-observed`），并在会话重启/恢复/Fork 时从 `session.snapshotEvents()` 自动折叠恢复。
- **不可绕过的单调守卫（`ctx.tools.guard()`）**：将敏感路径/Vault 黑名单与高危回执验签落在 `dsh` 官方单调守卫中，即使存在恶意插件通过 `{ prepend: true }` 在 `tools/pre-execute` 直接放行，也无法绕过最终拦截。
- **分层 HITL 零冲突共存**：
  - `yellow × untrusted`（如读取外部网页后再写文件）返回标准 `{ kind: 'ask' }`，完全兼容原生 `ui-approval` 与 `@michengai/dsh-im-connect` 远程 IM 审批；
  - `red`（不可逆删除/危险命令）与 `export-class`（外发邮件/签章/导出/保险箱管理）挂在多占槽位 `shell.overlay`（**绝不抢占** `ui-chat` 单槽位 `conversation.approval.detail`），展示脱敏业务预览、污点来源与 `SHA-256` 摘要，**硬禁记住、硬禁远程审批**，签发绑定 `(exec.token, callId, canonicalArgsSha256)` 的一次性进程内 HMAC 回执。
- **内置敏感路径与 Vault 黑名单**：默认拦截 `.credentials.yaml`、`.env*`、`~/.ssh/*`、`*.pem/*.key`、云凭据、用户自定义 `vaultPaths` 及 `governance/audit.sqlite`。PII 源头脱敏与社区 `dsh-redact` 保持解耦兼容。
- **松耦合联动**：暴露 `ctx.provide('governanceTaint', ...)`，若同时安装 `dsh-audit-ledger` 自动将所有拦截与强审批决策写入 SHA-256 哈希链审计库。

## 安装（官方 `dsh@0.2.2-rc.5`）

```bash
dsh plugin --profile web add github:Octo-o-o-o/dsh-camel-hitl
dsh web
```

## 配置项（`cordis.patch.yml`）

```yaml
- id: dsh-camel-hitl
  name: dsh-camel-hitl
  config:
    mode: enforce               # enforce（默认）或 shadow（仅观察不拦截）
    vaultPaths: []              # 额外禁止 Agent 读写的敏感目录列表
    askOnCleanYellow: false     # 未受污点污染的普通写操作是否也弹窗
    confirmTimeoutMs: 600000    # 强确认超时（默认 10 分钟，超时 fail-closed）
```

## 诚实安全边界

- `dsh@0.2.2-rc.5` 的 Host 插件共享同一 Node 进程，不构成插件级 OS 沙箱。
- 污点追踪基于会话级累积来源集合（工程子集），而非完整变量级数据流图；但配合 `red/export-class` 强制本机单次确认与 `ctx.tools.guard()`，可有效阻断提示注入驱动的静默外发与破坏。

## 许可证

[Apache-2.0](LICENSE) — Copyright 2026 OctoLab (`Octo-o-o-o`).
