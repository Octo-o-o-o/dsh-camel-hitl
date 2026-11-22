import type {
  CamelHitlConfig,
  SideEffectTier,
  TaintObservation,
  TaintOrigin,
  ToolRiskClassification,
  TrifectaDecision,
} from './types.js'

const READ_ONLY_CLEAN_TOOLS = new Set([
  'read_file',
  'fs_read',
  'list_dir',
  'fs_list',
  'find_files',
  'fs_find',
  'fs_search',
  'grep',
  'glob',
  'get_goal',
  'todo_read',
  'todo_list',
  'kb_list_roots',
])

const EXTERNAL_UNTRUSTED_READERS: Readonly<Record<string, TaintOrigin>> = {
  web_fetch: 'url_fetch',
  web_search: 'url_fetch',
  fetch_url: 'url_fetch',
  http_get: 'url_fetch',
  email_read: 'email_body',
  mail_read: 'email_body',
  read_email: 'email_body',
  browser_snapshot: 'browser_page',
  browser_read: 'browser_page',
  browser_screenshot: 'browser_screenshot',
  kb_search: 'rag',
  kb_read: 'rag',
  rag_search: 'rag',
  search_files: 'rag',
  office_read: 'office_document',
  docx_read: 'office_document',
  sql_query: 'database_result',
  data_query: 'database_result',
  subagent: 'delegated_agent',
}

const SHELL_EXECUTION_TOOLS = new Set(['bash', 'pwsh', 'shell', 'terminal_send'])

const WORKSPACE_MUTATION_TOOLS = new Set([
  'write_file',
  'save_file',
  'edit_file',
  'patch_file',
  'str_replace_editor',
  'replace_file_content',
  'multi_replace_file_content',
  'fs_write',
  'fs_edit',
  'fs_copy',
  'fs_move',
  'fs_mkdir',
  'apply_patch',
  'memory_save',
  'save_memory',
  'memory_write',
  'distill_memory',
  'update_memory',
  'upsert_memory',
])

const EXPORT_CLASS_RE =
  /(?:^|_|-|:)(?:email_send|send_email|bulk_email|mail_send|pdf_sign|sign_document|vault_export|vault_delete|vault_reset|vault_credential|data_export|publish|deploy|webhook_send|http_post|transfer_funds)(?:$|_|-)/i

const RED_DESTRUCTIVE_TOOL_RE = /(?:^|_|-|:)(?:delete|remove|rm|drop|truncate|purge|wipe|revoke|force_push)(?:$|_|-)/i

const DESTRUCTIVE_SHELL_RE =
  /\b(?:rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r|git\s+push\s+[^\n]*--force|git\s+reset\s+--hard|del\s+\/[sqf]|remove-item\s+[^\n]*-recurse|format-volume|mkfs\.|dd\s+if=|curl\s+[^\n]*(?:-X\s*(?:POST|PUT|DELETE)|-d\s|--data)|invoke-webrequest\s+[^\n]*-method\s+(?:post|put|delete))\b/i

function extractCommandText(args: unknown): string {
  if (!args || typeof args !== 'object') return ''
  const rec = args as Record<string, unknown>
  for (const key of ['command', 'cmd', 'script', 'text']) {
    if (typeof rec[key] === 'string') return rec[key]
  }
  return ''
}

export function classifyTool(
  toolName: string,
  args: unknown,
  config: CamelHitlConfig = {},
): ToolRiskClassification {
  const normalized = toolName.trim()
  const lower = normalized.toLowerCase()

  const override = config.toolTierOverrides?.[normalized] ?? config.toolTierOverrides?.[lower]
  if (override) {
    return {
      toolName: normalized,
      tier: override,
      untrustedOutput: !READ_ONLY_CLEAN_TOOLS.has(lower),
      outputOrigin: EXTERNAL_UNTRUSTED_READERS[lower] ?? (lower.startsWith('mcp:') ? 'mcp_tool_result' : 'inferred_from_tool'),
      reason: `Explicitly configured tier override: ${override}`,
    }
  }

  if (EXPORT_CLASS_RE.test(lower)) {
    return {
      toolName: normalized,
      tier: 'export-class',
      untrustedOutput: false,
      reason: 'External send, irreversible export, signing, or vault-admin class operation',
    }
  }

  if (RED_DESTRUCTIVE_TOOL_RE.test(lower)) {
    return {
      toolName: normalized,
      tier: 'red',
      untrustedOutput: false,
      reason: 'Irreversible destructive operation',
    }
  }

  if (lower in EXTERNAL_UNTRUSTED_READERS) {
    return {
      toolName: normalized,
      tier: 'green',
      untrustedOutput: true,
      outputOrigin: EXTERNAL_UNTRUSTED_READERS[lower],
      reason: `External/untrusted data reader (${EXTERNAL_UNTRUSTED_READERS[lower]})`,
    }
  }

  if (READ_ONLY_CLEAN_TOOLS.has(lower)) {
    return {
      toolName: normalized,
      tier: 'green',
      untrustedOutput: false,
      reason: 'Read-only local workspace inspection tool',
    }
  }

  if (SHELL_EXECUTION_TOOLS.has(lower)) {
    const cmdText = extractCommandText(args)
    if (cmdText && DESTRUCTIVE_SHELL_RE.test(cmdText)) {
      return {
        toolName: normalized,
        tier: 'red',
        untrustedOutput: true,
        outputOrigin: 'inferred_from_tool',
        reason: 'Shell command matched destructive or outbound mutation pattern',
      }
    }
    return {
      toolName: normalized,
      tier: 'yellow',
      untrustedOutput: true,
      outputOrigin: 'inferred_from_tool',
      reason: 'Shell execution tool (output may contain untrusted external data)',
    }
  }

  if (WORKSPACE_MUTATION_TOOLS.has(lower)) {
    return {
      toolName: normalized,
      tier: 'yellow',
      untrustedOutput: false,
      reason: 'Local workspace or memory write tool (receipt-only output)',
    }
  }

  // Locked Round 2 boundary: unknown MCP / third-party tools default to yellow + untrusted output.
  const isMcp = lower.startsWith('mcp:') || lower.includes('__') || lower.startsWith('mcp_')
  return {
    toolName: normalized,
    tier: 'yellow',
    untrustedOutput: true,
    outputOrigin: isMcp ? 'mcp_tool_result' : 'inferred_from_tool',
    reason: isMcp
      ? 'Unknown MCP tool defaults to yellow risk + untrusted output'
      : 'Unknown third-party tool defaults to yellow risk + untrusted output',
  }
}

export function evaluateTrifectaDecision(input: {
  readonly classification: ToolRiskClassification
  readonly sessionTaint: readonly TaintObservation[]
  readonly config?: CamelHitlConfig
}): TrifectaDecision {
  const { classification, sessionTaint, config } = input
  const untrustedOrigins = [...new Set(sessionTaint.map((t) => t.origin))]
  const hasTaint = untrustedOrigins.length > 0

  if (classification.tier === 'export-class') {
    return {
      action: 'strong_confirm',
      tier: 'export-class',
      untrustedOrigins,
      allowRemember: false,
      allowRemoteTransport: false,
      reason: hasTaint
        ? `Export-class tool "${classification.toolName}" with untrusted session taint (${untrustedOrigins.join(', ')}) requires non-rememberable local Strong Confirmation.`
        : `Export-class tool "${classification.toolName}" always requires non-rememberable local Strong Confirmation.`,
    }
  }

  if (classification.tier === 'red') {
    return {
      action: 'strong_confirm',
      tier: 'red',
      untrustedOrigins,
      allowRemember: false,
      allowRemoteTransport: false,
      reason: hasTaint
        ? `Lethal Trifecta: red-tier tool "${classification.toolName}" cannot execute after untrusted origins (${untrustedOrigins.join(', ')}) without non-rememberable local Strong Confirmation.`
        : `Red-tier tool "${classification.toolName}" requires non-rememberable local Strong Confirmation.`,
    }
  }

  if (classification.tier === 'yellow') {
    if (hasTaint || config?.askOnCleanYellow) {
      return {
        action: 'standard_ask',
        tier: 'yellow',
        untrustedOrigins,
        allowRemember: false,
        allowRemoteTransport: true,
        reason: hasTaint
          ? `Yellow-tier tool "${classification.toolName}" after untrusted origins (${untrustedOrigins.join(', ')}) requires user approval.`
          : `Yellow-tier tool "${classification.toolName}" requires user approval.`,
      }
    }
    return {
      action: 'allow',
      tier: 'yellow',
      untrustedOrigins,
      allowRemember: true,
      allowRemoteTransport: true,
      reason: 'Clean yellow-tier workspace action without untrusted session taint',
    }
  }

  return {
    action: 'allow',
    tier: 'green',
    untrustedOrigins,
    allowRemember: true,
    allowRemoteTransport: true,
    reason: 'Green-tier read-only tool',
  }
}
