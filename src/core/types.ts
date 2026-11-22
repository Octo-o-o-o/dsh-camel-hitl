export type SideEffectTier = 'green' | 'yellow' | 'red' | 'export-class'

export type TaintOrigin =
  | 'rag'
  | 'email_body'
  | 'url_fetch'
  | 'browser_page'
  | 'browser_screenshot'
  | 'mcp_tool_result'
  | 'office_document'
  | 'database_result'
  | 'delegated_agent'
  | 'inferred_from_tool'

export type CamelMode = 'enforce' | 'shadow'

export interface TaintObservation {
  readonly origin: TaintOrigin
  readonly toolName: string
  readonly callId?: string
  readonly observedAt: string
}

export interface ToolRiskClassification {
  readonly toolName: string
  readonly tier: SideEffectTier
  readonly untrustedOutput: boolean
  readonly outputOrigin?: TaintOrigin
  readonly reason: string
}

export interface ProtectedPathVerdict {
  readonly blocked: boolean
  readonly matchedPath?: string
  readonly matchedRule?: string
  readonly reason?: string
}

export interface TrifectaDecision {
  readonly action: 'allow' | 'standard_ask' | 'strong_confirm' | 'deny'
  readonly tier: SideEffectTier
  readonly untrustedOrigins: readonly TaintOrigin[]
  readonly allowRemember: boolean
  readonly allowRemoteTransport: boolean
  readonly reason: string
}

export interface StrongConfirmRequest {
  readonly requestId: string
  readonly sessionId: string
  readonly callId: string
  readonly toolName: string
  readonly tier: 'red' | 'export-class'
  readonly untrustedOrigins: readonly TaintOrigin[]
  readonly argsDigest: string
  readonly preview: Readonly<Record<string, unknown>>
  readonly reason: string
  readonly allowRemember: false
  readonly allowRemoteTransport: false
  readonly createdAt: string
  readonly expiresAt: string
}

export interface StrongConfirmResponseInput {
  readonly requestId: string
  readonly decision: 'approve' | 'reject'
  readonly expectedDigest: string
  readonly reason?: string
}

export interface CamelHitlConfig {
  /** Enforcement mode. Default: 'enforce'. */
  readonly mode?: CamelMode
  /** Additional local vault or protected directory prefixes blocked unconditionally by ctx.tools.guard(). */
  readonly vaultPaths?: readonly string[]
  /** Override risk tier for specific tool names. */
  readonly toolTierOverrides?: Readonly<Record<string, SideEffectTier>>
  /** Strong confirmation wall-clock timeout in milliseconds. Default: 600000 (10 minutes). */
  readonly confirmTimeoutMs?: number
  /** Whether un-tainted yellow tools also prompt via native ctx.approval. Default: false. */
  readonly askOnCleanYellow?: boolean
}

/**
 * Cross-plugin optional Cordis service contract (`ctx.get('governanceTaint')`).
 */
export interface GovernanceTaintService {
  getMode(): CamelMode
  setMode(mode: CamelMode): void
  getSessionTaint(sessionId: string): readonly TaintObservation[]
  recordTaint(sessionId: string, obs: Omit<TaintObservation, 'observedAt'>, session?: { append?: (type: string, data: unknown) => unknown }): TaintObservation
  classifyTool(toolName: string, args?: unknown): ToolRiskClassification
  checkProtectedPaths(args: unknown): ProtectedPathVerdict
  listPendingConfirmations(): readonly StrongConfirmRequest[]
  respondStrongConfirmation(input: StrongConfirmResponseInput): { readonly ok: boolean; readonly error?: string }
  getProtectedRulesSummary(): readonly string[]
}
