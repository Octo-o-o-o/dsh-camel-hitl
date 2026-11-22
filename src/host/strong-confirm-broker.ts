import { randomUUID } from 'node:crypto'
import type { ApprovalReceiptStore } from '../core/canonical-digest.js'
import type {
  StrongConfirmRequest,
  StrongConfirmResponseInput,
  TaintOrigin,
} from '../core/types.js'

const SENSITIVE_PREVIEW_KEYS = /password|passwd|secret|token|apikey|api_key|authorization|cookie|privatekey|credential/i
const PREVIEW_FIELD_LIMIT = 14

function sanitizePreviewValue(key: string, val: unknown): unknown {
  if (SENSITIVE_PREVIEW_KEYS.test(key)) return '[REDACTED]'
  if (typeof val === 'string') {
    const scrubbed = val
      .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi, 'Bearer [REDACTED]')
      .replace(/\b(?:sk|pk|rk|ghp|gho|xoxb|AIza)[-_A-Za-z0-9]{12,}\b/g, '[REDACTED_KEY]')
    return scrubbed.length > 260 ? `${scrubbed.slice(0, 260)}… (${val.length} chars)` : scrubbed
  }
  if (typeof val === 'number' || typeof val === 'boolean' || val === null) return val
  if (Array.isArray(val)) return `[Array(${val.length})]`
  if (typeof val === 'object') return `{Object(${Object.keys(val as object).length} keys)}`
  return String(val)
}

export function buildScrubbedConfirmPreview(args: unknown): Readonly<Record<string, unknown>> {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    return { valueType: Array.isArray(args) ? 'array' : typeof args }
  }
  const rec = args as Record<string, unknown>
  const out: Record<string, unknown> = {}
  const keys = Object.keys(rec).sort()
  for (const key of keys.slice(0, PREVIEW_FIELD_LIMIT)) {
    out[key] = sanitizePreviewValue(key, rec[key])
  }
  if (keys.length > PREVIEW_FIELD_LIMIT) {
    out._omittedFields = keys.length - PREVIEW_FIELD_LIMIT
  }
  return out
}

interface PendingEntry {
  readonly request: StrongConfirmRequest
  readonly execToken?: symbol
  readonly resolve: (outcome: { readonly approved: boolean; readonly reason: string; readonly receiptId?: string }) => void
  readonly timer: ReturnType<typeof setTimeout>
  readonly cleanupAbort?: () => void
}

export class StrongConfirmBroker {
  private readonly pending = new Map<string, PendingEntry>()
  private readonly receiptStore: ApprovalReceiptStore
  private readonly timeoutMs: number

  constructor(receiptStore: ApprovalReceiptStore, timeoutMs = 10 * 60_000) {
    this.receiptStore = receiptStore
    this.timeoutMs = Math.max(500, timeoutMs)
  }

  request(input: {
    readonly execToken?: symbol
    readonly sessionId: string
    readonly callId: string
    readonly toolName: string
    readonly tier: 'red' | 'export-class'
    readonly untrustedOrigins: readonly TaintOrigin[]
    readonly argsDigest: string
    readonly args: unknown
    readonly reason: string
    readonly signal?: AbortSignal
  }): Promise<{ readonly approved: boolean; readonly reason: string; readonly receiptId?: string }> {
    if (input.signal?.aborted) {
      return Promise.resolve({ approved: false, reason: 'Strong confirmation cancelled before dispatch' })
    }

    const requestId = randomUUID()
    const now = Date.now()
    const req: StrongConfirmRequest = {
      requestId,
      sessionId: input.sessionId,
      callId: input.callId,
      toolName: input.toolName,
      tier: input.tier,
      untrustedOrigins: [...input.untrustedOrigins],
      argsDigest: input.argsDigest,
      preview: buildScrubbedConfirmPreview(input.args),
      reason: input.reason,
      allowRemember: false,
      allowRemoteTransport: false,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + this.timeoutMs).toISOString(),
    }

    return new Promise((resolve) => {
      const finish = (outcome: { readonly approved: boolean; readonly reason: string; readonly receiptId?: string }) => {
        const entry = this.pending.get(requestId)
        if (!entry) return
        this.pending.delete(requestId)
        clearTimeout(entry.timer)
        entry.cleanupAbort?.()
        resolve(outcome)
      }

      const timer = setTimeout(() => {
        finish({ approved: false, reason: 'Strong confirmation expired (fail-closed)' })
      }, this.timeoutMs)

      let cleanupAbort: (() => void) | undefined
      if (input.signal) {
        const onAbort = () => finish({ approved: false, reason: 'Strong confirmation aborted by caller signal' })
        input.signal.addEventListener('abort', onAbort, { once: true })
        cleanupAbort = () => input.signal?.removeEventListener('abort', onAbort)
      }

      this.pending.set(requestId, {
        request: req,
        execToken: input.execToken,
        resolve: finish,
        timer,
        cleanupAbort,
      })
    })
  }

  respond(input: StrongConfirmResponseInput): { readonly ok: boolean; readonly error?: string } {
    const entry = this.pending.get(input.requestId)
    if (!entry) {
      return { ok: false, error: 'CONFIRMATION_NOT_FOUND_OR_SETTLED' }
    }
    if (!/^[a-f0-9]{64}$/i.test(input.expectedDigest ?? '')) {
      return { ok: false, error: 'INVALID_EXPECTED_DIGEST_FORMAT' }
    }
    if (input.expectedDigest.toLowerCase() !== entry.request.argsDigest.toLowerCase()) {
      // Fail closed and reject stale/mismatched digest without minting receipt.
      entry.resolve({
        approved: false,
        reason: 'Strong confirmation digest mismatch (preview drifted from pending call)',
      })
      return { ok: false, error: 'DIGEST_MISMATCH' }
    }

    if (input.decision === 'approve') {
      const receipt = this.receiptStore.mint({
        execToken: entry.execToken,
        callId: entry.request.callId,
        sessionId: entry.request.sessionId,
        toolName: entry.request.toolName,
        argsDigest: entry.request.argsDigest,
        ttlMs: this.timeoutMs,
      })
      entry.resolve({
        approved: true,
        reason: input.reason ?? 'User explicitly approved strong confirmation with matching digest',
        receiptId: receipt.receiptId,
      })
      return { ok: true }
    }

    entry.resolve({
      approved: false,
      reason: input.reason ?? 'User rejected strong confirmation',
    })
    return { ok: true }
  }

  listPending(): readonly StrongConfirmRequest[] {
    return [...this.pending.values()].map((e) => e.request)
  }

  cancelAll(reason = 'Plugin disposed'): void {
    for (const entry of [...this.pending.values()]) {
      entry.resolve({ approved: false, reason })
    }
  }
}
