import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

export function stableJsonStringify(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  const t = typeof value
  if (t === 'boolean') return value ? 'true' : 'false'
  if (t === 'number') return Number.isFinite(value as number) ? JSON.stringify(value) : 'null'
  if (t === 'bigint') return JSON.stringify((value as bigint).toString())
  if (t === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) {
    return `[${value.map((v) => (v === undefined || typeof v === 'function' ? 'null' : stableJsonStringify(v))).join(',')}]`
  }
  if (t === 'object') {
    const rec = value as Record<string, unknown>
    const pairs: string[] = []
    for (const k of Object.keys(rec).sort()) {
      const v = rec[k]
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue
      pairs.push(`${JSON.stringify(k)}:${stableJsonStringify(v)}`)
    }
    return `{${pairs.join(',')}}`
  }
  return 'null'
}

export function canonicalArgsSha256(toolName: string, args: unknown): string {
  const material = stableJsonStringify({ toolName, args: args ?? null })
  return createHash('sha256').update(material, 'utf8').digest('hex')
}

export interface SignedReceiptRecord {
  readonly receiptId: string
  readonly callId: string
  readonly sessionId: string
  readonly toolName: string
  readonly argsDigest: string
  readonly expiresAtMs: number
  readonly macHex: string
}

/**
 * In-process ephemeral HMAC-signed single-use approval receipt store.
 * - Uses a process-random 32-byte key (receipts never survive restart and cannot be forged).
 * - Bound to exact (execToken OR callId) + sessionId + toolName + canonicalArgsSha256.
 * - Atomically consumed on first verification inside `ctx.tools.guard()`.
 */
export class ApprovalReceiptStore {
  private readonly processKey: Buffer = randomBytes(32)
  private readonly byToken = new WeakMap<symbol, SignedReceiptRecord>()
  private readonly byCallId = new Map<string, SignedReceiptRecord>()

  private sign(fields: {
    readonly receiptId: string
    readonly callId: string
    readonly sessionId: string
    readonly toolName: string
    readonly argsDigest: string
    readonly expiresAtMs: number
  }): string {
    return createHmac('sha256', this.processKey).update(stableJsonStringify(fields), 'utf8').digest('hex')
  }

  mint(input: {
    readonly execToken?: symbol
    readonly callId: string
    readonly sessionId: string
    readonly toolName: string
    readonly argsDigest: string
    readonly ttlMs?: number
  }): SignedReceiptRecord {
    const receiptId = randomBytes(16).toString('hex')
    const expiresAtMs = Date.now() + Math.max(1000, input.ttlMs ?? 10 * 60_000)
    const macHex = this.sign({
      receiptId,
      callId: input.callId,
      sessionId: input.sessionId,
      toolName: input.toolName,
      argsDigest: input.argsDigest,
      expiresAtMs,
    })
    const record: SignedReceiptRecord = {
      receiptId,
      callId: input.callId,
      sessionId: input.sessionId,
      toolName: input.toolName,
      argsDigest: input.argsDigest,
      expiresAtMs,
      macHex,
    }
    if (input.execToken) {
      this.byToken.set(input.execToken, record)
    }
    this.byCallId.set(input.callId, record)
    return record
  }

  /**
   * Verify MAC, expiry, and exact (sessionId, toolName, argsDigest) binding,
   * then atomically burn the receipt so it can NEVER be replayed.
   */
  verifyAndConsume(input: {
    readonly execToken?: symbol
    readonly callId: string
    readonly sessionId: string
    readonly toolName: string
    readonly argsDigest: string
  }): { readonly valid: boolean; readonly reason?: string; readonly receiptId?: string } {
    const record = (input.execToken ? this.byToken.get(input.execToken) : undefined) ?? this.byCallId.get(input.callId)
    if (!record) {
      return { valid: false, reason: 'CAMEL_STRONG_CONFIRM_RECEIPT_MISSING' }
    }
    // Burn immediately on lookup attempt to guarantee single-use semantics.
    if (input.execToken) this.byToken.delete(input.execToken)
    this.byCallId.delete(input.callId)

    if (Date.now() > record.expiresAtMs) {
      return { valid: false, reason: 'CAMEL_STRONG_CONFIRM_RECEIPT_EXPIRED' }
    }
    if (
      record.callId !== input.callId ||
      record.sessionId !== input.sessionId ||
      record.toolName !== input.toolName ||
      record.argsDigest !== input.argsDigest
    ) {
      return { valid: false, reason: 'CAMEL_STRONG_CONFIRM_DIGEST_MISMATCH' }
    }
    const expectedMac = this.sign({
      receiptId: record.receiptId,
      callId: record.callId,
      sessionId: record.sessionId,
      toolName: record.toolName,
      argsDigest: record.argsDigest,
      expiresAtMs: record.expiresAtMs,
    })
    const a = Buffer.from(record.macHex, 'hex')
    const b = Buffer.from(expectedMac, 'hex')
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return { valid: false, reason: 'CAMEL_STRONG_CONFIRM_MAC_INVALID' }
    }
    return { valid: true, receiptId: record.receiptId }
  }
}
