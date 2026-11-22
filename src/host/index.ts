/**
 * Official dsh@0.2.2-rc.5 Host entrypoint for `dsh-camel-hitl`.
 *
 * Security invariants:
 * 1. Taint lineage is persisted via log-only `governance/taint-observed` SessionEvents +
 *    `sessionProjections` so app restart, resume, and session fork NEVER wipe taint.
 * 2. Hard security invariants (protected paths/vault + strong confirmation HMAC receipt verification)
 *    are enforced inside `ctx.tools.guard()` (DSH's monotonic guard that runs AFTER `tools/pre-execute`
 *    and `ctx.approval` and CANNOT be bypassed by a malicious `{ prepend: true }` waterfall listener).
 * 3. Layered HITL coexistence: `yellow × untrusted` returns standard `{ kind: 'ask' }` (compatible with
 *    native `ui-approval` and `@michengai/dsh-im-connect`); `red` and `export-class` use a dedicated
 *    non-rememberable local `shell.overlay` Strong Confirmation dialog (never collides with the
 *    single-occupant `conversation.approval.detail` slot).
 */
import { ApprovalReceiptStore, canonicalArgsSha256 } from '../core/canonical-digest.js'
import { classifyTool, evaluateTrifectaDecision } from '../core/policy-engine.js'
import { ProtectedPathMatcher } from '../core/protected-paths.js'
import { StrongConfirmBroker } from './strong-confirm-broker.js'
import { PersistentTaintStore } from './taint-store.js'
import type {
  CamelHitlConfig,
  CamelMode,
  GovernanceTaintService,
  StrongConfirmResponseInput,
  TaintObservation,
} from '../core/types.js'

export * from '../core/types.js'
export * from '../core/canonical-digest.js'
export * from '../core/protected-paths.js'
export * from '../core/policy-engine.js'
export { PersistentTaintStore, TAINT_SESSION_EVENT_TYPE } from './taint-store.js'
export { StrongConfirmBroker, buildScrubbedConfirmPreview } from './strong-confirm-broker.js'

interface OptionalAuditService {
  recordEvent?(input: Record<string, unknown>): unknown
}

interface ToolsServiceLike {
  guard?(fn: (exec: Record<string, unknown>) => string | { readonly reason: string; readonly info?: { name: string; code: string } } | undefined): () => void
}

interface OfficialHostConnection {
  readonly fetch: {
    register(route: {
      readonly path: string
      readonly methods: readonly ('GET' | 'HEAD' | 'POST')[]
      readonly requestBody: 'buffered' | 'streaming'
      readonly fetch: (request: Request) => Promise<Response>
    }): () => Promise<void> | void
  }
}

interface CordisLikeContext {
  get(key: string): unknown
  provide?(key: string, value: unknown): void
  inject?(deps: readonly string[], callback: (ctx: CordisLikeContext) => void): () => void
  on?(event: string, listener: (...args: any[]) => unknown, options?: { prepend?: boolean }): () => void
  effect?(run: () => void | (() => void | Promise<void>), label?: string): void
}

export const name = 'dsh-camel-hitl'

function resolveSession(exec: Record<string, unknown>): { id: string; raw?: any } {
  const agent = exec?.agent as { session?: { id?: string; events?: unknown[]; append?: (t: string, d: unknown) => unknown } } | undefined
  const sess = agent?.session
  if (sess && typeof sess.id === 'string') return { id: sess.id, raw: sess }
  if (typeof exec?.sessionId === 'string') return { id: exec.sessionId }
  return { id: 'default-session' }
}

export function apply(ctx: CordisLikeContext, config: CamelHitlConfig = {}): GovernanceTaintService {
  let mode: CamelMode = config.mode ?? 'enforce'
  const pathMatcher = new ProtectedPathMatcher(config.vaultPaths)
  const receiptStore = new ApprovalReceiptStore()
  const taintStore = new PersistentTaintStore()
  const broker = new StrongConfirmBroker(receiptStore, config.confirmTimeoutMs)

  taintStore.attachProjections(ctx.get('sessionProjections') as any)

  const recordAudit = (input: Record<string, unknown>) => {
    const audit = ctx.get('governanceAudit') as OptionalAuditService | undefined
    try {
      audit?.recordEvent?.(input)
    } catch {
      /* audit is optional and best-effort */
    }
  }

  const service: GovernanceTaintService = {
    getMode: () => mode,
    setMode: (next: CamelMode) => {
      mode = next
      recordAudit({
        stream: 'security',
        eventName: 'camel.mode_changed',
        actorType: 'user',
        actorId: 'local-owner',
        resourceType: 'camel_policy',
        outcome: 'success',
        payload: { mode: next },
      })
    },
    getSessionTaint: (sessionId: string) => taintStore.get(sessionId),
    recordTaint: (sessionId, obs, session) => taintStore.record(sessionId, obs, session),
    classifyTool: (toolName: string, args?: unknown) => classifyTool(toolName, args, config),
    checkProtectedPaths: (args: unknown) => pathMatcher.checkArguments(args),
    listPendingConfirmations: () => broker.listPending(),
    respondStrongConfirmation: (input: StrongConfirmResponseInput) => {
      const res = broker.respond(input)
      recordAudit({
        stream: 'security',
        eventName: res.ok
          ? input.decision === 'approve'
            ? 'camel.strong_confirm_approved'
            : 'camel.strong_confirm_rejected'
          : 'camel.strong_confirm_invalid',
        actorType: 'user',
        actorId: 'local-owner',
        resourceType: 'strong_confirmation',
        resourceId: input.requestId,
        outcome: res.ok ? (input.decision === 'approve' ? 'success' : 'denied') : 'failure',
        payload: { decision: input.decision, error: res.error ?? null },
      })
      return res
    },
    getProtectedRulesSummary: () => pathMatcher.getRulesSummary(),
  }

  if (typeof ctx.provide === 'function') {
    ctx.provide('governanceTaint', service)
  }

  const disposers: (() => void | Promise<void>)[] = []

  // 1. MONOTONIC GUARD (`ctx.tools.guard()`): CANNOT be bypassed by any `tools/pre-execute` waterfall listener!
  const attachToolsGuard = (toolsService: ToolsServiceLike, targetDisposers: (() => void | Promise<void>)[]) => {
    if (!toolsService || typeof toolsService.guard !== 'function') return
    targetDisposers.push(
      toolsService.guard((exec: Record<string, unknown>) => {
        const toolName = typeof exec?.name === 'string' ? exec.name : 'unknown_tool'
        const callId = typeof exec?.callId === 'string' ? exec.callId : 'unknown-call'
        const execToken = typeof exec?.token === 'symbol' ? exec.token : undefined
        const { id: sessionId, raw: session } = resolveSession(exec)

        // Hard Invariant A: Protected paths & Vault denylist (always enforced unless shadow)
        const pathCheck = pathMatcher.checkArguments(exec?.arguments)
        if (pathCheck.blocked) {
          recordAudit({
            stream: 'security',
            eventName: 'camel.protected_path_blocked',
            actorType: 'system',
            actorId: 'dsh-camel-hitl',
            resourceType: 'tool',
            resourceId: toolName,
            outcome: mode === 'enforce' ? 'denied' : 'observed',
            sessionId,
            severity: 'high',
            riskLevel: 'critical',
            payload: { matchedRule: pathCheck.matchedRule, mode },
          })
          if (mode === 'enforce') {
            return {
              reason: pathCheck.reason ?? 'Blocked by protected-path guard',
              info: { name: 'ProtectedPathDeniedError', code: 'PROTECTED_PATH_DENIED' },
            }
          }
        }

        // Hard Invariant B: Strong Confirmation receipt MUST exist and match canonicalArgsSha256
        const classification = classifyTool(toolName, exec?.arguments, config)
        const taint = taintStore.get(sessionId, session)
        const decision = evaluateTrifectaDecision({ classification, sessionTaint: taint, config })
        if (decision.action === 'strong_confirm') {
          if (mode === 'shadow') {
            recordAudit({
              stream: 'security',
              eventName: 'camel.shadow_strong_confirm',
              actorType: 'system',
              actorId: 'dsh-camel-hitl',
              resourceType: 'tool',
              resourceId: toolName,
              outcome: 'observed',
              sessionId,
              payload: { tier: decision.tier, origins: decision.untrustedOrigins },
            })
            return undefined
          }

          const argsDigest = canonicalArgsSha256(toolName, exec?.arguments)
          const verification = receiptStore.verifyAndConsume({
            execToken,
            callId,
            sessionId,
            toolName,
            argsDigest,
          })
          if (!verification.valid) {
            recordAudit({
              stream: 'security',
              eventName: 'camel.guard_denied_missing_receipt',
              actorType: 'system',
              actorId: 'dsh-camel-hitl',
              resourceType: 'tool',
              resourceId: toolName,
              outcome: 'denied',
              sessionId,
              severity: 'critical',
              riskLevel: 'critical',
              payload: { reason: verification.reason, tier: decision.tier, origins: decision.untrustedOrigins },
            })
            return {
              reason: `Monotonic guard blocked "${toolName}": ${verification.reason ?? 'missing valid strong-confirmation receipt'}`,
              info: { name: 'CamelGuardDeniedError', code: verification.reason ?? 'CAMEL_STRONG_CONFIRM_RECEIPT_MISSING' },
            }
          }
        }
        return undefined
      }),
    )
  }

  if (typeof ctx.inject === 'function') {
    ctx.inject(['tools'], (scope) => {
      const ts = scope.get('tools') as ToolsServiceLike | undefined
      if (!ts) return
      const localDisposers: (() => void | Promise<void>)[] = []
      attachToolsGuard(ts, localDisposers)
      scope.effect?.(() => async () => {
        for (const d of localDisposers) {
          try { await d() } catch { /* ignore */ }
        }
      }, 'dsh-camel-hitl: monotonic tools guard')
    })
  } else {
    const ts = ctx.get('tools') as ToolsServiceLike | undefined
    if (ts) attachToolsGuard(ts, disposers)
  }

  // 2. PRE-EXECUTE WATERFALL: routes yellow->standard ctx.approval, red/export-class->Strong Confirmation Overlay
  if (typeof ctx.on === 'function') {
    disposers.push(
      ctx.on('tools/pre-execute', async (exec: Record<string, unknown>, next: () => Promise<any>) => {
        const toolName = typeof exec?.name === 'string' ? exec.name : 'unknown_tool'
        const callId = typeof exec?.callId === 'string' ? exec.callId : 'unknown-call'
        const execToken = typeof exec?.token === 'symbol' ? exec.token : undefined
        const signal = exec?.signal as AbortSignal | undefined
        const { id: sessionId, raw: session } = resolveSession(exec)

        const pathCheck = pathMatcher.checkArguments(exec?.arguments)
        if (pathCheck.blocked && mode === 'enforce') {
          return {
            kind: 'deny',
            reason: pathCheck.reason ?? 'Blocked by protected path policy',
            info: { name: 'ProtectedPathDeniedError', code: 'PROTECTED_PATH_DENIED' },
          }
        }

        const classification = classifyTool(toolName, exec?.arguments, config)
        const taint = taintStore.get(sessionId, session)
        const decision = evaluateTrifectaDecision({ classification, sessionTaint: taint, config })

        if (mode === 'shadow') {
          if (decision.action !== 'allow') {
            recordAudit({
              stream: 'security',
              eventName: 'camel.shadow_observed',
              actorType: 'system',
              actorId: 'dsh-camel-hitl',
              resourceType: 'tool',
              resourceId: toolName,
              outcome: 'observed',
              sessionId,
              payload: { plannedAction: decision.action, tier: decision.tier, origins: decision.untrustedOrigins },
            })
          }
          return next()
        }

        if (decision.action === 'standard_ask') {
          const downstream = await next()
          if (downstream && downstream.kind !== 'allow') return downstream
          return {
            kind: 'ask',
            reason: decision.reason,
            displayReason: {
              en: decision.reason,
              zh: `工具「${toolName}」在接触不可信来源（${decision.untrustedOrigins.join('、')}）后发起变更，请确认是否单次放行。`,
            },
          }
        }

        if (decision.action === 'strong_confirm') {
          const argsDigest = canonicalArgsSha256(toolName, exec?.arguments)
          const outcome = await broker.request({
            execToken,
            sessionId,
            callId,
            toolName,
            tier: decision.tier as 'red' | 'export-class',
            untrustedOrigins: decision.untrustedOrigins,
            argsDigest,
            args: exec?.arguments,
            reason: decision.reason,
            signal,
          })
          if (!outcome.approved) {
            return {
              kind: 'deny',
              reason: `Strong confirmation denied for "${toolName}": ${outcome.reason}`,
              info: { name: 'CamelStrongConfirmDeniedError', code: 'CAMEL_STRONG_CONFIRM_DENIED' },
            }
          }
          // Let downstream pre-execute policies also inspect; monotonic guard will verify & burn the minted receipt.
          return next()
        }

        return next()
      }),
    )

    // 3. POST-EXECUTE WATERFALL: record untrusted tool outputs into persistent session taint
    disposers.push(
      ctx.on('tools/post-execute', async (exec: Record<string, unknown>, result: Record<string, unknown>, next: () => Promise<any>) => {
        if (!result?.isError) {
          const toolName = typeof exec?.name === 'string' ? exec.name : 'unknown_tool'
          const callId = typeof exec?.callId === 'string' ? exec.callId : undefined
          const { id: sessionId, raw: session } = resolveSession(exec)
          const classification = classifyTool(toolName, exec?.arguments, config)
          if (classification.untrustedOutput && classification.outputOrigin) {
            taintStore.record(
              sessionId,
              {
                origin: classification.outputOrigin,
                toolName,
                callId,
              },
              session,
            )
          }
        }
        return next()
      }),
    )

    // 4. Rehydrate taint when sessions are created/resumed/forked or events arrive
    disposers.push(
      ctx.on('session/created', (session: any) => {
        taintStore.hydrateFromSession(session)
      }),
    )
    disposers.push(
      ctx.on('session/event', (session: any, event: any) => {
        if (session?.id) taintStore.observeEvent(session.id, event)
      }),
    )
  }

  // 5. Authenticated RPC endpoint `/api/dshCamelHitl`
  const attachConnectionRoute = (connection: OfficialHostConnection, targetDisposers: (() => void | Promise<void>)[]) => {
    if (!connection?.fetch?.register) return
    targetDisposers.push(
      connection.fetch.register({
        path: '/api/dshCamelHitl',
        methods: ['POST'],
        requestBody: 'buffered',
        fetch: async (request) => {
          let body: any
          try {
            body = await request.json()
          } catch {
            return new Response('body is not JSON', { status: 400 })
          }
          const rpcId = typeof body?.rpcId === 'string' ? body.rpcId : '00000000-0000-0000-0000-000000000000'
          const envelope = (body?.payload ?? {}) as { method?: unknown; payload?: Record<string, any> }
          const method = typeof envelope.method === 'string' ? envelope.method : ''
          const p = (envelope.payload ?? {}) as Record<string, any>

          const dispatch = (): { ok: true; value: unknown } | { ok: false; error: { code: string; message: string; details: object } } => {
            try {
              switch (method) {
                case 'getState':
                  return {
                    ok: true,
                    value: {
                      mode,
                      pending: broker.listPending(),
                      taintBySession: taintStore.snapshotAll(),
                      protectedRules: pathMatcher.getRulesSummary(),
                    },
                  }
                case 'listPending':
                  return { ok: true, value: { pending: broker.listPending() } }
                case 'setMode':
                  if (p.mode !== 'enforce' && p.mode !== 'shadow') {
                    return { ok: false, error: { code: 'dsh-camel-hitl/invalid-mode', message: 'Mode must be enforce or shadow', details: {} } }
                  }
                  service.setMode(p.mode)
                  return { ok: true, value: { mode } }
                case 'respondConfirm': {
                  const res = service.respondStrongConfirmation({
                    requestId: String(p.requestId ?? ''),
                    decision: p.decision === 'approve' ? 'approve' : 'reject',
                    expectedDigest: String(p.expectedDigest ?? ''),
                    reason: typeof p.reason === 'string' ? p.reason : undefined,
                  })
                  return { ok: true, value: res }
                }
                default:
                  return { ok: false, error: { code: 'dsh-camel-hitl/not-found', message: `Unknown method: ${method}`, details: {} } }
              }
            } catch (error) {
              return {
                ok: false,
                error: { code: 'dsh-camel-hitl/error', message: error instanceof Error ? error.message : String(error), details: {} },
              }
            }
          }

          return Response.json({ type: 'server-response', rpcId, result: dispatch() })
        },
      }),
    )
  }

  if (typeof ctx.inject === 'function') {
    ctx.inject(['connection'], (scope) => {
      const conn = scope.get('connection') as OfficialHostConnection | undefined
      if (!conn) return
      const localDisposers: (() => void | Promise<void>)[] = []
      attachConnectionRoute(conn, localDisposers)
      scope.effect?.(() => async () => {
        for (const d of localDisposers) {
          try { await d() } catch { /* ignore */ }
        }
      }, 'dsh-camel-hitl: connection route')
    })
  } else {
    const conn = ctx.get('connection') as OfficialHostConnection | undefined
    if (conn) attachConnectionRoute(conn, disposers)
  }

  if (typeof ctx.effect === 'function') {
    ctx.effect(() => () => {
      broker.cancelAll('dsh-camel-hitl disposed')
      taintStore.dispose()
      for (const dispose of disposers) {
        try { void dispose() } catch { /* ignore */ }
      }
    }, 'dsh-camel-hitl: lifecycle')
  }

  return service
}
