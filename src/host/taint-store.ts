import type { TaintObservation, TaintOrigin } from '../core/types.js'

export const TAINT_SESSION_EVENT_TYPE = 'governance/taint-observed'

interface SessionLike {
  readonly id?: string
  readonly events?: readonly { readonly type?: string; readonly data?: unknown; readonly payload?: unknown }[]
  append?: (type: string, data: unknown) => unknown
}

interface SessionProjectionsLike {
  register?(unit: {
    readonly key: string
    readonly version: number
    initial(): TaintObservation[]
    reduce(state: TaintObservation[], event: { readonly type?: string; readonly data?: unknown }): TaintObservation[]
    project?(state: TaintObservation[]): readonly TaintObservation[]
  }): { stateOf?(session: unknown): readonly TaintObservation[]; dispose?(): void } | (() => void)
}

const VALID_ORIGINS = new Set<string>([
  'rag',
  'email_body',
  'url_fetch',
  'browser_page',
  'browser_screenshot',
  'mcp_tool_result',
  'office_document',
  'database_result',
  'delegated_agent',
  'inferred_from_tool',
])

function parseTaintObservation(raw: unknown): TaintObservation | null {
  if (!raw || typeof raw !== 'object') return null
  const r = raw as Record<string, unknown>
  if (typeof r.origin !== 'string' || !VALID_ORIGINS.has(r.origin)) return null
  if (typeof r.toolName !== 'string' || r.toolName.length === 0) return null
  return {
    origin: r.origin as TaintOrigin,
    toolName: r.toolName,
    ...(typeof r.callId === 'string' ? { callId: r.callId } : {}),
    observedAt: typeof r.observedAt === 'string' ? r.observedAt : new Date().toISOString(),
  }
}

/**
 * Durable session taint tracker:
 * - Writes `governance/taint-observed` log-only SessionEvents on untrusted tool completion
 * - Folds historical session logs via `ctx.sessionProjections` (or direct event replay)
 *   so session restart, resume, and fork NEVER erase untrusted taint state.
 */
export class PersistentTaintStore {
  private readonly cache = new Map<string, TaintObservation[]>()
  private projectionHandle: { stateOf?(session: unknown): readonly TaintObservation[]; dispose?(): void } | undefined
  private projectionDisposer: (() => void) | undefined

  attachProjections(sessionProjections: SessionProjectionsLike | undefined): void {
    if (!sessionProjections || typeof sessionProjections.register !== 'function') return
    try {
      const reg = sessionProjections.register({
        key: 'governanceTaint',
        version: 1,
        initial: () => [],
        reduce: (state, event) => {
          if (event?.type !== TAINT_SESSION_EVENT_TYPE) return state
          const parsed = parseTaintObservation(event.data)
          if (!parsed) return state
          return [...state, parsed]
        },
        project: (state) => state,
      })
      if (typeof reg === 'function') {
        this.projectionDisposer = reg
      } else if (reg && typeof reg === 'object') {
        this.projectionHandle = reg
        if (typeof reg.dispose === 'function') {
          this.projectionDisposer = () => reg.dispose!()
        }
      }
    } catch {
      /* optional host projection seam; falls back to direct event fold + cache */
    }
  }

  /** Rehydrate taint lineage from an existing or forked Session's durable event log. */
  hydrateFromSession(session: SessionLike | undefined): readonly TaintObservation[] {
    if (!session || typeof session.id !== 'string') return []

    // 1. Prefer official sessionProjections state when mounted
    if (this.projectionHandle && typeof this.projectionHandle.stateOf === 'function') {
      try {
        const projected = this.projectionHandle.stateOf(session)
        if (Array.isArray(projected) && projected.length > 0) {
          this.mergeIntoCache(session.id, projected)
          return this.cache.get(session.id) ?? []
        }
      } catch {
        /* fallback to direct event replay */
      }
    }

    // 2. Fallback: fold durable events directly from session.events (handles resume & fork seeds)
    if (Array.isArray(session.events)) {
      const replayed: TaintObservation[] = []
      for (const ev of session.events) {
        if (ev?.type !== TAINT_SESSION_EVENT_TYPE) continue
        const parsed = parseTaintObservation(ev.data ?? ev.payload)
        if (parsed) replayed.push(parsed)
      }
      if (replayed.length > 0) {
        this.mergeIntoCache(session.id, replayed)
      }
    }

    return this.cache.get(session.id) ?? []
  }

  observeEvent(sessionId: string, event: { readonly type?: string; readonly data?: unknown; readonly payload?: unknown }): void {
    if (event?.type !== TAINT_SESSION_EVENT_TYPE) return
    const parsed = parseTaintObservation(event.data ?? event.payload)
    if (!parsed) return
    this.mergeIntoCache(sessionId, [parsed])
  }

  record(
    sessionId: string,
    obs: Omit<TaintObservation, 'observedAt'>,
    session?: SessionLike,
  ): TaintObservation {
    const full: TaintObservation = {
      origin: obs.origin,
      toolName: obs.toolName,
      ...(obs.callId ? { callId: obs.callId } : {}),
      observedAt: new Date().toISOString(),
    }
    this.mergeIntoCache(sessionId, [full])
    if (session && typeof session.append === 'function') {
      try {
        session.append(TAINT_SESSION_EVENT_TYPE, full)
      } catch {
        /* outside open turn or read-only session: in-memory cache still preserves taint */
      }
    }
    return full
  }

  get(sessionId: string, session?: SessionLike): readonly TaintObservation[] {
    if (session) this.hydrateFromSession(session)
    return this.cache.get(sessionId) ?? []
  }

  snapshotAll(): Record<string, readonly TaintObservation[]> {
    const out: Record<string, readonly TaintObservation[]> = {}
    for (const [k, v] of this.cache.entries()) {
      out[k] = [...v]
    }
    return out
  }

  dispose(): void {
    try {
      this.projectionDisposer?.()
    } catch {
      /* ignore */
    }
    this.cache.clear()
  }

  private mergeIntoCache(sessionId: string, items: readonly TaintObservation[]): void {
    const existing = this.cache.get(sessionId) ?? []
    const seen = new Set(existing.map((e) => `${e.origin}|${e.toolName}|${e.callId ?? ''}|${e.observedAt}`))
    let mutated = false
    for (const item of items) {
      const key = `${item.origin}|${item.toolName}|${item.callId ?? ''}|${item.observedAt}`
      if (!seen.has(key)) {
        seen.add(key)
        existing.push(item)
        mutated = true
      }
    }
    if (mutated || !this.cache.has(sessionId)) {
      this.cache.set(sessionId, existing)
    }
  }
}
