import type { TaintObservation, TaintOrigin } from '../core/types.js'

/**
 * Official DSH ignorable plugin record type (`plugin:<pkg>/<event>`).
 * Using `@deepseek-ai/dsh-session`'s `appendPluginRecord()` sets `ignorable: true`
 * so DSH session persistence ALWAYS resumes & forks sessions cleanly.
 */
export const TAINT_SESSION_EVENT_TYPE = 'plugin:dsh-camel-hitl/taint-observed'
const LEGACY_TAINT_EVENT_TYPE = 'governance/taint-observed'

interface SessionEventLike {
  readonly type?: string
  readonly data?: unknown
  readonly payload?: unknown
}

interface SessionLike {
  readonly id?: string
  readonly events?: readonly SessionEventLike[]
  snapshotEvents?: () => readonly SessionEventLike[]
  append?: (type: string, data: unknown) => unknown
}

type AppendPluginRecordFn = (session: unknown, type: string, data: unknown) => unknown

let cachedAppendPluginRecord: AppendPluginRecordFn | null | undefined

async function resolveAppendPluginRecord(): Promise<AppendPluginRecordFn | null> {
  if (cachedAppendPluginRecord !== undefined) return cachedAppendPluginRecord
  try {
    // Resolved via DSH runtime module resolution when hosted inside dsh@0.2.2-rc.5
    const specifier = '@deepseek-ai/dsh-session'
    const mod = (await import(specifier)) as { appendPluginRecord?: AppendPluginRecordFn }
    cachedAppendPluginRecord = typeof mod.appendPluginRecord === 'function' ? mod.appendPluginRecord : null
  } catch {
    cachedAppendPluginRecord = null
  }
  return cachedAppendPluginRecord
}

// Kick off eager non-blocking lookup so synchronous `record()` has it immediately after host boot
void resolveAppendPluginRecord()

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

function isTaintEventType(type: unknown): boolean {
  return type === TAINT_SESSION_EVENT_TYPE || type === LEGACY_TAINT_EVENT_TYPE
}

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

function readSessionEvents(session: SessionLike): readonly SessionEventLike[] {
  if (typeof session.snapshotEvents === 'function') {
    try {
      const snap = session.snapshotEvents()
      if (Array.isArray(snap)) return snap
    } catch {
      /* fallback below */
    }
  }
  return Array.isArray(session.events) ? session.events : []
}

/**
 * Durable session taint tracker:
 * - Writes `plugin:dsh-camel-hitl/taint-observed` ignorable plugin records via
 *   `appendPluginRecord()` when running inside real `dsh@0.2.2-rc.5` (falling back
 *   to `session.append()` in standalone mocks).
 * - Rehydrates taint from `session.snapshotEvents()` (real DSH) or `session.events`
 *   on `session/created`, `session/event`, and before policy evaluation so app
 *   restart, resume, and session fork NEVER erase untrusted taint state.
 */
export class PersistentTaintStore {
  private readonly cache = new Map<string, TaintObservation[]>()

  attachProjections(_sessionProjections: unknown): void {
    // Real DSH sessionProjections requires a Zod stateSchema; we deliberately keep
    // zero runtime schema dependency and fold durably from `session.snapshotEvents()`
    // + `session/created` + `session/event` on official ignorable `plugin:` records.
  }

  /** Rehydrate taint lineage from an existing, resumed, or forked Session's durable log. */
  hydrateFromSession(session: SessionLike | undefined): readonly TaintObservation[] {
    if (!session || typeof session.id !== 'string') return []

    const events = readSessionEvents(session)
    if (events.length > 0) {
      const replayed: TaintObservation[] = []
      for (const ev of events) {
        if (!isTaintEventType(ev?.type)) continue
        const parsed = parseTaintObservation(ev.data ?? ev.payload)
        if (parsed) replayed.push(parsed)
      }
      if (replayed.length > 0) {
        this.mergeIntoCache(session.id, replayed)
      }
    }

    return this.cache.get(session.id) ?? []
  }

  observeEvent(sessionId: string, event: SessionEventLike): void {
    if (!isTaintEventType(event?.type)) return
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

    if (session) {
      // Real DSH Session: MUST use `appendPluginRecord` so `ignorable: true` is set!
      if (typeof session.snapshotEvents === 'function') {
        if (typeof cachedAppendPluginRecord === 'function') {
          try {
            cachedAppendPluginRecord(session, TAINT_SESSION_EVENT_TYPE, full)
          } catch {
            /* detached/read-only session: in-memory cache still preserves taint */
          }
        } else {
          void resolveAppendPluginRecord().then((fn) => {
            if (!fn) return
            try {
              fn(session, TAINT_SESSION_EVENT_TYPE, full)
            } catch {
              /* ignore */
            }
          })
        }
      } else if (typeof session.append === 'function') {
        // Standalone test mock session
        try {
          session.append(TAINT_SESSION_EVENT_TYPE, full)
        } catch {
          /* ignore */
        }
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
