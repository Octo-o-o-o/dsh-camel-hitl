/**
 * Official dsh@0.2.2-rc.5 Client entrypoint for `dsh-camel-hitl`.
 */
import { CamelPanel } from './CamelPanel.js'
import { StrongConfirmOverlay, type CamelRpcCaller } from './StrongConfirmOverlay.js'

interface LocaleApi {
  register(namespace: string, locale: string, dictionary: Record<string, string>): () => void
  bind(namespace: string): (key: string) => string
}

interface SlotsApi {
  inject(key: string, callback: () => unknown): () => void
  register(options: Record<string, unknown>, component: unknown): () => void
}

interface ConnectionClientApi {
  readonly rpc: {
    call<T = unknown>(
      channel: string,
      endpoint: string,
      payload?: unknown,
    ): Promise<{ ok: true; value: T } | { ok: false; error: { code: string; message: string } }>
  }
}

interface ClientContext {
  effect(run: () => void | (() => void), label?: string): void
  locale: LocaleApi
  slots: SlotsApi
  connection: ConnectionClientApi
}

const NS = 'dshCamelHitl'
const PANEL_ID = 'dsh-camel-hitl'

function CamelIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 1.5L13.5 3.8V8.2C13.5 11.5 11.1 14 8 14.8C4.9 14 2.5 11.5 2.5 8.2V3.8L8 1.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M8 5.2V8.8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="8" cy="11.2" r="0.9" fill="currentColor" />
    </svg>
  )
}

export const inject = ['slots', 'locale', 'layout', 'connection']

export function apply(ctx: ClientContext): void {
  ctx.effect(() => {
    const disposeZh = ctx.locale.register(NS, 'zh', {
      nav: 'CaMeL 强审批',
      title: 'CaMeL 污点追踪与强 HITL 守卫',
      subtitle: '持久化不可信来源追踪 · ctx.tools.guard() 单调守卫 · 参数摘要绑定强确认',
      'action.mode': '运行模式',
      'action.refresh': '刷新',
      'section.taint': '活跃会话污点来源（重启/fork 自动恢复）',
      'section.protected': '单调守卫敏感路径黑名单',
      'empty.taint': '当前没有已染色的活跃会话',
      'overlay.title': '高危操作强确认',
      'overlay.noRemember': '单次生效 · 不可记住',
      'overlay.localOnly': '仅限本机确认 · 禁远程审批',
      'overlay.expiresIn': '剩余',
      'overlay.reject': '拒绝执行',
      'overlay.approveOnce': '核对摘要并单次放行',
    })
    const disposeEn = ctx.locale.register(NS, 'en', {
      nav: 'CaMeL HITL',
      title: 'CaMeL Taint & Strong HITL Guard',
      subtitle: 'Persistent taint lineage · monotonic ctx.tools.guard() · digest-bound confirmations',
      'action.mode': 'Mode',
      'action.refresh': 'Refresh',
      'section.taint': 'Active Session Taint Lineage (Survives Restart & Fork)',
      'section.protected': 'Monotonic Guard Protected Path Rules',
      'empty.taint': 'No tainted active sessions',
      'overlay.title': 'Strong Confirmation Required',
      'overlay.noRemember': 'One-shot only · Non-rememberable',
      'overlay.localOnly': 'Local UI only · Remote IM disabled',
      'overlay.expiresIn': 'Expires in',
      'overlay.reject': 'Deny',
      'overlay.approveOnce': 'Verify Digest & Approve Once',
    })
    return () => {
      disposeZh()
      disposeEn()
    }
  }, 'dsh-camel-hitl: dictionaries')

  const t = ctx.locale.bind(NS)
  const rpc: CamelRpcCaller = {
    async call<T = any>(method: string, payload?: Record<string, unknown>): Promise<T> {
      const res = await ctx.connection.rpc.call<T>('/api', 'dshCamelHitl', {
        method,
        payload: payload ?? {},
      })
      if (!res.ok) throw new Error(res.error?.message ?? `RPC failed: ${method}`)
      return res.value
    },
  }

  // Register Strong Confirmation modal into list slot `shell.overlay` (zero slot collision!)
  ctx.slots.inject('shell.overlay', () => ctx.slots.register({
    name: 'shell.overlay',
    id: `${PANEL_ID}.strong-confirm`,
    locale: NS,
    inject: () => ({ rpc, t }),
  }, StrongConfirmOverlay))

  ctx.slots.inject('main', () => ctx.slots.register({
    name: 'main',
    key: PANEL_ID,
    locale: NS,
    inject: () => ({ rpc, t }),
  }, CamelPanel))

  ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({
    name: 'sidebar.panellist',
    id: PANEL_ID,
    order: 63,
    locale: NS,
    label: () => t('nav'),
  }, CamelIcon))
}
