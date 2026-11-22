import { useCallback, useEffect, useState } from 'react'
import css from './camel.module.css'
import type { CamelRpcCaller } from './StrongConfirmOverlay.js'
import type { CamelMode, StrongConfirmRequest, TaintObservation } from './core/types.js'

interface CamelState {
  readonly mode: CamelMode
  readonly pending: readonly StrongConfirmRequest[]
  readonly taintBySession: Record<string, readonly TaintObservation[]>
  readonly protectedRules: readonly string[]
}

export function CamelPanel({ rpc, t }: { readonly rpc: CamelRpcCaller; readonly t: (key: string) => string }) {
  const [state, setState] = useState<CamelState | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    setBusy(true)
    try {
      const next = await rpc.call<CamelState>('getState')
      setState(next)
    } finally {
      setBusy(false)
    }
  }, [rpc])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const toggleMode = async () => {
    if (!state) return
    const nextMode: CamelMode = state.mode === 'enforce' ? 'shadow' : 'enforce'
    await rpc.call('setMode', { mode: nextMode })
    await refresh()
  }

  return (
    <div className={css.panelRoot}>
      <div className={css.header}>
        <div>
          <h2 style={{ margin: 0, fontSize: 18 }}>{t('title')}</h2>
          <p style={{ margin: '4px 0 0', fontSize: 12, opacity: 0.72 }}>{t('subtitle')}</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button type="button" className={css.btn} disabled={busy || !state} onClick={() => void toggleMode()}>
            {t('action.mode')}: {state?.mode ?? '…'}
          </button>
          <button type="button" className={css.btn} disabled={busy} onClick={() => void refresh()}>
            {t('action.refresh')}
          </button>
        </div>
      </div>

      <div className={css.card}>
        <strong>{t('section.taint')}</strong>
        {state && Object.keys(state.taintBySession).length > 0 ? (
          <ul className={css.list}>
            {Object.entries(state.taintBySession).map(([sid, list]) => (
              <li key={sid}>
                <span className={css.mono}>{sid}</span>:{' '}
                {[...new Set(list.map((i) => `${i.origin}(${i.toolName})`))].join(', ')}
              </li>
            ))}
          </ul>
        ) : (
          <p style={{ fontSize: 12, opacity: 0.7 }}>{t('empty.taint')}</p>
        )}
      </div>

      <div className={css.card}>
        <strong>{t('section.protected')}</strong>
        <ul className={css.list}>
          {(state?.protectedRules ?? []).map((rule) => (
            <li key={rule} className={css.mono}>{rule}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}
