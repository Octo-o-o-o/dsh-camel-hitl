import { useEffect, useState } from 'react'
import css from './camel.module.css'
import type { StrongConfirmRequest } from './core/types.js'

export interface CamelRpcCaller {
  call<T = any>(method: string, payload?: Record<string, unknown>): Promise<T>
}

interface OverlayProps {
  readonly rpc: CamelRpcCaller
  readonly t: (key: string) => string
}

/**
 * Mounted into the multi-occupant `shell.overlay` list slot (never collides with
 * `conversation.approval.detail`). Displays non-rememberable Strong Confirmation
 * modals bound to `expectedDigest` SHA-256.
 */
export function StrongConfirmOverlay({ rpc, t }: OverlayProps) {
  const [pending, setPending] = useState<readonly StrongConfirmRequest[]>([])
  const [submitting, setSubmitting] = useState(false)
  const [nowMs, setNowMs] = useState(() => Date.now())

  useEffect(() => {
    let active = true
    const poll = async () => {
      try {
        const res = await rpc.call<{ pending: StrongConfirmRequest[] }>('listPending')
        if (active) setPending(res.pending)
      } catch {
        /* ignore transient disconnect */
      }
    }
    void poll()
    const id = setInterval(() => {
      if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
        setNowMs(Date.now())
      }
      void poll()
    }, 1500)
    return () => {
      active = false
      clearInterval(id)
    }
  }, [rpc])

  const current = pending[0]
  if (!current) return null

  const remainingSec = Math.max(0, Math.floor((Date.parse(current.expiresAt) - nowMs) / 1000))
  const expired = remainingSec <= 0

  const respond = async (decision: 'approve' | 'reject') => {
    if (submitting) return
    setSubmitting(true)
    try {
      await rpc.call('respondConfirm', {
        requestId: current.requestId,
        decision,
        expectedDigest: current.argsDigest,
      })
      const res = await rpc.call<{ pending: StrongConfirmRequest[] }>('listPending')
      setPending(res.pending)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className={css.overlayBackdrop} role="dialog" aria-modal="true" aria-label={t('overlay.title')}>
      <div className={css.modal}>
        <div className={css.modalHeader}>
          <h3 className={css.modalTitle}>{t('overlay.title')}: {current.toolName}</h3>
          <span className={css.badgeDanger}>{current.tier.toUpperCase()}</span>
        </div>

        <div className={css.badgeRow}>
          <span className={css.badgeDanger}>{t('overlay.noRemember')}</span>
          <span className={css.badgeDanger}>{t('overlay.localOnly')}</span>
          {current.untrustedOrigins.map((origin) => (
            <span key={origin} className={css.badgeWarn}>taint:{origin}</span>
          ))}
        </div>

        <p style={{ margin: 0, fontSize: 13 }}>{current.reason}</p>

        <div className={css.previewBox}>{JSON.stringify(current.preview, undefined, 2)}</div>

        <div className={css.digestLine}>
          SHA-256: {current.argsDigest} · {t('overlay.expiresIn')} {remainingSec}s
        </div>

        <div className={css.modalActions}>
          <button type="button" className={css.btn} disabled={submitting} onClick={() => void respond('reject')}>
            {t('overlay.reject')}
          </button>
          <button
            type="button"
            className={`${css.btn} ${css.btnDanger}`}
            disabled={submitting || expired}
            onClick={() => void respond('approve')}
          >
            {t('overlay.approveOnce')}
          </button>
        </div>
      </div>
    </div>
  )
}
