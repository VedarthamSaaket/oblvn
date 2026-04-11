import { createContext, useCallback, useContext, useState } from 'react'

const ToastCtx = createContext(null)

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const push = useCallback((msg, type = 'info') => {
    const id = Date.now()
    setToasts(t => [...t, { id, msg, type }])
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4500)
  }, [])

  const colours = { info: 'var(--sage)', error: 'rgba(196,74,66,0.8)', success: 'rgba(74,140,66,0.8)', warn: 'rgba(196,144,26,0.8)' }

  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div style={{ position: 'fixed', bottom: 40, right: 40, zIndex: 9999, display: 'flex', flexDirection: 'column', gap: 10 }}>
        {toasts.map(t => (
          <div key={t.id} style={{
            background: colours[t.type] || 'var(--sage)',
            color: 'var(--cream)', padding: '14px 22px', maxWidth: 360,
            fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.16em',
            boxShadow: '3px 3px 0 rgba(0,0,0,0.3)',
            animation: 'fadeIn 0.2s ease',
          }}>
            {t.msg}
          </div>
        ))}
      </div>
      <style>{`@keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }`}</style>
    </ToastCtx.Provider>
  )
}

export function useToast() {
  return useContext(ToastCtx)
}
