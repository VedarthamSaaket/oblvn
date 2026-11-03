export default function GoogleButton({ onClick, loading }) {
  return (
    <button type="button" onClick={onClick} disabled={loading} style={{
      width: '100%', marginTop: 14, fontFamily: 'var(--mono)', fontSize: 9,
      letterSpacing: '0.22em', textTransform: 'uppercase',
      color: loading ? 'rgba(240,235,224,0.35)' : 'var(--cream)',
      background: 'transparent', border: '1px solid rgba(240,235,224,0.14)', padding: '14px 34px',
      cursor: loading ? 'wait' : 'crosshair', transition: 'border-color 0.2s, background 0.2s',
      display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12,
    }}
      onMouseEnter={e => { if (!loading) { e.currentTarget.style.borderColor = 'rgba(196,180,138,0.55)'; e.currentTarget.style.background = 'rgba(240,235,224,0.03)' } }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(240,235,224,0.14)'; e.currentTarget.style.background = 'transparent' }}
    >
      <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
        <path d="M21.35 11.1H12v2.98h5.35c-.23 1.48-1.68 4.34-5.35 4.34-3.22 0-5.85-2.67-5.85-5.96S8.78 6.5 12 6.5c1.83 0 3.06.78 3.76 1.45l2.56-2.47C16.68 3.94 14.55 3 12 3 6.98 3 2.92 7.03 2.92 12S6.98 21 12 21c5.24 0 8.71-3.68 8.71-8.86 0-.6-.06-1.05-.15-1.5z" />
      </svg>
      {loading ? 'Opening Google…' : 'Continue with Google'}
    </button>
  )
}
