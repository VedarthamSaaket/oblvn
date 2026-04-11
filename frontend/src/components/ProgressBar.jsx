export default function ProgressBar({ pct, label, pass, totalPasses }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.16em', color: 'rgba(240,235,224,0.5)' }}>
          {label}
        </span>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.16em', color: 'var(--parchment)' }}>
          {pct.toFixed(1)}%
        </span>
      </div>
      <div style={{ height: 3, background: 'rgba(240,235,224,0.08)', position: 'relative' }}>
        <div style={{
          height: '100%', width: `${pct}%`, background: 'var(--parchment)',
          transition: 'width 0.4s ease',
        }} />
      </div>
      {pass != null && (
        <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.2em', color: 'rgba(240,235,224,0.2)', marginTop: 6 }}>
          PASS {pass} OF {totalPasses}
        </div>
      )}
    </div>
  )
}
