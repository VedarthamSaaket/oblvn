export function BtnSolid({ children, onClick, type = 'button', disabled, style = {} }) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      style={{
        fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.22em',
        textTransform: 'uppercase', color: 'var(--ink)', background: 'var(--cream)',
        padding: '12px 28px', boxShadow: '3px 3px 0 var(--sage)',
        transition: 'all .15s', opacity: disabled ? 0.4 : 1, cursor: disabled ? 'not-allowed' : 'crosshair',
        ...style,
      }}
    >
      {children}
    </button>
  )
}

export function BtnGhost({ children, onClick, type = 'button', disabled, style = {} }) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      style={{
        fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.2em',
        textTransform: 'uppercase', color: 'rgba(240,235,224,0.45)',
        borderBottom: '1px solid rgba(240,235,224,0.2)', paddingBottom: 2,
        transition: 'color .2s', opacity: disabled ? 0.4 : 1,
        cursor: disabled ? 'not-allowed' : 'crosshair', ...style,
      }}
    >
      {children}
    </button>
  )
}

export function BtnDanger({ children, onClick, type = 'button', disabled, style = {} }) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      style={{
        fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.22em',
        textTransform: 'uppercase', color: 'var(--cream)',
        background: 'rgba(196,74,66,0.7)', padding: '12px 28px',
        boxShadow: '3px 3px 0 rgba(196,74,66,0.3)',
        transition: 'all .15s', opacity: disabled ? 0.4 : 1,
        cursor: disabled ? 'not-allowed' : 'crosshair', ...style,
      }}
    >
      {children}
    </button>
  )
}
