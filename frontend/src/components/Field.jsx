export function Field({ label, value, mono = true }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <span style={{
        display: 'block', fontFamily: 'var(--mono)', fontSize: 7,
        letterSpacing: '0.3em', textTransform: 'uppercase',
        color: 'rgba(240,235,224,0.25)', marginBottom: 4,
      }}>
        {label}
      </span>
      <span style={{
        fontFamily: mono ? 'var(--mono)' : 'var(--sans)',
        fontSize: 11, color: 'var(--cream)', letterSpacing: '0.04em',
        wordBreak: 'break-all',
      }}>
        {value ?? 'N/A'}
      </span>
    </div>
  )
}

export function Input({ label, type = 'text', value, onChange, placeholder, required }) {
  return (
    <div style={{ marginBottom: 20 }}>
      {label && (
        <label style={{
          display: 'block', fontFamily: 'var(--mono)', fontSize: 7,
          letterSpacing: '0.28em', textTransform: 'uppercase',
          color: 'rgba(240,235,224,0.3)', marginBottom: 6,
        }}>
          {label}
        </label>
      )}
      <input
        type={type}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        required={required}
        style={{
          width: '100%', fontFamily: 'var(--mono)', fontSize: 11,
          color: 'var(--cream)', background: 'rgba(240,235,224,0.04)',
          border: '1px solid rgba(240,235,224,0.12)', padding: '10px 14px',
          letterSpacing: '0.04em',
        }}
      />
    </div>
  )
}

export function Select({ label, value, onChange, options }) {
  return (
    <div style={{ marginBottom: 20 }}>
      {label && (
        <label style={{
          display: 'block', fontFamily: 'var(--mono)', fontSize: 7,
          letterSpacing: '0.28em', textTransform: 'uppercase',
          color: 'rgba(240,235,224,0.3)', marginBottom: 6,
        }}>
          {label}
        </label>
      )}
      <select
        value={value}
        onChange={onChange}
        style={{
          width: '100%', fontFamily: 'var(--mono)', fontSize: 11,
          color: 'var(--cream)', background: 'var(--ink-mid)',
          border: '1px solid rgba(240,235,224,0.12)', padding: '10px 14px',
          letterSpacing: '0.04em',
        }}
      >
        {options.map(o => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  )
}

export function Textarea({ label, value, onChange, rows = 4, placeholder }) {
  return (
    <div style={{ marginBottom: 20 }}>
      {label && (
        <label style={{
          display: 'block', fontFamily: 'var(--mono)', fontSize: 7,
          letterSpacing: '0.28em', textTransform: 'uppercase',
          color: 'rgba(240,235,224,0.3)', marginBottom: 6,
        }}>
          {label}
        </label>
      )}
      <textarea
        value={value}
        onChange={onChange}
        rows={rows}
        placeholder={placeholder}
        style={{
          width: '100%', fontFamily: 'var(--mono)', fontSize: 10,
          color: 'var(--cream)', background: 'rgba(240,235,224,0.04)',
          border: '1px solid rgba(240,235,224,0.12)', padding: '10px 14px',
          letterSpacing: '0.04em', resize: 'vertical',
        }}
      />
    </div>
  )
}
