export default function SectionRule({ label, num, light = false }) {
  const c = light
    ? { txt: 'rgba(26,34,24,0.3)', line: 'rgba(26,34,24,0.1)', num: 'rgba(26,34,24,0.2)' }
    : { txt: 'rgba(240,235,224,0.22)', line: 'rgba(240,235,224,0.07)', num: 'rgba(240,235,224,0.18)' }
  return (
    <div style={{ display: 'flex', alignItems: 'center', marginBottom: 52 }}>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.28em',
        textTransform: 'uppercase', color: c.txt, paddingRight: 20, flexShrink: 0 }}>
        {label}
      </span>
      <span style={{ flex: 1, height: 1, background: c.line }} />
      <span style={{ fontFamily: 'var(--serif)', fontStyle: 'italic', fontSize: 18,
        color: c.num, paddingLeft: 20, flexShrink: 0 }}>
        {num}
      </span>
    </div>
  )
}
