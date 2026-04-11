import { useEffect, useState } from 'react'
import { api } from '../lib/api'

export default function RiskScore({ orgId }) {
  const [data, setData] = useState(null)

  useEffect(() => {
    api.anomalies.riskScore(orgId).then(setData).catch(() => {})
    const t = setInterval(() => {
      api.anomalies.riskScore(orgId).then(setData).catch(() => {})
    }, 30000)
    return () => clearInterval(t)
  }, [orgId])

  if (!data) return null

  return (
    <div style={{
      border: '1px solid rgba(240,235,224,0.1)',
      padding: '24px 28px',
      display: 'flex', alignItems: 'center', gap: 28,
    }}>
      <div style={{ position: 'relative', width: 72, height: 72, flexShrink: 0 }}>
        <svg width="72" height="72" viewBox="0 0 72 72">
          <circle cx="36" cy="36" r="30" fill="none" stroke="rgba(240,235,224,0.07)" strokeWidth="6" />
          <circle
            cx="36" cy="36" r="30"
            fill="none"
            stroke={data.colour}
            strokeWidth="6"
            strokeDasharray={`${(data.score / 100) * 188.5} 188.5`}
            strokeLinecap="round"
            transform="rotate(-90 36 36)"
            style={{ transition: 'stroke-dasharray 0.6s ease' }}
          />
        </svg>
        <span style={{
          position: 'absolute', top: '50%', left: '50%',
          transform: 'translate(-50%,-50%)',
          fontFamily: 'var(--serif)', fontStyle: 'italic', fontSize: 22,
          color: 'var(--cream)',
        }}>
          {data.score}
        </span>
      </div>
      <div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.3)', marginBottom: 6 }}>
          Risk Score
        </div>
        <div style={{ fontFamily: 'var(--serif)', fontSize: 18, color: data.colour, fontStyle: 'italic' }}>
          {data.level.toUpperCase()}
        </div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.14em', color: 'rgba(240,235,224,0.3)', marginTop: 4 }}>
          {data.open_count} open {data.open_count === 1 ? 'anomaly' : 'anomalies'}
        </div>
      </div>
    </div>
  )
}
