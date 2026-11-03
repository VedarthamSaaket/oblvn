import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'
import SectionRule from '../components/SectionRule'
import { BtnGhost } from '../components/Btn'
import ArtworkPanel from '../components/ArtworkPanel'

export default function Anomalies() {
  const toast = useToast()
  const [anomalies, setAnomalies] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('open')
  const [ackNote, setAckNote] = useState({})

  useEffect(() => {
    api.anomalies.list({ status: filter === 'all' ? undefined : filter })
      .then(d => { setAnomalies(d.anomalies || []); setLoading(false) })
      .catch(() => setLoading(false))
  }, [filter])

  async function acknowledge(id, resolved) {
    try {
      await api.anomalies.acknowledge(id, { note: ackNote[id] || '', resolved })
      setAnomalies(prev => filter === 'open' ? prev.filter(a => a.id !== id) : prev.map(a => a.id === id ? { ...a, status: resolved ? 'resolved' : 'acknowledged' } : a))
      toast(resolved ? 'Anomaly resolved' : 'Anomaly acknowledged', 'success')
    } catch (err) { toast(err.message, 'error') }
  }

  async function label(a, feedback) {
    try {
      const updated = await api.anomalies.acknowledge(a.id, {
        note: ackNote[a.id] || '',
        resolved: a.status === 'resolved',
        feedback,
      })
      setAnomalies(prev => prev.map(x => x.id === a.id ? { ...x, ...updated, feedback } : x))
      toast(feedback === 'true_positive' ? 'Marked as a real threat' : 'Marked as a false alarm', 'success')
    } catch (err) { toast(err.message, 'error') }
  }

  const feedbackLabels = { true_positive: 'Real threat', false_positive: 'False alarm' }

  const severityColours = {
    critical: '#c44a42', high: 'rgba(196,144,26,0.9)',
    medium: 'var(--parchment)', low: 'rgba(240,235,224,0.4)',
  }

  const statuses = ['all', 'open', 'acknowledged', 'resolved']

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)' }}>
      <div style={{ padding: '52px', maxWidth: 1000 }}>
        <SectionRule label="Anomaly Detection" num="05" />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 48 }}>
          <h2 style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 'clamp(36px,5vw,56px)', lineHeight: 0.9, letterSpacing: '-0.02em' }}>
            Threat<br /><em style={{ color: 'rgba(240,235,224,0.5)' }}>Intelligence.</em>
          </h2>
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 40 }}>
          {statuses.map(s => (
            <button key={s} onClick={() => setFilter(s)} style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.2em', textTransform: 'uppercase', cursor: 'crosshair', padding: '7px 14px', border: `1px solid ${filter === s ? 'var(--parchment)' : 'rgba(240,235,224,0.1)'}`, color: filter === s ? 'var(--parchment)' : 'rgba(240,235,224,0.3)', background: filter === s ? 'rgba(196,180,138,0.08)' : 'transparent', transition: 'all 0.15s' }}>
              {s}
            </button>
          ))}
        </div>
        {loading ? (
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.3)' }}>Loading...</div>
        ) : anomalies.length === 0 ? (
          <div style={{ padding: '48px 0', fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.25)', letterSpacing: '0.18em', lineHeight: 1.9 }}>No anomalies found.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {anomalies.map(a => (
              <div key={a.id} style={{ padding: '24px', border: `1px solid ${severityColours[a.severity] || 'rgba(240,235,224,0.08)'}`, background: 'rgba(240,235,224,0.02)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                  <div>
                    <div style={{ fontFamily: 'var(--serif)', fontWeight: 700, fontSize: 16, color: 'var(--cream)', marginBottom: 4 }}>{a.anomaly_type?.replace(/_/g, ' ')}</div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'rgba(240,235,224,0.3)', letterSpacing: '0.1em' }}>{a.detected_at ? new Date(a.detected_at).toLocaleString() : ''}</div>
                  </div>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.2em', textTransform: 'uppercase', color: severityColours[a.severity], border: `1px solid ${severityColours[a.severity]}`, padding: '4px 10px' }}>{a.severity}</span>
                </div>
                {a.description && <div style={{ fontFamily: 'var(--sans)', fontWeight: 300, fontSize: 10, color: 'rgba(240,235,224,0.45)', lineHeight: 1.75, marginBottom: 16 }}>{a.description}</div>}
                {a.status === 'open' && (
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    <input type="text" placeholder="Optional note..." value={ackNote[a.id] || ''} onChange={e => setAckNote(prev => ({ ...prev, [a.id]: e.target.value }))} style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--cream)', background: 'rgba(240,235,224,0.04)', border: '1px solid rgba(240,235,224,0.1)', padding: '8px 12px', flex: 1, outline: 'none', cursor: 'crosshair' }} />
                    <BtnGhost onClick={() => acknowledge(a.id, false)}>Acknowledge</BtnGhost>
                    <BtnGhost onClick={() => acknowledge(a.id, true)}>Resolve</BtnGhost>
                  </div>
                )}
                {a.status !== 'open' && <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.14em', color: 'rgba(240,235,224,0.3)', textTransform: 'uppercase' }}>{a.status}{a.feedback ? ` · ${feedbackLabels[a.feedback]}` : ''}</div>}
                {!a.feedback && (
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginTop: 14, paddingTop: 14, borderTop: '1px solid rgba(240,235,224,0.06)' }}>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.14em', color: 'rgba(240,235,224,0.3)', textTransform: 'uppercase', flex: 1 }}>Was this a real threat?</span>
                    <BtnGhost onClick={() => label(a, 'true_positive')}>Real threat</BtnGhost>
                    <BtnGhost onClick={() => label(a, 'false_positive')}>False alarm</BtnGhost>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
      <ArtworkPanel />
    </div>
  )
}