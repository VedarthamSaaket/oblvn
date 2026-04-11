import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'
import SectionRule from '../components/SectionRule'
import { BtnSolid, BtnGhost } from '../components/Btn'
import ArtworkPanel from '../components/ArtworkPanel'

export default function AuditLog() {
  const toast = useToast()
  const [entries, setEntries] = useState([])
  const [loading, setLoading] = useState(true)
  const [chainResult, setChainResult] = useState(null)
  const [exporting, setExporting] = useState(false)
  const [start, setStart] = useState('')
  const [end, setEnd] = useState('')

  function load() {
    setLoading(true)
    const params = {}
    if (start) params.start = start
    if (end) params.end = end
    api.audit.list(params)
      .then(d => { setEntries(d.entries || []); setLoading(false) })
      .catch(() => setLoading(false))
  }

  useEffect(load, [])

  async function verifyChain() {
    try {
      const r = await api.audit.verify()
      setChainResult(r)
    } catch (err) { toast(err.message, 'error') }
  }

  async function exportLog(fmt) {
    setExporting(true)
    try {
      const params = { format: fmt }
      if (start) params.start = start
      if (end) params.end = end

      // FIX: api.audit.export ALREADY returns the blob! 
      // Do not call .blob() on it again.
      const blob = await api.audit.export(params)

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `oblvn-audit.${fmt}`
      document.body.appendChild(a)
      a.click()

      a.remove()
      URL.revokeObjectURL(url)
    } catch (err) {
      toast(err.message, 'error')
    } finally {
      setExporting(false)
    }
  }

  const severityColours = {
    critical: '#c44a42', high: 'rgba(196,144,26,0.9)',
    medium: 'var(--parchment)', low: 'rgba(240,235,224,0.4)',
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)' }}>
      <div style={{ padding: '52px', maxWidth: 1000 }}>
        <SectionRule label="Audit Log" num="04" />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 48 }}>
          <h2 style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 'clamp(36px,5vw,56px)', lineHeight: 0.9, letterSpacing: '-0.02em' }}>
            Immutable<br /><em style={{ color: 'rgba(240,235,224,0.5)' }}>Record.</em>
          </h2>
          <div style={{ display: 'flex', gap: 12 }}>
            <BtnGhost onClick={verifyChain}>Verify Chain</BtnGhost>
            <BtnGhost onClick={() => exportLog('csv')} disabled={exporting}>CSV</BtnGhost>
            <BtnGhost onClick={() => exportLog('json')} disabled={exporting}>JSON</BtnGhost>
            <BtnSolid onClick={() => exportLog('pdf')} disabled={exporting}>Export PDF</BtnSolid>
          </div>
        </div>
        {chainResult && (
          <div style={{ padding: '16px 20px', marginBottom: 32, border: `1px solid ${chainResult.intact ? 'rgba(74,140,66,0.4)' : 'rgba(196,74,66,0.4)'}`, fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.14em', color: chainResult.intact ? '#6ab87a' : '#c44a42' }}>
            Chain integrity: {chainResult.intact ? 'INTACT' : `BROKEN at entry ${chainResult.broken_at_entry}`} Total entries: {chainResult.total_entries}
          </div>
        )}
        <div style={{ display: 'flex', gap: 16, marginBottom: 32, alignItems: 'flex-end' }}>
          <div>
            <label style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.3)', marginBottom: 6 }}>Start Date</label>
            <input type="datetime-local" value={start} onChange={e => setStart(e.target.value)} style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--cream)', background: 'rgba(240,235,224,0.04)', border: '1px solid rgba(240,235,224,0.12)', padding: '8px 12px', cursor: 'crosshair' }} />
          </div>
          <div>
            <label style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.3)', marginBottom: 6 }}>End Date</label>
            <input type="datetime-local" value={end} onChange={e => setEnd(e.target.value)} style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--cream)', background: 'rgba(240,235,224,0.04)', border: '1px solid rgba(240,235,224,0.12)', padding: '8px 12px', cursor: 'crosshair' }} />
          </div>
          <BtnGhost onClick={load}>Filter</BtnGhost>
        </div>
        {loading ? (
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.3)' }}>Loading...</div>
        ) : entries.length === 0 ? (
          <div style={{ padding: '48px 0', fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.25)', letterSpacing: '0.18em' }}>No audit entries found.</div>
        ) : (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: '60px 160px 1fr 80px 120px', gap: 12, paddingBottom: 10, borderBottom: '1px solid rgba(240,235,224,0.08)' }}>
              {['ID', 'Event', 'User', 'Anomaly', 'Time'].map(h => (
                <span key={h} style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.24em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.2)' }}>{h}</span>
              ))}
            </div>
            {entries.map(e => (
              <div key={e.id} style={{ display: 'grid', gridTemplateColumns: '60px 160px 1fr 80px 120px', gap: 12, padding: '12px 0', borderBottom: '1px solid rgba(240,235,224,0.04)', alignItems: 'start' }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'rgba(240,235,224,0.25)' }}>{e.id}</span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 8, color: e.is_anomaly ? '#c44a42' : 'rgba(240,235,224,0.6)' }}>{e.event_type}</span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'rgba(240,235,224,0.3)', wordBreak: 'break-all' }}>{e.user_id?.slice(0, 16)}...</span>
                {e.anomaly_severity ? <span style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.14em', textTransform: 'uppercase', color: severityColours[e.anomaly_severity] }}>{e.anomaly_severity}</span> : <span />}
                <span style={{ fontFamily: 'var(--mono)', fontSize: 7, color: 'rgba(240,235,224,0.2)' }}>{e.created_at ? new Date(e.created_at).toLocaleDateString() : ''}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      <ArtworkPanel />
    </div>
  )
}