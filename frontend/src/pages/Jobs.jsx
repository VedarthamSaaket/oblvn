import { useEffect, useState, useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import SectionRule from '../components/SectionRule'
import ArtworkPanel from '../components/ArtworkPanel'

const STATUS_COLOURS = {
  completed: 'var(--parchment)',
  running: '#6ab87a',
  failed: '#c44a42',
  queued: 'rgba(240,235,224,0.5)',
  pending_approval: 'rgba(196,144,26,0.9)',
  cancelled: 'rgba(240,235,224,0.2)',
}

const STATUS_BG = {
  completed: 'rgba(196,180,138,0.06)',
  running: 'rgba(106,184,122,0.04)',
  failed: 'rgba(196,74,66,0.04)',
}

const STATUSES = ['all', 'running', 'pending_approval', 'queued', 'completed', 'failed', 'cancelled']

export default function Jobs() {
  const navigate = useNavigate()
  const [jobs, setJobs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    api.jobs.list()
      .then(d => { setJobs(d.jobs || []); setLoading(false) })
      .catch((err) => { console.error("Failed to fetch jobs:", err); setError("Failed to load wipe history."); setLoading(false) })
  }, [])

  const counts = useMemo(() => {
    const acc = { all: jobs.length }
    STATUSES.forEach(s => { if (s !== 'all') acc[s] = 0 })
    jobs.forEach(j => { if (acc[j.status] !== undefined) acc[j.status]++ })
    return acc
  }, [jobs])

  const filtered = useMemo(() => {
    return filter === 'all' ? jobs : jobs.filter(j => j.status === filter)
  }, [jobs, filter])

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)' }}>
      <div style={{ padding: '52px', maxWidth: 1000 }}>
        <SectionRule label="Wipe Jobs" num="02" />
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 40, alignItems: 'flex-end', marginBottom: 48 }}>
          <div>
            <h2 style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 'clamp(36px,5vw,56px)', lineHeight: 0.9, letterSpacing: '-0.02em', marginBottom: 16 }}>
              Obliteration<br /><em style={{ color: 'rgba(240,235,224,0.5)' }}>History.</em>
            </h2>
            <p style={{ fontFamily: 'var(--sans)', fontWeight: 300, fontSize: 10.5, color: 'rgba(240,235,224,0.35)', lineHeight: 1.8, maxWidth: 400 }}>
              every wipe job is logged, chained, and certificate-anchored to the Bitcoin blockchain.
            </p>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, alignItems: 'flex-end' }}>
            <button
              onClick={() => navigate('/devices')}
              style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.22em', textTransform: 'uppercase', color: 'var(--ink)', background: 'var(--cream)', border: 'none', padding: '14px 28px', cursor: 'crosshair', boxShadow: '3px 3px 0 var(--sage)', transition: 'all 0.15s', whiteSpace: 'nowrap' }}
              onMouseEnter={e => { e.currentTarget.style.transform = 'translate(-2px,-2px)'; e.currentTarget.style.boxShadow = '5px 5px 0 var(--sage)' }}
              onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = '3px 3px 0 var(--sage)' }}
            >
              New Wipe Job
            </button>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 7.5, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.22)' }}>
              {jobs.length} total jobs
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 40, flexWrap: 'wrap', padding: '18px', background: 'rgba(240,235,224,0.02)', border: '1px solid rgba(240,235,224,0.06)' }}>
          {STATUSES.map(s => (
            <button key={s} onClick={() => setFilter(s)} style={{ fontFamily: 'var(--mono)', fontSize: 7.5, letterSpacing: '0.18em', textTransform: 'uppercase', cursor: 'crosshair', padding: '7px 14px', border: `1px solid ${filter === s ? 'var(--parchment)' : 'rgba(240,235,224,0.1)'}`, color: filter === s ? 'var(--parchment)' : 'rgba(240,235,224,0.3)', background: filter === s ? 'rgba(196,180,138,0.08)' : 'transparent', transition: 'all 0.15s', display: 'flex', alignItems: 'center', gap: 8 }}>
              {s.replace(/_/g, ' ')}
              {counts[s] > 0 && <span style={{ fontFamily: 'var(--mono)', fontSize: 7, color: filter === s ? 'var(--parchment)' : 'rgba(240,235,224,0.2)' }}>{counts[s]}</span>}
            </button>
          ))}
        </div>

        {loading ? (
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.3)', letterSpacing: '0.2em' }}>Loading...</div>
        ) : error ? (
          <div style={{ padding: '48px 24px', border: '1px solid #c44a42', color: '#c44a42', fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.18em', textAlign: 'center' }}>{error}</div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: '48px 24px', border: '1px solid rgba(240,235,224,0.06)', fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.25)', letterSpacing: '0.18em', textAlign: 'center' }}>No jobs found.</div>
        ) : (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 130px 130px 110px 70px', gap: 16, paddingBottom: 12, borderBottom: '1px solid rgba(240,235,224,0.08)', marginBottom: 4 }}>
              {['Device', 'Method', 'Standard', 'Status', ''].map(h => (
                <span key={h} style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.26em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.18)' }}>{h}</span>
              ))}
            </div>
            {filtered.map(j => (
              <div key={j.id} style={{ display: 'grid', gridTemplateColumns: '1fr 130px 130px 110px 70px', gap: 16, padding: '14px 0', borderBottom: '1px solid rgba(240,235,224,0.04)', alignItems: 'center', background: STATUS_BG[j.status] || 'transparent' }}>
                <div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--cream)' }}>{j.device_model || 'Unknown Device'}</div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'rgba(240,235,224,0.28)', marginTop: 2 }}>{j.device_serial || 'N/A'}</div>
                </div>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'rgba(240,235,224,0.38)' }}>{j.method?.replace(/_/g, ' ')}</span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'rgba(240,235,224,0.28)' }}>{j.standard?.replace(/_/g, ' ').toUpperCase()}</span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 8, textTransform: 'uppercase', letterSpacing: '0.12em', color: STATUS_COLOURS[j.status] }}>{j.status?.replace(/_/g, ' ')}</span>
                <Link to={`/jobs/${j.id}`} style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'rgba(240,235,224,0.28)', textDecoration: 'underline' }}>View</Link>
              </div>
            ))}
          </div>
        )}
      </div>
      <ArtworkPanel />
    </div>
  )
}