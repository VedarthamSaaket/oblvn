import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import SectionRule from '../components/SectionRule'
import RiskScore from '../components/RiskScore'
import ArtworkPanel from '../components/ArtworkPanel'

const STATUS_COLOURS = {
  completed: 'var(--parchment)',
  running: '#6ab87a',
  failed: '#c44a42',
  queued: 'rgba(240,235,224,0.4)',
  pending_approval: 'rgba(196,144,26,0.8)',
  cancelled: 'rgba(240,235,224,0.2)',
}

function StatBox({ num, label }) {
  return (
    <div style={{ borderTop: '1px solid rgba(240,235,224,0.1)', paddingTop: 18 }}>
      <span style={{
        fontFamily: 'var(--serif)', fontWeight: 700, fontStyle: 'normal',
        fontSize: 52, lineHeight: 1, color: 'var(--cream)',
        display: 'block', letterSpacing: '-0.03em',
      }}>
        {num}
      </span>
      <span style={{
        fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.2em',
        textTransform: 'uppercase', color: 'rgba(240,235,224,0.3)',
        display: 'block', marginTop: 4,
      }}>
        {label}
      </span>
    </div>
  )
}

function JobRow({ job }) {
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '1fr 150px 120px 90px 60px',
      gap: 16, padding: '16px 0',
      borderBottom: '1px solid rgba(240,235,224,0.05)', alignItems: 'center',
    }}>
      <div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--cream)' }}>{job.device_model}</div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'rgba(240,235,224,0.28)', marginTop: 2, letterSpacing: '0.1em' }}>{job.device_serial}</div>
      </div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.1em', color: 'rgba(240,235,224,0.38)' }}>
        {job.method?.replace(/_/g, ' ')}
      </div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.1em', color: 'rgba(240,235,224,0.28)' }}>
        {job.standard?.replace(/_/g, ' ').toUpperCase()}
      </div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.14em', textTransform: 'uppercase', color: STATUS_COLOURS[job.status] || 'var(--cream)' }}>
        {job.status?.replace(/_/g, ' ')}
      </div>
      <Link to={`/jobs/${job.id}`} style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.16em', color: 'rgba(240,235,224,0.28)', textDecoration: 'underline' }}>
        View
      </Link>
    </div>
  )
}

export default function Dashboard() {
  const { user } = useAuth()
  const [jobs, setJobs] = useState([])
  const [devices, setDevices] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      api.jobs.list().then(d => setJobs(d.jobs || [])),
      api.devices.list().then(d => setDevices(d.devices || [])).catch(() => { }),
    ]).finally(() => setLoading(false))
  }, [])

  const completed = jobs.filter(j => j.status === 'completed').length
  const running = jobs.filter(j => j.status === 'running').length
  const pending = jobs.filter(j => j.status === 'pending_approval').length
  const recent = jobs.slice(0, 8)

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)' }}>
      <div style={{ padding: '52px', maxWidth: 1000 }}>
        <SectionRule label="Dashboard" num="01" />
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 80, marginBottom: 80 }}>
          <div>
            <h1 style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 'clamp(52px,6vw,80px)', lineHeight: 0.88, letterSpacing: '-0.02em', marginBottom: 28 }}>
              Secure<br /><em style={{ fontStyle: 'italic', color: 'rgba(240,235,224,0.5)' }}>Obliteration.</em>
            </h1>
            <p style={{ fontFamily: 'var(--sans)', fontWeight: 300, fontSize: 11, lineHeight: 1.9, color: 'rgba(240,235,224,0.38)', maxWidth: 340, marginBottom: 32 }}>
              military-grade data destruction with blockchain-anchored proof. every byte gone, every wipe proven.
            </p>
            <RiskScore orgId={null} />
          </div>
          <div>
            <div style={{ background: 'rgba(240,235,224,0.03)', border: '1px solid rgba(240,235,224,0.07)', padding: '28px' }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.22)', marginBottom: 24 }}>Overview</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
                <StatBox num={completed} label="Completed Wipes" />
                <StatBox num={running} label="Running Now" />
                <StatBox num={pending} label="Awaiting Approval" />
                <StatBox num={devices.length} label="Devices Detected" />
              </div>
            </div>
          </div>
        </div>
        <SectionRule label="Recent Wipe Jobs" num="02" />
        {loading ? (
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.3)', letterSpacing: '0.2em' }}>Loading...</div>
        ) : recent.length === 0 ? (
          <div style={{ padding: '48px 0', fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.25)', letterSpacing: '0.2em', lineHeight: 1.9 }}>
            No wipe jobs yet. Go to Wipe Jobs to start one.
          </div>
        ) : (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 150px 120px 90px 60px', gap: 16, paddingBottom: 12, borderBottom: '1px solid rgba(240,235,224,0.08)' }}>
              {['Device', 'Method', 'Standard', 'Status', ''].map(h => (
                <span key={h} style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.26em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.18)' }}>{h}</span>
              ))}
            </div>
            {recent.map(j => <JobRow key={j.id} job={j} />)}
            {jobs.length > 8 && (
              <div style={{ paddingTop: 20 }}>
                <Link to="/jobs" style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.3)', textDecoration: 'underline' }}>
                  View all {jobs.length} jobs
                </Link>
              </div>
            )}
          </div>
        )}
      </div>
      <ArtworkPanel />
    </div>
  )
}