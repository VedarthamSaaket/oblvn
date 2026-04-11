import { useEffect, useRef, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'
import SectionRule from '../components/SectionRule'
import { BtnSolid, BtnGhost } from '../components/Btn'
import { Field } from '../components/Field'
import ArtworkPanel from '../components/ArtworkPanel'

const STATUS_COLOR = {
  queued: 'rgba(240,235,224,0.4)',
  running: 'var(--parchment)',
  completed: '#6ab87a',
  failed: 'rgba(196,74,66,0.9)',
  cancelled: 'rgba(240,235,224,0.25)',
  pending_approval: 'rgba(196,144,26,0.8)',
}

function ProgressBar({ pct, color = 'var(--parchment)' }) {
  return (
    <div style={{
      width: '100%', height: 3,
      background: 'rgba(240,235,224,0.07)',
      position: 'relative', overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', left: 0, top: 0, bottom: 0,
        width: `${Math.min(pct, 100)}%`,
        background: color,
        transition: 'width 0.4s ease',
      }} />
    </div>
  )
}

function PassBlock({ label, passPct, overallPct, passNum, totalPasses, fileIndex, fileTotal }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.12em', color: 'rgba(240,235,224,0.55)', maxWidth: '70%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {label}
        </div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--parchment)', flexShrink: 0, marginLeft: 12 }}>
          {Math.round(passPct)}%
        </div>
      </div>
      <ProgressBar pct={passPct} />
      {fileTotal > 1 && (
        <div style={{ marginTop: 6, display: 'flex', justifyContent: 'space-between' }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 7, color: 'rgba(240,235,224,0.22)', letterSpacing: '0.1em' }}>
            file {fileIndex} of {fileTotal}
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 7, color: 'rgba(240,235,224,0.22)' }}>
            overall {Math.round(overallPct)}%
          </div>
        </div>
      )}
      {totalPasses > 1 && (
        <div style={{ marginTop: 6 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 7, color: 'rgba(240,235,224,0.22)', letterSpacing: '0.1em', marginBottom: 4 }}>
            pass {passNum} of {totalPasses} — overall {Math.round(overallPct)}%
          </div>
          <ProgressBar pct={overallPct} color='rgba(196,180,138,0.35)' />
        </div>
      )}
    </div>
  )
}

export default function JobDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const toast = useToast()

  const [job, setJob] = useState(null)
  const [loading, setLoading] = useState(true)
  const [progress, setProgress] = useState(null)
  const [cancelling, setCancelling] = useState(false)
  const wsRef = useRef(null)
  const pollRef = useRef(null)
  const certPollRef = useRef(null)

  async function loadJob() {
    try {
      const j = await api.jobs.get(id)
      setJob(j)
      return j
    } catch (err) {
      toast(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  // After wipe completes, the backend still needs to run finalize (cert gen, sha256, db write).
  // Poll until sha256_hash appears — usually within 2-4s.
  function pollUntilCertReady() {
    if (certPollRef.current) return
    let attempts = 0
    const MAX = 30 // 30 * 1s = 30s max wait
    certPollRef.current = setInterval(async () => {
      attempts++
      try {
        const j = await api.jobs.get(id)
        if (j?.sha256_hash) {
          setJob(j)
          clearInterval(certPollRef.current)
          certPollRef.current = null
        } else if (attempts >= MAX) {
          // Gave up — show whatever we have
          setJob(j)
          clearInterval(certPollRef.current)
          certPollRef.current = null
        }
      } catch { /* ignore */ }
    }, 1000)
  }

  function stopCertPoll() {
    if (certPollRef.current) {
      clearInterval(certPollRef.current)
      certPollRef.current = null
    }
  }

  function startPolling() {
    if (pollRef.current) return
    pollRef.current = setInterval(async () => {
      try {
        const j = await api.jobs.get(id)
        setJob(prev => {
          if (prev?.status !== j.status || prev?.passes_completed !== j.passes_completed) {
            return j
          }
          return prev
        })
        if (['completed', 'failed', 'cancelled'].includes(j.status)) {
          clearInterval(pollRef.current)
          pollRef.current = null
          // If completed but no cert yet, kick off cert poll
          if (j.status === 'completed' && !j.sha256_hash) {
            pollUntilCertReady()
          }
        }
      } catch { /* ignore */ }
    }, 3000)
  }

  function stopPolling() {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  function connectWS(token) {
    if (wsRef.current) return
    const wsUrl = `ws://localhost:8000/ws/jobs/${id}?token=${token}`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)

        if (data.type === 'progress') {
          setProgress({
            label: data.label || '',
            passPct: data.pass_pct ?? 0,
            overallPct: data.overall_pct ?? 0,
            passNum: data.pass_num ?? data.file_index ?? 1,
            totalPasses: data.total_passes ?? data.file_total ?? 1,
            fileIndex: data.file_index ?? null,
            fileTotal: data.file_total ?? null,
          })
          setJob(prev => prev ? { ...prev, status: 'running' } : prev)
        }

        if (data.type === 'complete') {
          setProgress(null)
          stopPolling()
          // Apply whatever the WS complete event carries immediately
          setJob(prev => prev ? {
            ...prev,
            status: 'completed',
            sha256_hash: data.sha256_hash || prev.sha256_hash,
            certificate_id: data.certificate_id || prev.certificate_id,
          } : prev)
          // Then poll DB until sha256_hash is confirmed written
          // (finalize may not have committed yet when WS fires)
          pollUntilCertReady()
        }

        if (data.type === 'cancelled') {
          setProgress(null)
          setJob(prev => prev ? { ...prev, status: 'cancelled' } : prev)
          stopPolling()
        }

        if (data.type === 'error') {
          setProgress(null)
          setJob(prev => prev ? { ...prev, status: 'failed', error_message: data.error } : prev)
          stopPolling()
          toast(data.error || 'Wipe failed', 'error')
        }

        if (data.type === 'warning') {
          toast(data.message, 'warning')
        }
      } catch { /* ignore parse errors */ }
    }

    ws.onerror = () => { /* polling covers us */ }
    ws.onclose = () => { wsRef.current = null }
  }

  useEffect(() => {
    loadJob().then(j => {
      if (!j) return
      const token = localStorage.getItem('oblvn_token') || sessionStorage.getItem('oblvn_token')
      if (!token) return

      if (['queued', 'running'].includes(j.status)) {
        connectWS(token)
        startPolling()
      }

      // Landed on page after job completed but cert not yet written
      if (j.status === 'completed' && !j.sha256_hash) {
        pollUntilCertReady()
      }
    })

    return () => {
      if (wsRef.current) { wsRef.current.close(); wsRef.current = null }
      stopPolling()
      stopCertPoll()
    }
  }, [id])

  async function cancelJob() {
    setCancelling(true)
    try {
      await api.jobs.cancel(id)
      toast('Job cancelled', 'success')
      setJob(prev => prev ? { ...prev, status: 'cancelled' } : prev)
      setProgress(null)
      stopPolling()
    } catch (err) {
      toast(err.message, 'error')
    } finally {
      setCancelling(false)
    }
  }

  async function downloadCert() {
    try {
      const blob = await api.certificates.download(id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `OBLVN-${id}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) { toast(err.message, 'error') }
  }

  if (loading) {
    return (
      <div style={{ padding: '52px', fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.3)', letterSpacing: '0.14em' }}>
        Loading...
      </div>
    )
  }

  if (!job) {
    return (
      <div style={{ padding: '52px', fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(196,74,66,0.8)' }}>
        Job not found.
      </div>
    )
  }

  const isActive = ['queued', 'running'].includes(job.status)
  const isDone = job.status === 'completed'
  const isFailed = job.status === 'failed'
  const isCancelled = job.status === 'cancelled'
  // Cert is ready when sha256_hash is present — may arrive a few seconds after status=completed
  const certReady = isDone && !!job.sha256_hash

  const displaySerial = job.device_serial?.startsWith('file:')
    ? job.device_serial.replace(/^file:/, '')
    : job.device_serial

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 420px', minHeight: 'calc(100vh - 80px)' }}>
      <div style={{ padding: '52px', maxWidth: 900 }}>
        <SectionRule label="Wipe Job" num="01" />

        <div style={{ marginBottom: 52 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 8 }}>
            <h2 style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 'clamp(32px,4vw,52px)', lineHeight: 0.9, letterSpacing: '-0.02em' }}>
              {job.device_model}
            </h2>
            <div style={{
              fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.2em', textTransform: 'uppercase',
              color: STATUS_COLOR[job.status] || 'var(--cream)',
              border: `1px solid ${STATUS_COLOR[job.status] || 'rgba(240,235,224,0.2)'}`,
              padding: '6px 14px', flexShrink: 0, marginLeft: 24, marginTop: 4,
            }}>
              {job.status.replace(/_/g, ' ')}
            </div>
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.12em', color: 'rgba(240,235,224,0.25)', marginTop: 8 }}>
            {id}
          </div>
        </div>

        {isActive && (
          <div style={{ marginBottom: 48, padding: '28px 28px 24px', border: '1px solid rgba(196,180,138,0.2)', background: 'rgba(196,180,138,0.03)' }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.22)', marginBottom: 20 }}>
              {progress ? 'In Progress' : 'Queued — waiting to start'}
            </div>
            {progress ? (
              <PassBlock
                label={progress.label}
                passPct={progress.passPct}
                overallPct={progress.overallPct}
                passNum={progress.passNum}
                totalPasses={progress.totalPasses}
                fileIndex={progress.fileIndex}
                fileTotal={progress.fileTotal}
              />
            ) : (
              <div style={{ fontFamily: 'var(--mono)', fontSize: 8.5, color: 'rgba(240,235,224,0.3)', letterSpacing: '0.1em' }}>
                Starting...
              </div>
            )}
            <div style={{ marginTop: 24 }}>
              <BtnGhost onClick={cancelJob} disabled={cancelling}>
                {cancelling ? 'Cancelling...' : 'Cancel Job'}
              </BtnGhost>
            </div>
          </div>
        )}

        {isDone && !certReady && (
          <div style={{ marginBottom: 32, padding: '20px 24px', border: '1px solid rgba(106,184,122,0.2)', background: 'rgba(106,184,122,0.03)', fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.1em', color: 'rgba(106,184,122,0.6)', lineHeight: 1.8 }}>
            Wipe complete. Generating certificate...
          </div>
        )}

        {certReady && (
          <div style={{ marginBottom: 32, padding: '20px 24px', border: '1px solid rgba(106,184,122,0.3)', background: 'rgba(106,184,122,0.05)', fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.1em', color: 'rgba(106,184,122,0.9)', lineHeight: 1.8 }}>
            Wipe complete. Certificate of destruction generated.
          </div>
        )}

        {isFailed && (
          <div style={{ marginBottom: 32, padding: '20px 24px', border: '1px solid rgba(196,74,66,0.4)', background: 'rgba(196,74,66,0.06)', fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.1em', color: 'rgba(196,74,66,0.9)', lineHeight: 1.8 }}>
            {job.error_message || 'Wipe failed — check logs.'}
          </div>
        )}

        {isCancelled && (
          <div style={{ marginBottom: 32, padding: '20px 24px', border: '1px solid rgba(240,235,224,0.1)', background: 'rgba(240,235,224,0.02)', fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.1em', color: 'rgba(240,235,224,0.35)', lineHeight: 1.8 }}>
            Job cancelled.
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '28px 60px', marginBottom: 52 }}>
          <Field label="Device" value={job.device_model} />
          <Field label="Status" value={job.status.replace(/_/g, ' ').toUpperCase()} />
          <Field label="Serial" value={displaySerial} />
          <Field label="Created" value={job.created_at ? new Date(job.created_at).toLocaleString() : '—'} />
          <Field label="Method" value={job.method?.replace(/_/g, ' ')} />
          <Field label="Completed" value={job.completed_at ? new Date(job.completed_at).toLocaleString() : '—'} />
          <Field label="Standard" value={job.standard?.replace(/_/g, ' ').toUpperCase()} />
          <Field label="Passes Completed" value={job.passes_completed ?? '—'} />
          {job.verification_passed != null && (
            <Field label="Verification" value={job.verification_passed ? 'Passed' : 'Failed'} />
          )}
        </div>

        {certReady && (
          <>
            <SectionRule label="Certificate of Destruction" num="03" />
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.2)', marginBottom: 8 }}>SHA-256 Hash</div>
              <div style={{
                fontFamily: 'var(--mono)', fontSize: 8.5, color: 'rgba(240,235,224,0.5)',
                background: 'rgba(74,84,66,0.18)', padding: '12px 14px',
                wordBreak: 'break-all', lineHeight: 1.7, letterSpacing: '0.04em',
              }}>
                {job.sha256_hash}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 16, marginTop: 28 }}>
              <BtnSolid onClick={downloadCert}>Download Certificate PDF</BtnSolid>
              <a href={`/verify/${id}`} target="_blank" rel="noreferrer">
                <BtnGhost>Verify Online</BtnGhost>
              </a>
            </div>
          </>
        )}
      </div>
      <ArtworkPanel />
    </div>
  )
}