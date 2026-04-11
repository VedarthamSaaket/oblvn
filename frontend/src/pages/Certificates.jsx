import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'
import SectionRule from '../components/SectionRule'
import { BtnSolid, BtnGhost } from '../components/Btn'
import { Field } from '../components/Field'
import ArtworkPanel from '../components/ArtworkPanel'

export default function Certificates() {
  const toast = useToast()
  const [jobs, setJobs] = useState([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    api.jobs.list()
      .then(d => {
        setJobs((d.jobs || []).filter(j => j.status === 'completed' && j.sha256_hash))
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  async function download(id) {
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

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)' }}>
      <div style={{ padding: '52px', maxWidth: 1000 }}>
        <SectionRule label="Certificates of Destruction" num="03" />
        <h2 style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 'clamp(36px,5vw,56px)', lineHeight: 0.9, letterSpacing: '-0.02em', marginBottom: 52 }}>
          Proof of<br /><em style={{ color: 'rgba(240,235,224,0.5)' }}>Obliteration.</em>
        </h2>
        {loading ? (
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.3)' }}>Loading...</div>
        ) : jobs.length === 0 ? (
          <div style={{ padding: '48px 0', fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.25)', letterSpacing: '0.16em', lineHeight: 1.9 }}>
            No certificates yet.<br />Complete a wipe job to generate one.
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 1fr' : '1fr', gap: 40 }}>
            <div>
              {jobs.map(j => (
                <div key={j.id} onClick={() => setSelected(j)} style={{ padding: '24px', marginBottom: 10, cursor: 'crosshair', border: `1px solid ${selected?.id === j.id ? 'var(--parchment)' : 'rgba(240,235,224,0.07)'}`, background: selected?.id === j.id ? 'rgba(196,180,138,0.04)' : 'transparent', transition: 'all 0.2s' }}>
                  <div style={{ fontFamily: 'var(--serif)', fontWeight: 700, fontSize: 16, color: 'var(--cream)', marginBottom: 8 }}>{j.device_model}</div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'rgba(240,235,224,0.3)' }}>{j.device_serial}</div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'rgba(240,235,224,0.3)' }}>{j.method?.replace(/_/g, ' ')}</div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--parchment)' }}>{j.completed_at ? new Date(j.completed_at).toLocaleDateString() : ''}</div>
                  </div>
                </div>
              ))}
            </div>
            {selected && (
              <div style={{ padding: '32px', border: '1px solid rgba(240,235,224,0.08)', background: 'rgba(240,235,224,0.02)' }}>
                <div style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 24, marginBottom: 24, letterSpacing: '-0.01em', color: 'var(--cream)' }}>OBLVN</div>
                <Field label="Certificate ID" value={selected.id} />
                <Field label="Device" value={selected.device_model} />
                <Field label="Serial" value={selected.device_serial} />
                <Field label="Method" value={selected.method?.replace(/_/g, ' ')} />
                <Field label="Standard" value={selected.standard?.replace(/_/g, ' ').toUpperCase()} />
                <Field label="Passes" value={selected.passes_completed} />
                <Field label="Completed" value={selected.completed_at ? new Date(selected.completed_at).toLocaleString() : 'N/A'} />
                {selected.sha256_hash && (
                  <div style={{ background: 'rgba(74,84,66,0.2)', padding: '10px 12px', margin: '16px 0', fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.06em', color: 'rgba(240,235,224,0.4)', wordBreak: 'break-all', lineHeight: 1.7 }}>
                    SHA-256 {selected.sha256_hash}
                  </div>
                )}
                <div style={{ display: 'flex', gap: 16, marginTop: 24 }}>
                  <BtnSolid onClick={() => download(selected.id)}>Download PDF</BtnSolid>
                  <a href={`/verify/${selected.id}`} target="_blank" rel="noreferrer"><BtnGhost>Verify</BtnGhost></a>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
      <ArtworkPanel />
    </div>
  )
}