import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'
import SectionRule from '../components/SectionRule'
import { BtnSolid, BtnGhost } from '../components/Btn'
import { Field, Select } from '../components/Field'
import ArtworkPanel from '../components/ArtworkPanel'

const METHODS = [
  { value: 'binary_overwrite', label: 'Binary Obliteration (Overwrite)' },
  { value: 'crypto_erase', label: 'Crypto Erasure (AES-256)' },
  { value: 'full_sanitization', label: 'Full Sanitization (Overwrite + Crypto)' },
]

const FILE_METHODS = [
  { value: 'binary_overwrite', label: 'Binary Overwrite (DoD 3-pass)' },
  { value: 'crypto_erase', label: 'Crypto Erase (AES-256 + key destroy)' },
]

const STANDARDS = {
  hdd: [
    { value: 'dod_5220_22m', label: 'DoD 5220.22-M (3 pass)' },
    { value: 'gutmann', label: 'Gutmann (35 pass)' },
    { value: 'nist_800_88', label: 'NIST 800-88 (1 pass)' },
  ],
  ssd: [{ value: 'nist_800_88', label: 'NIST 800-88 (recommended for SSD)' }],
  nvme: [{ value: 'nist_800_88', label: 'NIST 800-88 (recommended for NVMe)' }],
  usb_flash: [{ value: 'nist_800_88', label: 'NIST 800-88' }],
  file: [
    { value: 'dod_5220_22m', label: 'DoD 5220.22-M (3 pass)' },
    { value: 'gutmann', label: 'Gutmann (35 pass)' },
    { value: 'nist_800_88', label: 'NIST 800-88 (1 pass)' },
  ],
}

function BohoEmptyArt({ style }) {
  return (
    <svg
      viewBox="0 0 260 180"
      xmlns="http://www.w3.org/2000/svg"
      style={{ width: 260, height: 180, opacity: 0.11, pointerEvents: 'none', ...style }}
    >
      <defs>
        <filter id="boho-noise">
          <feTurbulence type="fractalNoise" baseFrequency="0.055" numOctaves="3" seed="12" result="n" />
          <feDisplacementMap in="SourceGraphic" in2="n" scale="1.8" xChannelSelector="R" yChannelSelector="G" />
        </filter>
      </defs>
      <g filter="url(#boho-noise)" stroke="#ede5cc" fill="none" strokeLinecap="round">
        {[20, 34, 48, 62, 76, 90].map((r, i) => (
          <path key={i} d={`M ${130 - r} 130 A ${r} ${r} 0 0 1 ${130 + r} 130`}
            strokeWidth={i === 0 ? 2.2 : i < 3 ? 2 : 1.6} opacity={0.9 - i * 0.06} />
        ))}
        <ellipse cx="130" cy="60" rx="18" ry="26" strokeWidth="1.8" opacity="0.7" />
        <circle cx="130" cy="60" r="7" strokeWidth="1.4" opacity="0.6" />
        <circle cx="130" cy="60" r="2.5" fill="#ede5cc" stroke="none" opacity="0.5" />
        <path d="M 60 80 Q 48 65 55 52" strokeWidth="1.5" opacity="0.5" />
        <path d="M 60 80 Q 52 70 62 62" strokeWidth="1.3" opacity="0.4" />
        <path d="M 55 70 Q 40 60 44 48" strokeWidth="1.2" opacity="0.35" />
        <path d="M 200 80 Q 212 65 205 52" strokeWidth="1.5" opacity="0.5" />
        <path d="M 200 80 Q 208 70 198 62" strokeWidth="1.3" opacity="0.4" />
        <path d="M 205 70 Q 220 60 216 48" strokeWidth="1.2" opacity="0.35" />
        {[112, 122, 130, 138, 148].map((x, i) => (
          <circle key={i} cx={x} cy={28} r={i === 2 ? 2.5 : 1.5} fill="#ede5cc" stroke="none" opacity={0.4 - i * 0.02} />
        ))}
      </g>
    </svg>
  )
}

function Tab({ label, active, onClick }) {
  return (
    <button onClick={onClick} style={{
      fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.2em', textTransform: 'uppercase',
      cursor: 'crosshair', padding: '12px 0', background: 'none', border: 'none',
      borderBottom: `2px solid ${active ? 'var(--parchment)' : 'transparent'}`,
      color: active ? 'var(--cream)' : 'rgba(240,235,224,0.28)',
      transition: 'color 0.2s, border-color 0.2s', marginRight: 36,
    }}>
      {label}
    </button>
  )
}

function DeviceCard({ device, onSelect, selected }) {
  const typeColours = {
    ssd: 'var(--parchment)', hdd: 'rgba(240,235,224,0.5)',
    nvme: '#6ab87a', usb_flash: 'rgba(196,144,26,0.8)',
  }
  const hasAnomalies = device.anomalies && device.anomalies.length > 0
  return (
    <div onClick={() => onSelect(device)} style={{
      padding: '28px 24px',
      border: `1px solid ${selected ? 'var(--parchment)' : hasAnomalies ? 'rgba(196,74,66,0.4)' : 'rgba(240,235,224,0.08)'}`,
      cursor: 'crosshair', background: selected ? 'rgba(196,180,138,0.04)' : 'transparent', transition: 'all 0.2s',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
        <div>
          <div style={{ fontFamily: 'var(--serif)', fontWeight: 700, fontSize: 18, color: 'var(--cream)', marginBottom: 4 }}>{device.model}</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.16em', color: 'rgba(240,235,224,0.3)' }}>{device.serial}</div>
        </div>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.2em', textTransform: 'uppercase', color: typeColours[device.device_type] || 'var(--cream)' }}>
          {device.device_type?.replace('_', ' ')}
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <Field label="Capacity" value={device.capacity_human} />
        <Field label="Interface" value={device.interface} />
        <Field label="Health" value={device.health} />
      </div>
      {device.smart_snapshot?.temperature != null && <Field label="Temperature" value={`${device.smart_snapshot.temperature}C`} />}
      {hasAnomalies && (
        <div style={{ marginTop: 14, padding: '8px 12px', background: 'rgba(196,74,66,0.1)', border: '1px solid rgba(196,74,66,0.3)', fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.14em', color: 'rgba(240,235,224,0.7)' }}>
          {device.anomalies.length} S.M.A.R.T. anomaly{device.anomalies.length > 1 ? 'ies' : ''} detected
        </div>
      )}
    </div>
  )
}

function HardwareWipe() {
  const toast = useToast()
  const navigate = useNavigate()
  const [devices, setDevices] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [connected, setConnected] = useState(false)
  const [selected, setSelected] = useState(null)
  const [method, setMethod] = useState('binary_overwrite')
  const [standard, setStandard] = useState('dod_5220_22m')
  const [submitting, setSubmitting] = useState(false)
  const [confirm, setConfirm] = useState(false)

  async function connectDevices() {
    setLoading(true); setError(null); setConnected(false); setDevices([]); setSelected(null)
    try {
      const d = await api.devices.list()
      setDevices(d.devices || []); setConnected(true)
    } catch (e) {
      if (e.message?.includes('401') || e.message?.toLowerCase().includes('unauthorized')) {
        setError('Authentication error. Your session may have expired, please log out and log back in.')
      } else {
        setError(e.message)
      }
    } finally { setLoading(false) }
  }

  function onSelect(device) {
    setSelected(device)
    const standards = STANDARDS[device.device_type] || STANDARDS.hdd
    setStandard(standards[0].value); setConfirm(false)
  }

  async function startWipe() {
    if (!selected) return; setSubmitting(true)
    try {
      const job = await api.jobs.create({ device_serial: selected.serial, method, standard })
      toast('Wipe job created', 'success'); navigate(`/jobs/${job.id}`)
    } catch (err) { toast(err.message, 'error') } finally { setSubmitting(false); setConfirm(false) }
  }

  return (
    <div>
      <div style={{ padding: '28px 32px', border: '1px solid rgba(240,235,224,0.08)', background: 'rgba(240,235,224,0.02)', marginBottom: 36, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.3)', marginBottom: 6 }}>Hardware Detection</div>
          <div style={{ fontFamily: 'var(--sans)', fontWeight: 300, fontSize: 10.5, color: 'rgba(240,235,224,0.4)', lineHeight: 1.7, maxWidth: 420 }}>
            Connect a storage device to this machine, then click Detect Devices to scan for connected hardware.
          </div>
        </div>
        <button onClick={connectDevices} disabled={loading}
          style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.2em', textTransform: 'uppercase', color: loading ? 'rgba(26,34,24,0.5)' : 'var(--ink)', background: loading ? 'rgba(196,180,138,0.4)' : 'var(--cream)', border: 'none', padding: '13px 28px', cursor: loading ? 'wait' : 'crosshair', boxShadow: loading ? 'none' : '3px 3px 0 var(--sage)', transition: 'all 0.15s', whiteSpace: 'nowrap', flexShrink: 0 }}
          onMouseEnter={e => { if (!loading) { e.currentTarget.style.transform = 'translate(-2px, -2px)'; e.currentTarget.style.boxShadow = '5px 5px 0 var(--sage)' } }}
          onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = loading ? 'none' : '3px 3px 0 var(--sage)' }}
        >{loading ? 'Scanning...' : 'Detect Devices'}</button>
      </div>
      {error && (
        <div style={{ padding: '20px 24px', border: '1px solid rgba(196,74,66,0.4)', marginBottom: 32, fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.6)', background: 'rgba(196,74,66,0.06)', lineHeight: 1.85 }}>
          {error}
          <div style={{ marginTop: 10, color: 'rgba(240,235,224,0.3)', fontSize: 8 }}>No hardware detected? Switch to the File / Folder tab to securely delete files instead.</div>
        </div>
      )}
      {!connected && !loading && !error && (
        <div style={{ padding: '48px 0', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
          <BohoEmptyArt />
          <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.18)', textAlign: 'center' }}>No devices scanned yet</div>
        </div>
      )}
      {connected && devices.length === 0 && !error && (
        <div style={{ padding: '48px 0', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
          <BohoEmptyArt />
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.14em', color: 'rgba(240,235,224,0.35)', lineHeight: 1.9, textAlign: 'center' }}>No storage devices found.<br />Make sure drives are plugged in and try again.</div>
        </div>
      )}
      {connected && devices.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 16, marginBottom: 52 }}>
          {devices.map(d => <DeviceCard key={d.serial} device={d} selected={selected?.serial === d.serial} onSelect={onSelect} />)}
        </div>
      )}
      {selected && (
        <div style={{ borderTop: '1px solid rgba(240,235,224,0.08)', paddingTop: 48 }}>
          <SectionRule label="Configure Wipe" num="02" />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 60 }}>
            <div>
              <Select label="Wipe Method" value={method} onChange={e => setMethod(e.target.value)} options={METHODS} />
              <Select label="Standard" value={standard} onChange={e => setStandard(e.target.value)} options={STANDARDS[selected.device_type] || STANDARDS.hdd} />
            </div>
            <div>
              <Field label="Selected Device" value={selected.model} />
              <Field label="Serial" value={selected.serial} />
              <Field label="Type" value={selected.device_type?.toUpperCase()} />
              <Field label="Capacity" value={selected.capacity_human} />
            </div>
          </div>
          {!confirm ? (
            <BtnSolid onClick={() => setConfirm(true)}>Start Wipe</BtnSolid>
          ) : (
            <div style={{ padding: '28px 24px', border: '1px solid rgba(196,74,66,0.4)', background: 'rgba(196,74,66,0.06)' }}>
              <div style={{ fontFamily: 'var(--serif)', fontStyle: 'italic', fontSize: 22, color: 'var(--cream)', marginBottom: 12 }}>This action is irreversible.</div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.14em', color: 'rgba(240,235,224,0.5)', marginBottom: 24, lineHeight: 1.8 }}>
                All data on {selected.model} ({selected.serial}) will be permanently destroyed using {method.replace(/_/g, ' ')}. This cannot be undone.
              </div>
              <div style={{ display: 'flex', gap: 20 }}>
                <BtnSolid onClick={startWipe} disabled={submitting}>{submitting ? 'Submitting...' : 'Confirm and Destroy'}</BtnSolid>
                <BtnGhost onClick={() => setConfirm(false)}>Cancel</BtnGhost>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const EXT_COLOURS = {
  pdf: 'rgba(196,74,66,0.55)', docx: 'rgba(74,110,196,0.55)', doc: 'rgba(74,110,196,0.55)',
  xlsx: 'rgba(74,160,100,0.55)', csv: 'rgba(74,160,100,0.55)', jpg: 'rgba(196,144,26,0.55)',
  jpeg: 'rgba(196,144,26,0.55)', png: 'rgba(196,144,26,0.55)', mp4: 'rgba(130,74,196,0.55)',
  mov: 'rgba(130,74,196,0.55)', db: 'rgba(196,180,138,0.55)', sqlite: 'rgba(196,180,138,0.55)',
  zip: 'rgba(196,130,66,0.55)', tar: 'rgba(196,130,66,0.55)', key: 'rgba(196,74,66,0.8)',
  pem: 'rgba(196,74,66,0.8)', txt: 'rgba(240,235,224,0.2)', json: 'rgba(74,160,100,0.4)',
}

function FileTag({ ext }) {
  if (!ext) return null
  return (
    <span style={{
      fontFamily: 'var(--mono)', fontSize: 6.5, letterSpacing: '0.16em', textTransform: 'uppercase',
      padding: '3px 7px', background: EXT_COLOURS[ext] || 'rgba(240,235,224,0.08)',
      color: 'rgba(240,235,224,0.7)', flexShrink: 0,
    }}>{ext}</span>
  )
}

function SourceRow({ source, onRemove }) {
  const isFolder = source.type === 'folder'
  const displayName = source.path.replace(/\\/g, '/').split('/').pop() || source.path
  const ext = !isFolder && source.path.includes('.') ? source.path.split('.').pop().toLowerCase() : ''

  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      padding: '10px 14px', border: '1px solid rgba(240,235,224,0.07)',
      background: isFolder ? 'rgba(196,180,138,0.03)' : 'rgba(240,235,224,0.02)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
        {isFolder ? (
          <span style={{
            fontFamily: 'var(--mono)', fontSize: 6.5, letterSpacing: '0.16em', textTransform: 'uppercase',
            padding: '3px 7px', background: 'rgba(196,180,138,0.18)', color: 'rgba(196,180,138,0.9)', flexShrink: 0,
          }}>folder</span>
        ) : (
          <FileTag ext={ext} />
        )}
        <div style={{ minWidth: 0 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--cream)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {displayName}
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 7.5, color: 'rgba(240,235,224,0.3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {source.path}
            {isFolder && source.file_count != null && (
              <span style={{ marginLeft: 8, color: 'rgba(196,180,138,0.5)' }}>
                {source.file_count} file{source.file_count !== 1 ? 's' : ''}
              </span>
            )}
          </div>
        </div>
      </div>
      <button
        onClick={() => onRemove(source)}
        style={{ fontFamily: 'var(--mono)', fontSize: 7.5, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'rgba(196,74,66,0.6)', background: 'none', border: 'none', cursor: 'crosshair', padding: '4px 8px', flexShrink: 0 }}
      >
        Remove
      </button>
    </div>
  )
}

function PickerBtn({ onClick, children, disabled, loading: isLoading, secondary }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || isLoading}
      style={{
        fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.18em', textTransform: 'uppercase',
        padding: secondary ? '10px 20px' : '12px 24px',
        background: secondary ? 'transparent' : isLoading ? 'rgba(196,180,138,0.4)' : 'var(--cream)',
        color: secondary ? 'rgba(240,235,224,0.45)' : isLoading ? 'rgba(26,34,24,0.5)' : 'var(--ink)',
        border: secondary ? '1px solid rgba(240,235,224,0.13)' : 'none',
        cursor: disabled || isLoading ? 'wait' : 'crosshair',
        boxShadow: secondary || isLoading ? 'none' : '3px 3px 0 var(--sage)',
        transition: 'all 0.15s', whiteSpace: 'nowrap',
        opacity: disabled ? 0.4 : 1,
      }}
      onMouseEnter={e => {
        if (isLoading || disabled) return
        if (!secondary) { e.currentTarget.style.transform = 'translate(-2px,-2px)'; e.currentTarget.style.boxShadow = '5px 5px 0 var(--sage)' }
        else { e.currentTarget.style.borderColor = 'rgba(240,235,224,0.3)'; e.currentTarget.style.color = 'rgba(240,235,224,0.65)' }
      }}
      onMouseLeave={e => {
        e.currentTarget.style.transform = ''
        e.currentTarget.style.boxShadow = (secondary || isLoading) ? 'none' : '3px 3px 0 var(--sage)'
        e.currentTarget.style.borderColor = 'rgba(240,235,224,0.13)'
        e.currentTarget.style.color = secondary ? 'rgba(240,235,224,0.45)' : isLoading ? 'rgba(26,34,24,0.5)' : 'var(--ink)'
      }}
    >
      {isLoading ? 'Selecting...' : children}
    </button>
  )
}

function FileWipe() {
  const toast = useToast()
  const navigate = useNavigate()

  const [sources, setSources] = useState([])
  const [allPaths, setAllPaths] = useState([])
  const [method, setMethod] = useState('binary_overwrite')
  const [standard, setStandard] = useState('dod_5220_22m')
  const [submitting, setSubmitting] = useState(false)
  const [pickingFiles, setPickingFiles] = useState(false)
  const [pickingFolder, setPickingFolder] = useState(false)
  const [confirm, setConfirm] = useState(false)

  const picking = pickingFiles || pickingFolder
  const totalFiles = allPaths.length
  const folderCount = sources.filter(s => s.type === 'folder').length
  const fileCount = sources.filter(s => s.type === 'file').length

  function mergeResponse(res) {
    if (!res?.paths?.length) {
      toast('Nothing selected', 'error')
      return
    }
    const existingPaths = new Set(allPaths)
    const newPaths = res.paths.filter(p => !existingPaths.has(p))
    const newSources = (res.sources || []).filter(s =>
      s.type === 'folder' ? true : !existingPaths.has(s.path)
    )
    if (!newPaths.length) {
      toast('All selected items were already in the queue', 'error')
      return
    }
    setAllPaths(prev => [...prev, ...newPaths])
    setSources(prev => [...prev, ...newSources])
    setConfirm(false)
    toast(`${newPaths.length} file${newPaths.length !== 1 ? 's' : ''} added`, 'success')
  }

  async function pickFiles() {
    setPickingFiles(true)
    try {
      const res = await api.utils.selectFiles()
      mergeResponse(res)
    } catch (err) {
      if (!err.message?.includes('400')) toast(err.message || 'File picker failed', 'error')
    } finally {
      setPickingFiles(false)
    }
  }

  async function pickFolder() {
    setPickingFolder(true)
    try {
      const res = await api.utils.selectFolder()
      mergeResponse(res)
    } catch (err) {
      if (!err.message?.includes('400')) toast(err.message || 'Folder picker failed', 'error')
    } finally {
      setPickingFolder(false)
    }
  }

  function removeSource(source) {
    if (source.type === 'file') {
      setAllPaths(prev => prev.filter(p => p !== source.path))
      setSources(prev => prev.filter(s => !(s.type === 'file' && s.path === source.path)))
    } else {
      const removedFolder = source.path.replace(/\\/g, '/')
      setSources(prev => prev.filter(s => s !== source))
      setAllPaths(prev => prev.filter(p => {
        const n = p.replace(/\\/g, '/')
        return !n.startsWith(removedFolder + '/') && n !== removedFolder
      }))
    }
    setConfirm(false)
  }

  function clearAll() {
    setSources([]); setAllPaths([]); setConfirm(false)
  }

  async function startFileWipe() {
    if (!allPaths.length) return
    setSubmitting(true)
    try {
      const job = await api.jobs.create({
        device_serial: `file:${allPaths[0]}`,
        device_type: 'file',
        file_paths: allPaths,
        sources,
        method,
        standard,
      })
      toast('File wipe job queued', 'success')
      navigate(`/jobs/${job.id}`)
    } catch (err) {
      toast(err.message, 'error')
    } finally {
      setSubmitting(false)
      setConfirm(false)
    }
  }

  const summaryLabel = (() => {
    if (!sources.length) return null
    const parts = []
    if (fileCount > 0) parts.push(`${fileCount} loose file${fileCount !== 1 ? 's' : ''}`)
    if (folderCount > 0) parts.push(`${folderCount} folder${folderCount !== 1 ? 's' : ''}`)
    return parts.join(' + ') + ` — ${totalFiles} file${totalFiles !== 1 ? 's' : ''} total`
  })()

  return (
    <div style={{ maxWidth: 700 }}>

      {/* Info banner */}
      <div style={{ padding: '18px 22px', border: '1px solid rgba(196,180,138,0.18)', background: 'rgba(196,180,138,0.04)', marginBottom: 28, fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.1em', color: 'rgba(240,235,224,0.4)', lineHeight: 1.85 }}>
        Select individual files or entire folders — add as many as you need before starting the wipe.
        Files are destroyed at the byte level, not just unlinked.
      </div>

      {/* Picker buttons */}
      <div style={{ padding: '20px 24px', border: '1px solid rgba(240,235,224,0.08)', background: 'rgba(240,235,224,0.02)', marginBottom: 28 }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.22)', marginBottom: 14 }}>
          Add to queue
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <PickerBtn onClick={pickFiles} loading={pickingFiles} disabled={picking}>
            + Select Files
          </PickerBtn>
          <PickerBtn onClick={pickFolder} loading={pickingFolder} disabled={picking} secondary>
            + Select Folder(s)
          </PickerBtn>
          {sources.length > 0 && !picking && (
            <button
              onClick={clearAll}
              style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'rgba(196,74,66,0.5)', background: 'none', border: 'none', cursor: 'crosshair', padding: '4px 0', marginLeft: 4 }}
            >
              Clear all
            </button>
          )}
        </div>

        {/* How-to hint */}
        <div style={{ fontFamily: 'var(--mono)', fontSize: 7.5, color: 'rgba(240,235,224,0.2)', lineHeight: 1.9, marginTop: 14 }}>
          <span style={{ color: 'rgba(240,235,224,0.35)' }}>Select Files</span> — opens a dialog where you can highlight multiple files at once (hold Ctrl / Shift).
          <br />
          <span style={{ color: 'rgba(240,235,224,0.35)' }}>Select Folder(s)</span> — pick one folder, then another dialog opens automatically so you can keep adding folders. Cancel the dialog when you're done.
          <br />
          You can call either button multiple times to keep adding to the queue.
        </div>
      </div>

      {/* Empty state */}
      {sources.length === 0 && (
        <div style={{ padding: '48px 0', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, marginBottom: 28, border: '1px solid rgba(240,235,224,0.06)', background: 'rgba(240,235,224,0.01)' }}>
          <BohoEmptyArt style={{ opacity: 0.07 }} />
          <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.18)', textAlign: 'center' }}>Nothing queued</div>
        </div>
      )}

      {/* Source list */}
      {sources.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.22)', marginBottom: 10 }}>
            {summaryLabel}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {sources.map((s, i) => (
              <SourceRow key={`${s.type}-${s.path}-${i}`} source={s} onRemove={removeSource} />
            ))}
          </div>
        </div>
      )}

      {/* Config + confirm */}
      {sources.length > 0 && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 28 }}>
            <Select label="Wipe Method" value={method} onChange={e => setMethod(e.target.value)} options={FILE_METHODS} />
            <Select label="Standard" value={standard} onChange={e => setStandard(e.target.value)} options={STANDARDS.file} />
          </div>

          {!confirm ? (
            <BtnSolid onClick={() => {
              if (!allPaths.length) { toast('Select at least one file to wipe.', 'error'); return }
              setConfirm(true)
            }}>
              Queue Wipe — {totalFiles} file{totalFiles !== 1 ? 's' : ''}
            </BtnSolid>
          ) : (
            <div style={{ padding: '28px 24px', border: '1px solid rgba(196,74,66,0.4)', background: 'rgba(196,74,66,0.06)' }}>
              <div style={{ fontFamily: 'var(--serif)', fontStyle: 'italic', fontSize: 22, color: 'var(--cream)', marginBottom: 12 }}>This action is irreversible.</div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.14em', color: 'rgba(240,235,224,0.5)', marginBottom: 8, lineHeight: 1.8 }}>
                {totalFiles} file{totalFiles !== 1 ? 's' : ''} will be permanently destroyed using {method.replace(/_/g, ' ')}:
              </div>
              <div style={{ marginBottom: 24, maxHeight: 140, overflowY: 'auto' }}>
                {sources.map((s, i) => (
                  <div key={i} style={{ fontFamily: 'var(--mono)', fontSize: 7.5, color: 'rgba(240,235,224,0.35)', marginBottom: 3, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ color: s.type === 'folder' ? 'rgba(196,180,138,0.5)' : 'rgba(240,235,224,0.2)', fontSize: 7, letterSpacing: '0.1em' }}>
                      {s.type === 'folder' ? 'DIR' : 'FILE'}
                    </span>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.path}</span>
                    {s.type === 'folder' && s.file_count != null && (
                      <span style={{ color: 'rgba(196,180,138,0.4)', flexShrink: 0 }}>({s.file_count})</span>
                    )}
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 20 }}>
                <BtnSolid onClick={startFileWipe} disabled={submitting}>
                  {submitting ? 'Queuing...' : 'Confirm and Destroy'}
                </BtnSolid>
                <BtnGhost onClick={() => setConfirm(false)}>Cancel</BtnGhost>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default function Devices() {
  const [tab, setTab] = useState('hardware')

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 420px', minHeight: 'calc(100vh - 80px)' }}>
      <div style={{ padding: '52px', maxWidth: 1200 }}>
        <SectionRule label="New Wipe Job" num="01" />
        <div style={{ marginBottom: 40 }}>
          <h2 style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 'clamp(40px, 5vw, 64px)', lineHeight: 0.9, letterSpacing: '-0.02em', marginBottom: 16 }}>
            What are<br /><em style={{ color: 'rgba(240,235,224,0.5)' }}>you wiping?</em>
          </h2>
          <p style={{ fontFamily: 'var(--sans)', fontWeight: 300, fontSize: 10.5, color: 'rgba(240,235,224,0.35)', lineHeight: 1.8, maxWidth: 420 }}>
            Wipe a connected storage device entirely, or select specific files or folders you want permanently destroyed.
          </p>
        </div>
        <div style={{ borderBottom: '1px solid rgba(240,235,224,0.08)', marginBottom: 44 }}>
          <Tab label="Hardware Device" active={tab === 'hardware'} onClick={() => setTab('hardware')} />
          <Tab label="File / Folder" active={tab === 'file'} onClick={() => setTab('file')} />
        </div>
        {tab === 'hardware' && <HardwareWipe />}
        {tab === 'file' && <FileWipe />}
      </div>
      <ArtworkPanel />
    </div>
  )
}