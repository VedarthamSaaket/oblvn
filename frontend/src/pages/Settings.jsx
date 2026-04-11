import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../components/Toast'
import SectionRule from '../components/SectionRule'
import ArtworkPanel from '../components/ArtworkPanel'

function SettingRow({ label, description, children }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 40, padding: '28px 0', borderBottom: '1px solid rgba(240,235,224,0.06)', alignItems: 'start' }}>
      <div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.7)', marginBottom: 6 }}>{label}</div>
        {description && <div style={{ fontFamily: 'var(--sans)', fontWeight: 300, fontSize: 10, color: 'rgba(240,235,224,0.32)', lineHeight: 1.75 }}>{description}</div>}
      </div>
      <div style={{ display: 'flex', alignItems: 'center' }}>{children}</div>
    </div>
  )
}

function Toggle({ value, onChange, label }) {
  return (
    <label style={{ display: 'flex', alignItems: 'center', gap: 14, cursor: 'crosshair' }}>
      <div onClick={() => onChange(!value)} style={{ width: 44, height: 24, borderRadius: 0, background: value ? 'var(--parchment)' : 'rgba(240,235,224,0.1)', border: `1px solid ${value ? 'var(--parchment)' : 'rgba(240,235,224,0.15)'}`, position: 'relative', cursor: 'crosshair', transition: 'all 0.2s', flexShrink: 0 }}>
        <div style={{ position: 'absolute', top: 3, left: value ? 23 : 3, width: 16, height: 16, background: value ? 'var(--ink)' : 'rgba(240,235,224,0.3)', transition: 'left 0.2s, background 0.2s' }} />
      </div>
      {label && <span style={{ fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.1em', color: value ? 'rgba(240,235,224,0.7)' : 'rgba(240,235,224,0.3)', transition: 'color 0.2s' }}>{label}</span>}
    </label>
  )
}

function SelectInput({ value, onChange, options }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)} style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.1em', color: 'var(--cream)', background: 'rgba(240,235,224,0.04)', border: '1px solid rgba(240,235,224,0.12)', padding: '10px 14px', cursor: 'crosshair', outline: 'none', width: '100%' }}>
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  )
}

function SectionHeading({ label }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 0, marginBottom: 8, marginTop: 48 }}>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 7.5, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(196,180,138,0.5)', paddingRight: 16, flexShrink: 0 }}>{label}</span>
      <div style={{ flex: 1, height: 1, background: 'rgba(196,180,138,0.12)' }} />
    </div>
  )
}

export default function Settings() {
  const { user, logout } = useAuth()
  const toast = useToast()

  const [notifications, setNotifications] = useState({ wipeComplete: true, anomalyAlert: true, approvalRequired: true, chainVerificationFail: true, weeklyReport: false, loginAlert: true })
  const [security, setSecurity] = useState({ requireApproval: false, autoLogout: '30', sessionTimeout: '8h', ipRestriction: false, twoFactor: false, auditEverything: true })
  const [wipe, setWipe] = useState({ defaultMethod: 'binary_overwrite', defaultStandard: 'dod_5220_22m', alwaysConfirm: true, generateCertificate: true, bitcoinAnchor: true, smartSnapshot: true, verifyAfterWipe: true, retentionDays: '2555' })
  const [display, setDisplay] = useState({ dateFormat: 'iso', timezone: 'utc', compactView: false, showSerial: true, defaultTab: 'dashboard' })

  function save(section) { toast(`${section} settings saved`, 'success') }

  function SaveBtn({ section }) {
    return (
      <button onClick={() => save(section)} style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'var(--ink)', background: 'var(--cream)', border: 'none', padding: '10px 22px', cursor: 'crosshair', boxShadow: '2px 2px 0 var(--sage)', transition: 'all 0.15s', marginTop: 24 }}
        onMouseEnter={e => { e.currentTarget.style.transform = 'translate(-2px,-2px)'; e.currentTarget.style.boxShadow = '4px 4px 0 var(--sage)' }}
        onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = '2px 2px 0 var(--sage)' }}>
        Save Changes
      </button>
    )
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)' }}>
      <div style={{ padding: '52px', maxWidth: 900 }}>
        <SectionRule label="Settings" num="08" />

        <div style={{ marginBottom: 48 }}>
          <h2 style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 'clamp(36px, 4vw, 52px)', lineHeight: 0.9, letterSpacing: '-0.02em', marginBottom: 12 }}>
            Preferences &amp;<br /><em style={{ color: 'rgba(240,235,224,0.5)' }}>Controls.</em>
          </h2>
          <p style={{ fontFamily: 'var(--sans)', fontWeight: 300, fontSize: 10.5, color: 'rgba(240,235,224,0.35)', lineHeight: 1.8, maxWidth: 400 }}>
            configure your workspace, defaults, and security posture.
          </p>
        </div>

        <div style={{ padding: '20px 24px', background: 'rgba(196,180,138,0.06)', border: '1px solid rgba(196,180,138,0.12)', marginBottom: 48 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(196,180,138,0.5)', marginBottom: 6 }}>Current Account</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--cream)', letterSpacing: '0.06em' }}>{user?.email || 'Not signed in'}</div>
        </div>

        <SectionHeading label="Notifications" />
        <SettingRow label="Wipe Complete" description="Notify when a wipe job finishes successfully."><Toggle value={notifications.wipeComplete} onChange={v => setNotifications(p => ({ ...p, wipeComplete: v }))} label={notifications.wipeComplete ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Anomaly Alerts" description="Alert when the system detects suspicious activity or S.M.A.R.T. anomalies."><Toggle value={notifications.anomalyAlert} onChange={v => setNotifications(p => ({ ...p, anomalyAlert: v }))} label={notifications.anomalyAlert ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Approval Required" description="Notify team leads when a wipe job is queued and needs approval."><Toggle value={notifications.approvalRequired} onChange={v => setNotifications(p => ({ ...p, approvalRequired: v }))} label={notifications.approvalRequired ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Chain Verification Failure" description="Alert immediately if the audit log chain integrity check fails."><Toggle value={notifications.chainVerificationFail} onChange={v => setNotifications(p => ({ ...p, chainVerificationFail: v }))} label={notifications.chainVerificationFail ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Login Alerts" description="Notify on sign-in from a new IP address."><Toggle value={notifications.loginAlert} onChange={v => setNotifications(p => ({ ...p, loginAlert: v }))} label={notifications.loginAlert ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Weekly Summary" description="Receive a weekly digest of wipe activity and audit status."><Toggle value={notifications.weeklyReport} onChange={v => setNotifications(p => ({ ...p, weeklyReport: v }))} label={notifications.weeklyReport ? 'On' : 'Off'} /></SettingRow>
        <SaveBtn section="Notification" />

        <SectionHeading label="Security" />
        <SettingRow label="Two-Factor Authentication" description="Require TOTP verification on every login. Managed via Supabase MFA."><Toggle value={security.twoFactor} onChange={v => setSecurity(p => ({ ...p, twoFactor: v }))} label={security.twoFactor ? 'Enabled' : 'Disabled'} /></SettingRow>
        <SettingRow label="Require Approval Gate" description="All wipe jobs created by operators must be approved by a Team Lead before executing."><Toggle value={security.requireApproval} onChange={v => setSecurity(p => ({ ...p, requireApproval: v }))} label={security.requireApproval ? 'Enabled' : 'Disabled'} /></SettingRow>
        <SettingRow label="Audit Everything" description="Log all read events, not just write events."><Toggle value={security.auditEverything} onChange={v => setSecurity(p => ({ ...p, auditEverything: v }))} label={security.auditEverything ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="IP Restriction" description="Restrict access to a whitelist of IP addresses. Configure via Supabase Auth settings."><Toggle value={security.ipRestriction} onChange={v => setSecurity(p => ({ ...p, ipRestriction: v }))} label={security.ipRestriction ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Auto Logout" description="Automatically sign out after a period of inactivity.">
          <SelectInput value={security.autoLogout} onChange={v => setSecurity(p => ({ ...p, autoLogout: v }))} options={[{ value: '15', label: '15 minutes' }, { value: '30', label: '30 minutes' }, { value: '60', label: '1 hour' }, { value: '240', label: '4 hours' }, { value: 'never', label: 'Never' }]} />
        </SettingRow>
        <SaveBtn section="Security" />

        <SectionHeading label="Wipe Defaults" />
        <SettingRow label="Default Method" description="Pre-select this wipe method when creating a new job.">
          <SelectInput value={wipe.defaultMethod} onChange={v => setWipe(p => ({ ...p, defaultMethod: v }))} options={[{ value: 'binary_overwrite', label: 'Binary Obliteration' }, { value: 'crypto_erase', label: 'Crypto Erasure' }, { value: 'full_sanitization', label: 'Full Sanitization' }]} />
        </SettingRow>
        <SettingRow label="Default Standard" description="Pre-select this compliance standard when creating a new job.">
          <SelectInput value={wipe.defaultStandard} onChange={v => setWipe(p => ({ ...p, defaultStandard: v }))} options={[{ value: 'dod_5220_22m', label: 'DoD 5220.22-M (3 pass)' }, { value: 'gutmann', label: 'Gutmann (35 pass)' }, { value: 'nist_800_88', label: 'NIST 800-88 (1 pass)' }]} />
        </SettingRow>
        <SettingRow label="Always Confirm" description="Require a second confirmation step before starting any wipe job."><Toggle value={wipe.alwaysConfirm} onChange={v => setWipe(p => ({ ...p, alwaysConfirm: v }))} label={wipe.alwaysConfirm ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Generate Certificate" description="Automatically issue a certificate of destruction for every completed wipe."><Toggle value={wipe.generateCertificate} onChange={v => setWipe(p => ({ ...p, generateCertificate: v }))} label={wipe.generateCertificate ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Bitcoin Anchor" description="Submit certificate hash to OpenTimestamps on the Bitcoin blockchain after every wipe."><Toggle value={wipe.bitcoinAnchor} onChange={v => setWipe(p => ({ ...p, bitcoinAnchor: v }))} label={wipe.bitcoinAnchor ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="S.M.A.R.T. Snapshot" description="Capture drive health data before each wipe and include it in the certificate."><Toggle value={wipe.smartSnapshot} onChange={v => setWipe(p => ({ ...p, smartSnapshot: v }))} label={wipe.smartSnapshot ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Verify After Wipe" description="Run a read-back verification pass after overwriting to confirm zero data remains."><Toggle value={wipe.verifyAfterWipe} onChange={v => setWipe(p => ({ ...p, verifyAfterWipe: v }))} label={wipe.verifyAfterWipe ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Audit Retention" description="How many days to retain audit log entries. 2555 days is 7 years.">
          <SelectInput value={wipe.retentionDays} onChange={v => setWipe(p => ({ ...p, retentionDays: v }))} options={[{ value: '365', label: '1 year' }, { value: '1095', label: '3 years' }, { value: '2555', label: '7 years (recommended)' }, { value: '3650', label: '10 years' }, { value: 'forever', label: 'Forever' }]} />
        </SettingRow>
        <SaveBtn section="Wipe Default" />

        <SectionHeading label="Display" />
        <SettingRow label="Date Format" description="How timestamps are shown throughout the application.">
          <SelectInput value={display.dateFormat} onChange={v => setDisplay(p => ({ ...p, dateFormat: v }))} options={[{ value: 'iso', label: 'ISO 8601 (2026-03-22T09:14Z)' }, { value: 'local', label: 'Local (22 Mar 2026, 09:14)' }, { value: 'us', label: 'US (Mar 22, 2026 9:14 AM)' }]} />
        </SettingRow>
        <SettingRow label="Timezone" description="Display times in this timezone.">
          <SelectInput value={display.timezone} onChange={v => setDisplay(p => ({ ...p, timezone: v }))} options={[{ value: 'utc', label: 'UTC' }, { value: 'local', label: 'Browser local time' }]} />
        </SettingRow>
        <SettingRow label="Show Serial Numbers" description="Display device serial numbers in job lists and the dashboard."><Toggle value={display.showSerial} onChange={v => setDisplay(p => ({ ...p, showSerial: v }))} label={display.showSerial ? 'Shown' : 'Hidden'} /></SettingRow>
        <SettingRow label="Compact View" description="Reduce row height in job tables for higher information density."><Toggle value={display.compactView} onChange={v => setDisplay(p => ({ ...p, compactView: v }))} label={display.compactView ? 'On' : 'Off'} /></SettingRow>
        <SettingRow label="Default Landing Tab" description="Which page to show after signing in.">
          <SelectInput value={display.defaultTab} onChange={v => setDisplay(p => ({ ...p, defaultTab: v }))} options={[{ value: 'dashboard', label: 'Dashboard' }, { value: 'jobs', label: 'Wipe Jobs' }, { value: 'devices', label: 'New Wipe Job' }]} />
        </SettingRow>
        <SaveBtn section="Display" />

        <SectionHeading label="Danger Zone" />
        <div style={{ padding: '28px', border: '1px solid rgba(196,74,66,0.3)', background: 'rgba(196,74,66,0.04)', marginTop: 8 }}>
          <div style={{ fontFamily: 'var(--serif)', fontStyle: 'italic', fontSize: 20, color: 'rgba(240,235,224,0.7)', marginBottom: 8 }}>Sign out of all devices</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.1em', color: 'rgba(240,235,224,0.3)', lineHeight: 1.85, marginBottom: 20 }}>
            Invalidates all active sessions. You will be signed out immediately.
          </div>
          <button onClick={logout} style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.2em', textTransform: 'uppercase', color: '#c44a42', background: 'rgba(196,74,66,0.08)', border: '1px solid rgba(196,74,66,0.3)', padding: '10px 22px', cursor: 'crosshair', transition: 'all 0.15s' }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(196,74,66,0.16)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'rgba(196,74,66,0.08)' }}>
            Sign Out Everywhere
          </button>
        </div>
      </div>
      <ArtworkPanel />
    </div>
  )
}