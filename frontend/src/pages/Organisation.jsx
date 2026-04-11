import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'
import SectionRule from '../components/SectionRule'
import { BtnSolid, BtnGhost, BtnDanger } from '../components/Btn'
import { Input, Select, Field } from '../components/Field'
import ArtworkPanel from '../components/ArtworkPanel'

const ROLES = [
  { value: 'operator', label: 'Operator' },
  { value: 'team_lead', label: 'Team Lead' },
  { value: 'org_admin', label: 'Org Admin' },
]

const SENSITIVITY = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
]

export default function Organisation() {
  const toast = useToast()
  const [org, setOrg] = useState(null)
  const [members, setMembers] = useState([])
  const [loading, setLoading] = useState(true)
  const [orgId, setOrgId] = useState(null)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('operator')
  const [inviting, setInviting] = useState(false)
  const [creating, setCreating] = useState(false)
  const [newOrgName, setNewOrgName] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    const stored = localStorage.getItem('oblvn_org_id')
    if (stored) {
      setOrgId(stored)
      loadOrg(stored)
    } else {
      setLoading(false)
    }
  }, [])

  function loadOrg(id) {
    Promise.all([
      api.orgs.listMembers(id).then(d => setMembers(d.members || [])),
    ]).finally(() => setLoading(false))
  }

  async function createOrg() {
    setCreating(true)
    try {
      const created = await api.orgs.create({ name: newOrgName })
      localStorage.setItem('oblvn_org_id', created.id)
      setOrgId(created.id)
      setOrg(created)
      toast('Organisation created', 'success')
      loadOrg(created.id)
    } catch (err) { toast(err.message, 'error') }
    finally { setCreating(false) }
  }

  async function invite() {
    setInviting(true)
    try {
      await api.orgs.invite(orgId, { email: inviteEmail, role: inviteRole })
      toast(`Invite sent to ${inviteEmail}`, 'success')
      setInviteEmail('')
      loadOrg(orgId)
    } catch (err) { toast(err.message, 'error') }
    finally { setInviting(false) }
  }

  async function revoke(userId) {
    try {
      await api.orgs.revoke(orgId, userId)
      toast('Access revoked', 'success')
      loadOrg(orgId)
    } catch (err) { toast(err.message, 'error') }
  }

  async function changeRole(userId, role) {
    try {
      await api.orgs.changeRole(orgId, userId, role)
      toast('Role updated', 'success')
      loadOrg(orgId)
    } catch (err) { toast(err.message, 'error') }
  }

  async function saveSettings(update) {
    setSaving(true)
    try {
      await api.orgs.update(orgId, update)
      toast('Settings saved', 'success')
    } catch (err) { toast(err.message, 'error') }
    finally { setSaving(false) }
  }

  if (loading) return <div style={{ padding: 52, fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.3)' }}>Loading...</div>

  if (!orgId) {
    return (
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)' }}>
        <div style={{ padding: '52px', maxWidth: 600 }}>
          <SectionRule label="Organisation" num="06" />
          <h2 style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 48, lineHeight: 0.9, marginBottom: 40 }}>Create<br /><em style={{ color: 'rgba(240,235,224,0.55)' }}>Organisation.</em></h2>
          <Input label="Organisation Name" value={newOrgName} onChange={e => setNewOrgName(e.target.value)} />
          <BtnSolid onClick={createOrg} disabled={creating || !newOrgName.trim()}>
            {creating ? 'Creating...' : 'Create Organisation'}
          </BtnSolid>
        </div>
        <ArtworkPanel />
      </div>
    )
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)' }}>
      <div style={{ padding: '52px', maxWidth: 1000 }}>
        <SectionRule label="Organisation" num="06" />

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 80, marginBottom: 72 }}>
          <div>
            <h2 style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 48, lineHeight: 0.9, marginBottom: 40 }}>
              Team<br /><em style={{ color: 'rgba(240,235,224,0.55)' }}>Management.</em>
            </h2>

            <div style={{ borderTop: '1px solid rgba(240,235,224,0.08)', paddingTop: 24, marginBottom: 40 }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.24em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.25)', marginBottom: 20 }}>Members</div>
              {members.map(m => (
                <div key={m.id} style={{ display: 'grid', gridTemplateColumns: '1fr 120px 80px', gap: 12, padding: '12px 0', borderBottom: '1px solid rgba(240,235,224,0.05)', alignItems: 'center' }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'rgba(240,235,224,0.6)', overflow: 'hidden', textOverflow: 'ellipsis' }}>{m.user_id?.slice(0, 20)}...</span>
                  <select value={m.role} onChange={e => changeRole(m.user_id, e.target.value)} style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--cream)', background: 'rgba(240,235,224,0.04)', border: '1px solid rgba(240,235,224,0.1)', padding: '4px 8px' }}>
                    {ROLES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
                  </select>
                  <BtnDanger onClick={() => revoke(m.user_id)} style={{ padding: '6px 10px', fontSize: 7 }}>Revoke</BtnDanger>
                </div>
              ))}
            </div>

            <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.24em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.25)', marginBottom: 16 }}>Invite Member</div>
            <Input label="Email" type="email" value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} />
            <Select label="Role" value={inviteRole} onChange={e => setInviteRole(e.target.value)} options={ROLES} />
            <BtnSolid onClick={invite} disabled={inviting || !inviteEmail.trim()}>
              {inviting ? 'Sending...' : 'Send Invite'}
            </BtnSolid>
          </div>

          <div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.24em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.25)', marginBottom: 24 }}>Settings</div>
            <div style={{ marginBottom: 24 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'crosshair' }}>
                <input type="checkbox" onChange={e => saveSettings({ approval_gate_enabled: e.target.checked })} style={{ cursor: 'crosshair' }} />
                <span style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.12em', color: 'rgba(240,235,224,0.6)' }}>Enable approval gate for operators</span>
              </label>
            </div>
            <Select label="Anomaly Detection Sensitivity" value="medium" onChange={e => saveSettings({ anomaly_sensitivity: e.target.value })} options={SENSITIVITY} />
            <Input label="Audit Retention (days)" type="number" placeholder="2555" onChange={e => saveSettings({ audit_retention_days: parseInt(e.target.value) })} />
          </div>
        </div>
      </div>
      <ArtworkPanel />
    </div>
  )
}