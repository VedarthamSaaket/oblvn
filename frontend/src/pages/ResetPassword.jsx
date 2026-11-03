import { useState } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'
import ArtworkPanel from '../components/ArtworkPanel'
import { EyeBtn, Field, SubmitBtn } from './Login'

export default function ResetPassword() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const toast = useToast()
  const token = searchParams.get('token') || ''
  const isInvite = searchParams.get('invite') === '1'
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (password !== confirm) {
      toast('The two passwords do not match.', 'error')
      return
    }
    setSubmitting(true)
    try {
      await api.auth.updatePassword(token, password, isInvite)
      toast(isInvite ? 'Account activated. Sign in to continue.' : 'Password updated. Sign in with your new password.', 'success')
      navigate('/login', { replace: true })
    } catch (err) {
      toast(err?.message || 'Could not update the password.', 'error')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)', cursor: 'crosshair' }}>
      <div style={{ padding: '52px', maxWidth: 1000 }}>
        <div style={{ marginBottom: 52 }}>
          <div style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 48, letterSpacing: '-0.02em', color: 'var(--cream)', lineHeight: 1 }}>OBLVN</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 7.5, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.22)', marginTop: 8 }}>Secure Data Obliteration</div>
        </div>

        <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.2)', marginBottom: 28, display: 'flex', alignItems: 'center', gap: 12 }}>
          <span>{isInvite ? 'Accept Invite' : 'Set New Password'}</span>
          <div style={{ flex: 1, height: 1, background: 'rgba(240,235,224,0.07)' }} />
        </div>

        <div style={{ maxWidth: 400 }}>
          {!token ? (
            <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.06em', color: 'rgba(240,235,224,0.35)', lineHeight: 1.85 }}>
              This link is missing its token. Open the link from your email again, or request a new one from the sign in page.
            </div>
          ) : (
            <form onSubmit={handleSubmit}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.06em', color: 'rgba(240,235,224,0.35)', lineHeight: 1.85, marginBottom: 24 }}>
                {isInvite
                  ? 'Choose a password to activate your account and join your organisation.'
                  : 'Choose a new password. Every other signed-in device will be signed out.'}
              </div>
              <Field label="New Password" type={showPw ? 'text' : 'password'} value={password}
                onChange={e => setPassword(e.target.value)} required autoFocus
                rightSlot={<EyeBtn show={showPw} onToggle={() => setShowPw(p => !p)} />} />
              <Field label="Confirm Password" type={showPw ? 'text' : 'password'} value={confirm}
                onChange={e => setConfirm(e.target.value)} required />
              <SubmitBtn loading={submitting}>
                {submitting ? 'Saving…' : isInvite ? 'Activate Account →' : 'Update Password →'}
              </SubmitBtn>
            </form>
          )}

          <div style={{ marginTop: 28, textAlign: 'center' }}>
            <Link to="/login" style={{
              fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.18em', textTransform: 'uppercase',
              color: 'rgba(240,235,224,0.3)', textDecoration: 'none', borderBottom: '1px solid rgba(240,235,224,0.1)', paddingBottom: 2,
            }}>← Back to Sign In</Link>
          </div>
        </div>
      </div>
      <ArtworkPanel />
    </div>
  )
}
