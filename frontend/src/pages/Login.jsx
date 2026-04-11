import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../components/Toast'
import ArtworkPanel from '../components/ArtworkPanel'

function Field({ label, type = 'text', value, onChange, required, autoFocus, rightSlot }) {
  const [focused, setFocused] = useState(false)
  return (
    <div style={{ marginBottom: 22 }}>
      <label style={{
        display: 'block', fontFamily: 'var(--mono)', fontSize: 7,
        letterSpacing: '0.28em', textTransform: 'uppercase',
        color: focused ? 'var(--parchment)' : 'rgba(240,235,224,0.22)',
        marginBottom: 6, transition: 'color 0.2s',
      }}>{label}</label>
      <div style={{ position: 'relative' }}>
        <input
          type={type} value={value} onChange={onChange}
          required={required} autoFocus={autoFocus}
          onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
          style={{
            width: '100%',
            background: focused ? 'rgba(240,235,224,0.055)' : 'rgba(240,235,224,0.03)',
            border: `1px solid ${focused ? 'rgba(196,180,138,0.55)' : 'rgba(240,235,224,0.1)'}`,
            color: 'var(--cream)', fontFamily: 'var(--mono)', fontSize: 11,
            letterSpacing: '0.04em', padding: rightSlot ? '12px 44px 12px 14px' : '12px 14px',
            outline: 'none', transition: 'border-color 0.2s, background 0.2s',
            cursor: 'crosshair', boxSizing: 'border-box', display: 'block',
          }}
        />
        {rightSlot && (
          <div style={{ position: 'absolute', right: 0, top: 0, bottom: 0, display: 'flex', alignItems: 'center', paddingRight: 14 }}>
            {rightSlot}
          </div>
        )}
      </div>
    </div>
  )
}

function EyeBtn({ show, onToggle }) {
  return (
    <button type="button" onClick={onToggle} style={{
      background: 'none', border: 'none', cursor: 'crosshair',
      color: show ? 'var(--parchment)' : 'rgba(240,235,224,0.25)',
      padding: 0, transition: 'color 0.2s', lineHeight: 1,
    }}>
      {show ? (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
          <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
          <line x1="1" y1="1" x2="23" y2="23" />
        </svg>
      ) : (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
          <circle cx="12" cy="12" r="3" />
        </svg>
      )}
    </button>
  )
}

function SubmitBtn({ loading, children }) {
  return (
    <button type="submit" disabled={loading} style={{
      width: '100%', marginTop: 8, fontFamily: 'var(--mono)', fontSize: 9,
      letterSpacing: '0.22em', textTransform: 'uppercase',
      color: loading ? 'rgba(26,34,24,0.5)' : 'var(--ink)',
      background: loading ? 'rgba(196,180,138,0.45)' : 'var(--cream)',
      border: 'none', padding: '15px 34px',
      cursor: loading ? 'wait' : 'crosshair',
      boxShadow: loading ? 'none' : '3px 3px 0 var(--sage)',
      transition: 'all 0.15s',
    }}
      onMouseEnter={e => { if (!loading) { e.currentTarget.style.transform = 'translate(-2px,-2px)'; e.currentTarget.style.boxShadow = '5px 5px 0 var(--sage)' } }}
      onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = loading ? 'none' : '3px 3px 0 var(--sage)' }}
    >{children}</button>
  )
}

function GhostBtn({ onClick, children }) {
  return (
    <button type="button" onClick={onClick} style={{
      fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.18em',
      textTransform: 'uppercase', color: 'rgba(240,235,224,0.28)',
      background: 'none', border: 'none', borderBottom: '1px solid rgba(240,235,224,0.1)',
      paddingBottom: 2, cursor: 'crosshair', transition: 'color 0.2s, border-color 0.2s',
    }}
      onMouseEnter={e => { e.currentTarget.style.color = 'var(--cream)'; e.currentTarget.style.borderColor = 'rgba(240,235,224,0.4)' }}
      onMouseLeave={e => { e.currentTarget.style.color = 'rgba(240,235,224,0.28)'; e.currentTarget.style.borderColor = 'rgba(240,235,224,0.1)' }}
    >{children}</button>
  )
}

function ResetSentScreen({ email, onBack }) {
  return (
    <div>
      <div style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 48, letterSpacing: '-0.02em', color: 'var(--cream)', lineHeight: 1, marginBottom: 8 }}>OBLVN</div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 7.5, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.22)', marginBottom: 52 }}>Secure Data Obliteration</div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.2)', marginBottom: 24 }}>Password Reset</div>
      <div style={{ fontFamily: 'var(--serif)', fontWeight: 700, fontSize: 32, letterSpacing: '-0.01em', color: 'var(--cream)', lineHeight: 1.05, marginBottom: 24 }}>Email sent.</div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.06em', color: 'rgba(240,235,224,0.38)', lineHeight: 1.85, marginBottom: 32 }}>
        A reset link has been sent to<br />
        <span style={{ color: 'var(--parchment)' }}>{email}</span>.<br /><br />
        Follow the link to set a new password,<br />then return here to sign in.
      </div>
      <div style={{ background: 'rgba(74,84,66,0.15)', border: '1px solid rgba(74,84,66,0.3)', padding: '14px 18px', marginBottom: 32 }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 7.5, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.25)', lineHeight: 1.85 }}>
          No email? Check spam. Links expire in 1 hour.
        </div>
      </div>
      <GhostBtn onClick={onBack}>← Back to Sign In</GhostBtn>
    </div>
  )
}

export default function Login() {
  const { login, resetPassword, user, loading } = useAuth()
  const toast = useToast()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [mode, setMode] = useState('login')
  const [resetSent, setResetSent] = useState(false)

  const invitedEmail = searchParams.get('email') || ''
  const isInvite = !!searchParams.get('invite') || !!invitedEmail

  useEffect(() => {
    if (!loading && user) navigate('/dashboard', { replace: true })
  }, [user, loading, navigate])

  useEffect(() => {
    if (invitedEmail) setEmail(invitedEmail)
  }, [invitedEmail])

  function switchToReset() { setMode('reset'); setPassword('') }
  function switchToLogin() { setMode('login'); setResetSent(false) }

  async function handleLogin(e) {
    e.preventDefault()
    setSubmitting(true)
    try {
      await login(email, password)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      const msg = err?.message || ''
      if (msg.includes('Invalid login') || msg.includes('invalid_credentials')) {
        toast('Incorrect email or password.', 'error')
      } else if (msg.includes('confirm') || msg.includes('not confirmed')) {
        toast('Please confirm your email before signing in.', 'error')
      } else {
        toast(msg || 'Sign in failed.', 'error')
      }
    } finally {
      setSubmitting(false)
    }
  }

  async function handleReset(e) {
    e.preventDefault()
    setSubmitting(true)
    try {
      await resetPassword(email)
      setResetSent(true)
    } catch (err) {
      toast(err?.message || 'Could not send reset email.', 'error')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) return null

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)', cursor: 'crosshair' }}>
      {/* LEFT — form content, same padding as all other pages */}
      <div style={{ padding: '52px', maxWidth: 1000 }}>

        {mode === 'reset' && resetSent ? (
          <ResetSentScreen email={email} onBack={switchToLogin} />
        ) : (
          <>
            {/* Brand */}
            <div style={{ marginBottom: 52 }}>
              <div style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 48, letterSpacing: '-0.02em', color: 'var(--cream)', lineHeight: 1 }}>OBLVN</div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 7.5, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.22)', marginTop: 8 }}>Secure Data Obliteration</div>
            </div>

            {isInvite && (
              <div style={{ background: 'rgba(74,84,66,0.2)', border: '1px solid rgba(74,84,66,0.45)', padding: '14px 18px', marginBottom: 28 }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.22em', textTransform: 'uppercase', color: 'var(--parchment)', marginBottom: 6 }}>
                  Organisation Invite
                </div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 8.5, letterSpacing: '0.04em', color: 'rgba(240,235,224,0.45)', lineHeight: 1.75 }}>
                  You've been invited to join an organisation.<br />Sign in below to accept your role.
                </div>
              </div>
            )}

            <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.2)', marginBottom: 28, display: 'flex', alignItems: 'center', gap: 12 }}>
              <span>{mode === 'reset' ? 'Reset Password' : 'Sign In'}</span>
              <div style={{ flex: 1, height: 1, background: 'rgba(240,235,224,0.07)' }} />
            </div>

            <div style={{ maxWidth: 400 }}>
              {mode === 'login' && (
                <form onSubmit={handleLogin}>
                  <Field label="Email Address" type="email" value={email}
                    onChange={e => setEmail(e.target.value)} required
                    autoFocus={!invitedEmail} />
                  <Field label="Password" type={showPw ? 'text' : 'password'}
                    value={password} onChange={e => setPassword(e.target.value)} required
                    autoFocus={!!invitedEmail}
                    rightSlot={<EyeBtn show={showPw} onToggle={() => setShowPw(p => !p)} />}
                  />
                  <div style={{ marginTop: -14, marginBottom: 20, textAlign: 'right' }}>
                    <GhostBtn onClick={switchToReset}>Forgot password?</GhostBtn>
                  </div>
                  <SubmitBtn loading={submitting}>
                    {submitting ? 'Signing in…' : isInvite ? 'Sign In & Join Org →' : 'Sign In →'}
                  </SubmitBtn>
                </form>
              )}

              {mode === 'reset' && (
                <form onSubmit={handleReset}>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.06em', color: 'rgba(240,235,224,0.35)', lineHeight: 1.85, marginBottom: 24 }}>
                    Enter your email and we'll send a reset link.
                  </div>
                  <Field label="Email Address" type="email" value={email}
                    onChange={e => setEmail(e.target.value)} required autoFocus />
                  <SubmitBtn loading={submitting}>
                    {submitting ? 'Sending…' : 'Send Reset Email →'}
                  </SubmitBtn>
                  <div style={{ marginTop: 20 }}>
                    <GhostBtn onClick={switchToLogin}>← Back to Sign In</GhostBtn>
                  </div>
                </form>
              )}

              <div style={{ margin: '28px 0', display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ flex: 1, height: 1, background: 'rgba(240,235,224,0.06)' }} />
                <span style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.2em', color: 'rgba(240,235,224,0.18)', textTransform: 'uppercase' }}>or</span>
                <div style={{ flex: 1, height: 1, background: 'rgba(240,235,224,0.06)' }} />
              </div>

              <div style={{ textAlign: 'center' }}>
                <Link to="/register" style={{
                  fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.18em',
                  textTransform: 'uppercase', color: 'rgba(240,235,224,0.3)',
                  textDecoration: 'none', borderBottom: '1px solid rgba(240,235,224,0.1)', paddingBottom: 2,
                }}
                  onMouseEnter={e => { e.currentTarget.style.color = 'var(--cream)'; e.currentTarget.style.borderColor = 'rgba(240,235,224,0.4)' }}
                  onMouseLeave={e => { e.currentTarget.style.color = 'rgba(240,235,224,0.3)'; e.currentTarget.style.borderColor = 'rgba(240,235,224,0.1)' }}
                >
                  No account? Create one
                </Link>
              </div>

              <div style={{ marginTop: 60, paddingTop: 24, borderTop: '1px solid rgba(240,235,224,0.06)', display: 'flex', justifyContent: 'space-between' }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.12)' }}>GDPR · HIPAA · NIST</div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.12)' }}>© 2026 OBLVN</div>
              </div>
            </div>
          </>
        )}
      </div>

      {/* RIGHT — artwork panel, identical to all other pages */}
      <ArtworkPanel />
    </div>
  )
}