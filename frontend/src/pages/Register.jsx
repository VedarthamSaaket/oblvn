import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../components/Toast'
import ArtworkPanel from '../components/ArtworkPanel'

function getStrength(pw) {
    if (!pw) return { score: 0, label: '', color: 'transparent' }
    let score = 0
    if (pw.length >= 6) score++
    if (pw.length >= 10) score++
    if (/[A-Z]/.test(pw)) score++
    if (/[0-9]/.test(pw)) score++
    if (/[^A-Za-z0-9]/.test(pw)) score++
    if (score <= 1) return { score, label: 'Weak', color: '#c44a42' }
    if (score <= 2) return { score, label: 'Fair', color: '#c4913a' }
    if (score <= 3) return { score, label: 'Good', color: '#8aab6e' }
    return { score, label: 'Strong', color: '#c4b48a' }
}

function Field({ label, type = 'text', value, onChange, required, autoFocus, hint, rightSlot }) {
    const [focused, setFocused] = useState(false)
    return (
        <div style={{ marginBottom: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 6 }}>
                <label style={{
                    fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em',
                    textTransform: 'uppercase',
                    color: focused ? 'var(--parchment)' : 'rgba(240,235,224,0.22)',
                    transition: 'color 0.2s',
                }}>{label}</label>
                {hint && <span style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.1em', color: 'rgba(240,235,224,0.18)' }}>{hint}</span>}
            </div>
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

function StrengthBar({ password }) {
    const { score, label, color } = getStrength(password)
    if (!password) return null
    return (
        <div style={{ marginTop: -14, marginBottom: 18 }}>
            <div style={{ display: 'flex', gap: 3, marginBottom: 5 }}>
                {[1, 2, 3, 4].map(i => (
                    <div key={i} style={{
                        flex: 1, height: 2,
                        background: i <= score ? color : 'rgba(240,235,224,0.08)',
                        transition: 'background 0.3s',
                    }} />
                ))}
            </div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.18em', color, textTransform: 'uppercase' }}>
                {label}
            </div>
        </div>
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

function ConfirmScreen({ email }) {
    return (
        <div>
            <div style={{ fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 48, letterSpacing: '-0.02em', color: 'var(--cream)', lineHeight: 1, marginBottom: 8 }}>OBLVN</div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 7.5, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.22)', marginBottom: 52 }}>Secure Data Obliteration</div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.22)', marginBottom: 16 }}>
                Confirmation Required
            </div>
            <div style={{ fontFamily: 'var(--serif)', fontWeight: 700, fontSize: 32, letterSpacing: '-0.01em', color: 'var(--cream)', lineHeight: 1.05, marginBottom: 24 }}>
                Check your<br />inbox.
            </div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.06em', color: 'rgba(240,235,224,0.38)', lineHeight: 1.85, marginBottom: 28 }}>
                A confirmation link has been sent to<br />
                <span style={{ color: 'var(--parchment)' }}>{email}</span>.<br /><br />
                Click the link to activate your account,<br />then return here to sign in.
            </div>
            <div style={{ background: 'rgba(74,84,66,0.15)', border: '1px solid rgba(74,84,66,0.3)', padding: '14px 18px', marginBottom: 32 }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 7.5, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.25)', lineHeight: 1.85 }}>
                    No email? Check spam. Links expire in 24 hours.
                </div>
            </div>
            <Link to="/login" style={{
                display: 'block', width: '100%', textAlign: 'center',
                fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.22em',
                textTransform: 'uppercase', color: 'var(--ink)', background: 'var(--cream)',
                border: 'none', padding: '15px 34px', cursor: 'crosshair',
                boxShadow: '3px 3px 0 var(--sage)', textDecoration: 'none', boxSizing: 'border-box',
            }}>
                Go to Sign In →
            </Link>
        </div>
    )
}

export default function Register() {
    const { register, login } = useAuth()
    const toast = useToast()
    const navigate = useNavigate()
    const [searchParams] = useSearchParams()

    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [showPw, setShowPw] = useState(false)
    const [loading, setLoading] = useState(false)
    const [confirmed, setConfirmed] = useState(false)

    const invitedEmail = searchParams.get('email') || ''
    const isInvite = !!invitedEmail

    useEffect(() => {
        if (invitedEmail) setEmail(invitedEmail)
    }, [invitedEmail])

    async function handleSubmit(e) {
        e.preventDefault()
        if (password.length < 6) {
            toast('Password must be at least 6 characters.', 'error')
            return
        }
        setLoading(true)
        try {
            const result = await register(email, password)
            if (result?.confirm_email) {
                setConfirmed(true)
                return
            }
            await login(email, password)
            toast('Account created. Welcome.', 'success')
            navigate('/dashboard')
        } catch (err) {
            const msg = err?.message || ''
            if (msg.includes('already registered') || msg.includes('already been registered')) {
                toast('This email is already registered. Try signing in.', 'error')
            } else {
                toast(msg || 'Registration failed.', 'error')
            }
        } finally {
            setLoading(false)
        }
    }

    if (confirmed) {
        return (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)', cursor: 'crosshair' }}>
                <div style={{ padding: '52px', maxWidth: 1000 }}>
                    <ConfirmScreen email={email} />
                </div>
                <ArtworkPanel />
            </div>
        )
    }

    return (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', minHeight: 'calc(100vh - 80px)', cursor: 'crosshair' }}>
            {/* LEFT — form content, same padding as all other pages */}
            <div style={{ padding: '52px', maxWidth: 1000 }}>

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
                            You've been invited to join an organisation.<br />Create your account to get started.
                        </div>
                    </div>
                )}

                <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.28em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.2)', marginBottom: 28, display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span>{isInvite ? 'Join Organisation' : 'Create Account'}</span>
                    <div style={{ flex: 1, height: 1, background: 'rgba(240,235,224,0.07)' }} />
                </div>

                <div style={{ maxWidth: 400 }}>
                    <form onSubmit={handleSubmit}>
                        <Field
                            label="Email Address" type="email" value={email}
                            onChange={e => setEmail(e.target.value)} required
                            autoFocus={!isInvite}
                            rightSlot={isInvite ? (
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(196,180,138,0.4)" strokeWidth="1.5">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                </svg>
                            ) : null}
                        />
                        <Field
                            label="Password" type={showPw ? 'text' : 'password'}
                            value={password} onChange={e => setPassword(e.target.value)}
                            required hint="min. 6 chars" autoFocus={isInvite}
                            rightSlot={<EyeBtn show={showPw} onToggle={() => setShowPw(p => !p)} />}
                        />
                        <StrengthBar password={password} />

                        <SubmitBtn loading={loading}>
                            {loading
                                ? 'Creating account…'
                                : isInvite ? 'Create Account & Join Org →' : 'Create Account →'}
                        </SubmitBtn>
                    </form>

                    <div style={{ margin: '28px 0', display: 'flex', alignItems: 'center', gap: 12 }}>
                        <div style={{ flex: 1, height: 1, background: 'rgba(240,235,224,0.06)' }} />
                        <span style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.2em', color: 'rgba(240,235,224,0.18)', textTransform: 'uppercase' }}>or</span>
                        <div style={{ flex: 1, height: 1, background: 'rgba(240,235,224,0.06)' }} />
                    </div>

                    <div style={{ textAlign: 'center' }}>
                        <Link to="/login" style={{
                            fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '0.18em',
                            textTransform: 'uppercase', color: 'rgba(240,235,224,0.3)',
                            textDecoration: 'none', borderBottom: '1px solid rgba(240,235,224,0.1)', paddingBottom: 2,
                        }}
                            onMouseEnter={e => { e.currentTarget.style.color = 'var(--cream)'; e.currentTarget.style.borderColor = 'rgba(240,235,224,0.4)' }}
                            onMouseLeave={e => { e.currentTarget.style.color = 'rgba(240,235,224,0.3)'; e.currentTarget.style.borderColor = 'rgba(240,235,224,0.1)' }}
                        >
                            Already have an account? Sign in
                        </Link>
                    </div>

                    <div style={{ marginTop: 60, paddingTop: 24, borderTop: '1px solid rgba(240,235,224,0.06)', display: 'flex', justifyContent: 'space-between' }}>
                        <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.12)' }}>GDPR · HIPAA · NIST</div>
                        <div style={{ fontFamily: 'var(--mono)', fontSize: 7, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'rgba(240,235,224,0.12)' }}>© 2026 OBLVN</div>
                    </div>
                </div>
            </div>

            {/* RIGHT — artwork panel, identical to all other pages */}
            <ArtworkPanel />
        </div>
    )
}