import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'

const NAV = [
  { path: '/dashboard', label: 'Dashboard' },
  { path: '/devices', label: 'Devices' },
  { path: '/jobs', label: 'Wipe Jobs' },
  { path: '/certificates', label: 'Certificates' },
  { path: '/audit', label: 'Audit Log' },
  { path: '/anomalies', label: 'Anomalies' },
  { path: '/org', label: 'Organisation' },
  { path: '/settings', label: 'Settings' },
]

export default function Layout({ children }) {
  const { logout } = useAuth()
  const navigate = useNavigate()

  async function handleLogout() {
    await logout()
    navigate('/login')
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <nav style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 700,
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '22px 52px',
        borderBottom: '1px solid var(--ink-line)',
        background: 'var(--ink)',
      }}>
        <a
          href="/"
          style={{
            fontFamily: 'var(--serif)', fontWeight: 900, fontSize: 22,
            letterSpacing: '-0.02em', color: 'var(--cream)', textDecoration: 'none',
          }}
        >
          OBLVN
        </a>
        <ul style={{ listStyle: 'none', display: 'flex', gap: 28, alignItems: 'center', margin: 0, padding: 0 }}>
          {NAV.map(n => (
            <li key={n.path}>
              <NavLink
                to={n.path}
                style={({ isActive }) => ({
                  fontFamily: 'var(--mono)',
                  fontSize: 9,
                  letterSpacing: '0.18em',
                  textTransform: 'uppercase',
                  textDecoration: 'none',
                  color: isActive ? 'var(--cream)' : 'rgba(240,235,224,0.28)',
                  transition: 'color 0.2s',
                })}
              >
                {n.label}
              </NavLink>
            </li>
          ))}
          <li>
            <button
              onClick={handleLogout}
              style={{
                fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.18em',
                textTransform: 'uppercase', color: 'rgba(240,235,224,0.28)',
                background: 'none', border: 'none', cursor: 'crosshair',
                transition: 'color 0.2s',
              }}
              onMouseEnter={e => e.currentTarget.style.color = 'var(--cream)'}
              onMouseLeave={e => e.currentTarget.style.color = 'rgba(240,235,224,0.28)'}
            >
              Sign Out
            </button>
          </li>
        </ul>
      </nav>
      <main style={{ flex: 1, paddingTop: 80 }}>
        {children}
      </main>
    </div>
  )
}