import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './hooks/useAuth'
import Layout from './components/Layout'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import Devices from './pages/Devices'
import Jobs from './pages/Jobs'
import JobDetail from './pages/JobDetail'
import Certificates from './pages/Certificates'
import AuditLog from './pages/AuditLog'
import Anomalies from './pages/Anomalies'
import Organisation from './pages/Organisation'
import Settings from './pages/Settings'

function Guard({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <div style={{ minHeight: '100vh', background: 'var(--ink)' }} />
  if (!user) return <Navigate to="/login" replace />
  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      <Route path="/*" element={
        <Guard>
          <Layout>
            <Routes>
              <Route path="dashboard" element={<Dashboard />} />
              <Route path="devices" element={<Devices />} />
              <Route path="jobs" element={<Jobs />} />
              <Route path="jobs/:id" element={<JobDetail />} />
              <Route path="certificates" element={<Certificates />} />
              <Route path="audit" element={<AuditLog />} />
              <Route path="anomalies" element={<Anomalies />} />
              <Route path="org" element={<Organisation />} />
              <Route path="settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="dashboard" replace />} />
            </Routes>
          </Layout>
        </Guard>
      } />
    </Routes>
  )
}