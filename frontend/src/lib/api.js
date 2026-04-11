const BASE = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:8000/api';

function token() {
  return localStorage.getItem('oblvn_token') || ''
}

function headers(extra = {}) {
  const t = token()
  return {
    'Content-Type': 'application/json',
    ...(t ? { Authorization: `Bearer ${t}` } : {}),
    ...extra,
  }
}

function clearSession() {
  localStorage.removeItem('oblvn_token')
  localStorage.removeItem('oblvn_refresh')
  localStorage.removeItem('oblvn_user')
}

let refreshPromise = null;

async function attemptRefresh() {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    try {
      const refresh_token = localStorage.getItem('oblvn_refresh')
      if (!refresh_token) throw new Error('No refresh token available')

      const res = await fetch(`${BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token }),
      })

      if (!res.ok) throw new Error('Session refresh failed')

      const data = await res.json()
      if (data.access_token) localStorage.setItem('oblvn_token', data.access_token)
      if (data.refresh_token) localStorage.setItem('oblvn_refresh', data.refresh_token)

      return data
    } catch (error) {
      clearSession()
      window.location.href = '/app/login'
      throw error
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

async function req(method, path, body, isRetry = false, responseType = 'json') {
  const isFormData = body instanceof FormData

  const opts = {
    method,
    headers: isFormData ? { ...(token() ? { Authorization: `Bearer ${token()}` } : {}) } : headers(),
  }

  if (body !== undefined) {
    opts.body = isFormData ? body : JSON.stringify(body)
  }

  let res = await fetch(`${BASE}${path}`, opts)

  if (res.status === 401 && !isRetry) {
    await attemptRefresh()
    opts.headers = isFormData
      ? { ...(token() ? { Authorization: `Bearer ${token()}` } : {}) }
      : headers()

    res = await fetch(`${BASE}${path}`, opts)
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '')
    let errData = {}
    try { errData = JSON.parse(text) } catch { }
    throw new Error(errData.detail || errData.error || `HTTP ${res.status}`)
  }

  if (responseType === 'blob') return res.blob()

  const text = await res.text().catch(() => '')
  if (!text) return {}
  try { return JSON.parse(text) } catch { return {} }
}

const buildQuery = (params) => {
  const cleanParams = Object.fromEntries(
    Object.entries(params).filter(([_, v]) => v != null)
  );
  const q = new URLSearchParams(cleanParams).toString();
  return q ? `?${q}` : '';
}

export const api = {
  utils: {
    // Legacy single-file picker
    selectFiles: () => req('POST', '/utils/select-files'),
    // Legacy single-folder picker
    selectFolder: () => req('POST', '/utils/select-folder'),
    // Unified picker: files first (multi-select), then loop for folders until cancelled.
    // Returns { paths: string[], sources: {type, path, file_count?}[] }
    selectItems: () => req('POST', '/utils/select-items'),
  },
  get: (path) => req('GET', path),
  post: (path, body) => req('POST', path, body),
  patch: (path, body) => req('PATCH', path, body),
  delete: (path) => req('DELETE', path),

  downloadBlob: (path) => req('GET', path, undefined, false, 'blob'),

  auth: {
    register: (email, password) =>
      req('POST', '/auth/register', { email, password }),

    login: async (email, password) => {
      const res = await fetch(`${BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })

      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.detail || data.error || `HTTP ${res.status}`)

      if (data.access_token) localStorage.setItem('oblvn_token', data.access_token)
      if (data.refresh_token) localStorage.setItem('oblvn_refresh', data.refresh_token)
      if (data.user) localStorage.setItem('oblvn_user', JSON.stringify(data.user))

      return data
    },

    logout: () => {
      const promise = req('POST', '/auth/logout').catch(() => { })
      clearSession()
      return promise
    },

    refresh: attemptRefresh,

    resetPassword: (email) =>
      req('POST', '/auth/password/reset', { email }),
  },

  devices: {
    list: (org_id) => req('GET', `/devices${buildQuery({ org_id })}`),
    get: (serial) => req('GET', `/devices/${serial}`),
    refresh: () => req('POST', '/devices/refresh'),
  },

  jobs: {
    list: (org_id) => req('GET', `/jobs${buildQuery({ org_id })}`),
    create: (body) => req('POST', '/jobs', body),
    get: (id) => req('GET', `/jobs/${id}`),
    approve: (id, org_id) => req('POST', `/jobs/${id}/approve`, { org_id }),
    cancel: (id) => req('POST', `/jobs/${id}/cancel`),
  },

  certificates: {
    get: (id) => req('GET', `/certificates/${id}`),
    download: (id) => api.downloadBlob(`/certificates/${id}/download`),
  },

  audit: {
    list: (params = {}) => req('GET', `/audit${buildQuery(params)}`),
    export: (params = {}) => api.downloadBlob(`/audit/export${buildQuery(params)}`),
    verify: (org_id) => req('GET', `/audit/verify${buildQuery({ org_id })}`),
  },

  anomalies: {
    list: (params = {}) => req('GET', `/anomalies${buildQuery(params)}`),
    acknowledge: (id, body) => req('POST', `/anomalies/${id}/acknowledge`, body),
    riskScore: (org_id) => req('GET', `/anomalies/risk-score${buildQuery({ org_id })}`),
  },

  orgs: {
    create: (body) => req('POST', '/orgs', body),
    update: (id, body) => req('PATCH', `/orgs/${id}`, body),
    listMembers: (id) => req('GET', `/orgs/${id}/members`),
    invite: (id, body) => req('POST', `/orgs/${id}/invite`, body),
    revoke: (org_id, user_id) => req('DELETE', `/orgs/${org_id}/members/${user_id}`),
    changeRole: (org_id, user_id, role) =>
      req('PATCH', `/orgs/${org_id}/members/${user_id}/role`, { role }),
  },
}