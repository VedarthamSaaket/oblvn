import { createContext, useContext, useEffect, useReducer, useRef, useCallback } from 'react'
import { api } from '../lib/api'

const AuthCtx = createContext(null)

function authReducer(state, action) {
    switch (action.type) {
        case 'INIT': return { user: action.user, loading: false }
        case 'SET_USER': return { ...state, user: action.user }
        case 'CLEAR': return { user: null, loading: false }
        default: return state
    }
}

export function AuthProvider({ children }) {
    const [{ user, loading }, dispatch] = useReducer(authReducer, {
        user: null,
        loading: true,
    })

    const refreshTimer = useRef(null)

    const clearAuth = useCallback(() => {
        localStorage.removeItem('oblvn_token')
        localStorage.removeItem('oblvn_refresh')
        localStorage.removeItem('oblvn_user')
        dispatch({ type: 'CLEAR' })
        if (refreshTimer.current) clearTimeout(refreshTimer.current)
    }, [])

    const scheduleRefresh = useCallback(() => {
        if (refreshTimer.current) clearTimeout(refreshTimer.current)

        refreshTimer.current = setTimeout(async () => {
            const refresh = localStorage.getItem('oblvn_refresh')
            if (!refresh) return

            try {
                const data = await api.auth.refresh(refresh)

                if (data.access_token) {
                    localStorage.setItem('oblvn_token', data.access_token)
                    if (data.refresh_token) {
                        localStorage.setItem('oblvn_refresh', data.refresh_token)
                    }
                    scheduleRefresh()
                }
            } catch {
                clearAuth()
            }
        }, 55 * 60 * 1000)
    }, [clearAuth])

    // 🔴 FIXED INIT LOGIC
    useEffect(() => {
        async function init() {
            const token = localStorage.getItem('oblvn_token')

            if (!token) {
                dispatch({ type: 'INIT', user: null })
                return
            }

            try {
                // Wait until token is actually usable
                await api.get('/devices')

                let parsedUser = null
                const stored = localStorage.getItem('oblvn_user')

                if (stored) {
                    try { parsedUser = JSON.parse(stored) } catch { }
                }

                dispatch({
                    type: 'INIT',
                    user: parsedUser || { id: 'authenticated' }
                })

                scheduleRefresh()

            } catch (e) {
                console.error("Auth init failed:", e)
                clearAuth()
            }
        }

        init()
    }, [])

    async function login(email, password) {
        const data = await api.auth.login(email, password)

        if (data.access_token) localStorage.setItem('oblvn_token', data.access_token)
        if (data.refresh_token) localStorage.setItem('oblvn_refresh', data.refresh_token)
        if (data.user) localStorage.setItem('oblvn_user', JSON.stringify(data.user))

        dispatch({ type: 'SET_USER', user: data.user || { id: 'authenticated' } })
        scheduleRefresh()

        return data
    }

    async function register(email, password) {
        return api.auth.register(email, password)
    }

    async function logout() {
        await api.auth.logout().catch(() => { })
        clearAuth()
    }

    async function resetPassword(email) {
        return api.auth.resetPassword(email)
    }

    return (
        <AuthCtx.Provider value={{ user, loading, login, register, logout, resetPassword }}>
            {children}
        </AuthCtx.Provider>
    )
}

export function useAuth() {
    return useContext(AuthCtx)
}