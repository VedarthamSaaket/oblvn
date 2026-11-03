import { createContext, useContext, useEffect, useReducer, useRef, useCallback } from 'react'
import { api } from '../lib/api'
import { signInWithGoogle } from '../lib/firebase'

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
            try {
                const data = await api.auth.refresh()
                if (data.access_token) scheduleRefresh()
            } catch {
                clearAuth()
            }
        }, 13 * 60 * 1000)
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

    function finish(data) {
        if (data.mfa_required) return data
        dispatch({ type: 'SET_USER', user: data.user || { id: 'authenticated' } })
        scheduleRefresh()
        return data
    }

    async function login(email, password) {
        return finish(await api.auth.login(email, password))
    }

    async function loginWithGoogle() {
        const idToken = await signInWithGoogle()
        return finish(await api.auth.firebase(idToken))
    }

    async function completeMfa(mfaToken, code) {
        return finish(await api.auth.mfaLogin(mfaToken, code))
    }

    async function register(email, password) {
        return api.auth.register(email, password)
    }

    async function logout() {
        await api.auth.logout().catch(() => { })
        clearAuth()
    }

    async function logoutEverywhere() {
        await api.auth.logoutAll().catch(() => { })
        clearAuth()
    }

    async function resetPassword(email) {
        return api.auth.resetPassword(email)
    }

    return (
        <AuthCtx.Provider value={{ user, loading, login, loginWithGoogle, completeMfa, register, logout, logoutEverywhere, resetPassword }}>
            {children}
        </AuthCtx.Provider>
    )
}

export function useAuth() {
    return useContext(AuthCtx)
}