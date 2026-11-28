import type {
    Page,
    SystemInfo,
    ClientInfo,
    TunnelInfo,
    TunnelTrafficResp,
    ApiResponse,
    TokenMetricsResp,
    ConnectionInfo,
    ConfigReloadResp,
    HealthInfo,
} from '@/types/api'
import { ApiError } from './errors'

async function api<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(path, { credentials: 'include', ...init })
    if (res.status === 401) throw new ApiError('unauthorized')
    if (!res.ok) {
        // #3: carry the server's message when the body has one — the server
        // now answers errors with HTTP status == code and the JSON envelope.
        // The body may be plain text instead (auth middleware), so a failed
        // JSON parse falls back to the status text.
        let msg: string | undefined
        try {
            const body = (await res.json()) as ApiResponse<unknown> | null
            if (body && typeof body.msg === 'string' && body.msg.length > 0) {
                msg = body.msg
            }
        } catch {
            // not JSON — fall through to statusText
        }
        throw new ApiError('http', {
            status: res.status,
            statusText: res.statusText,
            ...(msg ? { msg } : {}),
        })
    }
    const body = (await res.json()) as ApiResponse<T>
    if (body.code !== 200) throw new ApiError('api', { msg: body.msg })
    return body.data
}

// ── auth ────────────────────────────────────────────────────────────────────────────────

export interface AuthStatus {
    webauthn: boolean
    password: boolean
    /** True when the server is configured with an OIDC provider (issue #35). */
    oidc: boolean
}

export interface SystemStats {
    clientsOnline: number
    clientsTotal: number
    tunnelsTotal: number
    activeConnections: number
    totalTrafficIn: number
    totalTrafficOut: number
}

export interface ReloadDiffResp {
    added: string[]
    removed: string[]
    modified: string[]
}

export async function fetchAuthStatus(): Promise<AuthStatus> {
    try {
        return await api<AuthStatus>('/api/v1/auth/status')
    } catch {
        return { webauthn: false, password: true, oidc: false }
    }
}

export function fetchSystemInfo() {
    return api<SystemInfo>('/api/v1/system/info')
}

/**
 * GET /api/v1/system/health
 * Returns structured health data: status, uptime, version, online clients,
 * and active connections.  Used by the Settings page health card.
 */
export function fetchSystemHealth() {
    return api<HealthInfo>('/api/v1/system/health')
}

export function fetchSystemStats() {
    return api<SystemStats>('/api/v1/system/stats')
}

export function fetchClients(page = 1, pageSize = 200) {
    return api<Page<ClientInfo>>(`/api/v1/clients?page=${page}&pageSize=${pageSize}`)
}

export function fetchClient(sessionId: string) {
    return api<ClientInfo>(`/api/v1/clients/${encodeURIComponent(sessionId)}`)
}

export function kickClient(sessionId: string) {
    return api<unknown>(`/api/v1/clients/${encodeURIComponent(sessionId)}`, {
        method: 'DELETE',
    })
}

export function kickClientLegacy(sessionId: string) {
    return api<unknown>(`/api/v1/clients/${encodeURIComponent(sessionId)}/kick`, {
        method: 'POST',
    })
}

export type TunnelListParams = {
    page?: number
    pageSize?: number
    sessionId?: string
    q?: string
}

export function fetchTunnels(pageOrParams: number | TunnelListParams = 1, pageSize = 200) {
    const params: TunnelListParams =
        typeof pageOrParams === 'number'
            ? { page: pageOrParams, pageSize }
            : pageOrParams
    const qs = new URLSearchParams()
    qs.set('page', String(params.page ?? 1))
    qs.set('pageSize', String(params.pageSize ?? 200))
    if (params.sessionId) qs.set('sessionId', params.sessionId)
    if (params.q) qs.set('q', params.q)
    return api<Page<TunnelInfo>>(`/api/v1/tunnels?${qs.toString()}`)
}

export function fetchTunnel(name: string) {
    return api<TunnelInfo>(`/api/v1/tunnels/${encodeURIComponent(name)}`)
}

export function kickProxy(name: string) {
    return api<unknown>(`/api/v1/proxies/${encodeURIComponent(name)}`, { method: 'DELETE' })
}

export type TrafficRange = '7d' | '24h'

function trafficQuery(range: TrafficRange = '7d') {
    return range === '24h' ? '?range=24h' : '?range=7d'
}

export function fetchTunnelTraffic(name: string, range: TrafficRange = '7d') {
    return api<TunnelTrafficResp>(
        `/api/v1/tunnels/${encodeURIComponent(name)}/traffic${trafficQuery(range)}`,
    )
}

export function fetchSystemTraffic(range: TrafficRange = '7d') {
    return api<TunnelTrafficResp>(`/api/v1/system/traffic${trafficQuery(range)}`)
}

export function fetchSystemTokens() {
    return api<TokenMetricsResp>('/api/v1/system/tokens')
}

// ── config ─────────────────────────────────────────────────────────────────────

/**
 * POST /api/v1/config/reload
 *
 * Hot-reloads the server access policy from the config file recorded at
 * startup. #3: the request body is ignored by the server — no path is
 * sent anymore. Returns the list of top-level config keys that changed;
 * empty list = no diff.
 */
export function reloadConfig() {
    return api<ConfigReloadResp>('/api/v1/config/reload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
    })
}

// ── connections ───────────────────────────────────────────────────────────────────

export type ConnectionListParams = {
    page?: number
    pageSize?: number
    q?: string
}

export function fetchConnections(tunnelName: string, params: ConnectionListParams = {}) {
    const qs = new URLSearchParams()
    qs.set('page', String(params.page ?? 1))
    qs.set('pageSize', String(params.pageSize ?? 20))
    if (params.q) qs.set('q', params.q)
    return api<Page<ConnectionInfo>>(
        `/api/v1/tunnels/${encodeURIComponent(tunnelName)}/connections?${qs.toString()}`,
    )
}

// ── config reload (issue #29) ─────────────────────────────────────────────────

/**
 * Describes the diff returned by POST /api/v1/config/reload.
 * Each array contains tunnel names that were added, removed, or modified
 * in the running config without a server restart.
 */
export interface ConfigReloadDiff {
    added: string[]
    removed: string[]
    modified: string[]
}
