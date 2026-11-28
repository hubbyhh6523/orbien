import {describe, it, expect, vi, beforeEach, afterEach} from 'vitest'
import {ApiError} from '../errors'

// All fetch calls are intercepted via vi.stubGlobal so no real network is used.

function mockFetch(status: number, body: unknown, ok = status >= 200 && status < 300) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: () => Promise.resolve(body),
  })
}

beforeEach(() => {
  vi.resetModules()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

async function importClient() {
  const m = await import('../client')
  return m
}

describe('api internals – fetch integration', () => {
  it('throws ApiError(unauthorized) on 401', async () => {
    vi.stubGlobal('fetch', mockFetch(401, null, false))
    const {fetchSystemInfo} = await importClient()
    await expect(fetchSystemInfo()).rejects.toMatchObject({code: 'unauthorized'})
  })

  it('throws ApiError(http) on non-ok response', async () => {
    vi.stubGlobal('fetch', mockFetch(500, null, false))
    const {fetchSystemInfo} = await importClient()
    await expect(fetchSystemInfo()).rejects.toMatchObject({code: 'http', params: {status: 500}})
  })

  it('carries the server msg on a non-ok JSON response', async () => {
    vi.stubGlobal('fetch', mockFetch(404, {code: 404, msg: 'tunnel not found: web', data: null}, false))
    const {fetchSystemInfo} = await importClient()
    await expect(fetchSystemInfo()).rejects.toMatchObject({
      code: 'http',
      params: {status: 404, msg: 'tunnel not found: web'},
    })
  })

  it('falls back to statusText when the error body is not JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      statusText: 'Forbidden',
      json: () => Promise.reject(new SyntaxError('not json')),
    }))
    const {fetchSystemInfo} = await importClient()
    await expect(fetchSystemInfo()).rejects.toMatchObject({
      code: 'http',
      params: {status: 403, statusText: 'Forbidden'},
    })
  })

  it('throws ApiError(api) when body.code !== 200', async () => {
    vi.stubGlobal('fetch', mockFetch(200, {code: 400, msg: 'bad request', data: null}))
    const {fetchSystemInfo} = await importClient()
    await expect(fetchSystemInfo()).rejects.toMatchObject({code: 'api', params: {msg: 'bad request'}})
  })

  it('returns body.data on success', async () => {
    const data = {version: '1.0'}
    vi.stubGlobal('fetch', mockFetch(200, {code: 200, msg: 'ok', data}))
    const {fetchSystemInfo} = await importClient()
    await expect(fetchSystemInfo()).resolves.toEqual(data)
  })

  it('passes credentials: include in every request', async () => {
    const fetchSpy = mockFetch(200, {code: 200, msg: 'ok', data: {}})
    vi.stubGlobal('fetch', fetchSpy)
    const {fetchSystemInfo} = await importClient()
    await fetchSystemInfo().catch(() => {})
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({credentials: 'include'}),
    )
  })

  it('throws ApiError(http) on 403 with correct status', async () => {
    vi.stubGlobal('fetch', mockFetch(403, null, false))
    const {fetchSystemInfo} = await importClient()
    await expect(fetchSystemInfo()).rejects.toMatchObject({code: 'http', params: {status: 403}})
  })

  it('throws ApiError(http) on 503 with correct status', async () => {
    vi.stubGlobal('fetch', mockFetch(503, null, false))
    const {fetchSystemInfo} = await importClient()
    await expect(fetchSystemInfo()).rejects.toMatchObject({code: 'http', params: {status: 503}})
  })
})

describe('fetchAuthStatus', () => {
  it('returns server data on success', async () => {
    vi.stubGlobal('fetch', mockFetch(200, {code: 200, msg: 'ok', data: {webauthn: true, password: true, oidc: false}}))
    const {fetchAuthStatus} = await importClient()
    await expect(fetchAuthStatus()).resolves.toEqual({webauthn: true, password: true, oidc: false})
  })

  it('returns server data when oidc is true', async () => {
    vi.stubGlobal('fetch', mockFetch(200, {code: 200, msg: 'ok', data: {webauthn: false, password: false, oidc: true}}))
    const {fetchAuthStatus} = await importClient()
    await expect(fetchAuthStatus()).resolves.toEqual({webauthn: false, password: false, oidc: true})
  })

  it('returns safe defaults on any error without throwing', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network')))
    const {fetchAuthStatus} = await importClient()
    await expect(fetchAuthStatus()).resolves.toEqual({webauthn: false, password: true, oidc: false})
  })

  it('returns safe defaults on 401', async () => {
    vi.stubGlobal('fetch', mockFetch(401, null, false))
    const {fetchAuthStatus} = await importClient()
    await expect(fetchAuthStatus()).resolves.toEqual({webauthn: false, password: true, oidc: false})
  })

  it('returns safe defaults on 500', async () => {
    vi.stubGlobal('fetch', mockFetch(500, null, false))
    const {fetchAuthStatus} = await importClient()
    await expect(fetchAuthStatus()).resolves.toEqual({webauthn: false, password: true, oidc: false})
  })

  it('returns safe defaults when server returns api error code', async () => {
    vi.stubGlobal('fetch', mockFetch(200, {code: 403, msg: 'forbidden', data: null}))
    const {fetchAuthStatus} = await importClient()
    await expect(fetchAuthStatus()).resolves.toEqual({webauthn: false, password: true, oidc: false})
  })
})

describe('fetchClients', () => {
  it('calls correct URL with default pagination', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {items: [], total: 0, page: 1, pageSize: 200}})
    vi.stubGlobal('fetch', spy)
    const {fetchClients} = await importClient()
    await fetchClients().catch(() => {})
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/clients?page=1&pageSize=200',
      expect.anything(),
    )
  })

  it('accepts custom page and pageSize', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {items: [], total: 0, page: 2, pageSize: 50}})
    vi.stubGlobal('fetch', spy)
    const {fetchClients} = await importClient()
    await fetchClients(2, 50).catch(() => {})
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/clients?page=2&pageSize=50',
      expect.anything(),
    )
  })
})

describe('fetchClient', () => {
  it('encodes sessionId in URL', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {sessionId: 'abc'}})
    vi.stubGlobal('fetch', spy)
    const {fetchClient} = await importClient()
    await fetchClient('session/abc').catch(() => {})
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/clients/session%2Fabc',
      expect.anything(),
    )
  })

  it('returns client data on success', async () => {
    const data = {sessionId: 'abc', user: 'alice'}
    vi.stubGlobal('fetch', mockFetch(200, {code: 200, msg: 'ok', data}))
    const {fetchClient} = await importClient()
    await expect(fetchClient('abc')).resolves.toMatchObject({sessionId: 'abc'})
  })
})

describe('kickClient', () => {
  it('sends DELETE to correct URL', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: null})
    vi.stubGlobal('fetch', spy)
    const {kickClient} = await importClient()
    await kickClient('sess-1').catch(() => {})
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/clients/sess-1',
      expect.objectContaining({method: 'DELETE'}),
    )
  })

  it('encodes special characters in sessionId', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: null})
    vi.stubGlobal('fetch', spy)
    const {kickClient} = await importClient()
    await kickClient('sess/1').catch(() => {})
    expect(spy.mock.calls[0][0]).toContain('sess%2F1')
  })
})

describe('fetchTunnels', () => {
  it('uses numeric page argument', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {items: [], total: 0, page: 1, pageSize: 200}})
    vi.stubGlobal('fetch', spy)
    const {fetchTunnels} = await importClient()
    await fetchTunnels(3, 50).catch(() => {})
    const url = spy.mock.calls[0][0] as string
    expect(url).toContain('page=3')
    expect(url).toContain('pageSize=50')
  })

  it('uses params object with sessionId and q', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {items: [], total: 0, page: 1, pageSize: 10}})
    vi.stubGlobal('fetch', spy)
    const {fetchTunnels} = await importClient()
    await fetchTunnels({page: 1, pageSize: 10, sessionId: 'sess-x', q: 'web'}).catch(() => {})
    const url = spy.mock.calls[0][0] as string
    expect(url).toContain('sessionId=sess-x')
    expect(url).toContain('q=web')
  })

  it('omits sessionId and q when not provided', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {items: [], total: 0, page: 1, pageSize: 200}})
    vi.stubGlobal('fetch', spy)
    const {fetchTunnels} = await importClient()
    await fetchTunnels({page: 1, pageSize: 200}).catch(() => {})
    const url = spy.mock.calls[0][0] as string
    expect(url).not.toContain('sessionId')
    expect(url).not.toContain('&q=')
  })

  it('uses default page=1 pageSize=200 when called with no args', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {items: [], total: 0, page: 1, pageSize: 200}})
    vi.stubGlobal('fetch', spy)
    const {fetchTunnels} = await importClient()
    await fetchTunnels().catch(() => {})
    const url = spy.mock.calls[0][0] as string
    expect(url).toContain('page=1')
    expect(url).toContain('pageSize=200')
  })
})

describe('kickProxy', () => {
  it('sends DELETE to correct URL', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: null})
    vi.stubGlobal('fetch', spy)
    const {kickProxy} = await importClient()
    await kickProxy('my-proxy').catch(() => {})
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/proxies/my-proxy',
      expect.objectContaining({method: 'DELETE'}),
    )
  })

  it('encodes proxy name with slashes', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: null})
    vi.stubGlobal('fetch', spy)
    const {kickProxy} = await importClient()
    await kickProxy('my/proxy').catch(() => {})
    expect(spy.mock.calls[0][0]).toContain('my%2Fproxy')
  })
})

describe('fetchTunnelTraffic', () => {
  it('defaults to 7d range', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {}})
    vi.stubGlobal('fetch', spy)
    const {fetchTunnelTraffic} = await importClient()
    await fetchTunnelTraffic('my-tunnel').catch(() => {})
    expect(spy.mock.calls[0][0]).toContain('range=7d')
  })

  it('uses 24h range when specified', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {}})
    vi.stubGlobal('fetch', spy)
    const {fetchTunnelTraffic} = await importClient()
    await fetchTunnelTraffic('my-tunnel', '24h').catch(() => {})
    expect(spy.mock.calls[0][0]).toContain('range=24h')
  })

  it('encodes tunnel name in URL', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {}})
    vi.stubGlobal('fetch', spy)
    const {fetchTunnelTraffic} = await importClient()
    await fetchTunnelTraffic('my/tunnel').catch(() => {})
    expect(spy.mock.calls[0][0]).toContain('my%2Ftunnel')
  })

  it('returns traffic data on success', async () => {
    const data = {name: 't1', unit: 'bytes', granularity: 'day', history: []}
    vi.stubGlobal('fetch', mockFetch(200, {code: 200, msg: 'ok', data}))
    const {fetchTunnelTraffic} = await importClient()
    await expect(fetchTunnelTraffic('t1')).resolves.toMatchObject({name: 't1'})
  })
})

describe('fetchSystemTraffic', () => {
  it('defaults to 7d range', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {}})
    vi.stubGlobal('fetch', spy)
    const {fetchSystemTraffic} = await importClient()
    await fetchSystemTraffic().catch(() => {})
    expect(spy.mock.calls[0][0]).toContain('range=7d')
  })

  it('uses 24h range when specified', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {}})
    vi.stubGlobal('fetch', spy)
    const {fetchSystemTraffic} = await importClient()
    await fetchSystemTraffic('24h').catch(() => {})
    expect(spy.mock.calls[0][0]).toContain('range=24h')
  })

  it('hits /api/v1/system/traffic endpoint', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {}})
    vi.stubGlobal('fetch', spy)
    const {fetchSystemTraffic} = await importClient()
    await fetchSystemTraffic().catch(() => {})
    expect(spy.mock.calls[0][0]).toContain('/api/v1/system/traffic')
  })
})

describe('fetchSystemTokens', () => {
  it('calls correct endpoint', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {tokens: []}})
    vi.stubGlobal('fetch', spy)
    const {fetchSystemTokens} = await importClient()
    await fetchSystemTokens().catch(() => {})
    expect(spy.mock.calls[0][0]).toBe('/api/v1/system/tokens')
  })

  it('returns token metrics data on success', async () => {
    const data = {tokens: [{token: 'tok1', activeConns: 2, allowedTunnels: [], allowedProtocols: [], allowedRemotePorts: []}]}
    vi.stubGlobal('fetch', mockFetch(200, {code: 200, msg: 'ok', data}))
    const {fetchSystemTokens} = await importClient()
    await expect(fetchSystemTokens()).resolves.toMatchObject({tokens: [{token: 'tok1'}]})
  })
})

describe('reloadConfig', () => {
  it('sends POST to /api/v1/config/reload', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {changed: []}})
    vi.stubGlobal('fetch', spy)
    const {reloadConfig} = await importClient()
    await reloadConfig().catch(() => {})
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/config/reload',
      expect.objectContaining({method: 'POST'}),
    )
  })

  it('never sends configPath', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {changed: ['auth']}})
    vi.stubGlobal('fetch', spy)
    const {reloadConfig} = await importClient()
    await reloadConfig().catch(() => {})
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/config/reload',
      expect.objectContaining({
        method: 'POST',
        body: '{}',
      }),
    )
  })

  it('returns ConfigReloadResp on success', async () => {
    const resp = {changed: ['auth', 'listen']}
    vi.stubGlobal('fetch', mockFetch(200, {code: 200, msg: 'ok', data: resp}))
    const {reloadConfig} = await importClient()
    await expect(reloadConfig()).resolves.toEqual(resp)
  })

  it('throws ApiError(unauthorized) on 401', async () => {
    vi.stubGlobal('fetch', mockFetch(401, null, false))
    const {reloadConfig} = await importClient()
    await expect(reloadConfig()).rejects.toMatchObject({code: 'unauthorized'})
  })

  it('passes credentials: include', async () => {
    const spy = mockFetch(200, {code: 200, msg: 'ok', data: {added: [], removed: [], modified: []}})
    vi.stubGlobal('fetch', spy)
    const {reloadConfig} = await importClient()
    await reloadConfig().catch(() => {})
    expect(spy).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({credentials: 'include'}),
    )
  })
})
