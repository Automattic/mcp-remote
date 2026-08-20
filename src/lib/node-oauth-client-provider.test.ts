import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import * as mcpAuthConfig from './mcp-auth-config'
import type { OAuthProviderOptions } from './types'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'

vi.mock('./mcp-auth-config')
vi.mock('./authorization-server-metadata', () => ({
  fetchAuthorizationServerMetadata: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('./utils', () => ({
  getServerUrlHash: () => 'test-hash',
  log: vi.fn(),
  debugLog: vi.fn(),
  DEBUG: false,
  MCP_REMOTE_VERSION: '1.0.0',
}))
vi.mock('open', () => ({ default: vi.fn() }))

describe('NodeOAuthClientProvider - OAuth Scope Handling', () => {
  let provider: NodeOAuthClientProvider
  let mockReadJsonFile: any
  let mockWriteJsonFile: any
  let mockDeleteConfigFile: any

  const defaultOptions: OAuthProviderOptions = {
    serverUrl: 'https://example.com',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }

  beforeEach(() => {
    mockReadJsonFile = vi.mocked(mcpAuthConfig.readJsonFile)
    mockWriteJsonFile = vi.mocked(mcpAuthConfig.writeJsonFile)
    mockDeleteConfigFile = vi.mocked(mcpAuthConfig.deleteConfigFile)

    mockReadJsonFile.mockResolvedValue(undefined)
    mockWriteJsonFile.mockResolvedValue(undefined)
    mockDeleteConfigFile.mockResolvedValue(undefined)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  /** An OAuth token pair. Omitting `refreshToken` models a server that does not rotate. */
  const pair = (accessToken: string, refreshToken?: string) => ({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
  })
  const tokensWith = (refreshToken: string) => pair(`access-for-${refreshToken}`, refreshToken)

  describe('scope priority', () => {
    it('should prioritize custom scope from staticOAuthClientMetadata', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom read write',
        } as any,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('custom read write')
    })

    it('should use scope from registration response', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile read:user',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile read:user')
    })

    it('should fallback to default scopes when none provided', () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })
  })

  describe('authorization URL', () => {
    it('should include scope parameter in authorization URL', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'github read:user',
        } as any,
      })

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('github read:user')
    })

    it('should include default scope in authorization URL when none specified', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('openid email profile')
    })
  })

  describe('backward compatibility', () => {
    it('should preserve existing custom scope behavior', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'user:email repo',
          client_name: 'My Custom Client',
        } as any,
      })

      const metadata = provider.clientMetadata

      expect(metadata).toMatchObject({
        scope: 'user:email repo',
        client_name: 'My Custom Client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        software_id: '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d',
        software_version: '1.0.0',
      })
    })
  })

  describe('credential invalidation', () => {
    it('should reset to default scopes after client invalidation', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'extracted custom scopes',
      }

      mockReadJsonFile.mockResolvedValueOnce(clientInfo)
      await provider.clientInformation()
      expect(provider.clientMetadata.scope).toBe('extracted custom scopes')

      await provider.invalidateCredentials('client')

      expect(provider.clientMetadata.scope).toBe('openid email profile')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'client_info.json')
    })

    it('should not delete client info when invalidating only tokens', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('tokens')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(mockDeleteConfigFile).not.toHaveBeenCalledWith('test-hash', 'client_info.json')
    })

    describe('rotation guard', () => {
      beforeEach(() => {
        provider = new NodeOAuthClientProvider(defaultOptions)
      })

      it('deletes tokens when the on-disk refresh token matches the one this process pinned', async () => {
        mockReadJsonFile.mockResolvedValue(tokensWith('refresh-1'))
        await provider.tokens()

        await provider.invalidateCredentials('tokens')

        expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      })

      it('keeps tokens when a concurrent process rotated them after this process read its copy', async () => {
        // This process loaded refresh-1, refreshed with it, and got invalid_grant because a
        // concurrent process already rotated it. The winner's refresh-2 is on disk.
        mockReadJsonFile.mockResolvedValueOnce(tokensWith('refresh-1'))
        await provider.tokens()
        mockReadJsonFile.mockResolvedValue(tokensWith('refresh-2'))

        await provider.invalidateCredentials('tokens')

        expect(mockDeleteConfigFile).not.toHaveBeenCalled()
      })

      it('deletes tokens when this process never read any tokens', async () => {
        mockReadJsonFile.mockResolvedValue(tokensWith('refresh-1'))

        await provider.invalidateCredentials('tokens')

        expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      })

      it('deletes tokens when the token file is gone', async () => {
        mockReadJsonFile.mockResolvedValueOnce(tokensWith('refresh-1'))
        await provider.tokens()
        mockReadJsonFile.mockResolvedValue(undefined)

        await provider.invalidateCredentials('tokens')

        expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      })

      it('does not let a hot-path read of a newer token move the pin', async () => {
        // tokens() is on the SDK's per-request path. This process pins refresh-1 and starts
        // refreshing with it; a concurrent process wins the rotation and writes refresh-2;
        // an ordinary request then reads tokens while our refresh is still in flight.
        mockReadJsonFile.mockResolvedValueOnce(tokensWith('refresh-1'))
        await provider.tokens()
        mockReadJsonFile.mockResolvedValue(tokensWith('refresh-2'))
        await provider.tokens()

        await provider.invalidateCredentials('tokens')

        // The pin is still refresh-1, so the winner's live pair survives.
        expect(mockDeleteConfigFile).not.toHaveBeenCalled()
      })

      it('does not let a concurrent flow saving tokens move the pin', async () => {
        // Two auth flows in one process share this provider. This flow pinned refresh-1 and
        // lost the race; the other flow won it and saved the rotated pair.
        mockReadJsonFile.mockResolvedValueOnce(tokensWith('refresh-1'))
        await provider.tokens()
        await provider.saveTokens(tokensWith('refresh-2') as any)
        mockReadJsonFile.mockResolvedValue(tokensWith('refresh-2'))

        await provider.invalidateCredentials('tokens')

        expect(mockDeleteConfigFile).not.toHaveBeenCalled()
      })

      it('retires the pin after keeping tokens, so the next attempt can still delete them', async () => {
        // A kept pair that really is dead must not be kept forever. Cycle one keeps because
        // the pin is stale; cycle two re-pins from disk, matches, and deletes.
        mockReadJsonFile.mockResolvedValueOnce(tokensWith('refresh-1'))
        await provider.tokens()
        mockReadJsonFile.mockResolvedValue(tokensWith('refresh-2'))
        await provider.invalidateCredentials('tokens')
        expect(mockDeleteConfigFile).not.toHaveBeenCalled()

        await provider.tokens()
        await provider.invalidateCredentials('tokens')

        expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      })

      it('retires the pin after deleting tokens', async () => {
        mockReadJsonFile.mockResolvedValue(tokensWith('refresh-1'))
        await provider.tokens()
        await provider.invalidateCredentials('tokens')

        // Pin cleared, so a rotation observed only after this point is respected again.
        await provider.tokens()
        mockReadJsonFile.mockResolvedValue(tokensWith('refresh-2'))
        mockDeleteConfigFile.mockClear()
        await provider.invalidateCredentials('tokens')

        expect(mockDeleteConfigFile).not.toHaveBeenCalled()
      })

      it('retires the pin when all credentials are invalidated', async () => {
        mockReadJsonFile.mockResolvedValueOnce(tokensWith('refresh-1'))
        await provider.tokens()

        await provider.invalidateCredentials('all')

        // A pin surviving a full wipe would point at a token that no longer exists, and
        // `??=` cannot correct it because a missing file reads as undefined.
        mockReadJsonFile.mockResolvedValue(tokensWith('refresh-2'))
        await provider.tokens()
        mockDeleteConfigFile.mockClear()
        await provider.invalidateCredentials('tokens')

        expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      })
    })
  })

  describe('refresh grant serialization', () => {
    const tokenUrl = 'https://idp.example.com/token'
    const refreshBody = (refreshToken: string) => new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken })
    const tokenResponse = (payload: Record<string, unknown>) =>
      new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } })

    let fetchSpy: any

    beforeEach(() => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      fetchSpy = vi.spyOn(globalThis, 'fetch')
    })

    afterEach(() => {
      fetchSpy.mockRestore()
    })

    it('leaves anything that is not a refresh grant untouched', async () => {
      fetchSpy.mockResolvedValue(tokenResponse({ ok: true }))

      await provider.transportFetch('https://example.com/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0' }) })

      expect(fetchSpy).toHaveBeenCalledOnce()
      expect(mockWriteJsonFile).not.toHaveBeenCalled()
    })

    it('sends the token on disk when it has rotated past the one this attempt was built with', async () => {
      mockReadJsonFile.mockResolvedValue(tokensWith('refresh-2'))
      fetchSpy.mockResolvedValue(tokenResponse(pair('a3', 'refresh-3')))

      const body = refreshBody('refresh-1')
      await provider.transportFetch(tokenUrl, { method: 'POST', body })

      expect(body.get('refresh_token')).toBe('refresh-2')
    })

    it('reports the retargeted token when the server omits refresh_token', async () => {
      // OAuth lets a server answer a refresh without a new refresh token. The SDK then
      // backfills the token it believed it sent - which after a retarget is already spent -
      // so the response has to name the one actually used.
      mockReadJsonFile.mockResolvedValue(tokensWith('refresh-2'))
      fetchSpy.mockResolvedValue(tokenResponse(pair('a3')))

      const response = await provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') })

      expect(await response.json()).toMatchObject({ access_token: 'a3', refresh_token: 'refresh-2' })
      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'tokens.json', expect.objectContaining({ refresh_token: 'refresh-2' }))
    })

    it('does not let the SDK re-save a pair the refresh already stored', async () => {
      // saveTokens runs after the queue has been released, so by then a later refresh may
      // have rotated past this pair; rewriting it would put a spent token back on disk.
      mockReadJsonFile.mockResolvedValue(tokensWith('refresh-1'))
      fetchSpy.mockResolvedValue(tokenResponse(pair('a2', 'refresh-2')))

      await provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') })
      mockWriteJsonFile.mockClear()

      // The SDK saves what the response carried, which is the pair the wrapper just wrote.
      await provider.saveTokens(pair('a2', 'refresh-2') as any)

      expect(mockWriteJsonFile).not.toHaveBeenCalled()
    })

    it('still saves a pair the refresh could not store itself', async () => {
      mockReadJsonFile.mockResolvedValue(tokensWith('refresh-1'))
      mockWriteJsonFile.mockRejectedValueOnce(new Error('disk full'))
      fetchSpy.mockResolvedValue(tokenResponse(pair('a2', 'refresh-2')))

      await provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') })
      mockWriteJsonFile.mockClear()

      await provider.saveTokens(pair('a2', 'refresh-2') as any)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'tokens.json', expect.objectContaining({ refresh_token: 'refresh-2' }))
    })

    it('still saves after a failed write when an earlier refresh succeeded on the same token', async () => {
      // A server that does not rotate hands back the same refresh token every time, so a
      // marker keyed on it would still match here and silently drop the new access token.
      mockReadJsonFile.mockResolvedValue(tokensWith('refresh-1'))
      fetchSpy.mockResolvedValueOnce(tokenResponse(pair('a2')))

      // First refresh stores its pair, and the save that follows is skipped as a duplicate.
      await provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') })
      await provider.saveTokens(pair('a2', 'refresh-1') as any)
      expect(mockWriteJsonFile).toHaveBeenCalledTimes(1)

      // Second refresh cannot store its own pair, so saveTokens is the only route to disk.
      mockWriteJsonFile.mockRejectedValueOnce(new Error('disk full'))
      fetchSpy.mockResolvedValueOnce(tokenResponse(pair('a3')))
      await provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') })
      mockWriteJsonFile.mockClear()

      await provider.saveTokens(pair('a3', 'refresh-1') as any)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'tokens.json', expect.objectContaining({ access_token: 'a3' }))
    })

    it('does not confuse two issuances that share an access token', async () => {
      // OAuth does not promise a fresh access token per refresh. Keying markers on it alone
      // would collapse {A,r2} and {A,r3} into one, letting the save for the older pair write
      // a spent refresh token over the newer one.
      mockReadJsonFile.mockResolvedValue(tokensWith('refresh-1'))
      fetchSpy.mockResolvedValueOnce(tokenResponse(pair('A', 'refresh-2')))
      await provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') })

      mockReadJsonFile.mockResolvedValue(tokensWith('refresh-2'))
      fetchSpy.mockResolvedValueOnce(tokenResponse(pair('A', 'refresh-3')))
      await provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-2') })

      mockWriteJsonFile.mockClear()
      // The newer save arrives first, then the delayed older one.
      await provider.saveTokens(pair('A', 'refresh-3') as any)
      await provider.saveTokens(pair('A', 'refresh-2') as any)

      expect(mockWriteJsonFile).not.toHaveBeenCalled()
    })

    it('reports the retargeted token even when it cannot store the pair itself', async () => {
      // Retarget plus an omitted refresh_token plus a failed write: saveTokens is the only
      // route to disk, so the response it parses must still name the token actually sent.
      mockReadJsonFile.mockResolvedValue(tokensWith('refresh-2'))
      mockWriteJsonFile.mockRejectedValueOnce(new Error('disk full'))
      fetchSpy.mockResolvedValue(tokenResponse(pair('a3')))

      const response = await provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') })

      expect(await response.json()).toMatchObject({ access_token: 'a3', refresh_token: 'refresh-2' })

      // No marker was recorded, so the SDK's save is the write that lands.
      mockWriteJsonFile.mockClear()
      await provider.saveTokens(pair('a3', 'refresh-2') as any)
      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'tokens.json', expect.objectContaining({ refresh_token: 'refresh-2' }))
    })

    it('forgets its markers when the stored tokens are invalidated', async () => {
      mockReadJsonFile.mockResolvedValue(tokensWith('refresh-1'))
      fetchSpy.mockResolvedValue(tokenResponse(pair('a2', 'refresh-2')))
      await provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') })

      await provider.invalidateCredentials('tokens')

      // Nothing this process wrote survives, so a later save must not be suppressed.
      mockWriteJsonFile.mockClear()
      await provider.saveTokens(pair('a2', 'refresh-2') as any)
      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'tokens.json', expect.objectContaining({ access_token: 'a2' }))
    })

    it('runs queued refreshes one at a time', async () => {
      mockReadJsonFile.mockResolvedValue(undefined)
      let inFlight = 0
      let overlapped = false
      fetchSpy.mockImplementation(async () => {
        inFlight += 1
        if (inFlight > 1) overlapped = true
        await Promise.resolve()
        inFlight -= 1
        return tokenResponse({ access_token: 'a', token_type: 'Bearer', expires_in: 3600 })
      })

      await Promise.all([
        provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') }),
        provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') }),
        provider.transportFetch(tokenUrl, { method: 'POST', body: refreshBody('refresh-1') }),
      ])

      expect(overlapped).toBe(false)
    })
  })

  describe('scopes_supported parsing', () => {
    it('should use custom scopes without filtering', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email', 'profile'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'openid email profile custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use all requested scopes without filtering
      expect(clientMetadata.scope).toBe('openid email profile custom:read custom:write')
    })

    it('should use requested scopes regardless of scopes_supported', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['some', 'other', 'scopes'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use requested scopes even if not in scopes_supported
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when scopes_supported is missing', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        // No scopes_supported
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write special:scope',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write special:scope')
    })

    it('should use scopes when scopes_supported is empty', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when no metadata is provided', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes from client registration response', async () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile custom:read',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const clientMetadata = provider.clientMetadata
      // Should use all scopes from registration response
      expect(clientMetadata.scope).toBe('openid email profile custom:read')
    })

    it('should use scopes_supported when no user or client scopes provided', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use scopes_supported when nothing else is provided
      expect(clientMetadata.scope).toBe('openid email')
    })

    it('should treat empty scope string as no scope and use default', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: '',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      // Empty scope should fallback to default
      expect(clientMetadata.scope).toBe('openid email profile')
    })
  })
})
