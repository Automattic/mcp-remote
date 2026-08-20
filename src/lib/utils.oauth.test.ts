import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import express from 'express'
import type { Server } from 'http'
import type { AddressInfo } from 'net'
import { randomBytes } from 'crypto'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { ListToolsResultSchema } from '@modelcontextprotocol/sdk/types.js'

import { connectToRemoteServer } from './utils'
import { writeJsonFile } from './mcp-auth-config'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import { useTempConfigDir } from './test-support'
import type { OAuthProviderOptions } from './types'

// Stands up a real express server on an ephemeral port and lets each test register handlers.
class MockServer {
  private app = express()
  private server: Server | null = null
  baseUrl = ''

  constructor() {
    this.app.use(express.json())
    this.app.use(express.urlencoded({ extended: true }))
  }

  on(method: 'GET' | 'POST' | 'DELETE', routePath: string, handler: express.RequestHandler) {
    this.app[method.toLowerCase() as 'get' | 'post' | 'delete'](routePath, handler)
  }

  async start() {
    await new Promise<void>((resolve, reject) => {
      this.server = this.app.listen(0, '127.0.0.1', () => {
        const addr = this.server!.address() as AddressInfo
        this.baseUrl = `http://127.0.0.1:${addr.port}`
        resolve()
      })
      this.server!.on('error', reject)
    })
  }

  async stop() {
    await new Promise<void>((resolve, reject) => {
      if (!this.server) return resolve()
      this.server.close((err) => (err ? reject(err) : resolve()))
    })
  }

  url(p: string) {
    return `${this.baseUrl}${p}`
  }
}

describe('Feature: OAuth flow end-to-end', () => {
  let mcp: MockServer
  let idp: MockServer

  useTempConfigDir()

  beforeEach(async () => {
    mcp = new MockServer()
    idp = new MockServer()
    await mcp.start()
    await idp.start()
  })

  afterEach(async () => {
    await mcp.stop()
    await idp.stop()
  })

  /** Minimal RFC 8414 metadata, mounted at the root so the SDK's well-known discovery finds it. */
  const serveIdpMetadata = () => {
    idp.on('GET', '/.well-known/oauth-authorization-server', (_req, res) => {
      res.json({
        issuer: idp.baseUrl,
        authorization_endpoint: idp.url('/authorize'),
        token_endpoint: idp.url('/token'),
        response_types_supported: ['code'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['none'],
      })
    })
  }

  /**
   * An MCP endpoint that 401s without the expected bearer token and otherwise answers
   * initialize and tools/list. `onUnauthenticated` observes rejected requests.
   */
  const serveMcp = ({ accessToken, onUnauthenticated }: { accessToken: string; onUnauthenticated?: () => void }) => {
    const resourceMetadataUrl = mcp.url('/per-server/oauth-protected-resource')

    mcp.on('POST', '/mcp', (req, res) => {
      const authHeader = req.headers.authorization
      // A missing token and a stale one both get 401 + WWW-Authenticate, as a real resource
      // server does - that header is what starts the SDK's auth flow.
      if (authHeader !== `Bearer ${accessToken}`) {
        if (!authHeader) onUnauthenticated?.()
        return res
          .status(401)
          .header('WWW-Authenticate', `Bearer realm="mcp", resource_metadata="${resourceMetadataUrl}"`)
          .json({ error: 'Unauthorized' })
      }
      const body = req.body
      const respond = (result: unknown) => res.header('content-type', 'application/json').json({ jsonrpc: '2.0', id: body.id, result })
      if (body.method === 'initialize') {
        return respond({
          protocolVersion: '2025-06-18',
          capabilities: { tools: {} },
          serverInfo: { name: 'mock-mcp', version: '0.0.0' },
        })
      }
      if (body.method === 'tools/list') {
        return respond({ tools: [{ name: 'echo', description: 'echoes input', inputSchema: { type: 'object' } }] })
      }
      // Notifications (no id) get a 202.
      return res.status(202).end()
    })

    // The WWW-Authenticate-supplied resource metadata URL is the only valid one;
    // intentionally do NOT serve the bare /.well-known/oauth-protected-resource path so
    // that any code that drops the per-server URL falls back to a 404 and fails.
    mcp.on('GET', '/per-server/oauth-protected-resource', (_req, res) => {
      res.json({ resource: mcp.url('/mcp'), authorization_servers: [idp.baseUrl] })
    })
  }

  const makeProvider = ({
    serverUrlHash,
    callbackPort,
    grantTypes = ['authorization_code'],
  }: {
    serverUrlHash: string
    callbackPort: number
    grantTypes?: string[]
  }) => {
    const callbackPath = '/oauth/callback'
    return new NodeOAuthClientProvider(<OAuthProviderOptions>{
      serverUrl: mcp.url('/mcp'),
      serverUrlHash,
      callbackPort,
      host: 'localhost',
      callbackPath,
      staticOAuthClientInfo: {
        client_id: 'test-client-id',
        redirect_uris: [`http://localhost:${callbackPort}${callbackPath}`],
        token_endpoint_auth_method: 'none',
        grant_types: grantTypes,
        response_types: ['code'],
      },
    })
  }

  it('Scenario: completes auth, reconnects with fresh transport, and serves a tools/list request', async () => {
    const mcpServerUrl = mcp.url('/mcp')
    const accessToken = 'test-access-token-' + randomBytes(4).toString('hex')

    let unauthenticatedPosts = 0
    serveMcp({ accessToken, onUnauthenticated: () => (unauthenticatedPosts += 1) })
    serveIdpMetadata()
    idp.on('POST', '/token', (req, res) => {
      // Validate redirect_uri matches what was registered — otherwise the test would silently
      // pass even if NodeOAuthClientProvider.redirectUrl diverged from the static redirect_uris.
      if (req.body.redirect_uri !== redirectUri) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' })
      }
      res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 })
    })

    const callbackPort = 33418
    const redirectUri = `http://localhost:${callbackPort}/oauth/callback`
    const authProvider = makeProvider({ serverUrlHash: 'oauth-flow-test', callbackPort })
    vi.spyOn(authProvider, 'redirectToAuthorization').mockResolvedValue()

    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: vi.fn().mockResolvedValue('mock-auth-code'),
      skipBrowserAuth: false,
    })

    const client = new Client({ name: 'oauth-flow-test', version: '0.0.0' }, { capabilities: {} })

    const transport = await connectToRemoteServer(client, mcpServerUrl, authProvider, {}, authInitializer, 'http-only')
    expect(transport).toBeDefined()

    // The reconnect after finishAuth must produce a client that can actually issue requests.
    // Without PR #10's recursion + close, this hangs ("Not connected" or aborted signal).
    const tools = await client.request({ method: 'tools/list' }, ListToolsResultSchema)
    expect(tools.tools.map((t) => t.name)).toEqual(['echo'])

    // Exactly one unauthenticated POST should hit the server — the initial probe. A second
    // would mean we re-probed after auth instead of using the freshly-issued Bearer token.
    expect(unauthenticatedPosts).toBe(1)

    await client.close()
  }, 15_000)

  it('Scenario: concurrent auth flows in one process do not spend the same refresh token', async () => {
    // The SDK lets concurrent sends enter authentication independently, and they all share
    // one provider. Both flows below read the same single-use refresh token before either
    // finishes refreshing, so unserialized they would race each other into invalid_grant
    // with no other process involved.
    const serverUrlHash = 'concurrent-refresh-test'
    const accessToken = 'access-token-for-all-generations'

    await writeJsonFile(serverUrlHash, 'tokens.json', {
      access_token: 'stale-access-token',
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: 'refresh-1',
    })

    serveMcp({ accessToken })
    serveIdpMetadata()

    // Single-use refresh tokens: presenting one twice is invalid_grant.
    const consumed = new Set<string>()
    let issued = 1
    let invalidGrants = 0
    const presented: string[] = []
    idp.on('POST', '/token', (req, res) => {
      const presentedToken = req.body.refresh_token
      presented.push(presentedToken)
      if (consumed.has(presentedToken)) {
        invalidGrants += 1
        return res.status(400).json({ error: 'invalid_grant', error_description: 'refresh token already used' })
      }
      consumed.add(presentedToken)
      issued += 1
      res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, refresh_token: `refresh-${issued}` })
    })

    const authProvider = makeProvider({
      serverUrlHash,
      callbackPort: 33421,
      grantTypes: ['authorization_code', 'refresh_token'],
    })
    const redirectSpy = vi.spyOn(authProvider, 'redirectToAuthorization').mockResolvedValue()
    const authInitializer = vi.fn().mockResolvedValue({ waitForAuthCode: vi.fn(), skipBrowserAuth: false })

    // Two flows sharing one provider, exactly as concurrent tool calls would produce.
    const clients = [
      new Client({ name: 'concurrent-a', version: '0.0.0' }, { capabilities: {} }),
      new Client({ name: 'concurrent-b', version: '0.0.0' }, { capabilities: {} }),
    ]
    await Promise.all(
      clients.map((client) => connectToRemoteServer(client, mcp.url('/mcp'), authProvider, {}, authInitializer, 'http-only')),
    )

    // Both refreshes were attempted, neither was rejected, and the second was retargeted at
    // the token the first produced rather than replaying the one it spent.
    expect(presented).toEqual(['refresh-1', 'refresh-2'])
    expect(invalidGrants).toBe(0)
    expect(redirectSpy).not.toHaveBeenCalled()

    for (const client of clients) await client.close()
  }, 15_000)

  it('Scenario: losing the rotation race twice reconnects instead of failing the connection', async () => {
    // Three processes share one tokens.json against a server with single-use refresh tokens.
    // This one loses the rotation twice: the SDK retries a refresh exactly once after
    // invalid_grant, so the second loss escapes auth() entirely. It must reconnect onto the
    // surviving process's tokens rather than dying or opening a browser.
    const serverUrlHash = 'rotation-race-test'
    const mcpServerUrl = mcp.url('/mcp')
    const goodAccessToken = 'access-after-recovery'

    await writeJsonFile(serverUrlHash, 'tokens.json', {
      access_token: 'stale-access-token',
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: 'refresh-1',
    })

    serveMcp({ accessToken: goodAccessToken })
    serveIdpMetadata()

    // Single-use rotation. The first two presented tokens have already been spent by other
    // processes, which each left their rotated pair on disk before we got here.
    const spentBy: Record<string, string> = { 'refresh-1': 'refresh-2', 'refresh-2': 'refresh-3' }
    const presentedRefreshTokens: string[] = []
    idp.on('POST', '/token', async (req, res) => {
      presentedRefreshTokens.push(req.body.refresh_token)
      const alreadyRotatedTo = spentBy[req.body.refresh_token]
      if (alreadyRotatedTo) {
        await writeJsonFile(serverUrlHash, 'tokens.json', {
          access_token: `access-for-${alreadyRotatedTo}`,
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: alreadyRotatedTo,
        })
        return res.status(400).json({ error: 'invalid_grant', error_description: 'refresh token already used' })
      }
      res.json({ access_token: goodAccessToken, token_type: 'Bearer', expires_in: 3600, refresh_token: 'refresh-4' })
    })

    const authProvider = makeProvider({
      serverUrlHash,
      callbackPort: 33420,
      grantTypes: ['authorization_code', 'refresh_token'],
    })
    const redirectSpy = vi.spyOn(authProvider, 'redirectToAuthorization').mockResolvedValue()
    const authInitializer = vi.fn().mockResolvedValue({ waitForAuthCode: vi.fn(), skipBrowserAuth: false })

    const client = new Client({ name: 'rotation-race-test', version: '0.0.0' }, { capabilities: {} })
    const transport = await connectToRemoteServer(client, mcpServerUrl, authProvider, {}, authInitializer, 'http-only')
    expect(transport).toBeDefined()

    const tools = await client.request({ method: 'tools/list' }, ListToolsResultSchema)
    expect(tools.tools.map((t) => t.name)).toEqual(['echo'])

    // Each attempt presented the token that was current on disk at the time: ours, then the
    // first winner's, then the second winner's — which finally succeeded.
    expect(presentedRefreshTokens).toEqual(['refresh-1', 'refresh-2', 'refresh-3'])
    // No browser. That is the whole point: the credentials were live the entire time.
    expect(redirectSpy).not.toHaveBeenCalled()

    await client.close()
  }, 15_000)

  it('Scenario: proxy-path probe does not leak Mcp-Session-Id to the main transport', async () => {
    // Mimics an SDK-stateful server: every initialize response stamps an Mcp-Session-Id,
    // and a second initialize that arrives with one is rejected. If the probe leaks the
    // session id onto the transport that the proxy will use, the first forwarded
    // initialize fails with 400.
    let initializeCount = 0
    let probeSessionId: string | undefined
    const terminatedSessionIds: string[] = []
    mcp.on('DELETE', '/mcp', (req, res) => {
      const incomingSessionId = req.headers['mcp-session-id'] as string | undefined
      if (incomingSessionId) terminatedSessionIds.push(incomingSessionId)
      res.status(204).end()
    })
    mcp.on('POST', '/mcp', (req, res) => {
      const body = req.body
      const incomingSessionId = req.headers['mcp-session-id'] as string | undefined
      if (body.method === 'initialize') {
        if (incomingSessionId) {
          return res.status(400).json({ jsonrpc: '2.0', id: body.id, error: { code: -32600, message: 'Server already initialized' } })
        }
        initializeCount += 1
        const newSessionId = `session-${initializeCount}`
        if (initializeCount === 1) probeSessionId = newSessionId
        return res.header('Mcp-Session-Id', newSessionId).json({
          jsonrpc: '2.0',
          id: body.id,
          result: {
            protocolVersion: '2025-06-18',
            capabilities: { tools: {} },
            serverInfo: { name: 'mock-stateful', version: '0.0.0' },
          },
        })
      }
      // Notifications and other non-initialize requests get accepted.
      return res.status(202).end()
    })

    const authProvider = makeProvider({ serverUrlHash: 'proxy-session-leak-test', callbackPort: 33419 })
    const authInitializer = vi.fn().mockResolvedValue({ waitForAuthCode: vi.fn(), skipBrowserAuth: false })

    // Proxy path: client === null.
    const transport = await connectToRemoteServer(null, mcp.url('/mcp'), authProvider, {}, authInitializer, 'http-only')

    expect(initializeCount).toBe(1) // probe ran once on the throwaway transport
    expect(probeSessionId).toBeDefined()
    expect((transport as unknown as { _sessionId?: string })._sessionId).toBeUndefined()
    // The throwaway transport's session was terminated on the server (DELETE) so it doesn't
    // linger until the server's idle timeout.
    expect(terminatedSessionIds).toEqual([probeSessionId])

    // Simulate the proxy forwarding the local client's real initialize through the main transport.
    // If the probe leaked its session id, the request would carry it and the server would 400.
    transport.onmessage = vi.fn()
    await transport.send({
      jsonrpc: '2.0',
      id: 99,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'real', version: '0.0.0' } },
    })

    expect(initializeCount).toBe(2) // a second initialize was accepted, not rejected
    expect((transport as unknown as { _sessionId?: string })._sessionId).toBe('session-2')
    expect((transport as unknown as { _sessionId?: string })._sessionId).not.toBe(probeSessionId)

    await transport.close()
  }, 15_000)
})
