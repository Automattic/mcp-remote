import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import express from 'express'
import type { Server } from 'http'
import type { AddressInfo } from 'net'
import * as os from 'os'
import * as path from 'path'
import * as fs from 'fs/promises'
import { randomBytes } from 'crypto'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { ListToolsResultSchema } from '@modelcontextprotocol/sdk/types.js'

import { connectToRemoteServer } from './utils'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
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

  on(method: 'GET' | 'POST', routePath: string, handler: express.RequestHandler) {
    this.app[method.toLowerCase() as 'get' | 'post'](routePath, handler)
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
  let tmpConfigDir: string
  let originalConfigDirEnv: string | undefined

  beforeEach(async () => {
    mcp = new MockServer()
    idp = new MockServer()
    await mcp.start()
    await idp.start()

    tmpConfigDir = path.join(os.tmpdir(), `mcp-remote-test-${randomBytes(6).toString('hex')}`)
    await fs.mkdir(tmpConfigDir, { recursive: true })
    originalConfigDirEnv = process.env.MCP_REMOTE_CONFIG_DIR
    process.env.MCP_REMOTE_CONFIG_DIR = tmpConfigDir
  })

  afterEach(async () => {
    await mcp.stop()
    await idp.stop()
    if (originalConfigDirEnv === undefined) {
      delete process.env.MCP_REMOTE_CONFIG_DIR
    } else {
      process.env.MCP_REMOTE_CONFIG_DIR = originalConfigDirEnv
    }
    await fs.rm(tmpConfigDir, { recursive: true, force: true })
  })

  it('Scenario: completes auth, reconnects with fresh transport, and serves a tools/list request', async () => {
    const mcpServerUrl = mcp.url('/mcp')
    const resourceMetadataUrl = mcp.url('/per-server/oauth-protected-resource')
    const accessToken = 'test-access-token-' + randomBytes(4).toString('hex')

    // mcp server: 401 with WWW-Authenticate → after auth, real initialize + tools/list responses.
    let unauthenticatedPosts = 0
    mcp.on('POST', '/mcp', (req, res) => {
      const authHeader = req.headers.authorization
      if (!authHeader) unauthenticatedPosts += 1
      if (!authHeader) {
        return res
          .status(401)
          .header('WWW-Authenticate', `Bearer realm="mcp", resource_metadata="${resourceMetadataUrl}"`)
          .json({ error: 'Unauthorized' })
      }
      if (authHeader !== `Bearer ${accessToken}`) {
        return res.status(403).json({ error: 'Forbidden' })
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
      res.json({
        resource: mcpServerUrl,
        authorization_servers: [idp.baseUrl],
      })
    })

    // idp server: minimal RFC 8414 metadata + token endpoint. Mounted at root so the SDK's
    // well-known discovery (which uses the issuer's origin) finds the metadata on the first try.
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
    idp.on('POST', '/token', (req, res) => {
      // Validate redirect_uri matches what was registered — otherwise the test would silently
      // pass even if NodeOAuthClientProvider.redirectUrl diverged from the static redirect_uris.
      if (req.body.redirect_uri !== redirectUri) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' })
      }
      res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 })
    })

    const callbackPort = 33418
    const callbackPath = '/oauth/callback'
    const redirectUri = `http://localhost:${callbackPort}${callbackPath}`
    const authProvider = new NodeOAuthClientProvider(<OAuthProviderOptions>{
      serverUrl: mcpServerUrl,
      serverUrlHash: 'oauth-flow-test',
      callbackPort,
      host: 'localhost',
      callbackPath,
      staticOAuthClientInfo: {
        client_id: 'test-client-id',
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code'],
        response_types: ['code'],
      },
    })
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
})
