import open from 'open'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions, StaticOAuthClientMetadata, TransportFetchProvider } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile } from './mcp-auth-config'
import { StaticOAuthClientInformationFull } from './types'
import { log, debugLog, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'
import { randomUUID } from 'node:crypto'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import type { ProtectedResourceMetadata } from './protected-resource-metadata'

/**
 * How many issuances written by transportFetch can be awaiting their saveTokens at once.
 * Only a leaked marker - an issuance whose save never arrived - is ever evicted.
 */
const MAX_PERSISTED_TOKEN_MARKERS = 8

/**
 * Identifies one token issuance. Both halves are needed: a non-rotating server repeats the
 * refresh token, and OAuth does not require a distinct access token per response either.
 * The separator is a NUL, which cannot appear in either token.
 */
const issuanceKey = (tokens: OAuthTokens) => `${tokens.access_token}\u0000${tokens.refresh_token ?? ''}`

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider, TransportFetchProvider {
  private serverUrlHash: string
  private callbackPath: string
  private clientName: string
  private clientUri: string
  private softwareId: string
  private softwareVersion: string
  private staticOAuthClientMetadata: StaticOAuthClientMetadata
  private staticOAuthClientInfo: StaticOAuthClientInformationFull
  private authorizeResource: string | undefined
  private _state: string
  private _clientInfo: OAuthClientInformationFull | undefined
  private _pinnedRefreshToken: string | undefined
  private _refreshQueue: Promise<unknown> = Promise.resolve()
  private _persistedIssuances = new Set<string>()
  private authorizationServerMetadata: AuthorizationServerMetadata | undefined
  private protectedResourceMetadata: ProtectedResourceMetadata | undefined
  private wwwAuthenticateScope: string | undefined

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = options.serverUrlHash
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
    this.authorizeResource = options.authorizeResource
    this._state = randomUUID()
    this._clientInfo = undefined
    this.authorizationServerMetadata = options.authorizationServerMetadata
    this.protectedResourceMetadata = options.protectedResourceMetadata
    this.wwwAuthenticateScope = options.wwwAuthenticateScope
  }

  get redirectUrl(): string {
    return `http://${this.options.host}:${this.options.callbackPort}${this.callbackPath}`
  }

  get clientMetadata() {
    const effectiveScope = this.getEffectiveScope()
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
      software_id: this.softwareId,
      software_version: this.softwareVersion,
      ...this.staticOAuthClientMetadata,
      scope: effectiveScope,
    }
  }

  state(): string {
    return this._state
  }

  /**
   * Gets the authorization server metadata, fetching it if not already available
   * @returns The authorization server metadata, or undefined if unavailable
   */
  async getAuthorizationServerMetadata(): Promise<AuthorizationServerMetadata | undefined> {
    // Already have metadata? Return it
    debugLog(`authorizationServerMetadata: ${JSON.stringify(this.authorizationServerMetadata)}`)
    if (this.authorizationServerMetadata) {
      return this.authorizationServerMetadata
    }

    // Fetch metadata and cache in memory for this session
    try {
      this.authorizationServerMetadata = await fetchAuthorizationServerMetadata(this.options.serverUrl)
      if (this.authorizationServerMetadata?.scopes_supported) {
        debugLog('Authorization server supports scopes', {
          scopes_supported: this.authorizationServerMetadata.scopes_supported,
        })
      }
      return this.authorizationServerMetadata
    } catch (error) {
      debugLog('Failed to fetch authorization server metadata', error)
      return undefined
    }
  }

  private getEffectiveScope(): string {
    // Priority 1: User-provided scope from staticOAuthClientMetadata (highest priority)
    if (this.staticOAuthClientMetadata?.scope && this.staticOAuthClientMetadata.scope.trim().length > 0) {
      debugLog('Using scope from staticOAuthClientMetadata', { scope: this.staticOAuthClientMetadata.scope })
      return this.staticOAuthClientMetadata.scope
    }

    // Priority 2: Scope from WWW-Authenticate header (per MCP spec)
    if (this.wwwAuthenticateScope && this.wwwAuthenticateScope.trim().length > 0) {
      debugLog('Using scope from WWW-Authenticate header', { scope: this.wwwAuthenticateScope })
      return this.wwwAuthenticateScope
    }

    // Priority 3: Scopes from Protected Resource Metadata (RFC 9728)
    if (this.protectedResourceMetadata?.scopes_supported?.length) {
      const scope = this.protectedResourceMetadata.scopes_supported.join(' ')
      debugLog('Using scopes from Protected Resource Metadata', {
        scopes_supported: this.protectedResourceMetadata.scopes_supported,
        scope,
      })
      return scope
    }

    // Priority 4: Scope from client registration response
    if (this._clientInfo?.scope && this._clientInfo.scope.trim().length > 0) {
      debugLog('Using scope from client registration response', { scope: this._clientInfo.scope })
      return this._clientInfo.scope
    }

    // Priority 5: Use authorization server's supported scopes if available
    if (this.authorizationServerMetadata?.scopes_supported?.length) {
      const scope = this.authorizationServerMetadata.scopes_supported.join(' ')
      debugLog('Using scopes from Authorization Server Metadata', {
        scopes_supported: this.authorizationServerMetadata.scopes_supported,
        scope,
      })
      return scope
    }

    // Priority 6: Fallback to hardcoded default
    debugLog('Using fallback default scope')
    return 'openid email profile'
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    debugLog('Reading client info')
    if (this.staticOAuthClientInfo) {
      debugLog('Returning static client info')
      this._clientInfo = this.staticOAuthClientInfo
      return this.staticOAuthClientInfo
    }
    const clientInfo = await readJsonFile<OAuthClientInformationFull>(
      this.serverUrlHash,
      'client_info.json',
      OAuthClientInformationFullSchema,
    )

    if (clientInfo) {
      this._clientInfo = clientInfo
    }

    debugLog('Client info result:', clientInfo ? 'Found' : 'Not found')
    return clientInfo
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    debugLog('Saving client info', { client_id: clientInformation.client_id })
    this._clientInfo = clientInformation
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * The fetch to hand the SDK transports. They thread it all the way into their OAuth token
   * requests, which is the only place this process can see which refresh token a given
   * attempt is about to spend.
   *
   * Refresh grants are serialized here and retargeted at whatever token is current on disk.
   * The SDK lets concurrent sends enter authentication independently, all sharing this one
   * provider, so without this two flows would read the same single-use refresh token and
   * one of them would lose its own race for no reason. Serialization is per provider
   * instance, which in practice is per process; it does nothing about other mcp-remote
   * processes sharing the same token file - see invalidateTokens for what covers those.
   *
   * Anything that is not a refresh grant passes straight through untouched.
   */
  readonly transportFetch: FetchLike = (url, init) => {
    const body = init?.body
    if (!(body instanceof URLSearchParams) || body.get('grant_type') !== 'refresh_token') {
      return globalThis.fetch(url, init)
    }
    return this.queueRefresh(() => this.sendRefreshGrant(url, init, body))
  }

  /**
   * Runs `work` after every refresh already queued on this provider has settled. Runs it
   * either way, so one failed refresh cannot wedge every later one behind it.
   */
  private queueRefresh<T>(work: () => Promise<T>): Promise<T> {
    const result = this._refreshQueue.then(work, work)
    // Mapped to undefined so the queue doesn't pin the resolved Response - and its body -
    // in memory for the idle hour until the next refresh.
    this._refreshQueue = result.then(
      () => undefined,
      () => undefined,
    )
    return result
  }

  /**
   * Issues one refresh grant, holding the queue across the whole read-send-persist cycle.
   *
   * Neither the retarget nor the write may turn a working refresh into a failure: the SDK
   * treats an unrecognized error from this call as "refresh unavailable" and falls through
   * to a browser re-authorization, so anything that goes wrong here degrades to sending the
   * request exactly as the SDK built it.
   */
  private async sendRefreshGrant(url: string | URL, init: RequestInit | undefined, body: URLSearchParams): Promise<Response> {
    await this.retargetToCurrentToken(body)

    const submitted = body.get('refresh_token')
    const response = await globalThis.fetch(url, init)
    if (!response.ok) {
      return response
    }

    try {
      // Cloned so the SDK still gets an unread body if anything below bails out.
      const refreshed = OAuthTokensSchema.safeParse(await response.clone().json())
      if (!refreshed.success) {
        return response
      }

      // A server that does not rotate omits refresh_token, and the token we submitted stays
      // valid - the same rule the SDK's refreshAuthorization applies. Spread conditionally so
      // a null from `body.get` cannot land on disk, where the token schema would reject it.
      const tokens = { ...(submitted ? { refresh_token: submitted } : {}), ...refreshed.data }

      try {
        // Persist before releasing the queue so the next refresh in line reads the pair we
        // just obtained rather than the token we spent. The marker is only recorded once
        // that write actually landed, so a failure here leaves saveTokens free to retry it.
        await this.persistTokens(tokens)
        this.rememberPersistedTokens(tokens)
      } catch (error) {
        debugLog('Could not store the refreshed tokens, leaving that to saveTokens', { error: String(error) })
      }

      // Hand the SDK a body naming the refresh token this request actually used.
      // refreshAuthorization backfills the token it *believed* it sent, from a variable our
      // retarget cannot reach, so after a retarget that value is one the server has already
      // retired. Returned even when the write above failed: saveTokens is then the only
      // route to disk, and it must not be handed the spent token.
      return new Response(JSON.stringify(tokens), {
        status: response.status,
        statusText: response.statusText,
        // Deliberately not forwarding the original headers: their content-length describes
        // the body we just replaced.
        headers: { 'content-type': response.headers.get('content-type') ?? 'application/json' },
      })
    } catch (error) {
      debugLog('Could not read the refresh response, passing it through untouched', { error: String(error) })
      return response
    }
  }

  /**
   * Points `body` at the refresh token currently on disk when it has rotated past the one
   * this attempt was built with, so a queued attempt spends the live token rather than one
   * the server has already retired.
   */
  private async retargetToCurrentToken(body: URLSearchParams): Promise<void> {
    try {
      const onDisk = await readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)
      if (onDisk?.refresh_token && onDisk.refresh_token !== body.get('refresh_token')) {
        log('Refresh token was rotated while this refresh was queued - sending the current one instead')
        body.set('refresh_token', onDisk.refresh_token)
      }
    } catch (error) {
      debugLog('Could not check for a rotated refresh token, sending the request unchanged', { error: String(error) })
    }
  }

  /**
   * Marks an issuance transportFetch has already written, so the matching saveTokens can
   * skip repeating the write.
   *
   * Keyed on both tokens, because neither alone identifies an issuance. A server that does
   * not rotate repeats the refresh token, so keying on that would conflate every issuance
   * and leave a marker matching forever. OAuth does not promise a fresh access token either,
   * so keying on that would collapse {A,r2} and {A,r3} into one marker - the save for one
   * would consume it and the save for the other would write a spent token over the newer
   * pair. Together they differ whenever the issuance differs.
   *
   * Markers are one-shot, consumed by the matching save. The cap is a leak guard for an
   * issuance whose save never arrives; refreshes are serialized by queueRefresh and each
   * save follows its own refresh within microtasks, so the number outstanding at once stays
   * far below it.
   */
  private rememberPersistedTokens(tokens: OAuthTokens): void {
    const markers = this._persistedIssuances
    markers.add(issuanceKey(tokens))
    const [oldest] = markers
    if (markers.size > MAX_PERSISTED_TOKEN_MARKERS && oldest) {
      markers.delete(oldest)
    }
  }

  /**
   * The one place tokens.json is written, so both the refresh path and the SDK's saveTokens
   * get the same validation and logging.
   */
  private async persistTokens(tokens: OAuthTokens): Promise<void> {
    const timeLeft = tokens.expires_in || 0

    // Alert if expires_in is invalid
    if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
      debugLog('⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', () => ({
        expiresIn: tokens.expires_in,
        tokenObject: tokens,
        stack: new Error('Invalid expires_in value').stack,
      }))
    }

    debugLog('Saving tokens', () => ({
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: `${timeLeft} seconds`,
      expiresInValue: tokens.expires_in,
    }))

    await writeJsonFile(this.serverUrlHash, 'tokens.json', tokens)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    debugLog('Reading OAuth tokens')
    // Thunked: this is the SDK's per-request hot path, so nothing here should be built
    // unless debug logging is actually on.
    debugLog('Token request stack trace:', () => new Error().stack)

    const tokens = await readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)
    // Pin the first refresh token we see. A later read may return another process's freshly
    // rotated token, and letting it overwrite the pin would make invalidateCredentials
    // mistake their live credential for ours and delete it.
    this._pinnedRefreshToken ??= tokens?.refresh_token

    if (tokens) {
      const timeLeft = tokens.expires_in || 0

      // Alert if expires_in is invalid
      if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
        debugLog('⚠️ WARNING: Invalid expires_in detected while reading tokens ⚠️', () => ({
          expiresIn: tokens.expires_in,
          tokenObject: tokens,
          stack: new Error('Invalid expires_in value').stack,
        }))
      }

      debugLog('Token result:', () => ({
        found: true,
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        isExpired: timeLeft <= 0,
        expiresInValue: tokens.expires_in,
      }))
    } else {
      debugLog('Token result: Not found')
    }

    return tokens
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    // transportFetch already wrote this pair, inside the refresh queue and using the token
    // the request actually spent. The SDK calls this afterwards, outside that queue, so a
    // refresh that has since rotated past this pair would otherwise be undone by it.
    // Consuming the marker keeps this to the one save that issuance belongs to.
    if (this._persistedIssuances.delete(issuanceKey(tokens))) {
      debugLog('Skipping saveTokens; the refresh that produced these tokens already stored them')
      return
    }

    // Deliberately leaves _pinnedRefreshToken alone: a concurrent flow may be mid-refresh
    // with the token it pinned, and retiring it here would make that flow's invalidation
    // delete the pair we just wrote. Only invalidateTokens retires the pin.
    await this.persistTokens(tokens)
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // Optionally fetch metadata for debugging/informational purposes (non-blocking)
    this.getAuthorizationServerMetadata().catch(() => {
      // Ignore errors, metadata is optional
    })

    if (this.authorizeResource) {
      authorizationUrl.searchParams.set('resource', this.authorizeResource)
    }

    const effectiveScope = this.getEffectiveScope()
    authorizationUrl.searchParams.set('scope', effectiveScope)
    debugLog('Added scope parameter to authorization URL', { scopes: effectiveScope })

    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    debugLog('Redirecting to authorization URL', authorizationUrl.toString())

    try {
      await open(sanitizeUrl(authorizationUrl.toString()))
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      debugLog('Failed to open browser', error)
    }
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    debugLog('Saving code verifier')
    await writeTextFile(this.serverUrlHash, 'code_verifier.txt', codeVerifier)
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    debugLog('Reading code verifier')
    const verifier = await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session')
    debugLog('Code verifier found:', !!verifier)
    return verifier
  }

  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    debugLog(`Invalidating credentials: ${scope}`)

    switch (scope) {
      case 'all':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'client_info.json'),
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
        ])
        this._clientInfo = undefined
        this._pinnedRefreshToken = undefined
        this._persistedIssuances.clear()
        debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        this._clientInfo = undefined
        debugLog('Client information invalidated')
        break

      case 'tokens':
        await this.invalidateTokens()
        break

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, 'code_verifier.txt')
        debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }

  /**
   * Deletes the stored tokens unless another party rotated them out from under us.
   *
   * Refresh tokens are single use on rotating servers: when several mcp-remote processes
   * share this token file, the first to refresh wins and the rest fail with invalid_grant
   * while holding the stale token. The winner's fresh pair is already on disk, so keep it -
   * the SDK re-runs its auth flow right after this call and picks it up, instead of
   * deleting a live credential and forcing a browser re-auth.
   *
   * This is a heuristic, not mutual exclusion, and the remaining gaps are deliberate:
   *
   * - The pin is per-provider, not per-refresh-attempt, because the SDK exposes no attempt
   *   handle. transportFetch serializes this process's refreshes so at most one attempt is
   *   ever outstanding against it, which is what makes the two equivalent here. Two
   *   providers for one server in a single process would break that assumption.
   * - Refreshes are not serialized across processes. N processes waking together still
   *   produce N rotations per expiry event.
   * - The read below and the delete are not atomic. A winner renaming its rotated pair into
   *   place between them still loses it. Atomic config writes remove torn reads as a cause
   *   of a wrong answer here, but not this window.
   * - A refresh failing for any reason other than invalid_grant never reaches this code, so
   *   the pin survives a network blip and goes stale.
   *
   * Losing a credential this way costs a browser re-auth, and recovery is bounded at roughly
   * four attempts - see the rotation-race scenario in utils.oauth.test.ts - beyond which the
   * connection fails rather than degrading to a re-auth.
   *
   * What remains is the cross-process half. It needs a lock around the token file, alongside
   * the in-process queue transportFetch already holds. That lock would retire this guard,
   * the InvalidGrantError reconnect in connectToRemoteServer, and the persisted-issuance
   * markers together - they are three layers of containment for one race.
   */
  private async invalidateTokens(): Promise<void> {
    // Retire the pin up front, so it happens on every path out of here. The next attempt
    // re-pins from disk, which is what bounds a wrong decision below to a single auth
    // cycle: if we keep tokens we should have deleted, the following attempt pins the
    // current token, matches it, deletes, and reaches browser auth. A pin left in place
    // would keep a dead pair forever.
    const pinned = this._pinnedRefreshToken
    this._pinnedRefreshToken = undefined

    const onDisk = pinned ? await readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema) : undefined
    if (onDisk?.refresh_token && onDisk.refresh_token !== pinned) {
      log('Stored tokens were rotated by a concurrent process - keeping the newer tokens and retrying with them')
      return
    }

    await deleteConfigFile(this.serverUrlHash, 'tokens.json')
    // Nothing we wrote is on disk any more, so no save should be suppressed on its behalf.
    this._persistedIssuances.clear()
    debugLog('OAuth tokens invalidated')
  }
}
