import { afterEach, beforeEach } from 'vitest'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'

/**
 * Points MCP_REMOTE_CONFIG_DIR at a fresh temp directory for the surrounding block and
 * restores the previous value afterwards, so tests can exercise the real mcp-auth-config
 * filesystem layer without touching the developer's ~/.mcp-auth.
 *
 * Call from inside a describe to scope the hooks to it.
 */
export function useTempConfigDir(): void {
  let tmpConfigDir = ''
  let originalConfigDirEnv: string | undefined

  beforeEach(async () => {
    tmpConfigDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-test-'))
    originalConfigDirEnv = process.env.MCP_REMOTE_CONFIG_DIR
    process.env.MCP_REMOTE_CONFIG_DIR = tmpConfigDir
  })

  afterEach(async () => {
    if (originalConfigDirEnv === undefined) {
      delete process.env.MCP_REMOTE_CONFIG_DIR
    } else {
      process.env.MCP_REMOTE_CONFIG_DIR = originalConfigDirEnv
    }
    await fs.rm(tmpConfigDir, { recursive: true, force: true })
  })
}
