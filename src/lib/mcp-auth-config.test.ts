import { describe, it, expect } from 'vitest'
import fs from 'fs/promises'
import { z } from 'zod'
import { getConfigDir, readJsonFile, writeJsonFile, writeTextFile, getConfigFilePath } from './mcp-auth-config'
import { useTempConfigDir } from './test-support'

// These tests care about file integrity, not token shape.
const anySchema = z.any()

describe('Feature: Config File Writes', () => {
  const serverUrlHash = 'test-hash'

  useTempConfigDir()

  it('Scenario: a reader never observes a partially written file', async () => {
    // Several mcp-remote processes share tokens.json. readJsonFile reports a JSON parse
    // failure as `undefined`, which the rotation guard cannot tell apart from "no tokens
    // saved" - so a torn read makes it delete a live credential. Writes alternate between
    // two very differently sized payloads to widen the window a non-atomic write would leave.
    const small = { refresh_token: 'refresh-1' }
    const large = { refresh_token: 'refresh-2', padding: 'x'.repeat(512 * 1024) }

    await writeJsonFile(serverUrlHash, 'tokens.json', small)

    const observed: any[] = []
    const readers = Array.from({ length: 40 }, async () => {
      for (let i = 0; i < 25; i++) {
        observed.push(await readJsonFile<any>(serverUrlHash, 'tokens.json', anySchema))
      }
    })
    const writers = (async () => {
      for (let i = 0; i < 25; i++) {
        await writeJsonFile(serverUrlHash, 'tokens.json', i % 2 === 0 ? large : small)
      }
    })()

    await Promise.all([...readers, writers])

    // Proves the readers actually ran, rather than the loop below vacuously passing.
    expect(observed).toHaveLength(40 * 25)
    // Every read is one of the two complete payloads - never undefined (torn/absent) and
    // never a value that parsed but lost fields.
    for (const value of observed) {
      expect(value).toBeDefined()
      expect(value.refresh_token).toMatch(/^refresh-[12]$/)
      if (value.refresh_token === 'refresh-2') {
        expect(value.padding).toHaveLength(512 * 1024)
      }
    }
  })

  it('Scenario: writes leave no temporary files behind', async () => {
    await writeJsonFile(serverUrlHash, 'tokens.json', { refresh_token: 'refresh-1' })
    await writeTextFile(serverUrlHash, 'code_verifier.txt', 'verifier')

    const entries = await fs.readdir(getConfigDir())

    expect(entries.sort()).toEqual([`${serverUrlHash}_code_verifier.txt`, `${serverUrlHash}_tokens.json`])
  })

  it('Scenario: the renamed file keeps owner-only permissions', async () => {
    await writeJsonFile(serverUrlHash, 'tokens.json', { refresh_token: 'refresh-1' })

    const stats = await fs.stat(getConfigFilePath(serverUrlHash, 'tokens.json'))

    // The mode is set on the staged file, so this also proves the rename carried it over.
    expect(stats.mode & 0o777).toBe(0o600)
  })

  it('Scenario: overwriting an existing file replaces its contents', async () => {
    await writeJsonFile(serverUrlHash, 'tokens.json', { refresh_token: 'refresh-1' })
    await writeJsonFile(serverUrlHash, 'tokens.json', { refresh_token: 'refresh-2' })

    const result = await readJsonFile<any>(serverUrlHash, 'tokens.json', anySchema)

    expect(result).toEqual({ refresh_token: 'refresh-2' })
  })
})
