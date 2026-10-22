import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

describe('CLI version output', () => {
  const packageJsonPath = resolve(__dirname, '../package.json')
  const cliPath = resolve(__dirname, '../dist/cli.js')
  const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf-8')) as { version: string }

  it('prints only the semver string and exits 0 for --version', () => {
    const stdout = execFileSync(process.execPath, [cliPath, '--version'], {
      encoding: 'utf-8',
    })
    expect(stdout.trim()).toBe(pkg.version)
  })

  it('prints only the semver string and exits 0 for version subcommand', () => {
    const stdout = execFileSync(process.execPath, [cliPath, 'version'], {
      encoding: 'utf-8',
    })
    expect(stdout.trim()).toBe(pkg.version)
  })
})
