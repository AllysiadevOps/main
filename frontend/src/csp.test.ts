/**
 * Tests for the Content Security Policy builder (src/csp.ts).
 *
 * Test structure
 * ──────────────
 * 1. extractOrigin        – URL-to-origin normalisation
 * 2. buildCsp             – directive presence and value correctness
 * 3. buildCsp – positive  – known-good configurations must pass validateCsp
 * 4. buildCsp – negative  – deliberate bad configs must be rejected
 * 5. validateCsp          – each individual violation is detected in isolation
 * 6. nginx.conf snapshot  – the production config file contains the CSP header
 *    and every required directive keyword so drift is caught at test time.
 */

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { buildCsp, extractOrigin, validateCsp } from './csp'

// ─── helpers ──────────────────────────────────────────────────────────────────

const API = 'https://api.harpocrates.example'
const RPC = 'https://soroban-testnet.stellar.org'
const NONCE = 'abc123XYZ'

/** Build a minimal valid policy for use in validation tests. */
function goodPolicy(overrides: Partial<Parameters<typeof buildCsp>[0]> = {}): string {
  return buildCsp({ apiBase: API, stellarRpcUrl: RPC, ...overrides })
}

/** Parse a CSP string into a map of directive → token array. */
function parsePolicy(policy: string): Map<string, string[]> {
  const map = new Map<string, string[]>()
  for (const part of policy.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean)
    if (tokens.length > 0) {
      map.set(tokens[0].toLowerCase(), tokens.slice(1))
    }
  }
  return map
}

// ─── 1. extractOrigin ─────────────────────────────────────────────────────────

describe('extractOrigin', () => {
  it('returns the origin for a full https URL', () => {
    expect(extractOrigin('https://api.example.com/some/path?q=1')).toBe('https://api.example.com')
  })

  it('returns the origin for an http URL with a non-standard port', () => {
    expect(extractOrigin('http://127.0.0.1:5050/api')).toBe('http://127.0.0.1:5050')
  })

  it('strips the path from a URL that is already just an origin', () => {
    expect(extractOrigin('https://soroban-testnet.stellar.org')).toBe(
      'https://soroban-testnet.stellar.org',
    )
  })

  it('returns the input unchanged when it is not a parseable URL', () => {
    expect(extractOrigin('not-a-url')).toBe('not-a-url')
  })

  it('handles URLs with explicit port 443', () => {
    expect(extractOrigin('https://secure.example.com:443/path')).toBe(
      'https://secure.example.com',
    )
  })
})

// ─── 2. buildCsp – directive presence and values ──────────────────────────────

describe('buildCsp – directive structure', () => {
  it('produces a non-empty string', () => {
    expect(goodPolicy()).toBeTruthy()
  })

  it('includes all required directive names', () => {
    const required = [
      'script-src',
      'style-src',
      'connect-src',
      'worker-src',
      'child-src',
      'img-src',
      'font-src',
      'object-src',
      'frame-ancestors',
      'frame-src',
      'base-uri',
      'form-action',
    ]
    const policy = goodPolicy()
    for (const directive of required) {
      expect(policy, `missing directive: ${directive}`).toContain(directive)
    }
  })

  it("includes 'wasm-unsafe-eval' in script-src for @aztec/bb.js WASM support", () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('script-src')).toContain("'wasm-unsafe-eval'")
  })

  it("includes 'strict-dynamic' in script-src for Vite ES-module chunks", () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('script-src')).toContain("'strict-dynamic'")
  })

  it('does NOT include unsafe-inline in script-src', () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('script-src')).not.toContain("'unsafe-inline'")
  })

  it('does NOT include unsafe-eval in script-src', () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('script-src')).not.toContain("'unsafe-eval'")
  })

  it('includes the API origin in connect-src', () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('connect-src')).toContain('https://api.harpocrates.example')
  })

  it('includes the Stellar RPC origin in connect-src', () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('connect-src')).toContain('https://soroban-testnet.stellar.org')
  })

  it("sets worker-src to 'self' blob: for @aztec/bb.js workers", () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('worker-src')).toContain("'self'")
    expect(map.get('worker-src')).toContain('blob:')
  })

  it("sets child-src to 'self' blob: as fallback for worker-src", () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('child-src')).toContain("'self'")
    expect(map.get('child-src')).toContain('blob:')
  })

  it("sets frame-ancestors to 'none' to prevent clickjacking", () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('frame-ancestors')).toContain("'none'")
  })

  it("sets object-src to 'none' to disable plugins", () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('object-src')).toContain("'none'")
  })

  it("sets base-uri to 'self' to prevent base-tag hijacking", () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('base-uri')).toContain("'self'")
  })

  it("sets form-action to 'self'", () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('form-action')).toContain("'self'")
  })

  it("sets img-src to 'self' data:", () => {
    const map = parsePolicy(goodPolicy())
    expect(map.get('img-src')).toContain("'self'")
    expect(map.get('img-src')).toContain('data:')
  })
})

// ─── 3. buildCsp – nonce handling ─────────────────────────────────────────────

describe('buildCsp – nonce', () => {
  it("includes the nonce token in script-src when provided", () => {
    const policy = buildCsp({ apiBase: API, stellarRpcUrl: RPC, nonce: NONCE })
    expect(policy).toContain(`'nonce-${NONCE}'`)
    const map = parsePolicy(policy)
    expect(map.get('script-src')).toContain(`'nonce-${NONCE}'`)
  })

  it('omits the nonce token when nonce is not provided', () => {
    const policy = buildCsp({ apiBase: API, stellarRpcUrl: RPC })
    expect(policy).not.toContain("'nonce-")
  })

  it('omits the nonce token when nonce is an empty string', () => {
    const policy = buildCsp({ apiBase: API, stellarRpcUrl: RPC, nonce: '' })
    expect(policy).not.toContain("'nonce-")
  })
})

// ─── 4. buildCsp – origin extraction ─────────────────────────────────────────

describe('buildCsp – origin extraction from URLs', () => {
  it('strips the path from VITE_API_BASE before inserting into connect-src', () => {
    const policy = buildCsp({
      apiBase: 'https://api.harpocrates.example/v1/some/path',
      stellarRpcUrl: RPC,
    })
    const map = parsePolicy(policy)
    expect(map.get('connect-src')).toContain('https://api.harpocrates.example')
    expect(map.get('connect-src')).not.toContain('/v1/some/path')
  })

  it('strips the path from VITE_STELLAR_RPC_URL before inserting into connect-src', () => {
    const policy = buildCsp({
      apiBase: API,
      stellarRpcUrl: 'https://soroban-testnet.stellar.org/rpc',
    })
    const map = parsePolicy(policy)
    expect(map.get('connect-src')).toContain('https://soroban-testnet.stellar.org')
    expect(map.get('connect-src')).not.toContain('/rpc')
  })

  it('handles a localhost API origin with port', () => {
    const policy = buildCsp({
      apiBase: 'http://127.0.0.1:5050',
      stellarRpcUrl: RPC,
    })
    const map = parsePolicy(policy)
    expect(map.get('connect-src')).toContain('http://127.0.0.1:5050')
  })
})

// ─── 5. validateCsp – positive (valid policies must return no violations) ─────

describe('validateCsp – positive cases (no violations expected)', () => {
  it('returns an empty array for the default testnet policy', () => {
    expect(validateCsp(goodPolicy())).toEqual([])
  })

  it('returns an empty array for the policy with a nonce', () => {
    expect(validateCsp(goodPolicy({ nonce: NONCE }))).toEqual([])
  })

  it('returns an empty array for a production mainnet policy', () => {
    const policy = buildCsp({
      apiBase: 'https://api.harpocrates.example',
      stellarRpcUrl: 'https://soroban-mainnet.stellar.org',
    })
    expect(validateCsp(policy)).toEqual([])
  })

  it('returns an empty array for a localhost development policy', () => {
    const policy = buildCsp({
      apiBase: 'http://127.0.0.1:5050',
      stellarRpcUrl: 'https://soroban-testnet.stellar.org',
    })
    expect(validateCsp(policy)).toEqual([])
  })
})

// ─── 6. validateCsp – negative (each bad pattern is individually detected) ────

describe('validateCsp – negative cases (violations must be reported)', () => {
  it('reports a violation when script-src contains a wildcard', () => {
    const policy = goodPolicy().replace(
      /script-src [^;]+/,
      "script-src 'self' * 'wasm-unsafe-eval'",
    )
    const violations = validateCsp(policy)
    expect(violations.some((v) => v.includes('script-src') && v.includes('*'))).toBe(true)
  })

  it('reports a violation when connect-src contains a wildcard', () => {
    const policy = goodPolicy().replace(/connect-src [^;]+/, 'connect-src *')
    const violations = validateCsp(policy)
    expect(violations.some((v) => v.includes('connect-src') && v.includes('*'))).toBe(true)
  })

  it("reports a violation when script-src contains 'unsafe-inline'", () => {
    const policy = goodPolicy().replace(
      /script-src [^;]+/,
      "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
    )
    const violations = validateCsp(policy)
    expect(violations.some((v) => /unsafe-inline/.test(v) && /script-src/.test(v))).toBe(true)
  })

  it("reports a violation when style-src contains 'unsafe-inline'", () => {
    const policy = goodPolicy().replace(/style-src [^;]+/, "style-src 'self' 'unsafe-inline'")
    const violations = validateCsp(policy)
    expect(violations.some((v) => /unsafe-inline/.test(v) && /style-src/.test(v))).toBe(true)
  })

  it("reports a violation when script-src contains 'unsafe-eval'", () => {
    const policy = goodPolicy().replace(
      /script-src [^;]+/,
      "script-src 'self' 'unsafe-eval'",
    )
    const violations = validateCsp(policy)
    expect(violations.some((v) => /unsafe-eval/.test(v) && !/wasm/.test(v))).toBe(true)
  })

  it('reports a violation when frame-ancestors is absent', () => {
    const policy = goodPolicy()
      .split(';')
      .filter((p) => !p.trim().startsWith('frame-ancestors'))
      .join(';')
    const violations = validateCsp(policy)
    expect(violations.some((v) => /frame-ancestors/.test(v) && /missing/.test(v))).toBe(true)
  })

  it("reports a violation when object-src is not 'none'", () => {
    const policy = goodPolicy().replace(/object-src [^;]+/, "object-src 'self'")
    const violations = validateCsp(policy)
    expect(violations.some((v) => /object-src/.test(v))).toBe(true)
  })

  it('reports a violation when connect-src is absent entirely', () => {
    const policy = goodPolicy()
      .split(';')
      .filter((p) => !p.trim().startsWith('connect-src'))
      .join(';')
    const violations = validateCsp(policy)
    expect(violations.some((v) => /connect-src/.test(v) && /missing/.test(v))).toBe(true)
  })

  it('can report multiple violations simultaneously', () => {
    // Inject both unsafe-inline and a wildcard in one policy.
    const policy =
      "script-src 'unsafe-inline' *; connect-src *; object-src 'self'"
    const violations = validateCsp(policy)
    expect(violations.length).toBeGreaterThanOrEqual(3)
  })
})

// ─── 7. nginx.conf snapshot – production config contains the CSP header ───────

describe('nginx.conf – production CSP header presence', () => {
  // Read the file relative to this test file's location so the path is
  // portable across machines and CI environments.
  const nginxConf = readFileSync(
    resolve(__dirname, '..', 'nginx.conf'),
    'utf8',
  )

  it('contains a Content-Security-Policy add_header directive', () => {
    expect(nginxConf).toMatch(/add_header\s+Content-Security-Policy\b/i)
  })

  it('includes the always flag on the CSP header', () => {
    expect(nginxConf).toMatch(/Content-Security-Policy[^;]+\balways\b/i)
  })

  it('references the API origin placeholder in connect-src', () => {
    expect(nginxConf).toContain('$VITE_API_BASE')
  })

  it('references the Stellar RPC placeholder in connect-src', () => {
    expect(nginxConf).toContain('$VITE_STELLAR_RPC_URL')
  })

  it("includes 'wasm-unsafe-eval' in the CSP header value", () => {
    expect(nginxConf).toContain('wasm-unsafe-eval')
  })

  it("includes 'strict-dynamic' in the CSP header value", () => {
    expect(nginxConf).toContain('strict-dynamic')
  })

  it("includes 'frame-ancestors' in the CSP header value", () => {
    expect(nginxConf).toContain('frame-ancestors')
  })

  it("includes 'object-src' in the CSP header value", () => {
    expect(nginxConf).toContain('object-src')
  })

  it("includes 'worker-src' in the CSP header value", () => {
    expect(nginxConf).toContain('worker-src')
  })

  it('also sets X-Frame-Options DENY as belt-and-suspenders', () => {
    expect(nginxConf).toMatch(/add_header\s+X-Frame-Options\s+DENY\b/i)
  })
})

// ─── 8. index.html snapshot – meta tag is present for local dev ───────────────

describe('index.html – CSP meta tag for local dev', () => {
  const indexHtml = readFileSync(
    resolve(__dirname, '..', 'index.html'),
    'utf8',
  )

  it('contains a Content-Security-Policy http-equiv meta tag', () => {
    expect(indexHtml).toMatch(/<meta\s[^>]*http-equiv=["']Content-Security-Policy["']/i)
  })

  it('includes wasm-unsafe-eval in the meta tag content', () => {
    expect(indexHtml).toContain('wasm-unsafe-eval')
  })

  it('includes the local-dev API origin in the meta tag content', () => {
    expect(indexHtml).toContain('127.0.0.1:5050')
  })

  it('includes the Stellar testnet RPC origin in the meta tag content', () => {
    expect(indexHtml).toContain('soroban-testnet.stellar.org')
  })

  it('does NOT include frame-ancestors in the meta tag (browser-ignored; HTTP header only)', () => {
    // Extract only the meta tag's content attribute value so we don't
    // accidentally match the explanatory comment above it.
    const metaMatch = indexHtml.match(/<meta\s[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>/i)
    expect(metaMatch).not.toBeNull()
    expect(metaMatch![0]).not.toContain('frame-ancestors')
  })
})

// ─── 9. nginx.conf – COOP/COEP headers for cross-origin isolation ─────────────

describe('nginx.conf – Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy', () => {
  const nginxConf = readFileSync(
    resolve(__dirname, '..', 'nginx.conf'),
    'utf8',
  )

  it('sets Cross-Origin-Opener-Policy: same-origin in the server block', () => {
    expect(nginxConf).toMatch(
      /add_header\s+Cross-Origin-Opener-Policy\s+"same-origin"\s+always/i,
    )
  })

  it('sets Cross-Origin-Embedder-Policy: require-corp in the server block', () => {
    expect(nginxConf).toMatch(
      /add_header\s+Cross-Origin-Embedder-Policy\s+"require-corp"\s+always/i,
    )
  })

  it('repeats COOP in the .wasm location block', () => {
    const wasmIndex = nginxConf.indexOf('location ~* \\.wasm$')
    const nextLocation = nginxConf.indexOf('location ~*', wasmIndex + 1)
    const wasmBlock = nextLocation === -1 ? nginxConf.slice(wasmIndex) : nginxConf.slice(wasmIndex, nextLocation)
    expect(wasmBlock).toContain('Cross-Origin-Opener-Policy')
  })

  it('repeats COEP in the .wasm location block', () => {
    const wasmIndex = nginxConf.indexOf('location ~* \\.wasm$')
    const nextLocation = nginxConf.indexOf('location ~*', wasmIndex + 1)
    const wasmBlock = nextLocation === -1 ? nginxConf.slice(wasmIndex) : nginxConf.slice(wasmIndex, nextLocation)
    expect(wasmBlock).toContain('Cross-Origin-Embedder-Policy')
  })

  it('repeats COOP in the static assets location block', () => {
    const assetsIndex = nginxConf.indexOf('location ~* \\.(js|css|')
    const nextLocation = nginxConf.indexOf('location ~*', assetsIndex + 1)
    const assetsBlock = nextLocation === -1 ? nginxConf.slice(assetsIndex) : nginxConf.slice(assetsIndex, nextLocation)
    expect(assetsBlock).toContain('Cross-Origin-Opener-Policy')
  })

  it('repeats COEP in the static assets location block', () => {
    const assetsIndex = nginxConf.indexOf('location ~* \\.(js|css|')
    const nextLocation = nginxConf.indexOf('location ~*', assetsIndex + 1)
    const assetsBlock = nextLocation === -1 ? nginxConf.slice(assetsIndex) : nginxConf.slice(assetsIndex, nextLocation)
    expect(assetsBlock).toContain('Cross-Origin-Embedder-Policy')
  })

  it('repeats COOP in the SPA fallback location block', () => {
    const spaIndex = nginxConf.indexOf('location /')
    const spaBlock = nginxConf.slice(spaIndex)
    expect(spaBlock).toContain('Cross-Origin-Opener-Policy')
  })

  it('repeats COEP in the SPA fallback location block', () => {
    const spaIndex = nginxConf.indexOf('location /')
    const spaBlock = nginxConf.slice(spaIndex)
    expect(spaBlock).toContain('Cross-Origin-Embedder-Policy')
  })

  it('uses the always flag on both COOP and COEP headers', () => {
    // Each header appears 4 times (server + 3 location blocks), always with 'always' flag.
    const coopMatches = nginxConf.match(/Cross-Origin-Opener-Policy[^;]*always/g)
    const coepMatches = nginxConf.match(/Cross-Origin-Embedder-Policy[^;]*always/g)
    expect(coopMatches).not.toBeNull()
    expect(coopMatches!.length).toBeGreaterThanOrEqual(4)
    expect(coepMatches).not.toBeNull()
    expect(coepMatches!.length).toBeGreaterThanOrEqual(4)
  })
})
