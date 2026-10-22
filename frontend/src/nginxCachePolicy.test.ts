import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

interface NginxLocationBlock {
  raw: string
  modifier: string
  pattern: string
  cacheControl: string | null
  headers: Map<string, string>
}

interface ParsedNginxConfig {
  serverHeaders: Map<string, string>
  locations: NginxLocationBlock[]
}

const REQUIRED_SECURITY_HEADERS = [
  'X-Content-Type-Options',
  'Referrer-Policy',
  'X-Frame-Options',
  'Cross-Origin-Resource-Policy',
  'Cross-Origin-Opener-Policy',
  'Cross-Origin-Embedder-Policy',
  'Content-Security-Policy',
]

/**
 * Parse an nginx server config to extract server-level headers and location blocks.
 */
function parseNginxConfig(configContent: string): ParsedNginxConfig {
  const lines = configContent.split('\n')
  const serverHeaders = new Map<string, string>()
  const locations: NginxLocationBlock[] = []

  let inLocation = false
  let currentLocationModifier = ''
  let currentLocationPattern = ''
  let currentLocationLines: string[] = []

  for (const rawLine of lines) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue

    const locationMatch = line.match(/^location\s+(\^~\s+|~\*\s+|~|=|)(.*?)\s*\{$/)
    if (locationMatch) {
      inLocation = true
      currentLocationModifier = locationMatch[1].trim()
      currentLocationPattern = locationMatch[2].trim()
      currentLocationLines = []
      continue
    }

    if (inLocation) {
      if (line === '}') {
        inLocation = false
        const locBlockContent = currentLocationLines.join('\n')
        const headers = new Map<string, string>()
        let cacheControl: string | null = null

        for (const locLine of currentLocationLines) {
          const headerMatch = locLine.match(/add_header\s+([\w-]+)\s+"([^"]+)"(?:\s+always)?;/i)
          if (headerMatch) {
            const [, headerName, headerVal] = headerMatch
            headers.set(headerName, headerVal)
            if (headerName.toLowerCase() === 'cache-control') {
              cacheControl = headerVal
            }
          }
        }

        locations.push({
          raw: locBlockContent,
          modifier: currentLocationModifier,
          pattern: currentLocationPattern,
          cacheControl,
          headers,
        })
      } else {
        currentLocationLines.push(line)
      }
    } else {
      const serverHeaderMatch = line.match(/add_header\s+([\w-]+)\s+"([^"]+)"(?:\s+always)?;/i)
      if (serverHeaderMatch) {
        serverHeaders.set(serverHeaderMatch[1], serverHeaderMatch[2])
      }
    }
  }

  return { serverHeaders, locations }
}

/**
 * Determine the effective location block matching a request path.
 * Follows nginx matching precedence:
 * 1. Exact match `=`
 * 2. Preferential prefix `^~`
 * 3. Regular expressions `~*` / `~` (first matched)
 * 4. Standard prefix (longest prefix)
 */
function resolveNginxLocation(locations: NginxLocationBlock[], path: string): NginxLocationBlock | undefined {
  // 1. Exact match
  for (const loc of locations) {
    if (loc.modifier === '=' && loc.pattern === path) {
      return loc
    }
  }

  // 2. Preferential prefix (^~)
  for (const loc of locations) {
    if (loc.modifier === '^~' && path.startsWith(loc.pattern)) {
      return loc
    }
  }

  // 3. Regular expression matches (~*)
  for (const loc of locations) {
    if (loc.modifier === '~*' || loc.modifier === '~') {
      const flags = loc.modifier === '~*' ? 'i' : ''
      const regex = new RegExp(loc.pattern, flags)
      if (regex.test(path)) {
        return loc
      }
    }
  }

  // 4. Longest standard prefix match
  let bestMatch: NginxLocationBlock | undefined
  let longestLength = -1
  for (const loc of locations) {
    if (loc.modifier === '' && path.startsWith(loc.pattern)) {
      if (loc.pattern.length > longestLength) {
        longestLength = loc.pattern.length
        bestMatch = loc
      }
    }
  }

  return bestMatch
}

describe('nginx.conf cache policy and security headers', () => {
  const nginxConfPath = resolve(__dirname, '..', 'nginx.conf')
  const nginxConf = readFileSync(nginxConfPath, 'utf8')
  const parsed = parseNginxConfig(nginxConf)

  describe('Server-level security headers', () => {
    it('defines all required security headers at server level', () => {
      for (const header of REQUIRED_SECURITY_HEADERS) {
        expect(parsed.serverHeaders.has(header), `Server missing ${header}`).toBe(true)
      }
    })
  })

  describe('Location-level repeated security headers', () => {
    it('repeats all required security headers in every location that uses add_header', () => {
      expect(parsed.locations.length).toBeGreaterThanOrEqual(4)
      for (const loc of parsed.locations) {
        for (const header of REQUIRED_SECURITY_HEADERS) {
          expect(
            loc.headers.has(header),
            `Location [${loc.modifier} ${loc.pattern}] missing repeated security header: ${header}`
          ).toBe(true)
        }
      }
    })
  })

  describe('Cache policy per path', () => {
    it('revalidates unhashed circuit artifacts under /noir/ on each load', () => {
      const circuitPaths = [
        '/noir/silent_witness.json',
        '/noir/silent_witness_helper.json',
        '/noir/silent_witness_aggregator.json',
        '/noir/silent_witness_aggregator_helper.json',
      ]

      for (const path of circuitPaths) {
        const matched = resolveNginxLocation(parsed.locations, path)
        expect(matched, `No matching location for ${path}`).toBeDefined()
        expect(matched?.modifier).toBe('^~')
        expect(matched?.pattern).toBe('/noir/')
        expect(matched?.cacheControl).toBe('no-cache')
      }
    })

    it('keeps immutable caching for Vite content-hashed assets under /assets/', () => {
      const assetPaths = [
        '/assets/index-D8x2n91a.js',
        '/assets/index-Cz91bAq2.css',
        '/assets/logo-Ak918b.png',
        '/assets/vendor-19bc71a.json',
      ]

      for (const path of assetPaths) {
        const matched = resolveNginxLocation(parsed.locations, path)
        expect(matched, `No matching location for ${path}`).toBeDefined()
        expect(matched?.modifier).toBe('^~')
        expect(matched?.pattern).toBe('/assets/')
        expect(matched?.cacheControl).toContain('immutable')
        expect(matched?.cacheControl).toContain('max-age=31536000')
      }
    })

    it('keeps immutable caching for wasm artifacts', () => {
      const wasmPaths = ['/bb.wasm', '/assets/barretenberg.wasm']
      for (const path of wasmPaths) {
        const matched = resolveNginxLocation(parsed.locations, path)
        expect(matched, `No matching location for ${path}`).toBeDefined()
        expect(matched?.cacheControl).toContain('immutable')
        expect(matched?.cacheControl).toContain('max-age=31536000')
      }
    })

    it('serves SPA fallback with no-store cache policy for HTML/root paths', () => {
      const spaPaths = ['/', '/index.html', '/verify', '/studio']
      for (const path of spaPaths) {
        const matched = resolveNginxLocation(parsed.locations, path)
        expect(matched, `No matching location for ${path}`).toBeDefined()
        expect(matched?.pattern).toBe('/')
        expect(matched?.cacheControl).toBe('no-store')
      }
    })
  })
})
