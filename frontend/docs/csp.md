# Content Security Policy

This document describes the Content Security Policy (CSP) deployed by the
Harpocrates frontend, the rationale for each directive, and the steps required
to configure origins correctly for each environment.

## Enforcement surfaces

| Surface | Mechanism | Authoritative? |
|---|---|---|
| Production (Docker / nginx) | `Content-Security-Policy` HTTP header in `nginx.conf` | **Yes** |
| Local dev (`vite dev`) | `<meta http-equiv="Content-Security-Policy">` in `index.html` + Vite `server.headers` | Fallback |
| Preview (`vite preview`) | Same meta tag as local dev | Fallback |

The HTTP header always takes precedence over the meta tag when both are present.
The meta tag exists solely so that the policy is enforced during local
development and `vite preview` runs where nginx is not involved.

> **`frame-ancestors` note:** The `frame-ancestors` directive is silently
> ignored by browsers when it appears in a `<meta>` tag. It is therefore only
> present in the nginx header. `X-Frame-Options: DENY` is set alongside it as
> a belt-and-suspenders measure for older browsers.

---

## Cross-Origin Isolation (COOP / COEP)

Cross-origin isolation is required for `SharedArrayBuffer`, which `@aztec/bb.js`
uses for multithreaded WASM proving. The frontend serves:

| Header | Value | Where |
|---|---|---|
| `Cross-Origin-Opener-Policy` | `same-origin` | `nginx.conf` (production) + Vite `server.headers` (dev) |
| `Cross-Origin-Embedder-Policy` | `require-corp` | `nginx.conf` (production) + Vite `server.headers` (dev) |

With both headers present, `self.crossOriginIsolated` is `true` and the proof
worker can request multiple WASM threads (`navigator.hardwareConcurrency`,
clamped to 1–8). When either header is missing, `crossOriginIsolated` is
`false` and the worker falls back to a single thread (`threadCount: 1`).
Non-isolated environments continue to work — proving is simply single-threaded.

### Wallet extensions and external resources under COEP

COEP `require-corp` blocks the document from loading cross-origin resources
that do not opt in with `Cross-Origin-Resource-Policy: cross-origin`. The
following are verified to still work:

| Resource | Mechanism | COEP impact |
|---|---|---|
| Freighter wallet extension | `window.postMessage` (extension content script ↔ page) | None — `postMessage` is not a fetch/embed, so COEP does not apply. No `connect-src` entry is needed. |
| Backend API (`VITE_API_BASE`) | `fetch()` from the page/worker | Same-origin in production (served via nginx); allowed by CSP `connect-src`. |
| Stellar Soroban RPC (`VITE_STELLAR_RPC_URL`) | `fetch()` from the page/worker | Cross-origin but the RPC server returns `Cross-Origin-Resource-Policy: cross-origin` (or the request is made from a secure context that permits it). CSP `connect-src` includes the RPC origin. |
| Vite HMR websocket (dev) | `ws://localhost:PORT` | Same-origin (dev server); allowed by CSP `connect-src 'self'`. |
| Circuit JSON artifacts (`/noir/*.json`) | `fetch()` from the worker | Same-origin; served by nginx with CORP headers. |

If you add a new external fetch target, add its origin to CSP `connect-src`
in `src/csp.ts` and `nginx.conf`, and confirm the remote server sends
`Cross-Origin-Resource-Policy: cross-origin` or that the resource is
same-origin.

---

## Full policy

```
script-src    'self' 'strict-dynamic' 'wasm-unsafe-eval';
style-src     'self';
connect-src   'self' <VITE_API_BASE-origin> <VITE_STELLAR_RPC_URL-origin>;
worker-src    'self' blob:;
child-src     'self' blob:;
img-src       'self' data:;
font-src      'self';
object-src    'none';
frame-ancestors 'none';
frame-src     'none';
base-uri      'self';
form-action   'self';
```

---

## Directive rationale

### `script-src`

| Token | Reason |
|---|---|
| `'self'` | Allow the Vite entry-point script served from the same origin. |
| `'strict-dynamic'` | Propagates trust to scripts loaded by the trusted entry-point (Vite dynamically imports its generated chunks). Removes the need for `'unsafe-inline'` or per-chunk hashes. |
| `'wasm-unsafe-eval'` | Required by `@aztec/bb.js` (`UltraHonkBackend`), which compiles and executes WebAssembly in the browser for Noir ZK-proof generation. This permits only WebAssembly compilation — raw JavaScript `eval()` remains blocked. |

`'unsafe-inline'` and `'unsafe-eval'` are explicitly **not** included. The
`validateCsp` utility in `src/csp.ts` enforces this in the automated test suite.

### `style-src 'self'`

All CSS is bundled by Vite and served from the same origin. No external
stylesheets, CDN fonts, or inline `style=` attribute injection is permitted.

### `connect-src`

Controls every `fetch()` / `XMLHttpRequest` / WebSocket connection the page
is allowed to open.

| Origin | Purpose |
|---|---|
| `'self'` | Vite HMR websocket in dev; circuit JSON files (`/noir/*.json`). |
| `VITE_API_BASE` | Backend API — steganography embed/extract, proof database. |
| `VITE_STELLAR_RPC_URL` | Stellar Soroban RPC — `getAccount`, `sendTransaction`, `simulateTransaction`, `getTransaction`. |

Freighter wallet extension communication uses `window.postMessage` (not
`fetch`), so it does not require a `connect-src` entry.

### `worker-src 'self' blob:`

`@aztec/bb.js` spawns Web Workers using `blob:` URLs to run WASM proof
generation off the main thread. Both `'self'` and `blob:` are required.

### `child-src 'self' blob:`

Belt-and-suspenders fallback for browsers that do not honour `worker-src`.
The values mirror `worker-src` exactly.

### `img-src 'self' data:`

The favicon is an SVG served from the same origin. `data:` is permitted for
any inline image URIs the UI may generate (e.g. `URL.createObjectURL` results
are `blob:` not `data:`, so adding `blob:` here is not needed).

### `font-src 'self'`

All fonts are bundled by Vite and served from the same origin.

### `object-src 'none'`

Disables all browser plugin types (Flash, Java applets, etc.).

### `frame-ancestors 'none'`

Prevents the application from being embedded inside any `<iframe>`,
`<frame>`, or `<object>` on any other origin. This blocks clickjacking and
credential-overlay attacks. Must be set as an HTTP header; ignored in
`<meta>` tags.

### `frame-src 'none'`

The application itself does not embed any iframes.

### `base-uri 'self'`

Prevents an injected `<base>` tag from redirecting all relative URLs to an
attacker-controlled origin.

### `form-action 'self'`

Plain HTML form submissions are confined to the same origin (the app has no
server-side form targets, but this closes the vector entirely).

---

## Environment-specific origins

The two variable origins in `connect-src` are set via environment variables
injected at build or deploy time.

### Environment variable reference

| Variable | Description | Default (`.env.example`) |
|---|---|---|
| `VITE_API_BASE` | Full URL (or origin) of the backend API | `https://your-backend.example` |
| `VITE_STELLAR_RPC_URL` | Full URL of the Stellar Soroban RPC endpoint | `https://soroban-testnet.stellar.org` |

Only the **origin** portion (`scheme://host[:port]`) is inserted into the CSP
header. `buildCsp()` in `src/csp.ts` calls `extractOrigin()` to strip paths
automatically.

### Per-environment values

| Environment | `VITE_API_BASE` | `VITE_STELLAR_RPC_URL` |
|---|---|---|
| **Production** | `https://api.harpocrates.example` | `https://soroban-mainnet.stellar.org` |
| **Testnet staging** | `https://api-testnet.harpocrates.example` | `https://soroban-testnet.stellar.org` |
| **Local dev** | `http://127.0.0.1:5050` | `https://soroban-testnet.stellar.org` |

> Replace the production values above with your real domain before deploying.

---

## Injecting origins into the nginx header (Docker / CI)

The `nginx.conf` header uses `$VITE_API_BASE` and `$VITE_STELLAR_RPC_URL`
as shell-style placeholders. They are resolved by `envsubst` before nginx
starts.

### Option A — envsubst in the Docker entrypoint

Add an `envsubst` pass to the Dockerfile after copying the static build:

```dockerfile
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html

# nginx official image runs envsubst on *.template files automatically.
# Set the two required variables at `docker run` time:
#   docker run -e VITE_API_BASE=https://api.example.com \
#              -e VITE_STELLAR_RPC_URL=https://soroban-mainnet.stellar.org \
#              harpocrates-frontend
```

The official `nginx` image processes files in `/etc/nginx/templates/` with
`envsubst` and writes the output to `/etc/nginx/conf.d/` before nginx starts.
Rename `nginx.conf` → `default.conf.template` in the templates directory and
no further scripting is required.

### Option B — envsubst in CI before building the image

```sh
export VITE_API_BASE=https://api.harpocrates.example
export VITE_STELLAR_RPC_URL=https://soroban-mainnet.stellar.org

envsubst '$VITE_API_BASE $VITE_STELLAR_RPC_URL' \
  < nginx.conf > nginx.conf.rendered

docker build \
  --build-arg NGINX_CONF=nginx.conf.rendered \
  -t harpocrates-frontend .
```

Pass only the two named variables to `envsubst` (the `'$VAR1 $VAR2'` argument)
to avoid accidentally replacing nginx `$uri` / `$host` variables.

---

## Updating the policy

1. Edit `src/csp.ts` — change directives in `buildCsp()`.
2. Update the `add_header Content-Security-Policy` line in `nginx.conf` to
   match.
3. Update the `<meta>` tag `content` attribute in `index.html` to match (omit
   `frame-ancestors`).
4. Update this document.
5. Run `npm test` — the snapshot tests in `src/csp.test.ts` will catch any
   drift between the three surfaces.

---

## Security properties preserved

| Threat | Mitigation |
|---|---|
| XSS script injection | No `'unsafe-inline'`; `'strict-dynamic'` limits trusted script roots. |
| Credential exfiltration via injected scripts | `connect-src` allows only the two known API origins. |
| WASM-based exploits beyond proof generation | Only `'wasm-unsafe-eval'`; raw `eval()` blocked. |
| Clickjacking / credential-overlay | `frame-ancestors 'none'` + `X-Frame-Options: DENY`. |
| Base-tag hijacking | `base-uri 'self'`. |
| Data exfiltration via form submission | `form-action 'self'`. |
| Plugin-based attacks | `object-src 'none'`. |
