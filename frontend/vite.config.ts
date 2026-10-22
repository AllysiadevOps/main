import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { browserBuildTargets } from './browser-support.mjs'

// Cross-Origin-Opener-Policy: same-origin and
// Cross-Origin-Embedder-Policy: require-corp are required for
// cross-origin isolation, which enables SharedArrayBuffer and
// multithreaded WASM proving via @aztec/bb.js.
const COOP_COEP_HEADERS = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
}

// https://vite.dev/config/
const config = {
  plugins: [react()],
  server: {
    headers: COOP_COEP_HEADERS,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: [],
  },
  build: {
    target: [...browserBuildTargets],
    chunkSizeWarningLimit: 3600,
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes('@noir-lang')) return 'noir-runtime'
          if (id.includes('@stellar') || id.includes('@scure') || id.includes('@noble')) {
            return 'stellar'
          }
          if (id.includes('react') || id.includes('react-dom')) return 'react'
        },
      },
    },
  },
}

export default defineConfig(config)
