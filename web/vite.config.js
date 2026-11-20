import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Construit dans keryx/web_dist, servi par FastAPI. Aucun script externe à l'exécution (CSP default-src 'self').
export default defineConfig({
  plugins: [react()],
  build: { outDir: '../keryx/web_dist', emptyOutDir: true, sourcemap: false },
  server: { proxy: { '/api': 'http://127.0.0.1:8000' } },
})
