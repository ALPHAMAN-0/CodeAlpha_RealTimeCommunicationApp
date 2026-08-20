import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://localhost:4000', changeOrigin: false },
      // `ws: true` ONLY on the socket path. Applying it to /api too would
      // collide with Vite's own HMR websocket and break hot reload.
      '/socket.io': { target: 'http://localhost:4000', ws: true, changeOrigin: false },
    },
  },
  build: {
    // Vite otherwise injects a small inline module-preload polyfill, which
    // would force 'unsafe-inline' into the production script-src and defeat
    // most of what the CSP is for.
    modulePreload: { polyfill: false },
    sourcemap: true,
    target: 'es2022',
  },
});
