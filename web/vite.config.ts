import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': { target: process.env.VITE_API_PROXY ?? 'http://localhost:8000', changeOrigin: true } } },
  test: { environment: 'jsdom', setupFiles: ['./tests/setup.ts'], exclude: ['e2e/**', 'node_modules/**', 'dist/**'], coverage: { provider: 'v8', reporter: ['text', 'json-summary'], reportsDirectory: '../artifacts/web-coverage' } },
});
