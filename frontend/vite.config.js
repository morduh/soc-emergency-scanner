import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  // Build to ../frontend/build so app.py can find it at frontend/build/index.html
  build: {
    outDir: 'build',
    emptyOutDir: true,
  },
  // Serve from root so PyWebView's file:// protocol works
  base: './',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
  },
});
