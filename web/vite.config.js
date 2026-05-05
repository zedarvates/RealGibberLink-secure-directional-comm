import { defineConfig } from 'vite';

export default defineConfig({
  resolve: {
    alias: {
      env: '/env.js',
    },
  },
  server: {
    open: true,
  },
  build: {
    outDir: 'dist',
    target: 'es2020',
  },
});
