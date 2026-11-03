import { defineConfig } from 'vite'

export default defineConfig({
  base: './',
  build: {
    outDir: 'dist-maintenance-console',
    rollupOptions: {
      input: 'maintenance-console.html',
      output: { entryFileNames: 'assets/console.js', assetFileNames: 'assets/[name][extname]' },
    },
  },
})
