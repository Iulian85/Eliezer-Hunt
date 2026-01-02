import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import process from 'node:process';

export default defineConfig({
  plugins: [react()],
  base: './', // Corect, previne rutele absolute greșite
  define: {
    'process.env': {},
  },
  server: {
    host: true,
    port: 3000,
    strictPort: true,
  },
  preview: {
    host: true,
    port: 3000,
    strictPort: true,
    allowedHosts: ['all']
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    minify: 'terser',
    target: 'es2022',
    modulePreload: false, // OPREȘTE importmap/preload
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true,
        pure_funcs: ['console.log', 'console.info', 'console.debug', 'console.warn']
      },
      mangle: {
        toplevel: true,
      },
      format: {
        comments: false,
      }
    },
    rollupOptions: {
      output: {
        // Această setare forțează tot codul în bundle-uri JS clasice
        entryFileNames: 'assets/core-[hash].js',
        chunkFileNames: 'assets/vendor-[hash].js',
        assetFileNames: 'assets/[hash].[ext]',
      },
    },
  },
  // ADAUGĂ ASTA: Forțează pre-procesarea librăriilor mari pentru a evita importurile externe
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'lucide-react',
      '@fingerprintjs/fingerprintjs',
      '@google/genai',
      '@tonconnect/ui-react',
      '@react-three/fiber',
      '@react-three/drei',
      'three',
      'leaflet',
      'react-leaflet',
      'clsx'
    ]
  },
  // Configurare pentru a preveni utilizarea importurilor externe nesigure
  resolve: {
    alias: {
      // Asigură că toate importurile sunt rezolvate local
    }
  }
});