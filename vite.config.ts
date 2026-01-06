
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  // Încărcăm variabilele de mediu pentru a le folosi doar pe cele necesare în 'define'
  const env = loadEnv(mode, process.cwd(), '');
  
  return {
    plugins: [react()],
    base: './',
    define: {
      // Definim doar variabilele specifice care NU încep cu VITE_
      // (Vite le încarcă automat pe cele cu VITE_ în import.meta.env)
      'process.env.ADMIN_WALLET_ADDRESS': JSON.stringify(env.VITE_ADMIN_WALLET_ADDRESS || ''),
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
      allowedHosts: ['eliezer-hunt-production.up.railway.app', 'all']
    },
    build: {
      outDir: 'dist',
      emptyOutDir: true,
      sourcemap: false,
      minify: 'terser',
      target: 'es2022', 
      modulePreload: false,
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
          entryFileNames: 'assets/core-[hash].js',
          chunkFileNames: 'assets/vendor-[hash].js',
          assetFileNames: 'assets/[hash].[ext]',
        },
      },
    },
    optimizeDeps: {
      include: ['react', 'react-dom', 'firebase/app', 'firebase/firestore', 'lucide-react']
    }
  };
});
