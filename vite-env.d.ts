// Manually define ImportMetaEnv as 'vite/client' types are not resolvable
interface ImportMetaEnv {
  readonly VITE_ADSGRAM_BLOCK_ID: string
  readonly VITE_RAILWAY_BACKEND_URL: string
  readonly VITE_GEMINI_API_KEY: string
  readonly VITE_TELEGRAM_BOT_TOKEN: string
  readonly ADMIN_WALLET_ADDRESS: string
  [key: string]: any
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}